/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include <boost/asio/ssl/context.hpp>
#include <libp2p/common/asio_buffer.hpp>
#include <libp2p/common/asio_cb.hpp>
#include <libp2p/muxer/muxed_connection_config.hpp>
#include <libp2p/security/tls/tls_details.hpp>
#include <libp2p/security/tls/tls_errors.hpp>
#include <libp2p/transport/quic/connection.hpp>
#include <libp2p/transport/quic/engine.hpp>
#include <libp2p/transport/quic/error.hpp>
#include <libp2p/transport/quic/init.hpp>
#include <libp2p/transport/quic/stream.hpp>
#include <libp2p/transport/tcp/tcp_util.hpp>
#include <qtils/option_take.hpp>
#include <cstdio>

#include <openssl/x509.h>

// lsquic + BoringSSL blob boundary (see quicblob_shim.c): SSL material
// crosses only as DER bytes.
extern "C" void *quicblob_ctx_new(const unsigned char *cert_der,
                                  size_t cert_len,
                                  const unsigned char *key_der,
                                  size_t key_len);
extern "C" int quicblob_take_peer_cert_der(const void *conn,
                                           unsigned char *out,
                                           size_t cap);

namespace libp2p::transport::lsquic {
  Engine::Engine(std::shared_ptr<boost::asio::io_context> io_context,
                 std::shared_ptr<security::QuicCertAndKey> quic_material,
                 const muxer::MuxedConnectionConfig &mux_config,
                 PeerId local_peer,
                 std::shared_ptr<crypto::marshaller::KeyMarshaller> key_codec,
                 boost::asio::ip::udp::socket &&socket,
                 bool client)
      : io_context_{std::move(io_context)},
        quic_ssl_ctx_{quicblob_ctx_new(quic_material->cert_der.data(),
                                       quic_material->cert_der.size(),
                                       quic_material->key_der.data(),
                                       quic_material->key_der.size())},
        local_peer_{std::move(local_peer)},
        key_codec_{std::move(key_codec)},
        socket_{std::move(socket)},
        timer_{*io_context_},
        socket_local_{socket_.local_endpoint()},
        local_{detail::makeQuicAddr(socket_local_).value()} {
    socket_.non_blocking(true);

    lsquicInit();

    auto flags = 0;
    if (not client) {
      flags |= LSENG_SERVER;
    }

    lsquic_engine_settings settings{};
    lsquic_engine_init_settings(&settings, flags);
    settings.es_init_max_stream_data_bidi_remote =
        mux_config.maximum_window_size;
    settings.es_init_max_stream_data_bidi_local =
        mux_config.maximum_window_size;
    settings.es_init_max_streams_bidi = mux_config.maximum_streams;
    // Connection-level flow control: default lsquic credit is far below the
    // per-stream figure above and throttles a busy gossip stream the same
    // way a small yamux window does. Match the stream allowance.
    settings.es_init_max_data = mux_config.maximum_window_size;
    settings.es_idle_timeout = std::chrono::duration_cast<std::chrono::seconds>(
                                   mux_config.no_streams_interval)
                                   .count();
    settings.es_handshake_to =
        std::chrono::microseconds{mux_config.dial_timeout}.count();

    static lsquic_stream_if stream_if{};
    stream_if.on_new_conn = +[](void *void_self, lsquic_conn_t *conn) {
      auto self = static_cast<Engine *>(void_self);
      auto op = qtils::optionTake(self->connecting_);
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto conn_ctx = new ConnCtx{self, conn, std::move(op)};
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      auto _conn_ctx = reinterpret_cast<lsquic_conn_ctx_t *>(conn_ctx);
      lsquic_conn_set_ctx(conn, _conn_ctx);
      if (not op) {
        stream_if.on_hsk_done(conn, LSQ_HSK_OK);
      }
      return _conn_ctx;
    };
    stream_if.on_conn_closed = +[](lsquic_conn_t *conn) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      auto conn_ctx = reinterpret_cast<ConnCtx *>(lsquic_conn_get_ctx(conn));
      auto op = qtils::optionTake(conn_ctx->connecting);
      // Null the QuicConnection's ctx BEFORE any app callback can run: this
      // callback fires from inside lsquic teardown (ietf_full_conn_ci_destroy),
      // and a synchronously-invoked callback that drops the last shared_ptr
      // re-enters lsquic_conn_close() on the very connection being destroyed
      // (heap corruption: "corrupted size vs. prev_size" in ci_destroy free).
      if (auto c = conn_ctx->conn.lock()) {
        c->onClose();
      }
      // Defer the app callback off the lsquic stack (mirrors on_read).
      if (op) {
        post(*conn_ctx->engine->io_context_,
             [cb{std::move(op->cb)}] { cb(QuicError::CONN_CLOSED); });
      }
      lsquic_conn_set_ctx(conn, nullptr);
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      delete conn_ctx;
    };
    stream_if.on_hsk_done = +[](lsquic_conn_t *conn, lsquic_hsk_status status) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      auto conn_ctx = reinterpret_cast<ConnCtx *>(lsquic_conn_get_ctx(conn));
      auto self = conn_ctx->engine;
      auto ok = status == LSQ_HSK_OK or status == LSQ_HSK_RESUMED_OK;
      fprintf(stderr, "[quic] handshake %s\n", ok ? "ok" : "failed");
      // Run the handshake-completion logic exactly once: on_new_conn
      // synthesizes on_hsk_done for accepted connections and lsquic may also
      // deliver the real one; a second pass would construct a second
      // QuicConnection aliasing this ConnCtx.
      if (conn_ctx->hsk_done) {
        return;
      }
      conn_ctx->hsk_done = true;
      auto op = qtils::optionTake(conn_ctx->connecting);
      auto res = [&]() -> outcome::result<std::shared_ptr<QuicConnection>> {
        if (not ok) {
          return QuicError::HANDSHAKE_FAILED;
        }
        unsigned char cert_der[8192];
        const int cert_len = quicblob_take_peer_cert_der(
            conn, cert_der, sizeof(cert_der));
        if (cert_len <= 0) {
          return QuicError::HANDSHAKE_FAILED;
        }
        const unsigned char *cert_p = cert_der;
        auto cert = d2i_X509(nullptr, &cert_p, cert_len);
        if (cert == nullptr) {
          return QuicError::HANDSHAKE_FAILED;
        }
        auto info_res = security::tls_details::verifyPeerAndExtractIdentity(
            cert, *self->key_codec_);
        X509_free(cert);
        OUTCOME_TRY(info, std::move(info_res));
        if (op and info.peer_id != op->peer) {
          return security::TlsError::TLS_UNEXPECTED_PEER_ID;
        }
        // Inbound (accepted) connections have no Connecting op: derive the
        // remote endpoint from lsquic instead of dereferencing an empty
        // optional (UB that read garbage on every accepted QUIC connection).
        Multiaddress remote_addr = [&] {
          if (op) {
            return detail::makeQuicAddr(op->remote).value();
          }
          const sockaddr *sa_local = nullptr;
          const sockaddr *sa_peer = nullptr;
          lsquic_conn_get_sockaddr(conn, &sa_local, &sa_peer);
          boost::asio::ip::udp::endpoint ep;
          if (sa_peer != nullptr and sa_peer->sa_family == AF_INET) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto *sin = reinterpret_cast<const sockaddr_in *>(sa_peer);
            ep = {boost::asio::ip::address_v4{ntohl(sin->sin_addr.s_addr)},
                  ntohs(sin->sin_port)};
          } else if (sa_peer != nullptr and sa_peer->sa_family == AF_INET6) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa_peer);
            boost::asio::ip::address_v6::bytes_type b{};
            memcpy(b.data(), sin6->sin6_addr.s6_addr, b.size());
            ep = {boost::asio::ip::address_v6{b}, ntohs(sin6->sin6_port)};
          }
          return detail::makeQuicAddr(ep).value();
        }();
        auto conn = std::make_shared<QuicConnection>(
            self->io_context_,
            conn_ctx,
            op.has_value(),
            self->local_,
            std::move(remote_addr),
            self->local_peer_,
            info.peer_id,
            info.public_key);
        conn_ctx->conn = conn;
        return conn;
      }();
      if (not res) {
        lsquic_conn_close(conn);
      }
      // Defer completion off the lsquic stack for the same reason as
      // on_new_stream: the connect/accept handlers open streams and write
      // immediately, re-entering the engine mid-pass.
      if (op) {
        post(*self->io_context_,
             [cb{std::move(op->cb)}, res{std::move(res)}] { cb(res); });
      } else if (res) {
        post(*self->io_context_,
             [self, conn2{std::move(res.value())}] { self->on_accept_(conn2); });
      }
    };
    stream_if.on_new_stream = +[](void *void_self, lsquic_stream_t *stream) {
      auto self = static_cast<Engine *>(void_self);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      auto conn_ctx = reinterpret_cast<ConnCtx *>(
          lsquic_conn_get_ctx(lsquic_stream_conn(stream)));
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto stream_ctx = new StreamCtx{self, stream};
      if (auto conn = conn_ctx->conn.lock()) {
        auto stream = std::make_shared<QuicStream>(
            conn, stream_ctx, conn_ctx->new_stream.has_value());
        stream_ctx->stream = stream;
        if (conn_ctx->new_stream) {
          *conn_ctx->new_stream = stream;
        } else {
          // Defer off the lsquic stack: this callback fires inside
          // lsquic_engine_process_conns, and the app handler (multiselect)
          // immediately writes, which re-enters the engine — lsquic's own
          // re-entrancy assert (ENPUB_PROC) is compiled out in the NDEBUG
          // blob, and the nested pass frees packets/streams the interrupted
          // outer pass still references (heap corruption, live-observed).
          post(*self->io_context_,
               [conn, stream{std::move(stream)}] { conn->onStream()(stream); });
        }
      } else {
        lsquic_stream_close(stream);
      }
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      return reinterpret_cast<lsquic_stream_ctx_t *>(stream_ctx);
    };
    stream_if.on_close =
        +[](lsquic_stream_t *stream, lsquic_stream_ctx_t *_stream_ctx) {
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          auto stream_ctx = reinterpret_cast<StreamCtx *>(_stream_ctx);
          auto op = qtils::optionTake(stream_ctx->reading);
          // Null the QuicStream's ctx BEFORE any app callback: on_close fires
          // from ietf_full_conn_ci_destroy's stream-destroy loop; a synchronous
          // callback that drops the last shared_ptr re-enters
          // lsquic_stream_close() on the stream being destroyed and mutates
          // all_streams mid-iteration (SIGSEGV / heap corruption).
          if (auto s2 = stream_ctx->stream.lock()) {
            s2->onClose();
          }
          // Defer the app callback off the lsquic stack (mirrors on_read).
          if (op) {
            post(*stream_ctx->engine->io_context_,
                 [cb{std::move(op->cb)}] { cb(QuicError::STREAM_CLOSED); });
          }
          // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
          delete stream_ctx;
        };
    stream_if.on_read =
        +[](lsquic_stream_t *stream, lsquic_stream_ctx_t *_stream_ctx) {
          lsquic_stream_wantread(stream, 0);
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          auto stream_ctx = reinterpret_cast<StreamCtx *>(_stream_ctx);
          auto op = qtils::optionTake(stream_ctx->reading).value();
          auto n = lsquic_stream_read(stream, op.out.data(), op.out.size());
          outcome::result<size_t> r = QuicError::STREAM_CLOSED;
          if (n > 0) {
            r = n;
          }
          post(*stream_ctx->engine->io_context_,
               [cb{std::move(op.cb)}, r] { cb(r); });
        };

    lsquic_engine_api api{};
    api.ea_settings = &settings;

    api.ea_stream_if = &stream_if;
    api.ea_stream_if_ctx = this;
    api.ea_packets_out = +[](void *void_self,
                             const lsquic_out_spec *out_spec,
                             unsigned n_packets_out) {
      auto self = static_cast<Engine *>(void_self);
      // https://github.com/cbodley/nexus/blob/d1d8486f713fd089917331239d755932c7c8ed8e/src/socket.cc#L218
      int r = 0;
      for (auto &spec : std::span{out_spec, n_packets_out}) {
        msghdr msg{};
        msg.msg_iov = spec.iov;
        msg.msg_iovlen = spec.iovlen;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        msg.msg_name = const_cast<sockaddr *>(spec.dest_sa);
        msg.msg_namelen = spec.dest_sa->sa_family == AF_INET
                            ? sizeof(sockaddr_in)
                            : sizeof(sockaddr_in6);
        auto n = sendmsg(self->socket_.native_handle(), &msg, 0);
        if (n == -1) {
          if (errno == EAGAIN or errno == EWOULDBLOCK) {
            auto cb = [weak_self{self->weak_from_this()}](
                          boost::system::error_code ec) {
              auto self = weak_self.lock();
              if (not self) {
                return;
              }
              if (ec) {
                return;
              }
              lsquic_engine_send_unsent_packets(self->engine_);
            };
            self->socket_.async_wait(boost::asio::socket_base::wait_write,
                                     std::move(cb));
          }
          break;
        }
        ++r;
      }
      return r;
    };
    api.ea_packets_out_ctx = this;
    api.ea_get_ssl_ctx = +[](void *void_self, const sockaddr *) {
      auto self = static_cast<Engine *>(void_self);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      return reinterpret_cast<ssl_ctx_st *>(self->quic_ssl_ctx_);
    };

    engine_ = lsquic_engine_new(flags, &api);
    if (not engine_) {
      throw std::logic_error{"lsquic_engine_new"};
    }
  }

  Engine::~Engine() {
    lsquic_engine_destroy(engine_);
  }

  void Engine::start() {
    if (started_) {
      return;
    }
    started_ = true;
    readLoop();
  }

  void Engine::connect(const boost::asio::ip::udp::endpoint &remote,
                       const PeerId &peer,
                       OnConnect cb) {
    if (connecting_) {
      throw std::logic_error{"Engine::connect invalid state"};
    }
    connecting_ = Connecting{remote, peer, std::move(cb)};
    start();
    lsquic_engine_connect(engine_,
                          N_LSQVER,
                          socket_local_.data(),
                          remote.data(),
                          this,
                          nullptr,
                          nullptr,
                          0,
                          nullptr,
                          0,
                          nullptr,
                          0);
    if (auto op = qtils::optionTake(connecting_)) {
      op->cb(QuicError::CANT_CREATE_CONNECTION);
    }
    process();
  }

  outcome::result<std::shared_ptr<QuicStream>> Engine::newStream(
      ConnCtx *conn_ctx) {
    if (conn_ctx->new_stream) {
      throw std::logic_error{"Engine::newStream invalid state"};
    }
    if (lsquic_conn_n_pending_streams(conn_ctx->ls_conn) != 0) {
      return QuicError::TOO_MANY_STREAMS;
    }
    conn_ctx->new_stream.emplace();
    lsquic_conn_make_stream(conn_ctx->ls_conn);
    auto stream = qtils::optionTake(conn_ctx->new_stream).value();
    if (not stream) {
      return QuicError::CANT_OPEN_STREAM;
    }
    return stream;
  }

  void Engine::process() {
    // Hard re-entrancy guard: lsquic forbids re-entering
    // lsquic_engine_process_conns (its assert is compiled out in the NDEBUG
    // blob). If any callback path still reaches process() synchronously,
    // remember the request and run one trailing pass instead.
    if (in_engine_) {
      pending_process_ = true;
      return;
    }
    in_engine_ = true;
    lsquic_engine_process_conns(engine_);
    while (pending_process_) {
      pending_process_ = false;
      lsquic_engine_process_conns(engine_);
    }
    in_engine_ = false;
    int us = 0;
    if (not lsquic_engine_earliest_adv_tick(engine_, &us)) {
      return;
    }
    timer_.expires_after(std::chrono::microseconds{us});
    auto cb = [weak_self{weak_from_this()}](boost::system::error_code ec) {
      auto self = weak_self.lock();
      if (not self) {
        return;
      }
      if (ec) {
        return;
      }
      self->process();
    };
    timer_.async_wait(std::move(cb));
  }

  void Engine::readLoop() {
    // https://github.com/cbodley/nexus/blob/d1d8486f713fd089917331239d755932c7c8ed8e/src/socket.cc#L293
    while (true) {
      socklen_t len = socket_local_.size();
      auto n = recvfrom(socket_.native_handle(),
                        reading_.buf.data(),
                        reading_.buf.size(),
                        0,
                        reading_.remote.data(),
                        &len);
      if (n == -1) {
        if (errno == EAGAIN or errno == EWOULDBLOCK) {
          auto cb =
              [weak_self{weak_from_this()}](boost::system::error_code ec) {
                auto self = weak_self.lock();
                if (not self) {
                  return;
                }
                if (ec) {
                  return;
                }
                self->readLoop();
              };
          socket_.async_wait(boost::asio::socket_base::wait_read,
                             std::move(cb));
        }
        return;
      }
      // Same re-entrancy rule as process(): callbacks fired from inside
      // packet_in must not re-enter the engine; they set pending_process_
      // and the explicit process() below runs the deferred pass.
      in_engine_ = true;
      lsquic_engine_packet_in(engine_,
                              reading_.buf.data(),
                              n,
                              socket_local_.data(),
                              reading_.remote.data(),
                              this,
                              0);
      in_engine_ = false;
      process();
    }
  }
}  // namespace libp2p::transport::lsquic
