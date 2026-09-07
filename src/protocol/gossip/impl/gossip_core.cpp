/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gossip_core.hpp"

#include <cassert>

#include <libp2p/crypto/crypto_provider.hpp>
#include <libp2p/crypto/key_marshaller.hpp>
#include <libp2p/peer/identity_manager.hpp>
#include <qtils/hex.hpp>

#include "connectivity.hpp"
#include "local_subscriptions.hpp"
#include "message_builder.hpp"
#include "remote_subscriptions.hpp"

namespace libp2p::protocol::gossip {

  std::shared_ptr<Gossip> create(
      std::shared_ptr<basic::Scheduler> scheduler,
      std::shared_ptr<Host> host,
      std::shared_ptr<peer::IdentityManager> idmgr,
      std::shared_ptr<crypto::CryptoProvider> crypto_provider,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller,
      Config config) {
    return std::make_shared<GossipCore>(std::move(config),
                                        std::move(scheduler),
                                        std::move(host),
                                        std::move(idmgr),
                                        std::move(crypto_provider),
                                        std::move(key_marshaller));
  }

  // clang-format off
  GossipCore::GossipCore(Config config,
                         std::shared_ptr<basic::Scheduler> scheduler,
                         std::shared_ptr<Host> host,
                         std::shared_ptr<peer::IdentityManager> idmgr,
                         std::shared_ptr<crypto::CryptoProvider> crypto_provider,
                         std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller)
      : config_(std::move(config)),
        create_message_id_([](const Bytes &from, const Bytes &seq,
                              const Bytes &data, const TopicId &){
          return createMessageId(from, seq, data);
        }),
        scheduler_(std::move(scheduler)),
        host_(std::move(host)),
        idmgr_(std::move(idmgr)),
        crypto_provider_(std::move(crypto_provider)),
        key_marshaller_(std::move(key_marshaller)),
        local_peer_id_(host_->getPeerInfo().id),
        msg_cache_(
            config_.message_cache_lifetime_msec,
            [sch = scheduler_] { return sch->now(); }
        ),
        local_subscriptions_(std::make_shared<LocalSubscriptions>(
            [this](bool subscribe, const TopicId &topic) {
              onLocalSubscriptionChanged(subscribe, topic);
            }
        )),
        msg_seq_(scheduler_->now().count()),
        heartbeat_timer_(),
        scorer_(config_.peer_score_params, config_.peer_score_thresholds),
        log_("gossip", "Gossip", local_peer_id_.toBase58().substr(46)) {
    // Verbatim Lighthouse/rust-libp2p scoring. Global params only at
    // construction; per-topic params are installed lazily when topics are
    // seen (fork-digest-dependent names), see ensureTopicScoreParams.
    auto params = score::lighthouse_mainnet_params("", {});
    params.topics.clear();
    score_thresholds2_ = score::lighthouse_thresholds();
    peer_score2_ = std::make_shared<score::PeerScore>(std::move(params),
                                                     score_thresholds2_);
  }
  // clang-format on

  void GossipCore::addBootstrapPeer(
      const peer::PeerId &id, boost::optional<multi::Multiaddress> address) {
    if (started_) {
      connectivity_->addBootstrapPeer(id, address);
    }
    bootstrap_peers_[id] = std::move(address);
  }

  outcome::result<void> GossipCore::addBootstrapPeer(
      const std::string &address) {
    OUTCOME_TRY(ma, libp2p::multi::Multiaddress::create(address));
    auto peer_id_str = ma.getPeerId();
    if (!peer_id_str) {
      return multi::Multiaddress::Error::INVALID_INPUT;
    }
    OUTCOME_TRY(peer_id, peer::PeerId::fromBase58(*peer_id_str));
    addBootstrapPeer(peer_id, {std::move(ma)});
    return outcome::success();
  }

  void GossipCore::start() {
    if (started_) {
      log_.warn("already started");
      return;
    }

    // clang-format off
    connectivity_ = std::make_shared<Connectivity>(
        config_,
        scheduler_,
        host_,
        shared_from_this(),
        [this](bool connected, const PeerContextPtr &ctx) {
          onPeerConnection(connected, ctx);
        }
    );
    // clang-format on

    for (const auto &p : bootstrap_peers_) {
      connectivity_->addBootstrapPeer(p.first, p.second);
    }

    remote_subscriptions_ = std::make_shared<RemoteSubscriptions>(
        config_, *connectivity_, *scheduler_, peer_score2_, log_);

    started_ = true;

    for (const auto &[topic, _] : local_subscriptions_->subscribedTo()) {
      remote_subscriptions_->onSelfSubscribed(true, topic);
    }

    setTimerHeartbeat();

    connectivity_->start();
  }

  void GossipCore::stop() {
    if (!started_) {
      return;
    }

    started_ = false;

    heartbeat_timer_.reset();

    // it closes all senders and receivers
    connectivity_->stop();

    remote_subscriptions_.reset();
    connectivity_.reset();

    local_subscriptions_->forwardEndOfSubscription();
  }

  void GossipCore::setValidator(const TopicId &topic, Validator validator) {
    assert(validator);
    auto sub = subscribe({topic}, [](const SubscriptionData &) {});
    validators_[topic] = {std::move(validator), std::move(sub)};
  }

  void GossipCore::setMessageIdFn(MessageIdFn fn) {
    assert(fn);
    create_message_id_ = std::move(fn);
  }

  Subscription GossipCore::subscribe(TopicSet topics,
                                     SubscriptionCallback callback) {
    assert(callback);
    assert(!topics.empty());

    return local_subscriptions_->subscribe(std::move(topics),
                                           std::move(callback));
  }

  bool GossipCore::publish(TopicId topic, Bytes data) {
    if (!started_) {
      return false;
    }

    auto msg = std::make_shared<TopicMessage>(
        local_peer_id_, ++msg_seq_, std::move(data), std::move(topic));

    if (config_.sign_messages) {
      auto res = signMessage(*msg);
      if (!res) {
        log_.warn("signMessage error: {}", res.error());
      }
    }

    MessageId msg_id = create_message_id_(msg->from, msg->seq_no, msg->data, msg->topic);

    [[maybe_unused]] bool inserted = msg_cache_.insert(msg, msg_id);
    assert(inserted);

    remote_subscriptions_->onNewMessage(boost::none, msg, msg_id);

    if (config_.echo_forward_mode) {
      local_subscriptions_->forwardMessage(msg, {});
    }

    return true;
  }

  std::vector<peer::PeerId> GossipCore::getConnectedPeers() const {
    std::vector<peer::PeerId> peers;
    connectivity_->getConnectedPeers().selectAll(
        [&peers](const PeerContextPtr &ctx) { peers.push_back(ctx->peer_id); });
    return peers;
  }

  std::vector<peer::PeerId> GossipCore::getMeshPeers() const {
    std::vector<peer::PeerId> peers;
    connectivity_->getConnectedPeers().selectAll(
        [&peers](const PeerContextPtr &ctx) {
          if (!ctx->mesh_since.empty()) {
            peers.push_back(ctx->peer_id);
          }
        });
    return peers;
  }

  outcome::result<void> GossipCore::signMessage(TopicMessage &msg) const {
    const auto &keypair = idmgr_->getKeyPair();
    OUTCOME_TRY(signable, MessageBuilder::signableMessage(msg));
    OUTCOME_TRY(signature,
                crypto_provider_->sign(signable, keypair.privateKey));
    msg.signature = std::move(signature);
    if (idmgr_->getId().toMultihash().getType() != multi::HashType::identity) {
      OUTCOME_TRY(key, key_marshaller_->marshal(keypair.publicKey));
      msg.key = std::move(key.key);
    }
    return outcome::success();
  }

  void GossipCore::onSubscription(const PeerContextPtr &peer,
                                  bool subscribe,
                                  const TopicId &topic) {
    assert(started_);

    log_.debug("peer {} {}subscribed, topic {}",
               peer->str,
               (subscribe ? "" : "un"),
               topic);
    if (subscribe) {
      remote_subscriptions_->onPeerSubscribed(peer, topic);
    } else {
      remote_subscriptions_->onPeerUnsubscribed(peer, topic, false);
    }
  }

  void GossipCore::onIHave(const PeerContextPtr &from,
                           const TopicId &topic,
                           const MessageId &msg_id) {
    assert(started_);

    log_.info("IHAVE from peer {} for topic {}", from->str, topic);

    if (remote_subscriptions_->hasTopic(topic)
        && !msg_cache_.contains(msg_id)) {
      log_.info("requesting IWANT msg_id={:x} from peer {}", msg_id, from->str);

      from->message_builder->addIWant(msg_id);
      // Eager pull for latency-critical sparse topics (eth2 beacon blocks):
      // flush the IWANT immediately, but ONLY for the first advertiser of
      // this msg_id — later IHAVEs for the same id go the lazy heartbeat
      // path. An unconditional immediate flush (all topics, all advertisers)
      // is an IWANT burst storm that gets this node rate-limited by peers
      // (observed 2026-08-15: beacon_block delivery collapsed in minutes).
      bool eager = false;
      // A/B toggle: default ON; set SILKWORM_GOSSIP_EAGER_IWANT=0 to fall back
      // to the pure heartbeat path so coverage can be compared across runs.
      static const bool eager_enabled = [] {
        const char* env = std::getenv("SILKWORM_GOSSIP_EAGER_IWANT");
        return env == nullptr || env[0] != '0';
      }();
      static constexpr std::string_view kEagerTopicSuffix = "/beacon_block/ssz_snappy";
      // Race the first K advertisers rather than only the first: block
      // transmission time (~100KB) makes single-source IWANT a lottery on
      // the advertiser's send-queue position; 3 parallel pulls take the min
      // at negligible cost (extra copies are dups we IDONTWANT away).
      static constexpr uint8_t kEagerAdvertisers = 3;
      if (eager_enabled && topic.size() >= kEagerTopicSuffix.size()
          && std::equal(kEagerTopicSuffix.rbegin(), kEagerTopicSuffix.rend(), topic.rbegin())) {
        auto [it, inserted] = eager_iwant_seen_.emplace(msg_id, 0);
        if (inserted) {
          eager_iwant_order_.push_back(msg_id);
          if (eager_iwant_order_.size() > 256) {
            eager_iwant_seen_.erase(eager_iwant_order_.front());
            eager_iwant_order_.pop_front();
          }
        }
        if (it->second < kEagerAdvertisers) {
          ++it->second;
          eager = true;
        }
      }
      if (eager) {
        // Countable marker for the A/B analysis: how often the eager path
        // actually fires (vs. beacon blocks arriving via mesh push, where
        // IWANT latency is irrelevant).
        log_.info("eager IWANT flush msg_id={:x} from peer {}", msg_id, from->str);
      }
      connectivity_->peerIsWritable(from, eager);
    }
  }

  void GossipCore::onIDontWant(const PeerContextPtr &from,
                               const MessageId &msg_id) {
    // gossipsub v1.2: the peer already has this message; suppress our
    // forward of it (bounded FIFO per peer)
    if (from->dont_want.insert(msg_id).second) {
      from->dont_want_order.push_back(msg_id);
      if (from->dont_want_order.size() > 128) {
        from->dont_want.erase(from->dont_want_order.front());
        from->dont_want_order.pop_front();
      }
    }
  }

  void GossipCore::onIWant(const PeerContextPtr &from,
                           const MessageId &msg_id) {
    log_.info("IWANT from peer {} for msg_id={:x}", from->str, msg_id);

    auto msg_found = msg_cache_.getMessage(msg_id);
    if (msg_found) {
      from->message_builder->addMessage(*msg_found.value(), msg_id);
      connectivity_->peerIsWritable(from, true);
    } else {
      log_.info("IWANT: message not in cache");
    }
  }

  void GossipCore::onGraft(const PeerContextPtr &from, const TopicId &topic) {
    assert(started_);

    log_.info("GRAFT from peer {} for topic {}", from->str, topic);

    remote_subscriptions_->onGraft(from, topic);
  }

  void GossipCore::onPrune(const PeerContextPtr &from,
                           const TopicId &topic,
                           uint64_t backoff_time) {
    assert(started_);

    log_.info("PRUNE from peer {} for topic {}, backoff={}s", from->str, topic, backoff_time);

    remote_subscriptions_->onPrune(from, topic, backoff_time);
  }

  void GossipCore::onPrunePeerExchange(const peer::PeerId &peer_id) {
    if (!started_) {
      return;
    }
    if (peer_id == local_peer_id_) {
      return;
    }
    log_.info("PX: adding peer {} from PRUNE peer exchange", peer_id.toBase58());
    addBootstrapPeer(peer_id, boost::none);
  }

  namespace {
    inline score::TimePoint toScoreTime(Time t) {
      return score::TimePoint{
          std::chrono::duration_cast<std::chrono::nanoseconds>(t)};
    }

    bool isBeaconBlockTopic(const TopicId &topic) {
      static constexpr std::string_view kSuffix = "/beacon_block/ssz_snappy";
      return topic.size() >= kSuffix.size()
          && std::equal(kSuffix.rbegin(), kSuffix.rend(), topic.rbegin());
    }
  }  // namespace

  void GossipCore::onTopicMessage(const PeerContextPtr &from,
                                  TopicMessage::Ptr msg) {
    assert(started_);

    // do we need this message?
    auto subscribed = remote_subscriptions_->hasTopic(msg->topic);
    if (!subscribed) {
      // ignore this message
      return;
    }

    // Graylist gate (gossipsub v1.1): ignore everything from peers whose
    // score fell below the graylist threshold.
    if (peer_score2_->score(from->peer_id) < score_thresholds2_.graylist_threshold) {
      log_.debug("graylisted peer {}, dropping message", from->str);
      return;
    }
    ensureTopicScoreParams(msg->topic);

    MessageId msg_id = create_message_id_(msg->from, msg->seq_no, msg->data, msg->topic);
    const std::string msg_id_str(msg_id.begin(), msg_id.end());
    // hot path: every gossip message (attestations included) passes here on
    // the libp2p-io thread — keep it below the configured info level
    log_.debug("MESSAGE arrived from peer {}, topic={}, size={}, msg_id={:x}",
               from->str, msg->topic, msg->data.size(), msg_id);

    if (msg_cache_.contains(msg_id)) {
      // duplicate delivery: measure this peer's lag vs the first copy
      if (isBeaconBlockTopic(msg->topic)) {
        auto it = first_delivery_.find(msg_id);
        if (it != first_delivery_.end() && it->second.second != from) {
          const auto lag =
              static_cast<double>((scheduler_->now() - it->second.first).count());
          ++from->dup_msg_deliveries;
          from->delivery_lag_ewma_ms = from->delivery_lag_ewma_ms < 0
              ? lag
              : 0.8 * from->delivery_lag_ewma_ms + 0.2 * lag;
        }
      }
      peer_score2_->duplicated_message(from->peer_id, msg_id_str, msg->topic,
                                       toScoreTime(scheduler_->now()));
      log_.debug("ignoring message, already in cache");
      return;
    }

    // validate message. If no validator is set then we
    // suppose that the message is valid (we might not know topic details)
    bool valid = true;

    if (!validators_.empty()) {
      auto it = validators_.find(msg->topic);
      if (it != validators_.end()) {
        valid = it->second.validator(msg->from, msg->data);
      }
    }

    peer_score2_->validate_message(from->peer_id, msg_id_str, msg->topic,
                                   toScoreTime(scheduler_->now()));
    if (!valid) {
      // P4 (InvalidMessageDeliveries): verbatim rust-libp2p semantics — the
      // reject fans out to every peer that delivered this id and the record
      // marks later copies invalid on arrival.
      peer_score2_->reject_message(from->peer_id, msg_id_str, msg->topic,
                                   score::RejectReason::kValidationError,
                                   toScoreTime(scheduler_->now()));
      PeerScorer::recordInvalidMessage(*from, msg->topic);
      log_.debug("message validation failed (P4 penalty applied to {})",
                 from->str);
      return;
    }
    peer_score2_->deliver_message(from->peer_id, msg_id_str, msg->topic,
                                  toScoreTime(scheduler_->now()));

    if (!msg_cache_.insert(msg, msg_id)) {
      log_.error("message cache error");
      return;
    }

    if (isBeaconBlockTopic(msg->topic)) {
      ++from->first_msg_deliveries;
      if (from->delivery_lag_ewma_ms < 0) {
        from->delivery_lag_ewma_ms = 0.0;
      } else {
        from->delivery_lag_ewma_ms *= 0.8;
      }
      first_delivery_.emplace(msg_id, std::make_pair(scheduler_->now(), from));
      first_delivery_order_.push_back(msg_id);
      if (first_delivery_order_.size() > 64) {
        first_delivery_.erase(first_delivery_order_.front());
        first_delivery_order_.pop_front();
      }
      // one line per block: who won the delivery race
      log_.info("first delivery msg_id={:x} from peer {}", msg_id, from->str);
    }

    log_.debug("forwarding message");

    local_subscriptions_->forwardMessage(msg, from->str);
    remote_subscriptions_->onNewMessage(from, msg, msg_id);
  }

  void GossipCore::onMessageEnd(const PeerContextPtr &from) {
    assert(started_);

    log_.debug("finished dispatching message from peer {}", from->str);

    // Apply immediate send operation to affected peers
    connectivity_->flush();
  }

  void GossipCore::onHeartbeat() {
    if (++heartbeat_seq_ % 128 == 0) {
      connectivity_->getConnectedPeers().selectAll(
          [this](const PeerContextPtr &ctx) {
            if (ctx->first_msg_deliveries + ctx->dup_msg_deliveries > 0) {
              log_.info(
                  "delivery-stats peer={} first={} dup={} lag_ewma_ms={} mesh={}",
                  ctx->str, ctx->first_msg_deliveries, ctx->dup_msg_deliveries,
                  static_cast<int64_t>(ctx->delivery_lag_ewma_ms),
                  ctx->mesh_since.empty() ? 0 : 1);
            }
          });
    }
    assert(started_);

    // shift cache
    msg_cache_.shift();

    // Tick the peer scorer once per heartbeat. The scorer applies counter
    // decay and refreshes PeerContext::cached_score for every connected peer.
    // Subsequent mesh-selection passes use the cache directly (O(1) lookup).
    // The internal decay_interval gate inside tick() keeps the work bounded
    // even at high heartbeat rates.
    auto now = scheduler_->now();
    std::vector<PeerContextPtr> ticked;
    connectivity_->getConnectedPeers().selectAll(
        [&ticked](const PeerContextPtr &p) { ticked.push_back(p); });
    scorer_.tick(now, ticked);

    // Verbatim scorer: decay/refresh once per decay_interval (12s), then
    // publish scores into PeerContext::cached_score for mesh decisions.
    if (last_score_refresh_ == Time{} ||
        now - last_score_refresh_ >= peer_score2_->params().decay_interval) {
      last_score_refresh_ = now;
      peer_score2_->refresh_scores(toScoreTime(now));
      for (auto &p : ticked) {
        p->cached_score = peer_score2_->score(p->peer_id);
      }
    }

    // heartbeat changes per topic
    remote_subscriptions_->onHeartbeat();

    // send changes to peers
    connectivity_->onHeartbeat(broadcast_on_heartbeat_);
    broadcast_on_heartbeat_.clear();

    setTimerHeartbeat();
  }

  void GossipCore::ensureTopicScoreParams(const TopicId &topic) {
    if (peer_score2_->params().topics.count(topic) != 0) {
      return;
    }
    // Pattern-match eth2 topic names; other topics score only globally.
    const bool is_block = topic.find("/beacon_block/") != std::string::npos;
    const bool is_subnet =
        topic.find("/beacon_attestation_") != std::string::npos;
    if (!is_block && !is_subnet) {
      return;
    }
    auto tmpl = is_block
        ? score::lighthouse_mainnet_params(topic, {})
        : score::lighthouse_mainnet_params("__unused__", {topic});
    auto it = tmpl.topics.find(topic);
    if (it != tmpl.topics.end()) {
      peer_score2_->set_topic_params(topic, it->second);
      log_.info("score params installed for {}", topic);
    }
  }

  void GossipCore::onPeerConnection(bool connected, const PeerContextPtr &ctx) {
    assert(started_);

    if (connected) {
      peer_score2_->add_peer(ctx->peer_id);
      log_.debug("peer {} connected", ctx->str);
      // notify the new peer about all topics we subscribed to
      if (!local_subscriptions_->subscribedTo().empty()) {
        for (const auto &local_sub : local_subscriptions_->subscribedTo()) {
          ctx->message_builder->addSubscription(true, local_sub.first);
        }
        connectivity_->peerIsWritable(ctx, true);
        connectivity_->flush();
      }
    } else {
      peer_score2_->remove_peer(ctx->peer_id, toScoreTime(scheduler_->now()));
      log_.debug("peer {} disconnected", ctx->str);
      remote_subscriptions_->onPeerDisconnected(ctx);
    }
  }

  void GossipCore::onLocalSubscriptionChanged(bool subscribe,
                                              const TopicId &topic) {
    if (!started_) {
      return;
    }

    // send this notification on next heartbeat to all connected peers
    auto it = broadcast_on_heartbeat_.find(topic);
    if (it == broadcast_on_heartbeat_.end()) {
      broadcast_on_heartbeat_.emplace(topic, subscribe);
    } else if (it->second != subscribe) {
      // save traffic
      broadcast_on_heartbeat_.erase(it);
    }

    // update meshes per topic
    remote_subscriptions_->onSelfSubscribed(subscribe, topic);
  }

  void GossipCore::setTimerHeartbeat() {
    heartbeat_timer_ = scheduler_->scheduleWithHandle(
        [weak_self{weak_from_this()}] {
          auto self = weak_self.lock();
          if (not self) {
            return;
          }
          self->onHeartbeat();
        },
        config_.heartbeat_interval_msec);
  }
}  // namespace libp2p::protocol::gossip
