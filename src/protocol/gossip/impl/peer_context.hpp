/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <array>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>

#include <libp2p/common/metrics/instance_count.hpp>

#include "common.hpp"

namespace libp2p::protocol::gossip {

  class MessageBuilder;
  class Stream;

  /// Config::peer_diagnostics: the counters of a peer's session, and the
  /// message IDs we announced to it with when (silkworm #167)
  struct PeerDiagnosticsState {
    PeerDiagnostics view;
    /// Begun at, disconnected at (zero while connected)
    Time started{0};
    Time disconnected{0};

    /// The first IHAVE of each of the last kAnnounced message IDs (by their
    /// first 8 bytes) we sent the peer: the age of the IDs it asks for
    static constexpr size_t kAnnounced = 512;
    std::unordered_map<uint64_t, Time> announced;
    std::array<uint64_t, kAnnounced> announced_order{};
    size_t announced_next = 0;

    void announce(const MessageId &msg_id, Time now);
    std::optional<Time> announcedAt(const MessageId &msg_id) const;
    PeerDiagnostics::Topic &topic(const TopicId &id) {
      return view.topics[id];
    }
  };

  /// Data related to peer needed by pub-sub protocols
  struct PeerContext {
    /// The key
    const peer::PeerId peer_id;

    /// String repr for logging purposes
    const std::string str;

    /// Builds message to be sent to this peer
    std::shared_ptr<MessageBuilder> message_builder;

    /// Set of topics this peer is subscribed to
    std::set<TopicId> subscribed_to;

    /// Streams connected to peer
    std::shared_ptr<Stream> outbound_stream;
    std::vector<std::shared_ptr<Stream>> inbound_streams;

    /// Dialing to this peer is banned until this timestamp
    Time banned_until{0};

    /// Current dial attempts
    unsigned dial_attempts = 0;

    /// If true, then outbound connection is in progress
    bool is_connecting = false;

    /// We dialed the connection to the peer (the outbound mesh quota D_out),
    /// unless it was from a peer exchange, see
    /// GossipCore::refreshConnectionInfo
    bool outbound = false;

    /// We dialed it because a PRUNE peer exchange named it: never outbound
    bool px_dialed = false;

    /// Its remote IPs known to the IP colocation score (P6)
    std::set<std::string> ips;

    /// Per-topic mesh entry time for P1 (TimeInMesh) scoring
    std::unordered_map<TopicId, Time> mesh_since;

    /// Message ids this peer asked us not to send (gossipsub v1.2
    /// IDONTWANT); bounded FIFO maintained by GossipCore::onIDontWant
    std::set<MessageId> dont_want;
    std::deque<MessageId> dont_want_order;

    /// Delivery telemetry for latency-aware curation (beacon_block only):
    /// first-delivery credit, duplicate count, EWMA of delivery lag vs the
    /// first-arrived copy in ms (-1 = no sample yet)
    uint64_t first_msg_deliveries = 0;
    uint64_t dup_msg_deliveries = 0;
    double delivery_lag_ewma_ms = -1.0;

    /// Block IHAVEs and messages of any topic it sent us: a silent block mesh
    /// member still announcing blocks does not count us in its mesh
    /// (silkworm #149)
    uint64_t block_ihaves_rx = 0;
    uint64_t messages_rx = 0;
    /// The same deliveries and IHAVEs for the execution payload envelopes
    uint64_t envelope_first_deliveries = 0;
    uint64_t envelope_dup_deliveries = 0;
    uint64_t envelope_ihaves_rx = 0;
    /// RPC frames read from it, and its IDONTWANTs for the blocks and the
    /// envelopes we hold; its connection is QUIC (silkworm #149)
    uint64_t rpcs_rx = 0;
    uint64_t block_idontwant_rx = 0;
    uint64_t envelope_idontwant_rx = 0;
    bool quic = false;

    /// Partial messages extension (gossipsub v1.3, silkworm #174), only while
    /// Config::partial_messages is on: the peer advertised it in the
    /// Extensions control message that opened its stream to us, we advertised
    /// it in the one that opened ours to it (our subscriptions to it carry our
    /// partial options only then), and the options of its subscriptions that
    /// set any. Partial messages are exchanged only when both advertised it
    bool partial_messages = false;
    bool partial_advertised = false;
    std::map<TopicId, PartialTopicOptions> partial_topics;

    /// Config::peer_diagnostics: its session, none outside one
    std::unique_ptr<PeerDiagnosticsState> diag;

    ~PeerContext() = default;
    PeerContext(PeerContext &&) = delete;
    PeerContext(const PeerContext &) = delete;
    PeerContext &operator=(const PeerContext &) = delete;
    PeerContext &operator=(PeerContext &&) = delete;

    explicit PeerContext(peer::PeerId id);

    LIBP2P_METRICS_INSTANCE_COUNT_IF_ENABLED(
        libp2p::protocol::gossip::PeerContext);
  };

  /// The diagnostics of \p ctx's session, begun (or continued) at \p now:
  /// a new one past \p keep after the previous one's disconnection
  PeerDiagnosticsState &beginDiagnostics(PeerContext &ctx, Time now, Time keep);

  /// What we queue for a peer, counted in its session if it has one
  inline void diagnoseMessage(PeerContext &ctx,
                              const TopicId &topic,
                              size_t bytes) {
    if (auto *diag = ctx.diag.get()) {
      auto &counters = diag->topic(topic);
      ++counters.messages;
      counters.message_bytes += bytes;
    }
  }
  inline void diagnoseIDontWant(PeerContext &ctx, const TopicId &topic) {
    if (auto *diag = ctx.diag.get()) {
      ++diag->view.idontwant_tx;
      ++diag->topic(topic).idontwant;
    }
  }
  inline void diagnoseIHave(PeerContext &ctx,
                            const TopicId &topic,
                            const MessageId &msg_id,
                            Time now,
                            bool on_subscribe = false) {
    if (auto *diag = ctx.diag.get()) {
      ++diag->view.ihave_ids_tx;
      auto &counters = diag->topic(topic);
      ++counters.ihave_ids;
      if (on_subscribe) {
        ++counters.ihave_ids_on_subscribe;
      }
      diag->announce(msg_id, now);
    }
  }
  inline void diagnoseGraft(PeerContext &ctx, const TopicId &topic) {
    if (auto *diag = ctx.diag.get()) {
      ++diag->view.graft_tx;
      ++diag->topic(topic).graft;
    }
  }
  inline void diagnosePrune(PeerContext &ctx, const TopicId &topic) {
    if (auto *diag = ctx.diag.get()) {
      ++diag->view.prune_tx;
      ++diag->topic(topic).prune;
    }
  }

  /// Operators needed to place PeerContextPtr into PeerSet but use
  /// const peer::PeerId& as a key
  bool operator<(const PeerContextPtr &ctx, const peer::PeerId &peer);
  bool operator<(const peer::PeerId &peer, const PeerContextPtr &ctx);
  bool operator<(const PeerContextPtr &a, const PeerContextPtr &b);

}  // namespace libp2p::protocol::gossip
