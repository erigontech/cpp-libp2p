/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <deque>
#include <set>
#include <unordered_map>

#include <libp2p/common/metrics/instance_count.hpp>

#include "common.hpp"

namespace libp2p::protocol::gossip {

  class MessageBuilder;
  class Stream;

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

    ~PeerContext() = default;
    PeerContext(PeerContext &&) = delete;
    PeerContext(const PeerContext &) = delete;
    PeerContext &operator=(const PeerContext &) = delete;
    PeerContext &operator=(PeerContext &&) = delete;

    explicit PeerContext(peer::PeerId id);

    LIBP2P_METRICS_INSTANCE_COUNT_IF_ENABLED(
        libp2p::protocol::gossip::PeerContext);
  };

  /// Operators needed to place PeerContextPtr into PeerSet but use
  /// const peer::PeerId& as a key
  bool operator<(const PeerContextPtr &ctx, const peer::PeerId &peer);
  bool operator<(const peer::PeerId &peer, const PeerContextPtr &ctx);
  bool operator<(const PeerContextPtr &a, const PeerContextPtr &b);

}  // namespace libp2p::protocol::gossip
