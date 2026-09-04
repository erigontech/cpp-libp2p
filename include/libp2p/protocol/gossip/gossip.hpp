/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <chrono>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/optional.hpp>

#include <libp2p/common/byteutil.hpp>
#include <libp2p/multi/multiaddress.hpp>
#include <libp2p/peer/peer_id.hpp>
#include <libp2p/protocol/common/subscription.hpp>

namespace libp2p {
  struct Host;
  namespace basic {
    class Scheduler;
  }
  namespace crypto {
    class CryptoProvider;
    namespace marshaller {
      class KeyMarshaller;
    }
  }  // namespace crypto
  namespace peer {
    struct IdentityManager;
  }
}  // namespace libp2p

namespace libp2p::protocol::gossip {

  /// Per-topic peer-score weights. Mirrors go-libp2p's TopicScoreParams.
  /// All defaults are zero ("feature off"); callers override the ones they
  /// care about.
  struct TopicScoreParams {
    /// Weight of this topic against the global score cap.
    double topic_weight = 0.5;

    /// P1: time in mesh — reward for being in the mesh.
    /// Score contribution = min(time_in_mesh / quantum, cap) * weight.
    double time_in_mesh_weight = 0.0;
    std::chrono::seconds time_in_mesh_quantum{12};
    double time_in_mesh_cap = 300.0;

    /// P4: invalid message deliveries — strong penalty.
    /// Score contribution = -(counter^2) * weight.
    double invalid_message_deliveries_weight = 0.0;
    double invalid_message_deliveries_decay = 0.5;
  };

  /// Global peer-score weights. Mirrors go-libp2p's PeerScoreParams (the
  /// subset that meaningfully drives mesh stability for eth2).
  struct PeerScoreParams {
    /// Per-topic parameters, keyed by topic id.
    std::unordered_map<std::string, TopicScoreParams> topics;

    /// Cap on per-topic contribution before global summation.
    double topic_score_cap = 32.72;

    /// P7: behaviour penalty — accumulated on protocol violations (e.g.
    /// GRAFT before backoff). Score = -max(0, counter - threshold)^2 * weight.
    double behaviour_penalty_weight = 0.0;
    double behaviour_penalty_threshold = 6.0;
    double behaviour_penalty_decay = 0.5;

    /// Counter decay period (typically one slot).
    std::chrono::seconds decay_interval{12};

    /// Counter values below this are clamped to zero after decay.
    double decay_to_zero = 0.01;

    /// Retain disconnected peers' scores for this long so reconnecting peers
    /// don't reset their penalty history. Zero disables retention.
    std::chrono::seconds retain_score{3600};
  };

  /// Score thresholds. Mirrors go-libp2p's PeerScoreThresholds.
  struct PeerScoreThresholds {
    double gossip_threshold = -4000.0;
    double publish_threshold = -8000.0;
    double graylist_threshold = -16000.0;
    double accept_px_threshold = 100.0;
    double opportunistic_graft_threshold = 5.0;
  };

  /// Gossip pub-sub protocol config
  struct Config {
    /// Network density factors for gossip meshes
    size_t D_min = 5;
    size_t D_max = 10;

    /// Ideal number of connected peers to support the network
    size_t ideal_connections_num = 100;

    /// Maximum number of simultaneous connections after which new
    /// incoming peers will be rejected
    size_t max_connections_num = 1000;

    /// Forward messages to all subscribers not in mesh
    /// (floodsub mode compatibility)
    bool floodsub_forward_mode = false;

    /// Forward local message to local subscribers
    bool echo_forward_mode = false;

    /// Read or write timeout per whole network operation
    std::chrono::milliseconds rw_timeout_msec{std::chrono::seconds(10)};

    /// Lifetime of a message in message cache
    std::chrono::milliseconds message_cache_lifetime_msec{
        std::chrono::minutes(2)};

    /// Topic's message seen cache lifetime
    std::chrono::milliseconds seen_cache_lifetime_msec{
        message_cache_lifetime_msec * 3 / 4};

    /// Topic's seen cache limit
    unsigned seen_cache_limit = 100;

    /// Heartbeat interval
    std::chrono::milliseconds heartbeat_interval_msec{1000};

    /// Ban interval between dial attempts to peer
    std::chrono::milliseconds ban_interval_msec{std::chrono::minutes(1)};

    /// Max number of dial attempts before peer is forgotten
    unsigned max_dial_attempts = 3;

    /// Expiration of gossip peers' addresses in address repository
    std::chrono::milliseconds address_expiration_msec{std::chrono::hours(1)};

    /// Max RPC message size
    size_t max_message_size = 1 << 24;

    /// Protocol version
    std::string protocol_version = "/meshsub/1.0.0";

    /// Sign published messages
    bool sign_messages = false;

    /// Peer-score parameters and thresholds. When all weights are zero
    /// (the default), scoring is effectively disabled — but the bookkeeping
    /// still runs at near-zero cost, so eth2 callers can leave the toggle
    /// alone and just supply non-zero weights for the topics that matter.
    PeerScoreParams peer_score_params;
    PeerScoreThresholds peer_score_thresholds;
  };

  using TopicId = std::string;
  using TopicList = std::vector<TopicId>;
  using TopicSet = std::set<TopicId>;

  /// Gossip protocol interface
  class Gossip {
   public:
    virtual ~Gossip() = default;

    /// Adds bootstrap peer to the set of connectable peers
    virtual void addBootstrapPeer(
        const peer::PeerId &id,
        boost::optional<multi::Multiaddress> address) = 0;

    /// Adds bootstrap peer address in string form
    virtual outcome::result<void> addBootstrapPeer(
        const std::string &address) = 0;

    /// Starts client and server
    virtual void start() = 0;

    /// Stops client and server
    virtual void stop() = 0;

    /// Message received on subscription.
    /// Temporary struct of fields the subscriber may store if they want
    struct Message {
      const Bytes &from;
      const TopicId &topic;
      const Bytes &data;
    };

    /// Validator of messages arriving from the wire
    using Validator = std::function<bool(const Bytes &from, const Bytes &data)>;

    /// Sets message validator for topic
    virtual void setValidator(const TopicId &topic, Validator validator) = 0;

    /// Creates unique message ID out of message fields
    using MessageIdFn = std::function<Bytes(
        const Bytes &from, const Bytes &seq, const Bytes &data,
        const TopicId &topic)>;

    /// Sets message ID funtion that differs from default (from+sec_no)
    virtual void setMessageIdFn(MessageIdFn fn) = 0;

    /// Empty message means EOS (end of subscription data stream)
    using SubscriptionData = boost::optional<const Message &>;
    using SubscriptionCallback = std::function<void(SubscriptionData)>;

    /// Subscribes to topics
    virtual Subscription subscribe(TopicSet topics,
                                   SubscriptionCallback callback) = 0;

    /// Publishes to topics. Returns false if validation fails or not started
    virtual bool publish(TopicId topic, Bytes data) = 0;

    /// Peers that currently have a live gossip stream (silkworm addition:
    /// lets the embedder protect gossip-active peers when pruning excess
    /// raw libp2p connections)
    virtual std::vector<peer::PeerId> getConnectedPeers() const = 0;

    /// Peers currently grafted into at least one topic mesh (silkworm
    /// addition: these are the peers that actually deliver messages and must
    /// survive connection pruning)
    virtual std::vector<peer::PeerId> getMeshPeers() const = 0;
  };

  // Creates Gossip object
  std::shared_ptr<Gossip> create(
      std::shared_ptr<basic::Scheduler> scheduler,
      std::shared_ptr<Host> host,
      std::shared_ptr<peer::IdentityManager> idmgr,
      std::shared_ptr<crypto::CryptoProvider> crypto_provider,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller,
      Config config = Config{});

}  // namespace libp2p::protocol::gossip
