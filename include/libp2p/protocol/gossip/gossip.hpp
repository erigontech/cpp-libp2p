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

  /// What the router learns about the connections to a peer when its gossip
  /// stream opens, and again when a connection to it opens and every
  /// kConnectionInfoSweepHeartbeats heartbeats
  struct PeerConnectionInfo {
    /// we dialed one of them
    bool outbound = false;
    /// their remote IP addresses, for the IP colocation score (P6)
    std::vector<std::string> ips;
  };

  /// Gossip pub-sub protocol config
  struct Config {
    /// Network density factors for gossip meshes: below D_min the heartbeat
    /// grafts up to D, above D_max it prunes down to D, keeping the D_score
    /// best-scoring members
    size_t D_min = 5;
    size_t D = 6;
    size_t D_max = 10;
    size_t D_score = 4;
    /// Outbound quota: the heartbeat keeps at least D_out mesh members whose
    /// connection we dialed (gossipsub v1.1), so that peers dialing us cannot
    /// take the whole mesh. Below D_min and at most D/2; 0 disables it
    size_t D_out = 2;

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

    /// Messages held at most while asynchronous validators decide on them:
    /// past that, a message for an asynchronous validator is dropped
    /// (ValidationResult::kDrop)
    size_t max_pending_validations = 4096;

    /// Heartbeat interval
    std::chrono::milliseconds heartbeat_interval_msec{1000};

    /// Ban interval between dial attempts to peer
    std::chrono::milliseconds ban_interval_msec{std::chrono::minutes(1)};

    /// Max number of dial attempts before peer is forgotten
    unsigned max_dial_attempts = 3;

    /// Consulted before every gossip dial: false skips the dial, which counts
    /// as a failed attempt (the peer is retried after ban_interval_msec and
    /// forgotten after max_dial_attempts). Lets the application keep the
    /// peers it banned (e.g. after a Goodbye) from being redialed. Empty: any
    /// peer may be dialed
    std::function<bool(const peer::PeerId &)> dial_filter;

    /// Answers what the router learns about the connections to a peer when
    /// its gossip stream opens. Empty: taken from the host's connection
    /// manager
    std::function<PeerConnectionInfo(const peer::PeerId &)> connection_info;

    /// Remote IPs exempt from the IP colocation score (P6): a devnet or a
    /// private cluster running many nodes behind one address (silkworm #84)
    std::vector<std::string> ip_colocation_whitelist;

    /// Expiration of gossip peers' addresses in address repository
    std::chrono::milliseconds address_expiration_msec{std::chrono::hours(1)};

    /// Max RPC message size
    size_t max_message_size = 1 << 24;

    /// Protocol version
    std::string protocol_version = "/meshsub/1.0.0";

    /// Sign published messages
    bool sign_messages = false;

  };

  using TopicId = std::string;
  using TopicList = std::vector<TopicId>;
  using TopicSet = std::set<TopicId>;

  /// What the router decided about meshes and peer exchange, since the
  /// counters were last taken
  struct RouterCounters {
    /// mesh members pruned by the heartbeat for a negative score
    uint64_t negative_score_prunes = 0;
    /// GRAFTs refused inside a backoff, and from a peer with a negative score
    uint64_t graft_refusals_in_backoff = 0;
    uint64_t graft_refusals_negative_score = 0;
    /// peers exchanged in a PRUNE not dialed, the pruning peer scoring below
    /// accept_px_threshold
    uint64_t px_dials_skipped = 0;
    /// peers we dialed from a PRUNE peer exchange, not counted as outbound
    /// (D_out): a peer exchange can be steered by an attacker
    uint64_t px_outbound_excluded = 0;
    /// changes of a connected peer's direction or IPs, learned after its
    /// gossip stream opened
    uint64_t conn_info_updates = 0;
    /// IPs of connected peers exempt from P6 by ip_colocation_whitelist
    uint64_t p6_whitelisted = 0;
  };

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
      /// base58 id of the peer whose copy was delivered first (empty for
      /// locally published messages). Under eth2 StrictNoSign 'from' is
      /// empty, so this is the only usable per-peer attribution.
      const std::string &delivered_by;
    };

    /// Validator of messages arriving from the wire
    using Validator = std::function<bool(const Bytes &from, const Bytes &data)>;

    /// Outcome of the validation of a message arriving from the wire, as in the
    /// gossipsub spec and rust-libp2p MessageAcceptance
    enum class ValidationResult {
      /// valid: deliver and forward
      kAccept,
      /// invalid: drop and penalize the sender (P4)
      kReject,
      /// drop without penalizing the sender: neither delivered, forwarded nor
      /// cached for IWANT, and later copies are dropped as duplicates (e.g. an
      /// equivocating block, or a message outside its propagation window)
      kIgnore,
      /// drop without penalizing the sender and without remembering the
      /// message: a later copy is validated (the validator could not take
      /// this one, e.g. its queue was full)
      kDrop,
    };

    /// Validator of messages arriving from the wire that can ignore messages
    using TriStateValidator =
        std::function<ValidationResult(const Bytes &from, const Bytes &data)>;

    /// Sets message validator for topic: true accepts, false rejects
    virtual void setValidator(const TopicId &topic, Validator validator) = 0;

    /// Sets message validator for topic
    virtual void setValidator(const TopicId &topic,
                              TriStateValidator validator) = 0;

    /// Reports the outcome of an asynchronous validation. It must be called
    /// once, on the thread the gossip runs on, and may be called before the
    /// validator returns
    using ValidationCallback = std::function<void(ValidationResult)>;

    /// Validator that decides later, e.g. on a worker thread (rust-libp2p
    /// validate_messages + report_message_validation_result): the message is
    /// held, neither delivered nor forwarded, until \p done reports the outcome
    using AsyncValidator = std::function<void(
        const Bytes &from, const Bytes &data, ValidationCallback done)>;

    /// Sets an asynchronous message validator for topic
    virtual void setAsyncValidator(const TopicId &topic,
                                   AsyncValidator validator) = 0;

    /// Removes the validator of topic, synchronous or asynchronous, with the
    /// subscription it holds (silkworm addition): unless another subscription
    /// holds the topic, the router leaves it and its mesh, and drops its
    /// messages, those waiting for an asynchronous verdict included
    virtual void removeValidator(const TopicId &topic) = 0;

    /// Whether the router is subscribed to topic, by a subscription or by a
    /// validator (silkworm addition)
    virtual bool isSubscribed(const TopicId &topic) const = 0;

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

    /// Gossip peers whose connection we dialed (the outbound quota's peers)
    virtual std::vector<peer::PeerId> getOutboundPeers() const = 0;

    /// Mesh members of one specific topic (application-driven mesh curation)
    virtual std::vector<peer::PeerId> getTopicMeshPeers(
        const TopicId &topic) const = 0;

    /// Application-driven mesh curation: graft a connected, topic-subscribed
    /// peer into the topic mesh (respects PRUNE backoff). True if grafted.
    virtual bool graftPeer(const TopicId &topic, const peer::PeerId &peer) = 0;

    /// Application-driven mesh curation: prune a mesh member (sends PRUNE
    /// with backoff). True if pruned.
    virtual bool prunePeer(const TopicId &topic, const peer::PeerId &peer) = 0;

    /// Returns the router counters and resets them (on the gossip thread)
    virtual RouterCounters takeCounters() = 0;

    /// Sizes the score parameters of the eth2 topics to the network, as
    /// Lighthouse does once per epoch: the attestation subnets expect message
    /// rates from \p active_validators (they are not scored until it is
    /// known), and penalties wait for \p current_slot to pass their
    /// activation. Re-installs the parameters of the topics already scored
    virtual void setNetworkSize(size_t active_validators,
                                uint64_t current_slot) = 0;
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
