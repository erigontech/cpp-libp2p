/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
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
    /// one of them is QUIC (silkworm #149)
    bool quic = false;
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

    /// gossipsub seen_ttl: a copy of a message seen in the last seen_ttl_msec
    /// is a duplicate, neither validated, delivered, forwarded nor announced,
    /// also once the message cache dropped the message. The IDs alone are
    /// kept, at most seen_ids_limit of them (the oldest dropped first)
    std::chrono::milliseconds seen_ttl_msec{message_cache_lifetime_msec};
    size_t seen_ids_limit = size_t{1} << 18;

    /// Messages held at most while asynchronous validators decide on them:
    /// past that, a message for an asynchronous validator is dropped
    /// (ValidationResult::kDrop)
    size_t max_pending_validations = 4096;

    /// Messages a validator held (ValidationResult::kHold), delivered but not
    /// forwarded yet: at most max_held_messages of them, each for held_msec
    /// at most, after which forwardHeld() no longer finds it
    size_t max_held_messages = 512;
    std::chrono::milliseconds held_msec{std::chrono::seconds(24)};

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

    /// Mesh repair of the beacon_block and execution_payload topics (silkworm
    /// #149): about once a minute, evict the members that delivered no message
    /// of the topic for 3 minutes and, while most first copies come from
    /// outside the mesh, graft the best non-mesh first deliverers. A mesh at
    /// D_lo is otherwise never refreshed
    bool mesh_repair = false;

    /// Expiration of gossip peers' addresses in address repository
    std::chrono::milliseconds address_expiration_msec{std::chrono::hours(1)};

    /// Max RPC message size
    size_t max_message_size = 1 << 24;

    /// Protocol version
    std::string protocol_version = "/meshsub/1.0.0";

    /// Sign published messages
    bool sign_messages = false;

    /// Publish messages without author fields: no from, seqno, signature nor
    /// key (the StrictNoSign signature policy, which eth2 requires). The
    /// StrictNoSign receivers reject a message carrying any of them, before
    /// they look whether they have it: go-libp2p-pubsub with
    /// RejectUnexpectedAuthInfo, rust-libp2p in its Anonymous mode. Overrides
    /// sign_messages. The message IDs must then come from the content
    /// (setMessageIdFn): the default ID, of from and seqno, would be the same
    /// for every message published
    bool strict_no_sign = false;

    /// Keep per-peer diagnostics (peerDiagnostics): counters of what we sent
    /// the peer and it sent us, from its first gossip stream until
    /// peer_diagnostics_keep_msec after its last. Off, nothing is counted
    bool peer_diagnostics = false;
    std::chrono::milliseconds peer_diagnostics_keep_msec{
        std::chrono::minutes(2)};

    /// gossipsub v1.3 partial messages extension (libp2p/specs
    /// pubsub/gossipsub/partial-messages.md; EIP-8136 for the eth2 data
    /// columns): advertised in the Extensions control message that opens the
    /// /meshsub/1.3.0 streams we write to, so protocol_version should be
    /// "/meshsub/1.3.0". Off, nothing is advertised and the partial messages
    /// and subscription options of the peers are ignored. On, a topic
    /// exchanges partial messages only once setPartialTopic enables it
    bool partial_messages = false;

    /// Partial message groups the peers may open on a topic (a group is
    /// opened by its first message when we did not publish in it), all peers
    /// together and each peer, as go-libp2p-pubsub: the messages of a group
    /// past either bound are dropped
    size_t partial_peer_groups_per_topic = 255;
    size_t partial_peer_groups_per_topic_per_peer = 8;

    /// Heartbeats a partial message group is kept after its last message,
    /// sent or received (go-libp2p-pubsub keeps a group 3 heartbeats after
    /// we publish in it)
    unsigned partial_group_ttl_heartbeats = 3;

    /// After we change the partial options of a topic, the time a peer may
    /// still send parts we no longer requested without a penalty (it may not
    /// have read our new subscription yet)
    std::chrono::milliseconds partial_options_grace_msec{
        std::chrono::seconds(10)};
  };

  using TopicId = std::string;
  using TopicList = std::vector<TopicId>;
  using TopicSet = std::set<TopicId>;

  /// Partial messages extension: the options we announce when subscribing to
  /// a topic (SubOpts requestsPartial, supportsSendingPartial)
  struct PartialTopicOptions {
    /// we prefer partial messages on the topic, which implies we support
    /// sending them
    bool requests_partial = false;
    /// we answer the partial message requests of the topic
    bool supports_sending_partial = false;
  };

  /// Partial messages extension: a partial messages RPC a peer sent us
  struct PartialMessage {
    peer::PeerId from;
    TopicId topic;
    Bytes group_id;
    /// Parts of the message of the group, encoded by the application. Only on
    /// a topic where we request partial messages
    std::optional<Bytes> partial_message;
    /// The parts the peer has and wants, encoded by the application: it
    /// replaces the previous one of the group
    std::optional<Bytes> parts_metadata;
  };

  /// Partial messages extension: what the router keeps of a peer in a group
  struct PartialPeerState {
    /// it requested partial messages on the topic: parts may be sent to it
    bool requests_partial = false;
    /// its last parts metadata in the group, which the application may update
    /// (e.g. with the parts it sent to it since)
    std::optional<Bytes> parts_metadata;
    /// the parts metadata we sent to it last in the group
    std::optional<Bytes> sent_parts_metadata;
  };
  using PartialPeerStates = std::unordered_map<peer::PeerId, PartialPeerState>;

  /// Partial messages extension: what to send to a peer in a group
  struct PartialPublishAction {
    peer::PeerId peer;
    /// parts to send, empty for none: not sent unless the peer requested
    /// partial messages on the topic
    Bytes partial_message;
    /// parts metadata to send, empty for none: not sent unless the peer
    /// supports sending partial messages on the topic
    Bytes parts_metadata;
  };

  /// Config::peer_diagnostics: what the router exchanged with a peer over its
  /// session, from its first gossip stream until a while after its last. A
  /// reconnection within Config::peer_diagnostics_keep_msec continues the
  /// session
  struct PeerDiagnostics {
    /// What we sent the peer on a topic, and the mesh changes it sent us
    struct Topic {
      /// Full messages (forwards, publishes, IWANT answers) and their bytes
      uint64_t messages = 0;
      uint64_t message_bytes = 0;
      /// Partial messages RPCs (the partial messages extension)
      uint64_t partial = 0;
      uint64_t idontwant = 0;
      /// Message IDs announced in IHAVEs, of those when it subscribed
      uint64_t ihave_ids = 0;
      uint64_t ihave_ids_on_subscribe = 0;
      uint64_t graft = 0;
      uint64_t prune = 0;
      uint64_t graft_rx = 0;
      uint64_t prune_rx = 0;
    };

    bool connected = false;
    /// Since the session began, and since the peer disconnected (zero while
    /// connected)
    std::chrono::milliseconds age{0};
    std::chrono::milliseconds since_disconnect{0};
    /// Gossip connections of the session (more than one: it reconnected)
    uint64_t sessions = 0;
    /// The score we give it now
    double score = 0;

    /// IHAVE message IDs we sent it, and IWANT message IDs it sent us: those
    /// we served, of them how many came more than 1 s and 3 s after our first
    /// IHAVE of the ID to it (and the latest, in ms), those we served without
    /// our IHAVE on record (unknown age), and those we no longer had (of them
    /// how many we had announced to it). Those ages are not how long the
    /// answers took: an IWANT promise runs from the IWANT (3 s in go and
    /// rust), and the answers queue at once behind the bytes still to be
    /// written to the peer, the most of which is iwant_backlog_max_bytes
    uint64_t ihave_ids_tx = 0;
    uint64_t iwant_ids_rx = 0;
    uint64_t iwant_served = 0;
    uint64_t iwant_served_bytes = 0;
    uint64_t iwant_after_1s = 0;
    uint64_t iwant_after_3s = 0;
    uint64_t iwant_max_ms = 0;
    uint64_t iwant_unannounced = 0;
    uint64_t iwant_missed = 0;
    uint64_t iwant_missed_announced = 0;
    uint64_t iwant_backlog_max_bytes = 0;

    /// How we sent it a full message: forwarded, published by us, or as the
    /// answer to its IWANT
    enum class PushKind : uint8_t { kForward, kPublish, kIWant };
    /// A full message we sent it, \p before its last PRUNE burst (or before
    /// the view was taken, in sent_recently). Its message ID, at most
    /// kPushIdBytes of it, and in sent_recently its data while we still
    /// cache the message (null after)
    static constexpr size_t kPushIdBytes = 20;
    struct Push {
      TopicId topic;
      PushKind kind = PushKind::kForward;
      std::chrono::milliseconds before{0};
      Bytes id;
      std::shared_ptr<const Bytes> data;
    };
    /// The full messages we sent it within kSentRecently before the view was
    /// taken, the latest first, at most 32: what a peer that says Goodbye for
    /// its score of us could have rejected (P4), whether or not it pruned us
    /// first (silkworm #167)
    static constexpr std::chrono::milliseconds kSentRecently{120'000};
    std::vector<Push> sent_recently;
    /// Its last PRUNE burst: the PRUNEs it sent us within a second of each
    /// other. A go or rust heartbeat prunes a peer whose score turned negative
    /// from all its meshes at once, which is how an invalid message (P4) we
    /// sent it shows (silkworm #167). The topics it pruned, how long ago the
    /// first PRUNE came (none yet: nullopt), and the messages we sent it within
    /// kPushesBeforePrune before that PRUNE, the latest first
    static constexpr std::chrono::milliseconds kPushesBeforePrune{10'000};
    uint64_t prune_burst_topics = 0;
    std::optional<std::chrono::milliseconds> prune_burst_age;
    std::vector<Push> pushes_before_prune;

    /// Control messages: IWANT IDs we sent, IHAVE IDs and IDONTWANTs it sent;
    /// GRAFT and PRUNE both ways; the Extensions control messages we sent and
    /// it sent (those not first on a stream, a P7 penalty, apart); the
    /// subscriptions we announced to it
    uint64_t iwant_ids_tx = 0;
    uint64_t ihave_ids_rx = 0;
    uint64_t idontwant_rx = 0;
    uint64_t idontwant_tx = 0;
    uint64_t graft_tx = 0;
    uint64_t prune_tx = 0;
    uint64_t graft_rx = 0;
    uint64_t prune_rx = 0;
    uint64_t extensions_tx = 0;
    uint64_t extensions_rx = 0;
    uint64_t extensions_repeated_rx = 0;
    uint64_t subscriptions_tx = 0;

    /// Streams: ours to it per protocol, its to us, those opened after the
    /// first of the session (reopens), the errors that closed them (the last
    /// one's text); the writes (batches of RPC frames) and bytes we sent it
    std::map<std::string, uint64_t> outbound_streams;
    uint64_t inbound_streams = 0;
    uint64_t outbound_reopens = 0;
    uint64_t inbound_reopens = 0;
    uint64_t stream_errors = 0;
    std::string last_stream_error;
    uint64_t writes_tx = 0;
    uint64_t bytes_tx = 0;
    /// Messages it sent us
    uint64_t messages_rx = 0;

    std::map<TopicId, Topic> topics;
  };

  /// Decides what to send in a group, from the peers' states, which it may
  /// update
  using PartialPublishFn =
      std::function<std::vector<PartialPublishAction>(PartialPeerStates &)>;

  /// Partial messages extension: the application's verdict on parts a peer
  /// sent, which the router cannot judge itself
  enum class PartialFeedback {
    /// novel and valid: a first message delivery (P2, and P3 in the mesh)
    kUseful,
    /// invalid: an invalid message delivery (P4)
    kInvalid,
  };

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
    /// beacon_block mesh maintenance (silkworm #149). First copies of blocks
    /// from a member of our mesh, and from any other peer: a pull answering
    /// our IWANT, or a peer that has us in its mesh but is not in ours
    uint64_t block_first_from_mesh = 0;
    uint64_t block_first_from_others = 0;
    /// IWANTs we sent for blocks
    uint64_t block_iwants_sent = 0;
    /// GRAFTs and PRUNEs we sent, and PRUNEs mesh members sent us
    uint64_t block_grafts_sent = 0;
    uint64_t block_prunes_sent = 0;
    uint64_t block_prunes_received = 0;
    /// Mesh members since the counters were last taken that delivered no
    /// block since, neither a first copy nor a duplicate
    uint64_t block_mesh_silent = 0;
    /// Of those, the ones that announced blocks with IHAVEs meanwhile, which
    /// do not count us in their mesh, and the ones that sent us nothing
    uint64_t block_mesh_silent_announcing = 0;
    uint64_t block_mesh_silent_mute = 0;
    /// Mesh members we grafted, and those that grafted us
    uint64_t block_mesh_by_us = 0;
    uint64_t block_mesh_by_them = 0;
    /// Config::mesh_repair: silent members evicted, first deliverers grafted
    uint64_t block_repair_evicted = 0;
    uint64_t block_repair_grafted = 0;
    /// The execution_payload topic (envelopes): first copies from mesh members
    /// and other peers, silent members (announcing, mute), and its repairs
    uint64_t envelope_first_from_mesh = 0;
    uint64_t envelope_first_from_others = 0;
    uint64_t envelope_mesh_silent = 0;
    uint64_t envelope_mesh_silent_announcing = 0;
    uint64_t envelope_mesh_silent_mute = 0;
    uint64_t envelope_repair_evicted = 0;
    uint64_t envelope_repair_grafted = 0;
    /// The silent members of each topic: those that sent no RPC at all and
    /// those that sent some, those that sent IDONTWANT for its messages (we
    /// are in their mesh), their transport and the direction of their
    /// connection, our bytes waiting on the stream to them and those without
    /// one, and the client families of the mute ones (silkworm #149)
    struct SilentMembers {
      uint64_t no_rpc = 0;
      uint64_t control_only = 0;
      uint64_t idontwant = 0;
      uint64_t quic = 0;
      uint64_t tcp = 0;
      uint64_t in = 0;
      uint64_t out = 0;
      uint64_t backlog_bytes = 0;
      uint64_t no_stream = 0;
      std::map<std::string, uint64_t> mute_agents;
    };
    SilentMembers block_silent;
    SilentMembers envelope_silent;
    /// GRAFTs we sent inside the backoff the peer's PRUNE announced, each a
    /// behaviour penalty (P7) there (silkworm #149)
    uint64_t graft_backoff_violations = 0;
    /// Blocks and envelopes forwarded: how many, the sum and the maximum of
    /// the delay from their first copy to the forward (the validation), and
    /// the copies sent to mesh members
    uint64_t block_forward_count = 0;
    uint64_t block_forward_ms_sum = 0;
    uint64_t block_forward_ms_max = 0;
    uint64_t block_forwarded_to = 0;
    uint64_t envelope_forward_count = 0;
    uint64_t envelope_forward_ms_sum = 0;
    uint64_t envelope_forward_ms_max = 0;
    uint64_t envelope_forwarded_to = 0;
    /// Subscribers the refills of beacon_block and execution_payload (D_lo,
    /// outbound quota, on subscription) passed over because the mesh repair
    /// evicted them for silence lately, one per peer and refill: the refill
    /// below D_lo runs at each heartbeat while the mesh is below (silkworm #162)
    uint64_t refill_skipped_silent = 0;
    /// Partial messages extension (silkworm #174). Streams that opened with
    /// a peer's Extensions control message advertising it (counted with the
    /// extension off too), and the Extensions control messages that came
    /// later on a stream (a P7 penalty)
    uint64_t partial_streams_advertised = 0;
    uint64_t extensions_repeated = 0;
    /// Partial messages RPCs received and handed to the application, with
    /// their parts and metadata bytes, and those dropped: the extension not
    /// advertised by both sides, a topic we did not enable, a group past the
    /// peer limits, or empty
    uint64_t partial_rpcs_rx = 0;
    uint64_t partial_bytes_rx = 0;
    uint64_t partial_rpcs_dropped = 0;
    /// Parts received on a topic where we did not request them (dropped, a
    /// P7 penalty past Config::partial_options_grace_msec)
    uint64_t partial_unrequested = 0;
    /// Partial messages RPCs sent, with their bytes, and the actions of the
    /// application not sent to a peer that did not ask for them
    uint64_t partial_rpcs_tx = 0;
    uint64_t partial_bytes_tx = 0;
    uint64_t partial_actions_dropped = 0;
    /// Full messages not forwarded, with their bytes, and IHAVEs not sent, to
    /// peers that requested partial messages on a topic where we send them
    uint64_t partial_full_forwards_skipped = 0;
    uint64_t partial_full_forward_bytes_skipped = 0;
    uint64_t partial_ihaves_skipped = 0;
    /// Messages not published as they were known already (Gossip::publish)
    uint64_t publish_known = 0;
    /// Messages a validator held (ValidationResult::kHold): delivered, then
    /// forwarded by forwardHeld(), or dropped unforwarded when they expired
    uint64_t held = 0;
    uint64_t held_forwarded = 0;
    uint64_t held_expired = 0;
    /// Copies of a message seen within seen_ttl dropped as duplicates once
    /// the message cache and the lists of ignored and rejected IDs had
    /// dropped it (without the seen IDs: validated, forwarded and announced)
    uint64_t seen_duplicates = 0;
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
      /// Held by its validator (ValidationResult::kHold): delivered, but not
      /// forwarded until the application calls forwardHeld() for it
      bool held = false;
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
      /// not valid yet, not invalid (e.g. an eth2 message ahead of the block
      /// it refers to, which the spec IGNOREs and the application queues):
      /// delivered to the subscribers with Message::held, but neither
      /// forwarded, cached for IWANT nor scored, as kIgnore, and later copies
      /// are dropped as duplicates. forwardHeld() forwards it once the
      /// application validated it (silkworm addition)
      kHold,
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

    /// Publishes to topics. Returns false if validation fails, not started,
    /// or the message is known already (received, being validated, refused
    /// or published)
    virtual bool publish(TopicId topic, Bytes data) = 0;

    /// Forwards a message its validator held (ValidationResult::kHold), which
    /// the application validated since: to the topic's mesh as a valid
    /// message received then, the peer that delivered it excepted, and cached
    /// for IWANT (silkworm addition). \p data is the message's data as
    /// delivered. False if no such message is held (never held, forwarded
    /// already, or expired after Config::held_msec)
    virtual bool forwardHeld(const TopicId &topic, const Bytes &data) = 0;

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

    /// Config::peer_diagnostics: the session of \p peer so far, none if it
    /// has none (never connected, or disconnected longer than
    /// peer_diagnostics_keep_msec ago). On the gossip thread
    virtual std::optional<PeerDiagnostics> peerDiagnostics(
        const peer::PeerId &peer) const = 0;

    /// Sizes the score parameters of the eth2 topics to the network, as
    /// Lighthouse does once per epoch: the attestation subnets expect message
    /// rates from \p active_validators (they are not scored until it is
    /// known), and penalties wait for \p current_slot to pass their
    /// activation. Re-installs the parameters of the topics already scored
    virtual void setNetworkSize(size_t active_validators,
                                uint64_t current_slot) = 0;

    /// Partial messages extension (Config::partial_messages): the options we
    /// announce for \p topic in our subscriptions. A topic is enabled while
    /// either option is set; the peers learn the change at the next
    /// heartbeat. False if the extension is off
    virtual bool setPartialTopic(const TopicId &topic,
                                 PartialTopicOptions options) = 0;

    /// Receives the partial messages RPCs of the enabled topics, from the
    /// peers that advertised the extension to us and we to them, on the
    /// gossip thread: it must not block, and the parts are not validated
    using PartialMessageHandler = std::function<void(const PartialMessage &)>;
    virtual void setPartialMessageHandler(PartialMessageHandler handler) = 0;

    /// At a heartbeat, the peers of \p topic the router gossips to, instead
    /// of IHAVEs, for each group we published in that they are not in yet:
    /// the application should publishPartial to them (partial message
    /// gossip)
    using PartialGossipHandler =
        std::function<void(const TopicId &topic,
                           const Bytes &group_id,
                           const std::vector<peer::PeerId> &peers)>;
    virtual void setPartialGossipHandler(PartialGossipHandler handler) = 0;

    /// Sends in the group \p group_id of \p topic what \p fn decides from
    /// the peers' states: the mesh members we exchange partial messages with
    /// on the topic, and the peers already in the group. An action may also
    /// name another connected peer. Full messages are not forwarded to the
    /// peers that requested partial messages on a topic where we support
    /// sending them: the application must send them the parts. False if not
    /// started, the extension is off or the topic is not enabled
    virtual bool publishPartial(const TopicId &topic,
                                const Bytes &group_id,
                                const PartialPublishFn &fn) = 0;

    /// Scores what \p peer sent in partial messages on \p topic. The
    /// application should cap the useful parts a peer is credited for per
    /// message, so that sending one part at a time scores no better than
    /// sending them together (EIP-8136)
    virtual void reportPartialMessage(const TopicId &topic,
                                      const peer::PeerId &peer,
                                      PartialFeedback feedback) = 0;
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
