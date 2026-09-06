/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

// Faithful C++20 port of rust-libp2p's gossipsub v1.1 peer scoring:
//   rust-libp2p protocols/gossipsub/src/peer_score.rs
//   rust-libp2p protocols/gossipsub/src/peer_score/params.rs
// as vendored in Lighthouse v8.2.2 (rev e423a66, gossipsub crate v0.50.0).
//
// The Lighthouse mainnet parameter factories at the bottom port:
//   lighthouse beacon_node/lighthouse_network/src/service/gossipsub_scoring_parameters.rs
// from the same Lighthouse revision.
//
// Deviations from the Rust original (intentional, see peer_score2.cpp):
//  - metrics and tracing removed;
//  - the message_delivery_time_callback and the "partial-messages" feature
//    are omitted;
//  - the internal Delay/decay timer is omitted: the caller drives
//    refresh_scores() every PeerScoreParams::decay_interval;
//  - every time-dependent entry point takes "now" explicitly
//    (std::chrono::steady_clock::time_point) so the class is testable;
//  - IP addresses are plain strings (C++ std has no IpAddr);
//  - PeerScoreParams additionally carries an optional app-specific score
//    hook (std::function). When unset, the per-peer value installed via
//    set_application_score() is used, exactly like Rust.

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <libp2p/peer/peer_id.hpp>

namespace libp2p::protocol::gossip::score {

  using PeerId = libp2p::peer::PeerId;
  using TopicId = std::string;
  using MessageId = std::string;
  /// Textual IP address ("1.2.3.4", "::1"); the std library has no IpAddr.
  using IpAddress = std::string;

  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Duration = Clock::duration;

  /// The number of seconds delivery messages are stored in the cache.
  inline constexpr Duration kTimeCacheDuration = std::chrono::seconds{120};

  /// The default number of seconds for a decay interval.
  inline constexpr Duration kDefaultDecayInterval = std::chrono::seconds{1};
  /// The default rate to decay to 0.
  inline constexpr double kDefaultDecayToZero = 0.1;

  /// Computes the decay factor for a parameter, assuming the decay_interval
  /// is 1s and that the value decays to zero if it drops below 0.01.
  double score_parameter_decay(Duration decay);

  /// Computes the decay factor for a parameter using base as the
  /// decay_interval.
  double score_parameter_decay_with_base(Duration decay,
                                         Duration base,
                                         double decay_to_zero);

  struct PeerScoreThresholds {
    /// The score threshold below which gossip propagation is suppressed;
    /// should be negative.
    double gossip_threshold = -10.0;

    /// The score threshold below which we shouldn't publish when using flood
    /// publishing (also applies to fanout peers); should be negative and
    /// <= gossip_threshold.
    double publish_threshold = -50.0;

    /// The score threshold below which message processing is suppressed
    /// altogether, implementing an effective graylist according to peer
    /// score; should be negative and <= publish_threshold.
    double graylist_threshold = -80.0;

    /// The score threshold below which px will be ignored; this should be
    /// positive and limited to scores attainable by bootstrappers and other
    /// trusted nodes.
    double accept_px_threshold = 10.0;

    /// The median mesh score threshold before triggering opportunistic
    /// grafting; this should have a small positive value.
    double opportunistic_graft_threshold = 20.0;

    /// Returns an error message on invalid thresholds, std::nullopt if valid.
    std::optional<std::string> validate() const;
  };

  struct TopicScoreParams {
    /// The weight of the topic.
    double topic_weight = 0.5;

    /// P1: time in the mesh
    /// This is the time the peer has been grafted in the mesh.
    /// The value of the parameter is the time/time_in_mesh_quantum, capped
    /// by time_in_mesh_cap. The weight of the parameter must be positive
    /// (or zero to disable).
    double time_in_mesh_weight = 1.0;
    Duration time_in_mesh_quantum = std::chrono::milliseconds{1};
    double time_in_mesh_cap = 3600.0;

    /// P2: first message deliveries
    /// This is the number of message deliveries in the topic.
    /// The value of the parameter is a counter, decaying with
    /// first_message_deliveries_decay, and capped by
    /// first_message_deliveries_cap.
    /// The weight of the parameter MUST be positive (or zero to disable).
    double first_message_deliveries_weight = 1.0;
    double first_message_deliveries_decay = 0.5;
    double first_message_deliveries_cap = 2000.0;

    /// P3: mesh message deliveries
    /// This is the number of message deliveries in the mesh, within the
    /// mesh_message_deliveries_window of message validation; deliveries
    /// during validation also count and are retroactively applied when
    /// validation succeeds.
    /// This window accounts for the minimum time before a hostile mesh peer
    /// trying to game the score could replay back a valid message we just
    /// sent them. It effectively tracks first and near-first deliveries, ie
    /// a message seen from a mesh peer before we have forwarded it to them.
    /// The parameter has an associated counter, decaying with
    /// mesh_message_deliveries_decay.
    /// If the counter exceeds the threshold, its value is 0.
    /// If the counter is below the mesh_message_deliveries_threshold, the
    /// value is the square of the deficit, ie
    /// (mesh_message_deliveries_threshold - counter)^2.
    /// The penalty is only activated after mesh_message_deliveries_activation
    /// time in the mesh. The weight of the parameter MUST be negative (or
    /// zero to disable).
    double mesh_message_deliveries_weight = -1.0;
    double mesh_message_deliveries_decay = 0.5;
    double mesh_message_deliveries_cap = 100.0;
    double mesh_message_deliveries_threshold = 20.0;
    Duration mesh_message_deliveries_window = std::chrono::milliseconds{10};
    Duration mesh_message_deliveries_activation = std::chrono::seconds{5};

    /// P3b: sticky mesh propagation failures
    /// This is a sticky penalty that applies when a peer gets pruned from the
    /// mesh with an active mesh message delivery penalty.
    /// The weight of the parameter MUST be negative (or zero to disable).
    double mesh_failure_penalty_weight = -1.0;
    double mesh_failure_penalty_decay = 0.5;

    /// P4: invalid messages
    /// This is the number of invalid messages in the topic.
    /// The value of the parameter is the square of the counter, decaying
    /// with invalid_message_deliveries_decay.
    /// The weight of the parameter MUST be negative (or zero to disable).
    double invalid_message_deliveries_weight = -1.0;
    double invalid_message_deliveries_decay = 0.3;

    /// Returns an error message on invalid params, std::nullopt if valid.
    std::optional<std::string> validate() const;
  };

  struct PeerScoreParams {
    /// Score parameters per topic.
    std::unordered_map<TopicId, TopicScoreParams> topics;

    /// Aggregate topic score cap; this limits the total contribution of
    /// topics towards a positive score. It must be positive (or 0 for no
    /// cap).
    double topic_score_cap = 3600.0;

    /// P5: Application-specific peer scoring.
    double app_specific_weight = 10.0;

    /// P5 hook: when set, the raw application-specific score of a peer is
    /// taken from this function; otherwise the per-peer value installed via
    /// PeerScore::set_application_score() is used (Rust behavior).
    std::function<double(const PeerId &)> app_specific_score_fn;

    /// P6: IP-colocation factor.
    /// The parameter has an associated counter which counts the number of
    /// peers with the same IP. If the number of peers in the same IP exceeds
    /// ip_colocation_factor_threshold, then the value is the square of the
    /// difference, ie (peers_in_same_ip - ip_colocation_threshold)^2. If the
    /// number of peers in the same IP is less than the threshold, then the
    /// value is 0. The weight of the parameter MUST be negative, unless you
    /// want to disable for testing.
    double ip_colocation_factor_weight = -5.0;
    double ip_colocation_factor_threshold = 10.0;
    std::unordered_set<IpAddress> ip_colocation_factor_whitelist;

    /// P7: behavioural pattern penalties.
    /// This parameter has an associated counter which tracks misbehaviour as
    /// detected by the router. The router currently applies penalties for
    /// the following behaviors:
    /// - attempting to re-graft before the prune backoff time has elapsed.
    /// - not following up in IWANT requests for messages advertised with
    ///   IHAVE.
    /// The value of the parameter is the square of the counter over the
    /// threshold, which decays with behaviour_penalty_decay.
    /// The weight of the parameter MUST be negative (or zero to disable).
    double behaviour_penalty_weight = -10.0;
    double behaviour_penalty_threshold = 0.0;
    double behaviour_penalty_decay = 0.2;

    /// The decay interval for parameter counters.
    Duration decay_interval = kDefaultDecayInterval;

    /// Counter value below which it is considered 0.
    double decay_to_zero = kDefaultDecayToZero;

    /// Time to remember counters for a disconnected peer.
    Duration retain_score = std::chrono::seconds{3600};

    /// Slow peer penalty conditions,
    /// by default slow_peer_weight is 50 times lower than
    /// behaviour_penalty_weight i.e. 50 slow peer penalties match 1
    /// behaviour penalty.
    double slow_peer_weight = -0.2;
    double slow_peer_threshold = 0.0;
    double slow_peer_decay = 0.2;

    /// Returns an error message on invalid params, std::nullopt if valid.
    std::optional<std::string> validate() const;
  };

  /// The reason a Gossipsub message has been rejected.
  /// (Rust carries the concrete ValidationError inside ValidationError(_);
  /// the payload only affects logging, so it is dropped here.)
  enum class RejectReason {
    /// The message failed the configured validation during decoding.
    kValidationError,
    /// The message source is us.
    kSelfOrigin,
    /// The peer that sent the message was blacklisted.
    kBlackListedPeer,
    /// The source (from field) of the message was blacklisted.
    kBlackListedSource,
    /// The validation was ignored.
    kValidationIgnored,
    /// The validation failed.
    kValidationFailed,
  };

  class PeerScore {
   public:
    explicit PeerScore(PeerScoreParams params,
                       PeerScoreThresholds thresholds = {});

    const PeerScoreParams &params() const {
      return params_;
    }
    const PeerScoreThresholds &thresholds() const {
      return thresholds_;
    }

    /// Returns the aggregate score for a peer (0 for unknown peers).
    double score(const PeerId &peer_id) const;

    /// P7 behavioural penalty: adds count to a peer's behaviour counter.
    void add_penalty(const PeerId &peer_id, size_t count);

    /// Applies decay to all counters, activates mesh message deliveries once
    /// a peer has been in the mesh long enough and expires retained scores
    /// of disconnected peers. Call once every params().decay_interval.
    void refresh_scores(TimePoint now);

    /// Adds a connected peer, initialising with empty ips (ips get added
    /// later through add_ip).
    void add_peer(const PeerId &peer_id);

    /// Adds a new ip to a peer, if the peer is not yet known creates a new
    /// peer_stats entry for it.
    void add_ip(const PeerId &peer_id, const IpAddress &ip);

    /// Removes an ip from a peer.
    void remove_ip(const PeerId &peer_id, const IpAddress &ip);

    /// Removes a peer from the score table. This retains peer statistics if
    /// their score is non-positive (sticky negative-score retention: the
    /// peer cannot reset a negative score by disconnecting and reconnecting
    /// until retain_score has elapsed).
    void remove_peer(const PeerId &peer_id, TimePoint now);

    /// Handles scoring functionality as a peer GRAFTs to a topic.
    void graft(const PeerId &peer_id, const TopicId &topic, TimePoint now);

    /// Handles scoring functionality as a peer PRUNEs from a topic (applies
    /// the sticky mesh delivery rate failure penalty if active).
    void prune(const PeerId &peer_id, const TopicId &topic);

    /// A message entered validation: creates an empty delivery record for it.
    void validate_message(const PeerId &from,
                          const MessageId &msg_id,
                          const TopicId &topic,
                          TimePoint now);

    /// A message was validated: rewards the first deliverer and, retro-
    /// actively, mesh peers that had already forwarded it to us.
    void deliver_message(const PeerId &from,
                         const MessageId &msg_id,
                         const TopicId &topic,
                         TimePoint now);

    /// Similar to reject_message except does not require the message id or
    /// reason for an invalid message.
    void reject_invalid_message(const PeerId &from, const TopicId &topic);

    /// A message failed validation (or was ignored): penalizes / clears
    /// according to reason and the delivery-status state machine.
    void reject_message(const PeerId &from,
                        const MessageId &msg_id,
                        const TopicId &topic,
                        RejectReason reason,
                        TimePoint now);

    /// A duplicate of a known message arrived from a peer.
    void duplicated_message(const PeerId &from,
                            const MessageId &msg_id,
                            const TopicId &topic,
                            TimePoint now);

    /// Indicate that a peer has been too slow to consume a message.
    void failed_message_slow_peer(const PeerId &peer_id);

    /// Sets the application specific score for a peer. Returns true if the
    /// peer is connected or if the score of the peer is not yet expired,
    /// and false otherwise.
    bool set_application_score(const PeerId &peer_id, double new_score);

    /// Sets scoring parameters for a topic (clamping existing counters to
    /// lowered caps, exactly like Rust).
    void set_topic_params(const TopicId &topic, TopicScoreParams params);

    /// Returns scoring parameters for a topic if existent.
    const TopicScoreParams *get_topic_params(const TopicId &topic) const;

    /// The current mesh message deliveries counter of a peer in a topic.
    std::optional<double> mesh_message_deliveries(const PeerId &peer_id,
                                                  const TopicId &topic) const;

   private:
    /// Status defining a peer's inclusion in the mesh and associated
    /// parameters (Rust MeshStatus).
    struct MeshStatus {
      bool active = false;
      /// The time the peer was last GRAFTed.
      TimePoint graft_time{};
      /// The time the peer has been in the mesh.
      Duration mesh_time{};

      static MeshStatus new_active(TimePoint now) {
        return MeshStatus{.active = true, .graft_time = now, .mesh_time{}};
      }
    };

    /// Stats assigned to peer for each topic.
    struct TopicStats {
      MeshStatus mesh_status{};
      /// Number of first message deliveries.
      double first_message_deliveries = 0.0;
      /// True if the peer has been in the mesh for enough time to activate
      /// mesh message deliveries.
      bool mesh_message_deliveries_active = false;
      /// Number of message deliveries from the mesh.
      double mesh_message_deliveries = 0.0;
      /// Mesh rate failure penalty.
      double mesh_failure_penalty = 0.0;
      /// Invalid message counter.
      double invalid_message_deliveries = 0.0;

      bool in_mesh() const {
        return mesh_status.active;
      }
    };

    /// General statistics for a given gossipsub peer.
    struct PeerStats {
      /// Connected while !disconnected; expire is only meaningful when
      /// disconnected (Rust ConnectionStatus).
      bool disconnected = false;
      /// Expiration time of the score state for disconnected peers.
      TimePoint expire{};
      /// Stats per topic.
      std::unordered_map<TopicId, TopicStats> topics;
      /// IP tracking for individual peers.
      std::unordered_set<IpAddress> known_ips;
      /// Behaviour penalty that is applied to the peer, assigned by the
      /// behaviour.
      double behaviour_penalty = 0.0;
      /// Application specific score. Can be manipulated by calling
      /// set_application_score.
      double application_score = 0.0;
      /// Scoring based on whether this peer consumes messages fast enough
      /// or not.
      double slow_peer_penalty = 0.0;
    };

    enum class DeliveryStatus {
      /// Don't know (yet) if the message is valid.
      kUnknown,
      /// The message is valid together with the validated time.
      kValid,
      /// The message is invalid.
      kInvalid,
      /// Instructed by the validator to ignore the message.
      kIgnored,
    };

    struct DeliveryRecord {
      DeliveryStatus status = DeliveryStatus::kUnknown;
      /// Validation time; meaningful only when status == kValid.
      TimePoint validated{};
      TimePoint first_seen{};
      std::unordered_set<PeerId> peers;
    };

    /// Port of Rust gossipsub's TimeCache<MessageId, DeliveryRecord>:
    /// entries expire ttl after first insertion (re-lookups do not extend
    /// the TTL); expired entries are purged lazily on each access.
    struct DeliveryRecords {
      struct Element {
        DeliveryRecord record;
        TimePoint expires;
      };

      /// Find-or-insert with default record; purges expired entries first.
      DeliveryRecord &entry(const MessageId &msg_id, TimePoint now);

      void remove_expired(TimePoint now);

      std::unordered_map<MessageId, Element> map;
      /// Keys ordered by expiry time (append-only ⇒ sorted).
      std::deque<std::pair<TimePoint, MessageId>> expirations;
      Duration ttl = kTimeCacheDuration;
    };

    /// Returns a pointer to topic stats if they exist, otherwise if the
    /// supplied parameters score the topic, inserts default stats and
    /// returns a pointer to those. If neither apply, returns nullptr.
    /// (Rust PeerStats::stats_or_default_mut.)
    TopicStats *stats_or_default(PeerStats &peer_stats, const TopicId &topic);

    static void remove_ips_for_peer(
        const PeerStats &peer_stats,
        std::unordered_map<IpAddress, std::unordered_set<PeerId>> &peer_ips,
        const PeerId &peer_id);

    /// Increments the "invalid message deliveries" counter for the topic.
    void mark_invalid_message_delivery(const PeerId &peer_id,
                                       const TopicId &topic);

    /// Increments the "first message deliveries" counter, as well as the
    /// "mesh message deliveries" counter if the peer is in the mesh for the
    /// topic.
    void mark_first_message_delivery(const PeerId &peer_id,
                                     const TopicId &topic);

    /// Increments the "mesh message deliveries" counter for messages we've
    /// seen before, as long as the message was received within the P3
    /// window.
    void mark_duplicate_message_delivery(
        const PeerId &peer_id,
        const TopicId &topic,
        std::optional<TimePoint> validated_time,
        TimePoint now);

    /// The score parameters.
    PeerScoreParams params_;
    /// The score thresholds.
    PeerScoreThresholds thresholds_;
    /// The stats per PeerId.
    std::unordered_map<PeerId, PeerStats> peer_stats_;
    /// Tracking peers per IP.
    std::unordered_map<IpAddress, std::unordered_set<PeerId>> peer_ips_;
    /// Message delivery tracking: a time-cache of DeliveryRecords.
    DeliveryRecords deliveries_;
  };

  // -- Lighthouse mainnet parameters ----------------------------------------
  //
  // Ported from lighthouse_network/src/service/gossipsub_scoring_parameters.rs
  // (Lighthouse v8.2.2), instantiated with the mainnet ChainSpec:
  //   seconds_per_slot = 12, slots_per_epoch = 32,
  //   attestation_subnet_count = 64, max_committees_per_slot = 64,
  //   target_committee_size = 128, target_aggregators_per_committee = 16.

  /// lighthouse_gossip_thresholds(): gossip -4000, publish -8000,
  /// graylist -16000, accept_px 100, opportunistic_graft 5.
  PeerScoreThresholds lighthouse_thresholds();

  /// Builds PeerScoreParams the way Lighthouse's PeerScoreSettings does for
  /// mainnet, with topic params for the beacon-block topic and the given
  /// attestation subnet topics (pass full topic strings as used on the
  /// wire).
  ///
  /// active_validators sizes the expected attestation rates (Lighthouse
  /// starts with slots_per_epoch = 32 and refreshes with the live count;
  /// the default here reflects a mature mainnet). mesh_n is the gossip mesh
  /// target degree (Lighthouse network_load 3 uses 5; cpp-libp2p sits
  /// between D_min 5 and D_max 10, hence default 8). current_slot gates the
  /// mesh-message-deliveries penalty on young chains exactly like
  /// Lighthouse; the default (a huge slot) enables it.
  PeerScoreParams lighthouse_mainnet_params(
      std::string beacon_block_topic,
      std::vector<std::string> attestation_subnet_topics,
      double slot_seconds = 12.0,
      size_t active_validators = 1'000'000,
      size_t mesh_n = 8,
      uint64_t current_slot = UINT64_MAX);

}  // namespace libp2p::protocol::gossip::score
