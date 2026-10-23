/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <deque>
#include <random>
#include <unordered_map>

#include <libp2p/log/sublogger.hpp>

#include "peer_set.hpp"
#include "score/peer_score2.hpp"

namespace libp2p::protocol::gossip {

  class Connectivity;

  /// Silent members of a mesh, see TopicSubscriptions::takeSilentMeshMembers
  struct MeshSilence {
    size_t silent = 0;
    /// silent ones that announced messages with IHAVEs meanwhile
    size_t announcing = 0;
    /// silent ones that sent us nothing at all meanwhile
    size_t mute = 0;
    /// members we grafted, members that grafted us
    size_t by_us = 0;
    size_t by_them = 0;
    /// the silent ones by what they sent, transport, direction and backlog
    RouterCounters::SilentMembers members;
  };

  /// Per-topic subscriptions
  class TopicSubscriptions {
   public:
    /// Ctor. Dependencies are passed by ref because this object is a part of
    /// RemoteSubscriptions and lives only within its scope
    TopicSubscriptions(TopicId topic,
                       const Config &config,
                       Connectivity &connectivity,
                       basic::Scheduler &scheduler,
                       std::shared_ptr<score::PeerScore> peer_score,
                       RouterCounters &counters,
                       log::SubLogger &log);

    /// Returns true if no peers subscribed and not self-subscribed and
    /// no fanout period at the moment (empty item may be erased)
    bool empty() const;

    /// Forwards message to mesh members and announce to other subscribers
    void onNewMessage(const boost::optional<PeerContextPtr> &from,
                      const TopicMessage::Ptr &msg,
                      const MessageId &msg_id,
                      Time now);

    /// Periodic job needed to update meshes and shift "I have" caches
    void onHeartbeat(Time now);

    /// Local host subscribes or unsubscribes, this affects mesh
    void onSelfSubscribed(bool self_subscribed);

    /// Remote peer subscribes to topic
    void onPeerSubscribed(const PeerContextPtr &p);

    /// Remote peer unsubscribes from topic
    void onPeerUnsubscribed(const PeerContextPtr &p);

    /// Remote peer includes this host into its mesh
    void onGraft(const PeerContextPtr &p);

    /// Remote peer kicks this host out of its mesh
    void onPrune(const PeerContextPtr &p, Time dont_bother_until);

    /// Application-driven mesh curation: graft a connected, topic-subscribed
    /// peer unless it is under PRUNE backoff or already in the mesh.
    /// Returns true if a GRAFT was sent.
    bool tryGraft(const PeerContextPtr &p);

    /// Application-driven mesh curation: prune a current mesh member
    /// (sends PRUNE with backoff). Returns true if pruned.
    bool tryPrune(const PeerContextPtr &p);

    /// Authoritative mesh membership (mesh_peers_) for this topic.
    std::vector<peer::PeerId> meshMemberIds() const;

    /// Mesh members at the previous call and now that delivered no envelope on
    /// execution_payload, no block elsewhere, first nor duplicate, in between
    /// (silkworm #149)
    MeshSilence takeSilentMeshMembers();

   private:
    /// Config::mesh_repair, once every kRepairTicks heartbeats
    void repairMesh();

    /// Puts \p p in backoff until \p until, or later if it already is
    void setBackoff(const PeerContextPtr &p, Time until);

    /// \p p is in the silence backoff of a repair eviction, which the refills
    /// skip; counts the skip
    bool skipSilenced(const PeerContextPtr &p);

    /// Adds a peer to mesh
    void addToMesh(const PeerContextPtr &p);

    /// Removes a peer from mesh
    void removeFromMesh(const PeerContextPtr &p);

    const TopicId topic_;
    const Config &config_;
    Connectivity &connectivity_;
    std::shared_ptr<score::PeerScore> peer_score_;
    basic::Scheduler &scheduler_;
    RouterCounters &counters_;

    /// What the mesh members had sent us at the last takeSilentMeshMembers
    struct SilentCheck {
      uint64_t delivered = 0;
      uint64_t ihaves = 0;
      uint64_t messages = 0;
      uint64_t rpcs = 0;
      uint64_t idontwants = 0;
    };
    std::unordered_map<peer::PeerId, SilentCheck> silent_check_;

    /// repairMesh: heartbeats, passes, each member's deliveries
    /// when a pass first saw it in the mesh, and each peer's first deliveries
    /// at the last pass
    struct RepairMember {
      uint64_t since_pass = 0;
      uint64_t delivered = 0;
    };
    /// Mesh members we grafted, the others grafted us
    std::unordered_map<peer::PeerId, bool> joined_by_us_;
    /// End of the backoff each peer's last PRUNE announced (silkworm #149)
    std::unordered_map<peer::PeerId, Time> remote_backoff_until_;
    uint64_t repair_ticks_ = 0;
    uint64_t repair_pass_ = 0;
    std::unordered_map<peer::PeerId, RepairMember> repair_members_;
    std::unordered_map<peer::PeerId, uint64_t> repair_firsts_;
    /// The members repairMesh evicted for silence: the end of the backoff in
    /// which the refills skip them, and how many times they were evicted
    struct SilenceBackoff {
      Time until{};
      uint64_t evictions = 0;
    };
    std::unordered_map<peer::PeerId, SilenceBackoff> silence_backoff_;

    /// This host subscribed to this topic or not, this affects mesh behavior
    bool self_subscribed_;

    /// Fanout period allows for publishing from this host without subscribing
    Time fanout_period_ends_;

    /// Peers subscribed to this topic, but not mesh members
    PeerSet subscribed_peers_;

    /// Mesh members to whom messages are forwarded in push manner
    PeerSet mesh_peers_;

    /// "I have" notifications for new subscribers aka seen messages cache
    std::deque<std::pair<Time, MessageId>> seen_cache_;

    /// Prune backoff times per peer
    std::unordered_map<PeerContextPtr, Time> dont_bother_until_;

    /// LH-faithful maintenance state (see lhMeshEnabled in the .cpp)
    uint64_t lh_heartbeat_ticks_ = 0;
    uint64_t lh_prunes_rx_ = 0;
    std::unordered_map<std::string, uint64_t> lh_mesh_since_tick_;
    uint64_t lh_forwards_ = 0;
    uint64_t lh_fwd_tel_ticks_ = 0;
    std::minstd_rand lh_rng_{0x51172};

    /// Random selection of the mesh members to graft and prune
    std::minstd_rand rng_{std::random_device{}()};

    /// Heartbeat counter for the periodic latency-aware mesh swap
    uint64_t heartbeat_count_ = 0;

    log::SubLogger &log_;
  };

}  // namespace libp2p::protocol::gossip
