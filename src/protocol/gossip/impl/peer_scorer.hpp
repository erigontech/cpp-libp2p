/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <libp2p/protocol/gossip/gossip.hpp>

#include "common.hpp"
#include "peer_context.hpp"

namespace libp2p::protocol::gossip {

  /// Gossipsub v1.1 peer-scoring engine.
  ///
  /// Subset implementation matching what go-libp2p uses for eth2 mesh stability:
  ///   P1  TimeInMesh                (per topic, positive)
  ///   P4  InvalidMessageDeliveries  (per topic, strong negative)
  ///   P7  BehaviourPenalty          (global, negative)
  ///
  /// Scores are cached on PeerContext::cached_score; the scorer recomputes
  /// them periodically (every PeerScoreParams::decay_interval) by calling
  /// tick() once per heartbeat in GossipCore. Lookups during mesh selection
  /// use the cache and run in O(1).
  class PeerScorer {
   public:
    PeerScorer(const PeerScoreParams &params,
               const PeerScoreThresholds &thresholds);

    /// Apply decay to all per-peer counters and recompute cached_score.
    /// Iterates the given peer collection.
    template <typename PeerRange>
    void tick(Time now, const PeerRange &peers) {
      if (now - last_tick_ < params_.decay_interval) {
        return;
      }
      last_tick_ = now;
      for (auto &p : peers) {
        decayCounters(*p);
        p->cached_score = computeScore(*p, now);
      }
    }

    /// Compute the score for a single peer at the given `now`. Does NOT
    /// apply decay (so it can be called from a const path).
    double computeScore(const PeerContext &peer, Time now) const;

    bool isGraylisted(const PeerContext &peer) const;
    bool isBelowPublishThreshold(const PeerContext &peer) const;
    bool isBelowGossipThreshold(const PeerContext &peer) const;

    /// Apply P4 (invalid message) penalty for a peer/topic.
    static void recordInvalidMessage(PeerContext &peer, const TopicId &topic);

    /// Apply P7 (behaviour) penalty.
    static void recordBehaviourPenalty(PeerContext &peer, double amount = 1.0);

    const PeerScoreParams &params() const { return params_; }
    const PeerScoreThresholds &thresholds() const { return thresholds_; }

   private:
    void decayCounters(PeerContext &peer);

    PeerScoreParams params_;
    PeerScoreThresholds thresholds_;
    Time last_tick_{0};
  };

}  // namespace libp2p::protocol::gossip
