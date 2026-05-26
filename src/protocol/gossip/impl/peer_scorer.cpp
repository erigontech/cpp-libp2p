/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "peer_scorer.hpp"

#include <algorithm>
#include <cmath>

namespace libp2p::protocol::gossip {

  namespace {
    double clampZero(double x, double dead_zone) {
      return std::abs(x) < dead_zone ? 0.0 : x;
    }
  }  // namespace

  PeerScorer::PeerScorer(const PeerScoreParams &params,
                         const PeerScoreThresholds &thresholds)
      : params_{params}, thresholds_{thresholds} {}

  double PeerScorer::computeScore(const PeerContext &peer, Time now) const {
    double score = 0.0;

    for (const auto &[topic_id, topic_params] : params_.topics) {
      double topic_score = 0.0;

      if (topic_params.time_in_mesh_weight != 0.0) {
        auto it = peer.mesh_since.find(topic_id);
        if (it != peer.mesh_since.end() && it->second != Time::zero()) {
          auto in_mesh = now - it->second;
          double quanta = static_cast<double>(in_mesh.count())
              / static_cast<double>(
                  std::chrono::duration_cast<std::chrono::milliseconds>(
                      topic_params.time_in_mesh_quantum)
                      .count());
          double p1 = std::min(quanta, topic_params.time_in_mesh_cap);
          topic_score += p1 * topic_params.time_in_mesh_weight;
        }
      }

      if (topic_params.invalid_message_deliveries_weight != 0.0) {
        auto it = peer.invalid_msg_deliveries.find(topic_id);
        if (it != peer.invalid_msg_deliveries.end() && it->second > 0.0) {
          double p4 = it->second * it->second;
          topic_score += p4 * topic_params.invalid_message_deliveries_weight;
        }
      }

      topic_score = std::min(topic_score, params_.topic_score_cap);
      score += topic_score * topic_params.topic_weight;
    }

    if (params_.behaviour_penalty_weight != 0.0
        && peer.behaviour_penalty > params_.behaviour_penalty_threshold) {
      double excess =
          peer.behaviour_penalty - params_.behaviour_penalty_threshold;
      score += excess * excess * params_.behaviour_penalty_weight;
    }

    return score;
  }

  bool PeerScorer::isGraylisted(const PeerContext &peer) const {
    return peer.cached_score < thresholds_.graylist_threshold;
  }

  bool PeerScorer::isBelowPublishThreshold(const PeerContext &peer) const {
    return peer.cached_score < thresholds_.publish_threshold;
  }

  bool PeerScorer::isBelowGossipThreshold(const PeerContext &peer) const {
    return peer.cached_score < thresholds_.gossip_threshold;
  }

  void PeerScorer::recordInvalidMessage(PeerContext &peer,
                                        const TopicId &topic) {
    peer.invalid_msg_deliveries[topic] += 1.0;
  }

  void PeerScorer::recordBehaviourPenalty(PeerContext &peer, double amount) {
    peer.behaviour_penalty += amount;
  }

  void PeerScorer::decayCounters(PeerContext &peer) {
    for (auto &[topic_id, counter] : peer.invalid_msg_deliveries) {
      auto it = params_.topics.find(topic_id);
      double decay = (it != params_.topics.end())
          ? it->second.invalid_message_deliveries_decay
          : 0.5;
      counter *= decay;
      counter = clampZero(counter, params_.decay_to_zero);
    }
    peer.behaviour_penalty *= params_.behaviour_penalty_decay;
    peer.behaviour_penalty =
        clampZero(peer.behaviour_penalty, params_.decay_to_zero);
  }

}  // namespace libp2p::protocol::gossip
