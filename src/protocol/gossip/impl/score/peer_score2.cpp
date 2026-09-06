/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

// Port of rust-libp2p gossipsub peer scoring; see peer_score2.hpp for
// provenance and the list of intentional deviations.

#include "peer_score2.hpp"

#include <algorithm>
#include <cmath>

namespace libp2p::protocol::gossip::score {

  double score_parameter_decay(Duration decay) {
    return score_parameter_decay_with_base(
        decay, kDefaultDecayInterval, kDefaultDecayToZero);
  }

  double score_parameter_decay_with_base(Duration decay,
                                         Duration base,
                                         double decay_to_zero) {
    // the decay is linear, so after n ticks the value is factor^n
    // so factor^n = decay_to_zero => factor = decay_to_zero^(1/n)
    auto ticks = std::chrono::duration<double>(decay).count()
               / std::chrono::duration<double>(base).count();
    return std::pow(decay_to_zero, 1.0 / ticks);
  }

  // -- validation -----------------------------------------------------------

  std::optional<std::string> PeerScoreThresholds::validate() const {
    if (gossip_threshold > 0.0) {
      return "invalid gossip threshold; it must be <= 0";
    }
    if (publish_threshold > 0.0 || publish_threshold > gossip_threshold) {
      return "Invalid publish threshold; it must be <= 0 and <= gossip "
             "threshold";
    }
    if (graylist_threshold > 0.0 || graylist_threshold > publish_threshold) {
      return "Invalid graylist threshold; it must be <= 0 and <= publish "
             "threshold";
    }
    if (accept_px_threshold < 0.0) {
      return "Invalid accept px threshold; it must be >= 0";
    }
    if (opportunistic_graft_threshold < 0.0) {
      return "Invalid opportunistic grafting threshold; it must be >= 0";
    }
    return std::nullopt;
  }

  std::optional<std::string> TopicScoreParams::validate() const {
    // make sure we have a sane topic weight
    if (topic_weight < 0.0) {
      return "invalid topic weight; must be >= 0";
    }

    if (time_in_mesh_quantum == Duration::zero()) {
      return "Invalid time_in_mesh_quantum; must be non zero";
    }
    if (time_in_mesh_weight < 0.0) {
      return "Invalid time_in_mesh_weight; must be positive (or 0 to "
             "disable)";
    }
    if (time_in_mesh_weight != 0.0 && time_in_mesh_cap <= 0.0) {
      return "Invalid time_in_mesh_cap must be positive";
    }

    if (first_message_deliveries_weight < 0.0) {
      return "Invalid first_message_deliveries_weight; must be positive (or "
             "0 to disable)";
    }
    if (first_message_deliveries_weight != 0.0
        && (first_message_deliveries_decay <= 0.0
            || first_message_deliveries_decay >= 1.0)) {
      return "Invalid first_message_deliveries_decay; must be between 0 and "
             "1";
    }
    if (first_message_deliveries_weight != 0.0
        && first_message_deliveries_cap <= 0.0) {
      return "Invalid first_message_deliveries_cap must be positive";
    }

    if (mesh_message_deliveries_weight > 0.0) {
      return "Invalid mesh_message_deliveries_weight; must be negative (or "
             "0 to disable)";
    }
    if (mesh_message_deliveries_weight != 0.0
        && (mesh_message_deliveries_decay <= 0.0
            || mesh_message_deliveries_decay >= 1.0)) {
      return "Invalid mesh_message_deliveries_decay; must be between 0 and 1";
    }
    if (mesh_message_deliveries_weight != 0.0
        && mesh_message_deliveries_cap <= 0.0) {
      return "Invalid mesh_message_deliveries_cap must be positive";
    }
    if (mesh_message_deliveries_weight != 0.0
        && mesh_message_deliveries_threshold <= 0.0) {
      return "Invalid mesh_message_deliveries_threshold; must be positive";
    }
    if (mesh_message_deliveries_weight != 0.0
        && mesh_message_deliveries_activation < std::chrono::seconds{1}) {
      return "Invalid mesh_message_deliveries_activation; must be at least "
             "1s";
    }

    // check P3b
    if (mesh_failure_penalty_weight > 0.0) {
      return "Invalid mesh_failure_penalty_weight; must be negative (or 0 "
             "to disable)";
    }
    if (mesh_failure_penalty_weight != 0.0
        && (mesh_failure_penalty_decay <= 0.0
            || mesh_failure_penalty_decay >= 1.0)) {
      return "Invalid mesh_failure_penalty_decay; must be between 0 and 1";
    }

    // check P4
    if (invalid_message_deliveries_weight > 0.0) {
      return "Invalid invalid_message_deliveries_weight; must be negative "
             "(or 0 to disable)";
    }
    if (invalid_message_deliveries_decay <= 0.0
        || invalid_message_deliveries_decay >= 1.0) {
      return "Invalid invalid_message_deliveries_decay; must be between 0 "
             "and 1";
    }
    return std::nullopt;
  }

  std::optional<std::string> PeerScoreParams::validate() const {
    for (auto &[topic, topic_params] : topics) {
      if (auto err = topic_params.validate()) {
        return "Invalid score parameters for topic " + topic + ": " + *err;
      }
    }

    // check that the topic score is 0 or something positive
    if (topic_score_cap < 0.0) {
      return "Invalid topic score cap; must be positive (or 0 for no cap)";
    }

    // check the IP colocation factor
    if (ip_colocation_factor_weight > 0.0) {
      return "Invalid ip_colocation_factor_weight; must be negative (or 0 "
             "to disable)";
    }
    if (ip_colocation_factor_weight != 0.0
        && ip_colocation_factor_threshold < 1.0) {
      return "Invalid ip_colocation_factor_threshold; must be at least 1";
    }

    // check the behaviour penalty
    if (behaviour_penalty_weight > 0.0) {
      return "Invalid behaviour_penalty_weight; must be negative (or 0 to "
             "disable)";
    }
    if (behaviour_penalty_weight != 0.0
        && (behaviour_penalty_decay <= 0.0 || behaviour_penalty_decay >= 1.0)) {
      return "invalid behaviour_penalty_decay; must be between 0 and 1";
    }

    if (behaviour_penalty_threshold < 0.0) {
      return "invalid behaviour_penalty_threshold; must be >= 0";
    }

    // check the decay parameters
    if (decay_interval < std::chrono::seconds{1}) {
      return "Invalid decay_interval; must be at least 1s";
    }
    if (decay_to_zero <= 0.0 || decay_to_zero >= 1.0) {
      return "Invalid decay_to_zero; must be between 0 and 1";
    }

    // no need to check the score retention; a value of 0 means that we don't
    // retain scores
    return std::nullopt;
  }

  // -- DeliveryRecords (TimeCache) ------------------------------------------

  void PeerScore::DeliveryRecords::remove_expired(TimePoint now) {
    while (!expirations.empty()) {
      auto &[expires, msg_id] = expirations.front();
      if (expires > now) {
        break;
      }
      if (auto it = map.find(msg_id);
          it != map.end() && it->second.expires <= now) {
        map.erase(it);
      }
      expirations.pop_front();
    }
  }

  PeerScore::DeliveryRecord &PeerScore::DeliveryRecords::entry(
      const MessageId &msg_id, TimePoint now) {
    remove_expired(now);
    auto [it, inserted] = map.try_emplace(msg_id);
    if (inserted) {
      it->second.expires = now + ttl;
      it->second.record.first_seen = now;
      expirations.emplace_back(it->second.expires, msg_id);
    }
    return it->second.record;
  }

  // -- PeerScore ------------------------------------------------------------

  PeerScore::PeerScore(PeerScoreParams params, PeerScoreThresholds thresholds)
      : params_{std::move(params)}, thresholds_{thresholds} {}

  double PeerScore::score(const PeerId &peer_id) const {
    auto stats_it = peer_stats_.find(peer_id);
    if (stats_it == peer_stats_.end()) {
      return 0.0;
    }
    auto &peer_stats = stats_it->second;
    double score = 0.0;

    // topic scores
    for (auto &[topic, topic_stats] : peer_stats.topics) {
      // topic parameters
      auto params_it = params_.topics.find(topic);
      if (params_it == params_.topics.end()) {
        continue;
      }
      auto &topic_params = params_it->second;
      // we are tracking the topic

      // the topic score
      double topic_score = 0.0;

      // P1: time in mesh
      if (topic_stats.mesh_status.active) {
        double p1 = std::min(
            std::chrono::duration<double>(topic_stats.mesh_status.mesh_time)
                    .count()
                / std::chrono::duration<double>(
                      topic_params.time_in_mesh_quantum)
                      .count(),
            topic_params.time_in_mesh_cap);
        topic_score += p1 * topic_params.time_in_mesh_weight;
      }

      // P2: first message deliveries
      double p2 = std::min(topic_stats.first_message_deliveries,
                           topic_params.first_message_deliveries_cap);
      topic_score += p2 * topic_params.first_message_deliveries_weight;

      // P3: mesh message deliveries
      if (topic_stats.mesh_message_deliveries_active
          && topic_stats.mesh_message_deliveries
                 < topic_params.mesh_message_deliveries_threshold
          && topic_params.mesh_message_deliveries_weight != 0.0) {
        double deficit = topic_params.mesh_message_deliveries_threshold
                       - topic_stats.mesh_message_deliveries;
        double p3 = deficit * deficit;
        topic_score += p3 * topic_params.mesh_message_deliveries_weight;
      }

      // P3b:
      // NOTE: the weight of P3b is negative (validated in
      // TopicScoreParams::validate), so this detracts.
      double p3b = topic_stats.mesh_failure_penalty;
      topic_score += p3b * topic_params.mesh_failure_penalty_weight;

      // P4: invalid messages
      // NOTE: the weight of P4 is negative (validated in
      // TopicScoreParams::validate), so this detracts.
      double p4 = topic_stats.invalid_message_deliveries
                * topic_stats.invalid_message_deliveries;
      topic_score += p4 * topic_params.invalid_message_deliveries_weight;

      // update score, mixing with topic weight
      score += topic_score * topic_params.topic_weight;
    }

    // apply the topic score cap, if any
    if (params_.topic_score_cap > 0.0 && score > params_.topic_score_cap) {
      score = params_.topic_score_cap;
    }

    // P5: application-specific score
    double p5 = params_.app_specific_score_fn
                  ? params_.app_specific_score_fn(peer_id)
                  : peer_stats.application_score;
    score += p5 * params_.app_specific_weight;

    // P6: IP colocation factor
    for (auto &ip : peer_stats.known_ips) {
      if (params_.ip_colocation_factor_whitelist.contains(ip)) {
        continue;
      }

      // P6 has a cliff (ip_colocation_factor_threshold); it's only applied
      // if at least that many peers are connected to us from that source IP
      // addr. It is quadratic, and the weight is negative (validated by
      // PeerScoreParams::validate()).
      auto ip_it = peer_ips_.find(ip);
      if (ip_it == peer_ips_.end()) {
        continue;
      }
      auto peers_in_ip = static_cast<double>(ip_it->second.size());
      if (peers_in_ip > params_.ip_colocation_factor_threshold
          && params_.ip_colocation_factor_weight != 0.0) {
        double surplus = peers_in_ip - params_.ip_colocation_factor_threshold;
        double p6 = surplus * surplus;
        score += p6 * params_.ip_colocation_factor_weight;
      }
    }

    // P7: behavioural pattern penalty.
    if (peer_stats.behaviour_penalty > params_.behaviour_penalty_threshold) {
      double excess =
          peer_stats.behaviour_penalty - params_.behaviour_penalty_threshold;
      double p7 = excess * excess;
      score += p7 * params_.behaviour_penalty_weight;
    }

    // Slow peer weighting.
    if (peer_stats.slow_peer_penalty > params_.slow_peer_threshold) {
      double excess = peer_stats.slow_peer_penalty - params_.slow_peer_threshold;
      score += excess * params_.slow_peer_weight;
    }

    return score;
  }

  void PeerScore::add_penalty(const PeerId &peer_id, size_t count) {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      it->second.behaviour_penalty += static_cast<double>(count);
    }
  }

  void PeerScore::remove_ips_for_peer(
      const PeerStats &peer_stats,
      std::unordered_map<IpAddress, std::unordered_set<PeerId>> &peer_ips,
      const PeerId &peer_id) {
    for (auto &ip : peer_stats.known_ips) {
      if (auto it = peer_ips.find(ip); it != peer_ips.end()) {
        it->second.erase(peer_id);
      }
    }
  }

  void PeerScore::refresh_scores(TimePoint now) {
    for (auto it = peer_stats_.begin(); it != peer_stats_.end();) {
      auto &peer_stats = it->second;
      if (peer_stats.disconnected) {
        // has the retention period expired?
        if (now > peer_stats.expire) {
          // yes, throw it away (but clean up the IP tracking first)
          remove_ips_for_peer(peer_stats, peer_ips_, it->first);
          it = peer_stats_.erase(it);
          continue;
        }

        // we don't decay retained scores, as the peer is not active. this
        // way the peer cannot reset a negative score by simply disconnecting
        // and reconnecting, unless the retention period has elapsed.
        // similarly, a well behaved peer does not lose its score by getting
        // disconnected.
        ++it;
        continue;
      }

      for (auto &[topic, topic_stats] : peer_stats.topics) {
        // the topic parameters
        auto params_it = params_.topics.find(topic);
        if (params_it == params_.topics.end()) {
          continue;
        }
        auto &topic_params = params_it->second;

        // decay counters
        topic_stats.first_message_deliveries *=
            topic_params.first_message_deliveries_decay;
        if (topic_stats.first_message_deliveries < params_.decay_to_zero) {
          topic_stats.first_message_deliveries = 0.0;
        }
        topic_stats.mesh_message_deliveries *=
            topic_params.mesh_message_deliveries_decay;
        if (topic_stats.mesh_message_deliveries < params_.decay_to_zero) {
          topic_stats.mesh_message_deliveries = 0.0;
        }
        topic_stats.mesh_failure_penalty *=
            topic_params.mesh_failure_penalty_decay;
        if (topic_stats.mesh_failure_penalty < params_.decay_to_zero) {
          topic_stats.mesh_failure_penalty = 0.0;
        }
        topic_stats.invalid_message_deliveries *=
            topic_params.invalid_message_deliveries_decay;
        if (topic_stats.invalid_message_deliveries < params_.decay_to_zero) {
          topic_stats.invalid_message_deliveries = 0.0;
        }

        // update mesh time and activate mesh message delivery parameter if
        // need be
        if (topic_stats.mesh_status.active) {
          topic_stats.mesh_status.mesh_time =
              now - topic_stats.mesh_status.graft_time;
          if (topic_stats.mesh_status.mesh_time
              > topic_params.mesh_message_deliveries_activation) {
            topic_stats.mesh_message_deliveries_active = true;
          }
        }
      }

      // decay P7 counter
      peer_stats.behaviour_penalty *= params_.behaviour_penalty_decay;
      if (peer_stats.behaviour_penalty < params_.decay_to_zero) {
        peer_stats.behaviour_penalty = 0.0;
      }

      // decay slow peer score
      peer_stats.slow_peer_penalty *= params_.slow_peer_decay;
      if (peer_stats.slow_peer_penalty < params_.decay_to_zero) {
        peer_stats.slow_peer_penalty = 0.0;
      }

      ++it;
    }
  }

  void PeerScore::add_peer(const PeerId &peer_id) {
    auto &peer_stats = peer_stats_[peer_id];

    // mark the peer as connected
    peer_stats.disconnected = false;
  }

  void PeerScore::add_ip(const PeerId &peer_id, const IpAddress &ip) {
    auto &peer_stats = peer_stats_[peer_id];

    // Mark the peer as connected (currently the default is connected, but we
    // don't want to rely on the default).
    peer_stats.disconnected = false;

    // Insert the ip
    peer_stats.known_ips.insert(ip);
    peer_ips_[ip].insert(peer_id);
  }

  void PeerScore::remove_ip(const PeerId &peer_id, const IpAddress &ip) {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      it->second.known_ips.erase(ip);
      if (auto ip_it = peer_ips_.find(ip); ip_it != peer_ips_.end()) {
        ip_it->second.erase(peer_id);
      }
    }
  }

  void PeerScore::remove_peer(const PeerId &peer_id, TimePoint now) {
    // we only retain non-positive scores of peers
    if (score(peer_id) > 0.0) {
      if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
        remove_ips_for_peer(it->second, peer_ips_, peer_id);
        peer_stats_.erase(it);
      }
      return;
    }

    // if the peer is retained (including its score) the
    // first_message_deliveries counters are reset to 0 and mesh delivery
    // penalties applied.
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) {
      return;
    }
    auto &peer_stats = it->second;
    for (auto &[topic, topic_stats] : peer_stats.topics) {
      topic_stats.first_message_deliveries = 0.0;

      if (auto params_it = params_.topics.find(topic);
          params_it != params_.topics.end()) {
        auto threshold = params_it->second.mesh_message_deliveries_threshold;
        if (topic_stats.in_mesh() && topic_stats.mesh_message_deliveries_active
            && topic_stats.mesh_message_deliveries < threshold) {
          double deficit = threshold - topic_stats.mesh_message_deliveries;
          topic_stats.mesh_failure_penalty += deficit * deficit;
        }
      }

      topic_stats.mesh_status = MeshStatus{};
      topic_stats.mesh_message_deliveries_active = false;
    }

    peer_stats.disconnected = true;
    peer_stats.expire = now + params_.retain_score;
  }

  void PeerScore::graft(const PeerId &peer_id,
                        const TopicId &topic,
                        TimePoint now) {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      // if we are scoring the topic, update the mesh status.
      if (auto *topic_stats = stats_or_default(it->second, topic)) {
        topic_stats->mesh_status = MeshStatus::new_active(now);
        topic_stats->mesh_message_deliveries_active = false;
      }
    }
  }

  void PeerScore::prune(const PeerId &peer_id, const TopicId &topic) {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      // if we are scoring the topic, update the mesh status.
      if (auto *topic_stats = stats_or_default(it->second, topic)) {
        // sticky mesh delivery rate failure penalty
        // (topic must exist in order for there to be topic stats)
        if (auto params_it = params_.topics.find(topic);
            params_it != params_.topics.end()) {
          auto threshold = params_it->second.mesh_message_deliveries_threshold;
          if (topic_stats->mesh_message_deliveries_active
              && topic_stats->mesh_message_deliveries < threshold) {
            double deficit = threshold - topic_stats->mesh_message_deliveries;
            topic_stats->mesh_failure_penalty += deficit * deficit;
          }
        }
        topic_stats->mesh_message_deliveries_active = false;
        topic_stats->mesh_status = MeshStatus{};
      }
    }
  }

  void PeerScore::validate_message(const PeerId &,
                                   const MessageId &msg_id,
                                   const TopicId &,
                                   TimePoint now) {
    // adds an empty record with the message id
    deliveries_.entry(msg_id, now);
  }

  void PeerScore::deliver_message(const PeerId &from,
                                  const MessageId &msg_id,
                                  const TopicId &topic,
                                  TimePoint now) {
    mark_first_message_delivery(from, topic);

    auto &record = deliveries_.entry(msg_id, now);

    // this should be the first delivery trace
    if (record.status != DeliveryStatus::kUnknown) {
      return;
    }

    // mark the message as valid and reward mesh peers that have already
    // forwarded it to us
    record.status = DeliveryStatus::kValid;
    record.validated = now;
    // copy out: mark_duplicate_message_delivery may touch the cache owner
    std::vector<PeerId> peers{record.peers.begin(), record.peers.end()};
    for (auto &peer : peers) {
      // this check is to make sure a peer can't send us a message twice and
      // get a double count if it is a first delivery
      if (peer != from) {
        mark_duplicate_message_delivery(peer, topic, std::nullopt, now);
      }
    }
  }

  void PeerScore::reject_invalid_message(const PeerId &from,
                                         const TopicId &topic) {
    mark_invalid_message_delivery(from, topic);
  }

  void PeerScore::reject_message(const PeerId &from,
                                 const MessageId &msg_id,
                                 const TopicId &topic,
                                 RejectReason reason,
                                 TimePoint now) {
    switch (reason) {
      // these messages are not tracked, but the peer is penalized as they
      // are invalid
      case RejectReason::kValidationError:
      case RejectReason::kSelfOrigin:
        reject_invalid_message(from, topic);
        return;
      // we ignore those messages, so do nothing.
      case RejectReason::kBlackListedPeer:
      case RejectReason::kBlackListedSource:
        return;
      default:
        // the rest are handled after record creation
        break;
    }

    std::vector<PeerId> peers;
    {
      auto &record = deliveries_.entry(msg_id, now);

      // Multiple peers can now reject the same message as we track which
      // peers send us the message. If we have already updated the status,
      // return.
      if (record.status != DeliveryStatus::kUnknown) {
        return;
      }

      if (reason == RejectReason::kValidationIgnored) {
        // we were explicitly instructed by the validator to ignore the
        // message but not penalize the peer
        record.status = DeliveryStatus::kIgnored;
        record.peers.clear();
        return;
      }

      // mark the message as invalid and penalize peers that have already
      // forwarded it.
      record.status = DeliveryStatus::kInvalid;
      // release the delivery time tracking map to free some memory early
      peers.assign(record.peers.begin(), record.peers.end());
      record.peers.clear();
    }

    mark_invalid_message_delivery(from, topic);
    for (auto &peer_id : peers) {
      mark_invalid_message_delivery(peer_id, topic);
    }
  }

  void PeerScore::duplicated_message(const PeerId &from,
                                     const MessageId &msg_id,
                                     const TopicId &topic,
                                     TimePoint now) {
    auto &record = deliveries_.entry(msg_id, now);

    if (record.peers.contains(from)) {
      // we have already seen this duplicate!
      return;
    }

    switch (record.status) {
      case DeliveryStatus::kUnknown:
        // the message is being validated; track the peer delivery and wait
        // for the Deliver/Reject notification.
        record.peers.insert(from);
        break;
      case DeliveryStatus::kValid:
        // mark the peer delivery time to only count a duplicate delivery
        // once.
        record.peers.insert(from);
        mark_duplicate_message_delivery(from, topic, record.validated, now);
        break;
      case DeliveryStatus::kInvalid:
        // we no longer track delivery time
        mark_invalid_message_delivery(from, topic);
        break;
      case DeliveryStatus::kIgnored:
        // the message was ignored; do nothing (we don't know if it was
        // valid)
        break;
    }
  }

  void PeerScore::failed_message_slow_peer(const PeerId &peer_id) {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      it->second.slow_peer_penalty += 1.0;
    }
  }

  bool PeerScore::set_application_score(const PeerId &peer_id,
                                        double new_score) {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      it->second.application_score = new_score;
      return true;
    }
    return false;
  }

  void PeerScore::set_topic_params(const TopicId &topic,
                                   TopicScoreParams topic_params) {
    auto [it, inserted] = params_.topics.try_emplace(topic, topic_params);
    if (inserted) {
      return;
    }
    auto old_params = it->second;
    it->second = std::move(topic_params);
    auto first_message_deliveries_cap = it->second.first_message_deliveries_cap;
    auto mesh_message_deliveries_cap = it->second.mesh_message_deliveries_cap;

    if (old_params.first_message_deliveries_cap > first_message_deliveries_cap) {
      for (auto &[_, stats] : peer_stats_) {
        if (auto tstats_it = stats.topics.find(topic);
            tstats_it != stats.topics.end()
            && tstats_it->second.first_message_deliveries
                   > first_message_deliveries_cap) {
          tstats_it->second.first_message_deliveries =
              first_message_deliveries_cap;
        }
      }
    }

    if (old_params.mesh_message_deliveries_cap > mesh_message_deliveries_cap) {
      for (auto &[_, stats] : peer_stats_) {
        if (auto tstats_it = stats.topics.find(topic);
            tstats_it != stats.topics.end()
            && tstats_it->second.mesh_message_deliveries
                   > mesh_message_deliveries_cap) {
          tstats_it->second.mesh_message_deliveries =
              mesh_message_deliveries_cap;
        }
      }
    }
  }

  const TopicScoreParams *PeerScore::get_topic_params(
      const TopicId &topic) const {
    auto it = params_.topics.find(topic);
    return it != params_.topics.end() ? &it->second : nullptr;
  }

  std::optional<double> PeerScore::mesh_message_deliveries(
      const PeerId &peer_id, const TopicId &topic) const {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      if (auto tit = it->second.topics.find(topic);
          tit != it->second.topics.end()) {
        return tit->second.mesh_message_deliveries;
      }
    }
    return std::nullopt;
  }

  PeerScore::TopicStats *PeerScore::stats_or_default(PeerStats &peer_stats,
                                                     const TopicId &topic) {
    if (params_.topics.contains(topic)) {
      return &peer_stats.topics[topic];
    }
    auto it = peer_stats.topics.find(topic);
    return it != peer_stats.topics.end() ? &it->second : nullptr;
  }

  void PeerScore::mark_invalid_message_delivery(const PeerId &peer_id,
                                                const TopicId &topic) {
    if (auto it = peer_stats_.find(peer_id); it != peer_stats_.end()) {
      if (auto *topic_stats = stats_or_default(it->second, topic)) {
        topic_stats->invalid_message_deliveries += 1.0;
      }
    }
  }

  void PeerScore::mark_first_message_delivery(const PeerId &peer_id,
                                              const TopicId &topic) {
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) {
      return;
    }
    auto *topic_stats = stats_or_default(it->second, topic);
    if (topic_stats == nullptr) {
      return;
    }
    // topic must exist if there are known topic_stats
    auto params_it = params_.topics.find(topic);
    if (params_it == params_.topics.end()) {
      return;
    }

    topic_stats->first_message_deliveries =
        std::min(topic_stats->first_message_deliveries + 1.0,
                 params_it->second.first_message_deliveries_cap);

    if (topic_stats->mesh_status.active) {
      topic_stats->mesh_message_deliveries =
          std::min(topic_stats->mesh_message_deliveries + 1.0,
                   params_it->second.mesh_message_deliveries_cap);
    }
  }

  void PeerScore::mark_duplicate_message_delivery(
      const PeerId &peer_id,
      const TopicId &topic,
      std::optional<TimePoint> validated_time,
      TimePoint now) {
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) {
      return;
    }
    auto *topic_stats = stats_or_default(it->second, topic);
    if (topic_stats == nullptr || !topic_stats->mesh_status.active) {
      return;
    }
    // topic must exist if there are known topic_stats
    auto params_it = params_.topics.find(topic);
    if (params_it == params_.topics.end()) {
      return;
    }
    auto &topic_params = params_it->second;

    // check against the mesh delivery window -- if the validated time is
    // not given, then the message was received before we finished validation
    // and thus falls within the mesh delivery window.
    bool falls_in_mesh_deliver_window = true;
    if (validated_time.has_value()) {
      auto window_time =
          *validated_time + topic_params.mesh_message_deliveries_window;
      if (now > window_time) {
        falls_in_mesh_deliver_window = false;
      }
    }

    if (falls_in_mesh_deliver_window) {
      topic_stats->mesh_message_deliveries =
          std::min(topic_stats->mesh_message_deliveries + 1.0,
                   topic_params.mesh_message_deliveries_cap);
    }
  }

  // -- Lighthouse mainnet parameters ----------------------------------------
  // Port of lighthouse_network/src/service/gossipsub_scoring_parameters.rs
  // (Lighthouse v8.2.2), specialised to the mainnet ChainSpec.

  namespace {

    constexpr double kMaxInMeshScore = 10.0;
    constexpr double kMaxFirstMessageDeliveriesScore = 40.0;
    constexpr double kBeaconBlockWeight = 0.5;
    constexpr double kBeaconAggregateProofWeight = 0.5;
    constexpr double kVoluntaryExitWeight = 0.05;
    constexpr double kProposerSlashingWeight = 0.05;
    constexpr double kAttesterSlashingWeight = 0.05;

    /// The time window (seconds) that we expect messages to be forwarded to
    /// us in the mesh.
    constexpr auto kMeshMessageDeliveriesWindow = std::chrono::seconds{2};

    // Mainnet ChainSpec / EthSpec constants.
    constexpr uint64_t kSlotsPerEpoch = 32;
    constexpr uint64_t kAttestationSubnetCount = 64;
    constexpr uint64_t kMaxCommitteesPerSlot = 64;
    constexpr uint64_t kTargetCommitteeSize = 128;
    constexpr uint64_t kTargetAggregatorsPerCommittee = 16;

    using DoubleSeconds = std::chrono::duration<double>;

    Duration to_duration(DoubleSeconds d) {
      return std::chrono::duration_cast<Duration>(d);
    }

    /// Mirrors PeerScoreSettings (the subset needed for the topics we build).
    struct Settings {
      DoubleSeconds slot;
      DoubleSeconds epoch;
      double max_positive_score;
      DoubleSeconds decay_interval;
      double decay_to_zero;
      size_t mesh_n;

      double score_parameter_decay(DoubleSeconds decay_time) const {
        return score_parameter_decay_with_base(to_duration(decay_time),
                                               to_duration(decay_interval),
                                               decay_to_zero);
      }
    };

    double decay_convergence(double decay, double rate) {
      return rate / (1.0 - decay);
    }

    double threshold(double decay, double rate) {
      return decay_convergence(decay, rate) * decay;
    }

    /// EthSpec::get_committee_count_per_slot_with for mainnet.
    uint64_t committee_count_per_slot(uint64_t active_validators) {
      return std::max<uint64_t>(
          1,
          std::min(kMaxCommitteesPerSlot,
                   active_validators / kSlotsPerEpoch / kTargetCommitteeSize));
    }

    struct MeshMessageInfo {
      uint64_t decay_slots;
      double cap_factor;
      DoubleSeconds activation_window;
      uint64_t current_slot;
    };

    /// PeerScoreSettings::get_topic_params.
    TopicScoreParams make_topic_params(
        const Settings &s,
        double topic_weight,
        double expected_message_rate,
        DoubleSeconds first_message_decay_time,
        std::optional<MeshMessageInfo> mesh_message_info) {
      TopicScoreParams t;

      t.topic_weight = topic_weight;

      t.time_in_mesh_quantum = to_duration(s.slot);
      t.time_in_mesh_cap = 3600.0 / s.slot.count();
      t.time_in_mesh_weight = 10.0 / t.time_in_mesh_cap;

      t.first_message_deliveries_decay =
          s.score_parameter_decay(first_message_decay_time);
      t.first_message_deliveries_cap = decay_convergence(
          t.first_message_deliveries_decay,
          2.0 * expected_message_rate / static_cast<double>(s.mesh_n));
      t.first_message_deliveries_weight = 40.0 / t.first_message_deliveries_cap;

      if (mesh_message_info.has_value()) {
        auto &[decay_slots, cap_factor, activation_window, current_slot] =
            *mesh_message_info;
        auto decay_time = s.slot * static_cast<double>(decay_slots);
        t.mesh_message_deliveries_decay = s.score_parameter_decay(decay_time);
        t.mesh_message_deliveries_threshold = threshold(
            t.mesh_message_deliveries_decay, expected_message_rate / 50.0);
        t.mesh_message_deliveries_cap =
            std::max(2.0, cap_factor * t.mesh_message_deliveries_threshold);
        t.mesh_message_deliveries_activation = to_duration(activation_window);
        t.mesh_message_deliveries_window = kMeshMessageDeliveriesWindow;
        t.mesh_failure_penalty_decay = t.mesh_message_deliveries_decay;
        t.mesh_message_deliveries_weight = -t.topic_weight;
        t.mesh_failure_penalty_weight = t.mesh_message_deliveries_weight;
        if (decay_slots >= current_slot) {
          t.mesh_message_deliveries_threshold = 0.0;
          t.mesh_message_deliveries_weight = 0.0;
        }
      } else {
        t.mesh_message_deliveries_weight = 0.0;
        t.mesh_message_deliveries_threshold = 0.0;
        t.mesh_message_deliveries_decay = 0.0;
        t.mesh_message_deliveries_cap = 0.0;
        t.mesh_message_deliveries_window = Duration::zero();
        t.mesh_message_deliveries_activation = Duration::zero();
        t.mesh_failure_penalty_decay = 0.0;
        t.mesh_failure_penalty_weight = 0.0;
      }

      t.invalid_message_deliveries_weight =
          -s.max_positive_score / t.topic_weight;
      t.invalid_message_deliveries_decay =
          s.score_parameter_decay(s.epoch * 50.0);

      return t;
    }

  }  // namespace

  PeerScoreThresholds lighthouse_thresholds() {
    return PeerScoreThresholds{
        .gossip_threshold = -4000.0,
        .publish_threshold = -8000.0,
        .graylist_threshold = -16000.0,
        .accept_px_threshold = 100.0,
        .opportunistic_graft_threshold = 5.0,
    };
  }

  PeerScoreParams lighthouse_mainnet_params(
      std::string beacon_block_topic,
      std::vector<std::string> attestation_subnet_topics,
      double slot_seconds,
      size_t active_validators,
      size_t mesh_n,
      uint64_t current_slot) {
    const double beacon_attestation_subnet_weight =
        1.0 / static_cast<double>(kAttestationSubnetCount);
    const double max_positive_score =
        (kMaxInMeshScore + kMaxFirstMessageDeliveriesScore)
        * (kBeaconBlockWeight + kBeaconAggregateProofWeight
           + beacon_attestation_subnet_weight
                 * static_cast<double>(kAttestationSubnetCount)
           + kVoluntaryExitWeight + kProposerSlashingWeight
           + kAttesterSlashingWeight);

    Settings s{
        .slot = DoubleSeconds{slot_seconds},
        .epoch = DoubleSeconds{slot_seconds * static_cast<double>(kSlotsPerEpoch)},
        .max_positive_score = max_positive_score,
        .decay_interval = std::max(DoubleSeconds{1.0}, DoubleSeconds{slot_seconds}),
        .decay_to_zero = 0.01,
        .mesh_n = mesh_n,
    };

    const auto thresholds = lighthouse_thresholds();

    PeerScoreParams params;
    params.decay_interval = to_duration(s.decay_interval);
    params.decay_to_zero = s.decay_to_zero;
    params.retain_score = to_duration(s.epoch * 100.0);
    params.app_specific_weight = 1.0;
    params.ip_colocation_factor_threshold = 8.0;  // Allow up to 8 nodes per IP
    params.behaviour_penalty_threshold = 6.0;
    params.behaviour_penalty_decay = s.score_parameter_decay(s.epoch * 10.0);
    params.slow_peer_decay = 0.1;
    params.slow_peer_weight = -10.0;
    params.slow_peer_threshold = 0.0;

    const double target_value =
        decay_convergence(params.behaviour_penalty_decay,
                          10.0 / static_cast<double>(kSlotsPerEpoch))
        - params.behaviour_penalty_threshold;
    params.behaviour_penalty_weight =
        thresholds.gossip_threshold / (target_value * target_value);

    params.topic_score_cap = max_positive_score * 0.5;
    params.ip_colocation_factor_weight = -params.topic_score_cap;

    // beacon block
    params.topics.emplace(
        std::move(beacon_block_topic),
        make_topic_params(s,
                          kBeaconBlockWeight,
                          1.0,
                          s.epoch * 20.0,
                          MeshMessageInfo{
                              .decay_slots = kSlotsPerEpoch * 5,
                              .cap_factor = 3.0,
                              .activation_window = s.epoch,
                              .current_slot = current_slot,
                          }));

    // beacon attestation subnets
    const auto committees_per_slot = committee_count_per_slot(active_validators);
    const bool multiple_bursts_per_subnet_per_epoch =
        committees_per_slot >= 2 * kAttestationSubnetCount / kSlotsPerEpoch;
    const auto beacon_attestation_subnet_params = make_topic_params(
        s,
        beacon_attestation_subnet_weight,
        static_cast<double>(active_validators)
            / static_cast<double>(kAttestationSubnetCount)
            / static_cast<double>(kSlotsPerEpoch),
        s.epoch * (multiple_bursts_per_subnet_per_epoch ? 1.0 : 4.0),
        MeshMessageInfo{
            .decay_slots =
                kSlotsPerEpoch * (multiple_bursts_per_subnet_per_epoch ? 4 : 16),
            .cap_factor = 16.0,
            .activation_window =
                multiple_bursts_per_subnet_per_epoch
                    ? s.slot * static_cast<double>(kSlotsPerEpoch / 2 + 1)
                    : s.epoch * 3.0,
            .current_slot = current_slot,
        });
    for (auto &topic : attestation_subnet_topics) {
      params.topics.emplace(std::move(topic), beacon_attestation_subnet_params);
    }

    return params;
  }

}  // namespace libp2p::protocol::gossip::score
