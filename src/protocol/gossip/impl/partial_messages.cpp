/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "partial_messages.hpp"

#include <algorithm>
#include <utility>

#include "peer_context.hpp"

namespace libp2p::protocol::gossip {

  namespace {
    // the options of the peer's subscription to topic, none unless both
    // sides advertised the extension
    PartialTopicOptions peerOptions(const PeerContext &peer,
                                    const TopicId &topic) {
      if (!peer.partial_messages || !peer.partial_advertised) {
        return {};
      }
      auto it = peer.partial_topics.find(topic);
      return it == peer.partial_topics.end() ? PartialTopicOptions{}
                                             : it->second;
    }
  }  // namespace

  PartialMessages::PartialMessages(const Config &config) : config_(config) {}

  bool PartialMessages::enabled() const {
    return config_.partial_messages;
  }

  std::optional<PartialTopicOptions> PartialMessages::topicOptions(
      const TopicId &topic) const {
    auto it = topics_.find(topic);
    if (it == topics_.end()) {
      return std::nullopt;
    }
    return it->second.options;
  }

  PartialTopicOptions PartialMessages::announced(const TopicId &topic) const {
    return topicOptions(topic).value_or(PartialTopicOptions{});
  }

  bool PartialMessages::setTopicOptions(const TopicId &topic,
                                        PartialTopicOptions options,
                                        Time now) {
    if (!enabled()) {
      return false;
    }
    // a node requesting partial messages must support sending them
    options.supports_sending_partial =
        options.supports_sending_partial || options.requests_partial;
    auto it = topics_.find(topic);
    if (!options.supports_sending_partial) {
      if (it == topics_.end()) {
        return false;
      }
      topics_.erase(it);
      groups_.erase(topic);
      return true;
    }
    if (it != topics_.end()
        && it->second.options.requests_partial == options.requests_partial) {
      return false;
    }
    topics_[topic] = TopicOptions{.options = options, .changed_at = now};
    return true;
  }

  Time PartialMessages::optionsChangedAt(const TopicId &topic) const {
    auto it = topics_.find(topic);
    return it == topics_.end() ? Time{} : it->second.changed_at;
  }

  bool PartialMessages::sendsPartialTo(const PeerContext &peer,
                                       const TopicId &topic) const {
    // on the forwarding path of every message: the cheap checks first
    return !topics_.empty() && peerOptions(peer, topic).requests_partial
        && topics_.contains(topic);
  }

  bool PartialMessages::exchangesWith(const PeerContext &peer,
                                      const TopicId &topic) const {
    auto ours = topicOptions(topic);
    if (!ours) {
      return false;
    }
    const auto theirs = peerOptions(peer, topic);
    return theirs.requests_partial
        || (ours->requests_partial && theirs.supports_sending_partial);
  }

  bool PartialMessages::mayReceiveParts(const PeerContext &peer,
                                        const TopicId &topic) const {
    return sendsPartialTo(peer, topic);
  }

  bool PartialMessages::mayReceiveMetadata(const PeerContext &peer,
                                           const TopicId &topic) const {
    return topics_.contains(topic)
        && peerOptions(peer, topic).supports_sending_partial;
  }

  void PartialMessages::TopicGroups::uncount(Group &group) {
    if (!group.counted_for) {
      return;
    }
    if (auto it = counted_by_peer.find(*group.counted_for);
        it != counted_by_peer.end()) {
      --counted;
      if (--it->second == 0) {
        counted_by_peer.erase(it);
      }
    }
    group.counted_for.reset();
  }

  PartialMessages::Group *PartialMessages::group(
      const TopicId &topic,
      const Bytes &group_id,
      const std::optional<peer::PeerId> &peer) {
    if (!topics_.contains(topic)) {
      return nullptr;
    }
    auto &topic_groups = groups_[topic];
    auto it = topic_groups.groups.find(group_id);
    if (it == topic_groups.groups.end()) {
      if (peer) {
        // DoS: the peers open a bounded number of groups (go-libp2p-pubsub
        // PeerInitiatedGroupLimitPerTopic, PerPeer)
        if (topic_groups.counted >= config_.partial_peer_groups_per_topic) {
          return nullptr;
        }
        auto by_peer = topic_groups.counted_by_peer.find(*peer);
        if (by_peer != topic_groups.counted_by_peer.end()
            && by_peer->second
                   >= config_.partial_peer_groups_per_topic_per_peer) {
          return nullptr;
        }
        ++topic_groups.counted;
        ++topic_groups.counted_by_peer[*peer];
      }
      it = topic_groups.groups.emplace(group_id, Group{}).first;
      it->second.counted_for = peer;
    }
    auto &group = it->second;
    if (!peer && !group.published) {
      // ours too now: it no longer counts against the peer that opened it
      group.published = true;
      topic_groups.uncount(group);
    }
    group.ttl = std::max(config_.partial_group_ttl_heartbeats, 1u);
    return &group;
  }

  std::map<Bytes, PartialMessages::Group> *PartialMessages::groups(
      const TopicId &topic) {
    auto it = groups_.find(topic);
    return it == groups_.end() ? nullptr : &it->second.groups;
  }

  void PartialMessages::addGossipPeer(const TopicId &topic,
                                      const peer::PeerId &peer) {
    gossip_peers_[topic].push_back(peer);
  }

  std::vector<PartialMessages::GossipEmission> PartialMessages::takeGossip() {
    std::vector<GossipEmission> emissions;
    for (const auto &[topic, peers] : std::exchange(gossip_peers_, {})) {
      auto it = groups_.find(topic);
      if (it == groups_.end()) {
        continue;
      }
      for (auto &[group_id, group] : it->second.groups) {
        // the groups the peers opened are theirs to gossip
        if (!group.published) {
          continue;
        }
        GossipEmission emission{
            .topic = topic, .group_id = group_id, .peers = {}};
        for (const auto &peer : peers) {
          if (group.peers.try_emplace(peer).second) {
            emission.peers.push_back(peer);
          }
        }
        if (!emission.peers.empty()) {
          emissions.push_back(std::move(emission));
        }
      }
    }
    return emissions;
  }

  void PartialMessages::onHeartbeat() {
    for (auto topic_it = groups_.begin(); topic_it != groups_.end();) {
      auto &topic_groups = topic_it->second;
      for (auto it = topic_groups.groups.begin();
           it != topic_groups.groups.end();) {
        if (--it->second.ttl == 0) {
          topic_groups.uncount(it->second);
          it = topic_groups.groups.erase(it);
        } else {
          ++it;
        }
      }
      if (topic_groups.groups.empty()) {
        topic_it = groups_.erase(topic_it);
      } else {
        ++topic_it;
      }
    }
  }

  void PartialMessages::onPeerDisconnected(const peer::PeerId &peer) {
    for (auto &[_, topic_groups] : groups_) {
      for (auto &[_, group] : topic_groups.groups) {
        group.peers.erase(peer);
        if (group.counted_for == peer) {
          topic_groups.uncount(group);
        }
      }
    }
  }

}  // namespace libp2p::protocol::gossip
