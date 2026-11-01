/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <functional>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

#include <libp2p/protocol/gossip/gossip.hpp>

#include "common.hpp"

namespace libp2p::protocol::gossip {

  /// Gossipsub partial messages extension (libp2p/specs
  /// pubsub/gossipsub/partial-messages.md): the topics we enabled and the
  /// partial message groups, with the state of the peers in each. The
  /// encodings of the parts and of the parts metadata are the application's:
  /// the router keeps the peers' latest metadata, bounds the groups the peers
  /// open (as go-libp2p-pubsub) and hands everything else to the application
  class PartialMessages {
   public:
    explicit PartialMessages(const Config &config);

    /// Config::partial_messages
    bool enabled() const;

    /// Our options of \p topic, nullopt while it is not enabled
    std::optional<PartialTopicOptions> topicOptions(const TopicId &topic) const;

    /// The options our subscriptions to \p topic announce (none while it is
    /// not enabled)
    PartialTopicOptions announced(const TopicId &topic) const;

    /// Sets our options of \p topic (requesting implies supporting sending);
    /// clearing both disables it and forgets its groups. True if they changed
    bool setTopicOptions(const TopicId &topic,
                         PartialTopicOptions options,
                         Time now);

    /// When our options of \p topic last changed
    Time optionsChangedAt(const TopicId &topic) const;

    /// The peer advertised the extension and requested partial messages on
    /// the enabled \p topic: it gets parts instead of full messages and
    /// IHAVEs
    bool sendsPartialTo(const PeerContext &peer, const TopicId &topic) const;

    /// We exchange partial messages with the peer on the enabled \p topic: it
    /// advertised the extension and requested partial messages, or it
    /// supports sending them and we requested them (go-libp2p-pubsub
    /// MeshPeers)
    bool exchangesWith(const PeerContext &peer, const TopicId &topic) const;

    /// What the peer may be sent on \p topic: parts if it requested partial
    /// messages, parts metadata if it supports sending them
    bool mayReceiveParts(const PeerContext &peer, const TopicId &topic) const;
    bool mayReceiveMetadata(const PeerContext &peer,
                            const TopicId &topic) const;

    struct Group {
      PartialPeerStates peers;
      /// heartbeats left
      unsigned ttl = 0;
      /// we published in it
      bool published = false;
      /// the peer it counts against (Config::partial_peer_groups_*): the one
      /// that opened it, until we publish in it or the peer disconnects
      std::optional<peer::PeerId> counted_for;
    };

    /// The group \p group_id of the enabled \p topic, opened if new, by us
    /// (\p peer empty) or by \p peer. Nullptr if \p peer would open one past
    /// the limits. Its lifetime restarts
    Group *group(const TopicId &topic,
                 const Bytes &group_id,
                 const std::optional<peer::PeerId> &peer);

    /// The groups of \p topic, nullptr if none
    std::map<Bytes, Group> *groups(const TopicId &topic);

    /// Heartbeat gossip: a peer gossip picked on \p topic, to get partial
    /// messages instead of IHAVEs
    void addGossipPeer(const TopicId &topic, const peer::PeerId &peer);

    /// Partial messages gossip to a group we published in: the peers gossip
    /// picked that were not in it yet, and joined it
    struct GossipEmission {
      TopicId topic;
      Bytes group_id;
      std::vector<peer::PeerId> peers;
    };

    /// The gossip emissions of the peers picked since the last call
    std::vector<GossipEmission> takeGossip();

    /// Ages the groups, forgets the expired ones
    void onHeartbeat();

    /// Forgets the state of a peer gone, and the groups it opened count no
    /// longer against it
    void onPeerDisconnected(const peer::PeerId &peer);

   private:
    struct TopicGroups {
      std::map<Bytes, Group> groups;
      /// the groups counted against the peers, all and by peer
      size_t counted = 0;
      std::unordered_map<peer::PeerId, size_t> counted_by_peer;

      void uncount(Group &group);
    };

    struct TopicOptions {
      PartialTopicOptions options;
      Time changed_at{};
    };

    const Config &config_;
    std::unordered_map<TopicId, TopicOptions> topics_;
    std::unordered_map<TopicId, TopicGroups> groups_;
    std::map<TopicId, std::vector<peer::PeerId>> gossip_peers_;
  };

}  // namespace libp2p::protocol::gossip
