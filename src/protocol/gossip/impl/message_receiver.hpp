/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <optional>

#include "common.hpp"

namespace libp2p::protocol::gossip {

  /// The extensions a peer advertised in a gossipsub v1.3 Extensions control
  /// message
  struct PeerExtensions {
    bool partial_messages = false;
  };

  /// Interface for accepting sub-messages read from wire
  class MessageReceiver {
   public:
    virtual ~MessageReceiver() = default;

    /// The first message of a stream from the peer, with its Extensions
    /// control message if it has one (gossipsub v1.3), or a later message of
    /// the stream with one (a protocol violation)
    virtual void onExtensions(const PeerContextPtr &from,
                              const std::optional<PeerExtensions> &extensions,
                              bool first_on_stream) = 0;

    /// The partial messages options of a subscription the peer sent, before
    /// onSubscription (subscriptions only)
    virtual void onPartialSubscription(const PeerContextPtr &from,
                                       const TopicId &topic,
                                       PartialTopicOptions options) = 0;

    /// Topic subscribe-unsubscribe request received
    virtual void onSubscription(const PeerContextPtr &from,
                                bool subscribe,
                                const TopicId &topic) = 0;

    /// "I have message ids" notification received
    virtual void onIHave(const PeerContextPtr &from,
                         const TopicId &topic,
                         const MessageId &msg_id) = 0;

    /// "I want message" request received
    virtual void onIWant(const PeerContextPtr &from,
                         const MessageId &msg_id) = 0;

    /// "Don't send me this message" notification (gossipsub v1.2)
    virtual void onIDontWant(const PeerContextPtr &from,
                             const MessageId &msg_id) = 0;

    /// Graft request received (gossip mesh control)
    virtual void onGraft(const PeerContextPtr &from, const TopicId &topic) = 0;

    /// Prune request received (gossip mesh control).
    /// the peer must not be bothered with GRAFT requests for at least
    /// backoff_time seconds
    virtual void onPrune(const PeerContextPtr &from,
                         const TopicId &topic,
                         uint64_t backoff_time) = 0;

    /// Peer exchange info received in a PRUNE message from \p from
    /// (gossipsub v1.1)
    virtual void onPrunePeerExchange(const PeerContextPtr &from,
                                     const peer::PeerId &peer_id) = 0;

    /// Message received
    virtual void onTopicMessage(const PeerContextPtr &from,
                                TopicMessage::Ptr msg) = 0;

    /// Partial messages RPC received (partial messages extension)
    virtual void onPartialMessage(const PeerContextPtr &from,
                                  PartialMessage msg) = 0;

    /// Current wire protocol message dispatch ended
    virtual void onMessageEnd(const PeerContextPtr &from) = 0;
  };

}  // namespace libp2p::protocol::gossip
