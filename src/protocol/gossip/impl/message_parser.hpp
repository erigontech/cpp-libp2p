/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "common.hpp"

namespace pubsub::pb {
  // protobuf message forward declaration
  class RPC;
}  // namespace pubsub::pb

namespace libp2p::protocol::gossip {

  class MessageReceiver;

  /// Protobuf message parser.
  class MessageParser {
   public:
    MessageParser();

    ~MessageParser();

    /// Parses RPC protobuf message received from wire
    bool parse(BytesIn bytes);

    /// Dispatches parts of parsed aggregate message to receiver. \p
    /// first_on_stream: the first message read from its stream, which carries
    /// the Extensions control message (gossipsub v1.3)
    void dispatch(const PeerContextPtr &from,
                  MessageReceiver &receiver,
                  bool first_on_stream = false);

   private:
    /// Parsed protobuf message
    std::unique_ptr<pubsub::pb::RPC> pb_msg_;
  };

}  // namespace libp2p::protocol::gossip
