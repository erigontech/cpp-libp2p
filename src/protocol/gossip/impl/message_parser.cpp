/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "message_parser.hpp"

#include <libp2p/log/logger.hpp>

#include "message_receiver.hpp"

#include <libp2p/peer/peer_id.hpp>

#include <generated/protocol/gossip/protobuf/rpc.pb.h>

namespace libp2p::protocol::gossip {

  namespace {
    auto log() {
      static auto logger = log::createLogger("gossip");
      return logger.get();
    }
  }  // namespace

  // need to define default ctor/dtor here in translation unit due to unique_ptr
  // to type which is incomplete in header
  MessageParser::MessageParser() = default;
  MessageParser::~MessageParser() = default;

  bool MessageParser::parse(BytesIn bytes) {
    if (!pb_msg_) {
      pb_msg_ = std::make_unique<pubsub::pb::RPC>();
    } else {
      pb_msg_->Clear();
    }
    return pb_msg_->ParseFromArray(bytes.data(),
                                   static_cast<int>(bytes.size()));
  }

  void MessageParser::dispatch(const PeerContextPtr &from,
                               MessageReceiver &receiver) {
    if (!pb_msg_) {
      return;
    }

    for (const auto &s : pb_msg_->subscriptions()) {
      if (!s.has_subscribe() || !s.has_topicid()) {
        continue;
      }
      receiver.onSubscription(from, s.subscribe(), s.topicid());
    }

    if (pb_msg_->has_control()) {
      const auto &c = pb_msg_->control();

      for (const auto &h : c.ihave()) {
        if (!h.has_topicid() || h.messageids_size() == 0) {
          continue;
        }
        const TopicId &topic = h.topicid();
        for (const auto &msg_id : h.messageids()) {
          if (msg_id.empty()) {
            continue;
          }
          receiver.onIHave(from, topic, fromString(msg_id));
        }
      }

      for (const auto &w : c.iwant()) {
        if (w.messageids_size() == 0) {
          continue;
        }
        for (const auto &msg_id : w.messageids()) {
          if (msg_id.empty()) {
            continue;
          }
          receiver.onIWant(from, fromString(msg_id));
        }
      }

      for (const auto &dw : c.idontwant()) {
        for (const auto &msg_id : dw.messageids()) {
          if (msg_id.empty()) {
            continue;
          }
          receiver.onIDontWant(from, fromString(msg_id));
        }
      }

      for (const auto &gr : c.graft()) {
        if (!gr.has_topicid()) {
          continue;
        }
        receiver.onGraft(from, gr.topicid());
      }

      for (const auto &pr : c.prune()) {
        if (!pr.has_topicid()) {
          continue;
        }
        uint64_t backoff_time = 60;
        if (pr.has_backoff()) {
          backoff_time = pr.backoff();
        }
        log()->info(
            "prune backoff={}, {} PX peers", backoff_time, pr.peers_size());
        for (const auto &peer_info : pr.peers()) {
          if (peer_info.peerid().empty()) {
            continue;
          }
          auto peer_id_res = peer::PeerId::fromBytes(BytesIn(
              reinterpret_cast<const uint8_t *>(peer_info.peerid().data()),
              peer_info.peerid().size()));
          if (peer_id_res) {
            log()->info("PX peer: {}", peer_id_res.value().toBase58());
            receiver.onPrunePeerExchange(peer_id_res.value());
          } else {
            log()->debug("PX peer: invalid peer id ({} bytes)",
                         peer_info.peerid().size());
          }
        }
        receiver.onPrune(from, pr.topicid(), backoff_time);
      }
    }

    for (const auto &m : pb_msg_->publish()) {
      // In eth2 StrictNoSign mode, messages have no `from` or `seqno` fields.
      // Only `data` and `topic` are required.
      if (!m.has_data() || !m.has_topic()) {
        continue;
      }
      auto message = std::make_shared<TopicMessage>(
          m.has_from() ? fromString(m.from()) : Bytes{},
          m.has_seqno() ? fromString(m.seqno()) : Bytes{},
          fromString(m.data()));
      message->topic = m.topic();
      if (m.has_signature()) {
        message->signature = fromString(m.signature());
      }
      if (m.has_key()) {
        message->key = fromString(m.key());
      }
      receiver.onTopicMessage(from, std::move(message));
    }

    receiver.onMessageEnd(from);
  }

}  // namespace libp2p::protocol::gossip
