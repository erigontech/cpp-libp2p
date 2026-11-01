/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "message_builder.hpp"

#include <libp2p/multi/uvarint.hpp>

#include <generated/protocol/gossip/protobuf/rpc.pb.h>

namespace libp2p::protocol::gossip {

  namespace {
    // helper needed since protobuf doesn't have a blob type
    inline const char *toString(const Bytes &bytes) {
      // NOLINTNEXTLINE
      return reinterpret_cast<const char *>(bytes.data());
    }

    template <typename Partial>
    void setPartial(pubsub::pb::RPC &rpc, const Partial &partial) {
      auto *dst = rpc.mutable_partial();
      dst->set_topicid(partial.topic);
      dst->set_groupid(toString(partial.group_id), partial.group_id.size());
      if (!partial.partial_message.empty()) {
        dst->set_partialmessage(toString(partial.partial_message),
                                partial.partial_message.size());
      }
      if (!partial.parts_metadata.empty()) {
        dst->set_partsmetadata(toString(partial.parts_metadata),
                               partial.parts_metadata.size());
      }
    }

    // appends the length-prefixed \p rpc to \p buffer
    bool appendFrame(const pubsub::pb::RPC &rpc, Bytes &buffer) {
      const size_t msg_sz = rpc.ByteSizeLong();
      const auto varint_vec = multi::UVarint{msg_sz}.toVector();
      const size_t offset = buffer.size();
      buffer.resize(offset + varint_vec.size() + msg_sz);
      memcpy(buffer.data() + offset, varint_vec.data(), varint_vec.size());
      // NOLINTNEXTLINE
      return rpc.SerializeToArray(buffer.data() + offset + varint_vec.size(),
                                  static_cast<int>(msg_sz));
    }
  }  // namespace

  MessageBuilder::MessageBuilder() : empty_(true), control_not_empty_(false) {}

  MessageBuilder::~MessageBuilder() = default;

  void MessageBuilder::clear() {
    pb_msg_->Clear();
    control_pb_msg_->Clear();
    empty_ = true;
    control_not_empty_ = false;
    ihaves_.clear();
    iwant_.clear();
    idontwant_.clear();
    messages_added_.clear();
    partials_.clear();
  }

  void MessageBuilder::reset() {
    pb_msg_.reset();
    control_pb_msg_.reset();
    empty_ = true;
    control_not_empty_ = false;
    decltype(ihaves_){}.swap(ihaves_);
    decltype(iwant_){}.swap(iwant_);
    decltype(idontwant_){}.swap(idontwant_);
    decltype(messages_added_){}.swap(messages_added_);
    decltype(partials_){}.swap(partials_);
  }

  void MessageBuilder::create_protobuf_structures() {
    if (pb_msg_ == nullptr) {
      pb_msg_ = std::make_unique<pubsub::pb::RPC>();
      control_pb_msg_ = std::make_unique<pubsub::pb::ControlMessage>();
    }
  }

  bool MessageBuilder::empty() const {
    return empty_;
  }

  outcome::result<SharedBuffer> MessageBuilder::serialize() {
    create_protobuf_structures();

    for (auto &[topic, message_ids] : ihaves_) {
      auto *ih = control_pb_msg_->add_ihave();
      ih->set_topicid(topic);
      for (auto &mid : message_ids) {
        ih->add_messageids(toString(mid), mid.size());
      }
    }

    if (!iwant_.empty()) {
      auto *iw = control_pb_msg_->add_iwant();
      for (auto &mid : iwant_) {
        iw->add_messageids(toString(mid), mid.size());
      }
    }

    if (!idontwant_.empty()) {
      auto *dw = control_pb_msg_->add_idontwant();
      for (auto &mid : idontwant_) {
        dw->add_messageids(toString(mid), mid.size());
      }
    }

    if (control_not_empty_) {
      pb_msg_->set_allocated_control(control_pb_msg_.get());
    }

    // one partial messages RPC per message: the first rides with the rest
    if (!partials_.empty()) {
      setPartial(*pb_msg_, partials_.front());
    }

    size_t msg_sz = pb_msg_->ByteSizeLong();

    auto buffer = std::make_shared<Bytes>();
    bool success = appendFrame(*pb_msg_, *buffer);

    if (control_not_empty_) {
      std::ignore = pb_msg_->release_control();
    }

    for (size_t i = 1; success && i < partials_.size(); ++i) {
      pubsub::pb::RPC rpc;
      setPartial(rpc, partials_[i]);
      msg_sz += rpc.ByteSizeLong();
      success = appendFrame(rpc, *buffer);
    }

    static constexpr size_t kSizeThreshold = 8192;
    if (msg_sz > kSizeThreshold) {
      reset();
    } else {
      clear();
    }

    if (success) {
      return buffer;
    }
    return Error::MESSAGE_SERIALIZE_ERROR;
  }

  void MessageBuilder::addSubscription(bool subscribe,
                                       const TopicId &topic,
                                       PartialTopicOptions partial) {
    create_protobuf_structures();

    auto *dst = pb_msg_->add_subscriptions();
    dst->set_subscribe(subscribe);
    dst->set_topicid(topic);
    if (subscribe && partial.requests_partial) {
      dst->set_requestspartial(true);
    }
    if (subscribe && partial.supports_sending_partial) {
      dst->set_supportssendingpartial(true);
    }
    empty_ = false;
  }

  void MessageBuilder::addExtensions(bool partial_messages) {
    create_protobuf_structures();

    auto *extensions = control_pb_msg_->mutable_extensions();
    if (partial_messages) {
      extensions->set_partialmessages(true);
    }
    control_not_empty_ = true;
    empty_ = false;
  }

  void MessageBuilder::addPartialMessage(const TopicId &topic,
                                         const Bytes &group_id,
                                         const Bytes &partial_message,
                                         const Bytes &parts_metadata) {
    create_protobuf_structures();

    partials_.push_back({topic, group_id, partial_message, parts_metadata});
    empty_ = false;
  }

  void MessageBuilder::addIHave(const TopicId &topic, const MessageId &msg_id) {
    ihaves_[topic].push_back(msg_id);
    control_not_empty_ = true;
    empty_ = false;
  }

  void MessageBuilder::addIWant(const MessageId &msg_id) {
    iwant_.push_back(msg_id);
    control_not_empty_ = true;
    empty_ = false;
  }

  void MessageBuilder::addIDontWant(const MessageId &msg_id) {
    idontwant_.push_back(msg_id);
    control_not_empty_ = true;
    empty_ = false;
  }

  void MessageBuilder::addGraft(const TopicId &topic) {
    create_protobuf_structures();

    control_pb_msg_->add_graft()->set_topicid(topic);
    control_not_empty_ = true;
    empty_ = false;
  }

  void MessageBuilder::addPrune(const TopicId &topic,
                                uint64_t backoff_seconds) {
    create_protobuf_structures();

    auto *prune = control_pb_msg_->add_prune();
    prune->set_topicid(topic);
    if (backoff_seconds > 0) {
      prune->set_backoff(backoff_seconds);
    }
    control_not_empty_ = true;
    empty_ = false;
  }

  void MessageBuilder::addMessage(const TopicMessage &msg,
                                  const MessageId &msg_id) {
    create_protobuf_structures();

    if (messages_added_.count(msg_id) != 0) {
      // prevent duplicates
      return;
    }
    messages_added_.insert(msg_id);

    auto *dst = pb_msg_->add_publish();
    // Only the author fields the message has: in proto2 an empty field set is
    // still present on the wire, and the StrictNoSign (eth2) receivers reject
    // a message with any of them as invalid, rust-libp2p's Anonymous mode and
    // go-libp2p-pubsub alike. Every forward and IWANT response cost us P4 at
    // Lighthouse and Caplin, which graylisted us within minutes (silkworm #149)
    if (!msg.from.empty()) {
      dst->set_from(msg.from.data(), msg.from.size());
    }
    dst->set_data(msg.data.data(), msg.data.size());
    if (!msg.seq_no.empty()) {
      dst->set_seqno(msg.seq_no.data(), msg.seq_no.size());
    }
    dst->set_topic(msg.topic);
    if (msg.signature && !msg.signature->empty()) {
      dst->set_signature(msg.signature.value().data(),
                         msg.signature.value().size());
    }
    if (msg.key && !msg.key->empty()) {
      dst->set_key(msg.key.value().data(), msg.key.value().size());
    }
    empty_ = false;
  }

  outcome::result<Bytes> MessageBuilder::signableMessage(
      const TopicMessage &msg) {
    pubsub::pb::Message pb_msg;
    pb_msg.set_from(msg.from.data(), msg.from.size());
    pb_msg.set_data(msg.data.data(), msg.data.size());
    pb_msg.set_seqno(msg.seq_no.data(), msg.seq_no.size());
    pb_msg.set_topic(msg.topic);
    constexpr std::string_view kPrefix{"libp2p-pubsub:"};
    auto size = pb_msg.ByteSizeLong();
    Bytes signable;
    signable.resize(kPrefix.size() + size);
    std::copy(kPrefix.begin(), kPrefix.end(), signable.begin());
    if (!pb_msg.SerializeToArray(&signable[kPrefix.size()],
                                 static_cast<int>(size))) {
      return Error::MESSAGE_SERIALIZE_ERROR;
    }
    return signable;
  }
}  // namespace libp2p::protocol::gossip
