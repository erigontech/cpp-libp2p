/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "peer_context.hpp"

#include <algorithm>

#include "message_builder.hpp"

namespace libp2p::protocol::gossip {

  namespace {

    std::string makeStringRepr(const peer::PeerId &id) {
      return id.toBase58().substr(46);
    }

  }  // namespace

  PeerContext::PeerContext(peer::PeerId id)
      : peer_id(std::move(id)),
        str(makeStringRepr(peer_id)),
        message_builder(std::make_shared<MessageBuilder>()) {}

  namespace {
    uint64_t idPrefix(const MessageId &msg_id) {
      uint64_t prefix = 0;
      for (size_t i = 0; i < msg_id.size() && i < sizeof(prefix); ++i) {
        prefix = (prefix << 8) | msg_id[i];
      }
      return prefix;
    }
  }  // namespace

  void PeerDiagnosticsState::announce(const MessageId &msg_id, Time now) {
    // the first announcement of an ID counts: its age is from then
    const auto prefix = idPrefix(msg_id);
    if (!announced.emplace(prefix, now).second) {
      return;
    }
    auto &slot = announced_order[announced_next];
    if (announced.size() > kAnnounced) {
      announced.erase(slot);
    }
    slot = prefix;
    announced_next = (announced_next + 1) % kAnnounced;
  }

  void PeerDiagnosticsState::pushed(const TopicId &id,
                                    PeerDiagnostics::PushKind kind,
                                    size_t bytes,
                                    const MessageId &msg_id,
                                    Time now) {
    const auto entry = view.topics.try_emplace(id).first;
    auto &counters = entry->second;
    ++counters.messages;
    counters.message_bytes += bytes;
    auto &record = pushes[pushes_next];
    record.at = now;
    record.topic = &entry->first;
    record.kind = kind;
    record.id_size = static_cast<uint8_t>(
        std::min(msg_id.size(), PeerDiagnostics::kPushIdBytes));
    std::copy_n(msg_id.begin(), record.id_size, record.id.begin());
    pushes_next = (pushes_next + 1) % kPushes;
  }

  std::vector<PeerDiagnostics::Push> PeerDiagnosticsState::sentRecently(
      Time now) const {
    std::vector<PeerDiagnostics::Push> sent;
    for (size_t back = 1; back <= kPushes; ++back) {
      const auto &record = pushes[(pushes_next + kPushes - back) % kPushes];
      if (record.topic == nullptr
          || now - record.at > PeerDiagnostics::kSentRecently) {
        break;
      }
      sent.push_back({.topic = *record.topic,
                      .kind = record.kind,
                      .before = now - record.at,
                      .id = record.messageId()});
    }
    return sent;
  }

  void PeerDiagnosticsState::pruneReceived(Time now) {
    // a heartbeat's PRUNEs come in one RPC
    if (prune_burst_at != Time{0} && now - prune_burst_at <= kPruneBurst) {
      ++view.prune_burst_topics;
      return;
    }
    prune_burst_at = now;
    view.prune_burst_topics = 1;
    view.pushes_before_prune.clear();
    // the latest first, back to kPushesBeforePrune before the PRUNE
    for (size_t back = 1; back <= kPushes; ++back) {
      const auto &record = pushes[(pushes_next + kPushes - back) % kPushes];
      if (record.topic == nullptr
          || now - record.at > PeerDiagnostics::kPushesBeforePrune) {
        break;
      }
      view.pushes_before_prune.push_back({.topic = *record.topic,
                                          .kind = record.kind,
                                          .before = now - record.at,
                                          .id = record.messageId()});
    }
  }

  std::optional<Time> PeerDiagnosticsState::announcedAt(
      const MessageId &msg_id) const {
    const auto it = announced.find(idPrefix(msg_id));
    if (it == announced.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  PeerDiagnosticsState &beginDiagnostics(PeerContext &ctx,
                                         Time now,
                                         Time keep) {
    auto &diag = ctx.diag;
    if (diag && diag->disconnected != Time{0}
        && now - diag->disconnected > keep) {
      diag.reset();
    }
    if (!diag) {
      diag = std::make_unique<PeerDiagnosticsState>();
      diag->started = now;
      diag->view.sessions = 1;
    } else if (diag->disconnected != Time{0}) {
      // reconnected within the session
      diag->disconnected = Time{0};
      ++diag->view.sessions;
    }
    return *diag;
  }

  bool operator<(const PeerContextPtr &ctx, const peer::PeerId &peer) {
    if (!ctx) {
      return false;
    }
    return less(ctx->peer_id, peer);
  }

  bool operator<(const peer::PeerId &peer, const PeerContextPtr &ctx) {
    if (!ctx) {
      return false;
    }
    return less(peer, ctx->peer_id);
  }

  bool operator<(const PeerContextPtr &a, const PeerContextPtr &b) {
    if (!a || !b) {
      return false;
    }
    return less(a->peer_id, b->peer_id);
  }

}  // namespace libp2p::protocol::gossip
