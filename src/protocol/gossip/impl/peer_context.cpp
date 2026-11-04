/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "peer_context.hpp"
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
