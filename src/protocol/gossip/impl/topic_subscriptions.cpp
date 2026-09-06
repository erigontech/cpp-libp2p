/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <cstdlib>
#include <string_view>
#include <vector>

#include "topic_subscriptions.hpp"

#include <algorithm>
#include <cassert>

#include "connectivity.hpp"
#include "message_builder.hpp"

namespace libp2p::protocol::gossip {

  namespace {
    // Latency-aware mesh curation (silkworm task #80). Default ON;
    // SILKWORM_GOSSIP_MESH_CURATION=0 restores the legacy random/newest-first
    // mesh maintenance for A/B comparison.
    bool curationEnabled() {
      static const bool on = [] {
        const char *env = std::getenv("SILKWORM_GOSSIP_MESH_CURATION");
        return env == nullptr || env[0] != '0';
      }();
      return on;
    }

    bool isBeaconBlockTopicId(const TopicId &topic) {
      static constexpr std::string_view kSuffix = "/beacon_block/ssz_snappy";
      return topic.size() >= kSuffix.size()
          && std::equal(kSuffix.rbegin(), kSuffix.rend(), topic.rbegin());
    }

    // Higher is better: first deliveries dominate, duplicate-lag EWMA breaks
    // ties; unknown lag (-1, no sample yet) is treated as a neutral 1500ms.
    double deliveryRank(const PeerContextPtr &p) {
      const double lag =
          p->delivery_lag_ewma_ms < 0 ? 1500.0 : p->delivery_lag_ewma_ms;
      return static_cast<double>(p->first_msg_deliveries) * 1000.0 - lag;
    }

    // Spec mesh target D sits between D_min (grow trigger) and D_max
    // (prune trigger); grafting is staggered to respect remote backoffs.
    // Spec D_lazy: peers to receive IHAVE gossip per message. The old code
    // announced to D_max*2 = 24 random peers per message — 4x the spec, per
    // message, on the hot thread.
    constexpr size_t kDLazy = 6;
    // Heartbeat windows of seen messages announced as IHAVE (spec
    // mcache_gossip) and a bound on ids per topic per beat (spec
    // max_ihave_length is 5000; we stay far below)
    constexpr uint32_t kGossipWindows = 3;
    constexpr size_t kMaxIHavePerBeat = 512;
    // gossipsub v1.2 IDONTWANT: announce-suppress threshold; only large
    // messages (blocks) are worth it
    constexpr size_t kIDontWantMinBytes = 1024;

    constexpr size_t kMeshTarget = 8;
    constexpr size_t kGraftPerHeartbeat = 2;
    constexpr uint64_t kSwapPeriodBeats = 86;  // ~60s at 700ms heartbeat
    constexpr uint64_t kPruneBackoffSec = 60;
    const Time kPruneBackoff = Time{60'000};
  }  // namespace

  namespace {

    // dont forward message to peer it was received from as well as to its
    // original issuer
    bool needToForward(const PeerContextPtr &ctx,
                       const boost::optional<PeerContextPtr> &from,
                       const outcome::result<peer::PeerId> &origin) {
      if (from && ctx->peer_id == from.value()->peer_id) {
        return false;
      }
      return !(origin && ctx->peer_id == origin.value());
    }

  }  // namespace

  TopicSubscriptions::TopicSubscriptions(TopicId topic,
                                         const Config &config,
                                         Connectivity &connectivity,
                                         basic::Scheduler &scheduler,
                                         log::SubLogger &log)
      : topic_(std::move(topic)),
        config_(config),
        connectivity_(connectivity),
        scheduler_(scheduler),
        self_subscribed_(false),
        fanout_period_ends_(0),
        log_(log) {}

  bool TopicSubscriptions::empty() const {
    return (not self_subscribed_)
        && (fanout_period_ends_ == std::chrono::milliseconds::zero())
        && subscribed_peers_.empty() && mesh_peers_.empty();
  }

  void TopicSubscriptions::onNewMessage(
      const boost::optional<PeerContextPtr> &from,
      const TopicMessage::Ptr &msg,
      const MessageId &msg_id,
      Time now) {
    bool is_published_locally = !from.has_value();

    if (is_published_locally) {
      fanout_period_ends_ = now + config_.seen_cache_lifetime_msec;
      log_.debug("setting fanout period for {}, {}->{}",
                 topic_,
                 now.count(),
                 fanout_period_ends_.count());
    }

    auto origin = peerFrom(*msg);

    const bool announce_idontwant =
        from.has_value() && msg->data.size() >= kIDontWantMinBytes;

    mesh_peers_.selectAll(
        [this, &msg, &msg_id, &from, &origin,
         announce_idontwant](const PeerContextPtr &ctx) {
          assert(ctx->message_builder);

          if (!needToForward(ctx, from, origin)) {
            return;
          }
          // honor the peer's IDONTWANT: they already have this message
          if (ctx->dont_want.count(msg_id) != 0) {
            return;
          }
          // tell the peer not to send us their copy back (v1.2); rides in
          // the same RPC as the forwarded message
          if (announce_idontwant) {
            ctx->message_builder->addIDontWant(msg_id);
          }
          ctx->message_builder->addMessage(*msg, msg_id);

          // forward immediately to those in mesh
          connectivity_.peerIsWritable(ctx, true);
        });

    // Remote messages are announced in heartbeat batches (see onHeartbeat);
    // only our own publishes announce themselves immediately.
    if (is_published_locally) {
      auto peers = subscribed_peers_.selectRandomPeers(kDLazy);
      for (const auto &ctx : peers) {
        assert(ctx->message_builder);

        if (needToForward(ctx, from, origin)) {
          ctx->message_builder->addIHave(topic_, msg_id);
          connectivity_.peerIsWritable(ctx, true);
        }
      }
    }

    seen_cache_.emplace_back(now + config_.seen_cache_lifetime_msec, msg_id);

    log_.debug("message forwarded, topic={}, m={}, s={}",
               topic_,
               mesh_peers_.size(),
               subscribed_peers_.size());
  }

  void TopicSubscriptions::onHeartbeat(Time now) {
    if (self_subscribed_) {
      log_.debug("heartbeat: topic={} mesh={} subscribed={} backoff={}",
                 topic_, mesh_peers_.size(), subscribed_peers_.size(), dont_bother_until_.size());
    }
    if (self_subscribed_ && !subscribed_peers_.empty()) {
      // add/remove mesh members according to desired network density D
      size_t sz = mesh_peers_.size();

      // drop expired backoffs so they stop shadowing candidates
      for (auto it = dont_bother_until_.begin();
           it != dont_bother_until_.end();) {
        it = (it->second < now) ? dont_bother_until_.erase(it) : std::next(it);
      }

      if (sz < config_.D_min && curationEnabled()) {
        // Grow toward the spec target D, at most kGraftPerHeartbeat per
        // beat (staggered — hammering GRAFTs draws P7 penalties at
        // remotes), picking the best-ranked deliverers instead of random.
        std::vector<PeerContextPtr> candidates;
        subscribed_peers_.selectIf(
            [&candidates](const PeerContextPtr &p) { candidates.push_back(p); },
            [this](const PeerContextPtr &p) {
              return dont_bother_until_.find(p) == dont_bother_until_.end();
            });
        std::sort(candidates.begin(), candidates.end(),
                  [](const PeerContextPtr &a, const PeerContextPtr &b) {
                    return deliveryRank(a) > deliveryRank(b);
                  });
        const size_t need = std::min(
            kGraftPerHeartbeat, kMeshTarget > sz ? kMeshTarget - sz : 0);
        for (size_t i = 0; i < need && i < candidates.size(); ++i) {
          auto &p = candidates[i];
          log_.info("[mesh-curation] graft peer={} first={} lag_ms={} topic={}",
                    p->str, p->first_msg_deliveries,
                    static_cast<int64_t>(p->delivery_lag_ewma_ms), topic_);
          addToMesh(p);
          subscribed_peers_.erase(p->peer_id);
        }
      } else if (sz < config_.D_min) {
        auto peers = subscribed_peers_.selectRandomPeers(config_.D_min - sz);
        for (auto &p : peers) {
          auto it = dont_bother_until_.find(p);
          if (it != dont_bother_until_.end()) {
            if (it->second < now) {
              dont_bother_until_.erase(it);
            } else {
              continue;
            }
          }

          addToMesh(p);
          subscribed_peers_.erase(p->peer_id);
        }
      } else if (sz > config_.D_max && curationEnabled()) {
        // Prune worst deliverers back to the spec target, never the peers
        // that actually win delivery races; pruned peers get a backoff so
        // we don't re-graft them next beat.
        auto all_mesh = mesh_peers_.selectRandomPeers(sz);
        std::sort(all_mesh.begin(), all_mesh.end(),
                  [](const PeerContextPtr &a, const PeerContextPtr &b) {
                    return deliveryRank(a) < deliveryRank(b);
                  });
        const size_t to_prune = sz - kMeshTarget;
        for (size_t i = 0; i < to_prune && i < all_mesh.size(); ++i) {
          auto &p = all_mesh[i];
          log_.info("[mesh-curation] prune peer={} first={} lag_ms={} topic={}",
                    p->str, p->first_msg_deliveries,
                    static_cast<int64_t>(p->delivery_lag_ewma_ms), topic_);
          dont_bother_until_[p] = now + kPruneBackoff;
          removeFromMesh(p);
          mesh_peers_.erase(p->peer_id);
        }
      } else if (sz > config_.D_max) {
        // Prune lowest-scored peers (P1: TimeInMesh) instead of random
        auto all_mesh = mesh_peers_.selectRandomPeers(sz);  // get all
        std::sort(all_mesh.begin(), all_mesh.end(),
            [this, &now](const PeerContextPtr &a, const PeerContextPtr &b) {
              auto a_it = a->mesh_since.find(topic_);
              auto b_it = b->mesh_since.find(topic_);
              Time a_time = (a_it != a->mesh_since.end()) ? (now - a_it->second) : Time{0};
              Time b_time = (b_it != b->mesh_since.end()) ? (now - b_it->second) : Time{0};
              return a_time < b_time;  // lowest time first
            });
        size_t to_prune = sz - config_.D_max;
        for (size_t i = 0; i < to_prune && i < all_mesh.size(); ++i) {
          removeFromMesh(all_mesh[i]);
          mesh_peers_.erase(all_mesh[i]->peer_id);
        }
      }
    }

    // Spec gossip emission: once per heartbeat announce the message ids
    // seen in the last kGossipWindows heartbeats to kDLazy random non-mesh
    // subscribers, batched into one control message per peer (the old
    // per-message announce built 24 IHAVE entries per message on the hot
    // thread). seen_cache_ stores expiry = seen_at + seen_cache_lifetime.
    if (self_subscribed_ && !subscribed_peers_.empty() && !seen_cache_.empty()) {
      const Time min_expiry = now + config_.seen_cache_lifetime_msec
          - Time{kGossipWindows * config_.heartbeat_interval_msec};
      std::vector<MessageId> recent;
      for (auto it = seen_cache_.rbegin();
           it != seen_cache_.rend() && recent.size() < kMaxIHavePerBeat;
           ++it) {
        if (it->first < min_expiry) {
          break;
        }
        recent.push_back(it->second);
      }
      if (!recent.empty()) {
        auto gossip_peers = subscribed_peers_.selectRandomPeers(kDLazy);
        for (const auto &ctx : gossip_peers) {
          assert(ctx->message_builder);
          for (const auto &mid : recent) {
            ctx->message_builder->addIHave(topic_, mid);
          }
          connectivity_.peerIsWritable(ctx, false);
        }
      }
    }

    // Latency-aware opportunistic swap (beacon_block only): once per
    // ~kSwapPeriodBeats, if a non-mesh peer demonstrably out-delivers the
    // worst mesh member, swap them. No production client selects mesh
    // members by measured delivery latency — this is the task #80 lever.
    if (self_subscribed_ && curationEnabled() && isBeaconBlockTopicId(topic_)
        && ++heartbeat_count_ % kSwapPeriodBeats == 0
        && mesh_peers_.size() >= config_.D_min) {
      PeerContextPtr worst, best;
      mesh_peers_.selectAll([&worst](const PeerContextPtr &p) {
        if (!worst || deliveryRank(p) < deliveryRank(worst)) worst = p;
      });
      subscribed_peers_.selectIf(
          [&best](const PeerContextPtr &p) {
            if (!best || deliveryRank(p) > deliveryRank(best)) best = p;
          },
          [this](const PeerContextPtr &p) {
            return dont_bother_until_.find(p) == dont_bother_until_.end();
          });
      if (worst && best && best->first_msg_deliveries > 0
          && (worst->first_msg_deliveries == 0
              || deliveryRank(best) > deliveryRank(worst) + 500.0)) {
        log_.info(
            "[mesh-curation] swap out={} (first={} lag_ms={}) in={} (first={} lag_ms={})",
            worst->str, worst->first_msg_deliveries,
            static_cast<int64_t>(worst->delivery_lag_ewma_ms), best->str,
            best->first_msg_deliveries,
            static_cast<int64_t>(best->delivery_lag_ewma_ms));
        dont_bother_until_[worst] = now + kPruneBackoff;
        removeFromMesh(worst);
        mesh_peers_.erase(worst->peer_id);
        addToMesh(best);
        subscribed_peers_.erase(best->peer_id);
      }
    }

    // fanout ends some time after this host ends publishing to the topic,
    // to save space and traffic
    if (fanout_period_ends_ != Time::zero() && fanout_period_ends_ < now) {
      fanout_period_ends_ = Time::zero();
      log_.debug("fanout period reset for {}", topic_);
    }

    // shift msg ids cache
    auto seen_cache_size = seen_cache_.size();
    bool changed = false;

    if (seen_cache_size > config_.seen_cache_limit) {
      auto b = seen_cache_.begin();
      auto e = b + ssize_t(seen_cache_size - config_.seen_cache_limit);
      seen_cache_.erase(b, e);
      changed = true;
    } else if (seen_cache_size != 0) {
      auto it = std::find_if(seen_cache_.begin(),
                             seen_cache_.end(),
                             [now](const auto &p) { return p.first >= now; });
      if (it != seen_cache_.begin()) {
        seen_cache_.erase(seen_cache_.begin(), it);
        changed = true;
      }
    }

    if (changed) {
      log_.debug("seen cache size changed {}->{} for {}",
                 seen_cache_size,
                 seen_cache_.size(),
                 topic_);
    }
  }

  void TopicSubscriptions::onSelfSubscribed(bool self_subscribed) {
    self_subscribed_ = self_subscribed;
    if (!self_subscribed_) {
      // remove the mesh
      log_.debug("removing mesh for {}", topic_);
      mesh_peers_.selectAll(
          [this](const PeerContextPtr &p) { removeFromMesh(p); });
      mesh_peers_.clear();
    }
  }

  void TopicSubscriptions::onPeerSubscribed(const PeerContextPtr &p) {
    assert(p->subscribed_to.count(topic_) != 0);

    // Immediately GRAFT when mesh needs peers — don't wait for heartbeat.
    // This prevents a dead state where mesh_peers_ is empty and the heartbeat
    // skips repair because subscribed_peers_ was also empty when it last ran.
    // BUT: respect the backoff list to avoid BehaviourPenalty from peers
    // who recently pruned us (gossipsub v1.1 anti-flood).
    if (self_subscribed_ && mesh_peers_.size() < config_.D_min) {
      auto it = dont_bother_until_.find(p);
      if (it == dont_bother_until_.end()) {
        addToMesh(p);
      } else {
        subscribed_peers_.insert(p);
      }
    } else {
      subscribed_peers_.insert(p);
    }

    // announce the peer about messages available for the topic
    for (const auto &[_, msg_id] : seen_cache_) {
      p->message_builder->addIHave(topic_, msg_id);
    }
    connectivity_.peerIsWritable(p, false);
  }

  void TopicSubscriptions::onPeerUnsubscribed(const PeerContextPtr &p) {
    auto res = subscribed_peers_.erase(p->peer_id);
    if (!res) {
      res = mesh_peers_.erase(p->peer_id);
    }
    dont_bother_until_.erase(p);
  }

  void TopicSubscriptions::onGraft(const PeerContextPtr &p) {
    auto res = mesh_peers_.find(p->peer_id);
    if (res) {
      // already there
      return;
    }

    if (!subscribed_peers_.contains(p->peer_id)) {
      // subscribe first
      p->subscribed_to.insert(topic_);
      onPeerSubscribed(p);
    }

    if (curationEnabled()) {
      auto bo = dont_bother_until_.find(p);
      if (bo != dont_bother_until_.end() && bo->second > scheduler_.now()) {
        // GRAFT before the backoff we gave them expired: behaviour penalty
        // (gossipsub v1.1 P7) and refuse.
        p->behaviour_penalty += 1.0;
        log_.info("[mesh-curation] GRAFT within backoff from {} (P7={})",
                  p->str, p->behaviour_penalty);
        p->message_builder->addPrune(topic_, kPruneBackoffSec);
        connectivity_.peerIsWritable(p, true);
        return;
      }
    }

    bool mesh_is_full = (mesh_peers_.size() >= config_.D_max);

    if (self_subscribed_ && !mesh_is_full) {
      mesh_peers_.insert(p);
      subscribed_peers_.erase(p->peer_id);
      log_.info("accepted GRAFT from peer {} (mesh size={}) for topic {}",
                p->str, mesh_peers_.size(), topic_);
    } else {
      // we don't have mesh for the topic or mesh is full
      log_.info("rejecting GRAFT from peer {} (self_sub={}, mesh={}/{}) for topic {}",
                p->str, self_subscribed_, mesh_peers_.size(), config_.D_max, topic_);
      p->message_builder->addPrune(topic_, kPruneBackoffSec);
      connectivity_.peerIsWritable(p, true);
    }
  }

  void TopicSubscriptions::onPrune(const PeerContextPtr &p,
                                   Time dont_bother_until) {
    bool was_in_mesh = mesh_peers_.erase(p->peer_id).has_value();
    if (p->subscribed_to.count(topic_) != 0) {
      subscribed_peers_.insert(p);
      dont_bother_until_.insert({p, dont_bother_until});
    }
    log_.info("onPrune: peer {} was_in_mesh={} (mesh={}, subscribed={}, backoff_until={}ms) for topic {}",
              p->str, was_in_mesh, mesh_peers_.size(), subscribed_peers_.size(),
              dont_bother_until.count(), topic_);
  }

  void TopicSubscriptions::addToMesh(const PeerContextPtr &p) {
    assert(p->message_builder);

    p->message_builder->addGraft(topic_);
    connectivity_.peerIsWritable(p, false);
    mesh_peers_.insert(p);
    p->mesh_since[topic_] = scheduler_.now();
    log_.info("peer {} added to mesh (size={}) for topic {}",
              p->str,
              mesh_peers_.size(),
              topic_);
  }

  void TopicSubscriptions::removeFromMesh(const PeerContextPtr &p) {
    assert(p->message_builder);

    p->message_builder->addPrune(topic_, kPruneBackoffSec);
    connectivity_.peerIsWritable(p, false);
    p->mesh_since.erase(topic_);
    subscribed_peers_.insert(p);
    log_.info("peer {} removed from mesh (size={}) for topic {}",
              p->str,
              mesh_peers_.size(),
              topic_);
  }

}  // namespace libp2p::protocol::gossip
