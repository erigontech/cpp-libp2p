/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "seen_ids.hpp"

#include <algorithm>

namespace libp2p::protocol::gossip {

  SeenIds::SeenIds(Time ttl, size_t max_ids)
      : ttl_(ttl),
        bucket_span_(std::max(ttl / static_cast<Time::rep>(kBuckets), Time{1})),
        max_ids_(ttl > Time::zero() ? max_ids : 0) {}

  bool SeenIds::contains(const MessageId &id) const {
    return ids_.contains(id);
  }

  bool SeenIds::insert(const MessageId &id, Time now) {
    if (max_ids_ == 0) {
      return false;
    }
    const auto [it, inserted] = ids_.insert(id);
    if (!inserted) {
      return false;
    }
    if (buckets_.empty() || now - buckets_.back().since >= bucket_span_) {
      buckets_.push_back({now, {}});
    }
    buckets_.back().ids.push_back(&*it);
    while (ids_.size() > max_ids_) {
      dropOldest();
    }
    return true;
  }

  void SeenIds::expire(Time now) {
    while (!buckets_.empty()
           && now - buckets_.front().since >= ttl_ + bucket_span_) {
      dropOldest();
    }
  }

  size_t SeenIds::size() const {
    return ids_.size();
  }

  void SeenIds::dropOldest() {
    for (const auto *id : buckets_.front().ids) {
      ids_.erase(ids_.find(*id));
    }
    buckets_.pop_front();
  }

}  // namespace libp2p::protocol::gossip
