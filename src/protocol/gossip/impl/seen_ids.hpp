/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstddef>
#include <deque>
#include <unordered_set>
#include <vector>

#include "common.hpp"

namespace libp2p::protocol::gossip {

  /// The IDs of the messages seen in the last ttl (gossipsub seen_ttl),
  /// without the messages: a copy of one is a duplicate also once the message
  /// cache dropped it. The IDs go into kBuckets time buckets of ttl /
  /// kBuckets, each dropped whole once its newest ID is ttl old, so that an ID
  /// is kept for ttl at least and a kBuckets-th of it more at most. At most
  /// max_ids are kept: past them the oldest bucket is dropped first
  class SeenIds {
   public:
    static constexpr size_t kBuckets = 64;

    /// A ttl or max_ids of 0 keeps none
    SeenIds(Time ttl, size_t max_ids);

    bool contains(const MessageId &id) const;

    /// Records the ID of a message seen at now, false if it was already
    bool insert(const MessageId &id, Time now);

    /// Drops the buckets whose IDs are all ttl old at now
    void expire(Time now);

    size_t size() const;

   private:
    struct Bucket {
      /// When its first ID was seen
      Time since;
      /// Its IDs, which ids_ holds: their addresses are stable
      std::vector<const MessageId *> ids;
    };

    void dropOldest();

    const Time ttl_;
    const Time bucket_span_;
    const size_t max_ids_;
    std::unordered_set<MessageId> ids_;
    std::deque<Bucket> buckets_;
  };

}  // namespace libp2p::protocol::gossip
