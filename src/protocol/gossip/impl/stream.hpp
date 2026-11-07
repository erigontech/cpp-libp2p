/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <deque>
#include <optional>

#include <libp2p/basic/scheduler.hpp>
#include <libp2p/common/metrics/instance_count.hpp>
#include <libp2p/connection/stream.hpp>
#include <libp2p/multi/uvarint.hpp>

#include "common.hpp"

namespace libp2p::protocol::gossip {

  class MessageReceiver;

  /// Reads/writes RPC messages from/to connected stream
  class Stream : public std::enable_shared_from_this<Stream> {
   public:
    /// Feedback interface to its owning object (i.e. pub-sub instance)
    using Feedback = std::function<void(PeerContextPtr from,
                                        outcome::result<Success> event)>;

    /// The writes of answers to IWANTs (silkworm #227): all, those that ended
    /// past Config::iwant_followup_msec from the IWANT, and the latest
    struct AnswerStats {
      uint64_t written = 0;
      uint64_t late = 0;
      uint64_t max_ms = 0;
    };

    /// Ctor. N.B. Stream instance cannot live longer than its creators
    /// by design, so dependencies are stored by reference.
    /// Also, peer is passed separately because it cannot be fetched from stream
    /// once the stream is dead. The writes of answers are counted in \p
    /// answers, if any
    Stream(size_t stream_id,
           const Config &config,
           basic::Scheduler &scheduler,
           const Feedback &feedback,
           MessageReceiver &msg_receiver,
           std::shared_ptr<connection::Stream> stream,
           PeerContextPtr peer,
           AnswerStats *answers = nullptr);

    /// Begins reading messages from stream
    void read();

    /// Writes an outgoing message to stream, if there is serialization error
    /// it will be posted in asynchronous manner
    void write(outcome::result<SharedBuffer> serialization_res);

    /// Writes the answers to the peer's IWANTs, the first of them received at
    /// \p requested, ahead of the messages waiting, after the write in
    /// progress: the peer counts a broken promise (P7) for an answer that
    /// comes past its followup time (silkworm #227)
    void writeAnswers(outcome::result<SharedBuffer> serialization_res,
                      Time requested);

    /// Closes the reader so that it will ignore further bytes from wire
    void close();

    /// Something was written to the stream, or is being: its first message,
    /// which opens it, is out
    bool begun() const {
      return begun_;
    }

    /// Bytes written and waiting to be written (silkworm #149)
    size_t backlogBytes() const {
      return writing_bytes_ + pending_bytes_;
    }

    /// How long the bytes written and waiting take to drain at \p now, at the
    /// rate the writes completed so far (kDefaultBytesPerMs before any), and
    /// no less than the write in progress has already taken (silkworm #227)
    Time drainTime(Time now) const;

    /// The rate assumed before a write completed: about 1 MB/s
    static constexpr double kDefaultBytesPerMs = 1024.0;

   private:
    /// A message to write, an answer to an IWANT received at requested
    struct Pending {
      SharedBuffer buffer;
      std::optional<Time> requested;
    };

    void enqueue(outcome::result<SharedBuffer> serialization_res,
                 std::optional<Time> requested);
    void onLengthRead(outcome::result<multi::UVarint> varint);
    void onMessageRead(outcome::result<void> res);
    void beginWrite(Pending pending);
    void onMessageWritten(outcome::result<void> res);
    /// Counts the write that ended at \p now in the rate and the answers
    void countWrite(Time now);
    void endWrite();
    void asyncPostError(Error error);

    [[maybe_unused]] const size_t stream_id_;
    const Time timeout_;
    const Time iwant_followup_;
    basic::Scheduler &scheduler_;
    const size_t max_message_size_;
    const Feedback &feedback_;
    MessageReceiver &msg_receiver_;
    std::shared_ptr<connection::Stream> stream_;
    PeerContextPtr peer_;
    AnswerStats *answers_;

    /// The messages waiting, the answers to IWANTs first: answers_waiting_ of
    /// them
    std::deque<Pending> pending_buffers_;
    size_t answers_waiting_ = 0;

    /// Number of bytes being awaited in active wrote operation
    size_t writing_bytes_ = 0;

    // TODO(artem): limit pending bytes and close slow streams that way
    size_t pending_bytes_ = 0;

    /// The write in progress: when it began, and when the IWANT it answers
    /// came, if one
    Time write_began_{0};
    std::optional<Time> writing_requested_;
    bool begun_ = false;

    /// The bytes of the writes completed and their time, each sum decayed by
    /// kRateDecay a write: the rate of the drainTime estimate
    static constexpr double kRateDecay = 0.9;
    double rate_bytes_ = 0;
    double rate_ms_ = 0;

    std::shared_ptr<Bytes> read_buffer_;
    /// Dont send feedback or schedule writes anymore
    bool closed_ = false;

    bool reading_ = false;

    /// Messages read from the stream: the first one carries the peer's
    /// Extensions control message (gossipsub v1.3)
    size_t messages_read_ = 0;

    /// Handle for current operation timeout guard
    basic::Scheduler::Handle timeout_handle_;

   public:
    LIBP2P_METRICS_INSTANCE_COUNT_IF_ENABLED(libp2p::protocol::gossip::Stream);
  };

}  // namespace libp2p::protocol::gossip
