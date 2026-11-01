/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "src/protocol/gossip/impl/message_builder.hpp"
#include "src/protocol/gossip/impl/message_parser.hpp"
#include "src/protocol/gossip/impl/message_receiver.hpp"
#include "src/protocol/gossip/impl/partial_messages.hpp"
#include "src/protocol/gossip/impl/peer_context.hpp"

#include <gtest/gtest.h>

#include <libp2p/multi/uvarint.hpp>

#include "testutil/libp2p/peer.hpp"

namespace g = libp2p::protocol::gossip;

using libp2p::Bytes;

namespace {

  /// Records what the parser dispatches
  struct Recorder : g::MessageReceiver {
    struct Extensions {
      std::optional<g::PeerExtensions> extensions;
      bool first_on_stream;
    };
    std::vector<Extensions> extensions;
    std::vector<std::pair<g::TopicId, g::PartialTopicOptions>>
        partial_subscriptions;
    std::vector<std::pair<bool, g::TopicId>> subscriptions;
    std::vector<g::PartialMessage> partials;
    size_t ends = 0;

    void onExtensions(const g::PeerContextPtr &,
                      const std::optional<g::PeerExtensions> &ext,
                      bool first_on_stream) override {
      extensions.push_back({ext, first_on_stream});
    }
    void onPartialSubscription(const g::PeerContextPtr &,
                               const g::TopicId &topic,
                               g::PartialTopicOptions options) override {
      partial_subscriptions.emplace_back(topic, options);
    }
    void onSubscription(const g::PeerContextPtr &,
                        bool subscribe,
                        const g::TopicId &topic) override {
      subscriptions.emplace_back(subscribe, topic);
    }
    void onIHave(const g::PeerContextPtr &,
                 const g::TopicId &,
                 const g::MessageId &) override {}
    void onIWant(const g::PeerContextPtr &, const g::MessageId &) override {}
    void onIDontWant(const g::PeerContextPtr &, const g::MessageId &) override {
    }
    void onGraft(const g::PeerContextPtr &, const g::TopicId &) override {}
    void onPrune(const g::PeerContextPtr &,
                 const g::TopicId &,
                 uint64_t) override {}
    void onPrunePeerExchange(const g::PeerContextPtr &,
                             const libp2p::peer::PeerId &) override {}
    void onTopicMessage(const g::PeerContextPtr &,
                        g::TopicMessage::Ptr) override {}
    void onPartialMessage(const g::PeerContextPtr &,
                          g::PartialMessage msg) override {
      partials.push_back(std::move(msg));
    }
    void onMessageEnd(const g::PeerContextPtr &) override {
      ++ends;
    }
  };

  /// The length-prefixed messages of a serialized buffer
  std::vector<Bytes> frames(const Bytes &buffer) {
    std::vector<Bytes> out;
    libp2p::BytesIn rest{buffer};
    while (!rest.empty()) {
      auto varint = libp2p::multi::UVarint::create(rest);
      EXPECT_TRUE(varint);
      if (!varint) {
        break;
      }
      const auto size = varint->toUInt64();
      rest = rest.subspan(varint->size());
      EXPECT_LE(size, rest.size());
      out.emplace_back(rest.begin(), rest.begin() + size);
      rest = rest.subspan(size);
    }
    return out;
  }

  /// Serializes \p builder and dispatches its messages to \p recorder, the
  /// first one as the first of its stream
  void deliver(g::MessageBuilder &builder,
               const g::PeerContextPtr &from,
               Recorder &recorder,
               size_t expected_frames) {
    auto serialized = builder.serialize();
    ASSERT_TRUE(serialized);
    const auto messages = frames(*serialized.value());
    ASSERT_EQ(messages.size(), expected_frames);
    bool first = true;
    for (const auto &message : messages) {
      g::MessageParser parser;
      ASSERT_TRUE(parser.parse(message));
      parser.dispatch(from, recorder, first);
      first = false;
    }
  }

  Bytes bytes(std::string_view s) {
    return Bytes(s.begin(), s.end());
  }

}  // namespace

/**
 * @given A subscription with partial options, the Extensions control message
 * and three partial messages RPCs
 * @when Serializing them and parsing what was serialized
 * @then The options, the extensions and the partial messages are read back:
 * requesting partial messages implies supporting them, the first partial
 * message rides with the rest and the others go in messages of their own
 */
TEST(GossipPartialMessages, BuilderAndParserRoundTrip) {
  auto from = std::make_shared<g::PeerContext>(testutil::randomPeerId());

  g::MessageBuilder builder;
  builder.addExtensions(true);
  builder.addSubscription(true, "columns", {.requests_partial = true});
  builder.addSubscription(true, "blocks");
  builder.addSubscription(true, "sidecars", {.supports_sending_partial = true});
  // the options are meaningless when unsubscribing
  builder.addSubscription(false, "old", {.requests_partial = true});
  builder.addPartialMessage(
      "columns", bytes("group1"), bytes("cells"), bytes("meta"));
  builder.addPartialMessage("columns", bytes("group2"), {}, bytes("meta2"));
  builder.addPartialMessage("sidecars", bytes("group3"), bytes("cells3"), {});

  Recorder recorder;
  deliver(builder, from, recorder, 3);
  EXPECT_TRUE(builder.empty());

  ASSERT_EQ(recorder.extensions.size(), 1);
  ASSERT_TRUE(recorder.extensions[0].extensions);
  EXPECT_TRUE(recorder.extensions[0].extensions->partial_messages);
  EXPECT_TRUE(recorder.extensions[0].first_on_stream);

  ASSERT_EQ(recorder.subscriptions.size(), 4);
  ASSERT_EQ(recorder.partial_subscriptions.size(), 3);
  EXPECT_EQ(recorder.partial_subscriptions[0].first, "columns");
  EXPECT_TRUE(recorder.partial_subscriptions[0].second.requests_partial);
  EXPECT_TRUE(
      recorder.partial_subscriptions[0].second.supports_sending_partial);
  EXPECT_EQ(recorder.partial_subscriptions[1].first, "blocks");
  EXPECT_FALSE(recorder.partial_subscriptions[1].second.requests_partial);
  EXPECT_FALSE(
      recorder.partial_subscriptions[1].second.supports_sending_partial);
  EXPECT_EQ(recorder.partial_subscriptions[2].first, "sidecars");
  EXPECT_FALSE(recorder.partial_subscriptions[2].second.requests_partial);
  EXPECT_TRUE(
      recorder.partial_subscriptions[2].second.supports_sending_partial);

  ASSERT_EQ(recorder.partials.size(), 3);
  EXPECT_EQ(recorder.partials[0].from, from->peer_id);
  EXPECT_EQ(recorder.partials[0].topic, "columns");
  EXPECT_EQ(recorder.partials[0].group_id, bytes("group1"));
  EXPECT_EQ(recorder.partials[0].partial_message, bytes("cells"));
  EXPECT_EQ(recorder.partials[0].parts_metadata, bytes("meta"));
  EXPECT_EQ(recorder.partials[1].group_id, bytes("group2"));
  EXPECT_FALSE(recorder.partials[1].partial_message);
  EXPECT_EQ(recorder.partials[1].parts_metadata, bytes("meta2"));
  EXPECT_EQ(recorder.partials[2].topic, "sidecars");
  EXPECT_EQ(recorder.partials[2].partial_message, bytes("cells3"));
  EXPECT_FALSE(recorder.partials[2].parts_metadata);
  EXPECT_EQ(recorder.ends, 3);
}

/**
 * @given The Extensions control message, a subscription requesting partial
 * messages and a partial messages RPC
 * @when Serializing each alone
 * @then The bytes carry the field numbers of the libp2p/specs registry
 * (extensions.proto): ControlMessage.extensions 6 with partialMessages 10,
 * SubOpts.requestsPartial 3 and supportsSendingPartial 4, RPC.partial 10 with
 * topicID 1, groupID 2, partialMessage 3 and partsMetadata 4
 */
TEST(GossipPartialMessages, WireFormat) {
  auto serialize = [](g::MessageBuilder &builder) {
    auto serialized = builder.serialize();
    EXPECT_TRUE(serialized);
    return serialized ? *serialized.value() : Bytes{};
  };
  g::MessageBuilder builder;

  builder.addExtensions(true);
  // length 6, RPC.control{extensions{partialMessages: true}}
  EXPECT_EQ(serialize(builder),
            Bytes({0x06, 0x1a, 0x04, 0x32, 0x02, 0x50, 0x01}));

  builder.addSubscription(true, "t", {.requests_partial = true});
  // RPC.subscriptions{subscribe: true, topicid: "t", requestsPartial: true}
  EXPECT_EQ(serialize(builder),
            Bytes({0x09, 0x0a, 0x07, 0x08, 0x01, 0x12, 0x01, 't', 0x18, 0x01}));

  builder.addSubscription(true, "t", {.supports_sending_partial = true});
  // supportsSendingPartial: true
  EXPECT_EQ(serialize(builder),
            Bytes({0x09, 0x0a, 0x07, 0x08, 0x01, 0x12, 0x01, 't', 0x20, 0x01}));

  builder.addPartialMessage("t", bytes("g"), bytes("p"), bytes("m"));
  // RPC.partial{topicID: "t", groupID: "g", partialMessage: "p",
  // partsMetadata: "m"}
  // clang-format off
  const Bytes partial{0x0e, 0x52, 0x0c, 0x0a, 0x01, 't', 0x12, 0x01, 'g',
                      0x1a, 0x01, 'p', 0x22, 0x01, 'm'};
  // clang-format on
  EXPECT_EQ(serialize(builder), partial);
}

/**
 * @given Messages without the Extensions control message, and one with it
 * after the first message of the stream
 * @when Dispatching them
 * @then The first message of the stream reports no extensions, the later
 * Extensions control message is reported as not the first of its stream, and
 * the other messages report nothing
 */
TEST(GossipPartialMessages, ExtensionsOnlyInTheFirstMessage) {
  auto from = std::make_shared<g::PeerContext>(testutil::randomPeerId());
  Recorder recorder;

  g::MessageBuilder builder;
  builder.addSubscription(true, "blocks");
  deliver(builder, from, recorder, 1);
  ASSERT_EQ(recorder.extensions.size(), 1);
  EXPECT_FALSE(recorder.extensions[0].extensions);
  EXPECT_TRUE(recorder.extensions[0].first_on_stream);

  auto later = [&](g::MessageBuilder &b) {
    auto serialized = b.serialize();
    ASSERT_TRUE(serialized);
    for (const auto &message : frames(*serialized.value())) {
      g::MessageParser parser;
      ASSERT_TRUE(parser.parse(message));
      parser.dispatch(from, recorder, false);
    }
  };
  builder.addSubscription(true, "columns");
  later(builder);
  EXPECT_EQ(recorder.extensions.size(), 1);

  builder.addExtensions(true);
  later(builder);
  ASSERT_EQ(recorder.extensions.size(), 2);
  EXPECT_TRUE(recorder.extensions[1].extensions);
  EXPECT_FALSE(recorder.extensions[1].first_on_stream);
}

namespace {

  /// A peer that advertised the extension, and we to it, with the options
  /// of its subscription to \p topic
  g::PeerContextPtr partialPeer(const g::TopicId &topic,
                                g::PartialTopicOptions options) {
    auto peer = std::make_shared<g::PeerContext>(testutil::randomPeerId());
    peer->partial_messages = true;
    peer->partial_advertised = true;
    peer->partial_topics[topic] = options;
    return peer;
  }

}  // namespace

/**
 * @given The partial messages state with the extension on
 * @when Enabling topics and asking who gets parts and metadata
 * @then Requesting implies supporting; parts go to the peers that requested
 * them, metadata to those that support sending parts, and nothing goes to a
 * peer unless both sides advertised the extension, nor on a topic not
 * enabled
 */
TEST(GossipPartialMessages, TopicOptionsAndPeers) {
  g::Config config;
  g::PartialMessages off(config);
  EXPECT_FALSE(off.setTopicOptions("columns", {.requests_partial = true}, {}));
  EXPECT_FALSE(off.topicOptions("columns"));

  config.partial_messages = true;
  g::PartialMessages partial(config);
  EXPECT_TRUE(partial.setTopicOptions(
      "columns", {.requests_partial = true}, g::Time{5}));
  EXPECT_FALSE(partial.setTopicOptions(
      "columns", {.requests_partial = true}, g::Time{6}));
  ASSERT_TRUE(partial.topicOptions("columns"));
  EXPECT_TRUE(partial.topicOptions("columns")->supports_sending_partial);
  EXPECT_EQ(partial.optionsChangedAt("columns"), g::Time{5});
  EXPECT_TRUE(partial.announced("columns").requests_partial);
  EXPECT_FALSE(partial.announced("blocks").supports_sending_partial);

  auto requester = partialPeer("columns", {true, true});
  auto supporter = partialPeer("columns", {false, true});
  auto plain = std::make_shared<g::PeerContext>(testutil::randomPeerId());
  auto silent = partialPeer("columns", {true, true});
  silent->partial_messages = false;
  // we did not advertise it to this one (its stream negotiated 1.2)
  auto unadvertised = partialPeer("columns", {true, true});
  unadvertised->partial_advertised = false;

  EXPECT_TRUE(partial.sendsPartialTo(*requester, "columns"));
  EXPECT_FALSE(partial.sendsPartialTo(*supporter, "columns"));
  EXPECT_FALSE(partial.sendsPartialTo(*plain, "columns"));
  EXPECT_FALSE(partial.sendsPartialTo(*silent, "columns"));
  EXPECT_FALSE(partial.sendsPartialTo(*unadvertised, "columns"));
  EXPECT_FALSE(partial.exchangesWith(*unadvertised, "columns"));
  EXPECT_FALSE(partial.sendsPartialTo(*requester, "blocks"));

  // we requested: we exchange with those that send parts too
  EXPECT_TRUE(partial.exchangesWith(*requester, "columns"));
  EXPECT_TRUE(partial.exchangesWith(*supporter, "columns"));
  EXPECT_FALSE(partial.exchangesWith(*plain, "columns"));
  EXPECT_TRUE(partial.mayReceiveMetadata(*supporter, "columns"));
  EXPECT_FALSE(partial.mayReceiveParts(*supporter, "columns"));
  EXPECT_FALSE(partial.mayReceiveMetadata(*plain, "columns"));

  // supporting only: only the requesters exchange with us
  EXPECT_TRUE(partial.setTopicOptions(
      "columns", {.supports_sending_partial = true}, g::Time{7}));
  EXPECT_TRUE(partial.exchangesWith(*requester, "columns"));
  EXPECT_FALSE(partial.exchangesWith(*supporter, "columns"));

  // disabled: its groups go too
  ASSERT_TRUE(partial.group("columns", bytes("g"), std::nullopt));
  EXPECT_TRUE(partial.setTopicOptions("columns", {}, g::Time{8}));
  EXPECT_FALSE(partial.topicOptions("columns"));
  EXPECT_FALSE(partial.groups("columns"));
  EXPECT_FALSE(partial.group("columns", bytes("g"), std::nullopt));
}

/**
 * @given A topic enabled with low limits on the groups peers open
 * @when Peers open groups, we publish in one, a peer disconnects
 * @then A peer cannot open more than its share nor the peers more than the
 * topic's; a group we publish in, or opened by a peer gone, no longer counts
 */
TEST(GossipPartialMessages, PeerGroupLimits) {
  g::Config config;
  config.partial_messages = true;
  config.partial_peer_groups_per_topic = 3;
  config.partial_peer_groups_per_topic_per_peer = 2;
  g::PartialMessages partial(config);
  ASSERT_TRUE(partial.setTopicOptions("t", {.requests_partial = true}, {}));

  const auto a = testutil::randomPeerId();
  const auto b = testutil::randomPeerId();
  EXPECT_TRUE(partial.group("t", bytes("a1"), a));
  EXPECT_TRUE(partial.group("t", bytes("a2"), a));
  EXPECT_FALSE(partial.group("t", bytes("a3"), a));
  // a group already open is not counted again
  EXPECT_TRUE(partial.group("t", bytes("a1"), a));
  EXPECT_TRUE(partial.group("t", bytes("a1"), b));
  EXPECT_TRUE(partial.group("t", bytes("b1"), b));
  // the topic's share is taken
  EXPECT_FALSE(partial.group("t", bytes("b2"), b));
  // not on a topic not enabled
  EXPECT_FALSE(partial.group("u", bytes("a1"), a));

  // we publish in a1: a may open another
  auto *ours = partial.group("t", bytes("a1"), std::nullopt);
  ASSERT_TRUE(ours);
  EXPECT_TRUE(ours->published);
  EXPECT_FALSE(ours->counted_for);
  EXPECT_TRUE(partial.group("t", bytes("a3"), a));

  // b is gone: its group counts no longer
  partial.group("t", bytes("b1"), b)->peers[b];
  partial.onPeerDisconnected(b);
  EXPECT_TRUE(partial.group("t", bytes("b1"), std::nullopt)->peers.empty());
  EXPECT_TRUE(partial.group("t", bytes("c1"), testutil::randomPeerId()));
}

/**
 * @given Groups of an enabled topic with a lifetime of 2 heartbeats
 * @when Heartbeats pass, with and without activity in a group
 * @then A group lives 2 heartbeats after its last message, sent or received
 */
TEST(GossipPartialMessages, GroupsExpire) {
  g::Config config;
  config.partial_messages = true;
  config.partial_group_ttl_heartbeats = 2;
  g::PartialMessages partial(config);
  ASSERT_TRUE(partial.setTopicOptions("t", {.requests_partial = true}, {}));

  const auto peer = testutil::randomPeerId();
  ASSERT_TRUE(partial.group("t", bytes("idle"), peer));
  ASSERT_TRUE(partial.group("t", bytes("busy"), std::nullopt));
  partial.onHeartbeat();
  ASSERT_TRUE(partial.group("t", bytes("busy"), std::nullopt));
  partial.onHeartbeat();
  ASSERT_TRUE(partial.groups("t"));
  EXPECT_EQ(partial.groups("t")->size(), 1);
  EXPECT_TRUE(partial.groups("t")->contains(bytes("busy")));
  partial.onHeartbeat();
  EXPECT_FALSE(partial.groups("t"));
}

/**
 * @given A group we published in, one a peer opened, and peers gossip picked
 * @when Taking the gossip emissions
 * @then The peers not yet in our group join it and are emitted once; the
 * group the peer opened is not gossiped
 */
TEST(GossipPartialMessages, GossipToOurGroups) {
  g::Config config;
  config.partial_messages = true;
  g::PartialMessages partial(config);
  ASSERT_TRUE(partial.setTopicOptions("t", {.requests_partial = true}, {}));

  const auto known = testutil::randomPeerId();
  const auto fresh = testutil::randomPeerId();
  partial.group("t", bytes("ours"), std::nullopt)->peers[known];
  ASSERT_TRUE(partial.group("t", bytes("theirs"), known));

  partial.addGossipPeer("t", known);
  partial.addGossipPeer("t", fresh);
  partial.addGossipPeer("u", fresh);
  auto emissions = partial.takeGossip();
  ASSERT_EQ(emissions.size(), 1);
  EXPECT_EQ(emissions[0].topic, "t");
  EXPECT_EQ(emissions[0].group_id, bytes("ours"));
  ASSERT_EQ(emissions[0].peers.size(), 1);
  EXPECT_EQ(emissions[0].peers[0], fresh);
  EXPECT_TRUE(
      partial.group("t", bytes("ours"), std::nullopt)->peers.contains(fresh));

  partial.addGossipPeer("t", fresh);
  EXPECT_TRUE(partial.takeGossip().empty());
}
