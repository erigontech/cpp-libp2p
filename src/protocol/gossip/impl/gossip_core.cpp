/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gossip_core.hpp"

#include <algorithm>
#include <cassert>
#include <utility>

#include <libp2p/crypto/crypto_provider.hpp>
#include <libp2p/crypto/key_marshaller.hpp>
#include <libp2p/network/connection_manager.hpp>
#include <libp2p/peer/identity_manager.hpp>
#include <libp2p/protocol/identify/agent_versions.hpp>
#include <qtils/hex.hpp>

#include "connectivity.hpp"
#include "local_subscriptions.hpp"
#include "message_builder.hpp"
#include "remote_subscriptions.hpp"

namespace libp2p::protocol::gossip {

  std::shared_ptr<Gossip> create(
      std::shared_ptr<basic::Scheduler> scheduler,
      std::shared_ptr<Host> host,
      std::shared_ptr<peer::IdentityManager> idmgr,
      std::shared_ptr<crypto::CryptoProvider> crypto_provider,
      std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller,
      Config config) {
    return std::make_shared<GossipCore>(std::move(config),
                                        std::move(scheduler),
                                        std::move(host),
                                        std::move(idmgr),
                                        std::move(crypto_provider),
                                        std::move(key_marshaller));
  }

  // clang-format off
  GossipCore::GossipCore(Config config,
                         std::shared_ptr<basic::Scheduler> scheduler,
                         std::shared_ptr<Host> host,
                         std::shared_ptr<peer::IdentityManager> idmgr,
                         std::shared_ptr<crypto::CryptoProvider> crypto_provider,
                         std::shared_ptr<crypto::marshaller::KeyMarshaller> key_marshaller)
      : config_(std::move(config)),
        create_message_id_([](const Bytes &from, const Bytes &seq,
                              const Bytes &data, const TopicId &){
          return createMessageId(from, seq, data);
        }),
        scheduler_(std::move(scheduler)),
        host_(std::move(host)),
        idmgr_(std::move(idmgr)),
        crypto_provider_(std::move(crypto_provider)),
        key_marshaller_(std::move(key_marshaller)),
        local_peer_id_(host_->getPeerInfo().id),
        msg_cache_(
            config_.message_cache_lifetime_msec,
            [sch = scheduler_] { return sch->now(); }
        ),
        seen_ids_(config_.seen_ttl_msec, config_.seen_ids_limit),
        local_subscriptions_(std::make_shared<LocalSubscriptions>(
            [this](bool subscribe, const TopicId &topic) {
              onLocalSubscriptionChanged(subscribe, topic);
            }
        )),
        partial_(config_),
        msg_seq_(scheduler_->now().count()),
        heartbeat_timer_(),
        log_("gossip", "Gossip", local_peer_id_.toBase58().substr(46)) {
    // Verbatim Lighthouse/rust-libp2p scoring. Global params only at
    // construction; per-topic params are installed lazily when topics are
    // seen (fork-digest-dependent names), see ensureTopicScoreParams.
    auto params = score::lighthouse_mainnet_params("", {});
    params.topics.clear();
    params.ip_colocation_factor_whitelist.insert(
        config_.ip_colocation_whitelist.begin(),
        config_.ip_colocation_whitelist.end());
    score_thresholds2_ = score::lighthouse_thresholds();
    peer_score2_ = std::make_shared<score::PeerScore>(std::move(params),
                                                     score_thresholds2_);
  }
  // clang-format on

  void GossipCore::addBootstrapPeer(
      const peer::PeerId &id, boost::optional<multi::Multiaddress> address) {
    if (started_) {
      connectivity_->addBootstrapPeer(id, address);
    }
    bootstrap_peers_[id] = std::move(address);
  }

  outcome::result<void> GossipCore::addBootstrapPeer(
      const std::string &address) {
    OUTCOME_TRY(ma, libp2p::multi::Multiaddress::create(address));
    auto peer_id_str = ma.getPeerId();
    if (!peer_id_str) {
      return multi::Multiaddress::Error::INVALID_INPUT;
    }
    OUTCOME_TRY(peer_id, peer::PeerId::fromBase58(*peer_id_str));
    addBootstrapPeer(peer_id, {std::move(ma)});
    return outcome::success();
  }

  void GossipCore::start() {
    if (started_) {
      log_.warn("already started");
      return;
    }

    // clang-format off
    connectivity_ = std::make_shared<Connectivity>(
        config_,
        scheduler_,
        host_,
        shared_from_this(),
        [this](bool connected, const PeerContextPtr &ctx) {
          onPeerConnection(connected, ctx);
        }
    );
    // clang-format on

    for (const auto &p : bootstrap_peers_) {
      connectivity_->addBootstrapPeer(p.first, p.second);
    }

    remote_subscriptions_ =
        std::make_shared<RemoteSubscriptions>(config_,
                                              *connectivity_,
                                              *scheduler_,
                                              peer_score2_,
                                              counters_,
                                              log_,
                                              &partial_);
    connectivity_->setPartialHooks(
        [this](const TopicId &topic) { return partial_.announced(topic); },
        [this](const PeerContextPtr &ctx) {
          for (const auto &[topic, _] : local_subscriptions_->subscribedTo()) {
            if (auto options = partial_.announced(topic);
                options.supports_sending_partial) {
              ctx->message_builder->addSubscription(true, topic, options);
              if (ctx->diag) {
                ++ctx->diag->view.subscriptions_tx;
              }
            }
          }
        });

    started_ = true;

    for (const auto &[topic, _] : local_subscriptions_->subscribedTo()) {
      remote_subscriptions_->onSelfSubscribed(true, topic);
    }

    setTimerHeartbeat();

    connectivity_->start();

    // A later connection may change a peer's direction or IPs (silkworm #84)
    new_connection_sub_ =
        host_->getBus()
            .getChannel<event::network::OnNewConnectionChannel>()
            .subscribe([weak_self{weak_from_this()}](
                           const std::weak_ptr<connection::CapableConnection>
                               &weak_connection) {
              auto self = weak_self.lock();
              auto connection = weak_connection.lock();
              if (!self || !self->started_ || !connection) {
                return;
              }
              auto peer_id = connection->remotePeer();
              if (!peer_id) {
                return;
              }
              if (auto ctx = self->connectivity_->getConnectedPeers().find(
                      peer_id.value())) {
                self->refreshConnectionInfo(ctx.value(), false);
              }
            });
  }

  void GossipCore::stop() {
    if (!started_) {
      return;
    }

    started_ = false;

    heartbeat_timer_.reset();
    new_connection_sub_.unsubscribe();

    // it closes all senders and receivers
    connectivity_->stop();

    remote_subscriptions_.reset();
    connectivity_.reset();
    pending_validations_.clear();
    held_.clear();

    local_subscriptions_->forwardEndOfSubscription();
  }

  void GossipCore::setValidator(const TopicId &topic, Validator validator) {
    assert(validator);
    setValidator(topic,
                 [validator{std::move(validator)}](const Bytes &from,
                                                   const Bytes &data) {
                   return validator(from, data) ? ValidationResult::kAccept
                                                : ValidationResult::kReject;
                 });
  }

  void GossipCore::setValidator(const TopicId &topic,
                                TriStateValidator validator) {
    assert(validator);
    auto sub = subscribe({topic}, [](const SubscriptionData &) {});
    validators_[topic] = {std::move(validator), {}, std::move(sub)};
  }

  void GossipCore::setAsyncValidator(const TopicId &topic,
                                     AsyncValidator validator) {
    assert(validator);
    auto sub = subscribe({topic}, [](const SubscriptionData &) {});
    validators_[topic] = {{}, std::move(validator), std::move(sub)};
  }

  void GossipCore::removeValidator(const TopicId &topic) {
    auto it = validators_.find(topic);
    if (it == validators_.end()) {
      return;
    }
    // Out of the map first: the last subscription of the topic leaves it as
    // it goes, which updates the meshes
    auto removed = std::move(it->second);
    validators_.erase(it);
  }

  bool GossipCore::isSubscribed(const TopicId &topic) const {
    return local_subscriptions_->subscribedTo().count(topic) != 0;
  }

  RouterCounters GossipCore::takeCounters() {
    if (remote_subscriptions_) {
      const auto silence = remote_subscriptions_->takeSilentMeshMembers(
          [](const TopicId &topic) {
            return topic.ends_with("/beacon_block/ssz_snappy");
          });
      counters_.block_mesh_silent = silence.silent;
      counters_.block_mesh_silent_announcing = silence.announcing;
      counters_.block_mesh_silent_mute = silence.mute;
      counters_.block_mesh_by_us = silence.by_us;
      counters_.block_mesh_by_them = silence.by_them;
      counters_.block_silent = silence.members;
      const auto envelope_silence =
          remote_subscriptions_->takeSilentMeshMembers(
              [](const TopicId &topic) {
                return topic.ends_with("/execution_payload/ssz_snappy");
              });
      counters_.envelope_mesh_silent = envelope_silence.silent;
      counters_.envelope_mesh_silent_announcing = envelope_silence.announcing;
      counters_.envelope_mesh_silent_mute = envelope_silence.mute;
      counters_.envelope_silent = envelope_silence.members;
    }
    return std::exchange(counters_, RouterCounters{});
  }

  void GossipCore::setMessageIdFn(MessageIdFn fn) {
    assert(fn);
    create_message_id_ = std::move(fn);
  }

  Subscription GossipCore::subscribe(TopicSet topics,
                                     SubscriptionCallback callback) {
    assert(callback);
    assert(!topics.empty());

    return local_subscriptions_->subscribe(std::move(topics),
                                           std::move(callback));
  }

  bool GossipCore::publish(TopicId topic, Bytes data) {
    if (!started_) {
      return false;
    }

    // StrictNoSign (eth2): no author fields at all, the receivers reject a
    // message with any of them as invalid
    TopicMessage::Ptr msg;
    if (config_.strict_no_sign) {
      msg = std::make_shared<TopicMessage>(Bytes{}, Bytes{}, std::move(data));
      msg->topic = std::move(topic);
    } else {
      msg = std::make_shared<TopicMessage>(
          local_peer_id_, ++msg_seq_, std::move(data), std::move(topic));
    }

    if (config_.sign_messages && !config_.strict_no_sign) {
      auto res = signMessage(*msg);
      if (!res) {
        log_.warn("signMessage error: {}", res.error());
      }
    }

    MessageId msg_id = create_message_id_(msg->from, msg->seq_no, msg->data, msg->topic);

    // A message already known (a peer's copy forwarded, being validated, or
    // refused) is not published again: with a message ID of the content
    // alone (eth2), a node that rebuilds a message it also received would
    // forward it twice
    if (msg_cache_.contains(msg_id) || pending_validations_.contains(msg_id)
        || ignored_.contains(msg_id) || rejected_.contains(msg_id)
        || seen_ids_.contains(msg_id)) {
      ++counters_.publish_known;
      return false;
    }

    [[maybe_unused]] bool inserted = msg_cache_.insert(msg, msg_id);
    assert(inserted);
    seen_ids_.insert(msg_id, scheduler_->now());

    remote_subscriptions_->onNewMessage(boost::none, msg, msg_id);

    if (config_.echo_forward_mode) {
      local_subscriptions_->forwardMessage(msg, {});
    }

    // the message goes out now, not with the next message or heartbeat
    connectivity_->flush();
    return true;
  }

  bool GossipCore::forwardHeld(const TopicId &topic, const Bytes &data) {
    if (!started_) {
      return false;
    }
    expireHeld();
    const auto it = std::find_if(
        held_.begin(), held_.end(), [&](const HeldMessage &held) {
          return held.msg->topic == topic && held.msg->data == data;
        });
    if (it == held_.end()) {
      return false;
    }
    auto held = std::move(*it);
    held_.erase(it);
    // we may have left the topic meanwhile
    if (!isSubscribed(topic) || !remote_subscriptions_->hasTopic(topic)
        || !msg_cache_.insert(held.msg, held.id)) {
      return false;
    }
    ++counters_.held_forwarded;
    // As a valid message received now from the peer that delivered it
    remote_subscriptions_->onNewMessage(held.from, held.msg, held.id);
    connectivity_->flush();
    return true;
  }

  void GossipCore::expireCaches() {
    msg_cache_.shift();
    seen_ids_.expire(scheduler_->now());
    expireHeld();
  }

  void GossipCore::expireHeld() {
    const auto now = scheduler_->now();
    while (!held_.empty() && now - held_.front().since >= config_.held_msec) {
      held_.pop_front();
      ++counters_.held_expired;
    }
  }

  std::vector<peer::PeerId> GossipCore::getConnectedPeers() const {
    std::vector<peer::PeerId> peers;
    connectivity_->getConnectedPeers().selectAll(
        [&peers](const PeerContextPtr &ctx) { peers.push_back(ctx->peer_id); });
    return peers;
  }

  std::vector<peer::PeerId> GossipCore::getMeshPeers() const {
    std::vector<peer::PeerId> peers;
    connectivity_->getConnectedPeers().selectAll(
        [&peers](const PeerContextPtr &ctx) {
          if (!ctx->mesh_since.empty()) {
            peers.push_back(ctx->peer_id);
          }
        });
    return peers;
  }

  std::vector<peer::PeerId> GossipCore::getOutboundPeers() const {
    std::vector<peer::PeerId> peers;
    connectivity_->getConnectedPeers().selectAll(
        [&peers](const PeerContextPtr &ctx) {
          if (ctx->outbound) {
            peers.push_back(ctx->peer_id);
          }
        });
    return peers;
  }

  std::vector<peer::PeerId> GossipCore::getTopicMeshPeers(
      const TopicId &topic) const {
    return remote_subscriptions_->meshMemberIds(topic);
  }

  bool GossipCore::graftPeer(const TopicId &topic, const peer::PeerId &peer) {
    auto ctx = connectivity_->getConnectedPeers().find(peer);
    if (!ctx) {
      return false;
    }
    return remote_subscriptions_->tryGraft(topic, *ctx);
  }

  bool GossipCore::prunePeer(const TopicId &topic, const peer::PeerId &peer) {
    auto ctx = connectivity_->getConnectedPeers().find(peer);
    if (!ctx) {
      return false;
    }
    return remote_subscriptions_->tryPrune(topic, *ctx);
  }

  outcome::result<void> GossipCore::signMessage(TopicMessage &msg) const {
    const auto &keypair = idmgr_->getKeyPair();
    OUTCOME_TRY(signable, MessageBuilder::signableMessage(msg));
    OUTCOME_TRY(signature,
                crypto_provider_->sign(signable, keypair.privateKey));
    msg.signature = std::move(signature);
    if (idmgr_->getId().toMultihash().getType() != multi::HashType::identity) {
      OUTCOME_TRY(key, key_marshaller_->marshal(keypair.publicKey));
      msg.key = std::move(key.key);
    }
    return outcome::success();
  }

  void GossipCore::onSubscription(const PeerContextPtr &peer,
                                  bool subscribe,
                                  const TopicId &topic) {
    assert(started_);

    log_.debug("peer {} {}subscribed, topic {}",
               peer->str,
               (subscribe ? "" : "un"),
               topic);
    if (subscribe) {
      remote_subscriptions_->onPeerSubscribed(peer, topic);
    } else {
      peer->partial_topics.erase(topic);
      remote_subscriptions_->onPeerUnsubscribed(peer, topic, false);
    }
  }

  void GossipCore::onExtensions(const PeerContextPtr &from,
                                const std::optional<PeerExtensions> &extensions,
                                bool first_on_stream) {
    if (from->diag && (extensions || !first_on_stream)) {
      ++(first_on_stream ? from->diag->view.extensions_rx
                         : from->diag->view.extensions_repeated_rx);
    }
    if (!first_on_stream) {
      // gossipsub v1.3: in the first message on the stream and only there
      ++counters_.extensions_repeated;
      peer_score2_->add_penalty(from->peer_id, 1);
      log_.debug("peer {} sent the Extensions control message again",
                 from->str);
      return;
    }
    const bool advertised = extensions && extensions->partial_messages;
    // counted with the extension off too: how many peers would use it
    if (advertised) {
      ++counters_.partial_streams_advertised;
    }
    from->partial_messages = config_.partial_messages && advertised;
  }

  void GossipCore::onPartialSubscription(const PeerContextPtr &from,
                                         const TopicId &topic,
                                         PartialTopicOptions options) {
    if (!config_.partial_messages) {
      return;
    }
    // a peer requesting partial messages supports sending them
    options.supports_sending_partial =
        options.supports_sending_partial || options.requests_partial;
    if (options.supports_sending_partial) {
      from->partial_topics[topic] = options;
    } else {
      from->partial_topics.erase(topic);
    }
  }

  void GossipCore::onPartialMessage(const PeerContextPtr &from,
                                    PartialMessage msg) {
    // the extension advertised by both sides, on a topic we enabled
    const auto options = partial_.topicOptions(msg.topic);
    if (!started_ || !config_.partial_messages || !from->partial_messages
        || !from->partial_advertised || !options
        || peer_score2_->score(from->peer_id)
               < score_thresholds2_.graylist_threshold) {
      ++counters_.partial_rpcs_dropped;
      return;
    }
    if (msg.partial_message && !options->requests_partial) {
      // parts we did not request: a violation, unless the peer had not read
      // our latest subscription yet
      ++counters_.partial_unrequested;
      if (scheduler_->now() - partial_.optionsChangedAt(msg.topic)
          > config_.partial_options_grace_msec) {
        peer_score2_->add_penalty(from->peer_id, 1);
      }
      msg.partial_message.reset();
    }
    if (!msg.partial_message && !msg.parts_metadata) {
      ++counters_.partial_rpcs_dropped;
      return;
    }
    auto *group = partial_.group(msg.topic, msg.group_id, from->peer_id);
    if (group == nullptr) {
      // past the groups the peers may open
      ++counters_.partial_rpcs_dropped;
      return;
    }
    auto &state = group->peers[from->peer_id];
    state.requests_partial = partial_.mayReceiveParts(*from, msg.topic);
    if (msg.parts_metadata) {
      // a later parts metadata replaces a prior one
      state.parts_metadata = msg.parts_metadata;
    }
    ++counters_.partial_rpcs_rx;
    counters_.partial_bytes_rx +=
        (msg.partial_message ? msg.partial_message->size() : 0)
        + (msg.parts_metadata ? msg.parts_metadata->size() : 0);
    if (partial_message_handler_) {
      partial_message_handler_(msg);
    }
  }

  bool GossipCore::setPartialTopic(const TopicId &topic,
                                   PartialTopicOptions options) {
    if (!config_.partial_messages) {
      return false;
    }
    if (partial_.setTopicOptions(topic, options, scheduler_->now())
        && isSubscribed(topic)) {
      partial_reannounce_.insert(topic);
    }
    return true;
  }

  void GossipCore::setPartialMessageHandler(PartialMessageHandler handler) {
    partial_message_handler_ = std::move(handler);
  }

  void GossipCore::setPartialGossipHandler(PartialGossipHandler handler) {
    partial_gossip_handler_ = std::move(handler);
  }

  std::vector<PeerContextPtr> GossipCore::partialPeers(
      const TopicId &topic) const {
    std::vector<PeerContextPtr> peers;
    const auto &connected = connectivity_->getConnectedPeers();
    for (const auto &id : remote_subscriptions_->meshMemberIds(topic)) {
      if (auto ctx = connected.find(id);
          ctx && partial_.exchangesWith(*ctx.value(), topic)) {
        peers.push_back(std::move(ctx.value()));
      }
    }
    // a topic we subscribed to has a mesh, whose members are the only ones
    // (go-libp2p-pubsub MeshPeers, consensus-specs partial columns "Mesh"):
    // the subscribers outside it get partial message gossip at the heartbeat
    if (isSubscribed(topic)) {
      return peers;
    }
    // no mesh (a topic we publish in without subscribing): up to D of the
    // subscribers, as a fanout
    connected.selectAll([&](const PeerContextPtr &ctx) {
      if (peers.size() < config_.D && ctx->subscribed_to.contains(topic)
          && partial_.exchangesWith(*ctx, topic)) {
        peers.push_back(ctx);
      }
    });
    return peers;
  }

  bool GossipCore::publishPartial(const TopicId &topic,
                                  const Bytes &group_id,
                                  const PartialPublishFn &fn) {
    if (!started_ || !config_.partial_messages) {
      return false;
    }
    auto *group = partial_.group(topic, group_id, std::nullopt);
    if (group == nullptr) {
      // the topic is not enabled
      return false;
    }
    for (const auto &ctx : partialPeers(topic)) {
      group->peers.try_emplace(ctx->peer_id);
    }
    const auto &connected = connectivity_->getConnectedPeers();
    for (auto it = group->peers.begin(); it != group->peers.end();) {
      auto ctx = connected.find(it->first);
      if (!ctx) {
        it = group->peers.erase(it);
        continue;
      }
      it->second.requests_partial =
          partial_.mayReceiveParts(*ctx.value(), topic);
      ++it;
    }
    const auto actions = fn(group->peers);
    for (const auto &action : actions) {
      auto ctx = connected.find(action.peer);
      if (!ctx) {
        ++counters_.partial_actions_dropped;
        continue;
      }
      // parts to the peers that requested them, metadata to those that
      // support sending parts
      const bool parts = !action.partial_message.empty()
                      && partial_.mayReceiveParts(*ctx.value(), topic);
      const bool metadata = !action.parts_metadata.empty()
                         && partial_.mayReceiveMetadata(*ctx.value(), topic);
      if ((!action.partial_message.empty() && !parts)
          || (!action.parts_metadata.empty() && !metadata)) {
        ++counters_.partial_actions_dropped;
      }
      if (!parts && !metadata) {
        continue;
      }
      static const Bytes kNone;
      ctx.value()->message_builder->addPartialMessage(
          topic,
          group_id,
          parts ? action.partial_message : kNone,
          metadata ? action.parts_metadata : kNone);
      if (ctx.value()->diag) {
        ++ctx.value()->diag->topic(topic).partial;
      }
      auto &state = group->peers[action.peer];
      state.requests_partial = partial_.mayReceiveParts(*ctx.value(), topic);
      if (metadata) {
        state.sent_parts_metadata = action.parts_metadata;
      }
      ++counters_.partial_rpcs_tx;
      counters_.partial_bytes_tx +=
          (parts ? action.partial_message.size() : 0)
          + (metadata ? action.parts_metadata.size() : 0);
      connectivity_->peerIsWritable(ctx.value(), true);
    }
    connectivity_->flush();
    return true;
  }

  void GossipCore::reportPartialMessage(const TopicId &topic,
                                        const peer::PeerId &peer,
                                        PartialFeedback feedback) {
    ensureTopicScoreParams(topic);
    if (feedback == PartialFeedback::kUseful) {
      peer_score2_->useful_partial_message(peer, topic);
    } else {
      peer_score2_->reject_invalid_message(peer, topic);
    }
  }

  void GossipCore::emitPartialGossip() {
    // the handler publishes in the groups: they are joined first
    for (const auto &emission : partial_.takeGossip()) {
      if (partial_gossip_handler_) {
        partial_gossip_handler_(
            emission.topic, emission.group_id, emission.peers);
      }
    }
  }

  void GossipCore::onIHave(const PeerContextPtr &from,
                           const TopicId &topic,
                           const MessageId &msg_id) {
    assert(started_);

    log_.info("IHAVE from peer {} for topic {}", from->str, topic);
    if (from->diag) {
      ++from->diag->view.ihave_ids_rx;
    }
    if (topic.ends_with("/beacon_block/ssz_snappy")) {
      ++from->block_ihaves_rx;
    } else if (topic.ends_with("/execution_payload/ssz_snappy")) {
      ++from->envelope_ihaves_rx;
    }

    // not for a topic we left
    if (isSubscribed(topic) && remote_subscriptions_->hasTopic(topic)
        && !msg_cache_.contains(msg_id)
        && !pending_validations_.contains(msg_id) && !ignored_.contains(msg_id)
        && !rejected_.contains(msg_id) && !seen_ids_.contains(msg_id)) {
      log_.info("requesting IWANT msg_id={:x} from peer {}", msg_id, from->str);

      from->message_builder->addIWant(msg_id);
      if (from->diag) {
        ++from->diag->view.iwant_ids_tx;
      }
      if (topic.ends_with("/beacon_block/ssz_snappy")) {
        ++counters_.block_iwants_sent;
      }
      // Eager pull for latency-critical sparse topics (eth2 beacon blocks):
      // flush the IWANT immediately, but ONLY for the first advertiser of
      // this msg_id — later IHAVEs for the same id go the lazy heartbeat
      // path. An unconditional immediate flush (all topics, all advertisers)
      // is an IWANT burst storm that gets this node rate-limited by peers
      // (observed 2026-08-15: beacon_block delivery collapsed in minutes).
      bool eager = false;
      // A/B toggle: default ON; set SILKWORM_GOSSIP_EAGER_IWANT=0 to fall back
      // to the pure heartbeat path so coverage can be compared across runs.
      static const bool eager_enabled = [] {
        const char* env = std::getenv("SILKWORM_GOSSIP_EAGER_IWANT");
        return env == nullptr || env[0] != '0';
      }();
      static constexpr std::string_view kEagerTopicSuffix = "/beacon_block/ssz_snappy";
      // Race the first K advertisers rather than only the first: block
      // transmission time (~100KB) makes single-source IWANT a lottery on
      // the advertiser's send-queue position; 3 parallel pulls take the min
      // at negligible cost (extra copies are dups we IDONTWANT away).
      static constexpr uint8_t kEagerAdvertisers = 3;
      if (eager_enabled && topic.size() >= kEagerTopicSuffix.size()
          && std::equal(kEagerTopicSuffix.rbegin(), kEagerTopicSuffix.rend(), topic.rbegin())) {
        auto [it, inserted] = eager_iwant_seen_.emplace(msg_id, 0);
        if (inserted) {
          eager_iwant_order_.push_back(msg_id);
          if (eager_iwant_order_.size() > 256) {
            eager_iwant_seen_.erase(eager_iwant_order_.front());
            eager_iwant_order_.pop_front();
          }
        }
        if (it->second < kEagerAdvertisers) {
          ++it->second;
          eager = true;
        }
      }
      if (eager) {
        // Countable marker for the A/B analysis: how often the eager path
        // actually fires (vs. beacon blocks arriving via mesh push, where
        // IWANT latency is irrelevant).
        log_.info("eager IWANT flush msg_id={:x} from peer {}", msg_id, from->str);
      }
      connectivity_->peerIsWritable(from, eager);
    }
  }

  void GossipCore::onIDontWant(const PeerContextPtr &from,
                               const MessageId &msg_id) {
    // gossipsub v1.2: the peer already has this message; suppress our
    // forward of it (bounded FIFO per peer)
    static uint64_t received_total = 0;
    if (++received_total == 1 || received_total % 1000 == 0) {
      log_.info("IDONTWANT flowing: received_total={} (last from {})",
                received_total, from->str);
    }
    if (from->diag) {
      ++from->diag->view.idontwant_rx;
    }
    // A member sending IDONTWANT for the blocks or envelopes we hold has us
    // in its mesh (silkworm #149)
    if (auto msg = msg_cache_.getMessage(msg_id)) {
      if (msg.value()->topic.ends_with("/beacon_block/ssz_snappy")) {
        ++from->block_idontwant_rx;
      } else if (msg.value()->topic.ends_with(
                     "/execution_payload/ssz_snappy")) {
        ++from->envelope_idontwant_rx;
      }
    }
    if (from->dont_want.insert(msg_id).second) {
      from->dont_want_order.push_back(msg_id);
      if (from->dont_want_order.size() > 128) {
        from->dont_want.erase(from->dont_want_order.front());
        from->dont_want_order.pop_front();
      }
    }
  }

  void GossipCore::onIWant(const PeerContextPtr &from,
                           const MessageId &msg_id) {
    log_.info("IWANT from peer {} for msg_id={:x}", from->str, msg_id);

    auto msg_found = msg_cache_.getMessage(msg_id);
    if (auto *diag = from->diag.get()) {
      // a message we no longer have is a broken promise (P7) there, as is an
      // answer that reaches it past its IWANT followup time: the answer
      // queues behind the bytes still to be written to it. The age of the
      // ID since our first IHAVE of it is not the answer's delay
      auto &view = diag->view;
      ++view.iwant_ids_rx;
      const auto announced = diag->announcedAt(msg_id);
      if (!msg_found) {
        ++view.iwant_missed;
        if (announced) {
          ++view.iwant_missed_announced;
        }
      } else {
        ++view.iwant_served;
        view.iwant_served_bytes += msg_found.value()->data.size();
        diag->pushed(msg_found.value()->topic,
                     PeerDiagnostics::PushKind::kIWant,
                     msg_found.value()->data.size(),
                     msg_id,
                     scheduler_->now());
        if (from->outbound_stream) {
          view.iwant_backlog_max_bytes =
              std::max<uint64_t>(view.iwant_backlog_max_bytes,
                                 from->outbound_stream->backlogBytes());
        }
        if (!announced) {
          ++view.iwant_unannounced;
        } else {
          const auto age = scheduler_->now() - *announced;
          if (age > std::chrono::seconds(1)) {
            ++view.iwant_after_1s;
          }
          if (age > std::chrono::seconds(3)) {
            ++view.iwant_after_3s;
          }
          view.iwant_max_ms = std::max<uint64_t>(
              view.iwant_max_ms, static_cast<uint64_t>(age.count()));
        }
      }
    }
    if (msg_found) {
      from->message_builder->addMessage(*msg_found.value(), msg_id);
      connectivity_->peerIsWritable(from, true);
    } else {
      log_.info("IWANT: message not in cache");
    }
  }

  void GossipCore::onGraft(const PeerContextPtr &from, const TopicId &topic) {
    assert(started_);

    log_.info("GRAFT from peer {} for topic {}", from->str, topic);
    if (from->diag) {
      ++from->diag->view.graft_rx;
      ++from->diag->topic(topic).graft_rx;
    }

    remote_subscriptions_->onGraft(from, topic);
  }

  void GossipCore::onPrune(const PeerContextPtr &from,
                           const TopicId &topic,
                           uint64_t backoff_time) {
    assert(started_);

    log_.info("PRUNE from peer {} for topic {}, backoff={}s", from->str, topic, backoff_time);
    if (from->diag) {
      ++from->diag->view.prune_rx;
      ++from->diag->topic(topic).prune_rx;
      from->diag->pruneReceived(scheduler_->now());
    }

    remote_subscriptions_->onPrune(from, topic, backoff_time);
  }

  void GossipCore::onPrunePeerExchange(const PeerContextPtr &from,
                                       const peer::PeerId &peer_id) {
    if (!started_) {
      return;
    }
    if (peer_id == local_peer_id_) {
      return;
    }
    // gossipsub v1.1: only the peers exchanged by a well-scored peer are
    // dialed, so that a misbehaving one cannot steer our connections
    if (peer_score2_->score(from->peer_id)
        < score_thresholds2_.accept_px_threshold) {
      ++counters_.px_dials_skipped;
      log_.debug("PX: ignoring peer {} from {}, below accept_px_threshold",
                 peer_id.toBase58(),
                 from->str);
      return;
    }
    log_.info("PX: adding peer {} from PRUNE peer exchange", peer_id.toBase58());
    // Not an outbound peer once connected (rust-libp2p px_peers)
    const auto now = scheduler_->now();
    std::erase_if(px_dialed_, [&](const auto &entry) {
      return now - entry.second > kPxDialedTtl;
    });
    if (px_dialed_.size() < kMaxPxDialed) {
      px_dialed_.emplace(peer_id, now);
    }
    addBootstrapPeer(peer_id, boost::none);
  }

  namespace {
    inline score::TimePoint toScoreTime(Time t) {
      return score::TimePoint{
          std::chrono::duration_cast<std::chrono::nanoseconds>(t)};
    }

    bool isEnvelopeTopic(const TopicId &topic) {
      return topic.ends_with("/execution_payload/ssz_snappy");
    }

    bool isBeaconBlockTopic(const TopicId &topic) {
      static constexpr std::string_view kSuffix = "/beacon_block/ssz_snappy";
      return topic.size() >= kSuffix.size()
          && std::equal(kSuffix.rbegin(), kSuffix.rend(), topic.rbegin());
    }
  }  // namespace

  void GossipCore::onTopicMessage(const PeerContextPtr &from,
                                  TopicMessage::Ptr msg) {
    assert(started_);

    ++from->messages_rx;
    if (from->diag) {
      ++from->diag->view.messages_rx;
    }

    // do we need this message? Not on a topic we left: the remote peers still
    // subscribed to it keep its entry
    auto subscribed =
        isSubscribed(msg->topic) && remote_subscriptions_->hasTopic(msg->topic);
    if (!subscribed) {
      // ignore this message
      return;
    }

    // Graylist gate (gossipsub v1.1): ignore everything from peers whose
    // score fell below the graylist threshold.
    if (peer_score2_->score(from->peer_id) < score_thresholds2_.graylist_threshold) {
      log_.debug("graylisted peer {}, dropping message", from->str);
      return;
    }
    ensureTopicScoreParams(msg->topic);

    // StrictNoSign: a message with an author field, even an empty one, is
    // invalid, rejected before the duplicate check as go-libp2p-pubsub's
    // checkSigningPolicy does (RejectUnexpectedAuthInfo). Its sender gets the
    // P4 of a validator's REJECT; the message is neither cached, delivered,
    // forwarded nor announced, and its ID is not seen: a copy without them
    // from another peer is still taken (silkworm #223)
    if (config_.strict_no_sign && msg->hasAuthorFields()) {
      peer_score2_->reject_invalid_message(from->peer_id, msg->topic);
      ++counters_.author_fields_rejected;
      ++counters_.author_fields_rejected_agents[agentFamilyOf(from->peer_id)];
      log_.debug("message with author fields from peer {} rejected", from->str);
      return;
    }

    MessageId msg_id = create_message_id_(msg->from, msg->seq_no, msg->data, msg->topic);
    const std::string msg_id_str(msg_id.begin(), msg_id.end());
    // hot path: every gossip message (attestations included) passes here on
    // the libp2p-io thread — keep it below the configured info level
    log_.debug("MESSAGE arrived from peer {}, topic={}, size={}, msg_id={:x}",
               from->str, msg->topic, msg->data.size(), msg_id);

    bool duplicate = msg_cache_.contains(msg_id) || ignored_.contains(msg_id)
                  || rejected_.contains(msg_id)
                  || pending_validations_.contains(msg_id);
    // Seen within seen_ttl, after the message cache dropped it: its ID is all
    // that is left of it (silkworm #211)
    if (!duplicate && seen_ids_.contains(msg_id)) {
      ++counters_.seen_duplicates;
      duplicate = true;
    }
    if (duplicate) {
      // duplicate delivery: measure this peer's lag vs the first copy
      if (isEnvelopeTopic(msg->topic)) {
        if (auto it = first_envelope_delivery_.find(msg_id);
            it != first_envelope_delivery_.end() && it->second != from) {
          ++from->envelope_dup_deliveries;
        }
      }
      if (isBeaconBlockTopic(msg->topic)) {
        auto it = first_delivery_.find(msg_id);
        if (it != first_delivery_.end() && it->second.second != from) {
          const auto lag =
              static_cast<double>((scheduler_->now() - it->second.first).count());
          ++from->dup_msg_deliveries;
          from->delivery_lag_ewma_ms = from->delivery_lag_ewma_ms < 0
              ? lag
              : 0.8 * from->delivery_lag_ewma_ms + 0.2 * lag;
        }
      }
      peer_score2_->duplicated_message(from->peer_id, msg_id_str, msg->topic,
                                       toScoreTime(scheduler_->now()));
      log_.debug("ignoring message, already in cache");
      return;
    }

    // The first copy of a block or envelope: its forward delay is measured
    // from now (silkworm #149)
    if (isBeaconBlockTopic(msg->topic) || isEnvelopeTopic(msg->topic)) {
      if (first_seen_at_.emplace(msg_id, scheduler_->now()).second) {
        first_seen_order_.push_back(msg_id);
        if (first_seen_order_.size() > 128) {
          first_seen_at_.erase(first_seen_order_.front());
          first_seen_order_.pop_front();
        }
      }
    }

    // validate message. If no validator is set then we
    // suppose that the message is valid (we might not know topic details)
    peer_score2_->validate_message(
        from->peer_id, msg_id_str, msg->topic, toScoreTime(scheduler_->now()));
    auto validator = validators_.find(msg->topic);
    if (validator == validators_.end()) {
      onMessageValidated(from, msg, msg_id, ValidationResult::kAccept);
      return;
    }
    if (!validator->second.async_validator) {
      onMessageValidated(
          from, msg, msg_id, validator->second.validator(msg->from, msg->data));
      return;
    }
    if (pending_validations_.size() >= config_.max_pending_validations) {
      log_.debug("too many messages pending validation, dropping");
      onMessageValidated(from, msg, msg_id, ValidationResult::kDrop);
      return;
    }
    // Held until the validator decides: the I/O thread goes on meanwhile
    pending_validations_.emplace(msg_id, PendingValidation{from, msg});
    validator->second.async_validator(
        msg->from,
        msg->data,
        [weak_self = weak_from_this(), msg_id](ValidationResult validation) {
          if (auto self = weak_self.lock()) {
            self->onAsyncValidationResult(msg_id, validation);
          }
        });
  }

  void GossipCore::onAsyncValidationResult(const MessageId &msg_id,
                                           ValidationResult validation) {
    auto it = pending_validations_.find(msg_id);
    if (it == pending_validations_.end()) {
      return;
    }
    auto pending = std::move(it->second);
    pending_validations_.erase(it);
    // we may have left the topic meanwhile
    if (!started_ || !isSubscribed(pending.msg->topic)
        || !remote_subscriptions_->hasTopic(pending.msg->topic)) {
      return;
    }
    onMessageValidated(pending.from, pending.msg, msg_id, validation);
    // the forwards go out now, not with the next message or heartbeat
    connectivity_->flush();
  }

  void GossipCore::onMessageValidated(const PeerContextPtr &from,
                                      const TopicMessage::Ptr &msg,
                                      const MessageId &msg_id,
                                      ValidationResult validation) {
    if (validation == ValidationResult::kDrop) {
      // not judged: neither scored nor remembered, so that a copy is validated
      log_.debug("message dropped without validation");
      return;
    }
    // Judged: its copies are duplicates for seen_ttl, whatever the verdict
    seen_ids_.insert(msg_id, scheduler_->now());
    const std::string msg_id_str(msg_id.begin(), msg_id.end());
    if (validation == ValidationResult::kIgnore) {
      // rust-libp2p MessageAcceptance::Ignore: neither forwarded nor penalized
      peer_score2_->reject_message(from->peer_id,
                                   msg_id_str,
                                   msg->topic,
                                   score::RejectReason::kValidationIgnored,
                                   toScoreTime(scheduler_->now()));
      ignored_.insert(msg_id);
      log_.debug("message ignored by validation");
      return;
    }
    if (validation == ValidationResult::kHold) {
      // Ignored as far as the network goes: neither forwarded, cached for
      // IWANT nor scored as a delivery. The application gets it, and
      // forwards it with forwardHeld() once it validated it (silkworm #219)
      peer_score2_->reject_message(from->peer_id,
                                   msg_id_str,
                                   msg->topic,
                                   score::RejectReason::kValidationIgnored,
                                   toScoreTime(scheduler_->now()));
      ignored_.insert(msg_id);
      expireHeld();
      held_.push_back({msg_id, from, msg, scheduler_->now()});
      if (held_.size() > config_.max_held_messages) {
        held_.pop_front();
        ++counters_.held_expired;
      }
      ++counters_.held;
      log_.debug("message held by validation");
      local_subscriptions_->forwardMessage(msg, from->str, /*held=*/true);
      return;
    }
    if (validation == ValidationResult::kReject) {
      // P4 (InvalidMessageDeliveries): verbatim rust-libp2p semantics — the
      // reject fans out to every peer that delivered this id and the record
      // marks later copies invalid on arrival.
      peer_score2_->reject_message(from->peer_id, msg_id_str, msg->topic,
                                   score::RejectReason::kValidationError,
                                   toScoreTime(scheduler_->now()));
      rejected_.insert(msg_id);
      log_.debug("message validation failed (P4 penalty applied to {})",
                 from->str);
      return;
    }
    peer_score2_->deliver_message(from->peer_id, msg_id_str, msg->topic,
                                  toScoreTime(scheduler_->now()));

    if (!msg_cache_.insert(msg, msg_id)) {
      log_.error("message cache error");
      return;
    }

    if (isBeaconBlockTopic(msg->topic)) {
      ++from->first_msg_deliveries;
      // Pushed by a mesh member, or pulled (silkworm #149)
      const auto mesh = remote_subscriptions_->meshMemberIds(msg->topic);
      ++(std::ranges::find(mesh, from->peer_id) != mesh.end()
             ? counters_.block_first_from_mesh
             : counters_.block_first_from_others);
      if (from->delivery_lag_ewma_ms < 0) {
        from->delivery_lag_ewma_ms = 0.0;
      } else {
        from->delivery_lag_ewma_ms *= 0.8;
      }
      first_delivery_.emplace(msg_id, std::make_pair(scheduler_->now(), from));
      first_delivery_order_.push_back(msg_id);
      if (first_delivery_order_.size() > 64) {
        first_delivery_.erase(first_delivery_order_.front());
        first_delivery_order_.pop_front();
      }
      // one line per block: who won the delivery race
      log_.info("first delivery msg_id={:x} from peer {}", msg_id, from->str);
    } else if (isEnvelopeTopic(msg->topic)) {
      // Pushed by a mesh member, or pulled (silkworm #149)
      ++from->envelope_first_deliveries;
      const auto mesh = remote_subscriptions_->meshMemberIds(msg->topic);
      ++(std::ranges::find(mesh, from->peer_id) != mesh.end()
             ? counters_.envelope_first_from_mesh
             : counters_.envelope_first_from_others);
      first_envelope_delivery_.emplace(msg_id, from);
      first_envelope_order_.push_back(msg_id);
      if (first_envelope_order_.size() > 64) {
        first_envelope_delivery_.erase(first_envelope_order_.front());
        first_envelope_order_.pop_front();
      }
    }

    log_.debug("forwarding message");

    if (const auto seen = first_seen_at_.find(msg_id);
        seen != first_seen_at_.end()) {
      const auto ms = static_cast<uint64_t>(
          std::max<int64_t>(0, (scheduler_->now() - seen->second).count()));
      const bool block = isBeaconBlockTopic(msg->topic);
      ++(block ? counters_.block_forward_count
               : counters_.envelope_forward_count);
      (block ? counters_.block_forward_ms_sum
             : counters_.envelope_forward_ms_sum) += ms;
      auto &max_ms = block ? counters_.block_forward_ms_max
                           : counters_.envelope_forward_ms_max;
      max_ms = std::max(max_ms, ms);
      first_seen_at_.erase(seen);
    }

    local_subscriptions_->forwardMessage(msg, from->str);
    remote_subscriptions_->onNewMessage(from, msg, msg_id);
  }

  void GossipCore::onMessageEnd(const PeerContextPtr &from) {
    assert(started_);

    log_.debug("finished dispatching message from peer {}", from->str);

    // Apply immediate send operation to affected peers
    connectivity_->flush();
  }

  void GossipCore::onHeartbeat() {
    if (++heartbeat_seq_ % 128 == 0) {
      connectivity_->getConnectedPeers().selectAll(
          [this](const PeerContextPtr &ctx) {
            if (ctx->first_msg_deliveries + ctx->dup_msg_deliveries > 0) {
              log_.info(
                  "delivery-stats peer={} first={} dup={} lag_ewma_ms={} mesh={}",
                  ctx->str, ctx->first_msg_deliveries, ctx->dup_msg_deliveries,
                  static_cast<int64_t>(ctx->delivery_lag_ewma_ms),
                  ctx->mesh_since.empty() ? 0 : 1);
            }
          });
    }
    assert(started_);

    expireCaches();

    // the per-peer diagnostics of the sessions that ended a while ago
    if (config_.peer_diagnostics
        && heartbeat_seq_ % kDiagnosticsSweepHeartbeats == 0) {
      connectivity_->dropDiagnostics(scheduler_->now());
    }

    // Decay and refresh the scores once per decay_interval (a slot)
    auto now = scheduler_->now();
    if (last_score_refresh_ == Time{} ||
        now - last_score_refresh_ >= peer_score2_->params().decay_interval) {
      last_score_refresh_ = now;
      peer_score2_->refresh_scores(toScoreTime(now));
    }

    // The close of one of several connections to a peer fires no event
    if (heartbeat_seq_ % kConnectionInfoSweepHeartbeats == 0) {
      refreshConnectionInfos();
    }

    // heartbeat changes per topic
    remote_subscriptions_->onHeartbeat();

    // partial messages: gossip, then the groups age
    emitPartialGossip();
    partial_.onHeartbeat();

    // the subscriptions whose partial options changed are announced again
    for (const auto &topic : partial_reannounce_) {
      if (isSubscribed(topic)) {
        broadcast_on_heartbeat_.try_emplace(topic, true);
      }
    }
    partial_reannounce_.clear();

    // send changes to peers
    connectivity_->onHeartbeat(broadcast_on_heartbeat_);
    broadcast_on_heartbeat_.clear();

    setTimerHeartbeat();
  }

  void GossipCore::ensureTopicScoreParams(const TopicId &topic) {
    if (peer_score2_->get_topic_params(topic) != nullptr) {
      return;
    }
    // eth2 topics only: the others score only globally
    if (auto params = score::eth2_topic_score_params(
            topic, active_validators_, current_slot_)) {
      peer_score2_->set_topic_params(topic, *params);
      log_.info("score params installed for {} ({} active validators)",
                topic,
                active_validators_);
    }
  }

  void GossipCore::setNetworkSize(size_t active_validators,
                                  uint64_t current_slot) {
    active_validators_ = active_validators;
    current_slot_ = current_slot;
    std::vector<TopicId> scored;
    for (const auto &[topic, _] : peer_score2_->params().topics) {
      scored.push_back(topic);
    }
    for (const auto &topic : scored) {
      if (auto params = score::eth2_topic_score_params(
              topic, active_validators_, current_slot_)) {
        peer_score2_->set_topic_params(topic, *params);
      }
    }
  }

  void GossipCore::onPeerConnection(bool connected, const PeerContextPtr &ctx) {
    assert(started_);

    if (connected) {
      peer_score2_->add_peer(ctx->peer_id);
      if (auto px = px_dialed_.find(ctx->peer_id); px != px_dialed_.end()) {
        ctx->px_dialed = true;
        px_dialed_.erase(px);
      }
      refreshConnectionInfo(ctx, true);
      log_.debug("peer {} connected", ctx->str);
      if (config_.peer_diagnostics) {
        beginDiagnostics(
            *ctx, scheduler_->now(), config_.peer_diagnostics_keep_msec);
      }
      // notify the new peer about all topics we subscribed to
      if (!local_subscriptions_->subscribedTo().empty()) {
        for (const auto &local_sub : local_subscriptions_->subscribedTo()) {
          // the partial options only once we advertised the extension
          ctx->message_builder->addSubscription(
              true,
              local_sub.first,
              ctx->partial_advertised ? partial_.announced(local_sub.first)
                                      : PartialTopicOptions{});
          if (ctx->diag) {
            ++ctx->diag->view.subscriptions_tx;
          }
        }
        connectivity_->peerIsWritable(ctx, true);
        connectivity_->flush();
      }
    } else {
      peer_score2_->remove_peer(ctx->peer_id, toScoreTime(scheduler_->now()));
      ctx->outbound = false;
      ctx->ips.clear();
      ctx->partial_messages = false;
      ctx->partial_advertised = false;
      ctx->partial_topics.clear();
      partial_.onPeerDisconnected(ctx->peer_id);
      // kept a while: its Goodbye may be read after its streams closed
      if (ctx->diag) {
        ctx->diag->disconnected = scheduler_->now();
      }
      log_.debug("peer {} disconnected", ctx->str);
      remote_subscriptions_->onPeerDisconnected(ctx);
    }
  }

  std::optional<PeerDiagnostics> GossipCore::peerDiagnostics(
      const peer::PeerId &peer) const {
    if (!connectivity_) {
      return std::nullopt;
    }
    const auto ctx = connectivity_->knownPeer(peer);
    if (!ctx || !ctx.value()->diag) {
      return std::nullopt;
    }
    const auto &diag = *ctx.value()->diag;
    const auto now = scheduler_->now();
    if (diag.disconnected != Time{0}
        && now - diag.disconnected > config_.peer_diagnostics_keep_msec) {
      return std::nullopt;
    }
    auto view = diag.view;
    view.connected = diag.disconnected == Time{0};
    view.age = now - diag.started;
    view.since_disconnect = view.connected ? Time{0} : now - diag.disconnected;
    view.score = peer_score2_->score(peer);
    if (diag.prune_burst_at != Time{0}) {
      view.prune_burst_age = now - diag.prune_burst_at;
    }
    // the data of those still cached, for the caller to read them
    view.sent_recently = diag.sentRecently(now);
    for (auto &push : view.sent_recently) {
      if (auto msg = msg_cache_.getMessage(push.id)) {
        push.data = std::shared_ptr<const Bytes>(*msg, &(*msg)->data);
      }
    }
    return view;
  }

  PeerContextPtr GossipCore::connectedPeer(const peer::PeerId &peer) const {
    if (!connectivity_) {
      return nullptr;
    }
    auto ctx = connectivity_->getConnectedPeers().find(peer);
    return ctx ? ctx.value() : nullptr;
  }

  void GossipCore::refreshConnectionInfos() {
    connectivity_->getConnectedPeers().selectAll(
        [this](const PeerContextPtr &ctx) {
          refreshConnectionInfo(ctx, false);
        });
  }

  void GossipCore::refreshConnectionInfo(const PeerContextPtr &ctx,
                                         bool connected_now) {
    const auto info = connectionInfo(ctx->peer_id);
    const bool outbound = info.outbound && !ctx->px_dialed;
    if (connected_now && info.outbound && ctx->px_dialed) {
      ++counters_.px_outbound_excluded;
    }
    // P6 (IP colocation): the peers sharing an IP beyond the threshold are
    // penalized, except on loopback (local multi-node setups). remove_peer
    // forgets the IPs of a peer that leaves
    std::set<std::string> ips;
    for (const auto &ip : info.ips) {
      if (!ip.starts_with("127.") && ip != "::1") {
        ips.insert(ip);
      }
    }
    if (!connected_now && (outbound != ctx->outbound || ips != ctx->ips)) {
      ++counters_.conn_info_updates;
    }
    ctx->outbound = outbound;
    ctx->quic = info.quic;
    for (const auto &ip : ctx->ips) {
      if (!ips.contains(ip)) {
        peer_score2_->remove_ip(ctx->peer_id, ip);
      }
    }
    const auto &whitelist =
        peer_score2_->params().ip_colocation_factor_whitelist;
    for (const auto &ip : ips) {
      if (!ctx->ips.contains(ip)) {
        peer_score2_->add_ip(ctx->peer_id, ip);
        if (whitelist.contains(ip)) {
          ++counters_.p6_whitelisted;
        }
      }
    }
    ctx->ips = std::move(ips);
  }

  PeerConnectionInfo GossipCore::connectionInfo(
      const peer::PeerId &peer) const {
    if (config_.connection_info) {
      return config_.connection_info(peer);
    }
    PeerConnectionInfo info;
    for (const auto &connection :
         host_->getNetwork().getConnectionManager().getConnectionsToPeer(
             peer)) {
      if (connection->isClosed()) {
        continue;
      }
      info.outbound = info.outbound || connection->isInitiator();
      if (auto address = connection->remoteMultiaddr()) {
        info.quic = info.quic
                 || address.value().hasProtocol(multi::Protocol::Code::QUIC_V1);
        for (const auto code :
             {multi::Protocol::Code::IP4, multi::Protocol::Code::IP6}) {
          if (auto ip = address.value().getFirstValueForProtocol(code)) {
            info.ips.push_back(std::move(ip.value()));
            break;
          }
        }
      }
    }
    return info;
  }

  void GossipCore::onLocalSubscriptionChanged(bool subscribe,
                                              const TopicId &topic) {
    if (!started_) {
      return;
    }

    // send this notification on next heartbeat to all connected peers
    auto it = broadcast_on_heartbeat_.find(topic);
    if (it == broadcast_on_heartbeat_.end()) {
      broadcast_on_heartbeat_.emplace(topic, subscribe);
    } else if (it->second != subscribe) {
      // save traffic
      broadcast_on_heartbeat_.erase(it);
    }

    // update meshes per topic
    remote_subscriptions_->onSelfSubscribed(subscribe, topic);
  }

  void GossipCore::setTimerHeartbeat() {
    heartbeat_timer_ = scheduler_->scheduleWithHandle(
        [weak_self{weak_from_this()}] {
          auto self = weak_self.lock();
          if (not self) {
            return;
          }
          self->onHeartbeat();
        },
        config_.heartbeat_interval_msec);
  }
}  // namespace libp2p::protocol::gossip
