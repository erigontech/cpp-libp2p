/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <libp2p/peer/peer_id.hpp>

namespace libp2p::protocol {

  namespace detail {
    struct AgentVersions {
      std::mutex mutex;
      std::unordered_map<peer::PeerId, std::string> families;
    };
    inline AgentVersions &agentVersions() {
      static AgentVersions versions;
      return versions;
    }
  }  // namespace detail

  /// The client family of an Identify agent version: lighthouse, prysm, teku,
  /// nimbus, lodestar, grandine, erigon, or other (silkworm #149)
  inline std::string agentFamily(std::string_view agent) {
    std::string lower{agent};
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    for (const std::string_view family : {"lighthouse",
                                          "prysm",
                                          "teku",
                                          "nimbus",
                                          "lodestar",
                                          "grandine",
                                          "erigon",
                                          "caplin",
                                          "silkworm"}) {
      if (lower.find(family) != std::string::npos) {
        return std::string{family};
      }
    }
    return "other";
  }

  /// Remembers the agent version a peer sent in Identify, at most for 4096
  /// peers
  inline void rememberAgentVersion(const peer::PeerId &peer,
                                   std::string_view agent) {
    auto &versions = detail::agentVersions();
    std::scoped_lock lock{versions.mutex};
    if (versions.families.size() >= 4096) {
      versions.families.clear();
    }
    versions.families.insert_or_assign(peer, agentFamily(agent));
  }

  /// The client family of a peer's agent version, "unknown" before its
  /// Identify
  inline std::string agentFamilyOf(const peer::PeerId &peer) {
    auto &versions = detail::agentVersions();
    std::scoped_lock lock{versions.mutex};
    const auto it = versions.families.find(peer);
    return it == versions.families.end() ? "unknown" : it->second;
  }

}  // namespace libp2p::protocol
