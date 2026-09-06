/**
 * Copyright Quadrivium LLC
 * All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <memory>

namespace boost::asio::ssl {
  class context;
}

namespace libp2p::peer {
  class IdentityManager;
}  // namespace libp2p::peer

namespace libp2p::crypto::marshaller {
  class KeyMarshaller;
}  // namespace libp2p::crypto::marshaller

namespace libp2p::security {
  /**
   * SSL context with libp2p TLS 1.3 certificate
   */
  /// DER certificate + key for the QUIC engine: lsquic runs on a private
  /// BoringSSL inside a symbol-localized blob, so SSL objects cannot cross
  /// the boundary — only DER bytes do.
  struct QuicCertAndKey {
    std::vector<uint8_t> cert_der;
    std::vector<uint8_t> key_der;
  };

  struct SslContext {
    SslContext(const peer::IdentityManager &idmgr,
               const crypto::marshaller::KeyMarshaller &key_marshaller);

    std::shared_ptr<boost::asio::ssl::context> tls;
    std::shared_ptr<boost::asio::ssl::context> quic;
    std::shared_ptr<QuicCertAndKey> quic_material;
  };
}  // namespace libp2p::security
