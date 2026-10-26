#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace guardian::server {

class CryptoError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Lowercase hex SHA-256 digest of `data`.
std::string sha256Hex(std::string_view data);

// "wdn_" followed by 64 lowercase hex characters (32 random bytes).
std::string randomToken();

// Timing-safe comparison; false when lengths differ.
bool constantTimeEquals(std::string_view a, std::string_view b) noexcept;

// RFC 4648 base64 (standard alphabet, padded).
std::string base64Encode(std::string_view bytes);
std::optional<std::string> base64Decode(std::string_view text);

struct CertPair {
  std::string certPem;
  std::string keyPem;
};

// Self-signed ECDSA P-256 certificate, subject CN=host, SAN = IP or DNS name.
CertPair generateSelfSignedCert(std::string_view host, int validDays);

// base64(SHA-256(DER SubjectPublicKeyInfo)) of the certificate.
std::string spkiPin(std::string_view certPem);

}  // namespace guardian::server
