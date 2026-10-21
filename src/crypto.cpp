#include "crypto.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>

namespace warden::server {

namespace {

struct PkeyFree {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct X509Free {
  void operator()(X509* x) const { X509_free(x); }
};
struct BioFree {
  void operator()(BIO* b) const { BIO_free(b); }
};
struct GeneralNamesFree {
  void operator()(GENERAL_NAMES* g) const { GENERAL_NAMES_free(g); }
};
struct GeneralNameFree {
  void operator()(GENERAL_NAME* g) const { GENERAL_NAME_free(g); }
};
struct Asn1IntegerFree {
  void operator()(ASN1_INTEGER* i) const { ASN1_INTEGER_free(i); }
};
struct BnFree {
  void operator()(BIGNUM* b) const { BN_free(b); }
};
struct MdCtxFree {
  void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;
using BioPtr = std::unique_ptr<BIO, BioFree>;

constexpr std::size_t kSha256Len = 32;
constexpr std::string_view kHexDigits = "0123456789abcdef";

[[noreturn]] void fail(const std::string& what) {
  // Only the OpenSSL error code is reported; never any key material.
  const unsigned long code = ERR_get_error();
  ERR_clear_error();
  throw CryptoError(what + " (openssl error " + std::to_string(code) + ")");
}

std::string toHex(const unsigned char* data, std::size_t len) {
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kHexDigits[data[i] >> 4U]);
    out.push_back(kHexDigits[data[i] & 0x0FU]);
  }
  return out;
}

std::array<unsigned char, kSha256Len> sha256Raw(std::string_view data) {
  std::array<unsigned char, kSha256Len> digest{};
  unsigned int len = 0;
  if (EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr) != 1 ||
      len != kSha256Len) {
    fail("sha256 failed");
  }
  return digest;
}

BioPtr newMemBio() {
  BioPtr bio{BIO_new(BIO_s_mem())};
  if (!bio) {
    fail("BIO_new failed");
  }
  return bio;
}

std::string bioToString(BIO* bio) {
  char* ptr = nullptr;
  const long len = BIO_get_mem_data(bio, &ptr);
  if (len < 0 || ptr == nullptr) {
    return {};
  }
  return {ptr, static_cast<std::size_t>(len)};
}

int base64Value(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

constexpr std::string_view kBase64Alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

}  // namespace

std::string sha256Hex(std::string_view data) {
  const auto digest = sha256Raw(data);
  return toHex(digest.data(), digest.size());
}

std::string randomToken() {
  std::array<unsigned char, 32> bytes{};
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    fail("RAND_bytes failed");
  }
  return "wdn_" + toHex(bytes.data(), bytes.size());
}

bool constantTimeEquals(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  if (a.empty()) {
    return true;
  }
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string base64Encode(std::string_view bytes) {
  std::string out;
  out.reserve((bytes.size() + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 2 < bytes.size(); i += 3) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8U) |
        static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 2]));
    out.push_back(kBase64Alphabet[(v >> 18U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(v >> 12U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(v >> 6U) & 0x3FU]);
    out.push_back(kBase64Alphabet[v & 0x3FU]);
  }
  const std::size_t rest = bytes.size() - i;
  if (rest == 1) {
    const std::uint32_t v = static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16U;
    out.push_back(kBase64Alphabet[(v >> 18U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(v >> 12U) & 0x3FU]);
    out += "==";
  } else if (rest == 2) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8U);
    out.push_back(kBase64Alphabet[(v >> 18U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(v >> 12U) & 0x3FU]);
    out.push_back(kBase64Alphabet[(v >> 6U) & 0x3FU]);
    out.push_back('=');
  }
  return out;
}

std::optional<std::string> base64Decode(std::string_view text) {
  if (text.size() % 4 != 0) {
    return std::nullopt;
  }
  std::string out;
  out.reserve(text.size() / 4 * 3);
  for (std::size_t i = 0; i < text.size(); i += 4) {
    const bool last = i + 4 == text.size();
    std::size_t pad = 0;
    std::uint32_t v = 0;
    for (std::size_t j = 0; j < 4; ++j) {
      const char c = text[i + j];
      v <<= 6U;
      if (c == '=') {
        // Padding is only valid in the last two positions of the final quantum.
        if (!last || j < 2) {
          return std::nullopt;
        }
        ++pad;
      } else {
        if (pad != 0) {
          return std::nullopt;
        }
        const int value = base64Value(c);
        if (value < 0) {
          return std::nullopt;
        }
        v |= static_cast<std::uint32_t>(value);
      }
    }
    out.push_back(static_cast<char>((v >> 16U) & 0xFFU));
    if (pad < 2) {
      out.push_back(static_cast<char>((v >> 8U) & 0xFFU));
    }
    if (pad < 1) {
      out.push_back(static_cast<char>(v & 0xFFU));
    }
  }
  return out;
}

CertPair generateSelfSignedCert(std::string_view host, int validDays) {
  if (host.empty() || validDays <= 0) {
    throw CryptoError("invalid certificate parameters");
  }
  const std::string hostStr{host};

  PkeyPtr key{EVP_EC_gen("P-256")};
  if (!key) {
    fail("EC key generation failed");
  }
  X509Ptr cert{X509_new()};
  if (!cert || X509_set_version(cert.get(), 2) != 1) {
    fail("X509_new failed");
  }

  // Random positive 128-bit serial.
  std::array<unsigned char, 16> serialBytes{};
  if (RAND_bytes(serialBytes.data(), static_cast<int>(serialBytes.size())) != 1) {
    fail("RAND_bytes failed");
  }
  serialBytes[0] &= 0x7FU;
  const std::unique_ptr<BIGNUM, BnFree> serialBn{
      BN_bin2bn(serialBytes.data(), static_cast<int>(serialBytes.size()), nullptr)};
  if (!serialBn ||
      BN_to_ASN1_INTEGER(serialBn.get(), X509_get_serialNumber(cert.get())) == nullptr) {
    fail("serial number failed");
  }

  if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(cert.get()),
                      static_cast<long>(validDays) * 24L * 60L * 60L) == nullptr) {
    fail("validity failed");
  }

  X509_NAME* name = X509_get_subject_name(cert.get());
  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                 reinterpret_cast<const unsigned char*>(hostStr.data()),
                                 static_cast<int>(hostStr.size()), -1, 0) != 1 ||
      X509_set_issuer_name(cert.get(), name) != 1 || X509_set_pubkey(cert.get(), key.get()) != 1) {
    fail("subject failed");
  }

  // SAN: IP address if the host parses as one, otherwise a DNS name.
  std::unique_ptr<GENERAL_NAME, GeneralNameFree> san{GENERAL_NAME_new()};
  if (!san) {
    fail("GENERAL_NAME_new failed");
  }
  std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> ip{
      a2i_IPADDRESS(hostStr.c_str()), &ASN1_OCTET_STRING_free};
  if (ip) {
    san->type = GEN_IPADD;
    san->d.iPAddress = ip.release();
  } else {
    ERR_clear_error();
    ASN1_IA5STRING* dns = ASN1_IA5STRING_new();
    if (dns == nullptr ||
        ASN1_STRING_set(dns, hostStr.data(), static_cast<int>(hostStr.size())) != 1) {
      ASN1_IA5STRING_free(dns);
      fail("DNS SAN failed");
    }
    san->type = GEN_DNS;
    san->d.dNSName = dns;
  }
  const std::unique_ptr<GENERAL_NAMES, GeneralNamesFree> names{sk_GENERAL_NAME_new_null()};
  if (!names || sk_GENERAL_NAME_push(names.get(), san.get()) <= 0) {
    fail("SAN list failed");
  }
  // Ownership of the entry moved to the stack (freed by GENERAL_NAMES_free).
  std::ignore = san.release();
  if (X509_add1_ext_i2d(cert.get(), NID_subject_alt_name, names.get(), 0, 0) != 1) {
    fail("SAN extension failed");
  }

  if (X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0) {
    fail("X509_sign failed");
  }

  CertPair pair;
  {
    const BioPtr bio = newMemBio();
    if (PEM_write_bio_X509(bio.get(), cert.get()) != 1) {
      fail("PEM cert write failed");
    }
    pair.certPem = bioToString(bio.get());
  }
  {
    const BioPtr bio = newMemBio();
    if (PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) !=
        1) {
      fail("PEM key write failed");
    }
    pair.keyPem = bioToString(bio.get());
  }
  return pair;
}

std::string spkiPin(std::string_view certPem) {
  if (certPem.empty() ||
      certPem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw CryptoError("invalid certificate PEM");
  }
  const BioPtr bio{BIO_new_mem_buf(certPem.data(), static_cast<int>(certPem.size()))};
  if (!bio) {
    fail("BIO_new_mem_buf failed");
  }
  const X509Ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
  if (!cert) {
    fail("cannot parse certificate");
  }
  unsigned char* der = nullptr;
  const int derLen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert.get()), &der);
  if (derLen <= 0 || der == nullptr) {
    fail("cannot encode public key");
  }
  const std::string derBytes(reinterpret_cast<const char*>(der), static_cast<std::size_t>(derLen));
  OPENSSL_free(der);
  const auto digest = sha256Raw(derBytes);
  return base64Encode(
      std::string_view{reinterpret_cast<const char*>(digest.data()), digest.size()});
}

}  // namespace warden::server
