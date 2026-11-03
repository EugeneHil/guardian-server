#include "crypto.hpp"

#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <regex>
#include <set>
#include <string>

using namespace guardian::server;

TEST(Sha256Hex, KnownVector) {
  EXPECT_EQ(sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(RandomToken, FormatAndUniqueness) {
  const std::regex re{"^wdn_[0-9a-f]{64}$"};
  std::set<std::string> seen;
  for (int i = 0; i < 1000; ++i) {
    const std::string token = randomToken();
    EXPECT_TRUE(std::regex_match(token, re)) << token;
    seen.insert(token);
  }
  EXPECT_EQ(seen.size(), 1000U);
}

TEST(ConstantTimeEquals, Cases) {
  EXPECT_TRUE(constantTimeEquals("", ""));
  EXPECT_TRUE(constantTimeEquals("abc", "abc"));
  EXPECT_FALSE(constantTimeEquals("abc", "abd"));
  EXPECT_FALSE(constantTimeEquals("abc", "abcd"));
  EXPECT_FALSE(constantTimeEquals("", "a"));
}

TEST(Base64, RoundTripAndRfc4648Vectors) {
  EXPECT_EQ(base64Encode(""), "");
  EXPECT_EQ(base64Encode("f"), "Zg==");
  EXPECT_EQ(base64Encode("fo"), "Zm8=");
  EXPECT_EQ(base64Encode("foo"), "Zm9v");
  EXPECT_EQ(base64Encode("foobar"), "Zm9vYmFy");
  EXPECT_EQ(base64Decode("Zm9vYmFy"), std::optional<std::string>{"foobar"});
  EXPECT_EQ(base64Decode("Zm8="), std::optional<std::string>{"fo"});
  EXPECT_EQ(base64Decode(""), std::optional<std::string>{""});
  const std::string binary("\x00\xff\x10\x80", 4);
  EXPECT_EQ(base64Decode(base64Encode(binary)), std::optional<std::string>{binary});
  EXPECT_FALSE(base64Decode("Zm9v!").has_value());
  EXPECT_FALSE(base64Decode("Zm9").has_value());
  EXPECT_FALSE(base64Decode("Zm=v").has_value());
}

namespace {
struct X509Free {
  void operator()(X509* x) const { X509_free(x); }
};
struct BioFree {
  void operator()(BIO* b) const { BIO_free(b); }
};
struct GeneralNamesFree {
  void operator()(GENERAL_NAMES* g) const { GENERAL_NAMES_free(g); }
};

std::unique_ptr<X509, X509Free> parseCert(const std::string& pem) {
  const std::unique_ptr<BIO, BioFree> bio{
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
  return std::unique_ptr<X509, X509Free>{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}
}  // namespace

TEST(SelfSignedCert, PinIsStable44CharBase64AndDiffersPerCert) {
  const CertPair a = generateSelfSignedCert("guardian.example", 30);
  const CertPair b = generateSelfSignedCert("guardian.example", 30);
  EXPECT_NE(a.certPem.find("BEGIN CERTIFICATE"), std::string::npos);
  EXPECT_NE(a.keyPem.find("PRIVATE KEY"), std::string::npos);
  const std::string pin = spkiPin(a.certPem);
  EXPECT_EQ(pin.size(), 44U);
  EXPECT_EQ(pin, spkiPin(a.certPem));
  EXPECT_NE(pin, spkiPin(b.certPem));
  const auto decoded = base64Decode(pin);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->size(), 32U);
}

TEST(SelfSignedCert, SanContainsIpOrDns) {
  const auto sanType = [](const std::string& host) {
    const CertPair pair = generateSelfSignedCert(host, 30);
    const auto cert = parseCert(pair.certPem);
    EXPECT_NE(cert, nullptr);
    const std::unique_ptr<GENERAL_NAMES, GeneralNamesFree> names{static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr))};
    EXPECT_NE(names, nullptr);
    EXPECT_EQ(sk_GENERAL_NAME_num(names.get()), 1);
    return sk_GENERAL_NAME_value(names.get(), 0)->type;
  };
  EXPECT_EQ(sanType("203.0.113.7"), GEN_IPADD);
  EXPECT_EQ(sanType("2001:db8::1"), GEN_IPADD);
  EXPECT_EQ(sanType("guardian.example"), GEN_DNS);
}

TEST(Spki, RejectsGarbagePem) {
  EXPECT_THROW(spkiPin("not a pem"), CryptoError);
  EXPECT_THROW(spkiPin(""), CryptoError);
}

TEST(SelfSignedCert, RejectsInvalidValidity) {
  EXPECT_THROW(generateSelfSignedCert("guardian.example", 0), CryptoError);
  EXPECT_THROW(generateSelfSignedCert("guardian.example", -1), CryptoError);
  EXPECT_THROW(generateSelfSignedCert("guardian.example", 36501), CryptoError);
  EXPECT_NO_THROW(generateSelfSignedCert("guardian.example", 36500));
}
