#include "config.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

using namespace guardian::server;

namespace {

constexpr const char* kPassword = "correct-horse-battery";

EnvLookup envOf(std::map<std::string, std::string> vars) {
  return [vars = std::move(vars)](std::string_view name) -> std::optional<std::string> {
    const auto it = vars.find(std::string(name));
    if (it == vars.end()) {
      return std::nullopt;
    }
    return it->second;
  };
}

bool hasError(const ConfigResult& r, const std::string& message) {
  return std::find(r.errors.begin(), r.errors.end(), message) != r.errors.end();
}

const std::string kPasswordError = "adminPassword: must be at least 12 characters";
const std::string kTlsError =
    "tls: certPath and keyPath are required (or set allowInsecureHttp on a loopback host)";
const std::string kInsecureError =
    "allowInsecureHttp: only allowed with host 127.0.0.1, ::1 or localhost";
const std::string kPortError = "port: must be between 1 and 65535";
const std::string kTls = R"("tls":{"certPath":"cert-path","keyPath":"key-path"})";

}  // namespace

TEST(Config, AcceptsMinimalValidConfig) {
  const auto r =
      loadConfig("{\"adminPassword\":\"correct-horse-battery\"," + kTls + "}", envOf({}));
  ASSERT_TRUE(r.config.has_value());
  EXPECT_TRUE(r.errors.empty());
  EXPECT_EQ(r.config->host, "0.0.0.0");
  EXPECT_EQ(r.config->port, 8443);
  EXPECT_EQ(r.config->dataDir, "data");
  EXPECT_EQ(r.config->webRoot, "web");
  EXPECT_FALSE(r.config->allowInsecureHttp);
  ASSERT_TRUE(r.config->tls.has_value());
  EXPECT_EQ(r.config->tls->certPath, "cert-path");
  EXPECT_EQ(r.config->tls->keyPath, "key-path");
}

TEST(Config, EnvOverridesFile) {
  const auto r =
      loadConfig("{\"host\":\"1.2.3.4\",\"port\":9000,\"dataDir\":\"a\",\"webRoot\":\"b\"," +
                     std::string("\"adminPassword\":\"short\",") + kTls + "}",
                 envOf({{"WARDEN_HOST", "10.0.0.1"},
                        {"WARDEN_PORT", "9443"},
                        {"WARDEN_DATA_DIR", "dd"},
                        {"WARDEN_WEB_ROOT", "ww"},
                        {"WARDEN_TLS_CERT", "env-cert"},
                        {"WARDEN_TLS_KEY", "env-key"},
                        {"WARDEN_ADMIN_PASSWORD", kPassword}}));
  ASSERT_TRUE(r.config.has_value());
  EXPECT_EQ(r.config->host, "10.0.0.1");
  EXPECT_EQ(r.config->port, 9443);
  EXPECT_EQ(r.config->dataDir, "dd");
  EXPECT_EQ(r.config->webRoot, "ww");
  EXPECT_EQ(r.config->adminPassword, kPassword);
  ASSERT_TRUE(r.config->tls.has_value());
  EXPECT_EQ(r.config->tls->certPath, "env-cert");
  EXPECT_EQ(r.config->tls->keyPath, "env-key");
}

TEST(Config, EnvAloneCanConfigureWithoutFile) {
  const auto r = loadConfig("", envOf({{"WARDEN_ADMIN_PASSWORD", kPassword},
                                       {"WARDEN_TLS_CERT", "cert-path"},
                                       {"WARDEN_TLS_KEY", "key-path"}}));
  EXPECT_TRUE(r.config.has_value());
}

TEST(Config, RejectsShortOrEmptyPassword) {
  for (const std::string& body : {"{\"adminPassword\":\"elevenchars\"," + kTls + "}",
                                  "{\"adminPassword\":\"\"," + kTls + "}", "{" + kTls + "}"}) {
    const auto r = loadConfig(body, envOf({}));
    EXPECT_FALSE(r.config.has_value()) << body;
    EXPECT_TRUE(hasError(r, kPasswordError)) << body;
  }
  const auto eleven = loadConfig("{\"adminPassword\":\"twelvechars\"," + kTls + "}", envOf({}));
  EXPECT_TRUE(hasError(eleven, kPasswordError));
  const auto twelve = loadConfig("{\"adminPassword\":\"twelvechars!\"," + kTls + "}", envOf({}));
  EXPECT_TRUE(twelve.config.has_value());
}

TEST(Config, RequiresTlsUnlessLoopbackInsecure) {
  const auto r = loadConfig(R"({"adminPassword":"correct-horse-battery"})", envOf({}));
  EXPECT_FALSE(r.config.has_value());
  EXPECT_TRUE(hasError(r, kTlsError));
  const auto half = loadConfig(
      R"({"adminPassword":"correct-horse-battery","tls":{"certPath":"cert-path"}})", envOf({}));
  EXPECT_TRUE(hasError(half, kTlsError));
  const auto loop = loadConfig(
      R"({"adminPassword":"correct-horse-battery","host":"127.0.0.1","allowInsecureHttp":true})",
      envOf({}));
  ASSERT_TRUE(loop.config.has_value());
  EXPECT_FALSE(loop.config->tls.has_value());
}

TEST(Config, InsecureHttpOnPublicHostIsRejected) {
  for (const char* host : {"0.0.0.0", "203.0.113.7"}) {
    const auto r = loadConfig(std::string(R"({"adminPassword":"correct-horse-battery","host":")") +
                                  host + R"(","allowInsecureHttp":true})",
                              envOf({}));
    EXPECT_FALSE(r.config.has_value()) << host;
    EXPECT_TRUE(hasError(r, kInsecureError)) << host;
  }
}

TEST(Config, InsecureHttpOnLoopbackIsAccepted) {
  for (const char* host : {"127.0.0.1", "::1", "localhost"}) {
    const auto r = loadConfig(std::string(R"({"adminPassword":"correct-horse-battery","host":")") +
                                  host + R"(","allowInsecureHttp":true})",
                              envOf({}));
    EXPECT_TRUE(r.config.has_value()) << host;
  }
}

TEST(Config, RejectsBadPorts) {
  const std::string pre = "{\"adminPassword\":\"correct-horse-battery\"," + kTls + ",\"port\":";
  for (const char* port : {"0", "65536", "-1"}) {
    const auto r = loadConfig(pre + port + "}", envOf({}));
    EXPECT_FALSE(r.config.has_value()) << port;
    EXPECT_TRUE(hasError(r, kPortError)) << port;
  }
  const auto str = loadConfig(pre + "\"8443\"}", envOf({}));
  EXPECT_FALSE(str.config.has_value());
  EXPECT_TRUE(hasError(str, "port: wrong type"));
  const auto env = loadConfig(pre + "8443}", envOf({{"WARDEN_PORT", "abc"}}));
  EXPECT_FALSE(env.config.has_value());
  EXPECT_TRUE(hasError(env, kPortError));
  const auto big = loadConfig(pre + "8443}", envOf({{"WARDEN_PORT", "99999999999999999999"}}));
  EXPECT_TRUE(hasError(big, kPortError));
  EXPECT_TRUE(loadConfig(pre + "65535}", envOf({})).config.has_value());
  EXPECT_TRUE(loadConfig(pre + "1}", envOf({})).config.has_value());
}

TEST(Config, RejectsUnknownKeysAndWrongTypes) {
  const auto unknown = loadConfig(
      "{\"adminPassword\":\"correct-horse-battery\"," + kTls + ",\"bogus\":1,\"_comment\":\"x\"}",
      envOf({}));
  EXPECT_FALSE(unknown.config.has_value());
  EXPECT_TRUE(hasError(unknown, "bogus: unknown key"));
  EXPECT_FALSE(hasError(unknown, "_comment: unknown key"));

  const auto nested = loadConfig(
      R"({"adminPassword":"correct-horse-battery","tls":{"certPath":"a","keyPath":"b","x":1}})",
      envOf({}));
  EXPECT_TRUE(hasError(nested, "tls.x: unknown key"));

  const auto types = loadConfig(
      R"({"host":1,"allowInsecureHttp":"yes","dataDir":2,"webRoot":[],"adminPassword":3,
          "tls":"x"})",
      envOf({}));
  EXPECT_FALSE(types.config.has_value());
  for (const char* key :
       {"host", "allowInsecureHttp", "dataDir", "webRoot", "adminPassword", "tls"}) {
    EXPECT_TRUE(hasError(types, std::string(key) + ": wrong type")) << key;
  }
  const auto tlsField = loadConfig(
      R"({"adminPassword":"correct-horse-battery","tls":{"certPath":1,"keyPath":"b"}})", envOf({}));
  EXPECT_TRUE(hasError(tlsField, "tls.certPath: wrong type"));
}

TEST(Config, GarbageJsonIsAnError) {
  const auto empty = loadConfig("{}", envOf({}));
  EXPECT_FALSE(empty.config.has_value());
  EXPECT_FALSE(hasError(empty, "$: invalid JSON"));
  for (const std::string& bad : {std::string("[]"), std::string("{"), std::string("42"),
                                 std::string("{\"host\":\"\xff\xfe\"}"), std::string("\xff")}) {
    const auto r = loadConfig(bad, envOf({}));
    EXPECT_FALSE(r.config.has_value());
    EXPECT_TRUE(hasError(r, "$: invalid JSON")) << bad;
  }
}

TEST(Config, ReportsAllErrorsTogether) {
  const auto r = loadConfig(
      R"({"port":0,"allowInsecureHttp":true,"adminPassword":"short","bogus":true})", envOf({}));
  EXPECT_FALSE(r.config.has_value());
  EXPECT_TRUE(hasError(r, kPortError));
  EXPECT_TRUE(hasError(r, kPasswordError));
  EXPECT_TRUE(hasError(r, kInsecureError));
  EXPECT_TRUE(hasError(r, "bogus: unknown key"));
  EXPECT_GE(r.errors.size(), 4U);
}

TEST(Config, ErrorsNeverContainThePassword) {
  const auto r = loadConfig(R"({"adminPassword":"SECRETVALUE","port":0,"bogus":1})", envOf({}));
  for (const auto& e : r.errors) {
    EXPECT_EQ(e.find("SECRETVALUE"), std::string::npos) << e;
  }
  const auto wrong = loadConfig(R"({"adminPassword":["SECRETVALUE"]})", envOf({}));
  for (const auto& e : wrong.errors) {
    EXPECT_EQ(e.find("SECRETVALUE"), std::string::npos) << e;
  }
}

TEST(Config, ExampleConfigParsesButIsNotValid) {
  std::ifstream in(std::string(GUARDIAN_SERVER_SOURCE_DIR) + "/config.example.json",
                   std::ios::binary);
  ASSERT_TRUE(in.is_open());
  std::stringstream buf;
  buf << in.rdbuf();
  const auto r = loadConfig(buf.str(), envOf({}));
  EXPECT_FALSE(r.config.has_value());
  EXPECT_TRUE(hasError(r, kPasswordError));
  EXPECT_FALSE(hasError(r, "$: invalid JSON"));
  for (const auto& e : r.errors) {
    EXPECT_EQ(e.find("unknown key"), std::string::npos) << e;
  }
}
