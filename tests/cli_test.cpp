#include "cli.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "agent_store.hpp"
#include "crypto.hpp"
#include "fs_util.hpp"

namespace warden::server {
namespace {

namespace fs = std::filesystem;

// Throwaway test value, not a real secret.
constexpr const char* kTestPassword = "test-only-password-123";

struct CliResult {
  int code = -1;
  std::string out;
  std::string err;
};

class CliTest : public ::testing::Test {
 protected:
  void SetUp() override {
    static std::atomic<int> counter{0};
    root_ =
        fs::temp_directory_path() /
        ("warden-cli-test-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
         "-" + std::to_string(counter++));
    fs::remove_all(root_);
    fs::create_directories(root_);
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(root_, ec);
  }

  [[nodiscard]] std::string dataDir() const { return (root_ / "data").string(); }

  CliResult run(const std::vector<std::string>& args,
                const std::map<std::string, std::string>& env = {}) const {
    std::ostringstream out;
    std::ostringstream err;
    const EnvLookup lookup = [&env](std::string_view key) -> std::optional<std::string> {
      const auto it = env.find(std::string(key));
      if (it == env.end()) {
        return std::nullopt;
      }
      return it->second;
    };
    const NowFn now = [] { return std::chrono::system_clock::now(); };
    const int code = runCli(args, out, err, lookup, now);
    return {code, out.str(), err.str()};
  }

  fs::path root_;
};

std::string trimNewline(std::string text) {
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
    text.pop_back();
  }
  return text;
}

TEST_F(CliTest, Version) {
  const auto r = run({"version"});
  EXPECT_EQ(r.code, 0);
  EXPECT_EQ(r.out, "warden-server 0.1.0\n");
}

TEST_F(CliTest, HelpAndNoArgs) {
  EXPECT_EQ(run({"help"}).code, 0);
  EXPECT_NE(run({"help"}).out.find("serve"), std::string::npos);
  const auto r = run({});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("usage"), std::string::npos);
}

TEST_F(CliTest, UnknownCommandIsUsageError2) {
  const auto r = run({"frobnicate"});
  EXPECT_EQ(r.code, 2);
  EXPECT_TRUE(r.out.empty());
  EXPECT_FALSE(r.err.empty());
}

TEST_F(CliTest, StrictArgumentParsing) {
  EXPECT_EQ(run({"token", "add", "a1", "--bogus", "x"}).code, 2);
  EXPECT_EQ(run({"token", "add", "a1", "--data-dir"}).code, 2);
  EXPECT_EQ(run({"token", "add", "a1", "--data-dir", "x", "--data-dir", "y"}).code, 2);
  EXPECT_EQ(run({"token", "add"}).code, 2);
  EXPECT_EQ(run({"token", "add", "a", "b"}).code, 2);
  EXPECT_EQ(run({"token"}).code, 2);
  EXPECT_EQ(run({"token", "wat"}).code, 2);
  EXPECT_EQ(run({"cert"}).code, 2);
  EXPECT_EQ(run({"cert", "generate"}).code, 2);
  EXPECT_EQ(run({"cert", "pin"}).code, 2);
  EXPECT_EQ(run({"serve", "--nope"}).code, 2);
  EXPECT_EQ(run({"serve", "--config"}).code, 2);
  EXPECT_EQ(run({"version", "extra"}).code, 2);
}

TEST_F(CliTest, TokenAddPrintsOnlyTokenAndItAuthenticates) {
  const auto r = run({"token", "add", "agent-1", "--data-dir", dataDir()});
  ASSERT_EQ(r.code, 0) << r.err;
  ASSERT_FALSE(r.out.empty());
  EXPECT_EQ(r.out.back(), '\n');
  const std::string token = trimNewline(r.out);
  EXPECT_EQ(token.find('\n'), std::string::npos);
  EXPECT_EQ(token.rfind("wdn_", 0), 0U);
  EXPECT_FALSE(r.err.empty());
  EXPECT_EQ(r.err.find(token), std::string::npos);

  FileAgentStore store(dataDir(), [] { return std::chrono::system_clock::now(); });
  EXPECT_EQ(store.authenticate(token), std::optional<std::string>("agent-1"));
}

TEST_F(CliTest, TokenCommandsUseDataDirFromEnv) {
  const auto r = run({"token", "add", "agent-1"}, {{"WARDEN_DATA_DIR", dataDir()}});
  ASSERT_EQ(r.code, 0) << r.err;
  EXPECT_TRUE(fs::exists(fs::path(dataDir()) / "agents.json"));
}

TEST_F(CliTest, TokenAddDuplicateExits1) {
  ASSERT_EQ(run({"token", "add", "agent-1", "--data-dir", dataDir()}).code, 0);
  const auto r = run({"token", "add", "agent-1", "--data-dir", dataDir()});
  EXPECT_EQ(r.code, 1);
  EXPECT_TRUE(r.out.empty());
  EXPECT_NE(r.err.find("already exists"), std::string::npos);
}

TEST_F(CliTest, TokenAddInvalidIdExits1) {
  const auto r = run({"token", "add", "bad id/../", "--data-dir", dataDir()});
  EXPECT_EQ(r.code, 1);
  EXPECT_TRUE(r.out.empty());
  EXPECT_NE(r.err.find("invalid agent id"), std::string::npos);
}

TEST_F(CliTest, TokenListNeverPrintsHashesOrTokens) {
  const auto a = run({"token", "add", "alpha", "--data-dir", dataDir()});
  const auto b = run({"token", "add", "beta", "--data-dir", dataDir()});
  const auto r = run({"token", "list", "--data-dir", dataDir()});
  ASSERT_EQ(r.code, 0) << r.err;
  EXPECT_NE(r.out.find("alpha"), std::string::npos);
  EXPECT_NE(r.out.find("beta"), std::string::npos);
  EXPECT_NE(r.out.find("20"), std::string::npos);  // createdAt year
  EXPECT_LT(r.out.find("alpha"), r.out.find("beta"));
  const std::string tokenA = trimNewline(a.out);
  const std::string tokenB = trimNewline(b.out);
  EXPECT_EQ(r.out.find("wdn_"), std::string::npos);
  EXPECT_EQ(r.out.find(tokenA.substr(4)), std::string::npos);
  EXPECT_EQ(r.out.find(sha256Hex(tokenA)), std::string::npos);
  EXPECT_EQ(r.out.find(sha256Hex(tokenB)), std::string::npos);
  const auto stored = readFile(fs::path(dataDir()) / "agents.json");
  ASSERT_TRUE(stored.has_value());
  EXPECT_EQ(r.out.find("tokenHash"), std::string::npos);
}

TEST_F(CliTest, TokenListOnEmptyStoreSucceeds) {
  const auto r = run({"token", "list", "--data-dir", dataDir()});
  EXPECT_EQ(r.code, 0);
  EXPECT_TRUE(r.out.empty());
}

TEST_F(CliTest, TokenRemoveRevokes) {
  const auto added = run({"token", "add", "agent-1", "--data-dir", dataDir()});
  const std::string token = trimNewline(added.out);
  const auto r = run({"token", "remove", "agent-1", "--data-dir", dataDir()});
  EXPECT_EQ(r.code, 0) << r.err;
  FileAgentStore store(dataDir(), [] { return std::chrono::system_clock::now(); });
  EXPECT_FALSE(store.authenticate(token).has_value());

  const auto again = run({"token", "remove", "agent-1", "--data-dir", dataDir()});
  EXPECT_EQ(again.code, 1);
  EXPECT_NE(again.err.find("unknown agent"), std::string::npos);
}

TEST_F(CliTest, TokenOnCorruptStoreExits1) {
  writeFileAtomic(fs::path(dataDir()) / "agents.json", "not json");
  const auto r = run({"token", "list", "--data-dir", dataDir()});
  EXPECT_EQ(r.code, 1);
  EXPECT_NE(r.err.find("error:"), std::string::npos);
}

TEST_F(CliTest, CertGenerateWritesFilesAndPrintsPin) {
  const std::string dir = (root_ / "tls").string();
  const auto r = run({"cert", "generate", "--host", "127.0.0.1", "--out-dir", dir});
  ASSERT_EQ(r.code, 0) << r.err;
  const auto cert = readFile(fs::path(dir) / "server.crt");
  const auto key = readFile(fs::path(dir) / "server.key");
  ASSERT_TRUE(cert.has_value());
  ASSERT_TRUE(key.has_value());
  EXPECT_EQ(r.out, "SPKI pin: " + spkiPin(*cert) + "\n");
#ifndef _WIN32
  const auto perms = fs::status(fs::path(dir) / "server.key").permissions();
  EXPECT_EQ(perms & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
#endif
  // The pin command agrees.
  const auto pin = run({"cert", "pin", (fs::path(dir) / "server.crt").string()});
  EXPECT_EQ(pin.code, 0);
  EXPECT_EQ(pin.out, spkiPin(*cert) + "\n");
}

TEST_F(CliTest, CertGenerateRefusesToOverwrite) {
  const std::string dir = (root_ / "tls").string();
  ASSERT_EQ(run({"cert", "generate", "--host", "localhost", "--out-dir", dir}).code, 0);
  const auto before = readFile(fs::path(dir) / "server.key");
  const auto r = run({"cert", "generate", "--host", "localhost", "--out-dir", dir});
  EXPECT_EQ(r.code, 1);
  EXPECT_TRUE(r.out.empty());
  EXPECT_NE(r.err.find("already exists"), std::string::npos);
  EXPECT_EQ(readFile(fs::path(dir) / "server.key"), before);
}

TEST_F(CliTest, CertGenerateRefusesWhenOnlyOneFileExists) {
  const std::string dir = (root_ / "tls").string();
  writeFileAtomic(fs::path(dir) / "server.key", "keep me");
  const auto r = run({"cert", "generate", "--host", "localhost", "--out-dir", dir});
  EXPECT_EQ(r.code, 1);
  EXPECT_FALSE(fs::exists(fs::path(dir) / "server.crt"));
  EXPECT_EQ(readFile(fs::path(dir) / "server.key"), std::optional<std::string>("keep me"));
}

TEST_F(CliTest, CertGenerateValidatesDays) {
  const std::string dir = (root_ / "tls").string();
  for (const char* bad : {"0", "-5", "abc", "36501", "", "12x", "99999999999999999999"}) {
    const auto r =
        run({"cert", "generate", "--host", "localhost", "--out-dir", dir, "--days", bad});
    EXPECT_EQ(r.code, 2) << bad;
    EXPECT_NE(r.err.find("--days"), std::string::npos) << bad;
  }
  EXPECT_FALSE(fs::exists(fs::path(dir) / "server.crt"));
  EXPECT_EQ(run({"cert", "generate", "--host", "localhost", "--out-dir", dir, "--days", "30"}).code,
            0);
}

TEST_F(CliTest, CertGenerateRejectsBadHostWithFixedMessage) {
  const auto r = run({"cert", "generate", "--host", "", "--out-dir", (root_ / "tls").string()});
  EXPECT_EQ(r.code, 1);
  EXPECT_NE(r.err.find("error:"), std::string::npos);
}

TEST_F(CliTest, CertPinOnGarbageFileExits1) {
  const auto file = root_ / "garbage.pem";
  writeFileAtomic(file, "this is not a certificate");
  const auto r = run({"cert", "pin", file.string()});
  EXPECT_EQ(r.code, 1);
  EXPECT_TRUE(r.out.empty());
  EXPECT_NE(r.err.find("error:"), std::string::npos);
  EXPECT_EQ(run({"cert", "pin", (root_ / "missing.pem").string()}).code, 1);
}

TEST_F(CliTest, ServeWithInvalidConfigPrintsAllErrorsAndExits1) {
  const auto r = run({"serve", "--config", (root_ / "missing.json").string()},
                     {{"WARDEN_ADMIN_PASSWORD", "short"}, {"WARDEN_DATA_DIR", dataDir()}});
  EXPECT_EQ(r.code, 1);
  EXPECT_TRUE(r.out.empty());
  EXPECT_NE(r.err.find("adminPassword"), std::string::npos);
  EXPECT_NE(r.err.find("tls"), std::string::npos);
}

TEST_F(CliTest, ServeErrorsNeverEchoThePassword) {
  const std::string secret = "weakpw-marker-xyz";
  const auto r = run({"serve", "--config", (root_ / "missing.json").string()},
                     {{"WARDEN_ADMIN_PASSWORD", secret}});
  EXPECT_EQ(r.code, 1);
  EXPECT_EQ(r.err.find(secret), std::string::npos);
  EXPECT_EQ(r.out.find(secret), std::string::npos);
}

TEST_F(CliTest, ServeWithUnreadableConfigExits1) {
  // A directory exists but cannot be read as a file.
  const auto r = run({"serve", "--config", root_.string()});
  EXPECT_EQ(r.code, 1);
  EXPECT_NE(r.err.find("cannot read config"), std::string::npos);
}

TEST_F(CliTest, ServeWithCorruptPolicyStoreExits1) {
  writeFileAtomic(fs::path(dataDir()) / "policies" / "active", "garbage\n");
  const auto cfg = root_ / "serve.json";
  writeFileAtomic(cfg, R"({"host":"127.0.0.1","port":18443,"allowInsecureHttp":true})");
  const auto r = run({"serve", "--config", cfg.string()},
                     {{"WARDEN_ADMIN_PASSWORD", kTestPassword}, {"WARDEN_DATA_DIR", dataDir()}});
  EXPECT_EQ(r.code, 1);
  EXPECT_NE(r.err.find("error: cannot open storage"), std::string::npos);
  EXPECT_EQ(r.err.find(kTestPassword), std::string::npos);
}

TEST_F(CliTest, ServeStartsAndStopsOnLoopbackPlainHttp) {
  const auto cfg = root_ / "serve.json";
  writeFileAtomic(cfg, R"({"host":"127.0.0.1","port":18443,"allowInsecureHttp":true})");
  ServeHooks hooks;
  bool hookCalled = false;
  hooks.onReady = [&hookCalled](const std::function<void()>& stop) {
    hookCalled = true;
    stop();  // stop before run(): run() must return true without serving
  };
  std::ostringstream out;
  std::ostringstream err;
  const std::map<std::string, std::string> env{{"WARDEN_ADMIN_PASSWORD", kTestPassword},
                                               {"WARDEN_DATA_DIR", dataDir()}};
  const EnvLookup lookup = [&env](std::string_view key) -> std::optional<std::string> {
    const auto it = env.find(std::string(key));
    return it == env.end() ? std::nullopt : std::optional<std::string>(it->second);
  };
  const NowFn now = [] { return std::chrono::system_clock::now(); };
  const int code = runCli({"serve", "--config", cfg.string()}, out, err, lookup, now, hooks);
  EXPECT_EQ(code, 0) << err.str();
  EXPECT_TRUE(hookCalled);
  EXPECT_NE(err.str().find("listening on 127.0.0.1:18443 (plain http)"), std::string::npos);
  EXPECT_EQ(err.str().find(kTestPassword), std::string::npos);
  EXPECT_TRUE(out.str().empty());
}

}  // namespace
}  // namespace warden::server
