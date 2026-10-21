#include "agent_store.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

#include "fs_util.hpp"
#include "timeutil.hpp"

using namespace warden::server;
namespace fs = std::filesystem;

namespace {
class TempDir {
 public:
  TempDir() {
    path_ = fs::temp_directory_path() / ("warden_agent_test_" + std::to_string(counter_++) + "_" +
                                         std::to_string(reinterpret_cast<std::uintptr_t>(this)));
    fs::create_directories(path_);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  static inline int counter_ = 0;
  fs::path path_;
};

NowFn fakeNow() {
  return [] { return TimePoint{std::chrono::seconds{1'792'571'400}}; };  // fixed instant
}

fs::path agentsFile(const TempDir& dir) { return dir.path() / "data" / "agents.json"; }
}  // namespace

TEST(AgentStore, AddReturnsTokenThatAuthenticates) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  const auto token = store.add("agent-1");
  ASSERT_TRUE(token.has_value());
  EXPECT_EQ(token->rfind("wdn_", 0), 0U);
  EXPECT_EQ(store.authenticate(*token), std::optional<std::string>{"agent-1"});
}

TEST(AgentStore, TokenIsStoredHashedOnly) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  const auto token = store.add("agent-1");
  ASSERT_TRUE(token.has_value());
  const auto raw = readFile(agentsFile(dir));
  ASSERT_TRUE(raw.has_value());
  EXPECT_EQ(raw->find(*token), std::string::npos);
  EXPECT_EQ(raw->find("wdn_"), std::string::npos);
  EXPECT_NE(raw->find("tokenHash"), std::string::npos);
}

TEST(AgentStore, DuplicateIdReturnsNullopt) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  ASSERT_TRUE(store.add("a").has_value());
  EXPECT_FALSE(store.add("a").has_value());
  EXPECT_EQ(store.list().size(), 1U);
}

TEST(AgentStore, InvalidIdThrows) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  EXPECT_THROW(store.add(""), std::invalid_argument);
  EXPECT_THROW(store.add(std::string(65, 'a')), std::invalid_argument);
  EXPECT_THROW(store.add("../x"), std::invalid_argument);
  EXPECT_THROW(store.add("a b"), std::invalid_argument);
  EXPECT_THROW(store.add(std::string("a\0b", 3)), std::invalid_argument);
  EXPECT_TRUE(isValidAgentId(std::string(64, 'a')));
  EXPECT_TRUE(isValidAgentId("A.b_c-9"));
}

TEST(AgentStore, RemoveRevokesImmediately) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  const auto token = store.add("a");
  ASSERT_TRUE(token.has_value());
  EXPECT_TRUE(store.remove("a"));
  EXPECT_FALSE(store.authenticate(*token).has_value());
  EXPECT_FALSE(store.remove("a"));
  EXPECT_TRUE(store.list().empty());
}

TEST(AgentStore, AuthenticateRejectsGarbage) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  const auto token = store.add("a");
  ASSERT_TRUE(token.has_value());
  EXPECT_FALSE(store.authenticate("").has_value());
  EXPECT_FALSE(store.authenticate(std::string(1024 * 1024, 'x')).has_value());
  EXPECT_FALSE(store.authenticate("bad_" + token->substr(4)).has_value());
  EXPECT_FALSE(store.authenticate(token->substr(0, token->size() - 1)).has_value());
  EXPECT_FALSE(store.authenticate(*token + "0").has_value());
}

TEST(AgentStore, CorruptAgentsFileAuthenticatesNobody) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  const auto token = store.add("a");
  ASSERT_TRUE(token.has_value());
  for (const char* corrupt : {"{\"agents\":[{\"id\":\"a\",\"tok", "[]", "{\"agents\":\"x\"}"}) {
    writeFileAtomic(agentsFile(dir), corrupt, true);
    EXPECT_FALSE(store.authenticate(*token).has_value()) << corrupt;
    EXPECT_THROW((void)store.list(), StorageError) << corrupt;
  }
}

TEST(AgentStore, MissingFileMeansNoAgents) {
  const TempDir dir;
  const FileAgentStore store(dir.path(), fakeNow());
  EXPECT_TRUE(store.list().empty());
  EXPECT_FALSE(store.authenticate("wdn_x").has_value());
}

TEST(AgentStore, SecondInstanceSeesChangesFromFirst) {
  const TempDir dir;
  FileAgentStore server(dir.path(), fakeNow());
  FileAgentStore cli(dir.path(), fakeNow());
  const auto token = cli.add("a");
  ASSERT_TRUE(token.has_value());
  EXPECT_EQ(server.authenticate(*token), std::optional<std::string>{"a"});
  EXPECT_TRUE(cli.remove("a"));
  EXPECT_FALSE(server.authenticate(*token).has_value());
}

TEST(AgentStore, ListIsSortedByIdWithCreatedAt) {
  const TempDir dir;
  FileAgentStore store(dir.path(), fakeNow());
  ASSERT_TRUE(store.add("zeta").has_value());
  ASSERT_TRUE(store.add("alpha").has_value());
  ASSERT_TRUE(store.add("mid").has_value());
  const auto agents = store.list();
  ASSERT_EQ(agents.size(), 3U);
  EXPECT_EQ(agents[0].id, "alpha");
  EXPECT_EQ(agents[1].id, "mid");
  EXPECT_EQ(agents[2].id, "zeta");
  EXPECT_EQ(agents[0].createdAt, formatUtc(fakeNow()()));
}
