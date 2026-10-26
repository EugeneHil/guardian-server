#include "auth.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "crypto.hpp"

using namespace guardian::server;

namespace {
constexpr int kThreads = 4;
constexpr int kIterations = 500;

struct FakeClock {
  TimePoint t = TimePoint(std::chrono::seconds(1000000));
  NowFn fn() {
    return [this] { return t; };
  }
  void advance(int s) { t += std::chrono::seconds(s); }
};

std::string basicHeader(const std::string& raw) { return "Basic " + base64Encode(raw); }
}  // namespace

TEST(Bearer, AcceptsValidAndCaseInsensitiveScheme) {
  EXPECT_EQ(parseBearer("Bearer wdn_abc"), std::optional<std::string>("wdn_abc"));
  EXPECT_EQ(parseBearer("bearer tok"), std::optional<std::string>("tok"));
  EXPECT_EQ(parseBearer("BEARER tok"), std::optional<std::string>("tok"));
  EXPECT_EQ(parseBearer("Bearer " + std::string(256, 'a')),
            std::optional<std::string>(std::string(256, 'a')));
}

TEST(Bearer, RejectsEmptyWhitespaceOversizeAndWrongScheme) {
  EXPECT_FALSE(parseBearer(""));
  EXPECT_FALSE(parseBearer("Bearer "));
  EXPECT_FALSE(parseBearer("Bearer"));
  EXPECT_FALSE(parseBearer("Bearer a b"));
  EXPECT_FALSE(parseBearer("Bearer  a"));
  EXPECT_FALSE(parseBearer("Bearer a "));
  EXPECT_FALSE(parseBearer("Basic x"));
  EXPECT_FALSE(parseBearer("Bearerx"));
  EXPECT_FALSE(parseBearer("Bearer\ttok"));
  EXPECT_FALSE(parseBearer("Bearer tok\t"));
  EXPECT_FALSE(parseBearer("Bearer " + std::string(257, 'a')));
  EXPECT_FALSE(parseBearer("Bearer " + std::string(10 * 1024, 'a')));
  EXPECT_FALSE(parseBearer(std::string(10 * 1024, 'B')));
  EXPECT_FALSE(parseBearer(std::string("Bearer a\0b", 10)));
  EXPECT_FALSE(parseBearer("Bearer \xff\xfe"));
}

TEST(Basic, ParsesUserAndPasswordWithColonInPassword) {
  auto c = parseBasic(basicHeader("admin:pa:ss:word"));
  ASSERT_TRUE(c);
  EXPECT_EQ(c->user, "admin");
  EXPECT_EQ(c->password, "pa:ss:word");
  auto lower = parseBasic("basic " + base64Encode("u:"));
  ASSERT_TRUE(lower);
  EXPECT_EQ(lower->user, "u");
  EXPECT_EQ(lower->password, "");
}

TEST(Basic, RejectsBadBase64AndMissingColon) {
  EXPECT_FALSE(parseBasic("Basic !!!"));
  EXPECT_FALSE(parseBasic("Basic Zm9v"));
  EXPECT_FALSE(parseBasic("Basic "));
  EXPECT_FALSE(parseBasic(""));
  EXPECT_FALSE(parseBasic("Bearer Zm9v"));
  EXPECT_FALSE(parseBasic("Basic\t" + base64Encode("a:b")));
  EXPECT_FALSE(parseBasic("Basic" + base64Encode("a:b")));
  EXPECT_FALSE(parseBasic(std::string("Basic \0\0", 8)));
  EXPECT_FALSE(parseBasic("Basic \xff\xfe\xfd"));
}

TEST(Basic, RejectsOversizeHeader) {
  EXPECT_FALSE(parseBasic("Basic " + base64Encode("admin:" + std::string(2000, 'x'))));
  EXPECT_FALSE(parseBasic(std::string(10 * 1024, 'B')));
  std::string raw = "a:" + std::string(700, 'x');  // 702 bytes -> 936 base64 chars + 6 = 942
  EXPECT_TRUE(parseBasic("Basic " + base64Encode(raw)));
}

TEST(AdminMatch, RequiresUserAdmin) {
  EXPECT_TRUE(adminCredentialsMatch({"admin", "secret"}, "secret"));
  EXPECT_FALSE(adminCredentialsMatch({"root", "secret"}, "secret"));
  EXPECT_FALSE(adminCredentialsMatch({"Admin", "secret"}, "secret"));
  EXPECT_FALSE(adminCredentialsMatch({"", "secret"}, "secret"));
}

TEST(AdminMatch, WrongOrEmptyPasswordFails) {
  EXPECT_FALSE(adminCredentialsMatch({"admin", "wrong"}, "secret"));
  EXPECT_FALSE(adminCredentialsMatch({"admin", ""}, "secret"));
  EXPECT_FALSE(adminCredentialsMatch({"admin", ""}, ""));
  EXPECT_FALSE(adminCredentialsMatch({"admin", "secret"}, ""));
}

TEST(Throttle, BlocksAfterFiveFailuresForSixtySeconds) {
  FakeClock clock;
  AuthThrottle t(clock.fn());
  for (int i = 0; i < 4; ++i) {
    t.recordFailure("ip");
    EXPECT_FALSE(t.blocked("ip"));
  }
  t.recordFailure("ip");
  EXPECT_TRUE(t.blocked("ip"));
  clock.advance(59);
  EXPECT_TRUE(t.blocked("ip"));
  clock.advance(1);
  EXPECT_FALSE(t.blocked("ip"));
}

TEST(Throttle, SuccessResetsCounter) {
  FakeClock clock;
  AuthThrottle t(clock.fn());
  for (int i = 0; i < 4; ++i) t.recordFailure("ip");
  t.recordSuccess("ip");
  for (int i = 0; i < 4; ++i) t.recordFailure("ip");
  EXPECT_FALSE(t.blocked("ip"));
  t.recordFailure("ip");
  EXPECT_TRUE(t.blocked("ip"));
}

TEST(Throttle, KeysAreIndependent) {
  FakeClock clock;
  AuthThrottle t(clock.fn());
  for (int i = 0; i < 5; ++i) t.recordFailure("a");
  EXPECT_TRUE(t.blocked("a"));
  EXPECT_FALSE(t.blocked("b"));
  t.recordSuccess("b");
  EXPECT_TRUE(t.blocked("a"));
}

TEST(Throttle, UnblocksAfterLockout) {
  FakeClock clock;
  AuthThrottle t(clock.fn(), 3, std::chrono::seconds(10));
  for (int i = 0; i < 3; ++i) t.recordFailure("a");
  EXPECT_TRUE(t.blocked("a"));
  clock.advance(10);
  EXPECT_FALSE(t.blocked("a"));
  // A fresh failure after lockout starts a new count rather than re-blocking at once.
  t.recordFailure("a");
  EXPECT_FALSE(t.blocked("a"));
}

TEST(Throttle, RetryAfterCountsDown) {
  FakeClock clock;
  AuthThrottle t(clock.fn());
  EXPECT_EQ(t.retryAfter("a").count(), 0);
  for (int i = 0; i < 5; ++i) t.recordFailure("a");
  EXPECT_EQ(t.retryAfter("a").count(), 60);
  clock.advance(20);
  EXPECT_EQ(t.retryAfter("a").count(), 40);
  clock.advance(40);
  EXPECT_EQ(t.retryAfter("a").count(), 0);
}

TEST(Throttle, BoundsMemory) {
  FakeClock clock;
  AuthThrottle t(clock.fn());
  for (int i = 0; i < 20000; ++i) t.recordFailure("k" + std::to_string(i));
  // Newest keys survive, oldest were evicted (their counters are gone).
  for (int i = 0; i < 4; ++i) t.recordFailure("k19999");
  EXPECT_TRUE(t.blocked("k19999"));
  for (int i = 0; i < 4; ++i) t.recordFailure("k0");
  EXPECT_FALSE(t.blocked("k0"));
  t.recordFailure("k0");
  EXPECT_TRUE(t.blocked("k0"));
}

TEST(Throttle, IsThreadSafe) {
  FakeClock clock;
  AuthThrottle t(clock.fn());
  std::vector<std::thread> threads;
  for (int n = 0; n < kThreads; ++n) {
    threads.emplace_back([&t, n] {
      for (int i = 0; i < kIterations; ++i) {
        std::string key = "k" + std::to_string((i + n) % 50);
        t.recordFailure(key);
        t.blocked(key);
        t.retryAfter(key);
        if (i % 7 == 0) t.recordSuccess(key);
      }
    });
  }
  for (auto& th : threads) th.join();
  SUCCEED();
}
