#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "timeutil.hpp"

namespace warden::server {

// "Bearer <token>": scheme is case-insensitive, exactly one space, token is 1..256 printable
// ASCII bytes without whitespace. Total: never throws.
std::optional<std::string> parseBearer(std::string_view authorizationHeader);

struct BasicCredentials {
  std::string user;
  std::string password;
};

// "Basic <base64(user:password)>": header at most 1024 bytes, split at the first ':'.
std::optional<BasicCredentials> parseBasic(std::string_view authorizationHeader);

// True only for user "admin" and a non-empty matching password. Both comparisons always run.
bool adminCredentialsMatch(const BasicCredentials& credentials,
                           std::string_view expectedPassword) noexcept;

// Per-key consecutive-failure lockout. Thread-safe; tracks at most kMaxKeys keys.
class AuthThrottle {
 public:
  static constexpr std::size_t kMaxKeys = 10000;

  explicit AuthThrottle(NowFn now, int maxFailures = 5,
                        std::chrono::seconds lockout = std::chrono::seconds(60));

  bool blocked(const std::string& key);
  std::chrono::seconds retryAfter(const std::string& key);
  void recordFailure(const std::string& key);
  void recordSuccess(const std::string& key);

 private:
  struct Entry {
    int failures = 0;
    TimePoint last;
    std::uint64_t seq = 0;
  };

  std::chrono::seconds remainingLocked(const std::string& key);

  NowFn now_;
  int maxFailures_;
  std::chrono::seconds lockout_;
  std::mutex mutex_;
  std::uint64_t nextSeq_ = 0;
  std::unordered_map<std::string, Entry> entries_;
  std::map<std::uint64_t, std::string> order_;  // seq -> key, oldest first
};

}  // namespace warden::server
