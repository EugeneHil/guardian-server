#include "auth.hpp"

#include <utility>

#include "crypto.hpp"

namespace guardian::server {

namespace {

constexpr std::size_t kMaxBearerTokenBytes = 256;
constexpr std::size_t kMaxBasicHeaderBytes = 1024;

char lowerAscii(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

// Matches "<scheme> " (case-insensitive scheme, exactly one space) and returns the remainder.
std::optional<std::string_view> stripScheme(std::string_view header, std::string_view scheme) {
  if (header.size() <= scheme.size()) {
    return std::nullopt;
  }
  for (std::size_t i = 0; i < scheme.size(); ++i) {
    if (lowerAscii(header[i]) != scheme[i]) {
      return std::nullopt;
    }
  }
  if (header[scheme.size()] != ' ') {
    return std::nullopt;
  }
  return header.substr(scheme.size() + 1);
}

bool isTokenChar(char c) {
  const auto u = static_cast<unsigned char>(c);
  return u >= 0x21 && u <= 0x7e;
}

}  // namespace

std::optional<std::string> parseBearer(std::string_view authorizationHeader) {
  auto rest = stripScheme(authorizationHeader, "bearer");
  if (!rest || rest->empty() || rest->size() > kMaxBearerTokenBytes) {
    return std::nullopt;
  }
  for (char c : *rest) {
    if (!isTokenChar(c)) {
      return std::nullopt;
    }
  }
  return std::string(*rest);
}

std::optional<BasicCredentials> parseBasic(std::string_view authorizationHeader) {
  if (authorizationHeader.size() > kMaxBasicHeaderBytes) {
    return std::nullopt;
  }
  auto rest = stripScheme(authorizationHeader, "basic");
  if (!rest || rest->empty()) {
    return std::nullopt;
  }
  auto decoded = base64Decode(*rest);
  if (!decoded) {
    return std::nullopt;
  }
  const auto colon = decoded->find(':');
  if (colon == std::string::npos) {
    return std::nullopt;
  }
  return BasicCredentials{decoded->substr(0, colon), decoded->substr(colon + 1)};
}

bool adminCredentialsMatch(const BasicCredentials& credentials,
                           std::string_view expectedPassword) noexcept {
  const bool userOk = constantTimeEquals(credentials.user, "admin");
  const bool passwordOk = constantTimeEquals(credentials.password, expectedPassword);
  const bool nonEmpty = !expectedPassword.empty();
  return userOk && passwordOk && nonEmpty;  // both comparisons were already evaluated above
}

AuthThrottle::AuthThrottle(NowFn now, int maxFailures, std::chrono::seconds lockout)
    : now_(std::move(now)), maxFailures_(maxFailures), lockout_(lockout) {}

std::chrono::seconds AuthThrottle::remainingLocked(const std::string& key) {
  const auto it = entries_.find(key);
  if (it == entries_.end() || it->second.failures < maxFailures_) {
    return std::chrono::seconds(0);
  }
  const auto left = it->second.last + lockout_ - now_();
  if (left <= TimePoint::duration::zero()) {
    return std::chrono::seconds(0);
  }
  // Round up so a client never retries early.
  return std::chrono::duration_cast<std::chrono::seconds>(left + std::chrono::seconds(1) -
                                                          TimePoint::duration(1));
}

bool AuthThrottle::blocked(const std::string& key) {
  const std::scoped_lock lock(mutex_);
  return remainingLocked(key).count() > 0;
}

std::chrono::seconds AuthThrottle::retryAfter(const std::string& key) {
  const std::scoped_lock lock(mutex_);
  return remainingLocked(key);
}

void AuthThrottle::recordFailure(const std::string& key) {
  const std::scoped_lock lock(mutex_);
  const TimePoint now = now_();
  auto it = entries_.find(key);
  if (it == entries_.end()) {
    while (entries_.size() >= kMaxKeys && !order_.empty()) {
      entries_.erase(order_.begin()->second);
      order_.erase(order_.begin());
    }
    it = entries_.emplace(key, Entry{}).first;
  } else {
    order_.erase(it->second.seq);
    if (it->second.failures >= maxFailures_ && now >= it->second.last + lockout_) {
      it->second.failures = 0;  // lockout served: start a fresh count
    }
  }
  it->second.failures += 1;
  it->second.last = now;
  it->second.seq = nextSeq_++;
  order_.emplace(it->second.seq, key);
}

void AuthThrottle::recordSuccess(const std::string& key) {
  const std::scoped_lock lock(mutex_);
  const auto it = entries_.find(key);
  if (it == entries_.end()) {
    return;
  }
  order_.erase(it->second.seq);
  entries_.erase(it);
}

}  // namespace guardian::server
