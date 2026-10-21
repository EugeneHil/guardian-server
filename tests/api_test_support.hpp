#pragma once

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "agent_store.hpp"
#include "api.hpp"
#include "auth.hpp"
#include "event_store.hpp"
#include "fs_util.hpp"
#include "policy_service.hpp"
#include "policy_store.hpp"

namespace warden::server::testing {

class ApiTempDir {
 public:
  ApiTempDir() {
    path_ = std::filesystem::temp_directory_path() /
            ("warden_api_test_" + std::to_string(counter_++) + "_" +
             std::to_string(reinterpret_cast<std::uintptr_t>(this)));
    std::filesystem::create_directories(path_);
  }
  ApiTempDir(const ApiTempDir&) = delete;
  ApiTempDir& operator=(const ApiTempDir&) = delete;
  ~ApiTempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  static inline int counter_ = 0;
  std::filesystem::path path_;
};

// EventStore double whose append() always throws `StorageError` (with a secret-looking message)
// or, when `plain` is set, a std::runtime_error.
class ThrowingEventStore final : public EventStore {
 public:
  explicit ThrowingEventStore(bool plain = false) : plain_(plain) {}
  void append(std::string_view, const std::vector<Event>&) override {
    if (plain_) {
      throw std::runtime_error("boom /secret/path");
    }
    throw StorageError("cannot write /secret/path/events.jsonl");
  }
  [[nodiscard]] std::vector<StoredEvent> recent(std::size_t) const override {
    throw StorageError("cannot read /secret/path/events.jsonl");
  }

 private:
  bool plain_;
};

// Real file-backed stores in a temp dir, a fake clock and an Api. Reusable by admin tests.
class ApiFixture : public ::testing::Test {
 public:
  static constexpr const char* kAdminPassword = "correct horse battery";

  ApiFixture()
      : policyStore_(dir_.path()),
        agents_(dir_.path(), clock()),
        events_(dir_.path(), clock()),
        throttle_(clock()),
        policies_(policyStore_),
        api_(deps(events_)) {}

  NowFn clock() {
    return [this] { return now_; };
  }
  void advance(int seconds) { now_ += std::chrono::seconds(seconds); }

  ApiDeps deps(EventStore& events) {
    return ApiDeps{policies_, agents_, events, throttle_, kAdminPassword, dir_.path() / "web"};
  }

  // Creates an agent and returns its token.
  std::string addAgent(const std::string& id) {
    auto token = agents_.add(id);
    EXPECT_TRUE(token.has_value());
    return token.value_or("");
  }

  static HttpRequest request(const std::string& method, const std::string& path,
                             const std::string& authorization = "",
                             const std::string& addr = "10.0.0.1") {
    HttpRequest r;
    r.method = method;
    r.path = path;
    r.remoteAddr = addr;
    if (!authorization.empty()) {
      r.headers["authorization"] = authorization;
    }
    return r;
  }
  static HttpRequest bearer(const std::string& method, const std::string& path,
                            const std::string& token, const std::string& addr = "10.0.0.1") {
    return request(method, path, "Bearer " + token, addr);
  }

  TimePoint now_ = TimePoint(std::chrono::seconds(1700000000));
  ApiTempDir dir_;
  FilePolicyStore policyStore_;
  FileAgentStore agents_;
  FileEventStore events_;
  AuthThrottle throttle_;
  PolicyService policies_;
  Api api_;
};

}  // namespace warden::server::testing
