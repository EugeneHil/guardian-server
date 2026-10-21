#pragma once

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "timeutil.hpp"

namespace warden::server {

// [A-Za-z0-9._-]{1,64}
bool isValidAgentId(std::string_view id) noexcept;

struct AgentInfo {
  std::string id;
  std::string createdAt;
};

class AgentStore {
 public:
  virtual ~AgentStore() = default;

  // Creates an agent and returns its new token (shown once, only its hash is stored).
  // nullopt if the id already exists. Throws StorageError on I/O or corrupt-store errors and
  // std::invalid_argument on an invalid id.
  virtual std::optional<std::string> add(std::string_view agentId) = 0;
  virtual bool remove(std::string_view agentId) = 0;
  // Sorted by id. Throws StorageError if the store is unreadable or corrupt.
  [[nodiscard]] virtual std::vector<AgentInfo> list() const = 0;
  // The agent id owning `token`, or nullopt. An unreadable or corrupt store authenticates nobody.
  [[nodiscard]] virtual std::optional<std::string> authenticate(std::string_view token) const = 0;
};

// Agents persisted in <dataDir>/agents.json. The file is re-read on every operation, so
// changes made by another process or instance (e.g. the CLI) apply immediately.
class FileAgentStore final : public AgentStore {
 public:
  FileAgentStore(const std::filesystem::path& dataDir, NowFn now);

  std::optional<std::string> add(std::string_view agentId) override;
  bool remove(std::string_view agentId) override;
  [[nodiscard]] std::vector<AgentInfo> list() const override;
  [[nodiscard]] std::optional<std::string> authenticate(std::string_view token) const override;

 private:
  struct Entry {
    std::string id;
    std::string tokenHash;
    std::string createdAt;
  };
  std::vector<Entry> load() const;  // throws StorageError when corrupt
  void save(const std::vector<Entry>& entries) const;

  std::filesystem::path file_;
  NowFn now_;
  mutable std::mutex mutex_;
};

}  // namespace warden::server
