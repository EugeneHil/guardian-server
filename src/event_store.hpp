#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string_view>
#include <vector>

#include "event.hpp"
#include "timeutil.hpp"

namespace warden::server {

class EventStore {
 public:
  virtual ~EventStore() = default;

  // Throws StorageError if the events cannot be persisted.
  virtual void append(std::string_view agentId, const std::vector<Event>& events) = 0;
  // Newest first; at most `limit` entries. Unreadable (e.g. torn) lines are skipped.
  [[nodiscard]] virtual std::vector<StoredEvent> recent(std::size_t limit) const = 0;
};

// One JSON object per line in <dataDir>/events.jsonl. When a line would push the file past
// maxFileBytes it rotates to events.1.jsonl ... events.<keepFiles-1>.jsonl (the oldest is
// deleted). keepFiles counts the live file, so it is clamped to at least 1.
constexpr std::uintmax_t kDefaultMaxEventFileBytes = 5242880;  // 5 MiB
constexpr int kDefaultKeepEventFiles = 5;

class FileEventStore final : public EventStore {
 public:
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): byte limit and file count are distinct
  FileEventStore(std::filesystem::path dataDir, NowFn now,
                 std::uintmax_t maxFileBytes = kDefaultMaxEventFileBytes,
                 int keepFiles = kDefaultKeepEventFiles);

  void append(std::string_view agentId, const std::vector<Event>& events) override;
  [[nodiscard]] std::vector<StoredEvent> recent(std::size_t limit) const override;

 private:
  [[nodiscard]] std::filesystem::path fileFor(int index) const;
  void rotate();

  std::filesystem::path dir_;
  NowFn now_;
  std::uintmax_t maxFileBytes_;
  int keepFiles_;
  mutable std::mutex mutex_;
};

}  // namespace warden::server
