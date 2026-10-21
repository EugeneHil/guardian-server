#include <fstream>
#include <system_error>
#include <utility>

#include "event_store.hpp"
#include "fs_util.hpp"

namespace warden::server {

namespace fs = std::filesystem;

namespace {

// True if the file is non-empty and does not end in '\n' (a torn last line).
bool endsMidLine(const fs::path& path) {
  std::ifstream in(path, std::ios::binary | std::ios::ate);
  if (!in) {
    return false;
  }
  const std::streamoff size = in.tellg();
  if (size <= 0) {
    return false;
  }
  in.seekg(-1, std::ios::end);
  char last = '\n';
  in.get(last);
  return in && last != '\n';
}

}  // namespace

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): byte limit and file count are distinct
FileEventStore::FileEventStore(fs::path dataDir, NowFn now, std::uintmax_t maxFileBytes,
                               int keepFiles)
    : dir_(std::move(dataDir)),
      now_(std::move(now)),
      maxFileBytes_(maxFileBytes),
      keepFiles_(keepFiles < 1 ? 1 : keepFiles) {}

fs::path FileEventStore::fileFor(int index) const {
  return dir_ /
         (index == 0 ? std::string("events.jsonl") : "events." + std::to_string(index) + ".jsonl");
}

void FileEventStore::rotate() {
  std::error_code ec;
  fs::remove(fileFor(keepFiles_ - 1), ec);
  if (ec) {
    throw StorageError("cannot remove oldest event file: " + ec.message());
  }
  for (int i = keepFiles_ - 2; i >= 0; --i) {
    const bool present = fs::exists(fileFor(i), ec);
    if (ec) {
      throw StorageError("cannot inspect event file: " + ec.message());
    }
    if (!present) {
      continue;
    }
    fs::rename(fileFor(i), fileFor(i + 1), ec);
    if (ec) {
      throw StorageError("cannot rotate event file: " + ec.message());
    }
  }
}

void FileEventStore::append(std::string_view agentId, const std::vector<Event>& events) {
  const std::scoped_lock lock(mutex_);
  std::error_code ec;
  fs::create_directories(dir_, ec);
  if (ec) {
    throw StorageError("cannot create " + dir_.string() + ": " + ec.message());
  }
  const std::string receivedAt = formatUtc(now_());
  const fs::path live = fileFor(0);
  for (const Event& event : events) {
    const StoredEvent stored{event, std::string(agentId), receivedAt};
    std::string line =
        toJson(stored).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    line += '\n';

    std::uintmax_t size = fs::exists(live, ec) ? fs::file_size(live, ec) : 0;
    if (ec) {
      throw StorageError("cannot inspect " + live.string() + ": " + ec.message());
    }
    if (size > 0 && size + line.size() > maxFileBytes_) {
      rotate();
      size = 0;
    }
    if (size > 0 && endsMidLine(live)) {
      line.insert(0, 1, '\n');  // never glue a record onto a torn line
    }
    std::ofstream out(live, std::ios::binary | std::ios::app);
    out.write(line.data(), static_cast<std::streamsize>(line.size()));
    out.flush();
    if (!out) {
      throw StorageError("cannot append to " + live.string());
    }
  }
}

std::vector<StoredEvent> FileEventStore::recent(std::size_t limit) const {
  const std::scoped_lock lock(mutex_);
  std::vector<StoredEvent> out;
  for (int index = 0; index < keepFiles_ && out.size() < limit; ++index) {
    const std::optional<std::string> text = readFile(fileFor(index));
    if (!text) {
      continue;
    }
    // Walk the lines backwards so the newest comes first.
    std::size_t end = text->size();
    while (end > 0 && out.size() < limit) {
      const std::size_t nl = text->rfind('\n', end - 1);
      const std::size_t begin = nl == std::string::npos ? 0 : nl + 1;
      if (end > begin) {
        if (auto event = parseStoredEvent(std::string_view(*text).substr(begin, end - begin))) {
          out.push_back(std::move(*event));
        }
      }
      if (nl == std::string::npos) {
        break;
      }
      end = nl;
    }
  }
  return out;
}

}  // namespace warden::server
