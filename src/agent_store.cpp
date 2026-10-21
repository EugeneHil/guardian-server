#include "agent_store.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

#include "crypto.hpp"
#include "fs_util.hpp"

namespace warden::server {

namespace {
using Json = nlohmann::json;

bool isIdChar(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
         c == '_' || c == '-';
}
}  // namespace

bool isValidAgentId(std::string_view id) noexcept {
  return !id.empty() && id.size() <= 64 && std::all_of(id.begin(), id.end(), isIdChar);
}

FileAgentStore::FileAgentStore(const std::filesystem::path& dataDir, NowFn now)
    : file_(dataDir / "data" / "agents.json"), now_(std::move(now)) {}

std::vector<FileAgentStore::Entry> FileAgentStore::load() const {
  const auto raw = readFile(file_);
  if (!raw) {
    std::error_code ec;
    if (!std::filesystem::exists(file_, ec) && !ec) {
      return {};  // no file yet: no agents
    }
    throw StorageError("cannot read agents file");
  }
  const Json doc = Json::parse(*raw, nullptr, false);
  if (!doc.is_object()) {
    throw StorageError("agents file is corrupt");
  }
  const auto agents = doc.find("agents");
  if (agents == doc.end() || !agents->is_array()) {
    throw StorageError("agents file is corrupt");
  }
  std::vector<Entry> entries;
  for (const auto& item : *agents) {
    if (!item.is_object()) {
      throw StorageError("agents file is corrupt");
    }
    Entry entry;
    for (const auto& [key, target] : {
             std::pair<const char*, std::string*>{"id", &entry.id},
             {"tokenHash", &entry.tokenHash},
             {"createdAt", &entry.createdAt},
         }) {
      const auto field = item.find(key);
      if (field == item.end() || !field->is_string()) {
        throw StorageError("agents file is corrupt");
      }
      *target = field->get<std::string>();
    }
    if (!isValidAgentId(entry.id)) {
      throw StorageError("agents file is corrupt");
    }
    entries.push_back(std::move(entry));
  }
  return entries;
}

void FileAgentStore::save(const std::vector<Entry>& entries) const {
  Json agents = Json::array();
  for (const auto& entry : entries) {
    agents.push_back(
        {{"id", entry.id}, {"tokenHash", entry.tokenHash}, {"createdAt", entry.createdAt}});
  }
  writeFileAtomic(file_, Json{{"agents", agents}}.dump(2), true);
}

std::optional<std::string> FileAgentStore::add(std::string_view agentId) {
  if (!isValidAgentId(agentId)) {
    throw std::invalid_argument("invalid agent id");
  }
  const std::scoped_lock lock(mutex_);
  auto entries = load();
  const bool exists =
      std::any_of(entries.begin(), entries.end(), [&](const Entry& e) { return e.id == agentId; });
  if (exists) {
    return std::nullopt;
  }
  std::string token = randomToken();
  entries.push_back({std::string(agentId), sha256Hex(token), formatUtc(now_())});
  save(entries);
  return token;
}

bool FileAgentStore::remove(std::string_view agentId) {
  const std::scoped_lock lock(mutex_);
  auto entries = load();
  const auto it = std::remove_if(entries.begin(), entries.end(),
                                 [&](const Entry& e) { return e.id == agentId; });
  if (it == entries.end()) {
    return false;
  }
  entries.erase(it, entries.end());
  save(entries);
  return true;
}

std::vector<AgentInfo> FileAgentStore::list() const {
  const std::scoped_lock lock(mutex_);
  std::vector<AgentInfo> out;
  for (auto& entry : load()) {
    out.push_back({std::move(entry.id), std::move(entry.createdAt)});
  }
  std::sort(out.begin(), out.end(),
            [](const AgentInfo& a, const AgentInfo& b) { return a.id < b.id; });
  return out;
}

std::optional<std::string> FileAgentStore::authenticate(std::string_view token) const {
  std::vector<Entry> entries;
  try {
    const std::scoped_lock lock(mutex_);
    entries = load();
  } catch (const std::exception&) {
    return std::nullopt;  // fail closed
  }
  const std::string hash = sha256Hex(token);
  std::optional<std::string> match;
  for (const auto& entry : entries) {  // no early exit: every entry is compared
    if (constantTimeEquals(hash, entry.tokenHash) && !match) {
      match = entry.id;
    }
  }
  return match;
}

}  // namespace warden::server
