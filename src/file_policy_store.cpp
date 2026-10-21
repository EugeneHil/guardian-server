#include <cctype>
#include <string>
#include <system_error>

#include "fs_util.hpp"
#include "policy_store.hpp"

namespace warden::server {

namespace {
constexpr const char* kBootstrapPolicy = R"({"schemaVersion":1,"version":1,"rules":[]})";

// Strict decimal parse of a positive int64 followed by exactly one optional trailing newline.
std::int64_t parsePointer(const std::string& text) {
  std::string digits = text;
  if (!digits.empty() && digits.back() == '\n') {
    digits.pop_back();
  }
  if (digits.empty() || digits.size() > 18) {
    return 0;
  }
  std::int64_t value = 0;
  for (const char c : digits) {
    if (std::isdigit(static_cast<unsigned char>(c)) == 0) {
      return 0;
    }
    value = (value * 10) + (c - '0');
  }
  return value;
}
}  // namespace

FilePolicyStore::FilePolicyStore(const std::filesystem::path& dataDir)
    : dir_(dataDir / "data" / "policies") {
  const std::scoped_lock lock(mutex_);
  const auto pointer = readFile(dir_ / "active");
  if (!pointer) {
    writeFileAtomic(versionFile(1), kBootstrapPolicy);
    writeFileAtomic(dir_ / "active", "1\n");
    active_ = PolicyDoc{1, kBootstrapPolicy};
    return;
  }
  const std::int64_t version = parsePointer(*pointer);
  if (version <= 0) {
    throw StorageError("corrupt policy pointer: " + (dir_ / "active").string());
  }
  auto json = readFile(versionFile(version));
  if (!json) {
    throw StorageError("missing policy file: " + versionFile(version).string());
  }
  active_ = PolicyDoc{version, std::move(*json)};
}

std::filesystem::path FilePolicyStore::versionFile(std::int64_t version) const {
  return dir_ / ("v" + std::to_string(version) + ".json");
}

PolicyDoc FilePolicyStore::active() const {
  const std::scoped_lock lock(mutex_);
  return active_;
}

std::optional<std::string> FilePolicyStore::draft() const {
  const std::scoped_lock lock(mutex_);
  return readFile(dir_ / "draft.json");
}

void FilePolicyStore::saveDraft(std::string_view text) {
  const std::scoped_lock lock(mutex_);
  writeFileAtomic(dir_ / "draft.json", text);
}

void FilePolicyStore::clearDraft() {
  const std::scoped_lock lock(mutex_);
  std::error_code ec;
  std::filesystem::remove(dir_ / "draft.json", ec);
  if (ec) {
    throw StorageError("cannot remove draft: " + ec.message());
  }
}

void FilePolicyStore::commit(const PolicyDoc& doc) {
  const std::scoped_lock lock(mutex_);
  if (doc.version != active_.version + 1) {
    throw StorageError("policy version " + std::to_string(doc.version) +
                       " is not the successor of " + std::to_string(active_.version));
  }
  writeFileAtomic(versionFile(doc.version), doc.json);                   // first the content ...
  writeFileAtomic(dir_ / "active", std::to_string(doc.version) + "\n");  // ... then the pointer
  active_ = doc;
}

}  // namespace warden::server
