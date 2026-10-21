#include "fs_util.hpp"

#include <atomic>
#include <fstream>
#include <iterator>
#include <random>
#include <system_error>

namespace warden::server {

namespace fs = std::filesystem;

namespace {

std::string uniqueSuffix() {
  static std::atomic<unsigned> counter{0};
  std::random_device rd;
  return std::to_string(rd()) + "." + std::to_string(counter.fetch_add(1));
}

void removeQuietly(const fs::path& path) {
  std::error_code ec;
  fs::remove(path, ec);
}

}  // namespace

void writeFileAtomic(const fs::path& path, std::string_view content, bool ownerOnly) {
  std::error_code ec;
  const fs::path parent = path.parent_path();
  if (!parent.empty()) {
    fs::create_directories(parent, ec);
    if (ec) {
      throw StorageError("cannot create directory " + parent.string() + ": " + ec.message());
    }
  }

  fs::path temp = path;
  temp += ".tmp." + uniqueSuffix();

  {
    // Create empty first so permissions are tightened before secret content is written.
    std::ofstream create(temp, std::ios::binary | std::ios::trunc);
    if (!create) {
      throw StorageError("cannot create temp file " + temp.string());
    }
  }
  if (ownerOnly) {
    fs::permissions(temp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace,
                    ec);
    if (ec) {
      removeQuietly(temp);
      throw StorageError("cannot restrict permissions of " + temp.string() + ": " + ec.message());
    }
  }
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    out.flush();
    if (!out) {
      out.close();
      removeQuietly(temp);
      throw StorageError("cannot write " + temp.string());
    }
  }
  fs::rename(temp, path, ec);
  if (ec) {
    removeQuietly(temp);
    throw StorageError("cannot rename to " + path.string() + ": " + ec.message());
  }
}

std::optional<std::string> readFile(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return std::nullopt;
  }
  std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (in.bad()) {
    return std::nullopt;
  }
  return data;
}

}  // namespace warden::server
