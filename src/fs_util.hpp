#pragma once

#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace warden::server {

class StorageError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Writes `content` to a temp file next to `path`, then renames it over `path`.
// Creates missing parent directories. With `ownerOnly` the file is restricted to the owner
// (0600) before any content is written. Throws StorageError on failure.
void writeFileAtomic(const std::filesystem::path& path, std::string_view content,
                     bool ownerOnly = false);

// Whole-file read; nullopt if the file does not exist or cannot be read.
std::optional<std::string> readFile(const std::filesystem::path& path);

}  // namespace warden::server
