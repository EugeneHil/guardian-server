#include "fs_util.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>

using namespace guardian::server;
namespace fs = std::filesystem;

namespace {
class TempDir {
 public:
  TempDir() {
    path_ = fs::temp_directory_path() / ("guardian_fs_test_" + std::to_string(counter_++) + "_" +
                                         std::to_string(reinterpret_cast<std::uintptr_t>(this)));
    fs::create_directories(path_);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  static inline int counter_ = 0;
  fs::path path_;
};
}  // namespace

TEST(WriteFileAtomic, ReplacesContentAndLeavesNoTempFile) {
  const TempDir dir;
  const fs::path target = dir.path() / "data.json";
  writeFileAtomic(target, "first");
  writeFileAtomic(target, "second", true);
  EXPECT_EQ(readFile(target), std::optional<std::string>{"second"});
  int entries = 0;
  for (const auto& entry : fs::directory_iterator(dir.path())) {
    (void)entry;
    ++entries;
  }
  EXPECT_EQ(entries, 1);
#ifndef _WIN32
  const auto perms = fs::status(target).permissions();
  EXPECT_EQ(perms & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
  EXPECT_NE(perms & fs::perms::owner_read, fs::perms::none);
#endif
}

TEST(WriteFileAtomic, CreatesParentDirs) {
  const TempDir dir;
  const fs::path target = dir.path() / "a" / "b" / "c.txt";
  writeFileAtomic(target, std::string("bin\0ary", 7));
  EXPECT_EQ(readFile(target), std::optional<std::string>{std::string("bin\0ary", 7)});
}

TEST(WriteFileAtomic, ThrowsStorageErrorWhenParentIsAFile) {
  const TempDir dir;
  writeFileAtomic(dir.path() / "file", "x");
  EXPECT_THROW(writeFileAtomic(dir.path() / "file" / "child", "y"), StorageError);
}

TEST(ReadFile, MissingIsNullopt) {
  const TempDir dir;
  EXPECT_FALSE(readFile(dir.path() / "nope").has_value());
}
