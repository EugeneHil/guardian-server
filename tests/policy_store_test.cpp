#include "policy_store.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "fs_util.hpp"
#include "warden/policy_parser.hpp"

using namespace warden::server;
namespace fs = std::filesystem;

namespace {
class TempDir {
 public:
  TempDir() {
    path_ = fs::temp_directory_path() / ("warden_policy_test_" + std::to_string(counter_++) + "_" +
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
  [[nodiscard]] fs::path policies() const { return path_ / "data" / "policies"; }

 private:
  static inline int counter_ = 0;
  fs::path path_;
};

std::string policyJson(int version) {
  return R"({"schemaVersion":1,"version":)" + std::to_string(version) + R"(,"rules":[]})";
}
}  // namespace

TEST(PolicyStore, BootstrapsEmptyPolicyV1) {
  TempDir dir;
  FilePolicyStore store(dir.path());
  const PolicyDoc doc = store.active();
  EXPECT_EQ(doc.version, 1);
  EXPECT_TRUE(warden::parsePolicy(doc.json).ok());
  EXPECT_TRUE(fs::exists(dir.policies() / "v1.json"));
  EXPECT_EQ(readFile(dir.policies() / "active"), "1\n");
}

TEST(PolicyStore, ReopeningKeepsActive) {
  TempDir dir;
  {
    FilePolicyStore store(dir.path());
    store.commit({2, policyJson(2)});
  }
  FilePolicyStore reopened(dir.path());
  EXPECT_EQ(reopened.active().version, 2);
  EXPECT_EQ(reopened.active().json, policyJson(2));
}

TEST(PolicyStore, CommitMakesNextVersionActive) {
  TempDir dir;
  FilePolicyStore store(dir.path());
  store.commit({2, policyJson(2)});
  EXPECT_EQ(store.active().version, 2);
  EXPECT_EQ(store.active().json, policyJson(2));
  store.commit({3, policyJson(3)});
  EXPECT_EQ(store.active().version, 3);
  EXPECT_TRUE(fs::exists(dir.policies() / "v2.json"));
}

TEST(PolicyStore, CommitRejectsNonConsecutiveVersions) {
  TempDir dir;
  FilePolicyStore store(dir.path());
  EXPECT_THROW(store.commit({1, policyJson(1)}), StorageError);
  EXPECT_THROW(store.commit({3, policyJson(3)}), StorageError);
  EXPECT_THROW(store.commit({0, policyJson(0)}), StorageError);
  EXPECT_EQ(store.active().version, 1);
  EXPECT_FALSE(fs::exists(dir.policies() / "v3.json"));
}

TEST(PolicyStore, CrashBeforePointerFlipKeepsOldVersion) {
  TempDir dir;
  {
    FilePolicyStore store(dir.path());
  }
  writeFileAtomic(dir.policies() / "v2.json", "partial garbage");  // written, pointer not flipped
  FilePolicyStore reopened(dir.path());
  EXPECT_EQ(reopened.active().version, 1);
  reopened.commit({2, policyJson(2)});
  EXPECT_EQ(reopened.active().version, 2);
  EXPECT_EQ(readFile(dir.policies() / "v2.json"), policyJson(2));
}

TEST(PolicyStore, DraftSaveReadClear) {
  TempDir dir;
  FilePolicyStore store(dir.path());
  EXPECT_FALSE(store.draft().has_value());
  store.saveDraft("draft one");
  EXPECT_EQ(store.draft(), "draft one");
  store.saveDraft("draft two");
  EXPECT_EQ(store.draft(), "draft two");
  store.clearDraft();
  EXPECT_FALSE(store.draft().has_value());
  EXPECT_NO_THROW(store.clearDraft());
}

TEST(PolicyStore, DraftKeepsInvalidTextVerbatim) {
  TempDir dir;
  FilePolicyStore store(dir.path());
  const std::string text = "{ not json \n\t\xE2\x9C\x93 ]";
  store.saveDraft(text);
  EXPECT_EQ(store.draft(), text);
  FilePolicyStore reopened(dir.path());
  EXPECT_EQ(reopened.draft(), text);
}

TEST(PolicyStore, CorruptPointerFailsFast) {
  for (const std::string bad : {"", "abc", "-1", "0", "2\n"}) {
    TempDir dir;
    {
      FilePolicyStore store(dir.path());
    }
    writeFileAtomic(dir.policies() / "active", bad);
    EXPECT_THROW(FilePolicyStore{dir.path()}, StorageError) << "pointer: '" << bad << "'";
  }
}

TEST(PolicyStore, MissingVersionFileFailsFast) {
  TempDir dir;
  {
    FilePolicyStore store(dir.path());
  }
  fs::remove(dir.policies() / "v1.json");
  EXPECT_THROW(FilePolicyStore{dir.path()}, StorageError);
}

TEST(PolicyStore, ConcurrentCommitsNeverCorrupt) {
  TempDir dir;
  FilePolicyStore store(dir.path());
  std::atomic<int> succeeded{0};
  std::atomic<int> failed{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 8; ++i) {
    threads.emplace_back([&] {
      try {
        store.commit({2, policyJson(2)});
        ++succeeded;
      } catch (const StorageError&) {
        ++failed;
      }
    });
  }
  for (auto& t : threads) t.join();
  EXPECT_EQ(succeeded.load(), 1);
  EXPECT_EQ(failed.load(), 7);
  EXPECT_EQ(store.active().version, 2);
  EXPECT_TRUE(warden::parsePolicy(store.active().json).ok());
}
