#include "event_store.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "fs_util.hpp"

using namespace warden::server;
namespace fs = std::filesystem;

namespace {
class TempDir {
 public:
  TempDir() {
    path_ = fs::temp_directory_path() / ("warden_events_test_" + std::to_string(counter_++) + "_" +
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

Event makeEvent(const std::string& file) {
  Event e;
  e.ts = "2026-10-21T08:30:00Z";
  e.process.path = "/bin/cat";
  e.file = file;
  e.decision = "deny";
  e.ruleId = "r1";
  return e;
}

// Namespace scope so lambdas can use them without capture (MSVC rejects implicit capture).
constexpr int kThreads = 8;
constexpr int kPerThread = 100;

NowFn fixedNow() {
  return [] { return TimePoint{std::chrono::seconds(1792571400)}; };
}
}  // namespace

TEST(EventStore, EmptyStoreIsEmpty) {
  const TempDir dir;
  const FileEventStore store(dir.path(), fixedNow());
  EXPECT_TRUE(store.recent(10).empty());
}

TEST(EventStore, AppendThenRecentNewestFirst) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow());
  store.append("a1", {makeEvent("/1"), makeEvent("/2")});
  store.append("a1", {makeEvent("/3")});
  const auto got = store.recent(10);
  ASSERT_EQ(got.size(), 3U);
  EXPECT_EQ(got[0].event.file, "/3");
  EXPECT_EQ(got[1].event.file, "/2");
  EXPECT_EQ(got[2].event.file, "/1");
  EXPECT_TRUE(fs::exists(dir.path() / "events.jsonl"));
}

TEST(EventStore, RecordsAgentIdAndReceivedAt) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow());
  store.append("agent-7", {makeEvent("/x")});
  const auto got = store.recent(1);
  ASSERT_EQ(got.size(), 1U);
  EXPECT_EQ(got[0].agentId, "agent-7");
  EXPECT_EQ(got[0].receivedAt, formatUtc(fixedNow()()));
  EXPECT_EQ(got[0].event.ruleId, "r1");
}

TEST(EventStore, LimitIsHonoured) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow());
  for (int i = 0; i < 5; ++i) {
    store.append("a", {makeEvent("/" + std::to_string(i))});
  }
  const auto got = store.recent(2);
  ASSERT_EQ(got.size(), 2U);
  EXPECT_EQ(got[0].event.file, "/4");
  EXPECT_EQ(got[1].event.file, "/3");
  EXPECT_TRUE(store.recent(0).empty());
}

TEST(EventStore, RotatesAndKeepsAtMostKeepFiles) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow(), 300, 3);
  for (int i = 0; i < 40; ++i) {
    store.append("a", {makeEvent("/" + std::to_string(i))});
  }
  EXPECT_TRUE(fs::exists(dir.path() / "events.jsonl"));
  EXPECT_TRUE(fs::exists(dir.path() / "events.1.jsonl"));
  EXPECT_TRUE(fs::exists(dir.path() / "events.2.jsonl"));
  EXPECT_FALSE(fs::exists(dir.path() / "events.3.jsonl"));
  for (const char* name : {"events.jsonl", "events.1.jsonl", "events.2.jsonl"}) {
    EXPECT_LE(fs::file_size(dir.path() / name), 300U);
  }
  const auto got = store.recent(1000);
  ASSERT_FALSE(got.empty());
  EXPECT_LT(got.size(), 40U);
  EXPECT_EQ(got[0].event.file, "/39");
}

TEST(EventStore, KeepOneFileDiscardsOnRotation) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow(), 200, 1);
  for (int i = 0; i < 10; ++i) {
    store.append("a", {makeEvent("/" + std::to_string(i))});
  }
  EXPECT_FALSE(fs::exists(dir.path() / "events.1.jsonl"));
  EXPECT_EQ(store.recent(100)[0].event.file, "/9");
}

TEST(EventStore, OversizeSingleLineIsStillStored) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow(), 10, 2);
  store.append("a", {makeEvent("/one"), makeEvent("/two")});
  const auto got = store.recent(10);
  ASSERT_EQ(got.size(), 2U);
  EXPECT_EQ(got[0].event.file, "/two");
}

TEST(EventStore, RecentSpansRotatedFiles) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow(), 400, 20);
  for (int i = 0; i < 12; ++i) {
    store.append("a", {makeEvent("/" + std::to_string(i))});
  }
  ASSERT_TRUE(fs::exists(dir.path() / "events.1.jsonl"));
  const auto got = store.recent(100);
  ASSERT_EQ(got.size(), 12U);
  for (std::size_t i = 0; i < got.size(); ++i) {
    EXPECT_EQ(got[i].event.file, "/" + std::to_string(11 - i));
  }
}

TEST(EventStore, TornLastLineIsSkipped) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow());
  store.append("a", {makeEvent("/1"), makeEvent("/2")});
  {
    std::ofstream out(dir.path() / "events.jsonl", std::ios::app | std::ios::binary);
    out << R"({"ts":"2026-10-21T08:30:00Z","proc)";
  }
  auto got = store.recent(10);
  ASSERT_EQ(got.size(), 2U);
  EXPECT_EQ(got[0].event.file, "/2");
  // The next append must not glue itself onto the torn line.
  store.append("a", {makeEvent("/3")});
  got = store.recent(10);
  ASSERT_EQ(got.size(), 3U);
  EXPECT_EQ(got[0].event.file, "/3");
}

TEST(EventStore, ControlCharsRoundTrip) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow());
  store.append("a", {makeEvent(std::string("<script>\0\n\"x", 12))});
  const auto got = store.recent(1);
  ASSERT_EQ(got.size(), 1U);
  EXPECT_EQ(got[0].event.file, std::string("<script>\0\n\"x", 12));
}

TEST(EventStore, ConcurrentAppendsDoNotInterleaveLines) {
  const TempDir dir;
  FileEventStore store(dir.path(), fixedNow(), 8 * 1024, 50);
  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&store, t] {
      for (int i = 0; i < kPerThread; ++i) {
        store.append("agent-" + std::to_string(t),
                     {makeEvent("/t" + std::to_string(t) + "/" + std::to_string(i) +
                                std::string(200, 'x'))});
      }
    });
  }
  for (auto& th : threads) {
    th.join();
  }
  const auto got = store.recent(100000);
  EXPECT_EQ(got.size(), static_cast<std::size_t>(kThreads * kPerThread));
  std::set<std::string> files;
  for (const auto& e : got) {
    files.insert(e.event.file);
  }
  EXPECT_EQ(files.size(), got.size());
}

TEST(EventStore, AppendFailsWithStorageErrorWhenDirectoryIsAFile) {
  const TempDir dir;
  writeFileAtomic(dir.path() / "blocker", "x");
  FileEventStore store(dir.path() / "blocker", fixedNow());
  EXPECT_THROW(store.append("a", {makeEvent("/1")}), StorageError);
  EXPECT_TRUE(store.recent(10).empty());
}
