#include "event.hpp"

#include <gtest/gtest.h>

#include <string>

using namespace guardian::server;

namespace {
std::string item(const std::string& extra = "") {
  return R"({"ts":"2026-10-21T08:30:00Z","process":{"path":"/bin/cat"},"file":"/a/secret.txt","decision":"deny")" +
         extra + "}";
}

std::string batch(const std::string& one, int count) {
  std::string out = "[";
  for (int i = 0; i < count; ++i) {
    out += (i == 0 ? "" : ",") + one;
  }
  return out + "]";
}

bool hasError(const EventBatchResult& r, const std::string& path, const std::string& message) {
  for (const auto& e : r.errors) {
    if (e.path == path && e.message == message) {
      return true;
    }
  }
  return false;
}
}  // namespace

TEST(EventParse, AcceptsMinimalAndFullEvent) {
  const std::string full =
      R"({"ts":"2026-10-21T08:30:00Z","process":{"path":"/p","signingId":"s","teamId":"T"},)"
      R"("responsible":{"path":"/r","signingId":"rs","teamId":"RT"},"file":"/f","decision":"allow","ruleId":"r1"})";
  const auto r = parseEventBatch("[" + item() + "," + full + "]");
  ASSERT_TRUE(r.errors.empty());
  ASSERT_EQ(r.events.size(), 2U);
  EXPECT_EQ(r.events[0].process.path, "/bin/cat");
  EXPECT_FALSE(r.events[0].responsible.has_value());
  EXPECT_EQ(r.events[0].ruleId, "");
  EXPECT_EQ(r.events[1].responsible->signingId, "rs");
  EXPECT_EQ(r.events[1].process.teamId, "T");
  EXPECT_EQ(r.events[1].ruleId, "r1");
  EXPECT_EQ(r.events[1].decision, "allow");
}

TEST(EventParse, NullResponsibleIsAbsent) {
  const auto r = parseEventBatch("[" + item(R"(,"responsible":null)") + "]");
  ASSERT_TRUE(r.errors.empty());
  EXPECT_FALSE(r.events[0].responsible.has_value());
}

TEST(EventParse, IgnoresUnknownKeys) {
  const auto r = parseEventBatch("[" + item(R"(,"extra":{"a":[1]})") + "]");
  EXPECT_TRUE(r.errors.empty());
  EXPECT_EQ(r.events.size(), 1U);
}

TEST(EventParse, RejectsNonArrayEmptyAndTooLarge) {
  EXPECT_TRUE(hasError(parseEventBatch("{}"), "$", "must be an array"));
  EXPECT_TRUE(hasError(parseEventBatch("[]"), "$", "must not be empty"));
  EXPECT_TRUE(hasError(parseEventBatch(batch(item(), 501)), "$", "more than 500 items"));
  const auto big = parseEventBatch(batch(item(), 10000));
  EXPECT_TRUE(hasError(big, "$", "more than 500 items"));
  EXPECT_EQ(big.errors.size(), 1U);
  EXPECT_TRUE(parseEventBatch(batch(item(), 500)).errors.empty());
}

TEST(EventParse, InvalidJsonHasFixedMessage) {
  const auto r = parseEventBatch("[{\"ts\": nope}");
  ASSERT_EQ(r.errors.size(), 1U);
  EXPECT_EQ(r.errors[0].path, "$");
  EXPECT_EQ(r.errors[0].message, "invalid JSON");
  EXPECT_TRUE(r.events.empty());
}

TEST(EventParse, ReportsAllItemErrorsWithPaths) {
  const std::string bad =
      R"({"ts":"2026-10-21T08:30:00Z","process":{"path":"/p"},"decision":"deny"})";
  const auto r = parseEventBatch("[" + item() + "," + item() + "," + bad + ",{}]");
  EXPECT_TRUE(hasError(r, "[2].file", "required string"));
  EXPECT_TRUE(hasError(r, "[3].ts", "required string"));
  EXPECT_TRUE(hasError(r, "[3].process.path", "required string"));
  EXPECT_TRUE(hasError(r, "[3].file", "required string"));
  EXPECT_TRUE(hasError(r, "[3].decision", "required string"));
  EXPECT_TRUE(r.events.empty());
}

TEST(EventParse, NonObjectItemIsReported) {
  EXPECT_TRUE(hasError(parseEventBatch("[1]"), "[0]", "must be an object"));
  EXPECT_TRUE(
      hasError(parseEventBatch(
                   R"([{"ts":"2026-10-21T08:30:00Z","process":5,"file":"f","decision":"deny"}])"),
               "[0].process.path", "required string"));
}

TEST(EventParse, RejectsBadDecision) {
  const auto r = parseEventBatch(
      R"([{"ts":"2026-10-21T08:30:00Z","process":{"path":"/p"},"file":"/f","decision":"maybe"}])");
  EXPECT_TRUE(hasError(r, "[0].decision", "must be \"deny\" or \"allow\""));
}

TEST(EventParse, RejectsBadTimestamp) {
  const auto r = parseEventBatch(
      R"([{"ts":"yesterday","process":{"path":"/p"},"file":"/f","decision":"deny"}])");
  EXPECT_TRUE(hasError(r, "[0].ts", "must be an ISO-8601 UTC timestamp"));
}

TEST(EventParse, RejectsOversizeStrings) {
  const std::string huge(kMaxEventStringBytes + 1, 'a');
  const auto r =
      parseEventBatch(R"([{"ts":"2026-10-21T08:30:00Z","process":{"path":"/p","teamId":")" + huge +
                      R"("},"file":")" + huge + R"(","decision":"deny"}])");
  EXPECT_TRUE(hasError(r, "[0].file", "longer than 4096 bytes"));
  EXPECT_TRUE(hasError(r, "[0].process.teamId", "longer than 4096 bytes"));
  const std::string exact(kMaxEventStringBytes, 'a');
  EXPECT_TRUE(parseEventBatch("[" + item(R"(,"ruleId":")" + exact + "\"") + "]").errors.empty());
}

TEST(EventParse, RejectsInvalidUtf8) {
  for (const std::string& bad :
       {std::string("\xff"), std::string("\xc0\xaf"), std::string("\xed\xa0\x80"),
        std::string("\xe2\x82"), std::string("\xf4\x90\x80\x80")}) {
    const auto r = parseEventBatch(
        "[{\"ts\":\"2026-10-21T08:30:00Z\",\"process\":{\"path\":\"/p\"},\"file\":\"" + bad +
        "\",\"decision\":\"deny\"}]");
    ASSERT_EQ(r.errors.size(), 1U);
    EXPECT_EQ(r.errors[0].path, "$");
    EXPECT_EQ(r.errors[0].message, "invalid UTF-8");
  }
  const auto ok = parseEventBatch("[" + item(",\"ruleId\":\"\xc3\xa9\xf0\x9f\x98\x80\"") + "]");
  EXPECT_TRUE(ok.errors.empty());
}

TEST(EventParse, DeepNestingDoesNotCrash) {
  const auto r = parseEventBatch(std::string(100000, '['));
  ASSERT_EQ(r.errors.size(), 1U);
  EXPECT_EQ(r.errors[0].path, "$");
  const auto objs = [] {
    std::string s;
    for (int i = 0; i < 100000; ++i) {
      s += "{\"a\":";
    }
    return s;
  }();
  EXPECT_EQ(parseEventBatch(objs).errors.size(), 1U);
}

TEST(EventParse, NestingLimitIsExactlySixtyFour) {
  const auto nested = [](int depth) {
    return std::string(static_cast<std::size_t>(depth), '[') +
           std::string(static_cast<std::size_t>(depth), ']');
  };
  // Batch array (1) + event object (1) + value nesting.
  const auto ok = parseEventBatch("[" + item(R"(,"x":)" + nested(62)) + "]");
  EXPECT_TRUE(ok.errors.empty());
  const auto bad = parseEventBatch("[" + item(R"(,"x":)" + nested(63)) + "]");
  ASSERT_EQ(bad.errors.size(), 1U);
  EXPECT_EQ(bad.errors[0].path, "$");
}

TEST(EventParse, BracketsInsideStringsDoNotCountAsNesting) {
  const std::string brackets(200, '[');
  const auto r = parseEventBatch("[" + item(R"(,"ruleId":")" + brackets + R"(\"[")") + "]");
  EXPECT_TRUE(r.errors.empty());
}

TEST(EventParse, ControlCharsAndHtmlAreKeptVerbatim) {
  const auto r = parseEventBatch(
      R"([{"ts":"2026-10-21T08:30:00Z","process":{"path":"/p"},"file":"<script>\u0000x\n","decision":"deny"}])");
  ASSERT_TRUE(r.errors.empty());
  EXPECT_EQ(r.events[0].file, std::string("<script>\0x\n", 11));
  const StoredEvent stored{r.events[0], "agent-1", "2026-10-21T09:00:00Z"};
  const nlohmann::json j = toJson(stored);
  EXPECT_EQ(j.at("file").get<std::string>(), std::string("<script>\0x\n", 11));
  EXPECT_EQ(j.at("agentId"), "agent-1");
  EXPECT_EQ(j.at("receivedAt"), "2026-10-21T09:00:00Z");
  EXPECT_EQ(j.at("process").at("path"), "/p");
  EXPECT_TRUE(j.at("responsible").is_null());
  const auto back = parseStoredEvent(j.dump());
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(back->event.file, r.events[0].file);
}

TEST(EventParse, StoredEventRejectsGarbage) {
  EXPECT_FALSE(parseStoredEvent("").has_value());
  EXPECT_FALSE(parseStoredEvent("{\"ts\":").has_value());
  EXPECT_FALSE(parseStoredEvent("[1]").has_value());
  EXPECT_FALSE(parseStoredEvent(R"({"ts":"x"})").has_value());
  EXPECT_FALSE(parseStoredEvent(std::string(100000, '[')).has_value());
  EXPECT_FALSE(parseStoredEvent("{\"a\":\"\xff\"}").has_value());
}
