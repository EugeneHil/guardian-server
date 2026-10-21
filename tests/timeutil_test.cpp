#include "timeutil.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

using namespace warden::server;

TEST(FormatUtc, EpochAndLeapDay) {
  EXPECT_EQ(formatUtc(TimePoint{}), "1970-01-01T00:00:00Z");
  const auto parsed = parseUtc("2024-02-29T23:59:59Z");
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(formatUtc(*parsed), "2024-02-29T23:59:59Z");
  const auto known = parseUtc("2026-10-21T08:30:00Z");
  ASSERT_TRUE(known.has_value());
  EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(known->time_since_epoch()).count(),
            1792571400);
  EXPECT_EQ(formatUtc(*known), "2026-10-21T08:30:00Z");
}

TEST(ParseUtc, RejectsBadInput) {
  EXPECT_FALSE(parseUtc("2026-02-30T00:00:00Z").has_value());
  EXPECT_FALSE(parseUtc("2026-10-21T08:30:00").has_value());
  EXPECT_FALSE(parseUtc("2026-10-21 08:30:00Z").has_value());
  EXPECT_FALSE(parseUtc("").has_value());
  EXPECT_FALSE(parseUtc(std::string(1U << 20, '9')).has_value());
  EXPECT_FALSE(parseUtc("2026-13-01T00:00:00Z").has_value());
  EXPECT_FALSE(parseUtc("2026-10-21T24:00:00Z").has_value());
  EXPECT_FALSE(parseUtc("2026-10-21T08:60:00Z").has_value());
  EXPECT_FALSE(parseUtc("2026-10-21T08:30:00.Z").has_value());
  EXPECT_FALSE(parseUtc("2026-10-21T08:30:00Zx").has_value());
  EXPECT_FALSE(parseUtc("2026-10-21T08:30:0xZ").has_value());
  EXPECT_FALSE(parseUtc("2026-02-29T00:00:00Z").has_value());
}

TEST(ParseUtc, AcceptsFraction) {
  const auto plain = parseUtc("2026-10-21T08:30:00Z");
  const auto frac = parseUtc("2026-10-21T08:30:00.123456Z");
  ASSERT_TRUE(plain.has_value());
  ASSERT_TRUE(frac.has_value());
  EXPECT_GE(*frac, *plain);
  EXPECT_LT(*frac - *plain, std::chrono::seconds{1});
  EXPECT_EQ(formatUtc(*frac), "2026-10-21T08:30:00Z");
}

TEST(ParseUtc, CenturyLeapRules) {
  EXPECT_FALSE(parseUtc("1900-02-29T00:00:00Z").has_value());
  EXPECT_TRUE(parseUtc("2000-02-29T00:00:00Z").has_value());
  const auto march = parseUtc("1900-03-01T00:00:00Z");
  ASSERT_TRUE(march.has_value());
  EXPECT_EQ(formatUtc(*march), "1900-03-01T00:00:00Z");
}

TEST(ParseUtc, ExtremeYearsAreDefinedOnEveryPlatform) {
  for (const char* text : {"0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z"}) {
    const auto parsed = parseUtc(text);
    if (parsed.has_value()) {
      EXPECT_EQ(formatUtc(*parsed), text);
    }
  }
}

TEST(ParseUtc, LongFractionIsAccepted) {
  const auto plain = parseUtc("2026-10-21T08:30:00Z");
  const auto frac = parseUtc("2026-10-21T08:30:00.123456789123Z");
  ASSERT_TRUE(plain.has_value());
  ASSERT_TRUE(frac.has_value());
  EXPECT_GT(*frac, *plain);
  EXPECT_LT(*frac - *plain, std::chrono::seconds{1});
}
