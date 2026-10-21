#include "timeutil.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace warden::server {

namespace {

constexpr std::size_t kMaxLength = 64;
constexpr std::int64_t kSecondsPerDay = 86400;

struct Civil {
  std::int64_t year;
  unsigned month;
  unsigned day;
};

// Howard Hinnant's days-from-civil: days since 1970-01-01 for a proleptic Gregorian date.
std::int64_t daysFromCivil(const Civil& date) {
  std::int64_t y = date.year;
  const unsigned m = date.month;
  const unsigned d = date.day;
  y -= (m <= 2) ? 1 : 0;
  const std::int64_t era = ((y >= 0) ? y : (y - 399)) / 400;
  const auto yoe = static_cast<unsigned>(y - (era * 400));
  const unsigned shiftedMonth = (m > 2) ? (m - 3) : (m + 9);
  const unsigned doy = (((153 * shiftedMonth) + 2) / 5) + d - 1;
  const unsigned doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy;
  return (era * 146097) + static_cast<std::int64_t>(doe) - 719468;
}

Civil civilFromDays(std::int64_t z) {
  z += 719468;
  const std::int64_t era = ((z >= 0) ? z : (z - 146096)) / 146097;
  const auto doe = static_cast<unsigned>(z - (era * 146097));
  const unsigned yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365;
  const std::int64_t y = static_cast<std::int64_t>(yoe) + (era * 400);
  const unsigned doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100));
  const unsigned mp = ((5 * doy) + 2) / 153;
  const unsigned d = doy - (((153 * mp) + 2) / 5) + 1;
  const unsigned m = (mp < 10) ? (mp + 3) : (mp - 9);
  return {y + ((m <= 2) ? 1 : 0), m, d};
}

bool isLeap(std::int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

unsigned daysInMonth(std::int64_t y, unsigned m) {
  constexpr std::array<unsigned, 12> kDays{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  return (m == 2 && isLeap(y)) ? 29U : kDays.at(m - 1);
}

// Parses exactly `count` ASCII digits at text[pos]; advances pos.
std::optional<unsigned> digits(std::string_view text, std::size_t& pos, std::size_t count) {
  if (pos + count > text.size()) {
    return std::nullopt;
  }
  unsigned value = 0;
  for (std::size_t i = 0; i < count; ++i) {
    const char c = text[pos + i];
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    value = (value * 10) + static_cast<unsigned>(c - '0');
  }
  pos += count;
  return value;
}

// Parses one or more fraction digits at text[pos] into nanoseconds (extra digits are ignored).
bool fraction(std::string_view text, std::size_t& pos, std::int64_t& nanos) {
  std::size_t count = 0;
  std::int64_t scale = 100000000;
  while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
    if (scale > 0) {
      nanos += static_cast<std::int64_t>(text[pos] - '0') * scale;
      scale /= 10;
    }
    ++pos;
    ++count;
  }
  return count > 0;
}

bool expect(std::string_view text, std::size_t& pos, char c) {
  if (pos >= text.size() || text[pos] != c) {
    return false;
  }
  ++pos;
  return true;
}

}  // namespace

std::string formatUtc(TimePoint tp) {
  const auto secs = std::chrono::floor<std::chrono::seconds>(tp).time_since_epoch().count();
  std::int64_t days = secs / kSecondsPerDay;
  std::int64_t rem = secs % kSecondsPerDay;
  if (rem < 0) {
    rem += kSecondsPerDay;
    --days;
  }
  const Civil c = civilFromDays(days);
  std::array<char, 48> buf{};
  const int n = std::snprintf(
      buf.data(), buf.size(), "%04lld-%02u-%02uT%02lld:%02lld:%02lldZ",
      static_cast<long long>(c.year), c.month, c.day, static_cast<long long>(rem / 3600),
      static_cast<long long>((rem % 3600) / 60), static_cast<long long>(rem % 60));
  return n > 0 ? std::string(buf.data(), static_cast<std::size_t>(n)) : std::string{};
}

std::optional<TimePoint> parseUtc(std::string_view text) {
  if (text.empty() || text.size() > kMaxLength) {
    return std::nullopt;
  }
  std::size_t pos = 0;
  const auto year = digits(text, pos, 4);
  if (!year || !expect(text, pos, '-')) {
    return std::nullopt;
  }
  const auto month = digits(text, pos, 2);
  if (!month || !expect(text, pos, '-')) {
    return std::nullopt;
  }
  const auto day = digits(text, pos, 2);
  if (!day || !expect(text, pos, 'T')) {
    return std::nullopt;
  }
  const auto hour = digits(text, pos, 2);
  if (!hour || !expect(text, pos, ':')) {
    return std::nullopt;
  }
  const auto minute = digits(text, pos, 2);
  if (!minute || !expect(text, pos, ':')) {
    return std::nullopt;
  }
  const auto second = digits(text, pos, 2);
  if (!second) {
    return std::nullopt;
  }

  std::int64_t nanos = 0;
  if (expect(text, pos, '.') && !fraction(text, pos, nanos)) {
    return std::nullopt;
  }
  if (!expect(text, pos, 'Z') || pos != text.size()) {
    return std::nullopt;
  }

  if (*month < 1 || *month > 12 || *day < 1 || *day > daysInMonth(*year, *month) || *hour > 23 ||
      *minute > 59 || *second > 59) {
    return std::nullopt;
  }

  const std::int64_t days = daysFromCivil({*year, *month, *day});
  const std::int64_t timeOfDay = (static_cast<std::int64_t>(*hour) * 3600) +
                                 (static_cast<std::int64_t>(*minute) * 60) +
                                 static_cast<std::int64_t>(*second);
  const std::int64_t secs = (days * kSecondsPerDay) + timeOfDay;
  // Range-check before converting: seconds -> ticks must not overflow TimePoint::duration::rep.
  // The limits are floored to whole seconds; the boundary seconds themselves are rejected so the
  // fraction cannot push the sum past the representable range.
  const auto minSecs = std::chrono::duration_cast<std::chrono::seconds>(TimePoint::duration::min());
  const auto maxSecs = std::chrono::duration_cast<std::chrono::seconds>(TimePoint::duration::max());
  if (secs <= minSecs.count() || secs >= maxSecs.count()) {
    return std::nullopt;
  }
  return TimePoint{
      std::chrono::duration_cast<TimePoint::duration>(std::chrono::seconds{secs}) +
      std::chrono::duration_cast<TimePoint::duration>(std::chrono::nanoseconds{nanos})};
}

}  // namespace warden::server
