#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace warden::server {

using TimePoint = std::chrono::system_clock::time_point;
using NowFn = std::function<TimePoint()>;

// "2026-10-21T08:30:00Z" (whole seconds, UTC).
std::string formatUtc(TimePoint tp);

// Accepts YYYY-MM-DDTHH:MM:SS[.fraction]Z; nullopt on anything else, including dates outside
// the range TimePoint can represent on this platform.
std::optional<TimePoint> parseUtc(std::string_view text);

}  // namespace warden::server
