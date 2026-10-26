#pragma once

#include <string_view>

namespace guardian::server {

/// Semantic version of warden-server (the CMake PROJECT_VERSION).
std::string_view serverVersion() noexcept;

}  // namespace guardian::server
