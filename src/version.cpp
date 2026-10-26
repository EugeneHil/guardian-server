#include "version.hpp"

namespace guardian::server {

std::string_view serverVersion() noexcept { return GUARDIAN_SERVER_VERSION; }

}  // namespace guardian::server
