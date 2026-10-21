#include "version.hpp"

namespace warden::server {

std::string_view serverVersion() noexcept { return WARDEN_SERVER_VERSION; }

}  // namespace warden::server
