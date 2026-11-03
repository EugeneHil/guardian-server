#pragma once

#include <filesystem>
#include <optional>
#include <string_view>

#include "api.hpp"

namespace guardian::server {

// Serves the admin panel from `root`. Only an in-code allowlist of URL paths is served and no
// filesystem path is ever derived from the URL. Files are read on every request.
class StaticFiles {
 public:
  explicit StaticFiles(std::filesystem::path root);

  // nullopt when the URL path is not on the allowlist or the file is missing or unreadable.
  [[nodiscard]] std::optional<HttpResponse> serve(std::string_view urlPath) const;

 private:
  std::filesystem::path root_;
};

}  // namespace guardian::server
