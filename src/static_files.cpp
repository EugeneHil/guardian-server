#include "static_files.hpp"

#include <array>
#include <system_error>
#include <utility>

#include "fs_util.hpp"

namespace warden::server {

namespace {

struct Entry {
  std::string_view urlPath;
  const char* fileName;
  const char* contentType;
  bool html;
};

constexpr std::array<Entry, 4> kAllowlist = {
    {
        {"/", "index.html", "text/html; charset=utf-8", true},
        {"/app.js", "app.js", "text/javascript; charset=utf-8", false},
        {"/panel.css", "panel.css", "text/css; charset=utf-8", false},
        {"/tokens.css", "tokens.css", "text/css; charset=utf-8", false},
    },
};

}  // namespace

StaticFiles::StaticFiles(std::filesystem::path root) : root_(std::move(root)) {}

std::optional<HttpResponse> StaticFiles::serve(std::string_view urlPath) const {
  for (const Entry& entry : kAllowlist) {
    if (entry.urlPath != urlPath) {
      continue;
    }
    const std::filesystem::path file = root_ / entry.fileName;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(file, ec) || ec) {
      return std::nullopt;
    }
    auto content = readFile(file);
    if (!content) {
      return std::nullopt;
    }
    HttpResponse response;
    response.headers["Content-Type"] = entry.contentType;
    if (entry.html) {
      response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'";
      response.headers["Referrer-Policy"] = "no-referrer";
    }
    response.body = std::move(*content);
    return response;
  }
  return std::nullopt;
}

}  // namespace warden::server
