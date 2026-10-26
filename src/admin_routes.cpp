// Admin routes (policy editing, event listing) and the static panel files. Every route here
// requires HTTP Basic credentials.
#include <cstddef>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "api.hpp"
#include "fs_util.hpp"
#include "static_files.hpp"

namespace guardian::server {

namespace {

constexpr std::size_t kDefaultEventLimit = 100;
constexpr std::size_t kMaxEventLimit = 1000;
constexpr std::size_t kMaxLimitDigits = 8;

// Checks the Basic credentials through the shared throttle gate. Returns true when
// authenticated, otherwise `denied` holds the response to send.
bool authenticateAdmin(const ApiDeps& deps, const HttpRequest& request, HttpResponse& denied) {
  return authenticateWith(
             deps, request, "admin",
             [&deps](const HttpRequest& req) -> std::optional<std::string> {
               const auto header = req.headers.find("authorization");
               if (header == req.headers.end()) {
                 return std::nullopt;
               }
               const auto credentials = parseBasic(header->second);
               if (credentials && adminCredentialsMatch(*credentials, deps.adminPassword)) {
                 return std::string("admin");
               }
               return std::nullopt;
             },
             R"(Basic realm="Guardian", charset="UTF-8")", denied)
      .has_value();
}

nlohmann::json errorsToJson(const std::vector<guardian::ValidationError>& errors) {
  nlohmann::json out = nlohmann::json::array();
  for (const auto& error : errors) {
    out.push_back({{"path", error.path}, {"message", error.message}});
  }
  return out;
}

nlohmann::json reportToJson(const ValidationReport& report) {
  return {{"valid", report.valid}, {"errors", errorsToJson(report.errors)}};
}

HttpResponse getPolicy(const ApiDeps& deps, const HttpRequest& /*request*/) {
  const PolicyDoc doc = deps.policies.active();
  auto policy = nlohmann::json::parse(doc.json, nullptr, false);
  if (policy.is_discarded()) {
    throw StorageError("active policy is not valid JSON");
  }
  nlohmann::json draft = nullptr;
  if (const auto text = deps.policies.draft()) {
    draft = {{"text", *text}, {"validation", reportToJson(deps.policies.validateDraft())}};
  }
  return jsonResponse(
      200, {{"active", {{"version", doc.version}, {"policy", policy}}}, {"draft", draft}});
}

HttpResponse putDraft(const ApiDeps& deps, const HttpRequest& request) {
  return jsonResponse(200, reportToJson(deps.policies.saveDraft(request.body)));
}

HttpResponse publish(const ApiDeps& deps, const HttpRequest& /*request*/) {
  const PublishResult result = deps.policies.publish();
  switch (result.failure) {
    case PublishResult::Failure::NoDraft:
      return errorResponse(409, "no_draft", "There is no draft to publish.");
    case PublishResult::Failure::Invalid: {
      return jsonResponse(422, {
                                   {"error", "invalid_draft"},
                                   {"message", "The draft is invalid."},
                                   {"errors", errorsToJson(result.errors)},
                               });
    }
    case PublishResult::Failure::None:
      break;
  }
  if (!result.published) {
    throw StorageError("publish returned no document");
  }
  return jsonResponse(200, {{"version", result.published->version}});
}

// Strictly digits (no sign, blanks, hex), bounded length, value in 1..kMaxEventLimit.
std::optional<std::size_t> parseLimit(const std::string& text) {
  if (text.empty() || text.size() > kMaxLimitDigits) {
    return std::nullopt;
  }
  std::size_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    value = (value * 10) + static_cast<std::size_t>(c - '0');
  }
  if (value < 1 || value > kMaxEventLimit) {
    return std::nullopt;
  }
  return value;
}

HttpResponse getEvents(const ApiDeps& deps, const HttpRequest& request) {
  std::size_t limit = kDefaultEventLimit;
  const auto param = request.query.find("limit");
  if (param != request.query.end()) {
    const auto parsed = parseLimit(param->second);
    if (!parsed) {
      return errorResponse(400, "bad_request", "limit must be an integer from 1 to 1000.");
    }
    limit = *parsed;
  }
  nlohmann::json events = nlohmann::json::array();
  for (const auto& event : deps.events.recent(limit)) {
    events.push_back(toJson(event));
  }
  return jsonResponse(200, {{"events", events}});
}

HttpResponse notFound() { return errorResponse(404, "not_found", "No such resource."); }

// Browsers attach cached Basic credentials to cross-site form posts. A custom header cannot be
// set by a cross-site form (and needs a CORS preflight, which the server never grants), so
// requiring it on state-changing calls closes that CSRF path.
bool hasRequestMarker(const HttpRequest& request) {
  const auto header = request.headers.find("x-guardian-request");
  return header != request.headers.end() && header->second == "1";
}

RouteHandler adminOnly(RouteHandler inner, bool stateChanging = false) {
  return
      [inner = std::move(inner), stateChanging](const ApiDeps& deps, const HttpRequest& request) {
        HttpResponse denied;
        if (!authenticateAdmin(deps, request, denied)) {
          return denied;
        }
        if (stateChanging && !hasRequestMarker(request)) {
          return errorResponse(400, "bad_request", "Header X-Guardian-Request: 1 is required.");
        }
        return inner(deps, request);
      };
}

RouteHandler staticRoute() {
  return adminOnly([](const ApiDeps& deps, const HttpRequest& request) {
    auto served = StaticFiles(deps.webRoot).serve(request.path);
    return served ? *served : notFound();
  });
}

}  // namespace

void registerAdminRoutes(RouteTable& table) {
  table.add("GET", "/api/v1/admin/policy", adminOnly(getPolicy));
  table.add("PUT", "/api/v1/admin/policy/draft", adminOnly(putDraft, true));
  table.add("POST", "/api/v1/admin/policy/publish", adminOnly(publish, true));
  table.add("GET", "/api/v1/admin/events", adminOnly(getEvents));
  for (const char* path : {"/", "/app.js", "/panel.css", "/tokens.css"}) {
    table.add("GET", path, staticRoute());
  }
}

}  // namespace guardian::server
