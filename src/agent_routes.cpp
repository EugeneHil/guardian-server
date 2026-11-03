// Agent-facing routes: health, policy download and event ingestion.
#include <string>
#include <string_view>

#include "api.hpp"
#include "event.hpp"
#include "version.hpp"

namespace guardian::server {

namespace {

std::string_view trimBlanks(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1);
  }
  return text;
}

// True when an If-None-Match value (comma-separated optionally weak quoted tags, or "*")
// contains `etag` (a quoted tag such as "\"v3\""). Malformed elements never match.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): header and tag are distinct by name
bool etagMatches(std::string_view header, std::string_view etag) {
  while (true) {
    const auto comma = header.find(',');
    auto item = trimBlanks(header.substr(0, comma));
    if (item == "*") {
      return true;
    }
    if (item.substr(0, 2) == "W/") {
      item.remove_prefix(2);
    }
    if (item.size() >= 2 && item.front() == '"' && item.back() == '"' && item == etag) {
      return true;
    }
    if (comma == std::string_view::npos) {
      return false;
    }
    header.remove_prefix(comma + 1);
  }
}

// Resolves the agent id from the bearer token through the shared throttle gate.
std::optional<std::string> authenticateAgent(const ApiDeps& deps, const HttpRequest& request,
                                             HttpResponse& denied) {
  return authenticateWith(
      deps, request, "agent",
      [&deps](const HttpRequest& req) -> std::optional<std::string> {
        const auto header = req.headers.find("authorization");
        if (header == req.headers.end()) {
          return std::nullopt;
        }
        const auto token = parseBearer(header->second);
        return token ? deps.agents.authenticate(*token) : std::nullopt;
      },
      "Bearer", denied);
}

HttpResponse health(const ApiDeps& /*deps*/, const HttpRequest& /*request*/) {
  return jsonResponse(200, {{"status", "ok"}, {"version", std::string(serverVersion())}});
}

HttpResponse getPolicy(const ApiDeps& deps, const HttpRequest& request) {
  HttpResponse denied;
  if (!authenticateAgent(deps, request, denied)) {
    return denied;
  }
  const PolicyDoc doc = deps.policies.active();
  const std::string etag = "\"v" + std::to_string(doc.version) + "\"";
  HttpResponse response;
  response.headers["ETag"] = etag;
  const auto inm = request.headers.find("if-none-match");
  if (inm != request.headers.end() && etagMatches(inm->second, etag)) {
    response.status = 304;
    return response;
  }
  response.headers["Content-Type"] = "application/json; charset=utf-8";
  response.body = doc.json;
  return response;
}

HttpResponse postEvents(const ApiDeps& deps, const HttpRequest& request) {
  HttpResponse denied;
  const auto agentId = authenticateAgent(deps, request, denied);
  if (!agentId) {
    return denied;
  }
  const EventBatchResult batch = parseEventBatch(request.body);
  if (!batch.errors.empty()) {
    nlohmann::json errors = nlohmann::json::array();
    for (const auto& error : batch.errors) {
      errors.push_back({{"path", error.path}, {"message", error.message}});
    }
    return jsonResponse(400, {
                                 {"error", "invalid_events"},
                                 {"message", "One or more events are invalid."},
                                 {"errors", errors},
                             });
  }
  deps.events.append(*agentId, batch.events);
  return jsonResponse(200, {{"accepted", batch.events.size()}});
}

}  // namespace

void registerAgentRoutes(RouteTable& table) {
  table.add("GET", "/healthz", health);
  table.add("GET", "/api/v1/policy", getPolicy);
  table.add("POST", "/api/v1/events", postEvents);
}

}  // namespace guardian::server
