// Agent-facing routes: health, policy download and event ingestion.
#include <algorithm>
#include <chrono>
#include <string>
#include <string_view>

#include "api.hpp"
#include "event.hpp"
#include "version.hpp"

namespace warden::server {

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

HttpResponse unauthorized() {
  HttpResponse response = errorResponse(401, "unauthorized", "Missing or invalid credentials.");
  response.headers["WWW-Authenticate"] = "Bearer";
  return response;
}

// Applies the throttle contract and resolves the agent id from the bearer token. Returns the
// agent id, or nullopt with `denied` set to the response to send.
//  - a locked-out address is refused before credentials are looked at and is NOT charged again;
//  - missing, malformed or unknown credentials count as one failure;
//  - a valid token resets the failure count.
std::optional<std::string> authenticateAgent(const ApiDeps& deps, const HttpRequest& request,
                                             HttpResponse& denied) {
  AuthThrottle& throttle = deps.throttle;
  if (throttle.blocked(request.remoteAddr)) {
    const auto seconds =
        std::max<std::chrono::seconds::rep>(1, throttle.retryAfter(request.remoteAddr).count());
    denied = errorResponse(429, "too_many_requests", "Too many failed attempts. Try again later.");
    denied.headers["Retry-After"] = std::to_string(seconds);
    return std::nullopt;
  }
  std::optional<std::string> agentId;
  const auto header = request.headers.find("authorization");
  if (header != request.headers.end()) {
    if (const auto token = parseBearer(header->second)) {
      agentId = deps.agents.authenticate(*token);
    }
  }
  if (!agentId) {
    throttle.recordFailure(request.remoteAddr);
    denied = unauthorized();
    return std::nullopt;
  }
  throttle.recordSuccess(request.remoteAddr);
  return agentId;
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

}  // namespace warden::server
