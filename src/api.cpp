#include "api.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <utility>

#include "fs_util.hpp"

namespace guardian::server {

namespace {
constexpr const char* kJsonType = "application/json; charset=utf-8";

HttpResponse notFound() { return errorResponse(404, "not_found", "No such resource."); }

std::string joinMethods(const std::map<std::string, RouteHandler>& methods) {
  std::string out;
  for (const auto& entry : methods) {
    out += (out.empty() ? "" : ", ") + entry.first;
  }
  return out;
}

template <typename F>
bool tryRun(F&& action) noexcept {
  try {
    action();
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

void addCommonHeaders(HttpResponse& response) {
  response.headers["Cache-Control"] = "no-store";
  response.headers["X-Content-Type-Options"] = "nosniff";
}

HttpResponse dispatch(const ApiDeps& deps, const RouteTable& routes, const HttpRequest& request) {
  if (request.body.size() > kMaxBodyBytes) {
    return errorResponse(413, "payload_too_large", "Request body is too large.");
  }
  const auto* methods = routes.find(request.path);
  if (methods == nullptr) {
    return notFound();
  }
  auto handler = methods->find(request.method);
  if (handler == methods->end()) {
    HttpResponse response =
        errorResponse(405, "method_not_allowed", "Method not allowed for this resource.");
    response.headers["Allow"] = joinMethods(*methods);
    return response;
  }
  return handler->second(deps, request);
}

// Cannot throw: used on the error paths of Api::handle (allocation failure yields a bare status).
HttpResponse fallbackError(int status, const char* code, const char* message) noexcept {
  HttpResponse response;
  response.status = status;
  if (!tryRun([&] { response = errorResponse(status, code, message); })) {
    response = HttpResponse{};
    response.status = status;
  }
  return response;
}

HttpResponse withCommonHeaders(HttpResponse response) noexcept {
  tryRun([&] { addCommonHeaders(response); });
  return response;
}
}  // namespace

void RouteTable::add(const std::string& method, const std::string& path, RouteHandler handler) {
  routes_[path][method] = std::move(handler);
}

const std::map<std::string, RouteHandler>* RouteTable::find(const std::string& path) const {
  auto it = routes_.find(path);
  return it == routes_.end() ? nullptr : &it->second;
}

HttpResponse jsonResponse(int status, const nlohmann::json& body) {
  HttpResponse response;
  response.status = status;
  response.headers["Content-Type"] = kJsonType;
  response.body = body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  return response;
}

HttpResponse errorResponse(int status, const std::string& code, const std::string& message) {
  return jsonResponse(status, nlohmann::json{{"error", code}, {"message", message}});
}

std::optional<std::string> authenticateWith(const ApiDeps& deps, const HttpRequest& request,
                                            const std::string& realm, const CredentialCheck& check,
                                            const std::string& challenge, HttpResponse& denied) {
  AuthThrottle& throttle = deps.throttle;
  const std::string key = realm + "|" + request.remoteAddr;
  if (throttle.blocked(key)) {
    const auto seconds = std::max<std::chrono::seconds::rep>(1, throttle.retryAfter(key).count());
    denied = errorResponse(429, "too_many_requests", "Too many failed attempts. Try again later.");
    denied.headers["Retry-After"] = std::to_string(seconds);
    return std::nullopt;
  }
  auto principal = check(request);
  if (!principal) {
    throttle.recordFailure(key);
    denied = errorResponse(401, "unauthorized", "Missing or invalid credentials.");
    denied.headers["WWW-Authenticate"] = challenge;
    return std::nullopt;
  }
  throttle.recordSuccess(key);
  return principal;
}

Api::Api(ApiDeps deps) : deps_(std::move(deps)) {
  registerAgentRoutes(routes_);
  registerAdminRoutes(routes_);
}

HttpResponse Api::handle(const HttpRequest& request) const noexcept {
  HttpResponse response;
  try {
    response = dispatch(deps_, routes_, request);
  } catch (const StorageError&) {
    response = fallbackError(500, "storage", "Storage failure.");
  } catch (...) {
    response = fallbackError(500, "internal", "Internal server error.");
  }
  return withCommonHeaders(std::move(response));
}

}  // namespace guardian::server
