#include "api.hpp"

#include <exception>
#include <utility>

#include "fs_util.hpp"

namespace warden::server {

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

Api::Api(ApiDeps deps) : deps_(std::move(deps)) { registerAgentRoutes(routes_); }

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

}  // namespace warden::server
