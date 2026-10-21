#pragma once

#include <cstddef>
#include <filesystem>
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "agent_store.hpp"
#include "auth.hpp"
#include "event_store.hpp"
#include "policy_service.hpp"

namespace warden::server {

struct HttpRequest {
  std::string method;
  std::string path;
  std::map<std::string, std::string> headers;  // lower-case names
  std::map<std::string, std::string> query;
  std::string body;
  std::string remoteAddr;
};

struct HttpResponse {
  int status = 200;
  std::map<std::string, std::string> headers;
  std::string body;
};

struct ApiDeps {
  PolicyService& policies;
  AgentStore& agents;
  EventStore& events;
  AuthThrottle& throttle;
  std::string adminPassword;
  std::filesystem::path webRoot;
};

constexpr std::size_t kMaxBodyBytes = std::size_t{1024} * 1024;

// Handlers may throw; Api::handle turns every exception into a detail-free 500.
using RouteHandler = std::function<HttpResponse(const ApiDeps&, const HttpRequest&)>;

// Exact-match table of method + path. Each task registers its routes with add().
class RouteTable {
 public:
  void add(const std::string& method, const std::string& path, RouteHandler handler);
  // nullptr when the path is unknown; otherwise the methods registered for it.
  [[nodiscard]] const std::map<std::string, RouteHandler>* find(const std::string& path) const;

 private:
  std::map<std::string, std::map<std::string, RouteHandler>> routes_;
};

// {"error":"<code>","message":"<text>"}; text must never contain exception or path details.
HttpResponse errorResponse(int status, const std::string& code, const std::string& message);
HttpResponse jsonResponse(int status, const nlohmann::json& body);

// Registered by Api's constructor.
void registerAgentRoutes(RouteTable& table);

class Api {
 public:
  explicit Api(ApiDeps deps);
  // Never throws.
  [[nodiscard]] HttpResponse handle(const HttpRequest& request) const noexcept;

 private:
  ApiDeps deps_;
  RouteTable routes_;
};

}  // namespace warden::server
