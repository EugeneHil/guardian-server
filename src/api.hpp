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

// Checks the credentials of one realm; returns the authenticated principal or nullopt.
using CredentialCheck = std::function<std::optional<std::string>(const HttpRequest&)>;

// Shared authentication gate with the throttle contract. The throttle is keyed by realm and
// remote address, so a success in one realm never resets failures counted in another.
//  - a locked-out key is refused with 429 + Retry-After before credentials are looked at and is
//    NOT charged again;
//  - missing, malformed or wrong credentials count as one failure and yield a 401 carrying
//    `challenge` as WWW-Authenticate;
//  - a success resets the failure count of that realm and address.
// Returns the principal, or nullopt with `denied` set to the response to send.
std::optional<std::string> authenticateWith(const ApiDeps& deps, const HttpRequest& request,
                                            const std::string& realm,
                                            const CredentialCheck& check,
                                            const std::string& challenge, HttpResponse& denied);

// Registered by Api's constructor.
void registerAgentRoutes(RouteTable& table);
void registerAdminRoutes(RouteTable& table);

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
