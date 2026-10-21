#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "api.hpp"
#include "api_test_support.hpp"
#include "crypto.hpp"
#include "version.hpp"

using namespace warden::server;
using namespace warden::server::testing;
using nlohmann::json;

namespace {
const char* const kValidEvent =
    R"({"ts":"2026-10-21T08:30:00Z","process":{"path":"/bin/cat"},"file":"/tmp/a","decision":"deny"})";

std::string batch(const std::string& item, int n = 1) {
  std::string out = "[";
  for (int i = 0; i < n; ++i) {
    out += (i ? "," : "") + item;
  }
  return out + "]";
}

std::string header(const HttpResponse& r, const std::string& name) {
  auto it = r.headers.find(name);
  return it == r.headers.end() ? std::string("<absent>") : it->second;
}

void expectError(const HttpResponse& r, int status, const std::string& code) {
  EXPECT_EQ(r.status, status);
  auto j = json::parse(r.body, nullptr, false);
  ASSERT_TRUE(j.is_object()) << r.body;
  EXPECT_EQ(j.value("error", ""), code);
  EXPECT_TRUE(j.contains("message"));
  EXPECT_EQ(header(r, "Content-Type"), "application/json; charset=utf-8");
}

void expectHardening(const HttpResponse& r) {
  EXPECT_EQ(header(r, "Cache-Control"), "no-store");
  EXPECT_EQ(header(r, "X-Content-Type-Options"), "nosniff");
}

std::string basic(const std::string& raw) { return "Basic " + base64Encode(raw); }
}  // namespace

using Healthz = ApiFixture;
using Policy = ApiFixture;
using Auth = ApiFixture;
using AgentThrottle = ApiFixture;
using Events = ApiFixture;
using Errors = ApiFixture;

TEST_F(Healthz, NoAuthOnlyVersion) {
  auto r = api_.handle(request("GET", "/healthz"));
  EXPECT_EQ(r.status, 200);
  EXPECT_EQ(json::parse(r.body),
            (json{{"status", "ok"}, {"version", std::string(serverVersion())}}));
  EXPECT_EQ(header(r, "Content-Type"), "application/json; charset=utf-8");
  expectHardening(r);
}

TEST_F(Policy, RequiresBearer401WithChallenge) {
  auto r = api_.handle(request("GET", "/api/v1/policy"));
  expectError(r, 401, "unauthorized");
  EXPECT_EQ(header(r, "WWW-Authenticate"), "Bearer");
  expectHardening(r);
  auto bad = api_.handle(bearer("GET", "/api/v1/policy", "wdn_nope"));
  expectError(bad, 401, "unauthorized");
  EXPECT_EQ(header(bad, "WWW-Authenticate"), "Bearer");
}

TEST_F(Policy, ReturnsBootstrapV1WithEtag) {
  auto token = addAgent("mac1");
  auto r = api_.handle(bearer("GET", "/api/v1/policy", token));
  EXPECT_EQ(r.status, 200);
  EXPECT_EQ(header(r, "ETag"), "\"v1\"");
  EXPECT_EQ(r.body, policies_.active().json);
  EXPECT_EQ(json::parse(r.body)["version"], 1);
  EXPECT_EQ(header(r, "Content-Type"), "application/json; charset=utf-8");
  expectHardening(r);
}

TEST_F(Policy, EtagMatchGives304) {
  auto token = addAgent("mac1");
  for (const char* inm : {"\"v1\"", "W/\"v1\"", "\"v0\", \"v1\"", "*", " \"v0\" ,\tW/\"v1\" "}) {
    auto req = bearer("GET", "/api/v1/policy", token);
    req.headers["if-none-match"] = inm;
    auto r = api_.handle(req);
    EXPECT_EQ(r.status, 304) << inm;
    EXPECT_TRUE(r.body.empty()) << inm;
    EXPECT_EQ(header(r, "ETag"), "\"v1\"") << inm;
    expectHardening(r);
  }
}

TEST_F(Policy, StaleOrMalformedEtagGives200) {
  auto token = addAgent("mac1");
  for (const char* inm : {"\"v0\"", "v1", "", "\"v1", "W/v1", "\"V1\"", "\"v1\"x", ",,", "**"}) {
    auto req = bearer("GET", "/api/v1/policy", token);
    req.headers["if-none-match"] = inm;
    auto r = api_.handle(req);
    EXPECT_EQ(r.status, 200) << inm;
    EXPECT_FALSE(r.body.empty()) << inm;
  }
}

TEST_F(Policy, NewVersionAfterPublish) {
  auto token = addAgent("mac1");
  policies_.saveDraft(R"({"schemaVersion":1,"version":0,"rules":[]})");
  ASSERT_EQ(policies_.publish().failure, PublishResult::Failure::None);
  auto r = api_.handle(bearer("GET", "/api/v1/policy", token));
  EXPECT_EQ(r.status, 200);
  EXPECT_EQ(header(r, "ETag"), "\"v2\"");
  EXPECT_EQ(json::parse(r.body)["version"], 2);
  auto req = bearer("GET", "/api/v1/policy", token);
  req.headers["if-none-match"] = "\"v2\"";
  EXPECT_EQ(api_.handle(req).status, 304);
  req.headers["if-none-match"] = "\"v1\"";
  EXPECT_EQ(api_.handle(req).status, 200);
}

TEST_F(Policy, RejectsRevokedToken) {
  auto token = addAgent("mac1");
  EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", token)).status, 200);
  ASSERT_TRUE(agents_.remove("mac1"));
  expectError(api_.handle(bearer("GET", "/api/v1/policy", token)), 401, "unauthorized");
}

TEST_F(Policy, RejectsAdminBasicCredentials) {
  auto r =
      api_.handle(request("GET", "/api/v1/policy", basic(std::string("admin:") + kAdminPassword)));
  expectError(r, 401, "unauthorized");
  EXPECT_EQ(header(r, "WWW-Authenticate"), "Bearer");
}

TEST_F(Auth, GarbageAuthorizationIs401) {
  const std::vector<std::string> values = {"",
                                           "Bearer ",
                                           "Bearer",
                                           "Basic !!!",
                                           std::string(10 * 1024, 'A'),
                                           "Bearer " + std::string(10 * 1024, 'a'),
                                           std::string("Bearer ab\0cd", 12),
                                           std::string("\0\0\0", 3),
                                           "Bearer a b",
                                           "Token abc"};
  for (const auto& v : values) {
    HttpRequest req = request("GET", "/api/v1/policy");
    req.headers["authorization"] = v;
    for (const char* path : {"/api/v1/policy", "/api/v1/events"}) {
      req.path = path;
      req.method = std::string(path) == "/api/v1/events" ? "POST" : "GET";
      req.body = batch(kValidEvent);
      req.remoteAddr = "192.0.2." + std::to_string(&v - values.data()) + path;  // avoid lockout
      auto r = api_.handle(req);
      EXPECT_EQ(r.status, 401) << v.size();
      EXPECT_EQ(header(r, "WWW-Authenticate"), "Bearer");
    }
  }
}

TEST_F(AgentThrottle, SixthBadTokenIs429WithRetryAfter) {
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", "wdn_bad")).status, 401) << i;
  }
  auto r = api_.handle(bearer("GET", "/api/v1/policy", "wdn_bad"));
  expectError(r, 429, "too_many_requests");
  EXPECT_NE(header(r, "Retry-After"), "<absent>");
  EXPECT_GE(std::stoi(header(r, "Retry-After")), 1);
  EXPECT_LE(std::stoi(header(r, "Retry-After")), 60);
  // Other addresses are unaffected.
  EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", "wdn_bad", "10.9.9.9")).status, 401);
}

TEST_F(AgentThrottle, MissingHeaderCountsAsFailure) {
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(api_.handle(request("GET", "/api/v1/policy")).status, 401);
  }
  EXPECT_EQ(api_.handle(request("GET", "/api/v1/policy")).status, 429);
}

TEST_F(AgentThrottle, GoodTokenAfterLockoutStillBlockedUntilExpiry) {
  auto token = addAgent("mac1");
  for (int i = 0; i < 5; ++i) {
    (void)api_.handle(bearer("GET", "/api/v1/policy", "wdn_bad"));
  }
  EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", token)).status, 429);
  advance(30);
  // Blocked requests must not extend the lockout.
  EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", token)).status, 429);
  advance(31);
  EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", token)).status, 200);
}

TEST_F(AgentThrottle, SuccessResetsFailures) {
  auto token = addAgent("mac1");
  for (int i = 0; i < 4; ++i) {
    (void)api_.handle(bearer("GET", "/api/v1/policy", "wdn_bad"));
  }
  EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", token)).status, 200);
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(api_.handle(bearer("GET", "/api/v1/policy", "wdn_bad")).status, 401);
  }
}

TEST_F(Events, AcceptsBatchAndStoresAgentIdFromToken) {
  auto token = addAgent("mac1");
  auto req = bearer("POST", "/api/v1/events", token);
  req.body =
      R"([{"agentId":"evil","ts":"2026-10-21T08:30:00Z","process":{"path":"/bin/cat"},"file":"/tmp/a","decision":"deny","ruleId":"r1"},)"
      R"({"ts":"2026-10-21T08:31:00Z","process":{"path":"/bin/ls"},"file":"/tmp/b","decision":"allow"}])";
  auto r = api_.handle(req);
  EXPECT_EQ(r.status, 200);
  EXPECT_EQ(json::parse(r.body), (json{{"accepted", 2}}));
  expectHardening(r);
  auto stored = events_.recent(10);
  ASSERT_EQ(stored.size(), 2U);
  for (const auto& e : stored) {
    EXPECT_EQ(e.agentId, "mac1");
  }
}

TEST_F(Events, InvalidItemRejectsWholeBatch400WithPaths) {
  auto token = addAgent("mac1");
  auto req = bearer("POST", "/api/v1/events", token);
  req.body = "[" + std::string(kValidEvent) + "," + kValidEvent +
             R"(,{"ts":"2026-10-21T08:30:00Z","process":{"path":"/bin/cat"},"decision":"deny"}])";
  auto r = api_.handle(req);
  EXPECT_EQ(r.status, 400);
  auto j = json::parse(r.body);
  EXPECT_EQ(j["error"], "invalid_events");
  ASSERT_TRUE(j["errors"].is_array());
  ASSERT_FALSE(j["errors"].empty());
  EXPECT_EQ(j["errors"][0]["path"], "[2].file");
  EXPECT_TRUE(j["errors"][0].contains("message"));
  EXPECT_TRUE(events_.recent(10).empty());
}

TEST_F(Events, OversizeBodyIs413) {
  auto token = addAgent("mac1");
  auto req = bearer("POST", "/api/v1/events", token);
  req.body = std::string(kMaxBodyBytes + 1, ' ');
  expectError(api_.handle(req), 413, "payload_too_large");
  req.body = std::string(kMaxBodyBytes, ' ');
  EXPECT_EQ(api_.handle(req).status, 400);  // at the limit it is parsed (and found invalid)
  EXPECT_TRUE(events_.recent(10).empty());
}

TEST_F(Events, RequiresBearer) {
  auto req = request("POST", "/api/v1/events");
  req.body = batch(kValidEvent);
  auto r = api_.handle(req);
  expectError(r, 401, "unauthorized");
  EXPECT_EQ(header(r, "WWW-Authenticate"), "Bearer");
  req.headers["authorization"] = basic(std::string("admin:") + kAdminPassword);
  expectError(api_.handle(req), 401, "unauthorized");
  EXPECT_TRUE(events_.recent(10).empty());
}

TEST_F(Events, WrongMethod405) {
  auto token = addAgent("mac1");
  auto r = api_.handle(bearer("GET", "/api/v1/events", token));
  expectError(r, 405, "method_not_allowed");
  EXPECT_EQ(header(r, "Allow"), "POST");
  auto p = api_.handle(bearer("POST", "/api/v1/policy", token));
  expectError(p, 405, "method_not_allowed");
  EXPECT_EQ(header(p, "Allow"), "GET");
  EXPECT_EQ(api_.handle(request("DELETE", "/healthz")).status, 405);
}

TEST_F(Events, NonJsonBody400) {
  auto token = addAgent("mac1");
  for (const char* body : {"", "not json", "{}", "[]", "[1]", "\xff\xfe"}) {
    auto req = bearer("POST", "/api/v1/events", token);
    req.body = body;
    auto r = api_.handle(req);
    EXPECT_EQ(r.status, 400) << body;
    EXPECT_EQ(json::parse(r.body)["error"], "invalid_events");
    EXPECT_EQ(r.body.find("nlohmann"), std::string::npos);
  }
}

TEST_F(Errors, UnknownPath404) {
  expectError(api_.handle(request("GET", "/nope")), 404, "not_found");
  expectError(api_.handle(request("GET", "/healthz/")), 404, "not_found");
  expectError(api_.handle(request("GET", "/api/v1/policy/../events")), 404, "not_found");
  expectHardening(api_.handle(request("GET", "/nope")));
}

TEST_F(Errors, StorageFailureIs500WithoutDetail) {
  auto token = addAgent("mac1");
  ThrowingEventStore throwing;
  Api api(deps(throwing));
  auto req = bearer("POST", "/api/v1/events", token);
  req.body = batch(kValidEvent);
  auto r = api.handle(req);
  expectError(r, 500, "storage");
  EXPECT_EQ(r.body.find("secret"), std::string::npos);
  EXPECT_EQ(r.body.find("events.jsonl"), std::string::npos);
  expectHardening(r);
}

TEST_F(Errors, NoExceptionEscapes) {
  auto token = addAgent("mac1");
  ThrowingEventStore throwing(true);
  Api api(deps(throwing));
  auto req = bearer("POST", "/api/v1/events", token);
  req.body = batch(kValidEvent);
  HttpResponse r;
  EXPECT_NO_THROW(r = api.handle(req));
  expectError(r, 500, "internal");
  EXPECT_EQ(r.body.find("secret"), std::string::npos);
  EXPECT_EQ(r.body.find("boom"), std::string::npos);
  HttpRequest weird;
  weird.method = std::string("\0\xff", 2);
  weird.path = std::string(100000, 'x');
  EXPECT_NO_THROW(r = api.handle(weird));
  EXPECT_EQ(r.status, 404);
}
