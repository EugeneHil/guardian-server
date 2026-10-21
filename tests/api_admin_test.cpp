#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "api.hpp"
#include "api_test_support.hpp"
#include "crypto.hpp"

using namespace warden::server;
using namespace warden::server::testing;
using nlohmann::json;

namespace {
const char* const kValidDraft =
    R"({"schemaVersion":1,"version":0,"rules":[{"id":"r","targets":["**/secret.txt"],"action":"deny","processes":[{"teamId":"X"}]}]})";
const char* const kInvalidDraft = R"({"schemaVersion":1,"version":0,"rules":[{"id":"r"}]})";
const char* const kChallenge = R"(Basic realm="Warden", charset="UTF-8")";

std::string basic(const std::string& raw) { return "Basic " + base64Encode(raw); }
std::string adminAuth() { return basic(std::string("admin:") + ApiFixture::kAdminPassword); }

std::string header(const HttpResponse& r, const std::string& name) {
  auto it = r.headers.find(name);
  return it == r.headers.end() ? std::string("<absent>") : it->second;
}

void expectError(const HttpResponse& r, int status, const std::string& code) {
  EXPECT_EQ(r.status, status) << r.body;
  auto j = json::parse(r.body, nullptr, false);
  ASSERT_TRUE(j.is_object()) << r.body;
  EXPECT_EQ(j.value("error", ""), code);
  EXPECT_TRUE(j.contains("message"));
}

struct RouteSpec {
  const char* method;
  const char* path;
};
const std::vector<RouteSpec> kAdminRoutes = {
    {"GET", "/api/v1/admin/policy"},
    {"PUT", "/api/v1/admin/policy/draft"},
    {"POST", "/api/v1/admin/policy/publish"},
    {"GET", "/api/v1/admin/events"},
    {"GET", "/"},
    {"GET", "/app.js"},
    {"GET", "/panel.css"},
    {"GET", "/tokens.css"},
};
}  // namespace

using Admin = ApiFixture;

TEST_F(Admin, AllRoutesRequireBasic) {
  const std::string token = addAgent("mac-1");
  int routeNo = 0;
  for (const auto& route : kAdminRoutes) {
    ++routeNo;
    const std::vector<std::string> attempts = {"", basic("admin:wrong"),
                                               basic(std::string("root:") + kAdminPassword),
                                               "Bearer " + token, "Basic !!!garbage"};
    int n = 0;
    for (const auto& auth : attempts) {
      // Distinct addresses so the throttle does not interfere with the table.
      auto r = api_.handle(request(route.method, route.path, auth,
                                   "10." + std::to_string(routeNo) + ".0." + std::to_string(++n)));
      SCOPED_TRACE(std::string(route.method) + " " + route.path + " auth=" + auth);
      expectError(r, 401, "unauthorized");
      EXPECT_EQ(header(r, "WWW-Authenticate"), kChallenge);
    }
  }
}

TEST_F(Admin, IdenticalBodyForAllFailureKinds) {
  auto a = api_.handle(request("GET", "/api/v1/admin/policy", "", "10.2.0.1"));
  auto b = api_.handle(request("GET", "/api/v1/admin/policy", basic("admin:x"), "10.2.0.2"));
  EXPECT_EQ(a.body, b.body);
}

TEST_F(Admin, GetPolicyShowsActiveAndNullDraft) {
  auto r = api_.handle(request("GET", "/api/v1/admin/policy", adminAuth()));
  ASSERT_EQ(r.status, 200) << r.body;
  auto j = json::parse(r.body);
  EXPECT_EQ(j["active"]["version"], 1);
  EXPECT_EQ(j["active"]["policy"]["version"], 1);
  EXPECT_TRUE(j["draft"].is_null());
}

TEST_F(Admin, GetPolicyShowsDraftWithValidation) {
  auto put = request("PUT", "/api/v1/admin/policy/draft", adminAuth());
  put.body = kInvalidDraft;
  ASSERT_EQ(api_.handle(put).status, 200);
  auto r = api_.handle(request("GET", "/api/v1/admin/policy", adminAuth()));
  auto j = json::parse(r.body);
  EXPECT_EQ(j["draft"]["text"], kInvalidDraft);
  EXPECT_FALSE(j["draft"]["validation"]["valid"].get<bool>());
  EXPECT_FALSE(j["draft"]["validation"]["errors"].empty());
}

TEST_F(Admin, PutDraftValidReturnsValidTrue) {
  auto put = request("PUT", "/api/v1/admin/policy/draft", adminAuth());
  put.body = kValidDraft;
  auto r = api_.handle(put);
  ASSERT_EQ(r.status, 200) << r.body;
  auto j = json::parse(r.body);
  EXPECT_TRUE(j["valid"].get<bool>());
  EXPECT_TRUE(j["errors"].empty());
}

TEST_F(Admin, PutDraftInvalidReturnsErrorsWithPathsAndStillSaves) {
  auto put = request("PUT", "/api/v1/admin/policy/draft", adminAuth());
  put.body = kInvalidDraft;
  auto r = api_.handle(put);
  ASSERT_EQ(r.status, 200) << r.body;
  auto j = json::parse(r.body);
  EXPECT_FALSE(j["valid"].get<bool>());
  ASSERT_FALSE(j["errors"].empty());
  EXPECT_TRUE(j["errors"][0].contains("path"));
  EXPECT_TRUE(j["errors"][0].contains("message"));
  EXPECT_EQ(policyStore_.draft().value_or(""), kInvalidDraft);
}

TEST_F(Admin, PutDraftOversizeIs413) {
  auto put = request("PUT", "/api/v1/admin/policy/draft", adminAuth());
  put.body.assign(kMaxBodyBytes + 1, 'x');
  expectError(api_.handle(put), 413, "payload_too_large");
  EXPECT_FALSE(policyStore_.draft().has_value());
}

TEST_F(Admin, PublishValidDraftReturnsNextVersionAndAgentSeesIt) {
  auto put = request("PUT", "/api/v1/admin/policy/draft", adminAuth());
  put.body = kValidDraft;
  ASSERT_EQ(api_.handle(put).status, 200);
  auto r = api_.handle(request("POST", "/api/v1/admin/policy/publish", adminAuth()));
  ASSERT_EQ(r.status, 200) << r.body;
  EXPECT_EQ(json::parse(r.body), json({{"version", 2}}));
  const std::string token = addAgent("mac-1");
  auto agent = api_.handle(bearer("GET", "/api/v1/policy", token));
  EXPECT_EQ(agent.status, 200);
  EXPECT_EQ(header(agent, "ETag"), "\"v2\"");
  EXPECT_EQ(json::parse(agent.body)["version"], 2);
  auto again = api_.handle(request("GET", "/api/v1/admin/policy", adminAuth()));
  EXPECT_TRUE(json::parse(again.body)["draft"].is_null());
}

TEST_F(Admin, PublishInvalidIs422WithErrors) {
  auto put = request("PUT", "/api/v1/admin/policy/draft", adminAuth());
  put.body = kInvalidDraft;
  ASSERT_EQ(api_.handle(put).status, 200);
  auto r = api_.handle(request("POST", "/api/v1/admin/policy/publish", adminAuth()));
  expectError(r, 422, "invalid_draft");
  auto j = json::parse(r.body);
  ASSERT_FALSE(j["errors"].empty());
  EXPECT_TRUE(j["errors"][0].contains("path"));
}

TEST_F(Admin, PublishWithoutDraftIs409) {
  expectError(api_.handle(request("POST", "/api/v1/admin/policy/publish", adminAuth())), 409,
              "no_draft");
}

TEST_F(Admin, EventsNewestFirstAndLimit) {
  const std::string token = addAgent("mac-1");
  for (int i = 0; i < 3; ++i) {
    auto post = bearer("POST", "/api/v1/events", token);
    post.body = R"([{"ts":"2026-10-21T08:30:0)" + std::to_string(i) +
                R"(Z","process":{"path":"/bin/cat"},"file":"/tmp/f)" + std::to_string(i) +
                R"(","decision":"deny"}])";
    ASSERT_EQ(api_.handle(post).status, 200);
  }
  auto r = api_.handle(request("GET", "/api/v1/admin/events", adminAuth()));
  ASSERT_EQ(r.status, 200) << r.body;
  auto j = json::parse(r.body);
  ASSERT_EQ(j["events"].size(), 3U);
  EXPECT_EQ(j["events"][0]["file"], "/tmp/f2");
  EXPECT_EQ(j["events"][0]["agentId"], "mac-1");
  EXPECT_TRUE(j["events"][0].contains("receivedAt"));
  auto limited = request("GET", "/api/v1/admin/events", adminAuth());
  limited.query["limit"] = "2";
  auto lr = api_.handle(limited);
  ASSERT_EQ(lr.status, 200);
  auto lj = json::parse(lr.body);
  ASSERT_EQ(lj["events"].size(), 2U);
  EXPECT_EQ(lj["events"][1]["file"], "/tmp/f1");
}

TEST_F(Admin, EventsBadLimitIs400) {
  for (const std::string bad : {"0", "1001", "-1", "+5", "abc", "", " 5", "5 ", "0x10", "1e2",
                                "99999999999999999999999999"}) {
    auto req = request("GET", "/api/v1/admin/events", adminAuth());
    req.query["limit"] = bad;
    SCOPED_TRACE("limit=" + bad);
    expectError(api_.handle(req), 400, "bad_request");
  }
  for (const std::string good : {"1", "1000", "0100"}) {
    auto req = request("GET", "/api/v1/admin/events", adminAuth());
    req.query["limit"] = good;
    SCOPED_TRACE("limit=" + good);
    EXPECT_EQ(api_.handle(req).status, 200);
  }
}

TEST_F(Admin, SixthBadPasswordIs429) {
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(api_.handle(request("GET", "/api/v1/admin/policy", basic("admin:bad"))).status, 401);
  }
  auto r = api_.handle(request("GET", "/api/v1/admin/policy", basic("admin:bad")));
  expectError(r, 429, "too_many_requests");
  EXPECT_NE(header(r, "Retry-After"), "<absent>");
  // Correct credentials are refused while locked out.
  EXPECT_EQ(api_.handle(request("GET", "/api/v1/admin/policy", adminAuth())).status, 429);
  advance(61);
  EXPECT_EQ(api_.handle(request("GET", "/api/v1/admin/policy", adminAuth())).status, 200);
}

TEST_F(Admin, SuccessResetsFailures) {
  for (int i = 0; i < 4; ++i) {
    (void)api_.handle(request("GET", "/api/v1/admin/policy", basic("admin:bad")));
  }
  EXPECT_EQ(api_.handle(request("GET", "/api/v1/admin/policy", adminAuth())).status, 200);
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(api_.handle(request("GET", "/api/v1/admin/policy", basic("admin:bad"))).status, 401);
  }
}

TEST_F(Admin, UnknownPathsDoNotConsumeThrottle) {
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(api_.handle(request("GET", "/api/v1/admin/nope", basic("admin:bad"))).status, 404);
    EXPECT_EQ(api_.handle(request("GET", "/../x")).status, 404);
  }
  EXPECT_EQ(api_.handle(request("GET", "/api/v1/admin/policy", adminAuth())).status, 200);
}

TEST_F(Admin, GetOnPublishIs405) {
  auto r = api_.handle(request("GET", "/api/v1/admin/policy/publish"));
  expectError(r, 405, "method_not_allowed");
  EXPECT_EQ(header(r, "Allow"), "POST");
  auto post = api_.handle(request("POST", "/api/v1/admin/policy"));
  EXPECT_EQ(post.status, 405);
  EXPECT_EQ(header(post, "Allow"), "GET");
}

TEST_F(Admin, AgentRoutesRejectAdminBasic) {
  EXPECT_EQ(api_.handle(request("GET", "/api/v1/policy", adminAuth())).status, 401);
}

TEST_F(Admin, EventsStorageFailureIs500WithoutDetails) {
  ThrowingEventStore broken;
  Api api(deps(broken));
  auto r = api.handle(request("GET", "/api/v1/admin/events", adminAuth()));
  EXPECT_EQ(r.status, 500);
  EXPECT_EQ(r.body.find("/secret"), std::string::npos);
}
