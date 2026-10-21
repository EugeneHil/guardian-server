#include "static_files.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "api.hpp"
#include "api_test_support.hpp"
#include "crypto.hpp"

using namespace warden::server;
using namespace warden::server::testing;
namespace fs = std::filesystem;

namespace {
void writeText(const fs::path& path, const std::string& text) {
  fs::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary);
  out << text;
}

std::string header(const HttpResponse& r, const std::string& name) {
  auto it = r.headers.find(name);
  return it == r.headers.end() ? std::string("<absent>") : it->second;
}

std::string adminAuth() {
  return "Basic " + base64Encode(std::string("admin:") + ApiFixture::kAdminPassword);
}
}  // namespace

class Static : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = dir_.path() / "web";
    writeText(root_ / "index.html", "<html>index</html>");
    writeText(root_ / "app.js", "console.log(1);");
    writeText(root_ / "panel.css", "body{}");
    writeText(root_ / "tokens.css", ":root{}");
    writeText(root_ / "agents.json", "not served");
    writeText(dir_.path() / "x", "outside");
  }
  ApiTempDir dir_;
  fs::path root_;
};

TEST_F(Static, ServesOnlyAllowlist) {
  StaticFiles files(root_);
  struct Case {
    const char* url;
    const char* body;
    const char* type;
  };
  const Case cases[] = {{"/", "<html>index</html>", "text/html; charset=utf-8"},
                        {"/app.js", "console.log(1);", "text/javascript; charset=utf-8"},
                        {"/panel.css", "body{}", "text/css; charset=utf-8"},
                        {"/tokens.css", ":root{}", "text/css; charset=utf-8"}};
  for (const auto& c : cases) {
    auto r = files.serve(c.url);
    ASSERT_TRUE(r.has_value()) << c.url;
    EXPECT_EQ(r->status, 200);
    EXPECT_EQ(r->body, c.body);
    EXPECT_EQ(header(*r, "Content-Type"), c.type);
  }
  const std::string localCfg = std::string("/config.") + "local.json";
  for (const std::string& url :
       {std::string("/index.html"), std::string("/data/agents.json"), localCfg,
        std::string("/web/app.js"), std::string("/agents.json"), std::string(""),
        std::string("app.js"), std::string("/APP.JS"), std::string("/app.js/")}) {
    EXPECT_FALSE(files.serve(url).has_value()) << url;
  }
}

TEST_F(Static, TraversalAttemptsAre404) {
  StaticFiles files(root_);
  for (const std::string& url :
       {std::string("/../x"), std::string("/%2e%2e/x"), std::string("//etc/passwd"),
        std::string("/app.js/../../x"), std::string("/app.js%00"), std::string("/app.js\\..\\x"),
        std::string("\\app.js"), std::string("/..\\x"), std::string("/./app.js"),
        std::string("/app.js/."), std::string("/app.js\x01"), std::string("/app.js\0", 8)}) {
    EXPECT_FALSE(files.serve(url).has_value()) << url;
  }
}

TEST_F(Static, HtmlHasSecurityHeaders) {
  StaticFiles files(root_);
  auto html = files.serve("/");
  ASSERT_TRUE(html.has_value());
  EXPECT_EQ(header(*html, "Content-Security-Policy"), "default-src 'self'; frame-ancestors 'none'");
  EXPECT_EQ(header(*html, "Referrer-Policy"), "no-referrer");
  auto js = files.serve("/app.js");
  ASSERT_TRUE(js.has_value());
  EXPECT_EQ(header(*js, "Content-Security-Policy"), "<absent>");
}

TEST_F(Static, MissingFileOnDiskIs404) {
  fs::remove(root_ / "app.js");
  StaticFiles files(root_);
  EXPECT_FALSE(files.serve("/app.js").has_value());
  EXPECT_TRUE(files.serve("/").has_value());
}

TEST_F(Static, DirectoryInPlaceOfFileIs404) {
  fs::remove(root_ / "panel.css");
  fs::create_directories(root_ / "panel.css");
  StaticFiles files(root_);
  EXPECT_FALSE(files.serve("/panel.css").has_value());
}

TEST_F(Static, ReadsFilePerRequest) {
  StaticFiles files(root_);
  EXPECT_EQ(files.serve("/app.js")->body, "console.log(1);");
  writeText(root_ / "app.js", "changed");
  EXPECT_EQ(files.serve("/app.js")->body, "changed");
}

using StaticApi = ApiFixture;

TEST_F(StaticApi, ServedThroughApiBehindAuth) {
  writeText(dir_.path() / "web" / "index.html", "<html>hi</html>");
  auto r = api_.handle(request("GET", "/", adminAuth()));
  ASSERT_EQ(r.status, 200);
  EXPECT_EQ(r.body, "<html>hi</html>");
  EXPECT_EQ(header(r, "Cache-Control"), "no-store");
  EXPECT_EQ(header(r, "X-Content-Type-Options"), "nosniff");
  EXPECT_EQ(header(r, "Referrer-Policy"), "no-referrer");
  auto missing = api_.handle(request("GET", "/app.js", adminAuth()));
  EXPECT_EQ(missing.status, 404);
  EXPECT_EQ(missing.body.find("web"), std::string::npos);
  auto post = api_.handle(request("POST", "/", adminAuth()));
  EXPECT_EQ(post.status, 405);
  EXPECT_EQ(header(post, "Allow"), "GET");
  for (const char* path :
       {"/../x", "/%2e%2e/x", "//etc/passwd", "/app.js/../../x", "/app.js%00", "/index.html"}) {
    EXPECT_EQ(api_.handle(request("GET", path, adminAuth())).status, 404) << path;
  }
}
