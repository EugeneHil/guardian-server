#include "http_server.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "api_test_support.hpp"
#include "crypto.hpp"
#include "fs_util.hpp"

namespace warden::server {
namespace {

using testing::ApiFixture;

constexpr const char* kLoopback = "127.0.0.1";
constexpr time_t kClientTimeoutSeconds = 5;

httplib::Headers authHeader(const std::string& value) {
  return httplib::Headers{{"Authorization", value}};
}

struct LogSink {
  std::mutex mutex;
  std::vector<std::string> lines;

  std::function<void(const std::string&)> callback() {
    return [this](const std::string& line) {
      const std::lock_guard<std::mutex> lock(mutex);
      lines.push_back(line);
    };
  }
  std::vector<std::string> snapshot() {
    const std::lock_guard<std::mutex> lock(mutex);
    return lines;
  }
};

class HttpServerTest : public ApiFixture {
 protected:
  // Writes a fresh self-signed certificate for 127.0.0.1 into the temp dir.
  TlsConfig writeCert(const std::string& name = "server") {
    const CertPair pair = generateSelfSignedCert(kLoopback, 1);
    certPem_ = pair.certPem;
    TlsConfig tls;
    tls.certPath = (dir_.path() / "tls" / (name + "-cert.txt")).string();
    tls.keyPath = (dir_.path() / "tls" / (name + "-private.txt")).string();
    writeFileAtomic(tls.certPath, pair.certPem);
    writeFileAtomic(tls.keyPath, pair.keyPem, true);
    return tls;
  }

  ServerOptions tlsOptions() {
    ServerOptions options;
    options.host = kLoopback;
    options.port = 0;
    options.tls = writeCert();
    options.accessLog = log_.callback();
    return options;
  }

  ServerOptions plainOptions() {
    ServerOptions options;
    options.host = kLoopback;
    options.port = 0;
    options.accessLog = log_.callback();
    return options;
  }

  static std::unique_ptr<httplib::SSLClient> tlsClient(int port) {
    auto client = std::make_unique<httplib::SSLClient>(kLoopback, port);
    client->enable_server_certificate_verification(false);  // tests only: self-signed cert
    client->enable_server_hostname_verification(false);
    client->set_connection_timeout(kClientTimeoutSeconds);
    client->set_read_timeout(kClientTimeoutSeconds);
    client->set_write_timeout(kClientTimeoutSeconds);
    return client;
  }

  static std::unique_ptr<httplib::Client> plainClient(int port) {
    auto client = std::make_unique<httplib::Client>(kLoopback, port);
    client->set_connection_timeout(kClientTimeoutSeconds);
    client->set_read_timeout(kClientTimeoutSeconds);
    client->set_write_timeout(kClientTimeoutSeconds);
    return client;
  }

  std::string certPem_;
  LogSink log_;
};

TEST_F(HttpServerTest, ServesHealthzOverTls) {
  HttpServer server(api_, tlsOptions());
  ASSERT_TRUE(server.start());
  ASSERT_GT(server.port(), 0);
  auto client = tlsClient(server.port());
  const auto result = client->Get("/healthz");
  ASSERT_TRUE(result);
  EXPECT_EQ(result->status, 200);
  EXPECT_EQ(result->get_header_value("Content-Type").rfind("application/json", 0), 0U);
}

TEST_F(HttpServerTest, ServedCertificateMatchesSpkiPin) {
  HttpServer server(api_, tlsOptions());
  ASSERT_TRUE(server.start());
  auto client = tlsClient(server.port());
  std::string seenPem;
  client->set_session_verifier([&seenPem](httplib::tls::session_t session) {
    auto* ssl = static_cast<SSL*>(session);
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (cert != nullptr) {
      BIO* bio = BIO_new(BIO_s_mem());
      if (bio != nullptr) {
        PEM_write_bio_X509(bio, cert);
        char* data = nullptr;
        const long length = BIO_get_mem_data(bio, &data);
        if (data != nullptr && length > 0) {
          seenPem.assign(data, static_cast<std::size_t>(length));
        }
        BIO_free(bio);
      }
      X509_free(cert);
    }
    return httplib::SSLVerifierResponse::CertificateAccepted;
  });
  const auto result = client->Get("/healthz");
  ASSERT_TRUE(result);
  ASSERT_FALSE(seenPem.empty());
  EXPECT_EQ(spkiPin(seenPem), spkiPin(certPem_));
}

TEST_F(HttpServerTest, PlainHttpModeWorksOnLoopback) {
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  const auto result = plainClient(server.port())->Get("/healthz");
  ASSERT_TRUE(result);
  EXPECT_EQ(result->status, 200);
}

TEST_F(HttpServerTest, PlainHttpRequestToTlsPortFailsHandshake) {
  HttpServer server(api_, tlsOptions());
  ASSERT_TRUE(server.start());
  const auto result = plainClient(server.port())->Get("/healthz");
  EXPECT_FALSE(result && result->status == 200);
  // The server must keep serving TLS clients afterwards.
  const auto ok = tlsClient(server.port())->Get("/healthz");
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->status, 200);
}

TEST_F(HttpServerTest, FailsToStartWithMissingCertFile) {
  ServerOptions options = tlsOptions();
  options.tls->certPath = (dir_.path() / "tls" / "missing-cert.txt").string();
  HttpServer server(api_, options);
  EXPECT_FALSE(server.start());
  server.stop();
}

TEST_F(HttpServerTest, FailsToStartWithGarbagePrivateKey) {
  ServerOptions options = tlsOptions();
  writeFileAtomic(options.tls->keyPath, "not a private key");
  HttpServer server(api_, options);
  EXPECT_FALSE(server.start());
}

TEST_F(HttpServerTest, FailsToStartWhenPortIsTaken) {
  HttpServer first(api_, plainOptions());
  ASSERT_TRUE(first.start());
  ServerOptions options = plainOptions();
  options.port = first.port();
  HttpServer second(api_, options);
  EXPECT_FALSE(second.start());
}

TEST_F(HttpServerTest, PolicyEndpointEndToEndWithRealToken) {
  const std::string token = addAgent("agent-1");
  HttpServer server(api_, tlsOptions());
  ASSERT_TRUE(server.start());
  auto client = tlsClient(server.port());

  const auto denied = client->Get("/api/v1/policy");
  ASSERT_TRUE(denied);
  EXPECT_EQ(denied->status, 401);

  const auto ok = client->Get("/api/v1/policy", authHeader("Bearer " + token));
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->status, 200);
  EXPECT_FALSE(ok->get_header_value("ETag").empty());
  EXPECT_FALSE(ok->body.empty());
}

TEST_F(HttpServerTest, NotModifiedHasNoContentTypeOrBody) {
  const std::string token = addAgent("agent-1");
  HttpServer server(api_, tlsOptions());
  ASSERT_TRUE(server.start());
  auto client = tlsClient(server.port());
  const auto first = client->Get("/api/v1/policy", authHeader("Bearer " + token));
  ASSERT_TRUE(first);
  httplib::Headers headers = authHeader("Bearer " + token);
  headers.emplace("If-None-Match", first->get_header_value("ETag"));
  const auto cached = client->Get("/api/v1/policy", headers);
  ASSERT_TRUE(cached);
  EXPECT_EQ(cached->status, 304);
  EXPECT_TRUE(cached->body.empty());
  EXPECT_FALSE(cached->has_header("Content-Type"));
}

TEST_F(HttpServerTest, AccessLogHasNoSecrets) {
  const std::string token = addAgent("agent-2");
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  auto client = plainClient(server.port());
  const std::string basic = "Basic " + base64Encode(std::string("admin:") + kAdminPassword);
  const auto first = client->Get("/api/v1/policy?limit=5", authHeader("Bearer " + token));
  ASSERT_TRUE(first);
  const auto second = client->Get("/api/v1/admin/events?limit=5", authHeader(basic));
  ASSERT_TRUE(second);
  server.stop();

  const auto lines = log_.snapshot();
  ASSERT_EQ(lines.size(), 2U);
  EXPECT_EQ(lines[0], std::string(kLoopback) + " GET /api/v1/policy 200");
  EXPECT_EQ(lines[1],
            std::string(kLoopback) + " GET /api/v1/admin/events " + std::to_string(second->status));
  for (const auto& line : lines) {
    EXPECT_EQ(line.find(token), std::string::npos);
    EXPECT_EQ(line.find(kAdminPassword), std::string::npos);
    EXPECT_EQ(line.find("Bearer"), std::string::npos);
    EXPECT_EQ(line.find("Basic"), std::string::npos);
    EXPECT_EQ(line.find("Authorization"), std::string::npos);
    EXPECT_EQ(line.find("limit"), std::string::npos);
    EXPECT_EQ(line.find('?'), std::string::npos);
  }
}

TEST_F(HttpServerTest, AccessLogSanitizesPath) {
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  auto client = plainClient(server.port());
  ASSERT_TRUE(client->Get("/a%0d%0aFAKE%20200"));
  ASSERT_TRUE(client->Get("/" + std::string(1000, 'x')));
  server.stop();

  const auto lines = log_.snapshot();
  ASSERT_EQ(lines.size(), 2U);
  for (const auto& line : lines) {
    EXPECT_EQ(line.find('\r'), std::string::npos);
    EXPECT_EQ(line.find('\n'), std::string::npos);
  }
  // The raw path is logged: escapes stay escapes, so no control byte can reach the log.
  EXPECT_EQ(lines[0], std::string(kLoopback) + " GET /a%0d%0aFAKE%20200 404");
  EXPECT_LE(lines[1].size(), 200U + 64U);
}

// Adapter text, deliberately different from Api's "Request body is too large.", so a pass proves
// the socket-level payload limit fired before Api ever saw the body.
constexpr const char* kSocketLimitMessage = "Request body too large.";

TEST_F(HttpServerTest, OversizeBodyRejected) {
  const std::string token = addAgent("agent-3");
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  auto client = plainClient(server.port());
  const std::string body(kMaxBodyBytes + 4096, 'a');
  const auto result =
      client->Post("/api/v1/events", authHeader("Bearer " + token), body, "application/json");
  ASSERT_TRUE(result) << "expected a 413 response, got error " << static_cast<int>(result.error());
  EXPECT_EQ(result->status, 413);
  EXPECT_NE(result->body.find(kSocketLimitMessage), std::string::npos) << result->body;
  EXPECT_NE(result->body.find("\"error\""), std::string::npos) << result->body;
  // The server stays healthy.
  const auto health = plainClient(server.port())->Get("/healthz");
  ASSERT_TRUE(health);
  EXPECT_EQ(health->status, 200);
}

TEST_F(HttpServerTest, OversizeChunkedBodyRejected) {
  const std::string token = addAgent("agent-4");
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  auto client = plainClient(server.port());
  const std::string chunk(64 * 1024, 'a');
  const std::size_t total = kMaxBodyBytes + 4 * chunk.size();
  const auto result = client->Post(
      "/api/v1/events", authHeader("Bearer " + token),
      [&chunk, total](std::size_t offset, httplib::DataSink& sink) {
        if (offset >= total) {
          sink.done();
        } else {
          sink.write(chunk.data(), chunk.size());
        }
        return true;
      },
      "application/json");
  ASSERT_TRUE(result) << "expected a 413 response, got error " << static_cast<int>(result.error());
  EXPECT_EQ(result->status, 413);
  EXPECT_NE(result->body.find(kSocketLimitMessage), std::string::npos) << result->body;
  const auto health = plainClient(server.port())->Get("/healthz");
  ASSERT_TRUE(health);
  EXPECT_EQ(health->status, 200);
}

TEST_F(HttpServerTest, StopIsIdempotentAndFreesPort) {
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  const int port = server.port();
  server.stop();
  server.stop();
  EXPECT_FALSE(plainClient(port)->Get("/healthz"));

  ServerOptions options = plainOptions();
  options.port = port;
  HttpServer again(api_, options);
  EXPECT_TRUE(again.start());
}

// Runs HttpServer::run() on a thread; the destructor always stops and joins, so a failing
// ASSERT can never leave a joinable std::thread behind (which would std::terminate).
class RunnerThread {
 public:
  explicit RunnerThread(HttpServer& server)
      : server_(&server), thread_([this, &server] { result_ = server.run(); }) {}
  RunnerThread(const RunnerThread&) = delete;
  RunnerThread& operator=(const RunnerThread&) = delete;
  ~RunnerThread() {
    if (server_ != nullptr) {
      server_->stop();
    }
    join();
  }
  // The caller already stopped and destroyed the server; only the thread is left to join.
  void detachServer() { server_ = nullptr; }
  bool join() {
    if (thread_.joinable()) {
      thread_.join();
    }
    return result_;
  }

 private:
  HttpServer* server_;
  bool result_ = false;
  std::thread thread_;
};

TEST_F(HttpServerTest, RunBlocksUntilStop) {
  HttpServer server(api_, plainOptions());
  RunnerThread runner(server);
  for (int i = 0; i < 5000 && server.port() == 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  ASSERT_GT(server.port(), 0);
  bool served = false;
  for (int i = 0; i < 200 && !served; ++i) {  // listen() may lag the bind by a moment
    const auto result = plainClient(server.port())->Get("/healthz");
    served = result && result->status == 200;
    if (!served) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }
  EXPECT_TRUE(served);
  server.stop();
  EXPECT_TRUE(runner.join());  // clean stop-requested exit
}

// stop() must not return while run() can still touch the object: destroy it right away, many
// times (meaningful under AddressSanitizer / ThreadSanitizer).
TEST_F(HttpServerTest, DestroyingServerRightAfterStopIsSafe) {
  for (int i = 0; i < 200; ++i) {
    auto server = std::make_unique<HttpServer>(api_, plainOptions());
    {
      RunnerThread runner(*server);
      // run() must be inside the object before it is destroyed (calling run() on a dead object
      // is a caller bug); bound port means run() holds the server.
      for (int spin = 0; spin < 20000 && server->port() == 0; ++spin) {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
      }
      server->stop();
      server.reset();  // destroyed immediately; the runner's own stop() is skipped (see below)
      runner.detachServer();
    }
  }
}

TEST_F(HttpServerTest, StopBeforeRunMakesRunReturnPromptly) {
  HttpServer server(api_, plainOptions());
  server.stop();
  const auto begin = std::chrono::steady_clock::now();
  EXPECT_TRUE(server.run());
  EXPECT_LT(std::chrono::steady_clock::now() - begin, std::chrono::seconds(2));
  EXPECT_FALSE(server.start());  // a stopped server stays stopped
}

TEST_F(HttpServerTest, RunReturnsFalseWhenPortIsTaken) {
  HttpServer first(api_, plainOptions());
  ASSERT_TRUE(first.start());
  ServerOptions options = plainOptions();
  options.port = first.port();
  HttpServer second(api_, options);
  EXPECT_FALSE(second.run());
}

TEST_F(HttpServerTest, RunReturnsFalseWithMissingCertFile) {
  ServerOptions options = tlsOptions();
  options.tls->certPath = (dir_.path() / "tls" / "missing-cert.txt").string();
  HttpServer server(api_, options);
  EXPECT_FALSE(server.run());
}

TEST_F(HttpServerTest, StopWithoutStartIsHarmless) {
  HttpServer server(api_, plainOptions());
  server.stop();
  EXPECT_EQ(server.port(), 0);
}

TEST_F(HttpServerTest, Tls10IsRefused) {
  HttpServer server(api_, tlsOptions());
  ASSERT_TRUE(server.start());
  auto client = tlsClient(server.port());
  auto* ctx = static_cast<SSL_CTX*>(client->tls_context());
  ASSERT_NE(ctx, nullptr);
  SSL_CTX_set_security_level(ctx, 0);
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ctx, TLS1_1_VERSION) != 1) {
    GTEST_SKIP() << "local OpenSSL cannot construct a TLS 1.0/1.1 client";
  }
  EXPECT_FALSE(client->Get("/healthz"));
  // A default TLS 1.2+ client still works.
  const auto ok = tlsClient(server.port())->Get("/healthz");
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->status, 200);
}

TEST_F(HttpServerTest, EveryMethodAndPathReachesApi) {
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  auto client = plainClient(server.port());

  const auto missing = client->Get("/nope");
  ASSERT_TRUE(missing);
  EXPECT_EQ(missing->status, 404);
  EXPECT_NE(missing->get_header_value("Content-Type").find("application/json"), std::string::npos);

  const auto wrongMethod = client->Patch("/healthz", "{}", "application/json");
  ASSERT_TRUE(wrongMethod);
  EXPECT_EQ(wrongMethod->status, 405);
  EXPECT_NE(wrongMethod->body.find("\"error\""), std::string::npos) << wrongMethod->body;

  const auto del = client->Delete("/healthz");
  ASSERT_TRUE(del);
  EXPECT_EQ(del->status, 405);

  const auto options = client->Options("/healthz");
  ASSERT_TRUE(options);
  EXPECT_NE(options->get_header_value("Content-Type").find("application/json"), std::string::npos)
      << "OPTIONS must be answered by Api, not by httplib";

  // HEAD is forwarded too; Api only registers GET, so it answers 405 (and httplib sends no body).
  const auto head = client->Head("/healthz");
  ASSERT_TRUE(head);
  EXPECT_EQ(head->status, 405);
  EXPECT_TRUE(head->body.empty());
}

// The adapter hands Api the raw, still percent-encoded path, so encoded dots/letters and
// doubled slashes can never be decoded into something Api would serve.
TEST_F(HttpServerTest, EncodedAndOddPathsDoNotLeakFiles) {
  writeFileAtomic(dir_.path() / "web" / "app.js", "SECRET-JS");
  writeFileAtomic(dir_.path() / "web" / "index.html", "SECRET-HTML");
  addAgent("agent-5");  // creates a real agents file in the data dir
  const auto agentsFile = readFile(dir_.path() / "agents.json");
  ASSERT_TRUE(agentsFile.has_value());
  const std::string traversalToConfig = std::string("/../config.") + "local.json";
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  auto client = plainClient(server.port());

  for (const char* path :
       {"/%61pp.js", "/%2e%2e/x", "/%2E%2E/%2e%2e/etc/passwd", "//etc/passwd", "/api/v1/policy%00",
        "/healthz%2f", "/..%2fapp.js", "/data/agents.json", traversalToConfig.c_str()}) {
    const auto result = client->Get(path);
    ASSERT_TRUE(result) << path;
    EXPECT_EQ(result->status, 404) << path;
    EXPECT_EQ(result->body.find("SECRET"), std::string::npos) << path;
    EXPECT_EQ(result->body.find("root:"), std::string::npos) << path;
    EXPECT_EQ(result->body.find("\"agents\""), std::string::npos) << path;
  }
}

TEST_F(HttpServerTest, QueryStringDoesNotChangeRouting) {
  HttpServer server(api_, plainOptions());
  ASSERT_TRUE(server.start());
  const auto result = plainClient(server.port())->Get("/healthz?x=1#frag");
  ASSERT_TRUE(result);
  EXPECT_EQ(result->status, 200);
}

}  // namespace
}  // namespace warden::server
