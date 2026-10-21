#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "api.hpp"
#include "config.hpp"

namespace httplib {
class Server;
}

namespace warden::server {

struct ServerOptions {
  std::string host = "127.0.0.1";
  int port = 8443;               // port 0 = pick a free port
  std::optional<TlsConfig> tls;  // none = plain HTTP (loopback only, enforced by Config)
  // One line per request: "<remote> <method> <path> <status>". May be called concurrently from
  // worker threads; the adapter serialises the calls.
  std::function<void(const std::string&)> accessLog;
};

// Thin adapter between cpp-httplib and Api. All routing, auth and validation live in Api.
// Assumption: the stores and services behind Api are internally synchronised, because httplib
// serves requests from a thread pool.
class HttpServer {
 public:
  HttpServer(const Api& api, ServerOptions options);
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;
  ~HttpServer();

  // Binds and serves on a background thread; false on bind/TLS-load failure (never throws).
  bool start();
  // Bound port after a successful start() or run() has bound; 0 before.
  [[nodiscard]] int port() const;
  // Blocking variant for the CLI: returns when stop() is called or on failure.
  void run();
  // Idempotent; releases the listening socket and joins the serving thread.
  void stop();

 private:
  bool bind();
  void logAccess(const std::string& line);

  const Api& api_;
  ServerOptions options_;
  mutable std::mutex mutex_;  // guards server_, thread_, port_
  std::mutex logMutex_;
  std::shared_ptr<httplib::Server> server_;
  std::thread thread_;
  int port_ = 0;
};

}  // namespace warden::server
