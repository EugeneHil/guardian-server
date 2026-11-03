#pragma once

#include <condition_variable>
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

namespace guardian::server {

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
  // Blocking variant for the CLI. Returns false on bind/TLS-load failure, true once serving
  // ended because stop() was called (also when stop() came before run() bound anything).
  bool run();
  // Final: after stop(), or after a start() that failed once it had bound, start()/run() cannot be
  // retried; construct a new HttpServer.
  // Idempotent and final: a stopped server cannot be started again. Releases the listening
  // socket, joins the serving thread and waits for a concurrent run() to unwind. It takes a
  // mutex, so it is NOT async-signal-safe: the CLI must call it from a watcher thread, never
  // from a signal handler, and never from the accessLog callback (deadlock).
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
  bool stopRequested_ = false;
  bool runActive_ = false;
  std::condition_variable runDone_;
};

}  // namespace guardian::server
