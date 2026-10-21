#include "http_server.hpp"

#include <httplib.h>
#include <openssl/ssl.h>

#include <cstddef>
#include <exception>
#include <utility>

namespace warden::server {
namespace {

// Socket-level limits. Namespace scope so they are usable from lambdas on every compiler.
constexpr time_t kReadTimeoutSeconds = 10;
constexpr time_t kWriteTimeoutSeconds = 10;
constexpr std::size_t kMaxLoggedPathChars = 200;
constexpr int kMaxPort = 65535;
// Matches every request target, including ones whose decoded form holds CR/LF (ECMAScript
// "." would not match those and httplib would answer with its own 404).
constexpr const char* kCatchAll = R"([\s\S]*)";

// httplib's default is SO_REUSEPORT, which would let another local process bind the same port
// and share (or steal) connections. Allow quick restarts only, never a second live listener.
void exclusiveSocketOptions(socket_t sock) {
#ifdef _WIN32
  httplib::set_socket_opt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
  httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
#endif
}

char lowerAscii(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

// Path of the request target exactly as the client sent it: no query, no fragment and,
// deliberately, no percent-decoding. httplib's own `req.path` is percent-decoded, which would
// let "/%2e%2e/x" or "/%61pp.js" turn into something Api's exact-match routing and static file
// lookup could be fooled by (and "%00" into an embedded NUL). Api therefore sees the encoded
// form, so every escape is just an ordinary (unmatched) character and yields a 404.
std::string rawPath(const std::string& target) {
  const std::size_t end = target.find_first_of("?#");
  return end == std::string::npos ? target : target.substr(0, end);
}

// Query parameters parsed from the target only. httplib's `req.params` would also merge
// urlencoded form bodies into the query, letting a POST body shadow query values.
std::map<std::string, std::string> parseQuery(const std::string& target) {
  std::map<std::string, std::string> query;
  const std::size_t mark = target.find('?');
  if (mark == std::string::npos) {
    return query;
  }
  const std::size_t hash = target.find('#', mark);
  const std::string text =
      target.substr(mark + 1, hash == std::string::npos ? std::string::npos : hash - mark - 1);
  std::size_t pos = 0;
  while (pos <= text.size()) {
    std::size_t amp = text.find('&', pos);
    if (amp == std::string::npos) {
      amp = text.size();
    }
    const std::string pair = text.substr(pos, amp - pos);
    pos = amp + 1;
    if (pair.empty()) {
      continue;
    }
    const std::size_t eq = pair.find('=');
    const std::string key = httplib::decode_query_component(pair.substr(0, eq));
    const std::string value = eq == std::string::npos
                                  ? std::string()
                                  : httplib::decode_query_component(pair.substr(eq + 1));
    if (!key.empty()) {
      query.emplace(key, value);  // first occurrence wins
    }
  }
  return query;
}

// Log-injection guard: control and non-ASCII bytes become '?', output is length-capped.
std::string sanitizeForLog(const std::string& text) {
  std::string out;
  const std::size_t count = text.size() < kMaxLoggedPathChars ? text.size() : kMaxLoggedPathChars;
  out.reserve(count + 3);
  for (std::size_t i = 0; i < count; ++i) {
    const auto c = static_cast<unsigned char>(text[i]);
    out.push_back((c < 0x20 || c >= 0x7f) ? '?' : static_cast<char>(c));
  }
  if (text.size() > count) {
    out += "...";
  }
  return out;
}

HttpRequest toApiRequest(const httplib::Request& req) {
  HttpRequest out;
  out.method = req.method;
  out.path = rawPath(req.target);
  for (const auto& header : req.headers) {
    std::string name = header.first;
    for (char& c : name) {
      c = lowerAscii(c);
    }
    out.headers.emplace(std::move(name), header.second);  // first occurrence wins
  }
  out.query = parseQuery(req.target);
  out.body = req.body;
  out.remoteAddr = req.remote_addr;
  return out;
}

void writeResponse(const HttpResponse& in, httplib::Response& out) {
  out.status = in.status;
  std::string contentType = "application/octet-stream";
  for (const auto& header : in.headers) {
    std::string lower = header.first;
    for (char& c : lower) {
      c = lowerAscii(c);
    }
    if (lower == "content-type") {
      contentType = header.second;
    } else if (lower != "content-length") {  // httplib frames the body itself
      out.set_header(header.first, header.second);
    }
  }
  // Bodiless answers (304) carry no Content-Type either.
  if (!in.body.empty()) {
    out.set_content(in.body, contentType);
  }
}

HttpResponse internalError() { return errorResponse(500, "internal", "Internal server error."); }

// JSON body for statuses httplib produces on its own (malformed request, 413, 414, ...).
const char* codeForStatus(int status) {
  switch (status) {
    case 400:
      return "bad_request";
    case 404:
      return "not_found";
    case 413:
      return "payload_too_large";
    case 414:
      return "uri_too_long";
    default:
      return status >= 500 ? "internal" : "error";
  }
}

const char* messageForStatus(int status) {
  switch (status) {
    case 400:
      return "Bad request.";
    case 404:
      return "Not found.";
    case 413:
      return "Request body too large.";
    case 414:
      return "Request target too long.";
    default:
      return status >= 500 ? "Internal server error." : "Request rejected.";
  }
}

}  // namespace

HttpServer::HttpServer(const Api& api, ServerOptions options)
    : api_(api), options_(std::move(options)) {}

HttpServer::~HttpServer() { stop(); }

void HttpServer::logAccess(const std::string& line) {
  if (!options_.accessLog) {
    return;
  }
  try {
    const std::scoped_lock lock(logMutex_);
    options_.accessLog(line);
  } catch (...) {  // NOLINT(bugprone-empty-catch): a failing log sink must never fail a request
  }
}

// Caller holds mutex_. Creates and configures the server and binds it; listening starts later.
bool HttpServer::bind() {
  if (options_.port < 0 || options_.port > kMaxPort) {
    return false;
  }

  std::shared_ptr<httplib::Server> server;
  if (options_.tls) {
    auto tlsServer = std::make_shared<httplib::SSLServer>(options_.tls->certPath.c_str(),
                                                          options_.tls->keyPath.c_str());
    if (!tlsServer->is_valid()) {
      return false;  // certificate or key could not be loaded
    }
    // httplib already defaults to TLS 1.2; pin it explicitly so a library change cannot
    // silently re-enable older protocols.
    auto* ctx = static_cast<SSL_CTX*>(tlsServer->tls_context());
    if (ctx == nullptr || SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
      return false;
    }
    server = std::move(tlsServer);
  } else {
    server = std::make_shared<httplib::Server>();
  }

  server->set_socket_options(exclusiveSocketOptions);
  server->set_payload_max_length(kMaxBodyBytes);  // socket-level 1 MiB cap, before Api sees a byte
  server->set_read_timeout(kReadTimeoutSeconds);
  server->set_write_timeout(kWriteTimeoutSeconds);

  // Every method and path goes to Api, which produces all routing, auth and 404/405 answers.
  // Handlers run on httplib worker threads; Api::handle is const and the stores behind it are
  // internally synchronised.
  const httplib::Server::Handler forward = [this](const httplib::Request& req,
                                                  httplib::Response& res) {
    try {
      writeResponse(api_.handle(toApiRequest(req)), res);
    } catch (...) {
      writeResponse(internalError(), res);
    }
  };
  server->Get(kCatchAll, forward);  // HEAD is routed here by httplib, then rejected by Api with 405
  server->Post(kCatchAll, forward);
  server->Put(kCatchAll, forward);
  server->Patch(kCatchAll, forward);
  server->Delete(kCatchAll, forward);
  server->Options(kCatchAll, forward);

  server->set_exception_handler(
      [](const httplib::Request&, httplib::Response& res, const std::exception_ptr&) {
        writeResponse(internalError(), res);
      });
  // Responses httplib generates itself (bad request line, oversize body, unknown method, ...)
  // get the same JSON error shape instead of an HTML page. Responses from Api keep their body.
  server->set_error_handler([](const httplib::Request&, httplib::Response& res) {
    if (res.body.empty()) {
      writeResponse(
          errorResponse(res.status, codeForStatus(res.status), messageForStatus(res.status)), res);
      return httplib::Server::HandlerResponse::Handled;
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });
  // Only remote address, method, raw path (no query) and status are ever logged.
  server->set_logger([this](const httplib::Request& req, const httplib::Response& res) {
    logAccess(sanitizeForLog(req.remote_addr) + " " + sanitizeForLog(req.method) + " " +
              sanitizeForLog(rawPath(req.target)) + " " + std::to_string(res.status));
  });

  int boundPort = options_.port;
  if (options_.port == 0) {
    boundPort = server->bind_to_any_port(options_.host);
    if (boundPort < 0) {
      return false;
    }
  } else if (!server->bind_to_port(options_.host, options_.port)) {
    return false;
  }

  server_ = std::move(server);
  port_ = boundPort;
  return true;
}

bool HttpServer::start() {
  std::shared_ptr<httplib::Server> server;
  try {
    const std::scoped_lock lock(mutex_);
    if (stopRequested_ || server_ || !bind()) {
      return false;
    }
    server = server_;
    thread_ = std::thread([server] { server->listen_after_bind(); });
  } catch (...) {
    stop();
    return false;
  }
  server->wait_until_ready();
  if (!server->is_running()) {
    stop();
    return false;
  }
  return true;
}

int HttpServer::port() const {
  const std::scoped_lock lock(mutex_);
  return port_;
}

bool HttpServer::run() {
  std::shared_ptr<httplib::Server> server;
  try {
    const std::scoped_lock lock(mutex_);
    if (stopRequested_) {
      return true;  // stop() arrived before we bound: nothing to serve, clean exit
    }
    if (server_ || !bind()) {
      return false;
    }
    server = server_;
    runActive_ = true;
  } catch (...) {
    stop();
    return false;
  }
  const bool listened = server->listen_after_bind();
  bool stopped = false;
  {
    const std::scoped_lock lock(mutex_);
    stopped = stopRequested_;
    runActive_ = false;
    // Notify while still holding the lock: once it is released, stop() may return and the
    // caller may destroy this object. Nothing of *this is touched after this block.
    runDone_.notify_all();
  }
  return listened || stopped;
}

void HttpServer::stop() {
  std::shared_ptr<httplib::Server> server;
  std::thread thread;
  {
    const std::scoped_lock lock(mutex_);
    stopRequested_ = true;
    server = std::move(server_);
    thread = std::move(thread_);
    server_.reset();
  }
  if (server) {
    server->stop();
  }
  if (thread.joinable()) {
    thread.join();
  }
  // Wait for a concurrent run() to unwind so the caller may destroy the object afterwards.
  std::unique_lock lock(mutex_);
  runDone_.wait(lock, [this] { return !runActive_; });
}

}  // namespace warden::server
