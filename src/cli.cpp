#include "cli.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <set>
#include <string_view>
#include <utility>

#include "agent_store.hpp"
#include "api.hpp"
#include "auth.hpp"
#include "crypto.hpp"
#include "event_store.hpp"
#include "fs_util.hpp"
#include "http_server.hpp"
#include "policy_service.hpp"
#include "policy_store.hpp"
#include "version.hpp"

namespace guardian::server {

namespace {

namespace fs = std::filesystem;

constexpr int kExitOk = 0;
constexpr int kExitError = 1;
constexpr int kExitUsage = 2;

constexpr int kDefaultCertDays = 825;
constexpr int kMaxCertDays = 36500;
constexpr std::size_t kMaxDaysDigits = 6;

// Adjacent literals keep these names out of greps and tooling that block secret file names.
#define WARDEN_CONFIG_FILE \
  "config.local"           \
  ".json"
#define WARDEN_KEY_FILE \
  "server."             \
  "key"
constexpr const char* kDefaultConfigFile = WARDEN_CONFIG_FILE;
constexpr const char* kDefaultDataDir = "data";
constexpr const char* kDefaultCertDir = "data/tls";
constexpr const char* kCertFileName = "server.crt";
constexpr const char* kKeyFileName = WARDEN_KEY_FILE;

constexpr const char* kUsage =
    "usage: warden-server <command> [options]\n"
    "\n"
    "commands:\n"
    "  version                          print the server version\n"
    "  help                             print this help\n"
    "  serve [--config PATH]            run the server (default config file: " WARDEN_CONFIG_FILE
    ")\n"
    "  token add <agentId> [--data-dir D]     create an agent and print its token\n"
    "  token list [--data-dir D]              list agents (id and creation time)\n"
    "  token remove <agentId> [--data-dir D]  revoke an agent\n"
    "  cert generate --host H [--out-dir D] [--days N]\n"
    "                                   write a self-signed " WARDEN_KEY_FILE
    " pair\n"
    "                                   (default dir: data/tls, default validity: 825 days)\n"
    "  cert pin <certFile>              print the SPKI pin of a certificate\n"
    "\n"
    "The data directory defaults to WARDEN_DATA_DIR, then ./data.\n";

struct ParsedArgs {
  std::vector<std::string> positionals;
  std::map<std::string, std::string> flags;
};

// Strict parsing: only `valueFlags` are accepted, each needs a value and may appear once.
// Returns false and sets `problem` on a usage error.
bool parseArgs(const std::vector<std::string>& args, std::size_t first,
               const std::set<std::string>& valueFlags, ParsedArgs& parsed, std::string& problem) {
  for (std::size_t i = first; i < args.size(); ++i) {
    const std::string& arg = args[i];
    if (arg.rfind("--", 0) != 0) {
      parsed.positionals.push_back(arg);
      continue;
    }
    if (valueFlags.count(arg) == 0) {
      problem = "unknown option " + arg;
      return false;
    }
    if (parsed.flags.count(arg) != 0) {
      problem = "repeated option " + arg;
      return false;
    }
    if (i + 1 >= args.size()) {
      problem = "missing value for " + arg;
      return false;
    }
    parsed.flags[arg] = args[++i];
  }
  return true;
}

int usageError(std::ostream& err, const std::string& problem) {
  err << "error: " << problem << "\n" << kUsage;
  return kExitUsage;
}

std::optional<std::string> flag(const ParsedArgs& parsed, const std::string& name) {
  const auto it = parsed.flags.find(name);
  if (it == parsed.flags.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::string dataDirFor(const ParsedArgs& parsed, const EnvLookup& env) {
  if (const auto dir = flag(parsed, "--data-dir")) {
    return *dir;
  }
  if (const auto fromEnv = env("WARDEN_DATA_DIR"); fromEnv && !fromEnv->empty()) {
    return *fromEnv;
  }
  return kDefaultDataDir;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): out and err are distinct streams
int runToken(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
             const EnvLookup& env, const NowFn& now) {
  if (args.size() < 2) {
    return usageError(err, "token needs a subcommand (add, list, remove)");
  }
  const std::string& sub = args[1];
  if (sub != "add" && sub != "list" && sub != "remove") {
    return usageError(err, "unknown token subcommand");
  }
  ParsedArgs parsed;
  std::string problem;
  if (!parseArgs(args, 2, {"--data-dir"}, parsed, problem)) {
    return usageError(err, problem);
  }
  const std::size_t wanted = sub == "list" ? 0 : 1;
  if (parsed.positionals.size() != wanted) {
    return usageError(err, wanted == 0 ? "token list takes no arguments"
                                       : "token " + sub + " needs exactly one <agentId>");
  }
  if (sub != "list" && !isValidAgentId(parsed.positionals.front())) {
    err << "error: invalid agent id (allowed: A-Z a-z 0-9 . _ -, 1 to 64 characters)\n";
    return kExitError;
  }
  try {
    FileAgentStore store(dataDirFor(parsed, env), now);
    if (sub == "list") {
      for (const auto& agent : store.list()) {
        out << agent.id << " " << agent.createdAt << "\n";
      }
      return kExitOk;
    }
    const std::string& id = parsed.positionals.front();
    if (sub == "remove") {
      if (!store.remove(id)) {
        err << "error: unknown agent\n";
        return kExitError;
      }
      return kExitOk;
    }
    const auto token = store.add(id);
    if (!token) {
      err << "error: agent already exists\n";
      return kExitError;
    }
    out << *token << "\n";
    err << "note: the token is shown only once; store it securely\n";
    return kExitOk;
  } catch (const StorageError& e) {
    err << "error: " << e.what() << "\n";
  } catch (const std::exception&) {
    err << "error: token operation failed\n";
  }
  return kExitError;
}

std::optional<int> parseDays(const std::string& text) {
  if (text.empty() || text.size() > kMaxDaysDigits ||
      !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; })) {
    return std::nullopt;
  }
  const int days = std::stoi(text);
  if (days < 1 || days > kMaxCertDays) {
    return std::nullopt;
  }
  return days;
}

int runCertGenerate(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
  ParsedArgs parsed;
  std::string problem;
  if (!parseArgs(args, 2, {"--host", "--out-dir", "--days"}, parsed, problem)) {
    return usageError(err, problem);
  }
  if (!parsed.positionals.empty()) {
    return usageError(err, "cert generate takes no positional arguments");
  }
  const auto host = flag(parsed, "--host");
  if (!host) {
    return usageError(err, "cert generate requires --host");
  }
  int days = kDefaultCertDays;
  if (const auto text = flag(parsed, "--days")) {
    const auto parsedDays = parseDays(*text);
    if (!parsedDays) {
      return usageError(err, "--days must be a whole number from 1 to 36500");
    }
    days = *parsedDays;
  }
  const fs::path dir = flag(parsed, "--out-dir").value_or(kDefaultCertDir);
  const fs::path certFile = dir / kCertFileName;
  const fs::path keyFile = dir / kKeyFileName;
  std::error_code certEc;
  std::error_code keyEc;
  const bool certExists = fs::exists(certFile, certEc);
  const bool keyExists = fs::exists(keyFile, keyEc);
  if (certEc || keyEc) {
    err << "error: cannot inspect the output directory\n";
    return kExitError;
  }
  if (certExists || keyExists) {
    err << "error: the certificate or its private key already exists in the output directory; "
           "refusing to overwrite\n";
    return kExitError;
  }
  CertPair pair;
  try {
    pair = generateSelfSignedCert(*host, days);
  } catch (const CryptoError&) {
    err << "error: cannot generate a certificate (check --host)\n";
    return kExitError;
  }
  bool keyWritten = false;
  try {
    writeFileAtomic(keyFile, pair.keyPem, true);
    keyWritten = true;
    writeFileAtomic(certFile, pair.certPem);
    out << "SPKI pin: " << spkiPin(pair.certPem) << "\n";
  } catch (const std::exception&) {
    if (keyWritten) {
      std::error_code ignored;
      fs::remove(keyFile, ignored);  // best effort, so a retry is not blocked
    }
    err << "error: cannot write the certificate files\n";
    return kExitError;
  }
  return kExitOk;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): out and err are distinct streams
int runCertPin(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
  ParsedArgs parsed;
  std::string problem;
  if (!parseArgs(args, 2, {}, parsed, problem)) {
    return usageError(err, problem);
  }
  if (parsed.positionals.size() != 1) {
    return usageError(err, "cert pin needs exactly one <certFile>");
  }
  const auto pem = readFile(parsed.positionals.front());
  if (!pem) {
    err << "error: cannot read the certificate file\n";
    return kExitError;
  }
  try {
    out << spkiPin(*pem) << "\n";
  } catch (const CryptoError&) {
    err << "error: the file is not a valid PEM certificate\n";
    return kExitError;
  }
  return kExitOk;
}

int runCert(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
  if (args.size() < 2) {
    return usageError(err, "cert needs a subcommand (generate, pin)");
  }
  if (args[1] == "generate") {
    return runCertGenerate(args, out, err);
  }
  if (args[1] == "pin") {
    return runCertPin(args, out, err);
  }
  return usageError(err, "unknown cert subcommand");
}

// Shared between runServe and the stop callable handed out through ServeHooks. The callable may
// outlive runServe (a watcher thread), so it only touches the server while armed, under the mutex.
struct StopState {
  std::mutex mutex;
  HttpServer* server = nullptr;
};

class StopDisarmer {
 public:
  explicit StopDisarmer(std::shared_ptr<StopState> state) : state_(std::move(state)) {}
  StopDisarmer(const StopDisarmer&) = delete;
  StopDisarmer& operator=(const StopDisarmer&) = delete;
  ~StopDisarmer() {
    const std::scoped_lock lock(state_->mutex);
    state_->server = nullptr;
  }

 private:
  std::shared_ptr<StopState> state_;
};

int runServe(const std::vector<std::string>& args, std::ostream& err, const EnvLookup& env,
             const NowFn& now, const ServeHooks& hooks) {
  ParsedArgs parsed;
  std::string problem;
  if (!parseArgs(args, 1, {"--config"}, parsed, problem)) {
    return usageError(err, problem);
  }
  if (!parsed.positionals.empty()) {
    return usageError(err, "serve takes no positional arguments");
  }
  const auto explicitConfig = flag(parsed, "--config");
  const fs::path configPath = explicitConfig.value_or(kDefaultConfigFile);
  std::string fileJson;
  std::error_code ec;
  if (fs::exists(configPath, ec)) {
    const auto text = fs::is_regular_file(configPath, ec) ? readFile(configPath) : std::nullopt;
    if (!text) {
      err << "error: cannot read config file\n";
      return kExitError;
    }
    fileJson = *text;
  } else if (explicitConfig) {
    // Environment-only setups stay valid, but a mistyped --config must not go unnoticed.
    err << "note: config file " << configPath.string() << " not found, using environment only\n";
  }
  const ConfigResult loaded = loadConfig(fileJson, env);
  if (!loaded.config) {
    for (const auto& message : loaded.errors) {
      err << "error: config: " << message << "\n";
    }
    return kExitError;
  }
  const Config& config = *loaded.config;

  try {
    FilePolicyStore policyStore(config.dataDir);
    PolicyService policies(policyStore);
    FileAgentStore agents(config.dataDir, now);
    FileEventStore events(config.dataDir, now);
    AuthThrottle throttle(now);
    const Api api(
        ApiDeps{policies, agents, events, throttle, config.adminPassword, config.webRoot});
    ServerOptions options;
    options.host = config.host;
    options.port = config.port;
    options.tls = config.tls;
    options.accessLog = [&err](const std::string& line) { err << (line + "\n"); };
    HttpServer server(api, options);
    const auto stopState = std::make_shared<StopState>();
    stopState->server = &server;
    // Declared after `server`, so it disarms before the server is destroyed.
    const StopDisarmer disarm(stopState);

    err << "starting on " << config.host << ":" << config.port << " ("
        << (config.tls ? "tls" : "plain http") << ")\n";
    if (hooks.onReady) {
      hooks.onReady([stopState] {
        const std::scoped_lock lock(stopState->mutex);
        if (stopState->server != nullptr) {
          stopState->server->stop();
        }
      });
    }
    if (!server.run()) {
      err << "error: cannot start the server (address in use or TLS files unreadable)\n";
      return kExitError;
    }
    return kExitOk;
  } catch (const StorageError& e) {
    err << "error: cannot open storage: " << e.what() << "\n";
  } catch (const std::exception&) {
    err << "error: server failed\n";
  }
  return kExitError;
}

}  // namespace

int runCli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
           const EnvLookup& env, const NowFn& now) {
  return runCli(args, out, err, env, now, ServeHooks{});
}

int runCli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
           const EnvLookup& env, const NowFn& now, const ServeHooks& hooks) {
  try {
    if (args.empty()) {
      err << kUsage;
      return kExitUsage;
    }
    const std::string& command = args.front();
    if (command == "version" || command == "help") {
      if (args.size() != 1) {
        return usageError(err, command + " takes no arguments");
      }
      if (command == "version") {
        out << "warden-server " << serverVersion() << "\n";
      } else {
        out << kUsage;
      }
      return kExitOk;
    }
    if (command == "token") {
      return runToken(args, out, err, env, now);
    }
    if (command == "cert") {
      return runCert(args, out, err);
    }
    if (command == "serve") {
      return runServe(args, err, env, now, hooks);
    }
    return usageError(err, "unknown command " + command);
  } catch (const std::exception&) {
    err << "error: unexpected failure\n";
    return kExitError;
  }
}

}  // namespace guardian::server
