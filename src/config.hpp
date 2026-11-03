#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guardian::server {

struct TlsConfig {
  std::string certPath;
  std::string keyPath;
};

struct Config {
  std::string host = "0.0.0.0";
  int port = 8443;
  std::optional<TlsConfig> tls;
  bool allowInsecureHttp = false;
  std::string dataDir = "data";
  std::string webRoot = "web";
  std::string adminPassword;
};

// config has a value if and only if errors is empty. Error messages never contain the password.
struct ConfigResult {
  std::optional<Config> config;
  std::vector<std::string> errors;
};

using EnvLookup = std::function<std::optional<std::string>(std::string_view)>;

// fileJson may be empty (no config file). Environment variables override file values.
// Never throws; every problem is reported in `errors`.
ConfigResult loadConfig(std::string_view fileJson, const EnvLookup& env);

// Hard cut after the rename: the environment variables of the former product name are not read.
// When any of them is set, returns a message naming each one with its replacement (never the
// values); otherwise nullopt. Callers must refuse to start instead of running on defaults.
std::optional<std::string> legacyEnvVarProblem(const EnvLookup& env);

}  // namespace guardian::server
