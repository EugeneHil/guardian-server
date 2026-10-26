#include "config.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <nlohmann/json.hpp>

namespace guardian::server {

namespace {

using nlohmann::json;

constexpr std::size_t kMinPasswordChars = 12;
constexpr int kMaxPort = 65535;

bool isBlank(std::string_view text) {
  return std::all_of(text.begin(), text.end(),
                     [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; });
}

bool ignoredKey(const std::string& key) { return !key.empty() && key.front() == '_'; }

// Reads a string member; reports "<path>: wrong type" otherwise.
void readString(const json& value, const std::string& path, std::string& out,
                std::vector<std::string>& errors) {
  if (value.is_string()) {
    out = value.get<std::string>();
  } else {
    errors.emplace_back(path + ": wrong type");
  }
}

void readTls(const json& value, Config& cfg, std::vector<std::string>& errors) {
  if (!value.is_object()) {
    errors.emplace_back("tls: wrong type");
    return;
  }
  TlsConfig tls;
  for (const auto& [key, member] : value.items()) {
    if (ignoredKey(key)) {
      continue;
    }
    if (key == "certPath") {
      readString(member, "tls.certPath", tls.certPath, errors);
    } else if (key == "keyPath") {
      readString(member, "tls.keyPath", tls.keyPath, errors);
    } else {
      errors.emplace_back("tls." + key + ": unknown key");
    }
  }
  cfg.tls = std::move(tls);
}

void readPort(const json& value, Config& cfg, std::vector<std::string>& errors) {
  if (!value.is_number_integer()) {
    errors.emplace_back("port: wrong type");
    return;
  }
  if (value.is_number_unsigned()) {
    const auto port = value.get<json::number_unsigned_t>();
    cfg.port = port > static_cast<json::number_unsigned_t>(kMaxPort) ? 0 : static_cast<int>(port);
  } else {
    cfg.port = 0;  // negative
  }
}

void applyFile(const json& root, Config& cfg, std::vector<std::string>& errors) {
  for (const auto& [key, value] : root.items()) {
    if (ignoredKey(key)) {
      continue;
    }
    if (key == "host") {
      readString(value, key, cfg.host, errors);
    } else if (key == "port") {
      readPort(value, cfg, errors);
    } else if (key == "tls") {
      readTls(value, cfg, errors);
    } else if (key == "allowInsecureHttp") {
      if (value.is_boolean()) {
        cfg.allowInsecureHttp = value.get<bool>();
      } else {
        errors.emplace_back("allowInsecureHttp: wrong type");
      }
    } else if (key == "dataDir") {
      readString(value, key, cfg.dataDir, errors);
    } else if (key == "webRoot") {
      readString(value, key, cfg.webRoot, errors);
    } else if (key == "adminPassword") {
      readString(value, key, cfg.adminPassword, errors);
    } else {
      errors.emplace_back(key + ": unknown key");
    }
  }
}

bool parsePortText(const std::string& text, int& out) {
  if (text.empty() || text.size() > 5 ||
      !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; })) {
    return false;
  }
  out = std::stoi(text);
  return true;
}

void applyEnv(const EnvLookup& env, Config& cfg) {
  if (const auto v = env("WARDEN_HOST")) {
    cfg.host = *v;
  }
  if (const auto v = env("WARDEN_PORT")) {
    int port = 0;
    cfg.port = parsePortText(*v, port) ? port : 0;
  }
  if (const auto v = env("WARDEN_TLS_CERT")) {
    if (!cfg.tls) {
      cfg.tls = TlsConfig{};
    }
    cfg.tls->certPath = *v;
  }
  if (const auto v = env("WARDEN_TLS_KEY")) {
    if (!cfg.tls) {
      cfg.tls = TlsConfig{};
    }
    cfg.tls->keyPath = *v;
  }
  if (const auto v = env("WARDEN_DATA_DIR")) {
    cfg.dataDir = *v;
  }
  if (const auto v = env("WARDEN_WEB_ROOT")) {
    cfg.webRoot = *v;
  }
  if (const auto v = env("WARDEN_ADMIN_PASSWORD")) {
    cfg.adminPassword = *v;
  }
}

std::size_t countChars(const std::string& text) {
  // UTF-8 code points: skip continuation bytes.
  return static_cast<std::size_t>(std::count_if(text.begin(), text.end(), [](char c) {
    return (static_cast<unsigned char>(c) & 0xC0U) != 0x80U;
  }));
}

bool isLoopbackHost(const std::string& host) {
  return host == "127.0.0.1" || host == "::1" || host == "localhost";
}

void validate(Config& cfg, std::vector<std::string>& errors) {
  if (cfg.port < 1 || cfg.port > kMaxPort) {
    errors.emplace_back("port: must be between 1 and 65535");
  }
  if (countChars(cfg.adminPassword) < kMinPasswordChars) {
    errors.emplace_back("adminPassword: must be at least 12 characters");
  }
  const bool tlsComplete = cfg.tls && !cfg.tls->certPath.empty() && !cfg.tls->keyPath.empty();
  if (cfg.allowInsecureHttp && !isLoopbackHost(cfg.host)) {
    errors.emplace_back("allowInsecureHttp: only allowed with host 127.0.0.1, ::1 or localhost");
  }
  if (!tlsComplete) {
    if (!cfg.allowInsecureHttp) {
      errors.emplace_back(
          "tls: certPath and keyPath are required (or set allowInsecureHttp on a loopback host)");
    }
    cfg.tls.reset();
  }
}

ConfigResult loadUnchecked(std::string_view fileJson, const EnvLookup& env) {
  ConfigResult result;
  Config cfg;
  if (!isBlank(fileJson)) {
    json root;
    try {
      root = json::parse(fileJson.begin(), fileJson.end());
    } catch (const json::exception&) {
      result.errors.emplace_back("$: invalid JSON");
      return result;
    }
    if (!root.is_object()) {
      result.errors.emplace_back("$: invalid JSON");
      return result;
    }
    applyFile(root, cfg, result.errors);
  }
  applyEnv(env, cfg);
  validate(cfg, result.errors);
  if (result.errors.empty()) {
    result.config = std::move(cfg);
  }
  return result;
}

}  // namespace

ConfigResult loadConfig(std::string_view fileJson, const EnvLookup& env) {
  try {
    return loadUnchecked(fileJson, env);
  } catch (const std::exception&) {
    ConfigResult failed;
    failed.errors.emplace_back("$: configuration could not be loaded");
    return failed;
  } catch (...) {
    ConfigResult failed;
    failed.errors.emplace_back("$: configuration could not be loaded");
    return failed;
  }
}

}  // namespace guardian::server
