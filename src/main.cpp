#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "cli.hpp"

namespace {

using guardian::server::EnvLookup;
using guardian::server::ServeHooks;

// Written from the signal handler, so it must be lock-free.
std::atomic<bool> g_stopRequested{false};
static_assert(std::atomic<bool>::is_always_lock_free);

constexpr std::chrono::milliseconds kWatchInterval{100};

extern "C" void onSignal(int /*signal*/) { g_stopRequested.store(true); }

std::optional<std::string> readEnv(std::string_view name) {
  const std::string key(name);
#ifdef _MSC_VER
  char* buffer = nullptr;
  std::size_t size = 0;
  if (_dupenv_s(&buffer, &size, key.c_str()) != 0 || buffer == nullptr) {
    return std::nullopt;
  }
  std::string value(buffer);
  std::free(buffer);
  return value;
#else
  const char* value = std::getenv(key.c_str());
  if (value == nullptr) {
    return std::nullopt;
  }
  return std::string(value);
#endif
}

}  // namespace

int main(int argc, char** argv) try {
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  // Only `serve` handles signals; Ctrl-C keeps its default behaviour for other commands.
  if (!args.empty() && args.front() == "serve") {
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
  }

  // HttpServer::stop() is not async-signal-safe, so a watcher thread turns the flag into a stop.
  std::atomic<bool> finished{false};
  std::thread watcher;
  ServeHooks hooks;
  hooks.onReady = [&watcher, &finished](const std::function<void()>& stop) {
    watcher = std::thread([stop, &finished] {
      while (!finished.load()) {
        if (g_stopRequested.load()) {
          stop();
          return;
        }
        std::this_thread::sleep_for(kWatchInterval);
      }
    });
  };

  const EnvLookup env = readEnv;
  const auto now = [] { return std::chrono::system_clock::now(); };
  const int code = guardian::server::runCli(args, std::cout, std::cerr, env, now, hooks);

  finished.store(true);
  if (watcher.joinable()) {
    watcher.join();
  }
  return code;
} catch (...) {
  std::cerr << "error: unexpected failure\n";
  return 1;
}
