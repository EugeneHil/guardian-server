#pragma once

#include <functional>
#include <iosfwd>
#include <string>
#include <vector>

#include "config.hpp"
#include "timeutil.hpp"

namespace warden::server {

// Optional integration points for `serve`; used by main for signal handling and by tests.
struct ServeHooks {
  // Called once, after the server is built and before it starts serving. `stop` is the server's
  // thread-safe, idempotent stop function and stays valid until runCli returns; it must not be
  // called from a signal handler or from the access log.
  std::function<void(const std::function<void()>& stop)> onReady;
};

// Exit codes: 0 ok, 1 runtime error, 2 usage error. `args` exclude argv[0]. Never throws.
// Error messages never contain the admin password or token values.
int runCli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
           const EnvLookup& env, const NowFn& now);
int runCli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
           const EnvLookup& env, const NowFn& now, const ServeHooks& hooks);

}  // namespace warden::server
