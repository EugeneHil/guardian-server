# ADR 0001: Server dependencies and build

> Formerly Warden.

## Status

Accepted (2026-10-21).

## Context

guardian-server is a small HTTPS service (design spec section 4.5) that receives
events and serves policies. It reuses the policy model from guardian-core, builds
with CMake on Windows (the VPS) and macOS (development), and must not pull in
more dependencies than it needs.

## Decision

- HTTP: cpp-httplib v0.60.0 (header-only, fetched with FetchContent) with
  OpenSSL 3 for TLS. Boost.Beast and Crow were rejected: Beast brings Boost and
  a large amount of hand-written HTTP glue, and Crow adds a framework and its
  own dependency tree for a handful of routes. Optional zlib/brotli/zstd
  support in cpp-httplib is switched off so builds do not depend on the host.
- JSON and tests: nlohmann/json v3.12.0 and GoogleTest v1.17.0, with the same
  pins and options as guardian-core. They are declared before
  `add_subdirectory(external/guardian-core)`, so guardian-core's declarations are
  ignored and both projects always use one version.
- OpenSSL on Windows comes from a vcpkg manifest (`vcpkg.json`) with a
  `builtin-baseline` commit, so the version is reproducible. The triplet is
  `x64-windows-static-md`: static libraries with the dynamic CRT, which matches
  GoogleTest's shared CRT (`gtest_force_shared_crt`). The VPS therefore needs
  the VC++ redistributable. On macOS OpenSSL comes from Homebrew `openssl@3`.
- guardian-core is a git submodule at `external/guardian-core`, pinned to a release
  tag. guardian-core's `include(Dependencies)` and `include(Warnings)` resolve to
  this repository's cmake modules because `CMAKE_MODULE_PATH` shadows its own,
  which is why those modules use `include_guard(GLOBAL)`.

## Consequences

- Every new dependency still needs its own ADR.
- Bumping guardian-core: `git -C external/guardian-core fetch --tags && git -C
  external/guardian-core checkout vX.Y.Z`, then re-check that its nlohmann/json
  and GoogleTest pins still equal ours (update `cmake/Dependencies.cmake` if
  not), build and test, and commit the new submodule pointer.
- Bumping the vcpkg baseline is a deliberate commit
  (`vcpkg x-update-baseline`) followed by a Windows build and test run.
- Windows deployments need the VC++ redistributable installed.
