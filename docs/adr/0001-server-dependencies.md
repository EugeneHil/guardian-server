# ADR 0001: Server dependencies and build

## Status

Accepted (2026-10-21).

## Context

warden-server is a small HTTPS service (design spec section 4.5) that receives
events and serves policies. It reuses the policy model from warden-core, builds
with CMake on Windows (the VPS) and macOS (development), and must not pull in
more dependencies than it needs.

## Decision

- HTTP: cpp-httplib v0.60.0 (header-only, fetched with FetchContent) with
  OpenSSL 3 for TLS. Boost.Beast and Crow were rejected: Beast brings Boost and
  a large amount of hand-written HTTP glue, and Crow adds a framework and its
  own dependency tree for a handful of routes. Optional zlib/brotli/zstd
  support in cpp-httplib is switched off so builds do not depend on the host.
- JSON and tests: nlohmann/json v3.12.0 and GoogleTest v1.17.0, with the same
  pins and options as warden-core. They are declared before
  `add_subdirectory(external/warden-core)`, so warden-core's declarations are
  ignored and both projects always use one version.
- OpenSSL on Windows comes from a vcpkg manifest (`vcpkg.json`) with a
  `builtin-baseline` commit, so the version is reproducible. The triplet is
  `x64-windows-static-md`: static libraries with the dynamic CRT, which matches
  GoogleTest's shared CRT (`gtest_force_shared_crt`). The VPS therefore needs
  the VC++ redistributable. On macOS OpenSSL comes from Homebrew `openssl@3`.
- warden-core is a git submodule at `external/warden-core`, pinned to a release
  tag.

## Consequences

- Every new dependency still needs its own ADR.
- Bumping warden-core: `git -C external/warden-core fetch --tags && git -C
  external/warden-core checkout vX.Y.Z`, then re-check that its nlohmann/json
  and GoogleTest pins still equal ours (update `cmake/Dependencies.cmake` if
  not), build and test, and commit the new submodule pointer.
- Bumping the vcpkg baseline is a deliberate commit
  (`vcpkg x-update-baseline`) followed by a Windows build and test run.
- Windows deployments need the VC++ redistributable installed.
