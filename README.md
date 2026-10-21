# warden-server

Policy server and admin web panel of **Warden**, a lightweight Endpoint DLP. C++17, runs on Windows, uses the shared rule engine from warden-core to validate policies.

Design: [warden-macos/docs/superpowers/specs/2026-10-20-warden-design.md](https://github.com/EugeneHil/warden-macos/blob/develop/docs/superpowers/specs/2026-10-20-warden-design.md)

## Build, test, lint, coverage

Requires CMake 3.25+, Ninja and (on macOS) Homebrew `llvm` and `openssl@3`. Clone with `--recurse-submodules` (or run `git submodule update --init`) to fetch `external/warden-core`.

```sh
cmake --preset macos            # or: windows (needs VCPKG_INSTALLATION_ROOT)
cmake --build --preset macos
ctest --preset macos
scripts/lint.sh                 # clang-format + clang-tidy, warnings are errors
scripts/coverage.sh             # line-coverage gate, MIN_COVERAGE defaults to 80
python3 -I -B -m unittest discover -s scripts   # coverage gate tests
```

## Layout

- `src/` server sources (`main.cpp` is the thin entry point)
- `tests/` GoogleTest unit tests (`*_test.cpp`)
- `external/warden-core` shared rule engine (git submodule)
- `cmake/` warnings and dependency modules
- `scripts/` lint and coverage gates
