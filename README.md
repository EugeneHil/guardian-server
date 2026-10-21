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
python3 -I -B -m unittest discover -s scripts   # script tests: coverage gate, design tokens (needs git on PATH), panel static checks
```

## Admin panel

The server serves a dependency-free admin panel (`web/index.html`, `app.js`, `panel.css`, `tokens.css`) from `webRoot` at `/`; the browser's Basic-auth prompt supplies the admin credentials. The panel builds its DOM with `textContent` only and works under the CSP `default-src 'self'`.

`web/tokens.css` is generated from the warden-core design tokens. After updating the submodule, regenerate it and commit the result; CI fails when it is stale:

```sh
python3 -I -B scripts/tokens.py          # regenerate web/tokens.css
python3 -I -B scripts/tokens.py --check  # exit 1 if it is stale
```

## Layout

- `src/` server sources (`main.cpp` is the thin entry point)
- `tests/` GoogleTest unit tests (`*_test.cpp`)
- `external/warden-core` shared rule engine (git submodule)
- `cmake/` warnings and dependency modules
- `web/` admin panel (static files)
- `scripts/` lint, coverage and design-token gates
