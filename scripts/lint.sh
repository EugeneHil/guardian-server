#!/usr/bin/env bash
# Format and static-analysis gate. Exits non-zero on any finding.
# clang-format checks src/ tests/; clang-tidy checks src/ only.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v clang-format >/dev/null 2>&1 || ! command -v run-clang-tidy >/dev/null 2>&1; then
  PATH="$(brew --prefix llvm)/bin:$PATH"
  export PATH
fi

BUILD_DIR="${BUILD_DIR:-build/macos}"
if [ ! -f "$BUILD_DIR/compile_commands.json" ]; then
  cmake --preset macos >/dev/null
fi

status=0

echo "== clang-format =="
find src tests \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0 \
  | xargs -0 clang-format --dry-run -Werror || status=1

echo "== clang-tidy =="
run-clang-tidy -quiet -p "$BUILD_DIR" "^$PWD/src/[^/]*[.]cpp$" || status=1

exit "$status"
