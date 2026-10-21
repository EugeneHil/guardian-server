#!/usr/bin/env bash
# Line-coverage gate (macOS). Builds with preset `coverage`, runs the tests with
# profiling on, merges profiles and fails when line coverage is below MIN_COVERAGE.
# Uses `xcrun llvm-profdata` / `xcrun llvm-cov` (matches Apple clang, which the
# coverage preset compiles with).
set -euo pipefail
cd "$(dirname "$0")/.."

MIN_COVERAGE="${MIN_COVERAGE:-80}"
BUILD_DIR="build/coverage"

cmake --preset coverage
cmake --build --preset coverage

rm -f "$BUILD_DIR"/*.profraw "$BUILD_DIR/coverage.profdata" "$BUILD_DIR/summary.json"
LLVM_PROFILE_FILE="$PWD/$BUILD_DIR/warden-%p.profraw" ctest --preset coverage

xcrun llvm-profdata merge -sparse "$BUILD_DIR"/*.profraw -o "$BUILD_DIR/coverage.profdata"
xcrun llvm-cov export -summary-only \
  -instr-profile="$BUILD_DIR/coverage.profdata" \
  -ignore-filename-regex='(_deps|/external/|/tests/|/src/main\.cpp$)' \
  "$BUILD_DIR/warden_tests" > "$BUILD_DIR/summary.json"

python3 -I -B scripts/coverage_gate.py "$BUILD_DIR/summary.json" --min "$MIN_COVERAGE"
