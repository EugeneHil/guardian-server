# CLAUDE.md

Warden — lightweight Endpoint DLP for macOS. Design: `warden-macos/docs/superpowers/specs/2026-10-20-warden-design.md`.

## Rules (non-negotiable)

- **TDD:** write the failing test first, watch it fail, then implement. No production code without a test that failed first.
- **Branches:** never commit or push to `main` or `develop`. Work in `feature/WRD-<n>-<slug>`, `fix/…`, `chore/…`, `spike/…`. PRs target `develop`. Releases: PR `develop → main` + tag `vX.Y.Z`.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`, `ci:`, `build:`). Never `--no-verify`, never force push.
- **Secrets:** never read, write or commit `.env*` (except `.env.example`), `*.pem`, `*.key`, `*.p12`, `*.cer`, `config.local.json`. Configuration goes into `*.example*` templates with placeholders.
- **Dependencies:** no new dependency without an ADR in `docs/adr/`.
- **Swift:** Swift Concurrency only (async/await, actors, `AsyncStream`); no GCD, `OperationQueue`, Combine or completion handlers in our code — wrap callback APIs once at the boundary. The only exception is the synchronous Endpoint Security handler (see design §7). No force unwraps, no `try!`.
- **Warnings are errors** in every language.
- **Docs:** English.

## Guard hook

`tooling/claude/guard.py` runs before every Read/Edit/Write/Bash call and enforces the secret and branch rules above. Do not disable it. Tests: `python3 -I -B -m unittest discover -s tooling/claude`.

## Build & test

```sh
cmake --preset macos && cmake --build --preset macos && ctest --preset macos   # windows preset on the VPS
scripts/lint.sh                                  # clang-format + clang-tidy
scripts/coverage.sh                              # line-coverage gate (MIN_COVERAGE, default 80)
python3 -I -B -m unittest discover -s scripts    # script, token, panel and docs checks
python3 -I -B scripts/tokens.py --check          # web/tokens.css is current
```
