# ADR 0002: Windows service host (NSSM)

> Formerly Warden.

## Status

Accepted (2026-10-21).

## Context

The server runs unattended on a Windows VPS (design spec section 8). It must
start at boot, restart after a crash and keep its logs bounded. `guardian-server
serve` is an ordinary console program that stops cleanly on SIGINT/SIGTERM and
writes its access log to stderr.

The project keeps platform-specific code out of `src/`: no WinAPI calls, so the
sources stay portable and the macOS development build covers the same code.

## Decision

Run `guardian-server serve` as a Windows service hosted by NSSM (the Non-Sucking
Service Manager), installed and configured by the deployment steps in
`docs/vps-setup.md`.

Rejected:

- A native Windows service: it needs the Service Control Manager entry points
  (`StartServiceCtrlDispatcher`, a control handler, status reporting), which is
  WinAPI code inside `src/` and a Windows-only path that CI on macOS cannot
  exercise.
- `sc.exe` alone: it can register any executable, but a console program does
  not speak the service protocol, so the SCM reports a start timeout and kills
  it; `sc.exe` also has no log capture, rotation or restart throttling.

## Consequences

- NSSM must be installed on the VPS. It is an operational tool, not a
  dependency of this repository: no new build or vcpkg dependency.
- NSSM redirects stdout/stderr to files and rotates them, so log rotation is
  configured in NSSM, not in the server.
- NSSM restarts the process on failure. It must be configured to stop the
  service with a console Ctrl-C (AppStopMethodConsole) so the server's SIGINT
  handler performs a clean shutdown.
- The service should run as a dedicated low-privilege account; the install
  steps set the ACLs on the data directory and the TLS private key.
- If the service model ever needs more (health-based restarts, native event
  log), this decision can be revisited in a new ADR.
