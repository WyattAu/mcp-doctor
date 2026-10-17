# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [0.1.0] - 2026-10-17

### Added
- `mcp-doctor-core` — pure domain: `Finding`, `Severity`, `Probe`, `Registry`,
  `Report`. No I/O, no MCP knowledge, deterministic text/JSON rendering.
- `mcp-doctor-probes` — four checks: `config.declared` (JSONC parse and schema
  completeness), `backend.present` (executable resolution and runnability),
  `credential.entitled` (gh token presence, authentication, scopes),
  `handshake.initialize` (real MCP `initialize` under `--deep`).
- `mcp-doctor-cli` — clap front-end; exit codes 0/1/2, `--strict`, `--only`,
  `--list-checks`, `--format json`.
- 52 tests: no network, no subprocesses, no fixtures on disk.

### Notes
- Version strings are recorded as evidence, never as availability: `ghidra-mcp`
  and `r2pm` reject `--version` (usage output, non-zero exit). The first cut of
  this tool reported both as broken; that was a false positive on a healthy
  fleet and is now covered by a regression test.
- A probe that cannot run is reported as a failure, never as a pass.
