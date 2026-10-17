# Requirements — mcp-doctor

## Problem

An OpenCode MCP fleet fails in ways that no existing check can see. The
observed incident: every `github` MCP tool call failed on every host, because
the server was configured as the remote `api.githubcopilot.com/mcp/` endpoint,
which requires a Copilot entitlement. The binary-level checks passed, the
config parsed, and the agent simply had no capability.

## Requirements

| id | requirement | verification |
|----|-------------|--------------|
| R1 | Report what the config declares, independently of what is installed | `config.declared` probe; unit tests parse JSONC fixtures |
| R2 | Distinguish "not installed" from "installed but broken" | `backend.present` returns Fail for both, with different remediation |
| R3 | A probe that cannot run must never render as healthy | `Registry::run` maps probe errors to `Fail`; test `probe_error_becomes_a_failure_not_a_pass` |
| R4 | Version strings are evidence, not availability | backends rejecting `--version` report Pass with a note; regression test uses a stub that exits non-zero |
| R5 | Credentials must be proven entitled, not merely present | `credential.entitled` runs `gh api user`; a token rejected there fails |
| R6 | No secret may reach stdout, JSON output, or a report | token values never formatted; identity probe requests `--jq .login` |
| R7 | Deep checks must speak real MCP, not guess | `handshake.initialize` requires an `initialize` response containing `serverInfo` |
| R8 | Reports must be deterministic and diffable | sorted server names, registration-ordered probes, byte-stable text renderer; test `rendering_is_deterministic_for_equal_reports` |
| R9 | Check logic must live outside the CLI | adding a check touches `probes` only; the CLI has no branch per check |

## Non-requirements

- Restarting or supervising servers.
- Probing remote servers over HTTP (no auth handling yet).
- Replacing `sys-check` as the hourly fleet gate.

## Constraints

- No `unsafe` (`[workspace.lints.rust] unsafe_code = "forbid"`).
- Unit tests must not require network, subprocesses, or fixtures on disk.
- Dependency versions declared once, in `[workspace.dependencies]`.
