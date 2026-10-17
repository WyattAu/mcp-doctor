# mcp-doctor

Audit an [OpenCode](https://opencode.ai) MCP fleet: what the config declares,
whether the backends exist, whether the credentials are *entitled*, and —
with `--deep` — whether the servers actually complete an MCP handshake.

Written after a real failure: the fleet's `github` server pointed at
`api.githubcopilot.com/mcp/`, which silently never authenticated. Nothing in
the stack could say so. `sys-check` checked the binary existed; the failure was
one layer above that, in the spawn wrapper.

## What it checks

| Check | Question | Fails when |
|-------|----------|------------|
| `config.declared` | Does `opencode.jsonc` parse, and does every server declare a command or url? | config missing/unparseable, or a server entry is incomplete |
| `backend.present` | Does each local backend exist and run? | executable not found, or found but cannot be spawned |
| `credential.entitled` | Does the GitHub credential authenticate, and carry `repo`/`workflow`/`read:org`? | token absent, rejected by the API, or missing scopes (warn) |
| `handshake.initialize` | Does the server answer a real `initialize`? (`--deep`) | no `serverInfo` response within 20s |

Design rules that shaped it:

- **A probe that cannot run is a failure, never a pass.** `Registry::run`
  turns a probe error into a `Fail` finding, because "I could not check" and
  "it is fine" must never render the same way.
- **Version strings are evidence, not availability.** `ghidra-mcp` and `r2pm`
  reject `--version` (they print usage and exit non-zero); the first version of
  this tool called both broken. A gate that cries wolf on a healthy fleet gets
  ignored, which is worse than having no gate.
- **Entitlement over presence.** `gh auth token` succeeding proves a string
  exists. `gh api user` proves the token works. Only the second one means the
  agent will see private repositories.
- **No secrets in output.** Token values are never printed; the identity probe
  asks for `--jq .login` so a pasted report does not carry an email address.

## Usage

```sh
mcp-doctor                        # cheap checks against the default config
mcp-doctor --config /path/to/opencode.jsonc
mcp-doctor --deep                 # also spawn servers and handshake (slow)
mcp-doctor --only credential      # filter by check-id prefix
mcp-doctor --format json          # machine-readable
mcp-doctor --list-checks
mcp-doctor --strict               # warnings become failures
```

Exit codes: `0` no failures · `1` at least one failure · `2` usage error.

Text output groups by subject and is byte-stable across runs, so it can be
diffed in CI.

## Architecture

Three crates, one direction of dependency. Nothing in `core` knows about MCP;
nothing in `cli` knows how a check works.

```
crates/
├── mcp-doctor-core/      pure domain: Finding, Severity, Probe trait,
│                         Registry, Report + renderers. No I/O, no MCP.
├── mcp-doctor-probes/    concrete checks, one module per concern:
│                         jsonc · config · backend · credential · handshake
│                         plus `testing` (FakeRunner/CtxBuilder) and `util`
└── mcp-doctor-cli/       clap parsing, wiring, exit codes. No check logic.
```

Why split this way:

- **Testability by injection.** Probes take `Arc<dyn CommandRunner>`; the
  crate ships `FakeRunner` so downstream consumers can test their own probes
  without spawning processes. Every probe is unit-tested without a filesystem.
- **Dependency direction.** `core` cannot grow an accidental dependency on a
  server implementation, because it has no idea servers exist.
- **One source of truth per concern.** All dependency versions live in
  `[workspace.dependencies]`; a bump is one edit and cannot drift between
  crates.

## Adding a check

1. Implement `Probe` in a new module under `mcp-doctor-probes/src/`.
2. Register it in `standard_registry`.
3. Add tests using `crate::testing::CtxBuilder` — no real processes.

If a check needs to change, no file in `mcp-doctor-cli` should have to change
with it. That is the test of whether the layering is real.

## Development

```sh
cargo test              # 52 tests, no network, no subprocesses
cargo clippy --all-targets --all-features
cargo fmt --check
cargo deny check        # supply chain: licenses, bans, advisories, sources
```

CI runs the estate's shared kit (`rust-kit.yml`), pinned by SHA.

## Non-goals

- **Not a supervisor.** It does not start, stop, or restart servers.
- **Not a replacement for `sys-check`.** `sys-check` is the hourly fleet gate;
  this is the deep, per-server diagnostic you run when something is broken.
  Wiring it into a gate should land advisory first (engineering-standards
  rule 3), not straight into the hourly path.
- **Not remote-server probing.** Remote servers are reported as declared;
  probing their HTTP endpoint would need per-server auth handling that does
  not exist yet.

## License

MIT OR Apache-2.0