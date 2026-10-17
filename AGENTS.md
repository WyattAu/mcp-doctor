# AGENTS.md — working in mcp-doctor

This repo implements the estate contract from
[WyattAu/engineering-standards](https://github.com/WyattAu/engineering-standards).
Read that repo's `AGENTS.md` before changing anything structural. The rules
that bite most often here:

1. **Measure, never assume.** The `--version` behaviour of backends was
   *measured* (`ghidra-mcp`, `r2pm` reject it), not guessed. If you change a
   check, run it against this machine's real fleet and record what you saw.
2. **Gates must be able to lie.** A check that cannot run must never look like
   a check that passed. See `Registry::run` and R3/R4 in REQUIREMENTS.md.
3. **One source of truth per concern.** Dependency versions live in
   `[workspace.dependencies]`. Do not add a second `Cargo.toml` version pin.
4. **Layering is enforced by review, not by the compiler.** `core` must stay
   MCP-free and I/O-free; `cli` must stay logic-free. If you find yourself
   adding a check-specific branch to the CLI, the check belongs elsewhere.

## Local gates

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo deny check
```

## Verified behaviour

`mcp-doctor --deep` on this machine: 10 handshakes pass, including r2mcp
1.8.8, Playwright 1.64.0-alpha, the terraform server in docker, and the
github server backed by the `gh` keyring.
