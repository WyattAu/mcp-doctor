//! Deep probe: does the server actually complete an MCP handshake?
//!
//! Only runs under `Ctx::deep`, because it spawns processes. This is the check
//! that catches the failure modes the cheap probes cannot: a backend that
//! exists, has the right version, and still never answers — a cold `bunx`
//! download exceeding the startup timeout, a wrapper whose package name is
//! wrong, a token the server rejects.
//!
//! Protocol: send `initialize` + `notifications/initialized`, then require an
//! `initialize` *response* carrying `serverInfo`. A server that only reads
//! stdin and exits 0 has not passed.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use mcp_doctor_core::{Ctx, Finding, Probe, ProbeError, Severity};

use crate::ServerSpec;

/// How long to wait for the `initialize` response.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Performs real handshakes.
pub struct HandshakeProbe {
    servers: Arc<Vec<ServerSpec>>,
}

impl HandshakeProbe {
    #[must_use]
    pub fn new(servers: Arc<Vec<ServerSpec>>) -> Self {
        Self { servers }
    }
}

impl Probe for HandshakeProbe {
    fn id(&self) -> &'static str {
        "handshake.initialize"
    }

    fn description(&self) -> &'static str {
        "each local server answers an MCP initialize handshake"
    }

    fn run(&self, ctx: &Ctx) -> Result<Vec<Finding>, ProbeError> {
        if !ctx.deep {
            return Ok(vec![
                Finding::new(self.id(), "fleet", Severity::Skip, "deep probe disabled")
                    .with_remediation("run with --deep to spawn servers and test handshakes"),
            ]);
        }

        let mut findings = Vec::new();
        for spec in self.servers.as_slice() {
            let ServerSpec::Local {
                name,
                argv,
                disabled,
            } = spec
            else {
                continue;
            };
            if *disabled || argv.is_empty() {
                continue;
            }

            let Some((program, args)) = argv.split_first() else {
                continue;
            };
            match handshake(program, args, TIMEOUT) {
                Ok(info) => findings.push(
                    Finding::new(self.id(), name.clone(), Severity::Pass, "handshake ok")
                        .with_detail(info),
                ),
                Err(reason) => findings.push(
                    Finding::new(self.id(), name.clone(), Severity::Fail, "handshake failed")
                        .with_detail(reason)
                        .with_remediation(
                            "raise mcp.timeout.startup, or prewarm the package (bun/uv cache)",
                        ),
                ),
            }
        }
        Ok(findings)
    }
}

/// Drive one MCP `initialize` handshake over stdio.
fn handshake(program: &str, args: &[String], timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;

    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;

    let request = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":"#,
        r#"{"protocolVersion":"2024-11-05","capabilities":{},"#,
        r#""clientInfo":{"name":"mcp-doctor","version":"0.1.0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n"
    );
    // Best-effort write. A server that answers before consuming its input
    // (or exits immediately after answering) closes the pipe under us, and
    // treating that as a handshake failure would report a working server as
    // broken. The verdict comes from what the child said, not from whether
    // the request landed; if nothing comes back, the timeout error says so.
    let mut write_note = String::new();
    if let Err(e) = stdin.write_all(request.as_bytes()) {
        write_note = format!("(request not fully written: {e}) ");
    } else if let Err(e) = stdin.flush() {
        write_note = format!("(request not fully flushed: {e}) ");
    }
    // Keep stdin open: closing it makes some servers exit before replying.
    std::mem::forget(stdin);

    // Read one line with a deadline from a thread we can abandon: MCP servers
    // are not required to exit when stdin closes, so killing the child is how
    // the read unblocks.
    let (tx, rx) = mpsc::channel::<String>();
    let handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) > 0 {
            let _ = tx.send(line);
        }
    });

    let line = rx.recv_timeout(timeout).ok();

    let _ = child.kill();
    let _ = child.wait();
    let _ = handle.join();

    match line {
        None => Err(format!(
            "{}no initialize response within {}s",
            write_note,
            timeout.as_secs()
        )),
        Some(line) if line.contains("\"serverInfo\"") => {
            Ok(truncate(&format!("{}{}", write_note, line.trim()), 160))
        }
        Some(line) => Err(format!(
            "responded, but not with serverInfo: {}",
            truncate(line.trim(), 120)
        )),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let flat = s.replace('\n', " ");
    if flat.chars().count() <= max {
        return flat;
    }
    format!("{}...", flat.chars().take(max).collect::<String>())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;
    use crate::testing::CtxBuilder;

    #[test]
    fn shallow_run_skips_rather_than_spawning() {
        let ctx = CtxBuilder::new("x").build();
        let servers = Arc::new(vec![ServerSpec::Local {
            name: "s".into(),
            argv: vec!["definitely-not-a-real-binary".into()],
            disabled: false,
        }]);
        let findings = HandshakeProbe::new(servers).run(&ctx).expect("findings");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Skip);
    }

    #[test]
    fn deep_run_reports_failure_for_a_non_spawning_binary() {
        let ctx = CtxBuilder::new("x").deep(true).build();
        let servers = Arc::new(vec![ServerSpec::Local {
            name: "s".into(),
            argv: vec!["/nonexistent/mcp".into()],
            disabled: false,
        }]);
        let findings = HandshakeProbe::new(servers).run(&ctx).expect("findings");
        assert_eq!(findings[0].severity, Severity::Fail);
        assert!(
            findings[0]
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("spawn failed")
        );
    }

    /// A stand-in for an MCP server, built from `sh`. Real subprocess, real
    /// stdio, canned protocol response: the paths under test are the ones that
    /// fail in production (silent server, wrong-shaped reply, missing binary).
    fn fake_server(script: &str) -> Vec<String> {
        vec!["-c".to_string(), script.to_string()]
    }

    const OK_RESPONSE: &str = concat!(
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","#,
        r#""serverInfo":{"name":"fake","version":"0.0.1"}}}"#,
        "\n"
    );

    #[test]
    fn a_server_that_answers_with_server_info_passes() {
        // Reply first, drain later: the handshake deliberately never closes
        // stdin, so a stand-in that reads stdin before replying would block
        // forever and the test would measure the test, not the code.
        let script = format!("printf '{OK_RESPONSE}'");
        let out = handshake("sh", &fake_server(&script), Duration::from_secs(10));
        assert!(out.is_ok(), "expected a pass, got {out:?}");
        assert!(out.expect("pass").contains("fake"));
    }

    #[test]
    fn a_server_that_exits_without_answering_fails_after_the_timeout() {
        let out = handshake("sh", &fake_server("exit 0"), Duration::from_secs(2));
        let err = out.expect_err("must not pass");
        assert!(err.contains("no initialize response"), "got {err}");
    }

    #[test]
    fn a_server_that_answers_the_wrong_shape_fails() {
        let script = "printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'";
        let out = handshake("sh", &fake_server(script), Duration::from_secs(10));
        let err = out.expect_err("must not pass");
        assert!(err.contains("not with serverInfo"), "got {err}");
    }

    #[test]
    fn a_missing_binary_reports_a_spawn_failure() {
        let err = handshake(
            "/nonexistent/definitely-not-here",
            &[],
            Duration::from_secs(1),
        )
        .expect_err("must not pass");
        assert!(err.contains("spawn failed"), "got {err}");
    }

    #[test]
    fn truncates_without_panicking_on_multibyte() {
        assert_eq!(truncate("a\u{e9}\u{4f60}bc", 3), "a\u{e9}\u{4f60}...");
    }
}
