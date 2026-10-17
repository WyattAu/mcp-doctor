//! Integration tests for the `mcp-doctor` binary.
//!
//! These test the *contract* a pipeline depends on — exit codes, filter
//! behaviour, output shape — by running the real binary. Unit tests elsewhere
//! cover probe internals; nothing else covers `main`.

// Integration tests assert on real process output; panicking with a readable
// message is the intended failure mode here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::assertions_on_constants)]

use std::path::Path;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mcp-doctor"))
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("mcp-doctor-cli-{name}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn write_config(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("opencode.jsonc");
    std::fs::write(&path, body).expect("write config");
    path
}

#[test]
fn list_checks_documents_every_probe_and_exits_zero() {
    let out = bin().arg("--list-checks").output().expect("run binary");
    assert!(out.status.success(), "--list-checks must always succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    for id in [
        "config.declared",
        "backend.present",
        "credential.entitled",
        "handshake.initialize",
    ] {
        assert!(text.contains(id), "missing check id {id} in:\n{text}");
    }
}

#[test]
fn missing_config_fails_with_a_remediation_and_exit_one() {
    let out = bin()
        .args(["--config", "/nonexistent/opencode.jsonc"])
        .output()
        .expect("run binary");
    assert_eq!(out.status.code(), Some(1), "a missing config is a failure");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("not found"),
        "expected a clear message:\n{text}"
    );
    assert!(
        text.contains("chezmoi apply"),
        "a failure must carry a fix:\n{text}"
    );
}

#[test]
fn empty_config_warns_but_exits_zero() {
    let dir = tmp("empty");
    let path = write_config(&dir, r#"{"model":"some/model"}"#);
    let out = bin()
        .args(["--config", path.to_str().expect("utf8")])
        .output()
        .expect("run binary");
    assert_eq!(out.status.code(), Some(0), "a warning is not a failure");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("no MCP servers"),
        "unexpected output:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strict_turns_warnings_into_a_nonzero_exit() {
    let dir = tmp("strict");
    let path = write_config(&dir, r#"{"model":"some/model"}"#);
    let out = bin()
        .args(["--config", path.to_str().expect("utf8"), "--strict"])
        .output()
        .expect("run binary");
    assert_eq!(
        out.status.code(),
        Some(1),
        "--strict must promote the warning to a failure"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_output_is_machine_readable() {
    let dir = tmp("json");
    let path = write_config(
        &dir,
        r#"{"mcp":{"servers":{"ctx7":{"type":"remote","url":"https://example.test"}}}}"#,
    );
    let out = bin()
        .args(["--config", path.to_str().expect("utf8"), "--format", "json"])
        .output()
        .expect("run binary");
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    let findings = value["findings"].as_array().expect("findings array");
    assert!(findings.iter().any(|_| true), "expected at least one finding");
    assert!(findings.iter().all(|f| f["check"].is_string()));
    // optional fields must be omitted, never null, so consumers can rely on
    // their absence
    assert!(
        findings
            .iter()
            .all(|f| f.get("detail").is_none_or(|d| !d.is_null()))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn only_filter_rejects_an_unknown_prefix_with_exit_two() {
    let out = bin()
        .args(["--only", "no.such.check"])
        .output()
        .expect("run binary");
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown prefix is a usage error"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("no check matches"),
        "unexpected stderr:\n{text}"
    );
}

#[test]
fn only_filter_restricts_the_report_to_matching_checks() {
    let dir = tmp("only");
    let path = write_config(
        &dir,
        r#"{"mcp":{"servers":{"ctx7":{"type":"remote","url":"https://example.test"}}}}"#,
    );
    let out = bin()
        .args([
            "--config",
            path.to_str().expect("utf8"),
            "--only",
            "config.",
            "--format",
            "json",
        ])
        .output()
        .expect("run binary");
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    let findings = value["findings"].as_array().expect("findings array");
    assert!(findings.iter().any(|_| true), "expected at least one finding");
    assert!(
        findings
            .iter()
            .all(|f| f["check"].as_str().expect("check").starts_with("config.")),
        "filter leaked other checks"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_ends_with_a_count_summary() {
    let dir = tmp("summary");
    let path = write_config(&dir, r#"{"model":"some/model"}"#);
    let out = bin()
        .args(["--config", path.to_str().expect("utf8")])
        .output()
        .expect("run binary");
    let text = String::from_utf8_lossy(&out.stdout);
    // The summary is the last line and always ends with the skip count; the
    // default run emits skips (remote-only config, deep probe disabled), so
    // pinning an exact string here would test the fleet, not the format.
    let last = text.trim_end().lines().next_back().expect("some output");
    assert!(
        last.contains("pass,") && last.ends_with("skip"),
        "last line must be the count summary, got {last:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
