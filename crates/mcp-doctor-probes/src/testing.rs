//! Test doubles.
//!
//! Shipped (not `#[cfg(test)]`) on purpose: a downstream consumer writing a
//! probe needs the same fake the crate's own tests use, and duplicating it in
//! every downstream test suite is how fixtures drift out of sync.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use mcp_doctor_core::{CmdOutput, CommandRunner, Ctx, ProbeError};

/// A runner that answers from a fixture instead of executing anything.
///
/// Keys are `program` plus a space-joined argument tail, longest match wins,
/// so `"gh auth token"` can be stubbed without stubbing every `gh` call.
#[derive(Default)]
pub struct FakeRunner {
    responses: HashMap<String, Result<CmdOutput, String>>,
    executables: Vec<String>,
}

impl FakeRunner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stub `program args...` with a successful result.
    #[must_use]
    pub fn with_ok(mut self, key: &str, stdout: &str) -> Self {
        self.responses.insert(
            key.to_string(),
            Ok(CmdOutput {
                status: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
            }),
        );
        self
    }

    /// Stub `program args...` with a failing result.
    #[must_use]
    pub fn with_fail(mut self, key: &str, status: i32, stderr: &str) -> Self {
        self.responses.insert(
            key.to_string(),
            Ok(CmdOutput {
                status,
                stdout: String::new(),
                stderr: stderr.to_string(),
            }),
        );
        self
    }

    /// Stub `program args...` with a spawn failure.
    #[must_use]
    pub fn with_spawn_error(mut self, key: &str) -> Self {
        self.responses
            .insert(key.to_string(), Err("stubbed spawn failure".into()));
        self
    }

    /// Declare that `program` exists on PATH.
    #[must_use]
    pub fn with_executable(mut self, program: &str) -> Self {
        self.executables.push(program.to_string());
        self
    }

    fn lookup(&self, program: &str, args: &[&str]) -> Option<Result<CmdOutput, String>> {
        let full = format!("{program} {}", args.join(" "));
        let full = full.trim_end().to_string();
        let mut best: Option<(&String, &Result<CmdOutput, String>)> = None;
        for (key, value) in &self.responses {
            let matches = full == *key
                || (full.starts_with(key.as_str())
                    && full.as_bytes().get(key.len()) == Some(&b' '));
            if matches && best.is_none_or(|(k, _)| k.len() < key.len()) {
                best = Some((key, value));
            }
        }
        best.map(|(_, v)| v.clone())
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, ProbeError> {
        match self.lookup(program, args) {
            Some(Ok(out)) => Ok(out),
            Some(Err(message)) => Err(ProbeError::Spawn {
                program: program.to_string(),
                message,
            }),
            None => Err(ProbeError::Spawn {
                program: program.to_string(),
                message: format!("no stub for `{program} {}`", args.join(" ")),
            }),
        }
    }

    fn which(&self, program: &str, _dirs: &[PathBuf]) -> Option<PathBuf> {
        self.executables
            .iter()
            .find(|p| p.as_str() == program)
            .map(|p| PathBuf::from("/usr/bin").join(p))
    }
}

/// Builder for a [`Ctx`] wired to a [`FakeRunner`].
pub struct CtxBuilder {
    config_path: String,
    runner: FakeRunner,
    deep: bool,
    extra_paths: Vec<PathBuf>,
}

impl CtxBuilder {
    /// Start a context for `config_path` with an empty fake runner.
    #[must_use]
    pub fn new(config_path: &str) -> Self {
        Self {
            config_path: config_path.to_string(),
            runner: FakeRunner::new(),
            deep: false,
            extra_paths: vec![PathBuf::from("/home/test/.local/bin")],
        }
    }

    #[must_use]
    pub fn runner(mut self, runner: FakeRunner) -> Self {
        self.runner = runner;
        self
    }

    #[must_use]
    pub fn deep(mut self, deep: bool) -> Self {
        self.deep = deep;
        self
    }

    #[must_use]
    pub fn build(self) -> Ctx {
        let mut ctx = Ctx::new(self.config_path, Arc::new(self.runner)).with_deep(self.deep);
        ctx = ctx.with_extra_paths(self.extra_paths);
        ctx
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;

    #[test]
    fn longest_stub_wins() {
        let runner = FakeRunner::new()
            .with_ok("gh", "general")
            .with_ok("gh auth token", "secret");
        let out = runner.run("gh", &["auth", "token"]).expect("stubbed");
        assert_eq!(out.stdout, "secret");
        assert_eq!(
            runner.run("gh", &["api"]).expect("stubbed").stdout,
            "general"
        );
    }

    #[test]
    fn unstubbed_program_is_a_spawn_error_not_a_pass() {
        let err = FakeRunner::new()
            .run("gh", &["auth", "token"])
            .expect_err("must not succeed silently");
        assert!(err.to_string().contains("no stub"));
    }

    #[test]
    fn which_resolves_only_registered_executables() {
        let runner = FakeRunner::new().with_executable("gh");
        assert!(runner.which("gh", &[]).is_some());
        assert!(runner.which("nope", &[]).is_none());
    }
}
