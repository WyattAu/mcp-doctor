//! Concrete probes for an `OpenCode` MCP fleet.
//!
//! One file per concern:
//!
//! - [`jsonc`]      — comment stripping (pure; only `serde_json` downstream)
//! - [`config`]     — what the config *declares*
//! - [`backend`]    — whether each declared backend *exists* on this machine
//! - [`credential`] — whether a credential can *prove* it is entitled
//!   (engineering-standards rule 7: gates must be able to lie)
//! - [`handshake`]  — deep probe: does the server actually speak MCP?
//!
//! The config is parsed once by [`config::load`] and injected as an
//! `Arc<Vec<ServerSpec>>`, so no probe re-reads the file and no two probes
//! can disagree about what was declared. Every probe returns at least one
//! finding: silence is never "healthy".

use std::path::Path;
use std::sync::Arc;

use mcp_doctor_core::Registry;

pub mod backend;
pub mod config;
pub mod credential;
pub mod handshake;
pub mod jsonc;
pub mod testing;
pub mod util;

/// A server as declared by the `OpenCode` config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSpec {
    /// Local stdio server: argv to execute.
    Local {
        name: String,
        argv: Vec<String>,
        disabled: bool,
    },
    /// Remote/HTTP server.
    Remote { name: String, url: String },
}

impl ServerSpec {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Local { name, .. } | Self::Remote { name, .. } => name,
        }
    }

    #[must_use]
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Local { disabled: true, .. })
    }
}

/// The standard probe set: declarations, backends, credentials, and (only
/// under `Ctx::deep`) handshakes.
#[must_use]
pub fn standard_registry(config_path: &Path, servers: Arc<Vec<ServerSpec>>) -> Registry {
    let mut registry = Registry::new();
    registry.register(Box::new(config::ConfigProbe::new(config_path)));
    registry.register(Box::new(backend::BackendProbe::new(Arc::clone(&servers))));
    registry.register(Box::new(credential::CredentialProbe));
    registry.register(Box::new(handshake::HandshakeProbe::new(servers)));
    registry
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;
    use mcp_doctor_core::{CommandRunner, Ctx, Probe, ProbeError, Severity};
    use std::path::PathBuf;

    struct NoopRunner;

    impl CommandRunner for NoopRunner {
        fn run(
            &self,
            program: &str,
            _args: &[&str],
        ) -> Result<mcp_doctor_core::CmdOutput, ProbeError> {
            Err(ProbeError::Spawn {
                program: program.to_string(),
                message: "test runner does not execute".into(),
            })
        }
        fn which(&self, _program: &str, _dirs: &[PathBuf]) -> Option<PathBuf> {
            None
        }
    }

    #[test]
    fn empty_registry_reports_nothing_and_does_not_panic() {
        let ctx = Ctx::new("/nonexistent", Arc::new(NoopRunner));
        let report = Registry::new().run(&ctx);
        assert!(
            report.findings.is_empty(),
            "no probes registered means nothing to report"
        );
        assert!(!report.has_failures());
    }

    #[test]
    fn probe_error_becomes_a_failure_not_a_pass() {
        struct Broken;
        impl Probe for Broken {
            fn id(&self) -> &'static str {
                "broken.probe"
            }
            fn description(&self) -> &'static str {
                "always errors"
            }
            fn run(&self, _ctx: &Ctx) -> Result<Vec<mcp_doctor_core::Finding>, ProbeError> {
                Err(ProbeError::Parse {
                    path: "/nope".into(),
                    message: "boom".into(),
                })
            }
        }
        let ctx = Ctx::new("/nonexistent", Arc::new(NoopRunner));
        let report = Registry::new().with(Box::new(Broken)).run(&ctx);
        assert!(
            report.has_failures(),
            "a probe that cannot run must never look healthy"
        );
        assert_eq!(report.worst(), Some(Severity::Fail));
    }

    #[test]
    fn standard_registry_registers_four_probes() {
        let registry = standard_registry(Path::new("/nope"), Arc::new(vec![]));
        assert_eq!(registry.len(), 4);
    }
}
