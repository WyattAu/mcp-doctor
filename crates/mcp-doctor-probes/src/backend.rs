//! Backend probe: does each declared local server actually exist here?
//!
//! Distinguishes three failure modes that all look like "MCP broken" to a user
//! but need different fixes:
//!
//! 1. the executable is missing (fix: install it),
//! 2. the executable is a *wrapper* (`bunx`/`uvx`/`npx`/`docker`) whose
//!    package may not be cached yet (fix: prewarm — a cold first launch is the
//!    single most common cause of a startup timeout),
//! 3. the executable exists but refuses to run (fix: read the error).
//!
//! Version strings are recorded as evidence, never parsed for a verdict: a
//! version that cannot be obtained is a `Skip`, not a failure.

use std::sync::Arc;

use mcp_doctor_core::{Ctx, Finding, Probe, ProbeError, Severity};

use crate::ServerSpec;
use crate::util::truncate;

/// Launchers that run a package rather than being the server itself.
const WRAPPERS: &[&str] = &["bunx", "uvx", "npx", "pnpm", "docker", "node"];

/// Reports whether each local backend is installed and runnable.
pub struct BackendProbe {
    servers: Arc<Vec<ServerSpec>>,
}

impl BackendProbe {
    #[must_use]
    pub fn new(servers: Arc<Vec<ServerSpec>>) -> Self {
        Self { servers }
    }
}

impl Default for BackendProbe {
    fn default() -> Self {
        Self::new(Arc::new(Vec::new()))
    }
}

impl Probe for BackendProbe {
    fn id(&self) -> &'static str {
        "backend.present"
    }

    fn description(&self) -> &'static str {
        "each local MCP backend is installed, and wrappers name a package"
    }

    fn run(&self, ctx: &Ctx) -> Result<Vec<Finding>, ProbeError> {
        let mut findings = Vec::new();

        for spec in self.servers.as_slice() {
            let ServerSpec::Local {
                name,
                argv,
                disabled,
            } = spec
            else {
                continue; // remote servers have no local backend
            };

            if *disabled {
                findings.push(Finding::new(
                    self.id(),
                    name.clone(),
                    Severity::Skip,
                    "server disabled in config; backend not required",
                ));
                continue;
            }

            let Some(program) = argv.first() else {
                findings.push(no_command(self.id(), name));
                continue;
            };

            findings.extend(check_backend(ctx, self.id(), name, program, argv));
        }

        if findings.is_empty() {
            findings.push(Finding::new(
                self.id(),
                "fleet",
                Severity::Skip,
                "no local servers declared (remote-only config)",
            ));
        }
        Ok(findings)
    }
}

/// One backend's worth of checks, as zero or more findings.
fn check_backend(
    ctx: &Ctx,
    check: &'static str,
    name: &str,
    program: &str,
    argv: &[String],
) -> Vec<Finding> {
    if ctx.runner.which(program, &ctx.search_paths()).is_none() {
        return vec![
            Finding::new(
                check,
                name.to_string(),
                Severity::Fail,
                format!("executable `{program}` not found on PATH"),
            )
            .with_detail(argv.join(" "))
            .with_remediation(
                "install it, or add its directory to PATH (~/.local/bin is searched automatically)",
            ),
        ];
    }

    if WRAPPERS.contains(&program) {
        let package = wrapper_package(program, &argv[1..]);
        let finding = Finding::new(
            check,
            name.to_string(),
            Severity::Pass,
            format!("`{program}` resolves (package: {package})"),
        );
        return vec![if ctx.deep {
            finding
        } else {
            finding.with_remediation(
                "first launch downloads the package \u{2014} run with --deep to test the spawn",
            )
        }];
    }

    // Version strings are *evidence*, not availability. Plenty of real
    // backends reject `--version` (r2pm and ghidra-mcp print usage and exit
    // non-zero), and reporting those as failures makes the gate cry wolf on a
    // healthy fleet.
    match ctx.runner.run(program, &["--version"]) {
        Ok(out) if out.ok() => vec![
            Finding::new(check, name.to_string(), Severity::Pass, "backend runs")
                .with_detail(truncate(&out.combined(), 120)),
        ],
        Ok(out) => {
            let first = out.combined().lines().next().unwrap_or("").to_string();
            vec![
                Finding::new(
                    check,
                    name.to_string(),
                    Severity::Pass,
                    "executable present",
                )
                .with_detail(format!(
                    "present; `--version` unsupported (exit {}): {}",
                    out.status,
                    truncate(&first, 80)
                )),
            ]
        }
        Err(e) => vec![
            Finding::new(
                check,
                name.to_string(),
                Severity::Fail,
                format!("`{program}` found but could not run"),
            )
            .with_detail(e.to_string())
            .with_remediation("check the executable bit and its dynamic libraries"),
        ],
    }
}

fn no_command(check: &'static str, name: &str) -> Finding {
    Finding::new(
        check,
        name.to_string(),
        Severity::Fail,
        "no command declared",
    )
    .with_remediation("add a \"command\" array to this server entry")
}

/// Name the thing a launcher will actually run.
///
/// `docker run -i --rm image` is not a package called "run": for docker the
/// interesting argument is the image, which is the last non-flag argument
/// that looks like a reference (`owner/name:tag`).
fn wrapper_package(program: &str, args: &[String]) -> String {
    if program == "docker" {
        return args
            .iter()
            .rev()
            .find(|a| a.contains('/') && !a.starts_with('-'))
            .cloned()
            .unwrap_or_else(|| "<image not found in argv>".into());
    }
    args.iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "<none>".into())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;
    use crate::testing::{CtxBuilder, FakeRunner};
    use mcp_doctor_core::Severity;

    fn specs() -> Arc<Vec<ServerSpec>> {
        Arc::new(vec![
            ServerSpec::Local {
                name: "gh".into(),
                argv: vec!["github-mcp-server".into(), "stdio".into()],
                disabled: false,
            },
            ServerSpec::Local {
                name: "fs".into(),
                argv: vec!["bunx".into(), "-y".into(), "@mcp/filesystem".into()],
                disabled: false,
            },
            ServerSpec::Local {
                name: "dead".into(),
                argv: vec!["not-installed".into()],
                disabled: false,
            },
            ServerSpec::Local {
                name: "off".into(),
                argv: vec!["whatever".into()],
                disabled: true,
            },
            ServerSpec::Remote {
                name: "ctx7".into(),
                url: "https://example.test".into(),
            },
        ])
    }

    #[test]
    fn missing_executable_fails_with_a_remediation() {
        let ctx = CtxBuilder::new("x").build(); // runner knows nothing
        let findings = BackendProbe::new(specs()).run(&ctx).expect("findings");
        let dead = findings
            .iter()
            .find(|f| f.subject == "dead")
            .expect("finding for dead");
        assert_eq!(dead.severity, Severity::Fail);
        assert!(dead.remediation.is_some(), "every Fail needs a fix");
    }

    #[test]
    fn wrapper_reports_the_package_without_executing_it() {
        let ctx = CtxBuilder::new("x")
            .runner(FakeRunner::new().with_executable("bunx"))
            .build();
        let findings = BackendProbe::new(specs()).run(&ctx).expect("findings");
        let fs = findings
            .iter()
            .find(|f| f.subject == "fs")
            .expect("finding");
        assert_eq!(fs.severity, Severity::Pass);
        assert!(fs.summary.contains("@mcp/filesystem"));
    }

    #[test]
    fn real_binary_version_is_recorded_as_evidence() {
        let ctx = CtxBuilder::new("x")
            .runner(
                FakeRunner::new()
                    .with_executable("github-mcp-server")
                    .with_ok("github-mcp-server --version", "Version: 2.0.2"),
            )
            .build();
        let findings = BackendProbe::new(specs()).run(&ctx).expect("findings");
        let gh = findings
            .iter()
            .find(|f| f.subject == "gh")
            .expect("finding");
        assert_eq!(gh.severity, Severity::Pass);
        assert_eq!(gh.detail.as_deref(), Some("Version: 2.0.2"));
    }

    #[test]
    fn disabled_server_is_skipped_not_failed() {
        let ctx = CtxBuilder::new("x").build();
        let findings = BackendProbe::new(specs()).run(&ctx).expect("findings");
        let off = findings
            .iter()
            .find(|f| f.subject == "off")
            .expect("finding");
        assert_eq!(off.severity, Severity::Skip);
    }

    #[test]
    fn remote_only_config_reports_skip_not_silence() {
        let ctx = CtxBuilder::new("x").build();
        let findings = BackendProbe::new(Arc::new(vec![ServerSpec::Remote {
            name: "ctx7".into(),
            url: "u".into(),
        }]))
        .run(&ctx)
        .expect("findings");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Skip);
    }
}
