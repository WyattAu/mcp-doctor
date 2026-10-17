//! Credential probe: can the credential behind a server *prove* it is
//! entitled to the claims the agent will make with it?
//!
//! Engineering-standards rule 7: a gate must be able to lie. A token that
//! exists is not a token that works — it may be expired, lack scopes, or be
//! unable to see private repositories. This probe therefore never accepts
//! "the file is non-empty" as evidence:
//!
//! 1. `gh auth token` — is there a token at all?
//! 2. `gh api user` — does the token authenticate, and *as whom*?
//! 3. `gh auth status` — which scopes does it carry?
//!
//! Step 2 is the entitlement proof: a token that cannot read the authenticated
//! user cannot read that user's private repos either, and the agent would
//! silently see an empty fleet.

use mcp_doctor_core::{Ctx, Finding, Probe, ProbeError, Severity};

/// Scopes the fleet's MCP usage needs. `workflow` is why we cannot get by with
/// a read-only token: the agent creates branches and pushes.
const REQUIRED_SCOPES: &[&str] = &["repo", "workflow", "read:org"];

/// Proves a GitHub credential is present, authenticating, and scoped.
pub struct CredentialProbe;

impl Probe for CredentialProbe {
    fn id(&self) -> &'static str {
        "credential.entitled"
    }

    fn description(&self) -> &'static str {
        "GitHub credential authenticates and carries the scopes the MCP needs"
    }

    fn run(&self, ctx: &Ctx) -> Result<Vec<Finding>, ProbeError> {
        let mut findings = present(ctx, self.id());
        if findings.iter().any(|f| f.severity == Severity::Fail)
            || findings.iter().any(|f| f.severity == Severity::Skip)
        {
            // No token, or no gh: identity and scopes are meaningless.
            return Ok(findings);
        }

        let identity = identifies(ctx, self.id());
        let identity_failed = identity.iter().any(|f| f.severity == Severity::Fail);
        findings.extend(identity);
        if identity_failed {
            // Scopes cannot be read for a token that does not authenticate.
            return Ok(findings);
        }

        findings.extend(scopes(ctx, self.id()));
        Ok(findings)
    }
}

/// Step 1: is there a token at all?
fn present(ctx: &Ctx, check: &str) -> Vec<Finding> {
    match ctx.runner.run("gh", &["auth", "token"]) {
        Ok(out) if out.ok() && !out.stdout.trim().is_empty() => vec![
            Finding::new(check, "gh-token", Severity::Pass, "token present")
                // never print the token itself
                .with_detail("gh keyring (value withheld)"),
        ],
        Ok(out) => vec![
            Finding::new(check, "gh-token", Severity::Fail, "no gh token available")
                .with_detail(out.combined())
                .with_remediation("run `gh auth login`"),
        ],
        Err(e) => vec![
            Finding::new(
                check,
                "gh-token",
                Severity::Skip,
                "gh not installed; cannot verify GitHub credential",
            )
            .with_detail(e.to_string())
            .with_remediation(
                "install github-cli if the github MCP server is enabled on this host",
            ),
        ],
    }
}

/// Step 2: does the token authenticate, and as whom?
///
/// `--jq .login` keeps the evidence to one field: the full user object carries
/// an email address and a follower list, which has no business in a report that
/// gets pasted into issues.
fn identifies(ctx: &Ctx, check: &str) -> Vec<Finding> {
    match ctx.runner.run("gh", &["api", "user", "--jq", ".login"]) {
        Ok(out) if out.ok() => {
            let login = out.stdout.trim().to_string();
            vec![
                Finding::new(check, "gh-identity", Severity::Pass, "token authenticates")
                    .with_detail(format!("login: {login}")),
            ]
        }
        Ok(out) => vec![
            Finding::new(
                check,
                "gh-identity",
                Severity::Fail,
                "token present but `gh api user` was rejected",
            )
            .with_detail(out.combined())
            .with_remediation("the token is expired or revoked: `gh auth refresh`"),
        ],
        Err(e) => vec![
            Finding::new(
                check,
                "gh-identity",
                Severity::Fail,
                "could not exercise the token against the API",
            )
            .with_detail(e.to_string())
            .with_remediation("an untested credential is an unproven credential; fix gh first"),
        ],
    }
}

/// Step 3: does it carry the scopes the agent needs?
fn scopes(ctx: &Ctx, check: &str) -> Vec<Finding> {
    match ctx.runner.run("gh", &["auth", "status"]) {
        Ok(out) if out.ok() => {
            let text = out.combined();
            let missing: Vec<&str> = REQUIRED_SCOPES
                .iter()
                .copied()
                .filter(|scope| !text.contains(scope))
                .collect();
            if missing.is_empty() {
                vec![
                    Finding::new(
                        check,
                        "gh-scopes",
                        Severity::Pass,
                        "token carries the required scopes",
                    )
                    .with_detail(REQUIRED_SCOPES.join(", ")),
                ]
            } else {
                vec![
                    Finding::new(
                        check,
                        "gh-scopes",
                        Severity::Warn,
                        format!("token missing scope(s): {}", missing.join(", ")),
                    )
                    .with_detail(format!("required: {}", REQUIRED_SCOPES.join(", ")))
                    .with_remediation(format!("gh auth refresh -s {}", missing.join(","))),
                ]
            }
        }
        Ok(out) => vec![
            Finding::new(
                check,
                "gh-scopes",
                Severity::Warn,
                "could not read scope list",
            )
            .with_detail(out.combined())
            .with_remediation("verify scopes manually with `gh auth status`"),
        ],
        Err(e) => vec![
            Finding::new(check, "gh-scopes", Severity::Skip, "scope list unavailable")
                .with_detail(e.to_string()),
        ],
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
    use crate::testing::{CtxBuilder, FakeRunner};

    fn healthy() -> FakeRunner {
        FakeRunner::new()
            .with_ok("gh auth token", "gho_secret")
            .with_ok("gh api user --jq .login", "WyattAu")
            .with_ok(
                "gh auth status",
                "Token scopes: 'gist', 'read:org', 'repo', 'workflow'",
            )
    }

    #[test]
    fn identity_evidence_is_the_login_alone_not_the_user_object() {
        let ctx = CtxBuilder::new("x")
            .runner(
                FakeRunner::new()
                    .with_ok("gh auth token", "t")
                    .with_ok("gh api user --jq .login", "WyattAu")
                    .with_ok("gh auth status", "Token scopes: repo, workflow, read:org"),
            )
            .build();
        let findings = CredentialProbe.run(&ctx).expect("findings");
        let id = findings
            .iter()
            .find(|f| f.subject == "gh-identity")
            .expect("id");
        assert_eq!(id.detail.as_deref(), Some("login: WyattAu"));
    }

    #[test]
    fn healthy_credential_all_passes_and_never_echoes_the_token() {
        let ctx = CtxBuilder::new("x").runner(healthy()).build();
        let findings = CredentialProbe.run(&ctx).expect("findings");
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.severity == Severity::Pass));
        let rendered: String = findings.iter().fold(String::new(), |mut acc, f| {
            use std::fmt::Write as _;
            let _ = writeln!(acc, "{:?} {:?} {:?}", f.summary, f.detail, f.remediation);
            acc
        });
        assert!(
            !rendered.contains("gho_secret"),
            "a token must never reach stdout or a report"
        );
    }

    #[test]
    fn token_that_cannot_authenticate_fails_and_stops_early() {
        let ctx = CtxBuilder::new("x")
            .runner(
                FakeRunner::new()
                    .with_ok("gh auth token", "gho_secret")
                    .with_fail("gh api user --jq .login", 1, "HTTP 401: Bad credentials"),
            )
            .build();
        let findings = CredentialProbe.run(&ctx).expect("findings");
        let id = findings
            .iter()
            .find(|f| f.subject == "gh-identity")
            .expect("identity finding");
        assert_eq!(id.severity, Severity::Fail);
        assert!(
            !findings.iter().any(|f| f.subject == "gh-scopes"),
            "scopes are meaningless once authentication fails"
        );
    }

    #[test]
    fn missing_scopes_warn_with_the_refresh_command() {
        let ctx = CtxBuilder::new("x")
            .runner(
                FakeRunner::new()
                    .with_ok("gh auth token", "t")
                    .with_ok("gh api user --jq .login", "x")
                    .with_ok("gh auth status", "Token scopes: 'gist', 'repo'"),
            )
            .build();
        let findings = CredentialProbe.run(&ctx).expect("findings");
        let scopes = findings
            .iter()
            .find(|f| f.subject == "gh-scopes")
            .expect("scope finding");
        assert_eq!(scopes.severity, Severity::Warn);
        assert_eq!(
            scopes.remediation.as_deref(),
            Some("gh auth refresh -s workflow,read:org")
        );
    }

    #[test]
    fn absent_gh_is_skipped_not_failed() {
        let ctx = CtxBuilder::new("x").build(); // nothing stubbed
        let findings = CredentialProbe.run(&ctx).expect("findings");
        assert_eq!(findings[0].severity, Severity::Skip);
    }

    #[test]
    fn empty_token_output_fails_rather_than_passing() {
        let ctx = CtxBuilder::new("x")
            .runner(FakeRunner::new().with_ok("gh auth token", "   \n"))
            .build();
        let findings = CredentialProbe.run(&ctx).expect("findings");
        assert_eq!(findings[0].severity, Severity::Fail);
    }
}
