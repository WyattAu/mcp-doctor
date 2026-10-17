//! Domain model for `mcp-doctor`.
//!
//! This crate is deliberately pure: it knows how to describe a finding, how
//! to aggregate findings, and how to render them. It knows nothing about MCP
//! servers, JSONC, or processes — those live behind [`Probe`] in
//! `mcp-doctor-probes`. The split exists so the reporting logic can be tested
//! without spawning anything and so a new probe is one trait impl, not a
//! change to this file.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Severity of a single finding, ordered from best to worst.
///
/// The ordering is load-bearing: [`Report::worst`] and the CLI's exit code
/// both rely on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
///
/// Declaration order *is* the severity ranking (`Pass < Skip < Warn <
/// Fail`), because `Ord` is derived and `Report::worst` takes a `max`. Keep
/// `Skip` below `Warn`: "could not check" is less alarming than "checked and
/// wrong", and both are worse than "healthy".
pub enum Severity {
    /// The thing was checked and is healthy.
    Pass,
    /// Not checkable in this environment (no network, no credential, ...).
    Skip,
    /// Usable, but something a human should know about.
    Warn,
    /// Broken: the agent loses the capability.
    Fail,
}

impl Severity {
    /// Single-character marker used by the text renderer.
    #[must_use]
    pub const fn marker(self) -> char {
        match self {
            Self::Pass => '✓',
            Self::Warn => '!',
            Self::Fail => 'x',
            Self::Skip => '-',
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skip => "skip",
        };
        f.write_str(s)
    }
}

/// One observation about one subject (a server, a file, a credential).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Finding {
    /// Stable probe id, e.g. `backend.present`. Filterable from the CLI.
    pub check: String,
    /// What was inspected: server name, file path, "github-token", ...
    pub subject: String,
    pub severity: Severity,
    /// One line, no trailing period.
    pub summary: String,
    /// Evidence: version string, command output, parse error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// What to do about it. Present whenever severity is `Warn` or `Fail`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Finding {
    /// Construct a finding; `detail` and `remediation` start empty.
    #[must_use]
    pub fn new(
        check: impl Into<String>,
        subject: impl Into<String>,
        severity: Severity,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            check: check.into(),
            subject: subject.into(),
            severity,
            summary: summary.into(),
            detail: None,
            remediation: None,
        }
    }

    /// Attach evidence.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach remediation text.
    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Result of running one external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    /// stdout and stderr joined, stderr last, each trimmed.
    #[must_use]
    pub fn combined(&self) -> String {
        let mut parts: Vec<&str> = [self.stdout.trim(), self.stderr.trim()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        if parts.is_empty() {
            return String::new();
        }
        parts.reverse();
        parts.join(" | ")
    }
}

/// Why a probe could not produce findings at all.
///
/// Distinct from a `Fail` finding: this is the tool being unable to look,
/// which must never be reported as "healthy".
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("config not found at {0}")]
    ConfigMissing(PathBuf),
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("command `{program}` could not be executed: {message}")]
    Spawn { program: String, message: String },
}

/// Everything a probe is allowed to touch.
///
/// Passing a context rather than reading globals is what makes the probes
/// testable: `FakeRunner` in the probes crate answers every command from a
/// fixture without executing anything.
pub struct Ctx {
    /// `OpenCode` config to audit (JSONC, comments included).
    pub config_path: PathBuf,
    /// Expensive probes (process handshakes) run only when true.
    pub deep: bool,
    /// Extra directories searched after `PATH` — `~/.local/bin` on the fleet.
    pub extra_paths: Vec<PathBuf>,
    /// Command execution port. Swappable for tests.
    pub runner: Arc<dyn CommandRunner>,
}

impl Ctx {
    #[must_use]
    pub fn new(config_path: impl Into<PathBuf>, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            config_path: config_path.into(),
            deep: false,
            extra_paths: Vec::new(),
            runner,
        }
    }

    #[must_use]
    pub fn with_deep(mut self, deep: bool) -> Self {
        self.deep = deep;
        self
    }

    #[must_use]
    pub fn with_extra_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.extra_paths = paths;
        self
    }

    /// Directories searched for an executable, most specific first.
    #[must_use]
    pub fn search_paths(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        out.extend(self.extra_paths.iter().cloned());
        if let Some(path) = std::env::var_os("PATH") {
            out.extend(std::env::split_paths(&path));
        }
        out
    }
}

/// The single external side effect a probe may perform.
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`, returning its output.
    ///
    /// # Errors
    /// [`ProbeError::Spawn`] when the program cannot be started at all.
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, ProbeError>;

    /// Resolve `program` to a path using the context's search directories.
    fn which(&self, program: &str, dirs: &[PathBuf]) -> Option<PathBuf>;
}

/// A check. Implementations return findings; they never exit or print.
pub trait Probe: Send + Sync {
    /// Stable, filterable id (`config.parse`, `backend.present`, ...).
    fn id(&self) -> &'static str;

    /// One-line description for `--list-checks`.
    fn description(&self) -> &'static str;

    /// Run the check. `Ok(vec![])` is never returned — a healthy probe
    /// returns at least one `Pass` finding so silence is never ambiguous.
    ///
    /// # Errors
    /// [`ProbeError`] when the probe could not look at all.
    fn run(&self, ctx: &Ctx) -> Result<Vec<Finding>, ProbeError>;
}

/// Ordered set of probes. Order is registration order, so reports are
/// byte-stable across runs — a requirement for diffing CI output.
#[derive(Default)]
pub struct Registry {
    probes: Vec<Box<dyn Probe>>,
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, probe: Box<dyn Probe>) -> &mut Self {
        self.probes.push(probe);
        self
    }

    #[must_use]
    pub fn with(mut self, probe: Box<dyn Probe>) -> Self {
        self.probes.push(probe);
        self
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    /// Borrow the registered probes, in registration order.
    #[must_use]
    pub fn probes(&self) -> &[Box<dyn Probe>] {
        &self.probes
    }

    /// Keep only probes whose id starts with `prefix`; returns how many remain.
    ///
    /// Filtering here rather than in the CLI keeps `--only` and any future
    /// filter share one implementation.
    #[must_use]
    pub fn filter_prefix(&mut self, prefix: &str) -> usize {
        self.probes.retain(|p| p.id().starts_with(prefix));
        self.probes.len()
    }

    /// Run every probe. A probe that errors yields a `Fail` finding against
    /// the probe itself: a check that could not run must never look like a
    /// check that passed (engineering-standards rule 7: gates must be able to
    /// lie).
    #[must_use]
    pub fn run(&self, ctx: &Ctx) -> Report {
        let mut findings = Vec::new();
        for probe in &self.probes {
            match probe.run(ctx) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => findings.push(
                    Finding::new(probe.id(), "probe", Severity::Fail, "check could not run")
                        .with_detail(e.to_string())
                        .with_remediation(
                            "run with --format json for the full error, then fix the cause at its source",
                        ),
                ),
            }
        }
        Report { findings }
    }
}

/// Aggregated findings plus renderers.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    #[must_use]
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Fail)
    }

    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Warn)
    }

    /// Worst severity present, if any.
    #[must_use]
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Stable, colourless, diffable text rendering.
    #[must_use]
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let mut current = String::new();
        for f in &self.findings {
            if f.subject != current {
                current.clone_from(&f.subject);
                let _ = writeln!(out, "\n{current}");
            }
            let _ = writeln!(
                out,
                "  {} {:<28} {}",
                f.severity.marker(),
                f.check,
                f.summary
            );
            if let Some(d) = &f.detail {
                let _ = writeln!(out, "        detail: {d}");
            }
            if let Some(r) = &f.remediation {
                let _ = writeln!(out, "        fix:    {r}");
            }
        }
        out.push('\n');
        let _ = writeln!(
            out,
            "{} pass, {} warn, {} fail, {} skip",
            self.count(Severity::Pass),
            self.count(Severity::Warn),
            self.count(Severity::Fail),
            self.count(Severity::Skip)
        );
        out
    }
}

/// Default location of the `OpenCode` config on this fleet.
#[must_use]
pub fn default_config_path() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from);
    Path::new(&home).join(".config/opencode/opencode.jsonc")
}
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;

    fn sample() -> Report {
        Report {
            findings: vec![
                Finding::new("config.declared", "/cfg", Severity::Pass, "config parses"),
                Finding::new("backend.present", "github", Severity::Pass, "backend runs")
                    .with_detail("Version: 2.0.2"),
                Finding::new(
                    "credential.entitled",
                    "gh-scopes",
                    Severity::Warn,
                    "missing scope",
                )
                .with_remediation("gh auth refresh -s workflow"),
                Finding::new("backend.present", "ghost", Severity::Fail, "not found")
                    .with_remediation("install it"),
            ],
        }
    }

    struct NoopRunner;
    impl CommandRunner for NoopRunner {
        fn run(&self, p: &str, _a: &[&str]) -> Result<CmdOutput, ProbeError> {
            Err(ProbeError::Spawn {
                program: p.into(),
                message: "noop".into(),
            })
        }
        fn which(&self, _p: &str, _d: &[PathBuf]) -> Option<PathBuf> {
            None
        }
    }

    struct AlwaysPass;
    impl Probe for AlwaysPass {
        fn id(&self) -> &'static str {
            "always.pass"
        }
        fn description(&self) -> &'static str {
            "passes"
        }
        fn run(&self, _ctx: &Ctx) -> Result<Vec<Finding>, ProbeError> {
            Ok(vec![Finding::new(self.id(), "s", Severity::Pass, "ok")])
        }
    }

    #[test]
    fn severity_orders_best_to_worst() {
        assert!(Severity::Pass < Severity::Skip);
        assert!(Severity::Skip < Severity::Warn);
        assert!(Severity::Warn < Severity::Fail);
        // A report containing a failure must never report a milder worst-case
        // just because a skip is also present.
        let mixed = Report {
            findings: vec![
                Finding::new("c", "s", Severity::Skip, "unchecked"),
                Finding::new("c", "s", Severity::Fail, "broken"),
            ],
        };
        assert_eq!(mixed.worst(), Some(Severity::Fail));
    }

    #[test]
    fn counts_and_worst_agree() {
        let r = sample();
        assert_eq!(r.count(Severity::Pass), 2);
        assert_eq!(r.count(Severity::Warn), 1);
        assert_eq!(r.count(Severity::Fail), 1);
        assert_eq!(r.count(Severity::Skip), 0);
        assert_eq!(r.worst(), Some(Severity::Fail));
        assert!(r.has_failures());
        assert!(r.has_warnings());
    }

    #[test]
    fn empty_report_has_no_worst_severity() {
        assert_eq!(Report::default().worst(), None);
    }

    #[test]
    fn text_rendering_groups_by_subject_and_includes_evidence() {
        let text = sample().render_text();
        // one header per subject, not one per finding
        assert_eq!(text.matches("\n/cfg\n").count(), 1);
        assert_eq!(text.matches("\ngithub\n").count(), 1);
        assert!(text.contains("detail: Version: 2.0.2"));
        assert!(text.contains("fix:    gh auth refresh -s workflow"));
        assert!(text.contains("2 pass, 1 warn, 1 fail, 0 skip"));
    }

    #[test]
    fn rendering_is_deterministic_for_equal_reports() {
        assert_eq!(sample().render_text(), sample().render_text());
    }

    #[test]
    fn json_omits_absent_optional_fields() {
        let json = serde_json::to_string(&Finding::new("c", "s", Severity::Pass, "ok")).unwrap();
        assert!(!json.contains("detail"));
        assert!(!json.contains("remediation"));
    }

    #[test]
    fn cmd_output_combines_streams_stderr_last() {
        let out = CmdOutput {
            status: 1,
            stdout: "out\n".into(),
            stderr: "err\n".into(),
        };
        assert_eq!(out.combined(), "err | out");
        assert!(!out.ok());
    }

    #[test]
    fn cmd_output_ignores_empty_streams() {
        let out = CmdOutput {
            status: 0,
            stdout: "only".into(),
            stderr: "   ".into(),
        };
        assert_eq!(out.combined(), "only");
    }

    #[test]
    fn search_paths_puts_extra_dirs_first() {
        let ctx = Ctx::new("/cfg", std::sync::Arc::new(NoopRunner)).with_extra_paths(vec![
            PathBuf::from("/extra/one"),
            PathBuf::from("/extra/two"),
        ]);
        let dirs = ctx.search_paths();
        assert_eq!(&dirs[0], Path::new("/extra/one"));
        assert_eq!(&dirs[1], Path::new("/extra/two"));
    }

    #[test]
    fn filter_prefix_keeps_matching_probes_and_reports_the_count() {
        let ctx = Ctx::new("/cfg", std::sync::Arc::new(NoopRunner));
        let mut registry = Registry::new()
            .with(Box::new(AlwaysPass))
            .with(Box::new(AlwaysPass));
        assert_eq!(registry.filter_prefix("always."), 2);
        assert_eq!(registry.filter_prefix("nope."), 0);
        assert!(
            registry.is_empty(),
            "a non-matching prefix removes every probe"
        );
        assert!(
            registry.run(&ctx).findings.is_empty(),
            "an empty registry reports nothing"
        );
    }
}
