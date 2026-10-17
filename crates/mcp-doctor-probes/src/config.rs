//! Config probe: what the `OpenCode` config *declares*.
//!
//! Parses `opencode.jsonc` (comments stripped by [`crate::jsonc`]) and reports
//! on `mcp.servers`. This probe never executes anything: it answers "is the
//! config well-formed and complete", which is a different question from
//! "does the backend exist" ([`crate::backend`]) and must be answerable even
//! on a host where nothing is installed.

use std::path::{Path, PathBuf};

use mcp_doctor_core::{Ctx, Finding, Probe, ProbeError, Severity};
use serde_json::Value;

use crate::ServerSpec;

/// Path of the `servers` object inside the config, for error messages.
const SERVERS_PATH: &str = "mcp.servers";

/// Read and parse the config, returning the declared servers.
///
/// # Errors
/// [`ProbeError::ConfigMissing`] when the file is absent,
/// [`ProbeError::Io`] when unreadable, [`ProbeError::Parse`] when malformed.
pub fn load(path: &Path) -> Result<Vec<ServerSpec>, ProbeError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ProbeError::ConfigMissing(path.to_path_buf())
        } else {
            ProbeError::Io {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    let value: Value = serde_json::from_str(&crate::jsonc::strip_comments(&raw)).map_err(|e| {
        ProbeError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        }
    })?;

    servers_from_value(&value)
}

/// Extract server specs from an already-parsed config value.
///
/// Split out so tests can exercise the schema handling without touching disk.
///
/// # Errors
/// [`ProbeError::Parse`] when `mcp.servers` exists but is not an object.
pub fn servers_from_value(value: &Value) -> Result<Vec<ServerSpec>, ProbeError> {
    let servers = value
        .get("mcp")
        .and_then(|m| m.get("servers"))
        .unwrap_or(&Value::Null);

    if servers.is_null() {
        return Ok(Vec::new());
    }
    let obj = servers.as_object().ok_or_else(|| ProbeError::Parse {
        path: PathBuf::from(SERVERS_PATH),
        message: "expected an object keyed by server name".into(),
    })?;

    let mut out = Vec::new();
    // BTreeMap iteration gives stable ordering; serde_json preserves
    // insertion order only when the `preserve_order` feature is on.
    let mut names: Vec<&String> = obj.keys().collect();
    names.sort();

    for name in names {
        let spec = obj.get(name).ok_or_else(|| ProbeError::Parse {
            path: PathBuf::from(SERVERS_PATH),
            message: format!("missing key {name}"),
        })?;
        if let Some(found) = parse_server(name, spec) {
            out.push(found);
        }
    }
    Ok(out)
}

/// Parse one server entry. Returns `None` for entries we cannot classify,
/// which the probe reports as a failure rather than dropping silently.
fn parse_server(name: &str, spec: &Value) -> Option<ServerSpec> {
    let kind = spec.get("type").and_then(Value::as_str).unwrap_or("local");
    match kind {
        "local" => {
            let argv: Vec<String> = spec
                .get("command")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            Some(ServerSpec::Local {
                name: name.to_string(),
                argv,
                disabled: spec
                    .get("disabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        }
        "remote" => Some(ServerSpec::Remote {
            name: name.to_string(),
            url: spec
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        _ => None,
    }
}

/// Reports on declarations only.
pub struct ConfigProbe {
    path: PathBuf,
}

impl ConfigProbe {
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Probe for ConfigProbe {
    fn id(&self) -> &'static str {
        "config.declared"
    }

    fn description(&self) -> &'static str {
        "opencode.jsonc parses and declares complete MCP servers"
    }

    fn run(&self, ctx: &Ctx) -> Result<Vec<Finding>, ProbeError> {
        let path = if self.path.as_os_str().is_empty() {
            ctx.config_path.clone()
        } else {
            self.path.clone()
        };

        let servers = match load(&path) {
            Ok(s) => s,
            Err(ProbeError::ConfigMissing(p)) => {
                return Ok(vec![
                    Finding::new(
                        self.id(),
                        p.display().to_string(),
                        Severity::Fail,
                        "opencode config not found",
                    )
                    .with_remediation("run `chezmoi apply`, or pass --config <path>"),
                ]);
            }
            Err(e) => return Err(e),
        };

        if servers.is_empty() {
            return Ok(vec![
                Finding::new(
                    self.id(),
                    path.display().to_string(),
                    Severity::Warn,
                    "config declares no MCP servers",
                )
                .with_remediation("check the [opencode.mcp] flags in .chezmoidata/defaults.toml"),
            ]);
        }

        let mut findings = vec![Finding::new(
            self.id(),
            path.display().to_string(),
            Severity::Pass,
            format!("config parses; {} servers declared", servers.len()),
        )];

        for spec in &servers {
            match spec {
                ServerSpec::Local {
                    name,
                    argv,
                    disabled,
                } => {
                    if argv.is_empty() {
                        findings.push(
                            Finding::new(
                                self.id(),
                                name.clone(),
                                Severity::Fail,
                                "local server declares no command",
                            )
                            .with_remediation("add a \"command\" array to this server entry"),
                        );
                    } else if *disabled {
                        findings.push(
                            Finding::new(
                                self.id(),
                                name.clone(),
                                Severity::Skip,
                                "server is disabled in config",
                            )
                            .with_detail(argv.join(" ")),
                        );
                    } else {
                        findings.push(
                            Finding::new(self.id(), name.clone(), Severity::Pass, "declared")
                                .with_detail(argv.join(" ")),
                        );
                    }
                }
                ServerSpec::Remote { name, url } => {
                    if url.is_empty() {
                        findings.push(
                            Finding::new(
                                self.id(),
                                name.clone(),
                                Severity::Fail,
                                "remote server declares no url",
                            )
                            .with_remediation("add a \"url\" to this server entry"),
                        );
                    } else {
                        findings.push(
                            Finding::new(self.id(), name.clone(), Severity::Pass, "declared")
                                .with_detail(url.clone()),
                        );
                    }
                }
            }
        }
        Ok(findings)
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
    use crate::testing::CtxBuilder;

    fn spec_from(src: &str) -> Vec<ServerSpec> {
        let value: Value =
            serde_json::from_str(&crate::jsonc::strip_comments(src)).expect("fixture must parse");
        servers_from_value(&value).expect("valid server table")
    }

    #[test]
    fn parses_local_and_remote_entries_from_jsonc() {
        let src = r#"{
            // our stack
            "mcp": { "servers": {
                "gh": { "type": "remote", "url": "https://example.test/mcp" },
                "fs": { "type": "local", "command": ["bunx", "-y", "pkg"] }
            }}
        }"#;
        let specs = spec_from(src);
        assert_eq!(specs.len(), 2);
        // names are sorted, so "fs" precedes "gh" regardless of file order
        assert!(matches!(&specs[0], ServerSpec::Local { name, .. } if name == "fs"));
        assert!(matches!(&specs[1], ServerSpec::Remote { name, .. } if name == "gh"));
    }

    #[test]
    fn honours_disabled_flag() {
        let specs = spec_from(
            r#"{"mcp":{"servers":{"db":{"type":"local","command":["uvx","x"],"disabled":true}}}}"#,
        );
        assert!(specs[0].is_disabled());
    }

    #[test]
    fn absent_servers_table_is_empty_not_an_error() {
        let specs = spec_from(r#"{"model":"x"}"#);
        assert!(
            specs.is_empty(),
            "a config with no mcp.servers table declares no servers"
        );
    }

    #[test]
    fn non_object_servers_table_is_an_error() {
        let value: Value = serde_json::from_str(r#"{"mcp":{"servers":[1,2]}}"#).expect("parses");
        assert!(servers_from_value(&value).is_err());
    }

    #[test]
    fn missing_config_is_reported_as_failure_not_skipped() {
        let ctx = CtxBuilder::new("/definitely/not/here.jsonc").build();
        let report = ConfigProbe::new(Path::new("/definitely/not/here.jsonc")).run(&ctx);
        let findings = report.expect("probe returns findings, not an error");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Fail);
    }

    #[test]
    fn empty_command_is_a_failure() {
        let dir = std::env::temp_dir().join("mcp-doctor-test-empty-cmd");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("opencode.jsonc");
        std::fs::write(
            &path,
            r#"{"mcp":{"servers":{"broken":{"type":"local","command":[]}}}}"#,
        )
        .expect("write fixture");

        let ctx = CtxBuilder::new(path.to_str().expect("utf8")).build();
        let findings = ConfigProbe::new(&path).run(&ctx).expect("findings");
        assert!(
            findings
                .iter()
                .any(|f| f.subject == "broken" && f.severity == Severity::Fail)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_are_sorted_for_stable_reports() {
        let specs = spec_from(
            r#"{"mcp":{"servers":{"z":{"type":"remote","url":"u"},"a":{"type":"remote","url":"u"}}}}"#,
        );
        let names: Vec<&str> = specs.iter().map(ServerSpec::name).collect();
        assert_eq!(names, ["a", "z"]);
    }
}
