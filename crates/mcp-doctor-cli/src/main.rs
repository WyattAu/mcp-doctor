//! `mcp-doctor` — audit an `OpenCode` MCP fleet.
//!
//! The CLI owns argument parsing, wiring, rendering, and exit codes. It
//! contains no check logic of its own; that lives in `mcp-doctor-probes` and
//! the reporting model in `mcp-doctor-core`. If a check ever needs changing,
//! no file in this crate should have to change with it.
//!
//! Exit codes (documented because CI depends on them):
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | no failures (warnings allowed) |
//! | 1    | at least one failure |
//! | 2    | usage error, or the config path could not be read at all |
//!
//! `--strict` promotes warnings to failures for pipelines that want zero
//! noise; the default does not, because a warning is information about the
//! environment, not a broken agent capability.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use mcp_doctor_core::{CmdOutput, CommandRunner, Ctx, ProbeError, Registry, default_config_path};
use mcp_doctor_probes::config;

/// Audit an `OpenCode` MCP fleet: config, backends, credentials, handshakes.
#[derive(Debug, Parser)]
#[command(name = "mcp-doctor", version, about, long_about = None)]
struct Cli {
    /// `OpenCode` config to audit.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Spawn servers and test MCP handshakes (slow; catches cold-start and
    /// credential failures the cheap probes cannot see).
    #[arg(long)]
    deep: bool,

    /// Also search this directory for executables (repeatable). Defaults to
    /// `~/.local/bin`, which is where the ansible role installs binaries and
    /// where a minimal systemd PATH would otherwise miss them.
    #[arg(long, value_name = "DIR")]
    path: Vec<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Treat warnings as failures.
    #[arg(long)]
    strict: bool,

    /// List the checks that would run, then exit.
    #[arg(long)]
    list_checks: bool,

    /// Only run checks whose id starts with this prefix.
    #[arg(long, value_name = "PREFIX")]
    only: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable, colourless, stable across runs.
    Text,
    /// Machine-readable JSON.
    Json,
}

/// Runner that executes real processes.
struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, ProbeError> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| ProbeError::Spawn {
                program: program.to_string(),
                message: e.to_string(),
            })?;
        Ok(CmdOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn which(&self, program: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
        // An absolute or explicitly relative path needs no PATH search.
        if program.contains('/') {
            let direct = PathBuf::from(program);
            return is_executable(&direct).then_some(direct);
        }
        dirs.iter()
            .map(|dir| dir.join(program))
            .find(|candidate| is_executable(candidate))
    }
}

fn is_executable(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config_path = cli.config.clone().unwrap_or_else(default_config_path);
    let servers = Arc::new(config::load(&config_path).unwrap_or_default());

    if cli.list_checks {
        for probe in mcp_doctor_probes::standard_registry(&config_path, servers).probes() {
            println!("{:<22} {}", probe.id(), probe.description());
        }
        return ExitCode::SUCCESS;
    }

    let mut registry = build_registry(&config_path, &servers);
    if let Some(prefix) = &cli.only {
        if registry.filter_prefix(prefix) == 0 {
            eprintln!("no check matches --only {prefix}");
            return ExitCode::from(2);
        }
    }

    let extra_paths = if cli.path.is_empty() {
        vec![home().join(".local/bin")]
    } else {
        cli.path.clone()
    };
    let ctx = Ctx::new(config_path, Arc::new(ProcessRunner))
        .with_deep(cli.deep)
        .with_extra_paths(extra_paths);

    let report = registry.run(&ctx);

    match cli.format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
            );
        }
        Format::Text => print!("{}", report.render_text()),
    }

    let failed = report.has_failures() || (cli.strict && report.has_warnings());
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn build_registry(
    config_path: &std::path::Path,
    servers: &Arc<Vec<mcp_doctor_probes::ServerSpec>>,
) -> Registry {
    mcp_doctor_probes::standard_registry(config_path, Arc::clone(servers))
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn is_executable_rejects_directories_and_missing_files() {
        assert!(!is_executable(std::path::Path::new("/nonexistent/binary")));
        assert!(!is_executable(std::path::Path::new("/tmp")));
    }

    #[test]
    fn default_config_path_is_under_home() {
        let p = default_config_path();
        assert!(p.ends_with("opencode.jsonc"));
        assert!(p.starts_with(home()));
    }
}
