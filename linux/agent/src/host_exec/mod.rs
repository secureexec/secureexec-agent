//! Read-only "live response" host commands the AI investigation/chat agent
//! can run on a Linux endpoint during a case investigation. Each tool is
//! built on a real binary (`ls`, `cat`/`head`/`tail`, `grep`, `find`, `ps`,
//! `journalctl`, `lsof`, `ss`, `stat`, `sha256sum`+`file`, `lsmod`, `last`/
//! `lastlog`/`who`, `ip`) invoked via `argv` — **never** through a shell.
//!
//! See `agent/linux/agent/src/host_exec/validate.rs` for path/pattern checks
//! and `limits.rs` for runtime/output caps.
//!
//! Dispatch is driven by [`run`], which `LinuxCommandHandler` calls when it
//! sees one of the `host_*` `command_type` strings.

mod limits;
mod runners;
mod validate;

pub use runners::HostExecOutput;

use serde::Deserialize;
use std::fmt;

/// Errors surfaced from host-exec runners. All variants are converted into a
/// `HostExecOutput` with `error_message` set so the gRPC ack still carries
/// the failure context back to the server.
#[derive(Debug)]
pub enum HostExecError {
    BadArg(String),
    Spawn(String),
    BadPayload(String),
}

impl fmt::Display for HostExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostExecError::BadArg(s) => write!(f, "bad argument: {s}"),
            HostExecError::Spawn(s) => write!(f, "spawn failed: {s}"),
            HostExecError::BadPayload(s) => write!(f, "bad payload: {s}"),
        }
    }
}

impl std::error::Error for HostExecError {}

/// True if `command_type` is one of the host-exec tools. Used by the Linux
/// command handler to decide whether to dispatch here.
pub fn is_host_exec_command(command_type: &str) -> bool {
    matches!(
        command_type,
        "host_list_files"
            | "host_read_file"
            | "host_search_files"
            | "host_find_files"
            | "host_list_processes"
            | "host_read_journal"
            | "host_list_open_files"
            | "host_list_sockets"
            | "host_stat_file"
            | "host_hash_file"
            | "host_list_modules"
            | "host_login_history"
            | "host_show_network"
    )
}

/// Run a host-exec command. Returns a [`HostExecOutput`] describing the
/// result; never returns `Err` — validation failures are reported as
/// `error_message` inside the output so they reach the analyst via the
/// normal ack path.
pub async fn run(command_type: &str, payload: &str) -> HostExecOutput {
    match dispatch(command_type, payload).await {
        Ok(out) => out,
        Err(e) => HostExecOutput {
            error_message: e.to_string(),
            exit_code: -1,
            ..Default::default()
        },
    }
}

async fn dispatch(command_type: &str, payload: &str) -> Result<HostExecOutput, HostExecError> {
    match command_type {
        "host_list_files" => {
            let args: runners::ListFilesArgs = parse_payload(payload)?;
            runners::run_list_files(&args).await
        }
        "host_read_file" => {
            let args: runners::ReadFileArgs = parse_payload(payload)?;
            runners::run_read_file(&args).await
        }
        "host_search_files" => {
            let args: runners::SearchFilesArgs = parse_payload(payload)?;
            runners::run_search_files(&args).await
        }
        "host_find_files" => {
            let args: runners::FindFilesArgs = parse_payload(payload)?;
            runners::run_find_files(&args).await
        }
        "host_list_processes" => {
            let args: runners::ListProcessesArgs = parse_payload(payload)?;
            runners::run_list_processes(&args).await
        }
        "host_read_journal" => {
            let args: runners::ReadJournalArgs = parse_payload(payload)?;
            runners::run_read_journal(&args).await
        }
        "host_list_open_files" => {
            let args: runners::ListOpenFilesArgs = parse_payload(payload)?;
            runners::run_list_open_files(&args).await
        }
        "host_list_sockets" => {
            // Empty `{}` is a valid payload — every field has a default —
            // so we route through `parse_payload_or_default`.
            let args: runners::ListSocketsArgs = parse_payload_or_default(payload)?;
            runners::run_list_sockets(&args).await
        }
        "host_stat_file" => {
            let args: runners::StatFileArgs = parse_payload(payload)?;
            runners::run_stat_file(&args).await
        }
        "host_hash_file" => {
            let args: runners::HashFileArgs = parse_payload(payload)?;
            runners::run_hash_file(&args).await
        }
        "host_list_modules" => {
            let args: runners::ListModulesArgs = parse_payload_or_default(payload)?;
            runners::run_list_modules(&args).await
        }
        "host_login_history" => {
            let args: runners::LoginHistoryArgs = parse_payload(payload)?;
            runners::run_login_history(&args).await
        }
        "host_show_network" => {
            let args: runners::ShowNetworkArgs = parse_payload(payload)?;
            runners::run_show_network(&args).await
        }
        other => Err(HostExecError::BadPayload(format!(
            "not a host-exec command: {other}"
        ))),
    }
}

fn parse_payload<T: for<'de> Deserialize<'de>>(payload: &str) -> Result<T, HostExecError> {
    if payload.is_empty() {
        return Err(HostExecError::BadPayload("empty payload".into()));
    }
    serde_json::from_str(payload).map_err(|e| HostExecError::BadPayload(e.to_string()))
}

/// Like [`parse_payload`] but treats an empty / missing body as `{}`.
/// Used for tools whose every field has a `#[serde(default)]` so that an
/// LLM legitimately calling the tool with no args (e.g.
/// `host_list_modules`, `host_list_sockets` in default mode) doesn't
/// trip the empty-payload guard.
fn parse_payload_or_default<T: for<'de> Deserialize<'de>>(
    payload: &str,
) -> Result<T, HostExecError> {
    let body = if payload.trim().is_empty() {
        "{}"
    } else {
        payload
    };
    serde_json::from_str(body).map_err(|e| HostExecError::BadPayload(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_rejects_unknown_command() {
        assert!(!is_host_exec_command("isolate_host"));
        assert!(is_host_exec_command("host_list_files"));
        assert!(is_host_exec_command("host_read_journal"));
        assert!(is_host_exec_command("host_list_open_files"));
        assert!(is_host_exec_command("host_list_sockets"));
        assert!(is_host_exec_command("host_stat_file"));
        assert!(is_host_exec_command("host_hash_file"));
        assert!(is_host_exec_command("host_list_modules"));
        assert!(is_host_exec_command("host_login_history"));
        assert!(is_host_exec_command("host_show_network"));
    }

    #[tokio::test]
    async fn list_open_files_requires_at_least_one_filter() {
        let out = run("host_list_open_files", "{}").await;
        assert!(
            out.error_message.contains("at least one of pid, port, or path"),
            "expected unfiltered-rejection, got: {}",
            out.error_message
        );
    }

    #[tokio::test]
    async fn list_open_files_validates_proto_choice() {
        let out = run(
            "host_list_open_files",
            r#"{"port":80,"proto":"raw"}"#,
        )
        .await;
        assert!(
            out.error_message.contains("proto must be one of"),
            "expected proto validation, got: {}",
            out.error_message
        );
    }

    #[tokio::test]
    async fn list_sockets_requires_tcp_or_udp() {
        let out = run(
            "host_list_sockets",
            r#"{"tcp":false,"udp":false}"#,
        )
        .await;
        assert!(
            out.error_message.contains("at least one of tcp/udp"),
            "expected tcp/udp validation, got: {}",
            out.error_message
        );
    }

    #[tokio::test]
    async fn show_network_validates_kind() {
        let out = run(
            "host_show_network",
            r#"{"kind":"flush"}"#,
        )
        .await;
        assert!(
            out.error_message.contains("kind must be one of"),
            "expected kind allowlist, got: {}",
            out.error_message
        );
    }

    #[tokio::test]
    async fn hash_file_rejects_denylisted_path() {
        let out = run("host_hash_file", r#"{"path":"/etc/shadow"}"#).await;
        assert!(
            out.error_message.contains("denylist"),
            "expected denylist rejection, got: {}",
            out.error_message
        );
    }

    #[tokio::test]
    async fn login_history_validates_kind() {
        let out = run(
            "host_login_history",
            r#"{"kind":"sudo"}"#,
        )
        .await;
        assert!(
            out.error_message.contains("kind must be one of"),
            "expected kind allowlist, got: {}",
            out.error_message
        );
    }

    #[tokio::test]
    async fn read_journal_validates_since_format() {
        // Valid RFC3339 must NOT fail validation. We can't assert success
        // because the test host may lack `journalctl`; what we *can* assert
        // is that the runner doesn't blow up on a plain `--since="now"`-
        // style hijack attempt.
        let bad = run(
            "host_read_journal",
            r#"{"since":"yesterday"}"#,
        )
        .await;
        assert!(
            bad.error_message.contains("RFC3339"),
            "expected RFC3339 validation error, got: {}",
            bad.error_message
        );
    }

    #[tokio::test]
    async fn read_journal_rejects_unit_with_dash_prefix() {
        let out = run(
            "host_read_journal",
            r#"{"since":"2024-01-01T00:00:00Z","unit":"-uall.target"}"#,
        )
        .await;
        assert!(
            out.error_message.contains("unit must not start with '-'"),
            "expected unit-prefix rejection, got: {}",
            out.error_message
        );
    }

    #[tokio::test]
    async fn list_files_reports_error_for_bad_path() {
        let out = run("host_list_files", "{\"path\":\"relative/path\"}").await;
        assert!(!out.error_message.is_empty(), "expected validation error");
    }

    #[tokio::test]
    async fn read_file_rejects_shadow() {
        let out = run("host_read_file", "{\"path\":\"/etc/shadow\"}").await;
        assert!(out.error_message.contains("denylist"));
    }

    #[tokio::test]
    async fn malformed_payload_is_reported() {
        let out = run("host_list_files", "not json").await;
        assert!(!out.error_message.is_empty());
    }

    /// End-to-end smoke: invoke `host_list_processes` against the real
    /// `/bin/ps` on the build host. The runner must produce non-empty
    /// stdout (every Linux box has at least PID 1 running) and exit 0.
    /// Skipped on platforms without `/bin/ps`.
    #[tokio::test]
    async fn list_processes_round_trip() {
        if !std::path::Path::new("/bin/ps").exists() {
            return;
        }
        let out = run("host_list_processes", "{}").await;
        assert!(
            out.error_message.is_empty(),
            "unexpected error: {}",
            out.error_message
        );
        assert_eq!(out.exit_code, 0, "ps exit was non-zero");
        assert!(!out.stdout.is_empty(), "ps produced no stdout");
    }

    /// Verify that a name_filter actually narrows results — and that the
    /// filtered output is shorter than the unfiltered baseline (proves the
    /// runner is filtering, not just shelling out blindly).
    #[tokio::test]
    async fn list_processes_filter_narrows_output() {
        if !std::path::Path::new("/bin/ps").exists() {
            return;
        }
        let unfiltered = run("host_list_processes", "{}").await;
        if unfiltered.exit_code != 0 || unfiltered.stdout.is_empty() {
            return;
        }
        // Filter that almost certainly matches no real process. We accept
        // either an empty stdout body (header-only output) or one strictly
        // shorter than the unfiltered case.
        let filtered = run(
            "host_list_processes",
            "{\"name_filter\":\"__no_such_process_zzz\"}",
        )
        .await;
        assert!(filtered.error_message.is_empty());
        assert!(
            filtered.stdout.len() < unfiltered.stdout.len(),
            "filter did not narrow output"
        );
    }
}
