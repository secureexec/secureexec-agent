//! Read-only "live response" host commands the AI investigation/chat agent
//! can run on a Linux endpoint during a case investigation. Five tools, each
//! built on a real binary (`ls`, `cat`/`head`/`tail`, `grep`, `find`, `ps`)
//! invoked via `argv` — **never** through a shell.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_rejects_unknown_command() {
        assert!(!is_host_exec_command("isolate_host"));
        assert!(is_host_exec_command("host_list_files"));
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
