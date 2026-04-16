//! Helpers for spawning detached shell scripts with output logged to per-run log files.
//!
//! We use `systemd-run --scope` so the script runs in a separate cgroup. Otherwise when the
//! agent's service is stopped (e.g. by dpkg prerm), systemd sends SIGTERM to the whole cgroup
//! and would kill the script and dpkg before they finish.
//!
//! Each invocation writes to a unique file `/var/log/secureexec-agent.<component>.<short_uuid>.log`.
//! The agent tails these files in real time (Phase 1) and drains any leftover files on startup
//! (Phase 2) so that dpkg/rpm output reaches the server even across agent restarts.

use std::path::PathBuf;
use std::process::Stdio;

use secureexec_generic::AgentError;
use tracing::{error, info};
use uuid::Uuid;

/// Directory where per-run script log files are written.
pub const SCRIPT_LOG_DIR: &str = "/var/log";
/// Filename prefix for per-run script log files.
pub const SCRIPT_LOG_PREFIX: &str = "secureexec-agent.";
/// Filename suffix for per-run script log files.
pub const SCRIPT_LOG_SUFFIX: &str = ".log";

/// Spawns a detached shell script in a separate systemd scope.
/// Stdout/stderr go to a unique log file: `/var/log/secureexec-agent.<component>.<uuid8>.log`.
/// Returns the log file path (for tailing).
///
/// The script is not in the agent's cgroup, so it survives when the agent is stopped.
/// Requires systemd (systemd-run in PATH).
/// `script` must not contain single quotes (it is wrapped in single quotes for sh -c).
///
/// A background thread is spawned that `wait()`s on the intermediate `sh -c`
/// child so the kernel can reap the PID immediately — otherwise we would
/// accumulate zombie processes for every isolate/release/update cycle.
pub fn spawn_detached_logged(
    script: &str,
    component: &str,
) -> Result<PathBuf, AgentError> {
    let run_id = Uuid::new_v4();
    let short_id = &run_id.to_string()[..8];
    let log_path = PathBuf::from(format!(
        "{}/{}{}.{}{}", SCRIPT_LOG_DIR, SCRIPT_LOG_PREFIX, component, short_id, SCRIPT_LOG_SUFFIX
    ));
    let inner = format!("exec >>{} 2>&1 || true; {}", log_path.display(), script);
    let escaped = inner.replace('\'', "'\"'\"'");
    let description = format!("secureexec-agent-script-{}", run_id);
    let with_scope = format!(
        "systemd-run --scope --description={} sh -c '{}' </dev/null &",
        description, escaped
    );
    info!(run_id = %run_id, component = component, log = %log_path.display(), "spawning detached script via systemd-run");
    let child = std::process::Command::new("sh")
        .args(["-c", &with_scope])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(mut c) => {
            let pid = c.id();
            info!(run_id = %run_id, pid = pid, "detached script spawn ok (systemd-run)");
            std::thread::Builder::new()
                .name(format!("detached-reaper-{}", pid))
                .spawn(move || {
                    let _ = c.wait();
                })
                .map_err(|e| AgentError::Platform(format!("spawn reaper thread: {e}")))?;
            Ok(log_path)
        }
        Err(e) => {
            error!(run_id = %run_id, error = %e, "detached script spawn failed (systemd-run)");
            Err(AgentError::Platform(format!("spawn detached script: {}", e)))
        }
    }
}
