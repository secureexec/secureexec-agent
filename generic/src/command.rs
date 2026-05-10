//! Command dispatch infrastructure.
//!
//! The `CommandHandler` trait is implemented by platform-specific code
//! (e.g. the Linux firewall controller) and registered with the Pipeline.
//! The Pipeline polls the server for pending commands and dispatches them.

use async_trait::async_trait;

use crate::error::Result;

/// A command received from the backend.
#[derive(Debug, Clone)]
pub struct AgentCommand {
    pub command_id: String,
    pub command_type: String,
    pub payload: String,
}

/// Side-channel data a command handler can attach to its ack. Carries the
/// captured stdout / stderr / exit info from read-only host-exec commands
/// (`host_list_files`, `host_read_file`, …). Legacy commands like
/// `isolate_host` ignore this and let the default values flow through —
/// the proto fields are zero-valued in that case, which the server already
/// treats as "no output captured".
#[derive(Debug, Clone, Default)]
pub struct CommandOutcome {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub truncated: bool,
    pub duration_ms: i64,
    /// Shell-quoted argv that was actually executed. Captured so the audit
    /// trail and chat UI can render the literal command an analyst could
    /// paste into a terminal on the host. Empty for legacy commands that
    /// don't shell out (isolate, release, kill_tree, uninstall).
    pub command_line: String,
}

/// Platform-specific command execution.
///
/// The Linux implementation drives the secureexec_kmod ioctl interface.
/// Other platforms should provide a no-op implementation or return
/// an appropriate error.
#[async_trait]
pub trait CommandHandler: Send + Sync + 'static {
    /// Execute a command and return Ok(outcome) on success. Most legacy
    /// command types return `CommandOutcome::default()`; only the host-exec
    /// commands populate the stdout/stderr/exit_code fields.
    async fn handle(&self, cmd: &AgentCommand) -> Result<CommandOutcome>;

    /// Report current network isolation state (for heartbeat telemetry).
    /// Returns false if isolation is not supported on this platform.
    fn net_isolated(&self) -> bool {
        false
    }

    /// True if `/dev/secureexec_kmod` was present at agent startup.
    fn kmod_available(&self) -> bool {
        false
    }

    /// Name of the active firewall backend: `"ebpf"`, `"kmod"`, or `""`.
    fn firewall_backend_name(&self) -> &str {
        ""
    }

    /// Loaded kmod version from `/sys/module/secureexec_kmod/version`, or `""` if not loaded.
    fn kmod_version(&self) -> &str {
        ""
    }

    /// Cumulative eBPF ring-buffer drop counts: `[process, file, network, security]`.
    /// Non-zero values indicate the kernel had to discard events because a ring
    /// buffer was full.
    fn ebpf_drop_counts(&self) -> [u64; 4] {
        [0; 4]
    }

    /// Total BPF ABI sanity-check failures detected at startup.
    /// Non-zero means the running kernel's tracepoint offsets or struct layouts
    /// differ from the values hard-coded in the eBPF programs.
    fn ebpf_offset_mismatches(&self) -> u64 {
        0
    }
}

/// A no-op command handler for platforms that don't support kmod commands.
pub struct NoopCommandHandler;

#[async_trait]
impl CommandHandler for NoopCommandHandler {
    async fn handle(&self, cmd: &AgentCommand) -> Result<CommandOutcome> {
        // Return an explicit error rather than a silent Ok(()). Previously
        // commands would be ack'd as "succeeded" on a platform that has no
        // handler wired up, making it impossible for the server to tell the
        // difference between "command executed" and "command silently dropped".
        tracing::warn!(command_type = %cmd.command_type, "command received but no handler registered");
        Err(crate::error::AgentError::Platform(format!(
            "no command handler registered on this platform (command_type={})",
            cmd.command_type
        )))
    }
}
