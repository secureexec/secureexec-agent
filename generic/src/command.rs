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

/// Platform-specific command execution.
///
/// The Linux implementation drives the secureexec_kmod ioctl interface.
/// Other platforms should provide a no-op implementation or return
/// an appropriate error.
#[async_trait]
pub trait CommandHandler: Send + Sync + 'static {
    /// Execute a command and return Ok(()) on success.
    async fn handle(&self, cmd: &AgentCommand) -> Result<()>;

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
}

/// A no-op command handler for platforms that don't support kmod commands.
pub struct NoopCommandHandler;

#[async_trait]
impl CommandHandler for NoopCommandHandler {
    async fn handle(&self, cmd: &AgentCommand) -> Result<()> {
        tracing::warn!(command_type = %cmd.command_type, "command received but no handler registered");
        Ok(())
    }
}
