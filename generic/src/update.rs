//! Agent self-update interface.
//!
//! Platform-specific implementations (Linux, macOS, Windows) live in their
//! respective agent crates and are registered with the pipeline via `set_agent_updater`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::transport::GrpcControlClient;

/// Platform-specific agent updater: download package for target version, install, restart.
/// Implemented by the Linux agent; macOS/Windows can add their own later.
#[async_trait]
pub trait AgentUpdater: Send + Sync {
    /// Platform key used when fetching target version and sha256 (e.g. "linux_amd64_deb").
    /// Return `None` if this platform does not support updates or cannot report a platform key.
    fn platform(&self) -> Option<String>;

    /// Download the update package, verify sha256 when provided, then install and restart.
    /// `expected_sha256` is the hex-encoded SHA-256 of the package from the server; empty means skip verification.
    /// `firewall_backend` is the configured firewall backend (e.g. "kmod", "ebpf", ""); used to
    /// decide whether to download and install the kmod package alongside the agent.
    async fn run_update(
        &self,
        ctrl: Arc<GrpcControlClient>,
        agent_id: String,
        target_version: String,
        expected_sha256: String,
        firewall_backend: String,
    ) -> Result<()>;
}
