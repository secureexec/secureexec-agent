//! Shared constants for the Linux agent.

/// Path to the legacy shared agent log file.
/// Superseded by per-run log files (see `detached_script.rs`) but kept in
/// case external tooling (logrotate configs, etc.) still references it.
#[allow(dead_code)]
pub const SECUREEXEC_SYSTEM_LOG_PATH: &str = "/var/log/secureexec.log";
