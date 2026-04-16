//! Linux-specific command handler — dispatches server commands to the firewall.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{info, warn};

use secureexec_generic::command::{AgentCommand, CommandHandler};
use secureexec_generic::error::{AgentError, Result};
use secureexec_generic::process_table::ProcessTable;

use std::path::Path;

use crate::detached_script::spawn_detached_logged;
use crate::log_tailer::tail_script_log;
use crate::sensors::ebpf::EbpfDropCounters;

/// Delay before `systemctl stop` in the uninstall script.
/// Gives enough time for the ack response and final events to reach the server.
const UNINSTALL_DELAY_SECS: u32 = 15;

use crate::firewall::{
    KmodFirewall, NetworkFirewall, SeFwRule, SE_FW_DIR_ANY, SE_FW_DIR_IN, SE_FW_DIR_OUT,
    SE_FW_PROTO_ANY, SE_FW_PROTO_TCP,
};

pub struct LinuxCommandHandler {
    firewall: Option<Box<dyn NetworkFirewall>>,
    /// true if `/dev/secureexec_kmod` was present at agent startup (regardless
    /// of which firewall backend is currently active).
    kmod_present: bool,
    /// Backend URL — resolved to IPs at isolation time so the agent keeps its
    /// gRPC connection alive while the host is isolated.
    backend_url: String,
    /// Shared handle to the agent's live process table.  Used by the
    /// `kill_process_tree` command to enumerate descendant PIDs.
    process_table: Option<Arc<RwLock<ProcessTable>>>,
    /// Loaded kmod version from `/sys/module/secureexec_kmod/version`, or empty string.
    kmod_ver: String,
    /// Shared eBPF ring-buffer drop counters (updated by the poll thread).
    drop_counters: Option<Arc<EbpfDropCounters>>,
}

/// JSON payload for the `kill_process_tree` command.
#[derive(Debug, Deserialize)]
struct KillTreePayload {
    ancestor_process_guid: String,
}

impl LinuxCommandHandler {
    pub fn new(
        firewall: Option<Box<dyn NetworkFirewall>>,
        kmod_present: bool,
        backend_url: impl Into<String>,
        process_table: Option<Arc<RwLock<ProcessTable>>>,
        drop_counters: Option<Arc<EbpfDropCounters>>,
    ) -> Self {
        let kmod_ver = std::fs::read_to_string("/sys/module/secureexec_kmod/version")
            .unwrap_or_default()
            .trim()
            .to_string();
        Self { firewall, kmod_present, backend_url: backend_url.into(), process_table, kmod_ver, drop_counters }
    }

    /// Extract a `host:port` pair from a URL like `https://example.com:50051`.
    /// Falls back to `host:50051` if no port is present.
    fn backend_host_port(url: &str) -> String {
        // Strip scheme
        let without_scheme = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        // Drop any path component
        let host_port = match without_scheme.find('/') {
            Some(i) => &without_scheme[..i],
            None => without_scheme,
        };
        // If there's no port, append the default gRPC port
        if host_port.starts_with('[') {
            // IPv6 like [::1]:50051 — has port only if there's a ']:'
            if host_port.contains("]:") {
                host_port.to_string()
            } else {
                format!("{host_port}:50051")
            }
        } else if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{host_port}:50051")
        }
    }

    /// Resolve the backend URL to IPv4 addresses and return bidirectional
    /// whitelist rules (outbound SYN + inbound for UDP responses).
    async fn backend_rules(url: &str) -> Vec<SeFwRule> {
        let host_port = Self::backend_host_port(url);
        let result = tokio::net::lookup_host(host_port.as_str()).await;
        match result {
            Ok(addrs) => {
                let mut rules = Vec::new();
                for sa in addrs {
                    if let Some(r) = KmodFirewall::rule_allow_ip_out(sa.ip()) {
                        rules.push(r);
                    }
                    if let Some(r) = KmodFirewall::rule_allow_ip_in(sa.ip()) {
                        rules.push(r);
                    }
                }
                if rules.is_empty() {
                    warn!(backend = %url, "backend resolved to no IPv4 addresses — agent traffic may be blocked during isolation");
                } else {
                    info!(backend = %url, rules = rules.len(), "whitelisted backend IPs for isolation");
                }
                rules
            }
            Err(e) => {
                warn!(backend = %url, error = %e, "failed to resolve backend host — agent traffic may be blocked during isolation");
                vec![]
            }
        }
    }

    /// Convert an `IsolateRule` (from JSON payload or gRPC) into a kernel `SeFwRule`.
    pub fn convert_rule(ip: &str, port: u16, direction: &str) -> SeFwRule {
        let ip_u32 = if ip.is_empty() {
            0u32
        } else {
            Ipv4Addr::from_str(ip)
                // kmod stores IPs in network byte order; Ipv4Addr::octets()
                // already returns bytes big-endian, so from_be_bytes yields
                // the correct NBO `u32` on any host endianness.
                .map(|a| u32::from_be_bytes(a.octets()))
                .unwrap_or_else(|_| {
                    warn!(ip = %ip, "invalid IP in isolation rule, treating as any");
                    0u32
                })
        };

        let fw_direction = match direction {
            "in" => SE_FW_DIR_IN,
            "out" => SE_FW_DIR_OUT,
            _ => SE_FW_DIR_ANY,
        };

        SeFwRule { ip: ip_u32, port, proto: SE_FW_PROTO_ANY, direction: fw_direction }
    }
}

/// A single firewall rule from the JSON payload (new format).
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct IsolateRule {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default = "default_dir_any")]
    pub direction: String,
}

fn default_dir_any() -> String { "any".into() }

/// JSON payload for the `isolate_host` command.
/// Legacy fields (`allow_ssh`, `allow_ips`) are kept for backward compat with
/// commands already stored in the DB before this version.
#[derive(Debug, Deserialize)]
struct IsolatePayload {
    /// Legacy: adds inbound TCP/22 rule if true.
    #[serde(default)]
    allow_ssh: bool,
    /// Legacy: adds outbound-any-port rules per IP.
    #[serde(default)]
    allow_ips: Vec<String>,
    /// New: full (ip, port, direction) rules from global isolation policy.
    #[serde(default)]
    allow_rules: Vec<IsolateRule>,
}

impl Default for IsolatePayload {
    fn default() -> Self {
        Self { allow_ssh: false, allow_ips: vec![], allow_rules: vec![] }
    }
}

#[async_trait]
impl CommandHandler for LinuxCommandHandler {
    async fn handle(&self, cmd: &AgentCommand) -> Result<()> {
        match cmd.command_type.as_str() {
            "isolate_host" => {
                let fw = self.firewall.as_ref().ok_or_else(|| {
                    AgentError::Platform("firewall not available — cannot isolate".into())
                })?;

                // Fail-closed: a malformed payload must not silently collapse
                // to "isolate with only the default rules", because that would
                // cut legitimate operators out of the host on top of the
                // attacker still having a foothold. Surface the error and let
                // the caller decide whether to retry.
                let payload: IsolatePayload = if cmd.payload.is_empty() {
                    IsolatePayload::default()
                } else {
                    serde_json::from_str(&cmd.payload).map_err(|e| {
                        warn!(error = %e, "rejecting isolate_host with malformed payload");
                        AgentError::Platform(format!("isolate_host: invalid payload: {e}"))
                    })?
                };

                let mut extra_rules: Vec<SeFwRule> = Vec::new();

                // New-style rules: full (ip, port, direction) from global policy.
                for r in &payload.allow_rules {
                    extra_rules.push(Self::convert_rule(&r.ip, r.port, &r.direction));
                }

                // Legacy: allow_ssh toggle.
                if payload.allow_ssh {
                    extra_rules.push(SeFwRule { ip: 0, port: 22, proto: SE_FW_PROTO_TCP, direction: SE_FW_DIR_IN });
                }

                // Legacy: plain IPs get bidirectional any-port access.
                for ip_str in &payload.allow_ips {
                    match ip_str.parse::<std::net::IpAddr>() {
                        Ok(ip) => {
                            if let Some(rule) = KmodFirewall::rule_allow_ip_out(ip) {
                                extra_rules.push(rule);
                            }
                            if let Some(rule) = KmodFirewall::rule_allow_ip_in(ip) {
                                extra_rules.push(rule);
                            }
                        }
                        Err(e) => warn!(ip = %ip_str, error = %e, "ignoring invalid IP in isolate payload"),
                    }
                }

                // Always whitelist the backend server IPs so the agent keeps its
                // gRPC connection and can receive the release command.
                extra_rules.extend(Self::backend_rules(&self.backend_url).await);

                fw.isolate(&extra_rules)?;
                info!("host isolated via command {}", cmd.command_id);
                Ok(())
            }

            "release_host" => {
                let fw = self.firewall.as_ref().ok_or_else(|| {
                    AgentError::Platform("firewall not available — cannot release".into())
                })?;
                fw.release()?;
                info!("host released from isolation via command {}", cmd.command_id);
                Ok(())
            }

            "uninstall" => {
                let pkg_cmd = if Path::new("/etc/debian_version").exists() {
                    "dpkg -r secureexec-agent"
                } else {
                    "rpm -e secureexec-agent"
                };
                info!(
                    component = "agent-delete",
                    command_id = %cmd.command_id,
                    delay_secs = UNINSTALL_DELAY_SECS,
                    "uninstall command accepted, spawning removal in {}s",
                    UNINSTALL_DELAY_SECS
                );
                let script = format!(
                    "sleep {delay}; systemctl stop secureexec-agent || true; \
                    {pkg} && rm -rf /opt/secureexec",
                    delay = UNINSTALL_DELAY_SECS,
                    pkg = pkg_cmd,
                );
                match spawn_detached_logged(&script, "agent-delete") {
                    Ok(log_path) => {
                        tokio::spawn(tail_script_log(log_path, "agent-delete".to_string(), None));
                        Ok(())
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to spawn uninstall script");
                        Err(e)
                    }
                }
            }

            "kill_process_tree" => {
                let payload: KillTreePayload = serde_json::from_str(&cmd.payload)
                    .map_err(|e| AgentError::Platform(format!("kill_process_tree: bad payload: {e}")))?;
                let ancestor_guid = payload.ancestor_process_guid;

                let pids = self.process_table.as_ref()
                    .ok_or_else(|| AgentError::Platform("kill_process_tree: process table unavailable".into()))?
                    .read()
                    .map_err(|_| AgentError::Platform("kill_process_tree: process table lock poisoned".into()))?
                    .pids_in_subtree(&ancestor_guid);

                info!(ancestor_guid = %ancestor_guid, count = pids.len(), "killing process subtree");
                for pid in pids {
                    // Safety: `pid` is a live PID read from the process table,
                    // which only contains entries observed by the eBPF sensor.
                    // SIGKILL is safe to send to any process we have permission for.
                    if let Err(e) = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGKILL,
                    ) {
                        warn!(pid, error = %e, "failed to kill process in subtree");
                    }
                }
                Ok(())
            }

            other => {
                warn!(command_type = %other, "unknown command type");
                Err(AgentError::Platform(format!("unknown command type: {other}")))
            }
        }
    }

    fn net_isolated(&self) -> bool {
        self.firewall.as_ref().map(|f| f.is_isolated()).unwrap_or(false)
    }

    fn kmod_available(&self) -> bool {
        self.kmod_present
    }

    fn firewall_backend_name(&self) -> &str {
        self.firewall.as_ref().map(|f| f.backend_name()).unwrap_or("")
    }

    fn kmod_version(&self) -> &str {
        &self.kmod_ver
    }

    fn ebpf_drop_counts(&self) -> [u64; 4] {
        self.drop_counters.as_ref().map(|dc| dc.snapshot()).unwrap_or([0; 4])
    }
}
