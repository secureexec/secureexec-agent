use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::error::{AgentError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Unique agent identifier — generated on first run and persisted.
    #[serde(default)]
    pub agent_id: String,

    /// Batch size: how many events to accumulate before flushing.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Maximum seconds to hold a partial batch before flushing anyway.
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,

    /// Backend gRPC endpoint URL, e.g. "http://[::1]:50051".
    #[serde(default = "default_backend_url")]
    pub backend_url: String,

    /// Path to the local SQLite spool database for durable event buffering.
    #[serde(default = "default_spool_path")]
    pub spool_path: PathBuf,

    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Which sensor categories to enable.
    #[serde(default = "default_sensors")]
    pub sensors: Vec<String>,

    /// Last assigned event sequence number — persisted so seqno is monotonic
    /// across agent restarts.
    #[serde(default)]
    pub last_seqno: i64,

    /// Path to CA certificate (PEM) used to verify the server. Enables TLS.
    #[serde(default)]
    pub tls_ca_cert: Option<PathBuf>,

    /// Path to agent client certificate (PEM) for mTLS.
    #[serde(default)]
    pub tls_client_cert: Option<PathBuf>,

    /// Path to agent client private key (PEM) for mTLS.
    #[serde(default)]
    pub tls_client_key: Option<PathBuf>,

    /// Server name used for TLS SNI + certificate verification.
    /// Must match one of the `subjectAltName` entries on the server cert.
    /// When `None`, the hostname is derived from `backend_url`; when the URL
    /// has no hostname (e.g. numeric-IP literal), TLS verification will be
    /// rejected. Set this explicitly for bare-IP deployments using a cert
    /// that pins a specific DNS name.
    #[serde(default)]
    pub tls_server_name: Option<String>,

    /// Bearer token sent to server with every gRPC call.
    #[serde(default)]
    pub auth_token: Option<String>,

    /// Preferred firewall backend: "auto" (default), "ebpf", or "kmod".
    /// "auto" tries eBPF first; falls back to kmod if unavailable.
    #[serde(default = "default_firewall_backend")]
    pub firewall_backend: String,
}

fn default_batch_size() -> usize {
    64
}

fn default_flush_interval_secs() -> u64 {
    5
}

fn default_spool_path() -> PathBuf {
    PathBuf::from("secureexec-spool.db")
}

fn default_backend_url() -> String {
    "http://[::1]:50051".into()
}

fn default_heartbeat_interval_secs() -> u64 {
    60
}

fn default_firewall_backend() -> String {
    "auto".into()
}

fn default_sensors() -> Vec<String> {
    vec![
        "process".into(),
        "file".into(),
        "network".into(),
    ]
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval_secs(),
            backend_url: default_backend_url(),
            spool_path: default_spool_path(),
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            sensors: default_sensors(),
            last_seqno: 0,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
            tls_server_name: None,
            auth_token: None,
            firewall_backend: default_firewall_backend(),
        }
    }
}

impl AgentConfig {
    /// Load config from `path`. If the file doesn't exist, create it with
    /// defaults. If `agent_id` is empty, generate a new one and save.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let mut config = if path.exists() {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str::<AgentConfig>(&data)
                .map_err(|e| AgentError::Config(format!("parse {}: {e}", path.display())))?
        } else {
            AgentConfig::default()
        };

        if config.agent_id.is_empty() {
            config.agent_id = Uuid::new_v4().to_string();
            info!(agent_id = %config.agent_id, "generated new agent id");
            config.save(path)?;
        }

        Ok(config)
    }

    /// Persist current config to disk as pretty-printed JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        info!(path = %path.display(), "config saved");
        Ok(())
    }

    pub fn flush_interval(&self) -> Duration {
        Duration::from_secs(self.flush_interval_secs)
    }

    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }
}
