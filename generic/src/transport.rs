use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tonic::metadata::MetadataValue;
use tracing::{debug, info, warn};

/// Per-request deadline for ordinary gRPC calls (poll_commands, ack, etc.).
const GRPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout for establishing the initial gRPC connection.
const GRPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Per-request deadline for download_agent_update (streaming, can be large).
const GRPC_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

use crate::command::AgentCommand;
use crate::error::{AgentError, Result};
use crate::event::{self, Event, EventKind};
use crate::log_sender::{entry_to_proto, AgentLogEntry};

pub mod pb {
    tonic::include_proto!("secureexec");
}

/// Trait for shipping events to a backend / SIEM.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    async fn send_batch(&self, events: &[Event]) -> Result<()>;

    /// Send agent log entries to the server. Default is no-op (e.g. StdoutTransport).
    async fn send_agent_logs(&self, _agent_id: &str, _entries: &[AgentLogEntry]) -> Result<()> {
        Ok(())
    }
}

/// Stdout transport — useful for development and debugging.
pub struct StdoutTransport;

#[async_trait]
impl Transport for StdoutTransport {
    async fn send_batch(&self, events: &[Event]) -> Result<()> {
        for event in events {
            let json = serde_json::to_string(event)?;
            println!("{json}");
        }
        Ok(())
    }
}

/// Optional TLS configuration for the gRPC transport.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub ca_cert: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

/// gRPC transport — ships event batches to secureexec-server via `SendEventBatch`.
pub struct GrpcTransport {
    endpoint: String,
    tls: TlsConfig,
    auth_token: Option<String>,
    client: Mutex<Option<pb::event_ingestion_client::EventIngestionClient<tonic::transport::Channel>>>,
}

impl GrpcTransport {
    pub fn new(endpoint: impl Into<String>, tls: TlsConfig, auth_token: Option<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            tls,
            auth_token,
            client: Mutex::new(None),
        }
    }

    async fn get_client(&self) -> Result<pb::event_ingestion_client::EventIngestionClient<tonic::transport::Channel>> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }

        debug!(endpoint = %self.endpoint, "connecting to secureexec-server");
        let mut ep = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
            .map_err(|e| AgentError::Transport(format!("invalid endpoint: {e}")))?
            .timeout(GRPC_REQUEST_TIMEOUT)
            .connect_timeout(GRPC_CONNECT_TIMEOUT);

        if let Some(ca_path) = &self.tls.ca_cert {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let ca_pem = std::fs::read(ca_path)
                .map_err(|e| AgentError::Transport(format!("read CA cert {}: {e}", ca_path.display())))?;
            let ca = tonic::transport::Certificate::from_pem(ca_pem);

            let mut tls_config = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name("localhost");

            if let (Some(cert_path), Some(key_path)) = (&self.tls.client_cert, &self.tls.client_key) {
                let cert_pem = std::fs::read(cert_path)
                    .map_err(|e| AgentError::Transport(format!("read client cert {}: {e}", cert_path.display())))?;
                let key_pem = std::fs::read(key_path)
                    .map_err(|e| AgentError::Transport(format!("read client key {}: {e}", key_path.display())))?;
                let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
                tls_config = tls_config.identity(identity);
                info!("mTLS enabled (CA + client cert)");
            } else {
                info!("TLS enabled (CA only, no client cert)");
            }

            ep = ep.tls_config(tls_config)
                .map_err(|e| AgentError::Transport(format!("tls config for {}: {e:?}", self.endpoint)))?;
        }

        let channel = ep.connect().await
            .map_err(|e| AgentError::Transport(format!("connect failed: {e}")))?;

        let client = pb::event_ingestion_client::EventIngestionClient::new(channel);
        *guard = Some(client.clone());
        Ok(client)
    }

    fn make_request<T>(&self, msg: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(msg);
        if let Some(token) = &self.auth_token {
            if let Ok(val) = format!("Bearer {token}").parse::<MetadataValue<tonic::metadata::Ascii>>() {
                req.metadata_mut().insert("authorization", val);
            }
        }
        req
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    async fn send_batch(&self, events: &[Event]) -> Result<()> {
        let proto_events: Vec<pb::AgentEvent> = events.iter().map(event_to_proto).collect();
        let batch = pb::EventBatch { events: proto_events };

        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };

        let request = self.make_request(batch);

        match client.send_event_batch(request).await {
            Ok(resp) => {
                debug!(accepted = resp.into_inner().accepted, "batch sent");
                Ok(())
            }
            Err(status) => {
                warn!(code = ?status.code(), message = %status.message(), "grpc send failed");
                *self.client.lock().await = None;
                Err(AgentError::Transport(format!("grpc: {status}")))
            }
        }
    }

    async fn send_agent_logs(&self, agent_id: &str, entries: &[AgentLogEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let proto_entries: Vec<pb::AgentLogEntry> = entries.iter().map(entry_to_proto).collect();
        let request = pb::SendAgentLogsRequest {
            agent_id: agent_id.to_string(),
            entries: proto_entries,
        };
        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };
        let req = self.make_request(request);
        match client.send_agent_logs(req).await {
            Ok(resp) => {
                let accepted = resp.into_inner().accepted;
                debug!(accepted, "agent logs sent");
                Ok(())
            }
            Err(status) => {
                warn!(code = ?status.code(), message = %status.message(), "send_agent_logs failed");
                *self.client.lock().await = None;
                Err(AgentError::Transport(format!("grpc: {status}")))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AgentControl gRPC client
// ---------------------------------------------------------------------------

/// Talks to the `AgentControl` gRPC service to poll for commands and ack them.
pub struct GrpcControlClient {
    endpoint: String,
    tls: TlsConfig,
    auth_token: Option<String>,
    client: Mutex<Option<pb::agent_control_client::AgentControlClient<tonic::transport::Channel>>>,
}

impl GrpcControlClient {
    pub fn new(endpoint: impl Into<String>, tls: TlsConfig, auth_token: Option<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            tls,
            auth_token,
            client: Mutex::new(None),
        }
    }

    async fn get_client(&self) -> Result<pb::agent_control_client::AgentControlClient<tonic::transport::Channel>> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let mut ep = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
            .map_err(|e| AgentError::Transport(format!("control endpoint invalid: {e}")))?
            .timeout(GRPC_REQUEST_TIMEOUT)
            .connect_timeout(GRPC_CONNECT_TIMEOUT);

        if let Some(ca_path) = &self.tls.ca_cert {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let ca_pem = std::fs::read(ca_path)
                .map_err(|e| AgentError::Transport(format!("control: read CA cert {}: {e}", ca_path.display())))?;
            let ca = tonic::transport::Certificate::from_pem(ca_pem);
            let mut tls_config = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name("localhost");
            if let (Some(cert_path), Some(key_path)) = (&self.tls.client_cert, &self.tls.client_key) {
                let cert_pem = std::fs::read(cert_path)
                    .map_err(|e| AgentError::Transport(format!("control: read client cert {}: {e}", cert_path.display())))?;
                let key_pem = std::fs::read(key_path)
                    .map_err(|e| AgentError::Transport(format!("control: read client key {}: {e}", key_path.display())))?;
                let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
                tls_config = tls_config.identity(identity);
            }
            ep = ep.tls_config(tls_config)
                .map_err(|e| AgentError::Transport(format!("control tls config: {e:?}")))?;
        }

        let channel = ep.connect().await
            .map_err(|e| AgentError::Transport(format!("control connect failed: {e}")))?;
        let client = pb::agent_control_client::AgentControlClient::new(channel);
        *guard = Some(client.clone());
        Ok(client)
    }

    fn make_request<T>(&self, msg: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(msg);
        if let Some(token) = &self.auth_token {
            if let Ok(val) = format!("Bearer {token}").parse::<MetadataValue<tonic::metadata::Ascii>>() {
                req.metadata_mut().insert("authorization", val);
            }
        }
        req
    }

    /// Fetch pending commands for this agent from the server.
    pub async fn poll_commands(&self, agent_id: &str) -> Result<Vec<AgentCommand>> {
        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };
        let req = self.make_request(pb::PollCommandsRequest { agent_id: agent_id.to_string() });
        match client.poll_commands(req).await {
            Ok(resp) => {
                let cmds = resp.into_inner().commands.into_iter().map(|c| AgentCommand {
                    command_id: c.command_id,
                    command_type: c.command_type,
                    payload: c.payload,
                }).collect();
                Ok(cmds)
            }
            Err(status) => {
                warn!(code = ?status.code(), "poll_commands failed");
                *self.client.lock().await = None;
                Err(AgentError::Transport(format!("poll_commands: {status}")))
            }
        }
    }

    /// Fetch the target agent version and sha256 for the update package from the server.
    /// `platform` is the agent's platform key (e.g. "linux_amd64_deb"); use "" if the agent has no updater.
    /// Returns (target_version, target_agent_version_sha256); sha256 is empty if server could not provide it.
    pub async fn get_target_version(
        &self,
        agent_id: &str,
        platform: &str,
    ) -> Result<(String, String)> {
        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };
        let req = self.make_request(pb::GetTargetVersionRequest {
            agent_id: agent_id.to_string(),
            platform: platform.to_string(),
        });
        match client.get_target_version(req).await {
            Ok(resp) => {
                let inner = resp.into_inner();
                Ok((inner.target_agent_version, inner.target_agent_version_sha256))
            }
            Err(status) => {
                warn!(code = ?status.code(), "get_target_version failed");
                *self.client.lock().await = None;
                Err(AgentError::Transport(format!("get_target_version: {status}")))
            }
        }
    }

    /// Fetch the active blocklist rules for this agent from the server.
    pub async fn get_blocklist_rules(&self, agent_id: &str) -> Result<Vec<pb::BlocklistRule>> {
        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };
        let req = self.make_request(pb::GetBlocklistRulesRequest { agent_id: agent_id.to_string() });
        match client.get_blocklist_rules(req).await {
            Ok(resp) => Ok(resp.into_inner().rules),
            Err(status) => {
                warn!(code = ?status.code(), "get_blocklist_rules failed");
                *self.client.lock().await = None;
                Err(AgentError::Transport(format!("get_blocklist_rules: {status}")))
            }
        }
    }

    /// Fetch the current enabled isolation firewall rules for this agent from the server.
    pub async fn get_isolation_rules(&self, agent_id: &str) -> Result<Vec<pb::IsolationRule>> {
        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };
        let req = self.make_request(pb::GetIsolationRulesRequest { agent_id: agent_id.to_string() });
        match client.get_isolation_rules(req).await {
            Ok(resp) => Ok(resp.into_inner().rules),
            Err(status) => {
                warn!(code = ?status.code(), "get_isolation_rules failed");
                *self.client.lock().await = None;
                Err(AgentError::Transport(format!("get_isolation_rules: {status}")))
            }
        }
    }

    /// Download the agent update package for the given platform and version, writing to path.
    pub async fn download_agent_update(
        &self,
        agent_id: &str,
        platform: &str,
        version: &str,
        path: &std::path::Path,
    ) -> Result<()> {
        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };
        let mut req = self.make_request(pb::GetAgentUpdateRequest {
            agent_id: agent_id.to_string(),
            platform: platform.to_string(),
            version: version.to_string(),
        });
        req.set_timeout(GRPC_DOWNLOAD_TIMEOUT);
        let mut stream = client
            .get_agent_update(req)
            .await
            .map_err(|e| AgentError::Transport(format!("get_agent_update: {e}")))?
            .into_inner();
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|e| AgentError::Transport(format!("create update file: {e}")))?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| AgentError::Transport(format!("stream: {e}")))?;
            file.write_all(&chunk.data)
                .await
                .map_err(|e| AgentError::Transport(format!("write update file: {e}")))?;
        }
        file.sync_all()
            .await
            .map_err(|e| AgentError::Transport(format!("sync update file: {e}")))?;
        Ok(())
    }

    /// Acknowledge a command execution result.
    pub async fn ack_command(&self, agent_id: &str, command_id: &str, success: bool, error_msg: &str) -> Result<()> {
        let mut client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                *self.client.lock().await = None;
                return Err(e);
            }
        };
        let req = self.make_request(pb::AckCommandRequest {
            agent_id: agent_id.to_string(),
            command_id: command_id.to_string(),
            success,
            error_message: error_msg.to_string(),
        });
        match client.ack_command(req).await {
            Ok(_) => Ok(()),
            Err(status) => {
                warn!(code = ?status.code(), "ack_command failed");
                *self.client.lock().await = None;
                Err(AgentError::Transport(format!("ack_command: {status}")))
            }
        }
    }
}

fn event_to_proto(event: &Event) -> pb::AgentEvent {
    let kind = match &event.kind {
        EventKind::ProcessCreate(e) => Some(pb::agent_event::Kind::ProcessCreate(process_to_proto(e))),
        EventKind::ProcessFork(e) => Some(pb::agent_event::Kind::ProcessFork(process_to_proto(e))),
        EventKind::ProcessExit(e) => Some(pb::agent_event::Kind::ProcessExit(process_to_proto(e))),
        EventKind::FileCreate(e) => Some(pb::agent_event::Kind::FileCreate(file_to_proto(e))),
        EventKind::FileModify(e) => Some(pb::agent_event::Kind::FileModify(file_to_proto(e))),
        EventKind::FileDelete(e) => Some(pb::agent_event::Kind::FileDelete(file_to_proto(e))),
        EventKind::FileRename(e) => Some(pb::agent_event::Kind::FileRename(pb::FileRenameEvent {
            old_path: e.old_path.clone(),
            new_path: e.new_path.clone(),
            pid: e.pid,
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            user_id: e.user_id.clone(),
        })),
        EventKind::NetworkConnect(e) => Some(pb::agent_event::Kind::NetworkConnect(net_to_proto(e))),
        EventKind::NetworkListen(e) => Some(pb::agent_event::Kind::NetworkListen(net_to_proto(e))),
        EventKind::DnsQuery(e) => Some(pb::agent_event::Kind::DnsQuery(pb::DnsEvent {
            pid: e.pid,
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            query: e.query.clone(),
            response: e.response.clone(),
            user_id: e.user_id.clone(),
        })),
        EventKind::RegistryWrite(e) => Some(pb::agent_event::Kind::RegistryWrite(pb::RegistryEvent {
            pid: e.pid,
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            key: e.key.clone(),
            value_name: e.value_name.clone(),
        })),
        EventKind::UserLogon(e) => Some(pb::agent_event::Kind::UserLogon(pb::UserLogonEvent {
            username: e.username.clone(),
            logon_type: e.logon_type.clone(),
            source_addr: e.source_addr.clone().unwrap_or_default(),
        })),
        EventKind::AgentStarted(e) => Some(pb::agent_event::Kind::AgentStarted(pb::AgentLifecycleEvent {
            version: e.version.clone(),
            os: e.os.clone(),
            os_version: e.os_version.clone(),
            os_kernel_version: e.os_kernel_version.clone(),
        })),
        EventKind::AgentStopping(e) => Some(pb::agent_event::Kind::AgentStopping(pb::AgentLifecycleEvent {
            version: e.version.clone(),
            os: e.os.clone(),
            os_version: e.os_version.clone(),
            os_kernel_version: e.os_kernel_version.clone(),
        })),
        EventKind::AgentHeartbeat(e) => Some(pb::agent_event::Kind::AgentHeartbeat(pb::AgentHeartbeatEvent {
            uptime_secs: e.uptime_secs,
            spool_pending: e.spool_pending,
            version: e.version.clone(),
            os: e.os.clone(),
            os_version: e.os_version.clone(),
            os_kernel_version: e.os_kernel_version.clone(),
            net_isolated: e.net_isolated,
            kmod_available: e.kmod_available,
            firewall_backend: e.firewall_backend.clone(),
            kmod_version: e.kmod_version.clone(),
            ebpf_drops_process: e.ebpf_drops_process,
            ebpf_drops_file: e.ebpf_drops_file,
            ebpf_drops_network: e.ebpf_drops_network,
            ebpf_drops_security: e.ebpf_drops_security,
        })),
        EventKind::Detection(e) => Some(pb::agent_event::Kind::Detection(pb::DetectionEvent {
            rule_name: e.rule_name.clone(),
            severity: match e.severity {
                event::Severity::Low      => pb::Severity::Low.into(),
                event::Severity::Medium   => pb::Severity::Medium.into(),
                event::Severity::High     => pb::Severity::High.into(),
                event::Severity::Critical => pb::Severity::Critical.into(),
            },
            description: e.description.clone(),
            source_event_ids: e.source_event_ids.iter().map(|id| id.to_string()).collect(),
            pid: e.pid.unwrap_or(0),
            process_guid: e.process_guid.clone(),
        })),
        EventKind::PrivilegeChange(e) => Some(pb::agent_event::Kind::PrivilegeChange(pb::PrivilegeChangeEvent {
            pid: e.pid,
            user_id: e.user_id.clone(),
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            syscall: e.syscall.clone(),
            new_uid: e.new_uid.unwrap_or(u32::MAX),
            new_gid: e.new_gid.unwrap_or(u32::MAX),
        })),
        EventKind::ProcessAccess(e) => Some(pb::agent_event::Kind::ProcessAccess(pb::ProcessAccessEvent {
            pid: e.pid,
            target_pid: e.target_pid,
            user_id: e.user_id.clone(),
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            request: e.request,
            request_name: e.request_name.clone(),
        })),
        EventKind::FilePermChange(e) => Some(pb::agent_event::Kind::FilePermChange(pb::FilePermChangeEvent {
            pid: e.pid,
            user_id: e.user_id.clone(),
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            path: e.path.clone(),
            kind: e.kind.clone(),
            new_mode: e.new_mode.unwrap_or(u32::MAX),
            new_uid: e.new_uid.unwrap_or(u32::MAX),
            new_gid: e.new_gid.unwrap_or(u32::MAX),
        })),
        EventKind::MemoryMap(e) => Some(pb::agent_event::Kind::MemoryMap(pb::MemoryMapEvent {
            pid: e.pid,
            user_id: e.user_id.clone(),
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            addr: e.addr,
            len: e.len,
            prot: e.prot,
            flags: e.flags,
            is_exec: e.is_exec,
            is_write: e.is_write,
        })),
        EventKind::KernelModuleLoad(e) => Some(pb::agent_event::Kind::KernelModuleLoad(pb::KernelModuleEvent {
            pid: e.pid,
            user_id: e.user_id.clone(),
            process_name: e.process_name.clone(),
            process_guid: e.process_guid.clone(),
            module_name: e.module_name.clone(),
        })),
        EventKind::ProcessVmAccess(e) => Some(pb::agent_event::Kind::ProcessVmAccess(pb::ProcessVmEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            target_pid: e.target_pid, is_write: e.is_write,
        })),
        EventKind::MemfdCreate(e) => Some(pb::agent_event::Kind::MemfdCreate(pb::MemfdCreateEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            name: e.name.clone(), flags: e.flags,
        })),
        EventKind::BpfProgram(e) => Some(pb::agent_event::Kind::BpfProgram(pb::BpfProgramEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            bpf_cmd: e.bpf_cmd, bpf_cmd_name: e.bpf_cmd_name.clone(),
        })),
        EventKind::CapabilityChange(e) => Some(pb::agent_event::Kind::CapabilityChange(pb::CapabilityChangeEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            effective: e.effective, permitted: e.permitted, inheritable: e.inheritable,
        })),
        EventKind::ProcessSignal(e) => Some(pb::agent_event::Kind::ProcessSignal(pb::ProcessSignalEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            target_pid: e.target_pid, signal: e.signal, signal_name: e.signal_name.clone(),
        })),
        EventKind::NamespaceChange(e) => Some(pb::agent_event::Kind::NamespaceChange(pb::NamespaceChangeEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            syscall: e.syscall.clone(), flags: e.flags, flags_name: e.flags_name.clone(),
        })),
        EventKind::Keyctl(e) => Some(pb::agent_event::Kind::Keyctl(pb::KeyctlEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            operation: e.operation, operation_name: e.operation_name.clone(),
        })),
        EventKind::IoUring(e) => Some(pb::agent_event::Kind::IoUring(pb::IoUringEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            entries: e.entries,
        })),
        EventKind::Mount(e) => Some(pb::agent_event::Kind::Mount(pb::MountEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            source: e.source.clone(), target: e.target.clone(), fs_type: e.fs_type.clone(),
            flags: e.flags, is_umount: e.is_umount,
        })),
        EventKind::FileLink(e) => Some(pb::agent_event::Kind::FileLink(pb::FileLinkEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            src_path: e.src_path.clone(), dst_path: e.dst_path.clone(), is_symlink: e.is_symlink,
        })),
        EventKind::ProcessBlocked(e) => Some(pb::agent_event::Kind::ProcessBlocked(pb::ProcessBlockedEvent {
            pid: e.pid, user_id: e.user_id.clone(),
            process_name: e.process_name.clone(), process_guid: e.process_guid.clone(),
            path: e.path.clone(), exe_hash: e.exe_hash.clone(), exe_size: e.exe_size,
            rule_name: e.rule_name.clone(), match_type: e.match_type.clone(),
            match_value: e.match_value.clone(), cmdline: e.cmdline.clone(),
        })),
    };

    pb::AgentEvent {
        id: event.id.to_string(),
        timestamp: event.timestamp.to_rfc3339(),
        agent_id: event.agent_id.clone(),
        hostname: event.hostname.clone(),
        os: event.os.clone(),
        content_hash: event.content_hash.clone(),
        process_guid: event.process_guid.clone(),
        username: event.username.clone(),
        seqno: event.seqno,
        process_pid: event.process_pid,
        process_user_id: event.process_user_id.clone(),
        process_name: event.process_name.clone(),
        process_cmdline: event.process_cmdline.clone(),
        parent_process_guid: event.parent_process_guid.clone(),
        parent_pid: event.parent_pid,
        parent_user_id: event.parent_user_id.clone(),
        parent_username: event.parent_username.clone(),
        parent_process_name: event.parent_process_name.clone(),
        parent_process_cmdline: event.parent_process_cmdline.clone(),
        container_id: event.container_id.clone(),
        process_exe_hash: event.process_exe_hash.clone(),
        process_exe_size: event.process_exe_size,
        kind,
    }
}

fn process_to_proto(e: &event::ProcessEvent) -> pb::ProcessEvent {
    pb::ProcessEvent {
        pid: e.pid,
        parent_pid: e.parent_pid,
        name: e.name.clone(),
        path: e.path.clone(),
        cmdline: e.cmdline.clone(),
        user_id: e.user_id.clone(),
        start_time: e.start_time.to_rfc3339(),
        snapshot: e.snapshot,
        parent_process_guid: e.parent_process_guid.clone(),
        exit_code: e.exit_code.unwrap_or(0),
        ld_preload: e.ld_preload.clone(),
        exe_hash: e.exe_hash.clone(),
        exe_size: e.exe_size,
    }
}

fn file_to_proto(e: &event::FileEvent) -> pb::FileEvent {
    pb::FileEvent {
        path: e.path.clone(),
        pid: e.pid,
        process_name: e.process_name.clone(),
        process_guid: e.process_guid.clone(),
        user_id: e.user_id.clone(),
    }
}

fn net_to_proto(e: &event::NetworkEvent) -> pb::NetworkEvent {
    pb::NetworkEvent {
        pid: e.pid,
        process_name: e.process_name.clone(),
        process_guid: e.process_guid.clone(),
        src_addr: e.src_addr.clone(),
        src_port: e.src_port as u32,
        dst_addr: e.dst_addr.clone(),
        dst_port: e.dst_port as u32,
        protocol: match e.protocol {
            event::Protocol::Tcp => pb::Protocol::Tcp.into(),
            event::Protocol::Udp => pb::Protocol::Udp.into(),
        },
        user_id: e.user_id.clone(),
    }
}
