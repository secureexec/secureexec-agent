use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use uuid::Uuid;

pub mod file;
pub mod misc;
pub mod network;
pub mod process;
pub mod security;

pub use file::{FileEvent, FilePermChangeEvent, FileLinkEvent, FileRenameEvent};
pub use misc::{
    AgentHeartbeatEvent, AgentLifecycleEvent, DetectionEvent, ProcessBlockedEvent,
    RegistryEvent, Severity, UserLogonEvent,
};
pub use network::{DnsEvent, NetworkEvent, Protocol};
pub use process::ProcessEvent;
pub use security::{
    BpfProgramEvent, CapabilityChangeEvent, IoUringEvent, KeyctlEvent, KernelModuleEvent,
    MemfdCreateEvent, MemoryMapEvent, MountEvent, NamespaceChangeEvent, ProcessAccessEvent,
    ProcessSignalEvent, ProcessVmEvent, PrivilegeChangeEvent,
};

static SEQNO: AtomicI64 = AtomicI64::new(0);

/// Set the starting sequence number (call once at agent startup from config).
pub fn init_seqno(start: i64) {
    SEQNO.store(start, Ordering::Relaxed);
}

/// Return the current (next-to-be-assigned) sequence number.
pub fn current_seqno() -> i64 {
    SEQNO.load(Ordering::Relaxed)
}

fn next_seqno() -> i64 {
    SEQNO.fetch_add(1, Ordering::Relaxed)
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Trait for computing a SHA-1 content hash of an event body.
/// Each struct feeds its meaningful fields into the hasher directly,
/// avoiding JSON serialization overhead.
pub trait ContentHash {
    fn content_hash_update(&self, hasher: &mut Sha1);

    fn content_hash(&self) -> [u8; 20] {
        let mut hasher = Sha1::new();
        self.content_hash_update(&mut hasher);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub seqno: i64,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub content_hash: String,
    /// Unique process identifier (SHA-256 of pid+start_time) resolved from the
    /// process table.  Empty for event kinds that have no associated PID.
    #[serde(default)]
    pub process_guid: String,
    /// Username of the process owner (uid→name resolved on Linux; empty on other OSes).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Container ID from cgroup if the process runs inside a container; empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container_id: String,
    /// Process context enriched from the process table — always present when a PID is known.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub process_pid: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub process_user_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub process_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub process_cmdline: String,
    /// Parent process context enriched from the process table.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_process_guid: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub parent_pid: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_user_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_process_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_process_cmdline: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub process_exe_hash: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub process_exe_size: u64,
    pub kind: EventKind,
}

impl Event {
    pub fn new(hostname: String, kind: EventKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            seqno: next_seqno(),
            timestamp: Utc::now(),
            agent_id: String::new(),
            hostname,
            os: String::new(),
            content_hash: String::new(),
            process_guid: String::new(),
            username: String::new(),
            container_id: String::new(),
            process_pid: 0,
            process_user_id: String::new(),
            process_name: String::new(),
            process_cmdline: String::new(),
            parent_process_guid: String::new(),
            parent_pid: 0,
            parent_user_id: String::new(),
            parent_username: String::new(),
            parent_process_name: String::new(),
            parent_process_cmdline: String::new(),
            process_exe_hash: String::new(),
            process_exe_size: 0,
            kind,
        }
    }

    /// Compute the SHA-1 content hash and store the hex string in
    /// `self.content_hash`.  Call this after all fields (agent_id, os, etc.)
    /// are finalised.
    pub fn compute_hash(&mut self) {
        let raw: [u8; 20] = self.content_hash();
        self.content_hash = hex::encode(raw);
    }
}

impl ContentHash for Event {
    fn content_hash_update(&self, hasher: &mut Sha1) {
        hasher.update(self.agent_id.as_bytes());
        hasher.update(self.hostname.as_bytes());
        hasher.update(self.os.as_bytes());
        self.kind.content_hash_update(hasher);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventKind {
    ProcessCreate(ProcessEvent),
    ProcessFork(ProcessEvent),
    ProcessExit(ProcessEvent),
    FileCreate(FileEvent),
    FileModify(FileEvent),
    FileDelete(FileEvent),
    FileRename(FileRenameEvent),
    NetworkConnect(NetworkEvent),
    NetworkListen(NetworkEvent),
    DnsQuery(DnsEvent),
    RegistryWrite(RegistryEvent),
    UserLogon(UserLogonEvent),
    AgentStarted(AgentLifecycleEvent),
    AgentStopping(AgentLifecycleEvent),
    AgentHeartbeat(AgentHeartbeatEvent),
    Detection(DetectionEvent),
    // Security events (existing)
    PrivilegeChange(PrivilegeChangeEvent),
    ProcessAccess(ProcessAccessEvent),
    FilePermChange(FilePermChangeEvent),
    MemoryMap(MemoryMapEvent),
    KernelModuleLoad(KernelModuleEvent),
    // Security events (new)
    ProcessVmAccess(ProcessVmEvent),
    MemfdCreate(MemfdCreateEvent),
    BpfProgram(BpfProgramEvent),
    CapabilityChange(CapabilityChangeEvent),
    ProcessSignal(ProcessSignalEvent),
    NamespaceChange(NamespaceChangeEvent),
    Keyctl(KeyctlEvent),
    IoUring(IoUringEvent),
    Mount(MountEvent),
    FileLink(FileLinkEvent),
    ProcessBlocked(ProcessBlockedEvent),
}

impl EventKind {
    /// Extract the PID carried by this event kind, if any.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::ProcessCreate(e) | Self::ProcessFork(e) | Self::ProcessExit(e) => Some(e.pid),
            Self::FileCreate(e) | Self::FileModify(e) | Self::FileDelete(e) => Some(e.pid),
            Self::FileRename(e) => Some(e.pid),
            Self::NetworkConnect(e) | Self::NetworkListen(e) => Some(e.pid),
            Self::DnsQuery(e) => Some(e.pid),
            Self::RegistryWrite(e) => Some(e.pid),
            Self::Detection(e) => e.pid,
            Self::PrivilegeChange(e) => Some(e.pid),
            Self::ProcessAccess(e) => Some(e.pid),
            Self::FilePermChange(e) => Some(e.pid),
            Self::MemoryMap(e) => Some(e.pid),
            Self::KernelModuleLoad(e) => Some(e.pid),
            Self::ProcessVmAccess(e) => Some(e.pid),
            Self::MemfdCreate(e) => Some(e.pid),
            Self::BpfProgram(e) => Some(e.pid),
            Self::CapabilityChange(e) => Some(e.pid),
            Self::ProcessSignal(e) => Some(e.pid),
            Self::NamespaceChange(e) => Some(e.pid),
            Self::Keyctl(e) => Some(e.pid),
            Self::IoUring(e) => Some(e.pid),
            Self::Mount(e) => Some(e.pid),
            Self::FileLink(e) => Some(e.pid),
            Self::ProcessBlocked(e) => Some(e.pid),
            Self::UserLogon(_)
            | Self::AgentStarted(_)
            | Self::AgentStopping(_)
            | Self::AgentHeartbeat(_) => None,
        }
    }

    /// Extract the calling process user ID carried by this event kind, if any.
    pub fn user_id(&self) -> Option<&str> {
        match self {
            Self::ProcessCreate(e) | Self::ProcessFork(e) | Self::ProcessExit(e) => Some(&e.user_id),
            Self::FileCreate(e) | Self::FileModify(e) | Self::FileDelete(e) => Some(&e.user_id),
            Self::FileRename(e) => Some(&e.user_id),
            Self::NetworkConnect(e) | Self::NetworkListen(e) => Some(&e.user_id),
            Self::PrivilegeChange(e) => Some(&e.user_id),
            Self::ProcessAccess(e) => Some(&e.user_id),
            Self::FilePermChange(e) => Some(&e.user_id),
            Self::MemoryMap(e) => Some(&e.user_id),
            Self::KernelModuleLoad(e) => Some(&e.user_id),
            Self::ProcessVmAccess(e) => Some(&e.user_id),
            Self::MemfdCreate(e) => Some(&e.user_id),
            Self::BpfProgram(e) => Some(&e.user_id),
            Self::CapabilityChange(e) => Some(&e.user_id),
            Self::ProcessSignal(e) => Some(&e.user_id),
            Self::NamespaceChange(e) => Some(&e.user_id),
            Self::Keyctl(e) => Some(&e.user_id),
            Self::IoUring(e) => Some(&e.user_id),
            Self::Mount(e) => Some(&e.user_id),
            Self::FileLink(e) => Some(&e.user_id),
            Self::DnsQuery(e) => Some(&e.user_id),
            Self::ProcessBlocked(e) => Some(&e.user_id),
            _ => None,
        }
    }

    /// Extract the process start time carried by this event kind, if any.
    /// Used for verified process table lookup to prevent PID reuse mismatches.
    pub fn process_start_time(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::ProcessCreate(e) | Self::ProcessFork(e) | Self::ProcessExit(e) => Some(e.start_time),
            Self::FileCreate(e) | Self::FileModify(e) | Self::FileDelete(e) => e.process_start_time,
            Self::FileRename(e) => e.process_start_time,
            Self::NetworkConnect(e) | Self::NetworkListen(e) => e.process_start_time,
            Self::DnsQuery(e) => e.process_start_time,
            Self::RegistryWrite(e) => e.process_start_time,
            Self::PrivilegeChange(e) => e.process_start_time,
            Self::ProcessAccess(e) => e.process_start_time,
            Self::FilePermChange(e) => e.process_start_time,
            Self::MemoryMap(e) => e.process_start_time,
            Self::KernelModuleLoad(e) => e.process_start_time,
            Self::ProcessVmAccess(e) => e.process_start_time,
            Self::MemfdCreate(e) => e.process_start_time,
            Self::BpfProgram(e) => e.process_start_time,
            Self::CapabilityChange(e) => e.process_start_time,
            Self::ProcessSignal(e) => e.process_start_time,
            Self::NamespaceChange(e) => e.process_start_time,
            Self::Keyctl(e) => e.process_start_time,
            Self::IoUring(e) => e.process_start_time,
            Self::Mount(e) => e.process_start_time,
            Self::FileLink(e) => e.process_start_time,
            Self::Detection(_)
            | Self::ProcessBlocked(_)
            | Self::UserLogon(_)
            | Self::AgentStarted(_)
            | Self::AgentStopping(_)
            | Self::AgentHeartbeat(_) => None,
        }
    }

    /// Return the process name stored inside the inner event struct (from
    /// eBPF `task->comm` or procfs cache).  Used as fallback when the process
    /// table lookup in the pipeline fails for short-lived processes.
    pub fn inner_process_name(&self) -> Option<&str> {
        match self {
            Self::ProcessCreate(e) | Self::ProcessFork(e) | Self::ProcessExit(e) => Some(&e.name),
            Self::FileCreate(e) | Self::FileModify(e) | Self::FileDelete(e) => Some(&e.process_name),
            Self::FileRename(e) => Some(&e.process_name),
            Self::NetworkConnect(e) | Self::NetworkListen(e) => Some(&e.process_name),
            Self::DnsQuery(e) => Some(&e.process_name),
            Self::RegistryWrite(e) => Some(&e.process_name),
            Self::PrivilegeChange(e) => Some(&e.process_name),
            Self::ProcessAccess(e) => Some(&e.process_name),
            Self::FilePermChange(e) => Some(&e.process_name),
            Self::MemoryMap(e) => Some(&e.process_name),
            Self::KernelModuleLoad(e) => Some(&e.process_name),
            Self::ProcessVmAccess(e) => Some(&e.process_name),
            Self::MemfdCreate(e) => Some(&e.process_name),
            Self::BpfProgram(e) => Some(&e.process_name),
            Self::CapabilityChange(e) => Some(&e.process_name),
            Self::ProcessSignal(e) => Some(&e.process_name),
            Self::NamespaceChange(e) => Some(&e.process_name),
            Self::Keyctl(e) => Some(&e.process_name),
            Self::IoUring(e) => Some(&e.process_name),
            Self::Mount(e) => Some(&e.process_name),
            Self::FileLink(e) => Some(&e.process_name),
            Self::ProcessBlocked(e) => Some(&e.process_name),
            Self::Detection(_)
            | Self::UserLogon(_)
            | Self::AgentStarted(_)
            | Self::AgentStopping(_)
            | Self::AgentHeartbeat(_) => None,
        }
    }

    pub fn inner_process_cmdline(&self) -> Option<&str> {
        match self {
            Self::ProcessCreate(e) | Self::ProcessFork(e) | Self::ProcessExit(e) => Some(&e.cmdline),
            _ => None,
        }
    }

    /// Stamp `process_guid` (and fill empty `process_name`) on inner event
    /// structs that carry a PID.
    pub fn enrich_process(&mut self, uid: &str, name: &str) {
        match self {
            Self::FileCreate(e) | Self::FileModify(e) | Self::FileDelete(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::FileRename(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::NetworkConnect(e) | Self::NetworkListen(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::DnsQuery(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::RegistryWrite(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::PrivilegeChange(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::ProcessAccess(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::FilePermChange(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::MemoryMap(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::KernelModuleLoad(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() {
                    e.process_name = name.to_string();
                }
            }
            Self::ProcessVmAccess(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::MemfdCreate(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::BpfProgram(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::CapabilityChange(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::ProcessSignal(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::NamespaceChange(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::Keyctl(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::IoUring(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::Mount(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::FileLink(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            Self::ProcessBlocked(e) => {
                e.process_guid = uid.to_string();
                if e.process_name.is_empty() { e.process_name = name.to_string(); }
            }
            _ => {}
        }
    }

    /// Stamp `parent_process_guid` on process event structs from the process
    /// table entry.
    pub fn enrich_parent_process_guid(&mut self, parent_uid: &str) {
        match self {
            Self::ProcessCreate(e) | Self::ProcessFork(e) | Self::ProcessExit(e) => {
                if e.parent_process_guid.is_empty() {
                    e.parent_process_guid = parent_uid.to_string();
                }
            }
            _ => {}
        }
    }
}

impl ContentHash for EventKind {
    fn content_hash_update(&self, h: &mut Sha1) {
        match self {
            Self::ProcessCreate(e)   => { h.update(b"ProcessCreate");   e.content_hash_update(h); }
            Self::ProcessFork(e)     => { h.update(b"ProcessFork");     e.content_hash_update(h); }
            Self::ProcessExit(e)     => { h.update(b"ProcessExit");     e.content_hash_update(h); }
            Self::FileCreate(e)      => { h.update(b"FileCreate");      e.content_hash_update(h); }
            Self::FileModify(e)      => { h.update(b"FileModify");      e.content_hash_update(h); }
            Self::FileDelete(e)      => { h.update(b"FileDelete");      e.content_hash_update(h); }
            Self::FileRename(e)      => { h.update(b"FileRename");      e.content_hash_update(h); }
            Self::NetworkConnect(e)  => { h.update(b"NetworkConnect");  e.content_hash_update(h); }
            Self::NetworkListen(e)   => { h.update(b"NetworkListen");   e.content_hash_update(h); }
            Self::DnsQuery(e)        => { h.update(b"DnsQuery");        e.content_hash_update(h); }
            Self::RegistryWrite(e)   => { h.update(b"RegistryWrite");   e.content_hash_update(h); }
            Self::UserLogon(e)       => { h.update(b"UserLogon");       e.content_hash_update(h); }
            Self::AgentStarted(e)    => { h.update(b"AgentStarted");    e.content_hash_update(h); }
            Self::AgentStopping(e)   => { h.update(b"AgentStopping");   e.content_hash_update(h); }
            Self::AgentHeartbeat(e)  => { h.update(b"AgentHeartbeat");  e.content_hash_update(h); }
            Self::Detection(e)       => { h.update(b"Detection");       e.content_hash_update(h); }
            Self::PrivilegeChange(e)  => { h.update(b"PrivilegeChange");  e.content_hash_update(h); }
            Self::ProcessAccess(e)    => { h.update(b"ProcessAccess");    e.content_hash_update(h); }
            Self::FilePermChange(e)   => { h.update(b"FilePermChange");   e.content_hash_update(h); }
            Self::MemoryMap(e)        => { h.update(b"MemoryMap");        e.content_hash_update(h); }
            Self::KernelModuleLoad(e) => { h.update(b"KernelModuleLoad"); e.content_hash_update(h); }
            Self::ProcessVmAccess(e)  => { h.update(b"ProcessVmAccess");  e.content_hash_update(h); }
            Self::MemfdCreate(e)      => { h.update(b"MemfdCreate");      e.content_hash_update(h); }
            Self::BpfProgram(e)       => { h.update(b"BpfProgram");       e.content_hash_update(h); }
            Self::CapabilityChange(e) => { h.update(b"CapabilityChange"); e.content_hash_update(h); }
            Self::ProcessSignal(e)    => { h.update(b"ProcessSignal");    e.content_hash_update(h); }
            Self::NamespaceChange(e)  => { h.update(b"NamespaceChange");  e.content_hash_update(h); }
            Self::Keyctl(e)           => { h.update(b"Keyctl");           e.content_hash_update(h); }
            Self::IoUring(e)          => { h.update(b"IoUring");          e.content_hash_update(h); }
            Self::Mount(e)            => { h.update(b"Mount");            e.content_hash_update(h); }
            Self::FileLink(e)         => { h.update(b"FileLink");         e.content_hash_update(h); }
            Self::ProcessBlocked(e)   => { h.update(b"ProcessBlocked");   e.content_hash_update(h); }
        }
    }
}
