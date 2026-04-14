use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use super::ContentHash;

/// Privilege escalation via setuid/setgid family of syscalls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeChangeEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    /// Syscall name: "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid".
    pub syscall: String,
    /// New effective uid being requested; `None` for gid-only syscalls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_uid: Option<u32>,
    /// New effective gid being requested; `None` for uid-only syscalls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_gid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for PrivilegeChangeEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.syscall.as_bytes());
        if let Some(u) = self.new_uid { h.update(u.to_le_bytes()); }
        if let Some(g) = self.new_gid { h.update(g.to_le_bytes()); }
    }
}

/// Process accessed another process via ptrace (injection / debug detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAccessEvent {
    /// Calling (attaching) process PID.
    pub pid: u32,
    /// Target (victim) process PID.
    pub target_pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    /// Raw ptrace request code.
    pub request: u32,
    /// Human-readable ptrace request name (e.g. "PTRACE_ATTACH").
    pub request_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for ProcessAccessEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.target_pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.request.to_le_bytes());
    }
}

/// Memory mapping with write+execute permissions (RWX page — injection indicator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMapEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub addr: u64,
    pub len: u64,
    /// Raw mmap prot flags.
    pub prot: u32,
    /// Raw mmap flags.
    pub flags: u32,
    pub is_exec: bool,
    pub is_write: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for MemoryMapEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.addr.to_le_bytes());
        h.update(self.len.to_le_bytes());
        h.update(self.prot.to_le_bytes());
    }
}

/// Kernel module loaded (rootkit detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModuleEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub module_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for KernelModuleEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.module_name.as_bytes());
    }
}

/// process_vm_readv / process_vm_writev — cross-process memory access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessVmEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub target_pid: u32,
    pub is_write: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for ProcessVmEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.target_pid.to_le_bytes());
        h.update(self.process_name.as_bytes());
    }
}

/// memfd_create — anonymous in-memory file (fileless attack indicator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemfdCreateEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    /// Name passed to memfd_create (usually empty or a short tag).
    pub name: String,
    pub flags: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for MemfdCreateEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.name.as_bytes());
    }
}

/// bpf() syscall — eBPF program or map creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfProgramEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub bpf_cmd: u32,
    pub bpf_cmd_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for BpfProgramEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.bpf_cmd.to_le_bytes());
    }
}

/// capset — Linux capability set modification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityChangeEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    /// Low 32 bits of effective capability bitmask being set.
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for CapabilityChangeEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.effective.to_le_bytes());
        h.update(self.permitted.to_le_bytes());
    }
}

/// kill() sent to a different process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSignalEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub target_pid: u32,
    pub signal: u32,
    pub signal_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for ProcessSignalEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.target_pid.to_le_bytes());
        h.update(self.signal.to_le_bytes());
        h.update(self.process_name.as_bytes());
    }
}

/// unshare() / setns() — Linux namespace manipulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceChangeEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    /// "unshare" or "setns".
    pub syscall: String,
    pub flags: u32,
    pub flags_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for NamespaceChangeEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.syscall.as_bytes());
        h.update(self.flags.to_le_bytes());
    }
}

/// keyctl() — kernel keyring operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyctlEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub operation: u32,
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for KeyctlEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.operation.to_le_bytes());
    }
}

/// io_uring_setup() — io_uring ring creation (evasion technique).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoUringEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub entries: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for IoUringEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.entries.to_le_bytes());
    }
}

/// mount() / umount2() — filesystem mount operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub flags: u32,
    pub is_umount: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for MountEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.target.as_bytes());
        h.update(self.source.as_bytes());
    }
}
