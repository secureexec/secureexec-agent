#![no_std]

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_FILENAME: usize  = 256;
pub const MAX_FS_TYPE: usize   = 32;
pub const MAX_DNS_PAYLOAD: usize = 256;

// ---------------------------------------------------------------------------
// Event tag constants — all ring buffers use tag-based dispatch.
// Tags need only be unique within their own ring buffer.
// ---------------------------------------------------------------------------

// PROCESS_EVENTS buffer tags
pub const PROC_EVT_EXEC: u8 = 0; // sched_process_exec
pub const PROC_EVT_EXIT: u8 = 1; // sched_process_exit
pub const PROC_EVT_FORK: u8 = 2; // sched_process_fork
pub const PROC_EVT_ARGV: u8 = 3; // sys_enter_execve (full argv + LD_PRELOAD)

// FILE_EVENTS buffer tags
pub const FILE_EVT_CREATE: u8 = 0;
pub const FILE_EVT_MODIFY: u8 = 1;
pub const FILE_EVT_DELETE: u8 = 2;
pub const FILE_EVT_RENAME: u8 = 3;

// NETWORK_EVENTS buffer tags (ip version + event type encoded in tag)
pub const NET_EVT_V4_CONNECT: u8 = 0;
pub const NET_EVT_V4_ACCEPT: u8  = 1;
pub const NET_EVT_V4_BIND: u8    = 2;
pub const NET_EVT_V6_CONNECT: u8 = 3;
pub const NET_EVT_V6_ACCEPT: u8  = 4;
pub const NET_EVT_V6_BIND: u8    = 5;
pub const NET_EVT_DNS_QUERY_V4: u8 = 6;
pub const NET_EVT_DNS_QUERY_V6: u8 = 7;

pub const NET_PROTO_TCP: u8 = 0;
pub const NET_PROTO_UDP: u8 = 1;

// SECURITY_EVENTS buffer tags
pub const SEC_EVT_PTRACE: u8       =  0;
pub const SEC_EVT_PRIV_CHANGE: u8  =  1;
pub const SEC_EVT_MMAP_EXEC: u8    =  2;
pub const SEC_EVT_KERNEL_MOD: u8   =  3;
pub const SEC_EVT_FILE_CHMOD: u8   =  4;
pub const SEC_EVT_FILE_CHOWN: u8   =  5;
pub const SEC_EVT_PROCESS_VM: u8   =  6;
pub const SEC_EVT_MEMFD_CREATE: u8 =  7;
pub const SEC_EVT_BPF_PROG: u8     =  8;
pub const SEC_EVT_CAPABILITY: u8   =  9;
pub const SEC_EVT_SIGNAL: u8       = 10;
pub const SEC_EVT_NAMESPACE: u8    = 11;
pub const SEC_EVT_KEYCTL: u8       = 12;
pub const SEC_EVT_IO_URING: u8     = 13;
pub const SEC_EVT_MOUNT: u8        = 14;
pub const SEC_EVT_UMOUNT: u8       = 15;
pub const SEC_EVT_SYMLINK: u8      = 16;
pub const SEC_EVT_HARDLINK: u8     = 17;

// ---------------------------------------------------------------------------
// Firewall eBPF map types and constants
// ---------------------------------------------------------------------------

/// Key for the FW_RULES hashmap — identifies a firewall whitelist entry.
/// Mirrors the kmod `SeFwRule` layout.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FwRuleKey {
    /// IPv4 address in network byte order; 0 = match any address.
    pub ip: u32,
    /// Port in host byte order; 0 = match any port.
    pub port: u16,
    /// Protocol: 6=TCP, 17=UDP, 0=any.
    pub proto: u8,
    /// Direction: 1=ingress, 2=egress, 0=any.
    pub direction: u8,
}

/// FW_MODE values stored in the `FW_MODE` BPF array map at index 0.
pub const FW_MODE_NORMAL: u8   = 0; // pass all traffic
pub const FW_MODE_ISOLATED: u8 = 1; // drop everything not whitelisted

/// Direction constants used in FwRuleKey (same as kmod SE_FW_DIR_*).
pub const FW_DIR_IN:  u8 = 1;
pub const FW_DIR_OUT: u8 = 2;
pub const FW_DIR_ANY: u8 = 0;

// ---------------------------------------------------------------------------
// Privilege-change sub-codes  (stored in PrivilegeChangeEvent.syscall)
// ---------------------------------------------------------------------------

pub const PRIV_SETUID: u8   = 0;
pub const PRIV_SETGID: u8   = 1;
pub const PRIV_SETREUID: u8 = 2;
pub const PRIV_SETREGID: u8 = 3;
pub const PRIV_SETRESUID: u8 = 4;
pub const PRIV_SETRESGID: u8 = 5;

/// Sentinel: caller passed -1 ("do not change this id").
pub const ID_UNCHANGED: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// PROCESS_EVENTS structs
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecEvent {
    pub event_tag: u8,        // PROC_EVT_EXEC
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_FILENAME],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitEvent {
    pub event_tag: u8,        // PROC_EVT_EXIT
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub exit_code: i32,
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessForkEvent {
    pub event_tag: u8,        // PROC_EVT_FORK
    pub _pad: [u8; 3],
    pub parent_pid: u32,
    pub parent_tgid: u32,
    pub child_pid: u32,
    pub child_tgid: u32,
    pub uid: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

pub const MAX_ARGV_ARGS: usize    = 16;
pub const MAX_ARG_SIZE: usize     = 64;
pub const MAX_LDPRELOAD_SIZE: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecArgvEvent {
    pub event_tag: u8,        // PROC_EVT_ARGV
    pub _pad: [u8; 3],
    pub tgid: u32,
    pub argc: u32,
    pub args: [[u8; MAX_ARG_SIZE]; MAX_ARGV_ARGS],
    /// First LD_PRELOAD= env var found in envp, or all zeros if absent.
    pub ld_preload: [u8; MAX_LDPRELOAD_SIZE],
}

// ---------------------------------------------------------------------------
// FILE_EVENTS structs
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEventData {
    pub event_tag: u8,        // FILE_EVT_CREATE / MODIFY / DELETE
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_FILENAME],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameEventData {
    pub event_tag: u8,        // FILE_EVT_RENAME
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub old_name: [u8; MAX_FILENAME],
    pub new_name: [u8; MAX_FILENAME],
}

// ---------------------------------------------------------------------------
// NETWORK_EVENTS structs
// ---------------------------------------------------------------------------

/// IPv4 network event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEventData {
    pub event_tag: u8,        // NET_EVT_V4_CONNECT / ACCEPT / BIND
    pub protocol: u8,         // NET_PROTO_TCP / UDP
    pub _pad: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub comm: [u8; TASK_COMM_LEN],
}

/// IPv6 network event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent6Data {
    pub event_tag: u8,        // NET_EVT_V6_CONNECT / ACCEPT
    pub protocol: u8,         // NET_PROTO_TCP / UDP
    pub _pad: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub saddr6: [u8; 16],
    pub daddr6: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub comm: [u8; TASK_COMM_LEN],
}

/// IPv4 DNS query event with bounded payload bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsQueryEventData {
    pub event_tag: u8,        // NET_EVT_DNS_QUERY_V4
    pub protocol: u8,         // NET_PROTO_TCP / UDP
    pub _pad: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub dns_len: u16,
    pub _pad2: u16,
    pub comm: [u8; TASK_COMM_LEN],
    pub payload: [u8; MAX_DNS_PAYLOAD],
}

/// IPv6 DNS query event with bounded payload bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsQueryEvent6Data {
    pub event_tag: u8,        // NET_EVT_DNS_QUERY_V6
    pub protocol: u8,         // NET_PROTO_TCP / UDP
    pub _pad: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub saddr6: [u8; 16],
    pub daddr6: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub dns_len: u16,
    pub _pad2: u16,
    pub comm: [u8; TASK_COMM_LEN],
    pub payload: [u8; MAX_DNS_PAYLOAD],
}

// ---------------------------------------------------------------------------
// SECURITY_EVENTS structs
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    pub event_tag: u8,        // SEC_EVT_PTRACE
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub request: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivilegeChangeEvent {
    pub event_tag: u8,        // SEC_EVT_PRIV_CHANGE
    pub syscall: u8,          // PRIV_SETUID / SETGID / etc.
    pub _pad: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub new_id1: u32,
    pub new_id2: u32,
    pub new_id3: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MmapExecEvent {
    pub event_tag: u8,        // SEC_EVT_MMAP_EXEC
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub prot: u32,
    pub flags: u32,
    pub _pad2: u32,
    pub len: u64,
    pub addr: u64,
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelModuleEvent {
    pub event_tag: u8,        // SEC_EVT_KERNEL_MOD
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub name: [u8; MAX_FILENAME],
}

/// chmod (SEC_EVT_FILE_CHMOD) or chown (SEC_EVT_FILE_CHOWN).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FilePermChangeEvent {
    pub event_tag: u8,        // SEC_EVT_FILE_CHMOD or SEC_EVT_FILE_CHOWN
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub mode: u32,            // new mode bits (chmod); ID_UNCHANGED for chown
    pub new_uid: u32,         // ID_UNCHANGED for chmod
    pub new_gid: u32,         // ID_UNCHANGED for chown
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_FILENAME],
}

/// process_vm_readv / process_vm_writev.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessVmEvent {
    pub event_tag: u8,        // SEC_EVT_PROCESS_VM
    pub is_write: u8,         // 1 = writev, 0 = readv
    pub _pad: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// memfd_create.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdCreateEvent {
    pub event_tag: u8,        // SEC_EVT_MEMFD_CREATE
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub flags: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub name: [u8; 64],
}

/// bpf() syscall.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfProgramEvent {
    pub event_tag: u8,        // SEC_EVT_BPF_PROG
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub bpf_cmd: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// capset.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapabilityChangeEvent {
    pub event_tag: u8,        // SEC_EVT_CAPABILITY
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// kill() to another process.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessSignalEvent {
    pub event_tag: u8,        // SEC_EVT_SIGNAL
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub signal: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// unshare() / setns().
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NamespaceChangeEvent {
    pub event_tag: u8,        // SEC_EVT_NAMESPACE
    pub syscall_type: u8,     // 0 = unshare, 1 = setns
    pub _pad: [u8; 2],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub flags: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// keyctl().
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyctlEvent {
    pub event_tag: u8,        // SEC_EVT_KEYCTL
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub operation: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// io_uring_setup().
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringSetupEvent {
    pub event_tag: u8,        // SEC_EVT_IO_URING
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub entries: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// mount() / umount2().
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountEventData {
    pub event_tag: u8,        // SEC_EVT_MOUNT or SEC_EVT_UMOUNT
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub flags: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub source: [u8; MAX_FILENAME],
    pub target: [u8; MAX_FILENAME],
    pub fs_type: [u8; MAX_FS_TYPE],
}

/// symlinkat() / linkat().
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileLinkEventData {
    pub event_tag: u8,        // SEC_EVT_SYMLINK or SEC_EVT_HARDLINK
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub _pad2: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub src_path: [u8; MAX_FILENAME],
    pub dst_path: [u8; MAX_FILENAME],
}

// ---------------------------------------------------------------------------
// Pod impls for userspace (aya)
// ---------------------------------------------------------------------------

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessExitEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessForkEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecArgvEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEventData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileRenameEventData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEventData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEvent6Data {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsQueryEventData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsQueryEvent6Data {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PtraceEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PrivilegeChangeEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for MmapExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for KernelModuleEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FilePermChangeEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessVmEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for MemfdCreateEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BpfProgramEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for CapabilityChangeEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessSignalEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NamespaceChangeEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for KeyctlEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IoUringSetupEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for MountEventData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileLinkEventData {}
#[cfg(feature = "user")]
// Safety: FwRuleKey is #[repr(C)] with no padding holes and all fields are POD.
unsafe impl aya::Pod for FwRuleKey {}
