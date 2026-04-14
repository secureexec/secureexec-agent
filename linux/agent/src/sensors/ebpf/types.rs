use std::sync::atomic::{AtomicU64, Ordering};

/// Cumulative ring-buffer drop counters read from kernel PerCpuArray maps.
/// Updated periodically by the eBPF poll thread; read by the heartbeat.
pub struct EbpfDropCounters {
    pub process: AtomicU64,
    pub file: AtomicU64,
    pub network: AtomicU64,
    pub security: AtomicU64,
    /// Events dropped because the userspace mpsc channel was full.
    pub channel_full: AtomicU64,
}

impl EbpfDropCounters {
    pub fn new() -> Self {
        Self {
            process: AtomicU64::new(0),
            file: AtomicU64::new(0),
            network: AtomicU64::new(0),
            security: AtomicU64::new(0),
            channel_full: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> [u64; 4] {
        [
            self.process.load(Ordering::Relaxed),
            self.file.load(Ordering::Relaxed),
            self.network.load(Ordering::Relaxed),
            self.security.load(Ordering::Relaxed),
        ]
    }
}

/// Internal event enum bridging eBPF ring buffers → pipeline.
/// One variant per event type parsed from the four ring buffers.
pub(super) enum BpfEvent {
    ExecArgv {
        tgid: u32,
        cmdline: String,
        ld_preload: String,
    },
    ProcessExec {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
    },
    ProcessExit {
        pid: u32,
        exit_code: i32,
        comm: String,
    },
    ProcessFork {
        parent_pid: u32,
        child_pid: u32,
        uid: u32,
        comm: String,
    },
    FileCreate {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
    },
    FileModify {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
    },
    FileDelete {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
    },
    FileRename {
        pid: u32,
        uid: u32,
        comm: String,
        old_name: String,
        new_name: String,
    },
    NetConnect {
        pid: u32,
        uid: u32,
        comm: String,
        src_addr: String,
        sport: u16,
        dst_addr: String,
        dport: u16,
        protocol: u8,
    },
    NetAccept {
        pid: u32,
        uid: u32,
        comm: String,
        src_addr: String,
        sport: u16,
        dst_addr: String,
        dport: u16,
        protocol: u8,
    },
    NetBind {
        pid: u32,
        uid: u32,
        comm: String,
        src_addr: String,
        sport: u16,
        protocol: u8,
    },
    DnsQuery {
        pid: u32,
        uid: u32,
        comm: String,
        query: String,
    },
    PrivChange {
        pid: u32,
        uid: u32,
        comm: String,
        syscall: u8,
        new_id1: u32,
        new_id2: u32,
    },
    Ptrace {
        pid: u32,
        uid: u32,
        comm: String,
        target_pid: u32,
        request: u32,
    },
    FilePerm {
        pid: u32,
        uid: u32,
        comm: String,
        is_chown: bool,
        mode: u32,
        new_uid: u32,
        new_gid: u32,
        filename: String,
    },
    MmapExec {
        pid: u32,
        uid: u32,
        comm: String,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
    },
    KernelMod {
        pid: u32,
        uid: u32,
        comm: String,
        name: String,
    },
    ProcessVm {
        pid: u32,
        uid: u32,
        comm: String,
        target_pid: u32,
        is_write: bool,
    },
    Memfd {
        pid: u32,
        uid: u32,
        comm: String,
        flags: u32,
        name: String,
    },
    BpfProg {
        pid: u32,
        uid: u32,
        comm: String,
        bpf_cmd: u32,
    },
    Capability {
        pid: u32,
        uid: u32,
        comm: String,
        effective: u32,
        permitted: u32,
        inheritable: u32,
    },
    Signal {
        pid: u32,
        uid: u32,
        comm: String,
        target_pid: u32,
        signal: u32,
    },
    Namespace {
        pid: u32,
        uid: u32,
        comm: String,
        syscall_type: u8,
        flags: u32,
    },
    Keyctl {
        pid: u32,
        uid: u32,
        comm: String,
        operation: u32,
    },
    IoUring {
        pid: u32,
        uid: u32,
        comm: String,
        entries: u32,
    },
    Mount {
        pid: u32,
        uid: u32,
        comm: String,
        is_umount: bool,
        source: String,
        target: String,
        fs_type: String,
        flags: u32,
    },
    FileLink {
        pid: u32,
        uid: u32,
        comm: String,
        is_symlink: bool,
        src_path: String,
        dst_path: String,
    },
}
