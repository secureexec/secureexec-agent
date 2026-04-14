use std::mem::size_of;

use secureexec_ebpf_common::{
    BpfProgramEvent as BpfBpfProg,
    CapabilityChangeEvent as BpfCapability,
    DnsQueryEvent6Data,
    DnsQueryEventData,
    ExecArgvEvent,
    FileLinkEventData as BpfFileLink,
    FilePermChangeEvent as BpfFilePerm,
    FileRenameEventData,
    FileEventData,
    IoUringSetupEvent as BpfIoUring,
    KeyctlEvent as BpfKeyctl,
    KernelModuleEvent as BpfKernelMod,
    MemfdCreateEvent as BpfMemfd,
    MmapExecEvent as BpfMmapExec,
    MountEventData as BpfMount,
    NamespaceChangeEvent as BpfNamespace,
    NetworkEvent6Data,
    NetworkEventData,
    PrivilegeChangeEvent as BpfPrivChange,
    ProcessExecEvent,
    ProcessExitEvent,
    ProcessForkEvent,
    ProcessSignalEvent as BpfSignal,
    ProcessVmEvent as BpfProcessVm,
    PtraceEvent as BpfPtrace,
    // PROCESS_EVENTS tags
    PROC_EVT_EXEC, PROC_EVT_EXIT, PROC_EVT_FORK, PROC_EVT_ARGV,
    // FILE_EVENTS tags
    FILE_EVT_CREATE, FILE_EVT_MODIFY, FILE_EVT_DELETE, FILE_EVT_RENAME,
    // NETWORK_EVENTS tags
    NET_EVT_V4_CONNECT, NET_EVT_V4_ACCEPT, NET_EVT_V4_BIND,
    NET_EVT_V6_CONNECT, NET_EVT_V6_ACCEPT, NET_EVT_V6_BIND,
    NET_EVT_DNS_QUERY_V4, NET_EVT_DNS_QUERY_V6,
    // SECURITY_EVENTS tags
    SEC_EVT_PTRACE, SEC_EVT_PRIV_CHANGE, SEC_EVT_MMAP_EXEC, SEC_EVT_KERNEL_MOD,
    SEC_EVT_FILE_CHMOD, SEC_EVT_FILE_CHOWN,
    SEC_EVT_PROCESS_VM, SEC_EVT_MEMFD_CREATE, SEC_EVT_BPF_PROG, SEC_EVT_CAPABILITY,
    SEC_EVT_SIGNAL, SEC_EVT_NAMESPACE, SEC_EVT_KEYCTL, SEC_EVT_IO_URING,
    SEC_EVT_MOUNT, SEC_EVT_UMOUNT, SEC_EVT_SYMLINK, SEC_EVT_HARDLINK,
    // Other
    MAX_LDPRELOAD_SIZE,
};

use super::helpers::{argv_to_cmdline, bytes_to_ipv6_string, bytes_to_string, parse_dns_query_name, u32_to_ipv4_string};
use super::types::BpfEvent;

// ---------------------------------------------------------------------------
// PROCESS_EVENTS ring buffer parser
// ---------------------------------------------------------------------------

pub(super) fn parse_process_event(data: &[u8]) -> Option<BpfEvent> {
    if data.is_empty() { return None; }
    match data[0] {
        PROC_EVT_EXEC => {
            if data.len() < size_of::<ProcessExecEvent>() { return None; }
            // Safety: bounds-checked above; ProcessExecEvent is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const ProcessExecEvent) };
            Some(BpfEvent::ProcessExec {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                filename: bytes_to_string(&e.filename),
            })
        }
        PROC_EVT_EXIT => {
            if data.len() < size_of::<ProcessExitEvent>() { return None; }
            // Safety: bounds-checked above; ProcessExitEvent is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const ProcessExitEvent) };
            Some(BpfEvent::ProcessExit {
                pid: e.tgid,
                exit_code: e.exit_code,
                comm: bytes_to_string(&e.comm),
            })
        }
        PROC_EVT_FORK => {
            if data.len() < size_of::<ProcessForkEvent>() { return None; }
            // Safety: bounds-checked above; ProcessForkEvent is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const ProcessForkEvent) };
            Some(BpfEvent::ProcessFork {
                parent_pid: e.parent_tgid,
                child_pid: e.child_pid,
                uid: e.uid,
                comm: bytes_to_string(&e.comm),
            })
        }
        PROC_EVT_ARGV => {
            if data.len() < size_of::<ExecArgvEvent>() { return None; }
            // Safety: bounds-checked above; ExecArgvEvent is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const ExecArgvEvent) };
            let cmdline = argv_to_cmdline(e.argc, &e.args);
            let raw: &[u8; MAX_LDPRELOAD_SIZE] = &e.ld_preload;
            let ld_preload = bytes_to_string(raw)
                .strip_prefix("LD_PRELOAD=")
                .map(|s| s.to_string())
                .unwrap_or_default();
            Some(BpfEvent::ExecArgv { tgid: e.tgid, cmdline, ld_preload })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// FILE_EVENTS ring buffer parser
// ---------------------------------------------------------------------------

pub(super) fn parse_file_event(data: &[u8]) -> Option<BpfEvent> {
    if data.is_empty() { return None; }
    let tag = data[0];
    match tag {
        FILE_EVT_CREATE | FILE_EVT_MODIFY | FILE_EVT_DELETE => {
            if data.len() < size_of::<FileEventData>() { return None; }
            // Safety: bounds-checked above; FileEventData is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const FileEventData) };
            let comm     = bytes_to_string(&e.comm);
            let filename = bytes_to_string(&e.filename);
            match tag {
                FILE_EVT_CREATE => Some(BpfEvent::FileCreate { pid: e.tgid, uid: e.uid, comm, filename }),
                FILE_EVT_MODIFY => Some(BpfEvent::FileModify { pid: e.tgid, uid: e.uid, comm, filename }),
                FILE_EVT_DELETE => Some(BpfEvent::FileDelete { pid: e.tgid, uid: e.uid, comm, filename }),
                _ => unreachable!(),
            }
        }
        FILE_EVT_RENAME => {
            if data.len() < size_of::<FileRenameEventData>() { return None; }
            // Safety: bounds-checked above; FileRenameEventData is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const FileRenameEventData) };
            Some(BpfEvent::FileRename {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                old_name: bytes_to_string(&e.old_name),
                new_name: bytes_to_string(&e.new_name),
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// NETWORK_EVENTS ring buffer parser
// ---------------------------------------------------------------------------

pub(super) fn parse_network_event(data: &[u8]) -> Option<BpfEvent> {
    if data.is_empty() { return None; }
    let tag = data[0];
    match tag {
        NET_EVT_V4_CONNECT | NET_EVT_V4_ACCEPT | NET_EVT_V4_BIND => {
            if data.len() < size_of::<NetworkEventData>() { return None; }
            // Safety: bounds-checked above; NetworkEventData is repr(C).
            let e    = unsafe { &*(data.as_ptr() as *const NetworkEventData) };
            let comm = bytes_to_string(&e.comm);
            let src  = u32_to_ipv4_string(e.saddr);
            let dst  = u32_to_ipv4_string(e.daddr);
            match tag {
                NET_EVT_V4_CONNECT => Some(BpfEvent::NetConnect {
                    pid: e.tgid, uid: e.uid, comm, src_addr: src, sport: e.sport,
                    dst_addr: dst, dport: e.dport, protocol: e.protocol,
                }),
                NET_EVT_V4_ACCEPT => Some(BpfEvent::NetAccept {
                    pid: e.tgid, uid: e.uid, comm, src_addr: src, sport: e.sport,
                    dst_addr: dst, dport: e.dport, protocol: e.protocol,
                }),
                NET_EVT_V4_BIND => Some(BpfEvent::NetBind {
                    pid: e.tgid, uid: e.uid, comm, src_addr: src, sport: e.sport,
                    protocol: e.protocol,
                }),
                _ => unreachable!(),
            }
        }
        NET_EVT_V6_CONNECT | NET_EVT_V6_ACCEPT | NET_EVT_V6_BIND => {
            if data.len() < size_of::<NetworkEvent6Data>() { return None; }
            // Safety: bounds-checked above; NetworkEvent6Data is repr(C).
            let e    = unsafe { &*(data.as_ptr() as *const NetworkEvent6Data) };
            let comm = bytes_to_string(&e.comm);
            let src  = bytes_to_ipv6_string(&e.saddr6);
            let dst  = bytes_to_ipv6_string(&e.daddr6);
            match tag {
                NET_EVT_V6_CONNECT => Some(BpfEvent::NetConnect {
                    pid: e.tgid, uid: e.uid, comm, src_addr: src, sport: e.sport,
                    dst_addr: dst, dport: e.dport, protocol: e.protocol,
                }),
                NET_EVT_V6_ACCEPT => Some(BpfEvent::NetAccept {
                    pid: e.tgid, uid: e.uid, comm, src_addr: src, sport: e.sport,
                    dst_addr: dst, dport: e.dport, protocol: e.protocol,
                }),
                NET_EVT_V6_BIND => Some(BpfEvent::NetBind {
                    pid: e.tgid, uid: e.uid, comm, src_addr: src, sport: e.sport,
                    protocol: e.protocol,
                }),
                _ => unreachable!(),
            }
        }
        NET_EVT_DNS_QUERY_V4 => {
            if data.len() < size_of::<DnsQueryEventData>() { return None; }
            // Safety: bounds-checked above; DnsQueryEventData is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const DnsQueryEventData) };
            let payload_len = (e.dns_len as usize).min(e.payload.len());
            let query = parse_dns_query_name(&e.payload[..payload_len])?;
            Some(BpfEvent::DnsQuery {
                pid: e.tgid,
                uid: e.uid,
                comm: bytes_to_string(&e.comm),
                query,
            })
        }
        NET_EVT_DNS_QUERY_V6 => {
            if data.len() < size_of::<DnsQueryEvent6Data>() { return None; }
            // Safety: bounds-checked above; DnsQueryEvent6Data is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const DnsQueryEvent6Data) };
            let payload_len = (e.dns_len as usize).min(e.payload.len());
            let query = parse_dns_query_name(&e.payload[..payload_len])?;
            Some(BpfEvent::DnsQuery {
                pid: e.tgid,
                uid: e.uid,
                comm: bytes_to_string(&e.comm),
                query,
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SECURITY_EVENTS ring buffer parser
// ---------------------------------------------------------------------------

pub(super) fn parse_security_event(data: &[u8]) -> Option<BpfEvent> {
    if data.is_empty() { return None; }
    let tag = data[0];
    match tag {
        SEC_EVT_PTRACE => {
            if data.len() < size_of::<BpfPtrace>() { return None; }
            // Safety: bounds-checked above; BpfPtrace is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfPtrace) };
            Some(BpfEvent::Ptrace {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                target_pid: e.target_pid,
                request: e.request,
            })
        }
        SEC_EVT_PRIV_CHANGE => {
            if data.len() < size_of::<BpfPrivChange>() { return None; }
            // Safety: bounds-checked above; BpfPrivChange is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfPrivChange) };
            Some(BpfEvent::PrivChange {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                syscall: e.syscall,
                new_id1: e.new_id1,
                new_id2: e.new_id2,
            })
        }
        SEC_EVT_MMAP_EXEC => {
            if data.len() < size_of::<BpfMmapExec>() { return None; }
            // Safety: bounds-checked above; BpfMmapExec is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfMmapExec) };
            Some(BpfEvent::MmapExec {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                addr: e.addr, len: e.len, prot: e.prot, flags: e.flags,
            })
        }
        SEC_EVT_KERNEL_MOD => {
            if data.len() < size_of::<BpfKernelMod>() { return None; }
            // Safety: bounds-checked above; BpfKernelMod is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfKernelMod) };
            Some(BpfEvent::KernelMod {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                name: bytes_to_string(&e.name),
            })
        }
        SEC_EVT_FILE_CHMOD | SEC_EVT_FILE_CHOWN => {
            if data.len() < size_of::<BpfFilePerm>() { return None; }
            // Safety: bounds-checked above; BpfFilePerm is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfFilePerm) };
            Some(BpfEvent::FilePerm {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                is_chown: tag == SEC_EVT_FILE_CHOWN,
                mode: e.mode, new_uid: e.new_uid, new_gid: e.new_gid,
                filename: bytes_to_string(&e.filename),
            })
        }
        SEC_EVT_PROCESS_VM => {
            if data.len() < size_of::<BpfProcessVm>() { return None; }
            // Safety: bounds-checked above; BpfProcessVm is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfProcessVm) };
            Some(BpfEvent::ProcessVm {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                target_pid: e.target_pid,
                is_write: e.is_write != 0,
            })
        }
        SEC_EVT_MEMFD_CREATE => {
            if data.len() < size_of::<BpfMemfd>() { return None; }
            // Safety: bounds-checked above; BpfMemfd is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfMemfd) };
            Some(BpfEvent::Memfd {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                flags: e.flags,
                name: bytes_to_string(&e.name),
            })
        }
        SEC_EVT_BPF_PROG => {
            if data.len() < size_of::<BpfBpfProg>() { return None; }
            // Safety: bounds-checked above; BpfBpfProg is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfBpfProg) };
            Some(BpfEvent::BpfProg {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                bpf_cmd: e.bpf_cmd,
            })
        }
        SEC_EVT_CAPABILITY => {
            if data.len() < size_of::<BpfCapability>() { return None; }
            // Safety: bounds-checked above; BpfCapability is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfCapability) };
            Some(BpfEvent::Capability {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                effective: e.effective,
                permitted: e.permitted,
                inheritable: e.inheritable,
            })
        }
        SEC_EVT_SIGNAL => {
            if data.len() < size_of::<BpfSignal>() { return None; }
            // Safety: bounds-checked above; BpfSignal is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfSignal) };
            Some(BpfEvent::Signal {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                target_pid: e.target_pid,
                signal: e.signal,
            })
        }
        SEC_EVT_NAMESPACE => {
            if data.len() < size_of::<BpfNamespace>() { return None; }
            // Safety: bounds-checked above; BpfNamespace is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfNamespace) };
            Some(BpfEvent::Namespace {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                syscall_type: e.syscall_type,
                flags: e.flags,
            })
        }
        SEC_EVT_KEYCTL => {
            if data.len() < size_of::<BpfKeyctl>() { return None; }
            // Safety: bounds-checked above; BpfKeyctl is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfKeyctl) };
            Some(BpfEvent::Keyctl {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                operation: e.operation,
            })
        }
        SEC_EVT_IO_URING => {
            if data.len() < size_of::<BpfIoUring>() { return None; }
            // Safety: bounds-checked above; BpfIoUring is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfIoUring) };
            Some(BpfEvent::IoUring {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                entries: e.entries,
            })
        }
        SEC_EVT_MOUNT | SEC_EVT_UMOUNT => {
            if data.len() < size_of::<BpfMount>() { return None; }
            // Safety: bounds-checked above; BpfMount is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfMount) };
            Some(BpfEvent::Mount {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                is_umount: tag == SEC_EVT_UMOUNT,
                source: bytes_to_string(&e.source),
                target: bytes_to_string(&e.target),
                fs_type: bytes_to_string(&e.fs_type),
                flags: e.flags,
            })
        }
        SEC_EVT_SYMLINK | SEC_EVT_HARDLINK => {
            if data.len() < size_of::<BpfFileLink>() { return None; }
            // Safety: bounds-checked above; BpfFileLink is repr(C).
            let e = unsafe { &*(data.as_ptr() as *const BpfFileLink) };
            Some(BpfEvent::FileLink {
                pid: e.tgid, uid: e.uid,
                comm: bytes_to_string(&e.comm),
                is_symlink: tag == SEC_EVT_SYMLINK,
                src_path: bytes_to_string(&e.src_path),
                dst_path: bytes_to_string(&e.dst_path),
            })
        }
        _ => None,
    }
}
