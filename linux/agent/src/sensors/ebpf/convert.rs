use std::collections::HashMap;

use chrono::{DateTime, Utc};
use lru::LruCache;
use secureexec_ebpf_common::ID_UNCHANGED;
use secureexec_generic::event::{
    BpfProgramEvent, CapabilityChangeEvent, DnsEvent, Event, EventKind, FileEvent,
    FilePermChangeEvent, FileLinkEvent, FileRenameEvent, IoUringEvent,
    KernelModuleEvent, KeyctlEvent, MemfdCreateEvent, MemoryMapEvent,
    MountEvent, NamespaceChangeEvent, NetworkEvent, PrivilegeChangeEvent,
    ProcessAccessEvent, ProcessEvent, ProcessSignalEvent, ProcessVmEvent,
};

use super::helpers::{
    bpf_cmd_name, keyctl_op_name, namespace_flags_name, proto_from_u8,
    priv_ids_to_uid_gid, priv_syscall_name, ptrace_request_name, resolve_path,
    signal_name,
};
use super::super::{exe_hash, procfs};
use super::types::BpfEvent;

// ---------------------------------------------------------------------------
// BpfEvent → pipeline Event conversion
// ---------------------------------------------------------------------------

pub(super) fn convert_bpf_events(
    bpf: BpfEvent,
    hostname: &str,
    cache: &mut LruCache<u32, procfs::ProcInfo>,
    pending_argv: &mut HashMap<u32, (String, String)>,
    uid_resolver: &mut procfs::UidResolver,
    exe_hash_cache: &mut exe_hash::ExeHashCache,
) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::with_capacity(2);

    let kind: Option<EventKind> = match bpf {
        BpfEvent::ExecArgv { tgid, cmdline, ld_preload } => {
            if !cmdline.is_empty() {
                // Cap pending_argv so a misbehaving process (exec that never
                // calls the post-exec tracepoint, ring-buffer drops, etc.)
                // cannot pin unbounded memory. 16k entries × (cmdline+LD_PRELOAD)
                // fits comfortably even on a high-churn host; eviction is
                // coarse but cheap.
                const PENDING_ARGV_CAP: usize = 16 * 1024;
                if pending_argv.len() >= PENDING_ARGV_CAP {
                    pending_argv.clear();
                }
                pending_argv.insert(tgid, (cmdline, ld_preload));
            }
            return out;
        }
        BpfEvent::ProcessExec { pid, uid, comm, filename } => {
            // parent_pid from eBPF event is always 0 (sched_process_exec has no
            // ppid field); read the real one from procfs instead.
            // For very short-lived processes /proc/{pid} may already be gone;
            // fall back to the cache entry populated by the earlier ProcessFork.
            let info = procfs::read_proc_info(pid);
            // Snapshot fork-cache into owned values before mutable cache ops.
            let fork_data = cache.get(&pid)
                .map(|c| (c.parent_pid, c.start_time, c.container_id.clone()));
            let real_ppid = info.as_ref().map(|i| i.parent_pid)
                .or_else(|| fork_data.as_ref().map(|(ppid, _, _)| *ppid))
                .unwrap_or(0);

            // Emit synthetic snapshot for uncached parent
            if real_ppid > 0 && !cache.contains(&real_ppid) {
                if let Some(parent_info) = procfs::read_proc_info(real_ppid) {
                    cache.put(real_ppid, parent_info.clone());
                    let parent_username  = uid_resolver.resolve(parent_info.uid, real_ppid);
                    let parent_container = parent_info.container_id.clone().unwrap_or_default();
                    let mut ev = Event::new(hostname.to_string(), EventKind::ProcessCreate(ProcessEvent {
                        pid: real_ppid,
                        parent_pid: parent_info.parent_pid,
                        name: parent_info.name,
                        path: parent_info.path,
                        cmdline: parent_info.cmdline,
                        user_id: parent_info.uid.to_string(),
                        start_time: parent_info.start_time,
                        snapshot: true,
                        parent_process_guid: String::new(),
                        exit_code: None,
                        ld_preload: String::new(),
                        exe_hash: String::new(),
                        exe_size: 0,
                    }));
                    ev.username        = parent_username;
                    ev.process_user_id = parent_info.uid.to_string();
                    ev.container_id    = parent_container;
                    out.push(ev);
                }
            }

            if let Some(ref i) = info {
                cache.put(pid, i.clone());
            }
            let (name, path, proc_cmdline, start_time, container_id) = match info {
                Some(i) => (i.name, i.path, i.cmdline, i.start_time, i.container_id.unwrap_or_default()),
                None    => {
                    // /proc gone — use eBPF comm/filename for the post-exec
                    // identity but recover timing + container from the fork cache.
                    let st = fork_data.as_ref().map(|(_, st, _)| *st).unwrap_or_else(Utc::now);
                    let cid = fork_data.and_then(|(_, _, cid)| cid).unwrap_or_default();
                    (comm.clone(), filename, comm, st, cid)
                }
            };
            let (argv_cmdline, ld_preload) = pending_argv.remove(&pid).unwrap_or_default();
            let cmdline  = if !argv_cmdline.is_empty() { argv_cmdline } else { proc_cmdline };
            let username = uid_resolver.resolve(uid, pid);
            let (exe_hash, exe_size) = exe_hash_cache.hash_exe(pid);
            let mut ev = Event::new(hostname.to_string(), EventKind::ProcessCreate(ProcessEvent {
                pid, parent_pid: real_ppid, name, path, cmdline, user_id: uid.to_string(), start_time,
                snapshot: false,
                parent_process_guid: String::new(),
                exit_code: None,
                ld_preload,
                exe_hash,
                exe_size,
            }));
            ev.username        = username;
            ev.process_user_id = uid.to_string();
            ev.container_id    = container_id;
            out.push(ev);
            return out;
        }
        BpfEvent::ProcessExit { pid, exit_code, comm } => {
            let cached = cache.pop(&pid);
            pending_argv.remove(&pid);
            let (parent_pid_val, uid, name, path, _cmdline, start_time, container_id) = match cached {
                Some(c) => (c.parent_pid, c.uid, c.name, c.path, c.cmdline, c.start_time, c.container_id.unwrap_or_default()),
                None    => (0, 0, comm.clone(), String::new(), comm, Utc::now(), String::new()),
            };
            let username = uid_resolver.resolve(uid, pid);
            let mut ev = Event::new(hostname.to_string(), EventKind::ProcessExit(ProcessEvent {
                pid, parent_pid: parent_pid_val,
                name: name.clone(), path, cmdline: name, user_id: uid.to_string(),
                start_time, snapshot: false,
                parent_process_guid: String::new(),
                exit_code: Some(exit_code),
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
            }));
            ev.username        = username;
            ev.process_user_id = uid.to_string();
            ev.container_id    = container_id;
            out.push(ev);
            return out;
        }
        BpfEvent::ProcessFork { parent_pid, child_pid, uid, comm } => {
            let (p_uid, p_name, p_path) = match cache.get(&parent_pid) {
                Some(p) => (p.uid, p.name.clone(), p.path.clone()),
                None => {
                    // Read the PARENT's exe, not the child's. Immediately
                    // after fork the child is still a clone of the parent,
                    // but any later exec() in the child would invalidate
                    // that assumption; parent_pid is the stable target.
                    let p_path = procfs::read_proc_exe(parent_pid).unwrap_or_default();
                    let p_name = if !p_path.is_empty() {
                        p_path.rsplit('/').next().unwrap_or(&p_path).to_string()
                    } else {
                        comm.clone()
                    };
                    (uid, p_name, p_path)
                }
            };
            let child_cmdline = procfs::read_proc_cmdline(child_pid).unwrap_or_default();
            let child_start   = procfs::read_proc_start_time(child_pid).unwrap_or_else(Utc::now);
            let container_id  = procfs::read_container_id(child_pid).unwrap_or_default();
            let username      = uid_resolver.resolve(p_uid, child_pid);
            // Cache the child so that a subsequent ProcessExec for a very
            // short-lived process can still recover parent_pid / start_time
            // even if /proc/{pid} has already disappeared.
            cache.put(child_pid, procfs::ProcInfo {
                pid: child_pid,
                parent_pid,
                uid: p_uid,
                name: p_name.clone(),
                path: p_path.clone(),
                cmdline: child_cmdline.clone(),
                start_time: child_start,
                container_id: if container_id.is_empty() { None } else { Some(container_id.clone()) },
            });
            let mut ev = Event::new(hostname.to_string(), EventKind::ProcessFork(ProcessEvent {
                pid: child_pid, parent_pid,
                name: p_name, path: p_path, cmdline: child_cmdline,
                user_id: p_uid.to_string(), start_time: child_start,
                snapshot: false,
                parent_process_guid: String::new(),
                exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
            }));
            ev.username        = username;
            ev.process_user_id = p_uid.to_string();
            ev.container_id    = container_id;
            out.push(ev);
            return out;
        }
        BpfEvent::FileCreate { pid, uid, comm, filename } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::FileCreate(FileEvent {
                path: resolve_path(pid, &filename), pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(), process_start_time: pst,
            }))
        }
        BpfEvent::FileModify { pid, uid, comm, filename } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::FileModify(FileEvent {
                path: resolve_path(pid, &filename), pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(), process_start_time: pst,
            }))
        }
        BpfEvent::FileDelete { pid, uid, comm, filename } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::FileDelete(FileEvent {
                path: resolve_path(pid, &filename), pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(), process_start_time: pst,
            }))
        }
        BpfEvent::FileRename { pid, uid, comm, old_name, new_name } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::FileRename(FileRenameEvent {
                old_path: resolve_path(pid, &old_name),
                new_path: resolve_path(pid, &new_name),
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(), process_start_time: pst,
            }))
        }
        BpfEvent::NetConnect { pid, uid, comm, src_addr, sport, dst_addr, dport, protocol } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::NetworkConnect(NetworkEvent {
                pid, user_id: uid.to_string(), process_name: pname, process_guid: String::new(),
                process_start_time: pst, src_addr, src_port: sport,
                dst_addr, dst_port: dport, protocol: proto_from_u8(protocol),
            }))
        }
        BpfEvent::NetAccept { pid, uid, comm, src_addr, sport, dst_addr, dport, protocol } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::NetworkListen(NetworkEvent {
                pid, user_id: uid.to_string(), process_name: pname, process_guid: String::new(),
                process_start_time: pst, src_addr, src_port: sport,
                dst_addr, dst_port: dport, protocol: proto_from_u8(protocol),
            }))
        }
        BpfEvent::NetBind { pid, uid, comm, src_addr, sport, protocol } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::NetworkListen(NetworkEvent {
                pid, user_id: uid.to_string(), process_name: pname, process_guid: String::new(),
                process_start_time: pst, src_addr, src_port: sport,
                dst_addr: "0.0.0.0".into(), dst_port: 0, protocol: proto_from_u8(protocol),
            }))
        }
        BpfEvent::DnsQuery { pid, uid, comm, query } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::DnsQuery(DnsEvent {
                pid,
                user_id: uid.to_string(),
                process_name: pname,
                process_guid: String::new(),
                process_start_time: pst,
                query,
                response: vec![],
            }))
        }
        BpfEvent::PrivChange { pid, uid, comm, syscall, new_id1, new_id2 } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            let (new_uid, new_gid) = priv_ids_to_uid_gid(syscall, new_id1, new_id2);
            Some(EventKind::PrivilegeChange(PrivilegeChangeEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                syscall: priv_syscall_name(syscall).into(),
                new_uid, new_gid, process_start_time: pst,
            }))
        }
        BpfEvent::Ptrace { pid, uid, comm, target_pid, request } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::ProcessAccess(ProcessAccessEvent {
                pid, user_id: uid.to_string(), target_pid,
                process_name: pname, process_guid: String::new(),
                request,
                request_name: ptrace_request_name(request).into(),
                process_start_time: pst,
            }))
        }
        BpfEvent::FilePerm { pid, uid, comm, is_chown, mode, new_uid, new_gid, filename } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            let path   = resolve_path(pid, &filename);
            let opt_id = |x: u32| if x != ID_UNCHANGED { Some(x) } else { None };
            Some(EventKind::FilePermChange(FilePermChangeEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                path,
                kind: if is_chown { "chown".into() } else { "chmod".into() },
                new_mode: opt_id(mode),
                new_uid:  opt_id(new_uid),
                new_gid:  opt_id(new_gid),
                process_start_time: pst,
            }))
        }
        BpfEvent::MmapExec { pid, uid, comm, addr, len, prot, flags } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::MemoryMap(MemoryMapEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                addr, len, prot, flags,
                is_exec:  (prot & 4) != 0,
                is_write: (prot & 2) != 0,
                process_start_time: pst,
            }))
        }
        BpfEvent::KernelMod { pid, uid, comm, name } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::KernelModuleLoad(KernelModuleEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                module_name: name, process_start_time: pst,
            }))
        }
        BpfEvent::ProcessVm { pid, uid, comm, target_pid, is_write } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::ProcessVmAccess(ProcessVmEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                target_pid, is_write, process_start_time: pst,
            }))
        }
        BpfEvent::Memfd { pid, uid, comm, flags, name } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::MemfdCreate(MemfdCreateEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                name, flags, process_start_time: pst,
            }))
        }
        BpfEvent::BpfProg { pid, uid, comm, bpf_cmd } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::BpfProgram(BpfProgramEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                bpf_cmd, bpf_cmd_name: bpf_cmd_name(bpf_cmd).into(),
                process_start_time: pst,
            }))
        }
        BpfEvent::Capability { pid, uid, comm, effective, permitted, inheritable } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::CapabilityChange(CapabilityChangeEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                effective, permitted, inheritable, process_start_time: pst,
            }))
        }
        BpfEvent::Signal { pid, uid, comm, target_pid, signal } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::ProcessSignal(ProcessSignalEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                target_pid, signal,
                signal_name: signal_name(signal).into(),
                process_start_time: pst,
            }))
        }
        BpfEvent::Namespace { pid, uid, comm, syscall_type, flags } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::NamespaceChange(NamespaceChangeEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                syscall: if syscall_type == 0 { "unshare".into() } else { "setns".into() },
                flags,
                flags_name: namespace_flags_name(flags),
                process_start_time: pst,
            }))
        }
        BpfEvent::Keyctl { pid, uid, comm, operation } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::Keyctl(KeyctlEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                operation,
                operation_name: keyctl_op_name(operation).into(),
                process_start_time: pst,
            }))
        }
        BpfEvent::IoUring { pid, uid, comm, entries } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::IoUring(IoUringEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                entries, process_start_time: pst,
            }))
        }
        BpfEvent::Mount { pid, uid, comm, is_umount, source, target, fs_type, flags } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::Mount(MountEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                source, target, fs_type, flags, is_umount,
                process_start_time: pst,
            }))
        }
        BpfEvent::FileLink { pid, uid, comm, is_symlink, src_path, dst_path } => {
            let (pname, pst) = lookup_cache(cache, pid, &comm);
            Some(EventKind::FileLink(FileLinkEvent {
                pid, user_id: uid.to_string(),
                process_name: pname, process_guid: String::new(),
                src_path, dst_path, is_symlink,
                process_start_time: pst,
            }))
        }
    };

    if let Some(k) = kind {
        let pid_val = k.pid().unwrap_or(0);
        let (uid_str, username) = match k.user_id().and_then(|s| s.parse::<u32>().ok()) {
            Some(uid_num) => (uid_num.to_string(), uid_resolver.resolve(uid_num, pid_val)),
            None => (String::new(), String::new()),
        };
        let container_id = cache.get(&pid_val)
            .and_then(|c| c.container_id.clone())
            .unwrap_or_default();
        let mut event = Event::new(hostname.to_string(), k);
        event.username        = username;
        event.process_user_id = uid_str;
        event.container_id    = container_id;
        out.push(event);
    }
    out
}

/// Look up process name and start_time from cache, falling back to comm.
/// Uses `get` (not `peek`) so that every query promotes the entry in the
/// LRU — long-running processes that are still emitting file/network/
/// security events stay hot even without any new fork/exec.
fn lookup_cache(
    cache: &mut LruCache<u32, procfs::ProcInfo>,
    pid: u32,
    comm: &str,
) -> (String, Option<DateTime<Utc>>) {
    match cache.get(&pid) {
        Some(c) => (c.name.clone(), Some(c.start_time)),
        None    => (comm.to_string(), None),
    }
}
