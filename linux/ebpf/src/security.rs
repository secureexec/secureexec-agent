use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use secureexec_ebpf_common::*;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// All security events: ptrace, priv-change, mmap-exec, kernel-mod, chmod/chown,
/// process_vm, memfd, bpf, capability, signal, namespace, keyctl, io_uring,
/// mount/umount, symlink/hardlink.  All tag-dispatched.
#[map]
static SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);

/// Per-CPU counter: incremented when SECURITY_EVENTS.reserve() fails (ring full).
#[map]
static SEC_DROP_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn bump_sec_drop() {
    // Safety: index 0 is always valid (max_entries=1); per-CPU so no races.
    if let Some(ptr) = SEC_DROP_COUNT.get_ptr_mut(0) {
        unsafe { *ptr += 1; }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROT_EXEC:  u64 = 4;
const PROT_WRITE: u64 = 2;

// ---------------------------------------------------------------------------
// Security: setuid / setgid family
// ---------------------------------------------------------------------------

fn emit_priv_change(syscall: u8, id1: u32, id2: u32, id3: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<PrivilegeChangeEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = SEC_EVT_PRIV_CHANGE;
        event.syscall = syscall;
        event._pad = [0; 2];
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = bpf_get_current_uid_gid() as u32;
        event.new_id1 = id1;
        event.new_id2 = id2;
        event.new_id3 = id3;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_setuid")]
pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    let uid: u32 = unsafe { ctx.read_at(16).unwrap_or(ID_UNCHANGED as u64) as u32 };
    emit_priv_change(PRIV_SETUID, uid, ID_UNCHANGED, ID_UNCHANGED);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setgid")]
pub fn sys_enter_setgid(ctx: TracePointContext) -> u32 {
    let gid: u32 = unsafe { ctx.read_at(16).unwrap_or(ID_UNCHANGED as u64) as u32 };
    emit_priv_change(PRIV_SETGID, gid, ID_UNCHANGED, ID_UNCHANGED);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setreuid")]
pub fn sys_enter_setreuid(ctx: TracePointContext) -> u32 {
    let ruid: u32 = unsafe { ctx.read_at(16).unwrap_or(ID_UNCHANGED as u64) as u32 };
    let euid: u32 = unsafe { ctx.read_at(24).unwrap_or(ID_UNCHANGED as u64) as u32 };
    emit_priv_change(PRIV_SETREUID, ruid, euid, ID_UNCHANGED);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setregid")]
pub fn sys_enter_setregid(ctx: TracePointContext) -> u32 {
    let rgid: u32 = unsafe { ctx.read_at(16).unwrap_or(ID_UNCHANGED as u64) as u32 };
    let egid: u32 = unsafe { ctx.read_at(24).unwrap_or(ID_UNCHANGED as u64) as u32 };
    emit_priv_change(PRIV_SETREGID, rgid, egid, ID_UNCHANGED);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setresuid")]
pub fn sys_enter_setresuid(ctx: TracePointContext) -> u32 {
    let ruid: u32 = unsafe { ctx.read_at(16).unwrap_or(ID_UNCHANGED as u64) as u32 };
    let euid: u32 = unsafe { ctx.read_at(24).unwrap_or(ID_UNCHANGED as u64) as u32 };
    let suid: u32 = unsafe { ctx.read_at(32).unwrap_or(ID_UNCHANGED as u64) as u32 };
    emit_priv_change(PRIV_SETRESUID, ruid, euid, suid);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setresgid")]
pub fn sys_enter_setresgid(ctx: TracePointContext) -> u32 {
    let rgid: u32 = unsafe { ctx.read_at(16).unwrap_or(ID_UNCHANGED as u64) as u32 };
    let egid: u32 = unsafe { ctx.read_at(24).unwrap_or(ID_UNCHANGED as u64) as u32 };
    let sgid: u32 = unsafe { ctx.read_at(32).unwrap_or(ID_UNCHANGED as u64) as u32 };
    emit_priv_change(PRIV_SETRESGID, rgid, egid, sgid);
    0
}

// ---------------------------------------------------------------------------
// Security: ptrace
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    match try_sys_enter_ptrace(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    let request: u32   = unsafe { ctx.read_at(16).unwrap_or(0) as u32 };
    let target_pid: u32 = unsafe { ctx.read_at(24).unwrap_or(0) as u32 };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<PtraceEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = SEC_EVT_PTRACE;
        event._pad = [0; 3];
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = bpf_get_current_uid_gid() as u32;
        event.target_pid = target_pid;
        event.request = request;
        event._pad2 = 0;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: chmod / chown
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_fchmodat")]
pub fn sys_enter_fchmodat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_fchmodat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_fchmodat(ctx: &TracePointContext) -> Result<(), i64> {
    // fchmodat(dfd, filename, mode) — dfd@16, filename@24, mode@32
    let filename_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let mode: u32 = unsafe { ctx.read_at(32).unwrap_or(0) as u32 };
    if filename_ptr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<FilePermChangeEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = SEC_EVT_FILE_CHMOD;
        event._pad = [0; 3];
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = bpf_get_current_uid_gid() as u32;
        event.mode = mode;
        event.new_uid = ID_UNCHANGED;
        event.new_gid = ID_UNCHANGED;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        // Ring buffer memory is reused across events and is NOT zeroed
        // between reservations; a failed bpf_probe_read_user_str_bytes would
        // otherwise leave stale bytes from a previous event visible in
        // event.filename, leaking path fragments across unrelated processes.
        event.filename[0] = 0;
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename);
        }
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_chown")]
pub fn sys_enter_chown(ctx: TracePointContext) -> u32 {
    match try_sys_enter_chown(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_lchown")]
pub fn sys_enter_lchown(ctx: TracePointContext) -> u32 {
    match try_sys_enter_chown(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_chown(ctx: &TracePointContext) -> Result<(), i64> {
    // chown(filename, user, group) — filename@16, user@24, group@32
    let filename_ptr: u64 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let new_uid: u32 = unsafe { ctx.read_at(24).unwrap_or(ID_UNCHANGED as u64) as u32 };
    let new_gid: u32 = unsafe { ctx.read_at(32).unwrap_or(ID_UNCHANGED as u64) as u32 };
    if filename_ptr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<FilePermChangeEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = SEC_EVT_FILE_CHOWN;
        event._pad = [0; 3];
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = bpf_get_current_uid_gid() as u32;
        event.mode = ID_UNCHANGED;
        event.new_uid = new_uid;
        event.new_gid = new_gid;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        // See comment in try_sys_enter_fchmodat: pre-zero the sentinel byte so
        // a partial/failed read cannot leak bytes from a prior ring event.
        event.filename[0] = 0;
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename);
        }
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: mmap RWX
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    match try_sys_enter_mmap(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_mmap(ctx: &TracePointContext) -> Result<(), i64> {
    // mmap(addr, len, prot, flags, fd, pgoff) — addr@16, len@24, prot@32, flags@40
    let prot:  u64 = unsafe { ctx.read_at(32).unwrap_or(0) };
    let flags: u64 = unsafe { ctx.read_at(40).unwrap_or(0) };

    if (prot & PROT_EXEC) == 0 || (prot & PROT_WRITE) == 0 {
        return Ok(());
    }

    let addr: u64 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let len:  u64 = unsafe { ctx.read_at(24).unwrap_or(0) };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<MmapExecEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = SEC_EVT_MMAP_EXEC;
        event._pad = [0; 3];
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = bpf_get_current_uid_gid() as u32;
        event.prot = prot as u32;
        event.flags = flags as u32;
        event._pad2 = 0;
        event.len = len;
        event.addr = addr;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: kernel module load
// ---------------------------------------------------------------------------

#[tracepoint(category = "module", name = "module_load")]
pub fn module_load(ctx: TracePointContext) -> u32 {
    match try_module_load(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_module_load(ctx: &TracePointContext) -> Result<(), i64> {
    // module_load tracepoint: __data_loc char[] name offset:8 size:4
    let data_loc: u32 = unsafe { ctx.read_at(8).unwrap_or(0) };
    let name_offset = (data_loc & 0xFFFF) as usize;

    let mut name = [0u8; MAX_FILENAME];
    if name_offset > 0 {
        let src = (ctx.as_ptr() as usize + name_offset) as *const u8;
        unsafe {
            let _ = bpf_probe_read_kernel_str_bytes(src, &mut name);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<KernelModuleEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = SEC_EVT_KERNEL_MOD;
        event._pad = [0; 3];
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = bpf_get_current_uid_gid() as u32;
        event._pad2 = 0;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        event.name = name;
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: process_vm_readv / process_vm_writev
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_process_vm_readv")]
pub fn sys_enter_process_vm_readv(ctx: TracePointContext) -> u32 {
    emit_process_vm(&ctx, false);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_process_vm_writev")]
pub fn sys_enter_process_vm_writev(ctx: TracePointContext) -> u32 {
    emit_process_vm(&ctx, true);
    0
}

fn emit_process_vm(ctx: &TracePointContext, is_write: bool) {
    // process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags) — pid@16
    let target_pid: u32 = unsafe { ctx.read_at(16).unwrap_or(0) as u32 };
    if target_pid == 0 {
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let my_tgid = (pid_tgid >> 32) as u32;
    if target_pid == my_tgid {
        return;
    }
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<ProcessVmEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_PROCESS_VM;
        e.is_write = is_write as u8;
        e._pad = [0; 2];
        e.pid = pid_tgid as u32;
        e.tgid = my_tgid;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.target_pid = target_pid;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
}

// ---------------------------------------------------------------------------
// Security: memfd_create
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    match try_sys_enter_memfd_create(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_memfd_create(ctx: &TracePointContext) -> Result<(), i64> {
    // memfd_create(uname_ptr, flags) — uname_ptr@16, flags@24
    let name_ptr: u64 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let flags: u32    = unsafe { ctx.read_at(24).unwrap_or(0) as u32 };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<MemfdCreateEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_MEMFD_CREATE;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.flags = flags;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        // Ring buffer memory is reused between reservations and is NOT zeroed
        // on allocation. Without this NUL sentinel, when `name_ptr` is NULL
        // (or the user-string read silently fails on the first byte) we
        // would leak whatever `name` from a prior memfd_create / unrelated
        // event still lives in that slot.
        e.name[0] = 0;
        if name_ptr != 0 {
            unsafe {
                let _ = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut e.name);
            }
        }
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: bpf() syscall
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_bpf")]
pub fn sys_enter_bpf(ctx: TracePointContext) -> u32 {
    // bpf(cmd, attr, size) — cmd@16
    let bpf_cmd: u32 = unsafe { ctx.read_at(16).unwrap_or(0) as u32 };

    // Only track BPF_PROG_LOAD (5) and BPF_BTF_LOAD (18)
    if bpf_cmd != 5 && bpf_cmd != 18 {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<BpfProgramEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_BPF_PROG;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.bpf_cmd = bpf_cmd;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    0
}

// ---------------------------------------------------------------------------
// Security: capset
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_capset")]
pub fn sys_enter_capset(ctx: TracePointContext) -> u32 {
    match try_sys_enter_capset(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_capset(ctx: &TracePointContext) -> Result<(), i64> {
    // capset(hdrp@16, datap@24)
    let datap: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };

    let effective: u32 = if datap != 0 {
        unsafe { bpf_probe_read_user((datap) as *const u32).unwrap_or(0) }
    } else { 0 };
    let permitted: u32 = if datap != 0 {
        unsafe { bpf_probe_read_user((datap + 4) as *const u32).unwrap_or(0) }
    } else { 0 };
    let inheritable: u32 = if datap != 0 {
        unsafe { bpf_probe_read_user((datap + 8) as *const u32).unwrap_or(0) }
    } else { 0 };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<CapabilityChangeEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_CAPABILITY;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.effective = effective;
        e.permitted = permitted;
        e.inheritable = inheritable;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: kill() to another process
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_kill")]
pub fn sys_enter_kill(ctx: TracePointContext) -> u32 {
    // kill(pid, sig) — pid@16, sig@24
    let target_pid_raw: i64 = unsafe { ctx.read_at(16).unwrap_or(0) as i64 };
    let signal: u32         = unsafe { ctx.read_at(24).unwrap_or(0) as u32 };

    if target_pid_raw <= 0 || signal == 0 {
        return 0;
    }
    let target_pid = target_pid_raw as u32;

    let pid_tgid = bpf_get_current_pid_tgid();
    let my_tgid = (pid_tgid >> 32) as u32;
    if target_pid == my_tgid {
        return 0;
    }

    if let Some(mut buf) = SECURITY_EVENTS.reserve::<ProcessSignalEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_SIGNAL;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = my_tgid;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.target_pid = target_pid;
        e.signal = signal;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    0
}

// ---------------------------------------------------------------------------
// Security: unshare() / setns()
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_unshare")]
pub fn sys_enter_unshare(ctx: TracePointContext) -> u32 {
    let flags: u32 = unsafe { ctx.read_at(16).unwrap_or(0) as u32 };
    emit_namespace_change(0, flags);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setns")]
pub fn sys_enter_setns(ctx: TracePointContext) -> u32 {
    // setns(fd, nstype) — fd@16, nstype@24
    let nstype: u32 = unsafe { ctx.read_at(24).unwrap_or(0) as u32 };
    emit_namespace_change(1, nstype);
    0
}

fn emit_namespace_change(syscall_type: u8, flags: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<NamespaceChangeEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_NAMESPACE;
        e.syscall_type = syscall_type;
        e._pad = [0; 2];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.flags = flags;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
}

// ---------------------------------------------------------------------------
// Security: keyctl()
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_keyctl")]
pub fn sys_enter_keyctl(ctx: TracePointContext) -> u32 {
    // keyctl(option, ...) — option@16
    let operation: u32 = unsafe { ctx.read_at(16).unwrap_or(0) as u32 };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<KeyctlEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_KEYCTL;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.operation = operation;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    0
}

// ---------------------------------------------------------------------------
// Security: io_uring_setup()
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_io_uring_setup")]
pub fn sys_enter_io_uring_setup(ctx: TracePointContext) -> u32 {
    // io_uring_setup(entries, params) — entries@16
    let entries: u32 = unsafe { ctx.read_at(16).unwrap_or(0) as u32 };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<IoUringSetupEvent>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_IO_URING;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.entries = entries;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    0
}

// ---------------------------------------------------------------------------
// Security: mount() / umount2()
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_mount")]
pub fn sys_enter_mount(ctx: TracePointContext) -> u32 {
    match try_sys_enter_mount(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_mount(ctx: &TracePointContext) -> Result<(), i64> {
    // mount(dev_name@16, dir_name@24, type@32, flags@40, data@48)
    let src_ptr:  u64 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let tgt_ptr:  u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let type_ptr: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };
    let flags: u32    = unsafe { ctx.read_at(40).unwrap_or(0) as u32 };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<MountEventData>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_MOUNT;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.flags = flags;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        // See comment in try_sys_enter_memfd_create: ring buffer slots are
        // reused without zeroing, so NULL user pointers (or short reads)
        // must not leak stale path bytes from prior events.
        e.source[0] = 0;
        e.target[0] = 0;
        e.fs_type[0] = 0;
        if src_ptr  != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(src_ptr  as *const u8, &mut e.source);  } }
        if tgt_ptr  != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(tgt_ptr  as *const u8, &mut e.target);  } }
        if type_ptr != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(type_ptr as *const u8, &mut e.fs_type); } }
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_umount")]
pub fn sys_enter_umount(ctx: TracePointContext) -> u32 {
    match try_sys_enter_umount(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_umount(ctx: &TracePointContext) -> Result<(), i64> {
    // umount2(name@16, flags@24)
    let name_ptr: u64 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let flags: u32    = unsafe { ctx.read_at(24).unwrap_or(0) as u32 };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<MountEventData>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_UMOUNT;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e.flags = flags;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        // Zero source/target/fs_type so that NULL name_ptr (or a short
        // user-space read) cannot surface stale path bytes from a previous
        // MountEvent / UmountEvent slot.
        e.source[0] = 0;
        e.target[0] = 0;
        e.fs_type[0] = 0;
        if name_ptr != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut e.target); } }
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: symlinkat() / linkat()
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_symlinkat")]
pub fn sys_enter_symlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_symlinkat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_symlinkat(ctx: &TracePointContext) -> Result<(), i64> {
    // symlinkat(oldname@16, newdfd@24, newname@32)
    let src_ptr: u64 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let dst_ptr: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<FileLinkEventData>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_SYMLINK;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        // Ring buffer memory is reused. If either pointer is NULL, or a read
        // fails partway, stale bytes from a prior event would otherwise leak
        // into the skipped path field. Zero the sentinel byte of both fields
        // so userspace sees an empty C string on skip/failure.
        e.src_path[0] = 0;
        e.dst_path[0] = 0;
        if src_ptr != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(src_ptr as *const u8, &mut e.src_path); } }
        if dst_ptr != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(dst_ptr as *const u8, &mut e.dst_path); } }
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_linkat")]
pub fn sys_enter_linkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_linkat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_linkat(ctx: &TracePointContext) -> Result<(), i64> {
    // linkat(olddfd@16, oldname@24, newdfd@32, newname@40, flags@48)
    let src_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let dst_ptr: u64 = unsafe { ctx.read_at(40).unwrap_or(0) };

    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(mut buf) = SECURITY_EVENTS.reserve::<FileLinkEventData>(0) {
        let e = unsafe { &mut *buf.as_mut_ptr() };
        e.event_tag = SEC_EVT_HARDLINK;
        e._pad = [0; 3];
        e.pid = pid_tgid as u32;
        e.tgid = (pid_tgid >> 32) as u32;
        e.uid = bpf_get_current_uid_gid() as u32;
        e._pad2 = 0;
        e.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        // See try_sys_enter_symlinkat: pre-zero both path sentinels to prevent
        // cross-event path leakage through reused ring buffer memory.
        e.src_path[0] = 0;
        e.dst_path[0] = 0;
        if src_ptr != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(src_ptr as *const u8, &mut e.src_path); } }
        if dst_ptr != 0 { unsafe { let _ = bpf_probe_read_user_str_bytes(dst_ptr as *const u8, &mut e.dst_path); } }
        buf.submit(0);
    } else {
        bump_sec_drop();
    }
    Ok(())
}
