use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use secureexec_ebpf_common::*;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Per-CPU counter: incremented when FILE_EVENTS.reserve() fails (ring full).
#[map]
static FILE_DROP_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn bump_file_drop() {
    // Safety: index 0 is always valid (max_entries=1); per-CPU so no races.
    if let Some(ptr) = FILE_DROP_COUNT.get_ptr_mut(0) {
        unsafe { *ptr += 1; }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const O_CREAT:  u64 = 0o100;
const O_WRONLY: u64 = 0o1;
const O_RDWR:   u64 = 0o2;

// ---------------------------------------------------------------------------
// sys_enter_openat
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let flags: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };

    let is_create = (flags & O_CREAT) != 0;
    let is_write  = (flags & (O_WRONLY | O_RDWR)) != 0;
    if !is_create && !is_write {
        return Ok(());
    }

    let event_tag = if is_create { FILE_EVT_CREATE } else { FILE_EVT_MODIFY };

    let filename_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    if filename_ptr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let mut filename = [0u8; MAX_FILENAME];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename);
    }

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileEventData>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = event_tag;
        event._pad = [0; 3];
        event.pid = pid;
        event.tgid = tgid;
        event.uid = uid;
        event.comm = comm;
        event.filename = filename;
        buf.submit(0);
    } else {
        bump_file_drop();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sys_enter_unlinkat
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_unlinkat")]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlinkat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_unlinkat(ctx: &TracePointContext) -> Result<(), i64> {
    let pathname_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    if pathname_ptr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let mut filename = [0u8; MAX_FILENAME];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut filename);
    }

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileEventData>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = FILE_EVT_DELETE;
        event._pad = [0; 3];
        event.pid = pid;
        event.tgid = tgid;
        event.uid = uid;
        event.comm = comm;
        event.filename = filename;
        buf.submit(0);
    } else {
        bump_file_drop();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sys_enter_renameat2
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_renameat2")]
pub fn sys_enter_renameat2(ctx: TracePointContext) -> u32 {
    match try_sys_enter_renameat2(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_renameat2(ctx: &TracePointContext) -> Result<(), i64> {
    let oldname_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let newname_ptr: u64 = unsafe { ctx.read_at(40).unwrap_or(0) };
    if oldname_ptr == 0 || newname_ptr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid = bpf_get_current_uid_gid() as u32;

    if let Some(mut buf) = FILE_EVENTS.reserve::<FileRenameEventData>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = FILE_EVT_RENAME;
        event._pad = [0; 3];
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = uid;
        event._pad2 = 0;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut event.old_name);
            let _ = bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut event.new_name);
        }
        buf.submit(0);
    } else {
        bump_file_drop();
    }

    Ok(())
}
