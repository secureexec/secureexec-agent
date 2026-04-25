use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use secureexec_ebpf_common::*;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

#[map]
static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Per-CPU counter: incremented when PROCESS_EVENTS.reserve() fails (ring full).
#[map]
static PROC_DROP_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Pending exit code: tgid → exit_code.  Written by exit_group, consumed by
/// sched_process_exit.
#[map]
static PENDING_EXIT: HashMap<u32, i32> = HashMap::with_max_entries(4096, 0);

/// `CLONE_THREAD` from `<linux/sched.h>` — set by every thread library
/// (pthread_create, std::thread, golang's runtime, etc.) to make the new
/// task share the parent's thread group.
const CLONE_THREAD: u64 = 0x0001_0000;

#[inline(always)]
fn bump_proc_drop() {
    // Safety: index 0 is always valid (max_entries=1); per-CPU so no races.
    if let Some(ptr) = PROC_DROP_COUNT.get_ptr_mut(0) {
        unsafe { *ptr += 1; }
    }
}

// ---------------------------------------------------------------------------
// sched_process_exec
// ---------------------------------------------------------------------------

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sched_process_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    // sched_process_exec has no ppid field: layout is
    //   [data_loc_filename@8] [pid@12] [old_pid@16] [string_data@20…]
    // Userspace will fill ppid from procfs.
    let parent_pid: u32 = 0;

    let data_loc: u32 = unsafe { ctx.read_at(8).unwrap_or(0) };
    let fname_offset = (data_loc & 0xFFFF) as usize;

    let mut filename = [0u8; MAX_FILENAME];
    if fname_offset > 0 {
        let src = (ctx.as_ptr() as usize + fname_offset) as *const u8;
        unsafe {
            let _ = bpf_probe_read_kernel_str_bytes(src, &mut filename);
        }
    }

    if let Some(mut buf) = PROCESS_EVENTS.reserve::<ProcessExecEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = PROC_EVT_EXEC;
        event._pad = [0; 3];
        event.pid = pid;
        event.tgid = tgid;
        event.parent_pid = parent_pid;
        event.uid = uid;
        event.comm = comm;
        event.filename = filename;
        buf.submit(0);
    } else {
        bump_proc_drop();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sys_enter_execve — capture full argv + scan for LD_PRELOAD
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    // argv is args[1] → offset 24
    let argv_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    if argv_ptr == 0 {
        return Ok(());
    }
    // envp is args[2] → offset 32
    let envp_ptr: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };

    if let Some(mut ring_entry) = PROCESS_EVENTS.reserve::<ExecArgvEvent>(0) {
        let event = unsafe { &mut *ring_entry.as_mut_ptr() };
        event.event_tag = PROC_EVT_ARGV;
        event._pad = [0; 3];
        event.tgid = tgid;
        event.argc = 0;
        // Sentinel must be zero before the scan so check_env! knows no match yet.
        // Ring buffer memory is not zero-initialized.
        event.ld_preload[0] = 0;

        macro_rules! read_arg {
            ($offset:expr, $idx:expr) => {{
                // Ring buffer memory is reused across events and is NOT zeroed
                // between reservations; without this NUL sentinel, a failed
                // `bpf_probe_read_user_str_bytes` would leave stale bytes from
                // a previous event visible in args[$idx], effectively leaking
                // argv fragments across unrelated processes.
                event.args[$idx][0] = 0;
                let ptr: u64 = unsafe {
                    bpf_probe_read_user((argv_ptr + $offset) as *const u64).unwrap_or(0)
                };
                if ptr != 0 {
                    unsafe {
                        let _ = bpf_probe_read_user_str_bytes(
                            ptr as *const u8,
                            &mut event.args[$idx],
                        );
                    }
                    event.argc += 1;
                }
            }};
        }

        read_arg!(0,   0);  read_arg!(8,   1);  read_arg!(16,  2);  read_arg!(24,  3);
        read_arg!(32,  4);  read_arg!(40,  5);  read_arg!(48,  6);  read_arg!(56,  7);
        read_arg!(64,  8);  read_arg!(72,  9);  read_arg!(80,  10); read_arg!(88,  11);
        read_arg!(96,  12); read_arg!(104, 13); read_arg!(112, 14); read_arg!(120, 15);

        // Scan envp for LD_PRELOAD= (first match wins)
        if envp_ptr != 0 {
            macro_rules! check_env {
                ($offset:expr) => {{
                    if event.ld_preload[0] == 0 {
                        let ptr: u64 = unsafe {
                            bpf_probe_read_user((envp_ptr + $offset) as *const u64).unwrap_or(0)
                        };
                        if ptr != 0 {
                            let mut prefix = [0u8; 12];
                            unsafe {
                                let _ = bpf_probe_read_user_str_bytes(ptr as *const u8, &mut prefix);
                            }
                            if prefix[0]  == b'L' && prefix[1]  == b'D' && prefix[2]  == b'_'
                            && prefix[3]  == b'P' && prefix[4]  == b'R' && prefix[5]  == b'E'
                            && prefix[6]  == b'L' && prefix[7]  == b'O' && prefix[8]  == b'A'
                            && prefix[9]  == b'D' && prefix[10] == b'=' {
                                unsafe {
                                    let _ = bpf_probe_read_user_str_bytes(
                                        ptr as *const u8,
                                        &mut event.ld_preload,
                                    );
                                }
                            }
                        }
                    }
                }};
            }

            check_env!(0);   check_env!(8);   check_env!(16);  check_env!(24);
            check_env!(32);  check_env!(40);  check_env!(48);  check_env!(56);
            check_env!(64);  check_env!(72);  check_env!(80);  check_env!(88);
            check_env!(96);  check_env!(104); check_env!(112); check_env!(120);
            check_env!(128); check_env!(136); check_env!(144); check_env!(152);
            check_env!(160); check_env!(168); check_env!(176); check_env!(184);
            check_env!(192); check_env!(200); check_env!(208); check_env!(216);
            check_env!(224); check_env!(232); check_env!(240); check_env!(248);
        }

        ring_entry.submit(0);
    } else {
        bump_proc_drop();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sched_process_exit — include exit code
// ---------------------------------------------------------------------------

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_sched_process_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sched_process_exit(_ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    // sched_process_exit fires on every task (thread) exit, but a process
    // is only "exited" when its group leader (pid == tgid) leaves. Emitting
    // an event for non-leader thread exits would let userspace evict live
    // processes from its cache and ship spurious ProcessExit telemetry.
    if pid != tgid {
        return Ok(());
    }

    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let exit_code: i32 = {
        let code = unsafe { PENDING_EXIT.get(&tgid).copied().unwrap_or(0) };
        let _ = PENDING_EXIT.remove(&tgid);
        code
    };

    if let Some(mut buf) = PROCESS_EVENTS.reserve::<ProcessExitEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = PROC_EVT_EXIT;
        event._pad = [0; 3];
        event.pid = pid;
        event.tgid = tgid;
        event.exit_code = exit_code;
        event.comm = comm;
        buf.submit(0);
    } else {
        bump_proc_drop();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sys_enter_exit_group — stash exit code
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_exit_group")]
pub fn sys_enter_exit_group(ctx: TracePointContext) -> u32 {
    let exit_code: i32 = unsafe { ctx.read_at(16).unwrap_or(0) as i32 };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = PENDING_EXIT.insert(&tgid, &exit_code, 0);
    0
}

// ---------------------------------------------------------------------------
// task_newtask — emit new-process events (threads filtered by CLONE_THREAD)
//
// task/task_newtask fires inside copy_process() for every clone/fork/vfork,
// and exposes clone_flags natively — no side-channel map needed.  Format:
//   pid@8 (pid_t, 4 bytes), comm@12 (char[16]), clone_flags@32 (u64).
// Offsets validated at agent startup by TracefsValidator in userspace.
//
// current = the parent task executing the clone syscall, so
// bpf_get_current_pid_tgid() >> 32 gives the parent's TGID directly —
// always the thread-group leader, even when cloned from a worker thread.
// ---------------------------------------------------------------------------

#[tracepoint(category = "task", name = "task_newtask")]
pub fn task_newtask(ctx: TracePointContext) -> u32 {
    match try_task_newtask(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_task_newtask(ctx: &TracePointContext) -> Result<(), i64> {
    let clone_flags: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };

    // CLONE_THREAD ⇒ new thread in an existing thread group, not a new
    // process.  Drop at the kernel layer so the ring buffer never sees it.
    if clone_flags & CLONE_THREAD != 0 {
        return Ok(());
    }

    // child pid == child tgid for non-CLONE_THREAD tasks (new thread-group
    // leader).  pid@8 in the tracepoint format.
    let child_pid: u32 = unsafe { ctx.read_at(8).unwrap_or(0) };
    let parent_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    // comm@12 (char[16]) — the new task's name, copied by the kernel before
    // this tracepoint fires.
    let mut comm = [0u8; TASK_COMM_LEN];
    unsafe {
        // Safety: ctx.as_ptr() points to the tracepoint common header;
        // comm is at a fixed offset of 12 bytes, fully within the struct.
        let _ = bpf_probe_read_kernel_buf(
            (ctx.as_ptr() as usize + 12) as *const u8,
            &mut comm,
        );
    }

    if let Some(mut buf) = PROCESS_EVENTS.reserve::<ProcessForkEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag  = PROC_EVT_FORK;
        event._pad       = [0; 3];
        event.parent_pid = parent_tgid;
        event.child_pid  = child_pid;
        event.uid        = uid;
        event.comm       = comm;
        buf.submit(0);
    } else {
        bump_proc_drop();
    }

    Ok(())
}
