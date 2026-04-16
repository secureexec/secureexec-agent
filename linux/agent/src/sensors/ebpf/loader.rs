use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use super::parsers::{parse_file_event, parse_network_event, parse_process_event, parse_security_event};
use super::types::{BpfEvent, EbpfDropCounters};

// ---------------------------------------------------------------------------
// eBPF loader
// ---------------------------------------------------------------------------

/// Load the eBPF bytecode and attach all telemetry programs (tracepoints,
/// kprobes).  Does NOT take any maps — the caller can extract firewall maps
/// before passing the handle to `poll_ebpf()` or `LinuxEbpfSensor::with_ebpf()`.
pub fn load_ebpf() -> std::result::Result<Ebpf, String> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // Safety: setrlimit is safe to call with a pointer to a stack-allocated rlimit.
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/secureexec-ebpf-probe"
    )))
    .map_err(|e| format!("failed to load eBPF: {e}"))?;

    // -- process --
    attach_tracepoint(&mut ebpf, "sched_process_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(&mut ebpf, "sched_process_exit", "sched", "sched_process_exit")?;
    attach_tracepoint(&mut ebpf, "sched_process_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut ebpf, "sys_enter_exit_group", "syscalls", "sys_enter_exit_group")?;
    attach_tracepoint(&mut ebpf, "sys_enter_execve", "syscalls", "sys_enter_execve")?;
    // -- file --
    attach_tracepoint(&mut ebpf, "sys_enter_openat",    "syscalls", "sys_enter_openat")?;
    attach_tracepoint(&mut ebpf, "sys_enter_unlinkat",  "syscalls", "sys_enter_unlinkat")?;
    attach_tracepoint(&mut ebpf, "sys_enter_renameat2", "syscalls", "sys_enter_renameat2")?;
    // -- security: privilege --
    attach_tracepoint(&mut ebpf, "sys_enter_setuid",   "syscalls", "sys_enter_setuid")?;
    attach_tracepoint(&mut ebpf, "sys_enter_setgid",   "syscalls", "sys_enter_setgid")?;
    attach_tracepoint(&mut ebpf, "sys_enter_setreuid", "syscalls", "sys_enter_setreuid")?;
    attach_tracepoint(&mut ebpf, "sys_enter_setregid", "syscalls", "sys_enter_setregid")?;
    attach_tracepoint(&mut ebpf, "sys_enter_setresuid","syscalls", "sys_enter_setresuid")?;
    attach_tracepoint(&mut ebpf, "sys_enter_setresgid","syscalls", "sys_enter_setresgid")?;
    // -- security: various --
    attach_tracepoint(&mut ebpf, "sys_enter_ptrace",   "syscalls", "sys_enter_ptrace")?;
    attach_tracepoint(&mut ebpf, "sys_enter_fchmodat", "syscalls", "sys_enter_fchmodat")?;
    attach_tracepoint(&mut ebpf, "sys_enter_chown",    "syscalls", "sys_enter_chown")?;
    attach_tracepoint(&mut ebpf, "sys_enter_lchown",   "syscalls", "sys_enter_lchown")?;
    attach_tracepoint(&mut ebpf, "sys_enter_mmap",     "syscalls", "sys_enter_mmap")?;
    attach_tracepoint(&mut ebpf, "module_load",        "module",   "module_load")?;
    attach_tracepoint(&mut ebpf, "sys_enter_process_vm_readv",  "syscalls", "sys_enter_process_vm_readv")?;
    attach_tracepoint(&mut ebpf, "sys_enter_process_vm_writev", "syscalls", "sys_enter_process_vm_writev")?;
    attach_tracepoint(&mut ebpf, "sys_enter_memfd_create",      "syscalls", "sys_enter_memfd_create")?;
    attach_tracepoint(&mut ebpf, "sys_enter_bpf",               "syscalls", "sys_enter_bpf")?;
    attach_tracepoint(&mut ebpf, "sys_enter_capset",            "syscalls", "sys_enter_capset")?;
    attach_tracepoint(&mut ebpf, "sys_enter_kill",              "syscalls", "sys_enter_kill")?;
    attach_tracepoint(&mut ebpf, "sys_enter_unshare",           "syscalls", "sys_enter_unshare")?;
    attach_tracepoint(&mut ebpf, "sys_enter_setns",             "syscalls", "sys_enter_setns")?;
    attach_tracepoint(&mut ebpf, "sys_enter_keyctl",            "syscalls", "sys_enter_keyctl")?;
    attach_tracepoint(&mut ebpf, "sys_enter_io_uring_setup",    "syscalls", "sys_enter_io_uring_setup")?;
    attach_tracepoint(&mut ebpf, "sys_enter_mount",             "syscalls", "sys_enter_mount")?;
    attach_tracepoint(&mut ebpf, "sys_enter_umount",            "syscalls", "sys_enter_umount")?;
    attach_tracepoint(&mut ebpf, "sys_enter_symlinkat",         "syscalls", "sys_enter_symlinkat")?;
    attach_tracepoint(&mut ebpf, "sys_enter_linkat",            "syscalls", "sys_enter_linkat")?;
    attach_tracepoint(&mut ebpf, "sys_enter_sendto",            "syscalls", "sys_enter_sendto")?;
    attach_tracepoint(&mut ebpf, "sys_enter_sendmsg",           "syscalls", "sys_enter_sendmsg")?;
    attach_tracepoint(&mut ebpf, "sys_enter_sendmmsg",          "syscalls", "sys_enter_sendmmsg")?;

    // -- kprobes --
    attach_kprobe(&mut ebpf, "tcp_v4_connect",      "tcp_v4_connect")?;
    attach_kretprobe(&mut ebpf, "tcp_v4_connect_ret", "tcp_v4_connect")?;
    attach_kretprobe(&mut ebpf, "inet_csk_accept_ret", "inet_csk_accept")?;
    attach_kprobe(&mut ebpf, "udp_sendmsg",         "udp_sendmsg")?;
    attach_kprobe(&mut ebpf, "tcp_v6_connect",      "tcp_v6_connect")?;
    attach_kretprobe(&mut ebpf, "tcp_v6_connect_ret", "tcp_v6_connect")?;
    attach_kprobe(&mut ebpf, "inet_bind_entry",     "inet_bind")?;
    attach_kprobe(&mut ebpf, "inet6_bind_entry",    "inet6_bind")?;

    info!("linux-ebpf: all telemetry programs attached");
    Ok(ebpf)
}

// ---------------------------------------------------------------------------
// Drop counter helpers
// ---------------------------------------------------------------------------

/// Sum all per-CPU values for a single PerCpuArray<u64> entry at index 0.
fn read_percpu_total(map: &PerCpuArray<aya::maps::MapData, u64>) -> u64 {
    match map.get(&0, 0) {
        Ok(vals) => vals.iter().copied().sum(),
        Err(_) => 0,
    }
}

type DropMaps = (
    Option<PerCpuArray<aya::maps::MapData, u64>>,
    Option<PerCpuArray<aya::maps::MapData, u64>>,
    Option<PerCpuArray<aya::maps::MapData, u64>>,
    Option<PerCpuArray<aya::maps::MapData, u64>>,
);

/// Try to take all four drop-counter maps from the Ebpf handle.
/// Returns None per slot if a map is missing (graceful degradation).
fn take_drop_maps(ebpf: &mut Ebpf) -> DropMaps {
    let proc_dc = ebpf.take_map("PROC_DROP_COUNT")
        .and_then(|m| PerCpuArray::try_from(m).ok());
    let file_dc = ebpf.take_map("FILE_DROP_COUNT")
        .and_then(|m| PerCpuArray::try_from(m).ok());
    let net_dc = ebpf.take_map("NET_DROP_COUNT")
        .and_then(|m| PerCpuArray::try_from(m).ok());
    let sec_dc = ebpf.take_map("SEC_DROP_COUNT")
        .and_then(|m| PerCpuArray::try_from(m).ok());
    (proc_dc, file_dc, net_dc, sec_dc)
}

const DROP_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Read all available drop-counter maps and store totals in the shared counters.
fn refresh_drop_counters(maps: &DropMaps, counters: &EbpfDropCounters) {
    if let Some(ref m) = maps.0 {
        counters.process.store(read_percpu_total(m), Ordering::Relaxed);
    }
    if let Some(ref m) = maps.1 {
        counters.file.store(read_percpu_total(m), Ordering::Relaxed);
    }
    if let Some(ref m) = maps.2 {
        counters.network.store(read_percpu_total(m), Ordering::Relaxed);
    }
    if let Some(ref m) = maps.3 {
        counters.security.store(read_percpu_total(m), Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Shared epoll poll loop
// ---------------------------------------------------------------------------

// epoll data tags — used only for registration; we drain all buffers on every wakeup.
const TAG_PROC: u64 = 0;
const TAG_FILE: u64 = 1;
const TAG_NET:  u64 = 2;
const TAG_SEC:  u64 = 3;

// How long epoll.wait() blocks before re-checking the stop flag.
const EPOLL_TIMEOUT_MS: u16 = 100;

/// Create an epoll instance and register all 4 ring buffer file descriptors.
fn make_epoll(
    proc_rb: &RingBuf<MapData>,
    file_rb: &RingBuf<MapData>,
    net_rb:  &RingBuf<MapData>,
    sec_rb:  &RingBuf<MapData>,
) -> std::result::Result<Epoll, String> {
    let epoll = Epoll::new(EpollCreateFlags::empty())
        .map_err(|e| format!("epoll_create: {e}"))?;

    // Safety: each RingBuf outlives the epoll instance (both live in poll_loop's
    // stack frame), so the borrowed FD is valid for the lifetime of the registration.
    unsafe {
        let fd = BorrowedFd::borrow_raw(proc_rb.as_raw_fd());
        epoll.add(fd, EpollEvent::new(EpollFlags::EPOLLIN, TAG_PROC))
            .map_err(|e| format!("epoll add PROCESS_EVENTS: {e}"))?;
        let fd = BorrowedFd::borrow_raw(file_rb.as_raw_fd());
        epoll.add(fd, EpollEvent::new(EpollFlags::EPOLLIN, TAG_FILE))
            .map_err(|e| format!("epoll add FILE_EVENTS: {e}"))?;
        let fd = BorrowedFd::borrow_raw(net_rb.as_raw_fd());
        epoll.add(fd, EpollEvent::new(EpollFlags::EPOLLIN, TAG_NET))
            .map_err(|e| format!("epoll add NETWORK_EVENTS: {e}"))?;
        let fd = BorrowedFd::borrow_raw(sec_rb.as_raw_fd());
        epoll.add(fd, EpollEvent::new(EpollFlags::EPOLLIN, TAG_SEC))
            .map_err(|e| format!("epoll add SECURITY_EVENTS: {e}"))?;
    }

    Ok(epoll)
}

/// Core poll loop shared by `poll_ebpf` and `poll_ebpf_from_arc`.
///
/// Blocks on epoll (up to 100 ms) then drains all 4 ring buffers.  This means
/// the kernel wakes us the instant any buffer has data — no busy-spin or fixed
/// sleep latency.
fn poll_loop(
    proc_rb: &mut RingBuf<MapData>,
    file_rb: &mut RingBuf<MapData>,
    net_rb:  &mut RingBuf<MapData>,
    sec_rb:  &mut RingBuf<MapData>,
    drop_maps: &DropMaps,
    tx: &mpsc::Sender<BpfEvent>,
    stop: &AtomicBool,
    drop_counters: &EbpfDropCounters,
) -> std::result::Result<(), String> {
    let epoll = make_epoll(proc_rb, file_rb, net_rb, sec_rb)?;
    let mut epoll_events = [EpollEvent::empty(); 4];
    let mut last_drop_read = Instant::now();

    while !stop.load(Ordering::Acquire) {
        // Block until at least one ring buffer has data, or timeout expires.
        // Errors other than EINTR are unexpected; treat them as transient and continue.
        let _ = epoll.wait(&mut epoll_events, EPOLL_TIMEOUT_MS);

        // Drain all buffers regardless of which FD(s) woke us — a single wakeup
        // can cover multiple buffers, and level-triggered mode guarantees we won't
        // miss events as long as we drain completely.
        while let Some(item) = proc_rb.next() {
            if let Some(evt) = parse_process_event(&*item) {
                match tx.try_send(evt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        drop_counters.channel_full.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
        while let Some(item) = file_rb.next() {
            if let Some(evt) = parse_file_event(&*item) {
                match tx.try_send(evt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        drop_counters.channel_full.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
        while let Some(item) = net_rb.next() {
            if let Some(evt) = parse_network_event(&*item) {
                match tx.try_send(evt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        drop_counters.channel_full.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
        while let Some(item) = sec_rb.next() {
            if let Some(evt) = parse_security_event(&*item) {
                match tx.try_send(evt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        drop_counters.channel_full.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => return Ok(()),
                }
            }
        }

        if last_drop_read.elapsed() >= DROP_POLL_INTERVAL {
            refresh_drop_counters(drop_maps, drop_counters);
            last_drop_read = Instant::now();
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Variant of `poll_ebpf` used when the `Ebpf` object is shared behind an
/// `Arc<Mutex>` (e.g. when the eBPF firewall watcher holds another reference).
/// Takes ring-buffer maps while holding the lock, then releases the lock before
/// entering the poll loop.
pub(super) fn poll_ebpf_from_arc(
    arc: Arc<std::sync::Mutex<Ebpf>>,
    tx: mpsc::Sender<BpfEvent>,
    stop: Arc<AtomicBool>,
    drop_counters: Arc<EbpfDropCounters>,
) {
    let (mut proc_rb, mut file_rb, mut net_rb, mut sec_rb, drop_maps) = {
        let mut guard = match arc.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let proc_rb = match guard.take_map("PROCESS_EVENTS")
            .and_then(|m| RingBuf::try_from(m).ok())
        {
            Some(rb) => rb,
            None => { error!("linux-ebpf: PROCESS_EVENTS map not found"); return; }
        };
        let file_rb = match guard.take_map("FILE_EVENTS")
            .and_then(|m| RingBuf::try_from(m).ok())
        {
            Some(rb) => rb,
            None => { error!("linux-ebpf: FILE_EVENTS map not found"); return; }
        };
        let net_rb = match guard.take_map("NETWORK_EVENTS")
            .and_then(|m| RingBuf::try_from(m).ok())
        {
            Some(rb) => rb,
            None => { error!("linux-ebpf: NETWORK_EVENTS map not found"); return; }
        };
        let sec_rb = match guard.take_map("SECURITY_EVENTS")
            .and_then(|m| RingBuf::try_from(m).ok())
        {
            Some(rb) => rb,
            None => { error!("linux-ebpf: SECURITY_EVENTS map not found"); return; }
        };
        let dm = take_drop_maps(&mut guard);
        (proc_rb, file_rb, net_rb, sec_rb, dm)
    };
    // Lock released before entering the poll loop.

    info!("linux-ebpf: polling ring buffers via epoll (shared Ebpf)");

    if let Err(e) = poll_loop(
        &mut proc_rb, &mut file_rb, &mut net_rb, &mut sec_rb,
        &drop_maps, &tx, &stop, &drop_counters,
    ) {
        error!(error = %e, "linux-ebpf: poll loop error (shared)");
    }

    debug!("linux-ebpf: poll thread stopping (shared)");
}

/// Take ring buffer maps from a loaded `Ebpf` handle and enter the poll loop.
/// Intended to run on a dedicated blocking thread.
pub(super) fn poll_ebpf(
    mut ebpf: Ebpf,
    tx: mpsc::Sender<BpfEvent>,
    stop: Arc<AtomicBool>,
    drop_counters: Arc<EbpfDropCounters>,
) -> std::result::Result<(), String> {
    // `take_map` returns None if the probe object is stale or the map was
    // renamed; panicking here would crash the agent on any loader mismatch.
    // Surface a structured error so the caller can log it and fall back.
    let take_rb = |ebpf: &mut Ebpf, name: &str| -> std::result::Result<RingBuf<MapData>, String> {
        let m = ebpf.take_map(name).ok_or_else(|| format!("map '{name}' not found in eBPF object"))?;
        RingBuf::try_from(m).map_err(|e| format!("{name}: {e}"))
    };
    let mut proc_rb = take_rb(&mut ebpf, "PROCESS_EVENTS")?;
    let mut file_rb = take_rb(&mut ebpf, "FILE_EVENTS")?;
    let mut net_rb  = take_rb(&mut ebpf, "NETWORK_EVENTS")?;
    let mut sec_rb  = take_rb(&mut ebpf, "SECURITY_EVENTS")?;
    let drop_maps = take_drop_maps(&mut ebpf);

    info!("linux-ebpf: polling ring buffers via epoll");

    poll_loop(
        &mut proc_rb, &mut file_rb, &mut net_rb, &mut sec_rb,
        &drop_maps, &tx, &stop, &drop_counters,
    )?;

    debug!("linux-ebpf: poll thread stopping");
    Ok(())
}

// ---------------------------------------------------------------------------
// Attach helpers
// ---------------------------------------------------------------------------

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    tp_name: &str,
) -> std::result::Result<(), String> {
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("program {prog_name} not found"))?
        .try_into()
        .map_err(|e| format!("{prog_name}: {e}"))?;
    prog.load().map_err(|e| format!("{prog_name} load: {e}"))?;
    prog.attach(category, tp_name)
        .map_err(|e| format!("{prog_name} attach: {e}"))?;
    Ok(())
}

fn attach_kprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
) -> std::result::Result<(), String> {
    let prog: &mut KProbe = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("program {prog_name} not found"))?
        .try_into()
        .map_err(|e| format!("{prog_name}: {e}"))?;
    prog.load().map_err(|e| format!("{prog_name} load: {e}"))?;
    prog.attach(fn_name, 0)
        .map_err(|e| format!("{prog_name} attach: {e}"))?;
    Ok(())
}

fn attach_kretprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
) -> std::result::Result<(), String> {
    let prog: &mut KProbe = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("program {prog_name} not found"))?
        .try_into()
        .map_err(|e| format!("{prog_name}: {e}"))?;
    prog.load().map_err(|e| format!("{prog_name} load: {e}"))?;
    prog.attach(fn_name, 0)
        .map_err(|e| format!("{prog_name} attach: {e}"))?;
    Ok(())
}
