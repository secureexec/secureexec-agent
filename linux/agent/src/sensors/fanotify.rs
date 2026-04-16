use std::collections::HashMap;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::num::NonZeroUsize;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use lru::LruCache;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use secureexec_generic::error::{AgentError, Result};
use secureexec_generic::event::{Event, EventKind, ProcessBlockedEvent};
use secureexec_generic::pipeline::BlocklistUpdater;
use secureexec_generic::sensor::Sensor;
use secureexec_generic::transport::pb::BlocklistRule;

use super::procfs;

// ---------------------------------------------------------------------------
// fanotify constants (Linux — not yet exposed by libc 0.2.x on all targets)
// ---------------------------------------------------------------------------

const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
const FAN_CLOEXEC: u32 = 0x0000_0001;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

const FAN_METADATA_VERSION: u8 = 3;

const AT_FDCWD: libc::c_int = -100;

/// Maximum bytes to read when computing a SHA-256 hash (50 MB, matching exe_hash.rs).
const MAX_HASH_READ: usize = 50 * 1024 * 1024;
const HASH_BUF: usize = 64 * 1024;
const HASH_CACHE_CAP: usize = 16384;

// ---------------------------------------------------------------------------
// fanotify kernel structs
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

// ---------------------------------------------------------------------------
// Hash cache key
// ---------------------------------------------------------------------------

#[derive(Hash, Eq, PartialEq)]
struct HashKey {
    dev: u64,
    ino: u64,
    mtime_ns: i64,
    size: u64,
}

// ---------------------------------------------------------------------------
// Blocklist state (shared between sensor loop and blocklist poll task)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct BlocklistState {
    /// sha256_hex → rule_name
    hash_rules: HashMap<String, String>,
    /// absolute path → rule_name
    path_rules: HashMap<String, String>,
}

impl BlocklistState {
    fn from_rules(rules: &[BlocklistRule]) -> Self {
        let mut s = Self::default();
        for r in rules {
            match r.match_type.as_str() {
                "hash" => { s.hash_rules.insert(r.match_value.clone(), r.name.clone()); }
                "path" => { s.path_rules.insert(r.match_value.clone(), r.name.clone()); }
                _ => {}
            }
        }
        s
    }

    fn check_path<'a>(&self, path: &'a str) -> Option<(&str, &'a str)> {
        self.path_rules.get(path).map(move |name| (name.as_str(), path))
    }

    fn check_hash<'a>(&self, hash: &'a str) -> Option<(&str, &'a str)> {
        self.hash_rules.get(hash).map(move |name| (name.as_str(), hash))
    }
}

/// Shared handle: writers build a new `Arc<BlocklistState>` and swap it in;
/// readers clone the `Arc` (cheap pointer bump) and work with a consistent
/// snapshot without holding any lock during the actual path/hash checks.
type SharedBlocklist = std::sync::RwLock<Arc<BlocklistState>>;

// ---------------------------------------------------------------------------
// FanotifySensor
// ---------------------------------------------------------------------------

/// Linux fanotify sensor that intercepts `execve` attempts and enforces
/// the server-managed blocklist (block by SHA-256 hash or absolute path).
///
/// The sensor holds a shared `Arc<BlocklistState>` behind an `RwLock`;
/// the pipeline's blocklist poll task calls `update_blocklist()` when rules
/// change, and the fanotify loop reads the state on each exec event.
#[derive(Clone)]
pub struct FanotifySensor {
    state: Arc<SharedBlocklist>,
}

impl FanotifySensor {
    pub fn new() -> Self {
        Self { state: Arc::new(std::sync::RwLock::new(Arc::new(BlocklistState::default()))) }
    }
}

impl BlocklistUpdater for FanotifySensor {
    fn update_blocklist(&self, rules: Vec<BlocklistRule>) {
        let new_state = Arc::new(BlocklistState::from_rules(&rules));
        if let Ok(mut s) = self.state.write() {
            *s = new_state;
        }
    }
}

#[async_trait]
impl Sensor for FanotifySensor {
    fn name(&self) -> &str {
        "fanotify"
    }

    async fn run(&self, tx: mpsc::Sender<Event>, mut cancel: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let state = Arc::clone(&self.state);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = Arc::clone(&shutdown);

        let blocking = tokio::task::spawn_blocking(move || {
            fanotify_loop(state, tx, shutdown2)
        });
        tokio::pin!(blocking);

        // Wait for shutdown signal and notify the blocking thread.
        tokio::select! {
            _ = cancel.changed() => {
                shutdown.store(true, Ordering::Relaxed);
            }
            result = &mut blocking => {
                match result {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(AgentError::Platform(e.to_string())),
                }
            }
        }

        // Wait for the blocking thread to finish processing and close fan_fd
        // before returning.  The poll timeout is 200 ms so this completes quickly.
        match blocking.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(AgentError::Platform(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Blocking fanotify event loop (runs on a dedicated thread pool thread)
// ---------------------------------------------------------------------------

fn fanotify_loop(
    state: Arc<SharedBlocklist>,
    tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let fan_fd = init_fanotify().map_err(|e| AgentError::Platform(format!("fanotify_init: {e}")))?;
    mark_filesystem(fan_fd).map_err(|e| {
        // SAFETY: fan_fd is a valid fd created by fanotify_init above.
        unsafe { libc::close(fan_fd) };
        AgentError::Platform(format!("fanotify_mark: {e}"))
    })?;

    info!("fanotify sensor started (FAN_OPEN_EXEC_PERM on '/')");

    // Safety: HASH_CACHE_CAP is a non-zero constant.
    let cap = NonZeroUsize::new(HASH_CACHE_CAP).unwrap();
    let mut hash_cache: LruCache<HashKey, (String, u64)> = LruCache::new(cap);
    let mut event_buf = vec![0u8; 4096];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Poll the fanotify fd with a 200 ms timeout so we can check `shutdown`.
        let ready = poll_readable(fan_fd, 200);
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            warn!(error = %err, "fanotify poll error");
            break;
        }
        if ready == 0 {
            continue;
        }

        let n = unsafe { libc::read(fan_fd, event_buf.as_mut_ptr() as *mut libc::c_void, event_buf.len()) };
        if n <= 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) || err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            warn!(error = %err, "fanotify read error");
            break;
        }

        let meta_size = size_of::<FanotifyEventMetadata>();
        let mut offset = 0usize;
        let n = n as usize;

        while offset + meta_size <= n {
            // SAFETY: buffer is aligned to u8; we validate size before casting.
            let meta = unsafe { &*(event_buf.as_ptr().add(offset) as *const FanotifyEventMetadata) };

            if meta.event_len == 0 { break; }

            if meta.vers != FAN_METADATA_VERSION {
                warn!("unexpected fanotify metadata version {}", meta.vers);
                if meta.fd >= 0 {
                    respond(fan_fd, meta.fd, FAN_ALLOW);
                }
                offset += meta.event_len as usize;
                continue;
            }

            if meta.mask & FAN_OPEN_EXEC_PERM != 0 && meta.fd >= 0 {
                handle_exec_event(
                    fan_fd,
                    meta,
                    &state,
                    &tx,
                    &mut hash_cache,
                );
            } else if meta.fd >= 0 {
                // SAFETY: meta.fd is a valid fd received from the kernel.
                unsafe { libc::close(meta.fd) };
            }

            offset += meta.event_len as usize;
        }
    }

    // SAFETY: fan_fd was created by fanotify_init and is valid until here.
    unsafe { libc::close(fan_fd) };
    debug!("fanotify sensor stopped");
    Ok(())
}

fn handle_exec_event(
    fan_fd: RawFd,
    meta: &FanotifyEventMetadata,
    state: &Arc<SharedBlocklist>,
    tx: &mpsc::Sender<Event>,
    hash_cache: &mut LruCache<HashKey, (String, u64)>,
) {
    let event_fd = meta.fd;
    let event_pid = meta.pid as u32;

    // Resolve the path from the open fd.
    let path = read_fd_path(event_fd).unwrap_or_default();

    // Clone the Arc (cheap pointer bump) so we don't hold the lock during
    // path/hash checks or I/O.
    let blocklist: Arc<BlocklistState> = match state.read() {
        Ok(s) => Arc::clone(&s),
        Err(_) => {
            respond(fan_fd, event_fd, FAN_ALLOW);
            return;
        }
    };

    // --- Check path rule ---
    if let Some((rule_name, match_value)) = blocklist.check_path(&path) {
        let cmdline = procfs::read_proc_cmdline(event_pid).unwrap_or_default();
        debug!(pid = event_pid, path = %path, rule = %rule_name, "blocking by path");
        respond(fan_fd, event_fd, FAN_DENY);
        emit_blocked(tx, event_pid, &path, "", 0, rule_name, "path", match_value, &cmdline);
        return;
    }

    // --- Compute hash and check hash rule ---
    let (hash, size) = hash_from_fd(event_fd, hash_cache);

    if !hash.is_empty() {
        if let Some((rule_name, match_value)) = blocklist.check_hash(&hash) {
        let cmdline = procfs::read_proc_cmdline(event_pid).unwrap_or_default();
        debug!(pid = event_pid, hash = %hash, rule = %rule_name, "blocking by hash");
            respond(fan_fd, event_fd, FAN_DENY);
            emit_blocked(tx, event_pid, &path, &hash, size, rule_name, "hash", match_value, &cmdline);
            return;
        }
    }

    respond(fan_fd, event_fd, FAN_ALLOW);
}

/// Write a fanotify permission response for `event_fd` and close the fd.
fn respond(fan_fd: RawFd, event_fd: RawFd, response: u32) {
    let resp = FanotifyResponse { fd: event_fd, response };
    // SAFETY: fan_fd and event_fd are valid fds; resp is correctly sized.
    unsafe {
        libc::write(
            fan_fd,
            &resp as *const FanotifyResponse as *const libc::c_void,
            size_of::<FanotifyResponse>(),
        );
        libc::close(event_fd);
    }
}

/// Counter incremented whenever a ProcessBlocked event is dropped because the
/// pipeline channel is saturated. Surfaced separately so operators can alert
/// on sustained fanotify saturation (which otherwise looks like silence).
pub static FANOTIFY_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

fn emit_blocked(
    tx: &mpsc::Sender<Event>,
    pid: u32,
    path: &str,
    exe_hash: &str,
    exe_size: u64,
    rule_name: &str,
    match_type: &str,
    match_value: &str,
    cmdline: &str,
) {
    let event = Event::new(
        String::new(), // hostname filled by the pipeline ingest loop
        EventKind::ProcessBlocked(ProcessBlockedEvent {
            pid,
            user_id: String::new(), // resolved by pipeline
            process_name: path.rsplit('/').next().unwrap_or("").to_string(),
            process_guid: String::new(),
            path: path.to_string(),
            exe_hash: exe_hash.to_string(),
            exe_size,
            rule_name: rule_name.to_string(),
            match_type: match_type.to_string(),
            match_value: match_value.to_string(),
            cmdline: cmdline.to_string(),
        }),
    );
    // IMPORTANT: never call `blocking_send` here. This function runs on the
    // fanotify worker thread; if it stalls, the kernel's fanotify queue fills
    // up and overflowed events are force-allowed, which would let processes
    // bypass the blocklist entirely. Prefer dropping the *telemetry* event
    // over letting the kernel drop permission events.
    match tx.try_send(event) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            let n = FANOTIFY_EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_power_of_two() {
                warn!(dropped = n, "fanotify: pipeline channel full — dropping ProcessBlocked events");
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            warn!("fanotify: pipeline channel closed — dropping ProcessBlocked event");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_fanotify() -> io::Result<RawFd> {
    // SAFETY: fanotify_init is a standard Linux syscall.
    let fd = unsafe { libc::syscall(libc::SYS_fanotify_init, FAN_CLASS_CONTENT | FAN_CLOEXEC, libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as RawFd)
}

fn mark_filesystem(fan_fd: RawFd) -> io::Result<()> {
    // Mark the root mount so all exec events are captured.
    let path = b"/\0";
    // SAFETY: all args are valid; path is a null-terminated C string.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            FAN_OPEN_EXEC_PERM,
            AT_FDCWD,
            path.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `poll()` a single fd for POLLIN.  Returns the number of ready fds (0 = timeout, <0 = error).
fn poll_readable(fd: RawFd, timeout_ms: i32) -> i32 {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: pfd is correctly initialised.
    unsafe { libc::poll(&mut pfd, 1, timeout_ms) }
}

/// Read the path of an open file descriptor via `/proc/self/fd/{fd}` (`readlink`).
fn read_fd_path(fd: RawFd) -> Option<String> {
    let link = format!("/proc/self/fd/{fd}");
    std::fs::read_link(&link).ok().map(|p| p.to_string_lossy().into_owned())
}

/// Compute (or look up cached) SHA-256 hash + file size for an open fd.
/// Uses `(dev, ino, mtime_ns, size)` as the cache key.
fn hash_from_fd(fd: RawFd, cache: &mut LruCache<HashKey, (String, u64)>) -> (String, u64) {
    // stat the fd.
    let mut stat: MaybeUninit<libc::stat64> = MaybeUninit::uninit();
    // SAFETY: stat64 is valid for fstat64; fd comes from the kernel.
    let ret = unsafe { libc::fstat64(fd, stat.as_mut_ptr()) };
    if ret < 0 {
        return (String::new(), 0);
    }
    // SAFETY: fstat64 succeeded, so stat is initialised.
    let stat = unsafe { stat.assume_init() };

    let key = HashKey {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
        mtime_ns: stat.st_mtime * 1_000_000_000 + stat.st_mtime_nsec,
        size: stat.st_size as u64,
    };
    let file_size = stat.st_size as u64;

    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }

    // Seek to start and hash the file content.
    unsafe { libc::lseek64(fd, 0, libc::SEEK_SET) };
    let hash = hash_fd_content(fd, MAX_HASH_READ);
    let result = (hash, file_size);
    cache.put(key, result.clone());
    result
}

fn hash_fd_content(fd: RawFd, max_bytes: usize) -> String {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    let mut remaining = max_bytes;

    loop {
        if remaining == 0 { break; }
        let to_read = remaining.min(buf.len());
        // SAFETY: buf has capacity `to_read`; fd is a valid open file descriptor.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, to_read) };
        if n <= 0 { break; }
        hasher.update(&buf[..n as usize]);
        remaining -= n as usize;
    }
    hex::encode(hasher.finalize())
}
