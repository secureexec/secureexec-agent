use std::collections::HashMap;
use std::fs;

use chrono::{DateTime, Utc};
use secureexec_generic::process_table::{ParentResolver, ResolvedProcess};

/// Cached info about a running process, read from /proc.
#[derive(Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub start_time: DateTime<Utc>,
    /// Container ID extracted from /proc/{pid}/cgroup, or None if not containerized.
    pub container_id: Option<String>,
}

/// Read full process information from /proc for a given pid.
pub fn read_proc_info(pid: u32) -> Option<ProcInfo> {
    let stat = read_proc_stat(pid)?;
    let path = read_proc_exe(pid).unwrap_or_default();
    let name = if !path.is_empty() {
        path.rsplit('/').next().unwrap_or(&path).to_string()
    } else {
        stat.name.clone()
    };
    let cmdline = read_proc_cmdline(pid).unwrap_or_else(|| name.clone());
    let container_id = read_container_id(pid);
    Some(ProcInfo {
        pid,
        parent_pid: stat.parent_pid,
        uid: stat.uid,
        name,
        path,
        cmdline,
        start_time: stat.start_time,
        container_id,
    })
}

/// Read the process start_time from /proc/[pid]/stat.
pub fn read_proc_start_time(pid: u32) -> Option<DateTime<Utc>> {
    read_proc_stat(pid).map(|s| s.start_time)
}

pub fn read_proc_exe(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

pub fn read_proc_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let cmdline = raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    if cmdline.is_empty() {
        None
    } else {
        Some(cmdline)
    }
}

pub fn read_proc_cwd(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Extract a container ID from /proc/{pid}/cgroup.
/// Supports Docker, containerd/CRI, and cgroup v2 scopes.
pub fn read_container_id(pid: u32) -> Option<String> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in cgroup.lines() {
        if let Some(id) = extract_container_id_from_line(line) {
            return Some(id);
        }
    }
    None
}

fn extract_container_id_from_line(line: &str) -> Option<String> {
    // Format: "hierarchy:controllers:path"
    let path = line.splitn(3, ':').nth(2)?;
    for segment in path.split('/') {
        // Strip known prefixes and trailing .scope
        let segment = segment.trim_end_matches(".scope");
        let id_candidate = if let Some(rest) = segment.strip_prefix("docker-") {
            rest
        } else if let Some(rest) = segment.strip_prefix("cri-containerd-") {
            rest
        } else if let Some(rest) = segment.strip_prefix("containerd-") {
            rest
        } else {
            segment
        };
        // A container ID is exactly 64 lowercase hex characters
        if id_candidate.len() == 64 && id_candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(id_candidate.to_string());
        }
    }
    None
}

/// Load a uid → username map from /etc/passwd.
/// Called once at agent startup; the result is cached in the sensor.
pub fn load_uid_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Ok(content) = fs::read_to_string("/etc/passwd") else {
        return map;
    };
    for line in content.lines() {
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let Some(username) = parts.next() else { continue };
        let _ = parts.next(); // password placeholder
        let Some(uid_str) = parts.next() else { continue };
        if let Ok(uid) = uid_str.parse::<u32>() {
            map.insert(uid, username.to_string());
        }
    }
    map
}

struct StatInfo {
    name: String,
    parent_pid: u32,
    uid: u32,
    start_time: DateTime<Utc>,
}

fn read_proc_stat(pid: u32) -> Option<StatInfo> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;

    // `comm` is the second field, wrapped in parens, and may itself contain
    // spaces, parens, or arbitrary bytes (e.g. `(ba)d(name)`). The rest of
    // the line is fixed-width whitespace-separated numeric fields, so the
    // LAST `)` in the line reliably marks the end of comm regardless of
    // what the process chose to set its name to.
    let comm_start = stat.find('(')?;
    let comm_end = stat.rfind(')')?;
    if comm_end <= comm_start {
        return None;
    }
    let name = stat[comm_start + 1..comm_end].to_string();

    // Guard against a truncated `/proc/pid/stat` line: if there aren't at
    // least two bytes after `)` we cannot parse the state+ppid fields.
    if comm_end + 2 > stat.len() {
        return None;
    }
    let rest = &stat[comm_end + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let parent_pid: u32 = fields.get(1)?.parse().ok()?;
    let starttime_ticks: u64 = fields.get(19)?.parse().ok()?;

    let clock_ticks = clock_ticks_per_sec();
    let boot_time = boot_time_secs();
    // `clock_ticks_per_sec` falls back to 100 on sysconf failure so this
    // division cannot panic even on exotic libcs/sysconf errors.
    let start_secs = boot_time + (starttime_ticks / clock_ticks);
    let start_time = DateTime::from_timestamp(start_secs as i64, 0).unwrap_or_default();

    let uid = read_proc_uid(pid).unwrap_or(0);

    Some(StatInfo {
        name,
        parent_pid,
        uid,
        start_time,
    })
}

fn read_proc_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn clock_ticks_per_sec() -> u64 {
    // Safety: sysconf(_SC_CLK_TCK) has no side effects; a negative return
    // indicates an error. Fall back to the canonical 100 Hz value rather
    // than trust a bogus value (or 0, which would div-by-zero in callers).
    let raw = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if raw <= 0 { 100 } else { raw as u64 }
}

fn boot_time_secs() -> u64 {
    let Ok(stat) = fs::read_to_string("/proc/stat") else {
        return 0;
    };
    for line in stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Resolves UID → username using the host `/etc/passwd` and, for container
/// processes, their namespaced `/proc/{pid}/root/etc/passwd`.
pub struct UidResolver {
    host_map: HashMap<u32, String>,
    container_cache: HashMap<String, HashMap<u32, String>>,
}

impl UidResolver {
    pub fn new(host_map: HashMap<u32, String>) -> Self {
        Self { host_map, container_cache: HashMap::new() }
    }

    /// Resolve a UID to a username.  Checks the host `/etc/passwd` first;
    /// falls back to reading `/proc/{pid}/root/etc/passwd` for container processes.
    pub fn resolve(&mut self, uid: u32, pid: u32) -> String {
        if let Some(name) = self.host_map.get(&uid) {
            return name.clone();
        }
        self.resolve_container(uid, pid)
    }

    fn resolve_container(&mut self, uid: u32, pid: u32) -> String {
        let cid = match read_container_id(pid) {
            Some(id) => id,
            None => return String::new(),
        };
        if let Some(cmap) = self.container_cache.get(&cid) {
            return cmap.get(&uid).cloned().unwrap_or_default();
        }
        let cmap = load_container_uid_map(pid);
        let result = cmap.get(&uid).cloned().unwrap_or_default();
        self.container_cache.insert(cid, cmap);
        result
    }
}

/// Read `/proc/{pid}/root/etc/passwd` to get a UID → username map for the
/// mount namespace of the given process (typically a container).
fn load_container_uid_map(pid: u32) -> HashMap<u32, String> {
    let path = format!("/proc/{pid}/root/etc/passwd");
    let mut map = HashMap::new();
    let Ok(content) = fs::read_to_string(path) else {
        return map;
    };
    for line in content.lines() {
        if line.starts_with('#') { continue; }
        let mut parts = line.split(':');
        let Some(username) = parts.next() else { continue };
        let _ = parts.next();
        let Some(uid_str) = parts.next() else { continue };
        if let Ok(uid) = uid_str.parse::<u32>() {
            map.insert(uid, username.to_string());
        }
    }
    map
}

/// Resolves parent processes by reading `/proc/{pid}`.
pub struct ProcfsParentResolver {
    uid_map: HashMap<u32, String>,
}

impl ProcfsParentResolver {
    pub fn new(uid_map: HashMap<u32, String>) -> Self {
        Self { uid_map }
    }
}

impl ParentResolver for ProcfsParentResolver {
    fn resolve(&self, pid: u32) -> Option<ResolvedProcess> {
        let info = read_proc_info(pid)?;
        let username = self.uid_map.get(&info.uid)
            .cloned()
            .or_else(|| load_container_uid_map(pid).get(&info.uid).cloned())
            .unwrap_or_default();
        Some(ResolvedProcess {
            pid: info.pid,
            parent_pid: info.parent_pid,
            uid: info.uid,
            username,
            name: info.name,
            path: info.path,
            cmdline: info.cmdline,
            start_time: info.start_time,
            container_id: info.container_id.unwrap_or_default(),
        })
    }
}
