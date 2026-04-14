use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::event::{Event, EventKind};

/// Resolved parent process info returned by platform-specific resolvers.
pub struct ResolvedProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub username: String,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub start_time: DateTime<Utc>,
    pub container_id: String,
}

/// Platform-specific fallback for resolving a process that is not (yet) in
/// the process table.  The Linux agent implements this via `/proc`; macOS
/// via `sysctl`; Windows via WMI.
pub trait ParentResolver: Send + Sync {
    fn resolve(&self, pid: u32) -> Option<ResolvedProcess>;
}

/// Globally unique process identifier derived from `(pid, start_time)`.
///
/// Stored as a hex-encoded SHA-256 so it is a fixed-length opaque string that
/// can be compared, logged, and transmitted without leaking raw PID internals.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessUid(String);

impl ProcessUid {
    pub fn new(agent_id: &str, pid: u32, start_time: DateTime<Utc>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(agent_id.as_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(start_time.timestamp_millis().to_le_bytes());
        Self(hex::encode(hasher.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProcessUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Snapshot of a single process tracked by the agent.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub uid: u32,
    pub username: String,
    pub container_id: String,
    pub start_time: DateTime<Utc>,
    pub exit_time: Option<DateTime<Utc>>,
    pub process_guid: ProcessUid,
    pub parent_process_guid: String,
    pub exe_hash: String,
    pub exe_size: u64,
}

/// Composite key for the process table: `(pid, start_time)`.
/// Two processes that reuse the same PID will always have distinct start
/// times, so this key uniquely identifies a process instance.
type ProcessKey = (u32, DateTime<Utc>);

fn truncate_to_millis(dt: DateTime<Utc>) -> DateTime<Utc> {
    let nanos = dt.nanosecond();
    let millis_only = (nanos / 1_000_000) * 1_000_000;
    dt.with_nanosecond(millis_only).unwrap_or(dt)
}

/// In-memory table of known processes, keyed by `(pid, start_time)`.
///
/// Because the key includes `start_time`, PID reuse never overwrites an
/// earlier entry — both coexist until the old one is reaped after its
/// `exit_ttl` expires.
pub struct ProcessTable {
    agent_id: String,
    processes: HashMap<ProcessKey, ProcessInfo>,
    exit_ttl: Duration,
}

impl ProcessTable {
    pub fn new(agent_id: String, exit_ttl: Duration) -> Self {
        Self {
            agent_id,
            processes: HashMap::new(),
            exit_ttl,
        }
    }

    /// Feed an event into the table.  Only `ProcessCreate` and `ProcessExit`
    /// events mutate state; everything else is ignored.
    pub fn update(&mut self, event: &Event) {
        match &event.kind {
            EventKind::ProcessCreate(pe) | EventKind::ProcessFork(pe) => {
                let st = truncate_to_millis(pe.start_time);
                let key = (pe.pid, st);
                let puid = ProcessUid::new(&self.agent_id, pe.pid, st);
                let parent_uid = self.lookup(pe.parent_pid, None)
                    .map(|p| p.process_guid.to_string())
                    .unwrap_or_default();
                let info = ProcessInfo {
                    pid: pe.pid,
                    parent_pid: pe.parent_pid,
                    name: pe.name.clone(),
                    path: pe.path.clone(),
                    cmdline: pe.cmdline.clone(),
                    uid: pe.user_id.parse().unwrap_or(0),
                    username: event.username.clone(),
                    container_id: event.container_id.clone(),
                    start_time: st,
                    exit_time: None,
                    process_guid: puid,
                    parent_process_guid: parent_uid,
                    exe_hash: pe.exe_hash.clone(),
                    exe_size: pe.exe_size,
                };
                self.processes.insert(key, info);
            }
            EventKind::ProcessExit(pe) => {
                let key = (pe.pid, truncate_to_millis(pe.start_time));
                if let Some(entry) = self.processes.get_mut(&key) {
                    entry.exit_time = Some(event.timestamp);
                }
            }
            _ => {}
        }
    }

    /// Look up a process by `(pid, start_time)` for an exact O(1) match.
    /// When `start_time` is `None` (event source didn't provide it), falls
    /// back to scanning entries for that PID and returns the most recent.
    pub fn lookup(&self, pid: u32, start_time: Option<DateTime<Utc>>) -> Option<&ProcessInfo> {
        if let Some(st) = start_time {
            if let Some(info) = self.processes.get(&(pid, truncate_to_millis(st))) {
                return Some(info);
            }
        }
        self.processes
            .values()
            .filter(|p| p.pid == pid)
            .max_by_key(|p| p.start_time)
    }

    /// Insert a synthetic process entry from a resolved parent.
    /// Used when the parent was not observed by the sensor but is still alive
    /// in the OS process table.
    pub fn insert_synthetic(&mut self, resolved: &ResolvedProcess) {
        let st = truncate_to_millis(resolved.start_time);
        let key = (resolved.pid, st);
        if self.processes.contains_key(&key) {
            return;
        }
        let puid = ProcessUid::new(&self.agent_id, resolved.pid, st);
        let parent_guid = self.lookup(resolved.parent_pid, None)
            .map(|p| p.process_guid.to_string())
            .unwrap_or_default();
        let info = ProcessInfo {
            pid: resolved.pid,
            parent_pid: resolved.parent_pid,
            name: resolved.name.clone(),
            path: resolved.path.clone(),
            cmdline: resolved.cmdline.clone(),
            uid: resolved.uid,
            username: resolved.username.clone(),
            container_id: resolved.container_id.clone(),
            start_time: st,
            exit_time: None,
            process_guid: puid,
            parent_process_guid: parent_guid,
            exe_hash: String::new(),
            exe_size: 0,
        };
        self.processes.insert(key, info);
    }

    /// Remove entries that exited longer than `exit_ttl` ago.
    pub fn reap_expired(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::from_std(self.exit_ttl).unwrap_or_default();
        let before = self.processes.len();
        self.processes.retain(|_key, info| {
            if let Some(exit) = info.exit_time {
                exit > cutoff
            } else {
                true
            }
        });
        let reaped = before - self.processes.len();
        if reaped > 0 {
            debug!(reaped, "process table: reaped expired entries");
        }
    }

    pub fn len(&self) -> usize {
        self.processes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    /// Return the PIDs of all live processes that are descendants of (or equal
    /// to) `ancestor_guid`.  Uses iterative BFS over `parent_process_guid`
    /// links so the full subtree is found regardless of depth.
    ///
    /// Only processes without an `exit_time` are considered.  A process is
    /// included only if walking its parent chain eventually reaches
    /// `ancestor_guid` — any process whose ancestry cannot be traced to the
    /// requested ancestor is skipped.
    pub fn pids_in_subtree(&self, ancestor_guid: &str) -> Vec<u32> {
        let live: Vec<&ProcessInfo> = self.processes.values()
            .filter(|p| p.exit_time.is_none())
            .collect();

        let mut in_tree: std::collections::HashSet<&str> = std::collections::HashSet::new();
        in_tree.insert(ancestor_guid);

        loop {
            let before = in_tree.len();
            for p in &live {
                if in_tree.contains(p.parent_process_guid.as_str()) {
                    in_tree.insert(p.process_guid.as_str());
                }
            }
            if in_tree.len() == before { break; }
        }

        live.iter()
            .filter(|p| in_tree.contains(p.process_guid.as_str()))
            .map(|p| p.pid)
            .collect()
    }

    pub fn running_count(&self) -> usize {
        self.processes.values().filter(|p| p.exit_time.is_none()).count()
    }

    pub fn exited_count(&self) -> usize {
        self.processes.values().filter(|p| p.exit_time.is_some()).count()
    }
}
