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

/// Hard ceiling on the number of entries kept in the table. Once reached,
/// the oldest entries (by `start_time`) are evicted so the table cannot grow
/// without bound if `ProcessExit` events are lost (e.g. SECURITY_EVENTS ring
/// overflow on a busy host).
const MAX_TABLE_SIZE: usize = 100_000;

/// Entries without an observed `ProcessExit` are force-reaped after this
/// duration. Long-running daemons are routinely recreated via synthetic
/// resolution, so a 7-day cap is safe and bounds memory for pathological
/// churn patterns where exits are never observed.
const FORCE_REAP_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

/// In-memory table of known processes, keyed by `(pid, start_time)`.
///
/// Because the key includes `start_time`, PID reuse never overwrites an
/// earlier entry — both coexist until the old one is reaped after its
/// `exit_ttl` expires.
pub struct ProcessTable {
    agent_id: String,
    processes: HashMap<ProcessKey, ProcessInfo>,
    /// Secondary index: pid → all `start_time`s currently present in
    /// `processes` for that pid.  Keeps `lookup(pid, None)` O(k) where k is
    /// the (tiny) number of distinct instances of that pid still in the
    /// table, instead of scanning the entire (up to 100 k entry) map on
    /// every event's parent-process resolution.  Must be kept strictly in
    /// sync with `processes` — see `add_pid_index` / `remove_pid_index`.
    by_pid: HashMap<u32, Vec<DateTime<Utc>>>,
    exit_ttl: Duration,
    force_reap_after: Duration,
    max_size: usize,
}

impl ProcessTable {
    pub fn new(agent_id: String, exit_ttl: Duration) -> Self {
        Self {
            agent_id,
            processes: HashMap::new(),
            by_pid: HashMap::new(),
            exit_ttl,
            force_reap_after: FORCE_REAP_AFTER,
            max_size: MAX_TABLE_SIZE,
        }
    }

    fn add_pid_index(&mut self, pid: u32, st: DateTime<Utc>) {
        let v = self.by_pid.entry(pid).or_default();
        if !v.contains(&st) {
            v.push(st);
        }
    }

    fn remove_pid_index(&mut self, pid: u32, st: &DateTime<Utc>) {
        if let Some(v) = self.by_pid.get_mut(&pid) {
            v.retain(|s| s != st);
            if v.is_empty() {
                self.by_pid.remove(&pid);
            }
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
                self.add_pid_index(pe.pid, st);
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
    /// When `start_time` is `None` (event source didn't provide it), or the
    /// exact key is absent, falls back to the most recent entry for that pid
    /// via the `by_pid` secondary index — O(k) where k is the (small) number
    /// of distinct instances of that pid still in the table.
    pub fn lookup(&self, pid: u32, start_time: Option<DateTime<Utc>>) -> Option<&ProcessInfo> {
        if let Some(st) = start_time {
            if let Some(info) = self.processes.get(&(pid, truncate_to_millis(st))) {
                return Some(info);
            }
        }
        let sts = self.by_pid.get(&pid)?;
        let max_st = sts.iter().max()?;
        self.processes.get(&(pid, *max_st))
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
        self.add_pid_index(resolved.pid, st);
    }

    /// Remove entries that exited longer than `exit_ttl` ago, force-reap
    /// live entries older than `force_reap_after` (ProcessExit was probably
    /// lost), and enforce the hard `max_size` cap by evicting oldest-first.
    pub fn reap_expired(&mut self) {
        let now = Utc::now();
        let exit_cutoff = now - chrono::Duration::from_std(self.exit_ttl).unwrap_or_default();
        let live_cutoff = now - chrono::Duration::from_std(self.force_reap_after).unwrap_or_default();
        let before = self.processes.len();
        let to_remove: Vec<ProcessKey> = self.processes.iter()
            .filter_map(|(k, info)| {
                let keep = match info.exit_time {
                    Some(exit) => exit > exit_cutoff,
                    None => info.start_time > live_cutoff,
                };
                if keep { None } else { Some(*k) }
            })
            .collect();
        for k in &to_remove {
            self.processes.remove(k);
            self.remove_pid_index(k.0, &k.1);
        }
        let reaped = before - self.processes.len();
        if reaped > 0 {
            debug!(reaped, "process table: reaped expired entries");
        }

        if self.processes.len() > self.max_size {
            let overflow = self.processes.len() - self.max_size;
            let mut by_age: Vec<(ProcessKey, DateTime<Utc>)> = self.processes.iter()
                .map(|(k, v)| (*k, v.start_time))
                .collect();
            by_age.sort_by_key(|(_, st)| *st);
            for (key, _) in by_age.into_iter().take(overflow) {
                self.processes.remove(&key);
                self.remove_pid_index(key.0, &key.1);
            }
            debug!(evicted = overflow, cap = self.max_size, "process table: evicted oldest entries to enforce cap");
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
        self.pids_in_subtree_with_start_time(ancestor_guid)
            .into_iter()
            .map(|(pid, _)| pid)
            .collect()
    }

    /// Same as [`pids_in_subtree`], but also returns the recorded start time
    /// for each pid. The caller can re-read `/proc/<pid>/stat` and compare
    /// start times to detect PID reuse before issuing a `kill(2)`, closing
    /// the TOCTOU window between lookup and signal delivery.
    pub fn pids_in_subtree_with_start_time(
        &self,
        ancestor_guid: &str,
    ) -> Vec<(u32, DateTime<Utc>)> {
        // Build a parent -> children adjacency list in one pass, then do a
        // standard BFS. The previous implementation was O(N^2 * depth) as it
        // re-scanned every live process on every expansion pass; on large
        // tables (think fork-bomb investigations) this became the bottleneck
        // while holding a read lock on the process table.
        use std::collections::HashMap;
        let mut children: HashMap<&str, Vec<&ProcessInfo>> = HashMap::new();
        let mut root: Option<&ProcessInfo> = None;
        for p in self.processes.values() {
            if p.exit_time.is_some() {
                continue;
            }
            if p.process_guid.as_str() == ancestor_guid {
                root = Some(p);
            }
            children
                .entry(p.parent_process_guid.as_str())
                .or_default()
                .push(p);
        }

        let mut out = Vec::new();
        let mut stack: Vec<&str> = Vec::new();
        if let Some(r) = root {
            out.push((r.pid, r.start_time));
        }
        stack.push(ancestor_guid);
        while let Some(guid) = stack.pop() {
            if let Some(kids) = children.get(guid) {
                for k in kids {
                    out.push((k.pid, k.start_time));
                    stack.push(k.process_guid.as_str());
                }
            }
        }
        out
    }

    pub fn running_count(&self) -> usize {
        self.processes.values().filter(|p| p.exit_time.is_none()).count()
    }

    pub fn exited_count(&self) -> usize {
        self.processes.values().filter(|p| p.exit_time.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind, ProcessEvent};
    use chrono::TimeZone;

    fn make_create_event(pid: u32, parent_pid: u32, start_time: DateTime<Utc>) -> Event {
        Event::new(
            "test-host".into(),
            EventKind::ProcessCreate(ProcessEvent {
                pid,
                parent_pid,
                name: format!("proc-{pid}"),
                path: String::new(),
                cmdline: String::new(),
                user_id: "0".into(),
                start_time,
                snapshot: false,
                parent_process_guid: String::new(),
                exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
            }),
        )
    }

    fn make_exit_event(pid: u32, start_time: DateTime<Utc>) -> Event {
        Event::new(
            "test-host".into(),
            EventKind::ProcessExit(ProcessEvent {
                pid,
                parent_pid: 0,
                name: format!("proc-{pid}"),
                path: String::new(),
                cmdline: String::new(),
                user_id: "0".into(),
                start_time,
                snapshot: false,
                parent_process_guid: String::new(),
                exit_code: Some(0),
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
            }),
        )
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn lookup_none_returns_most_recent_instance_via_index() {
        let mut t = ProcessTable::new("agent".into(), Duration::from_secs(60));
        t.update(&make_create_event(42, 1, ts(0)));
        t.update(&make_create_event(42, 1, ts(10)));
        t.update(&make_create_event(42, 1, ts(5)));

        let info = t.lookup(42, None).expect("found");
        assert_eq!(info.start_time, truncate_to_millis(ts(10)));
    }

    #[test]
    fn lookup_exact_key_hits_without_fallback() {
        let mut t = ProcessTable::new("agent".into(), Duration::from_secs(60));
        t.update(&make_create_event(100, 1, ts(0)));
        t.update(&make_create_event(100, 1, ts(30)));

        let info = t.lookup(100, Some(ts(0))).expect("found");
        assert_eq!(info.start_time, truncate_to_millis(ts(0)));
    }

    #[test]
    fn pid_index_stays_consistent_after_reap() {
        let mut t = ProcessTable::new("agent".into(), Duration::from_secs(1));
        t.force_reap_after = Duration::from_secs(1);
        let old = Utc::now() - chrono::Duration::seconds(3600);
        t.update(&make_create_event(7, 1, old));
        assert!(t.lookup(7, None).is_some());

        t.reap_expired();
        assert!(t.lookup(7, None).is_none(), "entry should be reaped");
        assert!(!t.by_pid.contains_key(&7), "by_pid index must drop reaped pid");
    }

    #[test]
    fn pid_index_drops_key_when_all_instances_reaped() {
        let mut t = ProcessTable::new("agent".into(), Duration::from_secs(1));
        t.force_reap_after = Duration::from_secs(1);
        let old1 = Utc::now() - chrono::Duration::seconds(7200);
        let old2 = Utc::now() - chrono::Duration::seconds(3600);
        t.update(&make_create_event(9, 1, old1));
        t.update(&make_create_event(9, 1, old2));
        assert_eq!(t.by_pid.get(&9).map(|v| v.len()), Some(2));

        t.reap_expired();
        assert!(!t.by_pid.contains_key(&9));
    }

    #[test]
    fn exit_marks_entry_but_keeps_index_entry() {
        let mut t = ProcessTable::new("agent".into(), Duration::from_secs(60));
        let st = ts(100);
        t.update(&make_create_event(5, 1, st));
        t.update(&make_exit_event(5, st));
        let info = t.lookup(5, None).expect("still resolvable before TTL");
        assert!(info.exit_time.is_some());
        assert!(t.by_pid.contains_key(&5));
    }

    #[test]
    fn many_entries_same_pid_do_not_scan_whole_table() {
        let mut t = ProcessTable::new("agent".into(), Duration::from_secs(60));
        for i in 0..1000u32 {
            t.update(&make_create_event(i + 1, 1, ts(i as i64)));
        }
        for i in 0..5u32 {
            t.update(&make_create_event(999_999, 1, ts(10_000 + i as i64)));
        }
        let info = t.lookup(999_999, None).expect("found");
        assert_eq!(info.start_time, truncate_to_millis(ts(10_004)));
        assert_eq!(t.by_pid.get(&999_999).map(|v| v.len()), Some(5));
    }
}
