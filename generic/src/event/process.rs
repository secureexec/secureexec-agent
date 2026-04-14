use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use super::{is_zero_u64, ContentHash};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub user_id: String,
    pub start_time: DateTime<Utc>,
    /// `true` when this event came from the initial process snapshot at agent
    /// startup rather than from a live kernel/ES notification.
    #[serde(default)]
    pub snapshot: bool,
    /// Globally unique ID of the parent process, resolved from the process
    /// table during pipeline enrichment.  Empty when the parent is unknown.
    #[serde(default)]
    pub parent_process_guid: String,
    /// Exit code; `Some` only for `ProcessExit` events.  `None` for create/fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// LD_PRELOAD value detected at execve time; empty if not set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ld_preload: String,
    /// SHA-256 hex digest of the executable binary; empty for exit/fork/snapshot
    /// or when the file could not be read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exe_hash: String,
    /// Size of the executable in bytes.  When exe_size > 50 MB the hash covers
    /// only the first 50 MB (partial hash).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub exe_size: u64,
}

impl ContentHash for ProcessEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.parent_pid.to_le_bytes());
        h.update(self.name.as_bytes());
        h.update(self.path.as_bytes());
        h.update(self.cmdline.as_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.start_time.timestamp_millis().to_le_bytes());
    }
}
