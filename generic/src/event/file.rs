use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use super::ContentHash;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub pid: u32,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user_id: String,
}

impl ContentHash for FileEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.path.as_bytes());
        h.update(self.pid.to_le_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.user_id.as_bytes());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRenameEvent {
    pub old_path: String,
    pub new_path: String,
    pub pid: u32,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user_id: String,
}

impl ContentHash for FileRenameEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.old_path.as_bytes());
        h.update(self.new_path.as_bytes());
        h.update(self.pid.to_le_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.user_id.as_bytes());
    }
}

/// File permission or ownership change (chmod / chown).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePermChangeEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    pub path: String,
    /// "chmod" or "chown".
    pub kind: String,
    /// New permission mode bits (chmod only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_mode: Option<u32>,
    /// New owner uid (chown only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_uid: Option<u32>,
    /// New owner gid (chown only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_gid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for FilePermChangeEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.path.as_bytes());
        h.update(self.kind.as_bytes());
        if let Some(m) = self.new_mode { h.update(m.to_le_bytes()); }
        if let Some(u) = self.new_uid  { h.update(u.to_le_bytes()); }
        if let Some(g) = self.new_gid  { h.update(g.to_le_bytes()); }
    }
}

/// symlinkat() / linkat() — symbolic or hard link creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLinkEvent {
    pub pid: u32,
    #[serde(default)]
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    /// Link target (symlink) or source file (hardlink).
    pub src_path: String,
    /// New link path.
    pub dst_path: String,
    pub is_symlink: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
}

impl ContentHash for FileLinkEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.src_path.as_bytes());
        h.update(self.dst_path.as_bytes());
    }
}
