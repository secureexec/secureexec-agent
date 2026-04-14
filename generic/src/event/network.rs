use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use super::ContentHash;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub protocol: Protocol,
    #[serde(default)]
    pub user_id: String,
}

impl ContentHash for NetworkEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.src_addr.as_bytes());
        h.update(self.src_port.to_le_bytes());
        h.update(self.dst_addr.as_bytes());
        h.update(self.dst_port.to_le_bytes());
        self.protocol.content_hash_update(h);
        h.update(self.user_id.as_bytes());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl ContentHash for Protocol {
    fn content_hash_update(&self, h: &mut Sha1) {
        match self {
            Self::Tcp => h.update(b"tcp"),
            Self::Udp => h.update(b"udp"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub pid: u32,
    pub user_id: String,
    pub process_name: String,
    #[serde(default)]
    pub process_guid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<DateTime<Utc>>,
    pub query: String,
    pub response: Vec<String>,
}

impl ContentHash for DnsEvent {
    fn content_hash_update(&self, h: &mut Sha1) {
        h.update(self.pid.to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.process_name.as_bytes());
        h.update(self.query.as_bytes());
        for r in &self.response {
            h.update(r.as_bytes());
        }
    }
}
