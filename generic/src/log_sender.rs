//! Tracing layer that enqueues log entries for spooling and sending to the server.
//! Events from this module (target `secureexec_generic::log_sender`) are never
//! enqueued to avoid recursion when sending logs.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::field::Field;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::transport::pb;

/// Number of agent log entries dropped because the spool channel was full.
/// Exposed as a process-global counter so it can be surfaced in heartbeats
/// / observed by an operator. Previously `try_send` errors were silently
/// ignored, making it impossible to detect log loss.
pub static LOG_ENTRIES_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Snapshot the current dropped-entry count.
pub fn dropped_log_entries() -> u64 {
    LOG_ENTRIES_DROPPED.load(Ordering::Relaxed)
}

/// One log entry produced by the layer and stored in the spool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLogEntry {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields_json: String,
}

/// Target prefix for code that must not be enqueued (avoids recursion).
const LOG_SENDER_TARGET_PREFIX: &str = "secureexec_generic::log_sender";

pub fn entry_to_proto(e: &AgentLogEntry) -> pb::AgentLogEntry {
    pb::AgentLogEntry {
        timestamp: e.timestamp.clone(),
        level: e.level.clone(),
        target: e.target.clone(),
        message: e.message.clone(),
        fields_json: e.fields_json.clone(),
    }
}

/// Layer that enqueues each event to a channel (non-blocking). Events whose
/// target starts with LOG_SENDER_TARGET_PREFIX are skipped.
/// When `tx` is None the layer is a no-op (for init without log spooling).
pub struct LogSpoolLayer {
    tx: Mutex<Option<tokio::sync::mpsc::Sender<AgentLogEntry>>>,
}

impl LogSpoolLayer {
    pub fn new(tx: Option<tokio::sync::mpsc::Sender<AgentLogEntry>>) -> Self {
        Self { tx: Mutex::new(tx) }
    }
}

impl<S> Layer<S> for LogSpoolLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if meta.target().starts_with(LOG_SENDER_TARGET_PREFIX) {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let (message, fields_json) = visitor.finish();
        let level = meta.level().to_string().to_lowercase();
        let timestamp = Utc::now().to_rfc3339();
        let entry = AgentLogEntry {
            timestamp,
            level,
            target: meta.target().to_string(),
            message,
            fields_json,
        };
        let guard = match self.tx.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(tx) = guard.as_ref() {
            if tx.try_send(entry).is_err() {
                // Channel is either full or closed. Either way we drop
                // this entry and increment the counter so loss is visible.
                LOG_ENTRIES_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Default)]
struct FieldVisitor {
    map: BTreeMap<String, serde_json::Value>,
    message: String,
}

impl FieldVisitor {
    fn finish(self) -> (String, String) {
        let message = if self.message.is_empty() {
            let parts: Vec<String> = self
                .map
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            parts.join(" ")
        } else {
            self.message
        };
        let fields_json = serde_json::to_string(&self.map).unwrap_or_default();
        (message, fields_json)
    }

    fn insert(&mut self, name: &str, value: serde_json::Value) {
        if name == "message" {
            self.message = value.as_str().unwrap_or_default().to_string();
        }
        self.map.insert(name.to_string(), value);
    }
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field.name(), serde_json::json!(format!("{:?}", value)));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field.name(), serde_json::json!(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field.name(), serde_json::json!(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field.name(), serde_json::json!(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field.name(), serde_json::json!(value));
    }
}
