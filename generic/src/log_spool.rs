//! SQLite spool for agent log entries. Separate DB from events spool.

use std::path::Path;

use rusqlite::{params, Connection};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::error::{AgentError, Result};
use crate::log_sender::AgentLogEntry;

/// Retention cap for agent-log spool. When the server is unreachable, this
/// bounds the on-disk footprint of the log database to a reasonable size;
/// excess rows are dropped oldest-first on every push.
const MAX_LOG_ROWS: i64 = 500_000;

struct LogSpoolInner {
    conn: Connection,
    pushes_since_retention: std::cell::Cell<u32>,
}

impl LogSpoolInner {
    fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| AgentError::Pipeline(format!("log spool open: {e}")))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS agent_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 json TEXT NOT NULL
             );",
        )
        .map_err(|e| AgentError::Pipeline(format!("log spool init: {e}")))?;
        Ok(Self {
            conn,
            pushes_since_retention: std::cell::Cell::new(0),
        })
    }

    fn push(&self, entries: &[AgentLogEntry]) -> Result<()> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| AgentError::Pipeline(format!("log spool tx begin: {e}")))?;
        {
            let mut stmt = tx
                .prepare_cached("INSERT INTO agent_logs (json) VALUES (?1)")
                .map_err(|e| AgentError::Pipeline(format!("log spool prepare: {e}")))?;
            for e in entries {
                let json = serde_json::to_string(e)?;
                stmt.execute(params![json])
                    .map_err(|e| AgentError::Pipeline(format!("log spool insert: {e}")))?;
            }
        }
        tx.commit()
            .map_err(|e| AgentError::Pipeline(format!("log spool tx commit: {e}")))?;
        self.enforce_retention();
        Ok(())
    }

    fn enforce_retention(&self) {
        // Run the COUNT(*) check only every N pushes to keep the hot path
        // cheap on a large spool. The overshoot is bounded by batch size.
        const RETENTION_CHECK_EVERY: u32 = 32;
        let n = self.pushes_since_retention.get().wrapping_add(1);
        if n < RETENTION_CHECK_EVERY {
            self.pushes_since_retention.set(n);
            return;
        }
        self.pushes_since_retention.set(0);

        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM agent_logs", [], |r| r.get(0))
            .unwrap_or(0);
        if count <= MAX_LOG_ROWS {
            return;
        }
        let overflow = count - MAX_LOG_ROWS;
        match self.conn.execute(
            "DELETE FROM agent_logs WHERE id IN (SELECT id FROM agent_logs ORDER BY id ASC LIMIT ?1)",
            params![overflow],
        ) {
            Ok(n) => warn!(dropped = n, retained = MAX_LOG_ROWS, "log spool hit retention cap; dropped oldest rows"),
            Err(e) => warn!(error = %e, "log spool retention delete failed"),
        }
    }

    fn peek(&self, limit: usize) -> Result<(Vec<i64>, Vec<AgentLogEntry>)> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT id, json FROM agent_logs ORDER BY id ASC LIMIT ?1")
            .map_err(|e| AgentError::Pipeline(format!("log spool prepare peek: {e}")))?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| AgentError::Pipeline(format!("log spool query: {e}")))?;
        let mut ids = Vec::new();
        let mut entries = Vec::new();
        for row in rows {
            let (id, json) = row.map_err(|e| AgentError::Pipeline(format!("log spool row: {e}")))?;
            let entry: AgentLogEntry = serde_json::from_str(&json)?;
            ids.push(id);
            entries.push(entry);
        }
        Ok((ids, entries))
    }

    fn remove(&self, ids: &[i64]) -> Result<()> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| AgentError::Pipeline(format!("log spool tx begin: {e}")))?;
        {
            let mut stmt = tx
                .prepare_cached("DELETE FROM agent_logs WHERE id = ?1")
                .map_err(|e| AgentError::Pipeline(format!("log spool prepare delete: {e}")))?;
            for id in ids {
                stmt.execute(params![id])
                    .map_err(|e| AgentError::Pipeline(format!("log spool delete: {e}")))?;
            }
        }
        tx.commit()
            .map_err(|e| AgentError::Pipeline(format!("log spool tx commit: {e}")))?;
        Ok(())
    }
}

enum LogSpoolCmd {
    Push {
        entries: Vec<AgentLogEntry>,
        reply: oneshot::Sender<Result<()>>,
    },
    Peek {
        limit: usize,
        reply: oneshot::Sender<Result<(Vec<i64>, Vec<AgentLogEntry>)>>,
    },
    Remove {
        ids: Vec<i64>,
        reply: oneshot::Sender<Result<()>>,
    },
}

#[derive(Clone)]
pub struct LogSpoolHandle {
    tx: mpsc::Sender<LogSpoolCmd>,
}

impl LogSpoolHandle {
    pub fn spawn(path: &Path) -> Result<Self> {
        let inner = LogSpoolInner::open(path)?;
        let (tx, mut rx) = mpsc::channel::<LogSpoolCmd>(256);
        std::thread::Builder::new()
            .name("log-spool-actor".into())
            .spawn(move || {
                while let Some(cmd) = rx.blocking_recv() {
                    match cmd {
                        LogSpoolCmd::Push { entries, reply } => {
                            let _ = reply.send(inner.push(&entries));
                        }
                        LogSpoolCmd::Peek { limit, reply } => {
                            let _ = reply.send(inner.peek(limit));
                        }
                        LogSpoolCmd::Remove { ids, reply } => {
                            let _ = reply.send(inner.remove(&ids));
                        }
                    }
                }
            })
            .map_err(|e| AgentError::Pipeline(format!("log spool thread spawn: {e}")))?;
        Ok(Self { tx })
    }

    pub async fn push(&self, entries: Vec<AgentLogEntry>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LogSpoolCmd::Push {
                entries,
                reply: reply_tx,
            })
            .await
            .map_err(|_| AgentError::Pipeline("log spool actor gone".into()))?;
        reply_rx
            .await
            .map_err(|_| AgentError::Pipeline("log spool actor dropped reply".into()))?
    }

    pub async fn peek(&self, limit: usize) -> Result<(Vec<i64>, Vec<AgentLogEntry>)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LogSpoolCmd::Peek {
                limit,
                reply: reply_tx,
            })
            .await
            .map_err(|_| AgentError::Pipeline("log spool actor gone".into()))?;
        reply_rx
            .await
            .map_err(|_| AgentError::Pipeline("log spool actor dropped reply".into()))?
    }

    pub async fn remove(&self, ids: Vec<i64>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(LogSpoolCmd::Remove {
                ids,
                reply: reply_tx,
            })
            .await
            .map_err(|_| AgentError::Pipeline("log spool actor gone".into()))?;
        reply_rx
            .await
            .map_err(|_| AgentError::Pipeline("log spool actor dropped reply".into()))?
    }
}
