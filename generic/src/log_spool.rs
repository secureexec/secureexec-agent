//! SQLite spool for agent log entries. Separate DB from events spool.

use std::path::Path;

use rusqlite::{params, Connection};
use tokio::sync::{mpsc, oneshot};

use crate::error::{AgentError, Result};
use crate::log_sender::AgentLogEntry;

struct LogSpoolInner {
    conn: Connection,
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
        Ok(Self { conn })
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
        Ok(())
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
