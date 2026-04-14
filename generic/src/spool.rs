use std::path::Path;

use rusqlite::{params, Connection};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

use crate::error::{AgentError, Result};
use crate::event::Event;

// ---------------------------------------------------------------------------
// Internal SQLite-backed spool (private — only accessed by the actor thread)
// ---------------------------------------------------------------------------

struct EventSpool {
    conn: Connection,
}

impl EventSpool {
    fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| AgentError::Pipeline(format!("spool open: {e}")))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous  = NORMAL;
             CREATE TABLE IF NOT EXISTS events (
                 id    INTEGER PRIMARY KEY AUTOINCREMENT,
                 json  TEXT NOT NULL
             );"
        )
        .map_err(|e| AgentError::Pipeline(format!("spool init: {e}")))?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap_or(0);
        if count > 0 {
            info!(pending = count, "spool contains unsent events from previous run");
        }

        Ok(Self { conn })
    }

    fn push(&self, events: &[Event]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| AgentError::Pipeline(format!("spool tx begin: {e}")))?;

        {
            let mut stmt = tx.prepare_cached("INSERT INTO events (json) VALUES (?1)")
                .map_err(|e| AgentError::Pipeline(format!("spool prepare: {e}")))?;

            for event in events {
                let json = serde_json::to_string(event)?;
                stmt.execute(params![json])
                    .map_err(|e| AgentError::Pipeline(format!("spool insert: {e}")))?;
            }
        }

        tx.commit()
            .map_err(|e| AgentError::Pipeline(format!("spool tx commit: {e}")))?;

        debug!(count = events.len(), "spooled events");
        Ok(())
    }

    fn peek(&self, limit: usize) -> Result<(Vec<i64>, Vec<Event>)> {
        let mut stmt = self.conn
            .prepare_cached("SELECT id, json FROM events ORDER BY id ASC LIMIT ?1")
            .map_err(|e| AgentError::Pipeline(format!("spool prepare peek: {e}")))?;

        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| AgentError::Pipeline(format!("spool query: {e}")))?;

        let mut ids = Vec::new();
        let mut events = Vec::new();
        for row in rows {
            let (id, json) = row.map_err(|e| AgentError::Pipeline(format!("spool row: {e}")))?;
            let event: Event = serde_json::from_str(&json)?;
            ids.push(id);
            events.push(event);
        }
        Ok((ids, events))
    }

    fn remove(&self, ids: &[i64]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| AgentError::Pipeline(format!("spool tx begin: {e}")))?;

        {
            let mut stmt = tx.prepare_cached("DELETE FROM events WHERE id = ?1")
                .map_err(|e| AgentError::Pipeline(format!("spool prepare delete: {e}")))?;

            for id in ids {
                stmt.execute(params![id])
                    .map_err(|e| AgentError::Pipeline(format!("spool delete: {e}")))?;
            }
        }

        tx.commit()
            .map_err(|e| AgentError::Pipeline(format!("spool tx commit: {e}")))?;

        debug!(count = ids.len(), "removed sent events from spool");
        Ok(())
    }

    fn len(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }
}

// ---------------------------------------------------------------------------
// Actor command enum (private)
// ---------------------------------------------------------------------------

enum SpoolCmd {
    Push { events: Vec<Event>, reply: oneshot::Sender<Result<()>> },
    Peek { limit: usize, reply: oneshot::Sender<Result<(Vec<i64>, Vec<Event>)>> },
    Remove { ids: Vec<i64>, reply: oneshot::Sender<Result<()>> },
    Len { reply: oneshot::Sender<usize> },
}

// ---------------------------------------------------------------------------
// Public async handle — Clone + Send, no mutex needed
// ---------------------------------------------------------------------------

/// Async handle to the spool actor.
///
/// All SQLite I/O happens on a dedicated OS thread; callers communicate
/// through an mpsc channel and receive results via oneshot replies.
#[derive(Clone)]
pub struct SpoolHandle {
    tx: mpsc::Sender<SpoolCmd>,
}

impl SpoolHandle {
    /// Open the SQLite spool at `path` and spawn the actor thread.
    pub fn spawn(path: &Path) -> Result<Self> {
        let spool = EventSpool::open(path)?;
        let (tx, mut rx) = mpsc::channel::<SpoolCmd>(256);

        std::thread::Builder::new()
            .name("spool-actor".into())
            .spawn(move || {
                while let Some(cmd) = rx.blocking_recv() {
                    match cmd {
                        SpoolCmd::Push { events, reply } => {
                            let _ = reply.send(spool.push(&events));
                        }
                        SpoolCmd::Peek { limit, reply } => {
                            let _ = reply.send(spool.peek(limit));
                        }
                        SpoolCmd::Remove { ids, reply } => {
                            let _ = reply.send(spool.remove(&ids));
                        }
                        SpoolCmd::Len { reply } => {
                            let _ = reply.send(spool.len());
                        }
                    }
                }
                debug!("spool actor thread exiting");
            })
            .map_err(|e| AgentError::Pipeline(format!("spool thread spawn: {e}")))?;

        Ok(Self { tx })
    }

    pub async fn push(&self, events: Vec<Event>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx.send(SpoolCmd::Push { events, reply: reply_tx }).await
            .map_err(|_| AgentError::Pipeline("spool actor gone".into()))?;
        reply_rx.await
            .map_err(|_| AgentError::Pipeline("spool actor dropped reply".into()))?
    }

    pub async fn peek(&self, limit: usize) -> Result<(Vec<i64>, Vec<Event>)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx.send(SpoolCmd::Peek { limit, reply: reply_tx }).await
            .map_err(|_| AgentError::Pipeline("spool actor gone".into()))?;
        reply_rx.await
            .map_err(|_| AgentError::Pipeline("spool actor dropped reply".into()))?
    }

    pub async fn remove(&self, ids: Vec<i64>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx.send(SpoolCmd::Remove { ids, reply: reply_tx }).await
            .map_err(|_| AgentError::Pipeline("spool actor gone".into()))?;
        reply_rx.await
            .map_err(|_| AgentError::Pipeline("spool actor dropped reply".into()))?
    }

    pub async fn len(&self) -> usize {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.tx.send(SpoolCmd::Len { reply: reply_tx }).await.is_err() {
            return 0;
        }
        reply_rx.await.unwrap_or(0)
    }
}
