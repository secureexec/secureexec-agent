mod client;
mod convert;
mod helpers;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event as secureexec_event;
use secureexec_generic::sensor::Sensor;

enum EsEvent {
    ProcessExec {
        pid: u32,
        parent_pid: u32,
        uid: u32,
        name: String,
        path: String,
        cmdline: String,
        start_time: DateTime<Utc>,
    },
    ProcessExit {
        pid: u32,
        parent_pid: u32,
        uid: u32,
        name: String,
        path: String,
        start_time: DateTime<Utc>,
    },
    ProcessFork {
        pid: u32,
        parent_pid: u32,
        uid: u32,
        name: String,
        path: String,
        start_time: DateTime<Utc>,
    },
    FileCreate {
        path: String,
        pid: u32,
        process_name: String,
        start_time: DateTime<Utc>,
    },
    FileWrite {
        path: String,
        pid: u32,
        process_name: String,
        start_time: DateTime<Utc>,
    },
    FileUnlink {
        path: String,
        pid: u32,
        process_name: String,
        start_time: DateTime<Utc>,
    },
    FileRename {
        old_path: String,
        new_path: String,
        pid: u32,
        process_name: String,
        start_time: DateTime<Utc>,
    },
}

pub struct MacosEsSensor;

impl MacosEsSensor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sensor for MacosEsSensor {
    fn name(&self) -> &str {
        "macos-es"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<secureexec_event::Event>,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<()> {
        let hostname = hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        // -- initial process snapshot via libproc (blocking) --
        let snap_tx = tx.clone();
        let snap_host = hostname.clone();
        let snap_join = tokio::task::spawn_blocking(move || {
            convert::emit_process_snapshot(&snap_tx, &snap_host);
        })
        .await;
        if let Err(e) = snap_join {
            tracing::error!(error = %e, "macos-es: process snapshot task crashed");
            return Err(secureexec_generic::error::AgentError::Pipeline(
                format!("process snapshot task panicked: {e}"),
            ));
        }
        info!("macos-es: process snapshot complete");

        // -- live ES events via dedicated thread --
        let (es_tx, mut es_rx) = tokio::sync::mpsc::channel::<EsEvent>(4096);
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();

        let es_thread = std::thread::Builder::new()
            .name("es-client".into())
            .spawn(move || {
                client::run_es_client(es_tx, stop2);
            })
            .map_err(|e| {
                secureexec_generic::error::AgentError::Pipeline(format!(
                    "failed to spawn es-client thread: {e}"
                ))
            })?;

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("macos-es sensor stopping");
                    stop.store(true, Ordering::Release);
                    es_thread.thread().unpark();
                    let _ = es_thread.join();
                    return Ok(());
                }
                maybe = es_rx.recv() => {
                    let Some(es_event) = maybe else {
                        warn!("macos-es: ES event channel closed");
                        return Ok(());
                    };
                    let event = convert::convert_es_event(es_event, &hostname);
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}
