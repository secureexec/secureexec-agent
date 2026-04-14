use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use aya::Ebpf;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use secureexec_generic::error::{AgentError, Result};
use secureexec_generic::event::Event;
use secureexec_generic::sensor::Sensor;

use super::super::{exe_hash, procfs, snapshot};
use super::convert::convert_bpf_events;
use super::loader::{load_ebpf, poll_ebpf, poll_ebpf_from_arc};
use super::types::{BpfEvent, EbpfDropCounters};

pub struct LinuxEbpfSensor {
    /// Shared eBPF handle.  When `Some`, the sensor takes ring-buffer maps
    /// from it and skips the internal load step.  When `None`, the sensor
    /// loads eBPF itself.
    shared_ebpf: Option<Arc<std::sync::Mutex<Ebpf>>>,
    /// Shared ring-buffer drop counters — updated by the poll thread,
    /// read by the heartbeat via `CommandHandler::ebpf_drop_counts()`.
    drop_counters: Arc<EbpfDropCounters>,
}

impl LinuxEbpfSensor {
    /// Create a sensor that loads eBPF internally at run time.
    pub fn new(drop_counters: Arc<EbpfDropCounters>) -> Self {
        Self { shared_ebpf: None, drop_counters }
    }

    /// Create a sensor that shares a pre-loaded `Ebpf` handle with the
    /// firewall.  The sensor will take the ring-buffer maps from it on start.
    pub fn with_shared_ebpf(ebpf: Arc<std::sync::Mutex<Ebpf>>, drop_counters: Arc<EbpfDropCounters>) -> Self {
        Self { shared_ebpf: Some(ebpf), drop_counters }
    }
}

#[async_trait]
impl Sensor for LinuxEbpfSensor {
    fn name(&self) -> &str {
        "linux-ebpf"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<Event>,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<()> {
        let hostname = hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        let uid_map = procfs::load_uid_map();
        info!("linux-ebpf: loaded {} uid→username entries", uid_map.len());

        let snap_tx   = tx.clone();
        let snap_host = hostname.clone();
        let uid_map_snap = uid_map.clone();
        tokio::task::spawn_blocking(move || {
            let mut resolver = procfs::UidResolver::new(uid_map_snap);
            snapshot::emit_process_snapshot(&snap_tx, &snap_host, &mut resolver);
        })
        .await
        .ok();
        info!("linux-ebpf: process snapshot complete");
        let mut uid_resolver = procfs::UidResolver::new(uid_map);

        let (bpf_tx, mut bpf_rx) = mpsc::channel::<BpfEvent>(65536);
        let stop  = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();

        let shared_ebpf = self.shared_ebpf.clone();
        let dc = self.drop_counters.clone();
        let bpf_thread = std::thread::Builder::new()
            .name("ebpf-poller".into())
            .spawn(move || {
                let ebpf = if let Some(arc) = shared_ebpf {
                    // Shared path: take the Ebpf out of the Arc<Mutex>.
                    // The firewall has already taken FW_MODE/FW_RULES maps and
                    // attached the TC programs; only ring-buffer maps remain.
                    match Arc::try_unwrap(arc) {
                        Ok(mutex) => mutex.into_inner().unwrap_or_else(|p| p.into_inner()),
                        Err(arc) => {
                            // Other references remain (e.g. watcher) — clone is not
                            // possible, so lock and extract rings directly.
                            // We take the maps while holding the lock, then release.
                            // After this the Arc stays alive for the watcher.
                            return poll_ebpf_from_arc(arc, bpf_tx, stop2, dc);
                        }
                    }
                } else {
                    match load_ebpf() {
                        Ok(e) => e,
                        Err(err) => {
                            error!(error = %err, "linux-ebpf: failed to load eBPF");
                            return;
                        }
                    }
                };
                if let Err(e) = poll_ebpf(ebpf, bpf_tx, stop2, dc) {
                    error!(error = %e, "linux-ebpf: eBPF thread exited with error");
                }
            })
            .map_err(|e| AgentError::Platform(format!("failed to spawn ebpf thread: {e}")))?;

        let mut proc_cache: HashMap<u32, procfs::ProcInfo> = HashMap::new();
        // tgid → (cmdline, ld_preload) buffered from PROC_EVT_ARGV
        let mut pending_argv: HashMap<u32, (String, String)> = HashMap::new();
        let mut exe_hash_cache = exe_hash::ExeHashCache::new();

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("linux-ebpf sensor stopping");
                    stop.store(true, Ordering::Release);
                    let _ = bpf_thread.join();
                    return Ok(());
                }
                maybe = bpf_rx.recv() => {
                    let Some(bpf_event) = maybe else {
                        warn!("linux-ebpf: BPF event channel closed");
                        return Ok(());
                    };
                    for event in convert_bpf_events(
                        bpf_event, &hostname, &mut proc_cache,
                        &mut pending_argv, &mut uid_resolver,
                        &mut exe_hash_cache,
                    ) {
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}
