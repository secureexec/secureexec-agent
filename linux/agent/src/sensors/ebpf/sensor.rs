use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aya::Ebpf;
use lru::LruCache;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use secureexec_generic::error::{AgentError, Result};
use secureexec_generic::event::Event;
use secureexec_generic::sensor::Sensor;

use super::super::{exe_hash, procfs, snapshot};
use super::convert::convert_bpf_events;
use super::loader::{load_ebpf, poll_ebpf, poll_ebpf_from_arc, validate_bpf_abi};
use super::types::{BpfEvent, EbpfDropCounters};

/// How often the sensor checks the pipeline-level reconnect signal.
const RECONNECT_POLL_INTERVAL_SECS: u64 = 5;

pub struct LinuxEbpfSensor {
    /// Shared eBPF handle.  When `Some`, the sensor takes ring-buffer maps
    /// from it and skips the internal load step.  When `None`, the sensor
    /// loads eBPF itself.
    shared_ebpf: Option<Arc<std::sync::Mutex<Ebpf>>>,
    /// Shared ring-buffer drop counters — updated by the poll thread,
    /// read by the heartbeat via `CommandHandler::ebpf_drop_counts()`.
    drop_counters: Arc<EbpfDropCounters>,
    /// Pipeline-owned counter that bumps on every transport re-connect past
    /// the initial one.  When set, the sensor watches it and re-emits a fresh
    /// `/proc` snapshot so the server can rebuild its process tree after a
    /// restart.  Optional: noop when the pipeline does not provide a handle.
    reconnect_generation: Option<Arc<AtomicU64>>,
}

impl LinuxEbpfSensor {
    /// Create a sensor that loads eBPF internally at run time.
    pub fn new(drop_counters: Arc<EbpfDropCounters>) -> Self {
        Self { shared_ebpf: None, drop_counters, reconnect_generation: None }
    }

    /// Create a sensor that shares a pre-loaded `Ebpf` handle with the
    /// firewall.  The sensor will take the ring-buffer maps from it on start.
    pub fn with_shared_ebpf(ebpf: Arc<std::sync::Mutex<Ebpf>>, drop_counters: Arc<EbpfDropCounters>) -> Self {
        Self { shared_ebpf: Some(ebpf), drop_counters, reconnect_generation: None }
    }

    /// Wire the pipeline-owned reconnect-generation counter into the sensor.
    /// On every observed bump, the sensor re-emits a `/proc` snapshot via the
    /// event channel, allowing the server to repopulate its in-memory
    /// `ServerProcessTables` after a restart without losing the long-lived
    /// process ancestry chain.
    pub fn set_reconnect_generation(&mut self, gen: Arc<AtomicU64>) {
        self.reconnect_generation = Some(gen);
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
        let snap_join = tokio::task::spawn_blocking(move || {
            let mut resolver = procfs::UidResolver::new(uid_map_snap);
            snapshot::emit_process_snapshot(&snap_tx, &snap_host, &mut resolver);
        })
        .await;
        if let Err(e) = snap_join {
            // Do not swallow a panic from the snapshot thread: if /proc
            // enumeration panicked we want the sensor startup to abort so
            // the agent can be restarted cleanly instead of running with
            // a partial/empty process table.
            tracing::error!(error = %e, "linux-ebpf: process snapshot task crashed");
            return Err(secureexec_generic::error::AgentError::Pipeline(
                format!("process snapshot task panicked: {e}"),
            ));
        }
        info!("linux-ebpf: process snapshot complete");
        // Clone before moving into the resolver so the reconnect snapshot
        // worker (spawned below) can build its own resolver on every retry
        // without sharing mutable state with the hot-path event loop.
        let uid_map_for_resnap = uid_map.clone();
        let mut uid_resolver = procfs::UidResolver::new(uid_map);

        let (bpf_tx, mut bpf_rx) = mpsc::channel::<BpfEvent>(65536);
        let stop  = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();

        let shared_ebpf = self.shared_ebpf.clone();
        let dc = self.drop_counters.clone();
        let bpf_thread = std::thread::Builder::new()
            .name("ebpf-poller".into())
            .spawn(move || {
                // Validate all hard-coded BPF offsets before loading/polling.
                validate_bpf_abi(&dc);

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

        // `proc_cache` is populated on fork/exec and pruned on observed
        // ProcessExit.  When exit events are lost (SECURITY/PROCESS ring
        // buffer drops on a busy host) the cache would grow without bound;
        // use an LRU so the least-recently-touched pids are evicted first
        // and active processes keep their context across file / network /
        // security events.  Each `get` in `convert_bpf_events` promotes the
        // entry, so hot pids stay resident.
        const PROC_CACHE_CAP: usize = 32 * 1024;
        let mut proc_cache: LruCache<u32, procfs::ProcInfo> =
            LruCache::new(NonZeroUsize::new(PROC_CACHE_CAP).unwrap());
        // tgid → (cmdline, ld_preload) buffered from PROC_EVT_ARGV
        let mut pending_argv: HashMap<u32, (String, String)> = HashMap::new();
        let mut exe_hash_cache = exe_hash::ExeHashCache::new();

        // Snapshot worker: watches the pipeline-level reconnect counter and
        // re-emits `/proc` whenever the transport re-connects past the
        // initial one.  Keeping it as a dedicated tokio task lets us run the
        // (blocking) /proc walk on `spawn_blocking` without competing with
        // the eBPF ring-buffer fast path for this select! arm.
        let mut snapshot_handle = self.reconnect_generation.clone().map(|gen| {
            let snap_tx = tx.clone();
            let snap_host = hostname.clone();
            let snap_uid_map = uid_map_for_resnap;
            let mut snap_cancel = cancel.clone();
            tokio::spawn(async move {
                // Start from 0 (not `gen.load()`): the initial /proc snapshot
                // above can take seconds, during which a server restart could
                // bump `reconnect_gen` 0→1 already.  If we initialised
                // `last_seen` to the live value, we'd treat that bump as the
                // baseline and skip the very re-snapshot it was meant to
                // trigger.  Starting from 0 makes any non-zero `current`
                // observed here drive a re-snapshot, which is the desired
                // behaviour after a server restart.
                let mut last_seen: u64 = 0;
                let mut ticker = tokio::time::interval(Duration::from_secs(RECONNECT_POLL_INTERVAL_SECS));
                ticker.tick().await; // skip the immediate first tick
                loop {
                    tokio::select! {
                        _ = snap_cancel.changed() => {
                            debug!("linux-ebpf snapshot worker stopping");
                            return;
                        }
                        _ = ticker.tick() => {
                            let current = gen.load(Ordering::Relaxed);
                            if current > last_seen {
                                info!(
                                    prev = last_seen,
                                    current,
                                    "linux-ebpf: reconnect signal received — re-emitting /proc snapshot",
                                );
                                let inner_tx = snap_tx.clone();
                                let inner_host = snap_host.clone();
                                let inner_uid_map = snap_uid_map.clone();
                                let join = tokio::task::spawn_blocking(move || {
                                    let mut resolver = procfs::UidResolver::new(inner_uid_map);
                                    snapshot::emit_process_snapshot(&inner_tx, &inner_host, &mut resolver);
                                }).await;
                                if let Err(e) = join {
                                    error!(error = %e, "linux-ebpf: re-snapshot task crashed");
                                }
                                last_seen = current;
                            }
                        }
                    }
                }
            })
        });

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("linux-ebpf sensor stopping");
                    stop.store(true, Ordering::Release);
                    let _ = bpf_thread.join();
                    if let Some(h) = snapshot_handle.take() {
                        let _ = h.await;
                    }
                    return Ok(());
                }
                maybe = bpf_rx.recv() => {
                    let Some(bpf_event) = maybe else {
                        warn!("linux-ebpf: BPF event channel closed");
                        if let Some(h) = snapshot_handle.take() {
                            h.abort();
                            let _ = h.await;
                        }
                        return Ok(());
                    };
                    for event in convert_bpf_events(
                        bpf_event, &hostname, &mut proc_cache,
                        &mut pending_argv, &mut uid_resolver,
                        &mut exe_hash_cache,
                    ) {
                        if tx.send(event).await.is_err() {
                            if let Some(h) = snapshot_handle.take() {
                                h.abort();
                                let _ = h.await;
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}
