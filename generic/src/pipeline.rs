use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::command::{AgentCommand, CommandHandler};
use crate::config::AgentConfig;
use crate::detection::{DetectionContext, DetectionEngine};
use crate::error::Result;
use crate::event::{self, AgentHeartbeatEvent, AgentLifecycleEvent, Event, EventKind};
use crate::filter::{DeduplicationFilter, FilterChain};
use crate::log_sender::AgentLogEntry;
use crate::log_spool::LogSpoolHandle;
use crate::process_table::{ParentResolver, ProcessInfo, ProcessTable};
use crate::sensor::Sensor;
use crate::spool::SpoolHandle;
use crate::transport::{self, GrpcControlClient, Transport};
use crate::update::AgentUpdater;

const BLOCKLIST_POLL_INTERVAL_SECS: u64 = 30;

const PROCESS_EXIT_TTL_SECS: u64 = 120;

const DEDUP_CAPACITY: usize = 65_536;

const LOG_SEND_INTERVAL_SECS: u64 = 15;
const LOG_BATCH_SIZE: usize = 100;
const LOG_SPOOL_BATCH: usize = 64;
const LOG_SHUTDOWN_FLUSH_SECS: u64 = 5;

/// Hard cap on the entire graceful-shutdown sequence (task awaits + final
/// drain + log flush).  Keeps restart/update latency bounded even when the
/// server is slow but reachable.  Individual steps keep generous per-step
/// timeouts so data is not discarded unnecessarily when the deadline has not
/// yet elapsed.
const SHUTDOWN_DEADLINE_SECS: u64 = 15;

/// Trait implemented by sensors that can accept blocklist rule updates.
/// The pipeline calls `update_blocklist` whenever the server-side list changes.
pub trait BlocklistUpdater: Send + Sync + 'static {
    fn update_blocklist(&self, rules: Vec<transport::pb::BlocklistRule>);
}

/// Central event pipeline.
///
/// Sensors → mpsc channel → stamp agent_id/os → SQLite spool → transport → server.
pub struct Pipeline {
    config: AgentConfig,
    config_path: PathBuf,
    version: String,
    sensors: Vec<Box<dyn Sensor>>,
    transport: Arc<dyn Transport>,
    parent_resolver: Option<Arc<dyn ParentResolver>>,
    command_handler: Option<Arc<dyn CommandHandler>>,
    control_client: Option<Arc<GrpcControlClient>>,
    agent_updater: Option<Arc<dyn AgentUpdater>>,
    blocklist_updater: Option<Arc<dyn BlocklistUpdater>>,
    log_rx: Option<mpsc::Receiver<AgentLogEntry>>,
    /// Shared process table — created eagerly so platform command handlers
    /// (e.g. `kill_process_tree`) can receive a handle before `run()` starts.
    process_table: Arc<RwLock<ProcessTable>>,
}

impl Pipeline {
    pub fn new(config: AgentConfig, config_path: impl Into<PathBuf>, version: impl Into<String>, transport: impl Transport) -> Self {
        let process_table = Arc::new(RwLock::new(
            ProcessTable::new(config.agent_id.clone(), Duration::from_secs(PROCESS_EXIT_TTL_SECS)),
        ));
        Self {
            config,
            config_path: config_path.into(),
            version: version.into(),
            sensors: Vec::new(),
            transport: Arc::new(transport),
            parent_resolver: None,
            command_handler: None,
            control_client: None,
            agent_updater: None,
            blocklist_updater: None,
            log_rx: None,
            process_table,
        }
    }

    /// Return a cloned handle to the shared process table.  Platform command
    /// handlers can receive this before `run()` is called to read live process
    /// state when executing commands such as `kill_process_tree`.
    pub fn process_table_handle(&self) -> Arc<RwLock<ProcessTable>> {
        Arc::clone(&self.process_table)
    }

    /// Set the receiver for log entries from the tracing layer. When set, logs are
    /// written to a separate spool and sent to the server periodically.
    pub fn set_log_receiver(&mut self, rx: mpsc::Receiver<AgentLogEntry>) {
        self.log_rx = Some(rx);
    }

    pub fn add_sensor(&mut self, sensor: impl Sensor) {
        self.sensors.push(Box::new(sensor));
    }

    /// Set a platform-specific parent resolver used to look up parent
    /// processes that are not yet in the process table.
    pub fn set_parent_resolver(&mut self, resolver: impl ParentResolver + 'static) {
        self.parent_resolver = Some(Arc::new(resolver));
    }

    /// Register a platform-specific command handler and the gRPC control
    /// client used to poll for commands from the server.
    pub fn set_command_handler(&mut self, handler: impl CommandHandler, client: GrpcControlClient) {
        self.command_handler = Some(Arc::new(handler));
        self.control_client = Some(Arc::new(client));
    }

    /// Register a platform-specific agent updater (Linux: dpkg/rpm + restart; mac/win: future).
    pub fn set_agent_updater(&mut self, updater: impl AgentUpdater + 'static) {
        self.agent_updater = Some(Arc::new(updater));
    }

    /// Register a blocklist updater (e.g. the fanotify sensor on Linux).
    /// When set, the pipeline polls for blocklist changes every 30 s and calls
    /// `update_blocklist` whenever the list differs from the last-known state.
    pub fn set_blocklist_updater(&mut self, updater: impl BlocklistUpdater) {
        self.blocklist_updater = Some(Arc::new(updater));
    }

    /// Run all sensors and the flush loop until a SIGINT / SIGTERM arrives.
    pub async fn run(mut self) -> Result<()> {
        let started_at = Instant::now();
        let hostname = hostname();
        let agent_id = self.config.agent_id.clone();
        let os = std::env::consts::OS.to_string();

        let version = self.version.clone();
        let os_info = read_os_info();
        event::init_seqno(self.config.last_seqno);
        info!(agent_id = %agent_id, hostname = %hostname, os = %os, version = %version,
              os_version = %os_info.os_version, os_kernel = %os_info.os_kernel_version,
              seqno = self.config.last_seqno, "pipeline starting");

        let spool = SpoolHandle::spawn(&self.config.spool_path)?;

        let os_version = os_info.os_version;
        let os_kernel_version = os_info.os_kernel_version;

        // --- AgentStarted ---
        let started_event = make_event(&agent_id, &hostname, &os, EventKind::AgentStarted(AgentLifecycleEvent {
            version: version.clone(),
            os: os.clone(),
            os_version: os_version.clone(),
            os_kernel_version: os_kernel_version.clone(),
        }));
        if let Err(e) = spool.push(vec![started_event]).await {
            error!(error = %e, "failed to spool AgentStarted event");
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (event_tx, event_rx) = mpsc::channel::<Event>(4096);

        let mut handles = Vec::new();

        for sensor in self.sensors {
            let tx = event_tx.clone();
            let rx = cancel_rx.clone();
            let name = sensor.name().to_owned();
            handles.push(tokio::spawn(async move {
                info!(sensor = %name, "starting sensor");
                if let Err(e) = sensor.run(tx, rx).await {
                    error!(sensor = %name, error = %e, "sensor exited with error");
                }
            }));
        }

        // --- Heartbeat task ---
        let heartbeat_handle = {
            let tx = event_tx.clone();
            let cancel_rx = cancel_rx.clone();
            let hostname = hostname.clone();
            let agent_id = agent_id.clone();
            let os = os.clone();
            let version = version.clone();
            let os_version = os_version.clone();
            let os_kernel_version = os_kernel_version.clone();
            let interval = self.config.heartbeat_interval();
            let spool = spool.clone();
            let cmd_handler = self.command_handler.clone();
            tokio::spawn(async move {
                heartbeat_loop(tx, cancel_rx, spool, hostname, agent_id, os, version, os_version, os_kernel_version, started_at, interval, cmd_handler).await;
            })
        };

        // --- Command polling task (optional) ---
        let command_handle = if let (Some(handler), Some(ctrl)) = (self.command_handler.clone(), self.control_client.clone()) {
            let cancel_rx = cancel_rx.clone();
            let agent_id = agent_id.clone();
            Some(tokio::spawn(async move {
                command_poll_loop(ctrl, handler, agent_id, cancel_rx).await;
            }))
        } else {
            None
        };

        // --- Agent update task (optional) ---
        let update_handle = if let Some(ctrl) = self.control_client.clone() {
            let cancel_rx = cancel_rx.clone();
            let agent_id = agent_id.clone();
            let version = version.clone();
            let updater = self.agent_updater.clone();
            let update_in_progress = Arc::new(AtomicBool::new(false));
            let firewall_backend = self.config.firewall_backend.clone();
            Some(tokio::spawn(async move {
                agent_update_loop(ctrl, agent_id, version, updater, update_in_progress, firewall_backend, cancel_rx).await;
            }))
        } else {
            None
        };

        // --- Blocklist polling task (optional) ---
        let blocklist_handle = if let (Some(ctrl), Some(updater)) = (self.control_client.clone(), self.blocklist_updater.take()) {
            let cancel_rx = cancel_rx.clone();
            let agent_id = agent_id.clone();
            Some(tokio::spawn(async move {
                blocklist_poll_loop(ctrl, agent_id, updater, cancel_rx).await;
            }))
        } else {
            None
        };

        drop(event_tx);

        let ptable = Arc::clone(&self.process_table);

        let ingest_handle = {
            let spool = spool.clone();
            let ptable = Arc::clone(&ptable);
            let batch_size = self.config.batch_size;
            let flush_interval = self.config.flush_interval();
            let agent_id = agent_id.clone();
            let hostname = hostname.clone();
            let os = os.clone();
            let mut filters = FilterChain::new();
            filters.add(DeduplicationFilter::new(DEDUP_CAPACITY));
            let engine = DetectionEngine::new();
            let resolver = self.parent_resolver.clone();
            tokio::spawn(async move {
                ingest_loop(event_rx, spool, ptable, batch_size, flush_interval, agent_id, hostname, os, filters, engine, resolver).await;
            })
        };

        let drain_handle = {
            let spool = spool.clone();
            let transport = Arc::clone(&self.transport);
            let batch_size = self.config.batch_size;
            let flush_interval = self.config.flush_interval();
            let cancel_rx = cancel_rx.clone();
            tokio::spawn(async move {
                drain_loop(spool, transport, batch_size, flush_interval, cancel_rx).await;
            })
        };

        let (log_spool_handle, log_send_handle) = if let Some(log_rx) = self.log_rx.take() {
            let log_spool_path = self
                .config
                .spool_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("secureexec-logs-spool.db");
            let log_spool = LogSpoolHandle::spawn(&log_spool_path)?;
            let log_spool_for_drain = log_spool.clone();
            let log_cancel_rx = cancel_rx.clone();
            let drain_join = tokio::spawn(async move {
                log_spool_drain(log_rx, log_spool_for_drain, log_cancel_rx).await;
            });
            let transport = Arc::clone(&self.transport);
            let agent_id = agent_id.clone();
            let cancel_rx = cancel_rx.clone();
            let send_join = tokio::spawn(async move {
                log_send_loop(transport, agent_id, log_spool, cancel_rx).await;
            });
            (Some(drain_join), Some(send_join))
        } else {
            (None, None)
        };

        shutdown_signal().await;
        info!("shutdown signal received, stopping sensors…");
        let _ = cancel_tx.send(true);

        // Collect every spawned handle so we can force-abort stragglers
        // if the graceful deadline expires.
        let mut all_handles: Vec<tokio::task::JoinHandle<()>> = handles;
        all_handles.push(heartbeat_handle);
        all_handles.push(ingest_handle);
        if let Some(h) = command_handle { all_handles.push(h); }
        if let Some(h) = update_handle { all_handles.push(h); }
        if let Some(h) = blocklist_handle { all_handles.push(h); }
        all_handles.push(drain_handle);
        if let Some(h) = log_spool_handle { all_handles.push(h); }
        if let Some(h) = log_send_handle { all_handles.push(h); }

        let graceful = async {
            for h in &mut all_handles {
                let _ = h.await;
            }

            // --- AgentStopping ---
            let stopping_event = make_event(&agent_id, &hostname, &os, EventKind::AgentStopping(AgentLifecycleEvent {
                version: version.clone(),
                os: os.clone(),
                os_version: os_version.clone(),
                os_kernel_version: os_kernel_version.clone(),
            }));
            if let Err(e) = spool.push(vec![stopping_event]).await {
                error!(error = %e, "failed to spool AgentStopping event");
            }

            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                drain_once(&spool, &self.transport, self.config.batch_size),
            ).await;
        };

        if tokio::time::timeout(Duration::from_secs(SHUTDOWN_DEADLINE_SECS), graceful).await.is_err() {
            warn!("graceful shutdown deadline ({}s) exceeded, aborting remaining tasks", SHUTDOWN_DEADLINE_SECS);
            for h in &all_handles {
                h.abort();
            }
        }

        let remaining = spool.len().await;
        if remaining > 0 {
            info!(remaining, "unsent events preserved in spool for next run");
        }

        // Persist the current seqno so the next run continues monotonically.
        let mut cfg = self.config.clone();
        cfg.last_seqno = event::current_seqno();
        if let Err(e) = cfg.save(&self.config_path) {
            error!(error = %e, "failed to persist last_seqno to config");
        }

        info!("agent stopped");
        Ok(())
    }
}

fn make_event(agent_id: &str, hostname: &str, os: &str, kind: EventKind) -> Event {
    let mut event = Event::new(hostname.to_string(), kind);
    event.agent_id = agent_id.to_string();
    event.os = os.to_string();
    event.compute_hash();
    event
}

async fn heartbeat_loop(
    tx: mpsc::Sender<Event>,
    mut cancel: watch::Receiver<bool>,
    spool: SpoolHandle,
    hostname: String,
    agent_id: String,
    os: String,
    version: String,
    os_version: String,
    os_kernel_version: String,
    started_at: Instant,
    interval: std::time::Duration,
    command_handler: Option<Arc<dyn CommandHandler>>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            _ = cancel.changed() => {
                debug!("heartbeat loop stopping");
                return;
            }
            _ = ticker.tick() => {
                let spool_pending = spool.len().await as u64;
                let net_isolated = command_handler.as_ref()
                    .map(|h| h.net_isolated())
                    .unwrap_or(false);
                let kmod_available = command_handler.as_ref()
                    .map(|h| h.kmod_available())
                    .unwrap_or(false);
                let firewall_backend = command_handler.as_ref()
                    .map(|h| h.firewall_backend_name().to_string())
                    .unwrap_or_default();
                let kmod_version = command_handler.as_ref()
                    .map(|h| h.kmod_version().to_string())
                    .unwrap_or_default();
                let drops = command_handler.as_ref()
                    .map(|h| h.ebpf_drop_counts())
                    .unwrap_or([0; 4]);
                let event = make_event(&agent_id, &hostname, &os, EventKind::AgentHeartbeat(AgentHeartbeatEvent {
                    uptime_secs: started_at.elapsed().as_secs(),
                    spool_pending,
                    version: version.clone(),
                    os: os.clone(),
                    os_version: os_version.clone(),
                    os_kernel_version: os_kernel_version.clone(),
                    net_isolated,
                    kmod_available,
                    firewall_backend,
                    kmod_version,
                    ebpf_drops_process: drops[0],
                    ebpf_drops_file: drops[1],
                    ebpf_drops_network: drops[2],
                    ebpf_drops_security: drops[3],
                }));
                if tx.send(event).await.is_err() {
                    return;
                }
            }
        }
    }
}

const COMMAND_POLL_INTERVAL_SECS: u64 = 10;
/// Interval between target-version checks (update task).
const UPDATE_CHECK_INTERVAL_SECS: u64 = 30;
/// Max random delay (seconds) before starting update, to spread load across a fleet.
const UPDATE_START_JITTER_SECS: u64 = 20;
/// Hard timeout for a single run_update attempt (download + verify + spawn install).
const UPDATE_TIMEOUT_SECS: u64 = 300;

/// If target version differs from current, spawn update task (with jitter).
/// The spawned task resets `update_in_progress` on completion (success or failure)
/// so the loop can retry on the next tick.
/// Returns the `JoinHandle` so the caller can abort it on shutdown.
fn maybe_spawn_update(
    ctrl: &Arc<GrpcControlClient>,
    agent_id: &str,
    version: &str,
    updater: &Arc<dyn AgentUpdater>,
    update_in_progress: &Arc<AtomicBool>,
    target: String,
    expected_sha256: String,
    firewall_backend: String,
    cancel: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if update_in_progress.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        debug!(component = "agent-update", "update already in progress, skipping");
        return None;
    }
    let jitter_secs = rand::thread_rng().gen_range(0..=UPDATE_START_JITTER_SECS);
    info!(component = "agent-update", target = %target, current = %version, jitter_secs = jitter_secs, "target version differs, spawning update after jitter");
    let ctrl_clone = Arc::clone(ctrl);
    let agent_id_clone = agent_id.to_string();
    let updater_clone = Arc::clone(updater);
    let update_done = Arc::clone(update_in_progress);
    let mut cancel = cancel;
    Some(tokio::spawn(async move {
        if jitter_secs > 0 {
            if !crate::shutdown::cancellable_sleep(Duration::from_secs(jitter_secs), &mut cancel).await {
                update_done.store(false, Ordering::Release);
                debug!(component = "agent-update", "update cancelled during jitter");
                return;
            }
        }
        let result = tokio::time::timeout(
            Duration::from_secs(UPDATE_TIMEOUT_SECS),
            updater_clone.run_update(ctrl_clone, agent_id_clone, target, expected_sha256, firewall_backend),
        )
        .await;
        update_done.store(false, Ordering::Release);
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(component = "agent-update", error = %e, "agent update failed"),
            Err(_) => error!(component = "agent-update", "agent update timed out after {}s", UPDATE_TIMEOUT_SECS),
        }
    }))
}

/// Dedicated task: periodically check target version and spawn update when needed.
/// Does **not** exit after spawning — if the update fails the loop retries on the next tick.
async fn agent_update_loop(
    ctrl: Arc<GrpcControlClient>,
    agent_id: String,
    version: String,
    updater: Option<Arc<dyn AgentUpdater>>,
    update_in_progress: Arc<AtomicBool>,
    firewall_backend: String,
    mut cancel: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(UPDATE_CHECK_INTERVAL_SECS));
    ticker.tick().await; // skip the immediate first tick

    let mut update_handle: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        tokio::select! {
            _ = cancel.changed() => {
                debug!(component = "agent-update", "update loop stopping");
                if let Some(h) = update_handle.take() {
                    h.abort();
                    let _ = h.await;
                }
                return;
            }
            _ = ticker.tick() => {}
        }

        if update_in_progress.load(Ordering::Acquire) {
            continue;
        }
        if let Some(ref h) = update_handle {
            if h.is_finished() {
                update_handle = None;
            }
        }

        let cancel_for_spawn = cancel.clone();
        let tick_work = async {
            let platform = updater.as_ref().and_then(|u| u.platform()).unwrap_or_default();
            let (target, expected_sha256) = match ctrl.get_target_version(&agent_id, &platform).await {
                Ok(t) => t,
                Err(_) => return,
            };
            if target.is_empty() || target == version {
                return;
            }
            let Some(u) = updater.as_ref() else {
                info!(component = "agent-update", target = %target, "update not implemented on this platform");
                return;
            };
            if let Some(h) = maybe_spawn_update(&ctrl, &agent_id, &version, u, &update_in_progress, target, expected_sha256, firewall_backend.clone(), cancel_for_spawn) {
                update_handle = Some(h);
            }
        };

        tokio::select! {
            _ = cancel.changed() => {
                debug!(component = "agent-update", "update loop stopping");
                if let Some(h) = update_handle.take() {
                    h.abort();
                    let _ = h.await;
                }
                return;
            }
            _ = tick_work => {}
        }
    }
}

async fn command_poll_loop(
    ctrl: Arc<GrpcControlClient>,
    handler: Arc<dyn CommandHandler>,
    agent_id: String,
    mut cancel: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(COMMAND_POLL_INTERVAL_SECS));
    ticker.tick().await; // skip the immediate first tick

    // Track last-seen isolation rules so we only reprogram the kmod when they change.
    let mut last_isolation_rules: Vec<crate::transport::pb::IsolationRule> = Vec::new();

    loop {
        tokio::select! {
            _ = cancel.changed() => {
                debug!("command poll loop stopping");
                return;
            }
            _ = ticker.tick() => {}
        }

        // Run the tick body in a select so in-flight gRPC calls are
        // dropped immediately when cancel fires.
        let tick_work = async {
            let commands = match ctrl.poll_commands(&agent_id).await {
                Ok(cmds) => cmds,
                Err(e) => {
                    warn!(error = %e, "poll_commands failed");
                    return;
                }
            };

            for cmd in commands {
                let id = cmd.command_id.clone();
                info!(command_id = %id, command_type = %cmd.command_type, "dispatching command");
                match handler.handle(&cmd).await {
                    Ok(()) => {
                        if let Err(e) = ctrl.ack_command(&agent_id, &id, true, "").await {
                            warn!(error = %e, command_id = %id, "ack_command failed");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, command_id = %id, "command handler failed");
                        let err_str = e.to_string();
                        if let Err(ae) = ctrl.ack_command(&agent_id, &id, false, &err_str).await {
                            warn!(error = %ae, command_id = %id, "ack_command failed");
                        }
                    }
                }
            }

            // While isolated, poll for rule changes and reprogram if needed.
            if handler.net_isolated() {
                match ctrl.get_isolation_rules(&agent_id).await {
                    Ok(new_rules) => {
                        if new_rules != last_isolation_rules {
                            info!("isolation rules changed, reprogramming firewall");
                            let allow_rules: Vec<serde_json::Value> = new_rules.iter().map(|r| {
                                serde_json::json!({
                                    "ip": r.ip,
                                    "port": r.port,
                                    "direction": r.direction,
                                })
                            }).collect();
                            let payload = serde_json::json!({ "allow_rules": allow_rules });
                            let synthetic = AgentCommand {
                                command_id: String::new(),
                                command_type: "isolate_host".into(),
                                payload: payload.to_string(),
                            };
                            if let Err(e) = handler.handle(&synthetic).await {
                                warn!(error = %e, "failed to reprogram firewall after rule change");
                            } else {
                                last_isolation_rules = new_rules;
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "get_isolation_rules failed"),
                }
            } else {
                // Reset cache when not isolated so we pick up changes fresh next time.
                if !last_isolation_rules.is_empty() {
                    last_isolation_rules.clear();
                }
            }
        };

        tokio::select! {
            _ = cancel.changed() => {
                debug!("command poll loop stopping");
                return;
            }
            _ = tick_work => {}
        }
    }
}

/// Periodically fetches blocklist rules from the server and pushes them to the
/// blocklist updater (e.g. the fanotify sensor) when they change.
async fn blocklist_poll_loop(
    ctrl: Arc<GrpcControlClient>,
    agent_id: String,
    updater: Arc<dyn BlocklistUpdater>,
    mut cancel: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(BLOCKLIST_POLL_INTERVAL_SECS));
    ticker.tick().await; // skip the immediate first tick

    let mut last_rules: Vec<transport::pb::BlocklistRule> = Vec::new();

    loop {
        tokio::select! {
            _ = cancel.changed() => {
                debug!("blocklist poll loop stopping");
                return;
            }
            _ = ticker.tick() => {}
        }

        let tick_work = async {
            let rules = match ctrl.get_blocklist_rules(&agent_id).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "get_blocklist_rules failed");
                    return;
                }
            };
            if rules != last_rules {
                info!(count = rules.len(), "blocklist rules changed, updating sensor");
                updater.update_blocklist(rules.clone());
                last_rules = rules;
            }
        };

        tokio::select! {
            _ = cancel.changed() => {
                debug!("blocklist poll loop stopping");
                return;
            }
            _ = tick_work => {}
        }
    }
}

/// Reads events from the mpsc channel, stamps agent_id + os, updates the
/// process table, computes hash, filters, runs detections, and writes to the spool.
async fn ingest_loop(
    mut rx: mpsc::Receiver<Event>,
    spool: SpoolHandle,
    ptable: Arc<RwLock<ProcessTable>>,
    batch_size: usize,
    flush_interval: Duration,
    agent_id: String,
    hostname: String,
    os: String,
    mut filters: FilterChain,
    mut engine: DetectionEngine,
    parent_resolver: Option<Arc<dyn ParentResolver>>,
) {
    let mut batch: Vec<Event> = Vec::with_capacity(batch_size);
    let mut flush_ticker = tokio::time::interval(flush_interval);
    flush_ticker.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(mut event) => {
                        if event.agent_id.is_empty() {
                            event.agent_id = agent_id.clone();
                        }
                        if event.os.is_empty() {
                            event.os = os.clone();
                        }
                        {
                            // Recover from a poisoned lock rather than propagating the
                            // panic: the process table is in-memory state that is
                            // safe to keep mutating even if another thread panicked
                            // mid-update. Swallowing `PoisonError` lets the pipeline
                            // stay up and keep forwarding events.
                            let mut table = ptable.write().unwrap_or_else(|e| e.into_inner());
                            table.update(&event);
                            if let Some(pid) = event.kind.pid() {
                                let pst = event.kind.process_start_time();
                                let mut info = table.lookup(pid, pst).cloned();
                                if info.is_none() {
                                    if let Some(ref resolver) = parent_resolver {
                                        if let Some(resolved) = resolver.resolve(pid) {
                                            table.insert_synthetic(&resolved);
                                            info = table.lookup(pid, None).cloned();
                                        }
                                    }
                                }
                                if let Some(info) = info {
                                    enrich_event_from_process_info(&mut event, pid, &info, &mut table, &parent_resolver);
                                }
                            }
                        }
                        if event.process_pid == 0 {
                            if let Some(pid) = event.kind.pid() {
                                event.process_pid = pid;
                            }
                        }
                        if event.process_name.is_empty() {
                            if let Some(name) = event.kind.inner_process_name() {
                                if !name.is_empty() {
                                    event.process_name = name.to_string();
                                }
                            }
                        }
                        if event.process_cmdline.is_empty() {
                            if let Some(cmdline) = event.kind.inner_process_cmdline() {
                                if !cmdline.is_empty() {
                                    event.process_cmdline = cmdline.to_string();
                                }
                            }
                        }
                        if event.content_hash.is_empty() {
                            event.compute_hash();
                        }
                        batch.push(event);
                        if batch.len() >= batch_size {
                            flush_batch(&mut batch, &mut filters, &mut engine, &ptable, &spool, &agent_id, &hostname, &os).await;
                        }
                    }
                    None => {
                        if !batch.is_empty() {
                            flush_batch(&mut batch, &mut filters, &mut engine, &ptable, &spool, &agent_id, &hostname, &os).await;
                        }
                        return;
                    }
                }
            }
            _ = flush_ticker.tick(), if !batch.is_empty() => {
                flush_batch(&mut batch, &mut filters, &mut engine, &ptable, &spool, &agent_id, &hostname, &os).await;
            }
        }
    }
}

fn enrich_event_from_process_info(
    event: &mut Event,
    pid: u32,
    info: &ProcessInfo,
    table: &mut ProcessTable,
    parent_resolver: &Option<Arc<dyn ParentResolver>>,
) {
    let uid = info.process_guid.to_string();
    if event.process_guid.is_empty() {
        event.process_guid = uid.clone();
    }
    event.kind.enrich_process(&uid, &info.name);
    event.kind.enrich_parent_process_guid(&info.parent_process_guid);
    event.process_pid = pid;
    if event.process_user_id.is_empty() {
        event.process_user_id = info.uid.to_string();
    }
    if event.username.is_empty() {
        event.username = info.username.clone();
    }
    if event.container_id.is_empty() {
        event.container_id = info.container_id.clone();
    }
    if event.process_name.is_empty() {
        event.process_name = info.name.clone();
    }
    if event.process_cmdline.is_empty() {
        event.process_cmdline = info.cmdline.clone();
    }
    if event.process_exe_hash.is_empty() {
        event.process_exe_hash = info.exe_hash.clone();
    }
    if event.process_exe_size == 0 {
        event.process_exe_size = info.exe_size;
    }
    event.parent_process_guid = info.parent_process_guid.clone();
    event.parent_pid = info.parent_pid;
    if info.parent_pid > 0 {
        if table.lookup(info.parent_pid, None).is_none() {
            if let Some(ref resolver) = parent_resolver {
                if let Some(resolved) = resolver.resolve(info.parent_pid) {
                    table.insert_synthetic(&resolved);
                }
            }
        }
        if let Some(parent) = table.lookup(info.parent_pid, None) {
            event.parent_user_id = parent.uid.to_string();
            event.parent_username = parent.username.clone();
            event.parent_process_name = parent.name.clone();
            event.parent_process_cmdline = parent.cmdline.clone();
        }
    }
}

/// Filter → detect → spool a completed batch.
async fn flush_batch(
    batch: &mut Vec<Event>,
    filters: &mut FilterChain,
    engine: &mut DetectionEngine,
    ptable: &Arc<RwLock<ProcessTable>>,
    spool: &SpoolHandle,
    agent_id: &str,
    hostname: &str,
    os: &str,
) {
    filters.apply(batch);
    if !batch.is_empty() {
        run_detections(engine, batch, ptable, agent_id, hostname, os);
        spool_push(spool, batch).await;
    } else {
        batch.clear();
    }
    ptable.write().unwrap_or_else(|e| e.into_inner()).reap_expired();
}

fn run_detections(
    engine: &mut DetectionEngine,
    batch: &mut Vec<Event>,
    ptable: &RwLock<ProcessTable>,
    agent_id: &str,
    hostname: &str,
    os: &str,
) {
    let detections = {
        let table = ptable.read().unwrap_or_else(|e| e.into_inner());
        let ctx = DetectionContext {
            process_table: &table,
        };
        engine.run(&ctx, batch)
    };
    for mut det in detections {
        if det.agent_id.is_empty() {
            det.agent_id = agent_id.to_string();
        }
        if det.hostname.is_empty() {
            det.hostname = hostname.to_string();
        }
        if det.os.is_empty() {
            det.os = os.to_string();
        }
        if det.content_hash.is_empty() {
            det.compute_hash();
        }
        batch.push(det);
    }
}

async fn spool_push(spool: &SpoolHandle, batch: &mut Vec<Event>) {
    let events = std::mem::take(batch);
    if let Err(e) = spool.push(events).await {
        error!(error = %e, "failed to spool events — dropping batch");
    }
}

/// Periodically drains events from the spool and sends them via transport.
async fn drain_loop(
    spool: SpoolHandle,
    transport: Arc<dyn Transport>,
    batch_size: usize,
    flush_interval: std::time::Duration,
    mut cancel: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(flush_interval);

    loop {
        tokio::select! {
            // `changed()` only fires on edge-transition. After the first
            // cancel notification we still want the loop to observe the
            // shutdown flag, so we also check `*cancel.borrow()` below.
            _ = cancel.changed() => {
                let _ = tokio::time::timeout(
                    Duration::from_secs(10),
                    drain_once(&spool, &transport, batch_size),
                ).await;
                return;
            }
            _ = interval.tick() => {
                if *cancel.borrow() {
                    // Saw the cancel on a prior iteration; honour it by
                    // doing one last bounded drain and exiting.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(10),
                        drain_once(&spool, &transport, batch_size),
                    ).await;
                    return;
                }
            }
        }

        // drain_once involves a gRPC send — drop it instantly on cancel.
        tokio::select! {
            _ = cancel.changed() => {
                // Give the in-flight drain one bounded opportunity to
                // finish so we don't lose the batch we just peeked.
                let _ = tokio::time::timeout(
                    Duration::from_secs(10),
                    drain_once(&spool, &transport, batch_size),
                ).await;
                return;
            }
            _ = drain_once(&spool, &transport, batch_size) => {}
        }
    }
}

/// Drains log entries from the mpsc channel into the log spool (batched).
/// Exits when the channel is closed **or** when the cancel signal fires
/// (the sender may live in a global tracing subscriber that outlives the pipeline).
async fn log_spool_drain(
    mut rx: mpsc::Receiver<AgentLogEntry>,
    log_spool: LogSpoolHandle,
    mut cancel: watch::Receiver<bool>,
) {
    let mut batch = Vec::with_capacity(LOG_SPOOL_BATCH);
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(entry) => {
                        batch.push(entry);
                        if batch.len() >= LOG_SPOOL_BATCH {
                            if let Err(e) = log_spool.push(std::mem::take(&mut batch)).await {
                                tracing::event!(
                                    target: "secureexec_generic::log_sender",
                                    tracing::Level::WARN,
                                    error = %e,
                                    "log spool push failed"
                                );
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = cancel.changed() => {
                debug!("log spool drain stopping (cancel)");
                break;
            }
        }
    }
    if !batch.is_empty() {
        let _ = log_spool.push(batch).await;
    }
}

/// Periodically sends log entries from the spool to the server. Logs from this path
/// use target secureexec_generic::log_sender so they are not enqueued again.
/// On shutdown (cancel), flushes remaining entries for LOG_SHUTDOWN_FLUSH_SECS without waiting for a full batch.
async fn log_send_loop(
    transport: Arc<dyn Transport>,
    agent_id: String,
    log_spool: LogSpoolHandle,
    mut cancel: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(LOG_SEND_INTERVAL_SECS));
    interval.tick().await;
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    let deadline = Instant::now() + Duration::from_secs(LOG_SHUTDOWN_FLUSH_SECS);
                    while Instant::now() < deadline {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() { break; }
                        let (ids, entries) = match log_spool.peek(LOG_BATCH_SIZE).await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        if entries.is_empty() {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                        let send = transport.send_agent_logs(&agent_id, &entries);
                        if tokio::time::timeout(remaining, send).await.ok().and_then(|r| r.ok()).is_some() {
                            let _ = log_spool.remove(ids).await;
                        } else {
                            break;
                        }
                    }
                }
                return;
            }
            _ = interval.tick() => {}
        }

        let tick_work = async {
            let (ids, entries) = match log_spool.peek(LOG_BATCH_SIZE).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::event!(
                        target: "secureexec_generic::log_sender",
                        tracing::Level::WARN,
                        error = %e,
                        "log spool peek failed"
                    );
                    return;
                }
            };
            if entries.is_empty() {
                return;
            }
            match transport.send_agent_logs(&agent_id, &entries).await {
                Ok(()) => {
                    if let Err(e) = log_spool.remove(ids).await {
                        tracing::event!(
                            target: "secureexec_generic::log_sender",
                            tracing::Level::WARN,
                            error = %e,
                            "log spool remove after send failed"
                        );
                    }
                }
                Err(_) => {}
            }
        };

        tokio::select! {
            _ = cancel.changed() => {
                return;
            }
            _ = tick_work => {}
        }
    }
}

async fn drain_once(
    spool: &SpoolHandle,
    transport: &Arc<dyn Transport>,
    batch_size: usize,
) {
    loop {
        let (ids, events) = match spool.peek(batch_size).await {
            Ok(pair) => pair,
            Err(e) => {
                error!(error = %e, "spool peek failed");
                return;
            }
        };

        if events.is_empty() {
            return;
        }

        let count = events.len();
        debug!(count, "draining spool batch");

        match transport.send_batch(&events).await {
            Ok(()) => {
                if let Err(e) = spool.remove(ids).await {
                    error!(error = %e, "failed to remove sent events from spool");
                } else {
                    info!(count, "sent and removed from spool");
                }
            }
            Err(e) => {
                warn!(count, error = %e, "transport send failed — events stay in spool for retry");
                return;
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c().await.expect("Ctrl-C handler");
    }
}

fn hostname() -> String {
    hostname::get()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into())
}

struct OsInfo {
    os_version: String,
    os_kernel_version: String,
}

fn read_os_info() -> OsInfo {
    #[cfg(target_os = "macos")]
    {
        let os_version = run_cmd("sw_vers", &["-productVersion"]);
        let os_kernel_version = run_cmd("uname", &["-r"]);
        OsInfo { os_version, os_kernel_version }
    }
    #[cfg(target_os = "linux")]
    {
        let os_version = std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            })
            .unwrap_or_default();
        let os_kernel_version = run_cmd("uname", &["-r"]);
        OsInfo { os_version, os_kernel_version }
    }
    #[cfg(target_os = "windows")]
    {
        let os_version = run_cmd("cmd", &["/C", "ver"]);
        let os_kernel_version = String::new();
        OsInfo { os_version, os_kernel_version }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        OsInfo { os_version: String::new(), os_kernel_version: String::new() }
    }
}

fn run_cmd(prog: &str, args: &[&str]) -> String {
    std::process::Command::new(prog)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
