mod command_handler;
mod constants;
mod detached_script;
mod ebpf_firewall;
mod firewall;
mod kmod;
mod log_tailer;
mod sensors;
mod update;

use std::path::Path;
use std::sync::{Arc, Mutex};

use secureexec_generic::config::AgentConfig;
use secureexec_generic::pipeline::Pipeline;
use secureexec_generic::transport::{GrpcControlClient, GrpcTransport, TlsConfig};
use tracing::{info, warn};

use command_handler::LinuxCommandHandler;
use ebpf_firewall::EbpfFirewall;
use firewall::{KmodFirewall, NetworkFirewall};
use sensors::auth::LinuxAuthSensor;
use sensors::ebpf::{load_ebpf, EbpfDropCounters, LinuxEbpfSensor};
use sensors::fanotify::FanotifySensor;
use sensors::procfs::{load_uid_map, ProcfsParentResolver};
use update::LinuxAgentUpdater;

const CONFIG_PATH: &str = "secureexec-agent.json";
const VERSION: &str = include_str!("../version");

#[tokio::main]
async fn main() -> secureexec_generic::error::Result<()> {
    let (log_tx, log_rx) = tokio::sync::mpsc::channel(4096);
    secureexec_generic::telemetry::init_with_log_layer(Some(log_tx));

    let config = AgentConfig::load_or_create(Path::new(CONFIG_PATH))?;
    info!(
        agent_id = %config.agent_id,
        backend = %config.backend_url,
        version = VERSION.trim(),
        firewall_pref = %config.firewall_backend,
        "secureexec agent starting (Linux)"
    );

    // -----------------------------------------------------------------------
    // Probe kmod availability (independent of which firewall is selected).
    // -----------------------------------------------------------------------
    let kmod_present = Path::new("/dev/secureexec_kmod").exists();

    // -----------------------------------------------------------------------
    // Firewall selection
    // -----------------------------------------------------------------------
    // Attempt to load eBPF once (if needed by auto or ebpf preference).
    // On success, the Ebpf object is wrapped in Arc<Mutex> so the firewall
    // watcher and the telemetry sensor can share it.
    let drop_counters = Arc::new(EbpfDropCounters::new());
    let (firewall, sensor, cancel_tx) = select_firewall_and_sensor(&config, drop_counters.clone());

    // -----------------------------------------------------------------------
    // Pipeline setup
    // -----------------------------------------------------------------------
    let tls = TlsConfig {
        ca_cert: config.tls_ca_cert.clone(),
        client_cert: config.tls_client_cert.clone(),
        client_key: config.tls_client_key.clone(),
    };
    let transport = GrpcTransport::new(&config.backend_url, tls, config.auth_token.clone());
    let mut pipeline = Pipeline::new(config.clone(), CONFIG_PATH, VERSION.trim(), transport);

    let uid_map = load_uid_map();
    pipeline.set_parent_resolver(ProcfsParentResolver::new(uid_map));
    pipeline.add_sensor(sensor);
    pipeline.add_sensor(LinuxAuthSensor::new());

    let fanotify = FanotifySensor::new();
    let blocklist_updater = fanotify.clone();
    pipeline.add_sensor(fanotify);
    pipeline.set_blocklist_updater(blocklist_updater);

    let process_table = pipeline.process_table_handle();
    let cmd_handler = LinuxCommandHandler::new(
        firewall,
        kmod_present,
        &config.backend_url,
        Some(process_table),
        Some(drop_counters),
    );
    let ctrl_tls = TlsConfig {
        ca_cert: config.tls_ca_cert.clone(),
        client_cert: config.tls_client_cert.clone(),
        client_key: config.tls_client_key.clone(),
    };
    let ctrl_client =
        GrpcControlClient::new(&config.backend_url, ctrl_tls, config.auth_token.clone());
    pipeline.set_command_handler(cmd_handler, ctrl_client);
    pipeline.set_agent_updater(LinuxAgentUpdater::new());
    pipeline.set_log_receiver(log_rx);

    // Drain leftover script log files from previous agent runs (Phase 2).
    log_tailer::drain_and_clean_script_logs().await;

    let result = pipeline.run().await;

    // Signal the eBPF firewall watcher (if any) to stop.
    if let Some(tx) = cancel_tx {
        let _ = tx.send(true);
    }

    result
}

/// Select the firewall backend according to `config.firewall_backend` and
/// construct the matching `LinuxEbpfSensor`.
///
/// Returns `(firewall, sensor, optional_cancel_sender)`.
/// The cancel sender is used to stop the eBPF firewall's interface watcher.
fn select_firewall_and_sensor(
    config: &AgentConfig,
    drop_counters: Arc<EbpfDropCounters>,
) -> (
    Option<Box<dyn NetworkFirewall>>,
    LinuxEbpfSensor,
    Option<tokio::sync::watch::Sender<bool>>,
) {
    let pref = config.firewall_backend.as_str();

    // Helper: try to initialise an eBPF firewall.
    let try_ebpf = || -> Result<
        (EbpfFirewall, Arc<Mutex<aya::Ebpf>>, tokio::sync::watch::Sender<bool>),
        String,
    > {
        let ebpf = load_ebpf().map_err(|e| format!("ebpf load: {e}"))?;
        let shared = Arc::new(Mutex::new(ebpf));
        let fw = EbpfFirewall::from_shared_ebpf(shared.clone())
            .map_err(|e| format!("ebpf firewall init: {e}"))?;
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        fw.start_iface_watcher(cancel_rx);
        Ok((fw, shared, cancel_tx))
    };

    match pref {
        "ebpf" => {
            match try_ebpf() {
                Ok((fw, shared, cancel_tx)) => {
                    info!("firewall: using eBPF TC classifier");
                    let sensor = LinuxEbpfSensor::with_shared_ebpf(shared, drop_counters);
                    (Some(Box::new(fw)), sensor, Some(cancel_tx))
                }
                Err(e) => {
                    warn!("firewall: eBPF requested but unavailable ({e}) — no isolation");
                    (None, LinuxEbpfSensor::new(drop_counters), None)
                }
            }
        }
        "kmod" => {
            let fw = KmodFirewall::try_open();
            if fw.is_some() {
                info!("firewall: using kmod (secureexec_kmod)");
            } else {
                warn!("firewall: kmod requested but /dev/secureexec_kmod not found — no isolation");
            }
            (fw.map(|f| Box::new(f) as Box<dyn NetworkFirewall>), LinuxEbpfSensor::new(drop_counters), None)
        }
        _ => {
            // "auto" or anything else: try eBPF first, fall back to kmod.
            match try_ebpf() {
                Ok((fw, shared, cancel_tx)) => {
                    info!("firewall: using eBPF TC classifier (auto)");
                    let sensor = LinuxEbpfSensor::with_shared_ebpf(shared, drop_counters.clone());
                    (Some(Box::new(fw)), sensor, Some(cancel_tx))
                }
                Err(e) => {
                    warn!("firewall: eBPF unavailable ({e}), trying kmod fallback");
                    let fw = KmodFirewall::try_open();
                    if fw.is_some() {
                        info!("firewall: using kmod (secureexec_kmod) as fallback");
                    } else {
                        warn!("firewall: no backend available — network isolation disabled");
                    }
                    (fw.map(|f| Box::new(f) as Box<dyn NetworkFirewall>), LinuxEbpfSensor::new(drop_counters), None)
                }
            }
        }
    }
}
