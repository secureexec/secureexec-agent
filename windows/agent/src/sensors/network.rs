use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::{Event, EventKind, NetworkEvent, Protocol};
use secureexec_generic::sensor::Sensor;

/// Network sensor for Windows.
///
/// TODO: replace the stub with real implementations — options include:
///   - ETW Microsoft-Windows-Kernel-Network provider
///   - WFP (Windows Filtering Platform) callout driver
///   - GetExtendedTcpTable / GetExtendedUdpTable polling
pub struct WindowsNetworkSensor;

impl WindowsNetworkSensor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sensor for WindowsNetworkSensor {
    fn name(&self) -> &str {
        "windows-network"
    }

    async fn run(&self, tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        let hostname = hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("windows-network sensor stopping");
                    return Ok(());
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    warn!("windows-network: stub — no real ETW / WFP integration yet");

                    let event = Event::new(
                        hostname.clone(),
                        EventKind::NetworkConnect(NetworkEvent {
                            pid: 0,
                            process_name: "stub.exe".into(),
                            process_guid: String::new(),
                            process_start_time: None,
                            src_addr: "0.0.0.0".into(),
                            src_port: 0,
                            dst_addr: "93.184.216.34".into(),
                            dst_port: 443,
                            protocol: Protocol::Tcp,
                            user_id: String::new(),
                        }),
                    );
                    let _ = tx.send(event).await;
                }
            }
        }
    }
}
