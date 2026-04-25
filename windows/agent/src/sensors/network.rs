use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::Event;
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

    async fn run(&self, _tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        // Stub: warn once, then idle until cancelled.  Synthetic
        // NetworkConnect events (e.g. to 93.184.216.34) would generate
        // false-positive alerts in any IDS pointed at this telemetry.
        warn!("windows-network: stub — no real ETW / WFP integration yet; sensor idle");
        let _ = cancel.changed().await;
        debug!("windows-network sensor stopping");
        Ok(())
    }
}
