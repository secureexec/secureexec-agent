use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::Event;
use secureexec_generic::sensor::Sensor;

/// Windows-only registry sensor.
///
/// TODO: replace the stub with real implementations — options include:
///   - ETW Microsoft-Windows-Kernel-Registry provider
///   - CmRegisterCallbackEx via a companion kernel driver
///   - RegNotifyChangeKeyValue polling for specific keys
pub struct WindowsRegistrySensor;

impl WindowsRegistrySensor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sensor for WindowsRegistrySensor {
    fn name(&self) -> &str {
        "windows-registry"
    }

    async fn run(&self, _tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        // Stub: warn once, then idle until cancelled.  Synthetic
        // RegistryWrite events (e.g. to HKLM\...\CurrentVersion\Run) match
        // common persistence indicators and would trigger false-positive
        // alerts on any backend that monitors autorun keys.
        warn!("windows-registry: stub — no real registry monitoring yet; sensor idle");
        let _ = cancel.changed().await;
        debug!("windows-registry sensor stopping");
        Ok(())
    }
}
