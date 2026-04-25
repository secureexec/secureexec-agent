use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::Event;
use secureexec_generic::sensor::Sensor;

/// File-system sensor for Windows.
///
/// TODO: replace the stub with real implementations — options include:
///   - ETW Microsoft-Windows-Kernel-File provider
///   - Minifilter driver (FltRegisterFilter) for real-time FS callbacks
///   - ReadDirectoryChangesW for user-mode directory monitoring
pub struct WindowsFileSensor;

impl WindowsFileSensor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sensor for WindowsFileSensor {
    fn name(&self) -> &str {
        "windows-file"
    }

    async fn run(&self, _tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        // Stub: emit a single startup warning so operators see the sensor
        // isn't implemented, then idle until cancelled. We deliberately do
        // NOT push synthetic events into the pipeline — fake telemetry
        // would pollute the backend with bogus FileCreate events that look
        // exactly like the indicators a backend would alert on.
        warn!("windows-file: stub — no real minifilter / ETW integration yet; sensor idle");
        let _ = cancel.changed().await;
        debug!("windows-file sensor stopping");
        Ok(())
    }
}
