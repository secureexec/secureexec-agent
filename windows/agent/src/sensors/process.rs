use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::Event;
use secureexec_generic::sensor::Sensor;

/// Process sensor for Windows.
///
/// TODO: replace the stub with real implementations — options include:
///   - ETW (Event Tracing for Windows) Microsoft-Windows-Kernel-Process provider
///   - WMI Win32_ProcessStartTrace / Win32_ProcessStopTrace
///   - PsSetCreateProcessNotifyRoutineEx via a companion kernel driver
///
/// TODO: replace snapshot stubs with CreateToolhelp32Snapshot enumeration
pub struct WindowsProcessSensor;

impl WindowsProcessSensor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sensor for WindowsProcessSensor {
    fn name(&self) -> &str {
        "windows-process"
    }

    async fn run(&self, _tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        // Stub: warn once, then idle until cancelled.  Previously this
        // sensor shipped a hardcoded "snapshot" of fake processes (System,
        // smss.exe, svchost.exe) plus a synthetic ProcessCreate every 2s
        // — both would corrupt production process telemetry on the
        // backend (impossible PIDs, ghost lineage, fake stub.exe events).
        warn!("windows-process: stub — no real ETW integration yet; sensor idle");
        let _ = cancel.changed().await;
        debug!("windows-process sensor stopping");
        Ok(())
    }
}
