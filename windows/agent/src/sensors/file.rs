use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::{Event, EventKind, FileEvent};
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

    async fn run(&self, tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        let hostname = hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("windows-file sensor stopping");
                    return Ok(());
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    warn!("windows-file: stub — no real minifilter / ETW integration yet");

                    let event = Event::new(
                        hostname.clone(),
                        EventKind::FileCreate(FileEvent {
                            path: r"C:\Temp\stub.txt".into(),
                            pid: 0,
                            process_name: "stub.exe".into(),
                            process_guid: String::new(),
                            process_start_time: None,
                            user_id: String::new(),
                        }),
                    );
                    let _ = tx.send(event).await;
                }
            }
        }
    }
}
