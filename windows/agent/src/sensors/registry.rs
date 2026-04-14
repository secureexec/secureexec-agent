use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::{Event, EventKind, RegistryEvent};
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

    async fn run(&self, tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        let hostname = hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("windows-registry sensor stopping");
                    return Ok(());
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    warn!("windows-registry: stub — no real registry monitoring yet");

                    let event = Event::new(
                        hostname.clone(),
                        EventKind::RegistryWrite(RegistryEvent {
                            pid: 0,
                            process_name: "stub.exe".into(),
                            process_guid: String::new(),
                            process_start_time: None,
                            key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
                            value_name: "StubEntry".into(),
                        }),
                    );
                    let _ = tx.send(event).await;
                }
            }
        }
    }
}
