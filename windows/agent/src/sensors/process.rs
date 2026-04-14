use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use secureexec_generic::error::Result;
use secureexec_generic::event::{Event, EventKind, ProcessEvent};
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

    async fn run(&self, tx: mpsc::Sender<Event>, mut cancel: watch::Receiver<bool>) -> Result<()> {
        let hostname = hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        // --- initial process snapshot ---
        // TODO: replace with real CreateToolhelp32Snapshot enumeration
        let snapshot_procs = vec![
            ("System", "", 4u32, 0u32),
            ("smss.exe", r"C:\Windows\System32\smss.exe", 300, 4),
            ("svchost.exe", r"C:\Windows\System32\svchost.exe", 800, 600),
        ];
        for (name, path, pid, parent_pid) in snapshot_procs {
            let event = Event::new(
                hostname.clone(),
                EventKind::ProcessCreate(ProcessEvent {
                    pid,
                    parent_pid,
                    name: name.into(),
                    path: path.into(),
                    cmdline: name.into(),
                    user_id: String::new(),
                    start_time: Utc::now(),
                    snapshot: true,
                    parent_process_guid: String::new(),
                    exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
                }),
            );
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        info!("windows-process: emitted {} snapshot entries (stub)", 3);

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("windows-process sensor stopping");
                    return Ok(());
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    warn!("windows-process: stub — no real ETW integration yet");

                    let event = Event::new(
                        hostname.clone(),
                        EventKind::ProcessCreate(ProcessEvent {
                            pid: 0,
                            parent_pid: 0,
                            name: "stub.exe".into(),
                            path: r"C:\Windows\System32\stub.exe".into(),
                            cmdline: "stub.exe --example".into(),
                            user_id: String::new(),
                            start_time: Utc::now(),
                            snapshot: false,
                            parent_process_guid: String::new(),
                            exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
                        }),
                    );
                    let _ = tx.send(event).await;
                }
            }
        }
    }
}
