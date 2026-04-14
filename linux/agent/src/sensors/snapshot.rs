use std::fs;

use tokio::sync::mpsc;
use tracing::info;

use secureexec_generic::event::{Event, EventKind, ProcessEvent};

use super::procfs;

/// Enumerate all running processes from /proc and emit snapshot events.
pub fn emit_process_snapshot(tx: &mpsc::Sender<Event>, hostname: &str, uid_resolver: &mut procfs::UidResolver) {
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "failed to read /proc");
            return;
        }
    };

    let mut count = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let Some(info) = procfs::read_proc_info(pid) else {
            continue;
        };

        let username = uid_resolver.resolve(info.uid, pid);
        let container_id = info.container_id.unwrap_or_default();
        let mut event = Event::new(
            hostname.to_string(),
            EventKind::ProcessCreate(ProcessEvent {
                pid,
                parent_pid: info.parent_pid,
                name: info.name,
                path: info.path,
                cmdline: info.cmdline,
                user_id: info.uid.to_string(),
                start_time: info.start_time,
                snapshot: true,
                parent_process_guid: String::new(),
                exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
            }),
        );
        event.username        = username;
        event.process_user_id = info.uid.to_string();
        event.container_id    = container_id;

        if tx.blocking_send(event).is_err() {
            return;
        }
        count += 1;
    }

    info!("linux-ebpf: emitted {count} snapshot processes");
}
