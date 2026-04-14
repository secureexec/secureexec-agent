use tokio::sync::mpsc;
use tracing::info;

use secureexec_generic::event::{
    self as secureexec_event, EventKind, FileEvent, FileRenameEvent, ProcessEvent,
};

use super::EsEvent;
use super::helpers::system_time_to_chrono;
use crate::ffi::libproc;

pub fn convert_es_event(es: EsEvent, hostname: &str) -> secureexec_event::Event {
    let kind = match es {
        EsEvent::ProcessExec {
            pid,
            parent_pid,
            uid,
            name,
            path,
            cmdline,
            start_time,
        } => EventKind::ProcessCreate(ProcessEvent {
            pid,
            parent_pid,
            name,
            path,
            cmdline,
            user_id: uid.to_string(),
            start_time,
            snapshot: false,
            parent_process_guid: String::new(),
            exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
        }),
        EsEvent::ProcessExit {
            pid,
            parent_pid,
            uid,
            name,
            path,
            start_time,
        } => EventKind::ProcessExit(ProcessEvent {
            pid,
            parent_pid,
            name: name.clone(),
            path,
            cmdline: name,
            user_id: uid.to_string(),
            start_time,
            snapshot: false,
            parent_process_guid: String::new(),
            exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
        }),
        EsEvent::ProcessFork {
            pid,
            parent_pid,
            uid,
            name,
            path,
            start_time,
        } => EventKind::ProcessFork(ProcessEvent {
            pid,
            parent_pid,
            name: name.clone(),
            path,
            cmdline: name,
            user_id: uid.to_string(),
            start_time,
            snapshot: false,
            parent_process_guid: String::new(),
            exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
        }),
        EsEvent::FileCreate {
            path,
            pid,
            process_name,
            start_time,
        } => EventKind::FileCreate(FileEvent {
            path,
            pid,
            process_name,
            process_guid: String::new(),
            process_start_time: Some(start_time),
            user_id: String::new(),
        }),
        EsEvent::FileWrite {
            path,
            pid,
            process_name,
            start_time,
        } => EventKind::FileModify(FileEvent {
            path,
            pid,
            process_name,
            process_guid: String::new(),
            process_start_time: Some(start_time),
            user_id: String::new(),
        }),
        EsEvent::FileUnlink {
            path,
            pid,
            process_name,
            start_time,
        } => EventKind::FileDelete(FileEvent {
            path,
            pid,
            process_name,
            process_guid: String::new(),
            process_start_time: Some(start_time),
            user_id: String::new(),
        }),
        EsEvent::FileRename {
            old_path,
            new_path,
            pid,
            process_name,
            start_time,
        } => EventKind::FileRename(FileRenameEvent {
            old_path,
            new_path,
            pid,
            process_name,
            process_guid: String::new(),
            process_start_time: Some(start_time),
            user_id: String::new(),
        }),
    };
    secureexec_event::Event::new(hostname.to_string(), kind)
}

pub fn emit_process_snapshot(tx: &mpsc::Sender<secureexec_event::Event>, hostname: &str) {
    let pids = libproc::list_all_pids();
    let mut count = 0u32;
    for pid in pids {
        let Some(info) = libproc::pid_info(pid) else {
            continue;
        };
        let path = libproc::pid_path(pid).unwrap_or_default();
        let cmdline = libproc::pid_cmdline(pid).unwrap_or_else(|| info.name.clone());
        let start = system_time_to_chrono(info.start_time);
        let event = secureexec_event::Event::new(
            hostname.to_string(),
            EventKind::ProcessCreate(ProcessEvent {
                pid: info.pid,
                parent_pid: info.parent_pid,
                name: info.name.clone(),
                path,
                cmdline,
                        user_id: info.uid.to_string(),
                start_time: start,
                snapshot: true,
                parent_process_guid: String::new(),
                exit_code: None,
                ld_preload: String::new(),
                exe_hash: String::new(),
                exe_size: 0,
            }),
        );
        if tx.blocking_send(event).is_err() {
            return;
        }
        count += 1;
    }
    info!("macos-es: emitted {count} snapshot processes");
}
