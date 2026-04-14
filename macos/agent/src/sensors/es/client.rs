use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use endpoint_sec::{Client, Event, Message};
use endpoint_sec_sys::es_event_type_t;
use tracing::{debug, error, info};

use super::EsEvent;
use super::helpers::*;

pub fn run_es_client(tx: tokio::sync::mpsc::Sender<EsEvent>, stop: Arc<AtomicBool>) {
    endpoint_sec::version::set_runtime_version(14, 0, 0);

    let handler_tx = tx.clone();
    let mut client = match Client::new(move |_client, msg: Message| {
        if let Some(es_event) = parse_message(&msg) {
            let _ = handler_tx.blocking_send(es_event);
        }
    }) {
        Ok(c) => c,
        Err(e) => {
            error!("macos-es: failed to create ES client: {e:?} — is the binary signed with the ES entitlement and running as root?");
            return;
        }
    };

    let events = [
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_WRITE,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
    ];
    if let Err(e) = client.subscribe(&events) {
        error!("macos-es: subscribe failed: {e:?}");
        return;
    }

    info!("macos-es: ES client running, subscribed to {} event types", events.len());

    while !stop.load(Ordering::Acquire) {
        std::thread::park_timeout(Duration::from_millis(500));
    }

    debug!("macos-es: ES client shutting down");
    drop(client);
}

fn parse_message(msg: &Message) -> Option<EsEvent> {
    let event = msg.event()?;
    match event {
        Event::NotifyExec(exec) => {
            let target = exec.target();
            let pid = target.audit_token().pid() as u32;
            let parent_pid = target.ppid() as u32;
            let uid = target.audit_token().euid();
            let name = process_name(&target);
            let path = process_path(&target);
            let cmdline = build_cmdline(&exec);
            let start_time = process_start_time(&target);
            Some(EsEvent::ProcessExec {
                pid,
                parent_pid,
                uid,
                name,
                path,
                cmdline,
                start_time,
            })
        }
        Event::NotifyExit(_exit) => {
            let proc = msg.process();
            let pid = proc.audit_token().pid() as u32;
            let parent_pid = proc.ppid() as u32;
            let uid = proc.audit_token().euid();
            let name = process_name(&proc);
            let path = process_path(&proc);
            let start_time = process_start_time(&proc);
            Some(EsEvent::ProcessExit {
                pid,
                parent_pid,
                uid,
                name,
                path,
                start_time,
            })
        }
        Event::NotifyFork(fork) => {
            let child = fork.child();
            let pid = child.audit_token().pid() as u32;
            let parent_pid = child.ppid() as u32;
            let uid = child.audit_token().euid();
            let name = process_name(&child);
            let path = process_path(&child);
            let start_time = process_start_time(&child);
            Some(EsEvent::ProcessFork {
                pid,
                parent_pid,
                uid,
                name,
                path,
                start_time,
            })
        }
        Event::NotifyCreate(create) => {
            let proc = msg.process();
            let pid = proc.audit_token().pid() as u32;
            let pname = process_name(&proc);
            let st = process_start_time(&proc);
            let path = create_destination_path(&create);
            Some(EsEvent::FileCreate {
                path,
                pid,
                process_name: pname,
                start_time: st,
            })
        }
        Event::NotifyWrite(write) => {
            let proc = msg.process();
            let pid = proc.audit_token().pid() as u32;
            let pname = process_name(&proc);
            let st = process_start_time(&proc);
            let path = os_str_to_string(write.target().path());
            Some(EsEvent::FileWrite {
                path,
                pid,
                process_name: pname,
                start_time: st,
            })
        }
        Event::NotifyUnlink(unlink) => {
            let proc = msg.process();
            let pid = proc.audit_token().pid() as u32;
            let pname = process_name(&proc);
            let st = process_start_time(&proc);
            let path = os_str_to_string(unlink.target().path());
            Some(EsEvent::FileUnlink {
                path,
                pid,
                process_name: pname,
                start_time: st,
            })
        }
        Event::NotifyRename(rename) => {
            let proc = msg.process();
            let pid = proc.audit_token().pid() as u32;
            let pname = process_name(&proc);
            let st = process_start_time(&proc);
            let old_path = os_str_to_string(rename.source().path());
            let new_path = rename_destination_path(&rename);
            Some(EsEvent::FileRename {
                old_path,
                new_path,
                pid,
                process_name: pname,
                start_time: st,
            })
        }
        _ => None,
    }
}
