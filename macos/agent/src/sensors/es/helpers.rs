use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use endpoint_sec::{
    EventCreate, EventCreateDestinationFile, EventExec, EventRename,
    EventRenameDestinationFile, Process,
};

pub fn os_str_to_string(s: &OsStr) -> String {
    s.to_string_lossy().into_owned()
}

pub fn system_time_to_chrono(st: SystemTime) -> DateTime<Utc> {
    let dur = st.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    DateTime::from_timestamp(dur.as_secs() as i64, dur.subsec_nanos()).unwrap_or_default()
}

pub fn process_name(proc: &Process<'_>) -> String {
    let exe = proc.executable();
    let path = os_str_to_string(exe.path());
    path.rsplit('/').next().unwrap_or(&path).to_string()
}

pub fn process_path(proc: &Process<'_>) -> String {
    os_str_to_string(proc.executable().path())
}

pub fn process_start_time(proc: &Process<'_>) -> DateTime<Utc> {
    proc.start_time()
        .map(system_time_to_chrono)
        .unwrap_or_else(Utc::now)
}

pub fn build_cmdline(exec: &EventExec<'_>) -> String {
    exec.args()
        .map(|a| os_str_to_string(a))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn create_destination_path(event: &EventCreate<'_>) -> String {
    match event.destination() {
        Some(EventCreateDestinationFile::ExistingFile(f)) => os_str_to_string(f.path()),
        Some(EventCreateDestinationFile::NewPath {
            directory,
            filename,
            ..
        }) => {
            let dir = os_str_to_string(directory.path());
            let name = os_str_to_string(filename);
            format!("{dir}/{name}")
        }
        None => "<unknown>".into(),
    }
}

pub fn rename_destination_path(event: &EventRename<'_>) -> String {
    match event.destination() {
        Some(EventRenameDestinationFile::ExistingFile(f)) => os_str_to_string(f.path()),
        Some(EventRenameDestinationFile::NewPath {
            directory,
            filename,
        }) => {
            let dir = os_str_to_string(directory.path());
            let name = os_str_to_string(filename);
            format!("{dir}/{name}")
        }
        None => "<unknown>".into(),
    }
}
