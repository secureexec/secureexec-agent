//! Captures output from detached update/uninstall scripts and feeds it into
//! the agent's tracing pipeline so it reaches the server as agent logs.
//!
//! **Phase 1 — live tail**: `tail_script_log` polls a per-run log file every
//! `POLL_INTERVAL` while the agent is alive.
//!
//! **Phase 2 — startup drain**: `drain_and_clean_script_logs` runs once at
//! startup, reads any leftover log files from previous agent runs (e.g. dpkg
//! output the old agent missed because it was killed), sends them, then deletes.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt};
use tracing::info;

use secureexec_generic::shutdown::{cancellable_sleep, is_cancelled};

use crate::detached_script::{SCRIPT_LOG_DIR, SCRIPT_LOG_PREFIX, SCRIPT_LOG_SUFFIX};

/// How often the live tailer checks for new data.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
/// After no new data for this long the script is assumed finished and the file is deleted.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Tail a single log file, emitting each line as a tracing event.
/// Polls every `POLL_INTERVAL`. Stops and deletes the file after no new data
/// for `IDLE_TIMEOUT` — meaning the script has finished.
///
/// An optional `cancel` receiver allows the caller to stop the tailer promptly
/// on agent shutdown.  When `None` the tailer relies on `IDLE_TIMEOUT` alone.
///
/// If the agent is killed before this function completes, the file stays on disk
/// and is picked up by `drain_and_clean_script_logs` on the next startup.
pub async fn tail_script_log(
    path: PathBuf,
    component: String,
    mut cancel: Option<tokio::sync::watch::Receiver<bool>>,
) {
    // Wait for the file to appear (the detached script may not have started yet).
    let mut wait_attempts = 0u32;
    loop {
        if tokio::fs::metadata(&path).await.is_ok() {
            break;
        }
        if cancel.as_ref().map_or(false, |c| is_cancelled(c)) {
            return;
        }
        wait_attempts += 1;
        if wait_attempts > 30 {
            tracing::warn!(component = %component, path = %path.display(), "script log file never appeared, giving up");
            return;
        }
        match cancel.as_mut() {
            Some(c) => { if !cancellable_sleep(POLL_INTERVAL, c).await { return; } }
            None => tokio::time::sleep(POLL_INTERVAL).await,
        }
    }

    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(component = %component, path = %path.display(), error = %e, "failed to open script log file");
            return;
        }
    };

    let mut reader = tokio::io::BufReader::new(file);
    let mut line_buf = String::new();
    let mut idle_elapsed = std::time::Duration::ZERO;

    loop {
        if cancel.as_ref().map_or(false, |c| is_cancelled(c)) {
            break;
        }
        line_buf.clear();
        match reader.read_line(&mut line_buf).await {
            Ok(0) => {
                // EOF — no new data yet.
                if idle_elapsed >= IDLE_TIMEOUT {
                    break;
                }
                match cancel.as_mut() {
                    Some(c) => { if !cancellable_sleep(POLL_INTERVAL, c).await { break; } }
                    None => tokio::time::sleep(POLL_INTERVAL).await,
                }
                idle_elapsed += POLL_INTERVAL;
            }
            Ok(_) => {
                idle_elapsed = std::time::Duration::ZERO;
                let line = line_buf.trim_end();
                if !line.is_empty() {
                    info!(component = %component, "{}", line);
                }
            }
            Err(e) => {
                tracing::warn!(component = %component, error = %e, "error reading script log");
                break;
            }
        }
    }

    if let Err(e) = tokio::fs::remove_file(&path).await {
        tracing::warn!(component = %component, path = %path.display(), error = %e, "failed to delete finished script log");
    }
}

/// On startup, find leftover script log files from previous agent runs,
/// send their content as tracing events, then delete the files.
/// This captures dpkg/rpm output the old agent missed because it was killed.
pub async fn drain_and_clean_script_logs() {
    let dir = Path::new(SCRIPT_LOG_DIR);
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !name.starts_with(SCRIPT_LOG_PREFIX) || !name.ends_with(SCRIPT_LOG_SUFFIX) {
            continue;
        }

        // Extract component from filename: secureexec-agent.<component>.<uuid>.log
        let inner = &name[SCRIPT_LOG_PREFIX.len()..name.len() - SCRIPT_LOG_SUFFIX.len()];
        let component = match inner.rfind('.') {
            Some(dot) => &inner[..dot],
            None => inner,
        };

        let path = entry.path();
        // Cap each log read to avoid exhausting memory if a runaway script
        // left behind a multi-GB log file. For oversize files we seek to
        // (file_len - MAX_DRAIN_BYTES) and read only the tail, so memory use
        // stays bounded regardless of file size.
        const MAX_DRAIN_BYTES: u64 = 8 * 1024 * 1024;
        let content = match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.len() > MAX_DRAIN_BYTES => {
                let total = meta.len();
                let tail_start = total - MAX_DRAIN_BYTES;
                match tokio::fs::File::open(&path).await {
                    Ok(mut f) => {
                        if let Err(e) = f.seek(std::io::SeekFrom::Start(tail_start)).await {
                            tracing::warn!(path = %path.display(), error = %e, "failed to seek in leftover script log");
                            continue;
                        }
                        let mut buf = Vec::with_capacity(MAX_DRAIN_BYTES as usize);
                        if let Err(e) = f.take(MAX_DRAIN_BYTES).read_to_end(&mut buf).await {
                            tracing::warn!(path = %path.display(), error = %e, "failed to read tail of leftover script log");
                            continue;
                        }
                        let s = String::from_utf8_lossy(&buf).to_string();
                        format!(
                            "[log truncated: {} bytes total, keeping last {}]\n{}",
                            total, MAX_DRAIN_BYTES, s
                        )
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "failed to open oversize script log");
                        continue;
                    }
                }
            }
            _ => match tokio::fs::read_to_string(&path).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "failed to read leftover script log");
                    continue;
                }
            },
        };

        if !content.is_empty() {
            info!(component = %component, "draining leftover script log: {}", path.display());
            for line in content.lines() {
                if !line.is_empty() {
                    info!(component = %component, "{}", line);
                }
            }
        }

        if let Err(e) = tokio::fs::remove_file(&path).await {
            tracing::warn!(path = %path.display(), error = %e, "failed to delete drained script log");
        }
    }
}
