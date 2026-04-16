use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use secureexec_generic::error::{AgentError, Result};
use secureexec_generic::event::{Event, EventKind, UserLogonEvent};
use secureexec_generic::sensor::Sensor;

pub struct LinuxAuthSensor;

impl LinuxAuthSensor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sensor for LinuxAuthSensor {
    fn name(&self) -> &str {
        "linux-auth"
    }

    async fn run(&self, tx: mpsc::Sender<Event>, cancel: watch::Receiver<bool>) -> Result<()> {
        let hostname = hostname::get().unwrap_or_default().to_string_lossy().into_owned();

        let journal_res = run_journalctl_follow(hostname.clone(), tx.clone(), cancel.clone()).await;
        if journal_res.is_ok() {
            return Ok(());
        }
        if let Err(e) = journal_res {
            warn!(error = %e, "linux-auth: journalctl source unavailable, falling back to auth logs");
        }

        if let Some(path) = existing_auth_log() {
            return run_auth_log_tail(path, hostname, tx, cancel).await;
        }

        warn!("linux-auth: no telemetry source found (journalctl/auth.log), sensor idle");
        let mut cancel_rx = cancel;
        let _ = cancel_rx.changed().await;
        Ok(())
    }
}

async fn run_journalctl_follow(
    hostname: String,
    tx: mpsc::Sender<Event>,
    mut cancel: watch::Receiver<bool>,
) -> Result<()> {
    let mut child = Command::new("journalctl")
        .args(["-f", "-n", "0", "-o", "cat", "-u", "sshd", "-u", "ssh"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| AgentError::Sensor(format!("journalctl spawn failed: {e}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AgentError::Sensor("journalctl stdout not piped".to_string()))?;

    info!("linux-auth: reading SSH auth events from journalctl");
    let mut lines = BufReader::new(stdout).lines();
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Ok(());
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        if let Some(logon) = parse_sshd_line(&l) {
                            send_logon(&hostname, &tx, logon).await?;
                        }
                    }
                    Ok(None) => {
                        let status = child.wait().await
                            .map_err(|e| AgentError::Sensor(format!("journalctl wait failed: {e}")))?;
                        return Err(AgentError::Sensor(format!("journalctl exited: {status}")));
                    }
                    Err(e) => {
                        return Err(AgentError::Sensor(format!("journalctl read failed: {e}")));
                    }
                }
            }
        }
    }
}

async fn run_auth_log_tail(
    path: PathBuf,
    hostname: String,
    tx: mpsc::Sender<Event>,
    mut cancel: watch::Receiver<bool>,
) -> Result<()> {
    info!(path = %path.display(), "linux-auth: tailing SSH auth log file");

    let mut offset = tokio::fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
    let mut carry = String::new();

    loop {
        tokio::select! {
            _ = cancel.changed() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                let meta = match tokio::fs::metadata(&path).await {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(error = %e, path = %path.display(), "linux-auth: failed to stat auth log");
                        continue;
                    }
                };
                if meta.len() < offset {
                    offset = 0;
                }
                if meta.len() == offset {
                    continue;
                }

                // Cap each tail read to prevent OOM if auth.log rotated
                // while we were asleep and now contains hundreds of MB of
                // new data. On overflow we skip ahead — an operator would
                // rather miss some old logon lines than crash the sensor.
                const MAX_CHUNK: u64 = 4 * 1024 * 1024;
                let available = meta.len().saturating_sub(offset);
                let to_read = available.min(MAX_CHUNK);
                if available > MAX_CHUNK {
                    warn!(
                        path = %path.display(),
                        skipped = available - MAX_CHUNK,
                        "linux-auth: auth log grew beyond read cap; skipping oldest bytes"
                    );
                    offset = meta.len() - MAX_CHUNK;
                    // `carry` holds the tail of a partial line from the
                    // previous iteration; it is only meaningful when the
                    // next chunk starts exactly where we stopped. After
                    // skipping ahead we'd otherwise glue a fragment of an
                    // old line to the middle of a new one, producing a
                    // bogus leading log entry.
                    carry.clear();
                }
                let mut file = File::open(&path).await?;
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                let mut buf = vec![0u8; to_read as usize];
                let n = file.read(&mut buf).await?;
                buf.truncate(n);
                let chunk = String::from_utf8_lossy(&buf).to_string();
                offset = file.stream_position().await?;

                let mut text = String::new();
                text.push_str(&carry);
                text.push_str(&chunk);

                let ends_with_newline = text.ends_with('\n');
                let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                if ends_with_newline {
                    carry.clear();
                } else {
                    carry = lines.pop().unwrap_or_default();
                }

                for line in lines {
                    if let Some(logon) = parse_sshd_line(&line) {
                        send_logon(&hostname, &tx, logon).await?;
                    }
                }
            }
        }
    }
}

async fn send_logon(hostname: &str, tx: &mpsc::Sender<Event>, logon: UserLogonEvent) -> Result<()> {
    let ev = Event::new(hostname.to_string(), EventKind::UserLogon(logon));
    tx.send(ev)
        .await
        .map_err(|_| AgentError::Sensor("linux-auth: pipeline channel closed".to_string()))
}

fn existing_auth_log() -> Option<PathBuf> {
    let candidates = ["/var/log/auth.log", "/var/log/secure"];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

fn parse_sshd_line(line: &str) -> Option<UserLogonEvent> {
    if line.contains("Accepted ") {
        let (username, source_addr) = parse_user_and_source(line, "Accepted ")?;
        return Some(UserLogonEvent {
            username,
            logon_type: "ssh_success".to_string(),
            source_addr: Some(source_addr),
        });
    }
    if line.contains("Failed ") {
        let (username, source_addr) = parse_user_and_source(line, "Failed ")?;
        return Some(UserLogonEvent {
            username,
            logon_type: "ssh_failure".to_string(),
            source_addr: Some(source_addr),
        });
    }
    None
}

fn parse_user_and_source(line: &str, status_prefix: &str) -> Option<(String, String)> {
    let after_status = line.split_once(status_prefix)?.1;
    let after_for = after_status.split_once(" for ")?.1;
    let (user_part, source_part) = after_for.split_once(" from ")?;
    let user = user_part.strip_prefix("invalid user ").unwrap_or(user_part).trim().to_string();
    let source = source_part.split_whitespace().next()?.to_string();
    if user.is_empty() || source.is_empty() {
        return None;
    }
    Some((user, source))
}
