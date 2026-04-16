use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use secureexec_generic::error::Result;
use chrono::{DateTime, Utc};
use secureexec_generic::event::{Event, EventKind, NetworkEvent, Protocol};
use secureexec_generic::sensor::Sensor;

// The system extension is launched by launchd as root so it will connect
// with euid=0. We only accept connections that match that so a random
// unprivileged process on the host cannot inject fake netflow events.
// NOTE: the socket path is still `/tmp/…` for compatibility with the
// Swift network extension bundle ID; changing it requires an extension
// code update. We mitigate the exposure with chmod(0600) + peer uid check.
const SOCKET_PATH: &str = "/tmp/secureexec-netflow.sock";
const EXPECTED_PEER_UID: u32 = 0;

/// JSON model matching the Swift extension's `FlowEvent`.
#[derive(Debug, Deserialize)]
struct FlowEvent {
    pid: i32,
    process_name: String,
    #[serde(default)]
    process_start_time: f64,
    src_addr: String,
    src_port: u16,
    dst_addr: String,
    dst_port: u16,
    protocol: String,
    #[serde(default)]
    direction: String,
}

fn epoch_to_chrono(secs: f64) -> Option<DateTime<Utc>> {
    if secs <= 0.0 {
        return None;
    }
    DateTime::from_timestamp(secs as i64, ((secs.fract()) * 1_000_000_000.0) as u32)
}

pub struct MacosNetworkSensor;

impl MacosNetworkSensor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sensor for MacosNetworkSensor {
    fn name(&self) -> &str {
        "macos-network"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<Event>,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<()> {
        let hostname = hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        let sock_path = Path::new(SOCKET_PATH);
        if sock_path.exists() {
            let _ = std::fs::remove_file(sock_path);
        }
        let listener = UnixListener::bind(sock_path).map_err(|e| {
            secureexec_generic::error::AgentError::Pipeline(format!(
                "failed to bind {SOCKET_PATH}: {e}"
            ))
        })?;
        // Tighten permissions so only the owner (root) can connect. Without
        // this, `/tmp` being world-writable means any local process could
        // inject fabricated FlowEvent lines into the agent.
        if let Err(e) = std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600)) {
            warn!(error = %e, "macos-network: failed to chmod socket — continuing but untrusted peers may connect");
        }
        info!("macos-network: listening on {SOCKET_PATH}");

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    debug!("macos-network sensor stopping");
                    let _ = std::fs::remove_file(sock_path);
                    return Ok(());
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            // Authenticate the peer before accepting
                            // anything from the socket. Without this a
                            // local non-root process that somehow reaches
                            // the socket could forge netflow events.
                            match peer_uid(&stream) {
                                Ok(uid) if uid == EXPECTED_PEER_UID => {
                                    info!(peer_uid = uid, "macos-network: extension connected");
                                    let tx2 = tx.clone();
                                    let mut cancel2 = cancel.clone();
                                    let host = hostname.clone();
                                    tokio::spawn(async move {
                                        handle_connection(stream, tx2, &mut cancel2, &host).await;
                                    });
                                }
                                Ok(uid) => {
                                    warn!(peer_uid = uid, "macos-network: rejecting peer with wrong uid");
                                    drop(stream);
                                }
                                Err(e) => {
                                    warn!("macos-network: peer uid check failed: {e} — rejecting connection");
                                    drop(stream);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("macos-network: accept error: {e}");
                        }
                    }
                }
            }
        }
    }
}

/// Read the peer's effective uid via `getpeereid(2)` (BSD/macOS).
/// This is the standard authenticated-peer mechanism on Darwin; unlike
/// SCM_CREDENTIALS on Linux, it requires no cooperation from the peer.
fn peer_uid(stream: &tokio::net::UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a valid file descriptor owned by `stream` for the
    // lifetime of this call; the out-pointers are writable u32s on stack.
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    tx: mpsc::Sender<Event>,
    cancel: &mut watch::Receiver<bool>,
    hostname: &str,
) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    loop {
        tokio::select! {
            _ = cancel.changed() => return,
            line = lines.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        match serde_json::from_str::<FlowEvent>(&text) {
                            Ok(flow) => {
                                let proto = match flow.protocol.as_str() {
                                    "tcp" => Protocol::Tcp,
                                    _ => Protocol::Udp,
                                };
                                let pst = epoch_to_chrono(flow.process_start_time);
                                let net = NetworkEvent {
                                    pid: flow.pid.max(0) as u32,
                                    process_name: flow.process_name,
                                    process_guid: String::new(),
                                    process_start_time: pst,
                                    src_addr: flow.src_addr,
                                    src_port: flow.src_port,
                                    dst_addr: flow.dst_addr,
                                    dst_port: flow.dst_port,
                                    protocol: proto,
                                    user_id: String::new(),
                                };
                                let kind = if flow.direction == "inbound" {
                                    EventKind::NetworkListen(net)
                                } else {
                                    EventKind::NetworkConnect(net)
                                };
                                let event = Event::new(hostname.to_string(), kind);
                                if tx.send(event).await.is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                warn!("macos-network: bad JSON line: {e}");
                            }
                        }
                    }
                    Ok(None) => {
                        info!("macos-network: extension disconnected");
                        return;
                    }
                    Err(e) => {
                        error!("macos-network: read error: {e}");
                        return;
                    }
                }
            }
        }
    }
}
