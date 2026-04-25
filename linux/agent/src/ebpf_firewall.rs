//! eBPF TC-based network firewall.
//!
//! `EbpfFirewall` implements `NetworkFirewall` using two TC classifier programs
//! (`tc_ingress` / `tc_egress`) loaded into the kernel eBPF probe.  It manages
//! the `FW_MODE` and `FW_RULES` BPF maps, enumerates all non-loopback network
//! interfaces at startup, and monitors for hotplug events via an
//! `AF_NETLINK / RTMGRP_LINK` socket so that containers, VPNs, and
//! dynamically created interfaces are covered immediately upon creation.
//!
//! Sharing the `Ebpf` handle with the sensor thread is done through
//! `Arc<Mutex<Ebpf>>`.  The sensor's blocking thread takes ring-buffer maps
//! at startup (consuming them from the shared object); the watcher later calls
//! `prog.attach()` for newly discovered interfaces.

use std::collections::HashSet;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::tc::{self, SchedClassifier, TcAttachType};
use aya::Ebpf;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use secureexec_ebpf_common::{FwRuleKey, FW_DIR_IN, FW_DIR_OUT, FW_MODE_ISOLATED, FW_MODE_NORMAL};
use secureexec_generic::error::{AgentError, Result};

use crate::firewall::{NetworkFirewall, SeFwRule, SE_FW_DIR_IN, SE_FW_DIR_OUT, SE_FW_PROTO_UDP};

/// Maximum number of rules the FW_RULES BPF map can hold. Must match the
/// `HashMap::with_max_entries(64, 0)` declaration on the eBPF side.
const FW_RULES_CAP: usize = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SharedEbpf    = Arc<Mutex<Ebpf>>;
type FwModeMap     = Arc<Mutex<Array<MapData, u8>>>;
type FwRulesMap    = Arc<Mutex<AyaHashMap<MapData, FwRuleKey, u8>>>;
type AttachedIfaces = Arc<Mutex<HashSet<String>>>;

pub struct EbpfFirewall {
    fw_mode:  FwModeMap,
    fw_rules: FwRulesMap,
    /// Shared Ebpf handle kept alive for prog.attach() on new interfaces.
    ebpf:     SharedEbpf,
    attached_ifaces: AttachedIfaces,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl EbpfFirewall {
    /// Extract firewall maps from the shared `Ebpf` handle, load the TC
    /// programs, and attach them to every non-loopback interface present now.
    ///
    /// The `Ebpf` object must already contain `FW_MODE` and `FW_RULES` maps
    /// and the `tc_ingress` / `tc_egress` programs produced by the eBPF probe.
    pub fn from_shared_ebpf(ebpf: SharedEbpf) -> std::result::Result<Self, String> {
        // Extract the firewall maps while holding the lock.
        let (fw_mode, fw_rules) = {
            let mut guard = ebpf.lock().map_err(|_| "ebpf mutex poisoned")?;

            let fw_mode_raw = guard
                .take_map("FW_MODE")
                .ok_or("FW_MODE map not found in eBPF object")?;
            let fw_rules_raw = guard
                .take_map("FW_RULES")
                .ok_or("FW_RULES map not found in eBPF object")?;

            let fw_mode: Array<MapData, u8> = Array::try_from(fw_mode_raw)
                .map_err(|e| format!("FW_MODE cast: {e}"))?;
            let fw_rules: AyaHashMap<MapData, FwRuleKey, u8> =
                AyaHashMap::try_from(fw_rules_raw)
                    .map_err(|e| format!("FW_RULES cast: {e}"))?;

            // Load tc_ingress and tc_egress programs.
            {
                let prog: &mut SchedClassifier = guard
                    .program_mut("tc_ingress")
                    .ok_or("tc_ingress not found")?
                    .try_into()
                    .map_err(|e| format!("tc_ingress: {e}"))?;
                prog.load().map_err(|e| format!("tc_ingress load: {e}"))?;
            }
            {
                let prog: &mut SchedClassifier = guard
                    .program_mut("tc_egress")
                    .ok_or("tc_egress not found")?
                    .try_into()
                    .map_err(|e| format!("tc_egress: {e}"))?;
                prog.load().map_err(|e| format!("tc_egress load: {e}"))?;
            }

            (fw_mode, fw_rules)
        };

        let fw = EbpfFirewall {
            fw_mode:         Arc::new(Mutex::new(fw_mode)),
            fw_rules:        Arc::new(Mutex::new(fw_rules)),
            ebpf,
            attached_ifaces: Arc::new(Mutex::new(HashSet::new())),
        };

        // Attach to all currently-present non-loopback interfaces.
        for iface in list_non_loopback_ifaces() {
            fw.attach_to_iface(&iface);
        }

        Ok(fw)
    }

    /// Spawn a background tokio task that watches for new network interfaces
    /// via `RTM_NEWLINK` netlink messages and attaches TC programs to them.
    pub fn start_iface_watcher(&self, mut cancel: watch::Receiver<bool>) {
        let ebpf    = self.ebpf.clone();
        let attached = self.attached_ifaces.clone();

        tokio::spawn(async move {
            let socket = match open_rtmgrp_link_socket() {
                Ok(s) => s,
                Err(e) => {
                    warn!("ebpf-firewall: netlink watcher disabled: {e}");
                    return;
                }
            };
            info!("ebpf-firewall: netlink interface watcher started");

            loop {
                // Each blocking iteration polls the netlink fd with a short
                // timeout and then either reads one message or returns
                // `RecvOutcome::Timeout`. This bounds the lifetime of the
                // blocking task so cancel propagates within ~500 ms.
                // Previously `recv_rtm_link_event` blocked forever, and
                // because dropping a `spawn_blocking` JoinHandle does NOT
                // abort the underlying thread, every shutdown leaked one
                // worker stuck in `recv()` until a netlink message arrived.
                let fd = socket.as_raw_fd();
                let result = tokio::select! {
                    _ = cancel.changed() => {
                        debug!("ebpf-firewall: interface watcher stopping");
                        return;
                    }
                    r = tokio::task::spawn_blocking(move || {
                        recv_rtm_link_event(fd, IFACE_WATCHER_POLL_MS)
                    }) => r
                };

                match result {
                    Ok(RecvOutcome::Event(NetlinkIfaceEvent::Del(ref name))) => {
                        if let Ok(mut set) = attached.lock() {
                            if set.remove(name) {
                                debug!("ebpf-firewall: interface {name} removed, cleared from attached set");
                            }
                        }
                    }
                    Ok(RecvOutcome::Event(NetlinkIfaceEvent::New(ref name))) => {
                        if name == "lo" {
                            continue;
                        }
                        let already = attached
                            .lock()
                            .ok()
                            .map(|s| s.contains(name))
                            .unwrap_or(true);
                        if !already {
                            if let Ok(mut guard) = ebpf.lock() {
                                attach_tc_via_ebpf(&mut guard, name, &attached);
                            }
                        }
                    }
                    // Timeout / non-link message / decode failure: just loop;
                    // the next iteration's `select!` checks cancel.
                    _ => {}
                }
            }
        });
    }

    fn attach_to_iface(&self, iface: &str) {
        if let Ok(mut guard) = self.ebpf.lock() {
            attach_tc_via_ebpf(&mut guard, iface, &self.attached_ifaces);
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkFirewall impl
// ---------------------------------------------------------------------------

impl NetworkFirewall for EbpfFirewall {
    fn isolate(&self, extra_rules: &[SeFwRule]) -> Result<()> {
        let mut rules_map = self
            .fw_rules
            .lock()
            .map_err(|_| AgentError::Platform("ebpf fw_rules mutex poisoned".into()))?;

        let default_rules: &[SeFwRule] = &[
            SeFwRule { ip: 0, port: 53, proto: SE_FW_PROTO_UDP, direction: SE_FW_DIR_IN },
            SeFwRule { ip: 0, port: 53, proto: SE_FW_PROTO_UDP, direction: SE_FW_DIR_OUT },
        ];

        // Build the deduped desired rule set up-front so we can pre-validate
        // capacity before mutating any state. The previous implementation
        // cleared the map first and then inserted rules one-by-one — if any
        // insert failed (e.g. overflow past the 64-entry cap, or a
        // re-isolation racing with another writer) the host was left in
        // ISOLATED mode with a *partial* allowlist, which can lock the
        // agent out of its own backend.
        let mut desired: Vec<FwRuleKey> = default_rules
            .iter()
            .chain(extra_rules.iter())
            .map(sefwrule_to_fwrulekey)
            .collect();
        desired.sort_by(fwrulekey_order);
        desired.dedup();

        if desired.len() > FW_RULES_CAP {
            return Err(AgentError::Platform(format!(
                "ebpf: refusing to isolate — rule count {} exceeds cap {}",
                desired.len(),
                FW_RULES_CAP
            )));
        }

        // Snapshot the current ruleset so we can roll back on failure
        // without leaving the host with a partial allowlist.
        let existing: Vec<FwRuleKey> = rules_map
            .keys()
            .filter_map(|r: std::result::Result<FwRuleKey, _>| r.ok())
            .collect();

        if let Err(e) = apply_ruleset(&mut rules_map, &existing, &desired) {
            // Rollback: best-effort restore of the snapshot.
            let current: Vec<FwRuleKey> = rules_map
                .keys()
                .filter_map(|r: std::result::Result<FwRuleKey, _>| r.ok())
                .collect();
            for key in &current {
                let _ = rules_map.remove(key);
            }
            for key in &existing {
                let _ = rules_map.insert(key, &1u8, 0);
            }
            return Err(AgentError::Platform(format!(
                "ebpf: insert rule failed, rolled back: {e}"
            )));
        }

        self.fw_mode
            .lock()
            .map_err(|_| AgentError::Platform("ebpf fw_mode mutex poisoned".into()))?
            .set(0, FW_MODE_ISOLATED, 0)
            .map_err(|e| AgentError::Platform(format!("ebpf: set FW_MODE: {e}")))?;

        info!("firewall(ebpf): host isolated ({} rules)", desired.len());
        Ok(())
    }

    fn release(&self) -> Result<()> {
        self.fw_mode
            .lock()
            .map_err(|_| AgentError::Platform("ebpf fw_mode mutex poisoned".into()))?
            .set(0, FW_MODE_NORMAL, 0)
            .map_err(|e| AgentError::Platform(format!("ebpf: set FW_MODE: {e}")))?;

        let mut rules_map = self
            .fw_rules
            .lock()
            .map_err(|_| AgentError::Platform("ebpf fw_rules mutex poisoned".into()))?;
        let existing: Vec<FwRuleKey> = rules_map
            .keys()
            .filter_map(|r: std::result::Result<FwRuleKey, _>| r.ok())
            .collect();
        for key in existing {
            let _ = rules_map.remove(&key);
        }

        info!("firewall(ebpf): host released from isolation");
        Ok(())
    }

    fn is_isolated(&self) -> bool {
        self.fw_mode
            .lock()
            .ok()
            .and_then(|m| m.get(&0, 0).ok())
            .map(|v| v == FW_MODE_ISOLATED)
            .unwrap_or(false)
    }

    fn backend_name(&self) -> &str {
        "ebpf"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sefwrule_to_fwrulekey(r: &SeFwRule) -> FwRuleKey {
    let direction = match r.direction {
        d if d == SE_FW_DIR_IN  => FW_DIR_IN,
        d if d == SE_FW_DIR_OUT => FW_DIR_OUT,
        _ => 0,
    };
    FwRuleKey { ip: r.ip, port: r.port, proto: r.proto, direction }
}

/// Total ordering on `FwRuleKey` so we can sort+dedup the desired rule set
/// without requiring `Ord` on the upstream type.
fn fwrulekey_order(a: &FwRuleKey, b: &FwRuleKey) -> std::cmp::Ordering {
    (a.ip, a.port, a.proto, a.direction).cmp(&(b.ip, b.port, b.proto, b.direction))
}

/// Apply `desired` to `rules_map` given the current `existing` snapshot.
/// Removes only keys that aren't in the new set first (freeing capacity
/// while keeping `existing ∩ desired` continuously allowed), then upserts
/// any new keys. This avoids the "clear, then partially insert" window
/// where the host is ISOLATED with a partial allowlist.
///
/// FwRuleKey doesn't derive Hash so membership is a linear scan; the cap
/// is 64 and rule sets are small, so O(n²) is negligible.
fn apply_ruleset(
    rules_map: &mut AyaHashMap<MapData, FwRuleKey, u8>,
    existing: &[FwRuleKey],
    desired: &[FwRuleKey],
) -> std::result::Result<(), String> {
    for key in existing {
        if !desired.contains(key) {
            let _ = rules_map.remove(key);
        }
    }
    for key in desired {
        if !existing.contains(key) {
            rules_map
                .insert(key, &1u8, 0)
                .map_err(|e| format!("{e}"))?;
        }
    }
    Ok(())
}

fn attach_tc_via_ebpf(ebpf: &mut Ebpf, iface: &str, attached: &AttachedIfaces) {
    if let Err(e) = tc::qdisc_add_clsact(iface) {
        debug!("ebpf-firewall: qdisc_add_clsact({iface}): {e}");
    }

    let ingress_ok = match ebpf.program_mut("tc_ingress") {
        Some(p) => {
            let prog: &mut SchedClassifier = match p.try_into() {
                Ok(sc) => sc,
                Err(_) => return,
            };
            prog.attach(iface, TcAttachType::Ingress).is_ok()
        }
        None => false,
    };

    let egress_ok = match ebpf.program_mut("tc_egress") {
        Some(p) => {
            let prog: &mut SchedClassifier = match p.try_into() {
                Ok(sc) => sc,
                Err(_) => return,
            };
            prog.attach(iface, TcAttachType::Egress).is_ok()
        }
        None => false,
    };

    if ingress_ok && egress_ok {
        info!("ebpf-firewall: TC attached to {iface}");
        if let Ok(mut set) = attached.lock() {
            set.insert(iface.to_string());
        }
    } else {
        warn!("ebpf-firewall: partial TC attach to {iface} (ingress={ingress_ok} egress={egress_ok})");
    }
}

fn list_non_loopback_ifaces() -> Vec<String> {
    let mut result = Vec::new();
    // Safety: if_nameindex returns a null-terminated array allocated by the C library.
    let ptr = unsafe { libc::if_nameindex() };
    if ptr.is_null() {
        return result;
    }
    let mut cur = ptr;
    loop {
        // Safety: iterating the null-terminated array returned by if_nameindex.
        let entry = unsafe { &*cur };
        if entry.if_index == 0 {
            break;
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr(entry.if_name)
                .to_string_lossy()
                .into_owned()
        };
        if name != "lo" {
            result.push(name);
        }
        cur = unsafe { cur.add(1) };
    }
    // Safety: ptr was obtained from if_nameindex and must be freed with if_freenameindex.
    unsafe { libc::if_freenameindex(ptr) };
    result
}

// ---------------------------------------------------------------------------
// Raw netlink socket for RTM_NEWLINK / RTM_DELLINK
// ---------------------------------------------------------------------------

const RTMGRP_LINK: u32 = 1;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const NLMSG_HDR_LEN: usize = 16; // sizeof(struct nlmsghdr)
const IFINFOMSG_LEN: usize = 16; // sizeof(struct ifinfomsg)

/// `poll()` timeout for each iteration of the netlink watcher. Bounds the
/// time we leak a `spawn_blocking` worker on shutdown to roughly this
/// value, since dropping the JoinHandle does not cancel a blocking task.
const IFACE_WATCHER_POLL_MS: i32 = 500;

#[derive(Debug)]
enum NetlinkIfaceEvent {
    New(String),
    Del(String),
}

/// Outcome of a single watcher poll/recv iteration.
enum RecvOutcome {
    /// One link event was decoded.
    Event(NetlinkIfaceEvent),
    /// A message arrived but it wasn't RTM_NEWLINK / RTM_DELLINK, or the
    /// payload couldn't be decoded.
    NotInteresting,
    /// `poll()` timed out — no data was available.
    Timeout,
    /// Lower-level error (poll/recv failed). Caller should keep looping.
    Error,
}

fn open_rtmgrp_link_socket() -> std::result::Result<std::net::UdpSocket, String> {
    // We use a raw AF_NETLINK socket via libc rather than the netlink-sys crate
    // to avoid pulling in the full dependency for a single use.
    use std::os::unix::io::FromRawFd;

    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE)
    };
    if fd < 0 {
        return Err(format!("socket(AF_NETLINK): errno={}", unsafe { *libc::__errno_location() }));
    }

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = RTMGRP_LINK;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return Err(format!("bind(AF_NETLINK): errno={}", unsafe { *libc::__errno_location() }));
    }

    // Wrap as UdpSocket just to hold the fd; we only use as_raw_fd() on it.
    // Safety: fd is a valid socket fd.
    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
}

/// Poll the netlink fd for up to `timeout_ms` milliseconds and, if data is
/// ready, read one message and return a `NetlinkIfaceEvent` if it's
/// `RTM_NEWLINK` / `RTM_DELLINK`. Always returns within `timeout_ms` plus
/// the time of one nonblocking recv, so a dropped `spawn_blocking`
/// JoinHandle leaks at most that much wall time.
fn recv_rtm_link_event(fd: std::os::unix::io::RawFd, timeout_ms: i32) -> RecvOutcome {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // Safety: pfd is valid; libc::poll signature.
    let pn = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if pn == 0 {
        return RecvOutcome::Timeout;
    }
    if pn < 0 {
        return RecvOutcome::Error;
    }

    let mut buf = [0u8; 4096];
    // Use MSG_DONTWAIT so we never block here even if poll lied about
    // readiness (e.g. spurious wakeup); poll already ensured POLLIN.
    // Safety: buf is valid writable memory; fd is a valid socket fd.
    let n = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    if n < NLMSG_HDR_LEN as isize {
        return RecvOutcome::NotInteresting;
    }
    let n = n as usize;

    // nlmsghdr layout: [u32 len][u16 type][u16 flags][u32 seq][u32 pid]
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    if msg_type != RTM_NEWLINK && msg_type != RTM_DELLINK {
        return RecvOutcome::NotInteresting;
    }

    // After nlmsghdr (16 B) comes ifinfomsg (16 B), then rtattrs.
    let attr_start = NLMSG_HDR_LEN + IFINFOMSG_LEN;
    let mut offset = attr_start;
    while offset + 4 <= n {
        let rta_len  = u16::from_ne_bytes([buf[offset], buf[offset + 1]]) as usize;
        let rta_type = u16::from_ne_bytes([buf[offset + 2], buf[offset + 3]]);
        if rta_len < 4 || offset + rta_len > n {
            break;
        }
        // IFLA_IFNAME = 3
        if rta_type == 3 {
            let data = &buf[offset + 4..offset + rta_len];
            let name = match std::str::from_utf8(data) {
                Ok(s) => s.trim_end_matches('\0').to_string(),
                Err(_) => return RecvOutcome::NotInteresting,
            };
            return if msg_type == RTM_NEWLINK {
                RecvOutcome::Event(NetlinkIfaceEvent::New(name))
            } else {
                RecvOutcome::Event(NetlinkIfaceEvent::Del(name))
            };
        }
        let aligned = (rta_len + 3) & !3;
        offset += aligned.max(4);
    }
    RecvOutcome::NotInteresting
}
