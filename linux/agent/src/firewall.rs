//! Firewall abstraction and kmod-based firewall controller.
//!
//! `NetworkFirewall` is the common trait implemented by both the eBPF TC
//! firewall (`EbpfFirewall`) and the kernel-module-based firewall (`KmodFirewall`).
//!
//! `KmodFirewall` drives the netfilter isolation state via ioctls on a
//! `KmodHandle` provided by the `kmod` module.

use std::net::IpAddr;

use nix::errno::Errno;
use tracing::info;

use secureexec_generic::error::{AgentError, Result};

use crate::kmod::{KmodHandle, SE_KMOD_MAGIC};

// ---------------------------------------------------------------------------
// ioctl constants — must mirror firewall.h exactly
// ---------------------------------------------------------------------------

// _IOW(magic, nr, type) encodes as: dir=1 (write), size=sizeof(type)
// Macro expansion (Linux convention):
//   ((dir << 30) | (type << 8) | nr | (size << 16))
// We compute them by hand to avoid a build-time C dependency.

#[repr(C)]
#[derive(Default)]
struct SeFwMode {
    mode: u8,
    _pad: [u8; 7],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct SeFwRule {
    /// IPv4 address in network byte order (0 = any)
    pub ip: u32,
    /// Port in host byte order (0 = any)
    pub port: u16,
    /// Protocol: 6=TCP, 17=UDP, 0=any
    pub proto: u8,
    /// Direction: 1=in, 2=out, 0=any
    pub direction: u8,
}

#[repr(C)]
#[derive(Default)]
struct SeFwStatus {
    mode: u8,
    _pad: [u8; 3],
    rule_count: u32,
}

pub const SE_FW_MODE_NORMAL: u8 = 0;
pub const SE_FW_MODE_ISOLATED: u8 = 1;

pub const SE_FW_PROTO_TCP: u8 = 6;
pub const SE_FW_PROTO_UDP: u8 = 17;
pub const SE_FW_PROTO_ANY: u8 = 0;

pub const SE_FW_DIR_IN: u8 = 1;
pub const SE_FW_DIR_OUT: u8 = 2;
pub const SE_FW_DIR_ANY: u8 = 0;

/// Maximum rules the kmod can hold per its `SE_FW_MAX_RULES` constant in
/// `agent/linux/kmod/firewall.h`. Used to pre-validate rule count before
/// mutating kmod state.
pub const SE_FW_MAX_RULES: usize = 64;

// ioctl numbers (matching Linux _IOW/_IOR/_IO macros):
//   dir:  write=1, read=2
//   bits: [31:30]=dir [29:16]=size [15:8]=type [7:0]=nr
nix::ioctl_write_ptr_bad!(se_fw_set_mode, nix::request_code_write!(SE_KMOD_MAGIC, 1, std::mem::size_of::<SeFwMode>()), SeFwMode);
nix::ioctl_write_ptr_bad!(se_fw_add_rule, nix::request_code_write!(SE_KMOD_MAGIC, 2, std::mem::size_of::<SeFwRule>()), SeFwRule);
nix::ioctl_write_ptr_bad!(se_fw_del_rule, nix::request_code_write!(SE_KMOD_MAGIC, 3, std::mem::size_of::<SeFwRule>()), SeFwRule);
nix::ioctl_read_bad!(se_fw_get_status, nix::request_code_read!(SE_KMOD_MAGIC, 4, std::mem::size_of::<SeFwStatus>()), SeFwStatus);
nix::ioctl_none_bad!(se_fw_clear_rules, nix::request_code_none!(SE_KMOD_MAGIC, 5));

// ---------------------------------------------------------------------------
// NetworkFirewall trait
// ---------------------------------------------------------------------------

/// Common interface for all network isolation backends.
pub trait NetworkFirewall: Send + Sync {
    /// Apply network isolation.  `extra_rules` are whitelisted in addition to
    /// the default safe rules (DNS, loopback).
    fn isolate(&self, extra_rules: &[SeFwRule]) -> Result<()>;
    /// Release network isolation and clear all rules.
    fn release(&self) -> Result<()>;
    /// Returns true if the host is currently isolated.
    fn is_isolated(&self) -> bool;
    /// Short backend identifier: `"kmod"` or `"ebpf"`.
    fn backend_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// KmodFirewall  (was: FirewallController)
// ---------------------------------------------------------------------------

/// Kmod-based firewall backend.  Drives the secureexec_kmod netfilter
/// isolation via ioctls on a shared `KmodHandle`.
#[derive(Debug, Clone)]
pub struct KmodFirewall {
    handle: KmodHandle,
}

/// Type alias kept for call-sites that have not been migrated yet.
#[allow(dead_code)]
pub type FirewallController = KmodFirewall;

impl KmodFirewall {
    /// Create a firewall controller from an already-opened kmod handle.
    pub fn new(handle: KmodHandle) -> Self {
        Self { handle }
    }

    /// Convenience: open the kmod and create a firewall in one step.
    /// Returns `None` and logs a warning if the kmod is unavailable.
    pub fn try_open() -> Option<Self> {
        KmodHandle::try_open().map(Self::new)
    }

    // -----------------------------------------------------------------------
    // Helper rule builders (also exposed as free functions for convenience)
    // -----------------------------------------------------------------------

    /// Build an outbound whitelist rule for a given IP address.
    ///
    /// The kmod/eBPF datapath compares against the IP header's `__be32`
    /// fields loaded as a raw host `u32` — i.e. the integer whose
    /// in-memory byte layout matches the wire (network byte order). On a
    /// little-endian host that is `from_ne_bytes(octets)`; `from_be_bytes`
    /// would byte-swap and produce a value that never matches real
    /// packets. `Ipv4Addr::octets()` already returns bytes in most-
    /// significant-first (network) order, so this preserves them as-is.
    pub fn rule_allow_ip_out(ip: IpAddr) -> Option<SeFwRule> {
        match ip {
            IpAddr::V4(v4) => {
                let ip_be = u32::from_ne_bytes(v4.octets());
                Some(SeFwRule {
                    ip: ip_be,
                    port: 0,
                    proto: SE_FW_PROTO_ANY,
                    direction: SE_FW_DIR_OUT,
                })
            }
            IpAddr::V6(_) => None,
        }
    }

    /// Build an inbound whitelist rule for a given IP address. See
    /// `rule_allow_ip_out` for the byte-order rationale.
    pub fn rule_allow_ip_in(ip: IpAddr) -> Option<SeFwRule> {
        match ip {
            IpAddr::V4(v4) => {
                let ip_be = u32::from_ne_bytes(v4.octets());
                Some(SeFwRule {
                    ip: ip_be,
                    port: 0,
                    proto: SE_FW_PROTO_ANY,
                    direction: SE_FW_DIR_IN,
                })
            }
            IpAddr::V6(_) => None,
        }
    }
}

impl NetworkFirewall for KmodFirewall {
    fn isolate(&self, extra_rules: &[SeFwRule]) -> Result<()> {
        let guard = self.handle.raw_fd()?;
        let raw = guard.as_raw_fd();

        let default_rules: &[SeFwRule] = &[
            SeFwRule { ip: 0, port: 53, proto: SE_FW_PROTO_UDP, direction: SE_FW_DIR_OUT },
            SeFwRule { ip: 0, port: 53, proto: SE_FW_PROTO_UDP, direction: SE_FW_DIR_IN },
        ];

        // Pre-validate rule count before mutating kmod state. The kmod's
        // `add_rule` ioctl rejects inserts past SE_FW_MAX_RULES; previously
        // we would clear all rules first and then fail mid-insert, leaving
        // the host with a partial allowlist while still in ISOLATED mode.
        let total = default_rules.len() + extra_rules.len();
        if total > SE_FW_MAX_RULES {
            return Err(AgentError::Platform(format!(
                "kmod: refusing to isolate — rule count {} exceeds cap {}",
                total, SE_FW_MAX_RULES
            )));
        }

        // Safety: raw fd is valid; ioctl syscall with correct nr and no data pointer.
        unsafe { se_fw_clear_rules(raw) }.map_err(|e| ioctl_err("clear_rules", e))?;

        for rule in default_rules.iter().chain(extra_rules.iter()) {
            // Safety: raw fd is valid; rule is a properly sized repr(C) struct.
            if let Err(e) = unsafe { se_fw_add_rule(raw, rule) } {
                // Roll back: the kmod has no enumerate ioctl, so we can't
                // restore the previous ruleset. Leaving a partial allowlist
                // active in ISOLATED mode would silently lock the agent
                // out of its backend; safer to fail open by clearing rules
                // and dropping back to NORMAL than to ship a half-applied
                // policy.
                let _ = unsafe { se_fw_clear_rules(raw) };
                let normal = SeFwMode { mode: SE_FW_MODE_NORMAL, _pad: [0; 7] };
                let _ = unsafe { se_fw_set_mode(raw, &normal) };
                return Err(ioctl_err("add_rule (rolled back to NORMAL)", e));
            }
        }

        let mode = SeFwMode { mode: SE_FW_MODE_ISOLATED, _pad: [0; 7] };
        // Safety: raw fd is valid; mode is a properly sized repr(C) struct.
        unsafe { se_fw_set_mode(raw, &mode) }.map_err(|e| ioctl_err("set_mode", e))?;

        info!("firewall(kmod): host isolated ({} rules)", total);
        Ok(())
    }

    fn release(&self) -> Result<()> {
        let guard = self.handle.raw_fd()?;
        let raw = guard.as_raw_fd();

        let mode = SeFwMode { mode: SE_FW_MODE_NORMAL, _pad: [0; 7] };
        // Safety: raw fd is valid; mode is properly sized repr(C) struct.
        unsafe { se_fw_set_mode(raw, &mode) }.map_err(|e| ioctl_err("set_mode", e))?;
        // Safety: raw fd is valid; no user data pointer needed.
        unsafe { se_fw_clear_rules(raw) }.map_err(|e| ioctl_err("clear_rules", e))?;

        info!("firewall(kmod): host released from isolation");
        Ok(())
    }

    fn is_isolated(&self) -> bool {
        let guard = match self.handle.raw_fd() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let raw = guard.as_raw_fd();
        let mut status = SeFwStatus::default();
        // Safety: raw fd is valid; status is a properly sized repr(C) struct.
        match unsafe { se_fw_get_status(raw, &mut status) } {
            Ok(_) => status.mode == SE_FW_MODE_ISOLATED,
            Err(_) => false,
        }
    }

    fn backend_name(&self) -> &str {
        "kmod"
    }
}

fn ioctl_err(name: &str, e: Errno) -> AgentError {
    AgentError::Platform(format!("secureexec_kmod: ioctl {name} failed: {e}"))
}
