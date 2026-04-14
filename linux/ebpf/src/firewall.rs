use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use secureexec_ebpf_common::*;

// ---------------------------------------------------------------------------
// Maps — shared with userspace EbpfFirewall
// ---------------------------------------------------------------------------

/// FW_MODE[0]: 0 = NORMAL (pass all), 1 = ISOLATED (whitelist-only)
#[map]
static FW_MODE: Array<u8> = Array::with_max_entries(1, 0);

/// FW_RULES: whitelist entries active during isolation.
/// Key: FwRuleKey (ip, port, proto, direction).
/// Value: 1 (present).  Max 64 entries mirrors kmod capacity.
#[map]
static FW_RULES: HashMap<FwRuleKey, u8> = HashMap::with_max_entries(64, 0);

// ---------------------------------------------------------------------------
// TC network firewall classifiers
// ---------------------------------------------------------------------------
//
// Two TC programs (ingress + egress) implement host network isolation.
// Logic mirrors the secureexec_kmod netfilter implementation:
//   - FW_MODE[0] == 0  -> pass all (NORMAL mode)
//   - FW_MODE[0] == 1  -> drop unless whitelisted in FW_RULES
//   - Loopback is always passed (userspace attaches only to non-loopback ifaces)
//   - TCP non-SYN packets are passed (stateless approximation, same as kmod)
//   - IPv6 in ISOLATED mode: drop all

const ETH_HDR_LEN: usize = 14;
const IPV4_PROTO_OFFSET: usize = ETH_HDR_LEN + 9;
const IPV4_SRC_OFFSET:   usize = ETH_HDR_LEN + 12;
const IPV4_DST_OFFSET:   usize = ETH_HDR_LEN + 16;
// Byte 0 of the IP header contains version (high nibble) and IHL (low nibble).
const IPV4_VER_IHL_OFFSET: usize = ETH_HDR_LEN;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

const ETH_P_IP:  u16 = 0x0800_u16.to_be();
const ETH_P_IPV6: u16 = 0x86DD_u16.to_be();
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Shared filtering logic for both ingress and egress.
/// `direction` matches FW_DIR_IN (1) for ingress, FW_DIR_OUT (2) for egress.
#[inline(always)]
fn fw_filter(ctx: &TcContext, direction: u8) -> i32 {
    // Read the current mode (default 0 = NORMAL if map not yet populated).
    let mode = FW_MODE.get(0).copied().unwrap_or(FW_MODE_NORMAL);
    if mode != FW_MODE_ISOLATED {
        return TC_ACT_OK as i32;
    }

    // Read ethertype (bytes 12–13 of ethernet header).
    let ethertype = match ctx.load::<u16>(12) {
        Ok(v) => v,
        Err(_) => return TC_ACT_OK as i32,
    };

    // Drop all IPv6 in isolated mode (same as kmod).
    if ethertype == ETH_P_IPV6 {
        return TC_ACT_SHOT as i32;
    }

    // Pass non-IPv4 (ARP, etc.) — not our concern.
    if ethertype != ETH_P_IP {
        return TC_ACT_OK as i32;
    }

    // From here on we know it's IPv4 in ISOLATED mode.  Any read failure
    // means the packet is malformed — drop it (fail-closed, same as kmod).
    let proto = match ctx.load::<u8>(IPV4_PROTO_OFFSET) {
        Ok(v) => v,
        Err(_) => return TC_ACT_SHOT as i32,
    };

    // Compute actual IP header length from the IHL nibble (×4 bytes).
    let ihl = match ctx.load::<u8>(IPV4_VER_IHL_OFFSET) {
        Ok(v) => ((v & 0x0F) as usize) * 4,
        Err(_) => return TC_ACT_SHOT as i32,
    };
    if ihl < 20 {
        return TC_ACT_SHOT as i32;
    }
    let l4_off = ETH_HDR_LEN + ihl;

    // Stateless TCP: only check pure SYN (syn=1, ack=0) against the whitelist.
    // Everything else (SYN-ACK, ACK, data, FIN, RST) is return/continuation
    // traffic that we pass unconditionally — same as kmod.
    if proto == IPPROTO_TCP {
        match ctx.load::<u8>(l4_off + 13) {
            Ok(flags) => {
                let is_pure_syn = flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_ACK == 0;
                if !is_pure_syn {
                    return TC_ACT_OK as i32;
                }
            }
            Err(_) => return TC_ACT_SHOT as i32,
        }
    }

    let src_ip = match ctx.load::<u32>(IPV4_SRC_OFFSET) {
        Ok(v) => v,
        Err(_) => return TC_ACT_SHOT as i32,
    };
    let dst_ip = match ctx.load::<u32>(IPV4_DST_OFFSET) {
        Ok(v) => v,
        Err(_) => return TC_ACT_SHOT as i32,
    };

    // Extract ports for TCP/UDP; other protocols (ICMP, etc.) use port=0
    // and still go through the whitelist check (same as kmod).
    let (sport, dport) = if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        let s = match ctx.load::<u16>(l4_off) {
            Ok(v) => u16::from_be(v),
            Err(_) => return TC_ACT_SHOT as i32,
        };
        let d = match ctx.load::<u16>(l4_off + 2) {
            Ok(v) => u16::from_be(v),
            Err(_) => return TC_ACT_SHOT as i32,
        };
        (s, d)
    } else {
        (0u16, 0u16)
    };

    // For egress (outbound) the remote IP is dst; for ingress it is src.
    let remote_ip = if direction == FW_DIR_OUT { dst_ip } else { src_ip };
    // TCP: dest port is always the service port for SYN packets (same as kmod).
    // UDP: outbound → dest port ("which service"), inbound → source port
    //      ("which service sent this reply").
    let match_port = if proto == IPPROTO_TCP {
        dport
    } else if direction == FW_DIR_OUT {
        dport
    } else {
        sport
    };

    // Check whitelist: exact match first, then wildcards.
    let candidates = [
        FwRuleKey { ip: remote_ip, port: match_port, proto, direction },
        FwRuleKey { ip: remote_ip, port: 0,          proto, direction },
        FwRuleKey { ip: 0,         port: match_port, proto, direction },
        FwRuleKey { ip: 0,         port: 0,          proto, direction },
        FwRuleKey { ip: remote_ip, port: match_port, proto: 0, direction },
        FwRuleKey { ip: remote_ip, port: 0,          proto: 0, direction },
        FwRuleKey { ip: 0,         port: match_port, proto: 0, direction },
        FwRuleKey { ip: 0,         port: 0,          proto: 0, direction },
        // Also try FW_DIR_ANY direction variants.
        FwRuleKey { ip: remote_ip, port: match_port, proto, direction: FW_DIR_ANY },
        FwRuleKey { ip: remote_ip, port: 0,          proto, direction: FW_DIR_ANY },
        FwRuleKey { ip: 0,         port: match_port, proto, direction: FW_DIR_ANY },
        FwRuleKey { ip: 0,         port: 0,          proto, direction: FW_DIR_ANY },
        FwRuleKey { ip: remote_ip, port: match_port, proto: 0, direction: FW_DIR_ANY },
        FwRuleKey { ip: remote_ip, port: 0,          proto: 0, direction: FW_DIR_ANY },
        FwRuleKey { ip: 0,         port: match_port, proto: 0, direction: FW_DIR_ANY },
        FwRuleKey { ip: 0,         port: 0,          proto: 0, direction: FW_DIR_ANY },
    ];

    for key in &candidates {
        // Safety: read-only BPF hashmap lookup with a valid key reference.
        if unsafe { FW_RULES.get(key) }.is_some() {
            return TC_ACT_OK as i32;
        }
    }

    TC_ACT_SHOT as i32
}

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    fw_filter(&ctx, FW_DIR_IN)
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    fw_filter(&ctx, FW_DIR_OUT)
}
