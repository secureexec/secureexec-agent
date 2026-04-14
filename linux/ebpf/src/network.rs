use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_user, bpf_probe_read_user_buf,
    },
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use secureexec_ebpf_common::*;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

#[map]
static NETWORK_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Per-CPU counter: incremented when NETWORK_EVENTS.reserve() fails (ring full).
#[map]
static NET_DROP_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn bump_net_drop() {
    // Safety: index 0 is always valid (max_entries=1); per-CPU so no races.
    if let Some(ptr) = NET_DROP_COUNT.get_ptr_mut(0) {
        unsafe { *ptr += 1; }
    }
}

#[map]
static SOCK_STORE: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[map]
static UDP_SRC_CACHE: HashMap<u32, UdpSrcCache> = HashMap::with_max_entries(8192, 0);

#[map]
static DNS_BUF_CACHE: HashMap<u32, DnsBufInfo> = HashMap::with_max_entries(4096, 0);

// ---------------------------------------------------------------------------
// Local types used only by network handlers
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct UdpSrcCache {
    family: u16,
    sport: u16,
    dport: u16,
    _pad: u16,
    saddr: u32,
    daddr: u32,
    saddr6: [u8; 16],
    daddr6: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DnsBufInfo {
    buf_ptr: u64,
    len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    _sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserIovec {
    iov_base: u64,
    iov_len: u64,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Address family constants (same as Linux AF_* values).
const AF_INET:  u16 =  2;
const AF_INET6: u16 = 10;

/// sock_common IPv6 field offsets (64-bit, CONFIG_NET_NS=y).
/// Layout: ...skc_bind_node(24)...skc_prot(40)...skc_net(48)...skc_v6_daddr(56)...skc_v6_rcv_saddr(72).
const SKC_V6_DADDR_OFF: usize = 56;
const SKC_V6_SADDR_OFF: usize = 72;

// ---------------------------------------------------------------------------
// Network: tcp_v4_connect (kprobe entry — save sock pointer)
// ---------------------------------------------------------------------------

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_v4_connect_entry(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_v4_connect_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let sock: u64 = ctx.arg(0).ok_or(1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = SOCK_STORE.insert(&pid_tgid, &sock, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Network: tcp_v4_connect (kretprobe — read connection details)
// ---------------------------------------------------------------------------

#[kretprobe]
pub fn tcp_v4_connect_ret(ctx: RetProbeContext) -> u32 {
    match try_tcp_v4_connect_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_v4_connect_ret(ctx: &RetProbeContext) -> Result<(), i64> {
    let retval: i32 = ctx.ret().unwrap_or(-1);
    let pid_tgid = bpf_get_current_pid_tgid();

    let sock_ptr = match unsafe { SOCK_STORE.get(&pid_tgid) } {
        Some(s) => *s,
        None => return Ok(()),
    };
    let _ = SOCK_STORE.remove(&pid_tgid);

    if retval != 0 {
        return Ok(());
    }

    read_sock_v4_and_emit(sock_ptr, NET_EVT_V4_CONNECT, NET_PROTO_TCP)
}

// ---------------------------------------------------------------------------
// Network: inet_csk_accept (kretprobe — accepted connection)
// ---------------------------------------------------------------------------

#[kretprobe]
pub fn inet_csk_accept_ret(ctx: RetProbeContext) -> u32 {
    match try_inet_csk_accept_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_inet_csk_accept_ret(ctx: &RetProbeContext) -> Result<(), i64> {
    let sock_ptr: u64 = ctx.ret().unwrap_or(0);
    if sock_ptr == 0 {
        return Ok(());
    }
    // Read skc_family to dispatch to the correct v4/v6 emit path.
    // Offset 16 matches the sock_common layout assumed by the rest of this file
    // (daddr@0, rcv_saddr@4, hash@8, portpair@12, family@16).
    let family: u16 = unsafe {
        bpf_probe_read_kernel((sock_ptr + 16) as *const u16).unwrap_or(AF_INET)
    };
    if family == AF_INET6 {
        read_sock_v6_and_emit(sock_ptr, NET_EVT_V6_ACCEPT, NET_PROTO_TCP)
    } else {
        read_sock_v4_and_emit(sock_ptr, NET_EVT_V4_ACCEPT, NET_PROTO_TCP)
    }
}

// ---------------------------------------------------------------------------
// Network: sendto / sendmsg / sendmmsg — DNS capture (outgoing UDP to port 53)
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_sendto")]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    match try_sys_enter_sendto(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_sendto(ctx: &TracePointContext) -> Result<(), i64> {
    // sendto(fd@16, buff@24, len@32, flags@40, addr@48, addr_len@56)
    // Safety: reading fixed offsets from tracepoint context; defaults used on failure.
    let buf_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    // Safety: reading fixed offsets from tracepoint context; defaults used on failure.
    let len: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };
    // Safety: reading fixed offsets from tracepoint context; defaults used on failure.
    let addr_ptr: u64 = unsafe { ctx.read_at(48).unwrap_or(0) };
    if buf_ptr == 0 || len < 12 {
        return Ok(());
    }

    if addr_ptr == 0 {
        // Connected socket (connect+send pattern); save buffer for kprobe.
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let _ = DNS_BUF_CACHE.insert(&tgid, &DnsBufInfo { buf_ptr, len }, 0);
        return Ok(());
    }

    // Safety: userspace sockaddr pointer comes from syscall argument and can be invalid.
    let family: u16 = unsafe { bpf_probe_read_user(addr_ptr as *const u16).unwrap_or(0) };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let dns_len = if (len as usize) >= MAX_DNS_PAYLOAD {
        (MAX_DNS_PAYLOAD - 1) as u16
    } else {
        len as u16
    };

    if family == AF_INET {
        // Safety: bounded copy of userspace sockaddr_in from syscall argument pointer.
        let sa: SockAddrIn = unsafe { bpf_probe_read_user(addr_ptr as *const SockAddrIn).unwrap_or(SockAddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            _sin_zero: [0; 8],
        }) };
        let dport = u16::from_be(sa.sin_port);
        if dport != 53 {
            return Ok(());
        }
        if let Some(mut buf) = NETWORK_EVENTS.reserve::<DnsQueryEventData>(0) {
            // Safety: ringbuf reservation guarantees writable event memory until submit/discard.
            let e = unsafe { &mut *buf.as_mut_ptr() };
            e.event_tag = NET_EVT_DNS_QUERY_V4;
            e.protocol = NET_PROTO_UDP;
            e._pad = [0; 2];
            e.pid = pid;
            e.tgid = tgid;
            e.uid = uid;
            e.saddr = 0;
            e.daddr = sa.sin_addr;
            e.sport = 0;
            e.dport = dport;
            e.dns_len = dns_len;
            e._pad2 = 0;
            e.comm = comm;
            e.payload = [0; MAX_DNS_PAYLOAD];
            // Safety: aya HashMap::get requires unsafe; no concurrent mutation from userspace.
            if let Some(cached) = unsafe { UDP_SRC_CACHE.get(&tgid) } {
                if cached.family == AF_INET && cached.dport == dport && cached.daddr == sa.sin_addr {
                    e.saddr = cached.saddr;
                    e.sport = cached.sport;
                }
            }
            // Re-read dns_len from ringbuf after map lookup; mask with 0xFF
            // so the BPF verifier sees a direct AND instruction bounding 0..255.
            let dn = (e.dns_len as usize) & 0xFF;
            if dn > 0 {
                // Safety: dn is bounded to 1..255 by & 0xFF mask; payload is MAX_DNS_PAYLOAD bytes.
                unsafe { let _ = bpf_probe_read_user_buf(buf_ptr as *const u8, &mut e.payload[..dn]); }
            }
            buf.submit(0);
        } else {
            bump_net_drop();
        }
    } else if family == AF_INET6 {
        // Safety: bounded copy of userspace sockaddr_in6 from syscall argument pointer.
        let sa: SockAddrIn6 = unsafe { bpf_probe_read_user(addr_ptr as *const SockAddrIn6).unwrap_or(SockAddrIn6 {
            sin6_family: 0,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: [0; 16],
            sin6_scope_id: 0,
        }) };
        let dport = u16::from_be(sa.sin6_port);
        if dport != 53 {
            return Ok(());
        }
        if let Some(mut buf) = NETWORK_EVENTS.reserve::<DnsQueryEvent6Data>(0) {
            // Safety: ringbuf reservation guarantees writable event memory until submit/discard.
            let e = unsafe { &mut *buf.as_mut_ptr() };
            e.event_tag = NET_EVT_DNS_QUERY_V6;
            e.protocol = NET_PROTO_UDP;
            e._pad = [0; 2];
            e.pid = pid;
            e.tgid = tgid;
            e.uid = uid;
            e.saddr6 = [0; 16];
            e.daddr6 = sa.sin6_addr;
            e.sport = 0;
            e.dport = dport;
            e.dns_len = dns_len;
            e._pad2 = 0;
            e.comm = comm;
            e.payload = [0; MAX_DNS_PAYLOAD];
            // Safety: aya HashMap::get requires unsafe; no concurrent mutation from userspace.
            if let Some(cached) = unsafe { UDP_SRC_CACHE.get(&tgid) } {
                if cached.family == AF_INET6 && cached.dport == dport && v6_eq(&cached.daddr6, &sa.sin6_addr) {
                    e.saddr6 = cached.saddr6;
                    e.sport = cached.sport;
                }
            }
            let dn = (e.dns_len as usize) & 0xFF;
            if dn > 0 {
                // Safety: dn is bounded to 1..255 by & 0xFF mask; payload is MAX_DNS_PAYLOAD bytes.
                unsafe { let _ = bpf_probe_read_user_buf(buf_ptr as *const u8, &mut e.payload[..dn]); }
            }
            buf.submit(0);
        } else {
            bump_net_drop();
        }
    }

    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_sendmsg")]
pub fn sys_enter_sendmsg(ctx: TracePointContext) -> u32 {
    match try_sys_enter_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_sendmsg(ctx: &TracePointContext) -> Result<(), i64> {
    // sendmsg(fd@16, msg@24, flags@32)
    // Safety: reading fixed offsets from tracepoint context; defaults used on failure.
    let msg_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    if msg_ptr == 0 {
        return Ok(());
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    emit_dns_from_user_msghdr(msg_ptr, tgid)
}

#[tracepoint(category = "syscalls", name = "sys_enter_sendmmsg")]
pub fn sys_enter_sendmmsg(ctx: TracePointContext) -> u32 {
    match try_sys_enter_sendmmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_sendmmsg(ctx: &TracePointContext) -> Result<(), i64> {
    // sendmmsg(fd@16, mmsg@24, vlen@32, flags@40)
    // Safety: reading fixed offsets from tracepoint context; defaults used on failure.
    let mmsg_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    // Safety: reading fixed offsets from tracepoint context; defaults used on failure.
    let vlen: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };
    if mmsg_ptr == 0 || vlen == 0 {
        return Ok(());
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    // struct mmsghdr is 64 bytes on 64-bit (msghdr=56 + msg_len=4 + 4 padding)
    const MMSGHDR_SIZE: u64 = 64;
    let count = if vlen > 4 { 4 } else { vlen };
    let mut i: u64 = 0;
    while i < count {
        let _ = emit_dns_from_user_msghdr(mmsg_ptr + i * MMSGHDR_SIZE, tgid);
        i += 1;
    }
    Ok(())
}

fn emit_dns_from_user_msghdr(msg_ptr: u64, tgid: u32) -> Result<(), i64> {
    // userspace msghdr (64-bit): msg_name@0, msg_namelen@8, msg_iov@16, msg_iovlen@24
    // Safety: user pointer from syscall arg can be invalid.
    let msg_name_ptr: u64 = unsafe { bpf_probe_read_user(msg_ptr as *const u64).unwrap_or(0) };
    // Safety: user pointer from syscall arg can be invalid.
    let msg_iov_ptr: u64 = unsafe { bpf_probe_read_user((msg_ptr + 16) as *const u64).unwrap_or(0) };
    // Safety: user pointer from syscall arg can be invalid.
    let msg_iovlen: u64 = unsafe { bpf_probe_read_user((msg_ptr + 24) as *const u64).unwrap_or(0) };
    if msg_iov_ptr == 0 || msg_iovlen == 0 {
        return Ok(());
    }

    // Safety: bounded read of first userspace iovec descriptor.
    let iov: UserIovec = unsafe { bpf_probe_read_user(msg_iov_ptr as *const UserIovec).unwrap_or(UserIovec { iov_base: 0, iov_len: 0 }) };
    if iov.iov_base == 0 || iov.iov_len < 12 {
        return Ok(());
    }

    if msg_name_ptr == 0 {
        // Connected socket (connect+sendmsg pattern); save buffer for kprobe.
        let _ = DNS_BUF_CACHE.insert(&tgid, &DnsBufInfo { buf_ptr: iov.iov_base, len: iov.iov_len }, 0);
        return Ok(());
    }
    let dns_len = if (iov.iov_len as usize) >= MAX_DNS_PAYLOAD {
        (MAX_DNS_PAYLOAD - 1) as u16
    } else {
        iov.iov_len as u16
    };

    // Safety: userspace sockaddr pointer from msghdr may be invalid.
    let family: u16 = unsafe { bpf_probe_read_user(msg_name_ptr as *const u16).unwrap_or(0) };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    if family == AF_INET {
        // Safety: bounded copy of userspace sockaddr_in from msghdr.
        let sa: SockAddrIn = unsafe { bpf_probe_read_user(msg_name_ptr as *const SockAddrIn).unwrap_or(SockAddrIn {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            _sin_zero: [0; 8],
        }) };
        let dport = u16::from_be(sa.sin_port);
        if dport != 53 {
            return Ok(());
        }
        if let Some(mut buf) = NETWORK_EVENTS.reserve::<DnsQueryEventData>(0) {
            // Safety: ringbuf reservation guarantees writable event memory until submit/discard.
            let e = unsafe { &mut *buf.as_mut_ptr() };
            e.event_tag = NET_EVT_DNS_QUERY_V4;
            e.protocol = NET_PROTO_UDP;
            e._pad = [0; 2];
            e.pid = pid;
            e.tgid = tgid;
            e.uid = uid;
            e.saddr = 0;
            e.daddr = sa.sin_addr;
            e.sport = 0;
            e.dport = dport;
            e.dns_len = dns_len;
            e._pad2 = 0;
            e.comm = comm;
            e.payload = [0; MAX_DNS_PAYLOAD];
            // Safety: aya HashMap::get requires unsafe; no concurrent mutation from userspace.
            if let Some(cached) = unsafe { UDP_SRC_CACHE.get(&tgid) } {
                if cached.family == AF_INET && cached.dport == dport && cached.daddr == sa.sin_addr {
                    e.saddr = cached.saddr;
                    e.sport = cached.sport;
                }
            }
            let dn = (e.dns_len as usize) & 0xFF;
            if dn > 0 {
                // Safety: dn is bounded to 1..255 by & 0xFF mask; payload is MAX_DNS_PAYLOAD bytes.
                unsafe { let _ = bpf_probe_read_user_buf(iov.iov_base as *const u8, &mut e.payload[..dn]); }
            }
            buf.submit(0);
        } else {
            bump_net_drop();
        }
    } else if family == AF_INET6 {
        // Safety: bounded copy of userspace sockaddr_in6 from msghdr.
        let sa: SockAddrIn6 = unsafe { bpf_probe_read_user(msg_name_ptr as *const SockAddrIn6).unwrap_or(SockAddrIn6 {
            sin6_family: 0,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: [0; 16],
            sin6_scope_id: 0,
        }) };
        let dport = u16::from_be(sa.sin6_port);
        if dport != 53 {
            return Ok(());
        }
        if let Some(mut buf) = NETWORK_EVENTS.reserve::<DnsQueryEvent6Data>(0) {
            // Safety: ringbuf reservation guarantees writable event memory until submit/discard.
            let e = unsafe { &mut *buf.as_mut_ptr() };
            e.event_tag = NET_EVT_DNS_QUERY_V6;
            e.protocol = NET_PROTO_UDP;
            e._pad = [0; 2];
            e.pid = pid;
            e.tgid = tgid;
            e.uid = uid;
            e.saddr6 = [0; 16];
            e.daddr6 = sa.sin6_addr;
            e.sport = 0;
            e.dport = dport;
            e.dns_len = dns_len;
            e._pad2 = 0;
            e.comm = comm;
            e.payload = [0; MAX_DNS_PAYLOAD];
            // Safety: aya HashMap::get requires unsafe; no concurrent mutation from userspace.
            if let Some(cached) = unsafe { UDP_SRC_CACHE.get(&tgid) } {
                if cached.family == AF_INET6 && cached.dport == dport && v6_eq(&cached.daddr6, &sa.sin6_addr) {
                    e.saddr6 = cached.saddr6;
                    e.sport = cached.sport;
                }
            }
            let dn = (e.dns_len as usize) & 0xFF;
            if dn > 0 {
                // Safety: dn is bounded to 1..255 by & 0xFF mask; payload is MAX_DNS_PAYLOAD bytes.
                unsafe { let _ = bpf_probe_read_user_buf(iov.iov_base as *const u8, &mut e.payload[..dn]); }
            }
            buf.submit(0);
        } else {
            bump_net_drop();
        }
    }
    Ok(())
}

fn emit_dns_from_sock(sock_ptr: u64, buf_ptr: u64, buf_len: u64) -> Result<(), i64> {
    let sk = sock_ptr as *const u8;
    // Safety: reading kernel sock_common fields at fixed offsets.
    let family: u16 = unsafe { bpf_probe_read_kernel(sk.add(16) as *const u16)? };
    let dport_be: u16 = unsafe { bpf_probe_read_kernel(sk.add(12) as *const u16)? };
    let dport = u16::from_be(dport_be);

    if dport != 53 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let dns_len = if (buf_len as usize) >= MAX_DNS_PAYLOAD {
        (MAX_DNS_PAYLOAD - 1) as u16
    } else {
        buf_len as u16
    };

    if family == AF_INET {
        // Safety: reading kernel sock_common IPv4 fields.
        let daddr: u32 = unsafe { bpf_probe_read_kernel(sk.add(0) as *const u32)? };
        let saddr: u32 = unsafe { bpf_probe_read_kernel(sk.add(4) as *const u32)? };
        let sport: u16 = unsafe { bpf_probe_read_kernel(sk.add(14) as *const u16)? };

        if let Some(mut buf) = NETWORK_EVENTS.reserve::<DnsQueryEventData>(0) {
            let e = unsafe { &mut *buf.as_mut_ptr() };
            e.event_tag = NET_EVT_DNS_QUERY_V4;
            e.protocol = NET_PROTO_UDP;
            e._pad = [0; 2];
            e.pid = pid;
            e.tgid = tgid;
            e.uid = uid;
            e.saddr = saddr;
            e.daddr = daddr;
            e.sport = sport;
            e.dport = dport;
            e.dns_len = dns_len;
            e._pad2 = 0;
            e.comm = comm;
            e.payload = [0; MAX_DNS_PAYLOAD];
            let dn = (e.dns_len as usize) & 0xFF;
            if dn > 0 {
                // Safety: dn bounded to 1..255; reading user buffer saved from sendto/sendmsg.
                unsafe { let _ = bpf_probe_read_user_buf(buf_ptr as *const u8, &mut e.payload[..dn]); }
            }
            buf.submit(0);
        } else {
            bump_net_drop();
        }
    } else if family == AF_INET6 {
        // Safety: reading kernel sock_common IPv6 fields at SKC_V6_*_OFF.
        let mut daddr6 = [0u8; 16];
        let mut saddr6 = [0u8; 16];
        unsafe {
            bpf_probe_read_kernel_buf(sk.add(SKC_V6_DADDR_OFF), &mut daddr6).map_err(|e| e)?;
            bpf_probe_read_kernel_buf(sk.add(SKC_V6_SADDR_OFF), &mut saddr6).map_err(|e| e)?;
        }
        let sport: u16 = unsafe { bpf_probe_read_kernel(sk.add(14) as *const u16)? };

        if let Some(mut buf) = NETWORK_EVENTS.reserve::<DnsQueryEvent6Data>(0) {
            let e = unsafe { &mut *buf.as_mut_ptr() };
            e.event_tag = NET_EVT_DNS_QUERY_V6;
            e.protocol = NET_PROTO_UDP;
            e._pad = [0; 2];
            e.pid = pid;
            e.tgid = tgid;
            e.uid = uid;
            e.saddr6 = saddr6;
            e.daddr6 = daddr6;
            e.sport = sport;
            e.dport = dport;
            e.dns_len = dns_len;
            e._pad2 = 0;
            e.comm = comm;
            e.payload = [0; MAX_DNS_PAYLOAD];
            let dn = (e.dns_len as usize) & 0xFF;
            if dn > 0 {
                // Safety: dn bounded to 1..255; reading user buffer saved from sendto/sendmsg.
                unsafe { let _ = bpf_probe_read_user_buf(buf_ptr as *const u8, &mut e.payload[..dn]); }
            }
            buf.submit(0);
        } else {
            bump_net_drop();
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Network: udp_sendmsg (kprobe — outgoing UDP)
// ---------------------------------------------------------------------------

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_udp_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    let sock: u64 = ctx.arg(0).ok_or(1i64)?;
    cache_udp_source(sock)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // Safety: aya HashMap::get requires unsafe; no concurrent mutation from userspace.
    if let Some(info) = unsafe { DNS_BUF_CACHE.get(&tgid) } {
        let bp = info.buf_ptr;
        let bl = info.len;
        let _ = DNS_BUF_CACHE.remove(&tgid);
        let _ = emit_dns_from_sock(sock, bp, bl);
    }

    read_sock_v4_and_emit(sock, NET_EVT_V4_CONNECT, NET_PROTO_UDP)
}

// ---------------------------------------------------------------------------
// Network: tcp_v6_connect
// ---------------------------------------------------------------------------

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_v6_connect_entry(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_v6_connect_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let sock: u64 = ctx.arg(0).ok_or(1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = SOCK_STORE.insert(&pid_tgid, &sock, 0);
    Ok(())
}

#[kretprobe]
pub fn tcp_v6_connect_ret(ctx: RetProbeContext) -> u32 {
    match try_tcp_v6_connect_ret(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_v6_connect_ret(ctx: &RetProbeContext) -> Result<(), i64> {
    let retval: i32 = ctx.ret().unwrap_or(-1);
    let pid_tgid = bpf_get_current_pid_tgid();

    let sock_ptr = match unsafe { SOCK_STORE.get(&pid_tgid) } {
        Some(s) => *s,
        None => return Ok(()),
    };
    let _ = SOCK_STORE.remove(&pid_tgid);

    if retval != 0 {
        return Ok(());
    }

    read_sock_v6_and_emit(sock_ptr, NET_EVT_V6_CONNECT, NET_PROTO_TCP)
}

// ---------------------------------------------------------------------------
// Network: inet_bind (IPv4) / inet6_bind (IPv6)
// ---------------------------------------------------------------------------

#[kprobe]
pub fn inet_bind_entry(ctx: ProbeContext) -> u32 {
    match try_inet_bind(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_inet_bind(ctx: &ProbeContext) -> Result<(), i64> {
    let sock: u64 = ctx.arg(0).ok_or(1i64)?;
    read_sock_v4_and_emit(sock, NET_EVT_V4_BIND, NET_PROTO_TCP)
}

#[kprobe]
pub fn inet6_bind_entry(ctx: ProbeContext) -> u32 {
    match try_inet6_bind(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_inet6_bind(ctx: &ProbeContext) -> Result<(), i64> {
    // inet6_bind(sock, uaddr, addr_len) — first arg is struct socket *,
    // which starts with struct sock * at offset 0.
    let sock: u64 = ctx.arg(0).ok_or(1i64)?;
    read_sock_v6_and_emit(sock, NET_EVT_V6_BIND, NET_PROTO_TCP)
}

// ---------------------------------------------------------------------------
// Shared helpers: read sock and emit IPv4 / IPv6 network events
// ---------------------------------------------------------------------------

/// sock_common layout assumed by this file
/// (pre-IPv6-union layout: daddr/rcv_saddr consecutive at 0/4):
///   offset  0: skc_daddr       (u32)
///   offset  4: skc_rcv_saddr   (u32)
///   offset 12: skc_dport       (u16, network order)
///   offset 14: skc_num         (u16, host order)
///   offset 16: skc_family      (u16)
fn read_sock_v4_and_emit(sock_ptr: u64, event_tag: u8, protocol: u8) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid  = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid  = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let sk = sock_ptr as *const u8;
    let daddr: u32 = unsafe { bpf_probe_read_kernel(sk.add(0) as *const u32)? };
    let saddr: u32 = unsafe { bpf_probe_read_kernel(sk.add(4) as *const u32)? };
    let dport: u16 = unsafe { bpf_probe_read_kernel(sk.add(12) as *const u16)? };
    let sport: u16 = unsafe { bpf_probe_read_kernel(sk.add(14) as *const u16)? };

    if let Some(mut buf) = NETWORK_EVENTS.reserve::<NetworkEventData>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = event_tag;
        event.protocol  = protocol;
        event._pad = [0; 2];
        event.pid  = pid;
        event.tgid = tgid;
        event.uid  = uid;
        event.saddr = saddr;
        event.daddr = daddr;
        event.sport = sport;
        event.dport = u16::from_be(dport);
        event.comm  = comm;
        buf.submit(0);
    } else {
        bump_net_drop();
    }

    Ok(())
}

/// sock_common IPv6 layout (64-bit, CONFIG_NET_NS=y):
///   offset SKC_V6_DADDR_OFF (56): skc_v6_daddr     ([u8; 16])
///   offset SKC_V6_SADDR_OFF (72): skc_v6_rcv_saddr ([u8; 16])
///   offset 12: skc_dport        (u16, network order)
///   offset 14: skc_num          (u16, host order)
fn read_sock_v6_and_emit(sock_ptr: u64, event_tag: u8, protocol: u8) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid  = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid  = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    let sk = sock_ptr as *const u8;

    let mut daddr6 = [0u8; 16];
    let mut saddr6 = [0u8; 16];
    unsafe {
        bpf_probe_read_kernel_buf(sk.add(SKC_V6_DADDR_OFF), &mut daddr6).map_err(|e| e)?;
        bpf_probe_read_kernel_buf(sk.add(SKC_V6_SADDR_OFF), &mut saddr6).map_err(|e| e)?;
    }
    let dport: u16 = unsafe { bpf_probe_read_kernel(sk.add(12) as *const u16)? };
    let sport: u16 = unsafe { bpf_probe_read_kernel(sk.add(14) as *const u16)? };

    if let Some(mut buf) = NETWORK_EVENTS.reserve::<NetworkEvent6Data>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.event_tag = event_tag;
        event.protocol  = protocol;
        event._pad = [0; 2];
        event.pid  = pid;
        event.tgid = tgid;
        event.uid  = uid;
        event.saddr6 = saddr6;
        event.daddr6 = daddr6;
        event.sport = sport;
        event.dport = u16::from_be(dport);
        event.comm  = comm;
        buf.submit(0);
    } else {
        bump_net_drop();
    }

    Ok(())
}

fn cache_udp_source(sock_ptr: u64) -> Result<(), i64> {
    let sk = sock_ptr as *const u8;
    let family: u16 = unsafe { bpf_probe_read_kernel(sk.add(16) as *const u16)? };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut cache = UdpSrcCache {
        family,
        sport: 0,
        dport: 0,
        _pad: 0,
        saddr: 0,
        daddr: 0,
        saddr6: [0; 16],
        daddr6: [0; 16],
    };

    if family == AF_INET {
        cache.daddr = unsafe { bpf_probe_read_kernel(sk.add(0) as *const u32)? };
        cache.saddr = unsafe { bpf_probe_read_kernel(sk.add(4) as *const u32)? };
        let dport_be: u16 = unsafe { bpf_probe_read_kernel(sk.add(12) as *const u16)? };
        cache.sport = unsafe { bpf_probe_read_kernel(sk.add(14) as *const u16)? };
        cache.dport = u16::from_be(dport_be);
    } else if family == AF_INET6 {
        // Safety: reading sock_common IPv6 fields at documented offsets.
        unsafe {
            bpf_probe_read_kernel_buf(sk.add(SKC_V6_DADDR_OFF), &mut cache.daddr6).map_err(|e| e)?;
            bpf_probe_read_kernel_buf(sk.add(SKC_V6_SADDR_OFF), &mut cache.saddr6).map_err(|e| e)?;
        }
        let dport_be: u16 = unsafe { bpf_probe_read_kernel(sk.add(12) as *const u16)? };
        cache.sport = unsafe { bpf_probe_read_kernel(sk.add(14) as *const u16)? };
        cache.dport = u16::from_be(dport_be);
    } else {
        return Ok(());
    }

    let _ = UDP_SRC_CACHE.insert(&tgid, &cache, 0);
    Ok(())
}

fn v6_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut i = 0usize;
    while i < 16 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
