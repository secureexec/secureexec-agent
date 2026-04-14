use std::net::{Ipv4Addr, Ipv6Addr};

use secureexec_ebpf_common::{
    ID_UNCHANGED, MAX_ARG_SIZE, MAX_ARGV_ARGS, NET_PROTO_UDP,
    PRIV_SETGID, PRIV_SETREGID, PRIV_SETRESGID, PRIV_SETRESUID, PRIV_SETREUID, PRIV_SETUID,
};
use secureexec_generic::event::Protocol;

use super::super::procfs;

// ---------------------------------------------------------------------------
// Low-level byte / address helpers
// ---------------------------------------------------------------------------

pub(super) fn bytes_to_string(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub(super) fn u32_to_ipv4_string(addr: u32) -> String {
    Ipv4Addr::from(addr.to_be()).to_string()
}

pub(super) fn bytes_to_ipv6_string(b: &[u8; 16]) -> String {
    Ipv6Addr::from(*b).to_string()
}

pub(super) fn proto_from_u8(p: u8) -> Protocol {
    match p {
        NET_PROTO_UDP => Protocol::Udp,
        _ => Protocol::Tcp,
    }
}

pub(super) fn resolve_path(pid: u32, path: &str) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    if let Some(cwd) = procfs::read_proc_cwd(pid) {
        format!("{cwd}/{path}")
    } else {
        path.to_string()
    }
}

pub(super) fn argv_to_cmdline(argc: u32, args: &[[u8; MAX_ARG_SIZE]; MAX_ARGV_ARGS]) -> String {
    let count = (argc as usize).min(MAX_ARGV_ARGS);
    let mut parts: Vec<String> = Vec::with_capacity(count);
    for i in 0..count {
        let s = bytes_to_string(&args[i]);
        if s.is_empty() {
            break;
        }
        parts.push(s);
    }
    parts.join(" ")
}

// ---------------------------------------------------------------------------
// DNS query name parser
// ---------------------------------------------------------------------------

pub(super) fn parse_dns_query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12usize;
    let mut labels: Vec<String> = Vec::new();
    let mut steps = 0usize;
    while idx < payload.len() {
        if steps > 128 {
            return None;
        }
        steps += 1;
        let label_len = payload[idx] as usize;
        idx += 1;
        if label_len == 0 {
            break;
        }
        if (label_len & 0xC0) != 0 {
            return None;
        }
        if label_len > 63 || idx + label_len > payload.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&payload[idx..idx + label_len]).to_ascii_lowercase();
        if label.is_empty() {
            return None;
        }
        labels.push(label);
        idx += label_len;
    }
    if labels.is_empty() || idx + 4 > payload.len() {
        return None;
    }
    Some(labels.join("."))
}

// ---------------------------------------------------------------------------
// Syscall / constant name lookup helpers
// ---------------------------------------------------------------------------

pub(super) fn ptrace_request_name(request: u32) -> &'static str {
    match request {
        0 => "PTRACE_TRACEME",
        1 => "PTRACE_PEEKTEXT",
        2 => "PTRACE_PEEKDATA",
        3 => "PTRACE_PEEKUSER",
        4 => "PTRACE_POKETEXT",
        5 => "PTRACE_POKEDATA",
        6 => "PTRACE_POKEUSER",
        7 => "PTRACE_CONT",
        8 => "PTRACE_KILL",
        9 => "PTRACE_SINGLESTEP",
        12 => "PTRACE_GETREGS",
        13 => "PTRACE_SETREGS",
        16 => "PTRACE_ATTACH",
        17 => "PTRACE_DETACH",
        24 => "PTRACE_SYSCALL",
        0x4206 => "PTRACE_SEIZE",
        0x4207 => "PTRACE_INTERRUPT",
        0x4208 => "PTRACE_LISTEN",
        _ => "PTRACE_UNKNOWN",
    }
}

pub(super) fn priv_syscall_name(code: u8) -> &'static str {
    match code {
        PRIV_SETUID   => "setuid",
        PRIV_SETGID   => "setgid",
        PRIV_SETREUID => "setreuid",
        PRIV_SETREGID => "setregid",
        PRIV_SETRESUID => "setresuid",
        PRIV_SETRESGID => "setresgid",
        _ => "unknown",
    }
}

pub(super) fn priv_ids_to_uid_gid(syscall: u8, id1: u32, id2: u32) -> (Option<u32>, Option<u32>) {
    let opt = |x: u32| if x != ID_UNCHANGED { Some(x) } else { None };
    match syscall {
        PRIV_SETUID               => (opt(id1), None),
        PRIV_SETGID               => (None, opt(id1)),
        PRIV_SETREUID | PRIV_SETRESUID => (opt(id2), None),
        PRIV_SETREGID | PRIV_SETRESGID => (None, opt(id2)),
        _ => (opt(id1), None),
    }
}

pub(super) fn signal_name(sig: u32) -> &'static str {
    match sig {
        1  => "SIGHUP",  2  => "SIGINT",  3  => "SIGQUIT", 4  => "SIGILL",
        5  => "SIGTRAP", 6  => "SIGABRT", 7  => "SIGBUS",  8  => "SIGFPE",
        9  => "SIGKILL", 10 => "SIGUSR1", 11 => "SIGSEGV", 12 => "SIGUSR2",
        13 => "SIGPIPE", 14 => "SIGALRM", 15 => "SIGTERM", 16 => "SIGSTKFLT",
        17 => "SIGCHLD", 18 => "SIGCONT", 19 => "SIGSTOP", 20 => "SIGTSTP",
        21 => "SIGTTIN", 22 => "SIGTTOU", 23 => "SIGURG",  24 => "SIGXCPU",
        25 => "SIGXFSZ", 26 => "SIGVTALRM", 27 => "SIGPROF", 28 => "SIGWINCH",
        29 => "SIGIO",   30 => "SIGPWR",  31 => "SIGSYS",
        _ => "SIG_UNKNOWN",
    }
}

pub(super) fn bpf_cmd_name(cmd: u32) -> &'static str {
    match cmd {
        0  => "BPF_MAP_CREATE",       1  => "BPF_MAP_LOOKUP_ELEM",
        2  => "BPF_MAP_UPDATE_ELEM",  3  => "BPF_MAP_DELETE_ELEM",
        4  => "BPF_MAP_GET_NEXT_KEY", 5  => "BPF_PROG_LOAD",
        6  => "BPF_OBJ_PIN",          7  => "BPF_OBJ_GET",
        8  => "BPF_PROG_ATTACH",      9  => "BPF_PROG_DETACH",
        10 => "BPF_PROG_TEST_RUN",    11 => "BPF_PROG_GET_NEXT_ID",
        16 => "BPF_RAW_TRACEPOINT_OPEN", 17 => "BPF_PROG_QUERY",
        18 => "BPF_BTF_LOAD",
        _ => "BPF_CMD_UNKNOWN",
    }
}

pub(super) fn keyctl_op_name(op: u32) -> &'static str {
    match op {
        0  => "KEYCTL_GET_KEYRING_ID",    1  => "KEYCTL_JOIN_SESSION_KEYRING",
        2  => "KEYCTL_UPDATE",            3  => "KEYCTL_REVOKE",
        4  => "KEYCTL_CHOWN",             5  => "KEYCTL_SETPERM",
        6  => "KEYCTL_DESCRIBE",          7  => "KEYCTL_CLEAR",
        8  => "KEYCTL_LINK",              9  => "KEYCTL_UNLINK",
        10 => "KEYCTL_SEARCH",            11 => "KEYCTL_READ",
        12 => "KEYCTL_INSTANTIATE",       13 => "KEYCTL_NEGATE",
        14 => "KEYCTL_SET_REQKEY_KEYRING", 15 => "KEYCTL_SET_TIMEOUT",
        16 => "KEYCTL_ASSUME_AUTHORITY",  17 => "KEYCTL_GET_SECURITY",
        18 => "KEYCTL_SESSION_TO_PARENT", 19 => "KEYCTL_REJECT",
        20 => "KEYCTL_INSTANTIATE_IOV",   21 => "KEYCTL_INVALIDATE",
        22 => "KEYCTL_GET_PERSISTENT",    29 => "KEYCTL_RESTRICT_KEYRING",
        _ => "KEYCTL_UNKNOWN",
    }
}

pub(super) fn namespace_flags_name(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x0002_0000 != 0 { parts.push("CLONE_NEWNS"); }
    if flags & 0x0200_0000 != 0 { parts.push("CLONE_NEWCGROUP"); }
    if flags & 0x0400_0000 != 0 { parts.push("CLONE_NEWUTS"); }
    if flags & 0x0800_0000 != 0 { parts.push("CLONE_NEWIPC"); }
    if flags & 0x1000_0000 != 0 { parts.push("CLONE_NEWUSER"); }
    if flags & 0x2000_0000 != 0 { parts.push("CLONE_NEWPID"); }
    if flags & 0x4000_0000 != 0 { parts.push("CLONE_NEWNET"); }
    if parts.is_empty() {
        format!("0x{flags:08x}")
    } else {
        parts.join("|")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::parse_dns_query_name;

    fn build_dns_query(labels: &[&str]) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        for label in labels {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // end of qname
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype A, qclass IN
        pkt
    }

    #[test]
    fn parse_dns_query_valid_a() {
        let pkt = build_dns_query(&["example", "com"]);
        assert_eq!(parse_dns_query_name(&pkt).as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_dns_query_truncated_payload() {
        let mut pkt = build_dns_query(&["example", "com"]);
        pkt.truncate(pkt.len() - 2);
        assert_eq!(parse_dns_query_name(&pkt), None);
    }

    #[test]
    fn parse_dns_query_invalid_label_length() {
        let mut pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x14, // claims 20 bytes label, but buffer is shorter
            b'a', b'b', b'c',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        pkt.truncate(18);
        assert_eq!(parse_dns_query_name(&pkt), None);
    }

    #[test]
    fn parse_dns_query_multi_label_domain() {
        let pkt = build_dns_query(&["api", "secureexec", "ru"]);
        assert_eq!(parse_dns_query_name(&pkt).as_deref(), Some("api.secureexec.ru"));
    }
}
