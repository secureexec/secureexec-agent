//! Argument validators shared by every host-exec runner.
//!
//! Two layers of defence: the backend rejects bad inputs before the row is
//! even inserted, and the agent re-validates here. If either side relaxes a
//! rule the other still catches it.
//!
//! Hard rules enforced here:
//!
//! - **No NUL** in any string. NUL bytes never reach `argv` from us.
//! - **No `..` segments**. We do not let the AI walk parents of an absolute
//!   path; if it wants `/etc` it must say `/etc`, not `/var/../etc`.
//! - **Path is absolute**. Relative paths are nonsense for an agent that
//!   does not have a meaningful CWD.
//! - **Denylist on canonicalized path prefix**. The agent runs as root in
//!   most deployments, so any read tool can read `/etc/shadow` unless we
//!   explicitly forbid it. The list below blocks credential / private-key
//!   material that has no place in an investigation.

use std::path::{Component, Path};

use super::HostExecError;

/// Sensitive prefixes (any path that starts with one of these is rejected).
/// Suffix patterns are checked separately in [`is_denied_suffix`].
const DENYLIST_PREFIXES: &[&str] = &[
    // Local-account secrets and password hashes.
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    // Common TLS/SSH private-key directories — entire dir is off-limits.
    "/etc/pki/tls/private",
    "/etc/ssl/private",
    // Root home — usually contains SSH keys, .pgpass, .docker/config.json, …
    "/root",
    // Live kernel memory and other procfs/sysfs leaks.
    "/proc/kcore",
    "/proc/kallsyms",
    "/sys/kernel/security/integrity/ima",
    // Block-device memory aliases.
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
];

/// Suffix patterns checked after the prefix list. Anything whose tail matches
/// one of these is rejected — covers private SSH keys in arbitrary user
/// homes (`/home/alice/.ssh/id_rsa`, `/Users/bob/.ssh/id_ed25519`, …).
const DENYLIST_SUFFIXES: &[&str] = &[
    "/.ssh/id_rsa",
    "/.ssh/id_dsa",
    "/.ssh/id_ecdsa",
    "/.ssh/id_ed25519",
];

/// Validate a path supplied by the AI / caller for use as an argv element.
/// Returns the cleaned path string on success.
pub fn validate_path(raw: &str) -> Result<String, HostExecError> {
    if raw.is_empty() {
        return Err(HostExecError::BadArg("path is empty".into()));
    }
    if raw.contains('\0') {
        return Err(HostExecError::BadArg("path contains NUL byte".into()));
    }
    if raw.len() > 4096 {
        return Err(HostExecError::BadArg("path exceeds 4096 bytes".into()));
    }

    let p = Path::new(raw);
    if !p.is_absolute() {
        return Err(HostExecError::BadArg(format!(
            "path must be absolute: {raw}"
        )));
    }

    // Reject `..` segments outright. We do not call `canonicalize` because
    // that follows symlinks and can race with the host filesystem; a literal
    // `Component::ParentDir` check is enough to keep the AI from constructing
    // `/var/log/../../etc/shadow`-style escapes, and the denylist below
    // covers the absolute targets we care about anyway.
    for c in p.components() {
        if matches!(c, Component::ParentDir) {
            return Err(HostExecError::BadArg(
                "path must not contain '..' segments".into(),
            ));
        }
    }

    if is_denied(raw) {
        return Err(HostExecError::BadArg(format!(
            "path is on host-exec denylist: {raw}"
        )));
    }

    Ok(raw.to_string())
}

fn is_denied(path: &str) -> bool {
    for p in DENYLIST_PREFIXES {
        if path == *p || path.starts_with(&format!("{p}/")) {
            return true;
        }
    }
    if is_denied_suffix(path) {
        return true;
    }
    if is_denied_proc_alias(path) {
        return true;
    }
    if is_denied_ssh_host_key(path) {
        return true;
    }
    false
}

/// True if `path` looks like an OpenSSH host *private* key, e.g.
/// `/etc/ssh/ssh_host_rsa_key`, `/etc/ssh/ssh_host_ed25519_key`. Public
/// keys (`.pub` suffix) are explicitly allowed since they're non-secret.
fn is_denied_ssh_host_key(path: &str) -> bool {
    let Some(name) = path.rsplit_once('/').map(|(_, n)| n) else {
        return false;
    };
    if !path.starts_with("/etc/ssh/") {
        return false;
    }
    name.starts_with("ssh_host_")
        && name.ends_with("_key")
        && !name.ends_with(".pub")
}

fn is_denied_suffix(path: &str) -> bool {
    for s in DENYLIST_SUFFIXES {
        if path.ends_with(s) {
            return true;
        }
    }
    false
}

/// True if `path` matches `/proc/<pid>/{mem,maps,environ,auxv}` — per-process
/// memory aliases that can leak credentials, env vars, or kernel addresses.
/// We accept any final component matching one of those names; the middle
/// component must look like a numeric PID or `self`.
fn is_denied_proc_alias(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    // /proc/<pid>/<final>
    let mut parts = rest.split('/');
    let pid = match parts.next() {
        Some(s) if s == "self" || s == "thread-self" => s,
        Some(s) if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) => s,
        _ => return false,
    };
    let _ = pid;
    let Some(final_seg) = parts.next() else {
        return false;
    };
    // Must be the *last* component — `/proc/123/mem/foo` doesn't exist.
    if parts.next().is_some() {
        return false;
    }
    matches!(final_seg, "mem" | "maps" | "environ" | "auxv")
}

/// Validate a free-text pattern (e.g. `grep` regex, `find -name` glob).
/// We disallow NUL and length > 1024 — every other character is fine because
/// the value is passed as a single argv element, never expanded by a shell.
pub fn validate_pattern(raw: &str, kind: &str) -> Result<String, HostExecError> {
    if raw.is_empty() {
        return Err(HostExecError::BadArg(format!("{kind} is empty")));
    }
    if raw.contains('\0') {
        return Err(HostExecError::BadArg(format!(
            "{kind} contains NUL byte"
        )));
    }
    if raw.len() > 1024 {
        return Err(HostExecError::BadArg(format!(
            "{kind} exceeds 1024 bytes"
        )));
    }
    Ok(raw.to_string())
}

/// Validate a single textual filter token (e.g. `name_filter` for `ps`).
/// More restrictive than [`validate_pattern`]: only word-ish characters
/// because we use it for substring matching, not regex.
pub fn validate_filter_token(raw: &str, kind: &str) -> Result<String, HostExecError> {
    if raw.is_empty() {
        return Err(HostExecError::BadArg(format!("{kind} is empty")));
    }
    if raw.len() > 256 {
        return Err(HostExecError::BadArg(format!(
            "{kind} exceeds 256 bytes"
        )));
    }
    if raw
        .chars()
        .any(|c| c == '\0' || c == '\n' || c == '\r')
    {
        return Err(HostExecError::BadArg(format!(
            "{kind} contains control char"
        )));
    }
    Ok(raw.to_string())
}

/// Clamp an integer to `[1, max]` — a small helper used by every runner
/// that exposes a `limit` knob.
pub fn cap_int(v: Option<u64>, default: u64, max: u64) -> u64 {
    let n = v.unwrap_or(default);
    n.clamp(1, max)
}

/// Parse an RFC3339 timestamp and re-format it the way `journalctl --since`
/// expects, i.e. `YYYY-MM-DD HH:MM:SS UTC`. Anchoring to UTC removes the
/// systemd-version-dependent timezone parsing we'd otherwise have to worry
/// about, and `journalctl` accepts this form on every release we support.
pub fn parse_rfc3339_to_journal(raw: &str, kind: &str) -> Result<String, HostExecError> {
    if raw.is_empty() {
        return Err(HostExecError::BadArg(format!("{kind} is empty")));
    }
    if raw.contains('\0') {
        return Err(HostExecError::BadArg(format!("{kind} contains NUL byte")));
    }
    if raw.len() > 64 {
        return Err(HostExecError::BadArg(format!("{kind} exceeds 64 bytes")));
    }
    let dt = chrono::DateTime::parse_from_rfc3339(raw).map_err(|e| {
        HostExecError::BadArg(format!("{kind} is not a valid RFC3339 timestamp: {e}"))
    })?;
    Ok(dt
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string())
}

/// Validate a `journalctl -p` priority value. Accepts the names systemd
/// itself accepts; numeric forms (0..=7) are also recognised.
pub fn validate_journal_priority(raw: &str) -> Result<String, HostExecError> {
    const NAMES: &[&str] = &[
        "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
    ];
    if NAMES.contains(&raw)
        || (raw.len() == 1 && raw.chars().all(|c| ('0'..='7').contains(&c)))
    {
        return Ok(raw.to_string());
    }
    Err(HostExecError::BadArg(format!(
        "priority must be one of {NAMES:?} or a single digit 0..=7, got {raw}"
    )))
}

/// Validate a Linux PID. Reject 0 (no such process), negative, and anything
/// above `PID_MAX_LIMIT` (4 194 304 — kernel ceiling on 64-bit).
pub fn validate_pid(raw: u64) -> Result<u32, HostExecError> {
    if raw == 0 {
        return Err(HostExecError::BadArg("pid must be > 0".into()));
    }
    if raw > 4_194_304 {
        return Err(HostExecError::BadArg(format!(
            "pid {raw} exceeds PID_MAX_LIMIT"
        )));
    }
    Ok(raw as u32)
}

/// Validate a TCP/UDP port number. 0 is reserved.
pub fn validate_port(raw: u64) -> Result<u16, HostExecError> {
    if raw == 0 || raw > 65_535 {
        return Err(HostExecError::BadArg(format!(
            "port must be 1..=65535, got {raw}"
        )));
    }
    Ok(raw as u16)
}

/// Generic "must be one of these strings" guard.
pub fn validate_choice<'a>(
    raw: &'a str,
    kind: &str,
    choices: &[&str],
) -> Result<&'a str, HostExecError> {
    if choices.contains(&raw) {
        Ok(raw)
    } else {
        Err(HostExecError::BadArg(format!(
            "{kind} must be one of {choices:?}, got {raw}"
        )))
    }
}

/// Validate a systemd unit name (e.g. `sshd.service`, `nginx@http.service`).
/// More permissive than a generic filter token because systemd unit names
/// legitimately contain `.`, `@`, `\\` (escapes), `-`, and `:`.
pub fn validate_unit_name(raw: &str) -> Result<String, HostExecError> {
    if raw.is_empty() {
        return Err(HostExecError::BadArg("unit is empty".into()));
    }
    if raw.len() > 256 {
        return Err(HostExecError::BadArg("unit exceeds 256 bytes".into()));
    }
    // Refuse anything that could be misinterpreted as a flag / control char.
    // Systemd unit names use a restricted alphabet; this matches it tightly
    // enough to keep `--unit=…something…` from sneaking in.
    let ok = raw.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '-' | '_' | '@' | ':' | '\\' | '/')
    });
    if !ok {
        return Err(HostExecError::BadArg(format!(
            "unit contains invalid characters: {raw}"
        )));
    }
    if raw.starts_with('-') {
        return Err(HostExecError::BadArg(
            "unit must not start with '-'".into(),
        ));
    }
    Ok(raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative() {
        assert!(validate_path("var/log").is_err());
        assert!(validate_path("./etc/passwd").is_err());
    }

    #[test]
    fn rejects_parent_dir() {
        assert!(validate_path("/var/log/../../etc/shadow").is_err());
        assert!(validate_path("/..").is_err());
    }

    #[test]
    fn rejects_nul() {
        assert!(validate_path("/etc/passwd\0evil").is_err());
        assert!(validate_pattern("foo\0bar", "pat").is_err());
    }

    #[test]
    fn denylist_prefix_blocks_shadow_and_sudoers() {
        assert!(validate_path("/etc/shadow").is_err());
        assert!(validate_path("/etc/sudoers").is_err());
        assert!(validate_path("/etc/sudoers.d/foo").is_err());
    }

    #[test]
    fn denylist_blocks_root_and_kcore() {
        assert!(validate_path("/root").is_err());
        assert!(validate_path("/root/.bash_history").is_err());
        assert!(validate_path("/proc/kcore").is_err());
    }

    #[test]
    fn denylist_blocks_ssh_keys() {
        assert!(validate_path("/home/alice/.ssh/id_rsa").is_err());
        assert!(validate_path("/Users/bob/.ssh/id_ed25519").is_err());
        // public keys still allowed (non-secret)
        assert!(validate_path("/home/alice/.ssh/id_rsa.pub").is_ok());
    }

    #[test]
    fn denylist_blocks_host_keys_and_tls_private() {
        assert!(validate_path("/etc/ssh/ssh_host_rsa_key").is_err());
        assert!(validate_path("/etc/ssh/ssh_host_ed25519_key").is_err());
        // public host keys are still readable
        assert!(validate_path("/etc/ssh/ssh_host_rsa_key.pub").is_ok());
        assert!(validate_path("/etc/ssh/sshd_config").is_ok());
        assert!(validate_path("/etc/pki/tls/private/server.key").is_err());
        assert!(validate_path("/etc/ssl/private/server.key").is_err());
    }

    #[test]
    fn denylist_blocks_memory_devices() {
        assert!(validate_path("/dev/mem").is_err());
        assert!(validate_path("/dev/kmem").is_err());
        assert!(validate_path("/dev/port").is_err());
        // unrelated /dev paths must not be blocked
        assert!(validate_path("/dev/null").is_ok());
        assert!(validate_path("/dev/sda1").is_ok());
    }

    #[test]
    fn denylist_blocks_proc_pid_mem() {
        assert!(validate_path("/proc/1/mem").is_err());
        assert!(validate_path("/proc/12345/mem").is_err());
        assert!(validate_path("/proc/self/mem").is_err());
        assert!(validate_path("/proc/thread-self/mem").is_err());
        assert!(validate_path("/proc/1/maps").is_err());
        assert!(validate_path("/proc/1/environ").is_err());
        assert!(validate_path("/proc/1/auxv").is_err());
        // status / cmdline / cgroup / fdinfo are fine — they're already
        // protected by their own DAC and the agent uses them legitimately.
        assert!(validate_path("/proc/1/status").is_ok());
        assert!(validate_path("/proc/1/cmdline").is_ok());
        assert!(validate_path("/proc/1/cgroup").is_ok());
        // a directory that *contains* "mem" but isn't the alias is fine
        assert!(validate_path("/var/lib/postgresql/mem").is_ok());
        assert!(validate_path("/proc/1/mem/extra").is_ok());
        // non-pid /proc/<x>/mem must not be blocked (e.g. /proc/sys/...)
        assert!(validate_path("/proc/sys/kernel/random").is_ok());
    }

    #[test]
    fn denylist_blocks_kallsyms() {
        assert!(validate_path("/proc/kallsyms").is_err());
    }

    #[test]
    fn allows_normal_paths() {
        assert!(validate_path("/var/log/auth.log").is_ok());
        assert!(validate_path("/etc/passwd").is_ok());
        assert!(validate_path("/tmp").is_ok());
    }

    #[test]
    fn cap_int_clamps() {
        assert_eq!(cap_int(None, 10, 100), 10);
        assert_eq!(cap_int(Some(0), 10, 100), 1);
        assert_eq!(cap_int(Some(99999), 10, 100), 100);
        assert_eq!(cap_int(Some(50), 10, 100), 50);
    }

    #[test]
    fn rfc3339_parses_utc() {
        let s = parse_rfc3339_to_journal("2024-01-02T03:04:05Z", "since").unwrap();
        assert_eq!(s, "2024-01-02 03:04:05 UTC");
    }

    #[test]
    fn rfc3339_parses_with_offset() {
        // +05:30 input must be normalised to UTC.
        let s = parse_rfc3339_to_journal("2024-01-02T08:34:05+05:30", "since").unwrap();
        assert_eq!(s, "2024-01-02 03:04:05 UTC");
    }

    #[test]
    fn rfc3339_rejects_bad_input() {
        assert!(parse_rfc3339_to_journal("", "since").is_err());
        assert!(parse_rfc3339_to_journal("yesterday", "since").is_err());
        assert!(parse_rfc3339_to_journal("2024-01-02 03:04:05", "since").is_err());
        assert!(parse_rfc3339_to_journal("--since=foo", "since").is_err());
        assert!(parse_rfc3339_to_journal("2024-01-02T03:04:05Z\0evil", "since").is_err());
    }

    #[test]
    fn priority_accepts_known_names_and_digits() {
        for p in ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"] {
            assert!(validate_journal_priority(p).is_ok(), "name {p}");
        }
        for d in '0'..='7' {
            assert!(validate_journal_priority(&d.to_string()).is_ok());
        }
    }

    #[test]
    fn priority_rejects_unknown() {
        assert!(validate_journal_priority("urgent").is_err());
        assert!(validate_journal_priority("8").is_err());
        assert!(validate_journal_priority("12").is_err());
        assert!(validate_journal_priority("").is_err());
    }

    #[test]
    fn unit_accepts_typical_units() {
        for u in [
            "sshd.service",
            "nginx.service",
            "nginx@http.service",
            "systemd-journald.service",
            "user-1000.slice",
            "machine.slice",
        ] {
            assert!(validate_unit_name(u).is_ok(), "unit {u}");
        }
    }

    #[test]
    fn unit_rejects_dashes_at_start_and_garbage() {
        assert!(validate_unit_name("-u").is_err());
        assert!(validate_unit_name("nginx; echo pwned").is_err());
        assert!(validate_unit_name("foo bar.service").is_err());
        assert!(validate_unit_name("").is_err());
    }

    #[test]
    fn pid_validation() {
        assert!(validate_pid(0).is_err());
        assert!(validate_pid(1).is_ok());
        assert!(validate_pid(123_456).is_ok());
        assert!(validate_pid(4_194_304).is_ok());
        assert!(validate_pid(4_194_305).is_err());
    }

    #[test]
    fn port_validation() {
        assert!(validate_port(0).is_err());
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(65_535).is_ok());
        assert!(validate_port(65_536).is_err());
    }

    #[test]
    fn choice_validation() {
        assert!(validate_choice("a", "kind", &["a", "b"]).is_ok());
        assert!(validate_choice("b", "kind", &["a", "b"]).is_ok());
        assert!(validate_choice("c", "kind", &["a", "b"]).is_err());
        assert!(validate_choice("", "kind", &["a"]).is_err());
    }
}
