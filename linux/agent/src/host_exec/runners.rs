//! Per-tool runners. Each function takes the parsed JSON payload, builds an
//! `argv`, and execs a real binary (`ls`, `cat`, `grep`, `find`, `ps`)
//! **without ever invoking a shell**. Output is captured byte-bounded into a
//! [`HostExecOutput`] which the dispatcher then converts into a
//! `CommandOutcome` for the gRPC ack.

use std::process::Stdio;
use std::time::Instant;

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tracing::{debug, warn};

use super::limits::{
    READ_FILE_DEFAULT_BYTES, READ_FILE_MAX_BYTES, STDERR_CAP, STDOUT_CAP, WALL_TIMEOUT,
};
use super::validate::{
    cap_int, parse_rfc3339_to_journal, validate_choice, validate_filter_token,
    validate_journal_priority, validate_path, validate_pattern, validate_pid, validate_port,
    validate_unit_name,
};
use super::HostExecError;

/// Result of a single host-exec invocation. Mirrors the proto fields on
/// `AckCommandRequest` plus a `success` boolean and an optional
/// `error_message` for the case where validation fails before we even spawn
/// a process.
#[derive(Debug, Clone, Default)]
pub struct HostExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub truncated: bool,
    pub duration_ms: i64,
    pub error_message: String,
    /// Shell-quoted reconstruction of the argv that ran. Used for audit
    /// trail UI; never re-executed.
    pub command_line: String,
}

// ─── Payload structs ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListFilesArgs {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub max_results: Option<u64>,
    #[serde(default)]
    pub include_hidden: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReadFileArgs {
    pub path: String,
    #[serde(default)]
    pub head_lines: Option<u64>,
    #[serde(default)]
    pub tail_lines: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SearchFilesArgs {
    pub path: String,
    pub pattern: String,
    #[serde(default)]
    pub max_matches: Option<u64>,
    #[serde(default)]
    pub file_glob: Option<String>,
    #[serde(default)]
    pub ignore_case: bool,
}

#[derive(Debug, Deserialize)]
pub struct FindFilesArgs {
    pub path: String,
    #[serde(default)]
    pub name_pattern: Option<String>,
    /// "f" (regular file), "d" (directory), "l" (symlink), or omitted (any).
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub max_depth: Option<u64>,
    #[serde(default)]
    pub max_results: Option<u64>,
    #[serde(default)]
    pub modified_within_minutes: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ListProcessesArgs {
    #[serde(default)]
    pub name_filter: Option<String>,
    #[serde(default)]
    pub user_filter: Option<String>,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ReadJournalArgs {
    /// RFC3339 lower bound — required. Anchors the time window so the AI
    /// doesn't accidentally request "all of journald history" on a busy
    /// host. We re-format to journalctl's preferred `YYYY-MM-DD HH:MM:SS UTC`
    /// in the runner.
    pub since: String,
    /// Optional RFC3339 upper bound. Defaults to "now" (no `--until` flag).
    #[serde(default)]
    pub until: Option<String>,
    /// Optional systemd unit (e.g. `sshd.service`).
    #[serde(default)]
    pub unit: Option<String>,
    /// Optional substring/regex matched against the MESSAGE field
    /// (`journalctl --grep`).
    #[serde(default)]
    pub pattern: Option<String>,
    /// Case-insensitive `--grep`. Default false.
    #[serde(default)]
    pub ignore_case: bool,
    /// Optional `journalctl -p` priority filter (e.g. `err`, `warning`, or
    /// a single digit `0..=7`).
    #[serde(default)]
    pub priority: Option<String>,
    /// Max log lines to return. Default 200, hard cap 5000.
    #[serde(default)]
    pub lines: Option<u64>,
    /// Restrict to kernel ring buffer (`journalctl -k`). Useful for catching
    /// OOM kills, kmod load failures, and exploit traces that don't go
    /// through any unit.
    #[serde(default)]
    pub kernel_only: bool,
}

// ─── Runners ────────────────────────────────────────────────────────────────

pub async fn run_list_files(args: &ListFilesArgs) -> Result<HostExecOutput, HostExecError> {
    let path = validate_path(&args.path)?;
    let max = cap_int(args.max_results, 200, 5_000);

    if args.recursive {
        // Use `find -maxdepth` for capped recursion. We pipe through the
        // child's natural stdout limiting in `spawn_capped` rather than try
        // to truncate via `head` (no shell here).
        let mut argv: Vec<String> = vec![
            "/usr/bin/find".into(),
            path,
            "-maxdepth".into(),
            "5".into(),
        ];
        if !args.include_hidden {
            // skip dot-entries below the root
            argv.extend([
                "-not".into(),
                "-path".into(),
                "*/.*".into(),
            ]);
        }
        spawn_capped(argv, Some(max as usize)).await
    } else {
        let mut argv: Vec<String> = vec!["/bin/ls".into(), "-la".into()];
        if args.include_hidden {
            // -la already shows dot-entries; nothing to add.
        } else {
            // -l without -a already hides dot entries; replace the previous arg
            argv[1] = "-l".into();
        }
        argv.push("--".into());
        argv.push(path);
        spawn_capped(argv, Some(max as usize)).await
    }
}

pub async fn run_read_file(args: &ReadFileArgs) -> Result<HostExecOutput, HostExecError> {
    let path = validate_path(&args.path)?;
    if args.head_lines.is_some() && args.tail_lines.is_some() {
        return Err(HostExecError::BadArg(
            "head_lines and tail_lines are mutually exclusive".into(),
        ));
    }

    let max_bytes = args
        .max_bytes
        .unwrap_or(READ_FILE_DEFAULT_BYTES)
        .min(READ_FILE_MAX_BYTES);

    let argv: Vec<String> = if let Some(n) = args.head_lines {
        let n = cap_int(Some(n), 100, 10_000);
        vec![
            "/usr/bin/head".into(),
            "-n".into(),
            n.to_string(),
            "--".into(),
            path,
        ]
    } else if let Some(n) = args.tail_lines {
        let n = cap_int(Some(n), 100, 10_000);
        vec![
            "/usr/bin/tail".into(),
            "-n".into(),
            n.to_string(),
            "--".into(),
            path,
        ]
    } else {
        // Plain `cat` — `spawn_capped` limits bytes captured; we also cap by
        // `max_bytes` post-hoc by truncating below.
        vec!["/bin/cat".into(), "--".into(), path]
    };

    let mut out = spawn_capped(argv, None).await?;
    if (out.stdout.len() as u64) > max_bytes {
        out.stdout.truncate(max_bytes as usize);
        out.truncated = true;
    }
    Ok(out)
}

pub async fn run_search_files(args: &SearchFilesArgs) -> Result<HostExecOutput, HostExecError> {
    let path = validate_path(&args.path)?;
    let pattern = validate_pattern(&args.pattern, "pattern")?;
    let max_matches = cap_int(args.max_matches, 200, 5_000);

    let mut argv: Vec<String> = vec![
        "/bin/grep".into(),
        // -r: recurse, -n: line numbers, -H: print filename, -s: silent on
        // permission errors so the AI doesn't get spammed.
        "-rnHsI".into(),
        "--max-count".into(),
        max_matches.to_string(),
        "--exclude-dir".into(),
        ".git".into(),
    ];
    if args.ignore_case {
        argv.push("-i".into());
    }
    if let Some(g) = &args.file_glob {
        let g = validate_pattern(g, "file_glob")?;
        argv.push("--include".into());
        argv.push(g);
    }
    argv.push("-e".into());
    argv.push(pattern);
    argv.push("--".into());
    argv.push(path);

    let out = spawn_capped(argv, None).await?;
    Ok(out)
}

pub async fn run_find_files(args: &FindFilesArgs) -> Result<HostExecOutput, HostExecError> {
    let path = validate_path(&args.path)?;
    let max_depth = cap_int(args.max_depth, 5, 20);
    let max_results = cap_int(args.max_results, 500, 10_000);

    let mut argv: Vec<String> = vec![
        "/usr/bin/find".into(),
        path,
        "-maxdepth".into(),
        max_depth.to_string(),
    ];
    if let Some(name) = &args.name_pattern {
        let name = validate_pattern(name, "name_pattern")?;
        argv.push("-name".into());
        argv.push(name);
    }
    if let Some(k) = &args.kind {
        let allowed = matches!(k.as_str(), "f" | "d" | "l");
        if !allowed {
            return Err(HostExecError::BadArg(format!(
                "type must be one of f|d|l, got {k}"
            )));
        }
        argv.push("-type".into());
        argv.push(k.clone());
    }
    if let Some(mins) = args.modified_within_minutes {
        let mins = cap_int(Some(mins), 60, 60 * 24 * 30);
        argv.push("-mmin".into());
        argv.push(format!("-{mins}"));
    }
    // Defence in depth: refuse if the AI ever sneaks `-exec` / `-delete` in
    // some other field. (None of the args above can produce those tokens,
    // but the assertion makes that property obvious.)
    debug_assert!(!argv.iter().any(|a| a == "-exec" || a == "-delete"));

    spawn_capped(argv, Some(max_results as usize)).await
}

pub async fn run_list_processes(
    args: &ListProcessesArgs,
) -> Result<HostExecOutput, HostExecError> {
    // Validate filters *before* spawning ps — a bad filter token shouldn't
    // burn a process spawn.
    let name_filter = args
        .name_filter
        .as_deref()
        .map(|s| validate_filter_token(s, "name_filter"))
        .transpose()?;
    let user_filter = args
        .user_filter
        .as_deref()
        .map(|s| validate_filter_token(s, "user_filter"))
        .transpose()?;
    let limit = cap_int(args.limit, 200, 2_000) as usize;

    let argv: Vec<String> = vec![
        "/bin/ps".into(),
        "-eo".into(),
        "pid,ppid,user,etime,pcpu,pmem,cmd".into(),
    ];
    let raw = spawn_capped(argv, None).await?;
    if !raw.error_message.is_empty() {
        return Ok(raw);
    }

    let mut lines = raw.stdout.lines();
    let header = lines.next().unwrap_or("");
    let mut filtered = String::with_capacity(raw.stdout.len().min(64 * 1024));
    filtered.push_str(header);
    filtered.push('\n');
    let mut kept = 0usize;
    for line in lines {
        // Columns are space-separated; `cmd` is everything after column 6.
        let mut iter = line.split_whitespace();
        let _pid = iter.next();
        let _ppid = iter.next();
        let user = iter.next().unwrap_or("");
        let _etime = iter.next();
        let _pcpu = iter.next();
        let _pmem = iter.next();
        if let Some(uf) = &user_filter {
            if !user.contains(uf.as_str()) {
                continue;
            }
        }
        if let Some(nf) = &name_filter {
            if !line.contains(nf.as_str()) {
                continue;
            }
        }
        filtered.push_str(line);
        filtered.push('\n');
        kept += 1;
        if kept >= limit {
            break;
        }
    }

    Ok(HostExecOutput {
        stdout: filtered,
        stderr: raw.stderr,
        exit_code: raw.exit_code,
        truncated: raw.truncated,
        duration_ms: raw.duration_ms,
        error_message: String::new(),
        command_line: raw.command_line,
    })
}

pub async fn run_read_journal(args: &ReadJournalArgs) -> Result<HostExecOutput, HostExecError> {
    let since = parse_rfc3339_to_journal(&args.since, "since")?;
    let until = args
        .until
        .as_deref()
        .map(|u| parse_rfc3339_to_journal(u, "until"))
        .transpose()?;
    let unit = args
        .unit
        .as_deref()
        .map(validate_unit_name)
        .transpose()?;
    let pattern = args
        .pattern
        .as_deref()
        .map(|p| validate_pattern(p, "pattern"))
        .transpose()?;
    let priority = args
        .priority
        .as_deref()
        .map(validate_journal_priority)
        .transpose()?;
    let lines = cap_int(args.lines, 200, 5_000);

    // `--no-pager` is non-negotiable: without it `journalctl` invokes a
    // pager which holds stdout open until the wall-clock timeout fires.
    // `short-iso` gives us `<iso-ts> host unit[pid]: msg` — compact and
    // analyst-readable.
    let mut argv: Vec<String> = vec![
        "/usr/bin/journalctl".into(),
        "--no-pager".into(),
        "--output=short-iso".into(),
        "--since".into(),
        since,
    ];
    if let Some(u) = until {
        argv.push("--until".into());
        argv.push(u);
    }
    if let Some(u) = unit {
        argv.push("-u".into());
        argv.push(u);
    }
    if let Some(p) = priority {
        argv.push("-p".into());
        argv.push(p);
    }
    if let Some(p) = pattern {
        argv.push(format!("--grep={p}"));
        if args.ignore_case {
            argv.push("--case-sensitive=false".into());
        }
    }
    if args.kernel_only {
        argv.push("-k".into());
    }
    argv.push("-n".into());
    argv.push(lines.to_string());

    // Defence in depth: refuse if any caller-controlled value somehow
    // produced a follow flag (`-f` / `--follow` would block until timeout)
    // or `--exec`-style escape.
    debug_assert!(!argv.iter().any(|a| {
        a == "-f" || a == "--follow" || a.starts_with("--exec")
    }));

    spawn_capped(argv, Some(lines as usize)).await
}

#[derive(Debug, Deserialize)]
pub struct ListOpenFilesArgs {
    /// At least one of `pid`, `port`, or `path` must be set; we refuse to
    /// run an unfiltered `lsof` because the output is enormous on busy
    /// hosts and leaks every fd of every process.
    #[serde(default)]
    pub pid: Option<u64>,
    #[serde(default)]
    pub port: Option<u64>,
    /// Restricts a `port` filter to a single protocol. Optional. Without
    /// it, `lsof` matches both TCP and UDP for the given port.
    #[serde(default)]
    pub proto: Option<String>,
    /// Show open files under this directory (`lsof +D <path>`). Useful for
    /// catching staging dirs and processes holding deleted files.
    #[serde(default)]
    pub path: Option<String>,
    /// Max output lines. Default 200, hard cap 2000.
    #[serde(default)]
    pub limit: Option<u64>,
}

pub async fn run_list_open_files(args: &ListOpenFilesArgs) -> Result<HostExecOutput, HostExecError> {
    if args.pid.is_none() && args.port.is_none() && args.path.is_none() {
        return Err(HostExecError::BadArg(
            "at least one of pid, port, or path must be set".into(),
        ));
    }

    // `lsof` lives in `/usr/bin` on Debian/Ubuntu/Alpine and `/usr/sbin`
    // on RHEL. PATH set in `spawn_capped` covers both.
    let mut argv: Vec<String> = vec!["lsof".into(), "-nP".into()];

    if let Some(pid_raw) = args.pid {
        let pid = validate_pid(pid_raw)?;
        argv.push("-p".into());
        argv.push(pid.to_string());
    }
    if let Some(port_raw) = args.port {
        let port = validate_port(port_raw)?;
        let proto = match args.proto.as_deref() {
            None => "",
            Some(p) => validate_choice(p, "proto", &["tcp", "udp"])?,
        };
        let spec = if proto.is_empty() {
            format!(":{port}")
        } else {
            format!("{proto}:{port}")
        };
        argv.push("-i".into());
        argv.push(spec);
    } else if args.proto.is_some() {
        return Err(HostExecError::BadArg(
            "proto is only meaningful with port".into(),
        ));
    }
    if let Some(p) = &args.path {
        let p = validate_path(p)?;
        argv.push("+D".into());
        argv.push(p);
    }

    let limit = cap_int(args.limit, 200, 2_000) as usize;
    spawn_capped(argv, Some(limit)).await
}

#[derive(Debug, Deserialize)]
pub struct ListSocketsArgs {
    /// Include TCP sockets. Default true.
    #[serde(default = "default_true")]
    pub tcp: bool,
    /// Include UDP sockets. Default true.
    #[serde(default = "default_true")]
    pub udp: bool,
    /// Restrict to listening sockets. Default false (shows established too).
    #[serde(default)]
    pub listening_only: bool,
    /// Max output lines. Default 500, hard cap 5000.
    #[serde(default)]
    pub limit: Option<u64>,
}

fn default_true() -> bool {
    true
}

pub async fn run_list_sockets(args: &ListSocketsArgs) -> Result<HostExecOutput, HostExecError> {
    if !args.tcp && !args.udp {
        return Err(HostExecError::BadArg(
            "at least one of tcp/udp must be true".into(),
        ));
    }

    // Always: -n (numeric, no DNS) -p (with process). Never `-K` (kills
    // sockets) or `-E` (exec).
    let mut argv: Vec<String> = vec!["ss".into(), "-n".into(), "-p".into()];
    if args.tcp {
        argv.push("-t".into());
    }
    if args.udp {
        argv.push("-u".into());
    }
    if args.listening_only {
        argv.push("-l".into());
    } else {
        argv.push("-a".into());
    }

    debug_assert!(!argv.iter().any(|a| a == "-K" || a == "--kill" || a == "-E" || a == "--exec"));

    let limit = cap_int(args.limit, 500, 5_000) as usize;
    spawn_capped(argv, Some(limit)).await
}

#[derive(Debug, Deserialize)]
pub struct StatFileArgs {
    pub path: String,
}

pub async fn run_stat_file(args: &StatFileArgs) -> Result<HostExecOutput, HostExecError> {
    let path = validate_path(&args.path)?;
    let argv: Vec<String> = vec!["/usr/bin/stat".into(), "--".into(), path];
    spawn_capped(argv, None).await
}

#[derive(Debug, Deserialize)]
pub struct HashFileArgs {
    pub path: String,
}

/// Compute SHA-256 + libmagic mime classification for a file. The two
/// utilities run sequentially (one spawn each) and we merge their output
/// into a single stdout block so the LLM sees a stable shape:
///
/// ```text
/// sha256: <64 hex>
/// type:   <libmagic description>
/// ```
pub async fn run_hash_file(args: &HashFileArgs) -> Result<HostExecOutput, HostExecError> {
    let path = validate_path(&args.path)?;

    // sha256sum: reads the whole file. Wall timeout (30s) protects against
    // multi-GB files. Output is a single line of 64 hex + 2 spaces + path.
    let sha = spawn_capped(
        vec![
            "/usr/bin/sha256sum".into(),
            "--".into(),
            path.clone(),
        ],
        None,
    )
    .await?;

    // file --brief: classifies via libmagic. Trivial bytes/cpu.
    let kind = spawn_capped(
        vec![
            "/usr/bin/file".into(),
            "--brief".into(),
            "--".into(),
            path.clone(),
        ],
        None,
    )
    .await?;

    let sha_line = sha.stdout.lines().next().unwrap_or("").trim();
    let sha_hex = sha_line.split_whitespace().next().unwrap_or("");
    let kind_line = kind.stdout.lines().next().unwrap_or("").trim();

    let merged = format!(
        "sha256: {sha_hex}\ntype:   {kind_line}\npath:   {path}\n"
    );
    let merged_stderr = if !sha.stderr.is_empty() {
        sha.stderr
    } else {
        kind.stderr
    };
    let exit = if sha.exit_code != 0 {
        sha.exit_code
    } else {
        kind.exit_code
    };

    Ok(HostExecOutput {
        stdout: merged,
        stderr: merged_stderr,
        exit_code: exit,
        truncated: sha.truncated || kind.truncated,
        duration_ms: sha.duration_ms + kind.duration_ms,
        error_message: if sha.error_message.is_empty() {
            kind.error_message
        } else {
            sha.error_message
        },
        // The two runs are independent; surface them as a logical-AND
        // chain so the audit reads as one paste-able pipeline.
        command_line: format!("{} && {}", sha.command_line, kind.command_line),
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct ListModulesArgs {}

pub async fn run_list_modules(_args: &ListModulesArgs) -> Result<HostExecOutput, HostExecError> {
    // `lsmod` reads `/proc/modules` and pretty-prints. It can live in
    // /sbin or /usr/sbin depending on distro — let PATH find it.
    let argv: Vec<String> = vec!["lsmod".into()];
    spawn_capped(argv, None).await
}

#[derive(Debug, Deserialize)]
pub struct LoginHistoryArgs {
    /// One of: `last` | `lastlog` | `who` | `btmp`.
    pub kind: String,
    /// Max entries to return (only honoured for `last`/`btmp`). Default 50,
    /// hard cap 1000.
    #[serde(default)]
    pub limit: Option<u64>,
}

pub async fn run_login_history(args: &LoginHistoryArgs) -> Result<HostExecOutput, HostExecError> {
    let kind = validate_choice(&args.kind, "kind", &["last", "lastlog", "who", "btmp"])?;
    let limit = cap_int(args.limit, 50, 1_000);

    let argv: Vec<String> = match kind {
        "last" => vec![
            "/usr/bin/last".into(),
            "-F".into(),
            "-w".into(),
            "-n".into(),
            limit.to_string(),
        ],
        "btmp" => vec![
            "/usr/bin/last".into(),
            "-F".into(),
            "-w".into(),
            "-n".into(),
            limit.to_string(),
            "-f".into(),
            "/var/log/btmp".into(),
        ],
        "lastlog" => vec!["/usr/bin/lastlog".into()],
        "who" => vec!["/usr/bin/who".into(), "-a".into()],
        _ => unreachable!("validate_choice guarantees one of the above"),
    };

    spawn_capped(argv, Some(limit as usize)).await
}

#[derive(Debug, Deserialize)]
pub struct ShowNetworkArgs {
    /// One of: `addr` | `route` | `neigh` | `link`. Maps to
    /// `ip <kind> show`.
    pub kind: String,
}

pub async fn run_show_network(args: &ShowNetworkArgs) -> Result<HostExecOutput, HostExecError> {
    let kind = validate_choice(&args.kind, "kind", &["addr", "route", "neigh", "link"])?;
    // `-j` gives JSON output. `ip` lives in /sbin or /usr/sbin; let PATH
    // find it. We pin the subcommand to `show` — never `add`/`del`/`flush`/
    // `change`/`replace`.
    let argv: Vec<String> = vec![
        "ip".into(),
        "-j".into(),
        kind.to_string(),
        "show".into(),
    ];
    debug_assert!(!argv
        .iter()
        .any(|a| matches!(a.as_str(), "add" | "del" | "delete" | "change" | "replace" | "flush")));
    spawn_capped(argv, None).await
}

// ─── spawn helper ───────────────────────────────────────────────────────────

/// Spawn an argv with no shell, capturing stdout/stderr with byte caps and a
/// wall-clock timeout. If `max_lines` is set, also truncates stdout after
/// that many newline-separated lines.
async fn spawn_capped(
    argv: Vec<String>,
    max_lines: Option<usize>,
) -> Result<HostExecOutput, HostExecError> {
    if argv.is_empty() {
        return Err(HostExecError::BadArg("empty argv".into()));
    }
    debug!(?argv, "host_exec: spawning");

    let started = Instant::now();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    // Don't inherit any environment beyond a sane minimum. This stops the
    // child from reading e.g. `LD_PRELOAD` set by an attacker who already
    // managed to write to `/etc/environment`.
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("LC_ALL", "C");

    let mut child: Child = cmd
        .spawn()
        .map_err(|e| HostExecError::Spawn(format!("{}: {e}", argv[0])))?;
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");

    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::with_capacity(8 * 1024);
        let mut chunk = [0u8; 8 * 1024];
        let mut truncated = false;
        loop {
            let n = match stdout_pipe.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if buf.len() + n > STDOUT_CAP {
                let take = STDOUT_CAP.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..take]);
                truncated = true;
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        (buf, truncated)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::with_capacity(2 * 1024);
        let mut chunk = [0u8; 4 * 1024];
        loop {
            let n = match stderr_pipe.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if buf.len() + n > STDERR_CAP {
                let take = STDERR_CAP.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..take]);
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        buf
    });

    let wait_res = tokio::time::timeout(WALL_TIMEOUT, child.wait()).await;
    let (status, timed_out) = match wait_res {
        Ok(Ok(s)) => (Some(s), false),
        Ok(Err(e)) => {
            warn!(error = %e, "host_exec: wait failed");
            (None, false)
        }
        Err(_) => {
            warn!(?argv, "host_exec: wall-clock timeout, killing child");
            let _ = child.kill().await;
            (None, true)
        }
    };

    let (stdout_bytes, mut truncated) = stdout_task.await.unwrap_or_default();
    let stderr_bytes = stderr_task.await.unwrap_or_default();
    let duration_ms = started.elapsed().as_millis() as i64;

    let mut stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    if let Some(max) = max_lines {
        let mut count = 0usize;
        let mut cut = stdout.len();
        for (i, b) in stdout.bytes().enumerate() {
            if b == b'\n' {
                count += 1;
                if count >= max {
                    cut = i + 1;
                    break;
                }
            }
        }
        if cut < stdout.len() {
            stdout.truncate(cut);
            truncated = true;
        }
    }

    let exit_code = status
        .as_ref()
        .and_then(|s| s.code())
        .unwrap_or(if timed_out { 124 } else { -1 });
    let error_message = if timed_out {
        format!("timeout after {}s", WALL_TIMEOUT.as_secs())
    } else {
        String::new()
    };

    Ok(HostExecOutput {
        stdout,
        stderr,
        exit_code,
        truncated,
        duration_ms,
        error_message,
        command_line: shell_quote_argv(&argv),
    })
}

/// Render an argv as a shell-paste-safe single line. Used purely for UI /
/// audit display — we never feed this back into a shell on the agent. Each
/// element gets POSIX single-quote escaping so that paths containing
/// spaces, quotes, `$`, `(`, etc. round-trip safely.
fn shell_quote_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(s: &str) -> String {
    // Fast path: bareword-safe characters need no quoting.
    let safe = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '-' | '/' | '.' | '=' | ':' | '+' | ',' | '@' | '%')
        });
    if safe {
        return s.to_string();
    }
    // Use single quotes; embedded `'` becomes `'\''`.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::{shell_quote, shell_quote_argv};

    #[test]
    fn quote_passes_barewords_through() {
        assert_eq!(shell_quote("ls"), "ls");
        assert_eq!(shell_quote("/usr/bin/ls"), "/usr/bin/ls");
        assert_eq!(shell_quote("--no-pager"), "--no-pager");
        assert_eq!(shell_quote("user@host"), "user@host");
        assert_eq!(shell_quote("k=v"), "k=v");
        assert_eq!(shell_quote("a,b"), "a,b");
        assert_eq!(shell_quote("100%"), "100%");
    }

    #[test]
    fn quote_wraps_special_chars_in_single_quotes() {
        // Empty string still needs quoting so it survives shell parsing as
        // an explicit empty argument rather than vanishing.
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("hello world"), "'hello world'");
        assert_eq!(shell_quote("a$b"), "'a$b'");
        assert_eq!(shell_quote("`whoami`"), "'`whoami`'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote("a;b"), "'a;b'");
        assert_eq!(shell_quote("a|b"), "'a|b'");
        assert_eq!(shell_quote("a&b"), "'a&b'");
        assert_eq!(shell_quote("a>b"), "'a>b'");
        assert_eq!(shell_quote("~/foo"), "'~/foo'");
        // History expansion / glob chars are inert inside single quotes.
        assert_eq!(shell_quote("rm -rf !"), "'rm -rf !'");
        assert_eq!(shell_quote("*.txt"), "'*.txt'");
    }

    #[test]
    fn quote_escapes_embedded_single_quote() {
        // POSIX-portable escape: close-quote, escaped quote, reopen-quote.
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        // Two adjacent quotes round-trip too.
        assert_eq!(shell_quote("a''b"), "'a'\\'''\\''b'");
    }

    #[test]
    fn quote_handles_utf8_and_control_chars() {
        // Non-ASCII drops to single-quote path; codepoints survive verbatim.
        assert_eq!(shell_quote("приве т"), "'приве т'");
        assert_eq!(shell_quote("emoji 🚀"), "'emoji 🚀'");
        // NUL is impossible because validators reject it; a literal newline
        // is still rendered inside single quotes (interpreted as embedded
        // newline by any POSIX shell that parses the result).
        assert_eq!(shell_quote("a\nb"), "'a\nb'");
    }

    #[test]
    fn argv_joined_with_single_space() {
        let argv = vec![
            "/usr/bin/journalctl".to_string(),
            "--no-pager".to_string(),
            "--since".to_string(),
            "2024-01-01 12:00:00 UTC".to_string(),
            "-n".to_string(),
            "200".to_string(),
        ];
        assert_eq!(
            shell_quote_argv(&argv),
            "/usr/bin/journalctl --no-pager --since '2024-01-01 12:00:00 UTC' -n 200"
        );
    }

    #[test]
    fn argv_with_quotes_and_specials() {
        let argv = vec![
            "/usr/bin/grep".to_string(),
            "--".to_string(),
            "it's a $trap".to_string(),
            "/var/log/auth.log".to_string(),
        ];
        assert_eq!(
            shell_quote_argv(&argv),
            "/usr/bin/grep -- 'it'\\''s a $trap' /var/log/auth.log"
        );
    }
}
