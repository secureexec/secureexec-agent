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
use super::validate::{cap_int, validate_filter_token, validate_path, validate_pattern};
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
    })
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
    })
}
