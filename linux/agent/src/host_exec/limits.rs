//! Hard caps for every host-exec invocation.
//!
//! These bound runtime, memory pressure, and the size of the row written to
//! Postgres on the way back. The defaults are intentionally tight — an AI
//! investigation tool shouldn't need megabytes of stdout to reason about a
//! host. The agent will truncate (and mark `truncated = true`) before
//! exceeding any of these.

use std::time::Duration;

/// Wall-clock timeout for any single host-exec command. The agent SIGKILLs
/// the child if it exceeds this and returns whatever output was captured so
/// far with `truncated = true`.
pub const WALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum stdout bytes captured from the child. Anything beyond this is
/// dropped on the floor and the `truncated` flag is set. 1 MiB is much more
/// than the LLM tool path will keep anyway (`MAX_TOOL_RESULT_CHARS` ≈ 12k),
/// but we want to give the analyst-facing audit log enough context.
pub const STDOUT_CAP: usize = 1024 * 1024;

/// Maximum stderr bytes captured. stderr is generally small for read-only
/// tools (find/grep print errors per inaccessible entry).
pub const STDERR_CAP: usize = 64 * 1024;

/// Maximum number of bytes [`run_read_file`] will return from a single file
/// when neither `head_lines`, `tail_lines`, nor `max_bytes` is provided.
pub const READ_FILE_DEFAULT_BYTES: u64 = 64 * 1024;

/// Hard ceiling on `host_read_file.max_bytes` regardless of what the caller
/// asked for. Stays under `STDOUT_CAP` so we never have to truncate twice.
pub const READ_FILE_MAX_BYTES: u64 = 512 * 1024;
