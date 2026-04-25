use std::collections::HashMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Shared types (used by both TracefsValidator and BtfStructValidator)
// ---------------------------------------------------------------------------

/// Discriminates the source of an `OffsetMismatch`.
#[derive(Debug)]
pub enum MismatchKind {
    /// Problem with a tracepoint format field (offset/size or missing tracepoint).
    Tracepoint,
    /// Problem with a kernel struct field (offset/size or missing struct/field).
    Struct,
    /// Whole-validator failure: tracefs or BTF is unavailable.
    Source,
}

/// A single BPF ABI sanity-check failure, produced by either validator.
pub struct OffsetMismatch {
    pub kind: MismatchKind,
    /// Tracepoint program name (e.g. "task_newtask") or struct name (e.g. "sock_common"),
    /// or validator name for Source failures.
    pub label: String,
    /// Field name, or "" for whole-source failures.
    pub field: String,
    pub expected_offset: Option<usize>,
    pub actual_offset:   Option<usize>,
    pub expected_size:   Option<usize>,
    pub actual_size:     Option<usize>,
    /// Machine-readable reason code for log filtering.
    /// One of: "offset_mismatch", "size_mismatch", "tracepoint_missing",
    /// "format_unparsable", "tracefs_unavailable",
    /// "btf_unavailable", "struct_missing", "field_missing".
    pub reason: &'static str,
}

// ---------------------------------------------------------------------------
// Tracepoint format validator
// ---------------------------------------------------------------------------

/// Expected offset+size for one field within a tracepoint's raw buffer.
pub struct ExpectedField {
    pub field:  &'static str,
    pub offset: usize,
    pub size:   usize,
}

impl ExpectedField {
    /// Field spec for a `sys_enter_*` syscall argument at index `idx`.
    ///
    /// On 64-bit kernels every syscall arg is stored at full register width
    /// (`unsigned long`, 8 bytes), regardless of the C type declaration —
    /// the slot starts at offset `16 + 8*idx` after the 16-byte common
    /// header + `__syscall_nr` slot.
    pub const fn syscall_arg(field: &'static str, idx: usize) -> Self {
        Self { field, offset: 16 + 8 * idx, size: 8 }
    }

    /// Field spec for a `__data_loc` field that immediately follows the
    /// 8-byte common tracepoint header (`__field`-less tracepoints whose
    /// first declared entry is `__string`/`__data_loc`).
    pub const fn data_loc(field: &'static str) -> Self {
        Self { field, offset: 8, size: 4 }
    }
}

/// One tracepoint we validate at startup.
pub struct TracepointSpec {
    /// Name used in log messages (usually the BPF program function name).
    pub program:  &'static str,
    pub category: &'static str,
    pub name:     &'static str,
    pub fields:   &'static [ExpectedField],
}

/// Validates that the kernel's tracefs format files agree with the offsets
/// hard-coded in the eBPF programs.
///
/// `new()` always succeeds; if tracefs is unavailable the first call to
/// `validate_all` returns a single `MismatchKind::Source` entry.
pub struct TracefsValidator {
    /// None if neither tracefs mount was found.
    base: Option<PathBuf>,
}

impl TracefsValidator {
    pub fn new() -> Self {
        // Prefer the modern non-debugfs mount.
        for candidate in &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
            let p = PathBuf::from(candidate);
            if p.join("events").exists() {
                return Self { base: Some(p) };
            }
        }
        Self { base: None }
    }

    /// Validate all specs.  Returns one `OffsetMismatch` per problem found.
    pub fn validate_all(&self, specs: &[TracepointSpec]) -> Vec<OffsetMismatch> {
        let base = match &self.base {
            Some(b) => b,
            None => {
                return vec![OffsetMismatch {
                    kind:            MismatchKind::Source,
                    label:           "tracefs".into(),
                    field:           String::new(),
                    expected_offset: None,
                    actual_offset:   None,
                    expected_size:   None,
                    actual_size:     None,
                    reason:          "tracefs_unavailable",
                }];
            }
        };

        let mut out = Vec::new();
        for spec in specs {
            match self.parse_format(base, spec.category, spec.name) {
                Err(_) => {
                    // File absent = tracepoint not compiled into this kernel.
                    let reason = if base
                        .join("events")
                        .join(spec.category)
                        .join(spec.name)
                        .join("format")
                        .exists()
                    {
                        "format_unparsable"
                    } else {
                        "tracepoint_missing"
                    };
                    out.push(OffsetMismatch {
                        kind:            MismatchKind::Tracepoint,
                        label:           spec.program.into(),
                        field:           String::new(),
                        expected_offset: None,
                        actual_offset:   None,
                        expected_size:   None,
                        actual_size:     None,
                        reason,
                    });
                }
                Ok(actual_fields) => {
                    for ef in spec.fields {
                        match actual_fields.get(ef.field) {
                            None => {
                                out.push(OffsetMismatch {
                                    kind:            MismatchKind::Tracepoint,
                                    label:           spec.program.into(),
                                    field:           ef.field.into(),
                                    expected_offset: Some(ef.offset),
                                    actual_offset:   None,
                                    expected_size:   Some(ef.size),
                                    actual_size:     None,
                                    reason:          "tracepoint_missing",
                                });
                            }
                            Some(&(actual_off, actual_sz)) => {
                                if actual_off != ef.offset {
                                    out.push(OffsetMismatch {
                                        kind:            MismatchKind::Tracepoint,
                                        label:           spec.program.into(),
                                        field:           ef.field.into(),
                                        expected_offset: Some(ef.offset),
                                        actual_offset:   Some(actual_off),
                                        expected_size:   Some(ef.size),
                                        actual_size:     Some(actual_sz),
                                        reason:          "offset_mismatch",
                                    });
                                } else if actual_sz != ef.size {
                                    out.push(OffsetMismatch {
                                        kind:            MismatchKind::Tracepoint,
                                        label:           spec.program.into(),
                                        field:           ef.field.into(),
                                        expected_offset: Some(ef.offset),
                                        actual_offset:   Some(actual_off),
                                        expected_size:   Some(ef.size),
                                        actual_size:     Some(actual_sz),
                                        reason:          "size_mismatch",
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Parse the kernel's tracefs `format` file for `<category>/<name>`.
    ///
    /// Returns a map from field name → (offset_bytes, size_bytes), or Err if
    /// the file cannot be read or no field lines were found.
    ///
    /// Format lines look like (tab-separated):
    ///   `\tfield:unsigned long clone_flags;\toffset:32;\tsize:8;\tsigned:0;`
    fn parse_format(
        &self,
        base: &PathBuf,
        category: &str,
        name: &str,
    ) -> Result<HashMap<String, (usize, usize)>, String> {
        let path = base.join("events").join(category).join(name).join("format");
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: {}", path.display(), e))?;

        let mut fields = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with("field:") {
                continue;
            }
            // Parse offset and size from the semicolon-separated segments.
            let offset = Self::extract_kv(line, "offset:");
            let size   = Self::extract_kv(line, "size:");
            let (offset, size) = match (offset, size) {
                (Some(o), Some(s)) => (o, s),
                _ => continue,
            };
            // Extract field name: last word before the first `;` in the
            // `field:…;` segment, stripping array brackets.
            let field_seg = line.split(';').next().unwrap_or("");
            let field_name = field_seg
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_end_matches(|c: char| c == ']' || c.is_ascii_digit())
                .trim_end_matches('[');
            if field_name.is_empty() {
                continue;
            }
            fields.insert(field_name.to_string(), (offset, size));
        }

        if fields.is_empty() {
            return Err(format!("{}: no field lines parsed", path.display()));
        }
        Ok(fields)
    }

    /// Extract the numeric value after `key` in a semicolon-separated line.
    /// E.g. `extract_kv("…\toffset:32;\tsize:8;…", "offset:")` → Some(32).
    fn extract_kv(line: &str, key: &str) -> Option<usize> {
        let start = line.find(key)? + key.len();
        let rest = &line[start..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().ok()
    }
}

// ---------------------------------------------------------------------------
// Validated tracepoints (all programs that use hard-coded ctx.read_at offsets)
// ---------------------------------------------------------------------------

/// Compact constructor for a `syscalls/<name>` tracepoint spec whose program
/// name matches `<name>` and whose fields all use the syscall-arg ABI
/// (offset = 16 + 8*idx, size 8).
const fn syscall(name: &'static str, fields: &'static [ExpectedField]) -> TracepointSpec {
    TracepointSpec { program: name, category: "syscalls", name, fields }
}

/// All tracepoints whose raw-buffer offsets are hard-coded in the eBPF
/// programs.  Every entry corresponds to an `attach_tracepoint(...)` call in
/// `loader.rs::load_ebpf` and matches `ctx.read_at(N)` reads in the kernel
/// program.  Validated at agent startup; any mismatch is reported as a
/// critical anomaly via the heartbeat counter and structured error log.
pub const VALIDATED_TRACEPOINTS: &[TracepointSpec] = &[
    // ==========================================================
    // process.rs
    // ==========================================================

    // sched/sched_process_exec — data_loc filename @ offset 8.
    TracepointSpec {
        program:  "sched_process_exec",
        category: "sched",
        name:     "sched_process_exec",
        fields:   &[ExpectedField::data_loc("filename")],
    },
    // sched/sched_process_exit — required for ProcessExit events; we don't
    // read any field via ctx.read_at, but presence of the tracepoint is
    // mandatory.  Existence-only validation (empty fields list).
    TracepointSpec {
        program:  "sched_process_exit",
        category: "sched",
        name:     "sched_process_exit",
        fields:   &[],
    },
    syscall("sys_enter_execve", &[
        ExpectedField::syscall_arg("argv", 1),
        ExpectedField::syscall_arg("envp", 2),
    ]),
    syscall("sys_enter_exit_group", &[
        ExpectedField::syscall_arg("error_code", 0),
    ]),
    // task/task_newtask — non-syscall tracepoint with a custom layout.
    // pid@8 (size 4), comm[16]@12 (size 16), then 4 bytes of padding to
    // align clone_flags as `unsigned long` at offset 32.
    TracepointSpec {
        program:  "task_newtask",
        category: "task",
        name:     "task_newtask",
        fields:   &[
            ExpectedField { field: "pid",         offset: 8,  size: 4  },
            ExpectedField { field: "comm",        offset: 12, size: 16 },
            ExpectedField { field: "clone_flags", offset: 32, size: 8  },
        ],
    },

    // ==========================================================
    // file.rs
    // ==========================================================

    syscall("sys_enter_openat", &[
        ExpectedField::syscall_arg("filename", 1),
        ExpectedField::syscall_arg("flags",    2),
    ]),
    syscall("sys_enter_unlinkat", &[
        ExpectedField::syscall_arg("pathname", 1),
    ]),
    syscall("sys_enter_renameat2", &[
        ExpectedField::syscall_arg("oldname", 1),
        ExpectedField::syscall_arg("newname", 3),
    ]),

    // ==========================================================
    // network.rs (tracepoints; kprobe symbol presence is enforced
    // implicitly by the program load + attach phase)
    // ==========================================================

    syscall("sys_enter_sendto", &[
        ExpectedField::syscall_arg("buff", 1),
        ExpectedField::syscall_arg("len",  2),
        ExpectedField::syscall_arg("addr", 4),
    ]),
    syscall("sys_enter_sendmsg", &[
        ExpectedField::syscall_arg("msg", 1),
    ]),
    syscall("sys_enter_sendmmsg", &[
        ExpectedField::syscall_arg("mmsg", 1),
        ExpectedField::syscall_arg("vlen", 2),
    ]),

    // ==========================================================
    // security.rs
    // ==========================================================

    // privilege transitions
    syscall("sys_enter_setuid",    &[ExpectedField::syscall_arg("uid", 0)]),
    syscall("sys_enter_setgid",    &[ExpectedField::syscall_arg("gid", 0)]),
    syscall("sys_enter_setreuid",  &[
        ExpectedField::syscall_arg("ruid", 0),
        ExpectedField::syscall_arg("euid", 1),
    ]),
    syscall("sys_enter_setregid",  &[
        ExpectedField::syscall_arg("rgid", 0),
        ExpectedField::syscall_arg("egid", 1),
    ]),
    syscall("sys_enter_setresuid", &[
        ExpectedField::syscall_arg("ruid", 0),
        ExpectedField::syscall_arg("euid", 1),
        ExpectedField::syscall_arg("suid", 2),
    ]),
    syscall("sys_enter_setresgid", &[
        ExpectedField::syscall_arg("rgid", 0),
        ExpectedField::syscall_arg("egid", 1),
        ExpectedField::syscall_arg("sgid", 2),
    ]),
    // process inspection / control
    syscall("sys_enter_ptrace", &[
        ExpectedField::syscall_arg("request", 0),
        ExpectedField::syscall_arg("pid",     1),
    ]),
    syscall("sys_enter_process_vm_readv",  &[ExpectedField::syscall_arg("pid", 0)]),
    syscall("sys_enter_process_vm_writev", &[ExpectedField::syscall_arg("pid", 0)]),
    syscall("sys_enter_kill", &[
        ExpectedField::syscall_arg("pid", 0),
        ExpectedField::syscall_arg("sig", 1),
    ]),
    // file-permission / ownership / linking
    syscall("sys_enter_fchmodat", &[
        ExpectedField::syscall_arg("filename", 1),
        ExpectedField::syscall_arg("mode",     2),
    ]),
    syscall("sys_enter_chown", &[
        ExpectedField::syscall_arg("filename", 0),
        ExpectedField::syscall_arg("user",     1),
        ExpectedField::syscall_arg("group",    2),
    ]),
    syscall("sys_enter_lchown", &[
        ExpectedField::syscall_arg("filename", 0),
        ExpectedField::syscall_arg("user",     1),
        ExpectedField::syscall_arg("group",    2),
    ]),
    syscall("sys_enter_symlinkat", &[
        ExpectedField::syscall_arg("oldname", 0),
        ExpectedField::syscall_arg("newname", 2),
    ]),
    syscall("sys_enter_linkat", &[
        ExpectedField::syscall_arg("oldname", 1),
        ExpectedField::syscall_arg("newname", 3),
    ]),
    // memory / capabilities
    syscall("sys_enter_mmap", &[
        ExpectedField::syscall_arg("addr",  0),
        ExpectedField::syscall_arg("len",   1),
        ExpectedField::syscall_arg("prot",  2),
        ExpectedField::syscall_arg("flags", 3),
    ]),
    syscall("sys_enter_memfd_create", &[
        ExpectedField::syscall_arg("uname", 0),
        ExpectedField::syscall_arg("flags", 1),
    ]),
    syscall("sys_enter_capset", &[
        ExpectedField::syscall_arg("header", 0),
        ExpectedField::syscall_arg("data",   1),
    ]),
    // namespaces / mount
    syscall("sys_enter_unshare", &[
        ExpectedField::syscall_arg("unshare_flags", 0),
    ]),
    syscall("sys_enter_setns", &[
        ExpectedField::syscall_arg("fd",     0),
        ExpectedField::syscall_arg("nstype", 1),
    ]),
    syscall("sys_enter_mount", &[
        ExpectedField::syscall_arg("dev_name", 0),
        ExpectedField::syscall_arg("dir_name", 1),
        ExpectedField::syscall_arg("type",     2),
        ExpectedField::syscall_arg("flags",    3),
    ]),
    syscall("sys_enter_umount", &[
        ExpectedField::syscall_arg("name",  0),
        ExpectedField::syscall_arg("flags", 1),
    ]),
    // misc
    syscall("sys_enter_bpf",            &[ExpectedField::syscall_arg("cmd",     0)]),
    syscall("sys_enter_keyctl",         &[ExpectedField::syscall_arg("option",  0)]),
    syscall("sys_enter_io_uring_setup", &[ExpectedField::syscall_arg("entries", 0)]),
    // module/module_load — `taints` is `__field` first, then `name` is
    // `__data_loc` at offset 12.  This was previously read at offset 8 in
    // security.rs (a bug); the eBPF program now reads at 12 to match.
    TracepointSpec {
        program:  "module_load",
        category: "module",
        name:     "module_load",
        fields:   &[ExpectedField { field: "name", offset: 12, size: 4 }],
    },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Realistic snapshot of /sys/kernel/tracing/events/task/task_newtask/format
    /// from a Linux 6.x kernel — tab-indented, with array brackets and a
    /// trailing print fmt line that must be ignored.
    const TASK_NEWTASK_FORMAT: &str = "name: task_newtask\n\
ID: 117\n\
format:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
\n\
\tfield:pid_t pid;\toffset:8;\tsize:4;\tsigned:1;\n\
\tfield:char comm[16];\toffset:12;\tsize:16;\tsigned:0;\n\
\tfield:unsigned long clone_flags;\toffset:32;\tsize:8;\tsigned:0;\n\
\tfield:short oom_score_adj;\toffset:40;\tsize:2;\tsigned:1;\n\
\n\
print fmt: \"pid=%d comm=%s clone_flags=%lx oom_score_adj=%hd\", REC->pid, REC->comm, REC->clone_flags, REC->oom_score_adj\n";

    /// Realistic snapshot of sys_enter_execve — uses `__data_loc` encoding for
    /// filename and pointer types for argv/envp.
    const SYS_ENTER_EXECVE_FORMAT: &str = "name: sys_enter_execve\n\
ID: 705\n\
format:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n\
\tfield:const char * filename;\toffset:16;\tsize:8;\tsigned:0;\n\
\tfield:const char *const * argv;\toffset:24;\tsize:8;\tsigned:0;\n\
\tfield:const char *const * envp;\toffset:32;\tsize:8;\tsigned:0;\n\
\n\
print fmt: \"filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx\", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))\n";

    /// Tiny RAII temp-dir wrapper to avoid pulling in tempfile as a dev-dep.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let mut p = std::env::temp_dir();
            p.push(format!("secureexec_{}_{}_{}_{}", label, pid, seq,
                           std::time::SystemTime::now()
                               .duration_since(std::time::UNIX_EPOCH)
                               .map(|d| d.as_nanos() as u64).unwrap_or(0)));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &std::path::Path { &self.0 }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Build a temporary tracefs hierarchy with the provided format files.
    fn make_tracefs(formats: &[(&str, &str, &str)]) -> TmpDir {
        let dir = TmpDir::new("tracefs_test");
        for (cat, name, body) in formats {
            let p = dir.path().join("events").join(cat).join(name);
            fs::create_dir_all(&p).unwrap();
            let mut f = fs::File::create(p.join("format")).unwrap();
            f.write_all(body.as_bytes()).unwrap();
        }
        dir
    }

    fn validator_with_base(base: PathBuf) -> TracefsValidator {
        TracefsValidator { base: Some(base) }
    }

    #[test]
    fn parses_typical_format_file() {
        let dir = make_tracefs(&[
            ("task", "task_newtask", TASK_NEWTASK_FORMAT),
        ]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "task_newtask",
                category: "task",
                name:     "task_newtask",
                fields:   &[
                    ExpectedField { field: "pid",         offset: 8,  size: 4  },
                    ExpectedField { field: "comm",        offset: 12, size: 16 },
                    ExpectedField { field: "clone_flags", offset: 32, size: 8  },
                ],
            },
        ]);
        assert!(r.is_empty(), "unexpected mismatches: {:?}",
                r.iter().map(|m| (&m.field, m.reason)).collect::<Vec<_>>());
    }

    #[test]
    fn flags_offset_size_and_missing_field() {
        let dir = make_tracefs(&[
            ("task", "task_newtask", TASK_NEWTASK_FORMAT),
        ]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "task_newtask",
                category: "task",
                name:     "task_newtask",
                fields:   &[
                    // wrong offset
                    ExpectedField { field: "pid",         offset: 0,  size: 4  },
                    // wrong size
                    ExpectedField { field: "clone_flags", offset: 32, size: 4  },
                    // not in tracepoint
                    ExpectedField { field: "no_such_field", offset: 0, size: 1 },
                ],
            },
        ]);
        let by_field: std::collections::HashMap<&str, &OffsetMismatch> =
            r.iter().map(|m| (m.field.as_str(), m)).collect();
        assert_eq!(by_field["pid"].reason,           "offset_mismatch");
        assert_eq!(by_field["pid"].actual_offset,    Some(8));
        assert_eq!(by_field["clone_flags"].reason,   "size_mismatch");
        assert_eq!(by_field["clone_flags"].actual_size, Some(8));
        assert_eq!(by_field["no_such_field"].reason, "tracepoint_missing");
    }

    #[test]
    fn missing_format_file_reports_tracepoint_missing() {
        let dir = make_tracefs(&[]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "task_newtask",
                category: "task",
                name:     "task_newtask",
                fields:   &[ExpectedField { field: "pid", offset: 8, size: 4 }],
            },
        ]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].reason, "tracepoint_missing");
        assert!(matches!(r[0].kind, MismatchKind::Tracepoint));
        assert_eq!(r[0].label, "task_newtask");
    }

    #[test]
    fn empty_format_file_reports_format_unparsable() {
        let dir = make_tracefs(&[("task", "task_newtask", "name: task_newtask\nID: 1\n")]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "task_newtask",
                category: "task",
                name:     "task_newtask",
                fields:   &[ExpectedField { field: "pid", offset: 8, size: 4 }],
            },
        ]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].reason, "format_unparsable");
    }

    #[test]
    fn tracefs_unavailable_when_base_missing() {
        let v = TracefsValidator { base: None };
        let r = v.validate_all(VALIDATED_TRACEPOINTS);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].reason, "tracefs_unavailable");
        assert!(matches!(r[0].kind, MismatchKind::Source));
    }

    #[test]
    fn handles_pointer_and_data_loc_field_names() {
        // Exercises `__data_loc char[] filename` and `const char *const *`
        // type prefixes, both of which leave the field name as the last
        // whitespace-separated token before the first ';'.
        let dir = make_tracefs(&[
            ("syscalls", "sys_enter_execve", SYS_ENTER_EXECVE_FORMAT),
        ]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "sys_enter_execve",
                category: "syscalls",
                name:     "sys_enter_execve",
                fields:   &[
                    ExpectedField { field: "filename", offset: 16, size: 8 },
                    ExpectedField { field: "argv",     offset: 24, size: 8 },
                    ExpectedField { field: "envp",     offset: 32, size: 8 },
                ],
            },
        ]);
        assert!(r.is_empty(), "unexpected: {:?}",
                r.iter().map(|m| (&m.field, m.reason)).collect::<Vec<_>>());
    }

    #[test]
    fn array_brackets_are_stripped_from_field_name() {
        // `char comm[16]` should resolve to field name "comm".
        let body = "name: t\nID: 1\nformat:\n\
\tfield:char comm[16];\toffset:12;\tsize:16;\tsigned:0;\n";
        let dir = make_tracefs(&[("task", "t", body)]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "t",
                category: "task",
                name:     "t",
                fields:   &[ExpectedField { field: "comm", offset: 12, size: 16 }],
            },
        ]);
        assert!(r.is_empty(), "{:?}",
                r.iter().map(|m| (&m.field, m.reason)).collect::<Vec<_>>());
    }

    // -----------------------------------------------------------------------
    // Helpers + new spec coverage
    // -----------------------------------------------------------------------

    #[test]
    fn syscall_arg_helper_offsets_and_size() {
        // Mirrors the kernel ABI: arg N at offset 16 + 8*N, size 8.
        let cases: &[(usize, usize)] = &[
            (0, 16), (1, 24), (2, 32), (3, 40), (4, 48), (5, 56),
        ];
        for &(idx, expected_off) in cases {
            let f = ExpectedField::syscall_arg("x", idx);
            assert_eq!(f.offset, expected_off, "idx {idx}");
            assert_eq!(f.size,   8,            "idx {idx}");
            assert_eq!(f.field,  "x");
        }
    }

    #[test]
    fn data_loc_helper_constants() {
        let f = ExpectedField::data_loc("filename");
        assert_eq!(f.offset, 8);
        assert_eq!(f.size,   4);
        assert_eq!(f.field,  "filename");
    }

    #[test]
    fn data_loc_at_offset_12_validates_against_module_load_layout() {
        // module/module_load: __field unsigned int taints @8, then
        // __data_loc char[] name @12.  Asserts the validator catches the
        // pre-fix bug (reading at 8) by reporting offset_mismatch when a
        // spec wrongly puts `name` at offset 8.
        let body = "name: module_load\nID: 1\nformat:\n\
\tfield:unsigned int taints;\toffset:8;\tsize:4;\tsigned:0;\n\
\tfield:__data_loc char[] name;\toffset:12;\tsize:4;\tsigned:0;\n";
        let dir = make_tracefs(&[("module", "module_load", body)]);
        let v = validator_with_base(dir.path().to_path_buf());

        // Buggy spec — should fire offset_mismatch.
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "module_load",
                category: "module",
                name:     "module_load",
                fields:   &[ExpectedField { field: "name", offset: 8, size: 4 }],
            },
        ]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].reason,        "offset_mismatch");
        assert_eq!(r[0].actual_offset, Some(12));

        // Correct spec — no mismatches.
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "module_load",
                category: "module",
                name:     "module_load",
                fields:   &[ExpectedField { field: "name", offset: 12, size: 4 }],
            },
        ]);
        assert!(r.is_empty(), "{:?}",
                r.iter().map(|m| (&m.field, m.reason)).collect::<Vec<_>>());
    }

    #[test]
    fn existence_only_spec_passes_when_format_present() {
        // sched_process_exit is in VALIDATED_TRACEPOINTS with `fields: &[]` —
        // the validator must not complain as long as the format file exists.
        let body = "name: sched_process_exit\nID: 1\nformat:\n\
\tfield:char comm[16];\toffset:8;\tsize:16;\tsigned:0;\n\
\tfield:pid_t pid;\toffset:24;\tsize:4;\tsigned:1;\n\
\tfield:int prio;\toffset:28;\tsize:4;\tsigned:1;\n";
        let dir = make_tracefs(&[("sched", "sched_process_exit", body)]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "sched_process_exit",
                category: "sched",
                name:     "sched_process_exit",
                fields:   &[],
            },
        ]);
        assert!(r.is_empty(), "{:?}",
                r.iter().map(|m| (&m.field, m.reason)).collect::<Vec<_>>());
    }

    #[test]
    fn existence_only_spec_fires_when_format_missing() {
        let dir = make_tracefs(&[]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(&[
            TracepointSpec {
                program:  "sched_process_exit",
                category: "sched",
                name:     "sched_process_exit",
                fields:   &[],
            },
        ]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].reason, "tracepoint_missing");
        assert_eq!(r[0].label,  "sched_process_exit");
    }

    #[test]
    fn syscall_helper_validates_against_realistic_format() {
        // Realistic sys_enter_kill format: pid@16 (size 8), sig@24 (size 8).
        const KILL_FIELDS: &[ExpectedField] = &[
            ExpectedField::syscall_arg("pid", 0),
            ExpectedField::syscall_arg("sig", 1),
        ];
        const KILL_SPEC: TracepointSpec = syscall("sys_enter_kill", KILL_FIELDS);

        let body = "name: sys_enter_kill\nID: 1\nformat:\n\
\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n\
\tfield:pid_t pid;\toffset:16;\tsize:8;\tsigned:0;\n\
\tfield:int sig;\toffset:24;\tsize:8;\tsigned:0;\n";
        let dir = make_tracefs(&[("syscalls", "sys_enter_kill", body)]);
        let v = validator_with_base(dir.path().to_path_buf());
        let r = v.validate_all(std::slice::from_ref(&KILL_SPEC));
        assert!(r.is_empty(), "{:?}",
                r.iter().map(|m| (&m.field, m.reason)).collect::<Vec<_>>());
    }

    #[test]
    fn validated_tracepoints_is_well_formed() {
        // Sanity-check the constant: every entry has program == name and
        // every field offset/size is plausible (size > 0, offset >= 8).
        for spec in VALIDATED_TRACEPOINTS {
            assert!(!spec.name.is_empty(),     "empty name for {}", spec.program);
            assert!(!spec.category.is_empty(), "empty category for {}", spec.program);
            for f in spec.fields {
                assert!(f.size > 0,    "{} field {}: size==0", spec.program, f.field);
                assert!(f.offset >= 8, "{} field {}: offset {} < 8", spec.program, f.field, f.offset);
            }
        }
    }
}
