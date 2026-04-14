# SecureExec Agent

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A multi-platform EDR (Endpoint Detection & Response) agent that collects security events and streams them to the [SecureExec](https://secureexec.co) server over gRPC/mTLS.

## Platforms

| Platform | Technology | Crate |
|----------|-----------|-------|
| Linux | eBPF (tracepoints + kprobes) | `linux/agent` |
| macOS | Endpoint Security + Network Extension | `macos/agent` |
| Windows | ETW / WMI | `windows/agent` |

Shared transport, pipeline, and event types live in `generic/`.

## Collected events

| Event | Linux | macOS | Windows |
|-------|:-----:|:-----:|:-------:|
| Process create / fork / exit | x | x | planned |
| File create / modify / delete | x | x | planned |
| File rename | x | x | |
| File permission change (chmod/chown) | x | | |
| File link / symlink | x | | |
| Network connect | x | x | planned |
| Network listen (accept / bind) | x | x | |
| DNS query | x | | |
| Registry write | | | planned |
| Privilege change (setuid/setgid) | x | | |
| Process access (ptrace) | x | | |
| Process VM read/write | x | | |
| Process signal (kill) | x | | |
| Memory map (exec/write) | x | | |
| memfd_create | x | | |
| Kernel module load | x | | |
| BPF program load | x | | |
| Capability change | x | | |
| Namespace change (unshare/setns) | x | | |
| Mount / unmount | x | | |
| keyctl | x | | |
| io_uring setup | x | | |
| Agent lifecycle / heartbeat | x | x | x |

## Repository layout

```
agent/
├── generic/          # Shared: EventKind, gRPC transport, pipeline, filter
├── proto/            # secureexec.proto (gRPC schema)
├── linux/
│   ├── agent/        # Userspace eBPF consumer
│   ├── ebpf/         # Kernel eBPF programs (tracepoints / kprobes)
│   ├── ebpf-common/  # Shared kernel↔userspace types
│   └── kmod/         # Optional kernel module (firewall)
├── macos/
│   ├── agent/        # Endpoint Security sensor (Rust)
│   ├── app/          # Menu bar app (Swift/SwiftUI)
│   ├── activator/    # System extension activator (Swift)
│   └── network-ext/  # Network Extension (Swift)
└── windows/
    └── agent/        # ETW/WMI sensor (Rust)
```

## Building

### Prerequisites

- Rust 1.81+ (`rustup update stable`)
- For Linux eBPF: `bpf-linker`, LLVM 18+, nightly Rust toolchain
- For macOS app: Xcode 15+
- Proto compiler: `protoc` (needed by `tonic-build` in `generic/build.rs`)
- Docker (for cross-compiling Linux agent from macOS)

### Linux agent (Docker — recommended)

Build from any host (macOS / Linux) without installing LLVM or bpf-linker locally.
First run takes ~5–10 min (builds the toolchain image); subsequent runs ~30–60 s.

```sh
make linux-build-docker
```

The static musl binary is written to `./target/x86_64-unknown-linux-musl/release/secureexec-agent-linux`.

To wipe the Docker build cache and start fresh:

```sh
make linux-build-docker-clean
```

### Linux agent (native)

Requires musl toolchain, LLVM 18+, and `bpf-linker` on the host.

```sh
make linux-build
```

### macOS agent

```sh
make macos-build
```

The binary is written to `./target/release/secureexec-agent-macos`.

### Windows agent

```sh
make windows-build
```

## Configuration

The agent reads a JSON config file (default: `/opt/secureexec/var/secureexec-agent.json`):

```json
{
  "backend_url": "https://your-server:50051",
  "tls_ca": "/opt/secureexec/etc/certs/ca.crt",
  "tls_client_cert": "/opt/secureexec/etc/certs/agent.crt",
  "tls_client_key": "/opt/secureexec/etc/certs/agent.key",
  "auth_token": "your-org-token"
}
```

## eBPF license note

The Linux eBPF kernel programs (`linux/ebpf/`) embed a `"Dual MIT/GPL"` license tag in the compiled binary. This is a technical requirement of the Linux kernel's BPF verifier for access to GPL-only BPF helpers, and is distinct from the Apache 2.0 license that governs the source code of this repository. See [NOTICE](NOTICE) for details.

## License

Apache 2.0 — see [LICENSE](LICENSE).

This agent is part of the [SecureExec](https://secureexec.co) platform.
