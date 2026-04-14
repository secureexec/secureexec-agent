# SecureExec Agent

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A multi-platform EDR (Endpoint Detection & Response) agent that collects security events and streams them to the [SecureExec](https://secureexec.co) server over gRPC/mTLS.

## Platforms

| Platform | Technology | Crate |
|----------|-----------|-------|
| Linux | eBPF (tracepoints + kprobes) | `linux/agent` |
| macOS | Endpoint Security framework | `macos/agent` |
| Windows | ETW / WMI | `windows/agent` |

Shared transport, pipeline, and event types live in `generic/`.

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

### Linux agent

```sh
# Native build (musl, statically linked)
cargo build --release -p secureexec-linux --target x86_64-unknown-linux-musl

# Or using Docker (recommended for cross-compilation from macOS)
make linux-build-docker
```

### macOS agent

```sh
# Rust sensor binary
cargo build --release -p secureexec-macos

# Full .app bundle (requires Xcode)
make macos-bundle
```

### Windows agent

```sh
cargo build --release -p secureexec-windows --target x86_64-pc-windows-msvc
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
