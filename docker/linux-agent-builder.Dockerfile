# Builder image for the Linux eBPF agent.
# Installs LLVM 20, Rust stable + pinned nightly, musl cross-toolchain, and
# bpf-linker.  The image is tagged with the nightly date so the heavy layers
# are automatically rebuilt when the toolchain is bumped.
#
# Usage (via Makefile):
#   make linux-build-docker
#
# Direct usage:
#   docker build --build-arg NIGHTLY=nightly-2025-07-10 \
#     -t secureexec-linux-builder:nightly-2025-07-10 \
#     -f docker/linux-agent-builder.Dockerfile .

ARG NIGHTLY=nightly-2025-07-10

# ── Layer 1: system packages (changes only when deps change) ─────────────────
FROM ubuntu:24.04 AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget ca-certificates gnupg && \
    # LLVM 20 APT repo
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
        | tee /etc/apt/trusted.gpg.d/llvm.asc >/dev/null && \
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-20 main" \
        > /etc/apt/sources.list.d/llvm20.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        llvm-20-dev \
        clang \
        libelf-dev \
        musl-tools \
        protobuf-compiler \
        curl \
        git \
        pkg-config \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

ENV LLVM_PREFIX=/usr/lib/llvm-20

# ── Layer 2: Rust toolchain (changes when NIGHTLY arg changes) ───────────────
FROM base AS toolchain

ARG NIGHTLY

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain stable && \
    # Install pinned nightly with rust-src (needed by aya-build for BPF target)
    rustup toolchain install ${NIGHTLY} --component rust-src && \
    # Add musl target to stable (cargo build uses this) and to nightly
    rustup target add x86_64-unknown-linux-musl && \
    rustup target add x86_64-unknown-linux-musl --toolchain ${NIGHTLY} && \
    # aya-build calls `rustup run nightly ...`; symlink pinned to the generic name
    ln -sf "${RUSTUP_HOME}/toolchains/${NIGHTLY}-x86_64-unknown-linux-gnu" \
           "${RUSTUP_HOME}/toolchains/nightly-x86_64-unknown-linux-gnu" && \
    rustup run nightly rustc -vV

# ── Layer 3: bpf-linker (cached until toolchain changes) ─────────────────────
FROM toolchain AS builder

ARG NIGHTLY

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    LLVM_PREFIX=/usr/lib/llvm-20

# Build bpf-linker against the local LLVM 20 (--no-default-features skips
# vendored LLVM, --features llvm-20 links against the system package).
RUN RUSTFLAGS="" cargo install \
        --no-default-features \
        --features llvm-20 \
        bpf-linker && \
    bpf-linker --version

# Final image re-uses the builder stage directly.
FROM builder

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    LLVM_PREFIX=/usr/lib/llvm-20 \
    RUSTFLAGS="-C link-arg=-static" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc

WORKDIR /src
