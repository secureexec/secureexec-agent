# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

LINUX_TARGET       ?= x86_64-unknown-linux-musl
LINUX_AGENT_BIN     = ./target/$(LINUX_TARGET)/release/secureexec-agent-linux
MACOS_AGENT_BIN     = ./target/release/secureexec-agent-macos

LINUX_NIGHTLY          ?= nightly-2025-07-10
LINUX_BUILDER_IMAGE     = secureexec-linux-builder:$(LINUX_NIGHTLY)
LINUX_BUILDER_DOCKERFILE = docker/linux-agent-builder.Dockerfile

LINUX_CARGO_REGISTRY_VOL = secureexec-cargo-registry
LINUX_CARGO_GIT_VOL      = secureexec-cargo-git
LINUX_TARGET_VOL         = secureexec-linux-target

# ---------------------------------------------------------------------------
# Linux — native build (requires musl toolchain + bpf-linker on the host)
# ---------------------------------------------------------------------------

linux-build:
	cargo build --release -p secureexec-linux --target $(LINUX_TARGET)

# ---------------------------------------------------------------------------
# Linux — Docker build (works from macOS or any host with Docker)
#
#   First run:  ~5–10 min  (builds LLVM 20 + Rust nightly + bpf-linker image)
#   Subsequent: ~30–60 s   (incremental, Cargo cache in named volumes)
#
#   Output binary: $(LINUX_AGENT_BIN)
# ---------------------------------------------------------------------------

linux-build-docker: _linux-builder-image _linux-cargo-volumes
	@echo "==> Compiling Linux agent (x86_64-unknown-linux-musl, static) ..."
	docker run --rm \
		--platform linux/amd64 \
		-v "$(abspath .):/src:ro" \
		-v "$(LINUX_TARGET_VOL):/src/target" \
		-v "$(LINUX_CARGO_REGISTRY_VOL):/usr/local/cargo/registry" \
		-v "$(LINUX_CARGO_GIT_VOL):/usr/local/cargo/git" \
		$(LINUX_BUILDER_IMAGE) \
		cargo build --release -p secureexec-linux --target x86_64-unknown-linux-musl
	@echo "==> Extracting binary to $(LINUX_AGENT_BIN) ..."
	@mkdir -p $(dir $(LINUX_AGENT_BIN))
	docker run --rm \
		--platform linux/amd64 \
		-v "$(LINUX_TARGET_VOL):/vol:ro" \
		-v "$(abspath $(dir $(LINUX_AGENT_BIN))):/out" \
		alpine \
		cp /vol/x86_64-unknown-linux-musl/release/secureexec-agent-linux /out/
	@echo ""
	@echo "==> $(LINUX_AGENT_BIN)"
	@file $(LINUX_AGENT_BIN) 2>/dev/null || true

_linux-builder-image:
	@if ! docker image inspect $(LINUX_BUILDER_IMAGE) >/dev/null 2>&1; then \
		echo "==> Building Linux agent builder image (one-time, ~5 min) ..."; \
		DOCKER_BUILDKIT=1 docker build \
			--platform linux/amd64 \
			--build-arg NIGHTLY=$(LINUX_NIGHTLY) \
			-t $(LINUX_BUILDER_IMAGE) \
			-f $(LINUX_BUILDER_DOCKERFILE) \
			.; \
	else \
		echo "==> Builder image $(LINUX_BUILDER_IMAGE) already exists (skip rebuild)"; \
	fi

_linux-cargo-volumes:
	@docker volume inspect $(LINUX_CARGO_REGISTRY_VOL) >/dev/null 2>&1 \
		|| docker volume create $(LINUX_CARGO_REGISTRY_VOL) >/dev/null
	@docker volume inspect $(LINUX_CARGO_GIT_VOL) >/dev/null 2>&1 \
		|| docker volume create $(LINUX_CARGO_GIT_VOL) >/dev/null
	@docker volume inspect $(LINUX_TARGET_VOL) >/dev/null 2>&1 \
		|| docker volume create $(LINUX_TARGET_VOL) >/dev/null

linux-builder-rebuild:
	DOCKER_BUILDKIT=1 docker build \
		--platform linux/amd64 \
		--build-arg NIGHTLY=$(LINUX_NIGHTLY) \
		--no-cache \
		-t $(LINUX_BUILDER_IMAGE) \
		-f $(LINUX_BUILDER_DOCKERFILE) \
		.

linux-build-docker-clean:
	docker volume rm -f $(LINUX_TARGET_VOL) $(LINUX_CARGO_REGISTRY_VOL) $(LINUX_CARGO_GIT_VOL) 2>/dev/null || true
	@echo "==> Linux Docker build volumes removed"

# ---------------------------------------------------------------------------
# macOS — native build
# ---------------------------------------------------------------------------

macos-build:
	cargo build --release -p secureexec-macos

# ---------------------------------------------------------------------------
# Windows — native build
# ---------------------------------------------------------------------------

windows-build:
	cargo build --release -p secureexec-windows --target x86_64-pc-windows-msvc

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	cargo clean

.PHONY: linux-build linux-build-docker linux-builder-rebuild linux-build-docker-clean \
	_linux-builder-image _linux-cargo-volumes \
	macos-build windows-build clean
