FROM alpine:3.20
# All agent packages collected into pkg/ at CI build time (with version in filename).
COPY pkg/ /pkg/
# At runtime:
#   1. Copy versioned files into the shared /agents/ host-path.
#   2. Create a versionless symlink so the backend can find the file without
#      knowing the version (e.g. secureexec-agent_linux_amd64_0.1.1.deb ->
#      secureexec-agent_linux_amd64.deb).
#   The version segment is the last _N.N.N before the extension, stripped via
#   sed so it works for both agent and kmod packages regardless of version.
CMD ["sh", "-c", "\
  for f in /pkg/*; do \
    base=$(basename \"$f\"); \
    cp \"$f\" \"/agents/$base\"; \
    noversion=$(echo \"$base\" | sed 's/_[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.\\([^.]*\\)$/.\\1/'); \
    if [ \"$noversion\" != \"$base\" ]; then \
      ln -sf \"$base\" \"/agents/$noversion\"; \
    fi; \
  done; \
  echo \"Agent files ready: $(ls /agents/)\" \
"]
