//! Linux-specific agent self-update: download .deb/.rpm, install, restart.
//!
//! We run dpkg/rpm in a detached process so that when the package's prerm runs
//! systemctl stop, the agent is not the process waiting on dpkg. The agent returns
//! and is later killed by prerm; no explicit exit.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use secureexec_generic::transport::GrpcControlClient;
use secureexec_generic::error::Result;
use secureexec_generic::{AgentError, AgentUpdater};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::detached_script::spawn_detached_logged;
use crate::log_tailer::tail_script_log;

const UPDATES_DIR: &str = "/opt/secureexec/updates";

/// Linux agent updater: downloads package via control client, runs dpkg/rpm in a detached process.
pub struct LinuxAgentUpdater;

impl LinuxAgentUpdater {
    pub fn new() -> Self {
        Self
    }
}

fn is_deb() -> bool {
    Path::new("/etc/debian_version").exists()
}

fn detect_platform() -> Result<String> {
    let arch = std::env::consts::ARCH;
    let arch_key = match arch {
        "x86_64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        _ => return Err(AgentError::Platform(format!("unsupported arch: {}", arch))),
    };
    let pkg = if is_deb() { "deb" } else { "rpm" };
    Ok(format!("linux_{}_{}", arch_key, pkg))
}

fn kmod_platform() -> &'static str {
    if is_deb() { "linux_kmod_deb" } else { "linux_kmod_rpm" }
}

fn update_filename(platform: &str, version: &str) -> Result<String> {
    let ext = if platform.ends_with("_deb") { "deb" } else { "rpm" };
    let base = match platform {
        "linux_amd64_deb" | "linux_amd64_rpm" => "secureexec-agent_linux_amd64",
        "linux_arm64_deb" | "linux_arm64_rpm" => "secureexec-agent_linux_arm64",
        _ => return Err(AgentError::Platform(format!("unknown platform: {}", platform))),
    };
    Ok(format!("{}_{}.{}", base, version, ext))
}

fn kmod_update_filename(version: &str) -> String {
    if is_deb() {
        format!("secureexec-kmod_linux_all_{}.deb", version)
    } else {
        format!("secureexec-kmod_linux_noarch_{}.rpm", version)
    }
}

/// Check whether the kmod package is already installed on the system.
fn kmod_is_installed() -> bool {
    if is_deb() {
        std::process::Command::new("dpkg")
            .args(["-s", "secureexec-kmod"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        std::process::Command::new("rpm")
            .args(["-q", "secureexec-kmod"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn needs_kmod(firewall_backend: &str) -> bool {
    firewall_backend == "kmod" || kmod_is_installed()
}

/// Stream-hash `path` in 1 MiB chunks and compare against `expected`.
/// Reading the whole file into memory would OOM the agent on large packages
/// (kmod debs can be 100+ MiB).
fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .map_err(|e| AgentError::Platform(format!("open file for sha256 verification: {}", e)))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| AgentError::Platform(format!("read file for sha256 verification: {}", e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());
    if !expected.eq_ignore_ascii_case(&actual) {
        Err(AgentError::Platform(format!(
            "sha256 mismatch: expected {}, got {}",
            expected, actual
        )))
    } else {
        Ok(())
    }
}

/// Basic allowlist for a semver-ish version string before it is embedded into
/// a shell command. The download pipeline places the version inside package
/// filenames (which we fully control), but `target_version` still originates
/// from the control plane, so we refuse anything containing shell
/// metacharacters as defense-in-depth.
fn validate_target_version(v: &str) -> Result<()> {
    if v.is_empty() || v.len() > 64 {
        return Err(AgentError::Platform(format!(
            "invalid target_version length: {}",
            v.len()
        )));
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        return Err(AgentError::Platform(format!(
            "target_version contains unsafe characters: {:?}",
            v
        )));
    }
    Ok(())
}

fn clean_updates_dir() {
    let Ok(entries) = std::fs::read_dir(UPDATES_DIR) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "deb" || e == "rpm") {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(component = "agent-update", path = %path.display(), error = %e, "failed to remove old update package");
            }
        }
    }
}

#[async_trait]
impl AgentUpdater for LinuxAgentUpdater {
    fn platform(&self) -> Option<String> {
        detect_platform().ok()
    }

    async fn run_update(
        &self,
        ctrl: Arc<GrpcControlClient>,
        agent_id: String,
        target_version: String,
        expected_sha256: String,
        firewall_backend: String,
    ) -> Result<()> {
        validate_target_version(&target_version)?;

        // Require a non-empty expected SHA256. An empty value previously
        // silently skipped verification, which means a compromised control
        // plane could ship a backdoored package and the agent would install
        // it unauthenticated. Updates without a hash must be rejected.
        if expected_sha256.is_empty() {
            return Err(AgentError::Platform(
                "refusing agent update: empty expected_sha256 (unauthenticated update)".to_string(),
            ));
        }

        let platform = detect_platform()?;
        std::fs::create_dir_all(UPDATES_DIR)
            .map_err(|e| AgentError::Platform(format!("create updates dir: {}", e)))?;
        clean_updates_dir();

        // --- Download and verify agent package ---
        let filename = update_filename(&platform, &target_version)?;
        let agent_path = Path::new(UPDATES_DIR).join(&filename);

        info!(component = "agent-update", path = %agent_path.display(), "downloading agent update");
        ctrl.download_agent_update(&agent_id, &platform, &target_version, &agent_path)
            .await?;

        // Verify against the server-provided digest using a streaming hash so
        // multi-hundred-MiB update packages don't force us to buffer the
        // entire file in RAM.
        let verify_path = agent_path.clone();
        let verify_expected = expected_sha256.clone();
        let verify_result = tokio::task::spawn_blocking(move || {
            verify_sha256(&verify_path, &verify_expected)
        })
        .await
        .map_err(|e| AgentError::Platform(format!("sha256 verify task panicked: {}", e)))?;
        if let Err(e) = verify_result {
            error!(component = "agent-update", path = %agent_path.display(), error = %e, "update package sha256 mismatch");
            return Err(e);
        }
        info!(component = "agent-update", "agent package sha256 verified");

        // --- Conditionally download and verify kmod package ---
        let kmod_path = if needs_kmod(&firewall_backend) {
            let kmod_plat = kmod_platform();
            let kmod_filename = kmod_update_filename(&target_version);
            let kmod_file = Path::new(UPDATES_DIR).join(&kmod_filename);

            // Fetch kmod SHA256 (reuses same gRPC call, platform key differs)
            let kmod_sha256 = match ctrl.get_target_version(&agent_id, kmod_plat).await {
                Ok((_, sha)) => sha,
                Err(e) => {
                    warn!(component = "agent-update", error = %e, "failed to fetch kmod sha256, skipping kmod update");
                    String::new()
                }
            };

            info!(component = "agent-update", path = %kmod_file.display(), "downloading kmod update");
            match ctrl.download_agent_update(&agent_id, kmod_plat, &target_version, &kmod_file).await {
                Ok(()) => {
                    // Verify kmod SHA256 if provided; mismatch aborts the entire update
                    if !kmod_sha256.is_empty() {
                        if let Err(e) = verify_sha256(&kmod_file, &kmod_sha256) {
                            error!(component = "agent-update", path = %kmod_file.display(), error = %e, "kmod sha256 mismatch — aborting update");
                            return Err(AgentError::Platform(format!("kmod update aborted: {}", e)));
                        }
                        info!(component = "agent-update", "kmod package sha256 verified");
                    }
                    Some(kmod_file)
                }
                Err(e) => {
                    // Download failure is non-fatal: proceed with agent-only update
                    warn!(component = "agent-update", error = %e, "kmod package download failed, proceeding with agent-only update");
                    None
                }
            }
        } else {
            debug!(component = "agent-update", "kmod not needed, skipping kmod download");
            None
        };

        // --- Build and spawn detached install script ---
        let agent_path_str = agent_path.to_string_lossy();
        let cmd = if let Some(ref kmod_file) = kmod_path {
            // Stop agent first to release the kmod fd, then install kmod + agent.
            // The agent dies at step 1; postinst of agent package restarts it.
            let kmod_path_str = kmod_file.to_string_lossy();
            if is_deb() {
                format!(
                    "systemctl stop secureexec-agent || true; \
                     dpkg -i {} && dpkg -i {}",
                    kmod_path_str, agent_path_str
                )
            } else {
                format!(
                    "systemctl stop secureexec-agent || true; \
                     rpm -U {} && rpm -U {}",
                    kmod_path_str, agent_path_str
                )
            }
        } else {
            if is_deb() {
                format!("dpkg -i {}", agent_path_str)
            } else {
                format!("rpm -U {}", agent_path_str)
            }
        };

        info!(component = "agent-update", kmod_included = kmod_path.is_some(), "spawning detached install and restart");
        let log_path = spawn_detached_logged(&cmd, "agent-update")?;
        tokio::spawn(tail_script_log(log_path, "agent-update".to_string(), None));
        Ok(())
    }
}
