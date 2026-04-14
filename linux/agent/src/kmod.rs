//! Common secureexec_kmod chardev handle.
//!
//! `KmodHandle` opens `/dev/secureexec_kmod`, verifies the ABI version, and
//! owns the file descriptor.  Subsystem-specific code (firewall, future
//! features) receives a `KmodHandle` and issues its own ioctls through
//! `KmodHandle::raw_fd()`.

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use tracing::{info, warn};

use secureexec_generic::error::{AgentError, Result};

const DEVICE_PATH: &str = "/dev/secureexec_kmod";

/// ioctl magic byte — must match `SE_KMOD_MAGIC` in `firewall.h`.
pub(crate) const SE_KMOD_MAGIC: u8 = b'S';

/// ABI version the agent expects from the kmod.  Must match
/// `SE_KMOD_ABI_VERSION` in `firewall.h`.  Bump both together.
const EXPECTED_ABI_VERSION: u32 = 1;

nix::ioctl_read_bad!(se_kmod_get_abi_version, nix::request_code_read!(SE_KMOD_MAGIC, 6, std::mem::size_of::<u32>()), u32);

/// Shared handle to the kmod chardev.  Cloneable — the underlying fd is
/// behind `Arc<Mutex<>>` so multiple subsystems can share it.
#[derive(Debug, Clone)]
pub struct KmodHandle {
    fd: std::sync::Arc<std::sync::Mutex<OwnedFd>>,
}

impl KmodHandle {
    /// Open the chardev and verify the ABI version.
    pub fn open() -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE_PATH)
            .map_err(|e| {
                AgentError::Platform(format!(
                    "secureexec_kmod: cannot open {DEVICE_PATH}: {e} \
                     (is the kernel module loaded?)"
                ))
            })?;

        let raw = file.into_raw_fd();
        Self::check_abi(raw)?;

        // Safety: raw is a valid open fd we own; ABI check passed.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd: std::sync::Arc::new(std::sync::Mutex::new(owned)),
        })
    }

    /// Try to open the kmod, returning `None` and logging a warning if
    /// unavailable or incompatible.
    pub fn try_open() -> Option<Self> {
        match Self::open() {
            Ok(h) => {
                info!("secureexec_kmod: chardev opened (ABI v{EXPECTED_ABI_VERSION})");
                Some(h)
            }
            Err(e) => {
                warn!("{e}");
                None
            }
        }
    }

    /// Obtain the raw fd for ioctl calls.  The returned guard holds the
    /// mutex — drop it promptly after the ioctl.
    pub fn raw_fd(&self) -> Result<RawFdGuard<'_>> {
        let guard = self
            .fd
            .lock()
            .map_err(|_| AgentError::Platform("kmod mutex poisoned".into()))?;
        Ok(RawFdGuard(guard))
    }

    fn check_abi(raw: RawFd) -> Result<()> {
        let mut kmod_abi: u32 = 0;
        // Safety: raw is a valid fd; kmod_abi is a properly sized u32.
        let result = unsafe { se_kmod_get_abi_version(raw, &mut kmod_abi) };
        match result {
            Ok(_) if kmod_abi == EXPECTED_ABI_VERSION => Ok(()),
            Ok(_) => {
                // Safety: raw is a valid fd we own.
                unsafe { libc::close(raw) };
                Err(AgentError::Platform(format!(
                    "secureexec_kmod: ABI version mismatch (kmod={kmod_abi}, \
                     agent expects={EXPECTED_ABI_VERSION}); \
                     please upgrade secureexec-kmod package"
                )))
            }
            Err(_) => {
                // Safety: raw is a valid fd we own.
                unsafe { libc::close(raw) };
                Err(AgentError::Platform(
                    "secureexec_kmod: kmod too old (no ABI version support); \
                     please upgrade secureexec-kmod package".into()
                ))
            }
        }
    }
}

/// RAII guard that dereferences to a `RawFd`.
pub struct RawFdGuard<'a>(std::sync::MutexGuard<'a, OwnedFd>);

impl<'a> RawFdGuard<'a> {
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
