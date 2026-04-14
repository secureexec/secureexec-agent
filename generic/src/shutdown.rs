//! Cancellation-aware helpers shared across sensors and pipeline tasks.

use std::time::Duration;
use tokio::sync::watch;

/// Sleep for `duration`, but return early if `cancel` fires.
/// Returns `true` if the sleep completed normally, `false` if cancelled.
pub async fn cancellable_sleep(duration: Duration, cancel: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => true,
        _ = cancel.changed() => false,
    }
}

/// Check (non-blocking) whether the cancel signal has already been sent.
pub fn is_cancelled(cancel: &watch::Receiver<bool>) -> bool {
    *cancel.borrow()
}
