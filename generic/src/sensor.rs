use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::error::Result;
use crate::event::Event;

/// Trait every platform-specific sensor must implement.
///
/// A sensor watches a single event source (processes, files, network, etc.)
/// and pushes `Event`s into the provided channel.
#[async_trait]
pub trait Sensor: Send + Sync + 'static {
    fn name(&self) -> &str;

    /// Start collecting events. Implementations should run until the
    /// cancellation token fires or an unrecoverable error occurs.
    async fn run(&self, tx: mpsc::Sender<Event>, cancel: tokio::sync::watch::Receiver<bool>) -> Result<()>;
}
