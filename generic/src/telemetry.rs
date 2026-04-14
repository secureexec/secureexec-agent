use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Layer, Registry};

use crate::log_sender::{AgentLogEntry, LogSpoolLayer};

/// Initialize structured JSON logging (Zap-style flat output, UTC timestamps).
///
/// Set the `SecureExec_LOG` env var to control verbosity, e.g.:
///   SecureExec_LOG=debug  or  SecureExec_LOG=secureexec_generic=trace
pub fn init() {
    init_with_log_layer(None);
}

/// Like `init()`, but also enqueues log entries to `tx` for spooling and sending.
/// Events from `secureexec_generic::log_sender` are never enqueued (avoids recursion).
pub fn init_with_log_layer(tx: Option<tokio::sync::mpsc::Sender<AgentLogEntry>>) {
    let filter = EnvFilter::try_from_env("SecureExec_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false);

    let subscriber = Registry::default()
        .with(filter.clone())
        .with(fmt_layer)
        .with(LogSpoolLayer::new(tx).with_filter(filter));

    tracing::subscriber::set_global_default(subscriber).expect("set_global_default");
}
