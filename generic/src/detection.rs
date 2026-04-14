use tracing::debug;

use crate::event::Event;
use crate::process_table::ProcessTable;

// ---------------------------------------------------------------------------
// Context passed to every detection rule
// ---------------------------------------------------------------------------

/// Read-only snapshot of pipeline state available during detection evaluation.
pub struct DetectionContext<'a> {
    pub process_table: &'a ProcessTable,
}

// ---------------------------------------------------------------------------
// Detection rule trait
// ---------------------------------------------------------------------------

/// Trait that every detection rule must implement.
///
/// Rules inspect a filtered batch of events (plus the process table for
/// context) and may produce new `Detection` events.
pub trait DetectionRule: Send + Sync {
    fn name(&self) -> &str;

    /// Evaluate the batch and return zero or more detection events.
    ///
    /// Returned events are automatically stamped with agent_id / os / hostname
    /// and spooled alongside the original batch.
    fn evaluate(&mut self, ctx: &DetectionContext, batch: &[Event]) -> Vec<Event>;
}

// ---------------------------------------------------------------------------
// Detection engine — runs a chain of rules on each batch
// ---------------------------------------------------------------------------

pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: impl DetectionRule + 'static) {
        self.rules.push(Box::new(rule));
    }

    /// Run all registered rules on `batch` and return the combined set of new
    /// detection events (may be empty).
    pub fn run(&mut self, ctx: &DetectionContext, batch: &[Event]) -> Vec<Event> {
        let mut detections = Vec::new();
        for rule in &mut self.rules {
            let hits = rule.evaluate(ctx, batch);
            if !hits.is_empty() {
                debug!(rule = rule.name(), count = hits.len(), "detections generated");
                detections.extend(hits);
            }
        }
        detections
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}
