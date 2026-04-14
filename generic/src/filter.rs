use std::collections::HashSet;

use tracing::debug;

use crate::event::Event;

// ---------------------------------------------------------------------------
// Filter trait
// ---------------------------------------------------------------------------

/// Decision returned by a filter for a single event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    Pass,
    Drop,
}

/// Trait that every filter must implement.
///
/// `filter_batch` receives a mutable batch and removes events that should be
/// dropped.  The default implementation calls `decide` per event.
pub trait EventFilter: Send + Sync {
    fn name(&self) -> &str;

    fn decide(&mut self, event: &Event) -> FilterVerdict;

    fn filter_batch(&mut self, batch: &mut Vec<Event>) {
        let before = batch.len();
        batch.retain(|e| self.decide(e) == FilterVerdict::Pass);
        let dropped = before - batch.len();
        if dropped > 0 {
            debug!(filter = self.name(), dropped, "events filtered out");
        }
    }
}

// ---------------------------------------------------------------------------
// Filter chain — runs a sequence of filters on each batch
// ---------------------------------------------------------------------------

pub struct FilterChain {
    filters: Vec<Box<dyn EventFilter>>,
}

impl FilterChain {
    pub fn new() -> Self {
        Self { filters: Vec::new() }
    }

    pub fn add(&mut self, filter: impl EventFilter + 'static) {
        self.filters.push(Box::new(filter));
    }

    /// Run every filter on the batch in order.  Each filter may shrink the
    /// batch; subsequent filters only see what passed earlier ones.
    pub fn apply(&mut self, batch: &mut Vec<Event>) {
        for f in &mut self.filters {
            if batch.is_empty() {
                return;
            }
            f.filter_batch(batch);
        }
    }
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Hash-based dedup filter
// ---------------------------------------------------------------------------

/// Drops events whose content hash has already been seen.
///
/// Useful for suppressing identical recurring events (e.g. the same process
/// launching repeatedly, or the same file being touched in a loop).
pub struct DeduplicationFilter {
    seen: HashSet<String>,
    capacity: usize,
}

impl DeduplicationFilter {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
            capacity,
        }
    }
}

impl EventFilter for DeduplicationFilter {
    fn name(&self) -> &str {
        "dedup"
    }

    fn decide(&mut self, event: &Event) -> FilterVerdict {
        if matches!(
            event.kind,
            crate::event::EventKind::AgentStarted(_)
            | crate::event::EventKind::AgentStopping(_)
            | crate::event::EventKind::AgentHeartbeat(_)
            | crate::event::EventKind::Detection(_)
        ) {
            return FilterVerdict::Pass;
        }

        if self.seen.contains(&event.content_hash) {
            return FilterVerdict::Drop;
        }

        if self.seen.len() >= self.capacity {
            debug!(filter = "dedup", capacity = self.capacity, "hash table full — clearing");
            self.seen.clear();
        }

        self.seen.insert(event.content_hash.clone());
        FilterVerdict::Pass
    }
}

// ---------------------------------------------------------------------------
// Decision callback helpers — building blocks for future filters
// ---------------------------------------------------------------------------

/// Returns `true` if `haystack` contains `needle` (case-sensitive).
pub fn find_substring(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

/// Returns `true` if `haystack` contains `needle` (case-insensitive).
pub fn find_substring_icase(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Returns `true` if the value matches any entry in the allowlist.
pub fn in_list<'a>(value: &str, list: impl IntoIterator<Item = &'a str>) -> bool {
    list.into_iter().any(|entry| entry == value)
}

/// Returns `true` if the value does NOT match any entry in the blocklist.
pub fn not_in_list<'a>(value: &str, list: impl IntoIterator<Item = &'a str>) -> bool {
    !in_list(value, list)
}
