//! Content filter - shadow-rejects events matching content patterns.
//!
//! Performs simple substring matching on event content.
//! Uses shadow reject so spammers don't know they're filtered.

use crate::{InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

/// Content filter - shadow-rejects events with matching content.
///
/// This filter uses `ShadowReject` instead of `Reject`, meaning the
/// client receives a success response but the event is silently dropped.
/// This prevents spammers from adapting to the filter.
///
/// ## Configuration
///
/// ```toml
/// [filters.content]
/// filters = ["buy now", "limited offer", "act fast"]
/// ```
///
/// Note: Matching is case-sensitive substring search.
#[derive(Deserialize, Default)]
pub struct Content {
    /// Substrings to match in event content
    filters: Vec<String>,
}

impl NoteFilter for Content {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        for pattern in &self.filters {
            if msg.event.content.contains(pattern) {
                // Shadow reject - client thinks it succeeded, but event is dropped
                return OutputMessage::shadow_reject(msg.event.id.clone());
            }
        }

        OutputMessage::accept(msg.event.id.clone())
    }

    fn name(&self) -> &'static str {
        "content"
    }
}
