//! Event kind filter - blocks specific Nostr event kinds.
//!
//! Use this to restrict which event types your relay accepts.

use crate::{InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::collections::HashMap;

/// Event kind filter - blocks events of specified kinds.
///
/// Useful for relays that only want to handle specific event types,
/// e.g., a relay that only accepts text notes and reactions.
///
/// ## Configuration
///
/// ```toml
/// [filters.kinds]
/// kinds = [4, 1984]  # Block DMs and reports
/// messages = { "4" = "DMs not accepted", "1984" = "No reports please" }  # Optional
/// ```
#[derive(Deserialize, Default)]
pub struct Kinds {
    /// Event kinds to reject
    kinds: Vec<i64>,
    /// Optional custom rejection messages per kind
    messages: Option<HashMap<String, String>>,
}

impl NoteFilter for Kinds {
    fn filter_note(&mut self, input: &InputMessage) -> OutputMessage {
        let kind = input.event.kind;

        // Event kind not in block list - accept
        if !self.kinds.contains(&kind) {
            return OutputMessage::accept(input.event.id.clone());
        }

        // Blocked kind - get custom message or use default
        let msg = self
            .messages
            .as_ref()
            .and_then(|msgs| msgs.get(&kind.to_string()).cloned())
            .unwrap_or_else(|| "blocked: note kind is not allowed here".to_string());

        OutputMessage::reject(input.event.id.clone(), msg)
    }

    fn name(&self) -> &'static str {
        "kinds"
    }
}
