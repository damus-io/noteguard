//! Protected events filter - rejects NIP-70 protected events.
//!
//! NIP-70 defines a `-` tag that marks events as "protected", meaning
//! they should only be accepted by relays the author explicitly trusts.

use crate::{InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

/// Protected events filter (NIP-70).
///
/// Rejects events that have a `-` tag as their first tag, indicating
/// the author wants the event protected and only accepted by trusted relays.
///
/// ## Configuration
///
/// ```toml
/// [filters.protected_events]
/// # No configuration needed - just include in pipeline
/// ```
///
/// ## Background
///
/// From NIP-70: "A `-` tag is a special tag that marks an event as protected.
/// Protected events should only be accepted by relays that the event author
/// has explicitly allowed."
#[derive(Deserialize, Default)]
pub struct ProtectedEvents {}

impl NoteFilter for ProtectedEvents {
    fn filter_note(&mut self, input: &InputMessage) -> OutputMessage {
        // Check if first tag is the protected marker "-"
        let is_protected = input
            .event
            .tags
            .first()
            .and_then(|tag| tag.first())
            .map(|entry| entry == "-")
            .unwrap_or(false);

        if is_protected {
            return OutputMessage::reject(
                input.event.id.clone(),
                "blocked: event marked as protected",
            );
        }

        OutputMessage::accept(input.event.id.clone())
    }

    fn name(&self) -> &'static str {
        "protected_events"
    }
}
