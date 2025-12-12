//! Message types for the noteguard filter pipeline.
//!
//! These types follow the strfry write policy plugin protocol but can be
//! used standalone for any relay integration.

use crate::Note;
use serde::{Deserialize, Serialize};

/// Input message containing the event to filter and metadata.
///
/// This structure matches the strfry write policy input format.
/// For non-strfry integrations, construct this from your relay's event data.
#[derive(Deserialize)]
pub struct InputMessage {
    /// Message type - typically "new" for new events
    #[serde(rename = "type")]
    pub message_type: String,

    /// The Nostr event to filter
    pub event: Note,

    /// Unix timestamp when the event was received
    #[serde(rename = "receivedAt")]
    pub received_at: u64,

    /// Source type (e.g., "IP4", "IP6", "stream")
    #[serde(rename = "sourceType")]
    pub source_type: String,

    /// Source identifier - typically the client IP address.
    /// Used by rate limiting and IP-based filters.
    #[serde(rename = "sourceInfo")]
    pub source_info: String,
}

/// Filter decision for an event.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    /// Event passes this filter and continues to the next
    Accept,
    /// Event is rejected with a message sent to the client
    Reject,
    /// Event is silently rejected - client sees success but event is dropped.
    /// Useful for spam filtering without revealing filter logic.
    ShadowReject,
}

/// Output from the filter pipeline.
#[derive(Serialize)]
pub struct OutputMessage {
    /// Event ID this decision applies to
    pub id: String,
    /// The filter decision
    pub action: Action,
    /// Optional rejection message (only meaningful for Reject)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
}

impl OutputMessage {
    /// Creates a new output message.
    pub fn new(id: String, action: Action, msg: Option<String>) -> Self {
        OutputMessage { id, action, msg }
    }

    /// Convenience constructor for Accept decisions.
    pub fn accept(id: String) -> Self {
        Self::new(id, Action::Accept, None)
    }

    /// Convenience constructor for Reject decisions.
    pub fn reject(id: String, msg: impl Into<String>) -> Self {
        Self::new(id, Action::Reject, Some(msg.into()))
    }

    /// Convenience constructor for ShadowReject decisions.
    pub fn shadow_reject(id: String) -> Self {
        Self::new(id, Action::ShadowReject, None)
    }
}
