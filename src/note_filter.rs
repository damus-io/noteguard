//! Core filter trait and Nostr event representation.

use crate::{InputMessage, OutputMessage};
use serde::{Deserialize, Serialize};

/// A Nostr event in its raw form.
///
/// This is a simplified representation suitable for filtering.
/// It mirrors the standard Nostr event structure from NIP-01.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Note {
    /// Event ID (32-byte hex)
    pub id: String,
    /// Author's public key (32-byte hex)
    pub pubkey: String,
    /// Event content
    pub content: String,
    /// Unix timestamp of creation
    pub created_at: i64,
    /// Event kind number
    pub kind: i64,
    /// Event tags (array of string arrays)
    pub tags: Vec<Vec<String>>,
    /// Schnorr signature
    pub sig: String,
}

/// Trait for implementing event filters.
///
/// Filters are stateful - they can maintain internal state like rate limit
/// token buckets. The `&mut self` parameter allows filters to update their
/// state on each invocation.
///
/// Filters must be `Send` to allow use across async task boundaries.
///
/// ## Implementing a Custom Filter
///
/// ```ignore
/// use noteguard::{NoteFilter, InputMessage, OutputMessage, Action};
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Default)]
/// pub struct MyFilter {
///     some_config: String,
/// }
///
/// impl NoteFilter for MyFilter {
///     fn name(&self) -> &'static str {
///         "my_filter"  // Used as key in noteguard.toml
///     }
///
///     fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
///         // Your filtering logic here
///         OutputMessage::accept(msg.event.id.clone())
///     }
/// }
/// ```
pub trait NoteFilter: Send {
    /// Applies the filter to an input message.
    ///
    /// Returns an `OutputMessage` indicating whether to accept or reject.
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage;

    /// Returns the configuration key for this filter.
    ///
    /// This must match the key used in the TOML config file.
    fn name(&self) -> &'static str;
}
