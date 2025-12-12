//! Whitelist filter - only allows events from approved sources.
//!
//! If configured, ONLY events from listed pubkeys or IPs are accepted.
//! All others are rejected.

use crate::{InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

/// Whitelist filter - rejects events not from approved sources.
///
/// This is an allow-list: if any whitelist is configured, only matching
/// sources are accepted. Useful for private relays or testing.
///
/// ## Configuration
///
/// ```toml
/// [filters.whitelist]
/// pubkeys = ["abc123..."]  # Optional: allowed public keys
/// ips = ["192.168.1.1"]    # Optional: allowed IP addresses
/// ```
///
/// If both are specified, matching either allows the event.
#[derive(Deserialize, Default)]
pub struct Whitelist {
    /// Allowed public keys (hex format)
    pub pubkeys: Option<Vec<String>>,
    /// Allowed IP addresses
    pub ips: Option<Vec<String>>,
}

impl NoteFilter for Whitelist {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        // Check pubkey whitelist
        if let Some(pubkeys) = &self.pubkeys {
            if pubkeys.contains(&msg.event.pubkey) {
                return OutputMessage::accept(msg.event.id.clone());
            }
        }

        // Check IP whitelist
        if let Some(ips) = &self.ips {
            if ips.contains(&msg.source_info) {
                return OutputMessage::accept(msg.event.id.clone());
            }
        }

        // No whitelist matched - reject
        OutputMessage::reject(
            msg.event.id.clone(),
            "blocked: pubkey/ip not on the whitelist",
        )
    }

    fn name(&self) -> &'static str {
        "whitelist"
    }
}
