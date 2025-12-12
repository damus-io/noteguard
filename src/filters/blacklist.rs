//! Blacklist filter - blocks events from banned sources.
//!
//! Supports blocking by pubkey, IP address, or CIDR range.

use crate::{InputMessage, NoteFilter, OutputMessage};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;

/// Configuration structure for deserialization.
#[derive(Deserialize, Default)]
pub struct BlacklistConfig {
    pub pubkeys: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
    pub cidrs: Option<Vec<String>>,
}

/// Blacklist filter - rejects events from banned sources.
///
/// Unlike whitelist, this is a deny-list: only matching sources are
/// rejected, all others pass through.
///
/// ## Configuration
///
/// ```toml
/// [filters.blacklist]
/// pubkeys = ["spammer123..."]     # Optional: blocked public keys
/// ips = ["1.2.3.4"]               # Optional: blocked IP addresses
/// cidrs = ["10.0.0.0/8"]          # Optional: blocked CIDR ranges
/// ```
#[derive(Default)]
pub struct Blacklist {
    /// Blocked public keys
    pubkeys: Option<Vec<String>>,
    /// Blocked individual IPs
    ips: Option<Vec<String>>,
    /// Blocked CIDR ranges (parsed from config)
    cidrs: Option<Vec<IpNetwork>>,
}

impl<'de> Deserialize<'de> for Blacklist {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let config = BlacklistConfig::deserialize(deserializer)?;
        Ok(Blacklist {
            pubkeys: config.pubkeys,
            ips: config.ips,
            cidrs: config.cidrs.map(|cidrs| {
                cidrs
                    .into_iter()
                    .filter_map(|s| IpNetwork::from_str(&s).ok())
                    .collect()
            }),
        })
    }
}

impl Blacklist {
    /// Checks if an IP is blocked by direct match or CIDR range.
    fn is_ip_blocked(&self, ip: &str) -> bool {
        // Check direct IP match
        if let Some(ips) = &self.ips {
            if ips.contains(&ip.to_string()) {
                return true;
            }
        }

        // Check CIDR ranges
        let Ok(addr) = IpAddr::from_str(ip) else {
            return false;
        };

        if let Some(cidrs) = &self.cidrs {
            if cidrs.iter().any(|network| network.contains(addr)) {
                return true;
            }
        }

        false
    }
}

impl NoteFilter for Blacklist {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        let reject_message = "blocked: pubkey/ip is blacklisted";

        // Check pubkey blacklist
        if let Some(pubkeys) = &self.pubkeys {
            if pubkeys.contains(&msg.event.pubkey) {
                return OutputMessage::reject(msg.event.id.clone(), reject_message);
            }
        }

        // Check IP blacklist
        if self.is_ip_blocked(&msg.source_info) {
            return OutputMessage::reject(msg.event.id.clone(), reject_message);
        }

        OutputMessage::accept(msg.event.id.clone())
    }

    fn name(&self) -> &'static str {
        "blacklist"
    }
}
