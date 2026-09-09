//! Reusable per-IP strike counter + temporary IP-ban, shared by write-path
//! filters that want to escalate repeat offenders into a short block.
//!
//! A filter embeds a [`BanTracker`] with `#[serde(flatten)]`, so its
//! `ban_after` / `ban_duration_secs` / `ban_message` knobs live at the filter's
//! own config table level. The tracker keeps the state; the *filter* decides
//! what a "strike" is (a rate-limit hit, a content match, …) and what action to
//! return while banned (a visible `Reject`, a stealth `ShadowReject`, …).
//!
//! Two streak policies fall out of which methods a filter calls:
//!
//! * **Consecutive** (e.g. `ratelimit`): call [`reset`](BanTracker::reset) on
//!   every clean event, so only an unbroken run of violations bans.
//! * **Cumulative** (e.g. `content`): never call `reset`, so violations accrue
//!   across a session until they cross the threshold.
//!
//! When `ban_after` is unset the tracker is inert and stores no per-IP state, so
//! a filter that leaves banning unconfigured behaves exactly as it did before.

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default ban length once an IP crosses the threshold: one hour.
const DEFAULT_BAN_DURATION_SECS: u64 = 3600;

/// The `ban_*` knobs, deserialized flat into the embedding filter's config.
#[derive(Deserialize, Default)]
struct BanConfig {
    /// IP-ban an offender after this many strikes. `None` disables banning.
    ban_after: Option<i32>,
    /// How long a ban lasts, in seconds. Defaults to [`DEFAULT_BAN_DURATION_SECS`].
    ban_duration_secs: Option<u64>,
    /// Message returned to a banned IP (filters that shadow-reject may ignore it).
    ban_message: Option<String>,
}

struct BanState {
    strikes: i32,
    banned_until: Option<Instant>,
}

/// Per-IP strike tracking plus the active-ban set. See the [module docs](self).
#[derive(Default)]
pub struct BanTracker {
    config: BanConfig,
    ips: HashMap<String, BanState>,
}

// Deserialized via the flattened `BanConfig`; the state map always starts empty.
impl<'de> Deserialize<'de> for BanTracker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(BanTracker {
            config: BanConfig::deserialize(deserializer)?,
            ips: HashMap::new(),
        })
    }
}

impl BanTracker {
    /// The message handed to a banned IP, or a generic fallback.
    pub fn message(&self) -> &str {
        self.config
            .ban_message
            .as_deref()
            .unwrap_or("banned: too many violations, try again later")
    }

    /// Whether `ip` is under an active ban. An expired ban is cleared here, along
    /// with its strike streak, so the next event starts fresh.
    pub fn is_banned(&mut self, ip: &str, now: Instant) -> bool {
        let Some(state) = self.ips.get_mut(ip) else {
            return false;
        };
        match state.banned_until {
            Some(until) if now < until => true,
            Some(_) => {
                state.banned_until = None;
                state.strikes = 0;
                false
            }
            None => false,
        }
    }

    /// Record a violation for `ip`. Returns `true` if this strike crossed
    /// `ban_after` and the IP is now banned. A no-op returning `false` when
    /// banning is disabled, so callers keep zero per-IP state in that case.
    pub fn strike(&mut self, ip: &str, now: Instant) -> bool {
        let Some(ban_after) = self.config.ban_after else {
            return false;
        };

        let state = self.ips.entry(ip.to_owned()).or_insert(BanState {
            strikes: 0,
            banned_until: None,
        });
        state.strikes += 1;

        if state.strikes >= ban_after {
            let secs = self
                .config
                .ban_duration_secs
                .unwrap_or(DEFAULT_BAN_DURATION_SECS);
            state.banned_until = Some(now + Duration::from_secs(secs));
            // Escalate to the edge if a Cloudflare banner is configured. This is
            // the single choke point every write-path filter's ban flows through,
            // so both ratelimit and content get edge-banning for free. No-op
            // unless the `cloudflare` feature is built and `[cloudflare]` is set.
            #[cfg(feature = "cloudflare")]
            crate::cloudflare::edge_ban(ip, Duration::from_secs(secs));
            true
        } else {
            false
        }
    }

    /// Clear `ip`'s strike streak after a clean event (the "consecutive" policy).
    /// Filters with cumulative semantics simply never call this.
    pub fn reset(&mut self, ip: &str) {
        if let Some(state) = self.ips.get_mut(ip) {
            state.strikes = 0;
        }
    }
}
