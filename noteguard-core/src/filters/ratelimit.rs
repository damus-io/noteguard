//! Token bucket rate limiter filter.
//!
//! Limits the number of events per minute from each source IP.
//! Uses a token bucket algorithm that refills over time.

use crate::{InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Token bucket state for a single source.
pub struct Tokens {
    pub tokens: i32,
    pub last_post: Instant,
}

/// Rate limiting filter using token bucket algorithm.
///
/// Each source IP gets a bucket of tokens that refills over time.
/// Posting consumes a token; empty bucket = rate limited.
///
/// ## Configuration
///
/// ```toml
/// [filters.ratelimit]
/// posts_per_minute = 10
/// whitelist = ["trusted-ip"]  # Optional: IPs exempt from rate limiting
/// message = "slow down"       # Optional: custom rejection message
/// ```
#[derive(Deserialize, Default)]
pub struct RateLimit {
    /// Maximum posts allowed per minute
    pub posts_per_minute: i32,
    /// Source IPs exempt from rate limiting
    pub whitelist: Option<Vec<String>>,
    /// Custom rejection message
    pub message: Option<String>,

    /// Internal state: token buckets per source IP
    #[serde(skip)]
    pub sources: HashMap<String, Tokens>,
}

impl NoteFilter for RateLimit {
    fn name(&self) -> &'static str {
        "ratelimit"
    }

    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        // Whitelisted sources bypass rate limiting
        if let Some(whitelist) = &self.whitelist {
            if whitelist.contains(&msg.source_info) {
                return OutputMessage::accept(msg.event.id.clone());
            }
        }

        // First post from this source - initialize bucket
        if !self.sources.contains_key(&msg.source_info) {
            self.sources.insert(
                msg.source_info.to_owned(),
                Tokens {
                    last_post: Instant::now(),
                    tokens: self.posts_per_minute,
                },
            );
            return OutputMessage::accept(msg.event.id.clone());
        }

        // Refill tokens based on elapsed time
        let entry = self.sources.get_mut(&msg.source_info).expect("checked above");
        let now = Instant::now();
        let elapsed = (now - entry.last_post).min(Duration::from_secs(60));

        let refill_percent = elapsed.as_secs_f32() / 60.0;
        let new_tokens = (refill_percent * self.posts_per_minute as f32).floor() as i32;
        entry.tokens = (entry.tokens + new_tokens - 1)
            .max(0)
            .min(self.posts_per_minute - 1);

        // Check if rate limited
        if entry.tokens == 0 {
            let message = self
                .message
                .as_deref()
                .unwrap_or("rate-limited: you are noting too much");
            return OutputMessage::reject(msg.event.id.clone(), message);
        }

        entry.last_post = now;
        OutputMessage::accept(msg.event.id.clone())
    }
}
