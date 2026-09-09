use crate::read_filter::{ConnContext, EventVerdict, OpenDecision, ReadFilter};
use crate::readmsg::UnparsedNote;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// An `Instant` token bucket of *bytes*, keyed per client IP. Mirrors the
/// write-side `ratelimit.rs` mechanism (there tokens are posts; here they are
/// bytes). Refills at `bytes_per_minute` bytes per minute up to that capacity,
/// and — like `ratelimit.rs`'s `sources` map — is **never evicted**: surviving a
/// reconnect is the entire point of keying on IP.
struct ByteBucket {
    /// Bytes of budget currently available. Starts full (capacity).
    tokens: f64,
    /// When `tokens` was last refilled.
    last_refill: Instant,
}

/// Read-bandwidth throttle: cap the *bytes* of events delivered per minute,
/// keyed per client IP so reconnecting with a fresh `connId` from the same IP
/// does not reset the budget. The read-side analogue of the write-side
/// `ratelimit` filter, metering the exact wire byte size of each delivered event
/// via a per-IP byte bucket.
///
/// Once an IP's bucket can't cover the next event, the rest of the batch is
/// withheld ([`EventVerdict::Stop`]). A whitelisted connection is exempt
/// entirely — and, since it then does no per-event work, is reported as
/// passthrough at `reqOpen`.
#[derive(Deserialize, Default)]
pub struct ReadBandwidth {
    /// Max bytes of events delivered per minute, per IP (bucket capacity).
    pub bytes_per_minute: u64,

    /// Entries exempt from the throttle: an entry matches a connection's client
    /// IP **or** its authed pubkey hex.
    #[serde(default)]
    pub whitelist: Vec<String>,

    /// Client IP (or `conn:<id>` fallback) -> its byte bucket. Never evicted, so
    /// a reconnect from the same IP shares the same budget.
    #[serde(skip)]
    buckets: HashMap<String, ByteBucket>,

    /// `connId` -> the bucket key to charge, resolved once at `reqOpen` (a
    /// connection's IP, whitelist status and authed pubkey are fixed for its
    /// life). `None` means exempt — whitelisted, so never metered. Freed at
    /// `connClose`; the buckets themselves are not.
    #[serde(skip)]
    conn_keys: HashMap<u64, Option<String>>,
}

impl ReadBandwidth {
    /// Whether this connection is exempt: a whitelist entry matching its client
    /// IP or authed pubkey.
    fn whitelisted(&self, ctx: &ConnContext) -> bool {
        if self.whitelist.is_empty() {
            return false;
        }
        let hit = |v: Option<&str>| v.is_some_and(|v| self.whitelist.iter().any(|e| e == v));
        hit(ctx.ip) || hit(ctx.authed)
    }

    /// The bucket key to charge this connection against: `None` if it is
    /// whitelisted, else its client IP, or a per-connection fallback when strfry
    /// sent no IP (old strfry — metering then degrades to per-connection and
    /// resets on reconnect).
    fn resolve_key(&self, ctx: &ConnContext) -> Option<String> {
        if self.whitelisted(ctx) {
            return None;
        }
        Some(match ctx.ip {
            Some(ip) => ip.to_string(),
            None => {
                log::warn!(
                    "readpolicy: no client IP for conn={} (old strfry?); metering \
                     bandwidth per-connection (resets on reconnect)",
                    ctx.conn_id
                );
                format!("conn:{}", ctx.conn_id)
            }
        })
    }
}

impl ReadFilter for ReadBandwidth {
    fn name(&self) -> &'static str {
        "read_bandwidth"
    }

    fn req_open(&mut self, ctx: &ConnContext, _filter: Option<&serde_json::Value>) -> OpenDecision {
        // Resolve identity once per connection, so the per-event path is a
        // single `connId` lookup with no allocation, no whitelist rescan, and
        // (against an old strfry) one missing-IP warning rather than a flood.
        let key = self.resolve_key(ctx);
        if let Some(key) = &key {
            // Create the bucket full on first sight of this IP — but never
            // reset an existing one, which must survive a reconnect.
            let cap = self.bytes_per_minute as f64;
            self.buckets.entry(key.clone()).or_insert(ByteBucket {
                tokens: cap,
                last_refill: Instant::now(),
            });
        }
        let exempt = key.is_none();
        self.conn_keys.insert(ctx.conn_id, key);

        // A whitelisted connection is never metered, so it does no per-event
        // work and can take the passthrough fast path. Everyone else needs `req`
        // batches so we can meter bytes.
        if exempt {
            OpenDecision::passthrough()
        } else {
            OpenDecision::needs_events()
        }
    }

    fn filter_event(&mut self, ctx: &ConnContext, ev: &UnparsedNote) -> EventVerdict {
        // Check only: refill and test affordability, but DON'T spend — the
        // event isn't delivered until every later filter also delivers, so the
        // byte is charged in `on_delivered`.
        //
        // A missing entry means whitelisted, or a `req` for a subscription we
        // never saw open: deliver either way (fail open).
        let cap = self.bytes_per_minute as f64;
        let Self {
            buckets, conn_keys, ..
        } = self;
        let Some(Some(key)) = conn_keys.get(&ctx.conn_id) else {
            return EventVerdict::Deliver;
        };
        let Some(bucket) = buckets.get_mut(key) else {
            return EventVerdict::Deliver;
        };

        // Refill: elapsed/60 of a full minute's worth of bytes, clamped to a
        // minute and capped at capacity (same shape as ratelimit.rs).
        let now = Instant::now();
        let mut elapsed = now.duration_since(bucket.last_refill);
        let min = Duration::from_secs(60);
        if elapsed > min {
            elapsed = min;
        }
        let refill = (elapsed.as_secs_f64() / 60.0) * cap;
        bucket.tokens = (bucket.tokens + refill).min(cap);
        bucket.last_refill = now;

        if bucket.tokens < ev.size() as f64 {
            EventVerdict::Stop
        } else {
            EventVerdict::Deliver
        }
    }

    fn on_delivered(&mut self, ctx: &ConnContext, ev: &UnparsedNote) {
        // The bucket was resolved (and refilled) in `filter_event` for this same
        // event, so it exists; charge the delivered event's exact wire size.
        let Self {
            buckets, conn_keys, ..
        } = self;
        if let Some(Some(key)) = conn_keys.get(&ctx.conn_id) {
            if let Some(bucket) = buckets.get_mut(key) {
                bucket.tokens -= ev.size() as f64;
            }
        }
    }

    fn conn_close(&mut self, conn_id: u64) {
        // Only the resolved key is per-connection. NB: no bucket eviction —
        // buckets are keyed by IP and must survive a reconnect, else the per-IP
        // budget resets.
        self.conn_keys.remove(&conn_id);
    }
}
