use crate::read_filter::{ConnContext, EventVerdict, OpenDecision, ReadFilter};
use crate::readfilters::shm::SharedByteBuckets;
use crate::readmsg::UnparsedNote;
use serde::Deserialize;
use std::collections::HashMap;

/// Nominal event size (bytes) assumed at `reqOpen`, where the next event's real
/// wire size is unknown. Used both to decide whether the IP's bucket can afford
/// "roughly one event" (and so whether to reject the subscription outright) and
/// to estimate the retry hint. A middling nostr event is a few hundred bytes;
/// the real per-event charge on `req` still meters each event's exact size. The
/// threshold is clamped to the bucket capacity below, so a fresh (full) bucket
/// always affords it and only a drained IP trips the reject.
const NOMINAL_EVENT_SIZE: u64 = 512;

/// Default table capacity: distinct IPs before the table fills and fails open.
/// ~65k slots × ~80 bytes ≈ 5 MB on tmpfs.
fn default_max_ips() -> u32 {
    65536
}

/// Where the per-IP byte buckets live for this process.
#[derive(Default)]
enum Store {
    /// Not yet built (built lazily on first `reqOpen`, since construction can't
    /// do I/O).
    #[default]
    Uninit,
    /// A shared path was configured but its `mmap`/init failed: this process
    /// meters nothing and fails open (delivers). Distinct from [`Store::Anon`],
    /// which is the intentional no-path mode.
    Failed,
    /// A working per-IP byte-bucket table (shared file, or a private anonymous
    /// map when no path was configured).
    Map(SharedByteBuckets),
}

/// Read-bandwidth throttle: cap the *bytes* of events delivered per minute,
/// keyed per client IP so reconnecting with a fresh `connId` from the same IP
/// does not reset the budget. The read-side analogue of the write-side
/// `ratelimit` filter, metering the exact wire byte size of each delivered event
/// via a per-IP byte bucket.
///
/// ## Cross-process enforcement
///
/// strfry runs one `noteguard read` process per read-serving thread, each with
/// its own memory, so an IP's reconnects fan across up to `numThreads`
/// processes — making a naive per-process bucket enforce `bytes_per_minute × N`.
/// To enforce ONE authoritative budget per IP while keeping N processes, the
/// buckets live in a shared `mmap`'d table
/// ([`SharedByteBuckets`](crate::readfilters::shm)) named by `shared_state_path`.
/// With no path configured the map is per-process (the old behavior); a
/// configured path that fails to attach fails open (delivers, unmetered).
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

    /// Path to the shared-memory file holding the per-IP buckets, shared by every
    /// `noteguard read` process on the host (all must agree on the path and
    /// `max_ips`). `None` (unset, or empty) => a private per-process map —
    /// accurate only within one process, i.e. the pre-shared-memory behavior. Set
    /// it to a `tmpfs` path such as `/dev/shm/noteguard-read-bandwidth` to enforce
    /// ONE budget per IP across all read processes. A configured but unattachable
    /// path fails open (delivers, unmetered).
    #[serde(default)]
    pub shared_state_path: Option<String>,

    /// Table capacity: distinct IPs held before the table fills and new IPs fail
    /// open (there is no eviction — buckets must survive reconnect). Rounded up
    /// to a power of two.
    #[serde(default = "default_max_ips")]
    pub max_ips: u32,

    /// The per-IP byte buckets for this process. Built lazily on first use.
    #[serde(skip)]
    store: Store,

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

    /// Build the byte-bucket store on first use (construction can't do I/O). A
    /// configured `shared_state_path` opens a shared file; unset (or empty) uses
    /// a private per-process map; a configured path that fails to attach records
    /// [`Store::Failed`] so the filter fails open (delivers, unmetered).
    fn ensure_store(&mut self) {
        if !matches!(self.store, Store::Uninit) {
            return;
        }
        let path = match self.shared_state_path.as_deref() {
            Some("") | None => None,
            Some(p) => Some(p.to_string()),
        };
        self.store = match path {
            None => match SharedByteBuckets::anonymous(self.max_ips) {
                Ok(m) => {
                    log::info!(
                        "read_bandwidth: no shared_state_path; per-process byte buckets \
                         ({} slots) — cross-process enforcement is OFF",
                        m.slot_count()
                    );
                    Store::Map(m)
                }
                Err(e) => {
                    log::error!("read_bandwidth: could not allocate byte buckets ({e}); failing open");
                    Store::Failed
                }
            },
            Some(path) => match SharedByteBuckets::open(&path, self.max_ips) {
                Ok(m) => {
                    log::info!(
                        "read_bandwidth: shared byte buckets at {} ({} slots)",
                        path,
                        m.slot_count()
                    );
                    Store::Map(m)
                }
                Err(e) => {
                    log::error!(
                        "read_bandwidth: shared byte-bucket init failed at {} ({}); \
                         FAILING OPEN (delivering unmetered)",
                        path,
                        e
                    );
                    Store::Failed
                }
            },
        };
    }

    /// The working byte-bucket table, or `None` if metering is unavailable
    /// (a failed shared init) — in which case the filter fails open.
    fn map(&self) -> Option<&SharedByteBuckets> {
        match &self.store {
            Store::Map(m) => Some(m),
            _ => None,
        }
    }
}

impl ReadFilter for ReadBandwidth {
    fn name(&self) -> &'static str {
        "read_bandwidth"
    }

    fn req_open(&mut self, ctx: &ConnContext, _filter: Option<&serde_json::Value>) -> OpenDecision {
        // Build the shared store on first use, then resolve identity once per
        // connection, so the per-event path is a single `connId` lookup with no
        // allocation, no whitelist rescan, and (against an old strfry) one
        // missing-IP warning rather than a flood.
        self.ensure_store();
        let key = self.resolve_key(ctx);
        let cap = self.bytes_per_minute as f64;

        // Peek the IP's (refilled) bucket to decide admission before serving a
        // single event. An already-drained IP is rejected outright so the client
        // gets a NIP-01 CLOSED + retry hint (real backpressure) instead of a
        // silent empty/truncated feed — the reconnect/churn abuse case. While
        // there is still budget we admit and meter per-event on `req` as before.
        //
        // A `None` from the map (fail open) or a failed store leaves this None,
        // so we admit.
        let mut reject_retry_ms: Option<u64> = None;
        if let (Some(key), Some(map)) = (&key, self.map()) {
            if let Some(tokens) = map.tokens_after_refill(key.as_bytes(), cap) {
                // Nominal event size clamped to capacity: a fresh (full) bucket
                // always affords it, so only a drained IP trips the reject.
                let nominal = (NOMINAL_EVENT_SIZE as f64).min(cap);
                if tokens < nominal {
                    // retry_ms: time to refill one nominal event at
                    // bytes_per_minute. An estimate — the next event's real size
                    // is unknown at reqOpen (documented on NOMINAL_EVENT_SIZE).
                    reject_retry_ms = Some(((nominal / cap) * 60_000.0).ceil() as u64);
                }
            }
        }

        // Metering happens only for a keyed connection with a working map; a
        // whitelisted conn (no key) or a failed store does no per-event work.
        let meters = key.is_some() && self.map().is_some();
        self.conn_keys.insert(ctx.conn_id, key);

        if let Some(retry_ms) = reject_retry_ms {
            return OpenDecision::reject(
                Some(format!(
                    "read bandwidth budget exhausted ({} bytes/min per IP)",
                    self.bytes_per_minute
                )),
                Some(retry_ms),
            );
        }

        // A connection we won't meter does no per-event work and can take the
        // passthrough fast path (whitelisted, or the store failed open).
        // Everyone else needs `req` batches so we can meter bytes.
        if meters {
            OpenDecision::needs_events()
        } else {
            OpenDecision::passthrough()
        }
    }

    fn filter_event(&mut self, ctx: &ConnContext, ev: &UnparsedNote) -> EventVerdict {
        // Check only: refill and test affordability, but DON'T spend — the
        // event isn't delivered until every later filter also delivers, so the
        // byte is charged in `on_delivered`.
        //
        // A missing entry means whitelisted, or a `req` for a subscription we
        // never saw open; a missing/failed map means fail open: deliver either
        // way.
        let cap = self.bytes_per_minute as f64;
        let Some(Some(key)) = self.conn_keys.get(&ctx.conn_id) else {
            return EventVerdict::Deliver;
        };
        let Some(map) = self.map() else {
            return EventVerdict::Deliver;
        };

        // Refill (elapsed/60 of a minute's bytes, capped at capacity) then test
        // affordability. `None` (fail open) delivers.
        match map.tokens_after_refill(key.as_bytes(), cap) {
            Some(tokens) if tokens < ev.size() as f64 => EventVerdict::Stop,
            _ => EventVerdict::Deliver,
        }
    }

    fn on_delivered(&mut self, ctx: &ConnContext, ev: &UnparsedNote) {
        // The bucket was resolved (and refilled) in `filter_event` for this same
        // event; charge the delivered event's exact wire size. Best-effort: a
        // fail-open acquire just skips the charge.
        let cap = self.bytes_per_minute as f64;
        let Some(Some(key)) = self.conn_keys.get(&ctx.conn_id) else {
            return;
        };
        let Some(map) = self.map() else {
            return;
        };
        map.spend(key.as_bytes(), cap, ev.size() as f64);
    }

    fn conn_close(&mut self, conn_id: u64) {
        // Only the resolved key is per-connection. NB: no bucket eviction —
        // buckets are keyed by IP and must survive a reconnect, else the per-IP
        // budget resets.
        self.conn_keys.remove(&conn_id);
    }
}
