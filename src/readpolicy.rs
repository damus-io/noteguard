//! Read-side (readPolicy) plugin engine.
//!
//! Speaks strfry's per-subscription REQ deliverability protocol
//! ([`crate::readmsg`]) and drives a config-composed pipeline of
//! [`ReadFilter`]s to make per-subscriber, per-event deliver/withhold decisions.
//! It is the read-path counterpart to the write-side [`Noteguard`] engine in
//! `main.rs`: a name-keyed `registered_filters` registry, a
//! [`register_filter`](ReadPolicy::register_filter) hook, and a config-driven
//! `pipeline: Vec<String>` composed in [`load_config`](ReadPolicy::load_config).
//!
//! ## Batch semantics (the check / commit split)
//!
//! Unlike the write side's pure `fn(event) -> action`, read filters carry
//! cross-event state (a per-IP byte bucket, a per-conn counter) and can withhold
//! the *rest* of a batch once a budget is exhausted. To compose these correctly
//! the engine runs a **two-phase** batch loop per event:
//!
//! 1. [`filter_event`](ReadFilter::filter_event) — a *check* over the pipeline in
//!    order. First [`Skip`](EventVerdict::Skip) withholds just this event; first
//!    [`Stop`](EventVerdict::Stop) withholds this event and breaks the batch. A
//!    filter must not consume budget here.
//! 2. [`on_delivered`](ReadFilter::on_delivered) — called on every filter, in
//!    order, *only if* every filter delivered the event, so counters/buckets
//!    advance exactly once and only for events that actually reach the client.
//!
//! This reproduces the old inline `continue`/`break` semantics faithfully: an
//! event a later filter withholds never charges an earlier filter's budget.
//!
//! ## Fail-open
//!
//! Like strfry, this loop FAILS OPEN. Filters honour that internally (a guest
//! trap delivers); the engine no-responds on unparseable input so strfry times
//! out and delivers, and a bad/unknown pipeline entry is logged and skipped
//! rather than aborting the loop.
//!
//! As an optimization, a subscription whose filters all report `!needs_events`
//! answers `reqOpen` with `passthrough: true`, telling strfry to skip per-event
//! marshaling and deliver via the zero-copy fast path (no `req` batches).

use crate::read_filter::{Admission, ConnContext, EventVerdict, OpenDecision, ReadFilter};
use crate::readfilters::{MaxEventsPerConn, ReadBandwidth};
use crate::readmsg::{ReadInput, ReqOpenResponse, ReqResponse, UnparsedNote};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

#[cfg(feature = "nscript")]
use crate::readfilters::NScriptRead;

/// The `[readpolicy]` config table (read from `noteguard.toml`, or the file
/// named by `$NOTEGUARD_CONFIG`). Mirrors the write-side `Config`: an ordered
/// `pipeline` of filter names plus a `filters` map of each filter's own config.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ReadPolicyConfig {
    /// Ordered list of read-filter names to compose. Empty => deliver all
    /// (every subscription is passthrough).
    pub pipeline: Vec<String>,

    /// Per-filter config tables, keyed by filter name (`[readpolicy.filters.X]`).
    pub filters: HashMap<String, toml::Value>,
}

/// Wrapper matching the surrounding `noteguard.toml` shape so the read loop can
/// share the same config file as the write loop (the write-side `pipeline` and
/// `filters` keys are ignored by serde here).
#[derive(Deserialize, Default)]
struct FileConfig {
    readpolicy: Option<ReadPolicyConfig>,
}

/// Per-connection identity captured at `reqOpen` and freed at `connClose`.
/// Cached because `req` batches carry no client IP, but a per-IP filter must
/// meter on `req` — so the engine caches the IP (and `authed`, for whitelists)
/// under `connId` and hands it to filters via [`ConnContext`].
struct ConnInfo {
    ip: Option<String>,
    authed: Option<String>,
}

/// Constructs a boxed [`ReadFilter`] from its TOML config. Mirrors the
/// write-side `ConstructFilter`.
type ConstructReadFilter = Box<fn(toml::Value) -> Result<Box<dyn ReadFilter>, toml::de::Error>>;

/// The read-policy engine: a name-keyed filter registry, the loaded pipeline,
/// and the engine-owned shared per-connection context.
#[derive(Default)]
pub struct ReadPolicy {
    registered_filters: HashMap<String, ConstructReadFilter>,
    pipeline: Vec<Box<dyn ReadFilter>>,
    /// `connId` -> its IP/authed identity, cached at `reqOpen`. Freed at
    /// `connClose`.
    conn_info: HashMap<u64, ConnInfo>,
}

impl ReadPolicy {
    /// A new engine with all built-in filters registered but an empty pipeline
    /// (call [`load_config`](Self::load_config) to compose it).
    pub fn new() -> Self {
        let mut rp = ReadPolicy::default();
        rp.register_builtin_filters();
        rp
    }

    /// Register a read filter, keyed by its [`name`](ReadFilter::name). Mirrors
    /// the write-side `register_filter`.
    pub fn register_filter<F: ReadFilter + 'static + Default + DeserializeOwned>(&mut self) {
        self.registered_filters.insert(
            F::name(&F::default()).to_string(),
            Box::new(|filter_config| {
                filter_config
                    .try_into()
                    .map(|filter: F| Box::new(filter) as Box<dyn ReadFilter>)
            }),
        );
    }

    /// All built-in read filters, available on every new [`ReadPolicy`]. The
    /// guest (`nscript`) filter is registered only in `nscript` builds.
    fn register_builtin_filters(&mut self) {
        self.register_filter::<MaxEventsPerConn>();
        self.register_filter::<ReadBandwidth>();

        #[cfg(feature = "nscript")]
        self.register_filter::<NScriptRead>();
    }

    /// Compose the pipeline from config. Unlike the write side (which panics on a
    /// bad/unknown pipeline entry), the read side fails open: a bad or unknown
    /// entry is logged and skipped, since a misconfigured read filter must not
    /// take down a subscriber's feed.
    pub fn load_config(&mut self, config: &ReadPolicyConfig) {
        self.pipeline.clear();

        for name in &config.pipeline {
            let cfg = config
                .filters
                .get(name)
                .cloned()
                .unwrap_or_else(|| toml::Value::Table(Default::default()));

            match self.registered_filters.get(name.as_str()) {
                Some(constructor) => match constructor(cfg) {
                    Ok(filter) => self.pipeline.push(filter),
                    Err(e) => log::error!(
                        "readpolicy: bad config for filter '{}' ({}); skipping (fail open)",
                        name,
                        e
                    ),
                },
                None => log::error!(
                    "readpolicy: unknown read filter '{}'; skipping (fail open)",
                    name
                ),
            }
        }
    }

    /// Handle one input line. Returns `Some(json)` to write back for
    /// `reqOpen`/`req`, or `None` for the fire-and-forget lifecycle messages
    /// (`reqClose`/`connClose`) and unparseable input (strfry fails open on no
    /// response).
    pub fn handle(&mut self, line: &str) -> Option<String> {
        let input: ReadInput = match serde_json::from_str(line) {
            Ok(input) => input,
            Err(e) => {
                // Can't recover a reqId, so we can't respond; strfry will time
                // out and deliver (fail open).
                log::error!("readpolicy: unparseable input ({}): {}", e, line);
                return None;
            }
        };

        match input {
            ReadInput::ReqOpen {
                req_id,
                conn_id,
                sub_id,
                authed,
                filter,
                ip,
            } => {
                log::info!(
                    "reqOpen conn={} sub={} authed={:?} ip={:?} filter={}",
                    conn_id,
                    sub_id,
                    authed,
                    ip,
                    filter.as_ref().map(|f| f.to_string()).unwrap_or_default()
                );
                Some(json(
                    &self.req_open(req_id, conn_id, sub_id, authed, ip, filter),
                ))
            }

            ReadInput::Req {
                req_id,
                conn_id,
                sub_id,
                authed: _,
                events,
            } => {
                let accept = self.filter_batch(conn_id, &sub_id, &events);
                log::info!(
                    "req conn={} sub={} events={} delivered={}",
                    conn_id,
                    sub_id,
                    events.len(),
                    accept.len()
                );
                Some(json(&ReqResponse { req_id, accept }))
            }

            ReadInput::ReqClose { conn_id, sub_id } => {
                log::info!("reqClose conn={} sub={}", conn_id, sub_id);
                for filter in &mut self.pipeline {
                    filter.req_close(conn_id, &sub_id);
                }
                None
            }

            ReadInput::ConnClose { conn_id } => {
                log::info!("connClose conn={}", conn_id);
                for filter in &mut self.pipeline {
                    filter.conn_close(conn_id);
                }
                self.conn_info.remove(&conn_id);
                None
            }
        }
    }

    /// Admit (or refuse) a subscription. Caches the connection identity, runs
    /// every filter's `req_open`, and composes the result: reject if any filter
    /// rejects (first message wins), else accept — with `passthrough` iff NO
    /// filter needs per-event batches.
    fn req_open(
        &mut self,
        req_id: u64,
        conn_id: u64,
        sub_id: String,
        authed: Option<String>,
        ip: Option<String>,
        filter: Option<serde_json::Value>,
    ) -> ReqOpenResponse {
        // Cache the connection's identity so per-IP filters can meter on `req`,
        // which carries no IP. Refreshed on each reqOpen (a connection's IP is
        // stable, but a later AUTH can add an authed pubkey).
        self.conn_info.insert(
            conn_id,
            ConnInfo {
                ip: ip.clone(),
                authed: authed.clone(),
            },
        );

        let ctx = ConnContext {
            conn_id,
            sub_id: &sub_id,
            ip: ip.as_deref(),
            authed: authed.as_deref(),
        };

        // Run req_open on EVERY filter (so each allocates its per-sub state and
        // gets symmetric reqClose/connClose cleanup even under reject), while
        // collecting the composed decision.
        let mut needs_events = false;
        let mut reject: Option<(Option<String>, Option<u64>)> = None;
        for f in &mut self.pipeline {
            let decision = f.req_open(&ctx, filter.as_ref());
            let OpenDecision {
                admission,
                needs_events: filter_needs,
            } = decision;
            needs_events |= filter_needs;
            if reject.is_none() {
                if let Admission::Reject { msg, retry_ms } = admission {
                    reject = Some((msg, retry_ms));
                }
            }
        }

        if let Some((msg, retry_ms)) = reject {
            return ReqOpenResponse::reject(req_id, msg, retry_ms);
        }

        // Passthrough iff no filter needs per-event work: strfry skips per-event
        // marshaling and delivers via its zero-copy fast path.
        ReqOpenResponse::accept(req_id, !needs_events)
    }

    /// Decide which events in a batch to deliver by running the two-phase
    /// pipeline (see the module docs). Returns the accept-list of event ids.
    fn filter_batch(&mut self, conn_id: u64, sub_id: &str, events: &[UnparsedNote]) -> Vec<String> {
        // Resolve the connection's cached identity (req carries no IP).
        // Destructured so the conn_info borrow is disjoint from the pipeline's.
        let ReadPolicy {
            pipeline,
            conn_info,
            ..
        } = self;
        let conn = conn_info.get(&conn_id);
        let ctx = ConnContext {
            conn_id,
            sub_id,
            ip: conn.and_then(|c| c.ip.as_deref()),
            authed: conn.and_then(|c| c.authed.as_deref()),
        };

        // The accept-list can never exceed the batch.
        let mut accept = Vec::with_capacity(events.len());
        'batch: for ev in events {
            // Phase 1: check the pipeline in order. First Skip withholds this
            // event; first Stop withholds this event and the rest of the batch.
            let mut deliver = true;
            for filter in pipeline.iter_mut() {
                match filter.filter_event(&ctx, ev) {
                    EventVerdict::Deliver => {}
                    EventVerdict::Skip => {
                        deliver = false;
                        break;
                    }
                    EventVerdict::Stop => break 'batch,
                }
            }
            if !deliver {
                continue;
            }

            // Phase 2: the event is delivered by ALL filters — commit budget.
            for filter in pipeline.iter_mut() {
                filter.on_delivered(&ctx, ev);
            }

            // Accept-list needs the id. A cheap id-only parse — the bandwidth-
            // only path still never full-parses. A malformed id (should not
            // happen post-delivery) just drops the event from the accept-list.
            match ev.id() {
                Ok(id) => accept.push(id),
                Err(e) => log::error!("readpolicy: unparseable event id (withholding): {}", e),
            }
        }
        accept
    }
}

/// Serialize a response to minified JSON (never fails for our types).
fn json<T: serde::Serialize>(msg: &T) -> String {
    serde_json::to_string(msg).expect("read policy response should always serialize")
}

/// Load the `[readpolicy]` table from the shared config file
/// ([`crate::config_path`]). A missing file or absent `[readpolicy]` table
/// yields the default (empty pipeline => deliver-all) config.
///
/// (Named apart from [`ReadPolicy::load_config`], which composes the pipeline
/// from an already-parsed config.)
fn read_config_file() -> ReadPolicyConfig {
    let path = crate::config_path();

    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("readpolicy: no config at {} ({}); delivering all", path, e);
            return ReadPolicyConfig::default();
        }
    };

    match toml::from_str::<FileConfig>(&contents) {
        Ok(cfg) => cfg.readpolicy.unwrap_or_default(),
        Err(e) => {
            log::error!("readpolicy: bad config {} ({}); delivering all", path, e);
            ReadPolicyConfig::default()
        }
    }
}

/// The `noteguard read` entrypoint: read line-delimited JSON requests from
/// stdin, write line-delimited JSON responses to stdout (line-buffered).
pub fn run() {
    log::info!("running noteguard read policy");
    let config = read_config_file();
    log::info!(
        "readpolicy pipeline: {:?} ({} filter configs)",
        config.pipeline,
        config.filters.len()
    );

    let mut engine = ReadPolicy::new();
    engine.load_config(&config);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("readpolicy: failed to read line: {}", e);
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        if let Some(response) = engine.handle(&line) {
            if writeln!(out, "{}", response).is_err() {
                break;
            }
            // strfry reads a response per request; keep the pipe line-buffered.
            let _ = out.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an engine from a `[readpolicy]`-inner TOML fragment (pipeline +
    /// filter tables), exercising the real registry + config path.
    ///
    /// NB: every `read_bandwidth` fragment below sets `shared_state_path = ""`
    /// (the per-process opt-out). Unset, the filter now DEFAULTS to the shared
    /// `/dev/shm` file, so tests would share (and pollute) one real host path and
    /// cross-contaminate each other's buckets — `""` gives each test a fresh,
    /// isolated, in-process map.
    fn engine(config: &str) -> ReadPolicy {
        let config: ReadPolicyConfig = toml::from_str(config).expect("test config parses");
        let mut engine = ReadPolicy::new();
        engine.load_config(&config);
        engine
    }

    /// An [`UnparsedNote`] built from wire JSON so `size()` is realistic.
    fn unparsed_note(id: &str, kind: i64, content: &str) -> UnparsedNote {
        let json = format!(
            r#"{{"id":"{}","pubkey":"00","content":"{}","created_at":0,"kind":{},"tags":[],"sig":"00"}}"#,
            id, content, kind
        );
        UnparsedNote::from_json(&json).unwrap()
    }

    fn events(ids: &[&str]) -> Vec<UnparsedNote> {
        ids.iter().map(|id| unparsed_note(id, 1, "")).collect()
    }

    fn parse_accept(json: &str) -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["accept"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn empty_pipeline_delivers_all_via_passthrough() {
        // No filters => no per-event work => passthrough (strfry fast path).
        let mut engine = engine("pipeline = []");

        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","authed":"aa"}"#)
            .unwrap();
        assert_eq!(open, r#"{"reqId":0,"action":"accept","passthrough":true}"#);

        // Belt-and-suspenders: if an older strfry still sends `req` for a
        // passthrough sub, we deliver everything anyway.
        let resp = engine
            .handle(
                r#"{"type":"req","reqId":1,"connId":1,"subId":"s","events":[{"id":"a","pubkey":"0","content":"","created_at":0,"kind":1,"tags":[],"sig":"0"},{"id":"b","pubkey":"0","content":"","created_at":0,"kind":1,"tags":[],"sig":"0"}]}"#,
            )
            .unwrap();
        assert_eq!(parse_accept(&resp), vec!["a", "b"]);
    }

    #[test]
    fn count_throttle_disables_passthrough() {
        // A configured throttle means strfry must keep sending `req` batches so
        // the connId counter can shrink delivery — so NOT passthrough.
        let mut engine = engine(
            r#"
            pipeline = ["max_events_per_conn"]
            [filters.max_events_per_conn]
            max = 10
        "#,
        );
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s"}"#)
            .unwrap();
        assert_eq!(open, r#"{"reqId":0,"action":"accept"}"#);
    }

    #[test]
    fn count_throttle_caps_delivery_per_connection() {
        let mut engine = engine(
            r#"
            pipeline = ["max_events_per_conn"]
            [filters.max_events_per_conn]
            max = 3
        "#,
        );
        engine.handle(r#"{"type":"reqOpen","reqId":0,"connId":7,"subId":"s"}"#);

        // Two batches of 2 events; only the first 3 (across batches) deliver.
        let first = engine.filter_batch(7, "s", &events(&["a", "b"]));
        assert_eq!(first, vec!["a", "b"]);

        let second = engine.filter_batch(7, "s", &events(&["c", "d"]));
        assert_eq!(second, vec!["c"]); // 3rd delivered, 4th withheld by cap

        let third = engine.filter_batch(7, "s", &events(&["e"]));
        assert!(third.is_empty()); // cap already reached
    }

    #[test]
    fn conn_close_frees_state_and_lifecycle_is_silent() {
        let mut engine = engine(
            r#"
            pipeline = ["max_events_per_conn"]
            [filters.max_events_per_conn]
            max = 1
        "#,
        );
        engine.handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s"}"#);

        // Deliver the one allowed event, then the cap is hit.
        assert_eq!(engine.filter_batch(1, "s", &events(&["a"])), vec!["a"]);
        assert!(engine.filter_batch(1, "s", &events(&["b"])).is_empty());

        // Lifecycle messages produce no response.
        assert!(engine
            .handle(r#"{"type":"reqClose","connId":1,"subId":"s"}"#)
            .is_none());
        assert!(engine
            .handle(r#"{"type":"connClose","connId":1}"#)
            .is_none());
        assert!(!engine.conn_info.contains_key(&1));

        // After connClose the per-conn counter is freed: reopening the same
        // connId delivers again.
        engine.handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s"}"#);
        assert_eq!(engine.filter_batch(1, "s", &events(&["c"])), vec!["c"]);
    }

    #[test]
    fn bandwidth_disables_passthrough() {
        // A bandwidth budget means strfry must keep sending `req` so we can meter
        // bytes — so NOT passthrough, even with no guest and no count cap.
        let mut engine = engine(
            r#"
            pipeline = ["read_bandwidth"]
            [filters.read_bandwidth]
            bytes_per_minute = 1000
            shared_state_path = ""
        "#,
        );
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","ip":"1.2.3.4"}"#)
            .unwrap();
        assert_eq!(open, r#"{"reqId":0,"action":"accept"}"#);
    }

    #[test]
    fn bandwidth_caps_delivery_by_bytes() {
        // Budget for exactly two events' worth of bytes (single-char ids => all
        // events are the same wire size). Refill over the sub-ms test window
        // floors to ~0, so the byte cap is deterministic.
        let size = unparsed_note("a", 1, "").size() as u64;
        let mut engine = engine(&format!(
            r#"
            pipeline = ["read_bandwidth"]
            [filters.read_bandwidth]
            bytes_per_minute = {}
            shared_state_path = ""
        "#,
            size * 2 + 1
        ));
        engine.handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","ip":"9.9.9.9"}"#);

        // First two fit the budget; the rest are withheld once bytes run out.
        assert_eq!(
            engine.filter_batch(1, "s", &events(&["a", "b", "c", "d"])),
            vec!["a", "b"]
        );
    }

    #[test]
    fn bandwidth_keyed_per_ip_survives_reconnect() {
        // Budget for exactly one event.
        let size = unparsed_note("a", 1, "").size() as u64;
        let mut engine = engine(&format!(
            r#"
            pipeline = ["read_bandwidth"]
            [filters.read_bandwidth]
            bytes_per_minute = {}
            shared_state_path = ""
        "#,
            size + 1
        ));

        // connId=1 from ip X spends the whole budget on its first event.
        engine.handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","ip":"1.2.3.4"}"#);
        let first = engine.filter_batch(1, "s", &events(&["a", "b"]));
        assert_eq!(first, vec!["a"]); // 2nd withheld; bucket now ~empty

        // Reconnect: brand-new connId, SAME ip. Because the bucket is keyed by IP
        // (and not evicted on connClose), the budget is still empty.
        engine.handle(r#"{"type":"connClose","connId":1}"#);
        engine.handle(r#"{"type":"reqOpen","reqId":0,"connId":2,"subId":"s","ip":"1.2.3.4"}"#);
        let second = engine.filter_batch(2, "s", &events(&["c"]));
        assert!(second.is_empty());
    }

    #[test]
    fn bandwidth_whitelist_exempts_and_passes_through() {
        // Whitelisted IP: the bandwidth gate is skipped entirely, so delivery
        // continues past a budget that would otherwise cap it — and, doing no
        // per-event work, the subscription is reported passthrough.
        let size = unparsed_note("a", 1, "").size() as u64;
        let mut engine = engine(&format!(
            r#"
            pipeline = ["read_bandwidth"]
            [filters.read_bandwidth]
            bytes_per_minute = {}
            whitelist = ["5.5.5.5"]
            shared_state_path = ""
        "#,
            size
        ));
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","ip":"5.5.5.5"}"#)
            .unwrap();
        assert_eq!(open, r#"{"reqId":0,"action":"accept","passthrough":true}"#);

        // And even if strfry sends `req`, all events deliver (no metering).
        assert_eq!(
            engine.filter_batch(1, "s", &events(&["a", "b", "c"])),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn bandwidth_rejects_at_open_when_drained() {
        // Budget for exactly one event. The first sub drains the IP's bucket; a
        // fresh REQ from the SAME IP is then rejected OUTRIGHT at reqOpen with a
        // CLOSED (msg + retryMs) — real backpressure — rather than a silent
        // empty feed. The not-yet-drained accept case is covered by
        // `bandwidth_disables_passthrough`.
        let size = unparsed_note("a", 1, "").size() as u64;
        let mut engine = engine(&format!(
            r#"
            pipeline = ["read_bandwidth"]
            [filters.read_bandwidth]
            bytes_per_minute = {}
            shared_state_path = ""
        "#,
            size + 1
        ));

        // Fresh IP: admitted (a full bucket affords the nominal event).
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","ip":"1.2.3.4"}"#)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&open).unwrap();
        assert_eq!(v["action"], "accept");

        // Spend the whole budget on the one affordable event.
        assert_eq!(engine.filter_batch(1, "s", &events(&["a"])), vec!["a"]);

        // Reconnect from the SAME IP (bucket keyed by IP, never evicted): now
        // drained, so reqOpen is rejected with a CLOSED + retry hint.
        engine.handle(r#"{"type":"connClose","connId":1}"#);
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":9,"connId":2,"subId":"s2","ip":"1.2.3.4"}"#)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&open).unwrap();
        assert_eq!(v["reqId"], 9);
        assert_eq!(v["action"], "reject");
        assert!(v["msg"].as_str().unwrap().contains("bandwidth"));
        assert!(v["retryMs"].as_u64().unwrap() > 0);
    }

    #[test]
    fn count_rejects_at_open_when_cap_reached() {
        // Once a connection has been delivered its lifetime cap, a new sub on the
        // same connId is rejected at reqOpen (CLOSED, no retryMs — the cap has no
        // refill on this connId, so a same-connId retry is futile). The
        // not-yet-capped accept case is covered by
        // `count_throttle_disables_passthrough`.
        let mut engine = engine(
            r#"
            pipeline = ["max_events_per_conn"]
            [filters.max_events_per_conn]
            max = 1
        "#,
        );
        // Fresh conn: admitted.
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s"}"#)
            .unwrap();
        assert_eq!(open, r#"{"reqId":0,"action":"accept"}"#);

        // Deliver the one allowed event to reach the cap.
        assert_eq!(engine.filter_batch(1, "s", &events(&["a"])), vec!["a"]);

        // A new sub on the SAME connId is now rejected — message, NO retryMs.
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":3,"connId":1,"subId":"s2"}"#)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&open).unwrap();
        assert_eq!(v["action"], "reject");
        assert!(v["msg"].as_str().unwrap().contains("cap reached"));
        assert!(v["retryMs"].is_null());

        // A reconnect (fresh connId) resets the counter and is admitted again.
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":4,"connId":2,"subId":"s"}"#)
            .unwrap();
        assert_eq!(open, r#"{"reqId":4,"action":"accept"}"#);
    }

    /// A test-only filter that withholds (`Skip`) any event whose id starts with
    /// `x`, and otherwise delivers. Used to exercise cross-filter composition
    /// (an earlier stateful filter must not charge an event a later filter
    /// withholds).
    #[derive(Default)]
    struct SkipX;
    impl ReadFilter for SkipX {
        fn name(&self) -> &'static str {
            "skip_x"
        }
        fn req_open(
            &mut self,
            _ctx: &ConnContext,
            _filter: Option<&serde_json::Value>,
        ) -> OpenDecision {
            OpenDecision::needs_events()
        }
        fn filter_event(&mut self, _ctx: &ConnContext, ev: &UnparsedNote) -> EventVerdict {
            if ev.id().unwrap().starts_with('x') {
                EventVerdict::Skip
            } else {
                EventVerdict::Deliver
            }
        }
    }

    impl ReadPolicy {
        /// Build an engine from pre-constructed filters (test-only, so a pipeline
        /// can include a filter that isn't in the registry).
        fn from_pipeline(pipeline: Vec<Box<dyn ReadFilter>>) -> Self {
            ReadPolicy {
                registered_filters: HashMap::new(),
                pipeline,
                conn_info: HashMap::new(),
            }
        }
    }

    #[test]
    fn skip_does_not_charge_an_earlier_stateful_filter() {
        // The crux of the check/commit split. Pipeline [count(max=2), skip_x].
        // count's counter must advance only for events delivered by the WHOLE
        // pipeline — a skipped event must NOT consume the count budget.
        let mut engine = ReadPolicy::from_pipeline(vec![
            Box::new(MaxEventsPerConn {
                max: 2,
                ..Default::default()
            }),
            Box::new(SkipX),
        ]);
        engine.handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s"}"#);

        // "x0" is skipped and must not charge count; then a, b deliver (using the
        // whole cap of 2); c is stopped by the cap. If count had charged the
        // skipped "x0", only "a" would survive.
        assert_eq!(
            engine.filter_batch(1, "s", &events(&["x0", "a", "b", "c"])),
            vec!["a", "b"]
        );
    }

    #[test]
    fn count_and_bandwidth_compose() {
        // count cap 5, bandwidth budget for 2 events, pipeline [count, bandwidth]:
        // bandwidth is the binding constraint here and caps the batch at 2.
        let size = unparsed_note("a", 1, "").size() as u64;
        let mut engine = engine(&format!(
            r#"
            pipeline = ["max_events_per_conn", "read_bandwidth"]
            [filters.max_events_per_conn]
            max = 5
            [filters.read_bandwidth]
            bytes_per_minute = {}
            shared_state_path = ""
        "#,
            size * 2 + 1
        ));
        // Both throttles need events, so the sub is non-passthrough.
        let open = engine
            .handle(r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","ip":"7.7.7.7"}"#)
            .unwrap();
        assert_eq!(open, r#"{"reqId":0,"action":"accept"}"#);

        assert_eq!(
            engine.filter_batch(1, "s", &events(&["a", "b", "c"])),
            vec!["a", "b"]
        );
    }
}
