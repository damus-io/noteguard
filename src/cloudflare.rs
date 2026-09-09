//! Shared Cloudflare edge-ban integration for the write-path [`BanTracker`].
//!
//! When a filter's local ban trips (ratelimit's consecutive streak or content's
//! cumulative one — both funnel through [`BanTracker::strike`](crate::filters)),
//! we also add the offender's IP to a Cloudflare **WAF IP list**, and remove it
//! again when the ban expires. The operator wires that list into a zone WAF
//! custom rule once (`ip.src in $your_list` → *block*); noteguard only manages
//! the list's *membership*, so a banned IP is dropped at Cloudflare's edge before
//! it ever reaches the relay.
//!
//! The banner is a single process-global background worker shared by every
//! `BanTracker` (both the ratelimit and content filters escalate to the same
//! list), configured once from the top-level `[cloudflare]` table plus the
//! `CLOUDFLARE_API_TOKEN` env var. It is entirely opt-in: with no `[cloudflare]`
//! section (or the feature compiled out) [`edge_ban`] is a no-op and noteguard
//! behaves exactly as before.
//!
//! ## Why a background worker and a timer
//!
//! Two things force the design:
//!
//! * **HTTP must not block the note path.** strfry feeds events line-by-line;
//!   a ban is rare but an API round-trip is slow, so bans are handed to a
//!   background thread over a channel and the filter returns immediately.
//! * **Expiry can't be driven by the note path.** Once an IP is blocked at the
//!   edge it never reaches noteguard again, so nothing on the ingest side can
//!   notice the local ban elapsing. The worker therefore schedules each removal
//!   on a timer of its own.
//!
//! ## Caveats
//!
//! * strfry runs one plugin process per ingester thread, each with its own
//!   worker; several may add the same IP. Cloudflare's list de-duplicates by
//!   value, so the redundant adds are harmless, and each worker removes on its
//!   own timer.
//! * If a process dies mid-ban its pending removal is lost and the IP lingers in
//!   the list until a later run (or a human) clears it. The per-item `comment`
//!   tags noteguard's entries so they're easy to find.

use log::{info, warn};
use serde::Deserialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Cloudflare API base, overridable via config for tests / self-hosted gateways.
fn default_api_base() -> String {
    "https://api.cloudflare.com/client/v4".to_string()
}

/// Marker embedded in each list item's comment, followed by the ban's wall-clock
/// expiry (unix seconds). This makes the Cloudflare list self-describing: on
/// startup [`BanWorker::reconcile`] re-reads these to recover removals that an
/// earlier process added but never got to delete (see the module docs). The
/// marker also scopes reconciliation to *our* items, so a shared list's other
/// entries are never touched.
const BAN_MARKER: &str = "noteguard-ban;until=";

/// Seconds since the unix epoch (saturating to 0 on the impossible pre-epoch
/// clock), used for the wall-clock expiry stamped into item comments. The
/// worker's in-process timer uses [`Instant`] instead; only the persisted stamp
/// needs to be wall-clock so it survives a restart.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse the expiry out of a list item's comment, or `None` if it isn't one of
/// noteguard's items.
fn parse_until(comment: &str) -> Option<u64> {
    let rest = comment.split(BAN_MARKER).nth(1)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The `[cloudflare]` config table. The API token is *not* here — it comes from
/// the `CLOUDFLARE_API_TOKEN` environment variable so the secret stays out of
/// the config file.
#[derive(Deserialize, Clone)]
pub struct CloudflareConfig {
    /// Cloudflare account that owns the IP list.
    pub account_id: String,
    /// Id of the WAF IP list to manage membership of.
    pub list_id: String,
    /// API base URL. Defaults to the public Cloudflare API.
    #[serde(default)]
    pub api_base: Option<String>,
    /// Comment stamped on each list item, so noteguard's entries are identifiable.
    #[serde(default)]
    pub comment: Option<String>,
    /// Per-request HTTP timeout in seconds. Defaults to 10.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// A request for the background worker: edge-ban `ip` for `duration`.
struct BanCommand {
    ip: String,
    duration: Duration,
}

/// The Cloudflare list operations the worker needs. Abstracted behind a trait so
/// the worker's scheduling/dedup logic can be unit-tested without real HTTP.
trait CfApi: Send {
    /// Append `ip` to the list with its `until_unix` expiry stamped into the
    /// comment (Cloudflare de-duplicates by value).
    fn add(&self, ip: &str, until_unix: u64);
    /// Resolve `ip`'s list-item id and delete it.
    fn remove(&self, ip: &str);
    /// Every noteguard-tagged item currently in the list, as `(ip, until_unix)`,
    /// for startup reconciliation.
    fn list_bans(&self) -> Vec<(String, u64)>;
}

/// Live Cloudflare Lists API client (`ureq`, blocking).
#[cfg(feature = "cloudflare")]
struct CloudflareApi {
    agent: ureq::Agent,
    token: String,
    account_id: String,
    list_id: String,
    api_base: String,
    comment: String,
}

#[cfg(feature = "cloudflare")]
impl CloudflareApi {
    fn items_url(&self) -> String {
        format!(
            "{}/accounts/{}/rules/lists/{}/items",
            self.api_base, self.account_id, self.list_id
        )
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

#[cfg(feature = "cloudflare")]
impl CfApi for CloudflareApi {
    fn add(&self, ip: &str, until_unix: u64) {
        // POST a one-element batch; the Lists API is async and returns an
        // operation_id, but for a single IP we fire-and-forget — membership
        // settles within seconds and the local ban covers the gap. The expiry is
        // stamped into the comment so a later process can reconcile it.
        let comment = format!("{} {BAN_MARKER}{until_unix}", self.comment);
        let body = serde_json::json!([{ "ip": ip, "comment": comment }]);
        match self
            .agent
            .post(&self.items_url())
            .set("Authorization", &self.bearer())
            .send_json(body)
        {
            Ok(_) => info!("cloudflare: queued edge-ban add for {ip}"),
            Err(e) => warn!("cloudflare: failed to add {ip} to list: {e}"),
        }
    }

    fn list_bans(&self) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        // Follow Cloudflare's pagination cursors so a large list is fully
        // reconciled rather than silently truncated to the first page.
        loop {
            let mut req = self
                .agent
                .get(&self.items_url())
                .set("Authorization", &self.bearer());
            if let Some(c) = &cursor {
                req = req.query("cursor", c);
            }
            let resp = match req.call() {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("cloudflare: failed to list items for reconcile: {e}");
                    break;
                }
            };
            let json: serde_json::Value = match resp.into_json() {
                Ok(json) => json,
                Err(e) => {
                    warn!("cloudflare: bad list-items response during reconcile: {e}");
                    break;
                }
            };
            if let Some(items) = json["result"].as_array() {
                for it in items {
                    let (Some(ip), Some(comment)) = (it["ip"].as_str(), it["comment"].as_str())
                    else {
                        continue;
                    };
                    if let Some(until) = parse_until(comment) {
                        out.push((ip.to_owned(), until));
                    }
                }
            }
            match json["result_info"]["cursors"]["after"].as_str() {
                Some(next) if !next.is_empty() => cursor = Some(next.to_owned()),
                _ => break,
            }
        }
        out
    }

    fn remove(&self, ip: &str) {
        // Deletion is by item id, so resolve it first. `search` is a substring
        // match, hence the exact-ip filter on the returned items.
        let resp = match self
            .agent
            .get(&self.items_url())
            .query("search", ip)
            .set("Authorization", &self.bearer())
            .call()
        {
            Ok(resp) => resp,
            Err(e) => {
                warn!("cloudflare: failed to look up list item for {ip}: {e}");
                return;
            }
        };
        let json: serde_json::Value = match resp.into_json() {
            Ok(json) => json,
            Err(e) => {
                warn!("cloudflare: bad list-items response for {ip}: {e}");
                return;
            }
        };
        let item_id = json["result"]
            .as_array()
            .and_then(|items| items.iter().find(|it| it["ip"].as_str() == Some(ip)))
            .and_then(|it| it["id"].as_str().map(str::to_owned));

        let Some(item_id) = item_id else {
            warn!("cloudflare: no list item for {ip}; nothing to remove");
            return;
        };

        let body = serde_json::json!({ "items": [ { "id": item_id } ] });
        match self
            .agent
            .delete(&self.items_url())
            .set("Authorization", &self.bearer())
            .send_json(body)
        {
            Ok(_) => info!("cloudflare: queued edge-ban removal for {ip}"),
            Err(e) => warn!("cloudflare: failed to remove {ip} from list: {e}"),
        }
    }
}

/// Background worker: owns the API client and the set of currently edge-banned
/// IPs, and schedules each removal on its own expiry timer.
struct BanWorker<A: CfApi> {
    api: A,
    /// ip -> the deadline its ban currently expires at.
    active: HashMap<String, Instant>,
    /// Min-heap (via `Reverse`) of `(deadline, ip)` driving removals. May hold
    /// stale entries superseded by an extension; [`sweep`](Self::sweep) skips
    /// any whose deadline no longer matches `active`.
    expiries: BinaryHeap<Reverse<(Instant, String)>>,
}

impl<A: CfApi> BanWorker<A> {
    fn new(api: A) -> Self {
        BanWorker {
            api,
            active: HashMap::new(),
            expiries: BinaryHeap::new(),
        }
    }

    /// Record `ip`'s removal deadline in the schedule. Does not touch Cloudflare
    /// — callers decide whether a list `add` is also needed.
    fn track(&mut self, ip: String, deadline: Instant) {
        self.active.insert(ip.clone(), deadline);
        self.expiries.push(Reverse((deadline, ip)));
    }

    /// Record a ban for `ip` expiring at `deadline` (wall-clock `until_unix`,
    /// stamped into the list item). Adds to the Cloudflare list only on the first
    /// ban for an IP; a later ban merely extends the deadline (a shorter one is
    /// ignored so a ban is never cut short). An extension updates only the local
    /// timer, not the persisted stamp, so after a restart an extended ban falls
    /// back to its original expiry — acceptable for a rare edge.
    fn on_ban(&mut self, ip: String, deadline: Instant, until_unix: u64) {
        match self.active.get(&ip) {
            Some(&current) if current >= deadline => {} // already banned at least this long
            Some(_) => self.track(ip, deadline),        // extend; already in the list
            None => {
                self.track(ip.clone(), deadline);
                self.api.add(&ip, until_unix);
            }
        }
    }

    /// Recover state from the Cloudflare list at startup: anything already past
    /// its stamped expiry is deleted now (these are the removals a prior process
    /// added but never got to run), and anything still live is re-scheduled on
    /// the worker's timer without re-adding it. `now_unix` is the current
    /// wall-clock time in unix seconds.
    fn reconcile(&mut self, now_unix: u64) {
        for (ip, until_unix) in self.api.list_bans() {
            if until_unix <= now_unix {
                self.api.remove(&ip);
            } else {
                let remaining = Duration::from_secs(until_unix - now_unix);
                self.track(ip, Instant::now() + remaining);
            }
        }
    }

    /// Remove from the list every ban whose deadline has passed as of `now`.
    fn sweep(&mut self, now: Instant) {
        while let Some(Reverse((deadline, _))) = self.expiries.peek() {
            if *deadline > now {
                break;
            }
            let Reverse((deadline, ip)) = self.expiries.pop().expect("peeked");
            // Act only if this entry is the live deadline for the IP; an entry
            // superseded by an extension has a different `active` deadline.
            if self.active.get(&ip) == Some(&deadline) {
                self.api.remove(&ip);
                self.active.remove(&ip);
            }
        }
    }

    /// The soonest scheduled removal, if any — how long the run loop may block.
    fn next_deadline(&self) -> Option<Instant> {
        self.expiries.peek().map(|Reverse((d, _))| *d)
    }

    /// Drive the worker: recover any pending removals left by a prior process,
    /// then block until the next command or the next removal is due, whichever
    /// comes first, and apply it. Exits when the sender is dropped.
    fn run(mut self, rx: Receiver<BanCommand>) {
        self.reconcile(now_unix());
        self.sweep(Instant::now());
        loop {
            let received = match self.next_deadline() {
                Some(deadline) => rx.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(cmd) => {
                    let until = now_unix().saturating_add(cmd.duration.as_secs());
                    self.on_ban(cmd.ip, Instant::now() + cmd.duration, until);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            self.sweep(Instant::now());
        }
    }
}

/// The process-global banner. `None` once initialized without a usable config
/// (e.g. missing token), so [`edge_ban`] stays a no-op in that case.
static BANNER: OnceLock<Option<Sender<BanCommand>>> = OnceLock::new();

/// Initialize the shared edge-banner from `[cloudflare]` config. Call once at
/// startup. A missing `CLOUDFLARE_API_TOKEN` disables edge-banning (logged, not
/// fatal — the relay still runs with relay-local bans).
#[cfg(feature = "cloudflare")]
pub fn init(config: CloudflareConfig) {
    let _ = BANNER.set(spawn(config));
}

#[cfg(feature = "cloudflare")]
fn spawn(config: CloudflareConfig) -> Option<Sender<BanCommand>> {
    let token = match std::env::var("CLOUDFLARE_API_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            warn!(
                "cloudflare: [cloudflare] configured but CLOUDFLARE_API_TOKEN is unset; \
                 edge-banning disabled"
            );
            return None;
        }
    };

    let list_id = config.list_id.clone();
    let api = CloudflareApi {
        agent: ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(config.timeout_secs.unwrap_or(10)))
            .build(),
        token,
        account_id: config.account_id,
        list_id: config.list_id,
        api_base: config.api_base.unwrap_or_else(default_api_base),
        comment: config.comment.unwrap_or_else(|| "noteguard auto-ban".to_string()),
    };

    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("cloudflare-banner".to_string())
        .spawn(move || BanWorker::new(api).run(rx))
        .expect("spawn cloudflare-banner thread");

    info!("cloudflare: edge-banning enabled (list {list_id})");
    Some(tx)
}

/// Escalate a local ban to the edge: add `ip` to the Cloudflare list for
/// `duration`. A no-op unless [`init`] configured a live banner. Never blocks —
/// the request is handed to the background worker.
pub fn edge_ban(ip: &str, duration: Duration) {
    if let Some(Some(tx)) = BANNER.get() {
        if tx
            .send(BanCommand {
                ip: ip.to_owned(),
                duration,
            })
            .is_err()
        {
            warn!("cloudflare: banner worker is gone; dropping edge-ban for {ip}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records `(op, ip)` calls instead of hitting the network. `existing` is the
    /// canned list the worker sees during [`reconcile`](BanWorker::reconcile).
    #[derive(Clone, Default)]
    struct MockApi {
        calls: Arc<Mutex<Vec<(String, String)>>>,
        existing: Arc<Mutex<Vec<(String, u64)>>>,
    }

    impl MockApi {
        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CfApi for MockApi {
        fn add(&self, ip: &str, _until_unix: u64) {
            self.calls.lock().unwrap().push(("add".into(), ip.into()));
        }
        fn remove(&self, ip: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(("remove".into(), ip.into()));
        }
        fn list_bans(&self) -> Vec<(String, u64)> {
            self.existing.lock().unwrap().clone()
        }
    }

    #[test]
    fn parses_until_out_of_comment() {
        assert_eq!(
            parse_until(&format!("noteguard auto-ban {BAN_MARKER}1757000000")),
            Some(1_757_000_000)
        );
        // A trailing human suffix after the digits is tolerated.
        assert_eq!(parse_until(&format!("{BAN_MARKER}42 (spam)")), Some(42));
        // Items that aren't ours are ignored.
        assert_eq!(parse_until("manually added by ops"), None);
    }

    #[test]
    fn config_parses_with_token_out_of_band() {
        let cfg: CloudflareConfig = toml::from_str(
            "account_id = \"acct\"\nlist_id = \"lst\"\ncomment = \"banned by noteguard\"\n",
        )
        .expect("valid cloudflare config");
        assert_eq!(cfg.account_id, "acct");
        assert_eq!(cfg.list_id, "lst");
        assert_eq!(cfg.comment.as_deref(), Some("banned by noteguard"));
        assert!(cfg.api_base.is_none());
    }

    #[test]
    fn adds_once_and_removes_on_expiry() {
        let api = MockApi::default();
        let mut w = BanWorker::new(api.clone());
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(60);

        w.on_ban("1.2.3.4".into(), deadline, 0);
        // A second ban for the same IP within the window must not re-add it.
        w.on_ban("1.2.3.4".into(), deadline, 0);
        w.sweep(t0 + Duration::from_secs(1)); // not yet expired
        assert_eq!(api.calls(), vec![("add".into(), "1.2.3.4".into())]);

        // Once the deadline passes, the IP is removed exactly once.
        w.sweep(t0 + Duration::from_secs(61));
        assert_eq!(
            api.calls(),
            vec![
                ("add".into(), "1.2.3.4".into()),
                ("remove".into(), "1.2.3.4".into()),
            ]
        );
    }

    #[test]
    fn extending_a_ban_defers_removal_and_never_double_removes() {
        let api = MockApi::default();
        let mut w = BanWorker::new(api.clone());
        let t0 = Instant::now();

        w.on_ban("9.9.9.9".into(), t0 + Duration::from_secs(60), 0);
        // Re-ban with a later deadline before the first elapses: extend it.
        w.on_ban("9.9.9.9".into(), t0 + Duration::from_secs(120), 0);

        // At the original deadline the (now stale) entry must NOT trigger a removal.
        w.sweep(t0 + Duration::from_secs(61));
        assert_eq!(api.calls(), vec![("add".into(), "9.9.9.9".into())]);

        // Only the extended deadline removes it, and only once.
        w.sweep(t0 + Duration::from_secs(121));
        assert_eq!(
            api.calls(),
            vec![
                ("add".into(), "9.9.9.9".into()),
                ("remove".into(), "9.9.9.9".into()),
            ]
        );
    }

    #[test]
    fn distinct_ips_are_tracked_independently() {
        let api = MockApi::default();
        let mut w = BanWorker::new(api.clone());
        let t0 = Instant::now();

        w.on_ban("1.1.1.1".into(), t0 + Duration::from_secs(30), 0);
        w.on_ban("2.2.2.2".into(), t0 + Duration::from_secs(90), 0);

        w.sweep(t0 + Duration::from_secs(31)); // only the first expired
        assert_eq!(
            api.calls(),
            vec![
                ("add".into(), "1.1.1.1".into()),
                ("add".into(), "2.2.2.2".into()),
                ("remove".into(), "1.1.1.1".into()),
            ]
        );
    }

    #[test]
    fn reconcile_removes_stale_and_reschedules_live_without_readding() {
        let api = MockApi::default();
        // Simulate the list left behind by a prior process: one ban already
        // past its expiry, one still live.
        *api.existing.lock().unwrap() = vec![
            ("5.5.5.5".into(), 1_000), // expired as of now_unix = 2_000
            ("6.6.6.6".into(), 3_000), // still 1_000s to go
        ];
        let mut w = BanWorker::new(api.clone());

        w.reconcile(2_000);
        // The stale ban's lost removal is recovered immediately; the live ban is
        // neither re-added (it's already in the list) nor removed yet.
        assert_eq!(api.calls(), vec![("remove".into(), "5.5.5.5".into())]);

        // The live ban is scheduled, so once its (rescheduled) deadline passes it
        // is removed — and never re-added.
        w.sweep(Instant::now() + Duration::from_secs(2_000));
        assert_eq!(
            api.calls(),
            vec![
                ("remove".into(), "5.5.5.5".into()),
                ("remove".into(), "6.6.6.6".into()),
            ]
        );
    }
}
