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
    /// Append `ip` to the list (Cloudflare de-duplicates by value).
    fn add(&self, ip: &str);
    /// Resolve `ip`'s list-item id and delete it.
    fn remove(&self, ip: &str);
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
    fn add(&self, ip: &str) {
        // POST a one-element batch; the Lists API is async and returns an
        // operation_id, but for a single IP we fire-and-forget — membership
        // settles within seconds and the local ban covers the gap.
        let body = serde_json::json!([{ "ip": ip, "comment": self.comment }]);
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

    /// Record a ban for `ip` expiring at `deadline`. Adds to the Cloudflare list
    /// only on the first ban for an IP; a later ban merely extends the deadline
    /// (a shorter one is ignored so a ban is never cut short).
    fn on_ban(&mut self, ip: String, deadline: Instant) {
        match self.active.get(&ip) {
            Some(&current) if current >= deadline => {} // already banned at least this long
            Some(_) => {
                // Extend: record the later deadline and push a fresh heap entry.
                // The old entry becomes stale and is skipped on sweep.
                self.active.insert(ip.clone(), deadline);
                self.expiries.push(Reverse((deadline, ip)));
            }
            None => {
                self.active.insert(ip.clone(), deadline);
                self.expiries.push(Reverse((deadline, ip.clone())));
                self.api.add(&ip);
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

    /// Drive the worker: block until the next command or the next removal is due,
    /// whichever comes first, then apply it. Exits when the sender is dropped.
    fn run(mut self, rx: Receiver<BanCommand>) {
        loop {
            let received = match self.next_deadline() {
                Some(deadline) => rx.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(cmd) => self.on_ban(cmd.ip, Instant::now() + cmd.duration),
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

    /// Records `(op, ip)` calls instead of hitting the network.
    #[derive(Clone, Default)]
    struct MockApi {
        calls: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl MockApi {
        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CfApi for MockApi {
        fn add(&self, ip: &str) {
            self.calls.lock().unwrap().push(("add".into(), ip.into()));
        }
        fn remove(&self, ip: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(("remove".into(), ip.into()));
        }
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

        w.on_ban("1.2.3.4".into(), deadline);
        // A second ban for the same IP within the window must not re-add it.
        w.on_ban("1.2.3.4".into(), deadline);
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

        w.on_ban("9.9.9.9".into(), t0 + Duration::from_secs(60));
        // Re-ban with a later deadline before the first elapses: extend it.
        w.on_ban("9.9.9.9".into(), t0 + Duration::from_secs(120));

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

        w.on_ban("1.1.1.1".into(), t0 + Duration::from_secs(30));
        w.on_ban("2.2.2.2".into(), t0 + Duration::from_secs(90));

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
}
