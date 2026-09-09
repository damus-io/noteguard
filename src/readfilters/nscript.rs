use crate::nscript::{Runtime, Verdict};
use crate::read_filter::{ConnContext, EventVerdict, OpenDecision, ReadFilter};
use crate::readmsg::UnparsedNote;
use serde::Deserialize;
use std::collections::HashMap;

/// Runs a user-supplied WASM guest as a per-subscription deliverability filter,
/// scoped to the subscriber (the NIP-42 `authed` pubkey = the script owner).
///
/// The guest is compiled once per process and re-scoped (no recompile) to each
/// subscriber at `req_open`. The [`Verdict`] collapses on the read path to
/// deliver (`Accept`) vs withhold (anything else) — there is no shadow concept
/// for reads. Fails open: a missing/failed module or a trapping guest delivers.
///
/// The `module` + `follows` fields stub out the eventual script-distribution
/// system: today the guest and its owner's follow-set are configured statically;
/// later they come from a signed submission event on the relay.
#[derive(Deserialize, Default)]
pub struct NScriptRead {
    /// Path to the compiled guest `.wasm`, applied to every subscription (owner =
    /// the authed subscriber). If unset, deliver everything.
    pub module: Option<String>,

    /// STUB for follow-set distribution: owner-hex -> the hex pubkeys that owner
    /// follows (backs the guest's `is_following` accessor).
    #[serde(default)]
    pub follows: HashMap<String, Vec<String>>,

    /// The compiled guest, built once on the first `req_open` and re-scoped per
    /// subscriber. Stays `None` when no module is configured or the load failed
    /// (fail open — deliver all); `load_attempted` keeps us from retrying a
    /// broken module (and re-logging) on every subscription.
    #[serde(skip)]
    compiled: Option<Runtime>,
    #[serde(skip)]
    load_attempted: bool,

    /// `connId` -> `subId` -> that subscriber's scoped guest. Only subscriptions
    /// that actually have a guest get an entry; everything else delivers all.
    #[serde(skip)]
    runtimes: HashMap<u64, HashMap<String, Runtime>>,
}

impl NScriptRead {
    /// The compiled guest, compiling it on first use. Returns `None` — meaning
    /// deliver-all — when no module is configured or the load failed (fail
    /// open); the failure is logged once, not once per subscription.
    fn compiled(&mut self) -> Option<&Runtime> {
        if !self.load_attempted {
            self.load_attempted = true;
            if let Some(module) = &self.module {
                // Compiled owner-less; `rescope` binds each subscriber's owner
                // and follow-set without recompiling.
                match Runtime::load(module, &None, &[]) {
                    Ok(rt) => self.compiled = Some(rt),
                    Err(e) => log::error!(
                        "readpolicy: failed to load {} (delivering all): {}",
                        module,
                        e
                    ),
                }
            }
        }
        self.compiled.as_ref()
    }
}

impl ReadFilter for NScriptRead {
    fn name(&self) -> &'static str {
        "nscript"
    }

    /// An unauthenticated subscription (`authed` == `None`) still runs the
    /// guest, but with no owner: an owner-scoped filter (like `follows-only`)
    /// then no-ops and delivers everything, while an owner-independent filter
    /// (e.g. content muting) still applies.
    fn req_open(&mut self, ctx: &ConnContext, _filter: Option<&serde_json::Value>) -> OpenDecision {
        let owner = ctx.authed.map(str::to_string);
        let follows = ctx
            .authed
            .and_then(|owner| self.follows.get(owner))
            .cloned()
            .unwrap_or_default();

        // Only a subscription that actually has a guest does per-event work; a
        // deliver-all sub (no module / failed load) can take passthrough.
        let Some(runtime) = self.compiled().map(|rt| rt.rescope(&owner, &follows)) else {
            return OpenDecision::passthrough();
        };

        self.runtimes
            .entry(ctx.conn_id)
            .or_default()
            .insert(ctx.sub_id.to_string(), runtime);
        OpenDecision::needs_events()
    }

    fn filter_event(&mut self, ctx: &ConnContext, ev: &UnparsedNote) -> EventVerdict {
        // No runtime (no module / failed load / never opened): deliver.
        let Some(rt) = self
            .runtimes
            .get(&ctx.conn_id)
            .and_then(|subs| subs.get(ctx.sub_id))
        else {
            return EventVerdict::Deliver;
        };

        // Only the guest path pays for a full parse.
        let note = match ev.parse() {
            Ok(note) => note,
            // Fail open on a malformed event, matching strfry's stance.
            Err(e) => {
                log::error!("readpolicy: unparseable event (delivering): {}", e);
                return EventVerdict::Deliver;
            }
        };

        match rt.run(&note) {
            Ok(Verdict::Accept) => EventVerdict::Deliver,
            // Reject / ShadowReject both collapse to withhold-this-event on the
            // read path — there is no shadow concept for deliverability.
            Ok(_) => EventVerdict::Skip,
            Err(e) => {
                // Fail open on guest trap / resource exhaustion.
                log::error!("readpolicy: guest error (delivering): {}", e);
                EventVerdict::Deliver
            }
        }
    }

    fn req_close(&mut self, conn_id: u64, sub_id: &str) {
        if let Some(subs) = self.runtimes.get_mut(&conn_id) {
            subs.remove(sub_id);
            if subs.is_empty() {
                self.runtimes.remove(&conn_id);
            }
        }
    }

    fn conn_close(&mut self, conn_id: u64) {
        self.runtimes.remove(&conn_id);
    }
}
