//! Read-side (readPolicy) filter trait — the deliverability-path analogue of
//! [`NoteFilter`](crate::NoteFilter).
//!
//! Where a [`NoteFilter`] decides whether an incoming event is *stored*, a
//! [`ReadFilter`] decides, per subscription, which already-stored events are
//! *delivered* to a particular subscriber. The read path needs richer semantics
//! than the pure `fn(event) -> action` write path, so the trait carries:
//!
//! * **Lifecycle hooks** — [`req_open`](ReadFilter::req_open) (admission +
//!   passthrough opt-out), [`req_close`](ReadFilter::req_close),
//!   [`conn_close`](ReadFilter::conn_close) — so a filter can allocate per-sub /
//!   per-conn state and free it deterministically.
//! * **Stateful, order-dependent batch filtering** — filters keep cross-event
//!   state (a per-conn delivery counter) and use
//!   [`EventVerdict::Stop`] to withhold the *rest* of a batch once a budget is
//!   exhausted, not just an independent per-event boolean.
//! * **A check / commit split** — [`filter_event`](ReadFilter::filter_event) is
//!   a *check* that must not consume budget; the engine calls
//!   [`on_delivered`](ReadFilter::on_delivered) exactly once, and only when
//!   *every* filter delivered the event, so counters advance only for
//!   events that actually reach the client (see the module docs on
//!   [`crate::readpolicy`]).
//! * **Shared per-connection context** — the engine caches the client IP +
//!   authed pubkey at `reqOpen` (a `req` batch carries no IP) and hands every
//!   hook a [`ConnContext`], so a per-client filter can key its own state by
//!   identity.
//!
//! **Fail-open** is a per-filter contract: a filter that errors or whose guest
//! traps must return [`EventVerdict::Deliver`] rather than withhold a
//! subscriber's own authorized feed. This matches strfry's stance and the engine
//! (which no-responds on unparseable input so strfry times out and delivers).

use crate::readmsg::UnparsedNote;
use serde_json::Value;

/// Per-`(connId, subId)` context handed to every [`ReadFilter`] hook.
///
/// The IP and authed pubkey are cached by the engine at `reqOpen` (a `req` batch
/// carries no IP), so a per-IP filter can meter on `req` without re-deriving
/// them. Borrowed, never owned — a filter that needs to retain identity keys its
/// own state by them.
pub struct ConnContext<'a> {
    pub conn_id: u64,
    pub sub_id: &'a str,
    /// The rendered client IP, if strfry sent one (newer builds). `None` against
    /// older strfry, which sends no IP on `reqOpen`.
    pub ip: Option<&'a str>,
    /// The NIP-42 authed pubkey hex, if the connection did AUTH.
    pub authed: Option<&'a str>,
}

/// A read filter's per-event decision.
///
/// The three variants map onto the batch loop's control flow: `Deliver`
/// continues to the next filter, `Skip` withholds just this event, and `Stop`
/// withholds this event *and the entire remainder of the batch* (the "budget
/// exhausted, `break`" semantics the throttles rely on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventVerdict {
    /// Deliver this event as far as this filter is concerned; continue the
    /// pipeline.
    Deliver,
    /// Withhold this event but keep processing the rest of the batch (e.g. a
    /// guest reject).
    Skip,
    /// Withhold this event and every subsequent event in the batch (e.g. a
    /// delivery budget just ran out).
    Stop,
}

/// A filter's `reqOpen` admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Admit the subscription.
    Accept,
    /// Refuse the whole subscription, with an optional client message and retry
    /// hint (milliseconds).
    Reject {
        msg: Option<String>,
        retry_ms: Option<u64>,
    },
}

/// What a filter reports at `reqOpen`: whether to admit the subscription and
/// whether it needs to see per-event `req` batches for it.
///
/// The engine ANDs `!needs_events` across all filters to decide passthrough: a
/// subscription is passthrough (strfry skips per-event marshaling) only if *no*
/// filter needs per-event work. `needs_events` is evaluated per subscription, so
/// it may depend on per-sub state established in `req_open` (e.g. whether this
/// connection is exempt from the filter entirely).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenDecision {
    pub admission: Admission,
    pub needs_events: bool,
}

impl OpenDecision {
    /// Admit and declare no per-event work (passthrough-friendly). The default.
    pub fn passthrough() -> Self {
        OpenDecision {
            admission: Admission::Accept,
            needs_events: false,
        }
    }

    /// Admit but declare this filter needs to see `req` batches (disables
    /// passthrough for the subscription).
    pub fn needs_events() -> Self {
        OpenDecision {
            admission: Admission::Accept,
            needs_events: true,
        }
    }

    /// Refuse the whole subscription.
    pub fn reject(msg: Option<String>, retry_ms: Option<u64>) -> Self {
        OpenDecision {
            admission: Admission::Reject { msg, retry_ms },
            needs_events: false,
        }
    }
}

/// A composable read-policy filter. See the [module docs](self) for the
/// semantics (lifecycle, check/commit, fail-open).
pub trait ReadFilter {
    /// The `[readpolicy].pipeline` key this filter is registered under.
    fn name(&self) -> &'static str;

    /// A subscription started serving. Allocate any per-sub state, and report
    /// admission + whether this filter needs per-event batches (passthrough).
    /// `filter` is the subscription's cached filter JSON, present only here.
    ///
    /// Defaults to admit + passthrough-friendly.
    fn req_open(&mut self, _ctx: &ConnContext, _filter: Option<&Value>) -> OpenDecision {
        OpenDecision::passthrough()
    }

    /// Decide one event. This is a **check only**: it must not consume budget —
    /// commit that in [`on_delivered`](Self::on_delivered), which the engine
    /// calls iff every filter delivered the event. This keeps a partial pipeline
    /// run (a later filter's `Stop`) from corrupting this filter's budget.
    ///
    /// Only called for non-passthrough subscriptions. To honour the fail-open
    /// contract, return [`EventVerdict::Deliver`] on internal error.
    ///
    /// Defaults to [`EventVerdict::Deliver`].
    fn filter_event(&mut self, _ctx: &ConnContext, _ev: &UnparsedNote) -> EventVerdict {
        EventVerdict::Deliver
    }

    /// Called, in pipeline order, after an event was delivered by *every*
    /// filter. The place to consume budget / bump counters exactly once. Defaults to a
    /// no-op (stateless filters need nothing here).
    fn on_delivered(&mut self, _ctx: &ConnContext, _ev: &UnparsedNote) {}

    /// A subscription went away — free its per-sub state.
    fn req_close(&mut self, _conn_id: u64, _sub_id: &str) {}

    /// A connection went away — free its per-conn state. (Note: per-IP state that
    /// must survive a reconnect is deliberately *not* freed here.)
    fn conn_close(&mut self, _conn_id: u64) {}
}
