use crate::read_filter::{ConnContext, EventVerdict, OpenDecision, ReadFilter};
use crate::readmsg::UnparsedNote;
use serde::Deserialize;
use std::collections::HashMap;

/// Per-connection delivery cap: withhold once a connection has been delivered
/// `max` events across the life of the connection (across all its
/// subscriptions).
///
/// The counter is keyed by `connId`, so it is shared by every subscription on a
/// connection and reset only when the connection closes. Once the cap is hit the
/// rest of the batch — and every future batch — is withheld
/// ([`EventVerdict::Stop`]).
#[derive(Deserialize, Default)]
pub struct MaxEventsPerConn {
    /// Max events delivered per `connId` over the connection's life.
    pub max: u64,

    /// `connId` -> events delivered so far. Committed in `on_delivered`, so it
    /// only counts events delivered by the *whole* pipeline.
    #[serde(skip)]
    pub delivered: HashMap<u64, u64>,
}

impl ReadFilter for MaxEventsPerConn {
    fn name(&self) -> &'static str {
        "max_events_per_conn"
    }

    fn req_open(
        &mut self,
        _ctx: &ConnContext,
        _filter: Option<&serde_json::Value>,
    ) -> OpenDecision {
        // A configured cap always needs to see events, so strfry must keep
        // sending `req` batches for the counter to bound delivery.
        OpenDecision::needs_events()
    }

    fn filter_event(&mut self, ctx: &ConnContext, _ev: &UnparsedNote) -> EventVerdict {
        // Check only: once the connection is at its cap, withhold this event and
        // the rest of the batch. The counter advances in `on_delivered`.
        let already = *self.delivered.get(&ctx.conn_id).unwrap_or(&0);
        if already >= self.max {
            EventVerdict::Stop
        } else {
            EventVerdict::Deliver
        }
    }

    fn on_delivered(&mut self, ctx: &ConnContext, _ev: &UnparsedNote) {
        *self.delivered.entry(ctx.conn_id).or_insert(0) += 1;
    }

    fn conn_close(&mut self, conn_id: u64) {
        self.delivered.remove(&conn_id);
    }
}
