//! Built-in [`ReadFilter`](crate::ReadFilter) implementations, composed by the
//! `[readpolicy].pipeline` config. The read-side counterpart to
//! [`crate::filters`].

mod bandwidth;
mod max_events;

pub use bandwidth::ReadBandwidth;
pub use max_events::MaxEventsPerConn;
