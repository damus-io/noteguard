//! Built-in [`ReadFilter`](crate::ReadFilter) implementations, composed by the
//! `[readpolicy].pipeline` config. The read-side counterpart to
//! [`crate::filters`].

mod max_events;

pub use max_events::MaxEventsPerConn;
