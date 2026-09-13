//! Built-in [`ReadFilter`](crate::ReadFilter) implementations, composed by the
//! `[readpolicy].pipeline` config. The read-side counterpart to
//! [`crate::filters`].

mod bandwidth;
mod max_events;
mod shm;

#[cfg(feature = "nscript")]
mod nscript;

pub use bandwidth::ReadBandwidth;
pub use max_events::MaxEventsPerConn;
pub use shm::{dump, BucketEntry, Dump, DEFAULT_PATH};

#[cfg(feature = "nscript")]
pub use nscript::NScriptRead;
