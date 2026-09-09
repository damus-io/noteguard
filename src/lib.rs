pub mod filters;
mod messages;
mod note_filter;
mod read_filter;
pub mod readfilters;
pub mod readmsg;
pub mod readpolicy;

pub use messages::{Action, InputMessage, OutputMessage};
pub use note_filter::{Note, NoteFilter};
pub use read_filter::{Admission, ConnContext, EventVerdict, OpenDecision, ReadFilter};

/// Path to the config file, from `$NOTEGUARD_CONFIG` or defaulting to
/// `noteguard.toml`. Shared by the write loop and the read loop so both halves
/// of the same deployment always read the same file.
pub fn config_path() -> String {
    std::env::var("NOTEGUARD_CONFIG").unwrap_or_else(|_| "noteguard.toml".to_string())
}
