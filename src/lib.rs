//! # noteguard
//!
//! A high-performance Nostr event filter library and strfry write policy plugin.
//!
//! This crate provides a configurable filter pipeline that can be:
//! - Embedded in any Nostr relay as a library
//! - Used as a standalone strfry write policy plugin
//!
//! ## Architecture
//!
//! The filtering system uses a pipeline pattern:
//! 1. Events enter the pipeline as `InputMessage`
//! 2. Each filter in the pipeline processes the event sequentially
//! 3. Filters return `Accept`, `Reject`, or `ShadowReject`
//! 4. First rejection terminates the pipeline; accepts continue to next filter
//!
//! ## Library Usage
//!
//! ```ignore
//! use noteguard::{Noteguard, Config, Action};
//!
//! let config: Config = toml::from_str(config_str)?;
//! let mut guard = Noteguard::new();
//! guard.load_config(&config)?;
//!
//! let output = guard.run(input_message);
//! match output.action {
//!     Action::Accept => { /* process event */ },
//!     Action::Reject | Action::ShadowReject => { /* drop event */ },
//! }
//! ```

pub mod filters;
mod messages;
mod note_filter;

pub use messages::{Action, InputMessage, OutputMessage};
pub use note_filter::{Note, NoteFilter};

use filters::{Blacklist, Content, Kinds, ProtectedEvents, RateLimit, Whitelist};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;

#[cfg(feature = "forwarder")]
use filters::Forwarder;

/// Configuration structure parsed from TOML.
///
/// The `pipeline` field defines the order in which filters are applied.
/// Each filter name must have a corresponding entry in the `filters` map.
#[derive(Deserialize)]
pub struct Config {
    /// Ordered list of filter names to apply. Filters run in sequence;
    /// first rejection stops the pipeline.
    pub pipeline: Vec<String>,
    /// Filter-specific configuration keyed by filter name.
    pub filters: HashMap<String, toml::Value>,
}

/// Type alias for filter constructor functions.
///
/// Each registered filter provides a constructor that deserializes
/// its configuration from a TOML value.
type ConstructFilter = Box<fn(toml::Value) -> Result<Box<dyn NoteFilter>, toml::de::Error>>;

/// The main filter registry and pipeline executor.
///
/// `Noteguard` manages filter registration and executes the configured
/// filter pipeline against incoming events.
#[derive(Default)]
pub struct Noteguard {
    /// Registry mapping filter names to their constructors
    registered_filters: HashMap<String, ConstructFilter>,
    /// The loaded filter pipeline, in execution order
    loaded_filters: Vec<Box<dyn NoteFilter>>,
}

impl Noteguard {
    /// Creates a new `Noteguard` instance with all built-in filters registered.
    pub fn new() -> Self {
        let mut noteguard = Noteguard::default();
        noteguard.register_builtin_filters();
        noteguard
    }

    /// Registers a custom filter type.
    ///
    /// The filter must implement `NoteFilter`, `Default`, and `DeserializeOwned`.
    /// The filter's `name()` method determines the key used in configuration.
    pub fn register_filter<F: NoteFilter + 'static + Default + DeserializeOwned>(&mut self) {
        self.registered_filters.insert(
            F::name(&F::default()).to_string(),
            Box::new(|filter_config| {
                filter_config
                    .try_into()
                    .map(|filter: F| Box::new(filter) as Box<dyn NoteFilter>)
            }),
        );
    }

    /// Registers all built-in filters.
    ///
    /// Built-in filters:
    /// - `ratelimit`: Token bucket rate limiting per source IP
    /// - `whitelist`: Allow-only list for pubkeys/IPs
    /// - `blacklist`: Block list for pubkeys/IPs/CIDRs
    /// - `protected_events`: Rejects NIP-70 protected events
    /// - `kinds`: Blocks specific event kinds
    /// - `content`: Shadow-rejects events matching content patterns
    /// - `forwarder`: Forwards events to another relay (requires `forwarder` feature)
    fn register_builtin_filters(&mut self) {
        self.register_filter::<RateLimit>();
        self.register_filter::<Whitelist>();
        self.register_filter::<Blacklist>();
        self.register_filter::<ProtectedEvents>();
        self.register_filter::<Kinds>();
        self.register_filter::<Content>();

        #[cfg(feature = "forwarder")]
        self.register_filter::<Forwarder>();
    }

    /// Runs the filter pipeline on an input message.
    ///
    /// Filters execute in pipeline order. The pipeline short-circuits on
    /// first `Reject` or `ShadowReject`. If all filters accept, returns
    /// the last filter's output (or a default Accept if pipeline is empty).
    ///
    /// **Important**: Call `load_config` before `run`, otherwise no filters
    /// will be applied and all events will be accepted.
    pub fn run(&mut self, input: InputMessage) -> OutputMessage {
        let id = input.event.id.clone();

        for filter in &mut self.loaded_filters {
            let out = filter.filter_note(&input);

            // Early return on rejection - no need to continue pipeline
            match out.action {
                Action::Accept => continue,
                Action::Reject | Action::ShadowReject => return out,
            }
        }

        // All filters accepted (or pipeline was empty)
        OutputMessage::new(id, Action::Accept, None)
    }

    /// Loads filter configuration and builds the pipeline.
    ///
    /// Clears any previously loaded filters and constructs a new pipeline
    /// based on the provided configuration. Each filter name in the pipeline
    /// must have both a registered constructor and a config entry.
    ///
    /// # Panics
    ///
    /// Panics if a pipeline entry has no matching config or no registered filter.
    pub fn load_config(&mut self, config: &Config) -> Result<(), toml::de::Error> {
        self.loaded_filters.clear();

        for name in &config.pipeline {
            let config_value = config
                .filters
                .get(name)
                .unwrap_or_else(|| panic!("could not find filter configuration for {}", name));

            let constructor = self
                .registered_filters
                .get(name.as_str())
                .unwrap_or_else(|| panic!("found config settings with no matching filter: {}", name));

            let filter = constructor(config_value.clone())?;
            self.loaded_filters.push(filter);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mock_input(event_id: &str, source_info: &str) -> InputMessage {
        InputMessage {
            message_type: "new".to_string(),
            event: Note {
                id: event_id.to_string(),
                pubkey: "mock_pubkey".to_string(),
                created_at: 0,
                kind: 1,
                tags: vec![],
                content: "test content".to_string(),
                sig: "mock_sig".to_string(),
            },
            received_at: 0,
            source_type: "IP4".to_string(),
            source_info: source_info.to_string(),
        }
    }

    #[test]
    fn test_empty_pipeline_accepts() {
        let mut guard = Noteguard::new();
        let config: Config = toml::from_str(
            r#"
            pipeline = []
            [filters]
            "#,
        )
        .unwrap();
        guard.load_config(&config).unwrap();

        let output = guard.run(create_mock_input("evt1", "127.0.0.1"));
        assert_eq!(output.action, Action::Accept);
    }

    #[test]
    fn test_pipeline_short_circuits_on_reject() {
        let mut guard = Noteguard::new();
        let config: Config = toml::from_str(
            r#"
            pipeline = ["whitelist", "ratelimit"]
            [filters.whitelist]
            pubkeys = ["other_pubkey"]
            [filters.ratelimit]
            posts_per_minute = 10
            "#,
        )
        .unwrap();
        guard.load_config(&config).unwrap();

        // Whitelist rejects, ratelimit never runs
        let output = guard.run(create_mock_input("evt1", "127.0.0.1"));
        assert_eq!(output.action, Action::Reject);
    }
}
