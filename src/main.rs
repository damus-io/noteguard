//! Noteguard - Strfry write policy plugin
//!
//! This binary reads events from stdin (strfry protocol) and outputs
//! filter decisions to stdout. It uses noteguard-core for the actual
//! filtering logic.
//!
//! ## Usage
//!
//! Configure in strfry.conf:
//! ```
//! writePolicy {
//!     plugin = "/path/to/noteguard"
//! }
//! ```
//!
//! Create noteguard.toml in the working directory with your filter config.

use log::info;
use noteguard_core::{Config, InputMessage, Noteguard, OutputMessage};

#[cfg(test)]
use noteguard_core::Action;
use std::io::{self, Read};

#[cfg(feature = "forwarder")]
#[tokio::main]
async fn main() {
    run_noteguard();
}

#[cfg(not(feature = "forwarder"))]
fn main() {
    run_noteguard();
}

/// Serializes an output message to JSON for strfry.
fn serialize_output(msg: &OutputMessage) -> String {
    serde_json::to_string(msg).expect("OutputMessage serialization should not fail")
}

/// Main entry point - loads config and processes stdin.
fn run_noteguard() {
    env_logger::init();
    info!("starting noteguard");

    // Load configuration
    let config_path = "noteguard.toml";
    let config: Config = {
        let mut file = std::fs::File::open(config_path)
            .unwrap_or_else(|e| panic!("failed to open {}: {}", config_path, e));
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", config_path, e));
        toml::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse {}: {}", config_path, e))
    };

    // Initialize filter pipeline
    let mut noteguard = Noteguard::new();
    noteguard
        .load_config(&config)
        .expect("failed to load filter configuration");

    // Process events from stdin
    let stdin = io::stdin();
    for line in stdin.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("failed to read line: {}", e);
                continue;
            }
        };

        let input: InputMessage = match serde_json::from_str(&line) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("failed to parse input: {}", e);
                continue;
            }
        };

        // Strfry only sends "new" type messages to write policy plugins
        if input.message_type != "new" {
            let out = OutputMessage::reject(
                input.event.id.clone(),
                "invalid strfry write policy input",
            );
            println!("{}", serialize_output(&out));
            continue;
        }

        let out = noteguard.run(input);
        println!("{}", serialize_output(&out));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noteguard_core::Note;

    fn mock_input(event_id: &str, pubkey: &str, source_info: &str) -> InputMessage {
        InputMessage {
            message_type: "new".to_string(),
            event: Note {
                id: event_id.to_string(),
                pubkey: pubkey.to_string(),
                created_at: 0,
                kind: 1,
                tags: vec![vec!["-".to_string()]],
                content: "test".to_string(),
                sig: "sig".to_string(),
            },
            received_at: 0,
            source_type: "IP4".to_string(),
            source_info: source_info.to_string(),
        }
    }

    #[test]
    fn test_builtin_filters_registered() {
        let noteguard = Noteguard::new();
        // Verify we can load a config using built-in filters
        let config: Config = toml::from_str(
            r#"
            pipeline = ["ratelimit"]
            [filters.ratelimit]
            posts_per_minute = 5
            "#,
        )
        .unwrap();
        let mut guard = noteguard;
        assert!(guard.load_config(&config).is_ok());
    }

    #[test]
    fn test_protected_events_rejected() {
        let mut noteguard = Noteguard::new();
        let config: Config = toml::from_str(
            r#"
            pipeline = ["protected_events"]
            [filters.protected_events]
            "#,
        )
        .unwrap();
        noteguard.load_config(&config).unwrap();

        let input = mock_input("evt1", "pk1", "127.0.0.1");
        let output = noteguard.run(input);
        assert_eq!(output.action, Action::Reject);
    }

    #[test]
    fn test_whitelist_reject_unknown() {
        let mut noteguard = Noteguard::new();
        let config: Config = toml::from_str(
            r#"
            pipeline = ["whitelist"]
            [filters.whitelist]
            pubkeys = ["allowed_pubkey"]
            "#,
        )
        .unwrap();
        noteguard.load_config(&config).unwrap();

        let input = mock_input("evt1", "unknown_pubkey", "127.0.0.1");
        let output = noteguard.run(input);
        assert_eq!(output.action, Action::Reject);
    }

    #[test]
    fn test_blacklist_blocks_pubkey() {
        let mut noteguard = Noteguard::new();
        let config: Config = toml::from_str(
            r#"
            pipeline = ["blacklist"]
            [filters.blacklist]
            pubkeys = ["bad_actor"]
            "#,
        )
        .unwrap();
        noteguard.load_config(&config).unwrap();

        let input = mock_input("evt1", "bad_actor", "127.0.0.1");
        let output = noteguard.run(input);
        assert_eq!(output.action, Action::Reject);
        assert!(output.msg.unwrap().contains("blacklisted"));
    }

    #[test]
    fn test_blacklist_allows_good_pubkey() {
        let mut noteguard = Noteguard::new();
        let config: Config = toml::from_str(
            r#"
            pipeline = ["blacklist"]
            [filters.blacklist]
            pubkeys = ["bad_actor"]
            "#,
        )
        .unwrap();
        noteguard.load_config(&config).unwrap();

        let input = mock_input("evt1", "good_actor", "127.0.0.1");
        let output = noteguard.run(input);
        assert_eq!(output.action, Action::Accept);
    }

    #[test]
    fn test_cidr_blocking() {
        let mut noteguard = Noteguard::new();
        let config: Config = toml::from_str(
            r#"
            pipeline = ["blacklist"]
            [filters.blacklist]
            cidrs = ["10.0.0.0/8"]
            "#,
        )
        .unwrap();
        noteguard.load_config(&config).unwrap();

        // IP in blocked range
        let input = mock_input("evt1", "pk1", "10.1.2.3");
        assert_eq!(noteguard.run(input).action, Action::Reject);

        // IP outside blocked range
        let input = mock_input("evt2", "pk1", "192.168.1.1");
        assert_eq!(noteguard.run(input).action, Action::Accept);
    }
}
