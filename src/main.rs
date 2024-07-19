use noteguard::filters::{Kinds, ProtectedEvents, RateLimit, Whitelist};

#[cfg(feature = "forwarder")]
use noteguard::filters::Forwarder;

use noteguard::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, Read};
use log::info;

#[derive(Deserialize)]
struct Config {
    pipeline: Vec<String>,
    filters: HashMap<String, toml::Value>,
}

type ConstructFilter = Box<fn(toml::Value) -> Result<Box<dyn NoteFilter>, toml::de::Error>>;

#[derive(Default)]
struct Noteguard {
    registered_filters: HashMap<String, ConstructFilter>,
    loaded_filters: Vec<Box<dyn NoteFilter>>,
}

impl Noteguard {
    pub fn new() -> Self {
        let mut noteguard = Noteguard::default();
        noteguard.register_builtin_filters();
        noteguard
    }

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

    /// All builtin filters are registered here, and are made available with
    /// every new instance of [`Noteguard`]
    fn register_builtin_filters(&mut self) {
        self.register_filter::<RateLimit>();
        self.register_filter::<Whitelist>();
        self.register_filter::<ProtectedEvents>();
        self.register_filter::<Kinds>();

        #[cfg(feature = "forwarder")]
        self.register_filter::<Forwarder>();
    }

    /// Run the loaded filters. You must call `load_config` before calling this, otherwise
    /// not filters will be run.
    fn run(&mut self, input: InputMessage) -> OutputMessage {
        let mut mout: Option<OutputMessage> = None;

        let id = input.event.id.clone();
        for filter in &mut self.loaded_filters {
            let out = filter.filter_note(&input);
            match out.action {
                Action::Accept => {
                    mout = Some(out);
                    continue;
                }
                Action::Reject => {
                    return out;
                }
                Action::ShadowReject => {
                    return out;
                }
            }
        }

        mout.unwrap_or_else(|| OutputMessage::new(id, Action::Accept, None))
    }

    /// Initializes a noteguard config. If it finds any filter configurations
    /// matching the registered filters, it loads those into our filter pipeline.
    fn load_config(&mut self, config: &Config) -> Result<(), toml::de::Error> {
        self.loaded_filters.clear();

        for name in &config.pipeline {
            let config_value = config
                .filters
                .get(name)
                .unwrap_or_else(|| panic!("could not find filter configuration for {}", name));

            if let Some(constructor) = self.registered_filters.get(name.as_str()) {
                let filter = constructor(config_value.clone())?;
                self.loaded_filters.push(filter);
            } else {
                panic!("Found config settings with no matching filter: {}", name);
            }
        }

        Ok(())
    }
}

#[cfg(feature = "forwarder")]
#[tokio::main]
async fn main() {
    noteguard();
}

#[cfg(not(feature = "forwarder"))]
fn main() {
    noteguard();
}

fn serialize_output_message(msg: &OutputMessage) -> String {
    serde_json::to_string(msg).expect("OutputMessage should always serialize correctly")
}


fn noteguard() {
    env_logger::init();
    info!("running noteguard");

    let config_path = "noteguard.toml";
    let mut noteguard = Noteguard::new();

    let config: Config = {
        let mut file = std::fs::File::open(config_path).expect("Failed to open config file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read config file");
        toml::from_str(&contents).expect("Failed to parse config file")
    };

    noteguard
        .load_config(&config)
        .expect("Expected filter config to be loaded ok");

    let stdin = io::stdin();

    for line in stdin.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("Failed to get line: {}", e);
                continue;
            }
        };

        let input_message: InputMessage = match serde_json::from_str(&line) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Failed to parse input: {}", e);
                continue;
            }
        };

        if input_message.message_type != "new" {
            let out = OutputMessage::new(input_message.event.id.clone(), Action::Reject, Some("invalid strfry write policy input".to_string()));
            println!("{}", serialize_output_message(&out));
            continue;
        }

        let out = noteguard.run(input_message);
        let json = serialize_output_message(&out);

        println!("{}", json);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use noteguard::filters::{Kinds, ProtectedEvents, RateLimit, Whitelist};
    use noteguard::{Action, Note};
    use serde_json::json;

    // Helper function to create a mock InputMessage
    fn create_mock_input_message(event_id: &str, message_type: &str) -> InputMessage {
        InputMessage {
            message_type: message_type.to_string(),
            event: Note {
                id: event_id.to_string(),
                pubkey: "mock_pubkey".to_string(),
                created_at: 0,
                kind: 1,
                tags: vec![vec!["-".to_string()]],
                content: "mock_content".to_string(),
                sig: "mock_signature".to_string(),
            },
            received_at: 0,
            source_type: "mock_source".to_string(),
            source_info: "mock_source_info".to_string(),
        }
    }

    // Helper function to create a mock OutputMessage
    fn create_mock_output_message(event_id: &str, action: Action, msg: Option<&str>) -> OutputMessage {
        OutputMessage {
            id: event_id.to_string(),
            action,
            msg: msg.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_register_builtin_filters() {
        let noteguard = Noteguard::new();
        assert!(noteguard.registered_filters.contains_key("ratelimit"));
        assert!(noteguard.registered_filters.contains_key("whitelist"));
        assert!(noteguard.registered_filters.contains_key("protected_events"));
        assert!(noteguard.registered_filters.contains_key("kinds"));
    }

    #[test]
    fn test_load_config() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (RateLimit)
        let config: Config = toml::from_str(r#"
            pipeline = ["ratelimit"]

            [filters.ratelimit]
            posts_per_minute = 3
        "#).expect("Failed to parse config");

        assert!(noteguard.load_config(&config).is_ok());
        assert_eq!(noteguard.loaded_filters.len(), 1);
    }

    #[test]
    fn test_run_filters_accept() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (RateLimit)
        let config: Config = toml::from_str(r#"
            pipeline = ["ratelimit"]

            [filters.ratelimit]
            posts_per_minute = 3
        "#).expect("Failed to parse config");

        noteguard.load_config(&config).expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_1", "new");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Accept);
    }

    #[test]
    fn test_run_filters_shadow_reject() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (ProtectedEvents) which will shadow reject the input
        let config: Config = toml::from_str(r#"
            pipeline = ["protected_events"]

            [filters.protected_events]
        "#).expect("Failed to parse config");

        noteguard.load_config(&config).expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_3", "new");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Reject);
    }

    #[test]
    fn test_whitelist_reject() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (Whitelist) which will reject the input
        let config: Config = toml::from_str(r#"
            pipeline = ["whitelist"]
            [filters.whitelist]
            pubkeys = ["something"]
        "#).expect("Failed to parse config");

        noteguard.load_config(&config).expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_2", "new");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Reject);
    }

    #[test]
    fn test_deserialize_input_message() {
        let input_json = r#"
        {
            "type": "new",
            "event": {
                "id": "test_event_5",
                "pubkey": "mock_pubkey",
                "created_at": 0,
                "kind": 1,
                "tags": [],
                "content": "mock_content",
                "sig": "mock_signature"
            },
            "receivedAt": 0,
            "sourceType": "mock_source",
            "sourceInfo": "mock_source_info"
        }
        "#;

        let input_message: InputMessage = serde_json::from_str(input_json).expect("Failed to deserialize input message");
        assert_eq!(input_message.event.id, "test_event_5");
        assert_eq!(input_message.message_type, "new");
    }
}
