use noteguard::filters::{ProtectedEvents, RateLimit, Whitelist};
use noteguard::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};

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

fn main() {
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
    let stdout = io::stdout();
    let handle = stdout.lock();
    let mut writer = io::BufWriter::new(handle);

    for line in stdin.lock().lines() {
        match line {
            Ok(input) => {
                let input_message: InputMessage = match serde_json::from_str(&input) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Failed to parse input: {}", e);
                        continue;
                    }
                };

                if input_message.message_type != "new" {
                    eprintln!("Unexpected request type");
                    continue;
                }

                let output_message = noteguard.run(input_message);

                match serde_json::to_string(&output_message) {
                    Ok(json) => {
                        writeln!(writer, "{}", json).unwrap();
                        writer.flush().unwrap();
                    }
                    Err(e) => {
                        eprintln!("Failed to serialize output: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to read line: {}", e);
            }
        }
    }
}
