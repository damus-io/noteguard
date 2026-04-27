use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use log::{error, info};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

// Upper bound on the size of a NIP-05 JSON payload (local or remote) we will
// read into memory. 10 MiB is far larger than any realistic nostr.json but
// small enough to prevent OOM from a hostile or misconfigured source.
const MAX_BYTES: u64 = 10 * 1024 * 1024;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_RELOAD_INTERVAL_SECS: u64 = 5;
const DEFAULT_RELOAD_INTERVAL_SECS: u64 = 60;

#[derive(Deserialize, Default)]
pub struct Nip05Whitelist {
    source: String,
    reload_interval_secs: Option<u64>,
    message: Option<String>,

    #[serde(skip)]
    pubkeys: Option<Arc<RwLock<HashSet<String>>>>,
}

#[derive(Deserialize)]
struct Nip05Json {
    names: HashMap<String, String>,
}

fn is_url(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

fn read_capped<R: Read>(mut reader: R, source: &str, kind: &str) -> Result<String, String> {
    let mut buf = Vec::new();
    // Read one byte past the cap so we can detect overflow without silently
    // truncating the payload and feeding a corrupt JSON fragment to the parser.
    reader
        .by_ref()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed to read {} {}: {}", kind, source, e))?;

    if buf.len() as u64 > MAX_BYTES {
        return Err(format!(
            "{} {} exceeded maximum size of {} bytes",
            kind, source, MAX_BYTES
        ));
    }

    String::from_utf8(buf)
        .map_err(|e| format!("failed to read {} {}: {}", kind, source, e))
}

fn fetch_pubkeys(source: &str) -> Result<HashSet<String>, String> {
    let body = if is_url(source) {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(HTTP_CONNECT_TIMEOUT)
            .timeout_read(HTTP_READ_TIMEOUT)
            .build();

        let reader = agent
            .get(source)
            .call()
            .map_err(|e| format!("HTTP request failed for {}: {}", source, e))?
            .into_reader();

        read_capped(reader, source, "response body from")?
    } else {
        let file = std::fs::File::open(source)
            .map_err(|e| format!("failed to read file {}: {}", source, e))?;
        read_capped(file, source, "file")?
    };

    let nip05: Nip05Json =
        serde_json::from_str(&body).map_err(|e| format!("failed to parse NIP-05 JSON: {}", e))?;

    Ok(nip05.names.into_values().collect())
}

fn spawn_reload_thread(source: String, interval: Duration, pubkeys: Arc<RwLock<HashSet<String>>>) {
    thread::spawn(move || loop {
        thread::sleep(interval);

        match fetch_pubkeys(&source) {
            Ok(new_set) => {
                let count = new_set.len();
                if let Ok(mut w) = pubkeys.write() {
                    *w = new_set;
                }
                info!(
                    "nip05_whitelist: reloaded {} pubkeys from {}",
                    count, source
                );
            }
            Err(e) => {
                error!("nip05_whitelist: reload failed, keeping previous set: {}", e);
            }
        }
    });
}

impl Nip05Whitelist {
    fn initialize(&mut self) {
        let initial_set = match fetch_pubkeys(&self.source) {
            Ok(set) => {
                info!(
                    "nip05_whitelist: loaded {} pubkeys from {}",
                    set.len(),
                    self.source
                );
                set
            }
            Err(e) => {
                error!("nip05_whitelist: initial load failed, starting with empty set: {}", e);
                HashSet::new()
            }
        };

        let pubkeys = Arc::new(RwLock::new(initial_set));
        self.pubkeys = Some(pubkeys.clone());

        let configured = self
            .reload_interval_secs
            .unwrap_or(DEFAULT_RELOAD_INTERVAL_SECS);
        let clamped = configured.max(MIN_RELOAD_INTERVAL_SECS);
        if clamped != configured {
            error!(
                "nip05_whitelist: reload_interval_secs={} is below minimum {}, clamping",
                configured, MIN_RELOAD_INTERVAL_SECS
            );
        }
        let interval = Duration::from_secs(clamped);
        spawn_reload_thread(self.source.clone(), interval, pubkeys);
    }
}

impl NoteFilter for Nip05Whitelist {
    fn name(&self) -> &'static str {
        "nip05_whitelist"
    }

    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        if self.pubkeys.is_none() {
            self.initialize();
        }

        let dominated = self
            .pubkeys
            .as_ref()
            .and_then(|pk| pk.read().ok())
            .map(|set| set.contains(&msg.event.pubkey))
            .unwrap_or(false);

        if dominated {
            OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
        } else {
            let reject_msg = self
                .message
                .clone()
                .unwrap_or_else(|| "blocked: not a verified member".to_string());
            OutputMessage::new(msg.event.id.clone(), Action::Reject, Some(reject_msg))
        }
    }
}
