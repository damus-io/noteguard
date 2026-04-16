use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use log::{error, info};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

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

fn fetch_pubkeys(source: &str) -> Result<HashSet<String>, String> {
    let body = if is_url(source) {
        ureq::get(source)
            .call()
            .map_err(|e| format!("HTTP request failed for {}: {}", source, e))?
            .into_string()
            .map_err(|e| format!("failed to read response body from {}: {}", source, e))?
    } else {
        std::fs::read_to_string(source)
            .map_err(|e| format!("failed to read file {}: {}", source, e))?
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

        let interval = Duration::from_secs(self.reload_interval_secs.unwrap_or(60));
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
