use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateInfo {
    pub last_note: Instant,
}

#[derive(Deserialize, Default)]
pub struct RateLimit {
    pub delay_seconds: u64,
    pub whitelist: Option<Vec<String>>,

    #[serde(skip)]
    pub sources: HashMap<String, RateInfo>,
}

impl NoteFilter for RateLimit {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        if let Some(whitelist) = &self.whitelist {
            if whitelist.contains(&msg.source_info) {
                return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
            }
        }

        if self.sources.contains_key(&msg.source_info) {
            let now = Instant::now();
            let entry = self.sources.get_mut(&msg.source_info).expect("impossiburu");
            if now - entry.last_note < Duration::from_secs(self.delay_seconds) {
                return OutputMessage::new(
                    msg.event.id.clone(),
                    Action::Reject,
                    Some("rate-limited: you are noting too fast".to_string()),
                );
            } else {
                entry.last_note = Instant::now();
                return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
            }
        } else {
            self.sources.insert(
                msg.source_info.to_owned(),
                RateInfo {
                    last_note: Instant::now(),
                },
            );
            return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
        }
    }

    fn name(&self) -> &'static str {
        "ratelimit"
    }
}
