use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct Tokens {
    pub tokens: i32,
    pub last_post: Instant,
}

#[derive(Deserialize, Default)]
pub struct RateLimit {
    pub posts_per_minute: i32,
    pub whitelist: Option<Vec<String>>,
    pub message: Option<String>,

    #[serde(skip)]
    pub sources: HashMap<String, Tokens>,
}

impl NoteFilter for RateLimit {
    fn name(&self) -> &'static str {
        "ratelimit"
    }

    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        if let Some(whitelist) = &self.whitelist {
            if whitelist.contains(&msg.source_info) {
                return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
            }
        }

        if !self.sources.contains_key(&msg.source_info) {
            self.sources.insert(
                msg.source_info.to_owned(),
                Tokens {
                    last_post: Instant::now(),
                    tokens: self.posts_per_minute,
                },
            );
            return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
        }

        let entry = self.sources.get_mut(&msg.source_info).expect("impossiburu");
        let now = Instant::now();
        let mut diff = now - entry.last_post;

        let min = Duration::from_secs(60);
        if diff > min {
            diff = min;
        }

        let percent = (diff.as_secs() as f32) / 60.0;
        let new_tokens = (percent * self.posts_per_minute as f32).floor() as i32;
        entry.tokens += new_tokens - 1;

        if entry.tokens <= 0 {
            entry.tokens = 0;
        }

        if entry.tokens >= self.posts_per_minute {
            entry.tokens = self.posts_per_minute - 1;
        }

        if entry.tokens == 0 {
            return OutputMessage::new(
                msg.event.id.clone(),
                Action::Reject,
                Some(
                    self.message
                        .clone()
                        .unwrap_or("rate-limited: you are noting too much".to_string()),
                ),
            );
        }

        entry.last_post = now;
        OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
    }
}
