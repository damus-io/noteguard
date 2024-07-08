use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Whitelist {
    pub pubkeys: Vec<String>,
    pub ips: Vec<String>,
}

impl NoteFilter for Whitelist {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        if self.pubkeys.contains(&msg.event.pubkey) || self.ips.contains(&msg.source_info) {
            OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
        } else {
            OutputMessage::new(
                msg.event.id.clone(),
                Action::Reject,
                Some("blocked: pubkey not on the whitelist".to_string()),
            )
        }
    }

    fn name(&self) -> &'static str {
        "whitelist"
    }
}
