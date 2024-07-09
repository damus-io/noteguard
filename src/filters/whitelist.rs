use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct Whitelist {
    pub pubkeys: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
}

impl NoteFilter for Whitelist {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        if let Some(pubkeys) = &self.pubkeys {
            if pubkeys.contains(&msg.event.pubkey) {
                return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
            }
        }

        if let Some(ips) = &self.ips {
            if ips.contains(&msg.source_info) {
                return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
            }
        }

        OutputMessage::new(
            msg.event.id.clone(),
            Action::Reject,
            Some("blocked: pubkey/ip not on the whitelist".to_string()),
        )
    }

    fn name(&self) -> &'static str {
        "whitelist"
    }
}
