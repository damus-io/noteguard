use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct Blacklist {
    pub pubkeys: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
}

impl NoteFilter for Blacklist {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        let reject_message = "blocked: pubkey/ip is blacklisted".to_string();
        if let Some(pubkeys) = &self.pubkeys {
            if pubkeys.contains(&msg.event.pubkey) {
                return OutputMessage::new(
                    msg.event.id.clone(),
                    Action::Reject,
                    Some(reject_message),
                );
            }
        }

        if let Some(ips) = &self.ips {
            if ips.contains(&msg.source_info) {
                return OutputMessage::new(
                    msg.event.id.clone(),
                    Action::Reject,
                    Some(reject_message),
                );
            }
        }

        OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
    }

    fn name(&self) -> &'static str {
        "blacklist"
    }
}
