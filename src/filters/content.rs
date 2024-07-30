use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct Content {
    filters: Vec<String>,
}

impl NoteFilter for Content {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        for filter in &self.filters {
            if msg.event.content.contains(filter) {
                return OutputMessage::new(msg.event.id.clone(), Action::ShadowReject, None);
            }
        }

        OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
    }

    fn name(&self) -> &'static str {
        "content"
    }
}
