use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Default)]
pub struct Kinds {
    kinds: Vec<i64>,
    messages: Option<HashMap<String, String>>,
}

impl NoteFilter for Kinds {
    fn filter_note(&mut self, input: &InputMessage) -> OutputMessage {
        let kind = input.event.kind;
        if self.kinds.contains(&kind) {
            let msg = self
                .messages
                .as_ref()
                .and_then(|msgs| msgs.get(&kind.to_string()).cloned())
                .unwrap_or_else(|| "blocked: note kind is not allowed here".to_string());
            OutputMessage::new(input.event.id.clone(), Action::Reject, Some(msg))
        } else {
            OutputMessage::new(input.event.id.clone(), Action::Accept, None)
        }
    }

    fn name(&self) -> &'static str {
        "kinds"
    }
}
