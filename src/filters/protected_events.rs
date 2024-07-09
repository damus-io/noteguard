use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct ProtectedEvents {}

impl NoteFilter for ProtectedEvents {
    fn filter_note(&mut self, input: &InputMessage) -> OutputMessage {
        if let Some(tag) = input.event.tags.first() {
            if let Some(entry) = tag.first() {
                if entry == "-" {
                    return OutputMessage::new(
                        input.event.id.clone(),
                        Action::Reject,
                        Some("blocked: event marked as protected".to_string()),
                    );
                }
            }
        }

        OutputMessage::new(input.event.id.clone(), Action::Accept, None)
    }

    fn name(&self) -> &'static str {
        "protected_events"
    }
}
