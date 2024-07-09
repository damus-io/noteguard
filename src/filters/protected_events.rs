use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct ProtectedEvents {}

impl NoteFilter for ProtectedEvents {
    fn filter_note(&mut self, input: &InputMessage) -> OutputMessage {
        for tag in &input.event.tags {
            for entry in tag {
                if entry == "-" {
                    return OutputMessage::new(
                        input.event.id.clone(),
                        Action::Reject,
                        Some("blocked: event marked as protected".to_string()),
                    );
                }
                break;
            }
            break;
        }

        OutputMessage::new(input.event.id.clone(), Action::Accept, None)
    }

    fn name(&self) -> &'static str {
        "protected_events"
    }
}
