use crate::nscript::{Runtime, Verdict};
use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;

/// Runs a user-supplied WASM guest as a note filter via the accessor ABI.
///
/// For the Phase 0 spike the guest is loaded from a local path and the owner
/// context comes from config; a later phase sources both from a signed
/// submission event on the relay.
#[derive(Deserialize, Default)]
pub struct NScript {
    /// Path to the compiled guest `.wasm`.
    module: String,

    /// Hex pubkey the script is scoped to (its "inbox owner").
    #[serde(default)]
    owner: Option<String>,

    /// Hex pubkeys the owner follows (backs `is_following`).
    #[serde(default)]
    follows: Vec<String>,

    /// Message returned to the client on reject.
    #[serde(default)]
    message: Option<String>,

    /// Compiled runtime, built lazily on first note.
    #[serde(skip)]
    runtime: Option<Runtime>,
}

impl NoteFilter for NScript {
    fn name(&self) -> &'static str {
        "nscript"
    }

    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        let id = msg.event.id.clone();

        if self.runtime.is_none() {
            match Runtime::load(&self.module, &self.owner, &self.follows) {
                Ok(rt) => self.runtime = Some(rt),
                Err(e) => {
                    // Fail open: a broken filter shouldn't block all writes.
                    log::error!("nscript: failed to load {}: {}", self.module, e);
                    return OutputMessage::new(id, Action::Accept, None);
                }
            }
        }

        let rt = self.runtime.as_ref().expect("runtime just loaded");
        match rt.run(&msg.event) {
            Ok(Verdict::Accept) => OutputMessage::new(id, Action::Accept, None),
            Ok(Verdict::Reject) => OutputMessage::new(id, Action::Reject, self.message.clone()),
            Ok(Verdict::ShadowReject) => OutputMessage::new(id, Action::ShadowReject, None),
            Err(e) => {
                // Fail open on guest trap / resource exhaustion.
                log::error!("nscript: guest error: {}", e);
                OutputMessage::new(id, Action::Accept, None)
            }
        }
    }
}
