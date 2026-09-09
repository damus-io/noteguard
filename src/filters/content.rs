use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use unicode_security::skeleton;

#[derive(Deserialize, Default)]
pub struct Content {
    filters: Vec<String>,

    /// Confusables-normalized, case-folded copies of `filters`, built lazily on
    /// first use. Matching against these catches homoglyph spoofs — e.g. Cyrillic
    /// `а`/`А` (U+0430/U+0410) standing in for Latin `a`/`A` in "Damus Airdrop"
    /// spam — that a raw byte-wise `contains` check silently misses.
    #[serde(skip)]
    normalized: Option<Vec<String>>,
}

/// Fold a string to its UTS #39 confusables skeleton, case-folded, so that
/// visually-identical strings built from different codepoints compare equal.
/// Case is folded both before and after skeletonizing: the confusable prototypes
/// are not case-stable (uppercase `А` and lowercase `а` skeletonize differently),
/// so lowercasing up front lines the inputs up before the skeleton is taken.
fn normalize(s: &str) -> String {
    skeleton(&s.to_lowercase()).collect::<String>().to_lowercase()
}

impl NoteFilter for Content {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        let normalized = self
            .normalized
            .get_or_insert_with(|| self.filters.iter().map(|f| normalize(f)).collect());

        let content = normalize(&msg.event.content);
        for filter in normalized.iter() {
            if content.contains(filter) {
                return OutputMessage::new(msg.event.id.clone(), Action::ShadowReject, None);
            }
        }

        OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
    }

    fn name(&self) -> &'static str {
        "content"
    }
}
