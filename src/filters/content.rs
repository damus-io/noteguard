use crate::filters::ban::BanTracker;
use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::time::Instant;
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

    /// IP-ban repeat offenders. Content violations accrue *cumulatively* per IP
    /// (a matching note never resets the count); once they cross `ban_after`
    /// every note from that IP is shadow-rejected until the ban expires. See
    /// [`BanTracker`]. Flattened so `ban_after` etc. sit at this filter's level.
    #[serde(flatten)]
    ban: BanTracker,
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
        let now = Instant::now();

        // A banned IP has everything silently dropped, not just matching notes —
        // shadow-rejected to keep the ban invisible to the offender, like a
        // content match itself.
        if self.ban.is_banned(&msg.source_info, now) {
            return OutputMessage::new(msg.event.id.clone(), Action::ShadowReject, None);
        }

        let matched = {
            let normalized = self
                .normalized
                .get_or_insert_with(|| self.filters.iter().map(|f| normalize(f)).collect());
            let content = normalize(&msg.event.content);
            normalized.iter().any(|filter| content.contains(filter))
        };

        if matched {
            // Count the violation (may trip a ban for next time); either way this
            // note is shadow-rejected.
            self.ban.strike(&msg.source_info, now);
            return OutputMessage::new(msg.event.id.clone(), Action::ShadowReject, None);
        }

        OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
    }

    fn name(&self) -> &'static str {
        "content"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Note;

    fn msg(id: &str, ip: &str, content: &str) -> InputMessage {
        InputMessage {
            message_type: "new".to_string(),
            event: Note {
                id: id.to_string(),
                pubkey: "pk".to_string(),
                created_at: 0,
                kind: 1,
                tags: vec![],
                content: content.to_string(),
                sig: "sig".to_string(),
            },
            received_at: 0,
            source_type: "IP4".to_string(),
            source_info: ip.to_string(),
        }
    }

    fn content(toml_cfg: &str) -> Content {
        toml::from_str(toml_cfg).expect("valid content config")
    }

    #[test]
    fn matches_shadow_reject_without_banning() {
        let mut c = content("filters = [\"spam\"]\n");
        assert_eq!(
            c.filter_note(&msg("e1", "1.2.3.4", "buy spam now")).action,
            Action::ShadowReject
        );
        // No ban configured, so a clean note from the same IP still passes.
        assert_eq!(
            c.filter_note(&msg("e2", "1.2.3.4", "hello")).action,
            Action::Accept
        );
    }

    #[test]
    fn bans_after_cumulative_violations() {
        let mut c = content("filters = [\"spam\"]\nban_after = 3\n");

        // Clean notes interleaved with spam must NOT reset the streak.
        assert_eq!(
            c.filter_note(&msg("e1", "9.9.9.9", "spam")).action,
            Action::ShadowReject
        );
        assert_eq!(
            c.filter_note(&msg("e2", "9.9.9.9", "hello")).action,
            Action::Accept
        );
        assert_eq!(
            c.filter_note(&msg("e3", "9.9.9.9", "spam")).action,
            Action::ShadowReject
        );
        // Third violation trips the ban.
        assert_eq!(
            c.filter_note(&msg("e4", "9.9.9.9", "spam")).action,
            Action::ShadowReject
        );

        // Now banned: even a perfectly clean note is silently dropped.
        assert_eq!(
            c.filter_note(&msg("e5", "9.9.9.9", "totally fine")).action,
            Action::ShadowReject
        );
        // A different IP is unaffected.
        assert_eq!(
            c.filter_note(&msg("e6", "8.8.8.8", "totally fine")).action,
            Action::Accept
        );
    }
}
