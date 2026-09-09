use crate::filters::ban::BanTracker;
use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct Tokens {
    pub tokens: i32,
    pub last_post: Instant,
}

#[derive(Deserialize, Default)]
pub struct RateLimit {
    pub posts_per_minute: i32,
    pub whitelist: Option<Vec<String>>,
    pub message: Option<String>,

    /// IP-ban persistent offenders. `ban_after` *consecutive* rate-limit
    /// rejections (a streak any accepted post resets) trips a ban; see
    /// [`BanTracker`]. Flattened so `ban_after` etc. sit at this filter's level.
    #[serde(flatten)]
    pub ban: BanTracker,

    #[serde(skip)]
    pub sources: HashMap<String, Tokens>,
}

impl NoteFilter for RateLimit {
    fn name(&self) -> &'static str {
        "ratelimit"
    }

    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage {
        if let Some(whitelist) = &self.whitelist {
            if whitelist.contains(&msg.source_info) {
                return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
            }
        }

        let now = Instant::now();

        // Enforce an active IP-ban before touching the token bucket, so a banned
        // IP cannot refill or reset anything by continuing to hammer us.
        if self.ban.is_banned(&msg.source_info, now) {
            return OutputMessage::new(
                msg.event.id.clone(),
                Action::Reject,
                Some(self.ban.message().to_owned()),
            );
        }

        if !self.sources.contains_key(&msg.source_info) {
            self.sources.insert(
                msg.source_info.to_owned(),
                Tokens {
                    last_post: now,
                    tokens: self.posts_per_minute,
                },
            );
            return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
        }

        let entry = self.sources.get_mut(&msg.source_info).expect("impossiburu");
        let mut diff = now - entry.last_post;

        let min = Duration::from_secs(60);
        if diff > min {
            diff = min;
        }

        let percent = (diff.as_secs() as f32) / 60.0;
        let new_tokens = (percent * self.posts_per_minute as f32).floor() as i32;
        entry.tokens += new_tokens - 1;

        if entry.tokens <= 0 {
            entry.tokens = 0;
        }

        if entry.tokens >= self.posts_per_minute {
            entry.tokens = self.posts_per_minute - 1;
        }

        if entry.tokens == 0 {
            // Persistent offender: escalate a streak of rate-limit hits into an
            // IP-ban once it crosses the configured threshold.
            if self.ban.strike(&msg.source_info, now) {
                return OutputMessage::new(
                    msg.event.id.clone(),
                    Action::Reject,
                    Some(self.ban.message().to_owned()),
                );
            }

            let message = self
                .message
                .as_deref()
                .unwrap_or("rate-limited: you are noting too much");

            return OutputMessage::new(
                msg.event.id.clone(),
                Action::Reject,
                Some(message.to_owned()),
            );
        }

        entry.last_post = now;
        // A successful post breaks the rate-limit streak.
        self.ban.reset(&msg.source_info);
        OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Note;

    fn msg(id: &str, ip: &str) -> InputMessage {
        InputMessage {
            message_type: "new".to_string(),
            event: Note {
                id: id.to_string(),
                pubkey: "pk".to_string(),
                created_at: 0,
                kind: 1,
                tags: vec![],
                content: "hi".to_string(),
                sig: "sig".to_string(),
            },
            received_at: 0,
            source_type: "IP4".to_string(),
            source_info: ip.to_string(),
        }
    }

    fn ratelimit(toml_cfg: &str) -> RateLimit {
        toml::from_str(toml_cfg).expect("valid ratelimit config")
    }

    #[test]
    fn bans_after_consecutive_strikes() {
        let mut rl = ratelimit("posts_per_minute = 1\nban_after = 3\n");

        // First post seeds the bucket and is accepted.
        assert_eq!(rl.filter_note(&msg("e1", "1.2.3.4")).action, Action::Accept);

        // The next three back-to-back posts are all rate-limited. The third one
        // trips `ban_after` and flips into a ban.
        let r2 = rl.filter_note(&msg("e2", "1.2.3.4"));
        let r3 = rl.filter_note(&msg("e3", "1.2.3.4"));
        let r4 = rl.filter_note(&msg("e4", "1.2.3.4"));
        assert_eq!(r2.action, Action::Reject);
        assert!(!r2.msg.unwrap().contains("banned"));
        assert_eq!(r3.action, Action::Reject);
        assert_eq!(r4.action, Action::Reject);
        assert!(r4.msg.unwrap().contains("banned"));

        // Once banned, further posts are rejected as banned regardless.
        let r5 = rl.filter_note(&msg("e5", "1.2.3.4"));
        assert_eq!(r5.action, Action::Reject);
        assert!(r5.msg.unwrap().contains("banned"));
    }

    #[test]
    fn no_ban_when_unconfigured() {
        let mut rl = ratelimit("posts_per_minute = 1\n");

        assert_eq!(rl.filter_note(&msg("e1", "1.2.3.4")).action, Action::Accept);
        // Without `ban_after`, persistent hammering only ever rate-limits.
        for i in 0..10 {
            let r = rl.filter_note(&msg(&format!("e{i}"), "1.2.3.4"));
            assert_eq!(r.action, Action::Reject);
            assert!(!r.msg.unwrap().contains("banned"));
        }
    }

    #[test]
    fn whitelisted_ip_is_never_banned() {
        let mut rl = ratelimit("posts_per_minute = 1\nban_after = 2\nwhitelist = [\"1.2.3.4\"]\n");

        for i in 0..10 {
            let r = rl.filter_note(&msg(&format!("e{i}"), "1.2.3.4"));
            assert_eq!(r.action, Action::Accept);
        }
    }

    #[test]
    fn a_successful_post_resets_the_streak() {
        let mut rl = ratelimit("posts_per_minute = 2\nban_after = 2\n");

        // Seed + drain, then one rate-limit rejection (strike 1).
        assert_eq!(rl.filter_note(&msg("e1", "5.6.7.8")).action, Action::Accept);
        assert_eq!(rl.filter_note(&msg("e2", "5.6.7.8")).action, Action::Accept);
        assert_eq!(rl.filter_note(&msg("e3", "5.6.7.8")).action, Action::Reject);

        // Refill the bucket so the next post is accepted, resetting the streak.
        rl.sources.get_mut("5.6.7.8").unwrap().last_post = Instant::now() - Duration::from_secs(120);
        assert_eq!(rl.filter_note(&msg("e4", "5.6.7.8")).action, Action::Accept);

        // A fresh streak now needs the full `ban_after` again — the next lone
        // rejection must NOT ban.
        let r = rl.filter_note(&msg("e5", "5.6.7.8"));
        assert_eq!(r.action, Action::Reject);
        assert!(!r.msg.unwrap().contains("banned"));
    }
}
