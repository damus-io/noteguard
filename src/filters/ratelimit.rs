use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default IP-ban duration once an IP trips [`RateLimit::ban_after`]: one hour.
const DEFAULT_BAN_DURATION_SECS: u64 = 3600;

pub struct Tokens {
    pub tokens: i32,
    pub last_post: Instant,
    /// Consecutive rate-limit rejections since the last accepted post. Reset to
    /// zero whenever a post is accepted, and whenever an expired ban is cleared.
    pub strikes: i32,
    /// When set and still in the future, every post from this IP is rejected
    /// outright (the IP-ban). Cleared, along with `strikes`, once it elapses.
    pub banned_until: Option<Instant>,
}

#[derive(Deserialize, Default)]
pub struct RateLimit {
    pub posts_per_minute: i32,
    pub whitelist: Option<Vec<String>>,
    pub message: Option<String>,

    /// IP-ban an offender after this many *consecutive* rate-limit rejections.
    /// `None` (the default) disables banning: the filter only ever rate-limits.
    pub ban_after: Option<i32>,
    /// How long an IP-ban lasts, in seconds. Defaults to
    /// [`DEFAULT_BAN_DURATION_SECS`] (one hour) when `ban_after` is set.
    pub ban_duration_secs: Option<u64>,
    /// Message returned to a banned IP. Falls back to a generic notice.
    pub ban_message: Option<String>,

    #[serde(skip)]
    pub sources: HashMap<String, Tokens>,
}

impl RateLimit {
    fn ban_reject(&self, id: String) -> OutputMessage {
        let message = self
            .ban_message
            .as_deref()
            .unwrap_or("banned: too many rate-limit violations, try again later");
        OutputMessage::new(id, Action::Reject, Some(message.to_owned()))
    }
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

        if !self.sources.contains_key(&msg.source_info) {
            self.sources.insert(
                msg.source_info.to_owned(),
                Tokens {
                    last_post: now,
                    tokens: self.posts_per_minute,
                    strikes: 0,
                    banned_until: None,
                },
            );
            return OutputMessage::new(msg.event.id.clone(), Action::Accept, None);
        }

        let entry = self.sources.get_mut(&msg.source_info).expect("impossiburu");

        // Enforce an active IP-ban before touching the token bucket, so a banned
        // IP cannot refill or reset anything by continuing to hammer us.
        if let Some(until) = entry.banned_until {
            if now < until {
                return self.ban_reject(msg.event.id.clone());
            }
            entry.banned_until = None;
            entry.strikes = 0;
        }

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
            if let Some(ban_after) = self.ban_after {
                entry.strikes += 1;
                if entry.strikes >= ban_after {
                    let secs = self.ban_duration_secs.unwrap_or(DEFAULT_BAN_DURATION_SECS);
                    entry.banned_until = Some(now + Duration::from_secs(secs));
                    return self.ban_reject(msg.event.id.clone());
                }
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
        entry.strikes = 0;
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

    #[test]
    fn bans_after_consecutive_strikes() {
        let mut rl = RateLimit {
            posts_per_minute: 1,
            ban_after: Some(3),
            ..Default::default()
        };

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
        let mut rl = RateLimit {
            posts_per_minute: 1,
            ..Default::default()
        };

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
        let mut rl = RateLimit {
            posts_per_minute: 1,
            ban_after: Some(2),
            whitelist: Some(vec!["1.2.3.4".to_string()]),
            ..Default::default()
        };

        for i in 0..10 {
            let r = rl.filter_note(&msg(&format!("e{i}"), "1.2.3.4"));
            assert_eq!(r.action, Action::Accept);
        }
    }

    #[test]
    fn expired_ban_clears_and_allows_again() {
        let mut rl = RateLimit {
            posts_per_minute: 2,
            ban_after: Some(2),
            ..Default::default()
        };

        // Seed + drain the bucket, then two back-to-back rejections trip the ban.
        assert_eq!(rl.filter_note(&msg("e1", "5.6.7.8")).action, Action::Accept);
        assert_eq!(rl.filter_note(&msg("e2", "5.6.7.8")).action, Action::Accept);
        assert_eq!(rl.filter_note(&msg("e3", "5.6.7.8")).action, Action::Reject);
        assert!(rl
            .filter_note(&msg("e4", "5.6.7.8"))
            .msg
            .unwrap()
            .contains("banned"));

        // Force the ban into the past and let the bucket refill: the next post
        // should clear the ban, reset strikes, and be accepted.
        let entry = rl.sources.get_mut("5.6.7.8").unwrap();
        entry.banned_until = Some(Instant::now() - Duration::from_secs(1));
        entry.last_post = Instant::now() - Duration::from_secs(120);
        assert_eq!(rl.filter_note(&msg("e5", "5.6.7.8")).action, Action::Accept);
        assert_eq!(rl.sources.get("5.6.7.8").unwrap().strikes, 0);
    }
}
