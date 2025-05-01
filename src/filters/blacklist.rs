use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Deserialize, Default)]
pub struct BlacklistConfig {
    pub pubkeys: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
    pub cidrs: Option<Vec<String>>,
}

#[derive(Default)]
pub struct Blacklist {
    pubkeys: Option<Vec<String>>,
    ips: Option<Vec<String>>,
    cidrs: Option<Vec<IpNetwork>>,
}

impl<'de> Deserialize<'de> for Blacklist {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let config = BlacklistConfig::deserialize(deserializer)?;
        Ok(Blacklist {
            pubkeys: config.pubkeys,
            ips: config.ips,
            cidrs: config.cidrs.map(|cidrs| {
                cidrs
                    .into_iter()
                    .filter_map(|s| IpNetwork::from_str(&s).ok())
                    .collect()
            }),
        })
    }
}

impl Blacklist {
    fn is_ip_blocked(&self, ip: &str) -> bool {
        if let Some(ips) = &self.ips {
            if ips.contains(&ip.to_string()) {
                return true;
            }
        }

        if let Ok(addr) = IpAddr::from_str(ip) {
            if let Some(cidrs) = &self.cidrs {
                if cidrs.iter().any(|network| network.contains(addr)) {
                    return true;
                }
            }
        }

        false
    }
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

        if self.is_ip_blocked(&msg.source_info) {
            return OutputMessage::new(msg.event.id.clone(), Action::Reject, Some(reject_message));
        }

        OutputMessage::new(msg.event.id.clone(), Action::Accept, None)
    }

    fn name(&self) -> &'static str {
        "blacklist"
    }
}
