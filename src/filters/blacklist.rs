use crate::{Action, InputMessage, NoteFilter, OutputMessage};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Deserialize, Default)]
pub struct Blacklist {
    pub pubkeys: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
    pub cidrs: Option<Vec<String>>,
}

impl Blacklist {
    fn is_ip_blocked(&self, ip: &str) -> bool {
        if let Some(cidrs) = &self.cidrs {
            for cidr in cidrs {
                if let Ok(network) = IpNetwork::from_str(cidr) {
                    if let Ok(addr) = IpAddr::from_str(ip) {
                        if network.contains(addr) {
                            return true;
                        }
                    }
                }
            }
        }

        if let Some(ips) = &self.ips {
            if ips.contains(&ip.to_string()) {
                return true;
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
