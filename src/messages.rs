use crate::Note;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct InputMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub event: Note,
    #[serde(rename = "receivedAt")]
    pub received_at: u64,
    #[serde(rename = "sourceType")]
    pub source_type: String,
    #[serde(rename = "sourceInfo")]
    pub source_info: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Accept,
    Reject,
    ShadowReject,
}

#[derive(Serialize)]
pub struct OutputMessage {
    pub id: String,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
}

impl OutputMessage {
    pub fn new(id: String, action: Action, msg: Option<String>) -> Self {
        OutputMessage { id, action, msg }
    }
}
