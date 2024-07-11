use crate::{InputMessage, OutputMessage};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone)]
pub struct Note {
    pub id: String,
    pub pubkey: String,
    pub content: String,
    pub created_at: i64,
    pub kind: i64,
    pub tags: Vec<Vec<String>>,
    pub sig: String,
}

pub trait NoteFilter {
    fn filter_note(&mut self, msg: &InputMessage) -> OutputMessage;

    /// A key corresponding to an entry in the noteguard.toml file.
    fn name(&self) -> &'static str;
}
