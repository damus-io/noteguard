//! Read-side (readPolicy) plugin wire protocol.
//!
//! strfry's read plugin is the REQ-path analogue of the writePolicy plugin
//! implemented in [`crate::messages`]. Whereas the write plugin decides whether
//! an incoming event is *stored* (a reject deletes it for everyone), the read
//! plugin decides, per subscription, which already-stored events are *delivered*
//! to that particular subscriber. See `strfry/docs/plugins.md` ("Read-policy
//! plugins") and `strfry/src/PluginReadPolicy.h` for the authoritative protocol.
//!
//! Every message is one minified JSON object followed by a newline. All requests
//! carry a monotonic `reqId`; responses to `reqOpen`/`req` must echo it.
//! `reqClose`/`connClose` are fire-and-forget — the plugin must NOT respond to
//! them (a stray response desyncs the pipe).

use crate::Note;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;

/// An event object from a `req` batch, kept in its original unparsed wire form.
///
/// Wrapping the raw JSON (rather than a fully-parsed [`Note`]) lets us measure
/// the exact number of bytes strfry streamed — [`size`](Self::size) is the wire
/// length with no re-serialization — while deferring the cost of a full parse to
/// the paths that actually need field access. The bandwidth-only metering path
/// never parses a `Note` at all; it only ever calls `size()` and, for the
/// accept-list, the cheap id-only [`id`](Self::id).
///
/// `RawValue` only captures the original source bytes when it is deserialized
/// straight from the top-level `serde_json` deserializer. That is why
/// [`ReadInput`] uses a manual `Deserialize` over a flat struct instead of the
/// derived `#[serde(tag = "type")]` enum: an internally-tagged enum buffers the
/// object into a serde `Content` value first, which strips `RawValue`'s capture.
#[derive(Deserialize, Debug)]
pub struct UnparsedNote(Box<RawValue>);

impl UnparsedNote {
    /// Exact byte length of the event object as strfry streamed it (the token
    /// cost charged by the bandwidth throttle). No re-serialization.
    pub fn size(&self) -> usize {
        self.0.get().len()
    }

    /// Fully parse the event into a [`Note`]. Only used when a guest filter
    /// actually needs the event's fields.
    pub fn parse(&self) -> serde_json::Result<Note> {
        serde_json::from_str(self.0.get())
    }

    /// Cheaply parse just the event `id` for the accept-list, avoiding a full
    /// [`Note`] parse on the bandwidth-only (no-guest) path.
    pub fn id(&self) -> serde_json::Result<String> {
        #[derive(Deserialize)]
        struct IdOnly {
            id: String,
        }
        let IdOnly { id } = serde_json::from_str(self.0.get())?;
        Ok(id)
    }

    /// Construct one directly from a JSON string (test helper / for callers that
    /// already hold the wire bytes).
    #[cfg(test)]
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        Ok(UnparsedNote(RawValue::from_string(json.to_string())?))
    }
}

/// A message sent from strfry to the read plugin, discriminated by `type`.
///
/// Deserialized via a manual `impl Deserialize` (below) rather than the derived
/// internally-tagged enum, so the nested `Vec<UnparsedNote>` in [`Req`] captures
/// true wire bytes for byte metering. See [`UnparsedNote`].
#[derive(Debug)]
pub enum ReadInput {
    /// A subscription started serving on a read thread. The admission/throttle
    /// hook and the authoritative place the subscription's `filter` arrives.
    ReqOpen {
        req_id: u64,
        conn_id: u64,
        sub_id: String,
        /// The authenticated pubkey (hex), present only if the connection did
        /// NIP-42 AUTH. This is the subscriber / script owner.
        authed: Option<String>,
        /// The subscription's filters, as a JSON array. Sent authoritatively
        /// here; omitted on `req`. Cache it per `(connId, subId)` if needed.
        filter: Option<Value>,
        /// The rendered client IP string, present when strfry knows it (newer
        /// strfry builds only; absent → `None` against older strfry). Cached
        /// per `connId` so the per-IP bandwidth throttle can meter on `req`,
        /// which carries no IP.
        ip: Option<String>,
    },

    /// A batch of already-matched events to make deliverability decisions about.
    /// `filter` is NOT resent here — use the one cached from `reqOpen`.
    Req {
        req_id: u64,
        conn_id: u64,
        sub_id: String,
        authed: Option<String>,
        events: Vec<UnparsedNote>,
    },

    /// A subscription went away. Free per-subscription state. No response.
    ReqClose { conn_id: u64, sub_id: String },

    /// A connection went away. Free all per-connection state. No response.
    ConnClose { conn_id: u64 },
}

/// Flat wire shape of every read-plugin message. Deserialized straight from the
/// top-level `serde_json` deserializer (no tag/flatten/untagged buffering) so
/// the nested `Vec<UnparsedNote>` keeps its raw bytes; [`ReadInput`]'s manual
/// `Deserialize` dispatches on `msg_type` to build the typed enum.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawInput {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    req_id: Option<u64>,
    #[serde(default)]
    conn_id: Option<u64>,
    #[serde(default)]
    sub_id: Option<String>,
    #[serde(default)]
    authed: Option<String>,
    #[serde(default)]
    filter: Option<Value>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    events: Vec<UnparsedNote>,
}

impl<'de> Deserialize<'de> for ReadInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let RawInput {
            msg_type,
            req_id,
            conn_id,
            sub_id,
            authed,
            filter,
            ip,
            events,
        } = RawInput::deserialize(deserializer)?;

        match msg_type.as_str() {
            "reqOpen" => Ok(ReadInput::ReqOpen {
                req_id: req_id.ok_or_else(|| D::Error::missing_field("reqId"))?,
                conn_id: conn_id.ok_or_else(|| D::Error::missing_field("connId"))?,
                sub_id: sub_id.ok_or_else(|| D::Error::missing_field("subId"))?,
                authed,
                filter,
                ip,
            }),
            "req" => Ok(ReadInput::Req {
                req_id: req_id.ok_or_else(|| D::Error::missing_field("reqId"))?,
                conn_id: conn_id.ok_or_else(|| D::Error::missing_field("connId"))?,
                sub_id: sub_id.ok_or_else(|| D::Error::missing_field("subId"))?,
                authed,
                events,
            }),
            "reqClose" => Ok(ReadInput::ReqClose {
                conn_id: conn_id.ok_or_else(|| D::Error::missing_field("connId"))?,
                sub_id: sub_id.ok_or_else(|| D::Error::missing_field("subId"))?,
            }),
            "connClose" => Ok(ReadInput::ConnClose {
                conn_id: conn_id.ok_or_else(|| D::Error::missing_field("connId"))?,
            }),
            other => Err(D::Error::unknown_variant(
                other,
                &["reqOpen", "req", "reqClose", "connClose"],
            )),
        }
    }
}

/// Admission action returned to a `reqOpen`.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReadAction {
    /// Admit the subscription.
    Accept,
    /// Refuse / throttle the whole subscription.
    Reject,
}

/// Response to a `reqOpen`: admit or refuse the subscription.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReqOpenResponse {
    pub req_id: u64,
    pub action: ReadAction,
    /// Reason surfaced to the client on reject (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    /// Retry hint in milliseconds, appended to the reject message (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_ms: Option<u64>,
    /// Opt out of per-event filtering for this subscription. When `true` (only
    /// meaningful on an `accept`), the plugin declares it needs no `req`
    /// batches: strfry skips all per-event marshaling and delivers this
    /// subscription via its zero-copy fast path, while still sending
    /// `reqClose`/`connClose` so the plugin can free state. Omitted from the
    /// wire when `false`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub passthrough: bool,
}

impl ReqOpenResponse {
    /// Admit the subscription. With `passthrough`, opt out of per-event
    /// filtering: strfry never sends `req` for it and delivers via the
    /// zero-copy fast path.
    pub fn accept(req_id: u64, passthrough: bool) -> Self {
        ReqOpenResponse {
            req_id,
            action: ReadAction::Accept,
            msg: None,
            retry_ms: None,
            passthrough,
        }
    }

    /// Refuse the subscription with an optional message and retry hint.
    pub fn reject(req_id: u64, msg: Option<String>, retry_ms: Option<u64>) -> Self {
        ReqOpenResponse {
            req_id,
            action: ReadAction::Reject,
            msg,
            retry_ms,
            passthrough: false,
        }
    }
}

/// Response to a `req`: the accept-list is authoritative. Every event in the
/// batch whose id is NOT listed is withheld from this subscriber. (Delivering
/// all = echo every id; withholding all = empty array.)
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReqResponse {
    pub req_id: u64,
    pub accept: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_req_open_with_filter_and_auth() {
        let line = r#"{"type":"reqOpen","reqId":7,"connId":3,"subId":"sub0","authed":"aa","filter":[{"kinds":[1]}]}"#;
        match serde_json::from_str::<ReadInput>(line).unwrap() {
            ReadInput::ReqOpen {
                req_id,
                conn_id,
                sub_id,
                authed,
                filter,
                ..
            } => {
                assert_eq!(req_id, 7);
                assert_eq!(conn_id, 3);
                assert_eq!(sub_id, "sub0");
                assert_eq!(authed.as_deref(), Some("aa"));
                assert!(filter.is_some());
            }
            other => panic!("expected reqOpen, got {:?}", other),
        }
    }

    #[test]
    fn parses_req_open_unauthed_no_filter() {
        let line = r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s"}"#;
        match serde_json::from_str::<ReadInput>(line).unwrap() {
            ReadInput::ReqOpen {
                authed, filter, ip, ..
            } => {
                assert!(authed.is_none());
                assert!(filter.is_none());
                // Absent `ip` field (older strfry) => None, still parses.
                assert!(ip.is_none());
            }
            other => panic!("expected reqOpen, got {:?}", other),
        }
    }

    #[test]
    fn parses_req_open_with_ip() {
        let line = r#"{"type":"reqOpen","reqId":0,"connId":1,"subId":"s","ip":"127.0.0.1"}"#;
        match serde_json::from_str::<ReadInput>(line).unwrap() {
            ReadInput::ReqOpen { ip, .. } => assert_eq!(ip.as_deref(), Some("127.0.0.1")),
            other => panic!("expected reqOpen, got {:?}", other),
        }
    }

    #[test]
    fn parses_req_with_events() {
        let event = r#"{"id":"ab","pubkey":"cd","content":"hi","created_at":1,"kind":1,"tags":[],"sig":"ef"}"#;
        let line =
            format!(r#"{{"type":"req","reqId":9,"connId":3,"subId":"sub0","events":[{event}]}}"#);
        match serde_json::from_str::<ReadInput>(&line).unwrap() {
            ReadInput::Req {
                req_id,
                conn_id,
                events,
                ..
            } => {
                assert_eq!(req_id, 9);
                assert_eq!(conn_id, 3);
                assert_eq!(events.len(), 1);
                // The raw wire bytes are captured verbatim...
                assert_eq!(events[0].size(), event.len());
                // ...and both the cheap id-only and full parse agree.
                assert_eq!(events[0].id().unwrap(), "ab");
                assert_eq!(events[0].parse().unwrap().id, "ab");
            }
            other => panic!("expected req, got {:?}", other),
        }
    }

    #[test]
    fn unparsed_note_size_is_raw_wire_length() {
        // Deliberately include whitespace: size() must reflect the exact bytes
        // as delivered, not a re-minified form.
        let raw = r#"{"id": "ab", "kind": 1}"#;
        let note = UnparsedNote::from_json(raw).unwrap();
        assert_eq!(note.size(), raw.len());
    }

    #[test]
    fn unparsed_note_parse_round_trips() {
        let raw = r#"{"id":"ab","pubkey":"cd","content":"hi","created_at":1,"kind":1,"tags":[],"sig":"ef"}"#;
        let note = UnparsedNote::from_json(raw).unwrap();
        let parsed = note.parse().unwrap();
        assert_eq!(parsed.id, "ab");
        assert_eq!(parsed.pubkey, "cd");
        assert_eq!(parsed.kind, 1);
    }

    #[test]
    fn parses_lifecycle_messages() {
        match serde_json::from_str::<ReadInput>(r#"{"type":"reqClose","connId":3,"subId":"sub0"}"#)
            .unwrap()
        {
            ReadInput::ReqClose { conn_id, sub_id } => {
                assert_eq!(conn_id, 3);
                assert_eq!(sub_id, "sub0");
            }
            other => panic!("expected reqClose, got {:?}", other),
        }

        match serde_json::from_str::<ReadInput>(r#"{"type":"connClose","connId":3}"#).unwrap() {
            ReadInput::ConnClose { conn_id } => assert_eq!(conn_id, 3),
            other => panic!("expected connClose, got {:?}", other),
        }
    }

    #[test]
    fn serializes_responses_minified() {
        let accept = ReqOpenResponse::accept(2, false);
        assert_eq!(
            serde_json::to_string(&accept).unwrap(),
            r#"{"reqId":2,"action":"accept"}"#
        );

        let passthrough = ReqOpenResponse::accept(2, true);
        assert_eq!(
            serde_json::to_string(&passthrough).unwrap(),
            r#"{"reqId":2,"action":"accept","passthrough":true}"#
        );

        let reject = ReqOpenResponse::reject(2, Some("slow down".into()), Some(1000));
        assert_eq!(
            serde_json::to_string(&reject).unwrap(),
            r#"{"reqId":2,"action":"reject","msg":"slow down","retryMs":1000}"#
        );

        let batch = ReqResponse {
            req_id: 5,
            accept: vec!["deadbeef".into()],
        };
        assert_eq!(
            serde_json::to_string(&batch).unwrap(),
            r#"{"reqId":5,"accept":["deadbeef"]}"#
        );
    }
}
