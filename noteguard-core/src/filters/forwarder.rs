//! Forwarder filter - forwards events to another relay.
//!
//! This is a pass-through filter that forwards all events to a configured
//! relay while still accepting them locally. Useful for relay federation.
//!
//! Requires the `forwarder` feature flag.

use crate::{Action, InputMessage, Note, NoteFilter, OutputMessage};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{sleep, timeout, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream};

/// Forwarder filter - forwards events to another relay.
///
/// This filter always accepts events locally, but also forwards them
/// to a configured upstream relay. The forwarding happens asynchronously
/// in a background task.
///
/// ## Configuration
///
/// ```toml
/// [filters.forwarder]
/// relay = "wss://relay.example.com"
/// queue_size = 1000  # Optional: bounded queue size (default: 1000)
/// ```
#[derive(Default, Deserialize)]
pub struct Forwarder {
    /// WebSocket URL of the relay to forward to
    relay: String,

    /// Size of the bounded queue for pending forwards
    queue_size: Option<u32>,

    /// Channel for communicating with the forwarder task
    #[serde(skip)]
    channel: Option<Sender<Note>>,
}

/// Establishes a WebSocket connection to the relay, retrying on failure.
async fn client_reconnect(
    relay: &str,
) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
    loop {
        match connect_async(relay).await {
            Err(e) => {
                error!("failed to connect to relay {}: {}", relay, e);
                sleep(Duration::from_secs(5)).await;
            }
            Ok((ws, _)) => {
                info!("connected to relay: {}", relay);
                return ws;
            }
        }
    }
}

/// Background task that forwards events to the upstream relay.
async fn forwarder_task(relay: String, mut rx: Receiver<Note>) {
    let stream = client_reconnect(&relay).await;
    let (mut writer, mut reader) = stream.split();

    loop {
        tokio::select! {
            result = timeout(Duration::from_secs(10), rx.recv()) => {
                match result {
                    Ok(Some(note)) => {
                        let payload = serde_json::to_string(&json!(["EVENT", note]))
                            .expect("note serialization should not fail");

                        if let Err(e) = writer.send(Message::Text(payload)).await {
                            error!("forward error: '{}', reconnecting...", e);
                            let (w, r) = client_reconnect(&relay).await.split();
                            writer = w;
                            reader = r;
                        }
                    }
                    Ok(None) => {
                        // Channel closed - task should exit
                        error!("channel closed, stopping forwarder_task");
                        break;
                    }
                    Err(_) => {
                        // Timeout - send ping to keep connection alive
                        let _r = reader.next();
                        debug!("timeout reading note queue, sending ping");

                        if let Err(e) = writer.send(Message::Ping(vec![])).await {
                            error!("ping error ({}), reconnecting...", e);
                            let (w, r) = client_reconnect(&relay).await.split();
                            writer = w;
                            reader = r;
                        }
                    }
                }
            }
        }
    }
}

impl NoteFilter for Forwarder {
    fn name(&self) -> &'static str {
        "forwarder"
    }

    fn filter_note(&mut self, input: &InputMessage) -> OutputMessage {
        // Lazily initialize the forwarder task on first event
        if self.channel.is_none() {
            let (tx, rx) = mpsc::channel(self.queue_size.unwrap_or(1000) as usize);
            let relay = self.relay.clone();

            tokio::task::spawn(async move {
                forwarder_task(relay, rx).await;
            });

            self.channel = Some(tx);
        }

        // Forward the event (non-blocking)
        if let Some(ref channel) = self.channel {
            if let Err(e) = channel.try_send(input.event.clone()) {
                // Queue full or closed - log but don't fail the filter
                eprintln!("could not forward note: {}", e);
            }
        }

        // Always accept locally
        OutputMessage::accept(input.event.id.clone())
    }
}
