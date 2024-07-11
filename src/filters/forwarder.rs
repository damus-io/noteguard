use serde::Deserialize;
use crate::{Note, Action, NoteFilter, InputMessage, OutputMessage};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{self, Sender, Receiver};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio::time::{sleep, timeout, Duration};
use serde_json::json;
use log::{error, info, debug};

#[derive(Default, Deserialize)]
pub struct Forwarder {
    relay: String,

    /// the size of our bounded queue
    queue_size: Option<u32>,

    /// The channel used for communicating with the forwarder thread
    #[serde(skip)]
    channel: Option<Sender<Note>>,
}

async fn client_reconnect(relay: &str) -> WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    loop {
        match connect_async(relay).await {
            Err(e) => {
                error!("failed to connect to relay {}: {}", relay, e);
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            Ok((ws, _)) => {
                info!("connected to relay: {}", relay);
                return ws;
            }
        }
    }
}

async fn forwarder_task(relay: String, mut rx: Receiver<Note>) {
    let stream = client_reconnect(&relay).await;
    let (mut writer, mut reader) = stream.split();

    loop {
        tokio::select! {
            result = timeout(Duration::from_secs(10), rx.recv()) => {
                match result {
                    Ok(Some(note)) => {
                        if let Err(e) = writer.send(Message::Text(serde_json::to_string(&json!(["EVENT", note])).unwrap())).await {
                            error!("got error: '{}', reconnecting...", e);
                            let (w, r) = client_reconnect(&relay).await.split();
                            writer = w;
                            reader = r;
                        }
                    },
                    Ok(None) => {
                        // Channel has been closed, exit the loop
                        error!("channel closed, stopping forwarder_task");
                        break;
                    }
                    Err(_) => {
                        // Timeout occurred, send a ping
                        // try reading for pongs, etc
                        let _r = reader.next();
                        debug!("timeout reading note queue, sending ping");

                        if let Err(e) = writer.send(Message::Ping(vec![])).await {
                            error!("error during ping ({}), reconnecting...", e);
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
        if self.channel.is_none() {
            let (tx, rx) = mpsc::channel(self.queue_size.unwrap_or(1000) as usize);
            let relay = self.relay.clone();

            tokio::task::spawn(async move {
                forwarder_task(relay, rx).await;
            });

            self.channel = Some(tx);
        }

        // Add code to process input and send through channel
        if let Some(ref channel) = self.channel {
            if let Err(e) = channel.try_send(input.event.clone()) {
                eprintln!("could not forward note: {}", e);
            }
        }

        // Create and return an appropriate OutputMessage
        OutputMessage::new(input.event.id.clone(), Action::Accept, None)
    }
}
