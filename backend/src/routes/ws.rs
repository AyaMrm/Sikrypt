use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Query;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::broadcast;

const DEFAULT_ROOM: &str = "lobby";
const MAX_MESSAGE_LEN: usize = 8192;

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);
static ROOMS: Lazy<Mutex<HashMap<String, broadcast::Sender<ServerMessage>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Deserialize)]
struct WsQuery {
    room: Option<String>,
    name: Option<String>,
    api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientMessage {
    #[serde(rename = "type")]
    kind: String,
    payload: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ServerMessage {
    #[serde(rename = "type")]
    kind: String,
    sender: String,
    payload: Option<String>,
}

fn normalize_label(value: Option<String>, fallback: &str) -> String {
    value
        .unwrap_or_else(|| fallback.to_string())
        .trim()
        .chars()
        .take(48)
        .collect::<String>()
}

fn room_sender(room: &str) -> broadcast::Sender<ServerMessage> {
    let mut rooms = ROOMS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    rooms
        .entry(room.to_string())
        .or_insert_with(|| {
            let (tx, _) = broadcast::channel(128);
            tx
        })
        .clone()
}

async fn secure_ws_handler(
    Query(params): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let expected = std::env::var("SIKRYPT_WS_API_KEY").ok();
    if let Some(expected_key) = expected {
        if !expected_key.trim().is_empty() {
            let provided = params.api_key.as_deref();
            if provided != Some(expected_key.as_str()) {
                return (axum::http::StatusCode::UNAUTHORIZED, "invalid_api_key").into_response();
            }
        }
    }

    ws.on_upgrade(move |socket| handle_socket(socket, params))
}

async fn handle_socket(socket: WebSocket, params: WsQuery) {
    let room = normalize_label(params.room, DEFAULT_ROOM);
    let mut name = normalize_label(params.name, "client");
    let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
    if name.is_empty() {
        name = format!("client-{client_id}");
    }

    let sender = room_sender(&room);
    let mut receiver = sender.subscribe();
    let join = ServerMessage {
        kind: "join".to_string(),
        sender: name.clone(),
        payload: Some(format!("{name} joined {room}")),
    };
    let _ = sender.send(join);

    let (mut ws_sender, mut ws_receiver) = socket.split();

    loop {
        tokio::select! {
            msg = receiver.recv() => {
                let Ok(server_msg) = msg else {
                    break;
                };
                let Ok(text) = serde_json::to_string(&server_msg) else {
                    continue;
                };
                if ws_sender.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_MESSAGE_LEN {
                            let _ = ws_sender.send(Message::Close(None)).await;
                            break;
                        }
                        let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) else {
                            continue;
                        };
                        if client_msg.kind == "message" {
                            let payload = client_msg.payload.unwrap_or_default();
                            let server_msg = ServerMessage {
                                kind: "message".to_string(),
                                sender: name.clone(),
                                payload: Some(payload),
                            };
                            let _ = sender.send(server_msg);
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    let leave = ServerMessage {
        kind: "leave".to_string(),
        sender: name.clone(),
        payload: Some(format!("{name} left {room}")),
    };
    let _ = sender.send(leave);
}

pub fn router() -> Router {
    Router::new().route("/ws/secure", get(secure_ws_handler))
}
