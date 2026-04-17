use axum::{ http::{header, HeaderValue, StatusCode}, response::{Html, IntoResponse, Response}, routing::get, Router, };
use axum::extract::ws::{WebSocketUpgrade, WebSocket, Message};
use std::{ net::{Ipv4Addr, SocketAddr, UdpSocket}, sync::{ atomic::{AtomicBool, Ordering}, Mutex, OnceLock, }, thread, };
use tokio::{net::TcpListener, sync::{mpsc, oneshot}};
use futures_util::{StreamExt, SinkExt};
use crate::{main_helpers, secure_channel_code};

static WEB_SERVER_STARTED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_TX: OnceLock<Mutex<Option<oneshot::Sender<()>>>> = OnceLock::new();
static WEB_CLIENTS: OnceLock<Mutex<Vec<mpsc::UnboundedSender<String>>>> = OnceLock::new();

// Embed files into the exe
const WEB_PORT: u16 = 38421;
const INDEX_HTML: &str = include_str!("../web_app/index.html");
const STYLES_CSS: &str = include_str!("../web_app/styles.css");
const APP_JS: &str = include_str!("../web_app/app.js");
const FAVICON_PNG: &[u8] = include_bytes!("../web_app/favicon.png");

#[derive(serde::Deserialize)]
struct WebChatMessage {
    #[serde(rename = "type")]
    msg_type: String,
    text: String,
}

pub fn start_web_server() -> Result<(), String> {
    if WEB_SERVER_STARTED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let (tx, rx) = oneshot::channel::<()>();

    let shutdown_slot = SHUTDOWN_TX.get_or_init(|| Mutex::new(None));
    {
        let mut guard = shutdown_slot
            .lock()
            .map_err(|_| "shutdown lock poisoned".to_string())?;
        *guard = Some(tx);
    }

    thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_e) => {
                //eprintln!("Failed to create Tokio runtime: {e}");
                WEB_SERVER_STARTED.store(false, Ordering::SeqCst);
                if let Some(lock) = SHUTDOWN_TX.get() {
                    if let Ok(mut guard) = lock.lock() {
                        *guard = None;
                    }
                }
                return;
            }
        };

        let result = rt.block_on(async { run_server(rx).await });

        if let Err(_e) = result {
            //eprintln!("Web server failed: {e}");
        }

        WEB_SERVER_STARTED.store(false, Ordering::SeqCst);

        if let Some(lock) = SHUTDOWN_TX.get() {
            if let Ok(mut guard) = lock.lock() {
                *guard = None;
            }
        }

        //println!("🛑 Web session ended");
    });

    create_qr_code();
    Ok(())
}

pub fn stop_web_server() -> Result<(), String> {
    if !WEB_SERVER_STARTED.load(Ordering::SeqCst) {
        return Ok(());
    }
    let payload_ending_session = serde_json::json!({
        "type": "system",
        "action": "session_end",
        "text": "Session has ended. Refreshing the webpage will not reconnect."
    });
    // send final message first
    broadcast_to_web_clients(payload_ending_session.to_string());
    // give it a tiny moment to go out
    std::thread::sleep(std::time::Duration::from_millis(200));
    let Some(lock) = SHUTDOWN_TX.get() else {
        return Err("shutdown handle not initialized".to_string());
    };
    let mut guard = lock
        .lock()
        .map_err(|_| "shutdown lock poisoned".to_string())?;
    if let Some(tx) = guard.take() {
        tx.send(())
            .map_err(|_| "failed to send shutdown signal".to_string())?;
    }
    Ok(())
}

pub fn is_web_server_running() -> bool { WEB_SERVER_STARTED.load(Ordering::SeqCst) }

pub fn create_qr_code() {
    if let Some(url) = get_url_to_main() {
        secure_channel_code::generate_QR_code(Some(&url));
        //println!("QR URL: {}", url);
    } else {
        //eprintln!("Could not determine QR IPv4");
    }
}

pub fn get_url_to_main() -> Option<String> { get_primary_ipv4_for_qr().map(|ip| format!("http://{}:{}", ip, WEB_PORT)) }

async fn run_server(shutdown_rx: oneshot::Receiver<()>) -> Result<(), String> {
    let app = Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(app_js))
        .route("/favicon.png", get(favicon))
        .route("/ws", get(ws_handler))
        .merge(crate::web_app_file_transfer::file_transfer_router());
    let addr = SocketAddr::from(([0, 0, 0, 0], WEB_PORT));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind failed: {e}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .map_err(|e| format!("server error: {e}"))?;
    Ok(())
}

async fn index() -> Html<&'static str> { Html(INDEX_HTML) }

async fn styles() -> impl IntoResponse { ( StatusCode::OK, [( header::CONTENT_TYPE, HeaderValue::from_static("text/css; charset=utf-8"), )], STYLES_CSS, ) }

async fn app_js() -> impl IntoResponse {
    ( StatusCode::OK, [( header::CONTENT_TYPE, HeaderValue::from_static("application/javascript; charset=utf-8"), )], APP_JS, ) 
}

async fn favicon() -> impl IntoResponse { ( StatusCode::OK, [(header::CONTENT_TYPE, HeaderValue::from_static("image/png"))], FAVICON_PNG, ) }

pub fn get_primary_ipv4_for_qr() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()? { SocketAddr::V4(addr) => Some(*addr.ip()), SocketAddr::V6(_) => None, }
}

async fn ws_handler(ws: WebSocketUpgrade) -> Response { ws.on_upgrade(handle_socket)}

async fn handle_socket(socket: WebSocket) {
    //println!("✅ Web client connected");
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        let clients = WEB_CLIENTS.get_or_init(|| Mutex::new(Vec::new()));
        if let Ok(mut guard) = clients.lock() {
            guard.push(tx);
        }
    }
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg.into())).await.is_err() { break; }}});
        let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_receiver.next().await {
            match msg {
                Message::Text(text) => {
                    //println!("📩 Received: {}", text);

                    match serde_json::from_str::<WebChatMessage>(&text) {
                        Ok(parsed) => {
                            if parsed.msg_type == "chat" {
                                let text = parsed.text.trim().to_string();
                                if text.is_empty() || text.starts_with("/") {
                                    continue;
                                }
                                main_helpers::append_message_from_web(parsed.text);
                            }
                        }
                        Err(_e) => {
                            //eprintln!("Failed to parse: {e}");
                        }
                    }
                }

                Message::Close(_) => {
                    //println!("❌ Client disconnected");
                    break;
                }
                _ => {}
            }
        }
    });

    let _ = tokio::join!(send_task, recv_task);
}

pub fn broadcast_to_web_clients(msg: String) {
    let clients = WEB_CLIENTS.get_or_init(|| Mutex::new(Vec::new()));
    if ignore_certain_messages(&msg) {
        return
    }
    if let Ok(mut guard) = clients.lock() {
        guard.retain(|tx| tx.send(msg.clone()).is_ok());
    }
}

fn ignore_certain_messages(text: &str) -> bool {
    let text = text.trim();
    (text.contains("LanChGo App") && text.contains("Talk freely, fast, and local.") && text.contains("Features:") && text.contains("Links:") && text.contains("© 2025"))
        || text.contains("Exiting in 1 seconds") ||
    (text.contains("/info") && text.contains("/help") && text.contains("/clear") && text.contains("/clearall"))
}

// Note for who ever inspects the code
// The app's web page scanner is to get revenue from ads, if you read this I think you know what you are doing and you can access the web companion by entering the URL only
// Thank you for using LanChGo and I hope it helps you
