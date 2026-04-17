use axum::{
    extract::Path,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::{Arc, Mutex, OnceLock};
use tokio_util::io::ReaderStream;
use tokio::fs::File;
use crate::file_transfer_protocol::{
    OfferRegistry, hex_to_offer_id, offer_id_to_hex, human_size,
};
use crate::web_app::{broadcast_to_web_clients, is_web_server_running};

static FILE_REGISTRY: OnceLock<Arc<Mutex<OfferRegistry>>> = OnceLock::new();

pub fn register_offer_registry(registry: Arc<Mutex<OfferRegistry>>) {
    FILE_REGISTRY.get_or_init(|| registry);
}

pub fn file_transfer_router() -> Router {
    Router::new().route("/download/{offer_id_hex}", get(download_handler))
}

pub fn notify_web_file_offer(offer_id: &[u8; 16], name: &str, size: u64) {
    if !is_web_server_running() {
        return;
    }
    let offer_id_hex = offer_id_to_hex(offer_id);
    let payload = serde_json::json!({
        "type": "file_offer",
        "offer_id": offer_id_hex,
        "name": name,
        "size": size,
        "size_human": human_size(size),
    });
    broadcast_to_web_clients(payload.to_string());
}

async fn download_handler(Path(offer_id_hex): Path<String>) -> Response {
    let registry = match FILE_REGISTRY.get() {
        Some(r) => r,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Registry not ready").into_response(),
    };

    let (path, name) = {
        let reg = registry.lock().unwrap();
        let id = match hex_to_offer_id(&offer_id_hex) {
            Some(id) => id,
            None => return (StatusCode::BAD_REQUEST, "Invalid offer id").into_response(),
        };
        match reg.get(&id) {
            Some(local) => (local.path.clone(), local.name.clone()),
            None => return (StatusCode::NOT_FOUND, "Offer not found").into_response(),
        }
    };

    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to open file").into_response(),
    };

    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    let content_disposition = format!("attachment; filename=\"{}\"", name);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")),
            (header::CONTENT_DISPOSITION, HeaderValue::from_str(&content_disposition).unwrap_or(HeaderValue::from_static("attachment"))),
        ],
        body,
    ).into_response()
}
