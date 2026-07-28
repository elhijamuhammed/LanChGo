use axum::{ extract::{Path, Multipart}, http::{header, HeaderValue, StatusCode}, response::{IntoResponse, Response}, routing::{get, post}, Router, };
use std::sync::{Arc, Mutex, OnceLock};
use tokio_util::io::ReaderStream;
use tokio::fs::File;
use fs2::available_space;
use crate::file_transfer_protocol::{ OfferRegistry, hex_to_offer_id, offer_id_to_hex, human_size, };
use crate::web_app::{broadcast_to_web_clients, is_web_server_running};

static FILE_REGISTRY: OnceLock<Arc<Mutex<OfferRegistry>>> = OnceLock::new();

#[derive(serde::Deserialize)]
struct PreflightRequest {
    size: u64,
}

pub fn register_offer_registry(registry: Arc<Mutex<OfferRegistry>>) {
    FILE_REGISTRY.get_or_init(|| registry);
}

pub fn notify_web_file_offer(offer_id: &[u8; 16], name: &str, size: u64) {
    if !is_web_server_running() {
        return;
    }
    let offer_id_hex = offer_id_to_hex(offer_id);
    let payload = serde_json::json!({ "type": "file_offer", "offer_id": offer_id_hex, "name": name, "size": size, "size_human": human_size(size), });
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

async fn upload_handler(mut multipart: Multipart) -> Response {
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.file_name().unwrap_or("unknown").to_string();
        let data = match field.bytes().await {
            Ok(b) => b,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file").into_response(),
        };

        let offer_id: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
        let dest_path = crate::file_transfer_protocol::make_temp_upload_path(&offer_id, &name);

        if let Err(_) = tokio::fs::write(&dest_path, &data).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file").into_response();
        }

        {
            let mut reg = FILE_REGISTRY.get().unwrap().lock().unwrap();
            reg.insert(offer_id, crate::file_transfer_protocol::LocalFileOffer {
                path: dest_path.clone(),
                kind: crate::file_transfer_protocol::OfferKind::SingleFile,
                size: data.len() as u64,
                name: name.clone(),
            });
        }

        let offer_id_hex = crate::file_transfer_protocol::offer_id_to_hex(&offer_id);
        
        // notify web clients with offer_id so they can download it
        let payload = serde_json::json!({
            "type": "file_received",
            "name": name,
            "size": data.len() as u64,
            "offer_id": offer_id_hex,
        });
        broadcast_to_web_clients(payload.to_string());
        crate::main_helpers::notify_web_upload_received(name.clone(), offer_id_hex.clone(), data.len() as u64);
    }
    (StatusCode::OK, "File received").into_response()
}

pub fn save_web_upload_to_folder(offer_id_hex: &str, dest_folder: &str) -> bool {
    let registry = match FILE_REGISTRY.get() {
        Some(r) => r,
        None => return false,
    };

    let mut reg = registry.lock().unwrap();
    let id = match crate::file_transfer_protocol::hex_to_offer_id(offer_id_hex) {
        Some(id) => id,
        None => return false,
    };

    let local = match reg.get(&id) {
        Some(l) => l.clone(),
        None => return false,
    };

    let dest = std::path::Path::new(dest_folder).join(&local.name);
    if std::fs::copy(&local.path, &dest).is_err() {
        return false;
    }

    // delete temp and update registry path
    let _ = std::fs::remove_file(&local.path);
    reg.get_mut(&id).unwrap().path = dest;
    true
}

async fn preflight_handler( axum::Json(body): axum::Json<PreflightRequest> ) -> Response {
    let temp_dir = std::env::temp_dir();

    let available = match available_space(&temp_dir) {
        Ok(space) => space,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Could not check disk space").into_response(),
    };

    if available < body.size {
        let msg = format!("Not enough storage. Available: {}, Required: {}",
            crate::file_transfer_protocol::human_size(available),
            crate::file_transfer_protocol::human_size(body.size)
        );
        let payload = serde_json::json!({ "type": "system", "text": format!("⚠️ {}", msg) });
        broadcast_to_web_clients(payload.to_string());
        return (StatusCode::INSUFFICIENT_STORAGE, msg).into_response();
    }

    // ✅ enough space
    let payload = serde_json::json!({
        "type": "system",
        "text": format!("✅ Storage check passed. Available: {}", 
            crate::file_transfer_protocol::human_size(available))
    });
    broadcast_to_web_clients(payload.to_string());

    (StatusCode::OK, "OK").into_response()
}

pub fn file_transfer_router() -> Router {
    Router::new()
        .route("/download/{offer_id_hex}", get(download_handler))
        .route("/upload", post(upload_handler))
        .route("/upload/preflight", post(preflight_handler))
}
