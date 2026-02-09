use serde::{Deserialize, Serialize};
use std::{ collections::HashMap, fs::File, io::{self, BufReader, Read, Write}, net::IpAddr, path::{Path, PathBuf}, sync::{atomic::{AtomicUsize, Ordering}, mpsc}, thread, time::{SystemTime, UNIX_EPOCH}, };
use uuid::Uuid;
use zip::{write::FileOptions, ZipWriter};

pub const FOFT_MAGIC: &[u8; 4] = b"FOFT";
pub const FILE_PROTOCOL_VERSION: u8 = 1;
pub const DEFAULT_TCP_PORT: u16 = 3001;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OfferKind {
    SingleFile,
    //Folder, removed feature
    ZipBundle,
}

/// ✅ This goes over the network (safe, portable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    pub offer_id: [u8; 16],
    pub name: String,
    pub size: u64,
    pub kind: OfferKind,
    pub protocol_version: u8,
    pub tcp_port: u16,
}

/// ✅ Local-only (DO NOT serialize). This is what the sender will actually stream later over TCP.
#[derive(Debug, Clone)]
pub struct LocalFileOffer {
    pub path: PathBuf, // real file path (single) OR temp zip path (bundle)
    pub kind: OfferKind,
    pub size: u64,
    pub name: String, // handy for logs/debug
}

#[derive(Debug)]
pub enum BundleEvent {
    Progress {
        offer_id: [u8; 16],
        done: u64,
        total: u64,
        current: PathBuf,
    },
    Finished {
        offer_id: [u8; 16],
        packet: Vec<u8>,
        local: LocalFileOffer,
    },
    Error {
        offer_id: [u8; 16],
        message: String,
    },
}

pub enum BuildResult {
    Ready(Vec<u8>), // single file -> packet now
    Bundling {
        offer_id: [u8; 16],
        rx: mpsc::Receiver<BundleEvent>,
        handle: thread::JoinHandle<()>,
    },
}

pub type OfferRegistry = HashMap<[u8; 16], LocalFileOffer>;
pub type RemoteWindowsOfferRegistry = HashMap<String, (IpAddr, crate::file_transfer_protocol::FileOffer)>; // for the FOFT
pub type RemoteMobileOfferRegistry = HashMap<String, (IpAddr, FileOffer)>; // for MFOFT
static ACTIVE_BUNDLES: AtomicUsize = AtomicUsize::new(0);
const MAX_BUNDLES: usize = 2;

pub fn pick_files() -> Option<Vec<PathBuf>> {
    rfd::FileDialog::new()
        .set_title("Select files to send")
        .pick_files()
}

/// Build bytes ready to broadcast: "FOFT" + bincode(FileOffer)
/// - 1 file  -> returns Ready(packet) immediately
/// - >1 file -> returns Bundling{rx,...} and the zip happens in a background thread
pub fn pick_and_build_foft_packet_async(registry: &mut OfferRegistry) -> io::Result<BuildResult> {
    let paths = pick_files()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "File selection cancelled"))?;

    if paths.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "No file selected"));
    }

    let offer_id: [u8; 16] = *Uuid::new_v4().as_bytes();

    if paths.len() == 1 {
        let packet = build_foft_packet_single(&paths[0], offer_id, registry)?;
        Ok(BuildResult::Ready(packet))
    } else {
        // Try to reserve a bundling slot
        let prev = ACTIVE_BUNDLES.fetch_add(1, Ordering::SeqCst);

        if prev >= MAX_BUNDLES {
            // undo reservation
            ACTIVE_BUNDLES.fetch_sub(1, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Too many bundles running (max {})", MAX_BUNDLES),
            ));
        }

        let (rx, handle) = spawn_zip_bundle_thread(paths, offer_id);
        Ok(BuildResult::Bundling { offer_id, rx, handle })
    }
}

// -------------------- Builders --------------------

fn build_foft_packet_single( path: &Path, offer_id: [u8; 16], registry: &mut OfferRegistry, ) -> io::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;

    if meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Folder sending not supported yet",
        ));
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let size = meta.len();

    // store locally for later TCP transfer
    registry.insert(
        offer_id,
        LocalFileOffer {
            path: path.to_path_buf(),
            kind: OfferKind::SingleFile,
            size,
            name: name.clone(),
        },
    );

    let offer = FileOffer {
        offer_id,
        name,
        size,
        kind: OfferKind::SingleFile,
        protocol_version: FILE_PROTOCOL_VERSION,
        tcp_port: DEFAULT_TCP_PORT,
    };

    encode_offer_packet(&offer)
}

// NOTE: You can keep this blocking builder if you want,
// but the async flow does NOT call it.
#[allow(dead_code)]
fn build_foft_packet_zip_bundle_with_progress<F: FnMut(u64, u64, &Path)>( paths: &[PathBuf], offer_id: [u8; 16], registry: &mut OfferRegistry, mut on_progress: F, ) -> io::Result<Vec<u8>> {
    let (packet, local) = build_zip_bundle_packet_no_registry(paths, offer_id, &mut on_progress)?;
    registry.insert(offer_id, local);
    Ok(packet)
}

fn encode_offer_packet(offer: &FileOffer) -> io::Result<Vec<u8>> {
    let payload = bincode::serde::encode_to_vec(offer, bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(FOFT_MAGIC);
    packet.extend_from_slice(&payload);
    Ok(packet)
}

// -------------------- Decode + helpers --------------------

pub fn decode_foft(bytes: &[u8]) -> Option<FileOffer> {
    if bytes.len() < 4 || &bytes[..4] != FOFT_MAGIC {
        return None;
    }

    let payload = &bytes[4..];
    let (offer, _) =
        bincode::serde::decode_from_slice::<FileOffer, _>(payload, bincode::config::standard())
            .ok()?;

    // reject conflicting protocol versions
    if offer.protocol_version != FILE_PROTOCOL_VERSION {
        return None;
    }
    Some(offer)
}

pub fn offer_id_to_hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let b = bytes as f64;

    if b < KB {
        format!("{} B", bytes)
    } else if b < 10.0 * KB {
        format!("{} KB", (b / KB).round() as u64)
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else if b < TB {
        format!("{:.1} GB", b / GB)
    } else {
        format!("{:.1} TB", b / TB)
    }
}

fn make_temp_zip_path(offer_id: &[u8; 16]) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push("LanChGo");
    dir.push("offers");

    // ensure folder exists
    std::fs::create_dir_all(&dir).ok();

    let hex: String = offer_id.iter().map(|b| format!("{:02x}", b)).collect();
    dir.push(format!("offer_{hex}.zip"));
    dir
}

pub fn cleanup_temp_offers(registry: &mut OfferRegistry) {
    let mut to_remove: Vec<[u8; 16]> = Vec::new();

    for (id, local) in registry.iter() {
        if matches!(local.kind, OfferKind::ZipBundle) {
            if let Err(e) = std::fs::remove_file(&local.path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    println!(
                        "[FOFT][CLEANUP] failed to delete {}: {}",
                        local.path.display(),
                        e
                    );
                }
            } else {
                println!("[FOFT][CLEANUP] deleted {}", local.path.display());
            }
            to_remove.push(*id);
        }
    }

    for id in to_remove {
        registry.remove(&id);
    }
}

pub fn build_unique_download_path(dir: &Path, filename: &str, offer_id_hex: &str) -> PathBuf {
    let mut ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    ts += 1;

    let short_id: String = offer_id_hex.chars().take(6).collect();

    let out = match filename.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}_{ts}_{short_id}.{ext}"),
        None => format!("{filename}_{ts}_{short_id}"),
    };
    dir.join(out)
}

/// Spawns a background thread that does the zip bundling.
pub fn spawn_zip_bundle_thread( paths: Vec<PathBuf>, offer_id: [u8; 16], ) -> (mpsc::Receiver<BundleEvent>, thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<BundleEvent>();
    let handle = thread::spawn(move || {
        let result: io::Result<(Vec<u8>, LocalFileOffer)> =
            build_zip_bundle_packet_no_registry(&paths, offer_id, |done, total, path| {
                let _ = tx.send(BundleEvent::Progress {
                    offer_id,
                    done,
                    total,
                    current: path.to_path_buf(),
                });
            });

        match result {
            Ok((packet, local)) => {
                let _ = tx.send(BundleEvent::Finished {
                    offer_id,
                    packet,
                    local,
                });
            }
            Err(e) => {
                let _ = tx.send(BundleEvent::Error {
                    offer_id,
                    message: e.to_string(),
                });
            }
        }
    });

    (rx, handle)
}

fn build_zip_bundle_packet_no_registry<F: FnMut(u64, u64, &Path)>( paths: &[PathBuf], offer_id: [u8; 16], mut on_progress: F, ) -> io::Result<(Vec<u8>, LocalFileOffer)> {
    let mut total_bytes: u64 = 0;
    let mut infos: Vec<(PathBuf, u64)> = Vec::with_capacity(paths.len());

    for path in paths {
        let meta = std::fs::metadata(path)?;
        if meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Folder inside multi-select not supported yet",
            ));
        }
        let sz = meta.len();
        total_bytes = total_bytes.saturating_add(sz);
        infos.push((path.clone(), sz));
    }

    // ✅ required function
    let zip_path = make_temp_zip_path(&offer_id);

    let file = File::create(&zip_path)?;
    let mut zip = ZipWriter::new(file);
    let options: FileOptions<'_, ()> = FileOptions::default();

    let mut done_bytes: u64 = 0;
    let mut buf = vec![0u8; 256 * 1024];

    for (path, _file_total) in infos {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        zip.start_file(name, options)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let f = File::open(&path)?;
        let mut r = BufReader::new(f);

        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            zip.write_all(&buf[..n])?;
            done_bytes += n as u64;
            on_progress(done_bytes, total_bytes, &path);
        }
    }

    zip.finish()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let zip_size = std::fs::metadata(&zip_path)?.len();
    let name = format!("bundle_{}.zip", offer_id_to_hex(&offer_id));

    let local = LocalFileOffer {
        path: zip_path,
        kind: OfferKind::ZipBundle,
        size: zip_size,
        name: name.clone(),
    };

    let offer = FileOffer {
        offer_id,
        name,
        size: zip_size,
        kind: OfferKind::ZipBundle,
        protocol_version: FILE_PROTOCOL_VERSION,
        tcp_port: DEFAULT_TCP_PORT,
    };

    let packet = encode_offer_packet(&offer)?;
    Ok((packet, local))
}

pub fn bundle_slot_release() {
    ACTIVE_BUNDLES.fetch_sub(1, Ordering::SeqCst);
}

pub fn hex_to_offer_id(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────
// Mobile (Flutter) file-offer decoder (MFOFT)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MobileFileOfferJson {
    #[serde(rename = "offer_id")]
    offer_id_hex: String,
    name: String,
    size: u64,
    kind: String,
    #[serde(rename = "protocol_version")]
    protocol_version: u8,
    #[serde(rename = "tcp_port")]
    tcp_port: u16,
}

pub fn decode_mfoft(payload: &[u8]) -> Option<(FileOffer, String)> {
    let m: MobileFileOfferJson = serde_json::from_slice(payload).ok()?;

    // version guard
    if m.protocol_version != FILE_PROTOCOL_VERSION {
        return None;
    }

    // currently mobile only supports single file
    if m.kind != "SingleFile" {
        return None;
    }

    let offer_id = hex_to_offer_id(&m.offer_id_hex)?;

    let offer = FileOffer {
        offer_id,
        name: m.name,
        size: m.size,
        kind: OfferKind::SingleFile,
        protocol_version: m.protocol_version,
        tcp_port: m.tcp_port,
    };

    Some((offer, m.offer_id_hex))
}

pub fn register_remote_offer(
    remote_offers: &std::sync::Arc<std::sync::Mutex<RemoteWindowsOfferRegistry>>,
    sender_ip: std::net::IpAddr,
    id_hex: String,
    offer: crate::file_transfer_protocol::FileOffer,
) -> bool {
    let mut reg = remote_offers.lock().unwrap();
    if reg.contains_key(&id_hex) {
        false // duplicate
    } else {
        reg.insert(id_hex, (sender_ip, offer));
        true // new
    }
}

// helper for both mobile and windows
pub fn truncate_name(name: &str, max_chars: usize) -> String {
    if name.chars().count() <= max_chars {
        return name.to_string();
    }
    let mut s: String = name.chars().take(max_chars.saturating_sub(1)).collect();
    s.push('…');
    s
}