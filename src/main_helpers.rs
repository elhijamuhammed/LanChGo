use crate::AppWindow;
use crate::classes::{BroadcastState, Config, InterfacesInfo};
use crate::file_transfer_protocol;
use crate::FileOfferItem;
use crate::secure_channel_code;
use get_if_addrs::{get_if_addrs, IfAddr};
use ipconfig;
use slint::VecModel;
use std::fs::File;
use std::io;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::path::{PathBuf, Path};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use slint::{ComponentHandle, SharedString, Model};
use rodio::{Decoder, OutputStreamBuilder, Sink};

const NUTELLA_BYTES: &[u8] = include_bytes!("../nutella.ogg");

/// To fix a bug that is not fixable
pub fn force_switch_to_public(app: &AppWindow, channel_mode: &Arc<Mutex<String>>) {
    set_channel_mode_only(channel_mode, "public");

    app.set_channel_mode("public".into());
    app.set_public_secure_helper(false);
    app.set_host_PIN("N/A".into());
    app.set_host_PIN_masked("N/A".into());
}

/// To clear the chatbox by a button
pub fn clear_chatbox(model: &Rc<VecModel<slint::SharedString>>) {
    model.set_vec(Vec::new());
}

/// Only change the mode the rest of the logic is built in another block of code
pub fn set_channel_mode_only(channel_mode: &Arc<Mutex<String>>, new_mode: &str) {
    let mut cm = channel_mode.lock().unwrap();
    *cm = new_mode.to_string();
}

pub fn get_local_ipv4() -> Option<Ipv4Addr> {
    // Iterate through all network adapters
    match ipconfig::get_adapters() {
        Ok(adapters) => {
            for adapter in adapters {
                // Skip adapters that are down
                if format!("{:?}", adapter.oper_status()) != "IfOperStatusUp" {
                    continue;
                }
                // Look through adapter IPs
                for ip in adapter.ip_addresses() {
                    if let IpAddr::V4(v4) = ip {
                        // Skip loopback addresses (127.x.x.x)
                        if !v4.is_loopback() {
                            return Some(*v4);
                        }
                    }
                }
            }
            None
        }
        Err(_e) => None,
    }
}

#[allow(nonstandard_style)]
pub fn update_ui_PIN(app: &AppWindow) {
    let pin_string = secure_channel_code::get_host_PIN_string();
    app.set_host_PIN(pin_string.into());

    if let Some(masked) = secure_channel_code::get_masked_host_PIN() {
        app.set_host_PIN_masked(masked.into());
    } else {
        // No PIN means we're back in Public mode → destroy channel
        secure_channel_code::destroy_channel();
        app.set_host_PIN_masked("N/A".into());
    }
    // ✅ Update the QR image if available
    if let Some(img) = crate::secure_channel_code::get_QR_slint_image() {
        app.set_QR_code_image(img);
    }
}

/// Gather user-friendly interfaces (name + broadcast)
pub fn collect_interfaces() -> Vec<InterfacesInfo> {
    let mut collection = Vec::new();
    let ifaces = get_if_addrs().unwrap_or_default();

    for adapter in ipconfig::get_adapters().unwrap_or_default() {
        let name = adapter.friendly_name().to_string();
        let status = format!("{:?}", adapter.oper_status());

        // Default fallback broadcast
        let mut broadcast_address = "255.255.255.255".to_string();

        // Match adapter IPs against get_if_addrs to find broadcast
        for ip in adapter.ip_addresses().iter().map(|ip| ip.to_string()) {
            for iface in &ifaces {
                if let IfAddr::V4(v4) = &iface.addr {
                    if v4.ip.to_string() == ip {
                        if let Some(b) = v4.broadcast {
                            broadcast_address = b.to_string();
                        }
                    }
                }
            }
        }

        // Only skip loopback and "all 255s"
        if broadcast_address != "127.255.255.255" && broadcast_address != "255.255.255.255" {
            collection.push(InterfacesInfo {
                name,
                address_to_broadcast: broadcast_address,
                status,
            });
        }
    }

    collection
}

/// Return the adapter’s first IPv4 gateway as string (or "0.0.0.0" if none)
pub fn get_gateway_for_adapter(name: &str) -> String {
    for adapter in ipconfig::get_adapters().unwrap_or_default() {
        if adapter.friendly_name() == name {
            // Prefer IPv4 gateways
            if let Some(gw) = adapter
                .gateways()
                .iter()
                .find_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4.to_string()),
                    _ => None,
                })
            {
                return gw;
            }
            // If only IPv6 or none:
            if let Some(gw_any) = adapter.gateways().get(0) {
                return gw_any.to_string();
            }
            return "0.0.0.0".to_string();
        }
    }
    "0.0.0.0".to_string()
}

pub fn get_broadcast_for_name(interfaces: &Vec<InterfacesInfo>, name: &str) -> Option<String> {
    interfaces
        .iter()
        .find(|it| it.name == name)
        .map(|it| it.address_to_broadcast.clone())
}

pub fn save_config(config: &Config) {
    let config_path = get_config_path();
    let file = File::create(&config_path).expect("Failed to create config file");
    serde_json::to_writer_pretty(file, &config).expect("Failed to write config file");
}

pub fn match_getifadd_ipconfig(state: &BroadcastState) -> String {
    let broadcast = state.get_broadcast_address();
    let mut matched_ip: Option<String> = None;

    for iface in get_if_addrs().unwrap_or_default() {
        if let IfAddr::V4(v4) = iface.addr {
            if let Some(b) = v4.broadcast {
                if b.to_string() == broadcast {
                    matched_ip = Some(v4.ip.to_string());
                    break;
                }
            }
        }
    }

    if let Some(ip) = matched_ip {
        for adapter in ipconfig::get_adapters().unwrap_or_default() {
            if adapter.ip_addresses().iter().any(|a| a.to_string() == ip) {
                return adapter.friendly_name().to_string();
            }
        }
    }

    "Unknown".to_string()
}

pub fn get_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    let config_path = dirs::data_dir()
        .unwrap()
        .join("LanChGoApp")
        .join("config.json");
    config_path
}

pub fn load_or_create_config(default: &Config, app: &AppWindow) -> (Config, bool) {
    let config_path = get_config_path();
    if config_path.exists() {
        let file = File::open(&config_path).expect("Failed to open config file");
        let config: Config =
            serde_json::from_reader(file).expect("Failed to parse config file");

        let current_version = env!("CARGO_PKG_VERSION").to_string();
        if config.version != current_version {
            std::fs::remove_file(&config_path).ok();
            let weak = app.as_weak();
            if let Some(app) = weak.upgrade() {
                app.invoke_show_new_version_popup();
            }
        }

        (config, false)
    } else {
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create config directory");
        }
        let file = File::create(&config_path).expect("Failed to create config file");
        serde_json::to_writer_pretty(file, &default).expect("Failed to write config file");
        (default.clone(), true)
    }
}

pub fn get_broadcast_address(state: &BroadcastState) {
    let address = get_if_addrs()
        .ok()
        .and_then(|addrs| {
            addrs.into_iter().find_map(|iface| {
                if let IfAddr::V4(v4) = iface.addr {
                    v4.broadcast.map(|b| b.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "255.255.255.255".to_string());

    state.set_broadcast_address(address);
}

pub fn bind_single_port_socket(port: u16) -> io::Result<Arc<UdpSocket>> {
    let sock = UdpSocket::bind(("0.0.0.0", port))?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(Arc::new(sock))
}
// to clear up the registry of sent file offers bundles in the temp
pub fn cleanup_file_offers( offer_registry: &Arc<Mutex<file_transfer_protocol::OfferRegistry>>, file_offer_model: Option<&Rc<VecModel<FileOfferItem>>>, ) {
    {
        let mut reg = offer_registry.lock().unwrap();
        file_transfer_protocol::cleanup_temp_offers(&mut reg);
        reg.clear();
    }

    if let Some(model) = file_offer_model {
        model.set_vec(Vec::new());
    }

    println!("[FOFT][CLEANUP] temp offers deleted + registry cleared");
}
// to show download progress 
pub fn progress_bucket_3(done: u64, total: u64) -> u32 {
    if total == 0 { return 0; }
    let percent = ((done.saturating_mul(100)) / total) as u32;
    if percent >= 100 { 100 } else { (percent / 3) * 3 }
}

pub fn set_offer_progress_text(app: &AppWindow, offer_id: &str, downloading: bool, text: &str) {
    let model_rc = app.get_file_offer();

    if let Some(vec) = model_rc.as_any().downcast_ref::<VecModel<FileOfferItem>>() {
        for i in 0..vec.row_count() {
            if let Some(mut row) = vec.row_data(i) {
                if row.offer_id.as_str() == offer_id {
                    row.is_downloading = downloading;
                    row.progress_text = SharedString::from(text);
                    vec.set_row_data(i, row);
                    break;
                }
            }
        }
    }
}

pub fn play_nutella_sound() {
    if let Ok(builder) = OutputStreamBuilder::from_default_device() {
        if let Ok(stream) = builder.open_stream() {
            let mixer = stream.mixer();
            let sink = Sink::connect_new(&mixer);
            let cursor = Cursor::new(NUTELLA_BYTES);
            if let Ok(source) = Decoder::new(cursor) {
                sink.append(source);
                sink.detach();
            }

            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(3));
                drop(stream);
            });
        }
    }
}

pub fn build_download_save_path( config: &Arc<Mutex<Config>>, offer_name: &str, offer_id_hex: &str, ) -> PathBuf {
    let download_dir = {
        let cfg = config.lock().unwrap();
        cfg.save_to_folder.clone()
    };
    file_transfer_protocol::build_unique_download_path(
        Path::new(&download_dir),
        offer_name,
        offer_id_hex,
    )
}

pub fn info_message() -> String {
        "   LanChGo App
        Talk freely, fast, and local.

        Features:
        • LAN chat & secure channels
        • File transfers (no cloud)
        • QR / PIN pairing

        Links:
        • Website: https://lanchgo.com/
        • GitHub:  https://github.com/elhijamuhammed/LanChGo

        © 2025 Muhammed Abu El-Hija"
    .to_string()
}

pub fn help_message() -> String {
        "Available Commands

        /info        Show app information
        /help        Show this help message
        /clear       Clear chat messages
        /clearfiles  Clear file transfer panel
        /clearall    Clear chat and files
        /disconnect  Disconnect from secure channel
        /exit        Exit LanChGo

        Tip:
        Commands are local and not sent over the network."
    .to_string()
}
