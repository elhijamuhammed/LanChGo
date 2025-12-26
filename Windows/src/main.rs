// Prevent console window in Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Other code files
mod secure_channel_code;   // Code to generate PIN decrypt and encrypt
mod phone_protocol;        // For phone connection and protocol
mod file_transfer_protocol; // For file transfering logic (future use)

use get_if_addrs::*;
use ipconfig;
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, LogicalSize, Model, ModelRc, VecModel};
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, sleep, JoinHandle};
use std::time::Duration;
use std::process;
use bincode;
use crate::phone_protocol::build_MANCH;

slint::include_modules!();

#[derive(Debug)]
pub struct BroadcastState {
    pub broadcast_address: Mutex<String>,
    pub port: Mutex<u16>, // single port
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    version: String,
    selected_interface: String,
    last_broadcast: String,
    last_gateway: String,
}

#[derive(Debug, Clone)]
struct InterfacesInfo {
    name: String,
    address_to_broadcast: String,
    status: String, // Up or Down
}

#[derive(Clone)]
pub struct InterfaceItem {
    pub name: slint::SharedString,
    pub broadcast: slint::SharedString,
}

impl BroadcastState {
    pub fn set_broadcast_address(&self, address: String) {
        *self.broadcast_address.lock().unwrap() = address;
    }
    pub fn get_broadcast_address(&self) -> String {
        self.broadcast_address.lock().unwrap().clone()
    }
    pub fn set_port(&self, p: u16) {
        *self.port.lock().unwrap() = p;
    }
    pub fn get_port(&self) -> u16 {
        *self.port.lock().unwrap()
    }
    pub fn target_v4(&self) -> SocketAddrV4 {
        let ip: Ipv4Addr = self
            .get_broadcast_address()
            .parse()
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 255));
        SocketAddrV4::new(ip, self.get_port())
    }
}

// ===================== Helpers =====================

/// To fix a bug that is not fixable
fn force_switch_to_public(app: &AppWindow, channel_mode: &Arc<Mutex<String>>) {
    set_channel_mode_only(channel_mode, "public");

    app.set_channel_mode("public".into());
    app.set_public_secure_helper(false);
    app.set_host_PIN("N/A".into());
    app.set_host_PIN_masked("N/A".into());
}

/// To clear the chatbox by a button
fn clear_chatbox(model: &Rc<VecModel<slint::SharedString>>) {
    model.set_vec(Vec::new());
}

/// Only change the mode the rest of the logic is built in another block of code
fn set_channel_mode_only(channel_mode: &Arc<Mutex<String>>, new_mode: &str) {
    let mut cm = channel_mode.lock().unwrap();
    *cm = new_mode.to_string();
}

fn get_local_ipv4() -> Option<Ipv4Addr> {
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
fn update_ui_PIN(app: &AppWindow) {
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
fn collect_interfaces() -> Vec<InterfacesInfo> {
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
fn get_gateway_for_adapter(name: &str) -> String {
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

fn get_broadcast_for_name(interfaces: &Vec<InterfacesInfo>, name: &str) -> Option<String> {
    interfaces
        .iter()
        .find(|it| it.name == name)
        .map(|it| it.address_to_broadcast.clone())
}

fn save_config(config: &Config) {
    let config_path = get_config_path();
    let file = File::create(&config_path).expect("Failed to create config file");
    serde_json::to_writer_pretty(file, &config).expect("Failed to write config file");
}

fn match_getifadd_ipconfig(state: &BroadcastState) -> String {
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

fn get_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    let config_path = dirs::data_dir()
        .unwrap()
        .join("LanChGoApp")
        .join("config.json");
    config_path
}

fn load_or_create_config(default: &Config, app: &AppWindow) -> (Config, bool) {
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

fn get_broadcast_address(state: &BroadcastState) {
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

fn bind_single_port_socket(port: u16) -> io::Result<Arc<UdpSocket>> {
    let sock = UdpSocket::bind(("0.0.0.0", port))?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(Arc::new(sock))
}

// ===================== Receiver loop =====================

fn start_udp_receiver(
    sock: Arc<UdpSocket>,
    running: Arc<AtomicBool>,
    ui_weak: slint::Weak<AppWindow>,
    channel_mode: Arc<Mutex<String>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let my_ip = get_local_ipv4();

        while running.load(Ordering::Relaxed) {
            match sock.recv_from(&mut buf) {
                Ok((n, _from)) => {
                    let msg_bytes = &buf[..n];
                    let mode = {
                        let cm = channel_mode.lock().unwrap();
                        cm.clone()
                    };

                    // ─── Secure Channel Mode ──────────────────────────────────────────────
                    if mode == "joined" || mode == "host" {
                        // 🛰 Step 1: Handle announcements
                        if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"ANCH" {
                            if let Some(ip) = my_ip {
                                if _from.ip() == ip {
                                    continue; // Ignore self-broadcasts
                                }
                            }
                            let payload = &msg_bytes[4..];

                            if secure_channel_code::store_announcement(payload) {
                                continue; // Successfully handled as announcement
                            }
                        } else if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MANCH" {
                            let payload = &msg_bytes[5..];
                            if phone_protocol::store_announcement_phone(payload) {
                                // ok
                            } else {
                                // failed
                            }
                            continue;
                        }
                        // 🔒 Step 2: Handle encrypted messages
                        else if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"ENCM" {
                            let payload = &msg_bytes[4..]; // Strip header

                            if let Some(decrypted) =
                                secure_channel_code::decrypt_message_from_bytes(
                                    payload,
                                )
                            {
                                let weak = ui_weak.clone();
                                slint::invoke_from_event_loop(move || {
                                    if let Some(app) = weak.upgrade() {
                                        if decrypted.eq_ignore_ascii_case("ping") {
                                            secure_channel_code::play_ping_sound();
                                        }
                                        if !decrypted.eq_ignore_ascii_case("/exit")
                                            || !decrypted
                                                .eq_ignore_ascii_case("/clear")
                                            || !decrypted
                                                .eq_ignore_ascii_case(
                                                    "/disconnect",
                                                )
                                        {
                                            app.invoke_append_message(
                                                decrypted.into(),
                                            );
                                        }
                                    }
                                })
                                .ok();
                            }
                            continue; // Done with encrypted message
                        } else if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MENCM" {
                            if let Some(ip) = my_ip {
                                if _from.ip() == ip {
                                    continue; // Ignore self-broadcasts
                                }
                            }
                            if msg_bytes.len() > 17 {
                                let nonce = &msg_bytes[5..17];
                                let ciphertext = &msg_bytes[17..];
                                if let Some(channel) =
                                    secure_channel_code::get_active_channel()
                                {
                                    let aes_key = &channel.key;
                                    if let Some(plain) =
                                        phone_protocol::decrypt_message_phone(
                                            aes_key,
                                            nonce,
                                            ciphertext,
                                        )
                                    {
                                        let weak = ui_weak.clone();
                                        slint::invoke_from_event_loop(move || {
                                            if let Some(app) = weak.upgrade() {
                                                if plain.eq_ignore_ascii_case("ping") {
                                                    secure_channel_code::play_ping_sound();
                                                }
                                                if !plain.eq_ignore_ascii_case("/exit")
                                                    && !plain.eq_ignore_ascii_case(
                                                        "/clear",
                                                    )
                                                    && !plain.eq_ignore_ascii_case(
                                                        "/disconnect",
                                                    )
                                                {
                                                    app.invoke_append_message(
                                                        plain.into(),
                                                    );
                                                }
                                            }
                                        })
                                        .ok();
                                    } else {
                                        // decryption failed
                                    }
                                } else {
                                    // no channel
                                }
                            } else {
                                // too short
                            }
                            continue; // important: skip further processing
                        }
                        // 🔁 Step 3: Handle REQA (request announcement)
                        else if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"REQA" {
                            if mode == "host" {
                                if let Some(channel) =
                                    secure_channel_code::get_active_channel()
                                {
                                    // Build and send ANCH packet (desktop)
                                    let announce =
                                        secure_channel_code::build_announcement(
                                            &channel,
                                        );
                                    if let Ok(payload) =
                                        bincode::serde::encode_to_vec(
                                            &announce,
                                            bincode::config::standard(),
                                        )
                                    {
                                        let mut packet = Vec::from(b"ANCH");
                                        packet.extend_from_slice(&payload);
                                        let _ = sock.send_to(&packet, _from);
                                    }

                                    // Build and send MANCH packet (mobile)
                                    if let Ok(man_json) = phone_protocol::build_MANCH(
                                        &channel,
                                    ) {
                                        let mut man_packet = Vec::from(b"MANCH");
                                        man_packet
                                            .extend_from_slice(man_json.as_bytes());
                                        let _ = sock.send_to(&man_packet, _from);
                                    }
                                }
                            }
                            continue;
                        } else if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"FOFR" {
                            // ignore FOFR in secure mode for now
                            continue;
                        }
                    }

                    // ─── Public Mode ──────────────────────────────────────────────────────
                    if mode == "public" {
                        // 1) Special handling for FOFR
                        if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"FOFR" {
                            // Ignore our own broadcasts
                            if let Some(ip) = my_ip {
                                if _from.ip() == ip {
                                    continue;
                                }
                            }
                            continue;
                        }

                        // 2️⃣ Normal text messages
                        if let Ok(msg) = String::from_utf8(msg_bytes.to_vec()) {
                            if msg.eq_ignore_ascii_case("ping") {
                                secure_channel_code::play_ping_sound();
                            }
                            if !msg.eq_ignore_ascii_case("/exit")
                                && !msg.eq_ignore_ascii_case("/clear")
                                && !msg.eq_ignore_ascii_case("/disconnect")
                                && !msg.eq_ignore_ascii_case("REQA")
                                && !msg.starts_with("MANCH")
                            {
                                let weak = ui_weak.clone();
                                slint::invoke_from_event_loop(move || {
                                    if let Some(app) = weak.upgrade() {
                                        app.invoke_append_message(msg.into());
                                    }
                                })
                                .ok();
                            }
                        }
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Expected timeouts
                }
                Err(_e) => {
                    break;
                }
            }
        }
    })
}

const MAX_DATAGRAM: usize = 1400;
fn broadcast_the_msg(sock: &UdpSocket, state: &BroadcastState, msg: &[u8]) -> io::Result<()> {
    let target = state.target_v4();
    if msg.len() >= MAX_DATAGRAM {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("message too long: {} > {}", msg.len(), MAX_DATAGRAM),
        ));
    }
    sock.send_to(msg, target)?;
    Ok(())
}

// ===================== main =====================

fn main() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(BroadcastState {
        broadcast_address: Mutex::new(String::new()),
        port: Mutex::new(3000),
    });
    get_broadcast_address(&state);

    let app = AppWindow::new()?;
    let w = app.window();
    w.set_fullscreen(false);
    w.set_maximized(false);
    w.set_size(LogicalSize::new(910.0, 620.0));

    let interfaces = collect_interfaces();
    let iface_rows: Vec<slint::SharedString> = interfaces
        .iter()
        .map(|it| format!("Name: {}\nBroadcast Address: {}", it.name, it.address_to_broadcast).into())
        .collect();
    let iface_model = Rc::new(VecModel::from(iface_rows));
    app.set_interfaces(ModelRc::new(iface_model.clone()));

    let model = Rc::new(VecModel::from(Vec::<slint::SharedString>::new()));
    app.set_messages(ModelRc::new(model.clone()));
    let model_for_clear = model.clone();

    let channel_mode = Arc::new(Mutex::new(String::from("public")));
    {
        let channel_mode = channel_mode.clone();
        let weak = app.as_weak();
        app.on_change_channel_mode(move |new_mode: slint::SharedString| {
            let mut cm = channel_mode.lock().unwrap();
            *cm = new_mode.to_string();
            if *cm == "public" {
                secure_channel_code::destroy_channel();
                if let Some(app) = weak.upgrade() {
                    app.set_host_PIN("N/A".into());
                    app.set_host_PIN_masked("N/A".into());
                }
            }
        });
    }

    {
        let model = model.clone();
        app.on_append_message(move |msg: slint::SharedString| {
            model.push(msg);
            if model.row_count() > 10 {
                model.remove(0);
            }
        });
    }

    let default_iface_name = match_getifadd_ipconfig(&state);
    let default_broadcast = get_broadcast_for_name(&interfaces, &default_iface_name)
        .unwrap_or_else(|| state.get_broadcast_address());
    let default_gateway = get_gateway_for_adapter(&default_iface_name);

    let default_config = Config {
        version: env!("CARGO_PKG_VERSION").to_string(),
        selected_interface: default_iface_name.clone(),
        last_broadcast: default_broadcast.clone(),
        last_gateway: default_gateway.clone(),
    };

    let (mut config, first_run) = load_or_create_config(&default_config, &app);

    let current_broadcast_for_config =
        get_broadcast_for_name(&interfaces, &config.selected_interface)
            .unwrap_or_else(|| state.get_broadcast_address());
    let current_gateway_for_config = get_gateway_for_adapter(&config.selected_interface);

    let lan_changed = config.last_broadcast != current_broadcast_for_config
        || config.last_gateway != current_gateway_for_config;
    app.set_changed_networks(lan_changed);

    state.set_broadcast_address(current_broadcast_for_config.clone());

    app.set_show_welcome(first_run || lan_changed);
    app.set_selected_interface(config.selected_interface.clone().into());
    app.set_broadcast_address(state.get_broadcast_address().into());

    if let Some(info) = interfaces.iter().find(|it| it.name == config.selected_interface) {
        app.set_interface_status(info.status.clone().into());
    } else {
        app.set_interface_status("IfOperStatusDown".into());
    }

    app.set_ui_port(state.get_port() as i32);
    app.set_show_version(env!("CARGO_PKG_VERSION").into());

    let sock = bind_single_port_socket(state.get_port())?;
    let running = Arc::new(AtomicBool::new(true));

    let _recv_handle = start_udp_receiver(
        Arc::clone(&sock),
        Arc::clone(&running),
        app.as_weak(),
        Arc::clone(&channel_mode),
    );

    // --- send button ---
    {
        let st = Arc::clone(&state);
        let s = Arc::clone(&sock);
        let weak = app.as_weak();

        app.on_send_clicked(move || {
            if let Some(app) = weak.upgrade() {
                let msg = app.get_input_text().to_string();
                let trimmed = msg.trim();

                if msg.eq_ignore_ascii_case("/exit") {
                    app.invoke_append_message("🚪 Exiting in 1 seconds...".into());
                    thread::spawn(|| {
                        sleep(Duration::from_secs(1));
                        process::exit(0);
                    });
                    return;
                }
                if msg.eq_ignore_ascii_case("/clear") {
                    model.set_vec(Vec::new());
                    app.set_input_text("".into());
                    return;
                }
                if msg.eq_ignore_ascii_case("/disconnect") {
                    app.invoke_disconnect_channel();
                    app.set_input_text("".into());
                    return;
                }
                if trimmed.is_empty() {
                    app.set_input_text("".into());
                    return;
                }
                if let Some(channel) = secure_channel_code::get_active_channel() {
                    // Windows packet
                    let encrypted =
                        secure_channel_code::encrypt_message(&channel.key, trimmed);
                    let payload = bincode::serde::encode_to_vec(
                        &encrypted,
                        bincode::config::standard(),
                    )
                    .expect("Failed to encode SecureMessage");
                    let mut packet_win = Vec::from(b"ENCM" as &[u8]);
                    packet_win.extend_from_slice(&payload);
                    let _ = broadcast_the_msg(&s, &st, &packet_win);

                    // Mobile packet
                    let packet_mob =
                        phone_protocol::encrypt_message_phone(&channel.key, trimmed);
                    let _ = broadcast_the_msg(&s, &st, &packet_mob);
                } else {
                    if let Err(_e) = broadcast_the_msg(&s, &st, trimmed.as_bytes()) {
                        app.invoke_show_popupmsg();
                    }
                }
                app.set_input_text("".into());
            }
        });
    }

    // Second change_channel_mode handler (kept from your original code)
    {
        let weak = app.as_weak();
        let sock = Arc::clone(&sock);
        let state = Arc::clone(&state);
        let channel_mode = Arc::clone(&channel_mode);

        app.on_change_channel_mode(move |new_mode: slint::SharedString| {
            if let Some(app) = weak.upgrade() {
                let new_mode_str = new_mode.as_str();

                // Update shared state
                set_channel_mode_only(&channel_mode, new_mode_str);

                // Handle transitions that require network actions
                match new_mode_str {
                    "public" => {
                        secure_channel_code::destroy_channel();
                        app.set_host_PIN("N/A".into());
                        app.set_host_PIN_masked("N/A".into());
                        app.set_public_secure_helper(false);
                    }
                    "host" => {
                        const REQA_MAGIC: &[u8] = b"REQA";
                        if let Err(_e) = broadcast_the_msg(&sock, &state, REQA_MAGIC) {
                            app.invoke_show_popupmsg();
                        }
                    }
                    "joined" => {
                        // nothing special for now
                    }
                    _ => {}
                }
            }
        });
    }

    app.on_interface_selected({
        let state = Arc::clone(&state);
        let interfaces = interfaces.clone();
        let weak = app.as_weak();
        move |iface_display: slint::SharedString| {
            if let Some(info) = interfaces.iter().find(|it| iface_display.contains(&it.name)) {
                state.set_broadcast_address(info.address_to_broadcast.clone());

                let gw = get_gateway_for_adapter(&info.name);
                config.selected_interface = info.name.clone();
                config.last_broadcast = info.address_to_broadcast.clone();
                config.last_gateway = gw;
                save_config(&config);

                if let Some(app) = weak.upgrade() {
                    app.set_selected_interface(info.name.clone().into());
                    app.set_broadcast_address(state.get_broadcast_address().into());
                    app.set_ui_port(state.get_port() as i32);
                    app.set_interface_status(info.status.clone().into());
                }
            }
        }
    });

    // When the user creates a new channel
    {
        let st = Arc::clone(&state);
        let s = Arc::clone(&sock);
        let weak = app.as_weak();

        app.on_create_channel(move || {
            let channel = secure_channel_code::create_new_channel();
            let announce = secure_channel_code::build_announcement(&channel);

            if let Ok(payload) =
                bincode::serde::encode_to_vec(&announce, bincode::config::standard())
            {
                const ANNOUNCE_MAGIC: &[u8] = b"ANCH";
                let mut packet = Vec::from(ANNOUNCE_MAGIC);
                packet.extend_from_slice(&payload);

                if let Err(_e) = broadcast_the_msg(&s, &st, &packet) {
                    if let Some(app) = weak.upgrade() {
                        app.invoke_show_popupmsg();
                    }
                }
            }

            // mobile MANCH
            if let Ok(man_json) = build_MANCH(&channel) {
                const MANCH_MAGIC: &[u8] = b"MANCH";
                let mut man_packet = Vec::from(MANCH_MAGIC);
                man_packet.extend_from_slice(man_json.as_bytes());
                if let Err(_e) = broadcast_the_msg(&s, &st, &man_packet) {
                    if let Some(app) = weak.upgrade() {
                        app.invoke_show_popupmsg();
                    }
                }
            }

            secure_channel_code::generate_QR_code();
            if let Some(app) = weak.upgrade() {
                update_ui_PIN(&app);
            }
        });
    }

    // When the user presses new PIN button
    {
        let st = Arc::clone(&state);
        let s = Arc::clone(&sock);
        let weak = app.as_weak();

        app.on_generate_new_PIN(move || {
            let channel = secure_channel_code::regenerate_PIN();

            // desktop ANCH
            let announce = secure_channel_code::build_announcement(&channel);
            if let Ok(payload) =
                bincode::serde::encode_to_vec(&announce, bincode::config::standard())
            {
                const ANNOUNCE_MAGIC: &[u8] = b"ANCH";
                let mut packet = Vec::from(ANNOUNCE_MAGIC);
                packet.extend_from_slice(&payload);

                if let Err(_e) = broadcast_the_msg(&s, &st, &packet) {
                    if let Some(app) = weak.upgrade() {
                        app.invoke_show_popupmsg();
                    }
                }
            }

            // mobile MANCH
            if let Ok(man_json) = build_MANCH(&channel) {
                const MANCH_MAGIC: &[u8] = b"MANCH";
                let mut man_packet = Vec::from(MANCH_MAGIC);
                man_packet.extend_from_slice(man_json.as_bytes());

                if let Err(_e) = broadcast_the_msg(&s, &st, &man_packet) {
                    if let Some(app) = weak.upgrade() {
                        app.invoke_show_popupmsg();
                    }
                }
            }

            secure_channel_code::generate_QR_code();
            if let Some(app) = weak.upgrade() {
                update_ui_PIN(&app);
            }
        });
    }

    // When the user presses disconnect button
    {
        let weak = app.as_weak();
        let channel_mode = Arc::clone(&channel_mode);

        app.on_disconnect_channel(move || {
            secure_channel_code::destroy_channel();

            if let Some(app) = weak.upgrade() {
                set_channel_mode_only(&channel_mode, "public");
                update_ui_PIN(&app);
                app.set_channel_mode("public".into());
                app.set_public_secure_helper(false);
                app.invoke_show_temp_message("🔌 Disconnected — returned to public mode".into());
            }
        });
    }

    // When the user presses join channel
    #[allow(nonstandard_style)]
    {
        let weak = app.as_weak();
        let channel_mode = Arc::clone(&channel_mode);

        app.on_join_channel(move |PIN: slint::SharedString| {
            if let Some(app) = weak.upgrade() {
                let join_PIN = PIN.to_string();
                let success = secure_channel_code::join_with_PIN(&join_PIN);
                app.invoke_show_connecting_popup();
                if success {
                    secure_channel_code::play_ping_sound();
                    set_channel_mode_only(&channel_mode, "joined");
                    app.set_channel_mode("joined".into());
                    app.set_public_secure_helper(true);
                    app.invoke_hide_connecting_popup();
                    app.set_temp_message("✅ Joined secure channel successfully!".into());
                } else {
                    set_channel_mode_only(&channel_mode, "public");
                    app.invoke_hide_connecting_popup();
                    app.set_channel_mode("public".into());
                    app.set_public_secure_helper(false);
                    app.set_temp_message("❌ Incorrect PIN or no secure channel found.".into());
                }
            }
        });
    }

    // Clear chatbox button
    {
        let model = model_for_clear.clone();
        app.on_clear_chatbox(move || {
            clear_chatbox(&model);
        });
    }

    // Fix for the bug where the cancel button does not change to public
    {
        let weak = app.as_weak();
        let channel_mode = Arc::clone(&channel_mode);

        app.on_fix_the_bug_please(move || {
            if let Some(app) = weak.upgrade() {
                force_switch_to_public(&app, &channel_mode);
            }
        });
    }

    // Exit when a new version is detected but old config file
    {
        app.on_exit_app(move || {
            std::process::exit(0);
        });
    }

    // // When the user clicks "Send File"
    // {
    //     let st = Arc::clone(&state);
    //     let s = Arc::clone(&sock);
    //     let weak = app.as_weak();
    //     let outgoing_bundles = Arc::clone(&outgoing_bundles);

    //     app.on_send_file_start(move || {
    //         if let Some(app) = weak.upgrade() {
    //             handle_send_file_clicked(app, &st, &s, &outgoing_bundles);
    //         }
    //     });
    // }

    app.run()?;
    running.store(false, Ordering::Relaxed);
    Ok(())
}