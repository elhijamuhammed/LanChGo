// Prevent console window in Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Other code files
mod secure_channel_code;    // Code to generate PIN decrypt and encrypt
mod phone_protocol;         // For phone connection and protocol
mod file_transfer_protocol; // For file transferring logic (future use)
mod classes;
mod main_helpers;
mod udp_receiver;
mod tcp_file_server;
mod tcp_file_client;
mod mobile_download;
mod web_app;
mod web_app_file_transfer;

use semaphore::Semaphore;
use slint::{ComponentHandle, LogicalSize, Model, ModelRc, VecModel};
use std::error::Error;
use std::io;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::rc::Rc;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex };
use std::thread::{self, sleep};
use std::time::Duration;
use std::process;
use bincode;
use crate::classes::{BroadcastState, Config};
use crate::phone_protocol::build_MANCH;
use crate::file_transfer_protocol::{ RemoteWindowsOfferRegistry, RemoteMobileOfferRegistry};
use crate::udp_receiver::start_udp_receiver;
use crate::main_helpers::{
    bind_single_port_socket, clear_chatbox, cleanup_file_offers, collect_interfaces,
    force_switch_to_public, get_broadcast_address, get_broadcast_for_name, get_gateway_for_adapter,
    load_or_create_config, match_getifadd_ipconfig, save_config, set_channel_mode_only,
    update_ui_PIN, update_ui_qr_only };
slint::include_modules!();

//static APP_HANDLE: OnceLock<slint::Weak<AppWindow>> = OnceLock::new();
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

    // -------- logic for appending web app companion messages
    main_helpers::set_app_handle(app.as_weak());

    // -------- interfaces list -> UI
    let interfaces = collect_interfaces();
    let iface_rows: Vec<slint::SharedString> = interfaces
        .iter().map(|it| { format!( "Name: {}\nBroadcast Address: {}", it.name, it.address_to_broadcast ).into()}).collect();
    let iface_model = Rc::new(VecModel::from(iface_rows));
    app.set_interfaces(ModelRc::new(iface_model.clone()));

    // -------- chat model
    let model = Rc::new(VecModel::from(Vec::<slint::SharedString>::new()));
    app.set_messages(ModelRc::new(model.clone()));
    let model_for_clear = model.clone();

    // -------- file offers model
    let file_offer_model = Rc::new(VecModel::<FileOfferItem>::from(Vec::new()));
    app.set_file_offer(ModelRc::new(file_offer_model.clone()));

    let offer_registry = Arc::new(Mutex::new(file_transfer_protocol::OfferRegistry::new()));
    web_app_file_transfer::register_offer_registry(Arc::clone(&offer_registry));
    // start tcp listner and put it in idle here
    let _tcp_handle = tcp_file_server::start_file_server(
        Arc::clone(&offer_registry),
        file_transfer_protocol::DEFAULT_TCP_PORT, )?; // <-- starts idle listener thread
    let remote_windows_offers: Arc<Mutex<RemoteWindowsOfferRegistry>> = Arc::new(Mutex::new(RemoteWindowsOfferRegistry::new()));
    let remote_mobile_offers: Arc<Mutex<RemoteMobileOfferRegistry>> = Arc::new(Mutex::new(RemoteMobileOfferRegistry::new()));
    // for pushing file offers in the Vector
    {
        let file_offer_model = file_offer_model.clone();
        app.on_add_file_offer(move |item: FileOfferItem| {
            file_offer_model.push(item);
        });
    }

    // clear button for the file transfer panel
    {
        let file_offer_model = file_offer_model.clone();
        let offer_registry = Arc::clone(&offer_registry);
        app.on_clear_file_transfer_panel(move || { cleanup_file_offers(&offer_registry, Some(&file_offer_model)); });
    }

    // -------- channel mode shared state
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

    // append message handler
    {
        let model = model.clone();
        app.on_append_message(move |msg: slint::SharedString| {
            model.push(msg.clone());
            if model.row_count() > 10 {
                model.remove(0);
            }
            // 🔥 send to web clients
            let payload = serde_json::json!({ "type": "chat", "sender": "app", "text": msg.to_string()});
            web_app::broadcast_to_web_clients(payload.to_string());
        });
    }

    // ===================== config creation + download folder =====================

    let default_iface_name = match_getifadd_ipconfig(&state);
    let default_broadcast = get_broadcast_for_name(&interfaces, &default_iface_name)
        .unwrap_or_else(|| state.get_broadcast_address());
    let default_gateway = get_gateway_for_adapter(&default_iface_name);

    let default_download_folder = dirs::download_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("LanChGo")
        .display()
        .to_string();

    let default_config = Config {
        version: env!("CARGO_PKG_VERSION").to_string(),
        selected_interface: default_iface_name.clone(),
        last_broadcast: default_broadcast.clone(),
        last_gateway: default_gateway.clone(),
        save_to_folder: default_download_folder,
        port: None,
        ui_scale: None
    };

    let (config_loaded, first_run) = load_or_create_config(&default_config, &app);
    let config = Arc::new(Mutex::new(config_loaded));

    // ensure folder exists + push to UI
    {
        let mut cfg = config.lock().unwrap();

        if cfg.save_to_folder.trim().is_empty() {
            cfg.save_to_folder = default_config.save_to_folder.clone();
            save_config(&cfg);
        }

        let _ = std::fs::create_dir_all(&cfg.save_to_folder);
        app.set_download_folder(cfg.save_to_folder.clone().into());
    }

    // ===================== network change checks (using locked config) =====================
    let (current_broadcast_for_config, _current_gateway_for_config, lan_changed, selected_iface_for_ui) =
    {
        let cfg = config.lock().unwrap();
        if let Some(scale) = cfg.ui_scale { app.set_global_scale(scale); }
        let current_broadcast_for_config =
            get_broadcast_for_name(&interfaces, &cfg.selected_interface)
                .unwrap_or_else(|| state.get_broadcast_address());
        let current_gateway_for_config = get_gateway_for_adapter(&cfg.selected_interface);

        let lan_changed = cfg.last_broadcast != current_broadcast_for_config
            || cfg.last_gateway != current_gateway_for_config;

        (current_broadcast_for_config, current_gateway_for_config, lan_changed, cfg.selected_interface.clone())
    };

    app.set_changed_networks(lan_changed);
    state.set_broadcast_address(current_broadcast_for_config.clone());

    // reading saved port from config file
    {
        let saved_port = config.lock().unwrap().port;

        match saved_port {
            Some(port) => {
                match main_helpers::try_set_manual_port(&state, &config, port) {
                    Ok(_) => {
                        app.set_manual_port_mode(true);
                    }
                    Err(_) => {
                        //main_helpers::checking_ports(&state);
                        app.set_manual_port_mode(false);
                        app.invoke_show_temp_message(
                            format!("⚠️ Saved port {} was in use, switched to {}", port, state.get_port()).into()
                        );
                    }
                }
            }
            None => {
                //main_helpers::checking_ports(&state);
                app.set_manual_port_mode(false); // ✅ and this
            }
        }
    }

    app.set_show_welcome(first_run || lan_changed);
    app.set_selected_interface(selected_iface_for_ui.clone().into());
    app.set_broadcast_address(state.get_broadcast_address().into());

    if let Some(info) = interfaces.iter().find(|it| it.name == selected_iface_for_ui) {
        app.set_interface_status(info.status.clone().into());
    } else {
        app.set_interface_status("IfOperStatusDown".into());
    }

    //main_helpers::checking_ports(&state);

    app.set_ui_port(state.get_port() as i32);
    app.set_show_version(env!("CARGO_PKG_VERSION").into());

    {
        let weak = app.as_weak();
        std::thread::spawn(move || {
            if let Ok(Some(version)) = main_helpers::check_for_update() {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(app) = weak.upgrade() {
                        app.set_latest_version(version.into());
                        app.set_update_available(true);
                    }
                });
            }
        });
    }

    // ===================== UDP receiver =====================
    let sock = bind_single_port_socket(state.get_port())?;
    let running = Arc::new(AtomicBool::new(true));

    let _recv_handle = start_udp_receiver(
        Arc::clone(&sock),
        Arc::clone(&running),
        app.as_weak(),
        Arc::clone(&channel_mode),
        Arc::clone(&remote_windows_offers),
        Arc::clone(&remote_mobile_offers),
    );

    // ===================== Send button =====================
    {
        let st = Arc::clone(&state);
        let s = Arc::clone(&sock);
        let weak = app.as_weak();

        let offer_registry2 = Arc::clone(&offer_registry);
        let running2 = Arc::clone(&running);
        let file_offer_model2 = file_offer_model.clone();
        let model2 = model.clone();
        let config_for_commands = Arc::clone(&config);

        app.on_send_clicked(move || {
            let Some(app) = weak.upgrade() else { return; };

            let msg = app.get_input_text().to_string();
            let trimmed = msg.trim();

            if msg.eq_ignore_ascii_case("/exit") {
                app.invoke_append_message("🚪 Exiting in 1 seconds...".into());

                running2.store(false, Ordering::Relaxed);

                {
                    let mut reg = offer_registry2.lock().unwrap();
                    file_transfer_protocol::cleanup_temp_offers(&mut reg);
                    reg.clear();
                }
                file_transfer_protocol::cleanup_temp_uploads();
                file_offer_model2.set_vec(Vec::new());

                thread::spawn(|| {
                    sleep(Duration::from_secs(1));
                    let _ = crate::web_app::stop_web_server();
                    process::exit(0);
                });

                return;
            }

            if msg.eq_ignore_ascii_case("/clear") {
                model2.set_vec(Vec::new());
                app.set_input_text("".into());
                return;
            }

            if msg.eq_ignore_ascii_case("/secure") {
                app.set_public_secure_helper(true);
                app.set_channel_mode("host".into());
                app.invoke_change_channel_mode("host".into());
                app.invoke_request_open_create_or_join();
                app.set_input_text("".into());
                return;
            }

            if msg.eq_ignore_ascii_case("/disconnect") {
                app.invoke_disconnect_channel();
                app.set_input_text("".into());
                return;
            }

            if msg.eq_ignore_ascii_case("/webstop") {
                match web_app::stop_web_server() {
                    Ok(()) => {
                        app.set_web_session_active(false);
                        app.invoke_show_temp_message("🛑 Web session stopped".into());
                    }
                    Err(e) => {
                        app.invoke_show_temp_message(format!("❌ {e}").into());
                    }
                }
                app.set_input_text("".into());
                return;
            }

            if msg.eq_ignore_ascii_case("/webjoin") {
                match web_app::start_web_server() {
                    Ok(()) => {
                        app.set_web_session_active(true);
                        update_ui_qr_only(&app);
                        match crate::web_app::get_url_to_main() {
                            Some(url) => app.set_url_link(url.into()),
                            None => {}
                        }
                        app.invoke_show_temp_message("🌐 Web session started".into());
                    }
                    Err(e) => {
                        app.invoke_show_temp_message(format!("❌ {e}").into());
                    }
                }
                app.set_input_text("".into());
                return;
            }

            if msg.eq_ignore_ascii_case("/clearfiles") {
                cleanup_file_offers(&offer_registry2, Some(&file_offer_model2));
                app.set_input_text("".into());
                return;
            }

            if msg.eq_ignore_ascii_case("/clearall") {
                model2.set_vec(Vec::new());
                cleanup_file_offers(&offer_registry2, Some(&file_offer_model2));
                app.set_input_text("".into());
                return;
            }
            
            if trimmed.eq_ignore_ascii_case("/info") {
                let info = main_helpers::info_message();
                app.invoke_append_message(info.into());
                app.set_input_text("".into());
                return;
            }

            if trimmed.eq_ignore_ascii_case("/help") {
                let info = main_helpers::help_message();
                app.invoke_append_message(info.into());
                app.set_input_text("".into());
                return;
            }

            if trimmed.eq_ignore_ascii_case("/settings") {
                app.set_show_welcome(true);
                app.set_input_text("".into());
                return;
            }            

            if trimmed.eq_ignore_ascii_case("/restart") {
                main_helpers::restart_app_after_delay(900);
                app.set_input_text("".into());
                return;
            }  

            if msg.eq_ignore_ascii_case("/downloads") {
                match main_helpers::open_download_folder_from_config(&config_for_commands) {
                    Ok(()) => {
                        app.invoke_show_temp_message("📁 Download folder opened".into());
                    }
                    Err(e) => {
                        app.invoke_show_temp_message(format!("❌ {}", e).into());
                    }
                }

                app.set_input_text("".into());
                return;
            }

            if msg.eq_ignore_ascii_case("/rescale") {
                let current = app.get_global_scale();
                let next = if current > 0.90 { 0.85 }
                    else if current > 0.80 { 0.75 }
                    else { 1.0 };
                app.set_global_scale(next);
                app.set_input_text("".into());
                app.invoke_show_temp_message(format!("🔎 UI scale set to {:.2}", next).into());
                // Save to config  <-- add this block
                {
                    let mut cfg = config_for_commands.lock().unwrap();
                    cfg.ui_scale = Some(next);
                    save_config(&cfg);
                }
                return;
            }

            if trimmed.is_empty() {
                app.set_input_text("".into());
                return;
            }

            if let Some(channel) = secure_channel_code::get_active_channel() {
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

                let packet_mob =
                    phone_protocol::encrypt_message_phone(&channel.key, trimmed);
                let _ = broadcast_the_msg(&s, &st, &packet_mob);
            } else {
                if let Err(_e) = broadcast_the_msg(&s, &st, trimmed.as_bytes()) {
                    app.invoke_show_popupmsg();
                }
            }

            app.set_input_text("".into());
        });
    }

    // Second change_channel_mode handler
    {
        let weak = app.as_weak();
        let sock = Arc::clone(&sock);
        let state = Arc::clone(&state);
        let channel_mode = Arc::clone(&channel_mode);

        app.on_change_channel_mode(move |new_mode: slint::SharedString| {
            if let Some(app) = weak.upgrade() {
                let new_mode_str = new_mode.as_str();
                set_channel_mode_only(&channel_mode, new_mode_str);

                match new_mode_str {
                    "public" => {
                        secure_channel_code::destroy_channel();
                        app.set_host_PIN("N/A".into());
                        app.set_host_PIN_masked("N/A".into());
                        app.set_public_secure_helper(false);
                        app.set_web_join_enabled(true);
                    }
                    "host" => {
                        let _ = crate::web_app::stop_web_server(); // stop web join
                        app.set_web_join_enabled(false);           // disable button
                        app.set_web_session_active(false);
                        // sending a REQA here because when changing from public to secure the first thing it changes is this
                        const REQA_MAGIC: &[u8] = b"REQA";
                        if let Err(_e) = broadcast_the_msg(&sock, &state, REQA_MAGIC) {
                            app.invoke_show_popupmsg();
                        }
                    }
                    "joined" => {
                        let _ = crate::web_app::stop_web_server(); // stop web join
                        app.set_web_join_enabled(false);           // disable button
                        app.set_web_session_active(false); // just setting the web join active to false
                    }
                    _ => {}
                }
            }
        });
    }

    // Interface selected
    app.on_interface_selected({
        let state = Arc::clone(&state);
        let interfaces = interfaces.clone();
        let weak = app.as_weak();
        let config = Arc::clone(&config);

        move |iface_display: slint::SharedString| {
            if let Some(info) = interfaces.iter().find(|it| iface_display.contains(&it.name)) {
                state.set_broadcast_address(info.address_to_broadcast.clone());
                let gw = get_gateway_for_adapter(&info.name);

                {
                    let mut cfg = config.lock().unwrap();
                    cfg.selected_interface = info.name.clone();
                    cfg.last_broadcast = info.address_to_broadcast.clone();
                    cfg.last_gateway = gw;
                    save_config(&cfg);
                }

                if let Some(app) = weak.upgrade() {
                    app.set_selected_interface(info.name.clone().into());
                    app.set_broadcast_address(state.get_broadcast_address().into());
                    app.set_ui_port(state.get_port() as i32);
                    app.set_interface_status(info.status.clone().into());
                }
            }
        }
    });

    // Create channel
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

            secure_channel_code::generate_QR_code(None);
            if let Some(app) = weak.upgrade() {
                update_ui_PIN(&app);
            }
        });
    }

    // Generate new PIN
    {
        let st = Arc::clone(&state);
        let s = Arc::clone(&sock);
        let weak = app.as_weak();

        app.on_generate_new_PIN(move || {
            let channel = secure_channel_code::regenerate_PIN();

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

            secure_channel_code::generate_QR_code(None);
            if let Some(app) = weak.upgrade() {
                update_ui_PIN(&app);
            }
        });
    }

    // Disconnect channel
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

    // Join channel
    #[allow(nonstandard_style)]
    {
        let weak = app.as_weak();
        let channel_mode = Arc::clone(&channel_mode);
        app.on_join_channel(move |PIN: slint::SharedString| {
            if let Some(app) = weak.upgrade() {
                let join_PIN = PIN.to_string();
                //println!("{} this prints is from the main block in line 512 and above on a comment join channel", join_PIN);
                let success = secure_channel_code::join_with_PIN(&join_PIN);
                app.invoke_show_connecting_popup();
                if success {
                    secure_channel_code::play_ping_sound();
                    set_channel_mode_only(&channel_mode, "joined");
                    app.set_channel_mode("joined".into());
                    app.set_public_secure_helper(true);
                    app.invoke_hide_connecting_popup();
                    app.invoke_show_temp_message("✅ Joined secure channel successfully!".into());
                } else {
                    set_channel_mode_only(&channel_mode, "public");
                    app.invoke_hide_connecting_popup();
                    app.set_channel_mode("public".into());
                    app.set_public_secure_helper(false);
                    app.invoke_show_temp_message("❌ Incorrect PIN or no secure channel found.".into());
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

    // Fix bug button
    {
        let weak = app.as_weak();
        let channel_mode = Arc::clone(&channel_mode);

        app.on_fix_the_bug_please(move || {
            if let Some(app) = weak.upgrade() {
                force_switch_to_public(&app, &channel_mode);
            }
        });
    }

    // Exit app
    {
        app.on_exit_app(move || {
            crate::file_transfer_protocol::cleanup_temp_uploads();
            let _ = crate::web_app::stop_web_server();
            std::process::exit(0);
        });
    }

    // files button (broadcast FOFT)
    {
        let st = Arc::clone(&state);
        let s = Arc::clone(&sock);
        let weak = app.as_weak();
        let offer_registry = Arc::clone(&offer_registry);

        // ✅ guard lives next to the handler so it persists across clicks
        let is_picking_files = Arc::new(AtomicBool::new(false));

        app.on_pick_files_send(move || {
            let Some(app) = weak.upgrade() else { return; };
            // 🚫 block re-entry (prevents 2 dialogs / 2 bundle starts)
            if is_picking_files.swap(true, Ordering::SeqCst) {
                return;
            }
            // 🔁 call the async builder (opens dialog; returns Ready or Bundling)
            let build = {
                let mut reg = offer_registry.lock().unwrap();
                file_transfer_protocol::pick_and_build_foft_packet_async(&mut reg)
            };
            // ✅ IMPORTANT: dialog is closed now → allow clicking Files again
            is_picking_files.store(false, Ordering::SeqCst);

            let build = match build {
                Ok(b) => b,
                Err(e) => {
                    app.invoke_show_temp_message(format!("❌ {}", e).into());
                    return;
                }
            };

            match build {
                // NOTE: in this section it builds an FOFT and then decodes it and does an MFOFT made this so i can move on 
                // i want to work on something else so i am leaving it at that maybe if i wanted to i will change it and make
                // it more tidy
                file_transfer_protocol::BuildResult::Ready(packet) => {
                    // 1) broadcast FOFT (Windows)
                    if let Err(_e) = broadcast_the_msg(&s, &st, &packet) {
                        app.invoke_show_popupmsg();
                        return;
                    }
                    // 2) broadcast MFOFT (Android)
                    if let Some(offer) = crate::file_transfer_protocol::decode_foft(&packet) {
                        if let Ok(mfoft_packet) = crate::file_transfer_protocol::encode_mfoft_packet(&offer) {
                            let _ = broadcast_the_msg(&s, &st, &mfoft_packet);
                        }
                        crate::web_app_file_transfer::notify_web_file_offer(&offer.offer_id, &offer.name, offer.size);
                    }
                    app.invoke_show_temp_message("📤 File offer broadcasted".into());
                }
                file_transfer_protocol::BuildResult::Bundling { rx, handle: _handle, offer_id: _ } => {
                    // ✅ show immediate UI feedback
                    app.invoke_show_temp_message("🧵 Bundling files in background...".into());

                    // clone everything needed into a waiter thread
                    let offer_registry2 = Arc::clone(&offer_registry);
                    let s2 = Arc::clone(&s);
                    let st2 = Arc::clone(&st);
                    let weak2 = app.as_weak();

                    use std::time::{Duration, Instant};

                    std::thread::spawn(move || {
                            // auto-release slot when this thread exits (Finished / Error / recv Err / panic)
                            struct BundleSlotGuard;
                            impl Drop for BundleSlotGuard {
                                fn drop(&mut self) {
                                    file_transfer_protocol::bundle_slot_release();
                                }
                            }
                            let _slot_guard = BundleSlotGuard;
                        // show the bundling row immediately
                        {
                            let weak_ui = weak2.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                let Some(app) = weak_ui.upgrade() else { return; };
                                app.set_bundle_in_progress(true);
                                app.set_bundle_progress(0.0);
                                app.set_bundle_progress_text("Bundling…".into());
                            });
                        }

                        let mut last_ui = Instant::now();
                        let min_interval = Duration::from_millis(50); // ~20 FPS

                        loop {
                            match rx.recv() {
                                Ok(file_transfer_protocol::BundleEvent::Progress { done, total, current, .. }) => {
                                    // throttle UI updates
                                    if last_ui.elapsed() < min_interval {
                                        continue;
                                    }
                                    last_ui = Instant::now();

                                    let frac = if total == 0 {
                                        0.0
                                    } else {
                                        (done as f64 / total as f64).clamp(0.0, 1.0)
                                    };

                                    let fname = current
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();

                                    let text = format!(
                                        "Bundling… {:>5.1}%  {}  ({}/{})",
                                        frac * 100.0,
                                        fname,
                                        file_transfer_protocol::human_size(done),
                                        file_transfer_protocol::human_size(total),
                                    );

                                    let weak_ui = weak2.clone();
                                    let _ = slint::invoke_from_event_loop(move || {
                                        let Some(app) = weak_ui.upgrade() else { return; };
                                        app.set_bundle_in_progress(true);
                                        app.set_bundle_progress(frac as f32);
                                        app.set_bundle_progress_text(text.into());
                                    });
                                }

                                Ok(file_transfer_protocol::BundleEvent::Finished { offer_id, packet, local }) => {
                                    // temporary fix cause the local_size is gone afterwards i need to figure something out with this one to fix a problem with line 673
                                    let local_name = local.name.clone();
                                    let local_size = local.size;
                                    // insert into registry
                                    {
                                        let mut reg = offer_registry2.lock().unwrap();
                                        reg.insert(offer_id, local);
                                    }
                                    crate::web_app_file_transfer::notify_web_file_offer(&offer_id, &local_name, local_size);
                                    // NOTE: need work and tiding up this block also like the previous note i just want to move on maybe in the future
                                    //debug_print_foft_packet(&packet);
                                    let ok_foft = broadcast_the_msg(&s2, &st2, &packet).is_ok();
                                    // Also send Android offer (MFOFT) as "SingleFile" (Android expects that)
                                    let ok_mfoft = {
                                        let offer = crate::file_transfer_protocol::FileOffer {
                                            offer_id,
                                            name: local_name.clone(),
                                            size: local_size,
                                            kind: crate::file_transfer_protocol::OfferKind::SingleFile, // android limitation
                                            protocol_version: crate::file_transfer_protocol::FILE_PROTOCOL_VERSION,
                                            tcp_port: crate::file_transfer_protocol::DEFAULT_TCP_PORT,
                                        };

                                        match crate::file_transfer_protocol::encode_mfoft_packet(&offer) {
                                            Ok(p) => broadcast_the_msg(&s2, &st2, &p).is_ok(),
                                            Err(_) => false,
                                        }
                                    };

                                    let ok = ok_foft || ok_mfoft;

                                    let weak_ui = weak2.clone();
                                    let _ = slint::invoke_from_event_loop(move || {
                                        let Some(app) = weak_ui.upgrade() else { return; };

                                        // hide bundling row
                                        app.set_bundle_in_progress(false);
                                        app.set_bundle_progress(0.0);
                                        app.set_bundle_progress_text("".into());

                                        if ok {
                                            app.invoke_show_temp_message("📤 File offer (FOFT) broadcasted".into());
                                        } else {
                                            app.invoke_show_popupmsg();
                                        }
                                    });

                                    break;
                                }

                                Ok(file_transfer_protocol::BundleEvent::Error { message, .. }) => {
                                    let weak_ui = weak2.clone();
                                    let _ = slint::invoke_from_event_loop(move || {
                                        let Some(app) = weak_ui.upgrade() else { return; };

                                        // hide bundling row
                                        app.set_bundle_in_progress(false);
                                        app.set_bundle_progress(0.0);
                                        app.set_bundle_progress_text("".into());

                                        app.invoke_show_temp_message(format!("❌ ZIP failed: {}", message).into());
                                    });
                                    break;
                                }

                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        });
    }

    // Save to… button
    {
        let weak = app.as_weak();
        let config = Arc::clone(&config);

        app.on_pick_download_folder(move || {
            let Some(app) = weak.upgrade() else { return; };

            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                if let Err(e) = std::fs::create_dir_all(&folder) {
                    app.invoke_show_temp_message(
                        format!("❌ Failed to create folder: {}", e).into(),
                    );
                    return;
                }

                let folder_str = folder.display().to_string();

                {
                    let mut cfg = config.lock().unwrap();
                    cfg.save_to_folder = folder_str.clone();
                    save_config(&cfg);
                }

                app.set_download_folder(folder_str.into());
                app.invoke_show_temp_message("📁 Download folder updated".into());
            }
        });
    }

    // Open download folder button
    {
        let weak = app.as_weak();
        let config = Arc::clone(&config);

        app.on_open_download_folder(move || {
            let Some(app) = weak.upgrade() else { return; };

            match main_helpers::open_download_folder_from_config(&config) {
                Ok(()) => {
                    app.invoke_show_temp_message("📁 Download folder opened".into());
                }
                Err(e) => {
                    app.invoke_show_temp_message(format!("❌ {}", e).into());
                }
            }
        });
    }
    // download thread cap to two
    let download_semaphore: Arc<Semaphore<()>> = Arc::new(Semaphore::new(2, ()));
    // clicking download on a file transfer offer
    {
        let remote_windows_offers = Arc::clone(&remote_windows_offers);
        let remote_mobile_offers = Arc::clone(&remote_mobile_offers);
        let config = Arc::clone(&config);
        let weak = app.as_weak();
        let sem = Arc::clone(&download_semaphore);

        app.on_download_offer(move |offer_id_hex| {
            // check if it is a web upload
            if web_app_file_transfer::save_web_upload_to_folder(
                offer_id_hex.as_str(),
                &config.lock().unwrap().save_to_folder
            ) {
                let weak_ui = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(app) = weak_ui.upgrade() {
                        secure_channel_code::play_ping_sound();
                        app.invoke_show_temp_message("✅ File saved to download folder".into());
                    }
                });
                return;
            }
        // Try to take a slot (non-blocking)
            let permit = match sem.try_access() {
                Ok(guard) => guard, // SemaphoreGuard<()> held while download runs :contentReference[oaicite:3]{index=3}
                Err(_e) => {
                    let weak_ui = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = weak_ui.upgrade() {
                            app.invoke_show_temp_message("⚠️ Maximum 2 downloads at a time".into());
                        }
                    });
                    return;
                }
            };

            // 1) Lookup sender_ip + offer from remote_offers, and check if it is mobile or windows
            let mut is_mobile: bool = false;
            // println!(
            //     "[DL] clicked id={} windows_has={} mobile_has={}",
            //     offer_id_hex,
            //     remote_windows_offers.lock().unwrap().contains_key(offer_id_hex.as_str()),
            //     remote_mobile_offers.lock().unwrap().contains_key(offer_id_hex.as_str()),
            // );
            let (sender_ip, offer) = {
                // 1️⃣ try Windows offers first
                if let Some(v) = remote_windows_offers.lock().unwrap().get(offer_id_hex.as_str()).cloned()
                { v }
                // 2️⃣ try Mobile offers
                else if let Some(v) = remote_mobile_offers.lock().unwrap().get(offer_id_hex.as_str()).cloned()
                {
                    is_mobile = true; // ✅ mark as mobile
                    v
                }
                else {
                    return;
                }
            };
            let weak_ui = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = weak_ui.upgrade() {
                    app.invoke_show_temp_message("📱 Mobile download path triggered".into());
                }
            });
            // 3) Get download dir from config + build save path
            let save_path = main_helpers::build_download_save_path( &config, &offer.name, offer_id_hex.as_str(),);
            // if it is mobile go to another function to deal with it else just continue (it is like that so i don't rewrite the code when it works perfectly)
            if is_mobile {
                mobile_download::spawn_mobile_download( sender_ip, offer, offer_id_hex.to_string(), save_path, weak.clone(), permit, );
                return;
            }
            // 2) Convert offer_id_hex -> [u8;16]
            let offer_id = match file_transfer_protocol::hex_to_offer_id(offer_id_hex.as_str()) {
                Some(id) => id,
                None => {
                    //println!("[DOWNLOAD] bad offer id hex: {}", offer_id_hex);
                    // permit drops here automatically
                    return;
                }
            };

            //println!( "[DOWNLOAD] Requested {} from {}:{} → {}", offer.name, sender_ip, offer.tcp_port, save_path.display() );

            // 4) Spawn download thread
            let weak_ui_thread = weak.clone();
            let offer_id_str_thread = offer_id_hex.to_string();

            std::thread::spawn(move || {
                // Hold permit for entire download lifetime (IMPORTANT)
                let _permit = permit;

                let mut last_bucket: u32 = 999;

                // --- 0% immediately ---
                {
                    let weak_ui0 = weak_ui_thread.clone();
                    let offer_id0 = offer_id_str_thread.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = weak_ui0.upgrade() {
                            main_helpers::set_offer_progress_text(&app, &offer_id0, true, "0%");
                        }
                    });
                }

                // Clone for progress closure
                let weak_ui_progress = weak_ui_thread.clone();
                let offer_id_progress = offer_id_str_thread.clone();

                let res = crate::tcp_file_client::download_offer(
                    sender_ip,
                    offer.tcp_port,
                    offer_id,
                    save_path,
                    move |done, total| {
                        let bucket = main_helpers::progress_bucket_3(done, total);
                        if bucket == last_bucket { return; }
                        last_bucket = bucket;

                        let text = format!("{}%", bucket);

                        let weak_ui = weak_ui_progress.clone();
                        let offer_id = offer_id_progress.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak_ui.upgrade() {
                                main_helpers::set_offer_progress_text(&app, &offer_id, true, &text);
                            }
                        });
                    },
                );

                // Finish/error UI
                let weak_ui_done = weak_ui_thread.clone();
                let offer_id_done = offer_id_str_thread.clone();

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(app) = weak_ui_done.upgrade() {
                        match res {
                            Ok(_) => {
                                main_helpers::set_offer_progress_text(&app, &offer_id_done, false, "100%");
                                secure_channel_code::play_ping_sound();
                                app.invoke_show_temp_message("✅ Download complete".into());
                            }
                            Err(e) => {
                                main_helpers::set_offer_progress_text(&app, &offer_id_done, false, "ERR");
                                app.invoke_show_temp_message(format!("❌ Download failed: {}", e).into());
                            }
                        }
                    }
                });

                // when thread ends, _permit is dropped -> slot released
            });
        });
    }
    // web join button clicked
    {
        let weak = app.as_weak();

        app.on_web_join_clicked(move || {
            let Some(app) = weak.upgrade() else { return; };

            if crate::web_app::is_web_server_running() {
                match crate::web_app::stop_web_server() {
                    Ok(()) => {
                        app.set_web_session_active(false);
                        app.invoke_show_temp_message("🛑 Web Join server stopped".into());
                    }
                    Err(e) => {
                        app.invoke_show_temp_message(format!("❌ {e}").into());
                    }
                }
            } else {
                match crate::web_app::start_web_server() {
                    Ok(()) => {
                        app.set_web_session_active(true);
                        update_ui_qr_only(&app);

                        match crate::web_app::get_url_to_main() {
                            Some(url) => app.set_url_link(url.into()),
                            None => {
                                app.invoke_show_temp_message("❌ Failed to get URL".into());
                                return;
                            }
                        }

                        app.invoke_show_temp_message("🌐 Web Join server started".into());
                        app.invoke_show_web_join_popup();
                    }
                    Err(e) => {
                        app.invoke_show_temp_message(format!("❌ {e}").into());
                    }
                }
            }
        });
    }
    // copy clipboard for the web join clicked
    // Handles "Copy link" button in Web Join popup (copies URL to clipboard)
    {
        let weak = app.as_weak();

        app.on_copy_web_url(move || {
            let Some(app) = weak.upgrade() else { return; };

            let url = app.get_url_link().to_string();

            match arboard::Clipboard::new() {
                Ok(mut clipboard) => {
                    if clipboard.set_text(url).is_err() {
                        app.invoke_show_temp_message("❌ Failed to copy link".into());
                    }
                }
                Err(_) => {
                    app.invoke_show_temp_message("❌ Failed to access clipboard".into());
                }
            }
        });
    }
    // setting the port for UDP manually
    {        
        app.on_apply_manual_port({
            let state = Arc::clone(&state);
            let weak = app.as_weak();
            let config = Arc::clone(&config);
            move |port| {
                if let Some(app) = weak.upgrade() {
                    match main_helpers::try_set_manual_port(&state, &config, port as u16) {
                        Ok(p) => {
                            app.set_ui_port(p as i32);
                            app.set_port_status("✅ Port available".into());
                            app.invoke_show_temp_message(
                                format!("✅ Port set to {}. Restarting LanChGo...", p).into()
                            );

                            app.set_show_welcome(false);

                            main_helpers::restart_app_after_delay(900);
                        }
                        Err(e) => {
                            app.set_port_status(e.into());
                        }
                    }
                }
            }
        });
    }
    // reseting port setting to default (automatic)
    {
        app.on_reset_port_to_auto({
            let state = Arc::clone(&state);
            let weak = app.as_weak();
            let config = Arc::clone(&config);
            move || {
                main_helpers::reset_port_to_auto(&state, &config);
                if let Some(app) = weak.upgrade() {
                    app.set_ui_port(state.get_port() as i32);
                    app.set_port_status("".into());
                    app.set_manual_port_mode(false);
                    app.invoke_show_temp_message(
                        "🔄 Returning to automatic port mode... Restarting LanChGo.".into()
                    );
                    app.set_show_welcome(false);
                    main_helpers::restart_app_after_delay(900);
                }
            }
        });
    }

    // run
    app.run()?;
    running.store(false, Ordering::Relaxed);
    cleanup_file_offers(&offer_registry, Some(&file_offer_model));
    Ok(())
}
