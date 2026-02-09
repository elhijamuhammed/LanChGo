use crate::AppWindow;
use crate::FileOfferItem;
use crate::file_transfer_protocol::RemoteWindowsOfferRegistry;
use crate::main_helpers;
use crate::phone_protocol;
use crate::secure_channel_code;
//use crate::file_transfer_protocol; // optional (you call it via crate::file_transfer_protocol::... but this is still fine)
//use crate::helpers::get_local_ipv4; // adjust path to wherever you moved get_local_ipv4()
use bincode;
use slint;
use std::io;
use std::net::UdpSocket;
use std::sync::{ Arc, Mutex, atomic::{AtomicBool, Ordering}, };
use std::thread::{self, JoinHandle};
use crate::main_helpers::get_local_ipv4;

pub fn start_udp_receiver( sock: Arc<UdpSocket>, running: Arc<AtomicBool>, ui_weak: slint::Weak<AppWindow>, 
    channel_mode: Arc<Mutex<String>>, remote_offers: Arc<Mutex<RemoteWindowsOfferRegistry>>,) -> JoinHandle<()> {
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
                                        } else if decrypted.to_ascii_lowercase().contains("nutella") {
                                            main_helpers::play_nutella_sound();
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
                                                } else if plain.to_ascii_lowercase().contains("nutella") {
                                                    main_helpers::play_nutella_sound();
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
                        if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"FOFT" {
                            if let Some(offer) = crate::file_transfer_protocol::decode_foft(msg_bytes) {
                                let id_hex =
                                    crate::file_transfer_protocol::offer_id_to_hex(&offer.offer_id);
                                let sender_ip = _from.ip();

                                {
                                    let mut reg = remote_offers.lock().unwrap();
                                    reg.insert(id_hex.clone(), (sender_ip, offer.clone()));
                                }

                                let weak = ui_weak.clone();

                                // ✅ truncate using helper
                                let display_name =
                                    crate::file_transfer_protocol::truncate_name(&offer.name, 16);

                                let size_text =
                                    crate::file_transfer_protocol::human_size(offer.size);

                                slint::invoke_from_event_loop(move || {
                                    if let Some(app) = weak.upgrade() {
                                        let item = FileOfferItem {
                                            offer_id: id_hex.into(),
                                            name: display_name.into(),
                                            size_text: size_text.into(),
                                            is_downloading: false,
                                            progress_text: "".into(),
                                        };

                                        app.invoke_add_file_offer(item);
                                    }
                                })
                                .ok();
                            }

                            continue;
                        }

                        if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MFOFT" {
                            let payload = &msg_bytes[5..];

                            if let Some((offer, id_hex)) = crate::file_transfer_protocol::decode_mfoft(payload) {
                                let sender_ip = _from.ip();

                                let is_new = crate::file_transfer_protocol::register_remote_offer(
                                    &remote_offers,
                                    sender_ip,
                                    id_hex.clone(),
                                    offer.clone(),
                                );

                                if !is_new {
                                    continue; // duplicate MFOFT, don't spam UI
                                }

                                let weak = ui_weak.clone();
                                let display_name =
                                    crate::file_transfer_protocol::truncate_name(&offer.name, 16);
                                let size_text =
                                    crate::file_transfer_protocol::human_size(offer.size);

                                slint::invoke_from_event_loop(move || {
                                    if let Some(app) = weak.upgrade() {
                                        app.invoke_add_file_offer(FileOfferItem {
                                            offer_id: id_hex.into(),
                                            name: display_name.into(),
                                            size_text: size_text.into(),
                                            is_downloading: false,
                                            progress_text: "".into(),
                                        });
                                    }
                                })
                                .ok();
                            }

                            continue;
                        }

                        // 2️⃣ Normal text messages
                        if let Ok(msg) = String::from_utf8(msg_bytes.to_vec()) {
                            if msg.eq_ignore_ascii_case("ping") {
                                secure_channel_code::play_ping_sound();
                            } else if msg.to_ascii_lowercase().contains("nutella") {
                                main_helpers::play_nutella_sound();
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
