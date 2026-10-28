use crate::AppWindow;
use crate::file_transfer_protocol::RemoteMobileOfferRegistry;
use crate::file_transfer_protocol::RemoteWindowsOfferRegistry;
use crate::main_helpers;
use crate::phone_protocol;
use crate::secure_channel_code;
use bincode;
use slint;
use std::io;
use std::net::UdpSocket;
use std::sync::{ Arc, Mutex, atomic::{AtomicBool, Ordering}, };
use std::thread::{self, JoinHandle};
use crate::main_helpers::get_local_ipv4;
//use crate::file_transfer_protocol; // optional (you call it via crate::file_transfer_protocol::... but this is still fine)
//use crate::helpers::get_local_ipv4; // adjust path to wherever you moved get_local_ipv4()

pub fn start_udp_receiver( 
    sock: Arc<UdpSocket>,
    running: Arc<AtomicBool>, 
    ui_weak: slint::Weak<AppWindow>, 
    channel_mode: Arc<Mutex<String>>, 
    remote_windows_offers: Arc<Mutex<RemoteWindowsOfferRegistry>>,
    remote_mobile_offers: Arc <Mutex<RemoteMobileOfferRegistry>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let my_ip: Option<std::net::IpAddr> = get_local_ipv4().map(std::net::IpAddr::V4);

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
                                    continue;
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
                                            || !decrypted.eq_ignore_ascii_case("/clear")
                                            || !decrypted.eq_ignore_ascii_case( "   ")
                                            || !decrypted.eq_ignore_ascii_case( "/clearfiles")
                                            || !decrypted.eq_ignore_ascii_case( "/clearall")
                                            || !decrypted.eq_ignore_ascii_case( "/webjoin")                
                                            || !decrypted.eq_ignore_ascii_case( "/webstop")
                                            || !decrypted.eq_ignore_ascii_case( "/restart")
                                            || !decrypted.eq_ignore_ascii_case( "/downloads")
                                        {
                                            app.invoke_append_message(decrypted.into(),);
                                        }
                                    }
                                })
                                .ok();
                            }
                            continue; // Done with encrypted message
                        } else if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MENCM" {
                            if let Some(ip) = my_ip {
                                if _from.ip() == ip {
                                    continue;
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
                                                    && !plain.eq_ignore_ascii_case("/clear")
                                                    && !plain.eq_ignore_ascii_case("/disconnect")
                                                    && !plain.eq_ignore_ascii_case("/clearfiles")
                                                    && !plain.eq_ignore_ascii_case("/clearall")
                                                    && !plain.eq_ignore_ascii_case("/webjoin")
                                                    && !plain.eq_ignore_ascii_case("/webstop")
                                                    && !plain.eq_ignore_ascii_case("/restart")
                                                    && !plain.eq_ignore_ascii_case("/downloads")
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
                        } else if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"EFOFT" {
                            // encrypted FOFT (desktop file offer)
                            if let Some(channel) = secure_channel_code::get_active_channel() {
                                if let Some(foft_packet) = crate::file_transfer_protocol::decrypt_efoft(&channel.key, &msg_bytes[5..]) {
                                    if let Some(offer) = crate::file_transfer_protocol::decode_foft(&foft_packet) {
                                        main_helpers::handle_foft_offer(offer, _from.ip(), &remote_windows_offers, &ui_weak);
                                    }
                                }
                            }
                            continue;
                        } else if msg_bytes.len() >= 6 && &msg_bytes[..6] == b"EMFOFT" {
                            // encrypted MFOFT (phone file offer)
                            if let Some(ip) = my_ip { if _from.ip() == ip { continue; } }
                            if let Some(channel) = secure_channel_code::get_active_channel() {
                                if let Some(mfoft_json) = crate::file_transfer_protocol::decrypt_emfoft(&channel.key, &msg_bytes[6..]) {
                                    if let Some((offer, id_hex)) = crate::file_transfer_protocol::decode_mfoft(&mfoft_json) {
                                        main_helpers::handle_mfoft_offer(offer, id_hex, _from.ip(), &remote_windows_offers, &remote_mobile_offers, &ui_weak);
                                    }
                                }
                            }
                            continue;
                        } else if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"FOFR" {
                            // ignore FOFR in secure mode for now
                            continue;
                        } else if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MFOFT" {
                            continue;
                        } else if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MTOOL" {
                            continue;
                        }
                    }

                    // ─── Public Mode ──────────────────────────────────────────────────────
                    if mode == "public" {
                        // 1) Special handling for FOFR
                        if msg_bytes.len() >= 4 && &msg_bytes[..4] == b"FOFT" {
                            if let Some(offer) = crate::file_transfer_protocol::decode_foft(msg_bytes) {
                                main_helpers::handle_foft_offer(offer, _from.ip(), &remote_windows_offers, &ui_weak);
                            }
                            continue;
                        }

                        if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MFOFT" {
                            if let Some(ip) = my_ip { if _from.ip() == ip { continue; } }
                            if let Some((offer, id_hex)) = crate::file_transfer_protocol::decode_mfoft(&msg_bytes[5..]) {
                                main_helpers::handle_mfoft_offer(offer, id_hex, _from.ip(), &remote_windows_offers, &remote_mobile_offers, &ui_weak);
                            }
                            continue;
                        }
                        if msg_bytes.len() >= 5 && &msg_bytes[..5] == b"MTOOL" {
                            if let Some(ip) = my_ip {
                                if _from.ip() == ip {
                                    continue;
                                }
                            }
                            let payload = &msg_bytes[5..];
                            main_helpers::recieve_tools_packet( payload, _from.ip(), ui_weak.clone(), );
                            continue;
                        }
                        // 2️⃣ Normal text messages
                        if let Ok(raw) = String::from_utf8(msg_bytes.to_vec()) {
                            if raw.starts_with("POLL") {
                                //println!("POLL: Packet reached receiver");
                                main_helpers::handle_poll_packet(&raw, ui_weak.clone());
                                continue;
                            }
                            if raw.starts_with("VOTE") {
                                main_helpers::handle_vote_packet(&raw, ui_weak.clone());
                                continue;
                            }
                            if raw.starts_with("DNPL") {
                                main_helpers::handle_done_packet(&raw, ui_weak.clone());
                                continue;
                            }
                            //println!("{:?} this is the raw before parsing", raw);
                            // text without the sender tag, used only for the checks below
                            let msg = match main_helpers::parse_sender_tag(&raw) {Some(tagged) => tagged.text, None => raw.clone(),};
                            //println!("{:?} this is the msg after parsing", raw);
                            if msg.eq_ignore_ascii_case("ping") {
                                secure_channel_code::play_ping_sound();
                            } else if msg.to_ascii_lowercase().contains("nutella") {
                                main_helpers::play_nutella_sound();
                            }
                            if !msg.starts_with("/") && !msg.starts_with("MANCH") && !msg.starts_with("REQA") {
                                let weak = ui_weak.clone();
                                slint::invoke_from_event_loop(move || {
                                    if let Some(app) = weak.upgrade() {
                                        app.invoke_append_message(raw.into());
                                    }
                                })
                                .ok();
                            }
                        }
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => { /* Expected timeouts */ }
                Err(_e) => {break;}
            }
        }
    })
}
