// Tools/tools_handshake.rs

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use sha2::{Sha256, Digest};
use rand::Rng;
use serde::{Deserialize, Serialize};

// ── Trusted devices file ───────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct TrustedDevices {
    devices: HashMap<String, String>, // device_id → secret_hex
}

fn trusted_devices_path() -> PathBuf {
    dirs::data_dir()
        .unwrap()
        .join("LanChGoApp")
        .join("trusted_devices.json")
}

fn load_trusted_devices() -> TrustedDevices {
    let path = trusted_devices_path();
    if !path.exists() {
        return TrustedDevices::default();
    }
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            println!("[TOOLS] Failed to open trusted_devices.json: {}", e);
            return TrustedDevices::default();
        }
    };
    serde_json::from_reader(file).unwrap_or_default()
}

fn save_trusted_devices(trusted: &TrustedDevices) {
    let path = trusted_devices_path();

    // Ensure the directory exists
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(e) => {
            println!("[TOOLS] Failed to save trusted_devices.json: {}", e);
            return;
        }
    };
    if let Err(e) = serde_json::to_writer_pretty(file, trusted) {
        println!("[TOOLS] Failed to write trusted_devices.json: {}", e);
    }
}

fn load_secret(device_id: &str) -> Option<Vec<u8>> {
    let trusted = load_trusted_devices();
    trusted
        .devices
        .get(device_id)
        .and_then(|hex| hex::decode(hex).ok())
}

fn store_secret(device_id: &str, secret: &[u8]) {
    let mut trusted = load_trusted_devices();
    trusted
        .devices
        .insert(device_id.to_string(), hex::encode(secret));
    save_trusted_devices(&trusted);
}

fn is_paired(device_id: &str) -> bool {
    load_trusted_devices().devices.contains_key(device_id)
}

// ── Handshake result ───────────────────────────────────────────────────────

pub enum HandshakeResult {
    Ok {
        device_id: String,
        secret: Vec<u8>,
    },
    Rejected,
}

// ── Main handshake ─────────────────────────────────────────────────────────

pub fn perform_handshake(stream: &mut TcpStream) -> HandshakeResult {
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            println!("[TOOLS] Handshake: failed to clone stream: {}", e);
            return HandshakeResult::Rejected;
        }
    };
    let mut reader = BufReader::new(reader_stream);

    // ── Step 1: Read HELLO <device_id> ────────────────────────────────────
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        println!("[TOOLS] Handshake: no HELLO received");
        return HandshakeResult::Rejected;
    }

    let device_id = match line.trim().strip_prefix("HELLO ") {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            println!("[TOOLS] Handshake: invalid HELLO: {}", line.trim());
            let _ = stream.write_all(b"REJECTED\n");
            return HandshakeResult::Rejected;
        }
    };

    println!("[TOOLS] Handshake: device identified: {}", device_id);

    // ── Step 2: Generate and send CHALLENGE <32_random_bytes_hex> ─────────
    let challenge: Vec<u8> = rand::rng()
        .sample_iter(rand::distr::StandardUniform)
        .take(32)
        .collect();
    let challenge_hex = hex::encode(&challenge);

    if stream
        .write_all(format!("CHALLENGE {}\n", challenge_hex).as_bytes())
        .is_err()
    {
        println!("[TOOLS] Handshake: failed to send challenge");
        return HandshakeResult::Rejected;
    }

    // ── Step 3: Read RESPONSE <hash> ──────────────────────────────────────
    let mut response_line = String::new();
    if reader.read_line(&mut response_line).unwrap_or(0) == 0 {
        println!("[TOOLS] Handshake: no RESPONSE received");
        return HandshakeResult::Rejected;
    }

    let received_hash = match response_line.trim().strip_prefix("RESPONSE ") {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => {
            println!(
                "[TOOLS] Handshake: invalid RESPONSE: {}",
                response_line.trim()
            );
            let _ = stream.write_all(b"REJECTED\n");
            return HandshakeResult::Rejected;
        }
    };

    // ── Step 4: Verify or pair ─────────────────────────────────────────────
    if is_paired(&device_id) {
        // Known device — verify hash(device_id + challenge + secret)
        let secret = load_secret(&device_id).unwrap();
        let expected = compute_hash(&device_id, &challenge, &secret);

        if received_hash != expected {
            println!(
                "[TOOLS] Handshake: wrong response from {} — rejected",
                device_id
            );
            let _ = stream.write_all(b"REJECTED\n");
            return HandshakeResult::Rejected;
        }

        println!(
            "[TOOLS] Handshake: trusted device authenticated: {}",
            device_id
        );
        let _ = stream.write_all(b"SESSION_OK\n");

        HandshakeResult::Ok { device_id, secret }
    } else {
        // New device — first pairing
        // PC generates secret, stores it, sends it to phone once
        let secret: Vec<u8> = rand::rng()
            .sample_iter(rand::distr::StandardUniform)
            .take(32)
            .collect();
        let secret_hex = hex::encode(&secret);

        store_secret(&device_id, &secret);

        println!(
            "[TOOLS] Handshake: new device paired: {}",
            device_id
        );

        if stream
            .write_all(format!("PAIRED {}\n", secret_hex).as_bytes())
            .is_err()
        {
            println!("[TOOLS] Handshake: failed to send PAIRED secret");
            // Device is stored but phone didn't get the secret
            // Remove it so they can retry cleanly next connection
            let mut trusted = load_trusted_devices();
            trusted.devices.remove(&device_id);
            save_trusted_devices(&trusted);
            return HandshakeResult::Rejected;
        }

        HandshakeResult::Ok { device_id, secret }
    }
}

// ── Hash helper ────────────────────────────────────────────────────────────
// sha256(device_id_bytes + challenge_bytes + secret_bytes)

fn compute_hash(device_id: &str, challenge: &[u8], secret: &[u8]) -> String {
    let challenge_hex = hex::encode(challenge);
    let secret_hex = hex::encode(secret);

    let input = format!("{}{}{}", device_id, challenge_hex, secret_hex);

    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());

    hex::encode(hasher.finalize())
}
