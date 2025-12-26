use std::sync::{OnceLock, Mutex};
use crate::secure_channel_code::{ChannelAnnounce, SecureMessage, Channel};
use serde_json::Value;
use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key}};
use rand::rngs::OsRng;
use rand::TryRngCore;
//use std::time::{Instant, Duration};

static ANNOUNCE_STORE_PHONE: OnceLock<Mutex<Vec<ChannelAnnounce>>> = OnceLock::new();

pub fn store_announcement_phone(bytes: &[u8]) -> bool {
    if let Ok(json_str) = std::str::from_utf8(bytes) {
        match serde_json::from_str::<Value>(json_str) {
            Ok(v) => {
                // --- Extract salt ---
                let salt_vec = match &v["salt"] {
                    Value::Array(arr) => arr.iter().filter_map(|x| x.as_u64()).map(|x| x as u8).collect::<Vec<u8>>(),
                    Value::String(s) => b64.decode(s).unwrap_or_default(),
                    _ => Vec::new(),
                };

                // --- Extract validation object ---
                let val = &v["validation"];
                let nonce_vec = match &val["nonce"] {
                    Value::Array(arr) => arr.iter().filter_map(|x| x.as_u64()).map(|x| x as u8).collect::<Vec<u8>>(),
                    Value::String(s) => b64.decode(s).unwrap_or_default(),
                    _ => Vec::new(),
                };
                let ciphertext = match &val["ciphertext"] {
                    Value::Array(arr) => arr.iter().filter_map(|x| x.as_u64()).map(|x| x as u8).collect::<Vec<u8>>(),
                    Value::String(s) => b64.decode(s).unwrap_or_default(),
                    _ => Vec::new(),
                };

                if salt_vec.len() != 16 || nonce_vec.len() != 12 {
                    //eprintln!("⚠️ Invalid salt or nonce length in MANCH");
                    return false;
                }

                // --- Convert Vec<u8> → fixed-size arrays ---
                let salt: [u8; 16] = salt_vec.try_into().expect("salt length mismatch");
                let nonce: [u8; 12] = nonce_vec.try_into().expect("nonce length mismatch");

                // --- Build ChannelAnnounce struct ---
                let incoming = ChannelAnnounce {
                    salt,
                    validation: SecureMessage { nonce, ciphertext },
                };

                // --- Store without duplicates ---
                let store = ANNOUNCE_STORE_PHONE.get_or_init(|| Mutex::new(Vec::new()));
                let mut vec = store.lock().unwrap();
                if !vec.iter().any(|a| a.salt == incoming.salt) {
                    vec.push(incoming);
                    //println!("✅ Stored mobile ChannelAnnounce (JSON), total = {}", vec.len());
                } else {
                    //println!("⚠️ Duplicate MANCH ignored");
                }
                true
            }
            Err(_e) => {
                //eprintln!("❌ Failed to parse MANCH JSON: {:?}", e);
                false
            }
        }
    } else {
        //eprintln!("❌ MANCH data not valid UTF-8");
        false
    }
}

/// Try to find a mobile announcement that matches the provided PIN.
/// If found, returns (salt, key) as fixed-size arrays ready to use with Channel::new_join_channel.
pub fn try_find_matching_announce(pin: i32) -> Option<([u8;16], [u8;32])> {
    // get phone announce store (may be empty)
    let store = ANNOUNCE_STORE_PHONE.get_or_init(|| Mutex::new(Vec::new()));
    let announcements = store.lock().unwrap();

    // iterate newest-first, same as desktop logic
    for ann in announcements.iter().rev() {
        // derive key using same function as desktop
        let key = crate::secure_channel_code::derive_key(pin, &ann.salt);

        // validate by attempting to decrypt the validation message
        if let Some(plaintext) = crate::secure_channel_code::decrypt_message(&key, &ann.validation) {
            if plaintext == "SECURE_OK" {
                // convert salt ([u8;16]) and key ([u8;32]) types expected by Channel::new_join_channel
                let mut salt_arr: [u8; 16] = [0u8; 16];
                salt_arr.copy_from_slice(&ann.salt);

                let mut key_arr: [u8; 32] = [0u8; 32];
                key_arr.copy_from_slice(&key);

                return Some((salt_arr, key_arr));
            }
        }
    }
    None
}

/// Encrypt the message for the phone
pub fn encrypt_message_phone(key: &[u8; 32], msg_content: &str) -> Vec<u8> {
    use aes_gcm::aead::generic_array::GenericArray;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce_bytes).expect("RNG failed");

    let nonce = GenericArray::from_slice(&nonce_bytes); // ✅ fixed

    let ciphertext = cipher
        .encrypt(nonce, msg_content.as_bytes())
        .expect("encryption failed");

    // Combine into: [MENCM][nonce][ciphertext]
    let mut packet = Vec::from(b"MENCM" as &[u8]);
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);
    packet
}

/// Decrypt messages from phone
pub fn decrypt_message_phone(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Option<String> {
    use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, generic_array::GenericArray}};
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_arr = GenericArray::from_slice(nonce);
    match cipher.decrypt(nonce_arr, ciphertext) {
        Ok(plain) => String::from_utf8(plain).ok(),
        Err(_) => None,
    }
}

#[allow(non_snake_case)]
pub fn build_MANCH(channel: &Channel) -> Result<String, serde_json::Error> {
    let validation = encrypt_message_phone(&channel.key, "SECURE_OK");

    let json = serde_json::json!({
        "salt": b64.encode(&channel.salt),
        "validation": {
            "nonce": b64.encode(&validation[5..17]),
            "ciphertext": b64.encode(&validation[17..]),
        }
    });

    let json_str = serde_json::to_string(&json)?;
    //println!("🔧 MANCH JSON: {}", json_str);

    Ok(json_str)
}
