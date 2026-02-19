#![allow(nonstandard_style)]

use rand::{Rng, rngs::OsRng, TryRngCore};
use std::sync::{Mutex, OnceLock};
use std::io::Cursor;
use rodio::{Decoder, OutputStreamBuilder, Sink};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
use serde::{Serialize, Deserialize};
use std::time::{Instant, Duration};
use qrcode::QrCode;
use image::{Luma, DynamicImage, ImageFormat};
use slint::{Image, SharedPixelBuffer};
use image::{GenericImageView};

static HOST_PIN: OnceLock<Mutex<Option<i32>>> = OnceLock::new();
static ACTIVE_CHANNEL: OnceLock<Mutex<Option<Channel>>> = OnceLock::new();
static BRUTE_FORCE_STATE: OnceLock<Mutex<BruteForceTracker>> = OnceLock::new();
const VALIDATION_TEXT: &str = "SECURE_OK";
/// To hold the QR code for the PIN
static QR_IMAGE_BYTES: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
/// Global store for channel announcements (for joiners)
static ANNOUNCE_STORE: OnceLock<Mutex<Vec<ChannelAnnounce>>> = OnceLock::new();
static PING_BYTES: &[u8] = include_bytes!("../Ping.ogg");

/// Channel struct
#[derive(Debug, Clone)]
pub struct Channel {
    pub salt: [u8; 16],
    pub key: [u8; 32],
    pub counter: u64,
}

impl Channel {
    pub fn new(PIN: i32) -> Self {
        let salt = generate_salt();
        let key = derive_key(PIN, &salt);
        Self { salt, counter: 0, key }
    }

    pub fn new_join_channel(salt: &[u8; 16], key: &[u8; 32]) -> Self {
        Self { salt: *salt, counter: 0, key: *key }
    }

    pub fn clear(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
        self.counter = 0;
    }
}

/// Message struct
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecureMessage {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChannelAnnounce {
    pub salt: [u8; 16],            // random salt for key derivation
    pub validation: SecureMessage, // encrypted "SECURE_OK"
}

struct BruteForceTracker {
    failed_attempts: u32,
    last_attempt: Instant,
    locked_until: Option<Instant>,
}

impl BruteForceTracker {
    fn new() -> Self {
        Self {
            failed_attempts: 0,
            last_attempt: Instant::now(),
            locked_until: None,
        }
    }
}

/// Encrypt and Decrypt
pub fn encrypt_message(key: &[u8; 32], msg_content: &str) -> SecureMessage {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce_bytes).expect("RNG failed");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, msg_content.as_bytes())
        .expect("encryption failed");
    SecureMessage { nonce: nonce_bytes, ciphertext }
}

pub fn decrypt_message(key: &[u8], secure_msg: &SecureMessage) -> Option<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&secure_msg.nonce);

    match cipher.decrypt(nonce, secure_msg.ciphertext.as_ref()) {
        Ok(plaintext_bytes) => String::from_utf8(plaintext_bytes).ok(),
        Err(_e) => {
            //eprintln!("❌ Decryption failed: {:?}", e);
            None
        }
    }
}

pub fn decrypt_message_from_bytes(bytes: &[u8]) -> Option<String> {
    let channel = get_active_channel()?;

    let decoded = bincode::serde::decode_from_slice::<SecureMessage, _>(
        bytes,
        bincode::config::standard(),
    );

    match decoded {
        Ok((secure_msg, _)) => decrypt_message(&channel.key, &secure_msg),
        Err(_e) => {
            //eprintln!("❌ Failed to decode SecureMessage: {:?}", e);
            None
        }
    }
}

/// Generate PIN
pub fn generate_PIN() -> i32 {
    let PIN = rand::rng().random_range(10_000_000..100_000_000);
    let lock = HOST_PIN.get_or_init(|| Mutex::new(None));
    *lock.lock().unwrap() = Some(PIN);
    //println!("Generated PIN: {PIN}");
    PIN
}

/// Getting the PIN
pub fn get_host_PIN() -> Option<i32> {
    HOST_PIN.get().and_then(|lock| *lock.lock().unwrap())
}

pub fn get_host_PIN_string() -> String {
    get_host_PIN().map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string())
}

pub fn get_masked_host_PIN() -> Option<String> {
    get_host_PIN().map(|p| {
        let s = p.to_string();
        format!("****{}", &s[s.len()-4..])
    })
}

/// New PIN and channel
pub fn regenerate_PIN() -> Channel {
    let mut guard = ACTIVE_CHANNEL.get_or_init(|| Mutex::new(None)).lock().unwrap();
    if let Some(mut old) = guard.take() {
        old.clear();
        drop(old);
        //println!("Old channel cleared!");
    }

    let PIN = generate_PIN();
    let new_channel = Channel::new(PIN);
    *guard = Some(new_channel.clone());
    //println!("New channel created with PIN {PIN}");
    new_channel
}

/// Helpers
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt).expect("RNG failed");
    salt
}

pub fn derive_key(PIN: i32, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(PIN.to_string().as_bytes(), salt, 100_000, &mut key);
    key
}

/// Create a channel (host side)
pub fn create_new_channel() -> Channel {
    let PIN = generate_PIN();
    let channel = Channel::new(PIN);

    let mut guard = ACTIVE_CHANNEL.get_or_init(|| Mutex::new(None)).lock().unwrap();
    *guard = Some(channel.clone());

    //println!("✅ Channel created: PIN {PIN}");
    channel
}

pub fn get_active_channel() -> Option<Channel> {
    let val = ACTIVE_CHANNEL.get().and_then(|lock| lock.lock().unwrap().clone());
    //println!("📦 get_active_channel: {:?}", val.is_some());
    val
}

/// Drop the active channel and clear the PIN
pub fn destroy_channel() {
    if let Some(lock) = ACTIVE_CHANNEL.get() {
        let mut guard = lock.lock().unwrap();
        if let Some(ch) = guard.as_mut() {
            ch.clear();
        }
        *guard = None;
    }

    if let Some(lock) = HOST_PIN.get() {
        *lock.lock().unwrap() = None;
    }

    //println!("🔓 Switched to Public: channel + PIN destroyed");
}

/// Build announcement (host side)
pub fn build_announcement(channel: &Channel) -> ChannelAnnounce {
    let validation = encrypt_message(&channel.key, VALIDATION_TEXT);
    ChannelAnnounce {
        salt: channel.salt,
        validation,
    }
}

/// Decode & store full ChannelAnnounce only if it’s not already in the store
pub fn store_announcement(bytes: &[u8]) -> bool {
    match bincode::serde::decode_from_slice::<ChannelAnnounce, _>(
        bytes,
        bincode::config::standard(),
    ) {
        Ok((incoming, _)) => {
            let store = ANNOUNCE_STORE.get_or_init(|| Mutex::new(Vec::new()));
            let mut vec = store.lock().unwrap();

            // 🔍 Check if an announcement with the same salt already exists
            let already_exists = vec.iter().any(|existing| existing.salt == incoming.salt);

            if !already_exists {
                vec.push(incoming);
                //println!("✅ Stored a new ChannelAnnounce, total stored = {}", vec.len());
            } else {
                //println!("⚠️ Skipped duplicate ChannelAnnounce");
            }

            true
        }
        Err(_e) => {
            //eprintln!("⚠️ Failed to decode ChannelAnnounce: {:?}", e);
            false
        }
    }
}

/// Try to validate PIN against stored ChannelAnnounce list
pub fn join_with_PIN(str_PIN: &str) -> bool {
    let now = Instant::now();

    let tracker = BRUTE_FORCE_STATE.get_or_init(|| Mutex::new(BruteForceTracker::new()));
    let mut guard = tracker.lock().unwrap();

    // 🚫 Check if locked
    if let Some(until) = guard.locked_until {
        if now < until {
            return false;
        } else {
            guard.locked_until = None;
            guard.failed_attempts = 0;
        }
    }

    guard.last_attempt = now;

    let Ok(in_PIN) = str_PIN.trim().parse::<i32>() else {
        guard.failed_attempts += 1;
        return false;
    };

    // 1) Check desktop ANNOUNCE_STORE first (existing behavior)
    {
        let store = ANNOUNCE_STORE.get_or_init(|| Mutex::new(Vec::new()));
        let announcements = store.lock().unwrap();

        if !announcements.is_empty() {
            for ann in announcements.iter().rev() {
                let key = derive_key(in_PIN, &ann.salt);
                if key_is_good(&key, ann) {
                    let channel = Channel::new_join_channel(&ann.salt, &key);
                    let mut active = ACTIVE_CHANNEL
                        .get_or_init(|| Mutex::new(None))
                        .lock()
                        .unwrap();
                    *active = Some(channel);

                    // reset brute-force tracker
                    guard.failed_attempts = 0;
                    guard.locked_until = None;
                    return true;
                }
            }
        }
    }

    // 2) If desktop announcement check failed, try phone announcements
    //    (calls into phone_protocol which returns salt+key if matched)
    if let Some((salt_arr, key_arr)) = crate::phone_protocol::try_find_matching_announce(in_PIN) {
        let channel = Channel::new_join_channel(&salt_arr, &key_arr);
        let mut active = ACTIVE_CHANNEL
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap();
        *active = Some(channel);

        // reset brute-force tracker
        guard.failed_attempts = 0;
        guard.locked_until = None;
        return true;
    }

    // ❌ Failed PIN
    guard.failed_attempts += 1;

    if guard.failed_attempts >= 3 {
        guard.locked_until = Some(Instant::now() + Duration::from_secs(10));
    }
    false
}

/// Validate derived key by decrypting ChannelAnnounce.validation
fn key_is_good(key: &[u8; 32], announce: &ChannelAnnounce) -> bool {
    if let Some(plaintext) = decrypt_message(key, &announce.validation) {
        if plaintext == VALIDATION_TEXT {
            return true;
        }
    }
    false
}

/// Easter Egg: play the embedded ping sound (non-blocking)
pub fn play_ping_sound() {
    if let Ok(builder) = OutputStreamBuilder::from_default_device() {
        if let Ok(stream) = builder.open_stream() {
            let mixer = stream.mixer();
            let sink = Sink::connect_new(&mixer);

            let cursor = Cursor::new(PING_BYTES);
            if let Ok(source) = Decoder::new(cursor) {
                sink.append(source);
                sink.detach();
            }
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(2));
                drop(stream);
            });
        }
    }
}

pub fn generate_QR_code() {
    if let Some(PIN) = get_host_PIN() {
        // Convert PIN to string
        let pin_str = PIN.to_string();

        // Generate QR code (standard error correction)
        let qr_code = QrCode::new(pin_str.as_bytes()).unwrap();

        // Render at 250x250 pixels
        let qr_image = qr_code
            .render::<Luma<u8>>()
            .min_dimensions(250, 250)
            .build();

        // Convert to PNG bytes
        let mut byte_vec = Vec::new();
        let dynamic_image = DynamicImage::ImageLuma8(qr_image);
        dynamic_image
            .write_to(&mut Cursor::new(&mut byte_vec), ImageFormat::Png)
            .unwrap();

        // Store globally
        let lock = QR_IMAGE_BYTES.get_or_init(|| Mutex::new(None));
        *lock.lock().unwrap() = Some(byte_vec);
    } else {
        //println!("Error: Host PIN is not available.");
    }
}

pub fn get_QR_image_data() -> Option<Vec<u8>> {
    QR_IMAGE_BYTES
        .get()
        .and_then(|lock| lock.lock().ok()?.clone())
}

pub fn get_QR_slint_image() -> Option<Image> {
    let bytes = get_QR_image_data()?;          // get the PNG bytes we stored earlier
    let img = image::load_from_memory(&bytes).ok()?; // decode the PNG
    let rgba = img.to_rgba8();
    let (width, height) = img.dimensions();

    let buffer = SharedPixelBuffer::clone_from_slice(rgba.as_raw(), width, height);
    Some(Image::from_rgba8(buffer))
}
