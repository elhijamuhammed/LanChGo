use enigo::{Enigo, Settings};

use super::keyboard_translator::KeyboardTranslator;
use super::touchpad_translator::TouchpadTranslator;

pub struct ToolsActionTranslator {
    enigo: Enigo,
}

impl ToolsActionTranslator {
    pub fn new() -> Self {
        Self {
            enigo: Enigo::new(&Settings::default()).unwrap(),
        }
    }

    pub fn handle_packet(&mut self, raw: &str) {
        let raw = raw.trim();

        if raw.is_empty() {
            return;
        }

        // Strip sequence number — format is "seq:PACKET_DATA"
        let packet = match raw.split_once(':') {
            Some((seq_str, data)) => {
                match seq_str.parse::<u16>() {
                    Ok(_) => data, // valid sequence number, use the data part
                    Err(_) => raw, // no valid sequence number, use raw (fallback)
                }
            }
            None => raw, // no colon at all, use raw (fallback)
        };

        if packet.is_empty() {
            return;
        }

        if packet.starts_with("KEY_") {
            KeyboardTranslator::handle_packet(&mut self.enigo, packet);
        } else {
            TouchpadTranslator::handle_packet(&mut self.enigo, packet);
        }
    }

    pub fn release_all(&mut self) {
        TouchpadTranslator::release_all(&mut self.enigo);
        KeyboardTranslator::release_all(&mut self.enigo);
    }
}
