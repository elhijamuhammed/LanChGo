use enigo::{Direction, Enigo, Key, Keyboard};

pub struct KeyboardTranslator;

impl KeyboardTranslator {
    pub fn handle_packet(enigo: &mut Enigo, packet: &str) {
        if let Some(text) = packet.strip_prefix("KEY_TEXT ") {
            Self::type_text(enigo, text);
            return;
        }

        if let Some(shortcut) = packet.strip_prefix("KEY_SHORTCUT ") {
            Self::handle_shortcut(enigo, shortcut);
            return;
        }

        match packet {
            "KEY_ENTER" => Self::tap(enigo, Key::Return),
            "KEY_BACKSPACE" => Self::tap(enigo, Key::Backspace),
            "KEY_TAB" => Self::tap(enigo, Key::Tab),
            "KEY_ESCAPE" | "KEY_ESC" => Self::tap(enigo, Key::Escape),
            "KEY_SPACE" => Self::tap(enigo, Key::Space),
            "KEY_DELETE" => Self::tap(enigo, Key::Delete),

            "KEY_LEFT" => Self::tap(enigo, Key::LeftArrow),
            "KEY_RIGHT" => Self::tap(enigo, Key::RightArrow),
            "KEY_UP" => Self::tap(enigo, Key::UpArrow),
            "KEY_DOWN" => Self::tap(enigo, Key::DownArrow),

            "KEY_CAPS_LOCK" => Self::tap(enigo, Key::CapsLock),

            "KEY_F1" => Self::tap(enigo, Key::F1),
            "KEY_F2" => Self::tap(enigo, Key::F2),
            "KEY_F3" => Self::tap(enigo, Key::F3),
            "KEY_F4" => Self::tap(enigo, Key::F4),
            "KEY_F5" => Self::tap(enigo, Key::F5),
            "KEY_F6" => Self::tap(enigo, Key::F6),
            "KEY_F7" => Self::tap(enigo, Key::F7),
            "KEY_F8" => Self::tap(enigo, Key::F8),
            "KEY_F9" => Self::tap(enigo, Key::F9),
            "KEY_F10" => Self::tap(enigo, Key::F10),
            "KEY_F11" => Self::tap(enigo, Key::F11),
            "KEY_F12" => Self::tap(enigo, Key::F12),

            _ => {}
        }
    }

    fn type_text(enigo: &mut Enigo, text: &str) {
        for ch in text.chars() {
            match ch {
                'A'..='Z' => {
                    Self::shift_char(enigo, ch.to_ascii_lowercase());
                }

                '!' => Self::shift_char(enigo, '1'),
                '@' => Self::shift_char(enigo, '2'),
                '#' => Self::shift_char(enigo, '3'),
                '$' => Self::shift_char(enigo, '4'),
                '%' => Self::shift_char(enigo, '5'),
                '^' => Self::shift_char(enigo, '6'),
                '&' => Self::shift_char(enigo, '7'),
                '*' => Self::shift_char(enigo, '8'),
                '(' => Self::shift_char(enigo, '9'),
                ')' => Self::shift_char(enigo, '0'),

                '_' => Self::shift_char(enigo, '-'),
                '+' => Self::shift_char(enigo, '='),
                '{' => Self::shift_char(enigo, '['),
                '}' => Self::shift_char(enigo, ']'),
                '|' => Self::shift_char(enigo, '\\'),
                ':' => Self::shift_char(enigo, ';'),
                '"' => Self::shift_char(enigo, '\''),
                '<' => Self::shift_char(enigo, ','),
                '>' => Self::shift_char(enigo, '.'),
                '?' => Self::shift_char(enigo, '/'),
                '~' => Self::shift_char(enigo, '`'),

                _ => {
                    let _ = enigo.key(Key::Unicode(ch), Direction::Click);
                }
            }
        }
    }

    fn shift_char(enigo: &mut Enigo, ch: char) {
        let _ = enigo.key(Key::Shift, Direction::Press);
        let _ = enigo.key(Key::Unicode(ch), Direction::Click);
        let _ = enigo.key(Key::Shift, Direction::Release);
    }

    fn handle_shortcut(enigo: &mut Enigo, shortcut: &str) {
        let keys: Vec<Key> = shortcut
            .split('+')
            .filter_map(|part| Self::key_from_name(part.trim()))
            .collect();

        if keys.is_empty() {
            return;
        }

        if keys.len() == 1 {
            let _ = enigo.key(keys[0], Direction::Click);
            return;
        }

        let modifiers = &keys[..keys.len() - 1];
        let main_key = keys[keys.len() - 1];

        for key in modifiers {
            let _ = enigo.key(*key, Direction::Press);
        }

        let _ = enigo.key(main_key, Direction::Click);

        for key in modifiers.iter().rev() {
            let _ = enigo.key(*key, Direction::Release);
        }
    }

    fn key_from_name(name: &str) -> Option<Key> {
        match name.to_uppercase().as_str() {
            "CTRL" | "CONTROL" => Some(Key::Control),
            "ALT" => Some(Key::Alt),
            "SHIFT" => Some(Key::Shift),
            "WIN" | "META" | "WINDOWS" => Some(Key::Meta),

            "ENTER" => Some(Key::Return),
            "BACKSPACE" => Some(Key::Backspace),
            "TAB" => Some(Key::Tab),
            "ESC" | "ESCAPE" => Some(Key::Escape),
            "SPACE" => Some(Key::Space),
            "DELETE" | "DEL" => Some(Key::Delete),

            "LEFT" => Some(Key::LeftArrow),
            "RIGHT" => Some(Key::RightArrow),
            "UP" => Some(Key::UpArrow),
            "DOWN" => Some(Key::DownArrow),

            "CAPS_LOCK" => Some(Key::CapsLock),

            "F1" => Some(Key::F1),
            "F2" => Some(Key::F2),
            "F3" => Some(Key::F3),
            "F4" => Some(Key::F4),
            "F5" => Some(Key::F5),
            "F6" => Some(Key::F6),
            "F7" => Some(Key::F7),
            "F8" => Some(Key::F8),
            "F9" => Some(Key::F9),
            "F10" => Some(Key::F10),
            "F11" => Some(Key::F11),
            "F12" => Some(Key::F12),

            single if single.chars().count() == 1 => {
                Some(Key::Unicode(single.chars().next()?))
            }

            _ => None,
        }
    }

    fn tap(enigo: &mut Enigo, key: Key) {
        let _ = enigo.key(key, Direction::Click);
    }

    pub fn release_all(enigo: &mut Enigo) {
        let _ = enigo.key(Key::Control, Direction::Release);
        let _ = enigo.key(Key::Alt, Direction::Release);
        let _ = enigo.key(Key::Shift, Direction::Release);
        let _ = enigo.key(Key::Meta, Direction::Release);
    }
}
