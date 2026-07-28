use enigo::{
    Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse,
};

pub struct TouchpadTranslator;

impl TouchpadTranslator {
    pub fn handle_packet(enigo: &mut Enigo, packet: &str) {
        let parts: Vec<&str> = packet.split_whitespace().collect();

        match parts.as_slice() {
            ["MOVE", x, y] => {
                if let (Ok(x), Ok(y)) = (x.parse::<f64>(), y.parse::<f64>()) {
                    let _ = enigo.move_mouse(x as i32, y as i32, Coordinate::Rel);
                }
            }

            ["LEFT_CLICK"] => {
                let _ = enigo.button(Button::Left, Direction::Click);
            }

            ["DOUBLE_CLICK"] => {
                let _ = enigo.button(Button::Left, Direction::Click);
                let _ = enigo.button(Button::Left, Direction::Click);
            }

            ["RIGHT_CLICK"] => {
                let _ = enigo.button(Button::Right, Direction::Click);
            }

            ["MIDDLE_CLICK"] => {
                let _ = enigo.button(Button::Middle, Direction::Click);
            }

            ["LONG_PRESS"] => {
                let _ = enigo.button(Button::Left, Direction::Press);
            }

            ["SCROLL_V", y] => {
                if let Ok(y) = y.parse::<f64>() {
                    let _ = enigo.scroll(-(y as i32), Axis::Vertical);
                }
            }

            ["SCROLL_H", x] => {
                if let Ok(x) = x.parse::<f64>() {
                    let _ = enigo.scroll(-(x as i32), Axis::Horizontal);
                }
            }

            ["ACTION_CENTER"] => {
                Self::shortcut(enigo, &[Key::Meta, Key::Unicode('a')]);
            }

            ["TASK_VIEW"] => {
                Self::shortcut(enigo, &[Key::Meta, Key::Tab]);
            }

            ["SHOW_DESKTOP"] => {
                Self::shortcut(enigo, &[Key::Meta, Key::Unicode('d')]);
            }

            ["SWITCH_APP_RIGHT"] => {
                Self::shortcut(enigo, &[Key::Alt, Key::Tab]);
            }

            ["SWITCH_APP_LEFT"] => {
                Self::shortcut(enigo, &[Key::Alt, Key::Shift, Key::Tab]);
            }

            _ => {}
        }
    }

    fn shortcut(enigo: &mut Enigo, keys: &[Key]) {
        for key in keys {
            let _ = enigo.key(*key, Direction::Press);
        }

        for key in keys.iter().rev() {
            let _ = enigo.key(*key, Direction::Release);
        }
    }

    pub fn release_all(enigo: &mut Enigo) {
        let _ = enigo.button(Button::Left, Direction::Release);
        let _ = enigo.button(Button::Right, Direction::Release);
        let _ = enigo.button(Button::Middle, Direction::Release);
    }
}
