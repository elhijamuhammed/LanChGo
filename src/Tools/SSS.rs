// pub fn open_window(window: &slint::Weak<SSSWindow>, device_name: &str) {
//     let w = window.clone();
//     let name = device_name.to_string();
//     let _ = slint::invoke_from_event_loop(move || {
//         if let Some(win) = w.upgrade() {
//             win.set_device_name(name.into());
//             win.set_streaming(false);
//             let _ = win.show();
//         }
//     });
// }

// pub fn close_window(window: &slint::Weak<SSSWindow>) {
//     let w = window.clone();
//     let _ = slint::invoke_from_event_loop(move || {
//         if let Some(win) = w.upgrade() {
//             let _ = win.hide();
//         }
//     });
// }
