use tray_icon::{TrayIconBuilder, TrayIcon, menu::{Menu, MenuItem, MenuEvent}};

pub fn setup_tray( on_open: impl Fn() + Send + 'static, on_exit: impl Fn() + Send + 'static, ) -> TrayIcon {
    let tray_menu = Menu::new();
    let open_item = MenuItem::new("Open LanChGo", true, None);
    let exit_item = MenuItem::new("Exit", true, None);
    tray_menu.append(&open_item).unwrap();
    tray_menu.append(&exit_item).unwrap();

    let icon_bytes = include_bytes!("../ui/assets/LanChGo_icon.png");
    let icon_image = image::load_from_memory(icon_bytes).unwrap().to_rgba8();
    let (w, h) = icon_image.dimensions();
    let tray_icon_img = tray_icon::Icon::from_rgba(icon_image.into_raw(), w, h).unwrap();

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("LanChGo")
        .with_icon(tray_icon_img)
        .build()
        .unwrap();

    let open_item_id = open_item.id().clone();
    let exit_item_id = exit_item.id().clone();

    std::thread::spawn(move || {
        loop {
            if let Ok(event) = MenuEvent::receiver().recv() {
                if event.id == exit_item_id {
                    on_exit();
                } else if event.id == open_item_id {
                    on_open();
                }
            }
        }
    });

    tray
}
