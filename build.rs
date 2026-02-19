fn main() {
    // --- Slint UI build step ---
    slint_build::compile("ui/app-window.slint")
        .expect("Slint build failed");

    // --- Windows resources (icon + version info) ---
    #[cfg(target_os = "windows")]
    {
        embed_resource::compile("app_icon.rc", embed_resource::NONE);
    }
}