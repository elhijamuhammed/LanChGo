fn main() {
    let config = slint_build::CompilerConfiguration::new()
        .with_library_paths(std::collections::HashMap::from([(
            "material".to_string(),
            std::path::Path::new(
                &std::env::var_os("CARGO_MANIFEST_DIR").unwrap(),
            )
            .join("material-1.0/material.slint"),
        )]));

    slint_build::compile_with_config("ui/app-window.slint", config).unwrap();

    // Set the Windows executable icon
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();

        res.set_icon(
            std::path::Path::new(
                &std::env::var_os("CARGO_MANIFEST_DIR").unwrap(),
            )
            .join("ui/assets/LanChGo_icon.ico")
            .to_str()
            .unwrap(),
        );

        res.compile().unwrap();
    }
}
