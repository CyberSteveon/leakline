fn main() {
    let attributes = tauri_build::Attributes::new();
    // Tauri normally embeds this manifest only in application binaries.
    // Windows test executables also need Common Controls v6 to load.
    // https://github.com/tauri-apps/tauri/issues/13419
    #[cfg(windows)]
    let attributes = {
        let manifest = std::path::PathBuf::from(
            std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo package directory"),
        )
        .join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        attributes.windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest())
    };
    tauri_build::try_build(attributes).expect("Tauri build setup failed");
}
