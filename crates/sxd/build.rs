//! Build script: on macOS, compile the LocalAuthentication ObjC shim and link
//! the frameworks it needs. No-op on other platforms.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        cc::Build::new()
            .file("src/touchid.m")
            .flag("-fobjc-arc")
            .compile("sxtouchid");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rerun-if-changed=src/touchid.m");
    }
}
