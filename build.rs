fn main() {
    let version = std::fs::read_to_string("VERSION")
        .map(|raw| raw.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string())
        });
    println!("cargo:rustc-env=MAXIO_VERSION={version}");
    println!("cargo:rerun-if-changed=VERSION");
}
