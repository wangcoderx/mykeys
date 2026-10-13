use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};

fn main() {
    const HTML: &str = "MyKeys-2.0/index.html";
    const CONFIG: &str = "tauri.conf.json";
    println!("cargo:rerun-if-changed={HTML}");
    println!("cargo:rerun-if-changed={CONFIG}");

    let html = std::fs::read_to_string(HTML).expect("failed to read frontend HTML");
    let script = html
        .split_once("<script>")
        .and_then(|(_, rest)| rest.split_once("</script>"))
        .map(|(script, _)| script)
        .expect("frontend must contain one inline script");
    let digest = B64.encode(Sha256::digest(script.as_bytes()));
    let config = std::fs::read_to_string(CONFIG).expect("failed to read Tauri config");
    assert!(
        config.contains(&format!("'sha256-{digest}'")),
        "Tauri CSP script hash is stale; expected sha256-{digest}"
    );
    assert!(
        !config.contains("script-src 'self' 'unsafe-inline'"),
        "unsafe-inline scripts are forbidden"
    );
    tauri_build::build()
}
