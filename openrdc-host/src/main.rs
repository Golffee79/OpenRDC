// SPDX-License-Identifier: Apache-2.0
use openrdc_host::audit::Audit;
use openrdc_host::backends::x11::{X11Input, X11Screen};
use openrdc_host::backends::FrameStore;
use openrdc_host::capabilities::Capabilities;
use openrdc_host::server::{router, AppState};
use openrdc_host::token;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn arg(name: &str, def: &str) -> String {
    let mut it = std::env::args().skip(1).peekable();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().unwrap_or_else(|| def.into());
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return v.to_string();
        }
    }
    def.into()
}

#[tokio::main]
async fn main() {
    // F5: exact hash-chain verifier using the same canonical serialization
    // as the writer. Exit 0 iff non-empty and valid.
    if std::env::args().any(|a| a == "--verify") {
        let file = arg("--audit", "/tmp/openrdc-audit.jsonl");
        let (n, ok) = Audit::verify(PathBuf::from(&file).as_path());
        println!("records={n} chain_valid={ok}");
        std::process::exit(if ok && n > 0 { 0 } else { 1 });
    }
    let port: u16 = arg("--port", "18789").parse().unwrap_or(18789);
    let caps_file = arg("--caps", "configs/host.capabilities.example.json");
    let audit_file = arg("--audit", "/tmp/openrdc-audit.jsonl");
    // Fail closed: an unreadable/invalid capability file must never boot a
    // zero-grant host. Use an absolute --caps path under daemons whose cwd
    // is not the repo (e.g. start-stop-daemon chdirs to /).
    let caps = match Capabilities::load_file(PathBuf::from(&caps_file).as_path()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("refusing to start: capability file: {e}");
            std::process::exit(1);
        }
    };
    let audit = Audit::open(PathBuf::from(&audit_file)).expect("audit open");
    // Token errors never include token material (see token::TokenError).
    let token_path = token::token_path();
    let tok = match token::load_or_mint(&token_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("refusing to start: {e}");
            std::process::exit(1);
        }
    };
    // F18: a host that cannot drive input must not serve callers.
    let input: Box<dyn openrdc_host::backends::InputBackend> = match X11Input::new() {
        Ok(i) => Box::new(i),
        Err(e) => {
            eprintln!("refusing to start: input backend unavailable ({e})");
            std::process::exit(1);
        }
    };
    let state = Arc::new(AppState {
        caps,
        audit,
        frames: FrameStore::new(),
        token: tok,
        screen: Box::new(X11Screen),
        input,
        input_hits: Mutex::new(vec![]),
        capture_hits: Mutex::new(vec![]),
    });
    // ponytail: loopback-only listener; token auth is the real boundary, not the interface.
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind");
    eprintln!("openrdc-host on 127.0.0.1:{port}");
    axum::serve(listener, app).await.expect("serve");
}
