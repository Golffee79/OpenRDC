// SPDX-License-Identifier: Apache-2.0
//! Server-level tests with fake backends (no X11 needed).
use axum_test::TestServer;
use openrdc_host::audit::Audit;
use openrdc_host::backends::{FrameStore, InputBackend, MonitorInfo, RawFrame, ScreenBackend};
use openrdc_host::capabilities::Capabilities;
use openrdc_host::server::{router, AppState};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct FakeScreen;
struct FakeInput;
/// Returns a zero-size frame (F19 path).
struct ZeroScreen;

impl ScreenBackend for FakeScreen {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn monitors(&self) -> Result<Vec<MonitorInfo>, String> {
        Ok(vec![MonitorInfo {
            monitor_id: "m0".into(),
            source_width: 800,
            source_height: 600,
            is_primary: true,
        }])
    }
    fn capture(&self, _m: Option<&str>) -> Result<RawFrame, String> {
        Ok(RawFrame {
            monitor_id: "m0".into(),
            source_width: 800,
            source_height: 600,
            rgba: [128, 64, 32, 255].repeat(800 * 600),
        })
    }
}

impl ScreenBackend for ZeroScreen {
    fn name(&self) -> &'static str {
        "fake-zero"
    }
    fn monitors(&self) -> Result<Vec<MonitorInfo>, String> {
        Ok(vec![])
    }
    fn capture(&self, _m: Option<&str>) -> Result<RawFrame, String> {
        Ok(RawFrame {
            monitor_id: "m0".into(),
            source_width: 0,
            source_height: 0,
            rgba: vec![],
        })
    }
}

impl InputBackend for FakeInput {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn click(&self, _x: u32, _y: u32, _b: &str) -> Result<(), String> {
        Ok(())
    }
    fn type_text(&self, _t: &str) -> Result<(), String> {
        Ok(())
    }
    fn press(&self, k: &str, _m: &[String]) -> Result<(), String> {
        if k == "Nope" {
            return Err("unknown key: Nope".into());
        }
        Ok(())
    }
}

fn server_with(granted: &str, screen: Box<dyn ScreenBackend>) -> (TestServer, PathBuf) {
    let p = std::env::temp_dir().join(format!("openrdc-it-{}.jsonl", uuid::Uuid::new_v4()));
    let state = Arc::new(AppState {
        caps: Capabilities::load_json(granted).unwrap(),
        audit: Audit::open(p.clone()).unwrap(),
        frames: FrameStore::new(),
        token: "test-token".into(),
        screen,
        input: Box::new(FakeInput),
        input_hits: Mutex::new(vec![]),
        capture_hits: Mutex::new(vec![]),
    });
    (TestServer::new(router(state)).unwrap(), p)
}

fn server(granted: &str) -> (TestServer, PathBuf) {
    server_with(granted, Box::new(FakeScreen))
}

/// Parse error envelope; assert the same request_id appears in the audit log.
fn assert_rid_audited(audit: &PathBuf, v: &serde_json::Value) -> String {
    let rid = v
        .get("error")
        .and_then(|e| e.get("request_id"))
        .and_then(|r| r.as_str())
        .expect("error envelope must carry request_id")
        .to_string();
    let content = std::fs::read_to_string(audit).unwrap();
    assert!(
        content.lines().any(|l| l.contains(&rid)),
        "request_id {rid} must appear in audit log"
    );
    rid
}

fn audit_records(audit: &PathBuf) -> Vec<serde_json::Value> {
    std::fs::read_to_string(audit)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn health_needs_no_auth() {
    let (s, _) = server(r#"{"granted":[]}"#);
    s.get("/health").await.assert_status_ok();
}

#[tokio::test]
async fn no_token_is_401() {
    let (s, _) = server(r#"{"granted":[]}"#);
    s.get("/v1/system").await.assert_status_unauthorized();
}

#[tokio::test]
async fn wrong_token_is_401() {
    let (s, _) = server(r#"{"granted":[]}"#);
    s.get("/v1/system")
        .add_header("authorization", "Bearer wrong")
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn system_reports_metadata() {
    let (s, _) = server(r#"{"granted":["screen.capture"]}"#);
    let v: serde_json::Value = s
        .get("/v1/system")
        .add_header("authorization", "Bearer test-token")
        .await
        .json();
    assert_eq!(v["protocol_version"], "1.0");
    assert_eq!(v["granted"], serde_json::json!(["screen.capture"]));
    assert_eq!(v["features"]["approval"], false);
}

#[tokio::test]
async fn missing_capability_is_403_and_audited() {
    let (s, audit) = server(r#"{"granted":[]}"#);
    let r = s
        .post("/v1/screen/capture")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({}))
        .await;
    r.assert_status_forbidden();
    let v: serde_json::Value = r.json();
    assert_eq!(v["error"]["code"], "forbidden_capability");
    assert_rid_audited(&audit, &v);
}

#[tokio::test]
async fn capture_then_click_frame_coords() {
    let (s, _) = server(r#"{"granted":["screen.capture","mouse.click"]}"#);
    let cap: serde_json::Value = s
        .post("/v1/screen/capture")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"max_width": 400}))
        .await
        .json();
    assert_eq!(cap["source_width"], 800);
    assert_eq!(cap["output_width"], 400);
    let fid = cap["frame_id"].as_str().unwrap();
    // Out-of-bounds in frame space.
    s.post("/v1/mouse/click")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"frame_id": fid, "x": 9999, "y": 0}))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);
    // Stale frame.
    s.post("/v1/mouse/click")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"frame_id": "00000000-0000-0000-0000-000000000000", "x": 1, "y": 1}))
        .await
        .assert_status(axum::http::StatusCode::GONE);
    // Valid click.
    s.post("/v1/mouse/click")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"frame_id": fid, "x": 10, "y": 10}))
        .await
        .assert_status_ok();
}

/// F3 adversarial: every modifier-bearing combo needs .dangerous.
#[tokio::test]
async fn any_modifier_needs_dangerous_capability() {
    let (s, audit) = server(r#"{"granted":["keyboard.press"]}"#);
    let cases = vec![
        ("Tab", vec!["alt"]),            // Alt+Tab
        ("t", vec!["ctrl", "alt"]),      // Ctrl+Alt+T
        ("w", vec!["ctrl"]),             // Ctrl+W
        ("q", vec!["ctrl"]),             // Ctrl+Q
        ("Q", vec!["ctrl", "shift"]),    // Ctrl+Shift+Q
        ("F4", vec!["alt"]),             // Alt+F4
        ("Delete", vec!["alt", "ctrl"]), // reordered Ctrl+Alt+Del
        ("q", vec!["ctrl", "ctrl"]),     // duplicate modifiers
        ("Enter", vec!["shift"]),        // even shifted Enter
    ];
    for (key, mods) in cases {
        let r = s
            .post("/v1/keyboard/press")
            .add_header("authorization", "Bearer test-token")
            .json(&serde_json::json!({"key": key, "modifiers": mods}))
            .await;
        r.assert_status_forbidden();
        let v: serde_json::Value = r.json();
        assert_eq!(v["error"]["code"], "forbidden_capability", "key={key}");
        assert_rid_audited(&audit, &v);
    }
    // Modifier-free keys still work with plain keyboard.press.
    for key in ["Enter", "Tab", "Escape"] {
        s.post("/v1/keyboard/press")
            .add_header("authorization", "Bearer test-token")
            .json(&serde_json::json!({"key": key}))
            .await
            .assert_status_ok();
    }
}

#[tokio::test]
async fn modifiers_allowed_with_dangerous_grant_and_audited() {
    let (s, audit) = server(r#"{"granted":["keyboard.press","keyboard.press.dangerous"]}"#);
    s.post("/v1/keyboard/press")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"key": "Tab", "modifiers": ["alt"]}))
        .await
        .assert_status_ok();
    // Audit records key AND modifiers (F9).
    let recs = audit_records(&audit);
    let last = recs.last().unwrap();
    assert_eq!(last["method"], "keyboard.press");
    assert_eq!(last["params_redacted"]["key"], "Tab");
    assert_eq!(
        last["params_redacted"]["modifiers"],
        serde_json::json!(["alt"])
    );
    // approval_id still rejected.
    let r = s
        .post("/v1/keyboard/press")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"key": "Enter", "approval_id": "forged"}))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn non_string_modifiers_rejected_and_audited() {
    let (s, audit) = server(r#"{"granted":["keyboard.press","keyboard.press.dangerous"]}"#);
    for body in [
        serde_json::json!({"key": "q", "modifiers": ["ctrl", 42]}),
        serde_json::json!({"key": "q", "modifiers": "ctrl"}),
        serde_json::json!({"key": "q", "modifiers": [null]}),
    ] {
        let r = s
            .post("/v1/keyboard/press")
            .add_header("authorization", "Bearer test-token")
            .json(&body)
            .await;
        r.assert_status(axum::http::StatusCode::BAD_REQUEST);
        let v: serde_json::Value = r.json();
        assert_rid_audited(&audit, &v);
    }
}

#[tokio::test]
async fn unknown_key_is_400_and_audited() {
    let (s, audit) = server(r#"{"granted":["keyboard.press"]}"#);
    let r = s
        .post("/v1/keyboard/press")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"key": "Nope"}))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
    let v: serde_json::Value = r.json();
    assert_rid_audited(&audit, &v);
}

#[tokio::test]
async fn huge_coordinates_rejected_before_cast() {
    let (s, audit) = server(r#"{"granted":["screen.capture","mouse.click"]}"#);
    let cap: serde_json::Value = s
        .post("/v1/screen/capture")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({}))
        .await
        .json();
    let fid = cap["frame_id"].as_str().unwrap();
    let r = s
        .post("/v1/mouse/click")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"frame_id": fid, "x": 4294967296u64, "y": 0}))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
    let v: serde_json::Value = r.json();
    assert_rid_audited(&audit, &v);
}

#[tokio::test]
async fn zero_size_frame_rejected() {
    let (s, audit) = server_with(r#"{"granted":["screen.capture"]}"#, Box::new(ZeroScreen));
    let r = s
        .post("/v1/screen/capture")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({}))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
    let v: serde_json::Value = r.json();
    assert_rid_audited(&audit, &v);
}

#[tokio::test]
async fn oversized_body_rejected() {
    let (s, _) = server(r#"{"granted":["keyboard.type"]}"#);
    let r = s
        .post("/v1/keyboard/type")
        .add_header("authorization", "Bearer test-token")
        .text("x".repeat(70 * 1024))
        .await;
    r.assert_status(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn oob_click_and_bad_text_audited_with_rid() {
    let (s, audit) = server(r#"{"granted":["screen.capture","mouse.click","keyboard.type"]}"#);
    let cap: serde_json::Value = s
        .post("/v1/screen/capture")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({}))
        .await
        .json();
    let fid = cap["frame_id"].as_str().unwrap();
    let r = s
        .post("/v1/mouse/click")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"frame_id": fid, "x": 99999, "y": 0}))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_rid_audited(&audit, &r.json());
    let r = s
        .post("/v1/keyboard/type")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"text": "x".repeat(1025)}))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
    let v: serde_json::Value = r.json();
    let rid = assert_rid_audited(&audit, &v);
    // The oversized text itself must not appear in the audit log.
    let content = std::fs::read_to_string(&audit).unwrap();
    assert!(!content.contains(&"x".repeat(1025)));
    let _ = rid;
}

#[tokio::test]
async fn type_limits_and_malformed() {
    let (s, _) = server(r#"{"granted":["keyboard.type"]}"#);
    // malformed
    s.post("/v1/keyboard/type")
        .add_header("authorization", "Bearer test-token")
        .text("not json{{{")
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);
    // ok
    s.post("/v1/keyboard/type")
        .add_header("authorization", "Bearer test-token")
        .json(&serde_json::json!({"text": "hello"}))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn rate_limit_triggers() {
    let (s, _) = server(r#"{"granted":["keyboard.type"]}"#);
    let mut limited = false;
    for _ in 0..25 {
        let r = s
            .post("/v1/keyboard/type")
            .add_header("authorization", "Bearer test-token")
            .json(&serde_json::json!({"text": "hi"}))
            .await;
        if r.status_code() == axum::http::StatusCode::TOO_MANY_REQUESTS {
            let v: serde_json::Value = r.json();
            assert_eq!(v["error"]["code"], "rate_limited");
            limited = true;
            break;
        }
    }
    assert!(limited, "expected rate_limited within 25 rapid requests");
}
