// SPDX-License-Identifier: Apache-2.0
use crate::audit::Audit;
use crate::backends::{FrameMeta, FrameStore, InputBackend, ScreenBackend};
use crate::capabilities::Capabilities;
use crate::error::err;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use image::RgbaImage;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

/// Max HTTP request body for M0 (requests are small JSON; images flow out).
pub const MAX_BODY_BYTES: u64 = 64 * 1024;

pub struct AppState {
    pub caps: Capabilities,
    pub audit: Audit,
    pub frames: FrameStore,
    pub token: String,
    pub screen: Box<dyn ScreenBackend>,
    pub input: Box<dyn InputBackend>,
    pub input_hits: Mutex<Vec<Instant>>,
    pub capture_hits: Mutex<Vec<Instant>>,
}

pub type Shared = Arc<AppState>;

/// Auth + declared body-size guard. Runs before routing into handlers.
/// A tower-http `RequestBodyLimitLayer` (installed in `router`) backstops
/// chunked/missing-length bodies that dodge the header check.
async fn guard(State(s): State<Shared>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }
    let rid = Uuid::new_v4().to_string();
    let ok = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {}", s.token))
        .unwrap_or(false);
    if !ok {
        let _ = s
            .audit
            .record(&rid, "auth", json!({}), "deny", "unauthorized");
        return err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "bad or missing token".into(),
            false,
            &rid,
        );
    }
    if let Some(len) = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len > MAX_BODY_BYTES {
            let _ = s.audit.record(
                &rid,
                req.uri().path(),
                json!({"content_length": len}),
                "deny",
                "body_too_large",
            );
            return err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "bad_argument",
                "body too large".into(),
                false,
                &rid,
            );
        }
    }
    next.run(req).await
}

fn rate_hit(slot: &Mutex<Vec<Instant>>, max: usize, window_ms: u64) -> bool {
    let mut v = slot.lock().unwrap();
    let now = Instant::now();
    v.retain(|t| now.duration_since(*t).as_millis() < window_ms as u128);
    if v.len() >= max {
        return false;
    }
    v.push(now);
    true
}

/// Common deny path: audit first; if the audit itself fails, fail closed.
/// Returns the response to send. `rid` is reused for the error envelope (F12).
fn deny(s: &Shared, rid: &str, method: &str, params: serde_json::Value, reason: &str) -> Response {
    if s.audit.record(rid, method, params, "deny", reason).is_err() {
        eprintln!("audit write failed for deny({method})");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "audit unavailable".into(),
            false,
            rid,
        );
    }
    err(
        StatusCode::FORBIDDEN,
        "forbidden_capability",
        reason.into(),
        false,
        rid,
    )
}

/// Common failure path for validation errors on privileged routes: audited,
/// same request_id in log and envelope.
fn fail(s: &Shared, rid: &str, method: &str, params: serde_json::Value, reason: &str) -> Response {
    if s.audit.record(rid, method, params, "deny", reason).is_err() {
        eprintln!("audit write failed for fail({method})");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "audit unavailable".into(),
            false,
            rid,
        );
    }
    err(
        StatusCode::BAD_REQUEST,
        "bad_argument",
        reason.into(),
        false,
        rid,
    )
}

/// M0 rule: ANY modifier-bearing press requires keyboard.press.dangerous.
/// Modifier-free keys need only keyboard.press. No shortcut deny-list.
fn needs_dangerous(mods: &[String]) -> bool {
    !mods.is_empty()
}

/// Strict modifier parsing: field must be absent or an array of strings.
/// Anything else is bad_argument (never silently coerced).
fn parse_modifiers(v: &serde_json::Value) -> Result<Vec<String>, &'static str> {
    match v.get("modifiers") {
        None => Ok(vec![]),
        Some(arr) => {
            let a = arr.as_array().ok_or("modifiers must be an array")?;
            a.iter()
                .map(|m| match m.as_str() {
                    Some(s) if matches!(s, "ctrl" | "shift" | "alt") => Ok(s.to_string()),
                    Some(_) => Err("bad modifier"),
                    None => Err("modifiers must be strings"),
                })
                .collect::<Result<Vec<_>, _>>()
        }
    }
}

pub fn router(s: Shared) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"ok": true, "version": "0.1.0"})) }),
        )
        .route("/v1/system", get(system))
        .route("/v1/capabilities", get(caps))
        .route("/v1/screen/capture", post(capture))
        .route("/v1/mouse/click", post(click))
        .route("/v1/keyboard/type", post(type_text))
        .route("/v1/keyboard/press", post(press))
        .layer(middleware::from_fn_with_state(s.clone(), guard))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_BODY_BYTES as usize,
        ))
        .with_state(s)
}

async fn system(State(s): State<Shared>) -> impl IntoResponse {
    Json(json!({
        "protocol_version": "1.0",
        "platform": "linux-x11",
        "backend": {"screen": s.screen.name(), "input": s.input.name()},
        "granted": s.caps.list(),
        "features": {"multi_monitor": true, "approval": false, "approval_id_accepted": false},
    }))
}

async fn caps(State(s): State<Shared>) -> impl IntoResponse {
    Json(json!({"granted": s.caps.list()}))
}

async fn capture(State(s): State<Shared>, body: axum::body::Bytes) -> Response {
    let rid = Uuid::new_v4().to_string();
    if !s.caps.allows("screen.capture") {
        return deny(
            &s,
            &rid,
            "screen.capture",
            json!({}),
            "capability not granted",
        );
    }
    if !rate_hit(&s.capture_hits, 5, 1000) {
        let _ = s
            .audit
            .record(&rid, "screen.capture", json!({}), "deny", "rate_limited");
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "slow down".into(),
            true,
            &rid,
        );
    }
    let v: serde_json::Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                return fail(&s, &rid, "screen.capture", json!({}), "malformed JSON");
            }
        }
    };
    if v.get("approval_id").is_some() {
        return fail(
            &s,
            &rid,
            "screen.capture",
            json!({}),
            "approval_id not accepted in M0",
        );
    }
    let monitor_id = v.get("monitor_id").and_then(|x| x.as_str());
    let max_width = v
        .get("max_width")
        .and_then(|x| x.as_u64())
        .unwrap_or(1280)
        .clamp(320, 3840) as u32;
    let raw = match s.screen.capture(monitor_id) {
        Ok(r) => r,
        Err(e) => {
            let _ = s
                .audit
                .record(&rid, "screen.capture", json!({}), "deny", &e);
            return err(StatusCode::BAD_GATEWAY, "capture_failed", e, true, &rid);
        }
    };
    if raw.source_width == 0 || raw.source_height == 0 {
        return fail(
            &s,
            &rid,
            "screen.capture",
            json!({"monitor_id": raw.monitor_id}),
            "zero-size frame",
        );
    }
    let scale = (max_width as f64 / raw.source_width as f64).min(1.0);
    let (ow, oh) = (
        (raw.source_width as f64 * scale).round() as u32,
        (raw.source_height as f64 * scale).round() as u32,
    );
    let img: RgbaImage = RgbaImage::from_raw(raw.source_width, raw.source_height, raw.rgba)
        .unwrap_or_else(|| RgbaImage::new(raw.source_width, raw.source_height));
    let small = image::imageops::resize(&img, ow, oh, image::imageops::FilterType::Triangle);
    let mut png = Vec::new();
    let mut cur = std::io::Cursor::new(&mut png);
    if image::DynamicImage::ImageRgba8(small)
        .write_to(&mut cur, image::ImageFormat::Png)
        .is_err()
    {
        let _ = s
            .audit
            .record(&rid, "screen.capture", json!({}), "deny", "encode failed");
        return err(
            StatusCode::BAD_GATEWAY,
            "capture_failed",
            "encode failed".into(),
            true,
            &rid,
        );
    }
    let monitors: Vec<_> = s
        .screen
        .monitors()
        .unwrap_or_default()
        .iter()
        .map(|m| {
            json!({"monitor_id": m.monitor_id, "source_width": m.source_width, "source_height": m.source_height, "is_primary": m.is_primary})
        })
        .collect();
    let fid = s.frames.insert(FrameMeta {
        monitor_id: raw.monitor_id.clone(),
        source_width: raw.source_width,
        source_height: raw.source_height,
        output_width: ow,
        output_height: oh,
        scale,
        created: Instant::now(),
    });
    if s.audit
        .record(
            &rid,
            "screen.capture",
            json!({"frame_id": fid, "monitor_id": raw.monitor_id}),
            "allow",
            "ok",
        )
        .is_err()
    {
        eprintln!("audit write failed for allow(screen.capture)");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "audit unavailable".into(),
            false,
            &rid,
        );
    }
    Json(json!({
        "frame_id": fid, "monitor_id": raw.monitor_id,
        "source_width": raw.source_width, "source_height": raw.source_height,
        "output_width": ow, "output_height": oh, "scale": scale,
        "image_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &png),
        "mime": "image/png", "monitors": monitors,
    }))
    .into_response()
}

async fn click(State(s): State<Shared>, body: axum::body::Bytes) -> Response {
    let rid = Uuid::new_v4().to_string();
    let v: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(&s, &rid, "mouse.click", json!({}), "malformed JSON"),
    };
    if v.get("approval_id").is_some() {
        return fail(
            &s,
            &rid,
            "mouse.click",
            json!({}),
            "approval_id not accepted in M0",
        );
    }
    let (fid, x, y) = match (
        v.get("frame_id").and_then(|x| x.as_str()),
        v.get("x").and_then(|x| x.as_u64()),
        v.get("y").and_then(|x| x.as_u64()),
    ) {
        (Some(fid), Some(x), Some(y)) => (fid, x, y),
        _ => return fail(&s, &rid, "mouse.click", json!({}), "need frame_id, x, y"),
    };
    if x > u32::MAX as u64 || y > u32::MAX as u64 {
        return fail(
            &s,
            &rid,
            "mouse.click",
            json!({"frame_id": fid}),
            "out of bounds",
        );
    }
    let button = v.get("button").and_then(|x| x.as_str()).unwrap_or("left");
    if !matches!(button, "left" | "right" | "middle") {
        return fail(
            &s,
            &rid,
            "mouse.click",
            json!({"frame_id": fid}),
            "bad button",
        );
    }
    if !s.caps.allows("mouse.click") {
        return deny(
            &s,
            &rid,
            "mouse.click",
            json!({"frame_id": fid}),
            "capability not granted",
        );
    }
    if !rate_hit(&s.input_hits, 10, 1000) {
        let _ = s.audit.record(
            &rid,
            "mouse.click",
            json!({"frame_id": fid}),
            "deny",
            "rate_limited",
        );
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "slow down".into(),
            true,
            &rid,
        );
    }
    let Some(meta) = s.frames.get(fid) else {
        let _ = s.audit.record(
            &rid,
            "mouse.click",
            json!({"frame_id": fid}),
            "deny",
            "stale_frame",
        );
        return err(
            StatusCode::GONE,
            "stale_frame",
            "re-capture first".into(),
            true,
            &rid,
        );
    };
    let Some((nx, ny)) = FrameStore::to_native(&meta, x as u32, y as u32) else {
        return fail(
            &s,
            &rid,
            "mouse.click",
            json!({"frame_id": fid, "x": x, "y": y}),
            "out of bounds",
        );
    };
    match s.input.click(nx, ny, button) {
        Ok(()) => {
            if s.audit
                .record(
                    &rid,
                    "mouse.click",
                    json!({"frame_id": fid, "x": x, "y": y, "native": [nx, ny]}),
                    "allow",
                    "ok",
                )
                .is_err()
            {
                eprintln!("audit write failed for allow(mouse.click)");
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "audit unavailable".into(),
                    false,
                    &rid,
                );
            }
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => {
            let _ = s.audit.record(
                &rid,
                "mouse.click",
                json!({"frame_id": fid, "x": x, "y": y}),
                "deny",
                &e,
            );
            err(StatusCode::BAD_GATEWAY, "input_failed", e, false, &rid)
        }
    }
}

async fn type_text(State(s): State<Shared>, body: axum::body::Bytes) -> Response {
    let rid = Uuid::new_v4().to_string();
    let v: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(&s, &rid, "keyboard.type", json!({}), "malformed JSON"),
    };
    if v.get("approval_id").is_some() {
        return fail(
            &s,
            &rid,
            "keyboard.type",
            json!({}),
            "approval_id not accepted in M0",
        );
    }
    let Some(text) = v.get("text").and_then(|x| x.as_str()) else {
        return fail(&s, &rid, "keyboard.type", json!({}), "need text");
    };
    if text.is_empty() || text.len() > 1024 {
        // Never log text content: length only.
        return fail(
            &s,
            &rid,
            "keyboard.type",
            json!({"text_len": text.len()}),
            "text must be 1..1024 chars",
        );
    }
    if !s.caps.allows("keyboard.type") {
        return deny(
            &s,
            &rid,
            "keyboard.type",
            json!({"text_len": text.len()}),
            "capability not granted",
        );
    }
    if !rate_hit(&s.input_hits, 10, 1000) {
        let _ = s.audit.record(
            &rid,
            "keyboard.type",
            json!({"text_len": text.len()}),
            "deny",
            "rate_limited",
        );
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "slow down".into(),
            true,
            &rid,
        );
    }
    match s.input.type_text(text) {
        Ok(()) => {
            if s.audit
                .record(
                    &rid,
                    "keyboard.type",
                    json!({"text_len": text.len()}),
                    "allow",
                    "ok",
                )
                .is_err()
            {
                eprintln!("audit write failed for allow(keyboard.type)");
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "audit unavailable".into(),
                    false,
                    &rid,
                );
            }
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => {
            let _ = s.audit.record(
                &rid,
                "keyboard.type",
                json!({"text_len": text.len()}),
                "deny",
                &e,
            );
            err(StatusCode::BAD_GATEWAY, "input_failed", e, false, &rid)
        }
    }
}

async fn press(State(s): State<Shared>, body: axum::body::Bytes) -> Response {
    let rid = Uuid::new_v4().to_string();
    let v: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(&s, &rid, "keyboard.press", json!({}), "malformed JSON"),
    };
    if v.get("approval_id").is_some() {
        return fail(
            &s,
            &rid,
            "keyboard.press",
            json!({}),
            "approval_id not accepted in M0",
        );
    }
    let Some(key) = v.get("key").and_then(|x| x.as_str()) else {
        return fail(&s, &rid, "keyboard.press", json!({}), "need key");
    };
    if key.len() > 32 {
        return fail(&s, &rid, "keyboard.press", json!({"key": key}), "bad key");
    }
    let mods = match parse_modifiers(&v) {
        Ok(m) => m,
        Err(reason) => {
            return fail(&s, &rid, "keyboard.press", json!({"key": key}), reason);
        }
    };
    if !s.caps.allows("keyboard.press") {
        return deny(
            &s,
            &rid,
            "keyboard.press",
            json!({"key": key}),
            "capability not granted",
        );
    }
    // M0: any modifier requires keyboard.press.dangerous. No deny-list.
    if needs_dangerous(&mods) && !s.caps.allows("keyboard.press.dangerous") {
        return deny(
            &s,
            &rid,
            "keyboard.press",
            json!({"key": key, "modifiers": mods}),
            "modifiers need keyboard.press.dangerous",
        );
    }
    if !rate_hit(&s.input_hits, 10, 1000) {
        let _ = s.audit.record(
            &rid,
            "keyboard.press",
            json!({"key": key}),
            "deny",
            "rate_limited",
        );
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "slow down".into(),
            true,
            &rid,
        );
    }
    match s.input.press(key, &mods) {
        Ok(()) => {
            if s.audit
                .record(
                    &rid,
                    "keyboard.press",
                    json!({"key": key, "modifiers": mods}),
                    "allow",
                    "ok",
                )
                .is_err()
            {
                eprintln!("audit write failed for allow(keyboard.press)");
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "audit unavailable".into(),
                    false,
                    &rid,
                );
            }
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => {
            if e.starts_with("unknown key") {
                return fail(
                    &s,
                    &rid,
                    "keyboard.press",
                    json!({"key": key, "modifiers": mods}),
                    "unknown key",
                );
            }
            let _ = s.audit.record(
                &rid,
                "keyboard.press",
                json!({"key": key, "modifiers": mods}),
                "deny",
                &e,
            );
            err(StatusCode::BAD_GATEWAY, "input_failed", e, false, &rid)
        }
    }
}
