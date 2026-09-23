// SPDX-License-Identifier: Apache-2.0
//! Backend traits. Protocol types must never mention xcap/enigo.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RawFrame {
    pub monitor_id: String,
    pub source_width: u32,
    pub source_height: u32,
    pub rgba: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MonitorInfo {
    pub monitor_id: String,
    pub source_width: u32,
    pub source_height: u32,
    pub is_primary: bool,
}

#[derive(Debug, Clone)]
pub struct FrameMeta {
    pub monitor_id: String,
    pub source_width: u32,
    pub source_height: u32,
    pub output_width: u32,
    pub output_height: u32,
    pub scale: f64,
    pub created: Instant,
}

/// In-memory frame registry. Host-only; never serialized to clients except geometry.
pub struct FrameStore {
    inner: Mutex<HashMap<String, FrameMeta>>,
    ttl: Duration,
    max: usize,
}

impl Default for FrameStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(60),
            max: 32,
        }
    }
    pub fn insert(&self, meta: FrameMeta) -> String {
        let mut m = self.inner.lock().unwrap();
        // Evict expired + enforce bound.
        m.retain(|_, v| v.created.elapsed() < self.ttl);
        if m.len() >= self.max {
            if let Some(k) = m.keys().next().cloned() {
                m.remove(&k);
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        m.insert(id.clone(), meta);
        id
    }
    pub fn get(&self, id: &str) -> Option<FrameMeta> {
        let mut m = self.inner.lock().unwrap();
        let v = m.get(id)?.clone();
        if v.created.elapsed() >= self.ttl {
            m.remove(id);
            return None;
        }
        Some(v)
    }
    /// frame-space -> native. Floor + clamp handled by caller bounds check.
    pub fn to_native(meta: &FrameMeta, x: u32, y: u32) -> Option<(u32, u32)> {
        if x >= meta.output_width || y >= meta.output_height {
            return None;
        }
        let nx = (x as f64 / meta.scale).floor() as u32;
        let ny = (y as f64 / meta.scale).floor() as u32;
        if nx >= meta.source_width || ny >= meta.source_height {
            return None;
        }
        Some((nx, ny))
    }
}

pub trait ScreenBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn monitors(&self) -> Result<Vec<MonitorInfo>, String>;
    fn capture(&self, monitor_id: Option<&str>) -> Result<RawFrame, String>;
}

pub trait InputBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn click(&self, x: u32, y: u32, button: &str) -> Result<(), String>;
    fn type_text(&self, text: &str) -> Result<(), String>;
    fn press(&self, key: &str, modifiers: &[String]) -> Result<(), String>;
}

pub mod x11;
