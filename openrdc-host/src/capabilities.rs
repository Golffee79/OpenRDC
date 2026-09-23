// SPDX-License-Identifier: Apache-2.0
//! Exact-match capability set, default-deny.
use std::collections::HashSet;

pub const KNOWN: &[&str] = &[
    "screen.capture",
    "mouse.click",
    "keyboard.type",
    "keyboard.press",
    "keyboard.press.dangerous",
];

#[derive(Debug, Clone)]
pub struct Capabilities {
    granted: HashSet<String>,
}

impl Capabilities {
    /// Load from a file. Any failure (missing, unreadable, invalid) is an
    /// error — the caller must refuse to start, never fall back to empty
    /// grants. Dogfood lesson: a daemon cwd silently resolving to a missing
    /// file once booted a zero-grant host.
    pub fn load_file(path: &std::path::Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::load_json(&s)
    }

    pub fn load_json(s: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
        let arr = v
            .get("granted")
            .and_then(|g| g.as_array())
            .ok_or("config needs {\"granted\": [...]}")?;
        let mut granted = HashSet::new();
        for c in arr {
            let name = c.as_str().ok_or("capability must be string")?;
            if !KNOWN.contains(&name) {
                return Err(format!("unknown capability: {name}"));
            }
            granted.insert(name.to_string());
        }
        Ok(Self { granted })
    }

    /// Exact match only. No inheritance, no wildcards.
    pub fn allows(&self, cap: &str) -> bool {
        self.granted.contains(cap)
    }

    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<_> = self.granted.iter().cloned().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_match_no_inheritance() {
        let c = Capabilities::load_json(r#"{"granted":["keyboard.press"]}"#).unwrap();
        assert!(c.allows("keyboard.press"));
        assert!(!c.allows("keyboard.press.dangerous"));
    }
    #[test]
    fn unknown_rejected() {
        assert!(Capabilities::load_json(r#"{"granted":["keyboard.*"]}"#).is_err());
    }
    #[test]
    fn missing_file_is_error_never_empty_grants() {
        let p = std::env::temp_dir().join(format!("openrdc-caps-{}.json", uuid::Uuid::new_v4()));
        assert!(Capabilities::load_file(&p).is_err());
    }
    #[test]
    fn invalid_file_is_error() {
        let p = std::env::temp_dir().join(format!("openrdc-caps-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&p, "not json{{{").unwrap();
        assert!(Capabilities::load_file(&p).is_err());
        std::fs::remove_file(&p).ok();
    }
    #[test]
    fn valid_file_loads() {
        let p = std::env::temp_dir().join(format!("openrdc-caps-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&p, r#"{"granted":["screen.capture"]}"#).unwrap();
        let c = Capabilities::load_file(&p).unwrap();
        assert!(c.allows("screen.capture"));
        std::fs::remove_file(&p).ok();
    }
}
