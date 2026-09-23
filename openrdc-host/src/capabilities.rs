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
}
