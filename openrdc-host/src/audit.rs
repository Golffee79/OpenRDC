// SPDX-License-Identifier: Apache-2.0
//! JSONL audit log with SHA-256 hash chain. Tamper-EVIDENT, not tamper-proof.
//!
//! Durability policy (M0): every record is flushed AND fsynced before the
//! handler responds. Write/flush/fsync errors are returned to the caller —
//! deny paths fail closed (500); allow paths report 500 after the action
//! (action cannot be un-taken; the 500 + stderr line signal the gap).
//! Crash/power loss can still lose at most the in-flight record; a writer
//! with filesystem access can truncate/regenerate the whole chain
//! (external anchoring deferred to M2).
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Audit {
    file: Mutex<std::fs::File>,
    seq: Mutex<u64>,
    prev_hash: Mutex<String>,
}

impl Audit {
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        let mut seq = 0u64;
        let mut prev = "GENESIS".to_string();
        // Replay existing log to continue chain.
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            for line in content.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if let (Some(s), Some(h)) = (
                        v.get("seq").and_then(|x| x.as_u64()),
                        v.get("hash").and_then(|x| x.as_str()),
                    ) {
                        seq = seq.max(s);
                        prev = h.to_string();
                    }
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            file: Mutex::new(file),
            seq: Mutex::new(seq),
            prev_hash: Mutex::new(prev),
        })
    }

    pub fn record(
        &self,
        request_id: &str,
        method: &str,
        params: serde_json::Value,
        decision: &str,
        reason: &str,
    ) -> std::io::Result<()> {
        let mut seq = self.seq.lock().unwrap();
        let mut prev = self.prev_hash.lock().unwrap();
        *seq += 1;
        let body = serde_json::json!({
            "seq": *seq, "ts": Utc::now().to_rfc3339(),
            "request_id": request_id, "method": method,
            "params_redacted": params, "decision": decision, "reason": reason,
            "prev_hash": *prev,
        });
        let canonical = serde_json::to_string(&body).unwrap();
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        let hash = format!("{:x}", h.finalize());
        let mut rec = body;
        rec["hash"] = hash.clone().into();
        *prev = hash;
        drop(prev);
        let line = serde_json::to_string(&rec).unwrap();
        let mut f = self.file.lock().unwrap();
        writeln!(f, "{line}")?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    }

    /// Verify chain. Returns (records, ok).
    pub fn verify(path: &std::path::Path) -> (usize, bool) {
        let Ok(content) = std::fs::read_to_string(path) else {
            return (0, false);
        };
        let mut prev = "GENESIS".to_string();
        let mut n = 0;
        let mut expected_seq = 0u64;
        for line in content.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                return (n, false);
            };
            expected_seq += 1;
            if v.get("seq").and_then(|x| x.as_u64()) != Some(expected_seq) {
                return (n, false);
            }
            if v.get("prev_hash").and_then(|x| x.as_str()) != Some(prev.as_str()) {
                return (n, false);
            }
            let Some(stored) = v
                .get("hash")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
            else {
                return (n, false);
            };
            let mut rec = v.clone();
            rec.as_object_mut().unwrap().remove("hash");
            let canonical = serde_json::to_string(&rec).unwrap_or_default();
            let mut h = Sha256::new();
            h.update(canonical.as_bytes());
            if format!("{:x}", h.finalize()) != stored {
                return (n, false);
            }
            prev = stored;
            n += 1;
        }
        (n, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chain_verifies_and_tamper_detected() {
        let p = std::env::temp_dir().join(format!("audit-test-{}.jsonl", uuid::Uuid::new_v4()));
        let a = Audit::open(p.clone()).unwrap();
        a.record("r1", "mouse.click", serde_json::json!({}), "allow", "ok")
            .unwrap();
        a.record("r2", "mouse.click", serde_json::json!({}), "deny", "no cap")
            .unwrap();
        assert_eq!(Audit::verify(&p), (2, true));
        // Tamper: flip a byte.
        let mut c = std::fs::read_to_string(&p).unwrap();
        c = c.replacen("allow", "deny", 1);
        std::fs::write(&p, c).unwrap();
        assert!(!Audit::verify(&p).1);
        std::fs::remove_file(&p).ok();
    }
}
