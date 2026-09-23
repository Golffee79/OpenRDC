// SPDX-License-Identifier: Apache-2.0
//! Bearer-token lifecycle. Hardened: mode 0600 at creation, no symlinks,
//! existing files verified (owner/type/mode) before use, OS CSPRNG only.
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const TOKEN_BYTES: usize = 32; // 256 bits minimum.

#[derive(Debug)]
pub enum TokenError {
    Io(String),
    Refused(String),
    NoEntropy(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Never include token material in errors.
            Self::Io(e) => write!(f, "token storage error: {e}"),
            Self::Refused(e) => write!(f, "token file refused: {e}"),
            Self::NoEntropy(e) => write!(f, "no secure randomness: {e}"),
        }
    }
}

/// Reject symlinks (and anything that is not a plain file owned by us).
fn inspect(path: &Path) -> Result<std::fs::Metadata, TokenError> {
    let md = std::fs::symlink_metadata(path).map_err(|e| TokenError::Io(e.to_string()))?;
    if md.file_type().is_symlink() {
        return Err(TokenError::Refused("is a symlink".into()));
    }
    if !md.is_file() {
        return Err(TokenError::Refused("not a regular file".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.uid() != unsafe { libc::getuid() } {
            return Err(TokenError::Refused("not owned by current user".into()));
        }
        if md.mode() & 0o777 != 0o600 {
            return Err(TokenError::Refused("permissions are not 0600".into()));
        }
    }
    Ok(md)
}

fn mint() -> Result<String, TokenError> {
    // OS CSPRNG only. No fallback: without entropy the host must not start.
    let mut f =
        std::fs::File::open("/dev/urandom").map_err(|e| TokenError::NoEntropy(e.to_string()))?;
    let mut bytes = [0u8; TOKEN_BYTES];
    f.read_exact(&mut bytes)
        .map_err(|e| TokenError::NoEntropy(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Load an existing verified token, or atomically create one with mode 0600.
/// Never follows symlinks. Never accepts permissive/foreign files.
pub fn load_or_mint(path: &Path) -> Result<String, TokenError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            // Something exists: verify strictly, then read without following
            // a swapped-in symlink (O_NOFOLLOW).
            inspect(path)?;
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            #[cfg(unix)]
            opts.custom_flags(libc::O_NOFOLLOW);
            let mut f = opts.open(path).map_err(|e| TokenError::Io(e.to_string()))?;
            let mut t = String::new();
            f.read_to_string(&mut t)
                .map_err(|e| TokenError::Io(e.to_string()))?;
            let t = t.trim().to_string();
            if t.len() < 32 {
                return Err(TokenError::Refused("token too short".into()));
            }
            Ok(t)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| TokenError::Io(e.to_string()))?;
            }
            let tok = mint()?;
            // create_new: fail if raced into existence. Mode set at creation,
            // never chmod-after-write.
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                opts.mode(0o600);
                opts.custom_flags(libc::O_NOFOLLOW);
            }
            use std::io::Write;
            let mut f = opts.open(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    TokenError::Refused("appeared concurrently; refusing".into())
                } else {
                    TokenError::Io(e.to_string())
                }
            })?;
            f.write_all(tok.as_bytes())
                .map_err(|e| TokenError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| TokenError::Io(e.to_string()))?;
            Ok(tok)
        }
        Err(e) => Err(TokenError::Io(e.to_string())),
    }
}

pub fn token_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("OPENRDC_TOKEN_FILE") {
        return std::path::PathBuf::from(p);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
                .join(".config")
        });
    base.join("openrdc").join("token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("openrdc-tok-{name}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn minted_file_is_0600_and_256_bits() {
        let p = tmp("mint");
        let t = load_or_mint(&p).unwrap();
        assert!(t.len() >= 64, "hex of 32 bytes");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Reload returns the same token.
        assert_eq!(load_or_mint(&p).unwrap(), t);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn permissive_existing_file_refused() {
        let p = tmp("perm");
        std::fs::write(&p, "a".repeat(64)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_mint(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn symlink_refused() {
        let target = tmp("target");
        std::fs::write(&target, "b".repeat(64)).unwrap();
        let link = tmp("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let r = load_or_mint(&link);
        assert!(r.is_err(), "symlink must be refused, got {r:?}");
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
    }

    #[test]
    fn short_token_refused() {
        let p = tmp("short");
        std::fs::write(&p, "tiny").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_or_mint(&p).is_err());
        std::fs::remove_file(&p).ok();
    }
}
