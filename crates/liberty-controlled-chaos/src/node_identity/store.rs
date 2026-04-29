//! Persistent storage for a node's long-term identity.
//!
//! `NodeIdentityStore` loads an existing identity from a JSON file or
//! generates and saves a fresh one if the file does not exist.
//!
//! NON-PRODUCTION: no file locking; single-process use only.

use std::fs;
use std::path::{Path, PathBuf};

use super::identity::{IdentityError, NodeIdentity};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from `NodeIdentityStore` operations.
#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Identity(IdentityError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "identity store I/O error: {e}"),
            StoreError::Identity(e) => write!(f, "identity store parse error: {e}"),
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<IdentityError> for StoreError {
    fn from(e: IdentityError) -> Self {
        StoreError::Identity(e)
    }
}

// ---------------------------------------------------------------------------
// NodeIdentityStore
// ---------------------------------------------------------------------------

/// Manages a node's long-term identity on disk.
pub struct NodeIdentityStore {
    path: PathBuf,
}

impl NodeIdentityStore {
    /// Create a store backed by `path`.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Load the identity from disk, or generate and save a new one.
    ///
    /// - If `path` exists: parse it and return the identity.
    /// - If `path` does not exist: call `NodeIdentity::generate()`, write it,
    ///   and return the new identity.
    pub fn load_or_generate(&self) -> Result<NodeIdentity, StoreError> {
        match fs::read_to_string(&self.path) {
            Ok(json) => {
                let id = NodeIdentity::from_json(&json)?;
                Ok(id)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = NodeIdentity::generate();
                self.save(&id)?;
                Ok(id)
            }
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// Save an identity to the backing file.
    pub fn save(&self, identity: &NodeIdentity) -> Result<(), StoreError> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, identity.to_json())?;
        Ok(())
    }

    /// Path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("liberty_ni_{name}.json"));
        p
    }

    fn cleanup(p: &Path) {
        let _ = fs::remove_file(p);
    }

    // NI_S1: load_or_generate creates a new file when none exists.
    #[test]
    fn ni_s1_creates_file_when_missing() {
        let path = tmp_path("s1");
        cleanup(&path);

        let store = NodeIdentityStore::new(&path);
        let id = store.load_or_generate().unwrap();

        assert!(path.exists(), "identity file must be created");
        assert!(id.is_valid());

        cleanup(&path);
    }

    // NI_S2: load_or_generate returns the same identity on the second call.
    #[test]
    fn ni_s2_load_returns_same_identity() {
        let path = tmp_path("s2");
        cleanup(&path);

        let store = NodeIdentityStore::new(&path);
        let first = store.load_or_generate().unwrap();
        let second = store.load_or_generate().unwrap();

        assert_eq!(first.node_id, second.node_id);
        assert_eq!(first.private_key, second.private_key);
        assert_eq!(first.public_key, second.public_key);

        cleanup(&path);
    }

    // NI_S3: save + load preserves all fields.
    #[test]
    fn ni_s3_save_load_round_trip() {
        let path = tmp_path("s3");
        cleanup(&path);

        let id = NodeIdentity::generate_from_seed([0xAAu8; 32]);
        let store = NodeIdentityStore::new(&path);
        store.save(&id).unwrap();

        let loaded = store.load_or_generate().unwrap();
        assert_eq!(id.node_id, loaded.node_id);
        assert_eq!(id.private_key, loaded.private_key);
        assert_eq!(id.public_key, loaded.public_key);

        cleanup(&path);
    }

    // NI_S4: loaded identity passes is_valid().
    #[test]
    fn ni_s4_loaded_identity_is_valid() {
        let path = tmp_path("s4");
        cleanup(&path);

        let store = NodeIdentityStore::new(&path);
        let id = store.load_or_generate().unwrap();
        assert!(id.is_valid());
        assert_eq!(id.node_id, sha256(&id.public_key));

        cleanup(&path);
    }
}
