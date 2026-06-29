//! Hash-addressed persistence for `Witness` records and their underlying bytes.
//!
//! Faithful Rust port of core/witness/store.py.
//!
//! Storage layout under the configured root directory:
//!
//! ```text
//! {root}/
//!     manifests/
//!         <sha256>.json          # Witness.to_dict() per witness
//!     blobs/
//!         <sha256>.bin           # raw bytes (de-duplicated by hash)
//! ```
//!
//! Same bytes seen by multiple pipelines collapse to a single blob —
//! the hash key naturally de-duplicates. Two `Witness` records can share
//! a single `blobs/<sha256>.bin` if their bytes happen to match; each
//! has its own manifest with its own provenance.
//!
//! The store is process-local: no concurrent-writer locking. Each pipeline
//! run gets its own `{out_dir}/witnesses/` root, so concurrent runs on the
//! same host don't collide.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::{compute_bytes_hash, Witness};

/// Monotonic counter used to make temp-file names unique within a process,
/// mirroring Python's `f".{os.getpid()}.{threading.get_ident()}.tmp"`.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── WitnessStoreError ─────────────────────────────────────────────────────────

/// Raised when a store operation fails in a way the caller needs to surface.
///
/// Mirrors Python's `WitnessStoreError`. Distinct from general `std::io::Error`
/// so callers can catch witness-store errors specifically.
#[derive(Debug)]
pub struct WitnessStoreError(pub String);

impl std::fmt::Display for WitnessStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WitnessStoreError {}

impl From<std::io::Error> for WitnessStoreError {
    fn from(e: std::io::Error) -> Self {
        WitnessStoreError(e.to_string())
    }
}

// ── WitnessStore ──────────────────────────────────────────────────────────────

/// Read/write `Witness` records + their bytes, hash-addressed.
///
/// Construct with a root directory; the store creates the manifest and blob
/// sub-directories on demand. `root` is typically `{run_out_dir}/witnesses/`.
pub struct WitnessStore {
    pub root: PathBuf,
    manifests_dir: PathBuf,
    blobs_dir: PathBuf,
}

impl WitnessStore {
    /// Construct a store rooted at `root`. Does not touch the filesystem.
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let manifests_dir = root.join("manifests");
        let blobs_dir = root.join("blobs");
        WitnessStore {
            root,
            manifests_dir,
            blobs_dir,
        }
    }

    /// Create the manifest + blob directories if absent (lazy, on first write).
    fn ensure_dirs(&self) -> Result<(), WitnessStoreError> {
        std::fs::create_dir_all(&self.manifests_dir)?;
        std::fs::create_dir_all(&self.blobs_dir)?;
        Ok(())
    }

    /// Persist `witness` and `data`. Returns the blob path.
    ///
    /// Validates four invariants before touching disk:
    ///
    /// 1. `witness.bytes_hash == sha256(data)` — catches the producer bug
    ///    of hashing a transformed copy of the bytes.
    /// 2. If `witness.bytes_len` is non-zero, it matches `len(data)`.
    ///    If left at default `0`, the store stamps it from the actual length.
    /// 3. `witness.outcome_detail` is JSON-serialisable. Pre-check catches
    ///    non-serialisable values before the blob is written.
    ///
    /// Blob writes are idempotent — if the same hash is put again, the
    /// existing blob is reused. Both blob and manifest writes are atomic via
    /// the temp-file + rename pattern (POSIX-equivalent on macOS/Linux).
    pub fn put(
        &self,
        witness: &mut Witness,
        data: &[u8],
    ) -> Result<PathBuf, WitnessStoreError> {
        // Invariant 1: hash must match.
        let expected = compute_bytes_hash(data);
        if expected != witness.bytes_hash {
            return Err(WitnessStoreError(format!(
                "witness.bytes_hash {:?}... does not match sha256(data) {:?}...; \
                 fix the producer to use compute_bytes_hash on the actual bytes being stored",
                &witness.bytes_hash[..16],
                &expected[..16],
            )));
        }

        // Invariant 2: bytes_len agreement when caller set it.
        if witness.bytes_len != 0 && witness.bytes_len != data.len() {
            return Err(WitnessStoreError(format!(
                "witness.bytes_len ({}) does not match len(data) ({}); \
                 pass bytes_len=0 to let the store stamp it, or fix the producer",
                witness.bytes_len,
                data.len(),
            )));
        }
        // Stamp bytes_len when caller left it at 0 and data is non-empty.
        if witness.bytes_len == 0 && !data.is_empty() {
            witness.bytes_len = data.len();
        }

        // Invariant 3: pre-serialise to catch non-JSON-safe outcome_detail values.
        let manifest_text = serde_json::to_string_pretty(&witness.to_dict())
            .map(|s| s + "\n")
            .map_err(|e| {
                WitnessStoreError(format!(
                    "witness manifest is not JSON-serialisable ({}); \
                     convert any non-serialisable values in outcome_detail to strings",
                    e
                ))
            })?;

        self.ensure_dirs()?;

        let blob_path = self.blobs_dir.join(format!("{}.bin", witness.bytes_hash));
        let manifest_path = self
            .manifests_dir
            .join(format!("{}.json", witness.bytes_hash));

        // Unique suffix per process + call for temp-file atomicity.
        // Mirrors Python: f".{os.getpid()}.{threading.get_ident()}.tmp"
        let suffix = format!(
            ".{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );

        // Atomic blob write: write to .tmp + rename.
        if !blob_path.exists() {
            let mut blob_tmp = blob_path.clone();
            let mut blob_ext = "bin".to_string();
            blob_ext.push_str(&suffix);
            blob_tmp.set_extension(blob_ext);
            std::fs::write(&blob_tmp, data)?;
            match std::fs::rename(&blob_tmp, &blob_path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Lost the race: another writer already placed the final
                    // blob. Same bytes (verified by hash); nothing to do.
                }
                Err(e) => return Err(WitnessStoreError(e.to_string())),
            }
        }

        // Atomic manifest write.
        let mut manifest_tmp = manifest_path.clone();
        let mut manifest_ext = "json".to_string();
        manifest_ext.push_str(&suffix);
        manifest_tmp.set_extension(manifest_ext);
        std::fs::write(&manifest_tmp, manifest_text.as_bytes())?;
        match std::fs::rename(&manifest_tmp, &manifest_path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(WitnessStoreError(e.to_string())),
        }

        Ok(blob_path)
    }

    /// True iff a manifest with `bytes_hash` exists in the store.
    pub fn has(&self, bytes_hash: &str) -> bool {
        self.manifests_dir.join(format!("{}.json", bytes_hash)).is_file()
    }

    /// Load the raw bytes for `bytes_hash`.
    ///
    /// Raises `WitnessStoreError` if the blob is missing.
    pub fn get_bytes(&self, bytes_hash: &str) -> Result<Vec<u8>, WitnessStoreError> {
        let blob_path = self.blobs_dir.join(format!("{}.bin", bytes_hash));
        if !blob_path.is_file() {
            return Err(WitnessStoreError(format!(
                "blob not found for hash {:?}... (expected at {})",
                &bytes_hash[..bytes_hash.len().min(16)],
                blob_path.display(),
            )));
        }
        std::fs::read(&blob_path).map_err(WitnessStoreError::from)
    }

    /// Load the `Witness` record for `bytes_hash`.
    ///
    /// Raises `WitnessStoreError` if the manifest is missing or malformed.
    pub fn get_witness(&self, bytes_hash: &str) -> Result<Witness, WitnessStoreError> {
        let manifest_path = self.manifests_dir.join(format!("{}.json", bytes_hash));
        if !manifest_path.is_file() {
            return Err(WitnessStoreError(format!(
                "manifest not found for hash {:?}... (expected at {})",
                &bytes_hash[..bytes_hash.len().min(16)],
                manifest_path.display(),
            )));
        }
        let text = std::fs::read_to_string(&manifest_path)
            .map_err(WitnessStoreError::from)?;
        let data: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            WitnessStoreError(format!(
                "manifest at {} is malformed JSON: {}",
                manifest_path.display(),
                e
            ))
        })?;
        Witness::from_dict(&data).map_err(|e| {
            WitnessStoreError(format!(
                "manifest at {} has invalid fields: {}",
                manifest_path.display(),
                e
            ))
        })
    }

    /// Iterate every `Witness` in the store.
    ///
    /// Skips manifests that fail to parse (logs at eprintln! for now,
    /// matching Python's `logger.warning`). One corrupt file does not
    /// abort enumeration.
    pub fn list_witnesses(&self) -> Vec<Witness> {
        if !self.manifests_dir.is_dir() {
            return vec![];
        }

        // Collect and sort (mirrors Python's `sorted(glob("*.json"))`).
        let mut paths: Vec<PathBuf> = match std::fs::read_dir(&self.manifests_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect(),
            Err(_) => return vec![],
        };
        paths.sort();

        let mut out = Vec::new();
        for path in paths {
            match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).map_err(|e| e.to_string()))
                .and_then(|v| Witness::from_dict(&v).map_err(|e| e.to_string()))
            {
                Ok(w) => out.push(w),
                Err(e) => {
                    eprintln!("WitnessStore: skipping malformed manifest {}: {}", path.display(), e);
                }
            }
        }
        out
    }

    /// Return the path to the raw bytes blob, or `None` if the store
    /// doesn't have one for this hash.
    ///
    /// Useful when a consumer wants to pass the bytes to a tool that takes
    /// a filename rather than reading them into memory.
    pub fn blob_path(&self, bytes_hash: &str) -> Option<PathBuf> {
        let path = self.blobs_dir.join(format!("{}.bin", bytes_hash));
        if path.is_file() { Some(path) } else { None }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WitnessOutcome, WitnessSource};
    use tempfile::TempDir;

    fn make_store() -> (TempDir, WitnessStore) {
        let dir = TempDir::new().unwrap();
        let store = WitnessStore::new(dir.path());
        (dir, store)
    }

    fn make_witness(data: &[u8]) -> Witness {
        let hash = compute_bytes_hash(data);
        Witness::new(hash, WitnessSource::Fuzz, WitnessOutcome::ExitSignal).unwrap()
    }

    #[test]
    fn test_put_and_get_bytes() {
        let (_dir, store) = make_store();
        let data = b"hello witness";
        let mut w = make_witness(data);
        store.put(&mut w, data).unwrap();
        assert_eq!(store.get_bytes(&w.bytes_hash).unwrap(), data);
    }

    #[test]
    fn test_put_stamps_bytes_len() {
        let (_dir, store) = make_store();
        let data = b"stamp me";
        let mut w = make_witness(data);
        assert_eq!(w.bytes_len, 0);
        store.put(&mut w, data).unwrap();
        assert_eq!(w.bytes_len, data.len());
    }

    #[test]
    fn test_put_rejects_hash_mismatch() {
        let (_dir, store) = make_store();
        let mut w =
            Witness::new("a".repeat(64), WitnessSource::Fuzz, WitnessOutcome::ExitSignal)
                .unwrap();
        let err = store.put(&mut w, b"different bytes").unwrap_err();
        assert!(err.0.contains("does not match"), "got: {}", err.0);
    }

    #[test]
    fn test_put_rejects_bytes_len_mismatch() {
        let (_dir, store) = make_store();
        let data = b"exact";
        let mut w = make_witness(data);
        w.bytes_len = 999; // caller lied
        let err = store.put(&mut w, data).unwrap_err();
        assert!(err.0.contains("bytes_len"), "got: {}", err.0);
    }

    #[test]
    fn test_has() {
        let (_dir, store) = make_store();
        let data = b"has-test";
        let mut w = make_witness(data);
        assert!(!store.has(&w.bytes_hash));
        store.put(&mut w, data).unwrap();
        assert!(store.has(&w.bytes_hash));
    }

    #[test]
    fn test_get_witness_round_trip() {
        let (_dir, store) = make_store();
        let data = b"get-witness";
        let mut w = make_witness(data);
        w.produced_by = Some("test-runner".to_string());
        store.put(&mut w, data).unwrap();
        let loaded = store.get_witness(&w.bytes_hash).unwrap();
        assert_eq!(loaded.bytes_hash, w.bytes_hash);
        assert_eq!(loaded.produced_by, Some("test-runner".to_string()));
    }

    #[test]
    fn test_list_witnesses() {
        let (_dir, store) = make_store();
        let inputs: &[&[u8]] = &[b"aaa", b"bbb", b"ccc"];
        for data in inputs {
            let mut w = make_witness(data);
            store.put(&mut w, data).unwrap();
        }
        let witnesses = store.list_witnesses();
        assert_eq!(witnesses.len(), 3);
    }

    #[test]
    fn test_list_witnesses_empty_store() {
        let (_dir, store) = make_store();
        assert!(store.list_witnesses().is_empty());
    }

    #[test]
    fn test_blob_path() {
        let (_dir, store) = make_store();
        let data = b"blob-path";
        let mut w = make_witness(data);
        assert!(store.blob_path(&w.bytes_hash).is_none());
        store.put(&mut w, data).unwrap();
        assert!(store.blob_path(&w.bytes_hash).is_some());
    }

    #[test]
    fn test_put_idempotent() {
        let (_dir, store) = make_store();
        let data = b"idempotent";
        let mut w = make_witness(data);
        store.put(&mut w, data).unwrap();
        // Second put with same data should succeed (idempotent blob write).
        let mut w2 = make_witness(data);
        store.put(&mut w2, data).unwrap();
        assert_eq!(store.list_witnesses().len(), 1);
    }
}
