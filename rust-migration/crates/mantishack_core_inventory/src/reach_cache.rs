//! Reachability adjacency-index cache — **partial** Rust port of
//! `core/inventory/_reach_cache.py`.
//!
//! Only the pure, self-contained pieces are ported here:
//!   * [`compute_fingerprint`] — the content fingerprint used as the cache key.
//!   * [`is_valid_fingerprint`] — the path-safety check on a fingerprint.
//!   * [`CACHE_VERSION`] — the schema-shape salt.
//!
//! `load_index` / `save_index` are intentionally NOT ported: they
//! (de)serialize `reachability::_AdjacencyIndex` (an un-ported, tree-sitter-
//! gated type) via Python `pickle`, so a faithful port is impossible until
//! `reachability` lands and a non-pickle on-disk format is chosen. The
//! fingerprint is the part that's both portable and worth verifying — it must
//! match Python byte-for-byte or a Rust builder and a Python builder would
//! disagree about cache identity.

use mantishack_core_hash::sha256_bytes;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Schema-shape salt. Bumping it invalidates every old cache entry.
/// Mirrors `_CACHE_VERSION` in the Python module.
pub const CACHE_VERSION: u32 = 7;

/// A stable content fingerprint for `inventory`, or `None` if the inventory
/// lacks the per-file `sha256` we need (test fixtures often do).
///
/// Folds `v={CACHE_VERSION}\n` followed by the sorted `(path, sha256)` rows
/// of every file into a single SHA-256 hexdigest. Volatile fields (mtime,
/// etc.) are excluded so two builds of the same tree at different times agree.
///
/// Returns `None` when `files` is missing/empty, or when any file entry is a
/// dict lacking a string `path`/`sha256` (can't form a stable fingerprint).
/// Non-dict file entries are skipped (matching the Python `continue`).
pub fn compute_fingerprint(inventory: &Value) -> Option<String> {
    let files = inventory.get("files")?.as_array()?;
    if files.is_empty() {
        return None;
    }

    let mut rows: Vec<(&str, &str)> = Vec::new();
    for fr in files {
        let Some(obj) = fr.as_object() else {
            continue; // non-dict entry: skip, like the Python loop
        };
        let path = obj.get("path").and_then(Value::as_str);
        let sha = obj.get("sha256").and_then(Value::as_str);
        match (path, sha) {
            (Some(p), Some(s)) => rows.push((p, s)),
            // Missing sha256 on any file → can't fingerprint → bail.
            _ => return None,
        }
    }
    if rows.is_empty() {
        return None;
    }
    rows.sort();

    // Build the exact byte stream the Python digest folds in order, then hash
    // once — SHA-256 over the concatenation is identical to incremental updates.
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(format!("v={CACHE_VERSION}\n").as_bytes());
    for (path, sha) in &rows {
        buf.extend_from_slice(path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(sha.as_bytes());
        buf.push(b'\n');
    }
    Some(sha256_bytes(&buf))
}

fn fingerprint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{64}$").unwrap())
}

/// Whether `fingerprint` is exactly 64 lowercase hex chars — the path-safety
/// check that stops a crafted fingerprint (`../../poison`) from escaping the
/// cache root. Mirrors `_FINGERPRINT_RE` / the guard in `_cache_path_for`.
pub fn is_valid_fingerprint(fingerprint: &str) -> bool {
    fingerprint_re().is_match(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fingerprint_is_stable_and_order_independent() {
        let a = json!({"files": [
            {"path": "b.py", "sha256": "bb"},
            {"path": "a.py", "sha256": "aa"},
        ]});
        let b = json!({"files": [
            {"path": "a.py", "sha256": "aa"},
            {"path": "b.py", "sha256": "bb"},
        ]});
        let fa = compute_fingerprint(&a).unwrap();
        // Insertion order must not change the fingerprint (rows are sorted).
        assert_eq!(fa, compute_fingerprint(&b).unwrap());
        assert!(is_valid_fingerprint(&fa));
    }

    #[test]
    fn fingerprint_changes_with_content() {
        let a = json!({"files": [{"path": "a.py", "sha256": "aa"}]});
        let b = json!({"files": [{"path": "a.py", "sha256": "cc"}]});
        assert_ne!(compute_fingerprint(&a).unwrap(), compute_fingerprint(&b).unwrap());
    }

    #[test]
    fn missing_sha_disables() {
        let inv = json!({"files": [{"path": "a.py"}]});
        assert_eq!(compute_fingerprint(&inv), None);
    }

    #[test]
    fn no_files_disables() {
        assert_eq!(compute_fingerprint(&json!({"files": []})), None);
        assert_eq!(compute_fingerprint(&json!({})), None);
    }

    #[test]
    fn non_dict_entries_skipped() {
        let inv = json!({"files": ["junk", {"path": "a.py", "sha256": "aa"}]});
        assert!(compute_fingerprint(&inv).is_some());
    }

    #[test]
    fn fingerprint_validation() {
        assert!(is_valid_fingerprint(&"a".repeat(64)));
        assert!(!is_valid_fingerprint(&"A".repeat(64))); // uppercase rejected
        assert!(!is_valid_fingerprint("../../poison"));
        assert!(!is_valid_fingerprint(&"a".repeat(63)));
    }
}
