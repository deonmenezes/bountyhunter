//! Locate WitnessStore-shaped directories visible to a run.
//!
//! Faithful Rust port of core/witness/discovery.py.
//!
//! Two scopes:
//!   * **Run-local** — always: the current run's own stores.
//!   * **Project-wide** — when a project root is known: all sibling
//!     runs' stores under that root.
//!
//! Stores are returned as paths to the store *root* (the directory
//! containing `manifests/` and `blobs/`). Consumers wrap each in
//! `WitnessStore::new(root)` and iterate.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::store::WitnessStore;
use crate::types::Witness;

/// Sub-paths within a run's output dir that conventionally hold witness stores.
/// Order is informational only — discovery returns every existing store.
const RUN_LOCAL_SUBPATHS: &[&str] = &[
    "witnesses",
    "analysis/witnesses",   // crash-agent under mantishack_fuzzing
    "autonomous/witnesses", // /agentic's AutonomousSecurityAgentV2
];

/// A directory is a `WitnessStore` root when it contains a `manifests/`
/// subdir (the `blobs/` subdir is created on first write but absent on a
/// never-written store).
fn is_store_dir(path: &Path) -> bool {
    path.is_dir() && path.join("manifests").is_dir()
}

/// Return all `WitnessStore` root directories visible to this run.
///
/// # Arguments
/// * `output_dir` — The current run's output dir. `None` is tolerated
///   (returns empty list when `project_root` is also `None`).
/// * `project_root` — When set, also scan every sibling run under this
///   directory. `None` for runs without a project.
///
/// # Returns
/// Deduplicated list of store roots. Run-local stores appear first;
/// project-wide siblings follow. Each path is verified to contain a
/// `manifests/` subdir.
///
/// Never panics. Missing dirs, permission errors, and unreadable project
/// roots produce a shorter list.
pub fn discover_witness_stores(
    output_dir: Option<&Path>,
    project_root: Option<&Path>,
) -> Vec<PathBuf> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut out: Vec<PathBuf> = Vec::new();

    // Run-local first.
    if let Some(odir) = output_dir {
        for sub in RUN_LOCAL_SUBPATHS {
            let candidate = odir.join(sub);
            if is_store_dir(&candidate) {
                let resolved = match candidate.canonicalize() {
                    Ok(p) => p,
                    Err(_) => candidate.clone(),
                };
                if seen.insert(resolved) {
                    out.push(candidate);
                }
            }
        }
    }

    // Project-wide siblings.
    if let Some(proot) = project_root {
        let entries: Vec<PathBuf> = match std::fs::read_dir(proot) {
            Ok(rd) => {
                let mut v: Vec<PathBuf> = rd
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .collect();
                v.sort();
                v
            }
            Err(_) => return out,
        };

        for run_dir in entries {
            if !run_dir.is_dir() {
                continue;
            }
            for sub in RUN_LOCAL_SUBPATHS {
                let candidate = run_dir.join(sub);
                if is_store_dir(&candidate) {
                    let resolved = match candidate.canonicalize() {
                        Ok(p) => p,
                        Err(_) => candidate.clone(),
                    };
                    if seen.insert(resolved) {
                        out.push(candidate);
                    }
                }
            }
        }
    }

    out
}

/// Yield `(store_path, Witness)` pairs across the supplied stores in their
/// listed order.
///
/// Dedup by `bytes_hash` — if the same exploit bytes appear in multiple
/// stores (cross-run dedup), only the first occurrence is returned.
/// Run-local stores come first per `discover_witness_stores`, so a
/// project's older duplicate is skipped after the current run's copy.
///
/// Failures within a store (malformed manifests, missing Witness fields)
/// are skipped per the store's own `list_witnesses` contract.
pub fn iter_visible_witnesses(stores: &[PathBuf]) -> Vec<(Option<PathBuf>, Witness)> {
    let mut seen_hashes: HashSet<String> = HashSet::new();
    let mut out: Vec<(Option<PathBuf>, Witness)> = Vec::new();

    for root in stores {
        let store = WitnessStore::new(root);
        for w in store.list_witnesses() {
            if seen_hashes.contains(&w.bytes_hash) {
                continue;
            }
            seen_hashes.insert(w.bytes_hash.clone());
            out.push((Some(root.clone()), w));
        }
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{compute_bytes_hash, WitnessOutcome, WitnessSource};
    use tempfile::TempDir;

    fn make_store_at(path: &Path) -> WitnessStore {
        WitnessStore::new(path)
    }

    fn put_witness(store: &WitnessStore, data: &[u8]) {
        let hash = compute_bytes_hash(data);
        let mut w =
            Witness::new(hash, WitnessSource::Fuzz, WitnessOutcome::ExitSignal).unwrap();
        store.put(&mut w, data).unwrap();
    }

    #[test]
    fn test_discover_witness_stores_empty_dir() {
        let dir = TempDir::new().unwrap();
        let stores = discover_witness_stores(Some(dir.path()), None);
        assert!(stores.is_empty());
    }

    #[test]
    fn test_discover_witness_stores_run_local() {
        let dir = TempDir::new().unwrap();
        let witnesses_dir = dir.path().join("witnesses");
        std::fs::create_dir_all(witnesses_dir.join("manifests")).unwrap();

        let stores = discover_witness_stores(Some(dir.path()), None);
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0], witnesses_dir);
    }

    #[test]
    fn test_discover_witness_stores_project_wide() {
        let project_root = TempDir::new().unwrap();
        // Simulate two sibling run directories each with a witnesses store.
        for run in &["run_a", "run_b"] {
            let witnesses_dir = project_root.path().join(run).join("witnesses");
            std::fs::create_dir_all(witnesses_dir.join("manifests")).unwrap();
        }

        let stores = discover_witness_stores(None, Some(project_root.path()));
        assert_eq!(stores.len(), 2);
    }

    #[test]
    fn test_discover_dedup_by_canonical_path() {
        // Both output_dir and project_root point to the same store.
        let dir = TempDir::new().unwrap();
        let witnesses_dir = dir.path().join("witnesses");
        std::fs::create_dir_all(witnesses_dir.join("manifests")).unwrap();

        // Use the same dir as both output and project root so they'd overlap.
        let stores =
            discover_witness_stores(Some(dir.path()), Some(dir.path()));
        // The store appears in run-local first and should not be duplicated.
        let paths: Vec<_> = stores
            .iter()
            .filter(|p| p.ends_with("witnesses"))
            .collect();
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_iter_visible_witnesses_dedup() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let store_a = make_store_at(dir_a.path());
        let store_b = make_store_at(dir_b.path());

        // Same bytes in both stores.
        let data = b"shared data";
        put_witness(&store_a, data);
        put_witness(&store_b, data);

        // Create manifests dirs so is_store_dir() passes.
        // (Already created by put_witness internally.)
        let stores = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let witnesses = iter_visible_witnesses(&stores);
        // Dedup: only one entry despite two stores having the same hash.
        assert_eq!(witnesses.len(), 1);
    }

    #[test]
    fn test_iter_visible_witnesses_all_stores() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let store_a = make_store_at(dir_a.path());
        let store_b = make_store_at(dir_b.path());

        put_witness(&store_a, b"unique-a");
        put_witness(&store_b, b"unique-b");

        let stores = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];
        let witnesses = iter_visible_witnesses(&stores);
        assert_eq!(witnesses.len(), 2);
    }
}
