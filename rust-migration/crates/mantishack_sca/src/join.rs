//! Join manifest + lockfile views of the same dependency tree — Rust port of
//! `packages/sca/join.py`. Pure: reconciles each lockfile row against a matching
//! manifest row (walking up the directory tree), promoting `direct` and copying
//! the manifest's `pin_style` + a combined confidence.

use std::collections::{HashMap, HashSet};

use crate::models::{Confidence, Dependency};

const MAX_ANCESTOR_WALK: usize = 64;

/// `PurePosixPath.parent` for a path string.
fn path_parent(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string(); // p was all slashes -> root
    }
    match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),        // "/a" -> "/"
        Some((parent, _)) => parent.to_string(), // "a/b" -> "a"
        None => ".".to_string(),                 // "a" -> "."
    }
}

fn level_rank(level: &str) -> i32 {
    match level {
        "low" => 0,
        "medium" => 1,
        "high" => 2,
        _ => 0,
    }
}

/// Combine a lockfile + manifest confidence (`_combine_confidence`).
fn combine_confidence(lockfile: &Confidence, manifest: &Confidence) -> Confidence {
    if lockfile.level == "high" && manifest.level == "high" {
        return Confidence::new("high", "manifest+lockfile agree on dep");
    }
    let weaker = if level_rank(&lockfile.level) <= level_rank(&manifest.level) {
        lockfile
    } else {
        manifest
    };
    // Python hard-truncates to 200 chars (no ellipsis) before Confidence.
    let reason: String = format!("join: weaker side {}", weaker.reason).chars().take(200).collect();
    Confidence::new(&weaker.level, &reason)
}

/// Index (ecosystem, manifest dir, name) -> manifest row index; first wins.
fn index_manifest_rows(deps: &[Dependency]) -> HashMap<(String, String, String), usize> {
    let mut index = HashMap::new();
    for (i, d) in deps.iter().enumerate() {
        if d.is_lockfile {
            continue;
        }
        index.entry((d.ecosystem.clone(), path_parent(&d.declared_in), d.name.clone())).or_insert(i);
    }
    index
}

/// Walk ancestors of a lockfile's dir for a manifest sharing (ecosystem, name)
/// (`_find_manifest_match`).
fn find_manifest_match(
    dep: &Dependency,
    index: &HashMap<(String, String, String), usize>,
) -> Option<usize> {
    let mut walked = 0;
    let mut cursor = path_parent(&dep.declared_in);
    let mut seen: HashSet<String> = HashSet::new();
    while walked < MAX_ANCESTOR_WALK {
        if seen.contains(&cursor) {
            break;
        }
        seen.insert(cursor.clone());
        if let Some(&i) = index.get(&(dep.ecosystem.clone(), cursor.clone(), dep.name.clone())) {
            return Some(i);
        }
        let parent = path_parent(&cursor);
        if parent == cursor {
            break; // filesystem root
        }
        cursor = parent;
        walked += 1;
    }
    None
}

fn resolve_one(
    dep: &Dependency,
    index: &HashMap<(String, String, String), usize>,
    deps: &[Dependency],
) -> Dependency {
    if !dep.is_lockfile {
        return dep.clone();
    }
    let Some(m_idx) = find_manifest_match(dep, index) else {
        return dep.clone();
    };
    let m = &deps[m_idx];
    if dep.direct && dep.pin_style == m.pin_style {
        return dep.clone(); // already reconciled — don't churn confidence
    }
    let mut out = dep.clone();
    out.direct = true;
    out.pin_style = m.pin_style;
    out.parser_confidence = combine_confidence(&dep.parser_confidence, &m.parser_confidence);
    out
}

/// Reconcile manifest + lockfile views (`join`). Returns a new list; input is
/// not mutated.
pub fn join(deps: &[Dependency]) -> Vec<Dependency> {
    let index = index_manifest_rows(deps);
    deps.iter().map(|d| resolve_one(d, &index, deps)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PinStyle;

    fn dep(name: &str, ps: PinStyle, ver: &str, lock: bool, decl: &str, direct: bool, conf: &str) -> Dependency {
        Dependency {
            ecosystem: "npm".into(),
            name: name.into(),
            version: Some(ver.into()),
            declared_in: decl.into(),
            scope: "main".into(),
            is_lockfile: lock,
            pin_style: ps,
            direct,
            purl: "p".into(),
            parser_confidence: Confidence::new(conf, ""),
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".into(),
            source_extra: None,
        }
    }

    #[test]
    fn reconcile_lockfile_against_manifest() {
        let out = join(&[
            dep("a", PinStyle::Caret, "^1.0", false, "pkg/package.json", false, "high"),
            dep("a", PinStyle::Exact, "1.0.5", true, "pkg/package-lock.json", false, "high"),
            dep("orphan", PinStyle::Exact, "2.0", true, "pkg/package-lock.json", false, "high"),
        ]);
        // Manifest row untouched.
        assert_eq!((out[0].direct, out[0].pin_style), (false, PinStyle::Caret));
        // Lockfile row: direct promoted, pin copied from manifest, confidence merged.
        assert_eq!((out[1].direct, out[1].pin_style), (true, PinStyle::Caret));
        assert_eq!(out[1].parser_confidence.reason, "manifest+lockfile agree on dep");
        // Orphan lockfile row (no manifest) untouched.
        assert_eq!((out[2].direct, out[2].pin_style), (false, PinStyle::Exact));
    }

    #[test]
    fn weaker_confidence_and_nochurn_and_ancestor() {
        // Weaker side chosen when not both high.
        let out = join(&[
            dep("b", PinStyle::Caret, "^1.0", false, "pkg/package.json", false, "low"),
            dep("b", PinStyle::Exact, "1.0.5", true, "pkg/package-lock.json", false, "high"),
        ]);
        let l = out.iter().find(|d| d.is_lockfile).unwrap();
        assert_eq!((l.direct, l.pin_style, l.parser_confidence.level.as_str()), (true, PinStyle::Caret, "low"));
        assert_eq!(l.parser_confidence.reason, "join: weaker side ");

        // Already reconciled (direct + same pin) -> no churn.
        let out = join(&[
            dep("c", PinStyle::Exact, "1.0", false, "pkg/package.json", false, "high"),
            dep("c", PinStyle::Exact, "1.0", true, "pkg/package-lock.json", true, "high"),
        ]);
        let l = out.iter().find(|d| d.is_lockfile).unwrap();
        assert_eq!(l.parser_confidence.reason, ""); // untouched

        // Ancestor walk: lockfile in subdir, manifest in parent dir.
        let out = join(&[
            dep("d", PinStyle::Tilde, "~1.0", false, "root/package.json", false, "high"),
            dep("d", PinStyle::Exact, "1.2", true, "root/sub/package-lock.json", false, "high"),
        ]);
        let l = out.iter().find(|d| d.is_lockfile).unwrap();
        assert_eq!((l.direct, l.pin_style), (true, PinStyle::Tilde));
        assert_eq!(l.parser_confidence.reason, "manifest+lockfile agree on dep");
    }
}
