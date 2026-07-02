//! Typosquat candidate detector — Rust port of
//! `packages/sca/supply_chain/typosquat.py`.
//!
//! For each direct dep, computes optimal-string-alignment (Damerau-Levenshtein
//! with adjacent transpositions) distance against the bundled per-ecosystem
//! popular-name list. Names within distance 1-2 are flagged; an exact match is
//! trusted. The popular lists are embedded at build time from the Python data
//! tree (`data/popular/<eco>.json`) for a single source of truth.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use mantishack_sca::{Confidence, Dependency};
use serde_json::Value;

const MAX_DISTANCE: usize = 2;

/// One typosquat candidate finding (`TyposquatFinding`).
#[derive(Clone, Debug, PartialEq)]
pub struct TyposquatFinding {
    pub dependency: Dependency,
    pub nearest_popular: String,
    pub distance: usize,
    pub severity: String,
    pub confidence: Confidence,
}

// Embedded popular-name lists (single source of truth with the Python tree).
const POPULAR_DATA: &[(&str, &str)] = &[
    ("Cargo", include_str!("../../../../packages/sca/data/popular/Cargo.json")),
    ("Go", include_str!("../../../../packages/sca/data/popular/Go.json")),
    ("Maven", include_str!("../../../../packages/sca/data/popular/Maven.json")),
    ("npm", include_str!("../../../../packages/sca/data/popular/npm.json")),
    ("NuGet", include_str!("../../../../packages/sca/data/popular/NuGet.json")),
    ("Packagist", include_str!("../../../../packages/sca/data/popular/Packagist.json")),
    ("PyPI", include_str!("../../../../packages/sca/data/popular/PyPI.json")),
    ("RubyGems", include_str!("../../../../packages/sca/data/popular/RubyGems.json")),
];

struct Popular {
    list: Vec<String>,
    set: HashSet<String>,
    by_len: HashMap<usize, Vec<String>>,
}

fn popular_cache() -> &'static HashMap<String, Popular> {
    static CACHE: OnceLock<HashMap<String, Popular>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = HashMap::new();
        for (eco, raw) in POPULAR_DATA {
            // Mirrors _load_popular: JSON list, lowercased, non-strings dropped.
            let list: Vec<String> = serde_json::from_str::<Value>(raw)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|n| n.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_default();
            let set: HashSet<String> = list.iter().cloned().collect();
            let mut by_len: HashMap<usize, Vec<String>> = HashMap::new();
            for name in &list {
                by_len.entry(name.chars().count()).or_default().push(name.clone());
            }
            out.insert((*eco).to_string(), Popular { list, set, by_len });
        }
        out
    })
}

/// Run the candidate check on every direct dep (`scan_deps`).
pub fn scan_deps(deps: &[Dependency]) -> Vec<TyposquatFinding> {
    deps.iter().filter(|d| d.direct).filter_map(check_one).collect()
}

/// Check one dependency for a typosquat candidate (`_check_one`).
pub fn check_one(dep: &Dependency) -> Option<TyposquatFinding> {
    let popular = popular_cache().get(&dep.ecosystem)?;
    if popular.list.is_empty() {
        return None;
    }
    let name_norm = dep.name.to_lowercase();
    if popular.set.contains(&name_norm) {
        return None; // it IS the popular package
    }

    let mut candidates = vec![name_norm.clone()];
    if name_norm.starts_with('@') {
        if let Some((_, rest)) = name_norm.split_once('/') {
            candidates.push(rest.to_string());
        }
    }

    let mut best: Option<(usize, String)> = None;
    for cand in &candidates {
        let cand_chars: Vec<char> = cand.chars().collect();
        let cand_len = cand_chars.len() as isize;
        let lo = cand_len - MAX_DISTANCE as isize;
        let hi = cand_len + MAX_DISTANCE as isize;
        let mut length = lo;
        while length <= hi {
            if length >= 0 {
                if let Some(shortlist) = popular.by_len.get(&(length as usize)) {
                    for pop in shortlist {
                        if cand == pop {
                            if best.as_ref().map_or(true, |(bd, _)| *bd > 0) {
                                best = Some((0, pop.clone()));
                            }
                            continue;
                        }
                        let pop_chars: Vec<char> = pop.chars().collect();
                        let d = damerau_levenshtein(&cand_chars, &pop_chars, MAX_DISTANCE + 1);
                        if d > MAX_DISTANCE {
                            continue;
                        }
                        if best.as_ref().map_or(true, |(bd, _)| d < *bd) {
                            best = Some((d, pop.clone()));
                        }
                    }
                }
            }
            length += 1;
        }
    }

    let (distance, nearest) = best?;
    let (severity, level, reason) = if distance == 0 {
        ("high", "high", format!("bare form matches popular '{nearest}'; scoped-name namespace squat shape"))
    } else if distance == 1 {
        ("high", "medium", format!("distance-1 from popular '{nearest}'; may be a legitimate package or a typosquat"))
    } else {
        ("medium", "low", format!("distance-{distance} from popular '{nearest}'; may be a legitimate package or a typosquat"))
    };

    Some(TyposquatFinding {
        dependency: dep.clone(),
        nearest_popular: nearest,
        distance,
        severity: severity.to_string(),
        confidence: Confidence::new(level, &reason),
    })
}

/// Optimal-string-alignment distance with early-exit `cutoff`
/// (`_damerau_levenshtein`). Returns `cutoff` when the true distance exceeds it.
/// Buffer rotation replicates the Python source exactly — including the initial
/// `prev_prev` row and the final-iteration rotation, which Python also never
/// reads (hence the allow).
#[allow(unused_assignments)]
pub fn damerau_levenshtein(a: &[char], b: &[char], cutoff: usize) -> usize {
    let (la, lb) = (a.len(), b.len());
    if (la as isize - lb as isize).unsigned_abs() >= cutoff {
        return cutoff;
    }
    if la == 0 {
        return lb.min(cutoff);
    }
    if lb == 0 {
        return la.min(cutoff);
    }

    let mut prev_prev: Vec<usize> = (0..=lb).collect();
    let mut prev: Vec<usize> = vec![0; lb + 1];
    let mut cur: Vec<usize> = vec![0; lb + 1];
    for i in 1..=la {
        // `cur, prev, prev_prev = [0]*(lb+1), cur, prev`
        let old_cur = std::mem::replace(&mut cur, vec![0; lb + 1]);
        prev_prev = std::mem::replace(&mut prev, old_cur);
        cur[0] = i;
        let mut row_min = cur[0];
        for j in 1..=lb {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                cur[j] = cur[j].min(prev_prev[j - 2] + 1);
            }
            if cur[j] < row_min {
                row_min = cur[j];
            }
        }
        if row_min >= cutoff {
            return cutoff;
        }
    }
    cur[lb].min(cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantishack_sca::PinStyle;

    fn dl(a: &str, b: &str, c: usize) -> usize {
        damerau_levenshtein(&a.chars().collect::<Vec<_>>(), &b.chars().collect::<Vec<_>>(), c)
    }

    #[test]
    fn damerau_matches_python() {
        assert_eq!(dl("lodash", "lodaash", 3), 1);
        assert_eq!(dl("lodash", "loadsh", 3), 1); // transposition
        assert_eq!(dl("kitten", "sitting", 3), 3);
        assert_eq!(dl("abc", "abc", 3), 0);
        assert_eq!(dl("", "abc", 3), 3);
        assert_eq!(dl("abc", "", 3), 3);
        assert_eq!(dl("ab", "ba", 3), 1);
        assert_eq!(dl("flask", "flassk", 3), 1);
        assert_eq!(dl("requests", "reqeusts", 3), 1);
        assert_eq!(dl("a", "abcd", 3), 3);
        assert_eq!(dl("teh", "the", 3), 1);
    }

    fn dep(name: &str, eco: &str, direct: bool) -> Dependency {
        Dependency {
            ecosystem: eco.to_string(),
            name: name.to_string(),
            version: Some("1".into()),
            declared_in: "x".into(),
            scope: "main".into(),
            is_lockfile: false,
            pin_style: PinStyle::Exact,
            direct,
            purl: "p".into(),
            parser_confidence: Confidence::new("high", ""),
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".into(),
            source_extra: None,
        }
    }

    #[test]
    fn typosquat_findings() {
        let f = check_one(&dep("lodaash", "npm", true)).unwrap();
        assert_eq!((f.nearest_popular.as_str(), f.distance, f.severity.as_str(), f.confidence.level.as_str()),
            ("lodash", 1, "high", "medium"));
        assert_eq!(f.confidence.reason, "distance-1 from popular 'lodash'; may be a legitimate package or a typosquat");

        // Exact popular match is trusted.
        assert!(check_one(&dep("lodash", "npm", true)).is_none());
        // Far-away name: no finding.
        assert!(check_one(&dep("zzzznotarealpkg", "npm", true)).is_none());
        // Scoped-name namespace squat: bare form matches popular -> distance 0.
        let f = check_one(&dep("@evil/lodash", "npm", true)).unwrap();
        assert_eq!((f.distance, f.severity.as_str(), f.confidence.level.as_str()), (0, "high", "high"));
        assert_eq!(f.confidence.reason, "bare form matches popular 'lodash'; scoped-name namespace squat shape");
        // PyPI typo.
        assert_eq!(check_one(&dep("reqeusts", "PyPI", true)).unwrap().nearest_popular, "requests");
        // Unknown ecosystem: no data -> None.
        assert!(check_one(&dep("foo", "WeirdEco", true)).is_none());
    }

    #[test]
    fn scan_deps_only_direct() {
        let deps = vec![
            dep("lodaash", "npm", true),
            dep("lodash", "npm", true),
            dep("indirect", "npm", false),
        ];
        assert_eq!(scan_deps(&deps).len(), 1);
    }
}
