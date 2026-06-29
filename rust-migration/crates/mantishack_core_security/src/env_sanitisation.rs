//! Faithful port of `core/security/env_sanitisation.py`.
//!
//! Two primitives shared by every subprocess-spawning path:
//!   * [`strip_env_vars`] — drop a blocklist of names, preserving the order of
//!     the surviving keys (Python preserves dict insertion order).
//!   * [`intersect_env_vars`] — the audit companion: the *sorted* list of keys
//!     present in both the env and the blocklist.

use std::collections::HashSet;

/// Insertion-ordered string map mirroring a Python `dict[str, str]`.
///
/// Python's `{k: v for k, v in env.items() if ...}` preserves insertion order,
/// so we model the env as an ordered `Vec` of pairs rather than a `HashMap`.
pub type EnvMap = Vec<(String, String)>;

/// Return a copy of `env` with every key in `names` removed.
///
/// Preserves the insertion order of the keys that remain. `names` is folded
/// into a set once for O(1) membership checks (Python builds a `frozenset`).
pub fn strip_env_vars<S: AsRef<str>>(env: &EnvMap, names: &[S]) -> EnvMap {
    let blocklist: HashSet<&str> = names.iter().map(|s| s.as_ref()).collect();
    env.iter()
        .filter(|(k, _)| !blocklist.contains(k.as_str()))
        .cloned()
        .collect()
}

/// Return the *sorted* list of keys from `env` that appear in `names`.
///
/// Audit / logging companion to [`strip_env_vars`]. Sorted output keeps log
/// lines stable across runs (Python `sorted(...)`).
pub fn intersect_env_vars<S: AsRef<str>>(env: &EnvMap, names: &[S]) -> Vec<String> {
    let blocklist: HashSet<&str> = names.iter().map(|s| s.as_ref()).collect();
    let mut out: Vec<String> = env
        .iter()
        .filter(|(k, _)| blocklist.contains(k.as_str()))
        .map(|(k, _)| k.clone())
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn em(pairs: &[(&str, &str)]) -> EnvMap {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn strip_removes_named_keys_preserving_order() {
        // Golden (Python): strip({PATH,TERMINAL,EDITOR,HOME,LD_PRELOAD},
        //                        [TERMINAL,EDITOR])
        //   == {PATH:/bin, HOME:/h, LD_PRELOAD:e.so}
        let env = em(&[
            ("PATH", "/bin"),
            ("TERMINAL", "x"),
            ("EDITOR", "vi"),
            ("HOME", "/h"),
            ("LD_PRELOAD", "e.so"),
        ]);
        let got = strip_env_vars(&env, &["TERMINAL", "EDITOR"]);
        assert_eq!(got, em(&[("PATH", "/bin"), ("HOME", "/h"), ("LD_PRELOAD", "e.so")]));
    }

    #[test]
    fn strip_preserves_surviving_order() {
        // Golden (Python): strip({B,A,C}, [A]) == {B:1, C:3}
        let env = em(&[("B", "1"), ("A", "2"), ("C", "3")]);
        assert_eq!(strip_env_vars(&env, &["A"]), em(&[("B", "1"), ("C", "3")]));
    }

    #[test]
    fn strip_empty_blocklist_is_identity() {
        let env = em(&[("A", "1"), ("B", "2")]);
        let empty: &[&str] = &[];
        assert_eq!(strip_env_vars(&env, empty), env);
    }

    #[test]
    fn strip_all_keys() {
        let env = em(&[("A", "1"), ("B", "2")]);
        assert_eq!(strip_env_vars(&env, &["A", "B"]), em(&[]));
    }

    #[test]
    fn intersect_returns_sorted_present_keys() {
        // Golden (Python): intersect({PATH,TERMINAL,EDITOR,HOME,LD_PRELOAD},
        //                            [TERMINAL,EDITOR,NOPE]) == ['EDITOR','TERMINAL']
        let env = em(&[
            ("PATH", "/bin"),
            ("TERMINAL", "x"),
            ("EDITOR", "vi"),
            ("HOME", "/h"),
            ("LD_PRELOAD", "e.so"),
        ]);
        assert_eq!(
            intersect_env_vars(&env, &["TERMINAL", "EDITOR", "NOPE"]),
            vec!["EDITOR".to_string(), "TERMINAL".to_string()]
        );
    }

    #[test]
    fn intersect_empty_when_no_overlap() {
        let env = em(&[("A", "1")]);
        assert!(intersect_env_vars(&env, &["X", "Y"]).is_empty());
    }
}
