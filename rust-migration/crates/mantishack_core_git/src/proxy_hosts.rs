//! Faithful port of `core/git/_proxy_hosts.py` — the egress-proxy hostname
//! allowlist for `core.git` subprocesses.
//!
//! Two-layer resolution: operator override → static default. There's no
//! calibrate layer (git's network reach is URL-derived per call, not
//! binary-scoped).
//!
//!   1. **Operator override** — `~/.config/mantishack/git-proxy-hosts.json` with
//!      a flat `{"hosts": [...]}` list. Required for private GitHub Enterprise /
//!      GitLab self-hosted / corporate git mirrors.
//!   2. **Static default** — the documented set of public forge hosts MANTISHACK
//!      commonly clones from (github.com + gitlab.com + the GitHub LFS /
//!      userassets / archive subdomains).
//!
//! The override REPLACES the default rather than extending it. The egress proxy
//! enforces deny-by-default at runtime regardless of what this module returns.

use std::path::{Path, PathBuf};

/// Static default — public forges + GitHub LFS / archive / userassets
/// subdomains LFS-using clones redirect through. These hosts MUST stay together
/// (an LFS clone breaks if any are missing).
pub const DEFAULT_GIT_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "media.githubusercontent.com",
];

/// The operator-override config path: `~/.config/mantishack/git-proxy-hosts.json`.
///
/// Mirrors Python `Path.home() / ".config" / "mantishack" / "git-proxy-hosts.json"`.
/// `Path.home()` reads `$HOME`; when unset we return the bare relative tail so
/// the (nonexistent) path degrades to "no override" — the loud failure mode is
/// at the proxy, never here.
pub fn override_config_path() -> PathBuf {
    let mut p = match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home),
        None => PathBuf::new(),
    };
    p.push(".config");
    p.push("mantishack");
    p.push("git-proxy-hosts.json");
    p
}

/// Parse override-config *text* into the resolved host list, or `None` when the
/// text doesn't yield a usable override.
///
/// Tolerant, matching Python's `_load_override`: malformed JSON, a non-object
/// root, a missing/non-array `hosts` key, or an all-garbage list all degrade to
/// `None`. Kept strings are deduplicated preserving first-seen order; an empty
/// result maps to `None` (falls through to the default rather than producing a
/// deny-all allowlist).
pub fn parse_override(text: &str) -> Option<Vec<String>> {
    let data: serde_json::Value = serde_json::from_str(text).ok()?;
    let obj = data.as_object()?;
    let hosts = obj.get("hosts")?.as_array()?;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut result: Vec<String> = Vec::new();
    for h in hosts {
        if let Some(s) = h.as_str() {
            if !s.is_empty() && !seen.contains(s) {
                seen.insert(s.to_string());
                result.push(s.to_string());
            }
        }
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Load the operator override from `path`, or `None` when no usable override is
/// configured.
///
/// Absent file, unreadable file, or non-UTF-8 bytes all degrade to `None`
/// (mirroring Python's `OSError` / `UnicodeDecodeError` tolerance). Content is
/// handed to [`parse_override`].
pub fn load_override_from(path: &Path) -> Option<Vec<String>> {
    if !path.exists() {
        return None;
    }
    // `read_to_string` fails on non-UTF-8 bytes (Python `UnicodeDecodeError`)
    // and on read errors (Python `OSError`) — both degrade to `None`.
    let text = std::fs::read_to_string(path).ok()?;
    parse_override(&text)
}

/// Resolve the allowlist against an explicit override-config `path`
/// (testable form).
///
/// Returns a fresh `Vec` each call so a caller can mutate / extend it (e.g.
/// `ls_remote` callers append the URL's host) without affecting subsequent
/// calls.
pub fn proxy_hosts_for_git_from(path: &Path) -> Vec<String> {
    match load_override_from(path) {
        Some(override_hosts) => override_hosts,
        None => DEFAULT_GIT_HOSTS.iter().map(|s| s.to_string()).collect(),
    }
}

/// Egress-proxy hostname allowlist for `core.git` subprocesses.
///
/// Two-layer resolution: operator override → static default. Reads the real
/// `~/.config/mantishack/git-proxy-hosts.json`.
pub fn proxy_hosts_for_git() -> Vec<String> {
    proxy_hosts_for_git_from(&override_config_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn default_vec() -> Vec<String> {
        DEFAULT_GIT_HOSTS.iter().map(|s| s.to_string()).collect()
    }

    fn write_cfg(dir: &tempfile::TempDir, contents: &str) -> PathBuf {
        let p = dir.path().join("git-proxy-hosts.json");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        p
    }

    #[test]
    fn default_when_no_override() {
        // Cold path: no override file → public-forge default in declared order.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("git-proxy-hosts.json");
        assert_eq!(
            proxy_hosts_for_git_from(&missing),
            vec![
                "github.com",
                "gitlab.com",
                "codeload.github.com",
                "objects.githubusercontent.com",
                "raw.githubusercontent.com",
                "media.githubusercontent.com",
            ]
        );
    }

    #[test]
    fn returns_fresh_list_each_call() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        let mut a = proxy_hosts_for_git_from(&missing);
        let b = proxy_hosts_for_git_from(&missing);
        assert_eq!(a, b);
        a.push("mutation.example.com".to_string());
        let c = proxy_hosts_for_git_from(&missing);
        assert!(!c.iter().any(|h| h == "mutation.example.com"));
    }

    #[test]
    fn override_takes_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(&dir, r#"{"hosts": ["git.corp.example.com"]}"#);
        assert_eq!(
            proxy_hosts_for_git_from(&p),
            vec!["git.corp.example.com".to_string()]
        );
    }

    #[test]
    fn override_replaces_does_not_extend() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(&dir, r#"{"hosts": ["git.corp.example.com"]}"#);
        let hosts = proxy_hosts_for_git_from(&p);
        assert!(!hosts.iter().any(|h| h == "github.com"));
        assert_eq!(hosts, vec!["git.corp.example.com".to_string()]);
    }

    #[test]
    fn override_dedupes_and_strips_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            r#"{"hosts": ["git.corp.example.com", "", "git.corp.example.com", 123, "mirror.corp.example.com"]}"#,
        );
        assert_eq!(
            proxy_hosts_for_git_from(&p),
            vec![
                "git.corp.example.com".to_string(),
                "mirror.corp.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn empty_override_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(&dir, r#"{"hosts": []}"#);
        assert_eq!(proxy_hosts_for_git_from(&p), default_vec());
    }

    #[test]
    fn override_missing_hosts_key_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(&dir, r#"{"github": ["github.com"]}"#);
        let hosts = proxy_hosts_for_git_from(&p);
        assert!(hosts.iter().any(|h| h == "github.com"));
        assert!(hosts.len() >= 6);
    }

    #[test]
    fn override_non_object_root_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(&dir, r#"["github.com"]"#);
        let hosts = proxy_hosts_for_git_from(&p);
        assert!(hosts.iter().any(|h| h == "github.com"));
        assert!(hosts.len() >= 6);
    }

    #[test]
    fn override_malformed_json_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(&dir, "{not valid json");
        let hosts = proxy_hosts_for_git_from(&p);
        assert!(hosts.iter().any(|h| h == "github.com"));
    }

    #[test]
    fn override_non_utf8_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("git-proxy-hosts.json");
        std::fs::write(&p, b"\xff\xfe\x00\x00 not utf-8").unwrap();
        let hosts = proxy_hosts_for_git_from(&p);
        assert!(hosts.iter().any(|h| h == "github.com"));
    }
}
