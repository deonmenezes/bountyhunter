//! JSON utilities — load, save, and comment-stripping.
//!
//! Faithful port of `core/json/utils.py`.
//!
//! `_strip_json_comments` is the CONFIG-flavor stripper (handles `//` and `#`
//! but NOT `/* */`). It is distinct from `jsonc::strip_jsonc_comments` which
//! targets the JSONC dialect. See Python docstrings for the full rationale.

use serde_json::Value;
use std::io::{self, Write as IoWrite};
use std::path::{Path, PathBuf};

// ── comment-stripping ────────────────────────────────────────────────────────

/// Strip `//` and `#` comments from JSON text, respecting string literals.
///
/// Config-flavor: handles `//` and `#` line comments only (no `/* */`).
/// `in_string` state persists across line boundaries so a `//` or `#` inside
/// a multi-line string value is not incorrectly treated as a comment start.
/// Direct port of Python `core.json.utils._strip_json_comments`.
pub fn strip_config_json_comments(text: &str) -> String {
    let mut lines_out: Vec<String> = Vec::new();
    let mut in_string = false;

    for line in text.split('\n') {
        let chars: Vec<char> = line.chars().collect();
        let n = chars.len();
        let mut i = 0;
        let mut cut = n; // default: keep the whole line

        while i < n {
            let ch = chars[i];
            if ch == '\\' && in_string {
                // skip escaped char — do not toggle string state on it
                i += 2;
                continue;
            }
            if ch == '"' {
                in_string = !in_string;
            } else if !in_string {
                if ch == '/' && i + 1 < n && chars[i + 1] == '/' {
                    cut = i;
                    break;
                }
                if ch == '#' {
                    cut = i;
                    break;
                }
            }
            i += 1;
        }

        lines_out.push(chars[..cut].iter().collect());
    }
    lines_out.join("\n")
}

// ── BOM handling ─────────────────────────────────────────────────────────────

/// Strip a UTF-8 BOM (`\u{FEFF}`) from the start of a string if present.
/// Mirrors Python's `encoding="utf-8-sig"`.
fn strip_bom(s: &str) -> &str {
    s.strip_prefix('\u{FEFF}').unwrap_or(s)
}

// ── load_json_with_comments ──────────────────────────────────────────────────

/// Load a JSON file that may contain `//` or `#` comments.
///
/// Returns `None` on missing file or parse error (same as Python).
/// Port of `core.json.utils.load_json_with_comments`.
pub fn load_json_with_comments(path: &Path) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("load_json_with_comments: failed to read {:?}: {}", path, e);
            return None;
        }
    };
    let text = strip_bom(&text);
    let stripped = strip_config_json_comments(text);
    if stripped.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(&stripped) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("load_json_with_comments: failed to parse {:?}: {}", path, e);
            None
        }
    }
}

// ── load_json ────────────────────────────────────────────────────────────────

/// Load a plain JSON file (no comment stripping).
///
/// Returns `None` if the file does not exist. If `strict` is false (default),
/// also returns `None` on parse errors after logging a warning. If `strict`
/// is true, propagates the error.
///
/// `allow_non_finite`: serde_json rejects NaN/Infinity by default (strict RFC
/// 8259), matching the Python default behaviour. When `allow_non_finite=true`,
/// this implementation makes a best-effort parse attempt but does not guarantee
/// preserving NaN/Infinity as special floats (serde_json has no such type).
///
/// Port of `core.json.utils.load_json`.
pub fn load_json(path: &Path, strict: bool) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let text = strip_bom(&text);
    if strict {
        let v = serde_json::from_str::<Value>(text)?;
        return Ok(Some(v));
    }
    match serde_json::from_str::<Value>(text) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            eprintln!("load_json: failed to parse {:?}: {}", path, e);
            Ok(None)
        }
    }
}

// ── save_json ────────────────────────────────────────────────────────────────

/// Save `data` as pretty-printed (indent=2) JSON.
///
/// Creates parent directories if needed. Uses atomic write (write to a temp
/// file then rename) with fsync before rename and directory fsync after.
/// Port of `core.json.utils.save_json`.
pub fn save_json(path: &Path, data: &Value, mode: Option<u32>) -> io::Result<()> {
    use std::fs;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let content = {
        let mut s = serde_json::to_string_pretty(data)?;
        s.push('\n');
        s
    };

    // Build temp path: `.~<name>.tmp.<pid>.<tid>`
    let pid = std::process::id();
    let tid = {
        // A stable per-thread id — use a thread-local counter approximation
        // since std doesn't expose a raw tid on all platforms.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TID: AtomicU64 = AtomicU64::new(1);
        thread_local! { static TID: u64 = NEXT_TID.fetch_add(1, Ordering::Relaxed); }
        TID.with(|t| *t)
    };
    let tmp_name = format!(
        ".~{}.tmp.{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("json"),
        pid,
        tid
    );
    let tmp: PathBuf = path.with_file_name(tmp_name);

    let write_result: io::Result<()> = (|| {
        let mut file = if let Some(m) = mode {
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(m)
                .open(&tmp)?
        } else {
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?
        };
        file.write_all(content.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        // best-effort: fsync the parent directory
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // ---------- strip_config_json_comments golden vectors ----------
    // Generated from Python core/json/utils._strip_json_comments

    #[test]
    fn config_strip_url_preserved() {
        assert_eq!(
            strip_config_json_comments(r#"{"url": "https://example.com"}"#),
            r#"{"url": "https://example.com"}"#
        );
    }

    #[test]
    fn config_strip_hash_in_string_preserved() {
        assert_eq!(
            strip_config_json_comments(r##"{"color": "#fff"}"##),
            r##"{"color": "#fff"}"##
        );
    }

    #[test]
    fn config_strip_hash_comment() {
        assert_eq!(
            strip_config_json_comments(r#"{"a": 1} # comment"#),
            r#"{"a": 1} "#
        );
    }

    #[test]
    fn config_strip_slash_comment() {
        assert_eq!(
            strip_config_json_comments(r#"{"a": 1} // comment"#),
            r#"{"a": 1} "#
        );
    }

    #[test]
    fn config_strip_both_comments() {
        // Python: '// header\n{"a": 1} # tail' → '\n{"a": 1} '
        assert_eq!(
            strip_config_json_comments("// header\n{\"a\": 1} # tail"),
            "\n{\"a\": 1} "
        );
    }

    #[test]
    fn config_strip_hash_inside_string_preserved() {
        assert_eq!(
            strip_config_json_comments(r##"{"tag": "#tag"}"##),
            r##"{"tag": "#tag"}"##
        );
    }

    #[test]
    fn config_strip_empty() {
        assert_eq!(strip_config_json_comments(""), "");
    }

    #[test]
    fn config_strip_pure_comment() {
        assert_eq!(strip_config_json_comments("# just a comment"), "");
    }

    #[test]
    fn config_strip_slash_only() {
        assert_eq!(strip_config_json_comments("// only"), "");
    }

    #[test]
    fn config_strip_nested_with_comment() {
        assert_eq!(
            strip_config_json_comments(r#"{"a":{"b":1}} // end"#),
            r#"{"a":{"b":1}} "#
        );
    }

    // ---------- load_json_with_comments golden vectors ----------
    // Generated from Python core/json/utils.load_json_with_comments

    fn write_tmp(content: &str) -> NamedTempFile {
        use std::io::Write as _;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn lwc_url_preserved() {
        let f = write_tmp(r#"{"url": "https://example.com"}"#);
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["url"], "https://example.com");
    }

    #[test]
    fn lwc_hash_in_string() {
        let f = write_tmp(r##"{"color": "#fff"}"##);
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["color"], "#fff");
    }

    #[test]
    fn lwc_hash_comment() {
        let f = write_tmp(r#"{"a": 1} # comment"#);
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn lwc_slash_comment() {
        let f = write_tmp(r#"{"a": 1} // comment"#);
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn lwc_both_comments() {
        let f = write_tmp("// header\n{\"a\": 1} # tail");
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn lwc_hash_inside_string() {
        let f = write_tmp(r##"{"tag": "#tag"}"##);
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["tag"], "#tag");
    }

    #[test]
    fn lwc_empty_returns_none() {
        let f = write_tmp("");
        assert!(load_json_with_comments(f.path()).is_none());
    }

    #[test]
    fn lwc_pure_comment_returns_none() {
        let f = write_tmp("# just a comment");
        assert!(load_json_with_comments(f.path()).is_none());
    }

    #[test]
    fn lwc_slash_only_returns_none() {
        let f = write_tmp("// only");
        assert!(load_json_with_comments(f.path()).is_none());
    }

    #[test]
    fn lwc_nested_with_comment() {
        let f = write_tmp(r#"{"a":{"b":1}} // end"#);
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["a"]["b"], 1);
    }

    #[test]
    fn lwc_missing_file_returns_none() {
        assert!(load_json_with_comments(Path::new("/nonexistent/file.json")).is_none());
    }

    #[test]
    fn lwc_bom_stripped() {
        // UTF-8 BOM (EF BB BF) prepended to valid JSON
        let bom = "\u{FEFF}";
        let f = write_tmp(&format!("{}{}", bom, r#"{"x":1}"#));
        let v = load_json_with_comments(f.path()).unwrap();
        assert_eq!(v["x"], 1);
    }
}
