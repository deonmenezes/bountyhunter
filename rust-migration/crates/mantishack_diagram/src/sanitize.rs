//! Mermaid label and ID sanitizer — Rust port of `packages/diagram/sanitize.py`.

use std::sync::OnceLock;

use regex::Regex;

/// Default max length for a single label line (`DEFAULT_MAX_LEN`).
pub const DEFAULT_MAX_LEN: usize = 80;

fn safe_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^A-Za-z0-9_-]").unwrap())
}

/// Escape characters that break Mermaid node labels (`sanitize`). Optionally
/// truncate to `max_len` with a `...` suffix (`None` / `0` disables).
pub fn sanitize(text: &str, max_len: Option<usize>) -> String {
    let result = text
        .replace('&', "&amp;")
        .replace('"', "'")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('{', "(")
        .replace('}', ")")
        .replace('\n', " ")
        .replace('\r', " ")
        .replace('\u{2028}', " ")
        .replace('\u{2029}', " ");
    match max_len {
        Some(m) if m != 0 && result.chars().count() > m => {
            let head: String = result.chars().take(m - 3).collect();
            format!("{head}...")
        }
        _ => result,
    }
}

/// Sanitize a Mermaid node ID (`sanitize_id`): strip all but `[A-Za-z0-9_-]`,
/// falling back to `"node"` when nothing meaningful remains.
pub fn sanitize_id(node_id: &str) -> String {
    let sanitized = safe_id_re().replace_all(node_id, "_").into_owned();
    if sanitized.trim_matches('_').is_empty() {
        "node".to_string()
    } else {
        sanitized
    }
}

/// Return `(sanitized_id, [raw ids that collapsed to it])` for any collision
/// (`detect_id_collisions`), in first-seen order.
pub fn detect_id_collisions(raw_ids: &[String]) -> Vec<(String, Vec<String>)> {
    let mut by_sanitized: Vec<(String, Vec<String>)> = Vec::new();
    for raw in raw_ids {
        let s = sanitize_id(raw);
        match by_sanitized.iter_mut().find(|(k, _)| *k == s) {
            Some((_, v)) => v.push(raw.clone()),
            None => by_sanitized.push((s, vec![raw.clone()])),
        }
    }
    by_sanitized
        .into_iter()
        .filter(|(_, originals)| originals.iter().collect::<std::collections::HashSet<_>>().len() > 1)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ss(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn label_sanitize() {
        assert_eq!(sanitize("a & b \"q\" <x> {y}\nz", None), "a &amp; b 'q' &lt;x&gt; (y) z");
        assert_eq!(sanitize("&<>{}", None), "&amp;&lt;&gt;()");
        assert_eq!(sanitize(&"x".repeat(100), Some(20)), format!("{}...", "x".repeat(17)));
        assert_eq!(sanitize("plain", None), "plain");
    }

    #[test]
    fn id_sanitize_and_collisions() {
        assert_eq!(sanitize_id("foo!"), "foo_");
        assert_eq!(sanitize_id("foo?"), "foo_");
        assert_eq!(sanitize_id("!!!"), "node");
        assert_eq!(sanitize_id("abc_123"), "abc_123");
        assert_eq!(sanitize_id("a b/c"), "a_b_c");
        assert_eq!(
            detect_id_collisions(&ss(&["foo!", "foo?", "bar", "bar", "baz#", "baz$"])),
            vec![("foo_".to_string(), ss(&["foo!", "foo?"])), ("baz_".to_string(), ss(&["baz#", "baz$"]))]
        );
    }
}
