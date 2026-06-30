//! NVD Patch-tagged reference parser — Rust port of `packages/nvd/parser.py`.
//!
//! Extracts deduplicated `(slug, sha)` pairs from NVD 2.0 vulnerability payloads
//! where `references[].tags` contains `"Patch"` and the URL matches a GitHub
//! commit or kernel.org shortlink pattern. Network I/O (the `NvdClient`) and the
//! verify oracle stay in Python; this is the pure payload parser.

use mantishack_core_url_patterns::{github_commit_url_re, kernel_sha_url_re, normalize_slug, LINUX_UPSTREAM_SLUG};
use serde_json::Value;

/// Return deduplicated `(slug, sha)` pairs from Patch-tagged refs in an NVD 2.0
/// payload (`extract_patch_refs`). Defensive on every dict/list step: a
/// malformed shape is skipped, never raised.
pub fn extract_patch_refs(payload: &Value) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let Some(vulnerabilities) = payload.get("vulnerabilities").and_then(Value::as_array) else {
        return pairs;
    };
    for vuln in vulnerabilities {
        if !vuln.is_object() {
            continue;
        }
        let Some(cve) = vuln.get("cve").and_then(Value::as_object) else { continue };
        let Some(references) = cve.get("references").and_then(Value::as_array) else { continue };
        for r in references {
            if !r.is_object() {
                continue;
            }
            let Some(tags) = r.get("tags").and_then(Value::as_array) else { continue };
            if !tags.iter().any(|t| t.as_str() == Some("Patch")) {
                continue;
            }
            let Some(url) = r.get("url").and_then(Value::as_str) else { continue };
            let url = url.trim();

            if let Some(m) = github_commit_url_re().captures(url) {
                let slug = normalize_slug(&m[1]);
                if slug.matches('/').count() != 1 {
                    continue;
                }
                let sha = m[2].to_lowercase();
                let key = (slug, sha);
                if !pairs.contains(&key) {
                    pairs.push(key);
                }
                continue;
            }
            if let Some(km) = kernel_sha_url_re().captures(url) {
                let sha = km[1].to_lowercase();
                let key = (LINUX_UPSTREAM_SLUG.to_lowercase(), sha);
                if !pairs.contains(&key) {
                    pairs.push(key);
                }
            }
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload(refs: Value) -> Value {
        json!({"vulnerabilities": [{"cve": {"references": refs}}]})
    }

    #[test]
    fn github_commit_patch_ref() {
        let p = payload(json!([
            {"tags": ["Patch"], "url": "https://github.com/Foo/Bar/commit/ABCDEF1234567890"},
            {"tags": ["Vendor Advisory"], "url": "https://github.com/x/y/commit/deadbeef00000000"},
        ]));
        let pairs = extract_patch_refs(&p);
        assert_eq!(pairs, vec![("foo/bar".to_string(), "abcdef1234567890".to_string())]);
    }

    #[test]
    fn dedup_and_malformed_shapes() {
        // dup ref + a dict-typed references (skipped) + string tags (skipped).
        let p = payload(json!([
            {"tags": ["Patch"], "url": "https://github.com/a/b/commit/1111111111111111"},
            {"tags": ["Patch"], "url": "https://github.com/a/b/commit/1111111111111111"},
            {"tags": "Patch", "url": "https://github.com/a/b/commit/2222222222222222"},
        ]));
        assert_eq!(extract_patch_refs(&p), vec![("a/b".to_string(), "1111111111111111".to_string())]);
        // non-list vulnerabilities -> empty.
        assert_eq!(extract_patch_refs(&json!({"vulnerabilities": {}})), Vec::new());
    }

    #[test]
    fn no_patch_tag_skipped() {
        let p = payload(json!([{"tags": ["Exploit"], "url": "https://github.com/a/b/commit/3333333333333333"}]));
        assert_eq!(extract_patch_refs(&p), Vec::new());
    }
}
