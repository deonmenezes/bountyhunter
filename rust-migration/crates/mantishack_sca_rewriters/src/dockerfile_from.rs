//! Dockerfile `FROM <image>:<tag>` in-place rewriter — Rust port of the pure
//! core of `packages/sca/rewriters/dockerfile_from.py`. Content in, content out.
//!
//! The `rewrite_dockerfile_from` dispatcher (fs read/write + delegation to the
//! ARG / inline-install rewriters) stays call-site in Python; the pure
//! kind-routing decision is exposed here as [`route_kind`].

use regex::Regex;
use serde_json::Value;

use crate::{docker_image_forms, py_repr, RewriteEdit, RewriteResult};

/// Classify which rewriter an edit routes to (`from` / `arg` / `inline_install`)
/// — the pure discriminator from `rewrite_dockerfile_from`. Prefers
/// `extra["kind"]`; falls back to the locator shape (`/` → image → FROM).
pub fn route_kind(edit: &RewriteEdit) -> &'static str {
    let kind = edit.extra.as_ref().and_then(|e| e.get("kind")).and_then(Value::as_str);
    match kind {
        Some("from_image") => "from",
        Some("arg") => "arg",
        Some("inline_install_pip") => "inline_install",
        _ => {
            if edit.locator.contains('/') {
                "from"
            } else {
                "arg"
            }
        }
    }
}

/// Apply FROM-image tag-bump edits to Dockerfile `text` (the pure body of
/// `_apply_from_edits`; fs read/atomic-write stays in Python).
pub fn rewrite_dockerfile_from_text(text: &str, edits: &[RewriteEdit]) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let (t, r) = apply_one_from(&new_text, edit);
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

fn apply_one_from(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    // Build the image-ref forms to match: the canonical locator plus Docker's
    // short forms when the registry is docker.io/library.
    let forms = docker_image_forms(&edit.locator);
    let image_alternates = forms.iter().map(|f| regex::escape(f)).collect::<Vec<_>>().join("|");
    let pattern = Regex::new(&format!(
        r"(?m)^(\s*FROM\s+(?:--platform=\S+\s+)?(?:{image_alternates}):)(\S+?)(\s|$|@|#)"
    ))
    .unwrap();

    let Some(caps) = pattern.captures(text) else {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found"));
    };
    let g2 = caps.get(2).unwrap();
    let current_tag = g2.as_str();
    if current_tag == edit.new_value {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "no_change"));
    }
    if current_tag != edit.old_value {
        let reason = format!(
            "value_mismatch: file has {}, plan expected {}",
            py_repr(current_tag),
            py_repr(&edit.old_value),
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }
    // Splice the tag span only (equivalent to Python's
    // ``pattern.sub(r"\g<1>{new}\g<3>", text, count=1)`` for the first match).
    let mut new_text = String::with_capacity(text.len());
    new_text.push_str(&text[..g2.start()]);
    new_text.push_str(&edit.new_value);
    new_text.push_str(&text[g2.end()..]);
    (new_text, RewriteResult::new(edit.clone(), true, "applied"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(text: &str, loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = apply_one_from(text, &RewriteEdit::new(loc, old, new));
        (t, r.applied, r.reason)
    }

    #[test]
    fn apply_from_cases() {
        assert_eq!(one("FROM docker.io/library/python:3.12 AS build\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM docker.io/library/python:3.13 AS build\n".into(), true, "applied".into()));
        assert_eq!(one("FROM python:3.12\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM python:3.13\n".into(), true, "applied".into()));
        assert_eq!(one("FROM library/python:3.12\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM library/python:3.13\n".into(), true, "applied".into()));
        assert_eq!(one("FROM --platform=linux/amd64 python:3.12 AS b\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM --platform=linux/amd64 python:3.13 AS b\n".into(), true, "applied".into()));
        assert_eq!(one("FROM ghcr.io/org/img:1.0\n", "ghcr.io/org/img", "1.0", "1.1"),
            ("FROM ghcr.io/org/img:1.1\n".into(), true, "applied".into()));
        assert_eq!(one("FROM python:9.9\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM python:9.9\n".into(), false, "value_mismatch: file has '9.9', plan expected '3.12'".into()));
        assert_eq!(one("FROM python:3.13\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM python:3.13\n".into(), false, "no_change".into()));
        assert_eq!(one("FROM alpine:3.19\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM alpine:3.19\n".into(), false, "not_found".into()));
        assert_eq!(one("FROM python:3.12 # base\n", "docker.io/library/python", "3.12", "3.13"),
            ("FROM python:3.13 # base\n".into(), true, "applied".into()));
    }

    #[test]
    fn kind_routing() {
        let mut from_kind = RewriteEdit::new("docker.io/library/python", "3.12", "3.13");
        from_kind.extra = Some(json!({"kind": "from_image"}));
        assert_eq!(route_kind(&from_kind), "from");
        let mut arg_kind = RewriteEdit::new("SEMGREP_VERSION", "1.0", "1.1");
        arg_kind.extra = Some(json!({"kind": "arg"}));
        assert_eq!(route_kind(&arg_kind), "arg");
        let mut inl = RewriteEdit::new("pip:foo", "1", "2");
        inl.extra = Some(json!({"kind": "inline_install_pip"}));
        assert_eq!(route_kind(&inl), "inline_install");
        // No kind → shape heuristic: '/' means image (FROM), else ARG.
        assert_eq!(route_kind(&RewriteEdit::new("docker.io/library/python", "3.12", "3.13")), "from");
        assert_eq!(route_kind(&RewriteEdit::new("SEMGREP_VERSION", "1.0", "1.1")), "arg");
    }
}
