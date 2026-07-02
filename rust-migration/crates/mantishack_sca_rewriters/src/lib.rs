//! Manifest version-pin rewriters — Rust port of `packages/sca/rewriters/`.
//!
//! The shared `RewriteEdit` / `RewriteResult` records and each rewriter's pure
//! content→(new_content, results) transform port here. The atomic file
//! read/write wrapper (`rewrite(path, edits)` dispatch + `_atomic_write`) stays
//! call-site in Python and drives these text functions.

use serde_json::Value;

pub mod dockerfile_arg;
pub mod dockerfile_from;
pub mod dockerfile_inline_install;
pub mod csproj;
pub mod directory_packages_props;
pub mod gha_uses;
pub mod gradle_version_catalog;
pub mod helm_chart;
pub mod yaml_image;

pub use csproj::rewrite_csproj_text;
pub use directory_packages_props::rewrite_directory_packages_props_text;
pub use gradle_version_catalog::rewrite_libs_versions_toml_text;
pub use helm_chart::rewrite_chart_yaml_text;
pub use dockerfile_arg::rewrite_dockerfile_arg_text;
pub use dockerfile_from::{rewrite_dockerfile_from_text, route_kind};
pub use dockerfile_inline_install::rewrite_dockerfile_inline_install_text;
pub use gha_uses::rewrite_gha_uses_text;
pub use yaml_image::rewrite_yaml_image_text;

/// A single proposed edit to a manifest file (`RewriteEdit`). `locator`
/// identifies WHAT to edit (semantics are rewriter-specific); `extra` is a
/// kind-specific metadata escape-hatch (e.g. GHA SHA pins).
#[derive(Clone, Debug, PartialEq)]
pub struct RewriteEdit {
    pub locator: String,
    pub old_value: String,
    pub new_value: String,
    pub extra: Option<Value>,
}

impl RewriteEdit {
    pub fn new(locator: &str, old_value: &str, new_value: &str) -> Self {
        Self {
            locator: locator.to_string(),
            old_value: old_value.to_string(),
            new_value: new_value.to_string(),
            extra: None,
        }
    }
}

/// Per-edit outcome from a rewriter (`RewriteResult`).
#[derive(Clone, Debug, PartialEq)]
pub struct RewriteResult {
    pub edit: RewriteEdit,
    pub applied: bool,
    pub reason: String,
}

impl RewriteResult {
    pub fn new(edit: RewriteEdit, applied: bool, reason: &str) -> Self {
        Self { edit, applied, reason: reason.to_string() }
    }
}

/// Build the image-ref forms to match for a `{registry}/{repository}` locator:
/// the canonical locator plus Docker's short forms when the registry is
/// `docker.io/library`. Shared by the `dockerfile_from` and `yaml_image`
/// rewriters (mirrors the identical `forms` construction in each).
pub(crate) fn docker_image_forms(locator: &str) -> Vec<String> {
    let mut forms = vec![locator.to_string()];
    let (registry, rest) = match locator.split_once('/') {
        Some((r, rest)) => (r, rest),
        None => (locator, ""),
    };
    if registry == "docker.io" && !rest.is_empty() {
        match rest.split_once('/') {
            Some((namespace, image)) if namespace == "library" && !image.is_empty() => {
                forms.push(image.to_string());
                forms.push(format!("library/{image}"));
                forms.push(format!("docker.io/{image}"));
            }
            _ => forms.push(rest.to_string()),
        }
    }
    forms
}

/// Shared body of the MSBuild XML rewriters (`csproj` +
/// `directory_packages_props`): try each pattern in order, and on the first
/// whose `version` named group matches, splice the new value (or report
/// `value_mismatch`). `applied` results carry an empty reason, matching Python.
/// `mismatch_label` is `version` (csproj) or `Version` (props).
pub(crate) fn apply_named_version_edit(
    text: &str,
    edit: &RewriteEdit,
    patterns: &[regex::Regex],
    mismatch_label: &str,
) -> (String, RewriteResult) {
    for pat in patterns {
        let Some(caps) = pat.captures(text) else { continue };
        let vg = caps.name("version").unwrap();
        let current = vg.as_str();
        if current != edit.old_value {
            let reason = format!(
                "value_mismatch: file has {mismatch_label}={}, edit expected {}",
                py_repr(current),
                py_repr(&edit.old_value),
            );
            return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
        }
        let mut new_text = String::with_capacity(text.len());
        new_text.push_str(&text[..vg.start()]);
        new_text.push_str(&edit.new_value);
        new_text.push_str(&text[vg.end()..]);
        return (new_text, RewriteResult::new(edit.clone(), true, ""));
    }
    (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found"))
}

/// CPython `repr()` for a `str` over the printable/common-escape range — used to
/// reproduce `{value!r}` interpolation in rewriter reason strings byte-for-byte.
pub(crate) fn py_repr(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
