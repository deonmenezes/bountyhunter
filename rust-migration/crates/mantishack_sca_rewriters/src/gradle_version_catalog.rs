//! Gradle `libs.versions.toml` rewriter — Rust port of the pure core of
//! `packages/sca/rewriters/gradle_version_catalog.py`. Content in, content out.
//!
//! The section-boundary anchor `(?:(?!^\s*\[)[\s\S])*?` uses a negative
//! lookahead, so these patterns run on `fancy-regex` rather than `regex`.

use fancy_regex::Regex;

use crate::{py_repr, RewriteEdit, RewriteResult};

fn version_key_pattern(key: &str) -> Regex {
    Regex::new(&format!(
        r#"(?m)(?P<hdr>^\s*\[versions\]\s*$)(?P<inter>(?:(?!^\s*\[)[\s\S])*?)(?P<lead>^\s*{key}\s*=\s*['"])(?P<version>[^'"]*)(?P<tail>['"])"#
    ))
    .unwrap()
}

fn inline_library_version_pattern(alias: &str) -> Regex {
    Regex::new(&format!(
        r#"(?m)(?P<hdr>^\s*\[libraries\]\s*$)(?P<inter>(?:(?!^\s*\[)[\s\S])*?)(?P<lead>^\s*{alias}\s*=\s*\{{[^}}\n]*?version\s*=\s*['"])(?P<version>[^'"]*)(?P<tail>['"][^}}\n]*\}})"#
    ))
    .unwrap()
}

fn inline_library_string_pattern(alias: &str) -> Regex {
    Regex::new(&format!(
        r#"(?m)(?P<hdr>^\s*\[libraries\]\s*$)(?P<inter>(?:(?!^\s*\[)[\s\S])*?)(?P<lead>^\s*{alias}\s*=\s*['"][^'":]+:[^'":]+:)(?P<version>[^'"]+)(?P<tail>['"])"#
    ))
    .unwrap()
}

fn inline_plugin_version_pattern(alias: &str) -> Regex {
    Regex::new(&format!(
        r#"(?m)(?P<hdr>^\s*\[plugins\]\s*$)(?P<inter>(?:(?!^\s*\[)[\s\S])*?)(?P<lead>^\s*{alias}\s*=\s*\{{[^}}\n]*?version\s*=\s*['"])(?P<version>[^'"]*)(?P<tail>['"][^}}\n]*\}})"#
    ))
    .unwrap()
}

/// Apply `[versions]` / `[libraries]` / `[plugins]` version edits to a Gradle
/// version catalog `text` (pure body of `rewrite_libs_versions_toml`; fs
/// read/atomic-write stays in Python). Each edit locator is
/// `version:<key>` / `library:<alias>` / `plugin:<alias>`.
pub fn rewrite_libs_versions_toml_text(text: &str, edits: &[RewriteEdit]) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let (t, r) = apply_one(&new_text, edit);
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

fn apply_one(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    let (section, key) = match edit.locator.split_once(':') {
        Some((s, k)) => (s, k),
        None => ("", ""),
    };
    if key.is_empty() {
        let reason = format!(
            "malformed locator {}; expected '<section>:<key>' (section in version/library/plugin)",
            py_repr(&edit.locator)
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }
    let k = fancy_regex::escape(key);
    let patterns: Vec<Regex> = match section {
        "version" => vec![version_key_pattern(&k)],
        "library" => vec![inline_library_version_pattern(&k), inline_library_string_pattern(&k)],
        "plugin" => vec![inline_plugin_version_pattern(&k)],
        _ => {
            let reason = format!("unknown locator section {}", py_repr(section));
            return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
        }
    };

    for pat in &patterns {
        let Ok(Some(caps)) = pat.captures(text) else { continue };
        let vg = caps.name("version").unwrap();
        let current = vg.as_str();
        if current != edit.old_value {
            let reason = format!(
                "value_mismatch: catalog has version={}, edit expected {}",
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

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = "[versions]\nspring-boot = \"3.0.0\"\njunit = \"5.9.0\"\n\n[libraries]\nguava = { module = \"com.google.guava:guava\", version = \"31.0\" }\nlombok = \"org.projectlombok:lombok:1.18.24\"\n\n[plugins]\nksp = { id = \"com.google.devtools.ksp\", version = \"1.9.0\" }\n";

    fn one(loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = apply_one(CATALOG, &RewriteEdit::new(loc, old, new));
        (t, r.applied, r.reason)
    }

    #[test]
    fn catalog_cases() {
        let (t, applied, _) = one("version:spring-boot", "3.0.0", "3.1.0");
        assert!(applied);
        assert!(t.contains("spring-boot = \"3.1.0\""));
        // junit lives under [versions], not [libraries] — section anchor keeps it right.
        let (t, applied, _) = one("version:junit", "5.9.0", "5.10.0");
        assert!(applied && t.contains("junit = \"5.10.0\""));
        let (t, applied, _) = one("library:guava", "31.0", "32.0");
        assert!(applied && t.contains("version = \"32.0\""));
        let (t, applied, _) = one("library:lombok", "1.18.24", "1.18.30");
        assert!(applied && t.contains("lombok:1.18.30"));
        let (t, applied, _) = one("plugin:ksp", "1.9.0", "2.0.0");
        assert!(applied && t.contains("version = \"2.0.0\""));
    }

    #[test]
    fn catalog_failure_modes() {
        assert_eq!(one("version:spring-boot", "9.9.9", "3.1.0").2,
            "value_mismatch: catalog has version='3.0.0', edit expected '9.9.9'");
        assert_eq!(one("version:nope", "1.0", "1.1").2, "not_found");
        assert_eq!(one("spring-boot", "3.0.0", "3.1.0").2,
            "malformed locator 'spring-boot'; expected '<section>:<key>' (section in version/library/plugin)");
        assert_eq!(one("foo:bar", "1.0", "1.1").2, "unknown locator section 'foo'");
    }
}
