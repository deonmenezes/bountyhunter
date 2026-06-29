use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

const TU_SOURCE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "c++", "m", "mm"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildExcluded {
    pub line: usize,
    pub summary: String,
}

fn go_build_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^//go:build\s+(.+?)\s*$").unwrap())
}

fn go_legacy_build_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^//\s*\+build\s+(.+?)\s*$").unwrap())
}

fn go_package_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*package\s+\w+").unwrap())
}

fn detect_go(content: &str) -> Option<BuildExcluded> {
    for (index, raw) in content.split('\n').enumerate() {
        let line = raw.trim();
        if go_package_re().is_match(raw) {
            return None;
        }
        if let Some(captures) = go_build_re().captures(line) {
            if captures.get(1)?.as_str().trim() == "ignore" {
                return Some(BuildExcluded {
                    line: index + 1,
                    summary: "//go:build ignore".into(),
                });
            }
        }
        if let Some(captures) = go_legacy_build_re().captures(line) {
            if captures.get(1)?.as_str().split_whitespace().eq(["ignore"]) {
                return Some(BuildExcluded {
                    line: index + 1,
                    summary: "// +build ignore".into(),
                });
            }
        }
    }
    None
}

pub fn detect_build_excluded(language: &str, content: &str) -> Option<BuildExcluded> {
    if content.is_empty() {
        return None;
    }
    match language {
        "go" => detect_go(content),
        _ => None,
    }
}

pub fn tu_membership_excluded(
    absolute_path: &str,
    translation_units: Option<&HashSet<String>>,
) -> Option<BuildExcluded> {
    let translation_units = translation_units?;
    let extension = Path::new(absolute_path)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase();
    if !TU_SOURCE_EXTENSIONS.contains(&extension.as_str())
        || translation_units.contains(absolute_path)
    {
        return None;
    }
    Some(BuildExcluded {
        line: 0,
        summary: "not in compile_commands.json".into(),
    })
}

pub fn crate_module_excluded(
    absolute_path: &str,
    crate_modules: Option<&HashSet<String>>,
) -> Option<BuildExcluded> {
    let crate_modules = crate_modules?;
    if !absolute_path.ends_with(".rs") || crate_modules.contains(absolute_path) {
        return None;
    }
    Some(BuildExcluded {
        line: 0,
        summary: "not reachable from any crate root (no mod path)".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_constraint_vectors_match_python() {
        let modern = detect_build_excluded(
            "go",
            "//go:build ignore\n\npackage main\nfunc main(){}\n",
        )
        .unwrap();
        assert_eq!(modern.line, 1);
        assert_eq!(modern.summary, "//go:build ignore");

        assert_eq!(
            detect_build_excluded("go", "// +build ignore\n\npackage main\n")
                .unwrap()
                .summary,
            "// +build ignore"
        );
        assert_eq!(
            detect_build_excluded("go", "//go:build ignore || linux\npackage main\n"),
            None
        );
        assert_eq!(
            detect_build_excluded("go", "package main\n//go:build ignore\n"),
            None
        );
        assert_eq!(
            detect_build_excluded("rust", "//go:build ignore\n"),
            None
        );
    }

    #[test]
    fn translation_unit_membership_vectors() {
        let units = HashSet::from(["/p/built.c".to_string()]);
        assert!(tu_membership_excluded("/p/unbuilt.c", Some(&units)).is_some());
        assert_eq!(
            tu_membership_excluded("/p/built.c", Some(&units)),
            None
        );
        for exempt in ["/p/u.h", "/p/u.hpp", "/p/a.py", "/p/a.rs"] {
            assert_eq!(tu_membership_excluded(exempt, Some(&units)), None);
        }
        for extension in ["cc", "cpp", "cxx", "c++", "m", "mm"] {
            assert!(
                tu_membership_excluded(&format!("/p/x.{extension}"), Some(&units)).is_some()
            );
        }
    }

    #[test]
    fn rust_module_membership_vectors() {
        let modules = HashSet::from(["/p/lib.rs".to_string()]);
        assert!(crate_module_excluded("/p/orphan.rs", Some(&modules)).is_some());
        assert_eq!(
            crate_module_excluded("/p/lib.rs", Some(&modules)),
            None
        );
        assert_eq!(crate_module_excluded("/p/a.c", Some(&modules)), None);
        assert_eq!(crate_module_excluded("/p/a.rs", None), None);
    }
}
