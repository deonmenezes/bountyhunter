//! CMake FetchContent parser — Rust port of
//! `packages/sca/parsers/cmake_fetchcontent.py`. Extracts
//! `FetchContent_Declare(...)` external deps from a `CMakeLists.txt`. Takes
//! already-read content.

use std::sync::OnceLock;

use regex::Regex;

use crate::models::{Confidence, Dependency, PinStyle};

fn fetchcontent_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)FetchContent_Declare\s*\(\s*([A-Za-z_][A-Za-z0-9_-]*)\s+([^)]*)\)").unwrap()
    })
}
fn github_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^https?://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$").unwrap()
    })
}
fn url_ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"/archive/(?:refs/tags/)?([^/]+?)\.(?:tar\.gz|tar\.xz|tar\.bz2|zip)").unwrap()
    })
}
fn comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"#[^\n]*").unwrap())
}

const KEYS: &[&str] = &[
    "GIT_REPOSITORY", "GIT_TAG", "GIT_SHALLOW", "GIT_PROGRESS", "GIT_SUBMODULES",
    "URL", "URL_HASH", "URL_MD5", "DOWNLOAD_NAME", "SOURCE_DIR", "BINARY_DIR",
    "PATCH_COMMAND", "CONFIGURE_COMMAND", "BUILD_COMMAND", "INSTALL_COMMAND",
    "OVERRIDE_FIND_PACKAGE", "FIND_PACKAGE_ARGS", "EXCLUDE_FROM_ALL", "SYSTEM",
];

fn tokenise(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '"' {
            match chars[i + 1..].iter().position(|&x| x == '"') {
                Some(rel) => {
                    let j = i + 1 + rel;
                    tokens.push(chars[i + 1..j].iter().collect());
                    i = j + 1;
                }
                None => {
                    tokens.push(chars[i + 1..].iter().collect());
                    break;
                }
            }
        } else {
            let mut j = i;
            while j < chars.len() && !chars[j].is_whitespace() {
                j += 1;
            }
            tokens.push(chars[i..j].iter().collect());
            i = j;
        }
    }
    tokens
}

fn parse_kv(args_text: &str) -> Vec<(String, String)> {
    let text = comment_re().replace_all(args_text, " ");
    let tokens = tokenise(&text);
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let upper = tokens[i].to_uppercase();
        if KEYS.contains(&upper.as_str()) {
            let mut j = i + 1;
            let mut value_parts = Vec::new();
            while j < tokens.len() && !KEYS.contains(&tokens[j].to_uppercase().as_str()) {
                value_parts.push(tokens[j].clone());
                j += 1;
            }
            // Last assignment wins (dict semantics).
            let value = value_parts.join(" ").trim().to_string();
            if let Some(slot) = out.iter_mut().find(|(k, _)| *k == upper) {
                slot.1 = value;
            } else {
                out.push((upper, value));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn kv_get<'a>(kv: &'a [(String, String)], key: &str) -> Option<&'a str> {
    kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

fn build_dep(name: &str, args_text: &str, declared_in: &str) -> Option<Dependency> {
    let kv = parse_kv(args_text);
    let git_repo = kv_get(&kv, "GIT_REPOSITORY");
    let git_tag = kv_get(&kv, "GIT_TAG");
    let url = kv_get(&kv, "URL");

    let (ecosystem, canonical_name, version, mut purl);
    if let Some(git_repo) = git_repo {
        version = git_tag.map(str::to_string);
        if let Some(gh) = github_re().captures(git_repo) {
            ecosystem = "GitHub";
            canonical_name = format!("{}/{}", &gh[1], &gh[2]);
            purl = format!("pkg:github/{}/{}", &gh[1], &gh[2]);
        } else {
            ecosystem = "CMake-FetchContent";
            canonical_name = name.to_string();
            purl = format!("pkg:generic/{name}");
        }
    } else if let Some(url) = url {
        let ref_ = url_ref_re().captures(url).map(|m| m[1].to_string());
        version = ref_;
        let before_archive = url.split("/archive/").next().unwrap_or(url);
        if let Some(gh) = github_re().captures(before_archive) {
            ecosystem = "GitHub";
            canonical_name = format!("{}/{}", &gh[1], &gh[2]);
            purl = format!("pkg:github/{}/{}", &gh[1], &gh[2]);
        } else {
            ecosystem = "CMake-FetchContent";
            canonical_name = name.to_string();
            purl = format!("pkg:generic/{name}");
        }
    } else {
        return None;
    }

    let pin_style = if version.is_some() { PinStyle::Exact } else { PinStyle::Wildcard };
    if let Some(v) = &version {
        purl = format!("{purl}@{v}");
    }
    Some(Dependency {
        ecosystem: ecosystem.to_string(),
        name: canonical_name,
        version,
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile: false,
        pin_style,
        direct: true,
        purl,
        parser_confidence: Confidence::new(
            "medium",
            "extracted from CMake FetchContent_Declare; OSV matching only fires for github.com-hosted deps",
        ),
        declared_license: None,
        commented_out: false,
        source_kind: "cmake".to_string(),
        source_extra: None,
    })
}

/// Parse a `CMakeLists.txt` (`parse_cmake_lists`): one Dependency per
/// `FetchContent_Declare`.
pub fn parse_cmake_lists(content: &str, declared_in: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    for m in fetchcontent_re().captures_iter(content) {
        if let Some(d) = build_dep(&m[1], &m[2], declared_in) {
            out.push(d);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetchcontent_decls() {
        let src = "cmake_minimum_required(VERSION 3.20)\n\nFetchContent_Declare(\n  googletest\n  GIT_REPOSITORY https://github.com/google/googletest.git\n  GIT_TAG v1.14.0  # comment\n)\n\nFetchContent_Declare(json\n  URL https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz\n)\n\nFetchContent_Declare(localdep\n  SOURCE_DIR /opt/local\n)\n";
        let deps = parse_cmake_lists(src, "CMakeLists.txt");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("google/googletest").ecosystem, "GitHub");
        assert_eq!(by("google/googletest").version.as_deref(), Some("v1.14.0"));
        assert_eq!(by("google/googletest").purl, "pkg:github/google/googletest@v1.14.0");
        // URL form: github owner/repo from before /archive/, ref from the tarball.
        assert_eq!(by("nlohmann/json").version.as_deref(), Some("v3.11.3"));
        // localdep has neither GIT_REPOSITORY nor URL -> dropped.
        assert_eq!(deps.len(), 2);
    }
}
