//! `.gitmodules` parser — Rust port of `packages/sca/parsers/gitmodules.py`.
//!
//! Parses the git-config submodule sections + classifies each URL. SHA
//! resolution (reading `.git/modules/<name>/HEAD`) is filesystem I/O left to
//! the caller; this content-based port records `version=None` (commit
//! unresolved), matching the Python parser run outside a git checkout.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::json;

use crate::models::{Confidence, Dependency, PinStyle};

const GITHUB_ECOSYSTEM: &str = "GitHub";
const GENERIC_ECOSYSTEM: &str = "GitGeneric";

fn section_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\[submodule\s+"(.+?)"\s*\]\s*$"#).unwrap())
}
fn keyval_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*(.+?)\s*$").unwrap())
}

fn parse_sections(text: &str) -> Vec<(String, HashMap<String, String>)> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_fields: HashMap<String, String> = HashMap::new();
    for raw in text.split('\n') {
        let stripped = raw.trim();
        if stripped.is_empty() || stripped.starts_with('#') || stripped.starts_with(';') {
            continue;
        }
        if let Some(m) = section_re().captures(stripped) {
            if let Some(name) = current_name.take() {
                out.push((name, std::mem::take(&mut current_fields)));
            }
            current_name = Some(m[1].to_string());
            continue;
        }
        if current_name.is_none() {
            continue;
        }
        if let Some(kv) = keyval_re().captures(raw) {
            current_fields.insert(kv[1].to_lowercase(), kv[2].to_string());
        }
    }
    if let Some(name) = current_name {
        out.push((name, current_fields));
    }
    out
}

/// `git@host:owner/repo.git` -> `https://host/owner/repo.git`; others unchanged.
fn normalise_git_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("git@") {
        if let Some((host, path)) = rest.split_once(':') {
            return format!("https://{host}/{path}");
        }
    }
    url.to_string()
}

/// `(host_lowercased, path)` from a URL (urlparse hostname/path). Scheme-less
/// inputs yield an empty host + the whole string as path.
fn url_host_path(url: &str) -> (String, String) {
    match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            let (netloc, path) = match rest.find('/') {
                Some(j) => (&rest[..j], &rest[j..]),
                None => (rest, ""),
            };
            let host_port = netloc.rsplit('@').next().unwrap_or(netloc);
            let host = host_port.split(':').next().unwrap_or(host_port);
            (host.to_lowercase(), path.to_string())
        }
        None => (String::new(), url.to_string()),
    }
}

fn generic_purl(host: &str, repo_path: &str, sha: Option<&str>) -> String {
    let mut purl = format!("pkg:generic/{host}/{repo_path}");
    if let Some(s) = sha {
        purl.push('@');
        purl.push_str(s);
    }
    purl
}

/// `(ecosystem, name, purl)` for a submodule URL (`_classify_url`).
fn classify_url(url: &str, sha: Option<&str>) -> (&'static str, Option<String>, String) {
    let (host, path) = url_host_path(&normalise_git_url(url));
    let mut repo_path = path.trim_start_matches('/').to_string();
    if let Some(stripped) = repo_path.strip_suffix(".git") {
        repo_path = stripped.to_string();
    }
    if repo_path.is_empty() {
        return (GENERIC_ECOSYSTEM, None, String::new());
    }
    if host == "github.com" || host.ends_with(".github.com") {
        match repo_path.split_once('/') {
            Some((owner, repo)) => {
                let mut purl = format!("pkg:github/{owner}/{repo}");
                if let Some(s) = sha {
                    purl.push('@');
                    purl.push_str(s);
                }
                (GITHUB_ECOSYSTEM, Some(repo_path), purl)
            }
            None => (GENERIC_ECOSYSTEM, Some(repo_path.clone()), generic_purl(&host, &repo_path, sha)),
        }
    } else {
        let name = format!("{host}/{repo_path}");
        let purl = generic_purl(&host, &repo_path, sha);
        (GENERIC_ECOSYSTEM, Some(name), purl)
    }
}

fn build_dep(section_name: &str, url: &str, sm_path: &str, sha: Option<&str>, declared_in: &str) -> Option<Dependency> {
    let (ecosystem, name, purl) = classify_url(url, sha);
    let name = name?;
    let pin_style = if sha.is_some() { PinStyle::Git } else { PinStyle::Wildcard };
    let (level, reason) = match sha {
        Some(s) => ("high", format!("git submodule pinned at {}", &s[..s.len().min(12)])),
        None => ("medium", "git submodule URL declared but commit unresolved".to_string()),
    };
    Some(Dependency {
        ecosystem: ecosystem.to_string(),
        name,
        version: sha.map(str::to_string),
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile: sha.is_some(),
        pin_style,
        direct: true,
        purl,
        parser_confidence: Confidence::new(level, &reason),
        declared_license: None,
        commented_out: false,
        source_kind: "git_submodule".to_string(),
        source_extra: Some(json!({"url": url, "path": sm_path, "submodule_name": section_name})),
    })
}

/// Parse a `.gitmodules` (`parse`). `version`/`pin` reflect an unresolved
/// commit (content-based); pass resolved SHAs at the call site for Git pins.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let sections = parse_sections(content);
    let mut out = Vec::new();
    for (section_name, fields) in &sections {
        let url = fields.get("url").map_or("", String::as_str).trim();
        let sm_path = fields.get("path").map_or("", String::as_str).trim();
        if url.is_empty() || sm_path.is_empty() {
            continue;
        }
        if let Some(d) = build_dep(section_name, url, sm_path, None, declared_in) {
            out.push(d);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submodule_sections() {
        let src = "# comment\n[submodule \"libfoo\"]\n\tpath = vendor/libfoo\n\turl = https://github.com/owner/libfoo.git\n[submodule \"sshmod\"]\n\tpath = vendor/ssh\n\turl = git@gitlab.com:group/proj.git\n[submodule \"incomplete\"]\n\tpath = vendor/x\n";
        let deps = parse(src, ".gitmodules");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        // github -> GitHub ecosystem, owner/repo name, pkg:github purl.
        assert_eq!(by("owner/libfoo").ecosystem, "GitHub");
        assert_eq!(by("owner/libfoo").purl, "pkg:github/owner/libfoo");
        assert_eq!(by("owner/libfoo").pin_style, PinStyle::Wildcard); // no sha
        // ssh git@ normalised -> gitlab generic.
        assert_eq!(by("gitlab.com/group/proj").ecosystem, "GitGeneric");
        assert_eq!(by("gitlab.com/group/proj").purl, "pkg:generic/gitlab.com/group/proj");
        // incomplete (no url) dropped.
        assert_eq!(deps.len(), 2);
    }
}
