//! `.pre-commit-config.yaml` parser — Rust port of
//! `packages/sca/parsers/precommit.py`. Takes already-read content.
//!
//! Each `repos:` entry pins a git `rev` of a hook-providing repo. Well-known
//! repos are resolved through the curated `data/precommit_repo_map.json` map
//! (embedded at build time from the Python tree — single source of truth) so
//! OSV matching fires against the underlying tool (PyPI/npm/…), not the GitHub
//! repo name. Unmapped repos fall back to a `pkg:github/...` purl. `local` and
//! `meta` pseudo-repos are skipped. Each repo emits ONE row (the `rev` pins the
//! whole repository); hook ids land in `source_extra.hook_ids`. Per-hook
//! `additional_dependencies` become their own rows.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const GITHUB_FALLBACK_ECOSYSTEM: &str = "GitHub";

// Embedded at compile time from the Python data file so the map has a single
// source of truth. Matches Python's `_REPO_MAP_PATH` load.
const REPO_MAP_JSON: &str =
    include_str!("../../../../packages/sca/data/precommit_repo_map.json");

/// Curated repo→(ecosystem, name) map. Keys starting with `_` are metadata and
/// skipped; entries must carry string `ecosystem` + `name` (mirrors
/// `_load_repo_map`).
fn repo_map() -> &'static HashMap<String, (String, String)> {
    static MAP: OnceLock<HashMap<String, (String, String)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut out = HashMap::new();
        let Ok(data) = serde_json::from_str::<Value>(REPO_MAP_JSON) else { return out };
        let Some(obj) = data.as_object() else { return out };
        for (key, val) in obj {
            if key.starts_with('_') {
                continue;
            }
            let Some(vobj) = val.as_object() else { continue };
            let eco = vobj.get("ecosystem").and_then(Value::as_str);
            let name = vobj.get("name").and_then(Value::as_str);
            if let (Some(eco), Some(name)) = (eco, name) {
                out.insert(key.clone(), (eco.to_string(), name.to_string()));
            }
        }
        out
    })
}

/// Parse a `.pre-commit-config.yaml` (`parse`). File reading stays at the call
/// site; `declared_in` is the manifest path.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_yaml::from_str::<Value>(content) else { return Vec::new() };
    let Some(obj) = data.as_object() else { return Vec::new() };

    // `repos = data.get("repos") or []; if not list: return []`. A truthy
    // non-list and a missing/empty value both yield an empty result.
    let Some(repos) = obj.get("repos").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut out: Vec<Dependency> = Vec::new();
    for entry in repos {
        if let Some(dep) = build_dep(entry, declared_in) {
            out.push(dep);
        }
        out.extend(extract_additional_deps(entry, declared_in));
    }
    out
}

fn build_dep(entry: &Value, declared_in: &str) -> Option<Dependency> {
    let obj = entry.as_object()?;
    let repo = obj.get("repo").and_then(Value::as_str)?;
    let repo = repo.trim();
    if repo.is_empty() || repo == "local" || repo == "meta" {
        return None;
    }

    let rev = obj.get("rev").and_then(Value::as_str)?;
    let rev = rev.trim();
    if rev.is_empty() {
        return None;
    }

    let canonical = canonicalise_repo(repo)?;

    let mut hook_ids: Vec<Value> = Vec::new();
    if let Some(hooks) = obj.get("hooks").and_then(Value::as_array) {
        for h in hooks {
            if let Some(hid) = h.as_object().and_then(|m| m.get("id")).and_then(Value::as_str) {
                hook_ids.push(Value::String(hid.to_string()));
            }
        }
    }

    let pin_style = classify_rev(rev);
    let (eco, name, purl, mapped);
    if let Some((meco, mname)) = repo_map().get(&canonical) {
        let purl_type = eco_to_purl(meco);
        purl = format!("pkg:{purl_type}/{mname}@{rev}");
        eco = meco.clone();
        name = mname.clone();
        mapped = true;
    } else {
        // Unmapped — GitHub purl for visibility. `canonical` is
        // `{host}/{path}` (lowercased); partition the host off.
        let (host, path) = match canonical.split_once('/') {
            Some((h, p)) => (h, p),
            None => (canonical.as_str(), ""),
        };
        name = if host == "github.com" && !path.is_empty() {
            path.to_string()
        } else {
            canonical.clone()
        };
        purl = format!("pkg:github/{name}@{rev}");
        eco = GITHUB_FALLBACK_ECOSYSTEM.to_string();
        mapped = false;
    }

    let (level, reason) = if mapped {
        ("high", format!("pre-commit repo {repo} mapped to {eco}:{name}"))
    } else {
        (
            "medium",
            format!("pre-commit repo {repo} unmapped \u{2014} emitted as GitHub purl"),
        )
    };

    Some(Dependency {
        ecosystem: eco,
        name,
        version: Some(rev.to_string()),
        declared_in: declared_in.to_string(),
        scope: "dev".to_string(),
        is_lockfile: false,
        pin_style,
        direct: true,
        purl,
        parser_confidence: Confidence::new(level, &reason),
        declared_license: None,
        commented_out: false,
        source_kind: "precommit".to_string(),
        source_extra: Some(json!({
            "repo": repo,
            "canonical": canonical,
            "hook_ids": Value::Array(hook_ids),
        })),
    })
}

fn extract_additional_deps(entry: &Value, declared_in: &str) -> Vec<Dependency> {
    let Some(obj) = entry.as_object() else { return Vec::new() };
    // Note: unlike `build_dep`, the Python code does NOT strip `repo` here.
    let Some(repo) = obj.get("repo").and_then(Value::as_str) else { return Vec::new() };
    if repo == "local" || repo == "meta" {
        return Vec::new();
    }
    let Some(hooks) = obj.get("hooks").and_then(Value::as_array) else { return Vec::new() };

    let ecosystem = match canonicalise_repo(repo) {
        Some(canonical) => repo_map()
            .get(&canonical)
            .map(|(eco, _)| eco.clone())
            .unwrap_or_else(|| "PyPI".to_string()),
        None => "PyPI".to_string(),
    };

    let mut out: Vec<Dependency> = Vec::new();
    for hook in hooks {
        let Some(hobj) = hook.as_object() else { continue };
        let hook_id = hobj.get("id").and_then(Value::as_str);
        let Some(addl) = hobj.get("additional_dependencies").and_then(Value::as_array) else {
            continue;
        };
        for spec in addl {
            let Some(spec) = spec.as_str() else { continue };
            if spec.trim().is_empty() {
                continue;
            }
            if let Some(dep) =
                build_addl_dep(spec.trim(), &ecosystem, declared_in, hook_id, repo)
            {
                out.push(dep);
            }
        }
    }
    out
}

fn build_addl_dep(
    spec: &str,
    ecosystem: &str,
    declared_in: &str,
    hook_id: Option<&str>,
    hook_repo: &str,
) -> Option<Dependency> {
    let (name, version, pin_style) = classify_addl_spec(spec, ecosystem);
    if name.is_empty() {
        return None;
    }
    let purl_type = eco_to_purl(ecosystem);
    let mut purl = format!("pkg:{purl_type}/{name}");
    // Python `if version:` — empty string is falsy, so no `@` is appended.
    if let Some(v) = version.as_deref() {
        if !v.is_empty() {
            purl.push('@');
            purl.push_str(v);
        }
    }
    let reason = format!(
        "pre-commit additional_dependencies spec {} on hook {} from {}",
        py_repr(spec),
        hook_id.unwrap_or("<unknown>"),
        hook_repo,
    );
    Some(Dependency {
        ecosystem: ecosystem.to_string(),
        name,
        version,
        declared_in: declared_in.to_string(),
        scope: "dev".to_string(),
        is_lockfile: false,
        pin_style,
        direct: true,
        purl,
        parser_confidence: Confidence::new("medium", &reason),
        declared_license: None,
        commented_out: false,
        source_kind: "precommit_additional".to_string(),
        source_extra: Some(json!({
            "spec": spec,
            "hook_id": hook_id,
            "hook_repo": hook_repo,
        })),
    })
}

fn addl_scoped_npm_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(@[^/]+/[^@<>=~ ]+)([<>=~@].*)?$").unwrap())
}

fn addl_general_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([A-Za-z0-9._\-]+)(\[[^\]]*\])?(.*)$").unwrap())
}

/// Split a PEP 508 / npm install spec into (name, version, pin_style).
fn classify_addl_spec(spec: &str, ecosystem: &str) -> (String, Option<String>, PinStyle) {
    if ecosystem == "npm" && spec.starts_with('@') {
        if let Some(caps) = addl_scoped_npm_re().captures(spec) {
            let name = caps.get(1).unwrap().as_str().to_string();
            let ver_part = caps
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .trim_start_matches('@')
                .trim();
            return wrap_version(name, ver_part);
        }
    }
    let Some(caps) = addl_general_re().captures(spec) else {
        return (String::new(), None, PinStyle::Unknown);
    };
    let name = caps.get(1).unwrap().as_str().to_string();
    let rest = caps.get(3).map(|m| m.as_str()).unwrap_or("").trim();
    wrap_version(name, rest)
}

fn wrap_version(name: String, ver_part: &str) -> (String, Option<String>, PinStyle) {
    if ver_part.is_empty() {
        return (name, None, PinStyle::Wildcard);
    }
    if let Some(rest) = ver_part.strip_prefix("==") {
        return (name, Some(rest.trim().to_string()), PinStyle::Exact);
    }
    if let Some(rest) = ver_part.strip_prefix('^') {
        return (name, Some(rest.trim().to_string()), PinStyle::Caret);
    }
    if let Some(rest) = ver_part.strip_prefix('~') {
        return (name, Some(rest.trim().to_string()), PinStyle::Tilde);
    }
    if ver_part.contains('<') || ver_part.contains('>') || ver_part.contains(',') {
        return (name, Some(ver_part.to_string()), PinStyle::Range);
    }
    if ver_part.starts_with('=') {
        return (name, Some(ver_part.trim_start_matches('=').trim().to_string()), PinStyle::Exact);
    }
    let v = ver_part.trim_start_matches('@').trim();
    let version = if v.is_empty() { None } else { Some(v.to_string()) };
    (name, version, PinStyle::Exact)
}

/// Normalise a pre-commit `repo:` URL to a lookup key
/// (`github.com/org/repo`, lowercased, `.git` stripped). SSH form
/// `git@host:path` is rewritten to `https://host/path` first.
fn canonicalise_repo(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches('/');
    let rewritten;
    let work: &str = if url.starts_with("git@") && url.contains(':') {
        let body = &url["git@".len()..];
        let (host, path) = body.split_once(':').unwrap();
        rewritten = format!("https://{host}/{path}");
        &rewritten
    } else {
        url
    };

    let (host, raw_path) = urlparse_host_path(work)?;
    let mut path = raw_path.trim_start_matches('/').to_string();
    if let Some(stripped) = path.strip_suffix(".git") {
        path = stripped.to_string();
    }
    if host.is_empty() || path.is_empty() {
        return None;
    }
    Some(format!("{host}/{path}").to_lowercase())
}

/// Minimal `urllib.parse.urlparse` facsimile: returns (hostname, path) for a
/// `scheme://netloc/path` URL. Returns None when there is no `://` (matching
/// urlparse yielding an empty hostname for a schemeless string). Hostname is
/// lowercased, userinfo/port stripped; path retains its leading slash.
fn urlparse_host_path(url: &str) -> Option<(String, String)> {
    let idx = url.find("://")?;
    let rest = &url[idx + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let netloc = &rest[..end];
    let after = &rest[end..];
    let path = if after.starts_with('/') {
        let p_end = after.find(['?', '#']).unwrap_or(after.len());
        &after[..p_end]
    } else {
        ""
    };
    let host_port = netloc.rsplit('@').next().unwrap_or(netloc);
    let host = host_port.split(':').next().unwrap_or(host_port).to_lowercase();
    Some((host, path.to_string()))
}

fn classify_rev(rev: &str) -> PinStyle {
    static SHA: OnceLock<Regex> = OnceLock::new();
    static SEMVERISH: OnceLock<Regex> = OnceLock::new();
    let sha = SHA.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{40}$").unwrap());
    let semverish = SEMVERISH.get_or_init(|| Regex::new(r"^v?\d").unwrap());
    if sha.is_match(rev) {
        PinStyle::Git
    } else if semverish.is_match(rev) {
        PinStyle::Exact
    } else {
        PinStyle::Unknown
    }
}

fn eco_to_purl(ecosystem: &str) -> String {
    match ecosystem {
        "PyPI" => "pypi".to_string(),
        "npm" => "npm".to_string(),
        "RubyGems" => "gem".to_string(),
        "Cargo" => "cargo".to_string(),
        "Go" => "golang".to_string(),
        "NuGet" => "nuget".to_string(),
        "Packagist" => "composer".to_string(),
        "Maven" => "maven".to_string(),
        other => other.to_lowercase(),
    }
}

/// CPython `repr()` for a `str` over the printable/common-escape range — used to
/// reproduce the `{spec!r}` interpolation in confidence reasons byte-for-byte.
fn py_repr(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_json(content: &str, declared_in: &str) -> Vec<Value> {
        parse(content, declared_in).iter().map(Dependency::to_json).collect()
    }

    #[test]
    fn mapped_and_unmapped() {
        let src = "repos:\n\
            \x20 - repo: https://github.com/astral-sh/ruff-pre-commit\n\
            \x20   rev: v0.6.9\n\
            \x20   hooks:\n\
            \x20     - id: ruff\n\
            \x20     - id: ruff-format\n\
            \x20 - repo: https://github.com/psf/black\n\
            \x20   rev: 24.10.0\n\
            \x20   hooks:\n\
            \x20     - id: black\n\
            \x20 - repo: https://github.com/some/unknown-hook.git\n\
            \x20   rev: v1.2.3\n\
            \x20   hooks:\n\
            \x20     - id: thing\n\
            \x20 - repo: local\n\
            \x20   hooks:\n\
            \x20     - id: my-script\n\
            \x20 - repo: meta\n\
            \x20   hooks:\n\
            \x20     - id: check-hooks-apply\n";
        let got = parse_json(src, "/x/.pre-commit-config.yaml");
        assert_eq!(got.len(), 3);
        assert_eq!(
            got[0],
            json!({
                "ecosystem": "PyPI", "name": "ruff", "version": "v0.6.9",
                "declared_in": "/x/.pre-commit-config.yaml", "scope": "dev",
                "is_lockfile": false, "pin_style": "exact", "direct": true,
                "purl": "pkg:pypi/ruff@v0.6.9",
                "parser_confidence": {"level": "high",
                    "reason": "pre-commit repo https://github.com/astral-sh/ruff-pre-commit mapped to PyPI:ruff",
                    "numeric": 0.95},
                "declared_license": null, "commented_out": false,
                "source_kind": "precommit",
                "source_extra": {"repo": "https://github.com/astral-sh/ruff-pre-commit",
                    "canonical": "github.com/astral-sh/ruff-pre-commit",
                    "hook_ids": ["ruff", "ruff-format"]},
                "key": "PyPI:ruff@v0.6.9",
            })
        );
        // Unmapped repo -> GitHub purl, name is the lowercased path.
        assert_eq!(got[2]["ecosystem"], json!("GitHub"));
        assert_eq!(got[2]["name"], json!("some/unknown-hook"));
        assert_eq!(got[2]["purl"], json!("pkg:github/some/unknown-hook@v1.2.3"));
        assert_eq!(got[2]["parser_confidence"]["reason"],
            json!("pre-commit repo https://github.com/some/unknown-hook.git unmapped \u{2014} emitted as GitHub purl"));
        // local + meta pseudo-repos skipped.
    }

    #[test]
    fn additional_dependencies() {
        let src = "repos:\n\
            \x20 - repo: https://github.com/pre-commit/mirrors-mypy\n\
            \x20   rev: v1.11.2\n\
            \x20   hooks:\n\
            \x20     - id: mypy\n\
            \x20       additional_dependencies:\n\
            \x20         - \"pydantic>=2.5\"\n\
            \x20         - \"types-PyYAML\"\n\
            \x20         - \"foo[extra]==1.2.3\"\n\
            \x20         - \"@types/node@20\"\n";
        let got = parse_json(src, "cfg.yaml");
        // mypy row + 3 addl (scoped npm spec dropped under PyPI ecosystem).
        assert_eq!(got.len(), 4);
        assert_eq!(got[0]["name"], json!("mypy"));
        assert_eq!(got[1], json!({
            "ecosystem": "PyPI", "name": "pydantic", "version": ">=2.5",
            "declared_in": "cfg.yaml", "scope": "dev", "is_lockfile": false,
            "pin_style": "range", "direct": true, "purl": "pkg:pypi/pydantic@>=2.5",
            "parser_confidence": {"level": "medium",
                "reason": "pre-commit additional_dependencies spec 'pydantic>=2.5' on hook mypy from https://github.com/pre-commit/mirrors-mypy",
                "numeric": 0.7},
            "declared_license": null, "commented_out": false,
            "source_kind": "precommit_additional",
            "source_extra": {"spec": "pydantic>=2.5", "hook_id": "mypy",
                "hook_repo": "https://github.com/pre-commit/mirrors-mypy"},
            "key": "PyPI:pydantic@>=2.5",
        }));
        assert_eq!(got[2]["name"], json!("types-PyYAML"));
        assert_eq!(got[2]["version"], Value::Null);
        assert_eq!(got[2]["pin_style"], json!("wildcard"));
        assert_eq!(got[2]["purl"], json!("pkg:pypi/types-PyYAML"));
        assert_eq!(got[3]["name"], json!("foo"));
        assert_eq!(got[3]["version"], json!("1.2.3"));
        assert_eq!(got[3]["pin_style"], json!("exact"));
    }

    #[test]
    fn sha_and_unknown_rev() {
        let src = "repos:\n\
            \x20 - repo: https://github.com/astral-sh/ruff-pre-commit\n\
            \x20   rev: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
            \x20   hooks:\n\
            \x20     - id: ruff\n\
            \x20 - repo: https://github.com/psf/black\n\
            \x20   rev: main\n\
            \x20   hooks:\n\
            \x20     - id: black\n";
        let got = parse_json(src, "cfg.yaml");
        assert_eq!(got[0]["pin_style"], json!("git"));
        assert_eq!(got[1]["pin_style"], json!("unknown"));
    }

    #[test]
    fn ssh_form_canonicalises() {
        let src = "repos:\n\
            \x20 - repo: git@github.com:astral-sh/ruff-pre-commit.git\n\
            \x20   rev: v0.7.0\n\
            \x20   hooks:\n\
            \x20     - id: ruff\n";
        let got = parse_json(src, "cfg.yaml");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["name"], json!("ruff"));
        assert_eq!(got[0]["source_extra"]["canonical"],
            json!("github.com/astral-sh/ruff-pre-commit"));
    }

    #[test]
    fn npm_scoped_and_plain_additional() {
        let src = "repos:\n\
            \x20 - repo: https://github.com/pre-commit/mirrors-eslint\n\
            \x20   rev: v9.0.0\n\
            \x20   hooks:\n\
            \x20     - id: eslint\n\
            \x20       additional_dependencies:\n\
            \x20         - \"@typescript-eslint/parser@7.0.0\"\n\
            \x20         - \"eslint-plugin-react@^7.0.0\"\n";
        let got = parse_json(src, "cfg.yaml");
        assert_eq!(got[0]["ecosystem"], json!("npm"));
        assert_eq!(got[1]["name"], json!("@typescript-eslint/parser"));
        assert_eq!(got[1]["version"], json!("7.0.0"));
        assert_eq!(got[1]["purl"], json!("pkg:npm/@typescript-eslint/parser@7.0.0"));
        // Unscoped npm spec goes through the general path; the `@` is stripped
        // into the version but the caret stays (pin_style exact, version `^7.0.0`).
        assert_eq!(got[2]["name"], json!("eslint-plugin-react"));
        assert_eq!(got[2]["version"], json!("^7.0.0"));
        assert_eq!(got[2]["pin_style"], json!("exact"));
    }

    #[test]
    fn http_scheme_and_trailing_slash() {
        let src = "repos:\n\
            \x20 - repo: http://github.com/psf/black/\n\
            \x20   rev: 24.1.0\n\
            \x20   hooks:\n\
            \x20     - id: black\n";
        let got = parse_json(src, "cfg.yaml");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["source_extra"]["canonical"], json!("github.com/psf/black"));
        // source_extra.repo keeps the raw (trailing-slash) form.
        assert_eq!(got[0]["source_extra"]["repo"], json!("http://github.com/psf/black/"));
    }

    #[test]
    fn schemeless_repo_dropped() {
        let src = "repos:\n\
            \x20 - repo: github.com/foo/bar\n\
            \x20   rev: v1.0\n\
            \x20   hooks:\n\
            \x20     - id: x\n";
        assert!(parse(src, "cfg.yaml").is_empty());
    }

    #[test]
    fn empty_and_missing_rev() {
        assert!(parse("foo: bar\n", "cfg.yaml").is_empty());
        let missing_rev = "repos:\n\
            \x20 - repo: https://github.com/psf/black\n\
            \x20   hooks:\n\
            \x20     - id: black\n";
        assert!(parse(missing_rev, "cfg.yaml").is_empty());
        assert!(parse("not: {valid", "cfg.yaml").is_empty());
    }
}
