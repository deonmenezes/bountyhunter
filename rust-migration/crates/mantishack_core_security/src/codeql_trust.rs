//! Faithful port of `core/security/codeql_trust.py`.
//!
//! Trust check for target-repo CodeQL pack files (`codeql-pack.yml`,
//! `qlpack.yml`, `.github/codeql/codeql-config.yml`). Returns `true` when DB
//! creation should be refused. Parallel to [`crate::cc_trust`] but for the
//! files the `codeql` binary itself loads during `database create`.
//!
//! Houses the **path-traversal defenses** (`..` / absolute / external refs)
//! the migration brief calls out as security-critical.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_yaml_ng::Value as Yaml;

use crate::cc_trust::{safe, truncate};
use crate::pyval::PyVal;

const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_PACK_FILES: usize = 200;

/// CodeQL's canonical (Microsoft-authored) pack namespace.
const CANONICAL_PACK_PREFIX: &str = "codeql/";

// ───────────────────────── trust override + dir skip ───────────────────────

static TRUST_OVERRIDE: Mutex<bool> = Mutex::new(false);

/// Port of `codeql_trust.set_trust_override`.
pub fn set_trust_override(val: bool) {
    *TRUST_OVERRIDE.lock().unwrap() = val;
}

fn is_trust_overridden() -> bool {
    *TRUST_OVERRIDE.lock().unwrap()
}

static MANTISHACK_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Configure the implicitly-trusted MANTISHACK repo root (skipped on scan).
pub fn set_mantishack_dir(dir: PathBuf) {
    *MANTISHACK_DIR.lock().unwrap() = Some(dir);
}

// ───────────────────────── Finding / FileScan ──────────────────────────────

/// Port of `codeql_trust.Finding`.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub label: String,
    pub value: String,
    pub blocking: bool,
}

impl Finding {
    fn new(label: impl Into<String>, value: impl Into<String>, blocking: bool) -> Finding {
        Finding { label: label.into(), value: value.into(), blocking }
    }
}

/// Port of `codeql_trust.FileScan`.
#[derive(Clone, Debug, PartialEq)]
pub struct FileScan {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
}

impl FileScan {
    fn new(path: impl Into<PathBuf>) -> FileScan {
        FileScan { path: path.into(), findings: Vec::new() }
    }
    pub fn has_blocking(&self) -> bool {
        self.findings.iter().any(|f| f.blocking)
    }
}

// ───────────────────────── path-traversal predicates ───────────────────────

/// `defaultSuiteFile` escapes the pack: `".." in s or s.startswith("/")`.
pub fn suite_escapes_pack(s: &str) -> bool {
    s.contains("..") || s.starts_with('/')
}

/// A `queries[].uses` value references an external repo/URL:
/// `"/" in uses and not uses.startswith(("./", "../"))`.
pub fn is_external_query(uses: &str) -> bool {
    uses.contains('/') && !(uses.starts_with("./") || uses.starts_with("../"))
}

/// A pack reference is non-canonical when it isn't under `codeql/`.
pub fn is_non_canonical_pack(reference: &str) -> bool {
    !reference.starts_with(CANONICAL_PACK_PREFIX)
}

// ───────────────────────── helpers ─────────────────────────────────────────

fn truthy(v: &Yaml) -> bool {
    match v {
        Yaml::Null => false,
        Yaml::Bool(b) => *b,
        Yaml::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Yaml::String(s) => !s.is_empty(),
        Yaml::Sequence(a) => !a.is_empty(),
        Yaml::Mapping(m) => !m.is_empty(),
        Yaml::Tagged(t) => truthy(&t.value),
    }
}

fn py_str(v: &Yaml) -> String {
    PyVal::from_yaml(v).py_str()
}

fn get<'a>(doc: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    doc.as_mapping().and_then(|m| m.get(Yaml::String(key.to_string())))
}

// ───────────────────────── value-level scanners ────────────────────────────

/// Scan a parsed `codeql-pack.yml` / `qlpack.yml` document.
/// Port of `_scan_pack_file`'s post-parse body (caller sets `path`).
pub fn scan_pack_value(doc: &Yaml) -> FileScan {
    let mut fs = FileScan::new(PathBuf::new());
    if doc.as_mapping().is_none() {
        fs.findings.push(Finding::new(
            "non-dict YAML",
            truncate(yaml_type_name(doc), 60),
            true,
        ));
        return fs;
    }

    // extractor: ANY truthy value.
    if let Some(ex) = get(doc, "extractor") {
        if truthy(ex) {
            fs.findings.push(Finding::new("extractor", truncate(&py_str(ex), 120), true));
        }
    }

    // dependencies: dict[name->ver] OR flat list of specs.
    let dep_specs: Vec<(String, String)> = match get(doc, "dependencies") {
        Some(Yaml::Mapping(m)) => m
            .iter()
            .map(|(n, v)| (py_str(n), py_str(v)))
            .collect(),
        Some(Yaml::Sequence(a)) => a.iter().map(|item| (py_str(item), String::new())).collect(),
        _ => Vec::new(),
    };
    for (n, v) in &dep_specs {
        if is_non_canonical_pack(n) {
            let label = if v.is_empty() { n.clone() } else { format!("{}: {}", n, v) };
            fs.findings
                .push(Finding::new("non-canonical dep", truncate(&label, 120), true));
        }
    }

    // defaultSuiteFile path-traversal.
    if let Some(suite) = get(doc, "defaultSuiteFile") {
        if truthy(suite) {
            let s = py_str(suite);
            if suite_escapes_pack(&s) {
                fs.findings.push(Finding::new(
                    "defaultSuiteFile (escapes pack)",
                    truncate(&s, 120),
                    true,
                ));
            }
        }
    }

    // pack-level subprocess hooks.
    for key in ["buildCommand", "setup", "preCompileScript", "postCompileScript"] {
        if let Some(v) = get(doc, key) {
            if truthy(v) {
                fs.findings.push(Finding::new(key, truncate(&py_str(v), 120), true));
            }
        }
    }

    fs
}

/// Scan a parsed `.github/codeql/codeql-config.yml` document.
/// Port of `_scan_codeql_config`'s post-parse body (caller sets `path`).
pub fn scan_codeql_config_value(doc: &Yaml) -> FileScan {
    let mut fs = FileScan::new(PathBuf::new());
    if doc.as_mapping().is_none() {
        fs.findings.push(Finding::new(
            "non-dict YAML",
            truncate(yaml_type_name(doc), 60),
            true,
        ));
        return fs;
    }

    // packs: dict-by-language OR flat list of pack-spec strings.
    if let Some(packs) = get(doc, "packs") {
        if truthy(packs) {
            let mut flat: Vec<String> = Vec::new();
            match packs {
                Yaml::Mapping(m) => {
                    for (_lang, refs) in m {
                        if let Yaml::Sequence(a) = refs {
                            for r in a {
                                if let Yaml::String(s) = r {
                                    flat.push(s.clone());
                                }
                            }
                        }
                    }
                }
                Yaml::Sequence(a) => {
                    for r in a {
                        if let Yaml::String(s) = r {
                            flat.push(s.clone());
                        }
                    }
                }
                _ => {}
            }
            for reference in &flat {
                if is_non_canonical_pack(reference) {
                    fs.findings
                        .push(Finding::new("non-canonical pack", truncate(reference, 120), true));
                }
            }
        }
    }

    // queries: external repo/URL references.
    if let Some(queries) = get(doc, "queries") {
        if truthy(queries) {
            let entries: Vec<&Yaml> = match queries {
                Yaml::Sequence(a) => a.iter().collect(),
                other => vec![other],
            };
            for e in entries {
                let uses = match e {
                    Yaml::Mapping(m) => m
                        .get(Yaml::String("uses".to_string()))
                        .map(py_str)
                        .unwrap_or_default(),
                    other => py_str(other),
                };
                if is_external_query(&uses) {
                    fs.findings
                        .push(Finding::new("external queries", truncate(&uses, 120), true));
                }
            }
        }
    }

    // manualBuildSteps / setup subprocess directives.
    for key in ["manualBuildSteps", "setup"] {
        if let Some(v) = get(doc, key) {
            if truthy(v) {
                fs.findings.push(Finding::new(key, truncate(&py_str(v), 120), true));
            }
        }
    }

    // pack-cache redirection.
    if let Some(v) = get(doc, "pack-cache") {
        if truthy(v) {
            fs.findings.push(Finding::new("pack-cache", truncate(&py_str(v), 120), true));
        }
    }

    fs
}

fn yaml_type_name(v: &Yaml) -> &'static str {
    match v {
        Yaml::Null => "NoneType",
        Yaml::Bool(_) => "bool",
        Yaml::Number(_) => "int",
        Yaml::String(_) => "str",
        Yaml::Sequence(_) => "list",
        Yaml::Mapping(_) => "dict",
        Yaml::Tagged(_) => "tagged",
    }
}

// ───────────────────────── file layer ──────────────────────────────────────

fn path_present(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

fn read_capped(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

/// Scan a pack file from disk. Port of `_scan_pack_file` (file layer).
fn scan_pack_file(path: &Path) -> FileScan {
    let raw = match read_capped(path) {
        Some(r) => r,
        None => {
            let mut fs = FileScan::new(path.to_path_buf());
            fs.findings.push(Finding::new(
                "oversized/unreadable",
                truncate(&path.to_string_lossy(), 120),
                true,
            ));
            return fs;
        }
    };
    match serde_yaml_ng::from_slice::<Yaml>(&raw) {
        Ok(doc) => {
            let mut fs = scan_pack_value(&doc);
            fs.path = path.to_path_buf();
            fs
        }
        Err(e) => {
            let mut fs = FileScan::new(path.to_path_buf());
            fs.findings.push(Finding::new(
                "malformed YAML",
                truncate(&e.to_string(), 120),
                true,
            ));
            fs
        }
    }
}

/// Scan a codeql-config file from disk. Port of `_scan_codeql_config`.
fn scan_codeql_config_file(path: &Path) -> FileScan {
    let raw = match read_capped(path) {
        Some(r) => r,
        None => {
            let mut fs = FileScan::new(path.to_path_buf());
            fs.findings.push(Finding::new(
                "oversized/unreadable",
                truncate(&path.to_string_lossy(), 120),
                true,
            ));
            return fs;
        }
    };
    match serde_yaml_ng::from_slice::<Yaml>(&raw) {
        Ok(doc) => {
            let mut fs = scan_codeql_config_value(&doc);
            fs.path = path.to_path_buf();
            fs
        }
        Err(e) => {
            let mut fs = FileScan::new(path.to_path_buf());
            fs.findings.push(Finding::new(
                "malformed YAML",
                truncate(&e.to_string(), 120),
                true,
            ));
            fs
        }
    }
}

fn rglob(root: &Path, name: &str, out: &mut Vec<PathBuf>) {
    fn walk(dir: &Path, name: &str, out: &mut Vec<PathBuf>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
                walk(&p, name, out);
            } else if p.file_name().map(|n| n == name).unwrap_or(false) {
                out.push(p);
            }
        }
    }
    walk(root, name, out);
}

/// Pure repo scan. Returns `(scans, any_blocking)`. Port of `_scan_cached`.
pub fn scan_repo(resolved_path: &Path) -> (Vec<FileScan>, bool) {
    if let Some(ref dir) = *MANTISHACK_DIR.lock().unwrap() {
        if resolved_path == dir {
            return (Vec::new(), false);
        }
    }

    let mut pack_files: Vec<PathBuf> = Vec::new();
    'outer: for name in ["codeql-pack.yml", "qlpack.yml"] {
        let mut found: Vec<PathBuf> = Vec::new();
        rglob(resolved_path, name, &mut found);
        found.sort();
        for p in found {
            if pack_files.len() >= MAX_PACK_FILES {
                break 'outer;
            }
            // Skip dotted ancestor dirs except `.github`.
            if let Ok(rel) = p.strip_prefix(resolved_path) {
                let parts: Vec<_> = rel.components().collect();
                let dir_parts = &parts[..parts.len().saturating_sub(1)];
                let skip = dir_parts.iter().any(|c| {
                    let s = c.as_os_str().to_string_lossy();
                    s.starts_with('.') && s != ".github"
                });
                if skip {
                    continue;
                }
            }
            pack_files.push(p);
        }
    }

    let config_path = resolved_path
        .join(".github")
        .join("codeql")
        .join("codeql-config.yml");
    if path_present(&config_path) {
        pack_files.push(config_path);
    }

    if pack_files.is_empty() {
        return (Vec::new(), false);
    }

    let mut scans: Vec<FileScan> = Vec::new();
    for path in pack_files {
        let is_symlink = std::fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink {
            let mut fs = FileScan::new(path.clone());
            let tgt = std::fs::read_link(&path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "<unreadable>".to_string());
            fs.findings.push(Finding::new("symlink", truncate(&tgt, 120), true));
            scans.push(fs);
            continue;
        }
        let scanned = if path.file_name().map(|n| n == "codeql-config.yml").unwrap_or(false) {
            scan_codeql_config_file(&path)
        } else {
            scan_pack_file(&path)
        };
        if !scanned.findings.is_empty() {
            scans.push(scanned);
        }
    }

    let any_blocking = scans.iter().any(|s| s.has_blocking());
    (scans, any_blocking)
}

fn resolve(repo_path: &str) -> Option<PathBuf> {
    let p = Path::new(repo_path);
    if let Ok(c) = std::fs::canonicalize(p) {
        return Some(c);
    }
    if p.is_absolute() {
        Some(p.to_path_buf())
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(p))
    }
}

/// Check a target repo for unsafe CodeQL pack config. Returns `true` if DB
/// creation should be refused. Port of `check_repo_codeql_trust`.
pub fn check_repo_codeql_trust(repo_path: &str, trust_override: Option<bool>) -> bool {
    if repo_path.is_empty() {
        return false;
    }
    let resolved = match resolve(repo_path) {
        Some(r) => r,
        None => return false,
    };
    let trust = trust_override.unwrap_or_else(is_trust_overridden);
    let (scans, any_blocking) = scan_repo(&resolved);
    if !scans.is_empty() {
        print!("{}", render_scan_report(&resolved, &scans, any_blocking, trust));
    }
    any_blocking && !trust
}

/// Port of `_render_scan_report` (returns the text).
pub fn render_scan_report(
    target: &Path,
    scans: &[FileScan],
    any_blocking: bool,
    trust_override: bool,
) -> String {
    let safe_target = safe(&target.to_string_lossy());
    let mut out = String::new();
    if any_blocking {
        if trust_override {
            out.push_str(&format!(
                "mantishack: {} has dangerous CodeQL pack config (trust override active):\n",
                safe_target
            ));
        } else {
            out.push_str(&format!(
                "mantishack: {} has dangerous CodeQL pack config:\n",
                safe_target
            ));
        }
    } else {
        out.push_str(&format!("mantishack: {} has CodeQL pack config:\n", safe_target));
    }
    for fs in scans {
        let rel = fs.path.strip_prefix(target).unwrap_or(&fs.path);
        out.push_str(&format!("  {}\n", safe(&rel.to_string_lossy())));
        if fs.findings.is_empty() {
            continue;
        }
        let label_w = fs.findings.iter().map(|f| f.label.chars().count()).max().unwrap_or(0) + 2;
        for f in &fs.findings {
            let pad = label_w.saturating_sub(f.label.chars().count());
            out.push_str(&format!("    {}{}{}\n", f.label, " ".repeat(pad), f.value));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(yaml: &str) -> Vec<(String, String, bool)> {
        let doc: Yaml = serde_yaml_ng::from_str(yaml).unwrap();
        scan_pack_value(&doc)
            .findings
            .into_iter()
            .map(|f| (f.label, f.value, f.blocking))
            .collect()
    }

    fn config(yaml: &str) -> Vec<(String, String, bool)> {
        let doc: Yaml = serde_yaml_ng::from_str(yaml).unwrap();
        scan_codeql_config_value(&doc)
            .findings
            .into_iter()
            .map(|f| (f.label, f.value, f.blocking))
            .collect()
    }

    #[test]
    fn path_traversal_predicates() {
        // Path-traversal defenses — reject `..` and absolute paths.
        assert!(suite_escapes_pack("../escape.qls"));
        assert!(suite_escapes_pack("/etc/passwd"));
        assert!(suite_escapes_pack("a/../b"));
        assert!(!suite_escapes_pack("suites/local.qls"));
        assert!(!suite_escapes_pack("./local.qls"));

        assert!(is_external_query("owner/repo/q.ql"));
        assert!(is_external_query("https://x/y"));
        assert!(!is_external_query("./local.ql"));
        assert!(!is_external_query("../sibling.ql"));
        assert!(!is_external_query("local.ql")); // no slash

        assert!(is_non_canonical_pack("evil/pack"));
        assert!(!is_non_canonical_pack("codeql/cpp-all"));
    }

    #[test]
    fn pack_file_findings_match_python() {
        // Golden (Python Q_A).
        let got = pack(
            "name: x\nextractor: javascript\ndependencies:\n  evil/pack: '1.0'\n  codeql/cpp-all: '*'\ndefaultSuiteFile: ../escape.qls\nbuildCommand: make\n",
        );
        assert_eq!(
            got,
            vec![
                ("extractor".into(), "javascript".into(), true),
                ("non-canonical dep".into(), "evil/pack: 1.0".into(), true),
                ("defaultSuiteFile (escapes pack)".into(), "../escape.qls".into(), true),
                ("buildCommand".into(), "make".into(), true),
            ]
        );
    }

    #[test]
    fn codeql_config_findings_match_python() {
        // Golden (Python Q_B).
        let got = config(
            "packs:\n  - codeql/cpp-queries\n  - evil/pack\nqueries:\n  - uses: owner/repo/q.ql\n  - uses: ./local.ql\nmanualBuildSteps:\n  - run: make\npack-cache: ./cache\n",
        );
        assert_eq!(
            got,
            vec![
                ("non-canonical pack".into(), "evil/pack".into(), true),
                ("external queries".into(), "owner/repo/q.ql".into(), true),
                ("manualBuildSteps".into(), "[{'run': 'make'}]".into(), true),
                ("pack-cache".into(), "./cache".into(), true),
            ]
        );
    }

    #[test]
    fn pack_deps_as_flat_list() {
        let got = pack("dependencies:\n  - evil/pack@1.0\n  - codeql/cpp-all@2\n");
        assert_eq!(got, vec![("non-canonical dep".into(), "evil/pack@1.0".into(), true)]);
    }

    #[test]
    fn canonical_only_pack_is_clean() {
        let got = pack("name: ok\ndependencies:\n  codeql/cpp-all: '*'\n");
        assert!(got.is_empty());
    }

    #[test]
    fn config_packs_dict_by_language() {
        let got = config("packs:\n  cpp:\n    - codeql/cpp-queries\n    - evil/x\n");
        assert_eq!(got, vec![("non-canonical pack".into(), "evil/x".into(), true)]);
    }

    #[test]
    fn config_local_query_not_flagged() {
        let got = config("queries:\n  - uses: ./local.ql\n");
        assert!(got.is_empty());
    }

    #[test]
    fn pack_setup_hooks_blocked() {
        let got = pack("setup: ./bootstrap.sh\npreCompileScript: gen.sh\npostCompileScript: post.sh\n");
        assert_eq!(
            got,
            vec![
                ("setup".into(), "./bootstrap.sh".into(), true),
                ("preCompileScript".into(), "gen.sh".into(), true),
                ("postCompileScript".into(), "post.sh".into(), true),
            ]
        );
    }

    #[test]
    fn defaultsuitefile_absolute_blocked() {
        let got = pack("defaultSuiteFile: /abs/suite.qls\n");
        assert_eq!(got, vec![("defaultSuiteFile (escapes pack)".into(), "/abs/suite.qls".into(), true)]);
    }

    #[test]
    fn non_dict_yaml_blocked() {
        let doc: Yaml = serde_yaml_ng::from_str("- just\n- a\n- list\n").unwrap();
        let fs = scan_pack_value(&doc);
        assert_eq!(fs.findings[0].label, "non-dict YAML");
        assert!(fs.has_blocking());
    }

    #[test]
    fn end_to_end_pack_scan() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("codeql-pack.yml")).unwrap();
        write!(f, "extractor: javascript\nbuildCommand: make\n").unwrap();
        let resolved = std::fs::canonicalize(dir.path()).unwrap();
        assert!(check_repo_codeql_trust(resolved.to_str().unwrap(), Some(false)));
        assert!(!check_repo_codeql_trust(resolved.to_str().unwrap(), Some(true)));
    }

    #[test]
    fn clean_repo_no_pack() {
        let dir = tempfile::tempdir().unwrap();
        let (scans, blocking) = scan_repo(&std::fs::canonicalize(dir.path()).unwrap());
        assert!(scans.is_empty());
        assert!(!blocking);
    }
}
