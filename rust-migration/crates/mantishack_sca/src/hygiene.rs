//! Dependency-hygiene checks — Rust port of the per-dep detectors in
//! `packages/sca/hygiene.py`. The lockfile-missing / drift / cross-manifest
//! checks (which need Manifest + version_compare + filesystem context) and the
//! `evaluate` orchestrator land as those land; the pure per-dep pin checks port
//! here.

use std::collections::HashMap;

use crate::models::{Confidence, Dependency, HygieneFinding, Manifest, PinStyle};

/// Per-ecosystem expected sibling lockfiles (`_EXPECTED_LOCKFILES`); `&[]` = no
/// expectation (Maven / Go without locking is normal).
fn expected_lockfiles(ecosystem: &str) -> &'static [&'static str] {
    match ecosystem {
        "npm" => &["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "shrinkwrap.json"],
        "PyPI" => &["Pipfile.lock", "poetry.lock"],
        "Cargo" => &["Cargo.lock"],
        "Go" => &["go.sum"],
        "RubyGems" => &["Gemfile.lock"],
        "NuGet" => &["packages.lock.json"],
        "Packagist" => &["composer.lock"],
        _ => &[],
    }
}

fn basename(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, n)| n).unwrap_or(path)
}

/// Classify a manifest by filename (`_manifest_role`): dev / test / optional /
/// main.
fn manifest_role(path: &str) -> &'static str {
    let name = basename(path).to_lowercase();
    if name.contains("dev") {
        "dev"
    } else if name.contains("test") {
        "test"
    } else if name.contains("optional") || name.contains("extras") || name.contains("all-") {
        "optional"
    } else if name.starts_with("requirements-") && name.ends_with(".txt") {
        "optional"
    } else {
        "main"
    }
}

fn placeholder_dep(m: &Manifest) -> Dependency {
    Dependency {
        ecosystem: m.ecosystem.clone(),
        name: "<manifest>".to_string(),
        version: None,
        declared_in: m.path.clone(),
        scope: "main".to_string(),
        is_lockfile: m.is_lockfile,
        pin_style: PinStyle::Unknown,
        direct: true,
        purl: String::new(),
        parser_confidence: Confidence::new("low", "placeholder for hygiene finding host"),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    }
}

/// Python `repr(list_of_str)`: `['a', 'b']`.
fn py_list_repr(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "))
}

/// `Path.parent` for the declared-in path string (used only for workspace
/// grouping): everything before the last `/`, or `.` when there is none.
fn parent_dir(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or(".")
}

/// `_versions_equal`: literal equality, else a per-ecosystem `compare == 0`,
/// falling back to literal equality on an unknown comparator.
fn versions_equal(ecosystem: &str, a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    matches!(mantishack_sca_versions::compare(ecosystem, a, b), Ok(0))
}

/// Run every hygiene check and return one finding list (`evaluate`).
pub fn evaluate(manifests: &[Manifest], deps: &[Dependency]) -> Vec<HygieneFinding> {
    let mut out = Vec::new();
    out.extend(check_lockfile_missing(manifests, deps));
    out.extend(check_lockfile_drift(deps));
    out.extend(check_unpinned(deps));
    out.extend(check_loose_pin(deps));
    out.extend(check_cross_manifest_inconsistency(deps));
    out
}

fn finding(kind: &str, dep: &Dependency, detail: String, severity: &str, confidence: Confidence) -> HygieneFinding {
    HygieneFinding {
        finding_id: format!("sca:hygiene:{}:{}:{}:{}", kind, dep.ecosystem, dep.name, dep.declared_in),
        kind: kind.to_string(),
        dependency: dep.clone(),
        detail,
        severity: severity.to_string(),
        confidence,
        related_findings: Vec::new(),
        suppressed: false,
        suppression_reason: None,
    }
}

/// Flag manifest entries with no version constraint (`check_unpinned`). Maven
/// entries with no version are exempt (parent-POM dependencyManagement idiom).
pub fn check_unpinned(deps: &[Dependency]) -> Vec<HygieneFinding> {
    let mut out = Vec::new();
    for d in deps {
        if d.is_lockfile {
            continue;
        }
        if d.ecosystem == "Maven" && d.version.is_none() {
            continue;
        }
        if matches!(d.pin_style, PinStyle::Wildcard | PinStyle::Unknown) || d.version.is_none() {
            out.push(finding(
                "unpinned_dependency",
                d,
                format!("{} declared without a version pin (pin_style={})", d.name, d.pin_style.as_str()),
                "medium",
                Confidence::new("high", "parser observed wildcard / no version"),
            ));
        }
    }
    out
}

/// Flag manifest entries with caret / tilde / range pinning (`check_loose_pin`).
pub fn check_loose_pin(deps: &[Dependency]) -> Vec<HygieneFinding> {
    let mut out = Vec::new();
    for d in deps {
        if d.is_lockfile {
            continue;
        }
        if matches!(d.pin_style, PinStyle::Caret | PinStyle::Tilde | PinStyle::Range) {
            let version = d.version.as_deref().filter(|v| !v.is_empty()).unwrap_or("*");
            out.push(finding(
                "loose_pin",
                d,
                format!(
                    "{} uses loose pinning ({} {}); range may admit new vulns silently",
                    d.name,
                    d.pin_style.as_str(),
                    version
                ),
                "low",
                Confidence::new("high", "parser observed caret/tilde/range pinning"),
            ));
        }
    }
    out
}

/// Flag `==X` manifest pins whose sibling lockfile resolves a different version
/// (`check_lockfile_drift`). Groups by (ecosystem, manifest parent dir, name);
/// keeps the first manifest + first lockfile per group, in first-seen order.
pub fn check_lockfile_drift(deps: &[Dependency]) -> Vec<HygieneFinding> {
    // (ecosystem, parent, name) -> (manifest_idx, lockfile_idx), insertion-ordered.
    let mut order: Vec<(String, String, String)> = Vec::new();
    let mut buckets: HashMap<(String, String, String), (Option<usize>, Option<usize>)> = HashMap::new();
    for (i, d) in deps.iter().enumerate() {
        let key = (d.ecosystem.clone(), parent_dir(&d.declared_in).to_string(), d.name.clone());
        let entry = buckets.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            (None, None)
        });
        // setdefault: keep the FIRST dep seen per bucket.
        if d.is_lockfile {
            entry.1.get_or_insert(i);
        } else {
            entry.0.get_or_insert(i);
        }
    }

    let mut out = Vec::new();
    for key in &order {
        let (m_idx, l_idx) = buckets[key];
        let (Some(m), Some(l)) = (m_idx, l_idx) else { continue };
        let manifest = &deps[m];
        let lockfile = &deps[l];
        if manifest.pin_style != PinStyle::Exact {
            continue;
        }
        let (Some(mv), Some(lv)) = (
            manifest.version.as_deref().filter(|v| !v.is_empty()),
            lockfile.version.as_deref().filter(|v| !v.is_empty()),
        ) else {
            continue;
        };
        if versions_equal(&key.0, mv, lv) {
            continue;
        }
        out.push(finding(
            "lockfile_drift",
            manifest,
            format!("manifest pins {mv} but lockfile resolves {lv}"),
            "high",
            Confidence::new("high", "manifest exact version differs from lockfile resolution"),
        ));
    }
    out
}

/// Surface manifests whose ecosystem expects a sibling lockfile that's absent
/// (`check_lockfile_missing`).
pub fn check_lockfile_missing(manifests: &[Manifest], deps: &[Dependency]) -> Vec<HygieneFinding> {
    let lockfile_dirs: std::collections::HashSet<(String, String)> = manifests
        .iter()
        .filter(|m| m.is_lockfile)
        .map(|m| (m.ecosystem.clone(), parent_dir(&m.path).to_string()))
        .collect();

    let mut out = Vec::new();
    for m in manifests {
        if m.is_lockfile {
            continue;
        }
        let expected = expected_lockfiles(&m.ecosystem);
        if expected.is_empty() {
            continue;
        }
        if lockfile_dirs.contains(&(m.ecosystem.clone(), parent_dir(&m.path).to_string())) {
            continue;
        }
        let host = deps
            .iter()
            .find(|d| d.declared_in == m.path)
            .cloned()
            .unwrap_or_else(|| placeholder_dep(m));
        out.push(finding(
            "lockfile_missing",
            &host,
            format!(
                "{} manifest at {} has no sibling lockfile; expected one of: {}",
                m.ecosystem,
                m.path,
                expected.join(", ")
            ),
            "medium",
            Confidence::new("high", "manifest exists but lockfile siblings absent"),
        ));
    }
    out
}

/// Flag the same dep declared at different versions across different workspaces
/// (`check_cross_manifest_inconsistency`).
pub fn check_cross_manifest_inconsistency(deps: &[Dependency]) -> Vec<HygieneFinding> {
    // (ecosystem, name, role, scope) -> row indices, insertion-ordered.
    let mut order: Vec<(String, String, &'static str, String)> = Vec::new();
    let mut by_key: HashMap<(String, String, &'static str, String), Vec<usize>> = HashMap::new();
    for (i, d) in deps.iter().enumerate() {
        if d.is_lockfile || d.version.is_none() {
            continue;
        }
        let role = manifest_role(&d.declared_in);
        let scope = if d.scope.is_empty() { "main".to_string() } else { d.scope.clone() };
        let key = (d.ecosystem.clone(), d.name.clone(), role, scope);
        by_key.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Vec::new()
        }).push(i);
    }

    let mut out = Vec::new();
    for key in &order {
        let rows = &by_key[key];
        let mut unique: Vec<String> = Vec::new();
        for &i in rows {
            if let Some(v) = deps[i].version.as_deref().filter(|v| !v.is_empty()) {
                if !unique.contains(&v.to_string()) {
                    unique.push(v.to_string());
                }
            }
        }
        if unique.len() <= 1 {
            continue;
        }
        let mut workspaces: Vec<String> = Vec::new();
        for &i in rows {
            let ws = parent_dir(&deps[i].declared_in).to_string();
            if !workspaces.contains(&ws) {
                workspaces.push(ws);
            }
        }
        if workspaces.len() <= 1 {
            continue;
        }
        unique.sort();
        let (eco, name, role, _scope) = key;
        let role_suffix = if *role != "main" { format!(" [{role} role]") } else { String::new() };
        let host = &deps[rows[0]];
        out.push(finding(
            "cross_manifest_inconsistency",
            host,
            format!(
                "{eco}:{name} declared at versions {} across {} workspaces{role_suffix}",
                py_list_repr(&unique),
                workspaces.len()
            ),
            "medium",
            Confidence::new("medium", "multi-workspace divergence"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Manifest;

    fn man(path: &str, eco: &str, is_lockfile: bool) -> Manifest {
        Manifest { path: path.to_string(), ecosystem: eco.to_string(), is_lockfile, workspace_root: None }
    }

    fn dep(name: &str, ps: PinStyle, version: Option<&str>, eco: &str, is_lockfile: bool) -> Dependency {
        Dependency {
            ecosystem: eco.to_string(),
            name: name.to_string(),
            version: version.map(str::to_string),
            declared_in: "pkg/package.json".to_string(),
            scope: "main".to_string(),
            is_lockfile,
            pin_style: ps,
            direct: true,
            purl: "p".to_string(),
            parser_confidence: Confidence::new("high", ""),
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".to_string(),
            source_extra: None,
        }
    }

    #[test]
    fn unpinned() {
        let deps = [
            dep("a", PinStyle::Wildcard, Some("1.0"), "npm", false),
            dep("b", PinStyle::Unknown, Some("1.0"), "npm", false),
            dep("c", PinStyle::Exact, None, "npm", false), // exact but no version -> flagged
            dep("d", PinStyle::Exact, Some("2.0"), "npm", false), // fine
            dep("e", PinStyle::Wildcard, Some("1.0"), "npm", true), // lockfile skip
            dep("m", PinStyle::Unknown, None, "Maven", false), // Maven no-version exempt
        ];
        let out = check_unpinned(&deps);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].finding_id, "sca:hygiene:unpinned_dependency:npm:a:pkg/package.json");
        assert_eq!(out[0].detail, "a declared without a version pin (pin_style=wildcard)");
        assert_eq!(out[2].detail, "c declared without a version pin (pin_style=exact)");
        assert_eq!((out[0].severity.as_str(), out[0].confidence.level.as_str(), out[0].confidence.reason.as_str()),
            ("medium", "high", "parser observed wildcard / no version"));
    }

    #[test]
    fn loose_pin() {
        let deps = [
            dep("x", PinStyle::Caret, Some("^1.0"), "npm", false),
            dep("y", PinStyle::Tilde, Some("~2.0"), "npm", false),
            dep("z", PinStyle::Range, None, "npm", false), // version -> "*"
            dep("w", PinStyle::Exact, Some("3.0"), "npm", false), // fine
            dep("v", PinStyle::Caret, Some("^9"), "npm", true), // lockfile skip
        ];
        let out = check_loose_pin(&deps);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].detail, "x uses loose pinning (caret ^1.0); range may admit new vulns silently");
        assert_eq!(out[2].detail, "z uses loose pinning (range *); range may admit new vulns silently");
        assert_eq!((out[0].severity.as_str(), out[0].kind.as_str()), ("low", "loose_pin"));
        assert_eq!(out[0].finding_id, "sca:hygiene:loose_pin:npm:x:pkg/package.json");
    }

    fn dep_at(name: &str, ps: PinStyle, version: Option<&str>, is_lockfile: bool, decl: &str) -> Dependency {
        let mut d = dep(name, ps, version, "npm", is_lockfile);
        d.declared_in = decl.to_string();
        d
    }

    #[test]
    fn lockfile_drift() {
        // Manifest ==1.0.0 vs lockfile 1.0.1 in the same dir -> drift.
        let out = check_lockfile_drift(&[
            dep_at("a", PinStyle::Exact, Some("1.0.0"), false, "pkg/package.json"),
            dep_at("a", PinStyle::Exact, Some("1.0.1"), true, "pkg/package-lock.json"),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].finding_id, "sca:hygiene:lockfile_drift:npm:a:pkg/package.json");
        assert_eq!(out[0].detail, "manifest pins 1.0.0 but lockfile resolves 1.0.1");
        assert_eq!(out[0].severity, "high");

        // Semver-equal 1.0 == 1.0.0 -> no drift.
        assert!(check_lockfile_drift(&[
            dep_at("b", PinStyle::Exact, Some("1.0"), false, "pkg/package.json"),
            dep_at("b", PinStyle::Exact, Some("1.0.0"), true, "pkg/package-lock.json"),
        ]).is_empty());

        // Non-exact manifest, missing lockfile, and cross-dir all skip.
        assert!(check_lockfile_drift(&[
            dep_at("c", PinStyle::Caret, Some("^1.0.0"), false, "pkg/package.json"),
            dep_at("c", PinStyle::Exact, Some("2.0.0"), true, "pkg/package-lock.json"),
        ]).is_empty());
        assert!(check_lockfile_drift(&[dep_at("d", PinStyle::Exact, Some("1.0.0"), false, "pkg/package.json")]).is_empty());
        assert!(check_lockfile_drift(&[
            dep_at("e", PinStyle::Exact, Some("1.0.0"), false, "a/package.json"),
            dep_at("e", PinStyle::Exact, Some("2.0.0"), true, "b/package-lock.json"),
        ]).is_empty());
    }

    #[test]
    fn manifest_roles() {
        assert_eq!(manifest_role("requirements.txt"), "main");
        assert_eq!(manifest_role("requirements-dev.txt"), "dev");
        assert_eq!(manifest_role("dev-requirements.txt"), "dev");
        assert_eq!(manifest_role("test_reqs.txt"), "test");
        assert_eq!(manifest_role("requirements-optional.txt"), "optional");
        assert_eq!(manifest_role("requirements-all.txt"), "optional");
        assert_eq!(manifest_role("extras.txt"), "optional");
        assert_eq!(manifest_role("requirements-ci.txt"), "optional");
        assert_eq!(manifest_role("package.json"), "main");
    }

    #[test]
    fn lockfile_missing() {
        let out = check_lockfile_missing(&[man("pkg/package.json", "npm", false)],
            &[dep_at("a", PinStyle::Exact, Some("1.0"), false, "pkg/package.json")]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].finding_id, "sca:hygiene:lockfile_missing:npm:a:pkg/package.json");
        assert_eq!(out[0].detail, "npm manifest at pkg/package.json has no sibling lockfile; expected one of: package-lock.json, yarn.lock, pnpm-lock.yaml, shrinkwrap.json");
        // Present lockfile sibling -> no finding.
        assert!(check_lockfile_missing(&[man("pkg/package.json", "npm", false), man("pkg/package-lock.json", "npm", true)],
            &[dep_at("a", PinStyle::Exact, Some("1.0"), false, "pkg/package.json")]).is_empty());
        // Maven has no lockfile expectation.
        assert!(check_lockfile_missing(&[man("pom.xml", "Maven", false)], &[]).is_empty());
        // No parsed deps -> placeholder host "<manifest>".
        let out = check_lockfile_missing(&[man("pkg/package.json", "npm", false)], &[]);
        assert_eq!(out[0].finding_id, "sca:hygiene:lockfile_missing:npm:<manifest>:pkg/package.json");
    }

    #[test]
    fn cross_manifest() {
        let out = check_cross_manifest_inconsistency(&[
            dep_at("lodash", PinStyle::Exact, Some("1.0"), false, "a/package.json"),
            dep_at("lodash", PinStyle::Exact, Some("2.0"), false, "b/package.json"),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].detail, "npm:lodash declared at versions ['1.0', '2.0'] across 2 workspaces");
        assert_eq!(out[0].severity, "medium");
        // Same workspace -> not flagged.
        assert!(check_cross_manifest_inconsistency(&[
            dep_at("lodash", PinStyle::Exact, Some("1.0"), false, "a/package.json"),
            dep_at("lodash", PinStyle::Exact, Some("2.0"), false, "a/req2.json"),
        ]).is_empty());
        // Non-main role appended to the detail.
        let mut d1 = dep("x", PinStyle::Exact, Some("1.0"), "PyPI", false);
        d1.declared_in = "a/requirements-dev.txt".to_string();
        let mut d2 = dep("x", PinStyle::Exact, Some("2.0"), "PyPI", false);
        d2.declared_in = "b/requirements-dev.txt".to_string();
        let out = check_cross_manifest_inconsistency(&[d1, d2]);
        assert_eq!(out[0].detail, "PyPI:x declared at versions ['1.0', '2.0'] across 2 workspaces [dev role]");
    }

    #[test]
    fn evaluate_concatenates() {
        let manifests = [man("pkg/package.json", "npm", false)];
        let deps = [
            dep_at("wild", PinStyle::Wildcard, Some("*"), false, "pkg/package.json"),
            dep_at("loose", PinStyle::Caret, Some("^1.0"), false, "pkg/package.json"),
        ];
        let out = evaluate(&manifests, &deps);
        // lockfile_missing (1) + unpinned (1) + loose_pin (1) = 3.
        let kinds: Vec<&str> = out.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["lockfile_missing", "unpinned_dependency", "loose_pin"]);
    }
}
