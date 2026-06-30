//! Stage C structural pre-checks via Coccinelle — faithful port of
//! `packages/coccinelle/prereqs.py`.
//!
//! `PrereqFacts`, `build_facts` (def:/call: message indexing) and
//! `evaluate_finding` are pure and golden-vector verified. `gather_prereqs`
//! drives `runner` + a filesystem source-scan; its skip semantics match the
//! Python (spatch absent / no C source / rules dir missing → skipped, not error).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::models::SpatchResult;

/// Same set as the `/scan` cocci leg's `_repo_has_c_cpp_source`.
pub const C_CPP_EXTS: [&str; 7] = [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"];

/// Structural facts derived from the function-inventory rule. Keys are bare
/// function names; values are the `(file, line)` sites where each is defined
/// (`defs`) or called (`calls`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrereqFacts {
    pub defs: BTreeMap<String, BTreeSet<(String, i64)>>,
    pub calls: BTreeMap<String, BTreeSet<(String, i64)>>,
    pub skipped_reason: Option<String>,
}

impl PrereqFacts {
    pub fn skipped(reason: &str) -> PrereqFacts {
        PrereqFacts { skipped_reason: Some(reason.to_string()), ..Default::default() }
    }

    pub fn is_skipped(&self) -> bool {
        self.skipped_reason.is_some()
    }

    pub fn function_exists(&self, name: &str) -> bool {
        self.defs.contains_key(name)
    }

    pub fn function_has_callers(&self, name: &str) -> bool {
        self.calls.get(name).map(|s| !s.is_empty()).unwrap_or(false)
    }

    /// Sorted `(file, line)` call sites (BTreeSet already yields tuple order).
    pub fn callers_of(&self, name: &str) -> Vec<(String, i64)> {
        self.calls.get(name).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }
}

/// Index `def:<name>` / `call:<name>` COCCIRESULT messages into facts. Unknown
/// or empty message shapes are ignored (the gather pass stays neutral).
pub fn build_facts(results: &[SpatchResult]) -> PrereqFacts {
    let mut facts = PrereqFacts::default();
    for r in results {
        for m in &r.matches {
            let msg = m.message.trim();
            if let Some(rest) = msg.strip_prefix("def:") {
                facts.defs.entry(rest.trim().to_string()).or_default().insert((m.file.clone(), m.line));
            } else if let Some(rest) = msg.strip_prefix("call:") {
                facts.calls.entry(rest.trim().to_string()).or_default().insert((m.file.clone(), m.line));
            }
        }
    }
    facts
}

/// `os.path.splitext`-compatible extension (incl. leading dot), lowercased.
/// A leading-dot basename (`.bashrc`) has no extension.
fn ext_lower(path: &str) -> String {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match base.rfind('.') {
        Some(idx) => {
            let leading_dots = base.bytes().take_while(|&b| b == b'.').count();
            if idx < leading_dots {
                String::new()
            } else {
                base[idx..].to_lowercase()
            }
        }
        None => String::new(),
    }
}

fn finding_str<'a>(finding: &'a Value, key: &str) -> &'a str {
    finding.get(key).and_then(Value::as_str).unwrap_or("").trim()
}

/// Per-finding mechanical evaluation against the prereq facts. Returns the dict
/// stored under `finding["cocci_prereqs"]`; never overwrites finding status —
/// these are facts, not verdicts.
pub fn evaluate_finding(finding: &Value, facts: &PrereqFacts) -> Value {
    let mut checks = Map::new();
    checks.insert("function_exists".into(), Value::Null);
    checks.insert("function_has_callers".into(), Value::Null);

    let mut out = Map::new();
    out.insert("applicable".into(), json!(false));
    out.insert("checks".into(), Value::Object(checks));
    out.insert("details".into(), Value::Object(Map::new()));
    out.insert("skipped_reason".into(), Value::Null);

    if facts.is_skipped() {
        out.insert("skipped_reason".into(), json!(facts.skipped_reason));
        return Value::Object(out);
    }

    let func_name = finding_str(finding, "function");
    let file_path = finding_str(finding, "file");

    if func_name.is_empty() {
        out.insert("skipped_reason".into(), json!("finding_missing_function"));
        return Value::Object(out);
    }
    if !file_path.is_empty() {
        let ext = ext_lower(file_path);
        if !ext.is_empty() && !C_CPP_EXTS.contains(&ext.as_str()) {
            out.insert("skipped_reason".into(), json!("non_c_cpp_file"));
            return Value::Object(out);
        }
    }

    out.insert("applicable".into(), json!(true));
    let exists = facts.function_exists(func_name);
    // function_has_callers is only meaningful when the function is defined here;
    // otherwise (libc symbol etc.) leave it null rather than asserting "no callers".
    let has_callers = if exists { json!(facts.function_has_callers(func_name)) } else { Value::Null };

    let checks = out.get_mut("checks").unwrap().as_object_mut().unwrap();
    checks.insert("function_exists".into(), json!(exists));
    checks.insert("function_has_callers".into(), has_callers);

    let details = out.get_mut("details").unwrap().as_object_mut().unwrap();
    details.insert("function".into(), json!(func_name));
    if exists {
        let count = facts.calls.get(func_name).map(|s| s.len()).unwrap_or(0);
        details.insert("callers_count".into(), json!(count));
    }

    Value::Object(out)
}

/// Bounded heuristic: any C/C++ source under `repo_path` (caps at `max_files`)?
pub fn has_c_cpp_source(repo_path: &Path, max_files: usize) -> bool {
    if !repo_path.is_dir() {
        return false;
    }
    let mut seen = 0usize;
    let mut found = false;
    walk_files(repo_path, &mut |p| {
        if found {
            return false;
        }
        seen += 1;
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if C_CPP_EXTS.contains(&ext_lower(name).as_str()) {
                found = true;
                return false;
            }
        }
        seen < max_files
    });
    found
}

/// Recursively visit files; `visit` returns false to stop the walk early.
fn walk_files(dir: &Path, visit: &mut dyn FnMut(&Path) -> bool) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !walk_files(&path, visit) {
                return false;
            }
        } else if path.is_file() && !visit(&path) {
            return false;
        }
    }
    true
}

/// Shipped prereq rules dir, resolved via `$MANTISHACK_DIR` (the repo-root env
/// var the codebase standardizes on, replacing Python's `__file__` walk), or
/// `None` if unset / missing (minimal install).
pub fn shipped_prereqs_rules_dir() -> Option<PathBuf> {
    let root = std::env::var("MANTISHACK_DIR").ok()?;
    let candidate = Path::new(&root).join("engine").join("coccinelle").join("prereqs");
    candidate.is_dir().then_some(candidate)
}

/// Run shipped prereq rules against `target` and build facts. `skipped_reason`
/// distinguishes "no structural evidence available" from an error.
pub fn gather_prereqs(target: &Path, rules_dir: Option<&Path>, timeout_per_rule: u64) -> PrereqFacts {
    if !crate::runner::is_available() {
        return PrereqFacts::skipped("spatch_not_available");
    }
    if !has_c_cpp_source(target, 200) {
        return PrereqFacts::skipped("no_c_cpp_source");
    }
    let effective = match rules_dir {
        Some(d) => Some(d.to_path_buf()),
        None => shipped_prereqs_rules_dir(),
    };
    let Some(dir) = effective else {
        return PrereqFacts::skipped("rules_dir_missing");
    };

    let opts = crate::runner::RunOptions { no_includes: true, ..Default::default() };
    let results = crate::runner::run_rules(target, &dir, timeout_per_rule, &opts, None);
    build_facts(&results)
}
