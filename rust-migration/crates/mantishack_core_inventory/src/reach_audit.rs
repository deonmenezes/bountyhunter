//! Reachability audit harness — Rust port of `core/inventory/reach_audit.py`.
//!
//! `classify_reachability` composes the public reachability accessors in
//! precedence order (the read-only "audit" sibling of the /agentic enrichment
//! prepass); `audit_corpus` tallies coverage + false-suppress over a labelled
//! corpus. The `build_inventory` fallback (when no inventory is injected) lives
//! in `builder.py`, not yet ported — this port requires an inventory argument,
//! matching how the tests drive the harness.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::reachability::{self as r, InternalFunction, Verdict};

/// Verdicts that mean "not reachable in this deployment" (`_DEAD_VERDICTS`).
const DEAD_VERDICTS: &[&str] = &["module_aborts", "lexical_dead", "build_excluded", "no_path_from_entry", "not_called"];

struct ClassifyCtx<'a> {
    inventory: &'a Value,
    file_path: &'a str,
    name: &'a str,
    line: i64,
    module: &'a str,
    target: InternalFunction,
    class_name: Option<String>,
}

fn stage_module_aborts(ctx: &ClassifyCtx) -> Option<&'static str> {
    let abort = r::module_aborts_on_load(ctx.inventory, ctx.file_path)?;
    let abort_line = abort.get("line").and_then(Value::as_i64).unwrap_or(0);
    if ctx.line != 0 && ctx.line > abort_line {
        Some("module_aborts")
    } else {
        None
    }
}

fn stage_lexical_dead(ctx: &ClassifyCtx) -> Option<&'static str> {
    r::is_lexically_dead(ctx.inventory, ctx.file_path, ctx.name, ctx.line).then_some("lexical_dead")
}

fn stage_build_excluded(ctx: &ClassifyCtx) -> Option<&'static str> {
    r::build_excluded(ctx.inventory, ctx.file_path).is_some().then_some("build_excluded")
}

fn stage_framework(ctx: &ClassifyCtx) -> Option<&'static str> {
    r::is_framework_callable(ctx.inventory, &ctx.target).then_some("framework_callable")
}

fn stage_registered(ctx: &ClassifyCtx) -> Option<&'static str> {
    r::is_registered_via_call(ctx.inventory, &ctx.target).then_some("registered_via_call")
}

fn stage_entry(ctx: &ClassifyCtx) -> Option<&'static str> {
    match r::entry_reachability(ctx.inventory, &ctx.target, 50) {
        "reachable" => Some("reachable"),
        "no_path_from_entry" => Some("no_path_from_entry"),
        _ => None,
    }
}

fn stage_one_hop(ctx: &ClassifyCtx) -> Option<&'static str> {
    // Class-qualified name first (catches this.m()/self.m() method-match), then
    // the bare module.name form.
    let mut candidates: Vec<String> = Vec::new();
    if let Some(cls) = &ctx.class_name {
        candidates.push(format!("{}.{}.{}", ctx.module, cls, ctx.name));
    }
    candidates.push(format!("{}.{}", ctx.module, ctx.name));

    let mut verdicts: Vec<Verdict> = Vec::new();
    for qn in &candidates {
        if let Ok(res) = r::function_called(ctx.inventory, qn, true) {
            verdicts.push(res.verdict);
        }
    }
    if verdicts.contains(&Verdict::Called) {
        return Some("called");
    }
    if verdicts.contains(&Verdict::NotCalled) {
        // CHA: a polymorphic-dispatch override reachable via an unresolved member
        // call could still be live -> fall through to uncertain, not not_called.
        if r::is_virtual_dispatch_candidate(ctx.inventory, ctx.class_name.as_deref(), ctx.name) {
            return None;
        }
        return Some("not_called");
    }
    None
}

const PRECEDENCE: &[fn(&ClassifyCtx) -> Option<&'static str>] = &[
    stage_module_aborts,
    stage_lexical_dead,
    stage_build_excluded,
    stage_framework,
    stage_registered,
    stage_entry,
    stage_one_hop,
];

fn lookup_class_name(inventory: &Value, file_path: &str, name: &str, line: i64) -> Option<String> {
    let files = inventory.get("files")?.as_array()?;
    for f in files {
        if !f.is_object() || f.get("path").and_then(Value::as_str) != Some(file_path) {
            continue;
        }
        for it in f.get("items").and_then(Value::as_array).into_iter().flatten() {
            if it.get("name").and_then(Value::as_str) != Some(name) {
                continue;
            }
            if line != 0 && it.get("line_start").and_then(Value::as_i64).unwrap_or(0) != line {
                continue;
            }
            return it.get("metadata").and_then(|m| m.get("class_name")).and_then(Value::as_str).map(str::to_string);
        }
    }
    None
}

/// Strongest applicable reachability verdict for one function — the first
/// precedence stage that fires, else `"uncertain"` (`classify_reachability`).
pub fn classify_reachability(inventory: &Value, file_path: &str, name: &str, line: i64, module: &str) -> String {
    let ctx = ClassifyCtx {
        inventory,
        file_path,
        name,
        line,
        module,
        target: InternalFunction::new(file_path, name, line),
        class_name: lookup_class_name(inventory, file_path, name, line),
    };
    for stage in PRECEDENCE {
        if let Some(verdict) = stage(&ctx) {
            return verdict.to_string();
        }
    }
    "uncertain".to_string()
}

/// Corpus audit tally (`AuditReport`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    pub total: i64,
    pub caught_dead: i64,
    pub missed_dead: i64,
    pub false_suppress: i64,
    pub live_ok: i64,
    pub not_found: i64,
    pub per_verdict: BTreeMap<String, i64>,
    pub false_suppress_detail: Vec<(String, String, String)>,
    pub missed_detail: Vec<(String, String, String)>,
    pub not_found_detail: Vec<(String, String)>,
}

impl AuditReport {
    pub fn coverage(&self) -> f64 {
        let dead = self.caught_dead + self.missed_dead;
        if dead != 0 {
            self.caught_dead as f64 / dead as f64
        } else {
            1.0
        }
    }
}

/// Classify each labelled `(rel_path, func_name, "dead"|"live")` against the
/// supplied inventory and tally coverage + false-suppress (`audit_corpus`).
pub fn audit_corpus(labels: &[(String, String, String)], inventory: &Value) -> AuditReport {
    // Index items by (rel_path, name) -> line, for label lookup.
    let mut line_of: BTreeMap<(String, String), i64> = BTreeMap::new();
    if let Some(files) = inventory.get("files").and_then(Value::as_array) {
        for f in files {
            if !f.is_object() {
                continue;
            }
            let rel = f.get("path").and_then(Value::as_str).unwrap_or("");
            for it in f.get("items").and_then(Value::as_array).into_iter().flatten() {
                if !it.is_object() {
                    continue;
                }
                let is_fn = match it.get("kind") {
                    None => true,
                    Some(Value::String(s)) => s == "function",
                    _ => false,
                };
                if !is_fn {
                    continue;
                }
                let name = it.get("name").and_then(Value::as_str).unwrap_or("");
                let line = it.get("line_start").and_then(Value::as_i64).unwrap_or(0);
                line_of.insert((rel.to_string(), name.to_string()), line);
            }
        }
    }

    let mut report = AuditReport::default();
    for (rel, name, label) in labels {
        let Some(module) = r::file_path_to_module(rel) else { continue };
        let key = (rel.clone(), name.clone());
        let Some(&line) = line_of.get(&key) else {
            report.not_found += 1;
            report.not_found_detail.push((rel.clone(), name.clone()));
            continue;
        };
        let verdict = classify_reachability(inventory, rel, name, line, &module);
        report.total += 1;
        *report.per_verdict.entry(verdict.clone()).or_insert(0) += 1;
        let is_dead = DEAD_VERDICTS.contains(&verdict.as_str());
        if label == "dead" {
            if is_dead {
                report.caught_dead += 1;
            } else {
                report.missed_dead += 1;
                report.missed_detail.push((rel.clone(), name.clone(), verdict));
            }
        } else if is_dead {
            report.false_suppress += 1;
            report.false_suppress_detail.push((rel.clone(), name.clone(), verdict));
        } else {
            report.live_ok += 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn corpus_inventory() -> Value {
        json!({"files": [
            {"path": "app/main.py", "language": "python",
             "items": [
                {"name": "run", "line_start": 5, "kind": "function"},
                {"name": "helper", "line_start": 1, "kind": "function"}
             ],
             "call_graph": {"imports": {"util": "app.util"},
               "calls": [{"chain": ["helper"], "line": 6, "caller": "run"}, {"chain": ["util", "do"], "line": 7, "caller": "run"}],
               "decorated_functions": [{"name": "run", "line": 5, "decorators": [["app", "route"]]}]
             }},
            {"path": "app/util.py", "language": "python",
             "items": [{"name": "do", "line_start": 2, "kind": "function"}, {"name": "orphan", "line_start": 9, "kind": "function"}],
             "call_graph": {"imports": {}, "calls": []}}
        ]})
    }

    #[test]
    fn classify_precedence() {
        let inv = corpus_inventory();
        // run is @app.route -> framework_callable.
        assert_eq!(classify_reachability(&inv, "app/main.py", "run", 5, "app.main"), "framework_callable");
        // do + helper are in the forward closure from the framework-callable
        // entry `run`, so stage_entry fires first -> reachable (not the later
        // 1-hop "called"; precedence puts entry-reachability before 1-hop).
        assert_eq!(classify_reachability(&inv, "app/util.py", "do", 2, "app.util"), "reachable");
        assert_eq!(classify_reachability(&inv, "app/main.py", "helper", 1, "app.main"), "reachable");
        // orphan: python is a fuzzy entry model, never called -> not_called.
        assert_eq!(classify_reachability(&inv, "app/util.py", "orphan", 9, "app.util"), "not_called");
    }

    #[test]
    fn audit_corpus_tally() {
        let inv = corpus_inventory();
        let labels = vec![
            ("app/main.py".into(), "run".into(), "live".into()),
            ("app/util.py".into(), "do".into(), "live".into()),
            ("app/util.py".into(), "orphan".into(), "dead".into()),
            ("app/util.py".into(), "ghost".into(), "dead".into()), // not in inventory
        ];
        let rep = audit_corpus(&labels, &inv);
        assert_eq!(rep.total, 3);
        assert_eq!(rep.caught_dead, 1); // orphan
        assert_eq!(rep.live_ok, 2); // run, do
        assert_eq!(rep.false_suppress, 0);
        assert_eq!(rep.not_found, 1); // ghost
        assert_eq!(rep.coverage(), 1.0);
    }
}
