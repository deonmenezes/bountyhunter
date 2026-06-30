//! Golden vectors mirroring `packages/coccinelle/tests/{test_models,
//! test_findings,test_coverage}.py` — every expectation matches the Python oracle.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::coverage::to_coverage_record;
use crate::findings::to_findings;
use crate::models::{SpatchMatch, SpatchResult};

// ── models ────────────────────────────────────────────────────────────────

#[test]
fn from_dict_full() {
    let d = json!({
        "file": "a.c", "line": 10, "col": 5, "line_end": 10,
        "col_end": 15, "rule": "test_rule", "message": "found it",
    });
    let m = SpatchMatch::from_dict(Some(&d));
    assert_eq!(m.file, "a.c");
    assert_eq!(m.line, 10);
    assert_eq!(m.column, 5);
    assert_eq!(m.line_end, 10);
    assert_eq!(m.column_end, 15);
    assert_eq!(m.rule, "test_rule");
    assert_eq!(m.message, "found it");
}

#[test]
fn from_dict_minimal() {
    let m = SpatchMatch::from_dict(Some(&json!({"file": "x.c", "line": 1})));
    assert_eq!(m.file, "x.c");
    assert_eq!(m.line, 1);
    assert_eq!(m.column, 0);
}

#[test]
fn from_dict_empty() {
    let m = SpatchMatch::from_dict(Some(&json!({})));
    assert_eq!(m.file, "");
    assert_eq!(m.line, 0);
}

#[test]
fn from_dict_none() {
    assert_eq!(SpatchMatch::from_dict(None).file, "");
    // A non-object (Python `not isinstance(d, dict)`) is also the empty match.
    assert_eq!(SpatchMatch::from_dict(Some(&json!(["x"]))).file, "");
}

#[test]
fn from_dict_column_fallback() {
    // `col` preferred, else `column`, else 0 (same for col_end/column_end).
    let m = SpatchMatch::from_dict(Some(&json!({"column": 7, "column_end": 9})));
    assert_eq!(m.column, 7);
    assert_eq!(m.column_end, 9);
}

#[test]
fn roundtrip() {
    let m = SpatchMatch {
        file: "a.c".into(),
        line: 5,
        column: 3,
        rule: "r1".into(),
        message: "msg".into(),
        ..Default::default()
    };
    let m2 = SpatchMatch::from_dict(Some(&m.to_dict()));
    assert_eq!(m2.file, m.file);
    assert_eq!(m2.line, m.line);
    assert_eq!(m2.rule, m.rule);
}

#[test]
fn result_ok() {
    assert!(SpatchResult { rule: "test".into(), returncode: 0, ..Default::default() }.ok());
    assert!(!SpatchResult {
        rule: "test".into(),
        returncode: 0,
        errors: vec!["parse error".into()],
        ..Default::default()
    }
    .ok());
    assert!(!SpatchResult { rule: "test".into(), returncode: 1, ..Default::default() }.ok());
}

#[test]
fn match_count() {
    let r = SpatchResult {
        rule: "test".into(),
        matches: vec![
            SpatchMatch { file: "a.c".into(), line: 1, ..Default::default() },
            SpatchMatch { file: "b.c".into(), line: 2, ..Default::default() },
        ],
        ..Default::default()
    };
    assert_eq!(r.match_count(), 2);
}

#[test]
fn result_to_dict() {
    let r = SpatchResult {
        rule: "test".into(),
        rule_path: "test.cocci".into(),
        matches: vec![SpatchMatch { file: "a.c".into(), line: 1, ..Default::default() }],
        files_examined: vec!["a.c".into()],
        elapsed_ms: 100,
        ..Default::default()
    };
    let d = r.to_dict();
    assert_eq!(d["rule"], "test");
    assert_eq!(d["matches"].as_array().unwrap().len(), 1);
    assert_eq!(d["matches"][0]["file"], "a.c");
    assert_eq!(d["elapsed_ms"], 100);
    // Full shape + key order parity.
    assert_eq!(
        d,
        json!({
            "rule": "test", "rule_path": "test.cocci",
            "matches": [{"file": "a.c", "line": 1, "column": 0, "line_end": 0,
                         "column_end": 0, "rule": "", "message": ""}],
            "files_examined": ["a.c"], "errors": [],
            "elapsed_ms": 100, "returncode": 0,
        })
    );
}

// ── findings ──────────────────────────────────────────────────────────────

fn m(file: &str, line: i64, message: &str) -> SpatchMatch {
    SpatchMatch { file: file.into(), line, message: message.into(), ..Default::default() }
}

#[test]
fn findings_empty_results() {
    assert_eq!(to_findings(&[]), Vec::<serde_json::Value>::new());
}

#[test]
fn findings_no_matches() {
    let results = [SpatchResult { rule: "r1".into(), ..Default::default() }];
    assert!(to_findings(&results).is_empty());
}

#[test]
fn findings_single_match() {
    let results = [SpatchResult {
        rule: "unchecked_return".into(),
        matches: vec![m("a.c", 10, "not checked")],
        ..Default::default()
    }];
    let f = to_findings(&results);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0]["id"], "COCCI-unchecked_return-1");
    assert_eq!(f[0]["file"], "a.c");
    assert_eq!(f[0]["line"], 10);
    assert_eq!(f[0]["origin"], "coccinelle");
    assert_eq!(f[0]["vuln_type"], "inconsistency");
    assert_eq!(f[0]["confidence"], "medium");
    assert_eq!(f[0]["rule"], "unchecked_return");
    assert_eq!(f[0]["description"], "not checked");
}

#[test]
fn findings_multiple_results() {
    let results = [
        SpatchResult {
            rule: "r1".into(),
            matches: vec![m("a.c", 1, ""), m("b.c", 2, "")],
            ..Default::default()
        },
        SpatchResult { rule: "r2".into(), matches: vec![m("c.c", 3, "")], ..Default::default() },
    ];
    let f = to_findings(&results);
    assert_eq!(f.len(), 3);
    assert_eq!(f[0]["id"], "COCCI-r1-1");
    assert_eq!(f[1]["id"], "COCCI-r1-2");
    assert_eq!(f[2]["id"], "COCCI-r2-1");
}

#[test]
fn findings_default_description() {
    let results = [SpatchResult {
        rule: "test_rule".into(),
        matches: vec![m("a.c", 1, "")],
        ..Default::default()
    }];
    let f = to_findings(&results);
    assert_eq!(f[0]["description"], "Inconsistency detected by test_rule");
}

#[test]
fn findings_ids_unique_across_same_rule_results() {
    let results = [
        SpatchResult { rule: "r1".into(), matches: vec![m("a.c", 1, "")], ..Default::default() },
        SpatchResult { rule: "r1".into(), matches: vec![m("b.c", 2, "")], ..Default::default() },
    ];
    let ids: Vec<String> =
        to_findings(&results).iter().map(|f| f["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids, ["COCCI-r1-1", "COCCI-r1-2"]);
}

// ── coverage ──────────────────────────────────────────────────────────────

fn res_files(rule: &str, files: &[&str]) -> SpatchResult {
    SpatchResult {
        rule: rule.into(),
        files_examined: files.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

#[test]
fn coverage_empty_results() {
    assert!(to_coverage_record(&[], "T").is_none());
}

#[test]
fn coverage_no_files_examined() {
    let results = [SpatchResult { rule: "r1".into(), ..Default::default() }];
    assert!(to_coverage_record(&results, "T").is_none());
}

#[test]
fn coverage_basic_record() {
    let results = [SpatchResult {
        rule: "unchecked_return".into(),
        files_examined: vec!["a.c".into(), "b.c".into()],
        matches: vec![m("a.c", 10, "")],
        ..Default::default()
    }];
    let record = to_coverage_record(&results, "2026-06-30T00:00:00+00:00").unwrap();
    assert_eq!(record["tool"], "coccinelle");
    assert_eq!(record["timestamp"], "2026-06-30T00:00:00+00:00");
    assert_eq!(record["files_examined"], json!(["a.c", "b.c"]));
    assert_eq!(record["rules_applied"], json!(["unchecked_return"]));
}

#[test]
fn coverage_merges_files_across_results() {
    let results = [res_files("r1", &["a.c", "b.c"]), res_files("r2", &["b.c", "c.c"])];
    let record = to_coverage_record(&results, "T").unwrap();
    assert_eq!(record["files_examined"], json!(["a.c", "b.c", "c.c"]));
    assert_eq!(record["rules_applied"], json!(["r1", "r2"]));
}

#[test]
fn coverage_rules_preserve_insertion_order() {
    let results = [
        res_files("zz_late", &["a.c"]),
        res_files("aa_early", &["a.c"]),
        res_files("zz_late", &["b.c"]),
    ];
    let record = to_coverage_record(&results, "T").unwrap();
    // rules_applied is insertion-order dedup, NOT sorted.
    assert_eq!(record["rules_applied"], json!(["zz_late", "aa_early"]));
}

#[test]
fn coverage_includes_failures() {
    let results = [SpatchResult {
        rule: "r1".into(),
        files_examined: vec!["a.c".into()],
        errors: vec!["parse error at line 5".into()],
        ..Default::default()
    }];
    let record = to_coverage_record(&results, "T").unwrap();
    assert_eq!(record["files_failed"], json!([{"rule": "r1", "reason": "parse error at line 5"}]));
}

#[test]
fn coverage_no_failures_key_when_clean() {
    let results = [res_files("r1", &["a.c"])];
    let record = to_coverage_record(&results, "T").unwrap();
    assert!(record.get("files_failed").is_none());
}

// ── shared temp helper ──────────────────────────────────────────────────────

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_tmp_dir(tag: &str) -> PathBuf {
    static C: AtomicU64 = AtomicU64::new(0);
    let n = C.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("cocci-rs-test-{tag}-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── sarif (mirrors test_sarif.py) ───────────────────────────────────────────

use crate::sarif::results_to_sarif;

#[test]
fn sarif_empty_results_emits_minimal_sarif() {
    let doc = results_to_sarif(&[], &PathBuf::from("/repo"));
    assert_eq!(doc["version"], "2.1.0");
    assert!(doc.get("$schema").is_some());
    let run = &doc["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "coccinelle");
    assert_eq!(run["tool"]["driver"]["rules"], json!([]));
    assert_eq!(run["results"], json!([]));
}

#[test]
fn sarif_single_match_round_trip() {
    let dir = unique_tmp_dir("sarif");
    let src = dir.join("vuln.c");
    std::fs::write(&src, "// stub\n").unwrap();
    let result = SpatchResult {
        rule: "missing_null_check".into(),
        rule_path: "engine/coccinelle/rules/missing_null_check.cocci".into(),
        matches: vec![SpatchMatch {
            file: src.to_string_lossy().into_owned(),
            line: 42,
            column: 8,
            line_end: 42,
            column_end: 20,
            rule: "missing_null_check".into(),
            message: "Allocation result p used without NULL check".into(),
        }],
        ..Default::default()
    };
    let doc = results_to_sarif(&[result], &dir);
    let run = &doc["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "missing_null_check");
    let sr = &run["results"][0];
    assert_eq!(sr["ruleId"], "missing_null_check");
    assert_eq!(sr["level"], "warning");
    assert!(sr["message"]["text"].as_str().unwrap().contains("Allocation result p used"));
    let loc = &sr["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], "vuln.c"); // normalized repo-relative
    let region = &loc["region"];
    assert_eq!(region["startLine"], 42);
    assert_eq!(region["endLine"], 42);
    assert_eq!(region["startColumn"], 8);
    assert_eq!(region["endColumn"], 20);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn sarif_relative_path_preserved() {
    let result = SpatchResult {
        rule: "r".into(),
        matches: vec![SpatchMatch { file: "src/parser.c".into(), line: 1, message: "x".into(), ..Default::default() }],
        ..Default::default()
    };
    let doc = results_to_sarif(&[result], &PathBuf::from("/repo"));
    assert_eq!(
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/parser.c"
    );
}

#[test]
fn sarif_cross_fs_path_preserved() {
    let result = SpatchResult {
        rule: "r".into(),
        matches: vec![SpatchMatch { file: "/usr/include/string.h".into(), line: 1, message: "x".into(), ..Default::default() }],
        ..Default::default()
    };
    let doc = results_to_sarif(&[result], &PathBuf::from("./some-other-repo"));
    assert_eq!(
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "/usr/include/string.h"
    );
}

#[test]
fn sarif_multiple_rules_dedup_in_driver() {
    let results = [
        SpatchResult { rule: "rule_a".into(), matches: vec![m("a.c", 1, "m1")], ..Default::default() },
        SpatchResult { rule: "rule_b".into(), matches: vec![m("b.c", 2, "m2")], ..Default::default() },
        SpatchResult { rule: "rule_a".into(), matches: vec![m("c.c", 3, "m3")], ..Default::default() },
    ];
    let doc = results_to_sarif(&results, &PathBuf::from("/repo"));
    let rule_ids: Vec<&str> = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(rule_ids, ["rule_a", "rule_b"]);
    assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 3);
}

#[test]
fn sarif_errors_without_matches_surface_as_invocations() {
    let result = SpatchResult {
        rule: "broken_rule".into(),
        errors: vec!["semantic error: unbound metavariable foo".into()],
        returncode: 1,
        ..Default::default()
    };
    let doc = results_to_sarif(&[result], &PathBuf::from("/repo"));
    let run = &doc["runs"][0];
    assert!(run.get("invocations").is_some());
    let notifs = run["invocations"][0]["toolExecutionNotifications"].as_array().unwrap();
    assert_eq!(notifs.len(), 1);
    assert!(notifs[0]["message"]["text"].as_str().unwrap().contains("unbound metavariable"));
    assert_eq!(notifs[0]["associatedRule"]["id"], "broken_rule");
    assert_eq!(run["results"], json!([]));
}

#[test]
fn sarif_no_errors_omits_invocations_block() {
    let result = SpatchResult { rule: "r".into(), matches: vec![m("a.c", 1, "m")], ..Default::default() };
    let doc = results_to_sarif(&[result], &PathBuf::from("/repo"));
    assert!(doc["runs"][0].get("invocations").is_none());
}

#[test]
fn sarif_match_without_message_synthesizes_one() {
    let result = SpatchResult { rule: "my_rule".into(), matches: vec![m("a.c", 1, "")], ..Default::default() };
    let doc = results_to_sarif(&[result], &PathBuf::from("/repo"));
    assert!(doc["runs"][0]["results"][0]["message"]["text"].as_str().unwrap().contains("my_rule"));
}

#[test]
fn sarif_optional_region_fields_omitted_when_zero() {
    let result = SpatchResult {
        rule: "r".into(),
        matches: vec![SpatchMatch { file: "a.c".into(), line: 5, message: "m".into(), ..Default::default() }],
        ..Default::default()
    };
    let doc = results_to_sarif(&[result], &PathBuf::from("/repo"));
    let region = &doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["startLine"], 5);
    assert!(region.get("endLine").is_none());
    assert!(region.get("startColumn").is_none());
    assert!(region.get("endColumn").is_none());
}

// ── prereqs (mirrors test_prereqs.py) ───────────────────────────────────────

use crate::prereqs::{build_facts, evaluate_finding, has_c_cpp_source, gather_prereqs, PrereqFacts};

fn facts_with(defs: &[(&str, &[(&str, i64)])], calls: &[(&str, &[(&str, i64)])]) -> PrereqFacts {
    let mut f = PrereqFacts::default();
    for (name, locs) in defs {
        f.defs.insert(name.to_string(), locs.iter().map(|(a, b)| (a.to_string(), *b)).collect());
    }
    for (name, locs) in calls {
        f.calls.insert(name.to_string(), locs.iter().map(|(a, b)| (a.to_string(), *b)).collect());
    }
    f
}

#[test]
fn prereq_facts_default_and_skipped() {
    let f = PrereqFacts::default();
    assert!(!f.is_skipped());
    assert!(!f.function_exists("foo"));
    assert!(!f.function_has_callers("foo"));
    assert!(PrereqFacts::skipped("spatch_not_available").is_skipped());
}

#[test]
fn prereq_facts_callers_of_returns_sorted() {
    let f = facts_with(&[], &[("foo", &[("b.c", 10), ("a.c", 1), ("a.c", 5)])]);
    assert_eq!(
        f.callers_of("foo"),
        vec![("a.c".to_string(), 1), ("a.c".to_string(), 5), ("b.c".to_string(), 10)]
    );
}

#[test]
fn prereq_build_facts_parses_def_and_call() {
    let results = [SpatchResult {
        rule: "function_inventory".into(),
        matches: vec![
            m("src/a.c", 10, "def:helper"),
            m("src/a.c", 20, "def:main"),
            m("src/a.c", 21, "call:helper"),
            m("src/a.c", 22, "call:printf"),
        ],
        ..Default::default()
    }];
    let facts = build_facts(&results);
    assert!(!facts.is_skipped());
    assert!(facts.function_exists("helper"));
    assert!(facts.function_exists("main"));
    assert!(!facts.function_exists("printf"));
    assert!(facts.function_has_callers("helper"));
    assert!(!facts.function_has_callers("main"));
    assert_eq!(facts.callers_of("helper"), vec![("src/a.c".to_string(), 21)]);
}

#[test]
fn prereq_build_facts_ignores_unknown_shapes() {
    let results = [SpatchResult {
        rule: "function_inventory".into(),
        matches: vec![m("x.c", 1, "def:f"), m("x.c", 2, "future_kind:something"), m("x.c", 3, "")],
        ..Default::default()
    }];
    let facts = build_facts(&results);
    assert!(facts.function_exists("f"));
    assert!(facts.calls.is_empty());
    assert_eq!(facts.defs.keys().cloned().collect::<Vec<_>>(), vec!["f".to_string()]);
}

#[test]
fn prereq_evaluate_skipped_facts() {
    let facts = PrereqFacts::skipped("spatch_not_available");
    let out = evaluate_finding(&json!({"function": "foo", "file": "a.c"}), &facts);
    assert_eq!(out["applicable"], false);
    assert_eq!(out["skipped_reason"], "spatch_not_available");
}

#[test]
fn prereq_evaluate_missing_function() {
    let out = evaluate_finding(&json!({"file": "a.c"}), &PrereqFacts::default());
    assert_eq!(out["applicable"], false);
    assert_eq!(out["skipped_reason"], "finding_missing_function");
}

#[test]
fn prereq_evaluate_non_c_cpp_file() {
    let facts = facts_with(&[("foo", &[("a.c", 1)])], &[]);
    let out = evaluate_finding(&json!({"function": "foo", "file": "src/auth.py"}), &facts);
    assert_eq!(out["applicable"], false);
    assert_eq!(out["skipped_reason"], "non_c_cpp_file");
}

#[test]
fn prereq_evaluate_exists_with_callers() {
    let facts = facts_with(&[("helper", &[("a.c", 10)])], &[("helper", &[("a.c", 20), ("b.c", 5)])]);
    let out = evaluate_finding(&json!({"function": "helper", "file": "a.c"}), &facts);
    assert_eq!(out["applicable"], true);
    assert_eq!(out["checks"]["function_exists"], true);
    assert_eq!(out["checks"]["function_has_callers"], true);
    assert_eq!(out["details"]["function"], "helper");
    assert_eq!(out["details"]["callers_count"], 2);
}

#[test]
fn prereq_evaluate_orphan_static_helper() {
    let facts = facts_with(&[("orphan", &[("a.c", 10)])], &[]);
    let out = evaluate_finding(&json!({"function": "orphan", "file": "a.c"}), &facts);
    assert_eq!(out["checks"]["function_exists"], true);
    assert_eq!(out["checks"]["function_has_callers"], false);
}

#[test]
fn prereq_evaluate_not_defined_locally() {
    let facts = facts_with(&[("main", &[("a.c", 1)])], &[("strlen", &[("a.c", 5)])]);
    let out = evaluate_finding(&json!({"function": "strlen", "file": "a.c"}), &facts);
    assert_eq!(out["checks"]["function_exists"], false);
    assert_eq!(out["checks"]["function_has_callers"], Value::Null);
    assert_eq!(out["details"], json!({"function": "strlen"}));
}

#[test]
fn prereq_evaluate_extensionless_treated_as_c() {
    let facts = facts_with(&[("foo", &[("a.c", 1)])], &[]);
    let out = evaluate_finding(&json!({"function": "foo", "file": "Makefile_target"}), &facts);
    assert_eq!(out["applicable"], true);
    assert_eq!(out["checks"]["function_exists"], true);
}

#[test]
fn prereq_has_c_cpp_source_detects_and_rejects() {
    let dir = unique_tmp_dir("hascpp");
    std::fs::write(dir.join("main.py"), "\n").unwrap();
    assert!(!has_c_cpp_source(&dir, 200));
    std::fs::write(dir.join("a.c"), "\n").unwrap();
    assert!(has_c_cpp_source(&dir, 200));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn prereq_gather_skips_on_python_only_target() {
    let dir = unique_tmp_dir("gather");
    std::fs::write(dir.join("main.py"), "\n").unwrap();
    // Robust to spatch presence: a python-only target is always skipped, with
    // reason spatch_not_available (no spatch) or no_c_cpp_source (spatch present).
    let facts = gather_prereqs(&dir, None, 300);
    assert!(facts.is_skipped());
    let reason = facts.skipped_reason.as_deref().unwrap();
    assert!(reason == "spatch_not_available" || reason == "no_c_cpp_source");
    std::fs::remove_dir_all(&dir).ok();
}

// ── runner (mirrors test_runner.py) ─────────────────────────────────────────

use crate::runner::{
    collect_files_examined, dedup_matches, inject_harness, parse_errors, parse_results,
    run_rule_impl, run_rules_impl, version_impl, RunOptions, Spawned, SpawnError, SubprocessRunner,
    RESULT_PREFIX,
};

enum FakeResult {
    Ok(i64, String, String),
    Timeout(String, String),
    Os(String),
}

struct Fake {
    result: FakeResult,
    captured_cmd: std::cell::RefCell<Vec<String>>,
    sp_file_existed: std::cell::Cell<bool>,
}

impl Fake {
    fn ok(stdout: &str, stderr: &str) -> Fake {
        Fake {
            result: FakeResult::Ok(0, stdout.into(), stderr.into()),
            captured_cmd: std::cell::RefCell::new(Vec::new()),
            sp_file_existed: std::cell::Cell::new(false),
        }
    }
    fn with(result: FakeResult) -> Fake {
        Fake { result, captured_cmd: std::cell::RefCell::new(Vec::new()), sp_file_existed: std::cell::Cell::new(false) }
    }
    fn sp_file(&self) -> PathBuf {
        let cmd = self.captured_cmd.borrow();
        let i = cmd.iter().position(|s| s == "--sp-file").unwrap();
        PathBuf::from(cmd[i + 1].clone())
    }
}

impl SubprocessRunner for Fake {
    fn run(&self, cmd: &[String], _env: &[(String, String)], _cwd: Option<&std::path::Path>, _timeout: u64) -> Result<Spawned, SpawnError> {
        *self.captured_cmd.borrow_mut() = cmd.to_vec();
        if let Some(i) = cmd.iter().position(|s| s == "--sp-file") {
            self.sp_file_existed.set(std::path::Path::new(&cmd[i + 1]).exists());
        }
        match &self.result {
            FakeResult::Ok(c, o, e) => Ok(Spawned { returncode: *c, stdout: o.clone(), stderr: e.clone() }),
            FakeResult::Timeout(o, e) => Err(SpawnError::Timeout { stdout: o.clone(), stderr: e.clone() }),
            FakeResult::Os(m) => Err(SpawnError::Os(m.clone())),
        }
    }
}

#[test]
fn runner_parse_single_result() {
    let output = format!("{RESULT_PREFIX}{}\n", json!({"file": "./a.c", "line": 10, "col": 5}));
    let matches = parse_results(&output, "test_rule");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].file, "./a.c");
    assert_eq!(matches[0].line, 10);
    assert_eq!(matches[0].rule, "test_rule");
}

#[test]
fn runner_parse_multiple_and_ignores_and_malformed_and_empty() {
    let mut lines = String::new();
    for i in 0..3 {
        lines.push_str(&format!("{RESULT_PREFIX}{}\n", json!({"file": format!("f{i}.c"), "line": i + 1})));
    }
    assert_eq!(parse_results(&lines, "r").len(), 3);

    let ignore = format!("init_defs_builtins: /usr/lib/coccinelle/standard.h\nHANDLING: ./test.c\n{RESULT_PREFIX}{{\"file\":\"a.c\",\"line\":1}}\n");
    assert_eq!(parse_results(&ignore, "r").len(), 1);

    let malformed = format!("{RESULT_PREFIX}not-json\n{RESULT_PREFIX}{{\"file\":\"a.c\",\"line\":1}}\n");
    assert_eq!(parse_results(&malformed, "r").len(), 1);

    assert!(parse_results("", "r").is_empty());
}

#[test]
fn runner_parse_errors_classification() {
    assert!(parse_errors("init_defs_builtins: /usr/lib/coccinelle/standard.h\nHANDLING: ./test.c\n").is_empty());
    let parse = parse_errors("minus: parse error:\n  File \"test.cocci\", line 6\n");
    assert!(parse.iter().any(|e| e.to_lowercase().contains("parse error")));
    assert!(parse_errors(&format!("{RESULT_PREFIX}{{\"file\":\"a.c\"}}\n")).is_empty());
    assert!(parse_errors("warning: some informational message about error recovery\n").is_empty());
    assert_eq!(parse_errors("Semantic error: bad use of ...\n").len(), 1);
}

#[test]
fn runner_dedup_matches() {
    fn sm(file: &str, line: i64, col: i64, rule: &str) -> SpatchMatch {
        SpatchMatch { file: file.into(), line, column: col, rule: rule.into(), ..Default::default() }
    }
    let dup = vec![sm("a.c", 10, 5, "r1"), sm("a.c", 10, 5, "r1"), sm("a.c", 20, 1, "r1")];
    assert_eq!(dedup_matches(dup).len(), 2);
    let ordered = vec![sm("b.c", 1, 0, "r1"), sm("a.c", 1, 0, "r1"), sm("b.c", 1, 0, "r1")];
    let d = dedup_matches(ordered);
    assert_eq!(d[0].file, "b.c");
    assert_eq!(d[1].file, "a.c");
    let diff_rules = vec![sm("a.c", 10, 5, "r1"), sm("a.c", 10, 5, "r2")];
    assert_eq!(dedup_matches(diff_rules).len(), 2);
    assert!(dedup_matches(vec![]).is_empty());
}

#[test]
fn runner_inject_harness_position_rule() {
    let rule = "@r@\nexpression E;\nposition p;\n@@\n\nE@p = malloc(...);\n";
    let result = inject_harness(rule, "test_rule");
    assert!(result.contains("script:python"));
    assert!(result.contains(RESULT_PREFIX));
    assert!(result.contains("test_rule"));
}

#[test]
fn runner_inject_harness_exact_string() {
    // Golden vector: the appended harness, byte-for-byte from the live Python
    // `_inject_harness` (`\\n` is a literal backslash-n inside the emitted
    // sys.stderr.write, mirroring Python's "\\n").
    let rule = "@r@\nexpression E;\nposition p;\n@@\n\nE@p = malloc(...);\n";
    let expected_tail = "\n\n@script:python@\np << r.p;\n@@\n\nimport json, sys\n\
for _p in p:\n    _m = {\"file\": _p.file, \"line\": int(_p.line), \"col\": int(_p.column), \
\"line_end\": int(_p.line_end), \"col_end\": int(_p.column_end), \"rule\": \"test_rule\"}\n    \
sys.stderr.write(\"COCCIRESULT:\" + json.dumps(_m) + \"\\n\")\n";
    assert_eq!(inject_harness(rule, "test_rule"), format!("{rule}{expected_tail}"));
}

#[test]
fn runner_inject_harness_no_position() {
    let rule = "@@\nexpression E;\n@@\n\nE = malloc(...);\n";
    assert_eq!(inject_harness(rule, "test_rule"), rule);
}

#[test]
fn runner_inject_harness_sanitizes_rule_name() {
    let rule = "@r@\nexpression E;\nposition p;\n@@\n\nE@p = malloc(...);\n";
    let result = inject_harness(rule, "evil\", \"extra\": \"injected");
    assert!(!result.contains("\"extra\""));
    assert!(result.contains("evil____extra____injected"));
}

#[test]
fn runner_inject_harness_denylist_and_multirule() {
    // `int` is a denied position var → unchanged.
    let denied = "@r@\nposition int;\n@@\nmalloc@int(...)\n";
    assert_eq!(inject_harness(denied, "x"), denied);
    // Multi-rule file (two distinct @names@) → unchanged.
    let multi = "@a@\nposition p;\n@@\nmalloc@p(...)\n@b@\nexpression E;\n@@\nfree(E)\n";
    assert_eq!(inject_harness(multi, "x"), multi);
}

#[test]
fn runner_collect_files_examined() {
    let dir = unique_tmp_dir("collect");
    let single = dir.join("test.c");
    std::fs::write(&single, "int main() {}\n").unwrap();
    let single_str = single.to_string_lossy().into_owned();

    let r = collect_files_examined(&single, &BTreeSet::new());
    assert!(r.contains(&single_str));

    let mut mf = BTreeSet::new();
    mf.insert("other.c".to_string());
    let r = collect_files_examined(&single, &mf);
    assert!(r.contains(&single_str) && r.contains(&"other.c".to_string()));

    let ddir = unique_tmp_dir("collectdir");
    std::fs::write(ddir.join("a.c"), "").unwrap();
    std::fs::write(ddir.join("b.c"), "").unwrap();
    std::fs::write(ddir.join("skip.txt"), "").unwrap();
    let r = collect_files_examined(&ddir, &BTreeSet::new());
    assert_eq!(r.len(), 2);
    assert!(r.iter().any(|f| f.ends_with("a.c")) && r.iter().any(|f| f.ends_with("b.c")));
    assert!(!r.iter().any(|f| f.ends_with("skip.txt")));

    let mut mf2 = BTreeSet::new();
    mf2.insert("a.c".to_string());
    assert_eq!(collect_files_examined(&dir.join("gone"), &mf2), vec!["a.c".to_string()]);

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&ddir).ok();
}

#[test]
fn runner_version_impl() {
    let fake = Fake::ok("spatch version 1.3 compiled with OCaml\n", "");
    let v = version_impl(true, &fake).unwrap();
    assert!(v.contains("1.3"));
    assert!(version_impl(false, &fake).is_none());
}

#[test]
fn runner_run_rule_not_installed() {
    let dir = unique_tmp_dir("notinst");
    let rule = dir.join("test.cocci");
    std::fs::write(&rule, "@@\nexpression E;\n@@\nE = malloc(...);\n").unwrap();
    let fake = Fake::ok("", "");
    let result = run_rule_impl(&dir, &rule, 300, &RunOptions::default(), false, &fake);
    assert!(!result.ok());
    assert!(result.errors[0].to_lowercase().contains("not installed"));
    assert_eq!(result.returncode, -1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_run_rule_missing_rule_file() {
    let dir = unique_tmp_dir("missing");
    let fake = Fake::ok("", "");
    let result = run_rule_impl(&dir, &dir.join("nonexistent.cocci"), 300, &RunOptions::default(), true, &fake);
    assert!(!result.ok());
    assert!(result.errors[0].to_lowercase().contains("not found"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_run_rule_with_mock() {
    let dir = unique_tmp_dir("mock");
    let rule = dir.join("test.cocci");
    // Pre-injected script:python → no harness, original rule path used.
    std::fs::write(&rule, "@r@\nposition p;\n@@\nmalloc@p(...)\n@script:python@\np << r.p;\n@@\nimport json,sys\n").unwrap();
    let target = dir.join("test.c");
    std::fs::write(&target, "void f() { void *p = malloc(10); }\n").unwrap();
    let fake = Fake::ok("", "COCCIRESULT:{\"file\":\"test.c\",\"line\":1}\n");
    let result = run_rule_impl(&target, &rule, 300, &RunOptions { env: Some(vec![]), ..Default::default() }, true, &fake);
    assert_eq!(result.rule, "test");
    assert_eq!(result.match_count(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_run_rule_timeout() {
    let dir = unique_tmp_dir("timeout");
    let rule = dir.join("test.cocci");
    std::fs::write(&rule, "@r@\nposition p;\n@@\nmalloc@p(...)\n").unwrap();
    let target = dir.join("test.c");
    std::fs::write(&target, "void f() {}\n").unwrap();
    let fake = Fake::with(FakeResult::Timeout(String::new(), String::new()));
    let result = run_rule_impl(&target, &rule, 5, &RunOptions { env: Some(vec![]), ..Default::default() }, true, &fake);
    assert!(!result.ok());
    assert!(result.errors[0].to_lowercase().contains("timeout"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_harnessed_rule_routes_via_tempfile_and_cleans_up() {
    let dir = unique_tmp_dir("harness");
    let rule = dir.join("needs_harness.cocci");
    std::fs::write(&rule, "@r@\nexpression e1, e2;\nposition p;\n@@\nstrcpy@p(e1, e2)\n").unwrap();
    let target = dir.join("x.c");
    std::fs::write(&target, "void f() {}\n").unwrap();
    let fake = Fake::ok("", "");
    run_rule_impl(&target, &rule, 300, &RunOptions { env: Some(vec![]), ..Default::default() }, true, &fake);

    let cmd = fake.captured_cmd.borrow().clone();
    assert!(!cmd.iter().any(|s| s == "-"), "regressed to --sp-file - (stdin): {cmd:?}");
    let sp = fake.sp_file();
    assert_ne!(sp, rule, "harnessed rule must route via a tempfile, not the original");
    assert!(fake.sp_file_existed.get(), "tempfile must exist during the spatch call");
    assert!(!sp.exists(), "tempfile must be cleaned up after run_rule returns");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_pre_injected_rule_bypasses_tempfile() {
    let dir = unique_tmp_dir("preinj");
    let rule = dir.join("self_emitting.cocci");
    std::fs::write(&rule, "@r@\nposition p;\n@@\nmalloc@p(...)\n@script:python@\np << r.p;\n@@\nimport json,sys\n").unwrap();
    let target = dir.join("x.c");
    std::fs::write(&target, "void f() {}\n").unwrap();
    let fake = Fake::ok("", "");
    run_rule_impl(&target, &rule, 300, &RunOptions { env: Some(vec![]), ..Default::default() }, true, &fake);
    assert_eq!(fake.sp_file(), rule, "rule with script:python should use original path");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_run_rule_oserror_cleans_tempfile() {
    let dir = unique_tmp_dir("oserr");
    let rule = dir.join("needs_harness.cocci");
    std::fs::write(&rule, "@r@\nposition p;\n@@\nstrcpy@p(...)\n").unwrap();
    let target = dir.join("x.c");
    std::fs::write(&target, "void f() {}\n").unwrap();
    let fake = Fake::with(FakeResult::Os("spatch went missing".into()));
    let result = run_rule_impl(&target, &rule, 300, &RunOptions { env: Some(vec![]), ..Default::default() }, true, &fake);
    assert!(!result.ok());
    assert_eq!(result.returncode, -1);
    // tempfile cleaned up despite the OSError early-return path
    assert!(!fake.sp_file().exists(), "tempfile leaked on OSError");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_run_rules_not_installed_empty_and_all() {
    let dir = unique_tmp_dir("rules");
    let rules_dir = dir.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("a.cocci"), "@r@\nposition p;\n@@\nmalloc@p(...)\n@script:python@\np << r.p;\n@@\nx\n").unwrap();
    std::fs::write(rules_dir.join("b.cocci"), "@r@\nposition p;\n@@\nfree@p(...)\n@script:python@\np << r.p;\n@@\nx\n").unwrap();
    let target = dir.join("test.c");
    std::fs::write(&target, "void f() {}\n").unwrap();
    let opts = RunOptions { env: Some(vec![]), ..Default::default() };

    // not installed → single coccinelle error result
    let fake = Fake::ok("", "");
    let r = run_rules_impl(&target, &rules_dir, 300, &opts, false, &fake);
    assert_eq!(r.len(), 1);
    assert!(r[0].errors[0].to_lowercase().contains("not installed"));

    // empty (no .cocci) → []
    let empty = dir.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    assert!(run_rules_impl(&target, &empty, 300, &opts, true, &fake).is_empty());

    // runs all in filename order
    let fake2 = Fake::ok("", "");
    let r = run_rules_impl(&target, &rules_dir, 300, &opts, true, &fake2);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].rule, "a");
    assert_eq!(r[1].rule, "b");

    std::fs::remove_dir_all(&dir).ok();
}
