//! Golden vectors mirroring `packages/coccinelle/tests/{test_models,
//! test_findings,test_coverage}.py` — every expectation matches the Python oracle.

use serde_json::json;

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
