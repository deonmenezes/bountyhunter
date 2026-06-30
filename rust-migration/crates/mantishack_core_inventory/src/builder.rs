//! Inventory builder — Rust port of `core/inventory/builder.py`.
//!
//! `process_file_content` is the content->record core of `_process_single_file`:
//! given a file's relative path, language, and decoded content, it assembles the
//! inventory file-record (items + interstitials, sloc, sha256, lexical-dead
//! tagging, per-language call_graph, macro-call targets, module-abort and
//! build-exclusion gates) exactly as the Python builder does for the parsed body.
//!
//! What is intentionally NOT ported here (filesystem / orchestration concerns of
//! `_process_single_file` + `build_inventory`): the tree walk, exclusion/binary/
//! generated/size pre-checks, the stat+sha256 incremental-rebuild cache, thread
//! pooling, and the `_stat` field (set to null — it's an mtime/size pair). The
//! `build_tus`/`crate_modules` build-membership gates need external compile-graph
//! state and are left to the caller. Python-`ast` call_graph (python files) is
//! the documented cross-module gap; all tree-sitter languages dispatch here.

use mantishack_core_hash::sha256_bytes;
use serde_json::{json, Value};

use crate::build_membership::detect_build_excluded;
use crate::call_graph::{
    extract_call_graph_c, extract_call_graph_cpp, extract_call_graph_csharp,
    extract_call_graph_go, extract_call_graph_java, extract_call_graph_js_lang,
    extract_call_graph_php, extract_call_graph_ruby, extract_call_graph_rust,
};
use crate::dead_scope::detect_dead_scopes;
use crate::extractors::{compute_interstitial_items, CodeItem};
use crate::module_load_abort::detect_module_load_abort;
use crate::translation_view::{detect_macro_call_targets, preprocess_view};
use crate::ts_extract::{count_sloc, extract_items, InventoryItem};

fn code_item_json(c: &CodeItem) -> Value {
    json!({
        "name": c.name, "kind": c.kind, "line_start": c.line_start,
        "line_end": c.line_end, "checked_by": c.checked_by,
    })
}

fn call_graph_for(language: &str, parse_text: &str) -> Option<Value> {
    let cg = match language {
        "javascript" | "typescript" | "tsx" => extract_call_graph_js_lang(parse_text, language),
        "go" => extract_call_graph_go(parse_text),
        "java" => extract_call_graph_java(parse_text),
        "rust" => extract_call_graph_rust(parse_text),
        "ruby" => extract_call_graph_ruby(parse_text),
        "csharp" | "c_sharp" => extract_call_graph_csharp(parse_text),
        "php" => extract_call_graph_php(parse_text),
        "c" => extract_call_graph_c(parse_text),
        "cpp" => extract_call_graph_cpp(parse_text),
        // python -> CPython `ast` (documented gap); unknown -> no call graph.
        _ => return None,
    };
    Some(cg.to_json())
}

/// Assemble the inventory file-record for one file's decoded `content` — the
/// parsed-body core of `_process_single_file`. `_stat` is `null` (an I/O field);
/// `sha256` is over the UTF-8 bytes of `content`.
pub fn process_file_content(rel_path: &str, language: &str, content: &str) -> Value {
    let line_count = content.matches('\n').count() as i64 + 1;
    let sha256 = sha256_bytes(content.as_bytes());

    // The tree-sitter / AST parse reads the TranslationView's parse_text (so
    // future #if 0 blanking slots in); metrics + text scanners use real content.
    let view = preprocess_view(language, content, false, None);
    let parse_text = view.parse_text;

    let items = extract_items(language, &parse_text);
    let bounds: Vec<CodeItem> = items
        .iter()
        .map(|it| CodeItem::new("", "", it.line_start(), it.line_end()))
        .collect();
    let interstitial = compute_interstitial_items(&bounds, &parse_text);

    let mut items_json: Vec<Value> = items.iter().map(InventoryItem::to_json).collect();
    items_json.extend(interstitial.iter().map(code_item_json));

    let sloc = count_sloc(language, content);

    // S3: per-function lexical-dead tagging (definition inside an always-false guard).
    let dead_ranges = detect_dead_scopes(language, content);
    if !dead_ranges.is_empty() {
        for item in &mut items_json {
            let ls = item.get("line_start").and_then(Value::as_i64).unwrap_or(0);
            if ls != 0 && dead_ranges.iter().any(|d| d.0 as i64 <= ls && ls <= d.1 as i64) {
                item["lexical_dead"] = json!(true);
            }
        }
    }

    let mut record = json!({
        "path": rel_path,
        "language": language,
        "lines": line_count,
        "sloc": sloc,
        "sha256": sha256,
        "_stat": Value::Null,
        "items": items_json,
    });

    // Per-language call-graph; C/C++ also record function-like-macro call targets.
    if let Some(mut cg) = call_graph_for(language, &parse_text) {
        if matches!(language, "c" | "cpp") {
            let macro_targets = detect_macro_call_targets(&parse_text);
            if !macro_targets.is_empty() {
                cg["macro_call_targets"] = json!(macro_targets.into_iter().collect::<Vec<_>>());
            }
        }
        record["call_graph"] = cg;
    }

    // S4: whole-file module-load-abort gate (stored only when detected).
    if let Some(abort) = detect_module_load_abort(language, content) {
        record["module_aborts_on_load"] = json!({"line": abort.line, "summary": abort.summary});
    }

    // Whole-file build exclusion (content-based; TU/crate-membership gates need
    // external state and are the caller's responsibility).
    if let Some(excluded) = detect_build_excluded(language, content) {
        record["build_excluded"] = json!({"line": excluded.line, "summary": excluded.summary});
    }

    record
}

/// Assemble the final inventory dict from processed file records — the
/// deterministic tail of `build_inventory` (sort, totals, metadata shape).
/// `generated_at` is supplied by the caller (the Python builder stamps
/// `datetime.now`, which is non-deterministic). Coverage carry-forward and the
/// `limitations` field (tree-sitter always available here) are out of scope.
pub fn assemble_inventory(
    mut files_info: Vec<Value>,
    mut excluded_files: Vec<Value>,
    exclude_patterns: &[String],
    target_path: &str,
    skipped: i64,
    generated_at: &str,
) -> Value {
    let path_key = |v: &Value| v.get("path").and_then(Value::as_str).unwrap_or("").to_string();
    files_info.sort_by_key(path_key);
    excluded_files.sort_by_key(path_key);

    let total_items: i64 = files_info
        .iter()
        .map(|f| f.get("items").and_then(Value::as_array).map_or(0, |a| a.len() as i64))
        .sum();
    let total_sloc: i64 = files_info.iter().map(|f| f.get("sloc").and_then(Value::as_i64).unwrap_or(0)).sum();
    let total_functions: i64 = files_info
        .iter()
        .flat_map(|f| f.get("items").and_then(Value::as_array).into_iter().flatten())
        .filter(|it| it.get("kind").and_then(Value::as_str).unwrap_or("function") == "function")
        .count() as i64;

    json!({
        "generated_at": generated_at,
        "target_path": target_path,
        "total_files": files_info.len(),
        "total_items": total_items,
        "total_functions": total_functions,
        "total_sloc": total_sloc,
        "skipped_files": skipped,
        "excluded_patterns": exclude_patterns,
        "excluded_files": excluded_files,
        "files": files_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn go_record_has_items_and_call_graph() {
        let src = "package main\n\nfunc main() {\n\thelper()\n}\n\nfunc helper() {}\n";
        let rec = process_file_content("main.go", "go", src);
        assert_eq!(rec["path"], "main.go");
        assert_eq!(rec["language"], "go");
        assert_eq!(rec["lines"], 8);
        assert!(rec["sha256"].as_str().unwrap().len() == 64);
        assert!(rec["items"].as_array().unwrap().iter().any(|i| i["name"] == "main"));
        // call_graph present with a main->helper edge.
        let calls = rec["call_graph"]["calls"].as_array().unwrap();
        assert!(calls.iter().any(|c| c["chain"] == json!(["helper"])));
    }

    #[test]
    fn assemble_sorts_and_totals() {
        let a = process_file_content("z.go", "go", "package main\nfunc a() {}\n");
        let b = process_file_content("a.go", "go", "package main\nfunc b() {}\nfunc c() {}\n");
        let inv = assemble_inventory(vec![a, b], vec![], &["node_modules".into()], "/tgt", 2, "TS");
        assert_eq!(inv["total_files"], 2);
        assert_eq!(inv["skipped_files"], 2);
        assert_eq!(inv["generated_at"], "TS");
        // files sorted by path: a.go before z.go.
        let files = inv["files"].as_array().unwrap();
        assert_eq!(files[0]["path"], "a.go");
        assert_eq!(files[1]["path"], "z.go");
        // total_functions counts kind==function items across files (3: a, b, c).
        assert_eq!(inv["total_functions"], 3);
        assert_eq!(inv["excluded_patterns"], json!(["node_modules"]));
    }

    #[test]
    fn go_build_excluded_gate() {
        let src = "//go:build ignore\n\npackage main\n\nfunc main() {}\n";
        let rec = process_file_content("ignored.go", "go", src);
        assert_eq!(rec["build_excluded"]["summary"], "//go:build ignore");
    }
}
