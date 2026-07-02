//! Semgrep SARIF merge tool — faithful Rust port of
//! `engine/semgrep/tools/sarif_merge.py`.
//!
//! The Python module is a thin CLI wrapper whose one module-level public symbol
//! is `merge_sarif_files(output_path, input_paths)`. It delegates the merge to
//! `core.sarif.parser.merge_sarif` (which itself loads via `core.sarif.parser.
//! load_sarif`) and writes with `core.json.save_json`.
//!
//! `core.sarif` deliberately kept the file-I/O loaders (`load_sarif`,
//! `merge_sarif`) in Python, so this glue crate reproduces them:
//!   * [`merge_sarif`] mirrors `core.sarif.parser.merge_sarif` — group runs by
//!     tool name, dedup results by the extended `_result_key`, union rules by id,
//!     merge `originalUriBaseIds` (later-wins per id), append `invocations`.
//!   * `load_sarif` mirrors `core.sarif.parser.load_sarif` — existence + 100 MiB
//!     size guard, bounded read, `utf-8`/replace decode, `json.loads(content or
//!     "{}")`, `None` on any error.
//!   * [`merge_sarif_files`] mirrors the module function — merge, save, print.
//!
//! Reused (not reimplemented): [`mantishack_core_sarif::result_key`] for the
//! dedup key and [`mantishack_core_json::save_json`] for the atomic writer.

use std::collections::HashMap;
use std::hash::Hash;
use std::io::Read;
use std::path::Path;

use mantishack_core_json::save_json;
use mantishack_core_sarif::result_key;
use serde_json::{Map, Value};

/// 100 MiB — the `load_sarif` size guard (`max_size`).
const MAX_SARIF_SIZE: u64 = 100 * 1024 * 1024;

/// The extended `_result_key` tuple, hashable for dedup:
/// (ruleId, uri, startLine, endLine, startColumn, fingerprint).
type ResultTupleKey = (String, String, i64, i64, i64, String);

/// Python truthiness for a JSON value (the `x or y` / `if not x` fallbacks).
fn json_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// An insertion-ordered map with "reassign keeps position" semantics — the
/// behaviour of a Python `dict` used as an accumulator. Iteration yields entries
/// in first-insertion order; re-inserting an existing key overwrites the value
/// in place without moving it.
struct OrderedMap<K: Eq + Hash + Clone, V> {
    index: HashMap<K, usize>,
    entries: Vec<(K, V)>,
}

impl<K: Eq + Hash + Clone, V> OrderedMap<K, V> {
    fn new() -> Self {
        Self { index: HashMap::new(), entries: Vec::new() }
    }

    fn insert(&mut self, k: K, v: V) {
        if let Some(&i) = self.index.get(&k) {
            self.entries[i].1 = v;
        } else {
            self.index.insert(k.clone(), self.entries.len());
            self.entries.push((k, v));
        }
    }

    fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        self.index.get(k).map(|&i| &mut self.entries[i].1)
    }

    fn contains_key(&self, k: &K) -> bool {
        self.index.contains_key(k)
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.entries.iter()
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }
}

/// Per-tool merge accumulator (`tool_runs[tool_name]`).
struct ToolRun {
    /// `run.get("tool", {})` of the FIRST run seen for this tool name.
    tool: Value,
    rules_by_id: OrderedMap<String, Value>,
    results: OrderedMap<ResultTupleKey, Value>,
    uri_bases: OrderedMap<String, Value>,
    invocations: Vec<Value>,
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

/// `run.get("tool", {}).get("driver", {}).get("name", "unknown")` as a grouping
/// key. Missing anywhere in the chain -> `"unknown"` (matching the `.get(k,
/// default)` defaults). A string name is used verbatim (including `""`). A
/// present-but-non-string name is a malformed-SARIF edge; Python would use the
/// raw value as a dict key — we key on its JSON rendering instead. (Python would
/// additionally raise `AttributeError` if `tool`/`driver` were present-but-null;
/// well-formed SARIF never triggers either path.)
fn merge_tool_name(run: &Value) -> String {
    match run
        .get("tool")
        .and_then(|t| t.get("driver"))
        .and_then(|d| d.get("name"))
    {
        None => "unknown".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// A rule id used as a dict key. Realistic SARIF ids are strings; a non-string
/// id (already filtered to truthy) is keyed on its JSON rendering.
fn rule_id_key(id: &Value) -> String {
    match id {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Load a SARIF file with the same safety guards as `core.sarif.parser.
/// load_sarif`: existence check, 100 MiB cap (stat then bounded read), lossy
/// UTF-8 decode, and `json.loads(content or "{}")`. Returns `None` on any error
/// (missing / too large / unreadable / invalid JSON). Note: an empty file
/// decodes to `""` and parses as `{}` (an empty object).
fn load_sarif(path: &Path) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_SARIF_SIZE {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    // Bounded read of max_size + 1: detect "too large" without loading more than
    // the cap. The extra byte is the "did we hit the limit" sentinel.
    if file
        .take(MAX_SARIF_SIZE + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return None;
    }
    if buf.len() as u64 > MAX_SARIF_SIZE {
        // Race: file grew between stat and read.
        return None;
    }
    let content = String::from_utf8_lossy(&buf);
    // `content or "{}"` — only the empty string is falsy.
    let to_parse: &str = if content.is_empty() { "{}" } else { &content };
    serde_json::from_str::<Value>(to_parse).ok()
}

/// `run[...]` array accessor: returns the slice when the key holds a JSON array,
/// else an empty slice (mirrors the `x or []` / `.get(k, [])` guards for the
/// realistic case; a present-but-non-array value contributes nothing).
fn array_at<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// Merge multiple SARIF files into a single SARIF dict.
///
/// Faithful port of `core.sarif.parser.merge_sarif`: group runs by tool name,
/// deduplicate results within each tool by the extended `_result_key` (latest
/// occurrence wins), union `tool.driver.rules` by id (later wins, first-seen
/// order), merge `originalUriBaseIds` (later wins per id) and append
/// `invocations`. Falsy loaded files (missing, empty, `{}`, `null`) are skipped.
pub fn merge_sarif(sarif_paths: &[String]) -> Value {
    let mut tool_runs: OrderedMap<String, ToolRun> = OrderedMap::new();

    for sarif_path in sarif_paths {
        let sarif_data = match load_sarif(Path::new(sarif_path)) {
            Some(d) if json_truthy(&d) => d,
            _ => continue, // `if not sarif_data: continue`
        };

        for run in array_at(&sarif_data, "runs") {
            let tool_name = merge_tool_name(run);
            if !tool_runs.contains_key(&tool_name) {
                let tool_val = run.get("tool").cloned().unwrap_or_else(empty_object);
                tool_runs.insert(
                    tool_name.clone(),
                    ToolRun {
                        tool: tool_val,
                        rules_by_id: OrderedMap::new(),
                        results: OrderedMap::new(),
                        uri_bases: OrderedMap::new(),
                        invocations: Vec::new(),
                    },
                );
            }
            let tr = tool_runs.get_mut(&tool_name).unwrap();

            // Union rules: run["tool"]["driver"]["rules"] or [].
            let rules = run
                .get("tool")
                .and_then(|t| t.get("driver"))
                .and_then(|d| d.get("rules"))
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for rule in rules {
                if rule.is_object() {
                    if let Some(id) = rule.get("id") {
                        if json_truthy(id) {
                            tr.rules_by_id.insert(rule_id_key(id), rule.clone());
                        }
                    }
                }
            }

            // Merge originalUriBaseIds — keyed dict, later wins.
            if let Some(bases) = run.get("originalUriBaseIds").and_then(Value::as_object) {
                for (base_id, base) in bases {
                    if base.is_object() {
                        tr.uri_bases.insert(base_id.clone(), base.clone());
                    }
                }
            }

            // Append invocations — each is its own logical invocation record.
            for inv in array_at(run, "invocations") {
                if inv.is_object() {
                    tr.invocations.push(inv.clone());
                }
            }

            // Dedup results by _result_key; latest occurrence wins.
            for result in array_at(run, "results") {
                let k = result_key(result);
                let tkey: ResultTupleKey =
                    (k.rule_id, k.uri, k.line, k.end_line, k.start_col, k.fingerprint);
                tr.results.insert(tkey, result.clone());
            }
        }
    }

    // Build final SARIF with one run per tool, in first-seen tool order.
    let mut merged_runs: Vec<Value> = Vec::new();
    for (_tool_name, run_data) in tool_runs.iter() {
        // tool_block = dict(run_data["tool"]) if run_data["tool"] else {}
        let mut tool_block: Map<String, Value> = if json_truthy(&run_data.tool) {
            run_data.tool.as_object().cloned().unwrap_or_default()
        } else {
            Map::new()
        };
        // driver = dict(tool_block.get("driver") or {})
        let mut driver: Map<String, Value> = tool_block
            .get("driver")
            .filter(|v| json_truthy(v))
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        if !run_data.rules_by_id.is_empty() {
            let rules: Vec<Value> = run_data.rules_by_id.values().cloned().collect();
            driver.insert("rules".to_string(), Value::Array(rules));
        }
        tool_block.insert("driver".to_string(), Value::Object(driver));

        let mut run_out: Map<String, Value> = Map::new();
        run_out.insert("tool".to_string(), Value::Object(tool_block));
        if !run_data.uri_bases.is_empty() {
            let mut m: Map<String, Value> = Map::new();
            for (k, v) in run_data.uri_bases.iter() {
                m.insert(k.clone(), v.clone());
            }
            run_out.insert("originalUriBaseIds".to_string(), Value::Object(m));
        }
        if !run_data.invocations.is_empty() {
            run_out.insert(
                "invocations".to_string(),
                Value::Array(run_data.invocations.clone()),
            );
        }
        let results: Vec<Value> = run_data.results.values().cloned().collect();
        run_out.insert("results".to_string(), Value::Array(results));
        merged_runs.push(Value::Object(run_out));
    }

    let mut root: Map<String, Value> = Map::new();
    root.insert("version".to_string(), Value::String("2.1.0".to_string()));
    root.insert(
        "$schema".to_string(),
        Value::String("https://json.schemastore.org/sarif-2.1.0.json".to_string()),
    );
    root.insert("runs".to_string(), Value::Array(merged_runs));
    Value::Object(root)
}

/// Merge multiple SARIF files into one and write the result.
///
/// Faithful port of `merge_sarif_files`: merge the inputs, `save_json` the
/// merged dict to `output_path`, then print the two status lines. Returns an
/// `Err` if the write fails (Python raises; `save_json` never fails silently).
pub fn merge_sarif_files(output_path: &str, input_paths: &[String]) -> std::io::Result<()> {
    let merged = merge_sarif(input_paths);

    save_json(Path::new(output_path), &merged, None)?;

    println!(
        "Merged {} SARIF files into {}",
        input_paths.len(),
        output_path
    );
    let total_runs = merged
        .get("runs")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    println!("Total runs: {}", total_runs);
    Ok(())
}

// ── PyO3 bindings ─────────────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::PyModule;

    /// `merge_sarif_files(output_path: str, input_paths: list) -> None`.
    #[pyfunction]
    fn merge_sarif_files(output_path: &str, input_paths: Vec<String>) -> PyResult<()> {
        super::merge_sarif_files(output_path, &input_paths)
            .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
    }

    #[pymodule]
    fn mantishack_engine_semgrep_tools(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(merge_sarif_files, m)?)?;
        Ok(())
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write as _;
    use tempfile::TempDir;

    /// Write `content` to `<dir>/<name>` and return its path string.
    fn write_file(dir: &TempDir, name: &str, content: &str) -> String {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p.to_str().unwrap().to_string()
    }

    /// Write a SARIF `Value` to a temp file and return its path string.
    fn write_sarif(dir: &TempDir, name: &str, v: &Value) -> String {
        write_file(dir, name, &serde_json::to_string(v).unwrap())
    }

    #[test]
    fn merge_single_file_wraps_run() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({
            "runs": [{
                "tool": {"driver": {"name": "Semgrep"}},
                "results": [{
                    "ruleId": "r1",
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": 10}
                    }}]
                }]
            }]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);

        assert_eq!(merged["version"], "2.1.0");
        assert_eq!(merged["$schema"], "https://json.schemastore.org/sarif-2.1.0.json");
        let runs = merged["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["tool"]["driver"]["name"], "Semgrep");
        assert_eq!(runs[0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(runs[0]["results"][0]["ruleId"], "r1");
    }

    #[test]
    fn top_level_key_order_is_version_schema_runs() {
        // preserve_order is enabled -> object iteration is insertion order.
        let dir = TempDir::new().unwrap();
        let p = write_sarif(&dir, "in.sarif", &json!({"runs": []}));
        let merged = merge_sarif(&[p]);
        let keys: Vec<&String> = merged.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["version", "$schema", "runs"]);
    }

    #[test]
    fn dedup_same_key_latest_wins() {
        // Two results with identical (ruleId, uri, startLine, endLine, startCol,
        // fingerprint) collapse to one; the LATER one wins.
        let dir = TempDir::new().unwrap();
        let mk = |tag: &str| {
            json!({
                "ruleId": "r1",
                "tag": tag,
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 5}
                }}]
            })
        };
        let sarif = json!({
            "runs": [{
                "tool": {"driver": {"name": "Semgrep"}},
                "results": [mk("first"), mk("second")]
            }]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        let results = merged["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["tag"], "second");
    }

    #[test]
    fn distinct_by_column_and_endline_kept() {
        // Same rule + uri + startLine, but different startColumn / endLine ->
        // the extended key keeps both.
        let dir = TempDir::new().unwrap();
        let sarif = json!({
            "runs": [{
                "tool": {"driver": {"name": "Semgrep"}},
                "results": [
                    {"ruleId": "r1", "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": 5, "startColumn": 1}}}]},
                    {"ruleId": "r1", "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": 5, "startColumn": 9}}}]},
                    {"ruleId": "r1", "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": 5, "endLine": 7}}}]}
                ]
            }]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        assert_eq!(merged["runs"][0]["results"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn fingerprint_disambiguates_same_line() {
        // Same line/column but different partialFingerprints -> two findings.
        let dir = TempDir::new().unwrap();
        let sarif = json!({
            "runs": [{
                "tool": {"driver": {"name": "Semgrep"}},
                "results": [
                    {"ruleId": "r1", "partialFingerprints": {"primaryLocationLineHash": "aaa"},
                     "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.py"}, "region": {"startLine": 5}}}]},
                    {"ruleId": "r1", "partialFingerprints": {"primaryLocationLineHash": "bbb"},
                     "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.py"}, "region": {"startLine": 5}}}]}
                ]
            }]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        assert_eq!(merged["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn groups_by_tool_name_in_first_seen_order() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({
            "runs": [
                {"tool": {"driver": {"name": "Semgrep"}}, "results": []},
                {"tool": {"driver": {"name": "CodeQL"}}, "results": []},
                {"tool": {"driver": {"name": "Semgrep"}}, "results": [
                    {"ruleId": "x", "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "b.py"}, "region": {"startLine": 1}}}]}
                ]}
            ]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        let runs = merged["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0]["tool"]["driver"]["name"], "Semgrep");
        assert_eq!(runs[1]["tool"]["driver"]["name"], "CodeQL");
        // Semgrep's second run's result folded into the first Semgrep group.
        assert_eq!(runs[0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(runs[1]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn same_tool_unions_rules_later_wins_first_seen_order() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({
            "runs": [
                {"tool": {"driver": {"name": "Semgrep", "rules": [{"id": "r1"}]}},
                 "results": []},
                {"tool": {"driver": {"name": "Semgrep",
                    "rules": [{"id": "r2"}, {"id": "r1", "extra": true}]}},
                 "results": []}
            ]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        let runs = merged["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let rules = runs[0]["tool"]["driver"]["rules"].as_array().unwrap();
        // Order: r1 (first seen), then r2 (appended). r1 updated to run-2 version.
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "r1");
        assert_eq!(rules[0]["extra"], true);
        assert_eq!(rules[1]["id"], "r2");
        // Driver name preserved from the first run's tool block.
        assert_eq!(runs[0]["tool"]["driver"]["name"], "Semgrep");
    }

    #[test]
    fn rules_without_truthy_id_skipped() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({
            "runs": [{
                "tool": {"driver": {"name": "Semgrep",
                    "rules": [{"id": "keep"}, {"noid": 1}, {"id": ""}, "not-a-dict"]}},
                "results": []
            }]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        let rules = merged["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "keep");
    }

    #[test]
    fn uri_bases_merged_later_wins_invocations_appended() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({
            "runs": [
                {"tool": {"driver": {"name": "Semgrep"}},
                 "originalUriBaseIds": {"SRCROOT": {"uri": "file:///a"}},
                 "invocations": [{"exitCode": 0}],
                 "results": []},
                {"tool": {"driver": {"name": "Semgrep"}},
                 "originalUriBaseIds": {"SRCROOT": {"uri": "file:///b"}, "OTHER": {"uri": "file:///c"}},
                 "invocations": [{"exitCode": 1}],
                 "results": []}
            ]
        });
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        let run = &merged["runs"][0];
        // Later run wins for the shared base id; OTHER added.
        assert_eq!(run["originalUriBaseIds"]["SRCROOT"]["uri"], "file:///b");
        assert_eq!(run["originalUriBaseIds"]["OTHER"]["uri"], "file:///c");
        // Both invocations preserved, in order.
        let invs = run["invocations"].as_array().unwrap();
        assert_eq!(invs.len(), 2);
        assert_eq!(invs[0]["exitCode"], 0);
        assert_eq!(invs[1]["exitCode"], 1);
    }

    #[test]
    fn empty_uri_bases_and_invocations_keys_omitted() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({"runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": []}]});
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        let run = merged["runs"][0].as_object().unwrap();
        assert!(!run.contains_key("originalUriBaseIds"));
        assert!(!run.contains_key("invocations"));
        assert!(run.contains_key("tool"));
        assert!(run.contains_key("results"));
        // Run key order: tool then results.
        let keys: Vec<&String> = run.keys().collect();
        assert_eq!(keys, vec!["tool", "results"]);
    }

    #[test]
    fn missing_empty_and_null_files_skipped() {
        let dir = TempDir::new().unwrap();
        let empty = write_file(&dir, "empty.sarif", "");
        let braces = write_file(&dir, "braces.sarif", "{}");
        let nullf = write_file(&dir, "null.sarif", "null");
        let no_runs = write_sarif(&dir, "noruns.sarif", &json!({"foo": 1}));
        let empty_runs = write_sarif(&dir, "emptyruns.sarif", &json!({"runs": []}));
        let missing = dir.path().join("does-not-exist.sarif").to_str().unwrap().to_string();
        let bad = write_file(&dir, "bad.sarif", "{not json");

        let merged = merge_sarif(&[empty, braces, nullf, no_runs, empty_runs, missing, bad]);
        assert_eq!(merged["runs"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn dedup_across_files_same_finding() {
        let dir = TempDir::new().unwrap();
        let one = json!({
            "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [
                {"ruleId": "r", "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "a.py"}, "region": {"startLine": 3}}}]}
            ]}]
        });
        let p1 = write_sarif(&dir, "a.sarif", &one);
        let p2 = write_sarif(&dir, "b.sarif", &one);
        let merged = merge_sarif(&[p1, p2]);
        let runs = merged["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn run_without_tool_grouped_under_unknown() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({"runs": [{"results": []}]});
        let p = write_sarif(&dir, "in.sarif", &sarif);
        let merged = merge_sarif(&[p]);
        let runs = merged["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        // Even a tool-less run emits tool.driver == {}.
        assert_eq!(runs[0]["tool"], json!({"driver": {}}));
    }

    #[test]
    fn no_input_paths_yields_empty_runs() {
        let merged = merge_sarif(&[]);
        assert_eq!(merged["runs"].as_array().unwrap().len(), 0);
        assert_eq!(merged["version"], "2.1.0");
    }

    #[test]
    fn merge_sarif_files_writes_ordered_json_with_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let sarif = json!({"runs": [
            {"tool": {"driver": {"name": "Semgrep"}}, "results": []},
            {"tool": {"driver": {"name": "CodeQL"}}, "results": []}
        ]});
        let inp = write_sarif(&dir, "in.sarif", &sarif);
        let out = dir.path().join("nested/out.sarif");
        let out_s = out.to_str().unwrap().to_string();

        merge_sarif_files(&out_s, &[inp]).unwrap();

        // File written (parent dir auto-created), ends with a single newline,
        // pretty-printed at indent=2.
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.ends_with("}\n"));
        assert!(text.contains("\n  \"version\": \"2.1.0\""));
        // Key order preserved on disk.
        let v_pos = text.find("\"version\"").unwrap();
        let s_pos = text.find("\"$schema\"").unwrap();
        let r_pos = text.find("\"runs\"").unwrap();
        assert!(v_pos < s_pos && s_pos < r_pos);

        // Round-trips to a two-run merge (Semgrep then CodeQL).
        let reparsed: Value = serde_json::from_str(&text).unwrap();
        let runs = reparsed["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0]["tool"]["driver"]["name"], "Semgrep");
        assert_eq!(runs[1]["tool"]["driver"]["name"], "CodeQL");
    }
}
