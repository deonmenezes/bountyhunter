//! SARIF codeFlow → dataflow-path extraction — Rust port of
//! `extract_dataflow_path` / `_path_from_locations` in `core/sarif/parser.py`.
//!
//! Message/snippet text is passed through `escape_nonprintable` (scanner text is
//! attacker-influenced). Python wraps the whole walk in `try/except` and returns
//! `None` on any error; malformed shapes (a `.get` on a non-dict) map to `Err`
//! here, which `extract_dataflow_path` converts to `None`.

use mantishack_core_security::log_sanitisation::escape_nonprintable;
use serde_json::{json, Map, Value};

/// Python truthiness for a JSON value.
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

/// `parent.get(key, default)` — errors when `parent` isn't a dict (Python would
/// raise `AttributeError`, aborting the extraction).
fn dict_get<'a>(parent: &'a Value, key: &str, default: &'a Value) -> Result<&'a Value, ()> {
    match parent {
        Value::Object(o) => Ok(o.get(key).unwrap_or(default)),
        _ => Err(()),
    }
}

/// `parent.get(key) or []` — a list value (empty or not), `[]` for falsy, and
/// `Err` for a truthy non-list (Python iterates it and fails downstream).
fn get_list(parent: &Value, key: &str) -> Result<Vec<Value>, ()> {
    let Value::Object(o) = parent else { return Err(()) };
    match o.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(v) if !json_truthy(v) => Ok(Vec::new()),
        Some(_) => Err(()),
    }
}

/// Resolve a `.get("text", "") or ""` result to a string, or `Err` for a
/// truthy non-string (Python's `escape_nonprintable` would then raise).
fn text_or_empty(v: &Value) -> Result<String, ()> {
    match v {
        Value::String(s) => Ok(s.clone()),
        v if !json_truthy(v) => Ok(String::new()),
        _ => Err(()),
    }
}

fn path_from_locations(locations: &[Value]) -> Result<Option<Value>, ()> {
    if locations.len() < 2 {
        return Ok(None);
    }
    let empty_obj = json!({});
    let empty_str = json!("");
    let zero = json!(0);

    let mut source = Value::Null;
    let mut sink = Value::Null;
    let mut steps: Vec<Value> = Vec::new();
    let last = locations.len() - 1;

    for (idx, loc_wrapper) in locations.iter().enumerate() {
        let location = dict_get(loc_wrapper, "location", &empty_obj)?;
        let physical_loc = dict_get(location, "physicalLocation", &empty_obj)?;
        let artifact = dict_get(physical_loc, "artifactLocation", &empty_obj)?;
        let region = dict_get(physical_loc, "region", &empty_obj)?;

        let message_container = dict_get(location, "message", &empty_obj)?;
        let message = escape_nonprintable(&text_or_empty(dict_get(message_container, "text", &empty_str)?)?, false);
        let snippet_container = dict_get(region, "snippet", &empty_obj)?;
        let snippet = escape_nonprintable(&text_or_empty(dict_get(snippet_container, "text", &empty_str)?)?, false);

        let mut step = Map::new();
        step.insert("file".into(), dict_get(artifact, "uri", &empty_str)?.clone());
        step.insert("line".into(), dict_get(region, "startLine", &zero)?.clone());
        step.insert("column".into(), dict_get(region, "startColumn", &zero)?.clone());
        step.insert("label".into(), Value::String(message));
        step.insert("snippet".into(), Value::String(snippet));
        let step = Value::Object(step);

        if idx == 0 {
            source = step;
        } else if idx == last {
            sink = step;
        } else {
            steps.push(step);
        }
    }

    let mut path = Map::new();
    path.insert("source".into(), source);
    path.insert("sink".into(), sink);
    path.insert("steps".into(), Value::Array(steps));
    path.insert("total_steps".into(), json!(locations.len()));
    Ok(Some(Value::Object(path)))
}

/// Extract dataflow-path info from SARIF `codeFlows` (`extract_dataflow_path`).
/// Returns the first usable path with `alternative_paths` for every other valid
/// (codeFlow, threadFlow) path, or `None` when there is no 2+ location path (or
/// the input is malformed).
pub fn extract_dataflow_path(code_flows: &[Value]) -> Option<Value> {
    if code_flows.is_empty() {
        return None;
    }
    match build_paths(code_flows) {
        Ok(Some(v)) => Some(v),
        _ => None,
    }
}

fn build_paths(code_flows: &[Value]) -> Result<Option<Value>, ()> {
    let mut all_paths: Vec<Value> = Vec::new();
    for flow in code_flows {
        for tflow in get_list(flow, "threadFlows")? {
            let locations = get_list(&tflow, "locations")?;
            if let Some(p) = path_from_locations(&locations)? {
                all_paths.push(p);
            }
        }
    }
    if all_paths.is_empty() {
        return Ok(None);
    }
    let mut primary = all_paths[0].clone();
    let alternatives = Value::Array(all_paths[1..].to_vec());
    primary.as_object_mut().unwrap().insert("alternative_paths".into(), alternatives);
    Ok(Some(primary))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(uri: &str, line: i64, col: i64, msg: &str, snip: &str) -> Value {
        json!({"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
            "region": {"startLine": line, "startColumn": col, "snippet": {"text": snip}}},
            "message": {"text": msg}}})
    }

    #[test]
    fn three_step_path_with_escaping() {
        let cf = vec![json!({"threadFlows": [{"locations": [
            loc("a.py", 1, 2, "src\u{1b}x", "s0"),
            loc("b.py", 5, 1, "mid", "s1"),
            loc("c.py", 9, 3, "sink", "s2"),
        ]}]})];
        let got = extract_dataflow_path(&cf).unwrap();
        assert_eq!(got["source"], json!({"file": "a.py", "line": 1, "column": 2, "label": "src\\x1bx", "snippet": "s0"}));
        assert_eq!(got["sink"]["file"], json!("c.py"));
        assert_eq!(got["steps"].as_array().unwrap().len(), 1);
        assert_eq!(got["total_steps"], json!(3));
        assert_eq!(got["alternative_paths"], json!([]));
    }

    #[test]
    fn empty_and_single_location() {
        assert_eq!(extract_dataflow_path(&[]), None);
        let cf = vec![json!({"threadFlows": [{"locations": [loc("a.py", 1, 2, "only", "s")]}]})];
        assert_eq!(extract_dataflow_path(&cf), None);
    }

    #[test]
    fn multiple_flows_populate_alternatives() {
        let cf = vec![
            json!({"threadFlows": [{"locations": [loc("a", 1, 1, "s", "x"), loc("b", 2, 2, "t", "y")]}]}),
            json!({"threadFlows": [{"locations": [loc("c", 3, 3, "u", "z"), loc("d", 4, 4, "v", "w")]}]}),
        ];
        let got = extract_dataflow_path(&cf).unwrap();
        assert_eq!(got["source"]["file"], json!("a"));
        let alts = got["alternative_paths"].as_array().unwrap();
        assert_eq!(alts.len(), 1);
        assert_eq!(alts[0]["source"]["file"], json!("c"));
        // Alternative-path dicts don't carry their own alternative_paths key.
        assert!(alts[0].get("alternative_paths").is_none());
    }

    #[test]
    fn malformed_message_aborts_to_none() {
        // message: null -> Python None.get(...) raises -> extract returns None.
        let cf = vec![json!({"threadFlows": [{"locations": [
            {"location": {"message": null, "physicalLocation": {}}},
            {"location": {"message": {"text": "ok"}}},
        ]}]})];
        assert_eq!(extract_dataflow_path(&cf), None);
    }
}
