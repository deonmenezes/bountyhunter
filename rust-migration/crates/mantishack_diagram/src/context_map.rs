//! Context-map Mermaid rendering — Rust port of the `generate` core of
//! `packages/diagram/context_map.py`. `generate_from_file` +
//! `generate_forward_reachable_blocks` are follow-ups.

use serde_json::{json, Value};

use crate::sanitize::{sanitize, sanitize_id};

fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `v.get(key)` stringified, or `default` when absent.
fn get_or(v: &Value, key: &str, default: &str) -> String {
    v.get(key).map(py_str).unwrap_or_else(|| default.to_string())
}

/// Truthy `or`-chain over string fields, falling back to `default`.
fn or_chain(v: &Value, keys: &[&str], default: &str) -> String {
    for k in keys {
        if let Some(val) = v.get(k).filter(|v| truthy(v)) {
            return py_str(val);
        }
    }
    default.to_string()
}

fn sid_of(v: &Value, key: &str, default: &str) -> String {
    sanitize_id(&get_or(v, key, default))
}

fn loc_str(file_ref: &str, line_ref: &str) -> String {
    if file_ref.is_empty() { String::new() } else { format!("{file_ref}:{line_ref}") }
}

/// Return a Mermaid flowchart from a context-map.json dict (`generate`).
pub fn generate(data: &Value) -> String {
    let mut lines = vec!["flowchart LR".to_string()];
    let empty: Vec<Value> = Vec::new();

    let mut entry_points: Vec<Value> = data.get("entry_points").and_then(Value::as_array).cloned().unwrap_or_default();
    let boundary_details = data.get("boundary_details").and_then(Value::as_array).unwrap_or(&empty);
    let mut sink_details: Vec<Value> = data.get("sink_details").and_then(Value::as_array).cloned().unwrap_or_default();
    let unchecked_flows = data.get("unchecked_flows").and_then(Value::as_array).unwrap_or(&empty);

    // Fallback: plain sources/sinks when detailed lists are absent.
    if entry_points.is_empty() {
        if let Some(sources) = data.get("sources").filter(|v| truthy(v)).and_then(Value::as_array) {
            entry_points = sources.iter().enumerate().map(|(i, s)| json!({
                "id": format!("EP-{:03}", i + 1),
                "type": s.get("type").map(py_str).unwrap_or_else(|| "source".to_string()),
                "path": or_chain(s, &["entry", "description", "name"], "unknown"),
                "file": "", "line": "",
            })).collect();
        }
    }
    if sink_details.is_empty() {
        if let Some(sinks) = data.get("sinks").filter(|v| truthy(v)).and_then(Value::as_array) {
            sink_details = sinks.iter().enumerate().map(|(i, s)| json!({
                "id": format!("SINK-{:03}", i + 1),
                "type": s.get("type").map(py_str).unwrap_or_else(|| "sink".to_string()),
                "operation": or_chain(s, &["location", "description", "name"], "unknown"),
                "file": "", "line": "",
            })).collect();
        }
    }

    if !entry_points.is_empty() {
        lines.push(String::new());
        lines.push("    %% Entry Points".to_string());
    }
    for ep in &entry_points {
        let ep_id = sid_of(ep, "id", "EP-?");
        let method = get_or(ep, "method", "");
        let path = or_chain(ep, &["path", "entry"], "?");
        let loc = loc_str(&get_or(ep, "file", ""), &get_or(ep, "line", ""));
        let auth = if ep.get("auth_required").map(truthy).unwrap_or(true) { "" } else { " [PUBLIC]" };
        let label = sanitize(format!("{method} {path}{auth}\\n{loc}").trim(), None);
        lines.push(format!("    {ep_id}[\"{label}\"]"));
    }

    if !boundary_details.is_empty() {
        lines.push(String::new());
        lines.push("    %% Trust Boundaries".to_string());
    }
    for tb in boundary_details {
        let tb_id = sid_of(tb, "id", "TB-?");
        let boundary = sanitize(&or_chain(tb, &["boundary", "type"], "?"), None);
        let loc = loc_str(&get_or(tb, "file", ""), &get_or(tb, "line", ""));
        let label = sanitize(format!("{boundary}\\n{loc}").trim(), None);
        lines.push(format!("    {tb_id}{{\"{label}\"}}"));
    }

    if !sink_details.is_empty() {
        lines.push(String::new());
        lines.push("    %% Sinks".to_string());
    }
    for sink in &sink_details {
        let sink_id = sid_of(sink, "id", "SINK-?");
        let op = or_chain(sink, &["operation", "type"], "?");
        let loc = loc_str(&get_or(sink, "file", ""), &get_or(sink, "line", ""));
        let label = sanitize(format!("{op}\\n{loc}").trim(), None);
        lines.push(format!("    {sink_id}[/\"{label}\"\\]"));
    }

    // EP -> TB (covers).
    lines.push(String::new());
    lines.push("    %% Flows".to_string());
    let sids_of = |v: &Value, key: &str| -> Vec<String> {
        v.get(key).and_then(Value::as_array).map(|a| a.iter().map(|e| sanitize_id(&py_str(e))).collect()).unwrap_or_default()
    };
    for tb in boundary_details {
        let tb_id = sid_of(tb, "id", "TB-?");
        for ep_id in sids_of(tb, "covers") {
            lines.push(format!("    {ep_id} --> {tb_id}"));
        }
    }

    // TB -> SINK (reaches_from), routed through the covering TB when present.
    for sink in &sink_details {
        let sink_id = sid_of(sink, "id", "SINK-?");
        for ep_id in sids_of(sink, "reaches_from") {
            let tb_for_ep: Vec<String> = boundary_details.iter()
                .filter(|tb| sids_of(tb, "covers").contains(&ep_id))
                .map(|tb| sanitize_id(&get_or(tb, "id", "None")))
                .collect();
            if !tb_for_ep.is_empty() {
                for tb_id in tb_for_ep {
                    lines.push(format!("    {tb_id} --> {sink_id}"));
                }
            } else {
                lines.push(format!("    {ep_id} --> {sink_id}"));
            }
        }
    }

    if !unchecked_flows.is_empty() {
        lines.push(String::new());
        lines.push("    %% Unchecked Flows (no trust boundary)".to_string());
    }
    for flow in unchecked_flows {
        let ep_id = sid_of(flow, "entry_point", "?");
        let sink_id = sid_of(flow, "sink", "?");
        let reason = sanitize(&get_or(flow, "missing_boundary", "no check"), None);
        lines.push(format!("    {ep_id} -. \"{reason}\" .-> {sink_id}"));
    }

    lines.push(String::new());
    lines.push("    classDef ep fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f".to_string());
    lines.push("    classDef tb fill:#fef9c3,stroke:#ca8a04,color:#713f12".to_string());
    lines.push("    classDef sink fill:#fee2e2,stroke:#dc2626,color:#7f1d1d".to_string());

    let join_ids = |items: &[Value]| items.iter().map(|v| sanitize_id(&get_or(v, "id", ""))).collect::<Vec<_>>().join(",");
    if !entry_points.is_empty() {
        lines.push(format!("    class {} ep", join_ids(&entry_points)));
    }
    if !boundary_details.is_empty() {
        lines.push(format!("    class {} tb", join_ids(boundary_details)));
    }
    if !sink_details.is_empty() {
        lines.push(format!("    class {} sink", join_ids(&sink_details)));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn full_context_map() {
        let data = json!({
            "entry_points": [
                {"id": "EP-001", "method": "POST", "path": "/login", "file": "a.py", "line": 10, "auth_required": false},
                {"id": "EP-002", "method": "GET", "path": "/pub", "auth_required": true},
            ],
            "boundary_details": [{"id": "TB-001", "boundary": "authz", "file": "b.py", "line": 5, "covers": ["EP-001"]}],
            "sink_details": [{"id": "SINK-001", "operation": "exec", "file": "c.py", "line": 3, "reaches_from": ["EP-001"]}],
            "unchecked_flows": [{"entry_point": "EP-002", "sink": "SINK-001", "missing_boundary": "no authz"}],
        });
        let expected = "flowchart LR\n\n    %% Entry Points\n    EP-001[\"POST /login [PUBLIC]\\na.py:10\"]\n    EP-002[\"GET /pub\\n\"]\n\n    %% Trust Boundaries\n    TB-001{\"authz\\nb.py:5\"}\n\n    %% Sinks\n    SINK-001[/\"exec\\nc.py:3\"\\]\n\n    %% Flows\n    EP-001 --> TB-001\n    TB-001 --> SINK-001\n\n    %% Unchecked Flows (no trust boundary)\n    EP-002 -. \"no authz\" .-> SINK-001\n\n    classDef ep fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f\n    classDef tb fill:#fef9c3,stroke:#ca8a04,color:#713f12\n    classDef sink fill:#fee2e2,stroke:#dc2626,color:#7f1d1d\n    class EP-001,EP-002 ep\n    class TB-001 tb\n    class SINK-001 sink";
        assert_eq!(generate(&data), expected);
    }

    #[test]
    fn sources_sinks_fallback() {
        let data = json!({"sources": [{"type": "http", "entry": "/x"}], "sinks": [{"type": "sql", "location": "q"}]});
        let expected = "flowchart LR\n\n    %% Entry Points\n    EP-001[\"/x\\n\"]\n\n    %% Sinks\n    SINK-001[/\"q\\n\"\\]\n\n    %% Flows\n\n    classDef ep fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f\n    classDef tb fill:#fef9c3,stroke:#ca8a04,color:#713f12\n    classDef sink fill:#fee2e2,stroke:#dc2626,color:#7f1d1d\n    class EP-001 ep\n    class SINK-001 sink";
        assert_eq!(generate(&data), expected);
    }
}
