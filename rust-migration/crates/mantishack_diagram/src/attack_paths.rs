//! Attack-paths Mermaid rendering — Rust port of the pure functions in
//! `packages/diagram/attack_paths.py`. `generate_from_file` (file read) stays
//! Python.

use serde_json::Value;

use crate::sanitize::sanitize;

fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
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

/// `path_data.get("proximity") or 0`, as a display Value.
fn proximity_or_zero(path_data: &Value) -> Value {
    match path_data.get("proximity") {
        Some(v) if truthy(v) => v.clone(),
        _ => Value::from(0),
    }
}

fn coerce_int(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0),
        Value::String(s) => s.trim().parse::<i64>().or_else(|_| s.trim().parse::<f64>().map(|f| f as i64)).unwrap_or(0),
        _ => 0,
    }
}

fn proximity_desc(score: i64) -> &'static str {
    match score {
        0 | 1 => "Theoretical only",
        2 | 3 => "Flow confirmed, blocked",
        4 | 5 => "Reachable, partial bypass",
        6 | 7 => "Exploit primitive confirmed",
        8 | 9 => "Working PoC",
        10 => "Reliable exploitation",
        _ => "Unknown",
    }
}

/// Mermaid for a single attack path (`generate_single`).
pub fn generate_single(path_data: &Value, path_index: usize) -> String {
    let path_id = path_data.get("id").map(py_str).unwrap_or_else(|| format!("PATH-{}", path_index + 1));
    let name = sanitize(&path_data.get("name").map(py_str).unwrap_or_else(|| path_id.clone()), None);
    let empty = Vec::new();
    let steps = path_data.get("steps").and_then(Value::as_array).unwrap_or(&empty);
    let proximity = proximity_or_zero(path_data);
    let prox_display = py_str(&proximity);
    let blockers = path_data.get("blockers").and_then(Value::as_array).unwrap_or(&empty);
    let status = path_data.get("status").and_then(Value::as_str).unwrap_or("uncertain");
    let prox_desc = proximity_desc(coerce_int(&proximity));

    let mut lines = vec!["flowchart TD".to_string()];
    let title_label = format!("{name}\\nProximity: {prox_display}/10,{prox_desc}\\nStatus: {status}");
    lines.push(format!("    TITLE_{path_index}[\"{}\"]", sanitize(&title_label, None)));
    lines.push(format!("    style TITLE_{path_index} fill:#f0f0f0,stroke:#999,font-weight:bold"));
    lines.push(String::new());

    let mut node_ids = vec![format!("TITLE_{path_index}")];
    for (i, step) in steps.iter().enumerate() {
        let nid = format!("P{path_index}S{}", i + 1);
        let label = if step.is_object() {
            let type_raw = match step.get("type") { Some(v) => py_str(v), None => "call".to_string() };
            let step_type = sanitize(&type_raw.to_uppercase(), None);
            let desc_raw = match step.get("description") {
                Some(v) => py_str(v),
                None => match step.get("action") { Some(v) => py_str(v), None => py_str(step) },
            };
            let desc = sanitize(&desc_raw, None);
            let loc_raw = match step.get("call_site").filter(|v| truthy(v)) {
                Some(v) => py_str(v),
                None => step.get("definition").filter(|v| truthy(v)).map(py_str).unwrap_or_default(),
            };
            let loc = sanitize(&loc_raw, None);
            let tainted_raw = match step.get("tainted_var") { Some(v) => py_str(v), None => String::new() };
            let tainted = sanitize(&tainted_raw, None);

            let mut parts = vec![format!("[{}] {step_type}", i + 1)];
            if !loc.is_empty() {
                parts.push(loc);
            }
            if !tainted.is_empty() {
                parts.push(format!("tainted: {tainted}"));
            }
            if !desc.is_empty() {
                let short = if desc.chars().count() <= 80 { desc } else { format!("{}...", desc.chars().take(77).collect::<String>()) };
                parts.push(short);
            }
            parts.join("\\n")
        } else {
            sanitize(&format!("[{}] {}", i + 1, py_str(step)), None)
        };
        lines.push(format!("    {nid}[\"{label}\"]"));
        node_ids.push(nid);
    }

    lines.push(String::new());
    for w in node_ids.windows(2) {
        lines.push(format!("    {} --> {}", w[0], w[1]));
    }

    if !blockers.is_empty() {
        lines.push(String::new());
        lines.push("    %% Blockers".to_string());
        for (j, blocker) in blockers.iter().enumerate() {
            let bid = format!("BLK{path_index}_{}", j + 1);
            let text_raw = if !blocker.is_object() {
                py_str(blocker)
            } else {
                match blocker.get("description") {
                    Some(v) => py_str(v),
                    None => match blocker.get("reason") { Some(v) => py_str(v), None => py_str(blocker) },
                }
            };
            let blocker_text = sanitize(&text_raw, None);
            lines.push(format!("    {bid}[/\"Blocker: {blocker_text}\"\\]"));
            lines.push(format!("    style {bid} fill:#fee2e2,stroke:#dc2626,color:#7f1d1d"));
            if let Some(last) = node_ids.last() {
                lines.push(format!("    {last} -. \"blocked\" .-> {bid}"));
            }
        }
    }
    lines.join("\n")
}

/// One Mermaid diagram per path, combined into markdown (`generate`).
pub fn generate(data: &[Value]) -> String {
    if data.is_empty() {
        return "```mermaid\nflowchart TD\n    EMPTY[\"No attack paths\"]\n```".to_string();
    }
    let mut sections: Vec<String> = Vec::new();
    for (i, path_data) in data.iter().enumerate() {
        let path_id = path_data.get("id").map(py_str).unwrap_or_else(|| format!("PATH-{}", i + 1));
        let name = path_data.get("name").map(py_str).unwrap_or_else(|| path_id.clone());
        let proximity = py_str(&proximity_or_zero(path_data));
        let status = path_data.get("status").and_then(Value::as_str).unwrap_or("uncertain");
        sections.push(format!("#### {path_id}: {name} (Proximity {proximity}/10, {status})\n"));
        sections.push("```mermaid".to_string());
        sections.push(generate_single(path_data, i));
        sections.push("```\n".to_string());
    }
    sections.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({"id": "AP-1", "name": "main path", "proximity": 7, "status": "confirmed",
            "steps": [{"type": "source", "description": "user input", "call_site": "a.c:10", "tainted_var": "buf"}, "raw step"],
            "blockers": [{"description": "canary"}, "NX"]})
    }

    #[test]
    fn single_path() {
        let expected = "flowchart TD\n    TITLE_0[\"main path\\nProximity: 7/10,Exploit primitive confirmed\\nStatus: confirmed\"]\n    style TITLE_0 fill:#f0f0f0,stroke:#999,font-weight:bold\n\n    P0S1[\"[1] SOURCE\\na.c:10\\ntainted: buf\\nuser input\"]\n    P0S2[\"[2] raw step\"]\n\n    TITLE_0 --> P0S1\n    P0S1 --> P0S2\n\n    %% Blockers\n    BLK0_1[/\"Blocker: canary\"\\]\n    style BLK0_1 fill:#fee2e2,stroke:#dc2626,color:#7f1d1d\n    P0S2 -. \"blocked\" .-> BLK0_1\n    BLK0_2[/\"Blocker: NX\"\\]\n    style BLK0_2 fill:#fee2e2,stroke:#dc2626,color:#7f1d1d\n    P0S2 -. \"blocked\" .-> BLK0_2";
        assert_eq!(generate_single(&sample(), 0), expected);
    }

    #[test]
    fn generate_wraps_and_empty() {
        let g = generate(&[sample()]);
        assert!(g.starts_with("#### AP-1: main path (Proximity 7/10, confirmed)\n\n```mermaid\nflowchart TD"));
        assert!(g.ends_with("```\n"));
        assert_eq!(generate(&[]), "```mermaid\nflowchart TD\n    EMPTY[\"No attack paths\"]\n```");
    }
}
