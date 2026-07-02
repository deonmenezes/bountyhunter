//! Attack-tree Mermaid rendering — Rust port of the pure helpers in
//! `packages/diagram/attack_tree.py`. The full `generate` renderer + subgraph
//! grouping + file I/O are a follow-up; the index builders and node
//! label/shape helpers port here.

use std::collections::HashMap;

use serde_json::Value;

use crate::sanitize::sanitize;

/// `_PROXIMITY_LABEL` range table.
fn proximity_desc(score: i64) -> &'static str {
    match score {
        0 | 1 => "theoretical",
        2 | 3 => "flow confirmed, blocked",
        4 | 5 => "partial bypass",
        6 | 7 => "primitive confirmed",
        8 | 9 => "working PoC",
        10 => "reliable",
        _ => "",
    }
}

fn str_of(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// `finding_id -> best proximity score` (`_build_proximity_index`).
pub fn build_proximity_index(attack_paths: &[Value]) -> HashMap<String, i64> {
    let mut index: HashMap<String, i64> = HashMap::new();
    for path in attack_paths {
        let fid = path.get("finding").and_then(Value::as_str).filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| str_of(path, "finding_id"));
        // int(score) with TypeError/ValueError -> 0.
        let score = match path.get("proximity") {
            Some(Value::Number(n)) => n.as_i64().unwrap_or_else(|| n.as_f64().map(|f| f as i64).unwrap_or(0)),
            Some(Value::String(s)) => s.trim().parse::<i64>().unwrap_or(0),
            _ => 0,
        };
        if !fid.is_empty() && score > *index.get(&fid).unwrap_or(&-1) {
            index.insert(fid, score);
        }
    }
    index
}

/// `finding_id -> why_wrong` (first entry wins) (`_build_disproven_index`).
pub fn build_disproven_index(disproven_list: &[Value]) -> HashMap<String, String> {
    let mut index: HashMap<String, String> = HashMap::new();
    for entry in disproven_list {
        let fid = str_of(entry, "finding");
        let reason = entry.get("why_wrong").and_then(Value::as_str)
            .or_else(|| entry.get("lesson").and_then(Value::as_str))
            .unwrap_or("").to_string();
        if !fid.is_empty() && !index.contains_key(&fid) && !reason.is_empty() {
            index.insert(fid, reason);
        }
    }
    index
}

/// `finding_id -> "status: claim"` (`_build_hypothesis_index`).
pub fn build_hypothesis_index(hypotheses: &[Value]) -> HashMap<String, String> {
    let mut index: HashMap<String, String> = HashMap::new();
    for h in hypotheses {
        let fid = h.get("finding").and_then(Value::as_str).filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| str_of(h, "finding_id"));
        let status = sanitize(&str_of(h, "status"), None);
        let claim = h.get("claim").and_then(Value::as_str)
            .or_else(|| h.get("hypothesis").and_then(Value::as_str))
            .unwrap_or("");
        if !fid.is_empty() && !index.contains_key(&fid) {
            let value = if !claim.is_empty() {
                let claim_head: String = claim.chars().take(60).collect();
                format!("{status}: {}", sanitize(&claim_head, None))
            } else {
                status
            };
            index.insert(fid, value);
        }
    }
    index
}

/// Node label with proximity / ruled-out annotations (`_node_label`).
pub fn node_label(node: &Value, proximity_idx: &HashMap<String, i64>, disproven_idx: &HashMap<String, String>) -> String {
    let nid = node.get("id").and_then(Value::as_str).unwrap_or("?");
    let goal_raw = node.get("goal").and_then(Value::as_str)
        .or_else(|| node.get("technique").and_then(Value::as_str))
        .unwrap_or(nid);
    let goal = sanitize(goal_raw, None);
    let technique = sanitize(&str_of(node, "technique"), None);
    let status = sanitize(node.get("status").and_then(Value::as_str).unwrap_or("unexplored"), None);

    let mut parts = vec![goal.clone()];
    if !technique.is_empty() && technique != goal {
        parts.push(technique);
    }
    if status == "confirmed" {
        if let Some(&score) = proximity_idx.get(nid) {
            let desc = proximity_desc(score);
            parts.push(if desc.is_empty() { format!("proximity {score}/10") } else { format!("proximity {score}/10,{desc}") });
        }
    }
    if status == "disproven" {
        if let Some(reason) = disproven_idx.get(nid) {
            let reason = sanitize(reason, None);
            let short = if reason.chars().count() <= 60 { reason } else { format!("{}...", reason.chars().take(57).collect::<String>()) };
            parts.push(format!("ruled out: {short}"));
        }
    }
    parts.push(format!("[{status}]"));
    parts.join("\\n")
}

/// Open/close bracket pair for a node status (`_node_shape`).
pub fn node_shape(status: &str) -> (&'static str, &'static str) {
    match status {
        "confirmed" | "disproven" => ("[\"", "\"]"),
        "exploring" | "uncertain" => ("{\"", "\"}"),
        _ => ("(\"", "\")"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proximity_and_indexes() {
        assert_eq!(proximity_desc(0), "theoretical");
        assert_eq!(proximity_desc(7), "primitive confirmed");
        assert_eq!(proximity_desc(10), "reliable");
        assert_eq!(proximity_desc(11), "");

        let paths = vec![
            json!({"finding": "F1", "proximity": 3}),
            json!({"finding": "F1", "proximity": "7"}),
            json!({"finding_id": "F2", "proximity": 5}),
        ];
        let idx = build_proximity_index(&paths);
        assert_eq!(idx.get("F1"), Some(&7)); // best wins
        assert_eq!(idx.get("F2"), Some(&5));

        let dis = build_disproven_index(&[json!({"finding": "F1", "why_wrong": "bad"}), json!({"finding": "F1", "why_wrong": "second"})]);
        assert_eq!(dis.get("F1").unwrap(), "bad"); // first wins
    }

    #[test]
    fn labels_and_shapes() {
        let mut prox = HashMap::new();
        prox.insert("N1".to_string(), 8);
        let n = json!({"id": "N1", "goal": "own the box", "technique": "rop", "status": "confirmed"});
        assert_eq!(node_label(&n, &prox, &HashMap::new()), "own the box\\nrop\\nproximity 8/10,working PoC\\n[confirmed]");

        let mut dis = HashMap::new();
        dis.insert("N2".to_string(), "sanitizer blocks it".to_string());
        let n2 = json!({"id": "N2", "goal": "xss", "status": "disproven"});
        assert_eq!(node_label(&n2, &HashMap::new(), &dis), "xss\\nruled out: sanitizer blocks it\\n[disproven]");

        assert_eq!(node_shape("confirmed"), ("[\"", "\"]"));
        assert_eq!(node_shape("exploring"), ("{\"", "\"}"));
        assert_eq!(node_shape("unexplored"), ("(\"", "\")"));
    }
}
