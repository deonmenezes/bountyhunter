//! Attack-tree Mermaid rendering — Rust port of the pure helpers in
//! `packages/diagram/attack_tree.py`. The full `generate` renderer + subgraph
//! grouping + file I/O are a follow-up; the index builders and node
//! label/shape helpers port here.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::sanitize::{sanitize, sanitize_id};

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

fn children_of(node_map: &HashMap<String, Value>, nid: &str) -> Vec<String> {
    let raw = node_map.get(nid).and_then(|n| n.get("leads_to")).and_then(Value::as_str).unwrap_or("");
    raw.split(',').map(str::trim).filter(|t| !t.is_empty() && node_map.contains_key(*t)).map(str::to_string).collect()
}

fn descendants(node_map: &HashMap<String, Value>, nid: &str, seen: &mut HashSet<String>) -> Vec<String> {
    if seen.contains(nid) {
        return Vec::new();
    }
    seen.insert(nid.to_string());
    let mut result = Vec::new();
    for child in children_of(node_map, nid) {
        if seen.contains(&child) {
            continue;
        }
        result.push(child.clone());
        result.extend(descendants(node_map, &child, seen));
    }
    result
}

/// Group the tree into subgraphs by the root's children (`_find_subgraph_groups`);
/// `None` if too flat. Order follows the root's children.
fn find_subgraph_groups(nodes: &[Value], root_id: &str) -> Option<Vec<(String, Vec<String>)>> {
    let node_map: HashMap<String, Value> = nodes.iter()
        .filter_map(|n| n.get("id").and_then(Value::as_str).map(|id| (id.to_string(), n.clone())))
        .collect();
    if root_id.is_empty() || !node_map.contains_key(root_id) {
        return None;
    }
    let root_children = children_of(&node_map, root_id);
    let eligible = root_children.iter().filter(|c| !children_of(&node_map, c).is_empty()).count();
    if eligible < 2 {
        return None;
    }
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for child in &root_children {
        let mut seen = HashSet::new();
        groups.push((child.clone(), descendants(&node_map, child, &mut seen)));
    }
    (groups.len() >= 2).then_some(groups)
}

fn goal_or(node: &Value, fallback: &str) -> String {
    node.get("goal").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| fallback.to_string())
}

/// Render an attack-tree.json dict as a Mermaid flowchart (`generate`).
pub fn generate(data: &Value, attack_paths: &[Value], disproven: &[Value], hypotheses: &[Value]) -> String {
    let root_raw = data.get("root").map(py_str).unwrap_or_else(|| "ROOT".to_string());
    let root_id = sanitize_id(&root_raw);

    let raw_nodes = data.get("nodes").and_then(Value::as_array);
    if raw_nodes.map(|a| a.is_empty()).unwrap_or(true) {
        return "flowchart TD\n    EMPTY[\"No attack tree nodes\"]".to_string();
    }
    // Shallow-copy each node with a sanitized id.
    let nodes: Vec<Value> = raw_nodes.unwrap().iter().map(|n| {
        let mut m = n.as_object().cloned().unwrap_or_default();
        let id_raw = m.get("id").map(py_str).unwrap_or_else(|| "?".to_string());
        m.insert("id".to_string(), Value::String(sanitize_id(&id_raw)));
        Value::Object(m)
    }).collect();
    let node_map: HashMap<String, Value> = nodes.iter()
        .filter_map(|n| n.get("id").and_then(Value::as_str).map(|id| (id.to_string(), n.clone())))
        .collect();

    let proximity_idx = build_proximity_index(attack_paths);
    let disproven_idx = build_disproven_index(disproven);
    let hyp_idx = build_hypothesis_index(hypotheses);

    let mut lines = vec!["flowchart TD".to_string()];
    let nid_of = |n: &Value| n.get("id").and_then(Value::as_str).unwrap_or("?").to_string();
    let status_of = |n: &Value| n.get("status").and_then(Value::as_str).unwrap_or("unexplored").to_string();
    let emit_node = |lines: &mut Vec<String>, indent: &str, id: &str, n: &Value| {
        let (open, close) = node_shape(&status_of(n));
        lines.push(format!("{indent}{id}{open}{}{close}", node_label(n, &proximity_idx, &disproven_idx)));
    };

    match find_subgraph_groups(&nodes, &root_id) {
        Some(groups) => {
            if let Some(root_node) = node_map.get(&root_id) {
                emit_node(&mut lines, "    ", &root_id, root_node);
            }
            for (group_id, desc_ids) in &groups {
                let empty = Value::Object(Default::default());
                let group_node = node_map.get(group_id).unwrap_or(&empty);
                let group_goal = sanitize(&goal_or(group_node, group_id), None);
                let prox_suffix = proximity_idx.get(group_id).map(|s| format!(",proximity {s}/10")).unwrap_or_default();
                let hyp_suffix = hyp_idx.get(group_id).map(|h| format!(",{h}")).unwrap_or_default();
                lines.push(format!("    subgraph {group_id} [\"{group_goal}{prox_suffix}{hyp_suffix}\"]"));
                emit_node(&mut lines, "        ", group_id, group_node);
                for did in desc_ids {
                    if let Some(dn) = node_map.get(did) {
                        emit_node(&mut lines, "        ", did, dn);
                    }
                }
                lines.push("    end".to_string());
            }
            for (group_id, _) in &groups {
                lines.push(format!("    {root_id} --> {group_id}"));
            }
            lines.push(String::new());
            lines.push("    %% Edges".to_string());
            let mut all_ids: HashSet<String> = [root_id.clone()].into_iter().collect();
            for (gid, ds) in &groups {
                all_ids.insert(gid.clone());
                all_ids.extend(ds.iter().cloned());
            }
            for node in &nodes {
                let nid = nid_of(node);
                if !all_ids.contains(&nid) {
                    continue;
                }
                let leads = node.get("leads_to").and_then(Value::as_str).unwrap_or("");
                for t in leads.split(',').map(str::trim).filter(|t| !t.is_empty()).map(sanitize_id).filter(|t| node_map.contains_key(t)) {
                    if t != root_id {
                        lines.push(format!("    {nid} --> {t}"));
                    }
                }
            }
        }
        None => {
            lines.push(String::new());
            lines.push("    %% Nodes".to_string());
            for node in &nodes {
                emit_node(&mut lines, "    ", &nid_of(node), node);
            }
            lines.push(String::new());
            lines.push("    %% Edges".to_string());
            for node in &nodes {
                let nid = nid_of(node);
                let leads = node.get("leads_to").and_then(Value::as_str).unwrap_or("");
                for t in leads.split(',').map(str::trim).filter(|t| !t.is_empty()).map(sanitize_id).filter(|t| node_map.contains_key(t)) {
                    lines.push(format!("    {nid} --> {t}"));
                }
            }
        }
    }

    // Style classes (insertion-ordered by sanitized status).
    let mut status_groups: Vec<(String, Vec<String>)> = Vec::new();
    for node in &nodes {
        let s = sanitize(&status_of(node), None);
        match status_groups.iter_mut().find(|(k, _)| *k == s) {
            Some((_, v)) => v.push(nid_of(node)),
            None => status_groups.push((s, vec![nid_of(node)])),
        }
    }
    lines.push(String::new());
    lines.push("    classDef confirmed fill:#dcfce7,stroke:#16a34a,color:#14532d".to_string());
    lines.push("    classDef disproven fill:#f1f5f9,stroke:#94a3b8,color:#64748b".to_string());
    lines.push("    classDef exploring fill:#fef9c3,stroke:#ca8a04,color:#713f12".to_string());
    lines.push("    classDef uncertain fill:#fef3c7,stroke:#d97706,color:#78350f".to_string());
    lines.push("    classDef unexplored fill:#f8fafc,stroke:#cbd5e1,color:#334155".to_string());
    for (status, ids) in &status_groups {
        let cls = if matches!(status.as_str(), "confirmed" | "disproven" | "exploring" | "uncertain" | "unexplored") { status.as_str() } else { "unexplored" };
        lines.push(format!("    class {} {cls}", ids.join(",")));
    }
    if node_map.contains_key(&root_id) {
        lines.push(format!("    style {root_id} stroke-width:3px"));
    }
    lines.join("\n")
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

    #[test]
    fn generate_empty_and_flat() {
        assert_eq!(generate(&json!({"nodes": []}), &[], &[], &[]), "flowchart TD\n    EMPTY[\"No attack tree nodes\"]");

        let data = json!({"root": "R", "nodes": [
            {"id": "R", "goal": "own", "status": "confirmed", "leads_to": "A,B"},
            {"id": "A", "goal": "leak", "status": "exploring"},
            {"id": "B", "goal": "write", "status": "unexplored"},
        ]});
        let expected = "flowchart TD\n\n    %% Nodes\n    R[\"own\\n[confirmed]\"]\n    A{\"leak\\n[exploring]\"}\n    B(\"write\\n[unexplored]\")\n\n    %% Edges\n    R --> A\n    R --> B\n\n    classDef confirmed fill:#dcfce7,stroke:#16a34a,color:#14532d\n    classDef disproven fill:#f1f5f9,stroke:#94a3b8,color:#64748b\n    classDef exploring fill:#fef9c3,stroke:#ca8a04,color:#713f12\n    classDef uncertain fill:#fef3c7,stroke:#d97706,color:#78350f\n    classDef unexplored fill:#f8fafc,stroke:#cbd5e1,color:#334155\n    class R confirmed\n    class A exploring\n    class B unexplored\n    style R stroke-width:3px";
        assert_eq!(generate(&data, &[], &[], &[]), expected);
    }

    #[test]
    fn generate_subgraph() {
        let data = json!({"root": "R", "nodes": [
            {"id": "R", "goal": "root", "status": "confirmed", "leads_to": "C1,C2"},
            {"id": "C1", "goal": "branch1", "status": "exploring", "leads_to": "G1"},
            {"id": "C2", "goal": "branch2", "status": "exploring", "leads_to": "G2"},
            {"id": "G1", "goal": "leaf1", "status": "unexplored"},
            {"id": "G2", "goal": "leaf2", "status": "unexplored"},
        ]});
        let expected = "flowchart TD\n    R[\"root\\n[confirmed]\"]\n    subgraph C1 [\"branch1,proximity 6/10\"]\n        C1{\"branch1\\n[exploring]\"}\n        G1(\"leaf1\\n[unexplored]\")\n    end\n    subgraph C2 [\"branch2\"]\n        C2{\"branch2\\n[exploring]\"}\n        G2(\"leaf2\\n[unexplored]\")\n    end\n    R --> C1\n    R --> C2\n\n    %% Edges\n    R --> C1\n    R --> C2\n    C1 --> G1\n    C2 --> G2\n\n    classDef confirmed fill:#dcfce7,stroke:#16a34a,color:#14532d\n    classDef disproven fill:#f1f5f9,stroke:#94a3b8,color:#64748b\n    classDef exploring fill:#fef9c3,stroke:#ca8a04,color:#713f12\n    classDef uncertain fill:#fef3c7,stroke:#d97706,color:#78350f\n    classDef unexplored fill:#f8fafc,stroke:#cbd5e1,color:#334155\n    class R confirmed\n    class C1,C2 exploring\n    class G1,G2 unexplored\n    style R stroke-width:3px";
        assert_eq!(generate(&data, &[json!({"finding": "C1", "proximity": 6})], &[], &[]), expected);
    }
}
