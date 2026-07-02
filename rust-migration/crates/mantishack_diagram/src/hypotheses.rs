//! Hypothesis-tree Mermaid rendering — Rust port of the pure functions in
//! `packages/diagram/hypotheses.py`. `generate_from_file` (file read) stays Python.

use std::collections::HashMap;

use serde_json::Value;

use crate::sanitize::{sanitize, sanitize_id};

fn s(v: &Value, key: &str, default: &str) -> String {
    sanitize(v.get(key).and_then(Value::as_str).unwrap_or(default), None)
}

/// `hyp.get(a) or hyp.get(b, "")`, truthy-chained.
fn or_field(v: &Value, a: &str, b: &str) -> String {
    v.get(a).and_then(Value::as_str).filter(|s| !s.is_empty())
        .or_else(|| v.get(b).and_then(Value::as_str))
        .unwrap_or("")
        .to_string()
}

fn truncate(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        text
    } else {
        format!("{}...", text.chars().take(max - 3).collect::<String>())
    }
}

fn prediction_label(pred: &Value) -> String {
    let pid = s(pred, "id", "?");
    let prediction = sanitize(&or_field(pred, "prediction", "test"), None);
    let result = s(pred, "result", "");
    let status = s(pred, "status", "testing");
    let mut parts = vec![format!("{pid} [{status}]"), truncate(prediction, 70)];
    if !result.is_empty() {
        parts.push(truncate(result, 70));
    }
    parts.join("\\n")
}

fn hyp_label(hyp: &Value) -> String {
    let hid = s(hyp, "id", "?");
    let claim = sanitize(&or_field(hyp, "claim", "hypothesis"), None);
    let status = s(hyp, "status", "testing");
    let finding = sanitize(&or_field(hyp, "finding", "finding_id"), None);
    let mut head = hid;
    if !finding.is_empty() {
        head.push_str(&format!(" \u{2192} {finding}"));
    }
    head.push_str(&format!(" [{status}]"));
    let mut parts = vec![head];
    if !claim.is_empty() {
        parts.push(truncate(claim, 70));
    }
    parts.join("\\n")
}

fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

struct Builder {
    counter: i64,
    lines: Vec<String>,
    hyp_node_ids: HashMap<String, String>,
    pred_node_ids: Vec<(String, String, String)>,
}

impl Builder {
    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!("{prefix}{}", self.counter)
    }

    fn emit_hypothesis(&mut self, hyp: &Value, indent: &str) -> String {
        let hid = match hyp.get("id") {
            Some(v) => py_str(v),
            None => format!("H{}", self.counter),
        };
        let nid = self.next_id("HN");
        self.hyp_node_ids.insert(hid, nid.clone());
        let label = hyp_label(hyp);
        let status = s(hyp, "status", "testing");
        if status == "confirmed" || status == "disproven" {
            self.lines.push(format!("{indent}{nid}[\"{label}\"]"));
        } else {
            self.lines.push(format!("{indent}{nid}{{\"{label}\"}}"));
        }
        if let Some(preds) = hyp.get("predictions").and_then(Value::as_array) {
            for pred in preds {
                let pnid = self.next_id("PN");
                let plabel = prediction_label(pred);
                let pstatus = s(pred, "status", "testing");
                if pstatus == "confirmed" || pstatus == "disproven" {
                    self.lines.push(format!("{indent}{pnid}[\"{plabel}\"]"));
                } else {
                    self.lines.push(format!("{indent}{pnid}((\"{plabel}\"))"));
                }
                self.pred_node_ids.push((nid.clone(), pnid, pstatus));
            }
        }
        nid
    }
}

/// Render a hypothesis tree as a Mermaid flowchart (`generate`).
pub fn generate(hypotheses: &[Value]) -> String {
    if hypotheses.is_empty() {
        return "flowchart TD\n    EMPTY[\"No hypotheses\"]".to_string();
    }

    // Group by finding, preserving first-seen order.
    let mut by_finding: Vec<(String, Vec<Value>)> = Vec::new();
    let mut ungrouped: Vec<Value> = Vec::new();
    for h in hypotheses {
        let fid = or_field(h, "finding", "finding_id");
        if !fid.is_empty() {
            match by_finding.iter_mut().find(|(k, _)| *k == fid) {
                Some((_, v)) => v.push(h.clone()),
                None => by_finding.push((fid, vec![h.clone()])),
            }
        } else {
            ungrouped.push(h.clone());
        }
    }

    let mut b = Builder { counter: 0, lines: vec!["flowchart TD".to_string()], hyp_node_ids: HashMap::new(), pred_node_ids: Vec::new() };

    for (fid, hyps) in &by_finding {
        b.lines.push(format!("    subgraph {} [\"{}\"]", sanitize_id(fid), sanitize(fid, None)));
        for hyp in hyps {
            b.emit_hypothesis(hyp, "        ");
        }
        b.lines.push("    end".to_string());
    }
    for hyp in &ungrouped {
        b.emit_hypothesis(hyp, "    ");
    }

    b.lines.push(String::new());
    b.lines.push("    %% Prediction edges".to_string());
    for (hyp_nid, pred_nid, _) in &b.pred_node_ids {
        b.lines.push(format!("    {hyp_nid} --> {pred_nid}"));
    }

    // Style classes for hypotheses (original order).
    let (mut confirmed, mut disproven, mut testing): (Vec<String>, Vec<String>, Vec<String>) = (Vec::new(), Vec::new(), Vec::new());
    for hyp in hypotheses {
        let hid = hyp.get("id").map(py_str).unwrap_or_default();
        let Some(nid) = b.hyp_node_ids.get(&hid) else { continue };
        match s(hyp, "status", "testing").as_str() {
            "confirmed" => confirmed.push(nid.clone()),
            "disproven" => disproven.push(nid.clone()),
            _ => testing.push(nid.clone()),
        }
    }

    b.lines.push(String::new());
    b.lines.push("    classDef confirmed fill:#dcfce7,stroke:#16a34a,color:#14532d".to_string());
    b.lines.push("    classDef disproven fill:#f1f5f9,stroke:#94a3b8,color:#64748b".to_string());
    b.lines.push("    classDef testing fill:#fef9c3,stroke:#ca8a04,color:#713f12".to_string());
    b.lines.push("    classDef pred_confirmed fill:#bbf7d0,stroke:#16a34a,color:#14532d".to_string());
    b.lines.push("    classDef pred_disproven fill:#e2e8f0,stroke:#94a3b8,color:#475569".to_string());
    b.lines.push("    classDef pred_testing fill:#fefce8,stroke:#ca8a04,color:#713f12".to_string());

    if !confirmed.is_empty() {
        b.lines.push(format!("    class {} confirmed", confirmed.join(",")));
    }
    if !disproven.is_empty() {
        b.lines.push(format!("    class {} disproven", disproven.join(",")));
    }
    if !testing.is_empty() {
        b.lines.push(format!("    class {} testing", testing.join(",")));
    }

    // Prediction status classes (first-seen order).
    let mut pred_by_status: Vec<(String, Vec<String>)> = Vec::new();
    for (_, pred_nid, pstatus) in &b.pred_node_ids {
        let key = if matches!(pstatus.as_str(), "confirmed" | "disproven" | "testing") { format!("pred_{pstatus}") } else { "pred_testing".to_string() };
        match pred_by_status.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(pred_nid.clone()),
            None => pred_by_status.push((key, vec![pred_nid.clone()])),
        }
    }
    for (cls, ids) in &pred_by_status {
        b.lines.push(format!("    class {} {cls}", ids.join(",")));
    }

    b.lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hypothesis_tree() {
        let hyps = vec![
            json!({"id": "H1", "finding": "F1", "claim": "buf overflow", "status": "confirmed", "predictions": [{"id": "P1", "prediction": "crash on 100 bytes", "result": "crashed", "status": "confirmed"}]}),
            json!({"id": "H2", "finding": "F1", "hypothesis": "reachable", "status": "testing"}),
            json!({"id": "H3", "claim": "ungrouped one", "status": "disproven"}),
        ];
        let expected = "flowchart TD\n    subgraph F1 [\"F1\"]\n        HN1[\"H1 \u{2192} F1 [confirmed]\\nbuf overflow\"]\n        PN2[\"P1 [confirmed]\\ncrash on 100 bytes\\ncrashed\"]\n        HN3{\"H2 \u{2192} F1 [testing]\\nreachable\"}\n    end\n    HN4[\"H3 [disproven]\\nungrouped one\"]\n\n    %% Prediction edges\n    HN1 --> PN2\n\n    classDef confirmed fill:#dcfce7,stroke:#16a34a,color:#14532d\n    classDef disproven fill:#f1f5f9,stroke:#94a3b8,color:#64748b\n    classDef testing fill:#fef9c3,stroke:#ca8a04,color:#713f12\n    classDef pred_confirmed fill:#bbf7d0,stroke:#16a34a,color:#14532d\n    classDef pred_disproven fill:#e2e8f0,stroke:#94a3b8,color:#475569\n    classDef pred_testing fill:#fefce8,stroke:#ca8a04,color:#713f12\n    class HN1 confirmed\n    class HN4 disproven\n    class HN3 testing\n    class PN2 pred_confirmed";
        assert_eq!(generate(&hyps), expected);
        assert_eq!(generate(&[]), "flowchart TD\n    EMPTY[\"No hypotheses\"]");
    }
}
