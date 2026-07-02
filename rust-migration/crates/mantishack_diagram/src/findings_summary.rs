//! Findings-summary pie charts — Rust port of `packages/diagram/findings_summary.py`.
//! Reuses the ported `get_display_status`/`title_case_type` + `sanitize`.

use mantishack_core_reporting::{get_display_status, title_case_type};
use serde_json::Value;

use crate::sanitize::sanitize;

/// Verdict display order + colour (`_VERDICT_ORDER`).
const VERDICT_ORDER: &[(&str, &str)] = &[
    ("Exploitable", "#dc2626"),
    ("Confirmed", "#f97316"),
    ("Confirmed (Constrained)", "#ca8a04"),
    ("Confirmed (Blocked)", "#d97706"),
    ("False Positive", "#94a3b8"),
    ("Ruled Out", "#64748b"),
    ("Unknown", "#cbd5e1"),
    ("Uncategorised", "#cbd5e1"),
];

/// Vulnerability-type slice colours (`_TYPE_COLOURS`).
const TYPE_COLOURS: &[&str] = &[
    "#dc2626", "#3b82f6", "#16a34a", "#ca8a04", "#8b5cf6", "#ec4899", "#06b6d4", "#f97316", "#6366f1", "#14b8a6",
];

/// Ordered counter: increment `key`, preserving first-seen order.
fn bump(counts: &mut Vec<(String, i64)>, key: String) {
    match counts.iter_mut().find(|(k, _)| *k == key) {
        Some(e) => e.1 += 1,
        None => counts.push((key, 1)),
    }
}

/// Pie chart of finding verdicts (`generate_verdict_pie`).
pub fn generate_verdict_pie(findings: &[Value]) -> String {
    let mut counts: Vec<(String, i64)> = Vec::new();
    for f in findings {
        bump(&mut counts, get_display_status(f));
    }

    let mut ordered: Vec<(String, i64, String)> = Vec::new();
    let mut consumed = vec![false; counts.len()];
    for (label, colour) in VERDICT_ORDER {
        if let Some(idx) = counts.iter().position(|(k, _)| k == label) {
            ordered.push((label.to_string(), counts[idx].1, colour.to_string()));
            consumed[idx] = true;
        }
    }
    // Remaining, insertion-ordered, stable-sorted by count descending.
    let mut remaining: Vec<(String, i64)> = counts.iter().enumerate().filter(|(i, _)| !consumed[*i]).map(|(_, e)| e.clone()).collect();
    remaining.sort_by(|a, b| b.1.cmp(&a.1));
    for (label, count) in remaining {
        ordered.push((label, count, "#cbd5e1".to_string()));
    }
    pie_with_colours("Finding Verdicts", &ordered)
}

/// Pie chart of vulnerability types (`generate_type_pie`).
pub fn generate_type_pie(findings: &[Value]) -> String {
    let mut counts: Vec<(String, i64)> = Vec::new();
    for f in findings {
        bump(&mut counts, title_case_type(f.get("vuln_type").and_then(Value::as_str).unwrap_or("")));
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1)); // -count, stable
    let ordered: Vec<(String, i64, String)> = counts.into_iter().enumerate()
        .map(|(i, (label, count))| (label, count, TYPE_COLOURS[i % TYPE_COLOURS.len()].to_string()))
        .collect();
    pie_with_colours("Vulnerability Types", &ordered)
}

fn pie_with_colours(title: &str, slices: &[(String, i64, String)]) -> String {
    if slices.is_empty() {
        return format!("pie title {title}\n    \"No findings\" : 1");
    }
    let theme_vars = slices.iter().enumerate()
        .map(|(i, (_, _, colour))| format!("'pie{}': '{}'", i + 1, colour))
        .collect::<Vec<_>>()
        .join(", ");
    let mut lines = vec![
        format!("%%{{init: {{'theme': 'base', 'themeVariables': {{{theme_vars}}}}}}}%%"),
        format!("pie title {title}"),
    ];
    for (label, count, _) in slices {
        lines.push(format!("    \"{}\" : {count}", sanitize(label, None)));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verdict_pie() {
        let findings = vec![
            json!({"final_status": "exploitable", "vuln_type": "buffer_overflow"}),
            json!({"final_status": "exploitable", "vuln_type": "xss"}),
            json!({"status": "ruled_out", "vuln_type": "buffer_overflow"}),
            json!({"status": "weird_new", "vuln_type": "buffer_overflow"}),
        ];
        let expected = "%%{init: {'theme': 'base', 'themeVariables': {'pie1': '#dc2626', 'pie2': '#64748b', 'pie3': '#cbd5e1'}}}%%\npie title Finding Verdicts\n    \"Exploitable\" : 2\n    \"Ruled Out\" : 1\n    \"Weird New\" : 1";
        assert_eq!(generate_verdict_pie(&findings), expected);
    }

    #[test]
    fn type_pie_and_empty() {
        let findings = vec![
            json!({"vuln_type": "buffer_overflow"}), json!({"vuln_type": "xss"}),
            json!({"vuln_type": "buffer_overflow"}), json!({"vuln_type": "buffer_overflow"}),
        ];
        let expected = "%%{init: {'theme': 'base', 'themeVariables': {'pie1': '#dc2626', 'pie2': '#3b82f6'}}}%%\npie title Vulnerability Types\n    \"Buffer Overflow\" : 3\n    \"Cross-Site Scripting\" : 1";
        assert_eq!(generate_type_pie(&findings), expected);
        assert_eq!(generate_verdict_pie(&[]), "pie title Finding Verdicts\n    \"No findings\" : 1");
    }
}
