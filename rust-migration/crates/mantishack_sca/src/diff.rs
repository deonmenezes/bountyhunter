//! Findings-diff between two runs — Rust port of the pure core of
//! `packages/sca/diff.py`. The CLI, file loading, and markdown/PR-comment
//! rendering stay Python; `compute_delta` + `canonical_key` + the sort port here.

use std::collections::HashMap;

use serde_json::Value;

use crate::findings::severity_rank;

/// The four+1 mutually-exclusive delta buckets (`DeltaResult`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeltaResult {
    pub new: Vec<Value>,
    pub resolved: Vec<Value>,
    pub suppression_added: Vec<Value>,
    pub suppression_lifted: Vec<Value>,
    pub persistent: Vec<Value>,
}

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

const EMPTY: Value = Value::Null;

fn str_or_empty(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// Identity for cross-run comparison (`_canonical_key`); `None` for rows without
/// a recognised vuln_type.
pub fn canonical_key(row: &Value) -> Option<Vec<String>> {
    let vuln_type = row.get("vuln_type").and_then(Value::as_str).unwrap_or("");
    let sca = row.get("sca").filter(|v| v.is_object());
    let eco = sca.and_then(|s| s.get("ecosystem")).map(str_or_empty).unwrap_or("").to_string();
    let name = sca.and_then(|s| s.get("name")).map(str_or_empty).unwrap_or("").to_string();

    if vuln_type == "sca:vulnerable_dependency" {
        let adv = sca.and_then(|s| s.get("advisory")).filter(|v| v.is_object());
        let cve = adv
            .and_then(|a| a.get("aliases"))
            .and_then(Value::as_array)
            .and_then(|arr| arr.iter().filter_map(Value::as_str).find(|a| a.to_uppercase().starts_with("CVE-")));
        let adv_key = match cve {
            Some(c) => c.to_uppercase(),
            None => adv.and_then(|a| a.get("id")).and_then(Value::as_str).unwrap_or("").to_string(),
        };
        if adv_key.is_empty() {
            return None;
        }
        return Some(vec!["vuln".into(), eco, name, adv_key]);
    }
    if vuln_type.starts_with("sca:hygiene:") {
        return Some(vec!["hygiene".into(), vuln_type.into(), eco, name]);
    }
    if vuln_type.starts_with("sca:supply_chain:") {
        return Some(vec!["supply".into(), vuln_type.into(), eco, name]);
    }
    if vuln_type.starts_with("sca:license:") {
        return Some(vec!["license".into(), vuln_type.into(), eco, name]);
    }
    None
}

/// `{canonical_key: row}` (first-wins), keeping insertion order in `.0`
/// (`_index_by_canonical_key`).
fn index_by_canonical_key(rows: &[Value]) -> (Vec<(Vec<String>, Value)>, HashMap<Vec<String>, usize>) {
    let mut ordered: Vec<(Vec<String>, Value)> = Vec::new();
    let mut map: HashMap<Vec<String>, usize> = HashMap::new();
    for row in rows {
        if !row.is_object() {
            continue;
        }
        let Some(key) = canonical_key(row) else { continue };
        if !map.contains_key(&key) {
            map.insert(key.clone(), ordered.len());
            ordered.push((key, row.clone()));
        }
    }
    (ordered, map)
}

/// Sort by (severity desc, KEV first, EPSS desc, name asc) (`_sorted`).
fn sorted(mut rows: Vec<Value>) -> Vec<Value> {
    fn sca<'a>(r: &'a Value) -> &'a Value {
        r.get("sca").filter(|v| v.is_object()).unwrap_or(&EMPTY)
    }
    rows.sort_by(|a, b| {
        let neg_rank = |r: &Value| -severity_rank(r.get("severity").and_then(Value::as_str).unwrap_or("info"));
        let not_kev = |r: &Value| !sca(r).get("in_kev").map(json_truthy).unwrap_or(false);
        let neg_epss = |r: &Value| -sca(r).get("epss").and_then(Value::as_f64).unwrap_or(0.0);
        let name = |r: &Value| sca(r).get("name").and_then(Value::as_str).unwrap_or("").to_string();
        neg_rank(a)
            .cmp(&neg_rank(b))
            .then(not_kev(a).cmp(&not_kev(b)))
            .then(neg_epss(a).partial_cmp(&neg_epss(b)).unwrap_or(std::cmp::Ordering::Equal))
            .then(name(a).cmp(&name(b)))
    });
    rows
}

/// Set-difference between two findings runs (`compute_delta`).
pub fn compute_delta(rows_a: &[Value], rows_b: &[Value], include_suppressed: bool) -> DeltaResult {
    let (a_ord, a_map) = index_by_canonical_key(rows_a);
    let (b_ord, b_map) = index_by_canonical_key(rows_b);

    let suppressed = |row: &Value| row.get("suppressed").map(json_truthy).unwrap_or(false);

    let mut new = Vec::new();
    for (key, row) in &b_ord {
        if a_map.contains_key(key) {
            continue;
        }
        if suppressed(row) && !include_suppressed {
            continue;
        }
        new.push(row.clone());
    }

    let mut resolved = Vec::new();
    for (key, row) in &a_ord {
        if b_map.contains_key(key) {
            continue;
        }
        if suppressed(row) && !include_suppressed {
            continue;
        }
        resolved.push(row.clone());
    }

    let mut suppression_added = Vec::new();
    let mut suppression_lifted = Vec::new();
    let mut persistent = Vec::new();
    for (key, a_row) in &a_ord {
        let Some(&bi) = b_map.get(key) else { continue };
        let b_row = &b_ord[bi].1;
        let a_sup = suppressed(a_row);
        let b_sup = suppressed(b_row);
        if a_sup != b_sup {
            if b_sup {
                suppression_added.push(b_row.clone());
            } else {
                suppression_lifted.push(b_row.clone());
            }
            continue;
        }
        if a_sup && !include_suppressed {
            continue;
        }
        persistent.push(b_row.clone());
    }

    DeltaResult {
        new: sorted(new),
        resolved: sorted(resolved),
        suppression_added: sorted(suppression_added),
        suppression_lifted: sorted(suppression_lifted),
        persistent: sorted(persistent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vuln(name: &str, cve: &str, sev: &str, sup: bool, kev: bool, epss: f64) -> Value {
        json!({"vuln_type": "sca:vulnerable_dependency", "severity": sev, "suppressed": sup,
            "sca": {"ecosystem": "npm", "name": name, "in_kev": kev, "epss": epss,
                "advisory": {"aliases": [cve], "id": "OSV-x"}}})
    }
    fn hyg(name: &str) -> Value {
        json!({"vuln_type": "sca:hygiene:loose_pin", "severity": "low", "suppressed": false,
            "sca": {"ecosystem": "npm", "name": name}})
    }
    fn names(rows: &[Value]) -> Vec<String> {
        rows.iter().map(|r| r["sca"]["name"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn canonical_keys() {
        assert_eq!(canonical_key(&vuln("a", "CVE-2021-1", "high", false, false, 0.0)).unwrap(),
            vec!["vuln", "npm", "a", "CVE-2021-1"]);
        assert_eq!(canonical_key(&hyg("b")).unwrap(), vec!["hygiene", "sca:hygiene:loose_pin", "npm", "b"]);
        assert_eq!(canonical_key(&json!({"vuln_type": "other"})), None);
    }

    #[test]
    fn delta_buckets() {
        let a = [vuln("a", "CVE-1", "high", false, false, 0.0), vuln("b", "CVE-2", "high", false, false, 0.0), hyg("c")];
        let b = [vuln("b", "CVE-2", "high", false, false, 0.0), vuln("d", "CVE-4", "high", false, false, 0.0), hyg("c")];
        let d = compute_delta(&a, &b, false);
        assert_eq!(names(&d.new), vec!["d"]);
        assert_eq!(names(&d.resolved), vec!["a"]);
        assert_eq!(names(&d.persistent), vec!["b", "c"]);

        // Suppression flip.
        let d = compute_delta(&[vuln("x", "CVE-9", "high", false, false, 0.0)], &[vuln("x", "CVE-9", "high", true, false, 0.0)], false);
        assert_eq!(names(&d.suppression_added), vec!["x"]);
        assert!(d.suppression_lifted.is_empty());
        assert!(d.new.is_empty());
    }

    #[test]
    fn sort_order() {
        let rows = vec![
            vuln("z", "C1", "low", false, false, 0.0),
            vuln("a", "C2", "high", false, false, 0.0),
            vuln("m", "C3", "high", false, true, 0.0),
            vuln("b", "C4", "high", false, false, 0.9),
        ];
        assert_eq!(names(&sorted(rows)), vec!["m", "b", "a", "z"]);
    }
}
