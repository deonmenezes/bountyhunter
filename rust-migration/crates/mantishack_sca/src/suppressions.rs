//! Finding-suppression matching — Rust port of the pure core of
//! `packages/sca/suppressions.py`. The YAML `load` and the `apply_to_findings`
//! object-view path stay Python; `SuppressionEntry` matching + `apply` (which
//! operates on findings.json row dicts) + `coerce_entry` port here. `today` is a
//! caller-supplied `(year, month, day)` so the check is deterministic.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// A calendar date as `(year, month, day)` — tuple ordering matches date order.
pub type Date = (i32, u32, u32);

/// One normalised suppression entry (`SuppressionEntry`).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SuppressionEntry {
    pub reason: String,
    pub expires: Option<Date>,
    pub finding_id: Option<String>,
    pub advisory_id: Option<String>,
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().filter(|s| !s.is_empty())
}

impl SuppressionEntry {
    /// `is_expired`: has an `expires` and `today` is strictly past it.
    pub fn is_expired(&self, today: Date) -> bool {
        matches!(self.expires, Some(e) if today > e)
    }

    /// True if a findings.json `row` matches this entry (`matches`).
    pub fn matches(&self, row: &Value) -> bool {
        if let Some(fid) = nonempty(&self.finding_id) {
            let by_finding_id = row.get("finding_id").and_then(Value::as_str) == Some(fid);
            let by_id = row.get("id").and_then(Value::as_str) == Some(fid);
            if !by_finding_id && !by_id {
                return false;
            }
        }
        let empty = Value::Object(Default::default());
        let sca = row.get("sca").filter(|v| v.is_object()).unwrap_or(&empty);
        if let Some(adv_id) = nonempty(&self.advisory_id) {
            let advisory = sca.get("advisory").filter(|v| v.is_object()).unwrap_or(&empty);
            let mut ids: Vec<&str> = Vec::new();
            if let Some(id) = advisory.get("id").and_then(Value::as_str) {
                ids.push(id);
            }
            if let Some(aliases) = advisory.get("aliases").and_then(Value::as_array) {
                ids.extend(aliases.iter().filter_map(Value::as_str));
            }
            if !ids.contains(&adv_id) {
                return false;
            }
        }
        if let Some(eco) = nonempty(&self.ecosystem) {
            if sca.get("ecosystem").and_then(Value::as_str) != Some(eco) {
                return false;
            }
        }
        if let Some(name) = nonempty(&self.name) {
            if sca.get("name").and_then(Value::as_str) != Some(name) {
                return false;
            }
        }
        if let Some(version) = nonempty(&self.version) {
            if sca.get("version").and_then(Value::as_str) != Some(version) {
                return false;
            }
        }
        // A key-less entry would match everything — reject defensively.
        nonempty(&self.finding_id).is_some()
            || nonempty(&self.advisory_id).is_some()
            || nonempty(&self.ecosystem).is_some()
            || nonempty(&self.name).is_some()
            || nonempty(&self.version).is_some()
    }
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

/// Mutate each row in-place, setting `suppressed`/`suppression_reason` when an
/// unexpired entry matches (`apply`). First-match-wins; already-suppressed rows
/// are left alone. Returns the number of rows affected.
pub fn apply(rows: &mut [Value], entries: &[SuppressionEntry], today: Date) -> usize {
    let mut n = 0;
    for row in rows.iter_mut() {
        if row.get("suppressed").map(json_truthy).unwrap_or(false) {
            continue;
        }
        let mut matched_reason: Option<String> = None;
        for entry in entries {
            if entry.is_expired(today) {
                continue;
            }
            if entry.matches(row) {
                matched_reason = Some(entry.reason.clone());
                break;
            }
        }
        if let Some(reason) = matched_reason {
            if let Some(obj) = row.as_object_mut() {
                obj.insert("suppressed".into(), Value::Bool(true));
                obj.insert("suppression_reason".into(), Value::String(reason.clone()));
                if let Some(sca) = obj.get_mut("sca").and_then(Value::as_object_mut) {
                    sca.insert("suppressed".into(), Value::Bool(true));
                    sca.insert("suppression_reason".into(), Value::String(reason));
                }
            }
            n += 1;
        }
    }
    n
}

/// `_str_or_none`: a stripped non-empty string, else `None`.
pub fn str_or_none(value: &Value) -> Option<String> {
    value.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn iso_date_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}").unwrap())
}

/// Parse an ISO `YYYY-MM-DD` prefix into a validated `Date` (like
/// `date.fromisoformat(s[:10])`); `None` if out of range.
fn parse_iso_date(s: &str) -> Option<Date> {
    let d = &s[..10];
    let mut parts = d.split('-');
    let y: i32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if (1..=12).contains(&m) && (1..=31).contains(&day) {
        Some((y, m, day))
    } else {
        None
    }
}

/// Parse a raw suppression item into an entry (`_coerce_entry`); `None` when it
/// lacks a reason or any match key.
pub fn coerce_entry(item: &Value) -> Option<SuppressionEntry> {
    let obj = item.as_object()?;
    let reason = obj.get("reason").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())?;

    let expires = match obj.get("expires") {
        Some(Value::String(s)) if iso_date_re().is_match(s) && s.len() >= 10 => parse_iso_date(s),
        _ => None,
    };

    let entry = SuppressionEntry {
        reason: reason.to_string(),
        expires,
        finding_id: str_or_none(obj.get("finding_id").unwrap_or(&Value::Null)),
        advisory_id: str_or_none(obj.get("advisory_id").unwrap_or(&Value::Null)),
        ecosystem: str_or_none(obj.get("ecosystem").unwrap_or(&Value::Null)),
        name: str_or_none(obj.get("name").unwrap_or(&Value::Null)),
        version: str_or_none(obj.get("version").unwrap_or(&Value::Null)),
    };
    // A match-key-less entry would suppress everything — skip (note: `version`
    // is intentionally NOT a sufficient key here, mirroring the Python guard).
    if entry.finding_id.is_none()
        && entry.advisory_id.is_none()
        && entry.ecosystem.is_none()
        && entry.name.is_none()
    {
        return None;
    }
    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn e(reason: &str) -> SuppressionEntry {
        SuppressionEntry { reason: reason.to_string(), ..Default::default() }
    }

    #[test]
    fn matching() {
        let row = json!({"finding_id": "F1", "sca": {"ecosystem": "npm", "name": "lodash", "version": "1.0",
            "advisory": {"id": "GHSA-x", "aliases": ["CVE-2021-1"]}}});
        assert!(SuppressionEntry { finding_id: Some("F1".into()), ..e("r") }.matches(&row));
        assert!(!SuppressionEntry { finding_id: Some("F2".into()), ..e("r") }.matches(&row));
        assert!(SuppressionEntry { advisory_id: Some("CVE-2021-1".into()), ..e("r") }.matches(&row));
        assert!(SuppressionEntry { advisory_id: Some("GHSA-x".into()), ..e("r") }.matches(&row));
        assert!(SuppressionEntry { ecosystem: Some("npm".into()), name: Some("lodash".into()), ..e("r") }.matches(&row));
        assert!(!SuppressionEntry { name: Some("lodash".into()), version: Some("9.9".into()), ..e("r") }.matches(&row));
        assert!(!e("r").matches(&row)); // no keys
        // finding_id falls back to the `id` field.
        assert!(SuppressionEntry { finding_id: Some("ID2".into()), ..e("r") }.matches(&json!({"id": "ID2", "sca": {}})));
    }

    #[test]
    fn expiry() {
        assert!(SuppressionEntry { expires: Some((2020, 1, 1)), finding_id: Some("F".into()), ..e("r") }.is_expired((2026, 1, 1)));
        assert!(!SuppressionEntry { expires: Some((2030, 1, 1)), finding_id: Some("F".into()), ..e("r") }.is_expired((2026, 1, 1)));
        assert!(!SuppressionEntry { finding_id: Some("F".into()), ..e("r") }.is_expired((2026, 1, 1)));
    }

    #[test]
    fn apply_mutates_and_counts() {
        let mut rows = vec![
            json!({"finding_id": "F1", "sca": {"ecosystem": "npm", "name": "lodash", "version": "1.0"}}),
            json!({"finding_id": "F2", "sca": {}}),
            json!({"finding_id": "F3", "suppressed": true, "sca": {}}),
        ];
        let n = apply(&mut rows, &[SuppressionEntry { finding_id: Some("F1".into()), ..e("because") }], (2026, 1, 1));
        assert_eq!(n, 1);
        assert_eq!(rows[0]["suppressed"], json!(true));
        assert_eq!(rows[0]["suppression_reason"], json!("because"));
        assert_eq!(rows[0]["sca"]["suppressed"], json!(true));
        assert_eq!(rows[0]["sca"]["suppression_reason"], json!("because"));
        assert!(rows[1].get("suppressed").is_none()); // unmatched untouched
    }

    #[test]
    fn coerce() {
        let ok = coerce_entry(&json!({"reason": " fix later ", "finding_id": "F1", "expires": "2026-12-31T00:00:00Z"})).unwrap();
        assert_eq!(ok.reason, "fix later");
        assert_eq!(ok.expires, Some((2026, 12, 31)));
        assert_eq!(ok.finding_id.as_deref(), Some("F1"));
        // No reason / no match keys -> None.
        assert!(coerce_entry(&json!({"finding_id": "F1"})).is_none());
        assert!(coerce_entry(&json!({"reason": "r"})).is_none());
        // Unparseable expires -> kept (has a name key), expires None.
        let bad = coerce_entry(&json!({"reason": "r", "name": "x", "expires": "nope"})).unwrap();
        assert_eq!(bad.expires, None);

        assert_eq!(str_or_none(&json!("  hi  ")).as_deref(), Some("hi"));
        assert_eq!(str_or_none(&json!("")), None);
        assert_eq!(str_or_none(&json!(null)), None);
        assert_eq!(str_or_none(&json!(5)), None);
    }
}
