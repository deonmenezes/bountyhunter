//! OSV record parsing — Rust port of `packages/osv/types.py` + `parser.py`.
//!
//! `parse_record` parses one OSV vulnerability record (references, affected
//! packages + version ranges with event reordering, severity, timestamps) into
//! a structured `OsvRecord`. The `OsvClient` HTTP transport + `JsonCache` stay
//! in Python; this crate is network/IO-free and parses `serde_json::Value`.

use chrono::{DateTime, Utc};
use mantishack_core_url_patterns::{
    extract_github_slug, github_commit_url_re, kernel_sha_url_re, normalize_slug, LINUX_UPSTREAM_SLUG,
};
use serde_json::{json, Map, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvReference {
    pub url: String,
    pub ty: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvRange {
    pub ty: String,
    pub repo: Option<String>,
    pub events: Vec<Map<String, Value>>, // raw event dicts (string values)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvAffected {
    pub package: Option<Map<String, Value>>,
    pub ranges: Vec<OsvRange>,
    pub versions: Vec<String>,
    pub ecosystem_specific: Option<Value>,
    pub database_specific: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvSeverity {
    pub ty: String,
    pub score: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvRecord {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub details: String,
    pub references: Vec<OsvReference>,
    pub affected: Vec<OsvAffected>,
    pub severity: Vec<OsvSeverity>,
    pub published: Option<String>, // UTC isoformat, matching Python
    pub modified: Option<String>,
    pub raw: Value,
}

/// Python `str(record.get(key) or "")` — empty when missing/null/empty/falsey.
fn str_or_empty(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        // Non-string truthy scalar -> Python str(); OSV uses strings here.
        Some(other) => {
            // `or ""` only replaces falsey values; 0 / false render via str().
            if is_falsey(other) {
                String::new()
            } else {
                python_str(other)
            }
        }
    }
}

fn is_falsey(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

fn python_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

/// Parse one OSV vulnerability record. `Err` if `id` is missing (`parse_record`).
pub fn parse_record(record: &Value) -> Result<OsvRecord, String> {
    let osv_id = str_or_empty(record.get("id"));
    if osv_id.is_empty() {
        return Err("OSV record missing id".to_string());
    }
    let aliases = record
        .get("aliases")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    Ok(OsvRecord {
        id: osv_id,
        aliases,
        summary: str_or_empty(record.get("summary")),
        details: str_or_empty(record.get("details")),
        references: parse_references(record.get("references")),
        affected: parse_affected(record.get("affected")),
        severity: parse_severity(record.get("severity")),
        published: parse_iso(record.get("published")),
        modified: parse_iso(record.get("modified")),
        raw: record.clone(),
    })
}

fn parse_references(refs: Option<&Value>) -> Vec<OsvReference> {
    let mut out = Vec::new();
    let Some(arr) = refs.and_then(Value::as_array) else { return out };
    for r in arr {
        let Some(obj) = r.as_object() else { continue };
        let Some(url) = obj.get("url").and_then(Value::as_str) else { continue };
        out.push(OsvReference { url: url.to_string(), ty: str_or_empty(obj.get("type")) });
    }
    out
}

fn str_map(obj: &Map<String, Value>) -> Map<String, Value> {
    obj.iter()
        .filter(|(_, v)| v.is_string())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn parse_affected(affected: Option<&Value>) -> Vec<OsvAffected> {
    let mut out = Vec::new();
    let Some(arr) = affected.and_then(Value::as_array) else { return out };
    for entry in arr {
        let Some(obj) = entry.as_object() else { continue };
        let package = obj.get("package").and_then(Value::as_object).map(str_map);
        let ranges = parse_ranges(obj.get("ranges"));
        let versions = obj
            .get("versions")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let eco = obj.get("ecosystem_specific").filter(|v| v.is_object()).cloned();
        let db = obj.get("database_specific").filter(|v| v.is_object()).cloned();
        out.push(OsvAffected { package, ranges, versions, ecosystem_specific: eco, database_specific: db });
    }
    out
}

fn event_order(ev: &Map<String, Value>) -> u8 {
    // Sort key on the FIRST key of the event dict (Python next(iter(ev.keys()))).
    match ev.keys().next().map(String::as_str) {
        Some("introduced") => 0,
        Some("fixed") | Some("last_affected") => 1,
        Some("limit") => 2,
        _ => 99,
    }
}

fn parse_ranges(ranges: Option<&Value>) -> Vec<OsvRange> {
    let mut out = Vec::new();
    let Some(arr) = ranges.and_then(Value::as_array) else { return out };
    for r in arr {
        let Some(obj) = r.as_object() else { continue };
        // Unknown type normalised to ECOSYSTEM (matches SCA matcher behaviour).
        let ty = match obj.get("type").and_then(Value::as_str) {
            Some(t @ ("GIT" | "SEMVER" | "ECOSYSTEM")) => t.to_string(),
            _ => "ECOSYSTEM".to_string(),
        };
        let repo = obj.get("repo").and_then(Value::as_str).map(str::to_string);
        let mut events: Vec<Map<String, Value>> = Vec::new();
        if let Some(evs) = obj.get("events").and_then(Value::as_array) {
            for ev in evs {
                if let Some(evobj) = ev.as_object() {
                    events.push(str_map(evobj));
                }
            }
        }
        // Stable sort: introduced before fixed/last_affected/limit.
        if !events.is_empty() {
            events.sort_by_key(event_order);
        }
        out.push(OsvRange { ty, repo, events });
    }
    out
}

fn parse_severity(severity: Option<&Value>) -> Vec<OsvSeverity> {
    let mut out = Vec::new();
    let Some(arr) = severity.and_then(Value::as_array) else { return out };
    for entry in arr {
        let Some(obj) = entry.as_object() else { continue };
        let Some(score) = obj.get("score").and_then(Value::as_str) else { continue };
        out.push(OsvSeverity { ty: str_or_empty(obj.get("type")), score: score.to_string() });
    }
    out
}

/// Parse an OSV ISO-8601 timestamp to a UTC isoformat string (`_parse_iso`).
/// `Z` is mapped to `+00:00`; the result is normalised to UTC and rendered to
/// match Python `datetime.isoformat()`. `None` on missing/malformed input.
fn parse_iso(value: Option<&Value>) -> Option<String> {
    let s = value.and_then(Value::as_str)?;
    if s.is_empty() {
        return None;
    }
    let normalised = s.replace('Z', "+00:00");
    let dt: DateTime<Utc> = DateTime::parse_from_rfc3339(&normalised).ok()?.with_timezone(&Utc);
    // Python isoformat: omit the fractional part when zero, else 6 digits.
    let formatted = if dt.timestamp_subsec_micros() == 0 {
        dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
    };
    Some(formatted)
}

impl OsvRecord {
    /// JSON in the shape of the Python dataclass fields (for parity tests).
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "aliases": self.aliases,
            "summary": self.summary,
            "details": self.details,
            "references": self.references.iter().map(|r| json!({"url": r.url, "type": r.ty})).collect::<Vec<_>>(),
            "affected": self.affected.iter().map(|a| json!({
                "package": a.package,
                "ranges": a.ranges.iter().map(|r| json!({"type": r.ty, "repo": r.repo, "events": r.events})).collect::<Vec<_>>(),
                "versions": a.versions,
                "ecosystem_specific": a.ecosystem_specific,
                "database_specific": a.database_specific,
            })).collect::<Vec<_>>(),
            "severity": self.severity.iter().map(|s| json!({"type": s.ty, "score": s.score})).collect::<Vec<_>>(),
            "published": self.published,
            "modified": self.modified,
        })
    }
}

// ---------------------------------------------------------------------------
// Commit-pair extraction + verdict types (verify.py pure core).
// ---------------------------------------------------------------------------

/// Per-CVE oracle verdict (`Verdict`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    MatchExact,
    MatchRange,
    MirrorDifferentSlug,
    Dispute,
    Orphan,
    LikelyHallucination,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::MatchExact => "match_exact",
            Verdict::MatchRange => "match_range",
            Verdict::MirrorDifferentSlug => "mirror_different_slug",
            Verdict::Dispute => "dispute",
            Verdict::Orphan => "orphan",
            Verdict::LikelyHallucination => "likely_hallucination",
        }
    }
    /// True for the verdicts that count as a passing oracle match.
    pub fn is_pass(self) -> bool {
        matches!(self, Verdict::MatchExact | Verdict::MatchRange | Verdict::MirrorDifferentSlug)
    }
}

/// Per-CVE verdict with the evidence that drove it (`OracleVerdict`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleVerdict {
    pub cve_id: String,
    pub picked_slug: String,
    pub picked_sha: String,
    pub verdict: Verdict,
    pub source: String,
    pub expected_slugs: Vec<String>,
    pub expected_shas: Vec<String>,
    pub notes: String,
}

impl OracleVerdict {
    pub fn to_json(&self) -> Value {
        json!({
            "cve_id": self.cve_id,
            "picked_slug": self.picked_slug,
            "picked_sha": self.picked_sha,
            "verdict": self.verdict.as_str(),
            "source": self.source,
            "expected_slugs": self.expected_slugs,
            "expected_shas": self.expected_shas,
            "notes": self.notes,
            "is_pass": self.verdict.is_pass(),
        })
    }
}

/// A list of `(slug, sha)` commit pairs.
pub type PairList = Vec<(String, String)>;

/// Return `(reference_pairs, range_pairs)` of `(slug, sha)` from an
/// `OsvRecord` (`_extract_pairs`): GitHub-commit + kernel.org refs, and `fixed`
/// events of GIT ranges (dropping empty / `"0"` shas and slug-less ranges).
pub fn extract_pairs(record: &OsvRecord) -> (PairList, PairList) {
    let mut ref_pairs: PairList = Vec::new();
    for r in &record.references {
        let url = r.url.trim();
        if let Some(m) = github_commit_url_re().captures(url) {
            ref_pairs.push((normalize_slug(&m[1]), m[2].to_lowercase()));
            continue;
        }
        if let Some(km) = kernel_sha_url_re().captures(url) {
            ref_pairs.push((LINUX_UPSTREAM_SLUG.to_lowercase(), km[1].to_lowercase()));
        }
    }

    let mut range_pairs: PairList = Vec::new();
    for aff in &record.affected {
        for rng in &aff.ranges {
            if rng.ty.to_uppercase() != "GIT" {
                continue;
            }
            let slug = extract_github_slug(rng.repo.as_deref().unwrap_or("")).unwrap_or_default();
            for ev in &rng.events {
                let sha = ev.get("fixed").and_then(Value::as_str).unwrap_or("").to_lowercase();
                if sha.is_empty() || sha == "0" {
                    continue;
                }
                if !slug.is_empty() {
                    range_pairs.push((slug.clone(), sha));
                }
            }
        }
    }
    (ref_pairs, range_pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_record() {
        let rec = json!({
            "id": "OSV-2024-1", "aliases": ["CVE-2024-1", 5],
            "summary": "s", "details": "d",
            "references": [{"url": "https://x/y", "type": "FIX"}, {"type": "WEB"}],
            "affected": [{"package": {"name": "p", "ecosystem": "npm"},
                "ranges": [{"type": "GIT", "repo": "https://r", "events": [{"fixed": "2"}, {"introduced": "1"}]}],
                "versions": ["1.0", 3]}],
            "severity": [{"type": "CVSS_V3", "score": "AV:N"}, {"type": "X"}],
            "published": "2024-01-15T10:30:00Z"
        });
        let r = parse_record(&rec).unwrap();
        assert_eq!(r.id, "OSV-2024-1");
        assert_eq!(r.aliases, vec!["CVE-2024-1"]); // non-string dropped
        assert_eq!(r.references.len(), 1); // ref without url dropped
        // events reordered: introduced before fixed.
        assert_eq!(r.affected[0].ranges[0].events[0].keys().next().unwrap(), "introduced");
        assert_eq!(r.affected[0].versions, vec!["1.0"]); // non-string dropped
        assert_eq!(r.severity.len(), 1); // severity without score dropped
        assert_eq!(r.published.as_deref(), Some("2024-01-15T10:30:00+00:00"));
    }

    #[test]
    fn unknown_range_type_normalised() {
        let rec = json!({"id": "X", "affected": [{"ranges": [{"type": "WEIRD", "events": []}]}]});
        let r = parse_record(&rec).unwrap();
        assert_eq!(r.affected[0].ranges[0].ty, "ECOSYSTEM");
    }

    #[test]
    fn missing_id_errors() {
        assert!(parse_record(&json!({"summary": "x"})).is_err());
    }

    #[test]
    fn non_utc_offset_normalised() {
        let rec = json!({"id": "X", "published": "2024-01-15T10:30:00+05:00"});
        let r = parse_record(&rec).unwrap();
        assert_eq!(r.published.as_deref(), Some("2024-01-15T05:30:00+00:00"));
    }

    #[test]
    fn extract_pairs_refs_and_ranges() {
        let rec = json!({"id": "X",
            "references": [
                {"url": "https://github.com/Foo/Bar/commit/ABCDEF1234567890", "type": "FIX"},
                {"url": "https://example.com/not-a-commit", "type": "WEB"}
            ],
            "affected": [{"ranges": [
                {"type": "GIT", "repo": "https://github.com/Foo/Bar", "events": [{"introduced": "0"}, {"fixed": "BEEFCAFE"}, {"fixed": "0"}]},
                {"type": "SEMVER", "events": [{"fixed": "1.0"}]}
            ]}]});
        let r = parse_record(&rec).unwrap();
        let (refs, ranges) = extract_pairs(&r);
        // Only the GitHub commit ref matches (non-commit URL dropped).
        assert_eq!(refs, vec![("foo/bar".to_string(), "abcdef1234567890".to_string())]);
        // Only the GIT range's non-"0" fixed event yields a pair.
        assert_eq!(ranges, vec![("foo/bar".to_string(), "beefcafe".to_string())]);
    }

    #[test]
    fn verdict_pass_and_json() {
        assert!(Verdict::MatchExact.is_pass());
        assert!(!Verdict::Orphan.is_pass());
        let v = OracleVerdict {
            cve_id: "CVE-1".into(), picked_slug: "a/b".into(), picked_sha: "deadbeef".into(),
            verdict: Verdict::MatchExact, source: "osv".into(),
            expected_slugs: vec!["a/b".into()], expected_shas: vec!["deadbeef".into()], notes: "".into(),
        };
        assert_eq!(v.to_json()["verdict"], "match_exact");
        assert_eq!(v.to_json()["is_pass"], true);
    }
}
