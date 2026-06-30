//! CVE enrichment data parsers — Rust port of `core/cve` (epss / kev /
//! vulnrichment).
//!
//! Only the pure data-transform core is ported: parsing EPSS API responses,
//! the KEV catalog, and CISA Vulnrichment SSVC scorecards, plus the
//! Vulnrichment URL sharding. The `EpssClient`/`KevClient`/`VulnrichmentClient`
//! HTTP + `JsonCache` layers (`core.http` / `core.json`) stay in Python — this
//! crate is network/IO-free and operates on payloads as `serde_json::Value`.

use serde_json::Value;

const REPO_RAW_BASE: &str = "https://raw.githubusercontent.com/cisagov/vulnrichment/HEAD";
const NO_SCORE_SENTINEL: f64 = -1.0;

// ---------------------------------------------------------------------------
// EPSS (api.first.org) — exploit-prediction scores.
// ---------------------------------------------------------------------------

/// Coerce an EPSS score value to `Some(f64)`, mapping the `-1.0` sentinel and
/// non-numeric values to `None` (`_coerce_score`).
pub fn coerce_score(value: &Value) -> Option<f64> {
    let n = value.as_f64()?;
    if n == NO_SCORE_SENTINEL {
        None
    } else {
        Some(n)
    }
}

/// Parse an EPSS API response into `{CVE -> score}` (`_parse_response`). CVE ids
/// are upper-cased; the `epss` field is parsed as a float (string or number).
/// Malformed payloads/entries are skipped; a non-object payload yields `{}`.
pub fn parse_response(payload: &Value) -> Vec<(String, f64)> {
    let Some(data) = payload.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<(String, f64)> = Vec::new();
    for entry in data {
        let Some(cve) = entry.get("cve").and_then(Value::as_str) else { continue };
        // Python `float(score)` accepts a number or a numeric string.
        let score = entry.get("epss");
        let score_f = match score {
            Some(Value::Number(n)) => n.as_f64(),
            Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
            _ => None,
        };
        let Some(score_f) = score_f else { continue };
        out.push((cve.to_uppercase(), score_f));
    }
    out
}

/// Split `items` into chunks of at most `size` (`_chunked`).
pub fn chunked<T: Clone>(items: &[T], size: usize) -> Vec<Vec<T>> {
    if size == 0 {
        return Vec::new();
    }
    items.chunks(size).map(<[T]>::to_vec).collect()
}

// ---------------------------------------------------------------------------
// KEV (CISA Known Exploited Vulnerabilities) catalog.
// ---------------------------------------------------------------------------

/// Pull the CVE-id set from a KEV catalog payload (`_extract_cves`). Upper-cased;
/// tolerates `cveID`/`cve_id`; any other shape yields an empty set.
pub fn extract_cves(record: &Value) -> Vec<String> {
    let Some(vulns) = record.get("vulnerabilities").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for entry in vulns {
        let cve = entry
            .get("cveID")
            .and_then(Value::as_str)
            .or_else(|| entry.get("cve_id").and_then(Value::as_str));
        if let Some(cve) = cve {
            if !cve.is_empty() {
                let up = cve.to_uppercase();
                if !out.contains(&up) {
                    out.push(up);
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Vulnrichment (CISA SSVC scorecards).
// ---------------------------------------------------------------------------

/// CISA SSVC decision points from one Vulnrichment entry (`SSVCDecision`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsvcDecision {
    pub exploitation: String,             // "none" / "poc" / "active"
    pub automatable: Option<String>,      // "yes" / "no" / None
    pub technical_impact: Option<String>, // "total" / "partial" / None
}

impl SsvcDecision {
    /// True when CISA records a public PoC OR active exploitation.
    pub fn has_exploit(&self) -> bool {
        matches!(self.exploitation.as_str(), "poc" | "active")
    }
    /// True when CISA records active in-the-wild exploitation.
    pub fn is_active(&self) -> bool {
        self.exploitation == "active"
    }
}

/// Build the `raw.githubusercontent.com` URL for a CVE's Vulnrichment entry
/// (`_url_for_cve`). Vulnrichment shards into `<year>/<NNNxxx>/` buckets where
/// `NNN = number // 1000` (`0xxx` for numbers below 1000). `None` if malformed.
pub fn url_for_cve(cve_id: &str) -> Option<String> {
    let upper = cve_id.to_uppercase();
    let parts: Vec<&str> = upper.split('-').collect();
    if parts.len() != 3 || parts[0] != "CVE" {
        return None;
    }
    let (year_str, num_str) = (parts[1], parts[2]);
    if !(is_ascii_digits(year_str) && is_ascii_digits(num_str)) {
        return None;
    }
    let num: u64 = num_str.parse().ok()?;
    let bucket = num / 1000;
    let bucket_dir = if bucket > 0 { format!("{bucket}xxx") } else { "0xxx".to_string() };
    Some(format!("{REPO_RAW_BASE}/{year_str}/{bucket_dir}/CVE-{year_str}-{num_str}.json"))
}

/// Python `str.isdigit()` for the ASCII case (the CVE-id segments are ASCII).
fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Pluck SSVC fields out of a CVE-JSON-5 record's CISA-ADP container
/// (`_decode_ssvc`). Returns `None` when no SSVC scorecard is present.
/// Option spellings are lower-cased.
pub fn decode_ssvc(record: &Value) -> Option<SsvcDecision> {
    let adp = record.get("containers")?.get("adp")?.as_array()?;
    for entry in adp {
        let provider = entry
            .get("providerMetadata")
            .and_then(|p| p.get("shortName"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !provider.contains("CISA-ADP") {
            continue;
        }
        let Some(metrics) = entry.get("metrics").and_then(Value::as_array) else { continue };
        for metric in metrics {
            let options = metric
                .get("other")
                .and_then(|o| o.get("content"))
                .and_then(|c| c.get("options"))
                .and_then(Value::as_array);
            let Some(options) = options else { continue };
            let mut exploitation: Option<String> = None;
            let mut automatable: Option<String> = None;
            let mut technical_impact: Option<String> = None;
            for opt in options {
                if let Some(v) = opt.get("Exploitation") {
                    exploitation = Some(value_to_lower_string(v));
                }
                if let Some(v) = opt.get("Automatable") {
                    automatable = Some(value_to_lower_string(v));
                }
                if let Some(v) = opt.get("Technical Impact") {
                    technical_impact = Some(value_to_lower_string(v));
                }
            }
            if let Some(exp) = &exploitation {
                if matches!(exp.as_str(), "none" | "poc" | "active") {
                    return Some(SsvcDecision {
                        exploitation: exp.clone(),
                        automatable,
                        technical_impact,
                    });
                }
            }
        }
    }
    None
}

/// `str(value).lower()` — a JSON string lower-cased, or other scalars rendered
/// the way Python `str()` would before lower-casing.
fn value_to_lower_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.to_lowercase(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Value::Null => "none".to_string(),
        other => other.to_string().to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn epss_coerce_and_parse() {
        assert_eq!(coerce_score(&json!(0.5)), Some(0.5));
        assert_eq!(coerce_score(&json!(-1.0)), None);
        assert_eq!(coerce_score(&json!("x")), None);

        let payload = json!({"data": [
            {"cve": "cve-2024-1", "epss": "0.25"},
            {"cve": "CVE-2024-2", "epss": 0.9},
            {"cve": "CVE-2024-3", "epss": "bad"},
            {"nope": true}
        ]});
        let out = parse_response(&payload);
        assert_eq!(out, vec![("CVE-2024-1".into(), 0.25), ("CVE-2024-2".into(), 0.9)]);
        assert_eq!(parse_response(&json!({})), Vec::new());
    }

    #[test]
    fn chunked_splits() {
        assert_eq!(chunked(&[1, 2, 3, 4, 5], 2), vec![vec![1, 2], vec![3, 4], vec![5]]);
        assert_eq!(chunked::<i32>(&[], 2), Vec::<Vec<i32>>::new());
    }

    #[test]
    fn kev_extract() {
        let rec = json!({"vulnerabilities": [
            {"cveID": "cve-2024-1"}, {"cve_id": "CVE-2024-2"}, {"cveID": ""}, {"x": 1}
        ]});
        assert_eq!(extract_cves(&rec), vec!["CVE-2024-1".to_string(), "CVE-2024-2".to_string()]);
        assert_eq!(extract_cves(&json!({})), Vec::<String>::new());
    }

    #[test]
    fn vulnrichment_url_sharding() {
        assert_eq!(
            url_for_cve("CVE-2024-12345").as_deref(),
            Some("https://raw.githubusercontent.com/cisagov/vulnrichment/HEAD/2024/12xxx/CVE-2024-12345.json")
        );
        assert_eq!(
            url_for_cve("cve-2024-500").as_deref(),
            Some("https://raw.githubusercontent.com/cisagov/vulnrichment/HEAD/2024/0xxx/CVE-2024-500.json")
        );
        assert_eq!(url_for_cve("GHSA-xxxx"), None);
        assert_eq!(url_for_cve("CVE-202X-1"), None);
    }

    #[test]
    fn vulnrichment_ssvc() {
        let rec = json!({"containers": {"adp": [
            {"providerMetadata": {"shortName": "CISA-ADP"},
             "metrics": [{"other": {"content": {"options": [
                {"Exploitation": "Active"}, {"Automatable": "Yes"}, {"Technical Impact": "Total"}
             ]}}}]}
        ]}});
        let d = decode_ssvc(&rec).unwrap();
        assert_eq!(d, SsvcDecision { exploitation: "active".into(), automatable: Some("yes".into()), technical_impact: Some("total".into()) });
        assert!(d.has_exploit());
        assert!(d.is_active());
        assert_eq!(decode_ssvc(&json!({})), None);
    }
}
