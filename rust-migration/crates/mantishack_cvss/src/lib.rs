//! CVSS v3.1 base score calculator — faithful Rust rewrite of
//! `packages/cvss/calculator.py`.
//!
//! This is a behavior-preserving port: same inputs produce the same outputs,
//! including the deliberate quirks the Python tests rely on —
//!   * strict end-of-string validation (`\Z`) that rejects a trailing newline
//!     and any CLI-injection payload after the vector,
//!   * duplicate metric-key rejection,
//!   * round-half-up to one decimal via `ceil(score * 10) / 10`,
//!   * conservative lower-bound scoring in `score_for_label`.
//!
//! No external crates. The optional `python` feature adds the PyO3 binding that
//! re-exports these functions under the original Python names so callers switch
//! by changing one import.

// --- metric weight tables (CVSS v3.1 specification) -------------------------

fn av(v: &str) -> Option<f64> {
    Some(match v { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.20, _ => return None })
}
fn ac(v: &str) -> Option<f64> {
    Some(match v { "L" => 0.77, "H" => 0.44, _ => return None })
}
fn pr_unchanged(v: &str) -> Option<f64> {
    Some(match v { "N" => 0.85, "L" => 0.62, "H" => 0.27, _ => return None })
}
fn pr_changed(v: &str) -> Option<f64> {
    Some(match v { "N" => 0.85, "L" => 0.68, "H" => 0.50, _ => return None })
}
fn ui(v: &str) -> Option<f64> {
    Some(match v { "N" => 0.85, "R" => 0.62, _ => return None })
}
fn cia(v: &str) -> Option<f64> {
    Some(match v { "H" => 0.56, "L" => 0.22, "N" => 0.0, _ => return None })
}

// _SEVERITY threshold table — (lower_bound, label). Forward and inverse both
// derive from this so the score<->label mapping can never drift.
const SEVERITY: [(f64, &str); 5] = [
    (0.0, "None"), (0.1, "Low"), (4.0, "Medium"), (7.0, "High"), (9.0, "Critical"),
];

/// Well-formedness check mirroring the Python `_VECTOR_RE` + duplicate-key guard.
///
/// Accepts base-only vectors and vectors carrying optional temporal/environmental
/// extensions. Rejects trailing newlines / junk (the `\Z` anchor), malformed base
/// segments, wrong ordering, and duplicate metric keys.
pub fn validate_vector(vector: &str) -> bool {
    // `\Z` semantics: no embedded or trailing CR/LF anywhere.
    if vector.contains('\n') || vector.contains('\r') {
        return false;
    }
    let parts: Vec<&str> = vector.split('/').collect();
    // prefix + 8 base metrics = at least 9 segments.
    if parts.len() < 9 {
        return false;
    }
    if parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1" {
        return false;
    }

    // Base segments in EXACT order with EXACT value classes.
    let base: [(&str, &[&str]); 8] = [
        ("AV", &["N", "A", "L", "P"]),
        ("AC", &["L", "H"]),
        ("PR", &["N", "L", "H"]),
        ("UI", &["N", "R"]),
        ("S", &["U", "C"]),
        ("C", &["N", "L", "H"]),
        ("I", &["N", "L", "H"]),
        ("A", &["N", "L", "H"]),
    ];
    for (i, (key, allowed)) in base.iter().enumerate() {
        let seg = parts[i + 1];
        let (k, v) = match seg.split_once(':') {
            Some(kv) => kv,
            None => return false,
        };
        if k != *key || !allowed.contains(&v) {
            return false;
        }
    }

    // Optional extension segments: METRIC:VALUE, metric alphabetic, value alnum.
    for seg in &parts[9..] {
        let (k, v) = match seg.split_once(':') {
            Some(kv) => kv,
            None => return false,
        };
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphabetic()) {
            return false;
        }
        if v.is_empty() || !v.chars().all(|c| c.is_ascii_alphanumeric()) {
            return false;
        }
    }

    // Duplicate-key rejection across all non-prefix segments.
    let mut seen: Vec<&str> = Vec::new();
    for part in &parts[1..] {
        if let Some((key, _)) = part.split_once(':') {
            if seen.contains(&key) {
                return false;
            }
            seen.push(key);
        }
    }
    true
}

/// Parse a validated vector into (key, value) base-metric lookups.
/// Returns `Err` if the vector is malformed (matches Python's `ValueError`).
fn parse_vector(vector: &str) -> Result<std::collections::HashMap<String, String>, ()> {
    if !validate_vector(vector) {
        return Err(());
    }
    let mut m = std::collections::HashMap::new();
    for part in vector.split('/').skip(1) {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k.to_string(), v.to_string());
        }
    }
    Ok(m)
}

/// Compute the CVSS v3.1 base score. `Err(())` on a malformed vector
/// (the caller's `compute_score_safe` turns that into `None`).
pub fn compute_base_score(vector: &str) -> Result<(f64, String), ()> {
    let m = parse_vector(vector)?;
    let g = |k: &str| m.get(k).map(|s| s.as_str()).unwrap_or("");

    let (c, i, a) = (cia(g("C")).ok_or(())?, cia(g("I")).ok_or(())?, cia(g("A")).ok_or(())?);
    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    if iss <= 0.0 {
        return Ok((0.0, "None".to_string()));
    }

    let scope_changed = g("S") == "C";
    let pr = if scope_changed { pr_changed(g("PR")) } else { pr_unchanged(g("PR")) }.ok_or(())?;
    let exploitability = 8.22 * av(g("AV")).ok_or(())? * ac(g("AC")).ok_or(())? * pr * ui(g("UI")).ok_or(())?;

    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Ok((0.0, "None".to_string()));
    }

    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // Round up to nearest 0.1, exactly like Python's math.ceil(score*10)/10.
    let score = (raw * 10.0).ceil() / 10.0;

    let mut label = "None";
    for (threshold, name) in SEVERITY.iter() {
        if score >= *threshold {
            label = name;
        }
    }
    Ok((score, label.to_string()))
}

/// `(Some(score), Some(label))` for a valid vector, `(None, None)` otherwise.
pub fn compute_score_safe(vector: Option<&str>) -> (Option<f64>, Option<String>) {
    match vector {
        Some(v) if !v.is_empty() => match compute_base_score(v) {
            Ok((s, l)) => (Some(s), Some(l)),
            Err(()) => (None, None),
        },
        _ => (None, None),
    }
}

/// Representative lower-bound numeric for a severity label (conservative).
/// Case-insensitive; `info` → 1.0; unknown/empty → `None`.
pub fn score_for_label(label: Option<&str>) -> Option<f64> {
    let label = label?;
    let norm = label.trim().to_ascii_lowercase();
    if norm.is_empty() {
        return None;
    }
    for (threshold, name) in SEVERITY.iter() {
        if name.to_ascii_lowercase() == norm {
            return Some(*threshold);
        }
    }
    if norm == "info" {
        return Some(1.0);
    }
    None
}

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    #[pyfunction]
    fn validate_vector(vector: &str) -> bool { super::validate_vector(vector) }

    #[pyfunction]
    fn compute_base_score(vector: &str) -> PyResult<(f64, String)> {
        super::compute_base_score(vector)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("Invalid CVSS v3.1 vector: {vector}")))
    }

    #[pyfunction]
    fn compute_score_safe(vector: Option<&str>) -> (Option<f64>, Option<String>) {
        super::compute_score_safe(vector)
    }

    #[pyfunction]
    fn score_for_label(label: Option<&str>) -> Option<f64> {
        super::score_for_label(label)
    }

    /// Mutate a finding dict in place — mirrors Python `score_finding`.
    #[pyfunction]
    fn score_finding(finding: &Bound<'_, PyDict>) -> PyResult<()> {
        if let Some(vec) = finding.get_item("cvss_vector")? {
            let vec: Option<String> = vec.extract().ok();
            let (score, label) = super::compute_score_safe(vec.as_deref());
            if let (Some(s), Some(l)) = (score, label) {
                finding.set_item("cvss_score_estimate", s)?;
                finding.set_item("severity_assessment", l.to_lowercase())?;
            }
        }
        Ok(())
    }

    #[pymodule]
    fn mantishack_cvss(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(validate_vector, m)?)?;
        m.add_function(wrap_pyfunction!(compute_base_score, m)?)?;
        m.add_function(wrap_pyfunction!(compute_score_safe, m)?)?;
        m.add_function(wrap_pyfunction!(score_for_label, m)?)?;
        m.add_function(wrap_pyfunction!(score_finding, m)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors generated by running the ORIGINAL Python calculator.
    // (packages/cvss/calculator.py) — this is the cross-language parity oracle.
    #[test]
    fn parity_scored_vectors() {
        let cases: &[(&str, bool, Option<f64>, Option<&str>)] = &[
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, Some(9.8), Some("Critical")),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", true, Some(10.0), Some("Critical")),
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", true, Some(2.9), Some("Low")),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", true, Some(0.0), Some("None")),
            ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L", true, Some(8.2), Some("High")),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C", true, Some(9.8), Some("Critical")),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", true, Some(0.0), Some("None")),
            ("garbage", false, None, None),
            // duplicate AC key -> rejected
            ("CVSS:3.1/AV:N/AC:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", false, None, None),
            // trailing-newline CLI-injection payload -> rejected (\Z anchor)
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\nrm -rf", false, None, None),
        ];
        for (vec, valid, score, label) in cases {
            assert_eq!(validate_vector(vec), *valid, "validate_vector({vec})");
            let (s, l) = compute_score_safe(Some(vec));
            assert_eq!(s, *score, "score({vec})");
            assert_eq!(l.as_deref(), *label, "label({vec})");
        }
    }

    #[test]
    fn parity_label_inverse() {
        assert_eq!(score_for_label(Some("CRITICAL")), Some(9.0));
        assert_eq!(score_for_label(Some("high")), Some(7.0));
        assert_eq!(score_for_label(Some("Medium")), Some(4.0));
        assert_eq!(score_for_label(Some("low")), Some(0.1));
        assert_eq!(score_for_label(Some("none")), Some(0.0));
        assert_eq!(score_for_label(Some("info")), Some(1.0));
        assert_eq!(score_for_label(Some("bogus")), None);
        assert_eq!(score_for_label(None), None);
    }
}
