//! Composite risk estimate — Rust port of `compute_risk_estimate` in
//! `packages/sca/risk.py`.
//!
//! Deterministic 0..100 score from a finding's signals. The `overrides`
//! grid-search hook (calibration refitter) and `_calibration_status` filesystem
//! read stay Python; the caller passes `calibration_status` in. All arithmetic
//! mirrors the Python formula stage-for-stage.

use serde_json::{Map, Value};

// Default tuned constants (overrides path stays Python).
const CVSS_MISSING_DEFAULT: f64 = 5.0;
const KEV_FLOOR: f64 = 96.8;
const KEV_MULTIPLIER: f64 = 1.7569;
const EXPLOIT_EVIDENCE_FLOOR: f64 = 79.86;
const EXPLOIT_EVIDENCE_MULTIPLIER: f64 = 1.5839;
const SSVC_ACTIVE_FLOOR: f64 = 96.8;
const SSVC_ACTIVE_MULTIPLIER: f64 = 1.452;
const SSVC_POC_FLOOR: f64 = 79.86;
const SSVC_POC_MULTIPLIER: f64 = 1.4399;
const SSVC_AUTOMATABLE_BONUS: f64 = 1.331;
const EPSS_FLOOR_MULTIPLIER: f64 = 0.3993;
const EPSS_RANGE_MULTIPLIER: f64 = 0.5103;
const EPSS_MISSING_DEFAULT: f64 = 0.5;
const REACH_NOT_REACHABLE_MAX_REDUCTION: f64 = 0.4593;
const REACH_NOT_EVALUATED_MULTIPLIER: f64 = 0.6817;
const EXPO_FLOOR_MULTIPLIER: f64 = 0.50;
const EXPO_RANGE_MULTIPLIER: f64 = 0.50;
const DEPTH_DECAY_BASE: f64 = 0.70;
const SCORE_MIN: f64 = 0.0;
const SCORE_MAX: f64 = 100.0;

/// The finding + dep signals the risk formula reads (the scalar projection of a
/// `VulnFinding` / `Dependency`).
#[derive(Clone, Debug)]
pub struct RiskInputs<'a> {
    pub cvss_score: Option<f64>,
    pub severity: &'a str,
    pub in_kev: bool,
    /// `exploit_evidence is not None and exploit_evidence.has_any`.
    pub has_exploit_evidence: bool,
    pub ssvc_exploitation: Option<&'a str>,
    pub ssvc_automatable: Option<&'a str>,
    pub epss: Option<f64>,
    pub reach_verdict: &'a str,
    pub reach_conf_numeric: f64,
    pub exposure_factor: f64,
    pub transitive_depth: i64,
    pub direct: bool,
    pub parser_confidence_numeric: f64,
    pub version_match_confidence_numeric: f64,
}

/// `x or default` for a float (Python truthiness: 0.0 is falsy).
fn or_default(x: f64, default: f64) -> f64 {
    if x != 0.0 {
        x
    } else {
        default
    }
}

/// Compute `(score, components)` for a finding (`compute_risk_estimate`, default
/// constants). `calibration_status` is resolved by the caller.
pub fn compute_risk_estimate(inputs: &RiskInputs, calibration_status: &str) -> (f64, Value) {
    let mut components = Map::new();

    // 1. CVSS base — numeric, else severity-label fallback, else neutral 5.0.
    let cvss = if let Some(score) = inputs.cvss_score {
        components.insert("cvss_source".into(), Value::from("numeric"));
        score
    } else if let Some(derived) = mantishack_cvss::score_for_label(Some(inputs.severity)) {
        components.insert("cvss_source".into(), Value::from("severity_label"));
        derived
    } else {
        components.insert("cvss_source".into(), Value::from("default"));
        CVSS_MISSING_DEFAULT
    };
    let mut base = (cvss / 10.0) * 100.0;
    components.insert("cvss_base".into(), Value::from(base));

    // 2. KEV floor + multiplier.
    if inputs.in_kev {
        base = base.max(KEV_FLOOR) * KEV_MULTIPLIER;
        components.insert("kev_multiplier".into(), Value::from(KEV_MULTIPLIER));
    } else {
        components.insert("kev_multiplier".into(), Value::from(1.0));
    }

    // 2-bis. Exploit evidence (independent of KEV, not double-counted).
    let has_evidence = inputs.has_exploit_evidence && !inputs.in_kev;
    if has_evidence {
        base = base.max(EXPLOIT_EVIDENCE_FLOOR) * EXPLOIT_EVIDENCE_MULTIPLIER;
        components.insert("exploit_evidence_multiplier".into(), Value::from(EXPLOIT_EVIDENCE_MULTIPLIER));
    } else {
        components.insert("exploit_evidence_multiplier".into(), Value::from(1.0));
    }

    // 2-ter. CISA Vulnrichment SSVC tiers.
    let ssvc = inputs.ssvc_exploitation;
    let mut ssvc_tier_applied = false;
    if ssvc == Some("active") && !inputs.in_kev {
        base = base.max(SSVC_ACTIVE_FLOOR) * SSVC_ACTIVE_MULTIPLIER;
        components.insert("ssvc_active_multiplier".into(), Value::from(SSVC_ACTIVE_MULTIPLIER));
        ssvc_tier_applied = true;
    } else if ssvc == Some("poc") && !inputs.in_kev && !has_evidence {
        base = base.max(SSVC_POC_FLOOR) * SSVC_POC_MULTIPLIER;
        components.insert("ssvc_poc_multiplier".into(), Value::from(SSVC_POC_MULTIPLIER));
        ssvc_tier_applied = true;
    }

    // SSVC Automatable=yes bonus (only on top of an applied tier).
    let automatable_yes = inputs.ssvc_automatable.unwrap_or("").to_lowercase() == "yes";
    if ssvc_tier_applied && automatable_yes {
        base *= SSVC_AUTOMATABLE_BONUS;
        components.insert("ssvc_automatable_multiplier".into(), Value::from(SSVC_AUTOMATABLE_BONUS));
    } else {
        components.insert("ssvc_automatable_multiplier".into(), Value::from(1.0));
    }

    // 3. EPSS 0..1 -> 0.30..1.00 multiplier.
    let epss = inputs.epss.unwrap_or(EPSS_MISSING_DEFAULT);
    let epss_mult = EPSS_FLOOR_MULTIPLIER + EPSS_RANGE_MULTIPLIER * epss;
    base *= epss_mult;
    components.insert("epss_multiplier".into(), Value::from(epss_mult));

    // 4. Reachability.
    let reach_mult = match inputs.reach_verdict {
        "not_reachable" | "not_function_reachable" | "called_in_dead_code" => {
            1.0 - REACH_NOT_REACHABLE_MAX_REDUCTION * inputs.reach_conf_numeric
        }
        "not_evaluated" => REACH_NOT_EVALUATED_MULTIPLIER,
        _ => 1.0,
    };
    base *= reach_mult;
    components.insert("reachability_multiplier".into(), Value::from(reach_mult));

    // 5. Exposure (call-site density, clamped 0..1).
    let expo = inputs.exposure_factor.clamp(0.0, 1.0);
    let expo_mult = EXPO_FLOOR_MULTIPLIER + EXPO_RANGE_MULTIPLIER * expo;
    base *= expo_mult;
    components.insert("exposure_multiplier".into(), Value::from(expo_mult));

    // 6. Direct vs transitive depth decay.
    let depth_mult = if inputs.direct || inputs.transitive_depth <= 0 {
        1.0
    } else {
        DEPTH_DECAY_BASE.powf(inputs.transitive_depth as f64)
    };
    base *= depth_mult;
    components.insert("depth_multiplier".into(), Value::from(depth_mult));

    // 7. Parser confidence haircut.
    let parser_conf = or_default(inputs.parser_confidence_numeric, 1.0);
    base *= parser_conf;
    components.insert("parser_confidence".into(), Value::from(parser_conf));

    // 8. Version-match confidence.
    let vmc = or_default(inputs.version_match_confidence_numeric, 1.0);
    base *= vmc;
    components.insert("version_match_confidence".into(), Value::from(vmc));

    let final_score = base.clamp(SCORE_MIN, SCORE_MAX);
    components.insert("final".into(), Value::from(final_score));
    components.insert("calibration_status".into(), Value::from(calibration_status));

    (final_score, Value::Object(components))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_inputs() -> RiskInputs<'static> {
        RiskInputs {
            cvss_score: Some(7.0),
            severity: "high",
            in_kev: false,
            has_exploit_evidence: false,
            ssvc_exploitation: None,
            ssvc_automatable: None,
            epss: Some(0.5),
            reach_verdict: "likely_called",
            reach_conf_numeric: 0.95,
            exposure_factor: 0.5,
            transitive_depth: 0,
            direct: true,
            parser_confidence_numeric: 0.95,
            version_match_confidence_numeric: 0.95,
        }
    }

    fn score(i: &RiskInputs) -> f64 {
        compute_risk_estimate(i, "unknown").0
    }

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-6, "expected {b}, got {a}");
    }

    #[test]
    fn matches_python_differential() {
        approx(score(&base_inputs()), 31.0086590625);
        approx(score(&RiskInputs { in_kev: true, ..base_inputs() }), 75.3368306964);
        approx(score(&RiskInputs { has_exploit_evidence: true, ..base_inputs() }), 56.0327594431);
        approx(score(&RiskInputs { ssvc_exploitation: Some("active"), ..base_inputs() }), 62.2625523201);
        approx(score(&RiskInputs { ssvc_exploitation: Some("poc"), ..base_inputs() }), 50.9385506169);
        approx(score(&RiskInputs { ssvc_exploitation: Some("active"), ssvc_automatable: Some("yes"), ..base_inputs() }), 82.8714571381);
        approx(score(&RiskInputs { reach_verdict: "not_reachable", ..base_inputs() }), 17.4784958105);
        approx(score(&RiskInputs { reach_verdict: "called_in_dead_code", reach_conf_numeric: 0.7, ..base_inputs() }), 21.0390650873);
        approx(score(&RiskInputs { reach_verdict: "not_evaluated", ..base_inputs() }), 21.1386028829);
        approx(score(&RiskInputs { direct: false, transitive_depth: 3, ..base_inputs() }), 10.6359700584);
        approx(score(&RiskInputs { cvss_score: None, severity: "", ..base_inputs() }), 22.1490421875);
        approx(score(&RiskInputs { exposure_factor: 1.5, ..base_inputs() }), 41.34487875);
        approx(score(&RiskInputs { exposure_factor: -0.5, ..base_inputs() }), 20.672439375);
    }

    #[test]
    fn components_shape() {
        let (_, comp) = compute_risk_estimate(&base_inputs(), "unknown");
        let c = comp.as_object().unwrap();
        assert_eq!(c["cvss_source"], Value::from("numeric"));
        assert_eq!(c["cvss_base"], Value::from(70.0));
        assert_eq!(c["calibration_status"], Value::from("unknown"));
        // No ssvc-tier key on a neutral finding; automatable multiplier is neutral.
        assert!(!c.contains_key("ssvc_active_multiplier"));
        assert_eq!(c["ssvc_automatable_multiplier"], Value::from(1.0));

        // ssvc active inserts its tier key before the automatable multiplier.
        let (_, comp) = compute_risk_estimate(&RiskInputs { ssvc_exploitation: Some("active"), ..base_inputs() }, "unknown");
        assert!(comp.as_object().unwrap().contains_key("ssvc_active_multiplier"));
    }
}
