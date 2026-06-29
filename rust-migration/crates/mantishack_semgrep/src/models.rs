//! Data models for Semgrep results — faithful port of `packages/semgrep/models.py`.
//!
//! `SemgrepFinding` and `SemgrepResult` mirror the Python dataclasses field-for-field.
//! `parse_sarif` and `parse_json_output` are faithful ports of the same-named
//! functions in models.py: they return empty/default values on malformed input
//! rather than propagating errors.

use std::collections::HashMap;

// ── SemgrepFinding ────────────────────────────────────────────────────────────

/// A single finding from a Semgrep rule, parsed from SARIF.
///
/// Mirrors Python `SemgrepFinding`. All integer fields default to 0; `level`
/// defaults to `"warning"` (matching Python's `level: str = "warning"`).
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepFinding {
    pub file: String,
    pub line: i64,
    pub rule_id: String,
    pub message: String,
    pub column: i64,
    pub line_end: i64,
    pub column_end: i64,
    pub level: String,
}

impl Default for SemgrepFinding {
    fn default() -> Self {
        Self {
            file: String::new(),
            line: 0,
            rule_id: String::new(),
            message: String::new(),
            column: 0,
            line_end: 0,
            column_end: 0,
            // Python: level: str = "warning"
            level: "warning".to_string(),
        }
    }
}

impl SemgrepFinding {
    /// Build from a single SARIF `runs[].results[]` entry.
    ///
    /// Returns a zeroed-out finding on null/non-object input, matching Python's
    /// `return cls(file="", line=0)` guard.
    pub fn from_sarif_result(result: &serde_json::Value) -> Self {
        if !result.is_object() {
            return Self::default();
        }

        let rule_id = result
            .get("ruleId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Python: if isinstance(msg, dict): message = msg.get("text", "")
        //         elif isinstance(msg, str): message = msg
        let message = match result.get("message") {
            Some(v) if v.is_object() => v
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string(),
            Some(v) if v.is_string() => v.as_str().unwrap_or("").to_string(),
            _ => String::new(),
        };

        let level = result
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("warning")
            .to_string();

        let mut file = String::new();
        let mut line: i64 = 0;
        let mut column: i64 = 0;
        let mut line_end: i64 = 0;
        let mut column_end: i64 = 0;

        // Python: locations = result.get("locations") or []
        //         if locations and isinstance(locations[0], dict):
        if let Some(locations) = result.get("locations").and_then(|v| v.as_array()) {
            if let Some(first) = locations.first() {
                if first.is_object() {
                    let empty_obj = serde_json::Value::Object(Default::default());

                    // Python: phys = locations[0].get("physicalLocation") or {}
                    let phys = first
                        .get("physicalLocation")
                        .filter(|v| !v.is_null())
                        .unwrap_or(&empty_obj);

                    // Python: artifact = phys.get("artifactLocation") or {}
                    let artifact = phys
                        .get("artifactLocation")
                        .filter(|v| !v.is_null())
                        .unwrap_or(&empty_obj);

                    file = artifact
                        .get("uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Python: region = phys.get("region") or {}
                    let region = phys
                        .get("region")
                        .filter(|v| !v.is_null())
                        .unwrap_or(&empty_obj);

                    // Python: int(region.get("startLine", 0))
                    line = value_to_i64(region.get("startLine"));
                    column = value_to_i64(region.get("startColumn"));
                    line_end = value_to_i64(region.get("endLine"));
                    column_end = value_to_i64(region.get("endColumn"));
                }
            }
        }

        Self {
            file,
            line,
            column,
            line_end,
            column_end,
            rule_id,
            message,
            level,
        }
    }

    /// Serialise to a plain JSON object matching Python's `to_dict()`.
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "file":       self.file,
            "line":       self.line,
            "column":     self.column,
            "line_end":   self.line_end,
            "column_end": self.column_end,
            "rule_id":    self.rule_id,
            "message":    self.message,
            "level":      self.level,
        })
    }
}

// ── SemgrepResult ─────────────────────────────────────────────────────────────

/// Results from running Semgrep with one config against a target.
///
/// Mirrors Python `SemgrepResult`. `files_failed` is a list of `{path, reason}` maps,
/// matching the shape written by `parse_json_output`.
#[derive(Debug, Clone, Default)]
pub struct SemgrepResult {
    pub name: String,
    pub config: String,
    pub target: String,
    pub findings: Vec<SemgrepFinding>,
    pub files_examined: Vec<String>,
    pub files_failed: Vec<HashMap<String, String>>,
    pub semgrep_version: String,
    pub returncode: i32,
    pub stderr: String,
    pub sarif: String,
    pub json_output: String,
    pub elapsed_ms: i64,
    pub errors: Vec<String>,
}

impl SemgrepResult {
    /// Python: `returncode in (0, 1) and not self.errors`
    pub fn ok(&self) -> bool {
        (self.returncode == 0 || self.returncode == 1) && self.errors.is_empty()
    }

    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Serialise to a plain JSON object matching Python's `to_dict()`.
    pub fn to_dict(&self) -> serde_json::Value {
        let findings: Vec<serde_json::Value> = self.findings.iter().map(|f| f.to_dict()).collect();
        let files_failed: Vec<serde_json::Value> = self
            .files_failed
            .iter()
            .map(|m| serde_json::to_value(m).unwrap_or(serde_json::Value::Null))
            .collect();
        serde_json::json!({
            "name":             self.name,
            "config":           self.config,
            "target":           self.target,
            "findings":         findings,
            "files_examined":   self.files_examined,
            "files_failed":     files_failed,
            "semgrep_version":  self.semgrep_version,
            "returncode":       self.returncode,
            "elapsed_ms":       self.elapsed_ms,
            "errors":           self.errors,
        })
    }
}

// ── Internal output struct from parse_json_output ────────────────────────────

/// Internal struct returned by `parse_json_output`; mirrors the Python dict shape.
pub(crate) struct ParsedJsonOutput {
    pub files_examined: Vec<String>,
    pub files_failed: Vec<HashMap<String, String>>,
    pub semgrep_version: String,
}

// ── parse_sarif ───────────────────────────────────────────────────────────────

/// Parse SARIF JSON text into `SemgrepFinding` objects.
///
/// Returns an empty list on malformed or empty input — Semgrep sometimes emits
/// empty output on rule errors. Faithful port of Python `parse_sarif`.
pub fn parse_sarif(text: &str) -> Vec<SemgrepFinding> {
    if text.trim().is_empty() {
        return vec![];
    }
    let data: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut findings = Vec::new();

    // Python: runs = data.get("runs") or []
    let runs = match data.get("runs").and_then(|v| v.as_array()) {
        Some(r) => r.clone(),
        None => return findings,
    };

    for run in &runs {
        if !run.is_object() {
            continue;
        }
        // Python: results = run.get("results") or []
        let results = match run.get("results").and_then(|v| v.as_array()) {
            Some(r) => r.clone(),
            None => continue,
        };
        for result in &results {
            findings.push(SemgrepFinding::from_sarif_result(result));
        }
    }
    findings
}

// ── parse_json_output ─────────────────────────────────────────────────────────

/// Parse Semgrep's `--json-output` content for `paths.scanned`, `errors`, `version`.
///
/// Returns empty values on malformed or empty input. Faithful port of Python
/// `parse_json_output`. Note the key rename: semgrep's `errors[].message`
/// becomes `"reason"` in the returned `files_failed` entries.
pub(crate) fn parse_json_output(text: &str) -> ParsedJsonOutput {
    let empty = ParsedJsonOutput {
        files_examined: vec![],
        files_failed: vec![],
        semgrep_version: String::new(),
    };

    if text.trim().is_empty() {
        return empty;
    }
    let data: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return empty,
    };
    if !data.is_object() {
        return empty;
    }

    // Python: paths = data.get("paths") or {}
    //         scanned = paths.get("scanned") or []
    //         out["files_examined"] = sorted(str(p) for p in scanned if p)
    let scanned = data
        .get("paths")
        .and_then(|v| v.get("scanned"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut files_examined: Vec<String> = scanned
        .iter()
        .filter_map(|v| {
            let s = v.as_str().unwrap_or("").to_string();
            if s.is_empty() { None } else { Some(s) }
        })
        .collect();
    files_examined.sort();

    // Python: errors = data.get("errors") or []
    //         [{"path": str(e.get("path","")), "reason": str(e.get("message","error"))}
    //          for e in errors if isinstance(e, dict) and e.get("path")]
    let errors_arr = data
        .get("errors")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let files_failed: Vec<HashMap<String, String>> = errors_arr
        .iter()
        .filter_map(|e| {
            if !e.is_object() {
                return None;
            }
            let path = e.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path.is_empty() {
                return None;
            }
            // Python: str(e.get("message", "error"))
            let reason = e
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("error")
                .to_string();
            let mut m = HashMap::new();
            m.insert("path".to_string(), path.to_string());
            m.insert("reason".to_string(), reason);
            Some(m)
        })
        .collect();

    // Python: out["semgrep_version"] = str(data.get("version", ""))
    let semgrep_version = data
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    ParsedJsonOutput {
        files_examined,
        files_failed,
        semgrep_version,
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Mirrors Python `int(region.get(key, 0))`: converts JSON number or numeric
/// string to i64, returning 0 for missing/unparseable values.
fn value_to_i64(v: Option<&serde_json::Value>) -> i64 {
    match v {
        None => 0,
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}
