//! Data models for Coccinelle results — faithful port of
//! `packages/coccinelle/models.py` (`SpatchMatch`, `SpatchResult`).

use serde_json::{json, Map, Value};

/// Coerce a JSON value to an integer the way Python's `int(...)` does for the
/// shapes that appear in spatch output: a JSON number truncates toward zero, a
/// numeric string parses, anything else (or absent) falls back to `default`.
fn coerce_int(v: Option<&Value>, default: i64) -> i64 {
    match v {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(f) = n.as_f64() {
                f.trunc() as i64
            } else {
                default
            }
        }
        Some(Value::String(s)) => s.trim().parse::<i64>().unwrap_or(default),
        _ => default,
    }
}

fn get_str(d: &Map<String, Value>, key: &str) -> String {
    match d.get(key) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// A single match from a Coccinelle rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpatchMatch {
    pub file: String,
    pub line: i64,
    pub column: i64,
    pub line_end: i64,
    pub column_end: i64,
    pub rule: String,
    pub message: String,
}

impl SpatchMatch {
    /// Mirrors `SpatchMatch.from_dict`: a `None`/non-object input yields the
    /// empty match (`file=""`, `line=0`); `col`/`col_end` take precedence over
    /// `column`/`column_end`.
    pub fn from_dict(d: Option<&Value>) -> SpatchMatch {
        let map = match d {
            Some(Value::Object(m)) => m,
            _ => return SpatchMatch::default(),
        };
        SpatchMatch {
            file: get_str(map, "file"),
            line: coerce_int(map.get("line"), 0),
            column: coerce_int(map.get("col").or_else(|| map.get("column")), 0),
            line_end: coerce_int(map.get("line_end"), 0),
            column_end: coerce_int(map.get("col_end").or_else(|| map.get("column_end")), 0),
            rule: get_str(map, "rule"),
            message: get_str(map, "message"),
        }
    }

    /// Mirrors `SpatchMatch.to_dict` — fixed key order.
    pub fn to_dict(&self) -> Value {
        json!({
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "line_end": self.line_end,
            "column_end": self.column_end,
            "rule": self.rule,
            "message": self.message,
        })
    }
}

/// Results from running a single Coccinelle rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpatchResult {
    pub rule: String,
    pub rule_path: String,
    pub matches: Vec<SpatchMatch>,
    pub files_examined: Vec<String>,
    pub errors: Vec<String>,
    pub elapsed_ms: i64,
    pub returncode: i64,
}

impl SpatchResult {
    /// `returncode == 0` and no errors.
    pub fn ok(&self) -> bool {
        self.returncode == 0 && self.errors.is_empty()
    }

    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Mirrors `SpatchResult.to_dict` — fixed key order.
    pub fn to_dict(&self) -> Value {
        let matches: Vec<Value> = self.matches.iter().map(SpatchMatch::to_dict).collect();
        json!({
            "rule": self.rule,
            "rule_path": self.rule_path,
            "matches": matches,
            "files_examined": self.files_examined,
            "errors": self.errors,
            "elapsed_ms": self.elapsed_ms,
            "returncode": self.returncode,
        })
    }
}
