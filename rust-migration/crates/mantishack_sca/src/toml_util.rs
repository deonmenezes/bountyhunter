//! Shared TOML helpers for the TOML-based SCA parsers.

use serde_json::Value;

/// Parse TOML text into a `serde_json::Value` (tables -> objects, arrays ->
/// arrays), or `None` on a TOML syntax error — so the rest of each parser can
/// traverse it with the same `serde_json` patterns as the JSON parsers.
pub fn parse_toml(content: &str) -> Option<Value> {
    let tv: toml::Value = toml::from_str(content).ok()?;
    serde_json::to_value(tv).ok()
}

/// Python truthiness for a JSON value (used by `X or Y` fallback chains).
pub fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}
