//! Python `str()` / `repr()` rendering of parsed config values.
//!
//! The trust scanners (`cc_trust`, `codeql_trust`) render finding values
//! through Python's `str()` / `repr()`. To keep the Rust port byte-for-byte
//! faithful in the rendered `value` field, we normalise both JSON
//! (`serde_json`) and YAML (`serde_yaml_ng`) into a single [`PyVal`] enum and
//! reproduce CPython's `str`/`repr` formatting on it.

use std::fmt::Write as _;

/// A Python-shaped value: mirrors the JSON/YAML node types that survive
/// `json.loads` / `yaml.safe_load` in the Python originals.
#[derive(Clone, Debug, PartialEq)]
pub enum PyVal {
    Str(String),
    Int(i64),
    /// Large unsigned ints that don't fit i64 (kept faithful to decimal repr).
    UInt(u64),
    Float(f64),
    Bool(bool),
    None,
    List(Vec<PyVal>),
    /// Ordered key/value pairs (Python dict preserves insertion order).
    Dict(Vec<(PyVal, PyVal)>),
}

impl PyVal {
    pub fn from_json(v: &serde_json::Value) -> PyVal {
        use serde_json::Value as J;
        match v {
            J::Null => PyVal::None,
            J::Bool(b) => PyVal::Bool(*b),
            J::Number(n) => {
                if let Some(i) = n.as_i64() {
                    PyVal::Int(i)
                } else if let Some(u) = n.as_u64() {
                    PyVal::UInt(u)
                } else {
                    PyVal::Float(n.as_f64().unwrap_or(0.0))
                }
            }
            J::String(s) => PyVal::Str(s.clone()),
            J::Array(a) => PyVal::List(a.iter().map(PyVal::from_json).collect()),
            J::Object(o) => PyVal::Dict(
                o.iter()
                    .map(|(k, val)| (PyVal::Str(k.clone()), PyVal::from_json(val)))
                    .collect(),
            ),
        }
    }

    pub fn from_yaml(v: &serde_yaml_ng::Value) -> PyVal {
        use serde_yaml_ng::Value as Y;
        match v {
            Y::Null => PyVal::None,
            Y::Bool(b) => PyVal::Bool(*b),
            Y::Number(n) => {
                if let Some(i) = n.as_i64() {
                    PyVal::Int(i)
                } else if let Some(u) = n.as_u64() {
                    PyVal::UInt(u)
                } else {
                    PyVal::Float(n.as_f64().unwrap_or(0.0))
                }
            }
            Y::String(s) => PyVal::Str(s.clone()),
            Y::Sequence(a) => PyVal::List(a.iter().map(PyVal::from_yaml).collect()),
            Y::Mapping(m) => PyVal::Dict(
                m.iter()
                    .map(|(k, val)| (PyVal::from_yaml(k), PyVal::from_yaml(val)))
                    .collect(),
            ),
            // serde_yaml_ng tagged values — render the inner value (best effort).
            Y::Tagged(t) => PyVal::from_yaml(&t.value),
        }
    }

    /// Python `str(value)`.
    pub fn py_str(&self) -> String {
        match self {
            PyVal::Str(s) => s.clone(),
            _ => self.py_repr(),
        }
    }

    /// Python `repr(value)`.
    pub fn py_repr(&self) -> String {
        match self {
            PyVal::Str(s) => repr_str(s),
            PyVal::Int(i) => i.to_string(),
            PyVal::UInt(u) => u.to_string(),
            PyVal::Float(f) => repr_float(*f),
            PyVal::Bool(b) => if *b { "True".into() } else { "False".into() },
            PyVal::None => "None".into(),
            PyVal::List(items) => {
                let mut out = String::from("[");
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&it.py_repr());
                }
                out.push(']');
                out
            }
            PyVal::Dict(pairs) => {
                let mut out = String::from("{");
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&k.py_repr());
                    out.push_str(": ");
                    out.push_str(&v.py_repr());
                }
                out.push('}');
                out
            }
        }
    }
}

/// CPython `repr()` of a `str`: pick a quote, escape backslash / the quote /
/// `\n` `\r` `\t`, and render other C0/C1 control chars as `\xNN`.
fn repr_str(s: &str) -> String {
    // CPython uses single quotes unless the string contains a single quote
    // and no double quote, in which case it switches to double quotes.
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };

    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Best-effort CPython `repr()` of a float. Integral finite floats render as
/// `N.0` (e.g. `1.0`); everything else uses Rust's shortest round-trip form,
/// which matches CPython for the common decimal cases seen in config files.
fn repr_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 {
        format!("{:.1}", f)
    } else if f.is_infinite() {
        if f > 0.0 { "inf".into() } else { "-inf".into() }
    } else if f.is_nan() {
        "nan".into()
    } else {
        format!("{}", f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn str_of_string_is_raw() {
        assert_eq!(PyVal::from_json(&json!("make")).py_str(), "make");
    }

    #[test]
    fn repr_of_string_is_quoted() {
        assert_eq!(PyVal::from_json(&json!("make")).py_repr(), "'make'");
    }

    #[test]
    fn repr_dict_matches_python() {
        // Python: repr({'run': 'make'}) == "{'run': 'make'}"
        let v = PyVal::from_json(&json!({"run": "make"}));
        assert_eq!(v.py_repr(), "{'run': 'make'}");
    }

    #[test]
    fn str_list_of_dict_matches_python() {
        // Python: str([{'run': 'make'}]) == "[{'run': 'make'}]"
        let v = PyVal::from_json(&json!([{"run": "make"}]));
        assert_eq!(v.py_str(), "[{'run': 'make'}]");
    }

    #[test]
    fn repr_empty_dict() {
        assert_eq!(PyVal::from_json(&json!({})).py_repr(), "{}");
    }

    #[test]
    fn bool_none_render() {
        assert_eq!(PyVal::from_json(&json!(true)).py_str(), "True");
        assert_eq!(PyVal::from_json(&json!(false)).py_str(), "False");
        assert_eq!(PyVal::from_json(&json!(null)).py_str(), "None");
    }

    #[test]
    fn quote_switch_on_apostrophe() {
        // Python: repr("a'b") == '"a\'b"' -> uses double quotes
        assert_eq!(PyVal::Str("a'b".into()).py_repr(), "\"a'b\"");
    }
}
