//! A byte-compatible re-implementation of CPython's `json.dumps` for the
//! subset the dataflow models emit — `ensure_ascii=True`, the compact
//! `(", ", ": ")` separators, and `indent=N` pretty-printing.

use serde_json::Value;

/// Encode a string like CPython `py_encode_basestring_ascii`.
fn encode_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) <= 0x1f => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) > 0x7e => {
                let cp = c as u32;
                if cp > 0xffff {
                    let v = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)));
                } else {
                    out.push_str(&format!("\\u{:04x}", cp));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn fmt(v: &Value, indent: Option<usize>, level: usize, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => encode_str(s, out),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                sep(indent, level, i, out);
                fmt(item, indent, level + 1, out);
            }
            close(indent, level, out);
            out.push(']');
        }
        Value::Object(o) => {
            if o.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in o.iter().enumerate() {
                sep(indent, level, i, out);
                encode_str(k, out);
                out.push_str(": ");
                fmt(val, indent, level + 1, out);
            }
            close(indent, level, out);
            out.push('}');
        }
    }
}

fn sep(indent: Option<usize>, level: usize, i: usize, out: &mut String) {
    match indent {
        None => {
            if i > 0 {
                out.push_str(", ");
            }
        }
        Some(n) => {
            if i > 0 {
                out.push(',');
            }
            out.push('\n');
            out.push_str(&" ".repeat(n * (level + 1)));
        }
    }
}

fn close(indent: Option<usize>, level: usize, out: &mut String) {
    if let Some(n) = indent {
        out.push('\n');
        out.push_str(&" ".repeat(n * level));
    }
}

/// `json.dumps(v, indent=indent)` for the emitted subset.
pub fn dumps(v: &Value, indent: Option<usize>) -> String {
    let mut out = String::new();
    fmt(v, indent, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compact_and_indent() {
        let v = json!({"a": 1, "b": [1, 2], "c": null});
        assert_eq!(dumps(&v, None), r#"{"a": 1, "b": [1, 2], "c": null}"#);
        assert_eq!(dumps(&v, Some(2)), "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2\n  ],\n  \"c\": null\n}");
        assert_eq!(dumps(&json!({}), None), "{}");
        assert_eq!(dumps(&json!([]), Some(2)), "[]");
    }

    #[test]
    fn ensure_ascii() {
        // Non-ASCII is escaped to \uXXXX (ensure_ascii=True).
        assert_eq!(dumps(&json!("café"), None), "\"caf\\u00e9\"");
        assert_eq!(dumps(&json!("a\tb\n"), None), "\"a\\tb\\n\"");
        assert_eq!(dumps(&json!("😀"), None), "\"\\ud83d\\ude00\""); // surrogate pair
    }
}
