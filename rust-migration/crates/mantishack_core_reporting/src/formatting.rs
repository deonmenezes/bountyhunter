//! Shared formatting utilities for report rendering.

use serde_json::Value;

/// CPython `str.title()`: titlecase the first letter of each maximal run of
/// letters, lowercase the rest.
fn py_title(s: &str) -> String {
    let mut out = String::new();
    let mut prev_cased = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            if prev_cased {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_cased = true;
        } else {
            out.push(c);
            prev_cased = false;
        }
    }
    out
}

/// Python `str(x)` for a JSON scalar (used for `error_type` / non-dict ruling).
fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Coerce a possibly-string-encoded boolean, else `None` (`_coerce_bool`).
fn coerce_bool(v: Option<&Value>) -> Option<bool> {
    match v {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => match s.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn status_map(status: &str) -> Option<&'static str> {
    Some(match status {
        "exploitable" => "Exploitable",
        "confirmed" => "Confirmed",
        "confirmed_constrained" => "Confirmed (Constrained)",
        "confirmed_blocked" => "Confirmed (Blocked)",
        "ruled_out" => "Ruled Out",
        "false_positive" => "False Positive",
        "poc_success" => "Exploitable",
        "not_disproven" => "Unconfirmed",
        "disproven" => "Ruled Out",
        "validated" => "Confirmed",
        "test_code" => "Ruled Out",
        "dead_code" => "Ruled Out",
        "mitigated" => "Ruled Out",
        "unreachable" => "Ruled Out",
        _ => return None,
    })
}

/// Derive a human-readable display status from a finding dict
/// (`get_display_status`).
pub fn get_display_status(finding: &Value) -> String {
    let Some(obj) = finding.as_object() else {
        return "Unknown".to_string();
    };

    if obj.contains_key("error") {
        let error_type = obj.get("error_type").map(py_str).unwrap_or_else(|| "unknown".to_string());
        return format!("Error ({error_type})");
    }

    if obj.contains_key("is_true_positive") || obj.contains_key("is_exploitable") {
        let tp = coerce_bool(obj.get("is_true_positive"));
        let ex = coerce_bool(obj.get("is_exploitable"));
        if tp == Some(false) {
            return "False Positive".to_string();
        }
        if ex == Some(true) {
            return "Exploitable".to_string();
        }
        if tp == Some(true) {
            return "Confirmed".to_string();
        }
    }

    let mut status = obj.get("final_status").and_then(Value::as_str).unwrap_or("").to_string();
    if status.is_empty() {
        match obj.get("ruling") {
            Some(Value::Object(r)) => {
                status = r.get("status").and_then(Value::as_str).unwrap_or("").to_string();
            }
            Some(other) => {
                // str(ruling) if ruling else "".
                status = if json_truthy(other) { py_str(other) } else { String::new() };
            }
            None => {}
        }
    }
    if status.is_empty() {
        status = obj.get("status").and_then(Value::as_str).unwrap_or("").to_string();
    }

    if let Some(mapped) = status_map(&status) {
        mapped.to_string()
    } else if status.is_empty() {
        "Unknown".to_string()
    } else {
        py_title(&status.replace('_', " "))
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

fn display_name(vuln_type: &str) -> Option<&'static str> {
    Some(match vuln_type {
        "null_deref" => "Null Pointer Dereference",
        "xss" => "Cross-Site Scripting",
        "ssrf" => "Server-Side Request Forgery",
        "csrf" => "Cross-Site Request Forgery",
        "xxe" => "XML External Entity",
        "rce" => "Remote Code Execution",
        "lfi" => "Local File Inclusion",
        "rfi" => "Remote File Inclusion",
        "idor" => "Insecure Direct Object Reference",
        "sca" => "Software Composition Analysis",
        "weak_crypto" => "Weak Cryptography",
        "sql_injection" => "SQL Injection",
        "out_of_bounds_read" => "Out-of-Bounds Read",
        "out_of_bounds_write" => "Out-of-Bounds Write",
        _ => return None,
    })
}

/// Convert a snake_case vuln_type to a human-readable display name
/// (`title_case_type`).
pub fn title_case_type(vuln_type: &str) -> String {
    if vuln_type.is_empty() {
        return "\u{2014}".to_string(); // em dash
    }
    display_name(vuln_type).map(str::to_string).unwrap_or_else(|| py_title(&vuln_type.replace('_', " ")))
}

/// Truncate a long path with a `...` prefix (`truncate_path`). Char-count based,
/// matching the ASCII fast path and the wcwidth-absent slow-path fallback (full
/// wide-char display-width fidelity would need a wcwidth port).
pub fn truncate_path(path: &str, max_len: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() > max_len {
        let tail: String = chars[chars.len() - (max_len - 3)..].iter().collect();
        format!("...{tail}")
    } else {
        path.to_string()
    }
}

/// Format seconds as a human-readable duration (`format_elapsed`).
pub fn format_elapsed(seconds: f64) -> String {
    if seconds < 60.0 {
        return format!("{seconds:.0}s");
    }
    let minutes = (seconds / 60.0).floor() as i64;
    let secs = (seconds % 60.0) as i64;
    if minutes < 60 {
        return format!("{minutes}m {secs}s");
    }
    let hours = minutes / 60;
    let mins = minutes % 60;
    format!("{hours}h {mins}m")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn display_status() {
        assert_eq!(get_display_status(&json!({"error": "boom", "error_type": "Timeout"})), "Error (Timeout)");
        assert_eq!(get_display_status(&json!({"error": "x"})), "Error (unknown)");
        assert_eq!(get_display_status(&json!({"is_true_positive": false})), "False Positive");
        assert_eq!(get_display_status(&json!({"is_exploitable": true})), "Exploitable");
        assert_eq!(get_display_status(&json!({"is_true_positive": true})), "Confirmed");
        // String-encoded booleans coerced.
        assert_eq!(get_display_status(&json!({"is_exploitable": "false"})), "Unknown");
        assert_eq!(get_display_status(&json!({"is_exploitable": "yes"})), "Exploitable");
        assert_eq!(get_display_status(&json!({"final_status": "confirmed_constrained"})), "Confirmed (Constrained)");
        assert_eq!(get_display_status(&json!({"ruling": {"status": "disproven"}})), "Ruled Out");
        assert_eq!(get_display_status(&json!({"ruling": "poc_success"})), "Exploitable");
        assert_eq!(get_display_status(&json!({"status": "not_disproven"})), "Unconfirmed");
        assert_eq!(get_display_status(&json!({"status": "some_new_thing"})), "Some New Thing");
        assert_eq!(get_display_status(&json!({})), "Unknown");
    }

    #[test]
    fn type_names_and_durations() {
        assert_eq!(title_case_type("xss"), "Cross-Site Scripting");
        assert_eq!(title_case_type("sql_injection"), "SQL Injection");
        assert_eq!(title_case_type("some_new_type"), "Some New Type");
        assert_eq!(title_case_type(""), "\u{2014}");

        assert_eq!(format_elapsed(5.0), "5s");
        assert_eq!(format_elapsed(45.7), "46s");
        assert_eq!(format_elapsed(60.0), "1m 0s");
        assert_eq!(format_elapsed(90.0), "1m 30s");
        assert_eq!(format_elapsed(3600.0), "1h 0m");
        assert_eq!(format_elapsed(3725.0), "1h 2m");
        assert_eq!(format_elapsed(7325.0), "2h 2m");
    }

    #[test]
    fn path_truncation() {
        assert_eq!(truncate_path(&"a".repeat(50), 40), format!("...{}", "a".repeat(37)));
        assert_eq!(truncate_path("short.py", 40), "short.py");
        assert_eq!(truncate_path("/very/long/path/to/some/deeply/nested/file.py", 30), ".../some/deeply/nested/file.py");
    }
}
