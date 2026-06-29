//! Shared schema constants for vulnerability findings — faithful Rust rewrite of
//! `core/schema_constants/__init__.py`.
//!
//! Behavior-preserving: same inputs produce the same outputs, including the
//! deliberate case/whitespace handling in `normalise_vuln_type`.
//!
//! The optional `python` feature adds a PyO3 binding that re-exports
//! `normalise_vuln_type` and `needs_feasibility_analysis` under the same names.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Vulnerability type enum — single source of truth
// ---------------------------------------------------------------------------

pub const VULN_TYPES: &[&str] = &[
    "command_injection", "sql_injection", "xss", "path_traversal",
    "ssrf", "deserialization", "buffer_overflow", "heap_overflow",
    "stack_overflow", "format_string", "use_after_free", "double_free",
    "integer_overflow", "integer_underflow",
    "out_of_bounds_read", "out_of_bounds_write",
    "null_deref", "type_confusion", "memory_leak", "privilege_confusion",
    "race_condition", "uninitialized_memory",
    "hardcoded_secret", "weak_crypto", "other",
];

// ---------------------------------------------------------------------------
// Memory corruption types
// Stage E feasibility analysis applies to these; all others skip Stage E.
// ---------------------------------------------------------------------------

pub const MEMORY_CORRUPTION_TYPES: &[&str] = &[
    "buffer_overflow", "heap_overflow", "stack_overflow",
    "format_string", "use_after_free", "double_free",
    "integer_overflow", "integer_underflow",
    "out_of_bounds_read", "out_of_bounds_write",
    "null_deref", "type_confusion", "uninitialized_memory",
];

fn memory_corruption_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| MEMORY_CORRUPTION_TYPES.iter().copied().collect())
}

fn vuln_types_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| VULN_TYPES.iter().copied().collect())
}

// ---------------------------------------------------------------------------
// LLM alias → canonical vuln_type mapping
// LLMs produce varied names for the same vuln type; this maps common
// alternatives to the canonical VULN_TYPES enum values.
// ---------------------------------------------------------------------------

pub fn vuln_type_aliases() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        // Race condition / TOCTOU
        m.insert("toctou", "race_condition");
        m.insert("time_of_check_time_of_use", "race_condition");
        m.insert("time_of_check_to_time_of_use", "race_condition");
        m.insert("race", "race_condition");
        // Null dereference
        m.insert("null_pointer_dereference", "null_deref");
        m.insert("null_ptr_dereference", "null_deref");
        m.insert("null_dereference", "null_deref");
        m.insert("nullptr_deref", "null_deref");
        m.insert("null_pointer", "null_deref");
        m.insert("null_ptr_deref", "null_deref");
        m.insert("null_pointer_deref", "null_deref");
        // Buffer overflow
        m.insert("bof", "buffer_overflow");
        m.insert("stack_buffer_overflow", "buffer_overflow");
        m.insert("heap_buffer_overflow", "heap_overflow");
        m.insert("stack_bof", "stack_overflow");
        m.insert("heap_bof", "heap_overflow");
        // Use-after-free
        m.insert("uaf", "use_after_free");
        m.insert("use_after_free_read", "use_after_free");
        m.insert("use_after_free_write", "use_after_free");
        // Double free
        m.insert("double-free", "double_free");
        // Format string
        m.insert("fmt_string", "format_string");
        m.insert("format_string_bug", "format_string");
        m.insert("format_string_vulnerability", "format_string");
        m.insert("printf_vulnerability", "format_string");
        // XSS
        m.insert("cross_site_scripting", "xss");
        m.insert("reflected_xss", "xss");
        m.insert("stored_xss", "xss");
        m.insert("dom_xss", "xss");
        // SQL injection
        m.insert("sqli", "sql_injection");
        m.insert("sql_injection_blind", "sql_injection");
        // Command injection
        m.insert("os_command_injection", "command_injection");
        m.insert("cmd_injection", "command_injection");
        m.insert("shell_injection", "command_injection");
        m.insert("code_injection", "command_injection");
        // RCE → "other" (consequence classification, not root cause)
        m.insert("rce", "other");
        m.insert("remote_code_execution", "other");
        // Path traversal
        m.insert("directory_traversal", "path_traversal");
        m.insert("lfi", "path_traversal");
        m.insert("local_file_inclusion", "path_traversal");
        m.insert("file_inclusion", "path_traversal");
        // SSRF
        m.insert("server_side_request_forgery", "ssrf");
        // Integer overflow / underflow (distinct CWEs — see Python comments)
        m.insert("int_overflow", "integer_overflow");
        m.insert("int_underflow", "integer_underflow");
        m.insert("integer_wrap", "integer_overflow");
        // Out of bounds
        m.insert("oob_read", "out_of_bounds_read");
        m.insert("oob_write", "out_of_bounds_write");
        m.insert("out_of_bounds", "out_of_bounds_read");
        m.insert("stack_overread", "out_of_bounds_read");
        m.insert("heap_overread", "out_of_bounds_read");
        m.insert("buffer_over_read", "out_of_bounds_read");
        m.insert("buffer_overread", "out_of_bounds_read");
        // Deserialization
        m.insert("insecure_deserialization", "deserialization");
        m.insert("unsafe_deserialization", "deserialization");
        // Memory leak
        m.insert("information_leak", "memory_leak");
        m.insert("info_leak", "memory_leak");
        // Crypto
        m.insert("weak_cryptography", "weak_crypto");
        m.insert("insecure_crypto", "weak_crypto");
        // Type confusion
        m.insert("type_confusion_vulnerability", "type_confusion");
        // Uninitialized memory
        m.insert("uninitialized_variable", "uninitialized_memory");
        m.insert("uninitialized_read", "uninitialized_memory");
        // Privilege
        m.insert("privilege_escalation", "privilege_confusion");
        // Hardcoded secrets
        m.insert("hardcoded_credentials", "hardcoded_secret");
        m.insert("hardcoded_password", "hardcoded_secret");
        m.insert("embedded_secret", "hardcoded_secret");
        m
    })
}

// ---------------------------------------------------------------------------
// Severity, ruling, confidence, and false-positive reason constants
// ---------------------------------------------------------------------------

pub const SEVERITY_LEVELS: &[&str] = &["critical", "high", "medium", "low", "informational"];

/// Agentic ruling values (single-pass categorised verdict).
pub const AGENTIC_RULING_VALUES: &[&str] = &[
    "validated", "false_positive", "unreachable",
    "test_code", "dead_code", "mitigated",
];

/// Validate ruling values (multi-stage pipeline outcome).
pub const VALIDATE_RULING_VALUES: &[&str] = &["confirmed", "ruled_out", "exploitable"];

/// Confidence levels for LLM self-assessment.
pub const CONFIDENCE_LEVELS: &[&str] = &["high", "medium", "low"];

/// False-positive reason categories.
pub const FP_REASONS: &[&str] = &[
    "sanitized_input", "dead_code", "test_only",
    "unreachable_path", "safe_api_usage", "compiler_optimized",
    "defense_in_depth", "other",
];

// ---------------------------------------------------------------------------
// CWE ↔ vuln_type bidirectional mapping
// ---------------------------------------------------------------------------

/// CWE → vuln_type: used by orchestrator to classify SARIF findings.
pub fn cwe_to_vuln_type() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("CWE-20", "other");             // Improper input validation
        m.insert("CWE-22", "path_traversal");
        m.insert("CWE-77", "command_injection");  // Command injection (parent)
        m.insert("CWE-78", "command_injection");
        m.insert("CWE-79", "xss");
        m.insert("CWE-89", "sql_injection");
        m.insert("CWE-90", "other");             // LDAP injection
        m.insert("CWE-91", "other");             // XML injection
        m.insert("CWE-93", "other");             // CRLF injection
        m.insert("CWE-94", "command_injection");  // Code injection
        m.insert("CWE-119", "buffer_overflow");   // Generic buffer issue
        m.insert("CWE-120", "buffer_overflow");
        m.insert("CWE-121", "stack_overflow");
        m.insert("CWE-122", "heap_overflow");
        m.insert("CWE-125", "out_of_bounds_read");
        m.insert("CWE-129", "out_of_bounds_read"); // Improper validation of array index
        m.insert("CWE-131", "buffer_overflow");   // Incorrect calculation of buffer size
        m.insert("CWE-134", "format_string");
        m.insert("CWE-170", "buffer_overflow");   // Improper null termination
        m.insert("CWE-190", "integer_overflow");
        m.insert("CWE-191", "integer_underflow");
        m.insert("CWE-193", "buffer_overflow");   // Off-by-one error
        m.insert("CWE-200", "other");             // Information disclosure
        m.insert("CWE-209", "other");             // Sensitive info in error message
        m.insert("CWE-269", "privilege_confusion"); // Improper privilege management
        m.insert("CWE-285", "other");             // Improper authorization
        m.insert("CWE-287", "other");             // Improper authentication
        m.insert("CWE-295", "weak_crypto");       // Improper certificate validation
        m.insert("CWE-306", "other");             // Missing authentication
        m.insert("CWE-311", "weak_crypto");       // Missing encryption
        m.insert("CWE-319", "weak_crypto");       // Cleartext transmission
        m.insert("CWE-326", "weak_crypto");       // Inadequate encryption strength
        m.insert("CWE-327", "weak_crypto");
        m.insert("CWE-328", "weak_crypto");       // Weak hash
        m.insert("CWE-330", "weak_crypto");       // Insufficient randomness
        m.insert("CWE-352", "other");             // CSRF
        m.insert("CWE-362", "race_condition");
        m.insert("CWE-367", "race_condition");
        m.insert("CWE-369", "other");             // Divide by zero
        m.insert("CWE-400", "other");             // Resource exhaustion / DoS
        m.insert("CWE-401", "memory_leak");       // Missing release of memory
        m.insert("CWE-415", "double_free");
        m.insert("CWE-416", "use_after_free");
        m.insert("CWE-426", "path_traversal");    // Untrusted search path
        m.insert("CWE-434", "other");             // Unrestricted file upload
        m.insert("CWE-444", "other");             // HTTP request smuggling
        m.insert("CWE-457", "uninitialized_memory");
        m.insert("CWE-476", "null_deref");
        m.insert("CWE-489", "other");             // Active debug code
        m.insert("CWE-494", "other");             // Download without integrity check
        m.insert("CWE-502", "deserialization");
        m.insert("CWE-552", "path_traversal");    // Files accessible to external parties
        m.insert("CWE-601", "ssrf");              // URL redirect to untrusted site
        m.insert("CWE-611", "other");             // XXE
        m.insert("CWE-639", "other");             // Authorization bypass via user-controlled key
        m.insert("CWE-732", "other");             // Incorrect permission assignment
        m.insert("CWE-770", "other");             // Allocation without limits
        m.insert("CWE-787", "out_of_bounds_write");
        m.insert("CWE-798", "hardcoded_secret");
        m.insert("CWE-805", "buffer_overflow");   // Buffer access with incorrect length
        m.insert("CWE-820", "race_condition");    // Missing synchronization
        m.insert("CWE-822", "out_of_bounds_read"); // Untrusted pointer dereference
        m.insert("CWE-824", "uninitialized_memory"); // Access of uninitialized pointer
        m.insert("CWE-843", "type_confusion");
        m.insert("CWE-862", "other");             // Missing authorization
        m.insert("CWE-863", "other");             // Incorrect authorization
        m.insert("CWE-908", "uninitialized_memory"); // Use of uninitialized resource
        m.insert("CWE-918", "ssrf");
        m.insert("CWE-923", "weak_crypto");       // Improper restriction of comm. channel
        m.insert("CWE-1004", "other");            // Sensitive cookie missing HttpOnly
        m.insert("CWE-1188", "other");            // Insecure default initialization
        m.insert("CWE-1333", "other");            // Inefficient regex (ReDoS)
        m
    })
}

/// vuln_type → preferred CWE: used by agentic to infer CWE when LLM omits it.
/// Explicit — not derived from the forward mapping (multiple CWEs may share a vuln_type).
pub fn vuln_type_to_cwe() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("path_traversal", "CWE-22");
        m.insert("command_injection", "CWE-78");
        m.insert("xss", "CWE-79");
        m.insert("sql_injection", "CWE-89");
        m.insert("buffer_overflow", "CWE-120");
        m.insert("stack_overflow", "CWE-121");
        m.insert("heap_overflow", "CWE-122");
        m.insert("out_of_bounds_read", "CWE-125");
        m.insert("format_string", "CWE-134");
        m.insert("integer_overflow", "CWE-190");
        m.insert("integer_underflow", "CWE-191");
        m.insert("memory_leak", "CWE-401");
        m.insert("weak_crypto", "CWE-327");
        m.insert("race_condition", "CWE-367");
        m.insert("double_free", "CWE-415");
        m.insert("use_after_free", "CWE-416");
        m.insert("null_deref", "CWE-476");
        m.insert("deserialization", "CWE-502");
        m.insert("out_of_bounds_write", "CWE-787");
        m.insert("hardcoded_secret", "CWE-798");
        m.insert("type_confusion", "CWE-843");
        m.insert("ssrf", "CWE-918");
        m.insert("uninitialized_memory", "CWE-908");
        m.insert("privilege_confusion", "CWE-269");
        m
    })
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Normalize a vuln_type string to its canonical form.
///
/// Accepts LLM-friendly aliases (toctou, null_pointer_dereference, etc.)
/// and returns the canonical VULN_TYPES enum value. Returns the ORIGINAL
/// string (preserving casing/whitespace) if no alias is known and the value
/// isn't already canonical — matches the Python behavior exactly.
pub fn normalise_vuln_type(vuln_type: &str) -> String {
    if vuln_type.is_empty() {
        return vuln_type.to_string();
    }
    let lowered = vuln_type.to_lowercase();
    let lower = lowered.trim();
    if let Some(&canonical) = vuln_type_aliases().get(lower) {
        return canonical.to_string();
    }
    if vuln_types_set().contains(lower) {
        return lower.to_string();
    }
    // Unknown — preserve the caller's original string (case/whitespace intact).
    vuln_type.to_string()
}

/// Check if a vuln_type requires Stage E binary feasibility analysis.
/// Normalises first, then checks membership in MEMORY_CORRUPTION_TYPES.
pub fn needs_feasibility_analysis(vuln_type: &str) -> bool {
    let normalised = normalise_vuln_type(vuln_type);
    memory_corruption_set().contains(normalised.as_str())
}

// ---------------------------------------------------------------------------
// PyO3 Python bindings (feature = "python")
// ---------------------------------------------------------------------------

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;

    #[pyfunction]
    fn normalise_vuln_type(vuln_type: &str) -> String {
        super::normalise_vuln_type(vuln_type)
    }

    #[pyfunction]
    fn needs_feasibility_analysis(vuln_type: &str) -> bool {
        super::needs_feasibility_analysis(vuln_type)
    }

    #[pymodule]
    fn mantishack_core_schema_constants(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(normalise_vuln_type, m)?)?;
        m.add_function(wrap_pyfunction!(needs_feasibility_analysis, m)?)?;
        // Expose constant slices as Python lists (optional per spec).
        m.add("VULN_TYPES", super::VULN_TYPES.to_vec())?;
        m.add("MEMORY_CORRUPTION_TYPES", super::MEMORY_CORRUPTION_TYPES.to_vec())?;
        m.add("SEVERITY_LEVELS", super::SEVERITY_LEVELS.to_vec())?;
        m.add("AGENTIC_RULING_VALUES", super::AGENTIC_RULING_VALUES.to_vec())?;
        m.add("VALIDATE_RULING_VALUES", super::VALIDATE_RULING_VALUES.to_vec())?;
        m.add("CONFIDENCE_LEVELS", super::CONFIDENCE_LEVELS.to_vec())?;
        m.add("FP_REASONS", super::FP_REASONS.to_vec())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Invariant: every member of MEMORY_CORRUPTION_TYPES must appear in VULN_TYPES.
    /// Mirrors the Python module-level assertion (`_drift = MEMORY_CORRUPTION_TYPES -
    /// _VULN_TYPES_SET`) so any drift fails the test suite immediately.
    #[test]
    fn memory_corruption_subset_of_vuln_types() {
        let vt_set = vuln_types_set();
        for &mc in MEMORY_CORRUPTION_TYPES {
            assert!(
                vt_set.contains(mc),
                "MEMORY_CORRUPTION_TYPES drifted: {mc:?} not in VULN_TYPES — \
                 add to VULN_TYPES or remove from MEMORY_CORRUPTION_TYPES"
            );
        }
    }

    /// 18 golden cases generated by running the ORIGINAL Python module
    /// (core/schema_constants/__init__.py). Each row is
    /// (input, expected_normalise_output, expected_needs_feasibility).
    #[test]
    fn golden_parity() {
        let cases: &[(&str, &str, bool)] = &[
            // --- aliases ---
            ("toctou",                   "race_condition",    false),
            ("uaf",                      "use_after_free",    true),
            ("sqli",                     "sql_injection",     false),
            ("rce",                      "other",             false),
            ("null_pointer_dereference", "null_deref",        true),
            ("int_underflow",            "integer_underflow", true),
            ("int_overflow",             "integer_overflow",  true),
            ("heap_bof",                 "heap_overflow",     true),
            ("double-free",              "double_free",       true),
            ("cross_site_scripting",     "xss",               false),
            ("integer_wrap",             "integer_overflow",  true),
            // --- canonical (case-folded match) ---
            ("BUFFER_OVERFLOW",          "buffer_overflow",   true),
            ("buffer_overflow",          "buffer_overflow",   true),
            ("XSS",                      "xss",               false),
            ("xss",                      "xss",               false),
            ("heap_overflow",            "heap_overflow",     true),
            // --- unknown — original string preserved ---
            ("weird_custom",             "weird_custom",      false),
            // --- empty — returned as-is ---
            ("",                         "",                  false),
        ];
        for &(input, expected_norm, expected_feas) in cases {
            assert_eq!(
                normalise_vuln_type(input),
                expected_norm,
                "normalise_vuln_type({input:?})"
            );
            assert_eq!(
                needs_feasibility_analysis(input),
                expected_feas,
                "needs_feasibility_analysis({input:?})"
            );
        }
    }

    /// Verify CWE_TO_VULN_TYPE spot-checks.
    #[test]
    fn cwe_map_spot_checks() {
        let m = cwe_to_vuln_type();
        assert_eq!(m.get("CWE-79"),  Some(&"xss"));
        assert_eq!(m.get("CWE-89"),  Some(&"sql_injection"));
        assert_eq!(m.get("CWE-416"), Some(&"use_after_free"));
        assert_eq!(m.get("CWE-191"), Some(&"integer_underflow"));
        assert_eq!(m.get("CWE-787"), Some(&"out_of_bounds_write"));
    }

    /// Verify VULN_TYPE_TO_CWE round-trips the most common types.
    #[test]
    fn vuln_type_to_cwe_spot_checks() {
        let m = vuln_type_to_cwe();
        assert_eq!(m.get("buffer_overflow"),  Some(&"CWE-120"));
        assert_eq!(m.get("use_after_free"),   Some(&"CWE-416"));
        assert_eq!(m.get("memory_leak"),      Some(&"CWE-401"));
        assert_eq!(m.get("hardcoded_secret"), Some(&"CWE-798"));
        assert_eq!(m.get("privilege_confusion"), Some(&"CWE-269"));
    }

    /// All static constant slices are non-empty.
    #[test]
    fn constants_non_empty() {
        assert!(!VULN_TYPES.is_empty());
        assert!(!MEMORY_CORRUPTION_TYPES.is_empty());
        assert!(!SEVERITY_LEVELS.is_empty());
        assert!(!AGENTIC_RULING_VALUES.is_empty());
        assert!(!VALIDATE_RULING_VALUES.is_empty());
        assert!(!CONFIDENCE_LEVELS.is_empty());
        assert!(!FP_REASONS.is_empty());
    }
}
