/// Z3 model → concrete value conversion with signed-bitvector reinterpretation.
///
/// Faithful port of `core/smt_solver/witness.py`.
///
/// A bitvector with the high bit set, extracted under signed semantics, still
/// comes out as a raw unsigned integer. MANTISHACK reports witnesses the way a
/// human reads the C value, so these helpers reinterpret high-bit-set values as
/// two's-complement negatives when `signed=true`.
///
/// # Z3 boundary
/// `format_witness` and `format_vars` in Python read live Z3 model objects.
/// In Rust those are replaced by `parse_z3_model()` which parses the textual
/// model output emitted by the `z3` binary. The public `bv_to_int` is a pure
/// arithmetic function, fully testable without Z3.
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// bv_to_int
// ---------------------------------------------------------------------------

/// Reinterpret an `as_long()` result as two's-complement when `signed`.
///
/// Faithful port of `witness.bv_to_int()`. `raw` must be in `[0, 2^width)`.
///
/// # Errors
/// - `width == 0` → `Err("width must be positive")`
/// - `raw < 0` → `Err("raw out of range")`
/// - `raw >= 2^width` → `Err("raw out of range")`
pub fn bv_to_int(raw: i64, width: u32, signed: bool) -> Result<i64, String> {
    if width == 0 {
        return Err(format!(
            "bv_to_int: width={} must be positive (degenerate decl?)",
            width
        ));
    }
    if raw < 0 {
        return Err(format!(
            "bv_to_int: raw={} out of range [0, {}) for width={}",
            raw,
            1i64.checked_shl(width).unwrap_or(i64::MAX),
            width
        ));
    }
    // For width >= 63 we need u128 arithmetic to avoid overflow.
    let upper = 1u128 << width;
    if (raw as u128) >= upper {
        return Err(format!(
            "bv_to_int: raw={} out of range [0, {}) for width={}",
            raw, upper, width
        ));
    }
    if signed && (raw as u128) >= (upper >> 1) {
        // Two's-complement reinterpretation: raw - 2^width
        Ok(raw - upper as i64)
    } else {
        Ok(raw)
    }
}

// ---------------------------------------------------------------------------
// parse_z3_model
// ---------------------------------------------------------------------------

/// Parse a Z3 binary model output string into `{name → int}`.
///
/// The z3 binary outputs models in SMT-LIB2 form:
/// ```text
/// (model
///   (define-fun x () (_ BitVec 32) (_ bv42 32))
///   (define-fun y () (_ BitVec 8) (_ bv128 8))
/// )
/// ```
///
/// Each `(_ bv<N> <W>)` value is extracted and passed through `bv_to_int`
/// with the per-variable signedness from `signed`. Variables with non-bitvector
/// values are silently skipped (mirrors Python's `if not z3.is_bv_value(val): continue`).
///
/// Collision detection: if the model contains two decls with the same name
/// (possible in push/pop traces), the second gets a `__1`, `__2` suffix —
/// mirrors Python's disambiguation suffix logic in `format_witness`.
pub fn parse_z3_model(
    model_output: &str,
    signed: &SignednessMap,
) -> HashMap<String, i64> {
    let mut out: HashMap<String, i64> = HashMap::new();
    // Match: (define-fun <name> () (_ BitVec <width>) (_ bv<value> <width>))
    // The regex captures name, width, value.
    use std::sync::OnceLock;
    use regex::Regex;

    static RE_DEFINE: OnceLock<Regex> = OnceLock::new();
    let re = RE_DEFINE.get_or_init(|| {
        Regex::new(
            r"\(define-fun\s+(\S+)\s+\(\)\s+\(_\s+BitVec\s+(\d+)\)\s+\(_\s+bv(\d+)\s+\d+\)\)"
        ).unwrap()
    });

    for cap in re.captures_iter(model_output) {
        let name = cap[1].to_string();
        let width: u32 = cap[2].parse().unwrap_or(0);
        let raw: i64 = cap[3].parse().unwrap_or(0);
        if width == 0 { continue; }

        let s = resolve_signedness(&name, signed);
        let v = match bv_to_int(raw, width, s) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Collision detection with disambiguating suffix.
        if out.contains_key(&name) {
            let mut suffix = 1usize;
            loop {
                let candidate = format!("{}__{}", name, suffix);
                if !out.contains_key(&candidate) {
                    out.insert(candidate, v);
                    break;
                }
                suffix += 1;
            }
        } else {
            out.insert(name, v);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SignednessMap — mirrors Python's `Union[bool, Mapping[str, bool]]`
// ---------------------------------------------------------------------------

/// Signedness specification: either uniform for all variables or per-variable.
///
/// Mirrors Python's `Union[bool, Mapping[str, bool]]` parameter to
/// `format_witness` / `format_vars`.
pub enum SignednessMap {
    /// Uniform signedness for every decl (legacy callers).
    Uniform(bool),
    /// Per-decl override; unmapped names fall back to `false` (unsigned).
    PerVar(HashMap<String, bool>),
}

fn resolve_signedness(name: &str, signed: &SignednessMap) -> bool {
    match signed {
        SignednessMap::Uniform(b) => *b,
        SignednessMap::PerVar(map) => *map.get(name).unwrap_or(&false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- bv_to_int golden vectors (Python-produced) ---

    #[test]
    fn bv_to_int_zero_unsigned_8() {
        // Golden: bv_to_int(0, 8, False) -> 0
        assert_eq!(bv_to_int(0, 8, false), Ok(0));
    }

    #[test]
    fn bv_to_int_max_unsigned_8() {
        // Golden: bv_to_int(255, 8, False) -> 255
        assert_eq!(bv_to_int(255, 8, false), Ok(255));
    }

    #[test]
    fn bv_to_int_high_bit_signed_8() {
        // Golden: bv_to_int(128, 8, True) -> -128
        assert_eq!(bv_to_int(128, 8, true), Ok(-128));
    }

    #[test]
    fn bv_to_int_max_signed_8() {
        // Golden: bv_to_int(127, 8, True) -> 127
        assert_eq!(bv_to_int(127, 8, true), Ok(127));
    }

    #[test]
    fn bv_to_int_zero_unsigned_32() {
        // Golden: bv_to_int(0, 32, False) -> 0
        assert_eq!(bv_to_int(0, 32, false), Ok(0));
    }

    #[test]
    fn bv_to_int_min_signed_32() {
        // Golden: bv_to_int(2147483648, 32, True) -> -2147483648
        assert_eq!(bv_to_int(2147483648, 32, true), Ok(-2147483648));
    }

    #[test]
    fn bv_to_int_max_unsigned_32() {
        // Golden: bv_to_int(4294967295, 32, False) -> 4294967295
        assert_eq!(bv_to_int(4294967295, 32, false), Ok(4294967295));
    }

    #[test]
    fn bv_to_int_negative_raw_errors() {
        // Golden: bv_to_int(-1, 8, False) -> ValueError
        assert!(bv_to_int(-1, 8, false).is_err());
    }

    #[test]
    fn bv_to_int_out_of_range_errors() {
        // Golden: bv_to_int(256, 8, False) -> ValueError
        assert!(bv_to_int(256, 8, false).is_err());
    }

    #[test]
    fn bv_to_int_zero_width_errors() {
        // Golden: bv_to_int(0, 0, False) -> ValueError
        let r = bv_to_int(0, 0, false);
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("width"));
        assert!(msg.contains("positive"));
    }

    // --- parse_z3_model ---

    #[test]
    fn parse_z3_model_basic() {
        let model = r"(model
  (define-fun x () (_ BitVec 32) (_ bv42 32))
  (define-fun y () (_ BitVec 8) (_ bv128 8))
)";
        let signed = SignednessMap::PerVar({
            let mut m = HashMap::new();
            m.insert("y".to_string(), true);
            m
        });
        let result = parse_z3_model(model, &signed);
        assert_eq!(result.get("x"), Some(&42i64));
        // y=128 with signed int8 → -128
        assert_eq!(result.get("y"), Some(&-128i64));
    }

    #[test]
    fn parse_z3_model_empty() {
        let model = "(model\n)\n";
        let result = parse_z3_model(model, &SignednessMap::Uniform(false));
        assert!(result.is_empty());
    }

    #[test]
    fn parse_z3_model_collision_disambiguation() {
        // Two variables that both stringify to "x" would collide; the parser
        // can't produce this from z3 binary output (names are unique per define-fun),
        // but the disambiguation code path is tested by constructing a model
        // string with two define-fun blocks for "x".
        let model = "(model\n  (define-fun x () (_ BitVec 8) (_ bv10 8))\n  (define-fun x () (_ BitVec 8) (_ bv20 8))\n)\n";
        let result = parse_z3_model(model, &SignednessMap::Uniform(false));
        // First occurrence keeps the bare name, second gets __1 suffix.
        assert!(result.contains_key("x"));
        assert!(result.contains_key("x__1"));
    }
}
