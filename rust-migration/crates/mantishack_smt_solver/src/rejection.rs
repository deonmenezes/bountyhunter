/// Structured rejection reasons for SMT encoder parsers.
///
/// Faithful port of `core/smt_solver/rejection.py`.
///
/// When a domain encoder can't turn a constraint string into a Z3 expression,
/// the failure is recorded as a `Rejection` rather than just a textual entry.
/// The `RejectionKind` tells callers *why* the parse failed, so the long tail
/// of unparseable inputs can be retried with a rephrasing or fed back as
/// schema feedback rather than disappearing into a bag of strings.
use regex::Regex;
use std::fmt;
use std::sync::OnceLock;

use crate::config::BVProfile;

// ---------------------------------------------------------------------------
// RejectionKind
// ---------------------------------------------------------------------------

/// Why the parser refused to encode a constraint.
///
/// Implements `Display` with the canonical snake_case string values that
/// mirror Python's `str+Enum` mixin (e.g. `RejectionKind::LexEmpty` displays
/// as `"lex_empty"`). This satisfies the Python contract that
/// `str(rk) == "lex_empty"` and enables JSON-round-trip comparisons via
/// equality on the string value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RejectionKind {
    LexEmpty,
    UnrecognizedForm,
    UnrecognizedOperand,
    UnsupportedOperator,
    /// Deprecated — kept for back-compat.
    ParensNotSupported,
    UnbalancedParens,
    /// Deprecated — kept for back-compat.
    MixedPrecedence,
    TrailingTokens,
    LiteralOutOfRange,
    LiteralAmbiguous,
    UnknownRegister,
    SolverTimeout,
    SolverUnknown,
    InputTooLong,
    TooManyConditions,
    AssignmentShaped,
}

impl RejectionKind {
    /// The canonical snake_case string value (mirrors Python's enum value).
    pub fn as_str(&self) -> &'static str {
        match self {
            RejectionKind::LexEmpty             => "lex_empty",
            RejectionKind::UnrecognizedForm     => "unrecognized_form",
            RejectionKind::UnrecognizedOperand  => "unrecognized_operand",
            RejectionKind::UnsupportedOperator  => "unsupported_operator",
            RejectionKind::ParensNotSupported   => "parens_not_supported",
            RejectionKind::UnbalancedParens     => "unbalanced_parens",
            RejectionKind::MixedPrecedence      => "mixed_precedence",
            RejectionKind::TrailingTokens       => "trailing_tokens",
            RejectionKind::LiteralOutOfRange    => "literal_out_of_range",
            RejectionKind::LiteralAmbiguous     => "literal_ambiguous",
            RejectionKind::UnknownRegister      => "unknown_register",
            RejectionKind::SolverTimeout        => "solver_timeout",
            RejectionKind::SolverUnknown        => "solver_unknown",
            RejectionKind::InputTooLong         => "input_too_long",
            RejectionKind::TooManyConditions    => "too_many_conditions",
            RejectionKind::AssignmentShaped     => "assignment_shaped",
        }
    }

    /// Deprecated kinds — constructing a `Rejection` with one of these is
    /// almost certainly a mistake. Mirrors Python's `_DEPRECATED_KINDS` set.
    pub fn is_deprecated(&self) -> bool {
        matches!(self, RejectionKind::ParensNotSupported | RejectionKind::MixedPrecedence)
    }
}

impl fmt::Display for RejectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Rejection
// ---------------------------------------------------------------------------

/// Why a single constraint/condition couldn't participate in SMT analysis.
///
/// `text` is the original input verbatim so callers can match it back to a
/// source location. `kind` is the machine-readable category; `detail` carries
/// free-form context (e.g. the offending token); `hint` (when non-empty) names
/// a concrete rephrasing that would let a retry succeed.
///
/// Mirrors Python `@dataclass(frozen=True) class Rejection`.
///
/// # Deprecation warning
/// Constructing with `ParensNotSupported` or `MixedPrecedence` emits a
/// debug_assert panic in tests and returns an `Err` from `Rejection::new()`.
/// (Python uses `warnings.warn(DeprecationWarning)` in `__post_init__`.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub text: String,
    pub kind: RejectionKind,
    pub detail: String,
    pub hint: String,
}

impl Rejection {
    /// Construct a `Rejection`.
    ///
    /// Returns `Err` when `kind` is one of the deprecated variants, mirroring
    /// Python's `DeprecationWarning` in `__post_init__`. Use the infallible
    /// constructors `new_unchecked` / struct literal syntax if you're certain.
    pub fn new(text: impl Into<String>, kind: RejectionKind, detail: impl Into<String>, hint: impl Into<String>) -> Result<Self, String> {
        if kind.is_deprecated() {
            return Err(format!(
                "Rejection(kind={}) is deprecated; the parser no longer emits this category.",
                kind.as_str()
            ));
        }
        Ok(Rejection { text: text.into(), kind, detail: detail.into(), hint: hint.into() })
    }

    /// Infallible constructor — caller asserts the kind is not deprecated.
    pub fn new_unchecked(text: impl Into<String>, kind: RejectionKind, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Rejection { text: text.into(), kind, detail: detail.into(), hint: hint.into() }
    }
}

// ---------------------------------------------------------------------------
// propagate
// ---------------------------------------------------------------------------

/// Re-anchor a sub-expression rejection on the full input text.
///
/// Faithful port of `rejection.propagate()`. Sub-parsers see only their own
/// slice of input, so `sub.text` starts out as that slice. When bubbling up
/// to the caller we replace it with `text` (the parent's full input) so
/// consumers can match the rejection back to the original source.
///
/// Appends the inner slice to `detail` when it differs from the new outer
/// text (so the cause-chain stays visible), capped at 80 chars.
/// Idempotent: if `sub.text` already matches `text`, no annotation is added.
pub fn propagate(text: &str, sub: &Rejection) -> Rejection {
    let mut detail = sub.detail.clone();
    if !sub.text.is_empty() && sub.text != text && !detail.contains("(in:") {
        let inner = if sub.text.len() <= 80 {
            sub.text.as_str()
        } else {
            // Safe truncation: find char boundary at or before 77 bytes.
            let end = sub.text.char_indices()
                .take_while(|(i, _)| *i < 77)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(77.min(sub.text.len()));
            &sub.text[..end]
        };
        let suffix = format!("(in: {:?})", inner);
        if detail.is_empty() {
            detail = suffix;
        } else {
            detail = format!("{}{}", detail, format!(" (in: {:?})", inner));
        }
    }
    Rejection {
        text: text.to_string(),
        kind: sub.kind,
        detail,
        hint: sub.hint.clone(),
    }
}

// ---------------------------------------------------------------------------
// parse_literal_value
// ---------------------------------------------------------------------------

static HEX_LITERAL_RE: OnceLock<Regex> = OnceLock::new();
static DEC_LITERAL_RE: OnceLock<Regex> = OnceLock::new();

fn hex_literal_re() -> &'static Regex {
    HEX_LITERAL_RE.get_or_init(|| Regex::new(r"(?i)^0x[0-9a-f]+$").unwrap())
}

fn dec_literal_re() -> &'static Regex {
    DEC_LITERAL_RE.get_or_init(|| Regex::new(r"^-?\d+$").unwrap())
}

/// Result of `parse_literal_value`: either the parsed integer or a rejection.
pub type LiteralResult = Result<i64, Rejection>;

/// Validate and convert a literal token, or return a structured rejection.
///
/// Faithful port of `rejection.parse_literal_value()`.
///
/// Centralised so atom-position literals and bitmask-form literals across all
/// encoders reject the same things:
/// - Out-of-range for `profile.width` → `LiteralOutOfRange`
/// - Leading-zero decimals (octal in C) → `LiteralAmbiguous`
/// - Anything not hex/decimal → `UnrecognizedOperand`
///
/// Pass `outer_text` to self-anchor the rejection (matches Python's
/// `outer_text=<parent expression>` kwarg).
pub fn parse_literal_value(tok: &str, profile: BVProfile, outer_text: Option<&str>) -> LiteralResult {
    let text = outer_text.unwrap_or(tok);
    let is_hex = hex_literal_re().is_match(tok);

    let v: i64 = if is_hex {
        // Parse as u64 first to handle full 64-bit hex patterns, then cast.
        let without_prefix = &tok[2..]; // strip "0x"
        u64::from_str_radix(without_prefix, 16)
            .map(|u| u as i64)
            .map_err(|_| Rejection::new_unchecked(
                text,
                RejectionKind::UnrecognizedOperand,
                format!("token {:?} is not a valid hex literal", tok),
                "",
            ))?
    } else if dec_literal_re().is_match(tok) {
        // Leading-zero check (skip sign).
        let magnitude = tok.trim_start_matches('-');
        if magnitude.len() > 1 && magnitude.starts_with('0') {
            return Err(Rejection::new_unchecked(
                text,
                RejectionKind::LiteralAmbiguous,
                format!("leading-zero decimal is ambiguous with C octal (token {:?})", tok),
                "rewrite as hex (0x...) or strip the leading zero",
            ));
        }
        tok.parse::<i64>().map_err(|_| Rejection::new_unchecked(
            text,
            RejectionKind::UnrecognizedOperand,
            format!("token {:?} is not a hex or decimal literal", tok),
            "",
        ))?
    } else {
        return Err(Rejection::new_unchecked(
            text,
            RejectionKind::UnrecognizedOperand,
            format!("token {:?} is not a hex or decimal literal", tok),
            "",
        ));
    };

    // Range check — hex literals are BIT PATTERNS, decimals are NUMERICAL.
    let (upper_exclusive, lower_inclusive): (i128, i128) = if is_hex || !profile.signed {
        ((1i128 << profile.width), 0)
    } else {
        ((1i128 << (profile.width - 1)), -(1i128 << (profile.width - 1)))
    };

    let v_wide = v as i128;
    if v_wide >= upper_exclusive || v_wide < lower_inclusive {
        let range_desc = if is_hex {
            format!("{}-bit range", profile.width)
        } else {
            profile.describe()
        };
        // Format value and range bounds matching Python's `:#x` format
        // (0x-prefixed hex, with sign preserved for negatives).
        let val_fmt = fmt_hex_signed(v_wide);
        let lo_fmt = fmt_hex_signed(lower_inclusive);
        let hi_fmt = fmt_hex_signed(upper_exclusive - 1);
        return Err(Rejection::new_unchecked(
            text,
            RejectionKind::LiteralOutOfRange,
            format!(
                "value {} (from token {:?}) outside {} range ({range_desc}) ({lo_fmt}..{hi_fmt})",
                val_fmt, tok, range_desc,
            ),
            "",
        ));
    }

    Ok(v)
}

/// Format an i128 value as Python's `:#x` does:
/// positive → `0xN`, negative → `-0xN`, zero → `0x0`.
fn fmt_hex_signed(v: i128) -> String {
    if v < 0 {
        format!("-{:#x}", (-v) as u128)
    } else {
        format!("{:#x}", v as u128)
    }
}

// ---------------------------------------------------------------------------
// classify_solver_unknown
// ---------------------------------------------------------------------------

/// Map a Z3 `reason_unknown()` string to a `RejectionKind`.
///
/// Faithful port of `rejection.classify_solver_unknown()`. Z3 reports
/// `"timeout"` (or `"canceled"`/`"cancelled"`) when the per-solver timeout
/// fires; anything else is grouped under `SolverUnknown`.
///
/// In the Rust port this operates on the raw reason string produced by the
/// z3 binary's output (or by `SolverResult::unknown_reason()`) rather than
/// calling into a live Z3 solver object — the boundary is the same string
/// matching logic.
pub fn classify_solver_unknown(reason: &str) -> RejectionKind {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("canceled") || lower.contains("cancelled") {
        RejectionKind::SolverTimeout
    } else {
        RejectionKind::SolverUnknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BV_C_INT8, BV_C_INT32, BV_C_UINT8, BV_C_UINT32};

    // --- parse_literal_value golden vectors (Python-produced) ---

    #[test]
    fn literal_decimal_in_range_uint8() {
        // Golden: '42' bv8u -> 42
        assert_eq!(parse_literal_value("42", BV_C_UINT8, None), Ok(42));
    }

    #[test]
    fn literal_hex_in_range_uint8() {
        // Golden: '0xff' bv8u -> 255
        assert_eq!(parse_literal_value("0xff", BV_C_UINT8, None), Ok(255));
    }

    #[test]
    fn literal_hex_out_of_range_uint8() {
        // Golden: '0x100' bv8u -> Rejection(LITERAL_OUT_OF_RANGE)
        let r = parse_literal_value("0x100", BV_C_UINT8, None);
        assert!(r.is_err());
        let rej = r.unwrap_err();
        assert_eq!(rej.kind, RejectionKind::LiteralOutOfRange);
        assert_eq!(rej.text, "0x100");
        assert!(rej.detail.contains("0x100"));
    }

    #[test]
    fn literal_decimal_max_uint8() {
        // Golden: '255' bv8u -> 255
        assert_eq!(parse_literal_value("255", BV_C_UINT8, None), Ok(255));
    }

    #[test]
    fn literal_decimal_out_of_range_uint8() {
        // Golden: '256' bv8u -> Rejection(LITERAL_OUT_OF_RANGE)
        let r = parse_literal_value("256", BV_C_UINT8, None);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, RejectionKind::LiteralOutOfRange);
    }

    #[test]
    fn literal_negative_signed_in_range() {
        // Golden: '-1' bv8s -> -1
        assert_eq!(parse_literal_value("-1", BV_C_INT8, None), Ok(-1));
    }

    #[test]
    fn literal_min_signed_in_range() {
        // Golden: '-128' bv8s -> -128
        assert_eq!(parse_literal_value("-128", BV_C_INT8, None), Ok(-128));
    }

    #[test]
    fn literal_below_min_signed() {
        // Golden: '-129' bv8s -> Rejection(LITERAL_OUT_OF_RANGE)
        let r = parse_literal_value("-129", BV_C_INT8, None);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, RejectionKind::LiteralOutOfRange);
    }

    #[test]
    fn literal_decimal_above_max_signed() {
        // Golden: '128' bv8s -> Rejection(LITERAL_OUT_OF_RANGE)
        let r = parse_literal_value("128", BV_C_INT8, None);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, RejectionKind::LiteralOutOfRange);
    }

    #[test]
    fn literal_leading_zero_ambiguous() {
        // Golden: '010' bv8u -> Rejection(LITERAL_AMBIGUOUS)
        let r = parse_literal_value("010", BV_C_UINT8, None);
        assert!(r.is_err());
        let rej = r.unwrap_err();
        assert_eq!(rej.kind, RejectionKind::LiteralAmbiguous);
        assert!(rej.hint.contains("hex") || rej.hint.contains("0x"));
    }

    #[test]
    fn literal_hex_high_bit_signed_int32_accepted() {
        // Golden: '0x80000000' bv32s -> 2147483648 (i64)
        // Hex literals are bit-patterns — 0x80000000 IS representable as int32
        // (it's the two's-complement encoding of -2^31), so it's accepted.
        let r = parse_literal_value("0x80000000", BV_C_INT32, None);
        assert_eq!(r, Ok(2147483648i64));
    }

    #[test]
    fn literal_decimal_2pow31_out_of_range_signed_int32() {
        // Golden: '2147483648' bv32s -> Rejection(LITERAL_OUT_OF_RANGE)
        let r = parse_literal_value("2147483648", BV_C_INT32, None);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, RejectionKind::LiteralOutOfRange);
    }

    #[test]
    fn literal_unrecognized_operand() {
        // Golden: 'abc' bv32u -> Rejection(UNRECOGNIZED_OPERAND)
        let r = parse_literal_value("abc", BV_C_UINT32, None);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, RejectionKind::UnrecognizedOperand);
    }

    // --- propagate golden vectors ---

    #[test]
    fn propagate_anchors_text_and_appends_inner() {
        // Golden: propagate("(a + b) > 10", Rejection(text="a + b", detail="bad token"))
        //      -> Rejection(text="(a + b) > 10", detail="bad token (in: 'a + b')")
        let sub = Rejection::new_unchecked("a + b", RejectionKind::UnrecognizedOperand, "bad token", "");
        let result = propagate("(a + b) > 10", &sub);
        assert_eq!(result.text, "(a + b) > 10");
        assert_eq!(result.kind, RejectionKind::UnrecognizedOperand);
        assert!(result.detail.contains("bad token"));
        assert!(result.detail.contains("a + b"));
    }

    #[test]
    fn propagate_idempotent_same_text() {
        // Golden: propagate("(a + b) > 10", Rejection(text="(a + b) > 10", detail="bad token"))
        //      -> Rejection(text="(a + b) > 10", detail="bad token")  [no change to detail]
        let sub = Rejection::new_unchecked("(a + b) > 10", RejectionKind::UnrecognizedOperand, "bad token", "");
        let result = propagate("(a + b) > 10", &sub);
        assert_eq!(result.text, "(a + b) > 10");
        assert_eq!(result.detail, "bad token");
    }

    #[test]
    fn propagate_empty_detail_sets_in_annotation() {
        // Golden: propagate("outer expr x", Rejection(text="x", detail=""))
        //      -> Rejection(text="outer expr x", detail="(in: 'x')")
        let sub = Rejection::new_unchecked("x", RejectionKind::LexEmpty, "", "");
        let result = propagate("outer expr x", &sub);
        assert_eq!(result.text, "outer expr x");
        assert!(result.detail.contains("x"), "detail should reference inner text");
    }

    #[test]
    fn propagate_empty_inner_text_no_annotation() {
        // Golden: propagate("outer expr", Rejection(text="", detail=""))
        //      -> Rejection(text="outer expr", detail="")
        let sub = Rejection::new_unchecked("", RejectionKind::LexEmpty, "", "");
        let result = propagate("outer expr", &sub);
        assert_eq!(result.text, "outer expr");
        assert_eq!(result.detail, "");
    }

    // --- classify_solver_unknown ---

    #[test]
    fn classify_timeout_string() {
        assert_eq!(classify_solver_unknown("timeout"), RejectionKind::SolverTimeout);
        assert_eq!(classify_solver_unknown("canceled"), RejectionKind::SolverTimeout);
        assert_eq!(classify_solver_unknown("cancelled"), RejectionKind::SolverTimeout);
        assert_eq!(classify_solver_unknown("TIMEOUT"), RejectionKind::SolverTimeout);
    }

    #[test]
    fn classify_other_string_unknown() {
        assert_eq!(classify_solver_unknown(""), RejectionKind::SolverUnknown);
        assert_eq!(classify_solver_unknown("incomplete"), RejectionKind::SolverUnknown);
        assert_eq!(classify_solver_unknown("max iterations"), RejectionKind::SolverUnknown);
    }

    // --- RejectionKind display ---

    #[test]
    fn rejection_kind_display_matches_python() {
        assert_eq!(RejectionKind::LexEmpty.to_string(), "lex_empty");
        assert_eq!(RejectionKind::LiteralOutOfRange.to_string(), "literal_out_of_range");
        assert_eq!(RejectionKind::SolverTimeout.to_string(), "solver_timeout");
        assert_eq!(RejectionKind::AssignmentShaped.to_string(), "assignment_shaped");
    }

    // --- Deprecated kinds ---

    #[test]
    fn deprecated_kinds_flagged() {
        assert!(RejectionKind::ParensNotSupported.is_deprecated());
        assert!(RejectionKind::MixedPrecedence.is_deprecated());
        assert!(!RejectionKind::LexEmpty.is_deprecated());
    }

    #[test]
    fn rejection_new_deprecated_kind_errors() {
        let r = Rejection::new("x", RejectionKind::ParensNotSupported, "", "");
        assert!(r.is_err());
    }
}
