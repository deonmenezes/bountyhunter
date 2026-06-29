/// Width-parametric bitvector helpers — SMT-LIB2 term construction.
///
/// Faithful port of `core/smt_solver/bitvec.py`.
///
/// Python's `bitvec.py` returns in-process Z3 BitVec expression objects.
/// In Rust, the external-seam design (Z3 invoked as a subprocess via SMT-LIB2)
/// means these helpers instead construct SMT-LIB2 expression strings.
///
/// # Mapping
/// | Python | Rust |
/// |--------|------|
/// | `z3.BitVec(name, w)` | `mk_var(name, w)` → named variable term |
/// | `z3.BitVecVal(v, w)` | `mk_val(v, w)` → SMT-LIB2 `(_ bvN W)` |
/// | `le(a, b, signed)` | `le(&a, &b, signed)` → comparison term |
/// | … | … |
///
/// The `SmtTerm` wrapper carries both the expression string and the bit width
/// so callers don't need to thread width separately through comparison builders.

/// An SMT-LIB2 bitvector term: an expression string and its bit width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtTerm {
    /// SMT-LIB2 expression (ready to embed in `assert`, `=`, etc.).
    pub expr: String,
    /// Bit width of this term.
    pub width: u32,
}

/// Create a named bitvector variable term.
///
/// Mirrors `z3.BitVec(name, width)`. The caller is responsible for emitting
/// the declaration `(declare-const <name> (_ BitVec <width>))` into the
/// solver's SMT-LIB2 input (via `SolverSession::add`).
pub fn mk_var(name: &str, width: u32) -> SmtTerm {
    SmtTerm {
        expr: name.to_string(),
        width,
    }
}

/// Create the SMT-LIB2 declaration statement for a named bitvector variable.
///
/// Emit this into the `SolverSession` before using the `SmtTerm` from `mk_var`.
pub fn mk_var_decl(name: &str, width: u32) -> String {
    format!("(declare-const {} (_ BitVec {}))", name, width)
}

/// Create a bitvector literal term.
///
/// Mirrors `z3.BitVecVal(v, width)`. `v` is treated as an unsigned bit
/// pattern — if `v` is negative, its two's-complement representation at
/// `width` bits is used (matches Python's `z3.BitVecVal` behaviour which
/// also accepts negative values via masking).
///
/// Output: `(_ bvN W)` where N is the unsigned integer value.
pub fn mk_val(v: i64, width: u32) -> SmtTerm {
    let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
    let unsigned = (v as u64) & mask;
    SmtTerm {
        expr: format!("(_ bv{} {})", unsigned, width),
        width,
    }
}

/// Less-than-or-equal: `a <= b`.
///
/// Mirrors `bitvec.le(a, b, signed)`.
/// Signed → SMT-LIB2 `bvsle`; unsigned → `bvule`.
pub fn le(a: &SmtTerm, b: &SmtTerm, signed: bool) -> String {
    if signed {
        format!("(bvsle {} {})", a.expr, b.expr)
    } else {
        format!("(bvule {} {})", a.expr, b.expr)
    }
}

/// Less-than: `a < b`.
///
/// Mirrors `bitvec.lt(a, b, signed)`.
/// Signed → `bvslt`; unsigned → `bvult`.
pub fn lt(a: &SmtTerm, b: &SmtTerm, signed: bool) -> String {
    if signed {
        format!("(bvslt {} {})", a.expr, b.expr)
    } else {
        format!("(bvult {} {})", a.expr, b.expr)
    }
}

/// Greater-than-or-equal: `a >= b`.
///
/// Mirrors `bitvec.ge(a, b, signed)`.
/// Signed → `bvsge`; unsigned → `bvuge`.
pub fn ge(a: &SmtTerm, b: &SmtTerm, signed: bool) -> String {
    if signed {
        format!("(bvsge {} {})", a.expr, b.expr)
    } else {
        format!("(bvuge {} {})", a.expr, b.expr)
    }
}

/// Greater-than: `a > b`.
///
/// Mirrors `bitvec.gt(a, b, signed)`.
/// Signed → `bvsgt`; unsigned → `bvugt`.
pub fn gt(a: &SmtTerm, b: &SmtTerm, signed: bool) -> String {
    if signed {
        format!("(bvsgt {} {})", a.expr, b.expr)
    } else {
        format!("(bvugt {} {})", a.expr, b.expr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mk_var_produces_named_term() {
        let t = mk_var("count", 32);
        assert_eq!(t.expr, "count");
        assert_eq!(t.width, 32);
    }

    #[test]
    fn mk_var_decl_format() {
        assert_eq!(mk_var_decl("count", 32), "(declare-const count (_ BitVec 32))");
    }

    #[test]
    fn mk_val_positive() {
        let t = mk_val(42, 32);
        assert_eq!(t.expr, "(_ bv42 32)");
        assert_eq!(t.width, 32);
    }

    #[test]
    fn mk_val_zero() {
        assert_eq!(mk_val(0, 8).expr, "(_ bv0 8)");
    }

    #[test]
    fn mk_val_max_uint8() {
        assert_eq!(mk_val(255, 8).expr, "(_ bv255 8)");
    }

    #[test]
    fn mk_val_negative_two_complement() {
        // -1 at 8 bits = 0xFF = 255
        assert_eq!(mk_val(-1, 8).expr, "(_ bv255 8)");
    }

    #[test]
    fn le_unsigned() {
        let a = mk_var("a", 32);
        let b = mk_var("b", 32);
        assert_eq!(le(&a, &b, false), "(bvule a b)");
    }

    #[test]
    fn le_signed() {
        let a = mk_var("a", 32);
        let b = mk_var("b", 32);
        assert_eq!(le(&a, &b, true), "(bvsle a b)");
    }

    #[test]
    fn lt_unsigned() {
        let a = mk_var("a", 16);
        let b = mk_val(100, 16);
        assert_eq!(lt(&a, &b, false), "(bvult a (_ bv100 16))");
    }

    #[test]
    fn ge_signed() {
        let a = mk_var("x", 64);
        let b = mk_val(0, 64);
        assert_eq!(ge(&a, &b, true), "(bvsge x (_ bv0 64))");
    }

    #[test]
    fn gt_unsigned() {
        let a = mk_var("n", 8);
        let b = mk_val(10, 8);
        assert_eq!(gt(&a, &b, false), "(bvugt n (_ bv10 8))");
    }
}
