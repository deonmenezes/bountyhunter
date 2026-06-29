/// C-semantics helpers for SMT bitvector reasoning — SMT-LIB2 construction.
///
/// Faithful port of `core/smt_solver/csem.py`.
///
/// Width coercion, overflow predicates, and shift disambiguators used by
/// domain encoders when they need to reason about real C arithmetic rather
/// than abstract bitvector math.
///
/// In Python, these functions take and return in-process Z3 expressions.
/// In Rust, they construct SMT-LIB2 string expressions (using `SmtTerm`),
/// preserving the same mathematical conditions — the external solver sees
/// equivalent formulae.
///
/// # CWE coverage
/// - **CWE-190** (integer overflow/wraparound): `uadd_overflows`, `sadd_overflows`,
///   `umul_overflows`, `smul_overflows`, `usub_underflows`, `ssub_overflows`
/// - **CWE-197** (numeric truncation): `truncation_loses_bits`
/// - Width coercion: `truncate`, `sign_extend`, `zero_extend`, `cast`
/// - Shift disambiguators: `ashr` (arithmetic), `lshr` (logical)
use crate::bitvec::SmtTerm;

// ---------------------------------------------------------------------------
// Width coercion
// ---------------------------------------------------------------------------

/// Discard high bits, keeping the low `to_width` bits.
///
/// Mirrors `csem.truncate(bv, to_width)`.
/// Returns `Err` when `to_width <= 0` or `to_width > bv.width`.
pub fn truncate(bv: &SmtTerm, to_width: u32) -> Result<SmtTerm, String> {
    if to_width == 0 || to_width > bv.width {
        return Err(format!(
            "truncate: to_width={} out of range for {}-bit operand (must be 1..{})",
            to_width, bv.width, bv.width
        ));
    }
    Ok(SmtTerm {
        expr: format!("((_ extract {} 0) {})", to_width - 1, bv.expr),
        width: to_width,
    })
}

/// Extend `bv` to `to_width` bits preserving the sign bit.
///
/// Mirrors `csem.sign_extend(bv, to_width)`.
/// Returns `Err` when `to_width < bv.width`.
pub fn sign_extend(bv: &SmtTerm, to_width: u32) -> Result<SmtTerm, String> {
    if to_width < bv.width {
        return Err(format!(
            "sign_extend: to_width={} narrower than source {}-bit operand \
             (use truncate() to narrow)",
            to_width, bv.width
        ));
    }
    let ext = to_width - bv.width;
    Ok(SmtTerm {
        expr: if ext == 0 {
            bv.expr.clone()
        } else {
            format!("((_ sign_extend {}) {})", ext, bv.expr)
        },
        width: to_width,
    })
}

/// Extend `bv` to `to_width` bits padding with zeros.
///
/// Mirrors `csem.zero_extend(bv, to_width)`.
/// Returns `Err` when `to_width < bv.width`.
pub fn zero_extend(bv: &SmtTerm, to_width: u32) -> Result<SmtTerm, String> {
    if to_width < bv.width {
        return Err(format!(
            "zero_extend: to_width={} narrower than source {}-bit operand \
             (use truncate() to narrow)",
            to_width, bv.width
        ));
    }
    let ext = to_width - bv.width;
    Ok(SmtTerm {
        expr: if ext == 0 {
            bv.expr.clone()
        } else {
            format!("((_ zero_extend {}) {})", ext, bv.expr)
        },
        width: to_width,
    })
}

/// Predicate: does truncating `bv` to `to_width` lose information?
///
/// Mirrors `csem.truncation_loses_bits(bv, to_width, to_signed)`.
/// SMT-LIB2: truncate to narrow, re-extend under `to_signed` semantics,
/// check inequality with original.
pub fn truncation_loses_bits(
    bv: &SmtTerm,
    to_width: u32,
    to_signed: bool,
) -> Result<SmtTerm, String> {
    let narrow = truncate(bv, to_width)?;
    let wide = if to_signed {
        sign_extend(&narrow, bv.width)?
    } else {
        zero_extend(&narrow, bv.width)?
    };
    Ok(SmtTerm {
        expr: format!("(not (= {} {}))", wide.expr, bv.expr),
        width: 1, // boolean predicate — width 1 (Bool in SMT-LIB2)
    })
}

// ---------------------------------------------------------------------------
// Overflow predicates
// ---------------------------------------------------------------------------

/// Unsigned addition wraps around (result < BOTH operands).
///
/// Mirrors `csem.uadd_overflows(a, b)` → `z3.Not(z3.BVAddNoOverflow(a, b, signed=False))`.
/// SMT-LIB2: zero-extend by 1 bit, add, check if the (n+1)-th bit is set.
pub fn uadd_overflows(a: &SmtTerm, b: &SmtTerm) -> Result<SmtTerm, String> {
    let n = a.width;
    let a_ext = zero_extend(a, n + 1)?;
    let b_ext = zero_extend(b, n + 1)?;
    Ok(SmtTerm {
        expr: format!(
            "(= ((_ extract {} {}) (bvadd {} {})) (_ bv1 1))",
            n, n, a_ext.expr, b_ext.expr
        ),
        width: 1,
    })
}

/// Signed addition overflows in either direction.
///
/// Mirrors `csem.sadd_overflows(a, b)` →
/// `z3.Or(z3.Not(BVAddNoOverflow(a,b,True)), z3.Not(BVAddNoUnderflow(a,b)))`.
/// SMT-LIB2: positive overflow (both positive inputs, negative result)
/// OR negative overflow (both negative inputs, positive result).
pub fn sadd_overflows(a: &SmtTerm, b: &SmtTerm) -> SmtTerm {
    let n = a.width;
    let zero = format!("(_ bv0 {})", n);
    SmtTerm {
        expr: format!(
            "(or \
              (and (bvsge {a} {z}) (bvsge {b} {z}) (bvslt (bvadd {a} {b}) {z})) \
              (and (bvslt {a} {z}) (bvslt {b} {z}) (bvsge (bvadd {a} {b}) {z})))",
            a = a.expr, b = b.expr, z = zero
        ),
        width: 1,
    }
}

/// Unsigned subtraction wraps around (`a < b`).
///
/// Mirrors `csem.usub_underflows(a, b)` → `z3.Not(z3.BVSubNoUnderflow(a, b, signed=False))`.
pub fn usub_underflows(a: &SmtTerm, b: &SmtTerm) -> SmtTerm {
    SmtTerm {
        expr: format!("(bvult {} {})", a.expr, b.expr),
        width: 1,
    }
}

/// Signed subtraction overflows in either direction.
///
/// Mirrors `csem.ssub_overflows(a, b)` →
/// `z3.Or(z3.Not(BVSubNoOverflow), z3.Not(BVSubNoUnderflow(a,b,True)))`.
/// SMT-LIB2: positive overflow (pos - neg → neg) OR negative overflow (neg - pos → pos).
pub fn ssub_overflows(a: &SmtTerm, b: &SmtTerm) -> SmtTerm {
    let n = a.width;
    let zero = format!("(_ bv0 {})", n);
    SmtTerm {
        expr: format!(
            "(or \
              (and (bvsge {a} {z}) (bvslt {b} {z}) (bvslt (bvsub {a} {b}) {z})) \
              (and (bvslt {a} {z}) (bvsge {b} {z}) (bvsge (bvsub {a} {b}) {z})))",
            a = a.expr, b = b.expr, z = zero
        ),
        width: 1,
    }
}

/// Unsigned multiplication wraps around.
///
/// Mirrors `csem.umul_overflows(a, b)` → `z3.Not(z3.BVMulNoOverflow(a, b, signed=False))`.
/// SMT-LIB2: zero-extend both by N bits, multiply, check if upper N bits are non-zero.
pub fn umul_overflows(a: &SmtTerm, b: &SmtTerm) -> Result<SmtTerm, String> {
    let n = a.width;
    let a_ext = zero_extend(a, n * 2)?;
    let b_ext = zero_extend(b, n * 2)?;
    Ok(SmtTerm {
        expr: format!(
            "(not (= ((_ extract {} {}) (bvmul {} {})) (_ bv0 {})))",
            n * 2 - 1, n, a_ext.expr, b_ext.expr, n
        ),
        width: 1,
    })
}

/// Signed multiplication overflows in either direction.
///
/// Mirrors `csem.smul_overflows(a, b)` →
/// `z3.Or(z3.Not(BVMulNoOverflow(a,b,True)), z3.Not(BVMulNoUnderflow(a,b)))`.
/// SMT-LIB2: sign-extend both by N bits, multiply, check if upper N+1 bits are not
/// all the same (the sign bit of the result determines direction).
pub fn smul_overflows(a: &SmtTerm, b: &SmtTerm) -> Result<SmtTerm, String> {
    let n = a.width;
    let a_ext = sign_extend(a, n * 2)?;
    let b_ext = sign_extend(b, n * 2)?;
    // The product fits in N signed bits iff the upper N bits are all copies
    // of the sign bit (bit n-1 of the product).
    Ok(SmtTerm {
        expr: format!(
            "(let ((prod (bvmul {} {}))) \
              (not (= ((_ extract {} {}) prod) \
                     ((_ repeat {}) ((_ extract {} {}) prod)))))",
            a_ext.expr, b_ext.expr,
            n * 2 - 1, n,   // upper N bits
            n,               // repeat N times
            n - 1, n - 1    // sign bit (bit n-1 of n-bit result)
        ),
        width: 1,
    })
}

// ---------------------------------------------------------------------------
// Shift disambiguators
// ---------------------------------------------------------------------------

/// Arithmetic right shift — preserves the sign bit.
///
/// Mirrors `csem.ashr(a, b)`. SMT-LIB2: `bvashr`.
pub fn ashr(a: &SmtTerm, b: &SmtTerm) -> SmtTerm {
    SmtTerm {
        expr: format!("(bvashr {} {})", a.expr, b.expr),
        width: a.width,
    }
}

/// Logical right shift — shifts in zeros (unsigned semantics).
///
/// Mirrors `csem.lshr(a, b)`. SMT-LIB2: `bvlshr`.
pub fn lshr(a: &SmtTerm, b: &SmtTerm) -> SmtTerm {
    SmtTerm {
        expr: format!("(bvlshr {} {})", a.expr, b.expr),
        width: a.width,
    }
}

// ---------------------------------------------------------------------------
// C-style cast
// ---------------------------------------------------------------------------

/// Simulate a C-style integer cast.
///
/// Mirrors `csem.cast(bv, to_width, from_signed)`.
/// - Widening: sign-extends when source is signed, zero-extends when unsigned.
/// - Narrowing: truncates.
/// - Same width: no-op.
pub fn cast(bv: &SmtTerm, to_width: u32, from_signed: bool) -> Result<SmtTerm, String> {
    match to_width.cmp(&bv.width) {
        std::cmp::Ordering::Greater => {
            if from_signed {
                sign_extend(bv, to_width)
            } else {
                zero_extend(bv, to_width)
            }
        }
        std::cmp::Ordering::Less => truncate(bv, to_width),
        std::cmp::Ordering::Equal => Ok(bv.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitvec::mk_var;

    #[test]
    fn truncate_valid() {
        let bv = mk_var("x", 32);
        let r = truncate(&bv, 8).unwrap();
        assert_eq!(r.width, 8);
        assert_eq!(r.expr, "((_ extract 7 0) x)");
    }

    #[test]
    fn truncate_zero_width_errors() {
        let bv = mk_var("x", 32);
        assert!(truncate(&bv, 0).is_err());
    }

    #[test]
    fn truncate_wider_than_source_errors() {
        let bv = mk_var("x", 8);
        let r = truncate(&bv, 16);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("truncate"));
    }

    #[test]
    fn sign_extend_valid() {
        let bv = mk_var("y", 8);
        let r = sign_extend(&bv, 32).unwrap();
        assert_eq!(r.width, 32);
        assert!(r.expr.contains("sign_extend"));
        assert!(r.expr.contains("24")); // 32 - 8 = 24 extra bits
    }

    #[test]
    fn sign_extend_narrower_errors() {
        let bv = mk_var("y", 32);
        assert!(sign_extend(&bv, 8).is_err());
    }

    #[test]
    fn zero_extend_valid() {
        let bv = mk_var("z", 8);
        let r = zero_extend(&bv, 16).unwrap();
        assert_eq!(r.width, 16);
        assert!(r.expr.contains("zero_extend"));
        assert!(r.expr.contains("8")); // 16 - 8 = 8 extra bits
    }

    #[test]
    fn zero_extend_same_width_noop() {
        let bv = mk_var("z", 32);
        let r = zero_extend(&bv, 32).unwrap();
        assert_eq!(r.expr, "z");
    }

    #[test]
    fn sign_extend_same_width_noop() {
        let bv = mk_var("z", 32);
        let r = sign_extend(&bv, 32).unwrap();
        assert_eq!(r.expr, "z");
    }

    #[test]
    fn truncation_loses_bits_unsigned() {
        let bv = mk_var("v", 32);
        let r = truncation_loses_bits(&bv, 8, false).unwrap();
        assert_eq!(r.width, 1);
        assert!(r.expr.contains("not"));
        assert!(r.expr.contains("zero_extend"));
    }

    #[test]
    fn truncation_loses_bits_signed() {
        let bv = mk_var("v", 32);
        let r = truncation_loses_bits(&bv, 8, true).unwrap();
        assert_eq!(r.width, 1);
        assert!(r.expr.contains("sign_extend"));
    }

    #[test]
    fn uadd_overflows_expression() {
        let a = mk_var("a", 32);
        let b = mk_var("b", 32);
        let r = uadd_overflows(&a, &b).unwrap();
        assert_eq!(r.width, 1);
        assert!(r.expr.contains("zero_extend"));
        assert!(r.expr.contains("bvadd"));
        assert!(r.expr.contains("extract"));
    }

    #[test]
    fn sadd_overflows_expression() {
        let a = mk_var("a", 32);
        let b = mk_var("b", 32);
        let r = sadd_overflows(&a, &b);
        assert_eq!(r.width, 1);
        assert!(r.expr.contains("or"));
        assert!(r.expr.contains("bvsge"));
        assert!(r.expr.contains("bvadd"));
    }

    #[test]
    fn usub_underflows_expression() {
        let a = mk_var("a", 32);
        let b = mk_var("b", 32);
        let r = usub_underflows(&a, &b);
        assert_eq!(r.expr, "(bvult a b)");
    }

    #[test]
    fn umul_overflows_expression() {
        let a = mk_var("a", 32);
        let b = mk_var("b", 32);
        let r = umul_overflows(&a, &b).unwrap();
        assert_eq!(r.width, 1);
        assert!(r.expr.contains("bvmul"));
        assert!(r.expr.contains("zero_extend"));
    }

    #[test]
    fn ashr_expression() {
        let a = mk_var("x", 32);
        let b = mk_var("s", 32);
        let r = ashr(&a, &b);
        assert_eq!(r.expr, "(bvashr x s)");
        assert_eq!(r.width, 32);
    }

    #[test]
    fn lshr_expression() {
        let a = mk_var("x", 32);
        let b = mk_var("s", 32);
        let r = lshr(&a, &b);
        assert_eq!(r.expr, "(bvlshr x s)");
    }

    #[test]
    fn cast_widening_unsigned() {
        let bv = mk_var("u8", 8);
        let r = cast(&bv, 32, false).unwrap();
        assert_eq!(r.width, 32);
        assert!(r.expr.contains("zero_extend"));
    }

    #[test]
    fn cast_widening_signed() {
        let bv = mk_var("i8", 8);
        let r = cast(&bv, 32, true).unwrap();
        assert_eq!(r.width, 32);
        assert!(r.expr.contains("sign_extend"));
    }

    #[test]
    fn cast_narrowing() {
        let bv = mk_var("x", 32);
        let r = cast(&bv, 8, false).unwrap();
        assert_eq!(r.width, 8);
        assert!(r.expr.contains("extract"));
    }

    #[test]
    fn cast_same_width_noop() {
        let bv = mk_var("x", 32);
        let r = cast(&bv, 32, true).unwrap();
        assert_eq!(r.expr, "x");
    }
}
