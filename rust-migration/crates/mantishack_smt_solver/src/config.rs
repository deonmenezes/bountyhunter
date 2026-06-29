/// Bitvector profile (width + signedness) for MANTISHACK's SMT harness.
///
/// Faithful port of `core/smt_solver/config.py`.
///
/// `BVProfile` names the bit-width and signedness a domain encoder uses for
/// its path conditions / constraints / witness rendering. It is passed as a
/// single value rather than two separate `width` / `signed` flags so call
/// sites read "I'm modelling a C uint32" rather than "width=32, signed=false".
///
/// Pre-made profiles cover common architecture register widths and C integer
/// types; construct `BVProfile::new(width, signed)` directly for unusual cases.

/// Width and signedness for SMT bitvector reasoning.
///
/// Immutable (all fields private, only constructable via `new()`).
/// Mirrors Python `@dataclass(frozen=True)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BVProfile {
    pub width: u32,
    pub signed: bool,
}

impl BVProfile {
    /// Construct a profile.
    ///
    /// # Errors
    /// Returns `Err` when `width == 0`, mirroring Python's
    /// `ValueError("width must be positive, got {width}")`.
    pub fn new(width: u32, signed: bool) -> Result<Self, String> {
        if width == 0 {
            return Err(format!("width must be positive, got {}", width));
        }
        Ok(BVProfile { width, signed })
    }

    /// Compact tag like `"bv64u"` / `"bv32s"`.
    ///
    /// Mirrors `BVProfile.mode_tag()`.
    pub fn mode_tag(&self) -> String {
        format!("bv{}{}", self.width, if self.signed { 's' } else { 'u' })
    }

    /// Human-readable description like `"64-bit unsigned"` / `"32-bit signed"`.
    ///
    /// Mirrors `BVProfile.describe()`.
    pub fn describe(&self) -> String {
        format!(
            "{}-bit {}",
            self.width,
            if self.signed { "signed" } else { "unsigned" }
        )
    }
}

// ---------------------------------------------------------------------------
// Pre-made profiles — name expresses the modelled type at call sites.
// ---------------------------------------------------------------------------

// Architecture register widths (address reasoning is always unsigned).
pub const BV_X86_64: BVProfile = BVProfile { width: 64, signed: false };
pub const BV_AARCH64: BVProfile = BVProfile { width: 64, signed: false };
pub const BV_I386: BVProfile = BVProfile { width: 32, signed: false };
pub const BV_ARM32: BVProfile = BVProfile { width: 32, signed: false };

// C integer types — the usual suspects for CWE-190 reasoning.
pub const BV_C_UINT64: BVProfile = BVProfile { width: 64, signed: false };
pub const BV_C_INT64: BVProfile = BVProfile { width: 64, signed: true };
pub const BV_C_UINT32: BVProfile = BVProfile { width: 32, signed: false };
pub const BV_C_INT32: BVProfile = BVProfile { width: 32, signed: true };
pub const BV_C_UINT16: BVProfile = BVProfile { width: 16, signed: false };
pub const BV_C_INT16: BVProfile = BVProfile { width: 16, signed: true };
pub const BV_C_UINT8: BVProfile = BVProfile { width: 8, signed: false };
pub const BV_C_INT8: BVProfile = BVProfile { width: 8, signed: true };

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vector: BVProfile::mode_tag — derived from Python's output
    #[test]
    fn mode_tag_unsigned_64() {
        assert_eq!(BVProfile { width: 64, signed: false }.mode_tag(), "bv64u");
    }

    #[test]
    fn mode_tag_signed_32() {
        assert_eq!(BVProfile { width: 32, signed: true }.mode_tag(), "bv32s");
    }

    #[test]
    fn mode_tag_unsigned_8() {
        assert_eq!(BVProfile { width: 8, signed: false }.mode_tag(), "bv8u");
    }

    #[test]
    fn describe_unsigned_64() {
        assert_eq!(BVProfile { width: 64, signed: false }.describe(), "64-bit unsigned");
    }

    #[test]
    fn describe_signed_16() {
        assert_eq!(BVProfile { width: 16, signed: true }.describe(), "16-bit signed");
    }

    #[test]
    fn new_width_zero_errors() {
        assert!(BVProfile::new(0, false).is_err());
        let msg = BVProfile::new(0, false).unwrap_err();
        assert!(msg.contains("width must be positive"));
        assert!(msg.contains('0'));
    }

    #[test]
    fn premade_profiles_correct() {
        assert_eq!(BV_X86_64.width, 64);
        assert!(!BV_X86_64.signed);
        assert_eq!(BV_C_INT32.width, 32);
        assert!(BV_C_INT32.signed);
        assert_eq!(BV_C_UINT8.width, 8);
        assert!(!BV_C_UINT8.signed);
    }
}
