//! Floating-point format encoding/decoding and emulation.
//!
//! Corresponds to Ghidra's `float.hh` / `float.cc` (773 lines).
//!
//! FloatFormat supports IEEE754 single/double precision encoding/decoding
//! and floating-point operation emulation (opAdd/opMult/opDiv/etc.).
//!
//! # Status
//! Core FloatFormat with IEEE754 single/double construction, host float
//! conversion, and basic operations. Uses Rust's f64/f32 for host format.
//! opInt2Float sign-extends its integer input from `size_in` bytes
//! (float.cc:611-617) and opFloat2Float delegates to the bit-level
//! convertEncoding port (float.cc:276-288/352-419).

/// The various classes of floating-point encodings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FloatClass {
    Normalized = 0,
    Infinity = 1,
    Zero = 2,
    Nan = 3,
    Denormalized = 4,
}

/// Encoding information for a single floating-point format.
/// Corresponds to Ghidra's `FloatFormat` (float.hh:32).
#[derive(Debug, Clone)]
pub struct FloatFormat {
    /// Size of float in bytes
    pub size: usize,
    /// Bit position of sign bit
    pub signbit_pos: u32,
    /// (lowest) bit position of fractional part
    pub frac_pos: u32,
    /// Number of bits in fractional part
    pub frac_size: u32,
    /// (lowest) bit position of exponent
    pub exp_pos: u32,
    /// Number of bits in exponent
    pub exp_size: u32,
    /// Bias to add to real exponent to get encoding
    pub bias: i32,
    /// Maximum possible exponent
    pub max_exponent: i32,
    /// Whether the integer bit (jbit) is implied
    pub jbit_implied: bool,
}

impl FloatFormat {
    // Ghidra: float.cc:36 FloatFormat::new
    /// Construct default IEEE 754 standard settings for the given byte size.
    /// Supports size=4 (single) and size=8 (double).
    pub fn new(size: usize) -> Self {
        match size {
            4 => Self {
                size: 4,
                signbit_pos: 31,
                frac_pos: 0,
                frac_size: 23,
                exp_pos: 23,
                exp_size: 8,
                bias: 127,
                max_exponent: 255, // (1<<exp_size)-1 — float.cc:59
                jbit_implied: true,
            },
            8 => Self {
                size: 8,
                signbit_pos: 63,
                frac_pos: 0,
                frac_size: 52,
                exp_pos: 52,
                exp_size: 11,
                bias: 1023,
                max_exponent: 2047, // (1<<exp_size)-1 — float.cc:59
                jbit_implied: true,
            },
            _ => panic!("Unsupported float size: {}", size),
        }
    }

    // Ghidra: float.hh:66 FloatFormat::getSize
    /// Get the size of the encoding in bytes.
    pub fn get_size(&self) -> usize { self.size }

    // Ghidra: float.cc:228 FloatFormat::getHostFloat
    /// Convert an encoding into the host's f64.
    pub fn get_host_float(&self, encoding: u64, ftype: &mut FloatClass) -> f64 {
        let sign = self.extract_sign(encoding);
        let exp_code = self.extract_exponent_code(encoding);
        let frac = self.extract_fractional_code(encoding);

        if exp_code == 0 {
            if frac == 0 {
                *ftype = FloatClass::Zero;
                return if sign { -0.0 } else { 0.0 };
            }
            *ftype = FloatClass::Denormalized;
            // Denormalized: value = (-1)^sign * 0.frac * 2^(1-bias)
            let val = (frac as f64) * 2f64.powi(1 - self.bias);
            return if sign { -val } else { val };
        }
        if exp_code as i32 == self.max_exponent {
            if frac == 0 {
                *ftype = FloatClass::Infinity;
                return if sign { f64::NEG_INFINITY } else { f64::INFINITY };
            }
            *ftype = FloatClass::Nan;
            // Ghidra float.cc:253-254 applies the encoding's sign to the NaN
            // (`return sgn ? -nan : +nan;`) — negation flips the sign bit.
            return if sign { -f64::NAN } else { f64::NAN };
        }
        *ftype = FloatClass::Normalized;
        // Normalized: value = (-1)^sign * 1.frac * 2^(exp-bias)
        let significand = if self.jbit_implied {
            (1u64 << self.frac_size) | frac
        } else {
            frac
        };
        let val = (significand as f64) * 2f64.powi(exp_code as i32 - self.bias - self.frac_size as i32);
        if sign { -val } else { val }
    }

    // Ghidra: float.cc:293 FloatFormat::getEncoding
    /// Convert the host's f64 into this encoding.
    pub fn get_encoding(&self, host: f64) -> u64 {
        match self.size {
            4 => (host as f32).to_bits() as u64,
            8 => host.to_bits(),
            _ => panic!("Unsupported float size"),
        }
    }

    // Ghidra: float.cc:276 FloatFormat::roundToNearestEven
    /// Round a floating point value to the nearest even.
    /// Faithful to Ghidra FloatFormat::roundToNearestEven (float.cc:276-288,
    /// static per float.hh:56): `signif` is mutated in place (reference
    /// parameter), and `lowbitpos` indexes the least-significant retained
    /// bit; returns whether rounding carried up.
    pub(crate) fn round_to_nearest_even(signif: &mut u64, lowbitpos: i32) -> bool {
        let lowbitmask = if lowbitpos < 64 { 1u64 << lowbitpos } else { 0 };
        let midbitmask = 1u64 << (lowbitpos - 1);
        let epsmask = midbitmask - 1;
        let odd = (*signif & lowbitmask) != 0;
        if (*signif & midbitmask) != 0 && ((*signif & epsmask) != 0 || odd) {
            // uintb wrap-around carry: the caller detects the overflow via
            // (signif >> 63) == 0 and rebalances (float.cc:391/403).
            *signif = signif.wrapping_add(midbitmask);
            return true;
        }
        false
    }

    // Ghidra: float.cc:352 FloatFormat::convertEncoding
    /// Convert between two different formats: `encoding` is a value in
    /// `formin`, returned as the equivalent value in `self` (the output
    /// format). Faithful to Ghidra FloatFormat::convertEncoding
    /// (float.cc:352-419): sign/fraction/exponent are extracted from
    /// `formin` bit-level, NaN/Infinity map through the *output* format's
    /// maxexponent, subnormal inputs are normalized via count_leading_zeros
    /// (address.cc:773), and too-small/too-large exponents clamp to
    /// zero/infinity encodings — never an intermediate host double.
    ///
    /// Alignment caveat (decisive): oracle `extractFractionalCode`
    /// (float.cc:113-119) aligns the fraction to the TOP of the 64-bit word,
    /// and the whole convertEncoding ladder (normalize `<<lz`, jbit room
    /// `(1<<63)|(signif>>1)`, roundToNearestEven positions, final `<<1` cut,
    /// `setFractionalCode` drop) is written in that top-aligned convention.
    /// This port therefore uses local top-aligned extract/pack operations;
    /// the right-aligned `extract_fractional_code`/`set_fractional_code`
    /// helpers serve the separate host-double paths only.
    pub fn convert_encoding(&self, encoding: u64, formin: &FloatFormat) -> u64 {
        // float.cc:113 extractFractionalCode, top-aligned: >>= frac_pos then
        // <<= 64 - frac_size (no mask needed: higher bits are the exponent).
        let mut signif = (encoding >> formin.frac_pos) << (64 - formin.frac_size);
        let sgn = formin.extract_sign(encoding);
        let mut exp = formin.extract_exponent_code(encoding) as i32;

        if exp == formin.max_exponent {
            // NaN or INFINITY encoding
            if signif != 0 {
                return self.get_nan_encoding(sgn);
            }
            return self.get_infinity_encoding(sgn);
        }

        if exp == 0 {
            // incoming is subnormal
            if signif == 0 {
                return self.get_zero_encoding(sgn);
            }
            // normalize
            let lz = signif.leading_zeros() as i32;
            signif <<= lz;
            exp = -formin.bias - lz;
        } else {
            // incoming is normal
            exp -= formin.bias;
            // Oracle float.cc:379 tests the *output* format's jbitimplied.
            if self.jbit_implied {
                signif = (1u64 << 63) | (signif >> 1);
            }
        }

        exp += self.bias;

        if exp < -(self.frac_size as i32) {
            // Exponent is too small to represent
            return self.get_zero_encoding(sgn); // TODO handle round to non-zero
        }

        // float.cc:144 setFractionalCode, top-aligned OR-into-zero:
        // code >>= 64 - frac_size, then <<= frac_pos.
        let pack_frac = |code: u64| (code >> (64 - self.frac_size)) << self.frac_pos;

        if exp < 1 {
            // Must be denormalized
            if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size as i32 - exp) {
                // TODO handle carry to normal case
                if (signif >> 63) == 0 {
                    signif = 1u64 << 63;
                    exp += 1;
                }
            }
            let res = self.get_zero_encoding(sgn);
            return res | pack_frac(signif >> (-exp));
        }

        if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size as i32 - 1) {
            // if high bit is clear, then the add overflowed. Increase exp and
            // set signif to 1.
            if (signif >> 63) == 0 {
                signif = 1u64 << 63;
                exp += 1;
            }
        }

        if exp >= self.max_exponent {
            // Exponent is too big to represent
            return self.get_infinity_encoding(sgn);
        }

        if self.jbit_implied && exp != 0 {
            signif <<= 1; // Cut off top bit (which should be 1)
        }

        let mut res: u64 = 0;
        res |= pack_frac(signif);
        res |= (exp as u64) << self.exp_pos; // float.cc:171 setExponentCode
        self.set_sign(res, sgn)
    }

    // Ghidra: float.cc:113 FloatFormat::extractFractionalCode
    /// Extract the fractional part of the encoding.
    pub fn extract_fractional_code(&self, x: u64) -> u64 {
        (x >> self.frac_pos) & ((1u64 << self.frac_size) - 1)
    }

    // Ghidra: float.cc:123 FloatFormat::extractSign
    /// Extract the sign bit from the encoding.
    pub fn extract_sign(&self, x: u64) -> bool {
        (x >> self.signbit_pos) & 1 != 0
    }

    // Ghidra: float.cc:132 FloatFormat::extractExponentCode
    /// Extract the exponent from the encoding.
    pub fn extract_exponent_code(&self, x: u64) -> u32 {
        ((x >> self.exp_pos) & ((1u64 << self.exp_size) - 1)) as u32
    }

    // Ghidra: float.cc:144 FloatFormat::setFractionalCode
    /// Set the fractional code bits in the encoding.
    /// Faithful to Ghidra FloatFormat::setFractionalCode (float.cc:144).
    pub fn set_fractional_code(&self, x: u64, code: u64) -> u64 {
        let mask = ((1u64 << self.frac_size) - 1) << self.frac_pos;
        (x & !mask) | ((code << self.frac_pos) & mask)
    }

    // Ghidra: float.cc:158 FloatFormat::setSign
    /// Set the sign bit in the encoding.
    /// Faithful to Ghidra FloatFormat::setSign (float.cc:158).
    pub fn set_sign(&self, x: u64, sign: bool) -> u64 {
        if sign { x | (1u64 << self.signbit_pos) } else { x & !(1u64 << self.signbit_pos) }
    }

    // Ghidra: float.cc:171 FloatFormat::setExponentCode
    /// Set the exponent bits in the encoding.
    /// Faithful to Ghidra FloatFormat::setExponentCode (float.cc:171).
    pub fn set_exponent_code(&self, x: u64, code: u32) -> u64 {
        let mask = ((1u64 << self.exp_size) - 1) << self.exp_pos;
        (x & !mask) | (((code as u64) << self.exp_pos) & mask)
    }

    // Ghidra: float.cc:181 FloatFormat::getZeroEncoding
    /// Get the encoding for zero (positive or negative).
    /// Faithful to Ghidra FloatFormat::getZeroEncoding (float.cc:181).
    pub fn get_zero_encoding(&self, sgn: bool) -> u64 {
        self.set_sign(0, sgn)
    }

    // Ghidra: float.cc:193 FloatFormat::getInfinityEncoding
    /// Get the encoding for infinity (positive or negative).
    /// Faithful to Ghidra FloatFormat::getInfinityEncoding (float.cc:193).
    pub fn get_infinity_encoding(&self, sgn: bool) -> u64 {
        let inf_exp = (1u64 << self.exp_size) - 1; // All exponent bits set
        self.set_sign(self.set_fractional_code(0, 0) | (inf_exp << self.exp_pos), sgn)
    }

    // Ghidra: float.cc:205 FloatFormat::getNaNEncoding
    /// Get the encoding for NaN (positive or negative).
    /// Faithful to Ghidra FloatFormat::getNaNEncoding (float.cc:205).
    pub fn get_nan_encoding(&self, sgn: bool) -> u64 {
        let inf_exp = (1u64 << self.exp_size) - 1;
        let nan_frac = 1u64 << (self.frac_size - 1); // MSB of fraction
        self.set_sign(self.set_fractional_code(0, nan_frac) | (inf_exp << self.exp_pos), sgn)
    }

    // Ghidra: float.cc:483 FloatFormat::opNotEqual
    /// Inequality comparison (!=)
    pub fn op_not_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va != vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:496 FloatFormat::opLess
    /// Less-than comparison (<)
    pub fn op_less(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va < vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:509 FloatFormat::opLessEqual
    /// Less-than-or-equal comparison (<=)
    pub fn op_less_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va <= vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:631 FloatFormat::opTrunc
    /// Convert floating-point to integer (truncate toward zero)
    pub fn op_trunc(&self, a: u64, _size_out: usize) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        va.trunc() as i64 as u64
    }

    // Ghidra: float.cc:664 FloatFormat::opRound
    /// Round to nearest integer
    pub fn op_round(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.round())
    }

    // Ghidra: float.cc:622 FloatFormat::opFloat2Float
    /// Convert between floating-point precisions.
    /// Faithful to Ghidra float.cc:625 `return outformat.convertEncoding(a,
    /// this);` — the bit-level converter runs on the *output* format with
    /// `this` as the input format (no host-double intermediate).
    pub fn op_float2_float(&self, a: u64, outformat: &FloatFormat) -> u64 {
        outformat.convert_encoding(a, self)
    }

    // Ghidra: float.cc:470 FloatFormat::opEqual
    /// Equality comparison (==)
    pub fn op_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va == vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:533 FloatFormat::opAdd
    /// Addition (+)
    pub fn op_add(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va + vb)
    }

    // Ghidra: float.cc:569 FloatFormat::opSub
    /// Subtraction (-)
    pub fn op_sub(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va - vb)
    }

    // Ghidra: float.cc:557 FloatFormat::opMult
    /// Multiplication (*)
    pub fn op_mult(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va * vb)
    }

    // Ghidra: float.cc:545 FloatFormat::opDiv
    /// Division (/)
    pub fn op_div(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va / vb)
    }

    // Ghidra: float.cc:580 FloatFormat::opNeg
    /// Unary negate
    pub fn op_neg(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(-va)
    }

    // Ghidra: float.cc:590 FloatFormat::opAbs
    /// Absolute value (abs)
    pub fn op_abs(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.abs())
    }

    // Ghidra: float.cc:600 FloatFormat::opSqrt
    /// Square root (sqrt)
    pub fn op_sqrt(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.sqrt())
    }

    // Ghidra: float.cc:654 FloatFormat::opFloor
    /// Floor
    pub fn op_floor(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.floor())
    }

    // Ghidra: float.cc:644 FloatFormat::opCeil
    /// Ceiling (ceil)
    pub fn op_ceil(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.ceil())
    }

    // Ghidra: float.cc:521 FloatFormat::opNan
    /// Test if Not-a-Number (NaN)
    pub fn op_nan(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        self.get_host_float(a, &mut ta);
        if ta == FloatClass::Nan { 1 } else { 0 }
    }

    // Ghidra: float.cc:611 FloatFormat::opInt2Float
    /// Convert integer to floating-point.
    /// Faithful to Ghidra float.cc:611-617: the input is a *signed* integer
    /// of `size_in` bytes — `sign_extend(a, 8*sizein-1)` (address.hh:543)
    /// discards bits above the size_in sign bit and sign-extends before the
    /// `(double)` cast; the cast rounds to nearest even in both languages.
    pub fn op_int2float(&self, a: u64, size_in: usize) -> u64 {
        // address.hh:543 sign_extend(val, bit): sa = 64 - (bit + 1);
        // (val << sa) >> sa with an arithmetic right shift on intb.
        // size_in == 8 yields sa == 0 (identity on intb); 1..=7 discard the
        // high bytes and restore the sign from bit 8*size_in-1.
        let sa = 64 - 8 * size_in as u32;
        let ival = ((a << sa) as i64) >> sa;
        self.get_encoding(ival as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float_format_double() {
        let fmt = FloatFormat::new(8);
        assert_eq!(fmt.get_size(), 8);
        let encoding = fmt.get_encoding(3.14);
        let mut fc = FloatClass::Zero;
        let val = fmt.get_host_float(encoding, &mut fc);
        assert!((val - 3.14).abs() < 1e-10);
        assert_eq!(fc, FloatClass::Normalized);
    }

    #[test]
    fn test_float_format_single() {
        let fmt = FloatFormat::new(4);
        let encoding = fmt.get_encoding(1.5);
        let mut fc = FloatClass::Zero;
        let val = fmt.get_host_float(encoding, &mut fc);
        assert!((val - 1.5).abs() < 1e-6);
    }

    #[test]
    fn test_float_zero() {
        let fmt = FloatFormat::new(8);
        let encoding = fmt.get_encoding(0.0);
        let mut fc = FloatClass::Zero;
        let _ = fmt.get_host_float(encoding, &mut fc);
        assert_eq!(fc, FloatClass::Zero);
    }

    #[test]
    fn test_float_add() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(2.5);
        let b = fmt.get_encoding(3.5);
        let result = fmt.op_add(a, b);
        let mut fc = FloatClass::Zero;
        assert!((fmt.get_host_float(result, &mut fc) - 6.0).abs() < 1e-10);
    }

    #[test]
    fn test_float_mult() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(4.0);
        let b = fmt.get_encoding(0.5);
        let result = fmt.op_mult(a, b);
        let mut fc = FloatClass::Zero;
        assert!((fmt.get_host_float(result, &mut fc) - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_float_div() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(6.0);
        let b = fmt.get_encoding(3.0);
        let result = fmt.op_div(a, b);
        let mut fc = FloatClass::Zero;
        assert!((fmt.get_host_float(result, &mut fc) - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_float_not_equal() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(1.0);
        let b = fmt.get_encoding(2.0);
        assert_eq!(fmt.op_not_equal(a, b), 1);
        assert_eq!(fmt.op_not_equal(a, a), 0);
    }

    #[test]
    fn test_float_less_equal() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(1.0);
        let b = fmt.get_encoding(2.0);
        assert_eq!(fmt.op_less_equal(a, b), 1);
        assert_eq!(fmt.op_less_equal(a, a), 1);
        assert_eq!(fmt.op_less_equal(b, a), 0);
    }

    #[test]
    fn test_float_trunc() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(3.7);
        let result = fmt.op_trunc(a, 4);
        assert_eq!(result & 0xffffffff, 3);
    }

    #[test]
    fn test_float2float() {
        let fmt8 = FloatFormat::new(8);
        let fmt4 = FloatFormat::new(4);
        let a = fmt8.get_encoding(1.5);
        let result = fmt8.op_float2_float(a, &fmt4);
        let mut fc = FloatClass::Zero;
        assert!((fmt4.get_host_float(result, &mut fc) - 1.5).abs() < 1e-6);
    }

    #[test]
    fn test_set_get_encoding_ops() {
        let fmt = FloatFormat::new(8);
        let x = fmt.get_encoding(1.5);
        let frac = fmt.extract_fractional_code(x);
        let exp = fmt.extract_exponent_code(x);
        let sign = fmt.extract_sign(x);
        let y = fmt.set_fractional_code(0, frac);
        let y = fmt.set_exponent_code(y, exp);
        let y = fmt.set_sign(y, sign);
        assert_eq!(x, y);
    }

    #[test]
    fn test_zero_infinity_nan_encoding() {
        let fmt = FloatFormat::new(8);
        let pos_zero = fmt.get_zero_encoding(false);
        let neg_zero = fmt.get_zero_encoding(true);
        assert_eq!(pos_zero, 0);
        assert_ne!(pos_zero, neg_zero);
        let pos_inf = fmt.get_infinity_encoding(false);
        assert_eq!(fmt.extract_exponent_code(pos_inf), (1 << fmt.exp_size) - 1);
        assert_eq!(fmt.extract_fractional_code(pos_inf), 0);
        let nan = fmt.get_nan_encoding(false);
        assert_eq!(fmt.extract_exponent_code(nan), (1 << fmt.exp_size) - 1);
        assert_ne!(fmt.extract_fractional_code(nan), 0);
    }

    // Regression for FLOAT-OPINT2FLOAT-SIGN-0001 (Ghidra float.cc:611-617):
    // opInt2Float sign-extends the integer from size_in bytes. Oracle proof
    // lives in tests/oracle/float_int2float_sign_1204 (runner
    // tools/run_float_int2float_sign_oracle.sh); these asserts only pin the
    // Rust side against drift.
    #[test]
    fn test_int2float_sign_extend() {
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        // -7 as a 4-byte two's complement integer -> -7.0 encodings.
        assert_eq!(fmt4.op_int2float(0xFFFFFFF9, 4), 0xC0E00000);
        assert_eq!(fmt8.op_int2float(0xFFFFFFF9, 4), 0xC01C000000000000);
        // -7 as a 1-byte integer.
        assert_eq!(fmt4.op_int2float(0xF9, 1), 0xC0E00000);
        // -9 as a 2-byte integer -> -9.0f.
        assert_eq!(fmt4.op_int2float(0xFFF7, 2), 0xC1100000);
        // INT32_MIN -> -2^31 exactly.
        assert_eq!(fmt4.op_int2float(0x80000000, 4), 0xCF000000);
        // INT32_MAX rounds to nearest even to 2^31 in f32.
        assert_eq!(fmt4.op_int2float(0x7FFFFFFF, 4), 0x4F000000);
        // Bits above the size_in sign bit are discarded by sign_extend.
        assert_eq!(fmt8.op_int2float(0xABCDFFFFFFF9, 4), 0xC01C000000000000);
        // i64::MIN converts exactly; i64::MIN+1/i64::MAX round to +-2^63.
        assert_eq!(fmt8.op_int2float(0x8000000000000000, 8), 0xC3E0000000000000);
        assert_eq!(fmt8.op_int2float(0x8000000000000001, 8), 0xC3E0000000000000);
        assert_eq!(fmt8.op_int2float(0x7FFFFFFFFFFFFFFF, 8), 0x43E0000000000000);
    }

    // Regression for the opFloat2Float bit-level convertEncoding port
    // (Ghidra float.cc:622-626/352-419). Oracle proof lives in
    // tests/oracle/float_int2float_sign_1204.
    #[test]
    fn test_float2float_convert_encoding() {
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        // Widening keeps negatives and the NaN sign bit.
        assert_eq!(fmt4.op_float2_float(0xBF800000, &fmt8), 0xBFF0000000000000);
        assert_eq!(fmt4.op_float2_float(0x80000000, &fmt8), 0x8000000000000000);
        assert_eq!(fmt4.op_float2_float(0xFFC00000, &fmt8), 0xFFF8000000000000);
        // Subnormal single -> normal double (normalize branch).
        assert_eq!(fmt4.op_float2_float(0x00000001, &fmt8), 0x36A0000000000000);
        // Narrowing with round-to-nearest-even at the tie.
        assert_eq!(fmt8.op_float2_float(0xBFF0000000000000, &fmt4), 0xBF800000);
        // 1+2^-24 is the exact tie between 1.0f and nextafter(1.0f): ties to
        // even keep 1.0f; 1+2^-24+2^-25 is above half and rounds up.
        assert_eq!(fmt8.op_float2_float(0x3FF0000010000000, &fmt4), 0x3F800000);
        assert_eq!(fmt8.op_float2_float(0x3FF0000018000000, &fmt4), 0x3F800001);
        assert_eq!(fmt8.op_float2_float(0xBFF0000010000000, &fmt4), 0xBF800000);
        // Denormalized output branch and clamps.
        assert_eq!(fmt8.op_float2_float(0x3800000000000000, &fmt4), 0x00400000);
        assert_eq!(fmt8.op_float2_float(0x2100000000000000, &fmt4), 0x00000000);
        assert_eq!(fmt8.op_float2_float(0x7FEFFFFFFFFFFFFF, &fmt4), 0x7F800000);
        assert_eq!(fmt8.op_float2_float(0xFFEFFFFFFFFFFFFF, &fmt4), 0xFF800000);
        assert_eq!(fmt8.op_float2_float(0xFFF8000000000000, &fmt4), 0xFFC00000);
        assert_eq!(fmt8.op_float2_float(0x8000000000000000, &fmt4), 0x80000000);
    }
}
