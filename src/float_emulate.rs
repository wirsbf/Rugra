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
                max_exponent: 254,
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
                max_exponent: 2046,
                jbit_implied: true,
            },
            _ => panic!("Unsupported float size: {}", size),
        }
    }

    /// Get the size of the encoding in bytes.
    pub fn get_size(&self) -> usize { self.size }

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
            return f64::NAN;
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

    /// Convert the host's f64 into this encoding.
    pub fn get_encoding(&self, host: f64) -> u64 {
        match self.size {
            4 => (host as f32).to_bits() as u64,
            8 => host.to_bits(),
            _ => panic!("Unsupported float size"),
        }
    }

    /// Extract the fractional part of the encoding.
    pub fn extract_fractional_code(&self, x: u64) -> u64 {
        (x >> self.frac_pos) & ((1u64 << self.frac_size) - 1)
    }

    /// Extract the sign bit from the encoding.
    pub fn extract_sign(&self, x: u64) -> bool {
        (x >> self.signbit_pos) & 1 != 0
    }

    /// Extract the exponent from the encoding.
    pub fn extract_exponent_code(&self, x: u64) -> u32 {
        ((x >> self.exp_pos) & ((1u64 << self.exp_size) - 1)) as u32
    }

    /// Inequality comparison (!=)
    pub fn op_not_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va != vb { 1 } else { 0 }
    }

    /// Less-than comparison (<)
    pub fn op_less(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va < vb { 1 } else { 0 }
    }

    /// Less-than-or-equal comparison (<=)
    pub fn op_less_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va <= vb { 1 } else { 0 }
    }

    /// Convert floating-point to integer (truncate toward zero)
    pub fn op_trunc(&self, a: u64, _size_out: usize) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        va.trunc() as i64 as u64
    }

    /// Round to nearest integer
    pub fn op_round(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.round())
    }

    /// Convert between floating-point precisions
    pub fn op_float2_float(&self, a: u64, outformat: &FloatFormat) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        outformat.get_encoding(va)
    }

    /// Equality comparison (==)
    pub fn op_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va == vb { 1 } else { 0 }
    }

    /// Addition (+)
    pub fn op_add(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va + vb)
    }

    /// Subtraction (-)
    pub fn op_sub(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va - vb)
    }

    /// Multiplication (*)
    pub fn op_mult(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va * vb)
    }

    /// Division (/)
    pub fn op_div(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va / vb)
    }

    /// Unary negate
    pub fn op_neg(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(-va)
    }

    /// Absolute value (abs)
    pub fn op_abs(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.abs())
    }

    /// Square root (sqrt)
    pub fn op_sqrt(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.sqrt())
    }

    /// Floor
    pub fn op_floor(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.floor())
    }

    /// Ceiling (ceil)
    pub fn op_ceil(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.ceil())
    }

    /// Test if Not-a-Number (NaN)
    pub fn op_nan(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        self.get_host_float(a, &mut ta);
        if ta == FloatClass::Nan { 1 } else { 0 }
    }

    /// Convert integer to floating-point
    pub fn op_int2float(&self, a: u64, _size_in: usize) -> u64 {
        self.get_encoding(a as f64)
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
}
