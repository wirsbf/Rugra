//! Range utilities: CircleRange for integer value range analysis.
//!
//! Corresponds to Ghidra's `rangeutil.hh` / `rangeutil.cc` (3015 lines).
//!
//! `CircleRange` represents a half-open interval [left, right) over integers
//! mod 2^n, with optional stride. It supports intersection, union, pull-back
//! through pcode ops, and push-forward evaluation.
//!
//! Key class: `CircleRange` — circular integer range.
//! Also: `ValueSet` — a range attached to a Varnode in data-flow analysis.
//!
//! # Status
//! Core CircleRange with construction, containment, intersection, union,
//! and iteration. Pull-back/push-forward through pcode ops is deferred
//! (requires opbehavior integration).

/// A class for manipulating integer value ranges over integers mod 2^n.
/// Corresponds to Ghidra's `CircleRange` (rangeutil.hh:50).
#[derive(Debug, Clone)]
pub struct CircleRange {
    /// Left boundary of the open range [left, right)
    pub left: u64,
    /// Right boundary of the open range [left, right)
    pub right: u64,
    /// Bit mask defining the size (modulus) and stride
    pub mask: u64,
    /// True if the set is empty
    pub isempty: bool,
    /// Explicit step size
    pub step: u64,
}

impl CircleRange {
    /// Construct an empty range.
    pub fn empty() -> Self {
        Self { left: 0, right: 0, mask: 0, isempty: true, step: 1 }
    }

    /// Construct a full range of the given byte size.
    pub fn full(size: usize) -> Self {
        let mask = Self::calc_mask(size);
        Self { left: 0, right: 0, mask, isempty: false, step: 1 }
    }

    /// Construct a range with a single value.
    pub fn single(val: u64, size: usize) -> Self {
        let mask = Self::calc_mask(size);
        let val = val & mask;
        Self { left: val, right: (val + 1) & mask, mask, isempty: false, step: 1 }
    }

    /// Construct given specific boundaries [left, right) with step.
    pub fn new(left: u64, right: u64, size: usize, step: u64) -> Self {
        let mask = Self::calc_mask(size);
        let mut r = Self { left: left & mask, right: right & mask, mask, isempty: false, step };
        r.normalize();
        r
    }

    /// Construct a boolean range (0 or 1).
    pub fn boolean(val: bool) -> Self {
        Self::single(if val { 1 } else { 0 }, 1)
    }

    /// Calculate mask for a given byte size.
    fn calc_mask(size: usize) -> u64 {
        if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 }
    }

    /// Return true if the range is empty.
    pub fn is_empty(&self) -> bool { self.isempty }

    /// Return true if this contains all possible values.
    pub fn is_full(&self) -> bool {
        !self.isempty && self.step == 1 && self.left == self.right
    }

    /// Return true if this contains a single value.
    pub fn is_single(&self) -> bool {
        !self.isempty && self.right == ((self.left + self.step) & self.mask)
    }

    /// Get the left boundary.
    pub fn get_left(&self) -> u64 { self.left }

    /// Get the right boundary (exclusive).
    pub fn get_right(&self) -> u64 { self.right }

    /// Get the mask.
    pub fn get_mask(&self) -> u64 { self.mask }

    /// Get the step.
    pub fn get_step(&self) -> u64 { self.step }

    /// Check containment of a specific integer.
    pub fn contains_val(&self, val: u64) -> bool {
        if self.isempty { return false; }
        if self.is_full() { return true; }
        let val = val & self.mask;
        if self.step != 1 {
            if (val.wrapping_sub(self.left)) % self.step != 0 { return false; }
        }
        if self.left < self.right {
            val >= self.left && val < self.right
        } else {
            val >= self.left || val < self.right
        }
    }

    /// Normalize the representation of full sets.
    fn normalize(&mut self) {
        if self.right == self.left && self.step == 1 {
            // Full range: [x, x) with step 1 = full.
        }
        // Ensure right != left unless it's a full range or empty.
        if self.right == self.left && self.step == 1 && !self.isempty {
            // Full range: left == right is fine.
        }
    }

    /// Intersect this range with another.
    /// Returns: 0=empty result, 1=non-empty intersection, 2=this contains op2.
    pub fn intersect(&mut self, op2: &CircleRange) -> i32 {
        if self.isempty || op2.isempty { self.isempty = true; return 0; }
        if self.is_full() { *self = op2.clone(); return 1; }
        if op2.is_full() { return 1; }
        // Simplified intersection for step==1 ranges.
        if self.step != 1 || op2.step != 1 { return 1; } // Conservatively keep non-empty.
        // For [a, b) and [c, d) over mod mask:
        // Try all 4 wrap-around cases.
        let mut best: Option<CircleRange> = None;
        for start1 in [self.left, self.right] {
            for start2 in [op2.left, op2.right] {
                // Test each possible intersection segment.
            }
        }
        // Simplified: for non-wrapping ranges, compute standard intersection.
        if self.left < self.right && op2.left < op2.right {
            let new_left = self.left.max(op2.left);
            let new_right = self.right.min(op2.right);
            if new_left < new_right {
                self.left = new_left;
                self.right = new_right;
                return 1;
            }
        }
        // Wrapping case: keep current range conservatively.
        1
    }

    /// Union two ranges.
    /// Returns: 0=empty, 1=result in this, 2=this contains op2, 3=op2 contains this.
    pub fn union(&mut self, op2: &CircleRange) -> i32 {
        if self.isempty { *self = op2.clone(); return 1; }
        if op2.isempty { return 2; }
        if self.is_full() { return 2; }
        if op2.is_full() { *self = op2.clone(); return 3; }
        if self.step != 1 || op2.step != 1 { return 1; }
        // Simplified union for non-wrapping ranges.
        if self.left < self.right && op2.left < op2.right {
            if self.contains_val(op2.left) || self.contains_val(op2.right.wrapping_sub(1) & self.mask) {
                let new_left = self.left.min(op2.left);
                let new_right = self.right.max(op2.right);
                self.left = new_left;
                self.right = new_right;
                return 1;
            }
        }
        1
    }

    /// Advance an integer within the range. Returns false when reaching the end.
    pub fn next(&self, val: &mut u64) -> bool {
        *val = (*val + self.step) & self.mask;
        *val != self.right
    }

    /// Get the size of this range (number of elements).
    pub fn get_size(&self) -> u64 {
        if self.isempty { return 0; }
        if self.step == 1 {
            if self.left == self.right { return self.mask + 1; } // Full
            self.right.wrapping_sub(self.left) & self.mask
        } else {
            // With stride, size = (right - left) / step
            let raw = self.right.wrapping_sub(self.left) & self.mask;
            raw / self.step
        }
    }

    /// Convert to complementary range (invert).
    /// Corresponds to `CircleRange::invert` (rangeutil.cc).
    /// Returns the number of pieces: 0=full, 1=single range, 2=two pieces.
    pub fn invert(&mut self) -> i32 {
        if self.isempty {
            self.set_full(8);
            return 0;
        }
        if self.is_full() {
            self.isempty = true;
            return 0;
        }
        // Swap left and right to get complement.
        let tmp = self.left;
        self.left = self.right;
        self.right = tmp;
        if self.step != 1 {
            // Simplified: for stepped ranges, inversion is complex.
            return 1;
        }
        if self.left == self.right {
            self.set_full(8);
            return 0;
        }
        1
    }

    /// Set a completely full range.
    pub fn set_full(&mut self, size: usize) {
        self.mask = Self::calc_mask(size);
        self.left = 0;
        self.right = 0;
        self.step = 1;
        self.isempty = false;
    }

    /// Push-forward this range through a unary operator.
    /// Corresponds to `CircleRange::pushForwardUnary` (rangeutil.hh:94).
    /// Returns true if the transform was possible.
    pub fn push_forward_unary(&mut self, opc: crate::opcodes::OpCode, in1: &CircleRange, in_size: usize, out_size: usize) -> bool {
        let out_mask = Self::calc_mask(out_size);
        match opc {
            crate::opcodes::OpCode::CPUI_COPY | crate::opcodes::OpCode::CPUI_INT_ZEXT => {
                *self = in1.clone();
                self.mask = out_mask;
                true
            }
            crate::opcodes::OpCode::CPUI_INT_SEXT => {
                *self = in1.clone();
                self.mask = out_mask;
                true
            }
            crate::opcodes::OpCode::CPUI_INT_NOT => {
                if in1.is_full() {
                    self.set_full(out_size);
                } else if in1.is_empty() {
                    *self = CircleRange::empty();
                } else {
                    // ~[left,right) = [~right, ~left]
                    self.left = (!in1.right) & out_mask;
                    self.right = (!in1.left) & out_mask;
                    self.mask = out_mask;
                    self.step = in1.step;
                    self.isempty = false;
                }
                true
            }
            crate::opcodes::OpCode::CPUI_INT_NEG => {
                if in1.is_empty() { *self = CircleRange::empty(); return true; }
                // -[left,right) = [-right, -left)
                self.left = ((!in1.right).wrapping_add(1)) & out_mask;
                self.right = ((!in1.left).wrapping_add(1)) & out_mask;
                self.mask = out_mask;
                self.step = in1.step;
                self.isempty = false;
                true
            }
            _ => false,
        }
    }

    /// Push-forward this range through a binary operator.
    /// Corresponds to `CircleRange::pushForwardBinary` (rangeutil.hh:95).
    /// Returns true if the transform was possible.
    pub fn push_forward_binary(&mut self, opc: crate::opcodes::OpCode, in1: &CircleRange, in2: &CircleRange, in_size: usize, out_size: usize, _max_step: i32) -> bool {
        let out_mask = Self::calc_mask(out_size);
        match opc {
            crate::opcodes::OpCode::CPUI_INT_ADD => {
                if in1.is_empty() || in2.is_empty() {
                    *self = CircleRange::empty();
                    return true;
                }
                if in1.is_full() || in2.is_full() {
                    self.set_full(out_size);
                    return true;
                }
                // [a,b) + [c,d) = [a+c, b+d) if no overflow in size
                self.left = in1.left.wrapping_add(in2.left) & out_mask;
                self.right = in1.right.wrapping_add(in2.right) & out_mask;
                self.mask = out_mask;
                self.step = 1;
                self.isempty = false;
                true
            }
            crate::opcodes::OpCode::CPUI_INT_AND => {
                if in1.is_full() { *self = in2.clone(); self.mask = out_mask; return true; }
                if in2.is_full() { *self = in1.clone(); self.mask = out_mask; return true; }
                // Conservative: result could be anything in [0, min(max1,max2))
                false
            }
            crate::opcodes::OpCode::CPUI_INT_OR => {
                if in1.is_full() || in2.is_full() { self.set_full(out_size); return true; }
                false
            }
            crate::opcodes::OpCode::CPUI_INT_XOR => {
                if in1.is_full() || in2.is_full() { self.set_full(out_size); return true; }
                false
            }
            _ => false,
        }
    }

    /// Translate this range to a comparison op.
    /// Corresponds to `CircleRange::translate2Op` (rangeutil.hh:99).
    /// Returns Some((opcode, constant, slot)) if the range can be expressed as a comparison.
    pub fn translate_to_op(&self) -> Option<(crate::opcodes::OpCode, u64, i32)> {
        if self.isempty || self.is_full() { return None; }
        if self.step != 1 { return None; }
        // [0, right) → INT_LESS(right) on slot 1
        if self.left == 0 && self.right != 0 {
            return Some((crate::opcodes::OpCode::CPUI_INT_LESS, self.right, 1));
        }
        // [left, 0) → INT_LESS(left) on slot 0 (i.e. value < left is false)
        if self.right == 0 && self.left != 0 {
            return Some((crate::opcodes::OpCode::CPUI_INT_LESS, self.left, 0));
        }
        // [left, right) non-wrapping → value >= left && value < right
        // Express as INT_LESSEQUAL(left, slot 0) && INT_LESS(right, slot 1) — too complex.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let r = CircleRange::empty();
        assert!(r.is_empty());
        assert!(!r.is_full());
    }

    #[test]
    fn test_full() {
        let r = CircleRange::full(4);
        assert!(!r.is_empty());
        assert!(r.is_full());
        assert_eq!(r.get_mask(), 0xffffffff);
    }

    #[test]
    fn test_single() {
        let r = CircleRange::single(5, 4);
        assert!(r.is_single());
        assert!(r.contains_val(5));
        assert!(!r.contains_val(6));
    }

    #[test]
    fn test_range_contains() {
        let r = CircleRange::new(0, 10, 4, 1);
        assert!(r.contains_val(0));
        assert!(r.contains_val(9));
        assert!(!r.contains_val(10));
    }

    #[test]
    fn test_intersect() {
        let mut a = CircleRange::new(0, 10, 4, 1);
        let b = CircleRange::new(5, 15, 4, 1);
        let res = a.intersect(&b);
        assert!(res >= 1);
        assert_eq!(a.get_left(), 5);
        assert_eq!(a.get_right(), 10);
    }

    #[test]
    fn test_boolean() {
        let r = CircleRange::boolean(true);
        assert!(r.is_single());
        assert!(r.contains_val(1));
        assert!(!r.contains_val(0));
    }

    #[test]
    fn test_invert() {
        let mut r = CircleRange::new(0, 5, 4, 1); // [0,5)
        let res = r.invert();
        assert!(res <= 2);
        // [0,5) complement is [5,0) which is {5,6,...,0xffffffff}
        assert!(!r.contains_val(3));
        assert!(r.contains_val(5));
    }

    #[test]
    fn test_push_forward_add() {
        let mut result = CircleRange::empty();
        let in1 = CircleRange::new(0, 10, 4, 1);  // [0,10)
        let in2 = CircleRange::new(5, 15, 4, 1);   // [5,15)
        let ok = result.push_forward_binary(
            crate::opcodes::OpCode::CPUI_INT_ADD,
            &in1, &in2, 4, 4, 1);
        assert!(ok);
        assert!(result.contains_val(5));  // 0+5=5
        assert!(result.contains_val(24)); // 9+14=23? Actually 9+14=23 < 24
        assert!(!result.contains_val(4));
    }

    #[test]
    fn test_push_forward_copy() {
        let mut result = CircleRange::empty();
        let in1 = CircleRange::new(3, 7, 4, 1);
        let ok = result.push_forward_unary(
            crate::opcodes::OpCode::CPUI_COPY,
            &in1, 4, 4);
        assert!(ok);
        assert!(result.contains_val(3));
        assert!(!result.contains_val(7));
    }

    #[test]
    fn test_translate_to_op() {
        let r = CircleRange::new(0, 5, 4, 1); // [0,5)
        let result = r.translate_to_op();
        assert!(result.is_some());
        let (opc, val, slot) = result.unwrap();
        assert_eq!(opc, crate::opcodes::OpCode::CPUI_INT_LESS);
        assert_eq!(val, 5);
        assert_eq!(slot, 1);
    }
}
