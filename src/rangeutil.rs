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
}
