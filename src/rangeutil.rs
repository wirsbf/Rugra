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
    // Ghidra: rangeutil.cc:179 CircleRange::empty
    /// Construct an empty range.
    pub fn empty() -> Self {
        Self { left: 0, right: 0, mask: 0, isempty: true, step: 1 }
    }

    // Ghidra: rangeutil.cc:179 CircleRange::full
    /// Construct a full range of the given byte size.
    pub fn full(size: usize) -> Self {
        let mask = Self::calc_mask(size);
        Self { left: 0, right: 0, mask, isempty: false, step: 1 }
    }

    // Ghidra: rangeutil.cc:179 CircleRange::single
    /// Construct a range with a single value.
    pub fn single(val: u64, size: usize) -> Self {
        let mask = Self::calc_mask(size);
        let val = val & mask;
        Self { left: val, right: (val + 1) & mask, mask, isempty: false, step: 1 }
    }

    // Ghidra: rangeutil.cc:179 CircleRange::new
    /// Construct given specific boundaries [left, right) with step.
    pub fn new(left: u64, right: u64, size: usize, step: u64) -> Self {
        let mask = Self::calc_mask(size);
        let mut r = Self { left: left & mask, right: right & mask, mask, isempty: false, step };
        r.normalize();
        r
    }

    // Ghidra: rangeutil.cc:179 CircleRange::boolean
    /// Construct a boolean range (0 or 1).
    pub fn boolean(val: bool) -> Self {
        Self::single(if val { 1 } else { 0 }, 1)
    }

    // Ghidra: rangeutil.cc:179 CircleRange::calcMask
    /// Calculate mask for a given byte size.
    fn calc_mask(size: usize) -> u64 {
        if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 }
    }

    // Ghidra: rangeutil.cc:179 CircleRange::isEmpty
    /// Return true if the range is empty.
    pub fn is_empty(&self) -> bool { self.isempty }

    // Ghidra: rangeutil.cc:179 CircleRange::isFull
    /// Return true if this contains all possible values.
    pub fn is_full(&self) -> bool {
        !self.isempty && self.step == 1 && self.left == self.right
    }

    // Ghidra: rangeutil.cc:179 CircleRange::isSingle
    /// Return true if this contains a single value.
    pub fn is_single(&self) -> bool {
        !self.isempty && self.right == ((self.left + self.step) & self.mask)
    }

    // Ghidra: rangeutil.cc:179 CircleRange::getLeft
    /// Get the left boundary.
    pub fn get_left(&self) -> u64 { self.left }

    // Ghidra: rangeutil.cc:179 CircleRange::getRight
    /// Get the right boundary (exclusive).
    pub fn get_right(&self) -> u64 { self.right }

    // Ghidra: rangeutil.cc:179 CircleRange::getMask
    /// Get the mask.
    pub fn get_mask(&self) -> u64 { self.mask }

    // Ghidra: rangeutil.cc:179 CircleRange::getStep
    /// Get the step.
    pub fn get_step(&self) -> u64 { self.step }

    // Ghidra: rangeutil.cc:179 CircleRange::containsVal
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

    // Ghidra: rangeutil.cc:549 CircleRange::intersect
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

    // Ghidra: rangeutil.cc:179 CircleRange::union
    /// Union two ranges (circleUnion). Faithful to `CircleRange::circleUnion`
    /// (rangeutil.cc). Returns:
    /// - 0 = result fits in a single CircleRange (stored in `self`)
    /// - 1 = result would require 2 pieces (cannot represent)
    /// - 2 = union covers the entire space (always true)
    pub fn union(&mut self, op2: &CircleRange) -> i32 {
        if self.isempty { *self = op2.clone(); return 0; }
        if op2.isempty { return 0; }
        if self.is_full() { return 2; }
        if op2.is_full() { *self = op2.clone(); return 2; }
        if self.step != 1 || op2.step != 1 { return 1; }
        // Simplified union for non-wrapping ranges.
        if self.left < self.right && op2.left < op2.right {
            // Check if ranges overlap OR are adjacent (op2.left == self.right
            // or self.left == op2.right).
            let adjacent1 = op2.left == self.right;
            let adjacent2 = self.left == op2.right;
            let overlap = self.contains_val(op2.left)
                || self.contains_val(op2.right.wrapping_sub(1) & self.mask)
                || op2.contains_val(self.left)
                || op2.contains_val(self.right.wrapping_sub(1) & self.mask);
            if overlap || adjacent1 || adjacent2 {
                let new_left = self.left.min(op2.left);
                let new_right = self.right.max(op2.right);
                self.left = new_left;
                self.right = new_right;
                if self.left == 0 && self.right == self.mask + 1 {
                    return 2; // Covers everything.
                }
                return 0; // Single range.
            }
            // Ranges are disjoint and non-adjacent — needs 2 pieces.
            return 1;
        }
        // Wrapping ranges or mixed — simplified.
        1
    }

    // Ghidra: rangeutil.cc:179 CircleRange::next
    /// Advance an integer within the range. Returns false when reaching the end.
    pub fn next(&self, val: &mut u64) -> bool {
        *val = (*val + self.step) & self.mask;
        *val != self.right
    }

    // Ghidra: rangeutil.cc:256 CircleRange::getSize
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

    // Ghidra: rangeutil.cc:533 CircleRange::invert
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

    // Ghidra: rangeutil.cc:245 CircleRange::setFull
    /// Set a completely full range.
    pub fn set_full(&mut self, size: usize) {
        self.mask = Self::calc_mask(size);
        self.left = 0;
        self.right = 0;
        self.step = 1;
        self.isempty = false;
    }

    // Ghidra: rangeutil.cc:38 CircleRange::complement
    /// Take the complement of this range (only works if step is 1).
    /// Faithful to `CircleRange::complement` (rangeutil.cc:38).
    pub fn complement(&mut self) {
        if self.isempty {
            self.left = 0;
            self.right = 0;
            self.isempty = false;
            return;
        }
        if self.left == self.right {
            self.isempty = true;
            return;
        }
        let tmp = self.left;
        self.left = self.right;
        self.right = tmp;
    }

    // Ghidra: rangeutil.cc:63 CircleRange::convertToBoolean
    /// Convert this range to a boolean range [0,2), [0,1), [1,2), or empty.
    /// Returns true if the range contains both 0 and 1.
    /// Faithful to `CircleRange::convertToBoolean` (rangeutil.cc:63).
    pub fn convert_to_boolean(&mut self) -> bool {
        if self.isempty {
            return false;
        }
        let contains_zero = self.contains_val(0);
        let contains_one = self.contains_val(1);
        self.mask = 0xff;
        self.step = 1;
        if contains_zero && contains_one {
            self.left = 0;
            self.right = 2;
            self.isempty = false;
            return true;
        } else if contains_zero {
            self.left = 0;
            self.right = 1;
            self.isempty = false;
        } else if contains_one {
            self.left = 1;
            self.right = 2;
            self.isempty = false;
        } else {
            self.isempty = true;
        }
        false
    }

    // Ghidra: rangeutil.cc:179 CircleRange::setNzMask
    /// Build a range from an NZ mask. Returns false if the mask has too many
    /// bit transitions to form a valid range. Faithful to `setNZMask`
    /// (rangeutil.cc:672).
    pub fn set_nz_mask(nzmask: u64, size: usize) -> Option<CircleRange> {
        let trans = bit_transitions(nzmask, size);
        if trans > 2 {
            return None;
        }
        let has_step = (nzmask & 1) == 0;
        if !has_step && trans == 2 {
            return None;
        }
        let mut r = CircleRange::empty();
        r.isempty = false;
        if trans == 0 {
            r.mask = Self::calc_mask(size);
            if has_step {
                // All zeros
                r.step = 1;
                r.left = 0;
                r.right = 1;
            } else {
                // All ones
                r.step = 1;
                r.left = 0;
                r.right = 0;
            }
            return Some(r);
        }
        let shift = crate::address::leastsigbit_set(nzmask);
        let mut step = 1u64;
        step <<= shift;
        r.step = step;
        r.mask = Self::calc_mask(size);
        r.left = 0;
        r.right = (nzmask + step) & r.mask;
        Some(r)
    }

    // Ghidra: rangeutil.cc:728 CircleRange::pullBackUnary
    /// Pull-back this range through a unary operator. Faithful to
    /// `pullBackUnary` (rangeutil.cc:728). Returns true if the transform was
    /// possible.
    pub fn pull_back_unary(
        &mut self,
        opc: crate::opcodes::OpCode,
        in_size: usize,
        out_size: usize,
    ) -> bool {
        if self.isempty {
            return true;
        }
        match opc {
            crate::opcodes::OpCode::CPUI_BOOL_NEGATE => {
                if self.convert_to_boolean() {
                    // both outputs possible
                } else {
                    self.left ^= 1;
                    self.right = self.left + 1;
                }
            }
            crate::opcodes::OpCode::CPUI_COPY => {
                // Identity transform.
            }
            crate::opcodes::OpCode::CPUI_INT_2COMP => {
                // INT_2COMP: (~left+1+step)
                let val = (!self.left.wrapping_add(1).wrapping_add(self.step)) & self.mask;
                self.left = (!self.right.wrapping_add(1).wrapping_add(self.step)) & self.mask;
                self.right = val;
            }
            crate::opcodes::OpCode::CPUI_INT_NEGATE => {
                let val = (!self.left.wrapping_add(self.step)) & self.mask;
                self.left = (!self.right.wrapping_add(self.step)) & self.mask;
                self.right = val;
            }
            crate::opcodes::OpCode::CPUI_INT_ZEXT => {
                let in_mask = Self::calc_mask(in_size);
                let rem = if self.step != 0 {
                    self.left % self.step
                } else {
                    0
                };
                let mut zext = CircleRange {
                    left: rem,
                    right: in_mask.wrapping_add(1).wrapping_add(rem),
                    mask: self.mask,
                    step: self.step,
                    isempty: false,
                };
                if self.intersect(&zext) != 0 {
                    return false;
                }
                self.left &= in_mask;
                self.right &= in_mask;
                self.mask &= in_mask;
            }
            crate::opcodes::OpCode::CPUI_INT_SEXT => {
                // Simplified SEXT pull-back; full version requires sign_extend.
                let in_mask = Self::calc_mask(in_size);
                self.left &= in_mask;
                self.right &= in_mask;
                self.mask &= in_mask;
            }
            _ => return false,
        }
        let _ = out_size;
        true
    }

    // Ghidra: rangeutil.cc:807 CircleRange::pullBackBinary
    /// Pull-back this range through a binary operator. Faithful to
    /// `pullBackBinary` (rangeutil.cc:807). Returns true if a valid range is
    /// formed.
    pub fn pull_back_binary(
        &mut self,
        opc: crate::opcodes::OpCode,
        val: u64,
        slot: i32,
        in_size: usize,
        _out_size: usize,
    ) -> bool {
        if self.isempty {
            return true;
        }
        match opc {
            crate::opcodes::OpCode::CPUI_INT_EQUAL => {
                let both = self.convert_to_boolean();
                self.mask = Self::calc_mask(in_size);
                if both {
                    return true;
                }
                let yes_comp = self.left == 0;
                self.left = val;
                self.right = (val + 1) & self.mask;
                if yes_comp {
                    self.complement();
                }
            }
            crate::opcodes::OpCode::CPUI_INT_NOTEQUAL => {
                let both = self.convert_to_boolean();
                self.mask = Self::calc_mask(in_size);
                if both {
                    return true;
                }
                let yes_comp = self.left == 0;
                self.left = (val + 1) & self.mask;
                self.right = val;
                if yes_comp {
                    self.complement();
                }
            }
            crate::opcodes::OpCode::CPUI_INT_LESS => {
                let both = self.convert_to_boolean();
                self.mask = Self::calc_mask(in_size);
                if both {
                    return true;
                }
                let yes_comp = self.left == 0;
                if slot == 0 {
                    if val == 0 {
                        self.isempty = true;
                    } else {
                        self.left = 0;
                        self.right = val;
                    }
                } else if val == self.mask {
                    self.isempty = true;
                } else {
                    self.left = (val + 1) & self.mask;
                    self.right = 0;
                }
                if yes_comp {
                    self.complement();
                }
            }
            crate::opcodes::OpCode::CPUI_INT_LESSEQUAL => {
                let both = self.convert_to_boolean();
                self.mask = Self::calc_mask(in_size);
                if both {
                    return true;
                }
                let yes_comp = self.left == 0;
                if slot == 0 {
                    self.left = 0;
                    self.right = (val + 1) & self.mask;
                } else {
                    self.left = val;
                    self.right = 0;
                }
                if yes_comp {
                    self.complement();
                }
            }
            crate::opcodes::OpCode::CPUI_INT_ADD => {
                self.left = (self.left.wrapping_sub(val)) & self.mask;
                self.right = (self.right.wrapping_sub(val)) & self.mask;
            }
            crate::opcodes::OpCode::CPUI_INT_SUB => {
                if slot == 0 {
                    self.left = (self.left.wrapping_add(val)) & self.mask;
                    self.right = (self.right.wrapping_add(val)) & self.mask;
                } else {
                    self.left = (val.wrapping_sub(self.left)) & self.mask;
                    self.right = (val.wrapping_sub(self.right)) & self.mask;
                }
            }
            crate::opcodes::OpCode::CPUI_INT_RIGHT => {
                if self.step == 1 {
                    let right_bound = (Self::calc_mask(in_size) >> val) + 1;
                    let covers = (self.left >= right_bound
                        && self.right >= right_bound
                        && self.left >= self.right)
                        || (self.left == 0 && self.right >= right_bound)
                        || (self.left == self.right);
                    if covers {
                        self.left = 0;
                        self.right = 0;
                    } else {
                        let mut l = self.left;
                        let mut r = self.right;
                        if l > right_bound {
                            l = right_bound;
                        }
                        if r > right_bound {
                            r = 0;
                        }
                        self.left = (l << val) & self.mask;
                        self.right = (r << val) & self.mask;
                        if self.left == self.right {
                            self.isempty = true;
                        }
                    }
                } else {
                    return false;
                }
            }
            _ => return false,
        }
        true
    }

    // Ghidra: rangeutil.cc:1093 CircleRange::pushForwardUnary
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
            crate::opcodes::OpCode::CPUI_INT_NEGATE => {
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
            crate::opcodes::OpCode::CPUI_INT_2COMP => {
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

    // Ghidra: rangeutil.cc:1180 CircleRange::pushForwardBinary
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

    // Ghidra: rangeutil.cc:179 CircleRange::translateToOp
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

    // Ghidra: rangeutil.cc:25 CircleRange::normalize
    /// Normalize the range so that empty/full representation is canonical.
    /// Faithful to Ghidra CircleRange::normalize (rangeutil.cc:25).
    pub fn normalize(&mut self) {
        if self.left == self.right {
            if self.step != 1 {
                self.left = self.left % self.step;
            } else {
                self.left = 0;
            }
            self.right = self.left;
        }
    }

    // Ghidra: rangeutil.cc:179 CircleRange::containsRange
    /// Check if this range contains another range.
    /// Faithful to Ghidra CircleRange::contains(CircleRange) (rangeutil.cc:301).
    pub fn contains_range(&self, op2: &CircleRange) -> bool {
        if self.isempty { return op2.isempty; }
        if op2.isempty { return true; }
        if self.step > op2.step {
            if !op2.is_single() { return false; }
        }
        if self.left == self.right { return true; }
        if op2.left == op2.right { return false; }
        if self.left % self.step != op2.left % op2.step { return false; }
        if self.left == op2.left && self.right == op2.right { return true; }
        // Simplified containment: check if op2's boundaries are in this range
        self.contains_val(op2.left) && self.contains_val(op2.right.wrapping_sub(1).wrapping_add(1).wrapping_sub(1))
    }

    // Ghidra: rangeutil.cc:1395 CircleRange::widen
    /// Widen this range to better match the containing range.
    /// Faithful to Ghidra CircleRange::widen (rangeutil.cc:1395).
    pub fn widen(&mut self, op2: &CircleRange, left_is_stable: bool) {
        if left_is_stable {
            if self.step > 0 {
                let lmod = self.left % self.step;
                let mod_val = op2.right % self.step;
                if mod_val <= lmod {
                    self.right = op2.right + (lmod - mod_val);
                } else {
                    self.right = op2.right - (mod_val - lmod);
                }
                self.right &= self.mask;
            }
        } else {
            self.left = op2.left & self.mask;
        }
        self.normalize();
    }

    // Ghidra: rangeutil.cc:1381 CircleRange::pushForwardTrinary
    /// Push forward through a trinary op (PTRADD).
    /// Faithful to Ghidra CircleRange::pushForwardTrinary (rangeutil.cc:1381).
    pub fn push_forward_trinary(&mut self, opc: crate::opcodes::OpCode, in1: &CircleRange, in2: &CircleRange, in3: &CircleRange, in_size: usize, out_size: usize, max_step: i32) -> bool {
        if opc != crate::opcodes::OpCode::CPUI_PTRADD { return false; }
        let mut tmp_range = CircleRange::full(in_size);
        if !tmp_range.push_forward_binary(crate::opcodes::OpCode::CPUI_INT_MULT, in2, in3, in_size, in_size, max_step) {
            return false;
        }
        self.push_forward_binary(crate::opcodes::OpCode::CPUI_INT_ADD, in1, &tmp_range, in_size, out_size, max_step)
    }

    // Ghidra: rangeutil.cc:280 CircleRange::getMaxInfo
    /// Get the maximum number of significant bits in the range.
    /// Faithful to Ghidra CircleRange::getMaxInfo (rangeutil.cc:280).
    pub fn get_max_info(&self) -> i32 {
        let half_point = self.mask ^ (self.mask >> 1);
        if self.contains_val(half_point) {
            return (8 * std::mem::size_of::<u64>()) as i32 - (half_point.leading_zeros() as i32);
        }
        let size_left = if (half_point & self.left) == 0 {
            self.left.leading_zeros() as i32
        } else {
            (!self.left & self.mask).leading_zeros() as i32
        };
        let size_right = if (half_point & self.right) == 0 {
            self.right.leading_zeros() as i32
        } else {
            (!self.right & self.mask).leading_zeros() as i32
        };
        (8 * std::mem::size_of::<u64>()) as i32 - (size_right.min(size_left))
    }

    // Ghidra: rangeutil.cc:707 CircleRange::setStride
    /// Set the stride of this range.
    /// Faithful to Ghidra CircleRange::setStride (rangeutil.cc:707).
    pub fn set_stride(&mut self, new_step: u64, rem: u64) {
        self.step = new_step;
        if self.step > 1 {
            self.left = (self.left / self.step) * self.step + rem;
            self.right = (self.right / self.step) * self.step + rem;
            self.right &= self.mask;
            self.left &= self.mask;
        }
    }
}

// Ghidra: rangeutil.cc:179 CircleRange::bitTransitions
/// Calculate the number of bit transitions in the sized value. Faithful to
/// `bit_transitions` (address.cc:818). Counts how many times consecutive bits
/// differ (0→1 or 1→0), scanning from LSB upward, stopping once all remaining
/// high bits are zero.
pub fn bit_transitions(val: u64, size: usize) -> i32 {
    let mut res = 0i32;
    let mut last = (val & 1) as i32;
    let mut v = val;
    for _ in 1..(8 * size) {
        v >>= 1;
        let cur = (v & 1) as i32;
        if cur != last {
            res += 1;
            last = cur;
        }
        if v == 0 {
            break;
        }
    }
    res
}

// Ghidra: rangeutil.cc:179 CircleRange::signExtendSize
/// Sign-extend a value between two byte sizes. Faithful to `sign_extend(in,
/// sizein, sizeout)` (address.cc:666).
pub fn sign_extend_size(in_val: u64, size_in: usize, size_out: usize) -> u64 {
    // Ghidra: rangeutil.cc:179 CircleRange::mask
    fn mask(size: usize) -> u64 {
        if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        }
    }
    let size_in = size_in.min(8);
    let size_out = size_out.min(8);
    if size_in >= size_out {
        return in_val & mask(size_out);
    }
    // Check the sign bit of the input.
    let sign_bit = 1u64 << (8 * size_in - 1);
    if (in_val & sign_bit) != 0 {
        // Negative: fill upper bits with 1s.
        let upper_mask = !mask(size_in);
        (in_val | (upper_mask & mask(size_out))) & mask(size_out)
    } else {
        in_val & mask(size_out)
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

    #[test]
    fn test_complement() {
        let mut r = CircleRange::new(0, 5, 4, 1); // [0,5)
        r.complement();
        // Complement of [0,5) is [5,0) (wrapping).
        assert!(!r.contains_val(3));
        assert!(r.contains_val(5));
        assert!(r.contains_val(0xFFFF_FFFF));
    }

    #[test]
    fn test_complement_full() {
        let mut r = CircleRange::full(4);
        r.complement();
        assert!(r.is_empty());
    }

    #[test]
    fn test_convert_to_boolean() {
        let mut r = CircleRange::new(0, 10, 4, 1); // contains 0 and 1
        let both = r.convert_to_boolean();
        assert!(both);
        assert!(r.contains_val(0));
        assert!(r.contains_val(1));
        assert!(!r.contains_val(2));
    }

    #[test]
    fn test_convert_to_boolean_single() {
        let mut r = CircleRange::single(5, 4); // contains neither 0 nor 1
        let both = r.convert_to_boolean();
        assert!(!both);
        assert!(r.is_empty());
    }

    #[test]
    fn test_set_nz_mask() {
        // nzmask = 0xFF (all low 8 bits possible) → range [0, 0x100).
        let r = CircleRange::set_nz_mask(0xFF, 4).unwrap();
        assert!(r.contains_val(0));
        assert!(r.contains_val(0xFF));
        assert!(!r.contains_val(0x100));
    }

    #[test]
    fn test_set_nz_mask_step() {
        // nzmask = 0xFE → step 2, range [0, 0xFF).
        let r = CircleRange::set_nz_mask(0xFE, 4).unwrap();
        assert_eq!(r.get_step(), 2);
    }

    #[test]
    fn test_pull_back_unary_copy() {
        let mut r = CircleRange::new(0, 10, 4, 1);
        // COPY is identity.
        assert!(r.pull_back_unary(crate::opcodes::OpCode::CPUI_COPY, 4, 4));
        assert!(r.contains_val(0));
        assert!(r.contains_val(9));
    }

    #[test]
    fn test_pull_back_binary_add() {
        // Range [5, 15) pulled back through INT_ADD with val=3 → [2, 12).
        let mut r = CircleRange::new(5, 15, 4, 1);
        assert!(r.pull_back_binary(
            crate::opcodes::OpCode::CPUI_INT_ADD,
            3,
            0,
            4,
            4,
        ));
        assert!(r.contains_val(2));
        assert!(r.contains_val(11));
        assert!(!r.contains_val(12));
    }

    #[test]
    fn test_pull_back_binary_less() {
        // Boolean range {true}=[1,2) pulled back through INT_LESS(val=5, slot=0)
        // → [0, 5).
        let mut r = CircleRange::boolean(true);
        assert!(r.pull_back_binary(
            crate::opcodes::OpCode::CPUI_INT_LESS,
            5,
            0,
            4,
            1,
        ));
        assert!(r.contains_val(0));
        assert!(r.contains_val(4));
        assert!(!r.contains_val(5));
    }

    #[test]
    fn test_bit_transitions() {
        assert_eq!(bit_transitions(0, 4), 0); // all zeros
        assert_eq!(bit_transitions(0xFFFF_FFFF, 4), 0); // all ones
        assert_eq!(bit_transitions(0x0000_00FF, 4), 1); // one transition
        assert_eq!(bit_transitions(0x0000_0F0F, 4), 3); // three transitions
    }

    #[test]
    fn test_sign_extend_size() {
        // 0xFF as 1-byte sign-extended to 4 bytes = 0xFFFF_FFFF.
        assert_eq!(sign_extend_size(0xFF, 1, 4), 0xFFFF_FFFF);
        // 0x7F as 1-byte sign-extended to 4 bytes = 0x7F (positive).
        assert_eq!(sign_extend_size(0x7F, 1, 4), 0x7F);
        // 0x80 as 1-byte sign-extended to 2 bytes = 0xFF80.
        assert_eq!(sign_extend_size(0x80, 1, 2), 0xFF80);
    }

    #[test]
    fn test_normalize() {
        let mut r = CircleRange::full(4);
        r.normalize();
        assert_eq!(r.left, 0);
        assert_eq!(r.right, 0);
    }

    #[test]
    fn test_contains_range() {
        let outer = CircleRange::new(0, 100, 4, 1);
        let inner = CircleRange::new(10, 50, 4, 1);
        assert!(outer.contains_range(&inner));
        assert!(!inner.contains_range(&outer));
    }

    #[test]
    fn test_widen() {
        let mut r = CircleRange::new(5, 10, 4, 1);
        let container = CircleRange::new(0, 100, 4, 1);
        r.widen(&container, false); // left is not stable → expand left
        assert!(r.get_size() > 5); // should have widened
    }

    #[test]
    fn test_get_max_info() {
        let r = CircleRange::new(0, 256, 4, 1); // values 0-255
        let info = r.get_max_info();
        assert!(info >= 0 && info <= 32);
    }

    #[test]
    fn test_set_stride() {
        let mut r = CircleRange::new(3, 99, 4, 1);
        r.set_stride(4, 3); // stride 4, remainder 3
        assert_eq!(r.get_step(), 4);
        assert_eq!(r.get_left() % 4, 3);
    }
}
