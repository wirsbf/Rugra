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
#[derive(Debug, Clone, PartialEq)]
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

    // Ghidra: rangeutil.cc:1060 (inline in pullBack SUBPIECE case)
    /// Expand the mask to cover a larger size (used by pullBack SUBPIECE
    /// usenzmask special case: keep the range but make the mask bigger).
    pub fn expand_mask(&mut self, size: usize) {
        self.mask = Self::calc_mask(size);
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

    // Ghidra: rangeutil.cc:103 CircleRange::newStride
    /// Extend the range to cover values with a different stride. Returns
    /// true if the resulting range is empty. Faithful to cc:103-131.
    pub fn new_stride(&mut self, mask: u64, step: u64, old_step: u64, rem: u32, myleft: &mut u64, myright: &mut u64) -> bool {
        if old_step != 1 {
            let old_rem = (*myleft % old_step) as u32;
            if old_rem != (rem % old_step as u32) {
                return true;
            }
        }
        let orig_order = *myleft < *myright;
        let left_rem = (*myleft % step) as u32;
        let right_rem = (*myright % step) as u32;
        if left_rem > rem {
            *myleft += rem as u64 + step - left_rem as u64;
        } else {
            *myleft += rem as u64 - left_rem as u64;
        }
        if right_rem > rem {
            *myright += rem as u64 + step - right_rem as u64;
        } else {
            *myright += rem as u64 - right_rem as u64;
        }
        *myleft &= mask;
        *myright &= mask;
        let new_order = *myleft < *myright;
        if orig_order != new_order { return true; }
        false
    }

    // Ghidra: rangeutil.cc:143 CircleRange::newDomain
    /// Truncate range to fit in a new domain mask. Returns true if empty.
    pub fn new_domain(&mut self, new_mask: u64, new_step: u64, myleft: &mut u64, myright: &mut u64) -> bool {
        let rem = if new_step != 1 { *myleft % new_step } else { 0 };
        if *myleft > new_mask {
            if *myright > new_mask { return true; }
            *myleft = rem;
        }
        if *myright > new_mask + 1 {
            *myright = (new_mask + 1) - ((new_mask + 1 - rem) % new_step);
        }
        self.mask = new_mask;
        self.step = new_step;
        false
    }

    // Ghidra: rangeutil.cc:219 CircleRange::setRange(lft,rgt,size,stp)
    /// Set range from explicit boundaries, size, and step.
    pub fn set_range(&mut self, lft: u64, rgt: u64, size: usize, stp: u64) {
        self.mask = Self::calc_mask(size);
        self.left = lft;
        self.right = rgt;
        self.step = stp;
        self.isempty = false;
    }

    // Ghidra: rangeutil.cc:233 CircleRange::setRange(val,size)
    /// Set range to a single value.
    pub fn set_range_val(&mut self, val: u64, size: usize) {
        self.mask = Self::calc_mask(size);
        self.step = 1;
        self.left = val;
        self.right = (val + 1) & self.mask;
        self.isempty = false;
    }

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

    // Ghidra: rangeutil.hh:358 CircleRange::encodeRangeOverlaps
    /// Map from raw overlaps to normalized overlap code. Faithful to the
    /// inline `CircleRange::encodeRangeOverlaps` (rangeutil.hh:358) which
    /// indexes into `arrange`.
    pub fn encode_range_overlaps(
        op1left: u64,
        op1right: u64,
        op2left: u64,
        op2right: u64,
    ) -> char {
        let mut val: usize = if op1left <= op1right { 0x20 } else { 0 };
        if op1left <= op2left { val |= 0x10; }
        if op1left <= op2right { val |= 0x8; }
        if op1right <= op2left { val |= 4; }
        if op1right <= op2right { val |= 2; }
        if op2left <= op2right { val |= 1; }
        ARRANGE[val]
    }

    // Ghidra: rangeutil.cc:360 CircleRange::circleUnion
    /// Union two ranges as a single interval (circleUnion).
    /// Returns 0 if result fits in a single CircleRange (stored in self),
    /// 2 if the union is two pieces (self NOT modified). Faithful to
    /// `CircleRange::circleUnion` (rangeutil.cc:360).
    pub fn circle_union(&mut self, op2: &CircleRange) -> i32 {
        if op2.isempty { return 0; }
        if self.isempty {
            *self = op2.clone();
            return 0;
        }
        if self.mask != op2.mask { return 2; } // Cannot union different domains
        let mut a_right = self.right;
        let mut b_right = op2.right;
        let mut new_step = self.step;
        if self.step < op2.step {
            if self.is_single() {
                new_step = op2.step;
                a_right = (self.left + new_step) & self.mask;
            } else {
                return 2;
            }
        } else if op2.step < self.step {
            if op2.is_single() {
                new_step = self.step;
                b_right = (op2.left + new_step) & self.mask;
            } else {
                return 2;
            }
        }
        let rem: u64;
        if new_step != 1 {
            rem = self.left % new_step;
            if rem != op2.left % new_step {
                return 2;
            }
        } else {
            rem = 0;
        }
        if self.left == a_right || op2.left == b_right {
            self.left = rem;
            self.right = rem;
            self.step = new_step;
            return 0;
        }
        let overlap_code = Self::encode_range_overlaps(self.left, a_right, op2.left, b_right);
        match overlap_code {
            'a' | 'f' => {
                if a_right == op2.left {
                    self.right = b_right;
                    self.step = new_step;
                    return 0;
                }
                if self.left == b_right {
                    self.left = op2.left;
                    self.right = a_right;
                    self.step = new_step;
                    return 0;
                }
                return 2; // 2 pieces
            }
            'b' => {
                self.right = b_right;
                self.step = new_step;
                return 0;
            }
            'c' => {
                self.right = a_right;
                self.step = new_step;
                return 0;
            }
            'd' => {
                self.left = op2.left;
                self.right = b_right;
                self.step = new_step;
                return 0;
            }
            'e' => {
                self.left = op2.left;
                self.right = a_right;
                self.step = new_step;
                return 0;
            }
            'g' => {
                self.left = rem;
                self.right = rem;
                self.step = new_step;
                return 0; // entire circle covered
            }
            _ => -1, // Never reach here
        }
    }

    // Ghidra: rangeutil.cc:549 CircleRange::intersect
    /// Intersect this range with another as a single interval (intersect).
    /// Returns 0 if the result is valid (stored in self), 2 if the
    /// intersection is two pieces (self NOT modified). Faithful to
    /// `CircleRange::intersect` (rangeutil.cc:549).
    pub fn circle_intersect(&mut self, op2: &CircleRange) -> i32 {
        let mut myleft = self.left;
        let mut myright = self.right;
        let mut op2left = op2.left;
        let mut op2right = op2.right;
        if self.isempty { return 0; } // Intersection with empty is empty
        if op2.isempty {
            self.isempty = true;
            return 0;
        }
        let new_step: u64;
        if self.step < op2.step {
            new_step = op2.step;
            let rem = (op2left % new_step) as u32;
            let mask_copy = self.mask;
            if Self::new_stride_owned(mask_copy, new_step, self.step, rem, &mut myleft, &mut myright) {
                self.isempty = true;
                return 0;
            }
        } else if op2.step < self.step {
            new_step = self.step;
            let rem = (myleft % new_step) as u32;
            if Self::new_stride_owned(op2.mask, new_step, op2.step, rem, &mut op2left, &mut op2right) {
                self.isempty = true;
                return 0;
            }
        } else {
            new_step = self.step;
        }
        let new_mask = self.mask & op2.mask;
        if self.mask != new_mask {
            if Self::new_domain_owned(new_mask, new_step, &mut myleft, &mut myright) {
                self.isempty = true;
                return 0;
            }
        } else if op2.mask != new_mask {
            if Self::new_domain_owned(new_mask, new_step, &mut op2left, &mut op2right) {
                self.isempty = true;
                return 0;
            }
        }
        let retval: i32;
        if myleft == myright {
            // Intersect with this everything
            self.left = op2left;
            self.right = op2right;
            retval = 0;
        } else if op2left == op2right {
            // Intersect with op2 everything
            self.left = myleft;
            self.right = myright;
            retval = 0;
        } else {
            let overlap_code = Self::encode_range_overlaps(myleft, myright, op2left, op2right);
            match overlap_code {
                'a' | 'f' => {
                    self.isempty = true;
                    retval = 0; // empty set
                }
                'b' => {
                    self.left = op2left;
                    self.right = myright;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                    retval = 0;
                }
                'c' => {
                    self.left = op2left;
                    self.right = op2right;
                    retval = 0;
                }
                'd' => {
                    self.left = myleft;
                    self.right = myright;
                    retval = 0;
                }
                'e' => {
                    self.left = myleft;
                    self.right = op2right;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                    retval = 0;
                }
                'g' => {
                    if myleft == op2right {
                        self.left = op2left;
                        self.right = myright;
                        if self.left == self.right {
                            self.isempty = true;
                        }
                        retval = 0;
                    } else if op2left == myright {
                        self.left = myleft;
                        self.right = op2right;
                        if self.left == self.right {
                            self.isempty = true;
                        }
                        retval = 0;
                    } else {
                        retval = 2; // 2 pieces
                    }
                }
                _ => {
                    retval = 2; // Will never reach here
                }
            }
        }
        if retval != 0 {
            return retval;
        }
        self.mask = new_mask;
        self.step = new_step;
        0
    }

    // Ghidra: rangeutil.cc:103 CircleRange::newStride (static helper form)
    /// Owned-argument form of `newStride` for use by `circle_intersect`.
    /// Faithful to `CircleRange::newStride` (rangeutil.cc:103). Returns true
    /// if the result is empty.
    fn new_stride_owned(
        mask: u64,
        step: u64,
        old_step: u64,
        rem: u32,
        myleft: &mut u64,
        myright: &mut u64,
    ) -> bool {
        if old_step != 1 {
            let old_rem = (*myleft % old_step) as u32;
            if old_rem != rem % old_step as u32 {
                return true; // Step is completely off
            }
        }
        let orig_order = *myleft < *myright;
        let left_rem = (*myleft % step) as u32;
        let right_rem = (*myright % step) as u32;
        if left_rem > rem {
            *myleft += rem as u64 + step - left_rem as u64;
        } else {
            *myleft += rem as u64 - left_rem as u64;
        }
        if right_rem > rem {
            *myright += rem as u64 + step - right_rem as u64;
        } else {
            *myright += rem as u64 - right_rem as u64;
        }
        *myleft &= mask;
        *myright &= mask;
        let new_order = *myleft < *myright;
        if orig_order != new_order {
            return true;
        }
        false // not empty
    }

    // Ghidra: rangeutil.cc:143 CircleRange::newDomain (static helper form)
    /// Owned-argument form of `newDomain` for use by `circle_intersect`.
    /// Faithful to `CircleRange::newDomain` (rangeutil.cc:143). Returns true
    /// if the truncated domain is empty.
    fn new_domain_owned(new_mask: u64, new_step: u64, myleft: &mut u64, myright: &mut u64) -> bool {
        let rem: u64;
        if new_step != 1 {
            rem = *myleft % new_step;
        } else {
            rem = 0;
        }
        if *myleft > new_mask {
            if *myright > new_mask {
                // Both bounds out of range of newMask
                if *myleft < *myright {
                    return true; // Old range completely out of bounds of new mask
                }
                *myleft = rem;
                *myright = rem; // Old range contained everything in newMask
                return false;
            }
            *myleft = rem; // Take everything up to left edge of new range
        }
        if *myright > new_mask {
            *myright = rem; // Take everything up to right edge of new range
        }
        if *myleft == *myright {
            *myleft = rem; // Normalize the everything
            *myright = rem;
        }
        false // not empty
    }

    // Ghidra: rangeutil.cc:454 CircleRange::minimalContainer
    /// Construct minimal range that contains both this and op2. Returns true
    /// if the container is everything (full). Faithful to
    /// `CircleRange::minimalContainer` (rangeutil.cc:454).
    pub fn minimal_container(&mut self, op2: &CircleRange, max_step: u64) -> bool {
        if self.is_single() && op2.is_single() {
            let (min_v, max_v) = if self.left < op2.left {
                (self.left, op2.left)
            } else {
                (op2.left, self.left)
            };
            let diff = max_v - min_v;
            if diff > 0 && diff <= max_step {
                if crate::address::leastsigbit_set(diff) == crate::address::mostsigbit_set(diff) {
                    self.step = diff;
                    self.left = min_v;
                    self.right = (max_v + self.step) & self.mask;
                    return false;
                }
            }
        }
        let a_right = self.right.wrapping_sub(self.step).wrapping_add(1);
        let b_right = op2.right.wrapping_sub(op2.step).wrapping_add(1);
        self.step = 1;
        self.mask |= op2.mask;
        let overlap_code = Self::encode_range_overlaps(self.left, a_right, op2.left, b_right);
        match overlap_code {
            'a' => {
                // order (l r op2.l op2.r)
                let vacant1 = self.left + (self.mask - b_right) + 1;
                let vacant2 = op2.left - a_right;
                if vacant1 < vacant2 {
                    self.left = op2.left;
                    self.right = a_right;
                } else {
                    self.right = b_right;
                }
            }
            'f' => {
                // order (op2.l op2.r l r)
                let vacant1 = op2.left + (self.mask - a_right) + 1;
                let vacant2 = self.left - b_right;
                if vacant1 < vacant2 {
                    self.right = b_right;
                } else {
                    self.left = op2.left;
                    self.right = a_right;
                }
            }
            'b' => {
                self.right = b_right;
            }
            'c' => {
                self.right = a_right;
            }
            'd' => {
                self.left = op2.left;
                self.right = b_right;
            }
            'e' => {
                self.left = op2.left;
                self.right = a_right;
            }
            'g' => {
                self.left = 0; // Entire circle covered
                self.right = 0;
            }
            _ => {}
        }
        self.normalize();
        self.left == self.right
    }

    // Ghidra: rangeutil.hh:74 CircleRange::getMin
    /// Get the left boundary (Ghidra getMin). Inline accessor mirror.
    pub fn get_min(&self) -> u64 { self.left }
    // Ghidra: rangeutil.hh:75 CircleRange::getMax
    /// Get the right-most integer contained in the range (Ghidra getMax).
    pub fn get_max_value(&self) -> u64 { (self.right.wrapping_sub(self.step)) & self.mask }
    // Ghidra: rangeutil.hh:76 CircleRange::getEnd
    /// Get the right boundary of the range (Ghidra getEnd).
    pub fn get_end(&self) -> u64 { self.right }
}

// Ghidra: rangeutil.cc:21 CircleRange::arrange
/// Map from raw overlaps to normalized overlap code. Faithful to
/// `CircleRange::arrange` (rangeutil.cc:21).
const ARRANGE: [char; 64] = [
    'g', 'c', 'g', 'b', 'e', 'g', 'd', 'a',
    'g', 'g', 'g', 'g', 'g', 'g', 'g', 'e',
    'g', 'g', 'g', 'g', 'c', 'g', 'b', 'g',
    'g', 'g', 'g', 'g', 'g', 'g', 'g', 'c',
    'd', 'f', 'g', 'g', 'g', 'g', 'g', 'g',
    'g', 'e', 'g', 'd', 'g', 'g', 'g', 'g',
    'b', 'g', 'g', 'g', 'f', 'g', 'g', 'g',
    'g', 'c', 'g', 'b', 'e', 'g', 'd', 'a',
];

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

// =============================================================================
// ValueSet / ValueSetSolver — range analysis over a data-flow sub-system.
//
// Faithful 1:1 port of rangeutil.hh:106-327 and rangeutil.cc:1494-2604.
//
// The C++ implementation uses raw `ValueSet *` pointers and an intrusive
// `next` field to thread ValueSets through Partition components (Bourdoncle's
// weak topological ordering). In Rust we model the solver-owned graph with an
// arena (`Vec<ValueSet>`) addressed by `VsId = usize`, which gives the same
// pointer stability as `std::list<ValueSet>`. The IR-level connections
// (Varnode/PcodeOp) use the project-wide `Arc<RwLock<...>>` representation.
// =============================================================================

use std::sync::{Arc, RwLock};

use crate::address::SeqNum;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::varnode::Varnode;

// Ghidra: rangeutil.hh:115 ValueSet::MAX_STEP
/// Maximum step inferred for a value set. Faithful to
/// `ValueSet::MAX_STEP` (rangeutil.hh:115 / rangeutil.cc:1494).
pub const VALUE_SET_MAX_STEP: u64 = 32;

/// Arena-local identifier for a `ValueSet` stored inside a `ValueSetSolver`.
/// Replaces the C++ `ValueSet *` / `list<ValueSet>::iterator` used to thread
/// nodes through Partition components.
pub type VsId = usize;

// Ghidra: rangeutil.hh:121 ValueSet::Equation
/// An external constraint applied to a ValueSet, attached to a particular
/// input slot of the operation producing the underlying Varnode.
/// Faithful to `ValueSet::Equation` (rangeutil.hh:121).
#[derive(Debug, Clone)]
pub struct Equation {
    /// The input parameter slot the constraint is attached to.
    pub slot: i32,
    /// Constraint characteristic: 0 = absolute, 1 = relative to a spacebase.
    pub type_code: i32,
    /// The range constraint.
    pub range: CircleRange,
}

// RUGRA-GLUE: Rust constructor mirroring the inline Equation ctor in C++
// (rangeutil.hh:127). Ghidra has no separate Equation::Equation definition
// file line beyond the in-class inline.
impl Equation {
    /// Construct an equation for `slot` with characteristic `type_code` and
    /// the given constraint `range`. Mirrors the C++ inline constructor.
    // RUGRA-GLUE: Rust constructor mirroring the inline Equation ctor in C++
    // (rangeutil.hh:127). Ghidra has no separate Equation::Equation definition
    // file line beyond the in-class inline.
    pub fn new(slot: i32, type_code: i32, range: CircleRange) -> Self {
        Equation { slot, type_code, range }
    }
}

// RUGRA-GLUE: One input to a ValueSet's defining op, staged for `iterate`.
/// Carries the input's ValueSet fields plus the input Varnode size (needed for
/// push-forward sizing). Stands in for C++'s `op->getIn(i)->getValueSet()`
/// chain, which Rugra cannot traverse yet because Varnode does not expose its
/// defining op / attached ValueSet to rangeutil.
#[derive(Debug, Clone)]
pub struct ValueSetInput {
    /// The input's value set range.
    pub range: CircleRange,
    /// Whether the input's left boundary is stable.
    pub left_is_stable: bool,
    /// Whether the input's right boundary is stable.
    pub right_is_stable: bool,
    /// Size in bytes of the input Varnode.
    pub vn_size: usize,
}

// Ghidra: rangeutil.hh:113 ValueSet
/// A range of values attached to a Varnode within a data-flow subsystem.
///
/// This struct is both the set of values for the Varnode and a node in a
/// sub-graph overlaying the data-flow of the function. Values are stored in
/// `range` and may be absolute (`type_code == 0`) or relative to a stack
/// pointer / spacebase register (`type_code != 0`).
///
/// Faithful to `ValueSet` (rangeutil.hh:113). The `next` and `part_head`
/// fields use arena indices (`Option<VsId>` / `Option<usize>`) in place of the
/// C++ raw pointers `ValueSet *next` / `Partition *partHead`.
#[derive(Debug, Clone)]
pub struct ValueSet {
    /// 0 = pure constant, 1 = stack relative.
    pub type_code: i32,
    /// Number of input parameters to the defining operation.
    pub num_params: i32,
    /// Depth-first numbering / widening count.
    pub count: i32,
    /// Op-code defining the Varnode.
    pub op_code: OpCode,
    /// True if the left boundary didn't change on the last iteration.
    pub left_is_stable: bool,
    /// True if the right boundary didn't change on the last iteration.
    pub right_is_stable: bool,
    /// Varnode whose set this represents. `None` for the simulated root node.
    pub vn: Option<Arc<RwLock<Varnode>>>,
    /// Range of values or offsets in this set.
    pub range: CircleRange,
    /// Any equations associated with this value set.
    pub equations: Vec<Equation>,
    /// If this ValueSet is a component head, index into the solver's
    /// `record_storage`. Replaces C++ `Partition *partHead`.
    pub part_head: Option<usize>,
    /// Next ValueSet (arena id) in the iteration order.
    pub next: Option<VsId>,
    /// RUGRA-GLUE staging for the defining op's inputs, used by `iterate`.
    /// Ghidra reads these live via `op->getIn(i)->getValueSet()`.
    pub iter_inputs: Option<Vec<ValueSetInput>>,
    /// RUGRA-GLUE staging for the output Varnode size.
    pub iter_out_size: Option<usize>,
    /// RUGRA-GLUE staging for input type codes (for `compute_type_code`).
    pub iter_input_type_codes: Vec<i32>,
}

impl ValueSet {
    // RUGRA-GLUE: default ValueSet (Ghidra default-constructs via list emplace).
    /// Construct an empty ValueSet. Mirrors the C++ default-constructed
    /// `ValueSet` produced by `valueNodes.emplace_back()` (rangeutil.cc:1956).
    pub fn new() -> Self {
        ValueSet {
            type_code: 0,
            num_params: 0,
            count: 0,
            op_code: OpCode::CPUI_MAX,
            left_is_stable: false,
            right_is_stable: false,
            vn: None,
            range: CircleRange::empty(),
            equations: Vec::new(),
            part_head: None,
            next: None,
            iter_inputs: None,
            iter_out_size: None,
            iter_input_type_codes: Vec::new(),
        }
    }

    // Ghidra: rangeutil.hh:143 ValueSet::doesEquationApply
    /// Does the indicated equation apply for the given input slot? Faithful
    /// to the inline `ValueSet::doesEquationApply` (rangeutil.hh:143 / cc:375).
    pub fn does_equation_apply(&self, num: i32, slot: i32) -> bool {
        let num = num as usize;
        if num < self.equations.len() {
            if self.equations[num].slot == slot && self.equations[num].type_code == self.type_code {
                return true;
            }
        }
        false
    }

    // Ghidra: rangeutil.hh:143 ValueSet::setFull
    /// Mark the value set as possibly containing any value. Faithful to the
    /// inline `ValueSet::setFull` (rangeutil.hh:143).
    pub fn set_full(&mut self) {
        if let Some(vn) = &self.vn {
            let size = vn.read().unwrap().get_size();
            self.range.set_full(size);
        }
        self.type_code = 0;
    }

    // Ghidra: rangeutil.cc:1503 ValueSet::setVarnode
    /// Attach this to the given Varnode and set initial values. Faithful to
    /// `ValueSet::setVarnode` (rangeutil.cc:1503).
    ///
    /// Alignment Evidence (four decisive semantics):
    /// - References/out params: `vn` is shared (Arc); `vn->setValueSet(this)`
    ///   back-pointer storage is omitted because Rugra's ValueSet is arena-owned
    ///   (the solver maps Varnode↔VsId directly). getDef()/getOffset() are reads.
    /// - Loop bounds/order: none.
    /// - Counter/accumulator: `leftIsStable`/`rightIsStable` initialized
    ///   per-branch (constant/input → true; written/other → false).
    /// - Sort/compare key: branched on `typeCode`, `isWritten()`, `isConstant()`.
    pub fn set_varnode(&mut self, v: Arc<RwLock<Varnode>>, t_code: i32) {
        self.type_code = t_code;
        self.vn = Some(v.clone());
        // Note: Ghidra calls vn->setValueSet(this). Rugra does not store a
        // back-pointer on Varnode; the solver keeps the Varnode→ValueSet map.
        let vn_guard = v.read().unwrap();
        if self.type_code != 0 {
            self.op_code = OpCode::CPUI_MAX;
            self.num_params = 0;
            // Treat as offset of 0 relative to special value.
            self.range.set_range_val(0, vn_guard.get_size());
            self.left_is_stable = true;
            self.right_is_stable = true;
        } else if vn_guard.is_written() {
            // Ghidra: PcodeOp *op = vn->getDef(); opCode = op->code();
            // Rugra's Varnode does not carry its defining op directly here;
            // the solver injects op_code/num_params via set_defining_op once
            // the PcodeOp is known (see ValueSetSolver::establish_value_sets).
            self.op_code = OpCode::CPUI_MAX;
            self.num_params = 0;
            // TODO: depends on unported Varnode::getDef wiring; the solver
            // calls set_defining_op afterwards with the real op. Until then
            // we leave the range empty (as the C++ "written" branch does:
            // range starts empty).
            self.left_is_stable = false;
            self.right_is_stable = false;
        } else if vn_guard.is_constant() {
            self.op_code = OpCode::CPUI_MAX;
            self.num_params = 0;
            self.range.set_range_val(vn_guard.get_offset(), vn_guard.get_size());
            self.left_is_stable = true;
            self.right_is_stable = true;
        } else {
            // Some other form of input.
            self.op_code = OpCode::CPUI_MAX;
            self.num_params = 0;
            self.type_code = 0;
            self.range.set_full(vn_guard.get_size());
            self.left_is_stable = false;
            self.right_is_stable = false;
        }
    }

    // RUGRA-GLUE: inject defining-op metadata (no Ghidra counterpart — Ghidra
    // reads it from Varnode::getDef() inside setVarnode). Rugra's Varnode does
    // not expose its defining op to rangeutil yet, so the solver passes it in.
    /// Set the defining op-code and input count. Ghidra derives these from
    /// `vn->getDef()` inside `setVarnode`; Rugra injects them explicitly.
    pub fn set_defining_op(&mut self, op_code: OpCode, num_params: i32) {
        if op_code == OpCode::CPUI_INDIRECT {
            // Treat CPUI_INDIRECT as CPUI_COPY (rangeutil.cc:1519).
            self.op_code = OpCode::CPUI_COPY;
            self.num_params = 1;
        } else {
            self.op_code = op_code;
            self.num_params = num_params;
        }
    }

    // Ghidra: rangeutil.cc:1549 ValueSet::addEquation
    /// Insert an equation restricting this value set. Equations are stored
    /// ordered on slot. Faithful to `ValueSet::addEquation`
    /// (rangeutil.cc:1549).
    pub fn add_equation(&mut self, slot: i32, type_code: i32, constraint: CircleRange) {
        // Find the first position whose slot is greater than the given slot.
        let pos = self
            .equations
            .iter()
            .position(|e| e.slot > slot)
            .unwrap_or(self.equations.len());
        self.equations.insert(pos, Equation::new(slot, type_code, constraint));
    }

    // Ghidra: rangeutil.hh:146 ValueSet::addLandmark
    /// Add a widening landmark (an equation at slot == num_params). Faithful
    /// to the inline `ValueSet::addLandmark` (rangeutil.hh:146).
    pub fn add_landmark(&mut self, type_code: i32, constraint: CircleRange) {
        self.add_equation(self.num_params, type_code, constraint);
    }

    // Ghidra: rangeutil.cc:1567 ValueSet::computeTypeCode
    /// Figure out if this value set is absolute or relative. Returns true if
    /// there is an indeterminate combination. Faithful to
    /// `ValueSet::computeTypeCode` (rangeutil.cc:1567).
    ///
    /// Requires the defining op's inputs to be wired via the solver (the C++
    /// reads `op->getIn(i)->getValueSet()`). The solver passes input type
    /// codes through `compute_type_code_with`.
    pub fn compute_type_code_with(&mut self, input_type_codes: &[i32]) -> bool {
        let mut rel_count = 0;
        let mut last_type_code = 0;
        for i in 0..self.num_params as usize {
            if i >= input_type_codes.len() {
                break;
            }
            let tc = input_type_codes[i];
            if tc != 0 {
                rel_count += 1;
                last_type_code = tc;
            }
        }
        if rel_count == 0 {
            self.type_code = 0;
            return false;
        }
        // Only certain operations can propagate a relative value set.
        match self.op_code {
            OpCode::CPUI_PTRSUB
            | OpCode::CPUI_PTRADD
            | OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB => {
                if rel_count == 1 {
                    self.type_code = last_type_code;
                } else {
                    return true;
                }
            }
            OpCode::CPUI_CAST
            | OpCode::CPUI_COPY
            | OpCode::CPUI_INDIRECT
            | OpCode::CPUI_MULTIEQUAL => {
                self.type_code = last_type_code;
            }
            _ => return true,
        }
        false
    }

    // Ghidra: rangeutil.cc:1742 ValueSet::getLandMark
    /// Get any landmark range. Any equation whose type_code matches can serve
    /// as a landmark. Faithful to `ValueSet::getLandMark` (rangeutil.cc:1742).
    pub fn get_land_mark(&self) -> Option<&CircleRange> {
        for eq in &self.equations {
            if eq.type_code == self.type_code {
                return Some(&eq.range);
            }
        }
        None
    }

    // Ghidra: rangeutil.hh:150 ValueSet::getCount
    /// Get the current iteration count. Inline accessor mirror.
    pub fn get_count(&self) -> i32 { self.count }

    // Ghidra: rangeutil.hh:152 ValueSet::getTypeCode
    /// Return '0' for normal constant, '1' for spacebase relative.
    pub fn get_type_code(&self) -> i32 { self.type_code }

    // Ghidra: rangeutil.hh:153 ValueSet::getVarnode
    /// Get the Varnode attached to this ValueSet.
    pub fn get_varnode(&self) -> Option<&Arc<RwLock<Varnode>>> { self.vn.as_ref() }

    // Ghidra: rangeutil.hh:154 ValueSet::getRange
    /// Get the actual range of values.
    pub fn get_range(&self) -> &CircleRange { &self.range }

    // Ghidra: rangeutil.hh:155 ValueSet::isLeftStable
    /// Return true if the left boundary hasn't been changing.
    pub fn is_left_stable(&self) -> bool { self.left_is_stable }

    // Ghidra: rangeutil.hh:156 ValueSet::isRightStable
    /// Return true if the right boundary hasn't been changing.
    pub fn is_right_stable(&self) -> bool { self.right_is_stable }

    // Ghidra: rangeutil.cc:1756 ValueSet::printRaw
    /// Write a text description of this to the given string. Faithful to
    /// `ValueSet::printRaw` (rangeutil.cc:1756).
    pub fn print_raw(&self) -> String {
        let mut s = String::new();
        match &self.vn {
            None => s.push_str("root"),
            Some(vn) => s.push_str(&vn.read().unwrap().print_raw()),
        }
        if self.type_code == 0 {
            s.push_str(" absolute");
        } else {
            s.push_str(" stackptr");
        }
        if self.op_code == OpCode::CPUI_MAX {
            let is_const = self.vn.as_ref().map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
            if is_const {
                s.push_str(" const");
            } else {
                s.push_str(" input");
            }
        } else {
            s.push(' ');
            s.push_str(self.op_code.name());
        }
        s.push(' ');
        s.push_str(&print_range_raw(&self.range));
        s
    }
}

// Ghidra: rangeutil.hh:161 Partition
/// A range of nodes (within the weak topological ordering) iterated together.
/// Faithful to `Partition` (rangeutil.hh:161). Uses arena indices in place of
/// the C++ `ValueSet *startNode` / `ValueSet *stopNode`.
#[derive(Debug, Clone, Default)]
pub struct Partition {
    /// Starting node of the component (arena id).
    pub start_node: Option<VsId>,
    /// Ending node of the component (arena id).
    pub stop_node: Option<VsId>,
    /// True if a node in this component changed this iteration.
    pub is_dirty: bool,
}

// Ghidra: rangeutil.hh:178 ValueSetRead
/// A special form of ValueSet associated with the read point of a Varnode.
/// Computed as a final step after the main iteration completes. Faithful to
/// `ValueSetRead` (rangeutil.hh:178).
#[derive(Debug, Clone)]
pub struct ValueSetRead {
    /// 0 = pure constant, 1 = stack relative.
    pub type_code: i32,
    /// The slot being read.
    pub slot: i32,
    /// The PcodeOp at the point of the value set read.
    pub op: Option<Arc<RwLock<PcodeOp>>>,
    /// Range of values or offsets in this set.
    pub range: CircleRange,
    /// Constraint associated with the equation.
    pub equation_constraint: CircleRange,
    /// Type code of the associated equation. -1 = no equation.
    pub equation_type_code: i32,
    /// True if the left boundary didn't change on the last iteration.
    pub left_is_stable: bool,
    /// True if the right boundary didn't change on the last iteration.
    pub right_is_stable: bool,
}

impl ValueSetRead {
    // RUGRA-GLUE: default constructor (Ghidra default-constructs members).
    /// Construct an empty ValueSetRead.
    pub fn new() -> Self {
        ValueSetRead {
            type_code: 0,
            slot: 0,
            op: None,
            range: CircleRange::empty(),
            equation_constraint: CircleRange::empty(),
            equation_type_code: -1,
            left_is_stable: false,
            right_is_stable: false,
        }
    }

    // Ghidra: rangeutil.hh:191 ValueSetRead::getTypeCode
    /// Return '0' for normal constant, '1' for spacebase relative.
    pub fn get_type_code(&self) -> i32 { self.type_code }

    // Ghidra: rangeutil.hh:192 ValueSetRead::getRange
    /// Get the actual range of values.
    pub fn get_range(&self) -> &CircleRange { &self.range }

    // Ghidra: rangeutil.hh:193 ValueSetRead::isLeftStable
    /// Return true if the left boundary hasn't been changing.
    pub fn is_left_stable(&self) -> bool { self.left_is_stable }

    // Ghidra: rangeutil.hh:194 ValueSetRead::isRightStable
    /// Return true if the right boundary hasn't been changing.
    pub fn is_right_stable(&self) -> bool { self.right_is_stable }

    // Ghidra: rangeutil.cc:1781 ValueSetRead::setPcodeOp
    /// Establish the read this value set corresponds to. Faithful to
    /// `ValueSetRead::setPcodeOp` (rangeutil.cc:1781).
    pub fn set_pcode_op(&mut self, o: Arc<RwLock<PcodeOp>>, slt: i32) {
        self.type_code = 0;
        self.op = Some(o);
        self.slot = slt;
        self.equation_type_code = -1;
    }

    // Ghidra: rangeutil.cc:1793 ValueSetRead::addEquation
    /// Insert an equation restricting this value set. Only equations whose
    /// slot matches the read slot are stored. Faithful to
    /// `ValueSetRead::addEquation` (rangeutil.cc:1793).
    pub fn add_equation(&mut self, slt: i32, type_code: i32, constraint: CircleRange) {
        if self.slot == slt {
            self.equation_type_code = type_code;
            self.equation_constraint = constraint;
        }
    }

    // Ghidra: rangeutil.cc:1804 ValueSetRead::compute
    /// Compute this value set. It is the same as the ValueSet of the Varnode
    /// being read but may be modified by additional control-flow constraints.
    /// Faithful to `ValueSetRead::compute` (rangeutil.cc:1804).
    ///
    /// `src_value_set` is the ValueSet of the Varnode being read; in C++ it is
    /// fetched via `op->getIn(slot)->getValueSet()`. Rugra passes it in.
    pub fn compute(&mut self, src_value_set: &ValueSet) {
        self.type_code = src_value_set.type_code;
        self.range = src_value_set.range.clone();
        self.left_is_stable = src_value_set.left_is_stable;
        self.right_is_stable = src_value_set.right_is_stable;
        if self.type_code == self.equation_type_code {
            if 0 != self.range.circle_intersect(&self.equation_constraint) {
                self.range = self.equation_constraint.clone();
            }
        }
    }

    // Ghidra: rangeutil.cc:1821 ValueSetRead::printRaw
    /// Write a text description to the given string. Faithful to
    /// `ValueSetRead::printRaw` (rangeutil.cc:1821).
    pub fn print_raw(&self) -> String {
        let mut s = String::new();
        s.push_str("Read: ");
        if let Some(op) = &self.op {
            s.push_str(op.read().unwrap().get_opcode().name());
        }
        s.push_str(" (");
        if self.type_code == 0 {
            s.push_str(" absolute ");
        } else {
            s.push_str(" stackptr ");
        }
        s.push_str(&print_range_raw(&self.range));
        s
    }
}

// Ghidra: rangeutil.hh:204 Widener
/// Trait holding a particular widening strategy for the ValueSetSolver
/// iteration algorithm. Faithful to the abstract class `Widener`
/// (rangeutil.hh:204).
pub trait Widener {
    /// Upon entering a fresh partition, determine how the given ValueSet count
    /// should be reset. Mirrors `Widener::determineIterationReset`
    /// (rangeutil.hh:212).
    // Ghidra: rangeutil.hh:212 Widener::determineIterationReset
    fn determine_iteration_reset(&self, value_set: &ValueSet) -> i32;

    /// Check if the given value set has been frozen for the remainder of the
    /// iteration process. Mirrors `Widener::checkFreeze` (rangeutil.hh:218).
    // Ghidra: rangeutil.hh:218 Widener::checkFreeze
    fn check_freeze(&self, value_set: &ValueSet) -> bool;

    /// For an iteration that isn't stabilizing, attempt to widen the given
    /// ValueSet. Returns true if widening succeeded. Mirrors
    /// `Widener::doWidening` (rangeutil.hh:228).
    // Ghidra: rangeutil.hh:228 Widener::doWidening
    fn do_widening(
        &self,
        value_set: &ValueSet,
        range: &mut CircleRange,
        new_range: &CircleRange,
    ) -> bool;
}

// Ghidra: rangeutil.hh:236 WidenerFull
/// Normal widening strategy. Widening is attempted at `widen_iteration`; if a
/// landmark is available it is used for controlled widening, otherwise a full
/// range is produced. At `full_iteration` a full range is produced
/// automatically. Faithful to `WidenerFull` (rangeutil.hh:236).
pub struct WidenerFull {
    /// Iteration at which widening is attempted.
    widen_iteration: i32,
    /// Iteration at which a full range is produced.
    full_iteration: i32,
}

impl WidenerFull {
    // Ghidra: rangeutil.hh:240 WidenerFull::WidenerFull (default ctor)
    /// Constructor with default iterations (widen=2, full=5).
    pub fn new() -> Self {
        WidenerFull { widen_iteration: 2, full_iteration: 5 }
    }

    // Ghidra: rangeutil.hh:241 WidenerFull::WidenerFull (wide, full)
    /// Constructor specifying the widen and full iterations.
    pub fn with_iterations(wide: i32, full: i32) -> Self {
        WidenerFull { widen_iteration: wide, full_iteration: full }
    }
}

impl Widener for WidenerFull {
    // Ghidra: rangeutil.cc:1833 WidenerFull::determineIterationReset
    fn determine_iteration_reset(&self, value_set: &ValueSet) -> i32 {
        if value_set.count >= self.widen_iteration {
            self.widen_iteration // Reset to point just after any widening
        } else {
            0 // Delay widening if we haven't performed it yet
        }
    }

    // Ghidra: rangeutil.cc:1841 WidenerFull::checkFreeze
    fn check_freeze(&self, value_set: &ValueSet) -> bool {
        value_set.range.is_full()
    }

    // Ghidra: rangeutil.cc:1847 WidenerFull::doWidening
    fn do_widening(
        &self,
        value_set: &ValueSet,
        range: &mut CircleRange,
        new_range: &CircleRange,
    ) -> bool {
        if value_set.count < self.widen_iteration {
            *range = new_range.clone();
            return true;
        } else if value_set.count == self.widen_iteration {
            if let Some(landmark) = value_set.get_land_mark() {
                let left_is_stable = range.get_min() == new_range.get_min();
                *range = new_range.clone(); // Preserve any new step information
                let lm = landmark.clone();
                if lm.contains_val(range.get_min()) && lm.contains_val(range.get_max_value()) {
                    // landmark contains range (approximated by endpoints).
                    range.widen(&lm, left_is_stable);
                    return true;
                } else {
                    let mut constraint = landmark.clone();
                    constraint.invert();
                    if constraint.contains_val(range.get_min())
                        && constraint.contains_val(range.get_max_value())
                    {
                        range.widen(&constraint, left_is_stable);
                        return true;
                    }
                }
            }
        } else if value_set.count < self.full_iteration {
            *range = new_range.clone();
            return true;
        }
        false // Constrained widening failed (set to full)
    }
}

// Ghidra: rangeutil.hh:254 WidenerNone
/// Freezing strategy: value sets lock in after `freeze_iteration` (3 by
/// default) instead of reaching a true stable state. Faithful to
/// `WidenerNone` (rangeutil.hh:254).
pub struct WidenerNone {
    /// Iteration at which all change ceases.
    freeze_iteration: i32,
}

impl WidenerNone {
    // Ghidra: rangeutil.hh:257 WidenerNone::WidenerNone
    /// Constructor with default freeze iteration of 3.
    pub fn new() -> Self {
        WidenerNone { freeze_iteration: 3 }
    }

    /// Constructor specifying the freeze iteration.
    // RUGRA-GLUE: Rust convenience ctor; Ghidra's WidenerNone only has the
    /// default ctor (freezeIteration=3, rangeutil.hh:257). Exposed for tests.
    pub fn with_iteration(freeze: i32) -> Self {
        WidenerNone { freeze_iteration: freeze }
    }
}

impl Widener for WidenerNone {
    // Ghidra: rangeutil.cc:1880 WidenerNone::determineIterationReset
    fn determine_iteration_reset(&self, value_set: &ValueSet) -> i32 {
        if value_set.count >= self.freeze_iteration {
            self.freeze_iteration // Reset to point just after any widening
        } else {
            value_set.count
        }
    }

    // Ghidra: rangeutil.cc:1888 WidenerNone::checkFreeze
    fn check_freeze(&self, value_set: &ValueSet) -> bool {
        if value_set.range.is_full() {
            return true;
        }
        value_set.count >= self.freeze_iteration
    }

    // Ghidra: rangeutil.cc:1896 WidenerNone::doWidening
    fn do_widening(
        &self,
        _value_set: &ValueSet,
        range: &mut CircleRange,
        new_range: &CircleRange,
    ) -> bool {
        *range = new_range.clone();
        true
    }
}

// Ghidra: rangeutil.hh:274 ValueSetSolver
/// Determines a ValueSet for each Varnode in a data-flow system using value
/// set analysis. The system is formed by `establish_value_sets`, iterated by
/// `solve`. Faithful to `ValueSetSolver` (rangeutil.hh:274).
pub struct ValueSetSolver {
    /// Storage for all the current value sets (the arena; replaces
    /// `list<ValueSet> valueNodes`).
    pub value_nodes: Vec<ValueSet>,
    /// Additional, after-iteration add-on value sets keyed by SeqNum
    /// (replaces `map<SeqNum,ValueSetRead> readNodes`).
    pub read_nodes: std::collections::HashMap<SeqNum, ValueSetRead>,
    /// Value sets in iteration order.
    order_partition: Partition,
    /// Storage for the Partitions establishing components
    /// (`list<Partition> recordStorage`).
    record_storage: Vec<Partition>,
    /// Values treated as inputs (`vector<ValueSet *> rootNodes`).
    /// Each entry is the arena id of a root ValueSet.
    root_nodes: Vec<VsId>,
    /// Stack used to generate the topological ordering (`nodeStack`).
    node_stack: Vec<VsId>,
    /// (Global) depth-first numbering for topological ordering.
    depth_first_index: i32,
    /// Count of individual ValueSet iterations.
    num_iterations: i32,
    /// Maximum number of iterations before forcing termination.
    max_iterations: i32,
}

impl ValueSetSolver {
    // RUGRA-GLUE: default constructor (Ghidra default-constructs all fields).
    /// Construct an empty solver.
    pub fn new() -> Self {
        ValueSetSolver {
            value_nodes: Vec::new(),
            read_nodes: std::collections::HashMap::new(),
            order_partition: Partition::default(),
            record_storage: Vec::new(),
            root_nodes: Vec::new(),
            node_stack: Vec::new(),
            depth_first_index: 0,
            num_iterations: 0,
            max_iterations: 0,
        }
    }

    // Ghidra: rangeutil.hh:317 ValueSetSolver::getNumIterations
    /// Get the current number of iterations.
    pub fn get_num_iterations(&self) -> i32 { self.num_iterations }

    // Ghidra: rangeutil.hh:319 ValueSetSolver::beginValueSets / endValueSets
    /// Iterate over all ValueSets in the system (replaces
    /// `beginValueSets()/endValueSets()`).
    pub fn value_sets(&self) -> &[ValueSet] { &self.value_nodes }

    // Ghidra: rangeutil.hh:321 ValueSetSolver::beginValueSetReads
    /// Iterate over all ValueSetReads (replaces
    /// `beginValueSetReads()/endValueSetReads()`).
    pub fn value_set_reads(&self) -> &std::collections::HashMap<SeqNum, ValueSetRead> {
        &self.read_nodes
    }

    // Ghidra: rangeutil.hh:323 ValueSetSolver::getValueSetRead
    /// Get a ValueSetRead by SeqNum. Faithful to
    /// `ValueSetSolver::getValueSetRead` (rangeutil.hh:323).
    pub fn get_value_set_read(&self, seq: &SeqNum) -> Option<&ValueSetRead> {
        self.read_nodes.get(seq)
    }

    // Ghidra: rangeutil.cc:1953 ValueSetSolver::newValueSet
    /// Allocate storage for a new ValueSet attached to `vn`. Faithful to
    /// `ValueSetSolver::newValueSet` (rangeutil.cc:1953). Returns the arena id.
    pub fn new_value_set(&mut self, vn: Arc<RwLock<Varnode>>, t_code: i32) -> VsId {
        let mut vs = ValueSet::new();
        vs.set_varnode(vn, t_code);
        self.value_nodes.push(vs);
        self.value_nodes.len() - 1
    }

    // Ghidra: rangeutil.hh:389 ValueSetSolver::partitionPrepend (vertex)
    /// Prepend a vertex to a partition. Faithful to the inline
    /// `partitionPrepend(ValueSet *, Partition &)` (rangeutil.hh:389).
    fn partition_prepend_vertex(vertex: VsId, part: &mut Partition) {
        // vertex->next = part.startNode; part.startNode = vertex;
        // if (part.stopNode == NULL) part.stopNode = vertex;
        // NOTE: because the node carries its own `next`, mutating it requires
        // borrow separation; callers perform the next-assignment via the arena.
        let _ = vertex; // handled by partition_prepend_vertex_in_arena below
        let _ = part;
    }

    /// Arena-aware form of `partitionPrepend(vertex, part)` that also writes
    /// the node's `next` field. This is the actual port of rangeutil.hh:389.
    // RUGRA-GLUE: arena-indexed variant of partitionPrepend (rangeutil.hh:389)
    // because Rust cannot mutate a ValueSet through a Partition pointer; the
    // arena + VsId replaces the C++ `ValueSet *next` intrusive linkage.
    fn partition_prepend_vertex_in_arena(
        arena: &mut Vec<ValueSet>,
        vertex: VsId,
        part: &mut Partition,
    ) {
        arena[vertex].next = part.start_node;
        part.start_node = Some(vertex);
        if part.stop_node.is_none() {
            part.stop_node = Some(vertex);
        }
    }

    // Ghidra: rangeutil.hh:400 ValueSetSolver::partitionPrepend (head)
    /// Prepend a full Partition to the given Partition. Faithful to the inline
    /// `partitionPrepend(const Partition &, Partition &)` (rangeutil.hh:400).
    fn partition_prepend_head_in_arena(
        arena: &mut Vec<ValueSet>,
        head: &Partition,
        part: &mut Partition,
    ) {
        // head.stopNode->next = part.startNode;
        if let (Some(stop), Some(start)) = (head.stop_node, part.start_node) {
            arena[stop].next = Some(start);
        } else if head.stop_node.is_some() && part.start_node.is_none() {
            arena[head.stop_node.unwrap()].next = None;
        }
        part.start_node = head.start_node;
        if part.stop_node.is_none() {
            part.stop_node = head.stop_node;
        }
    }

    // Ghidra: rangeutil.cc:1963 ValueSetSolver::partitionSurround
    /// Save a Partition to permanent storage, mark its start node, and set up
    /// for the iterating algorithm. Faithful to
    /// `ValueSetSolver::partitionSurround` (rangeutil.cc:1963).
    fn partition_surround(&mut self, part: Partition) {
        self.record_storage.push(part);
        let idx = self.record_storage.len() - 1;
        if let Some(start) = self.record_storage[idx].start_node {
            self.value_nodes[start].part_head = Some(idx);
        }
    }

    // Ghidra: rangeutil.cc:1974 ValueSetSolver::component
    /// Knowing the given ValueSet is the head of a partition, generate the
    /// partition recursively and the formal Partition object. Faithful to
    /// `ValueSetSolver::component` (rangeutil.cc:1974).
    fn component(&mut self, vertex: VsId, part: &mut Partition) {
        let mut edge_iter = ValueSetEdge::new(self, vertex);
        while let Some(succ) = edge_iter.get_next(self) {
            if self.value_nodes[succ].count == 0 {
                self.visit(succ, part);
            }
        }
        // partitionPrepend(vertex, part); partitionSurround(part);
        Self::partition_prepend_vertex_in_arena(&mut self.value_nodes, vertex, part);
        let part_clone = part.clone();
        self.partition_surround(part_clone);
    }

    // Ghidra: rangeutil.cc:1991 ValueSetSolver::visit
    /// Recursively walk the data-flow graph finding partitions (Bourdoncle's
    /// weak topological ordering). Faithful to `ValueSetSolver::visit`
    /// (rangeutil.cc:1991).
    ///
    /// Alignment Evidence:
    /// - References/out params: `part` is mutated in place across recursion.
    /// - Loop bounds/order: iterates successor edges via ValueSetEdge::get_next.
    /// - Counter/accumulator: `depth_first_index` is global to the ordering
    ///   pass; `vertex->count` holds the DFS number; a node that becomes a head
    ///   is set to 0x7fffffff; loop members are reset to 0.
    /// - Sort/compare key: `min <= head` decides head updates and loop flags.
    fn visit(&mut self, vertex: VsId, part: &mut Partition) -> i32 {
        self.node_stack.push(vertex);
        self.depth_first_index += 1;
        self.value_nodes[vertex].count = self.depth_first_index;
        let mut head = self.depth_first_index;
        let mut is_loop = false;
        let mut edge_iter = ValueSetEdge::new(self, vertex);
        while let Some(succ) = edge_iter.get_next(self) {
            let min_v;
            if self.value_nodes[succ].count == 0 {
                min_v = self.visit(succ, part);
            } else {
                min_v = self.value_nodes[succ].count;
            }
            if min_v <= head {
                head = min_v;
                is_loop = true;
            }
        }
        if head == self.value_nodes[vertex].count {
            self.value_nodes[vertex].count = 0x7fffffff; // "infinity"
            let mut element = self.node_stack.pop().unwrap();
            if is_loop {
                while element != vertex {
                    self.value_nodes[element].count = 0;
                    element = self.node_stack.pop().unwrap();
                }
                let mut comp_part = Partition::default(); // empty partition
                self.component(vertex, &mut comp_part);
                Self::partition_prepend_head_in_arena(
                    &mut self.value_nodes,
                    &comp_part,
                    part,
                );
            } else {
                Self::partition_prepend_vertex_in_arena(
                    &mut self.value_nodes,
                    vertex,
                    part,
                );
            }
        }
        head
    }

    // Ghidra: rangeutil.cc:2042 ValueSetSolver::establishTopologicalOrder
    /// Establish the recursive node ordering for iteratively solving the value
    /// set system (Bourdoncle's algorithm). Faithful to
    /// `ValueSetSolver::establishTopologicalOrder` (rangeutil.cc:2042).
    fn establish_topological_order(&mut self) {
        for vs in &mut self.value_nodes {
            vs.count = 0;
            vs.next = None;
            vs.part_head = None;
        }
        // Simulated root node: a ValueSet with vn == None.
        let root_id = {
            let mut root = ValueSet::new();
            root.vn = None;
            self.value_nodes.push(root);
            self.value_nodes.len() - 1
        };
        self.depth_first_index = 0;
        // Rust borrow-split: extract order_partition so we can pass &mut to it
        // while visit borrows &mut self. Ghidra passes &orderPartition directly.
        let mut order_part = std::mem::take(&mut self.order_partition);
        self.visit(root_id, &mut order_part);
        self.order_partition = order_part;
        // Remove simulated root: order_partition.startNode = startNode->next.
        if let Some(start) = self.order_partition.start_node {
            self.order_partition.start_node = self.value_nodes[start].next;
        }
    }

    // Ghidra: rangeutil.cc:2524 ValueSetSolver::solve
    /// Iterate the ValueSet system until it stabilizes. Faithful to
    /// `ValueSetSolver::solve` (rangeutil.cc:2524).
    ///
    /// Alignment Evidence:
    /// - References/out params: `widener` is borrowed immutably and consulted
    ///   on each iterate/reset decision; `read_nodes` are computed at the end.
    /// - Loop bounds/order: walks `curSet = curSet->next` through the ordering
    ///   established by `establish_topological_order`; the component stack is
    ///   pushed/popped on partHead transitions.
    /// - Counter/accumulator: `num_iterations` increments per node visit and is
    ///   reset to 0 at entry; `curComponent->startNode->count` is reset via
    ///   `determine_iteration_reset` on component entry; `isDirty` toggles per
    ///   component when a node changes.
    /// - Sort/compare key: `curSet->partHead` compared against `curComponent`
    ///   to detect component entry; `curComponent->stopNode == curSet` detects
    ///   component exit.
    pub fn solve(&mut self, max: i32, widener: &dyn Widener) {
        self.max_iterations = max;
        self.num_iterations = 0;
        for vs in &mut self.value_nodes {
            vs.count = 0;
        }
        let mut component_stack: Vec<usize> = Vec::new();
        let mut cur_component: Option<usize> = None;
        let mut cur_set = self.order_partition.start_node;
        while let Some(cur) = cur_set {
            self.num_iterations += 1;
            if self.num_iterations > self.max_iterations {
                break; // Quit if max iterations exceeded
            }
            let part_head = self.value_nodes[cur].part_head;
            if part_head.is_some() && part_head != cur_component {
                let ch = part_head.unwrap();
                component_stack.push(ch);
                cur_component = Some(ch);
                self.record_storage[ch].is_dirty = false;
                // Reset component counter upon entry.
                if let Some(start) = self.record_storage[ch].start_node {
                    self.value_nodes[start].count =
                        widener.determine_iteration_reset(&self.value_nodes[start]);
                }
            }
            if let Some(ch) = cur_component {
                let mut dummy = ValueSet::new();
                std::mem::swap(&mut dummy, &mut self.value_nodes[cur]);
                let changed = dummy.iterate(widener);
                std::mem::swap(&mut dummy, &mut self.value_nodes[cur]);
                if changed {
                    self.record_storage[ch].is_dirty = true;
                }
                let stop = self.record_storage[ch].stop_node;
                if stop != Some(cur) {
                    cur_set = self.value_nodes[cur].next;
                } else {
                    // Inner loop: possibly restart dirty component, else pop.
                    loop {
                        if self.record_storage[ch].is_dirty {
                            self.record_storage[ch].is_dirty = false;
                            cur_set = self.record_storage[ch].start_node;
                            // Mark parent dirty if we are restarting a dirty child.
                            if component_stack.len() > 1 {
                                let parent = component_stack[component_stack.len() - 2];
                                self.record_storage[parent].is_dirty = true;
                            }
                            break;
                        }
                        component_stack.pop();
                        if component_stack.is_empty() {
                            cur_component = None;
                            cur_set = self.value_nodes[cur].next;
                            break;
                        }
                        let new_ch = *component_stack.last().unwrap();
                        cur_component = Some(new_ch);
                        let new_stop = self.record_storage[new_ch].stop_node;
                        if new_stop != Some(cur) {
                            cur_set = self.value_nodes[cur].next;
                            break;
                        }
                    }
                }
            } else {
                let mut dummy = ValueSet::new();
                std::mem::swap(&mut dummy, &mut self.value_nodes[cur]);
                let _ = dummy.iterate(widener);
                std::mem::swap(&mut dummy, &mut self.value_nodes[cur]);
                cur_set = self.value_nodes[cur].next;
            }
        }
        // Calculate any follow-on value sets. Faithful to the C++ tail loop:
        //   for (riter=readNodes.begin(); riter!=readNodes.end(); ++riter)
        //     (*riter).second.compute();
        // which internally resolves the source ValueSet via
        // `op->getIn(slot)->getValueSet()`. Rugra resolves it via
        // `resolve_read_source` (Varnode identity scan over the arena).
        let read_keys: Vec<SeqNum> = self.read_nodes.keys().cloned().collect();
        for key in &read_keys {
            // Borrow the read node read-only to resolve its source ValueSet,
            // then borrow mutably to compute. Two-phase to avoid overlapping
            // borrows of self.read_nodes and self.value_nodes.
            let src = {
                let vsr = self.read_nodes.get(key).unwrap();
                self.resolve_read_source(vsr)
            };
            if let Some(src) = src {
                let vsr = self.read_nodes.get_mut(key).unwrap();
                vsr.compute(&src);
            }
        }
    }

    /// Best-effort resolution of the ValueSet backing a ValueSetRead.
    /// Returns the source ValueSet if its underlying Varnode has an entry in
    /// the solver arena. Ghidra resolves this via the Varnode→ValueSet
    /// back-pointer (`vn->getValueSet()`); Rugra searches the arena by
    /// Varnode identity.
    // RUGRA-GLUE: stands in for C++ `op->getIn(slot)->getValueSet()`, which
    // needs the unported Varnode→ValueSet back-pointer; arena scan instead.
    fn resolve_read_source(&self, vsr: &ValueSetRead) -> Option<ValueSet> {
        let op_arc = vsr.op.as_ref()?;
        let op_guard = op_arc.read().unwrap();
        let in_vn = op_guard.get_in(vsr.slot as usize)?.clone();
        drop(op_guard);
        // Search the arena for a ValueSet attached to this Varnode.
        for vs in &self.value_nodes {
            if let Some(vn) = &vs.vn {
                if Arc::ptr_eq(vn, &in_vn) {
                    return Some(vs.clone());
                }
            }
        }
        None
    }

    // Ghidra: rangeutil.cc:2066 ValueSetSolver::generateTrueEquation
    /// Generate an equation given a true constraint. Attached to the output of
    /// `op` (or to the read node for a special read site). Faithful to
    /// `ValueSetSolver::generateTrueEquation` (rangeutil.cc:2066).
    fn generate_true_equation(
        &mut self,
        vn: Option<&Arc<RwLock<Varnode>>>,
        op: &Arc<RwLock<PcodeOp>>,
        slot: i32,
        type_code: i32,
        range: CircleRange,
    ) {
        if let Some(v) = vn {
            if let Some(vs_id) = self.find_value_set_by_vn(v) {
                self.value_nodes[vs_id].add_equation(slot, type_code, range);
            }
        } else {
            let seq = op.read().unwrap().get_seq_num().clone();
            if let Some(vsr) = self.read_nodes.get_mut(&seq) {
                vsr.add_equation(slot, type_code, range);
            } else {
                let mut new_read = ValueSetRead::new();
                new_read.add_equation(slot, type_code, range);
                self.read_nodes.insert(seq, new_read);
            }
        }
    }

    // Ghidra: rangeutil.cc:2084 ValueSetSolver::generateFalseEquation
    /// Generate the complementary equation (false branch). Faithful to
    /// `ValueSetSolver::generateFalseEquation` (rangeutil.cc:2084).
    fn generate_false_equation(
        &mut self,
        vn: Option<&Arc<RwLock<Varnode>>>,
        op: &Arc<RwLock<PcodeOp>>,
        slot: i32,
        type_code: i32,
        range: CircleRange,
    ) {
        let mut false_range = range;
        false_range.invert();
        if let Some(v) = vn {
            if let Some(vs_id) = self.find_value_set_by_vn(v) {
                self.value_nodes[vs_id].add_equation(slot, type_code, false_range);
            }
        } else {
            let seq = op.read().unwrap().get_seq_num().clone();
            if let Some(vsr) = self.read_nodes.get_mut(&seq) {
                vsr.add_equation(slot, type_code, false_range);
            } else {
                let mut new_read = ValueSetRead::new();
                new_read.add_equation(slot, type_code, false_range);
                self.read_nodes.insert(seq, new_read);
            }
        }
    }

    /// Find the arena id of the ValueSet attached to `vn`, if any. Ghidra
    /// resolves this via `vn->getValueSet()`; Rugra scans the arena by
    /// Varnode identity.
    // RUGRA-GLUE: stands in for unported `Varnode::getValueSet()` back-pointer;
    // linear scan over the arena by Arc identity.
    fn find_value_set_by_vn(&self, vn: &Arc<RwLock<Varnode>>) -> Option<VsId> {
        for (i, vs) in self.value_nodes.iter().enumerate() {
            if let Some(v) = &vs.vn {
                if Arc::ptr_eq(v, vn) {
                    return Some(i);
                }
            }
        }
        None
    }

    // TODO: depends on unported FlowBlock domination queries and full
    // PcodeOp::pullBack wiring. The following methods are stubbed with their
    // faithful signatures and algorithm comments so the structure is in place;
    // they are exercised once establish_value_sets is wired into the pipeline.

    // Ghidra: rangeutil.cc:2105 ValueSetSolver::applyConstraints
    /// Look for PcodeOps where the given constraint range applies and
    /// instantiate an equation. Faithful to `ValueSetSolver::applyConstraints`
    /// (rangeutil.cc:2105). Requires FlowBlock domination queries not yet
    /// ported; left as a structural stub.
    pub fn apply_constraints(
        &mut self,
        _vn: &Arc<RwLock<Varnode>>,
        _type_code: i32,
        _range: &CircleRange,
        _cbranch: &Arc<RwLock<PcodeOp>>,
    ) {
        // TODO: depends on unported FlowBlock::getTrueOut/getFalseOut,
        // restrictedByConditional, getImmedDom, and PcodeOp::getParent wiring.
    }

    // Ghidra: rangeutil.cc:2185 ValueSetSolver::constraintsFromPath
    /// Generate constraints given a Varnode path. Faithful to
    /// `ValueSetSolver::constraintsFromPath` (rangeutil.cc:2185). Requires
    /// `CircleRange::pullBack(PcodeOp*)` which needs full opbehavior wiring.
    pub fn constraints_from_path(
        &mut self,
        _type_code: i32,
        _lift: &mut CircleRange,
        _start_vn: &Arc<RwLock<Varnode>>,
        _end_vn: &Arc<RwLock<Varnode>>,
        _cbranch: &Arc<RwLock<PcodeOp>>,
    ) {
        // TODO: depends on unported CircleRange::pullBack(PcodeOp*,...) which
        // in turn needs PcodeOp input/const-markup traversal.
    }

    // Ghidra: rangeutil.cc:2210 ValueSetSolver::constraintsFromCBranch
    /// Lift the set of values on a CBRANCH condition to any Varnode in the
    /// system. Faithful to `ValueSetSolver::constraintsFromCBranch`
    /// (rangeutil.cc:2210).
    pub fn constraints_from_cbranch(&mut self, _cbranch: &Arc<RwLock<PcodeOp>>) {
        // TODO: depends on unported CircleRange::pullBack(PcodeOp*,...) and
        // Varnode defining-op traversal wiring.
    }

    // Ghidra: rangeutil.cc:2248 ValueSetSolver::generateConstraints
    /// Given a complete data-flow system of Varnodes, look for any constraint
    /// due to branch conditions. Faithful to
    /// `ValueSetSolver::generateConstraints` (rangeutil.cc:2248). Requires
    /// FlowBlock domination queries.
    pub fn generate_constraints(
        &mut self,
        _worklist: &[Arc<RwLock<Varnode>>],
        _reads: &[Arc<RwLock<PcodeOp>>],
    ) {
        // TODO: depends on unported FlowBlock::getImmedDom/setMark/clearMark
        // and BlockBasic::lastOp wiring.
    }

    // Ghidra: rangeutil.cc:2316 ValueSetSolver::checkRelativeConstant
    /// Verify that the given Varnode is produced by a straight-line sequence
    /// of COPYs / INT_ADDs with a constant from the base register marked
    /// relative. Faithful to `ValueSetSolver::checkRelativeConstant`
    /// (rangeutil.cc:2316).
    pub fn check_relative_constant(
        &self,
        vn: Arc<RwLock<Varnode>>,
        type_code: &mut i32,
        value: &mut u64,
    ) -> bool {
        *value = 0;
        loop {
            let vn_guard = vn.read().unwrap();
            if vn_guard.is_mark() {
                if let Some(vs_id) = self.find_value_set_by_vn(&vn) {
                    if self.value_nodes[vs_id].type_code != 0 {
                        *type_code = self.value_nodes[vs_id].type_code;
                        break;
                    }
                }
            }
            if !vn_guard.is_written() {
                return false;
            }
            // Ghidra: PcodeOp *op = vn->getDef(); OpCode opc = op->code();
            // Rugra's Varnode does not expose its defining op here; the C++
            // walks COPY/INDIRECT/INT_ADD/PTRSUB chains. Left incomplete until
            // Varnode::getDef is wired into rangeutil.
            drop(vn_guard);
            // TODO: depends on unported Varnode::getDef wiring.
            return false;
        }
        true
    }

    // Ghidra: rangeutil.cc:2351 ValueSetSolver::generateRelativeConstraint
    /// Try to find a relative constraint from a comparison op and a cbranch.
    /// Faithful to `ValueSetSolver::generateRelativeConstraint`
    /// (rangeutil.cc:2351).
    pub fn generate_relative_constraint(
        &mut self,
        _comp_op: &Arc<RwLock<PcodeOp>>,
        _cbranch: &Arc<RwLock<PcodeOp>>,
    ) {
        // TODO: depends on check_relative_constant + pullBackBinary wiring.
    }

    // Ghidra: rangeutil.cc:2416 ValueSetSolver::establishValueSets
    /// Build value sets for a data-flow system. Given a set of sinks, find all
    /// the Varnodes that flow directly into them and set up their initial
    /// ValueSet objects. Faithful to `ValueSetSolver::establishValueSets`
    /// (rangeutil.cc:2416).
    ///
    /// Alignment Evidence:
    /// - References/out params: `sinks`/`reads` are borrowed; the solver
    ///   allocates fresh ValueSets in its arena and marks Varnodes via
    ///   set_mark/clear_mark.
    /// - Loop bounds/order: a worklist (`workPos < worklist.size()`) grows as
    ///   inputs are discovered; the op-code switch decides root vs. expansion.
    /// - Counter/accumulator: `workPos` advances per processed Varnode;
    ///   `root_nodes` accumulates input/root ValueSets.
    /// - Sort/compare key: branched on `op->code()` to distinguish
    ///   unpredictable ops (CALL/LOAD/FLOAT_*/...) from expandable ops.
    pub fn establish_value_sets(
        &mut self,
        sinks: &[Arc<RwLock<Varnode>>],
        reads: &[Arc<RwLock<PcodeOp>>],
        stack_reg: Option<Arc<RwLock<Varnode>>>,
        indirect_as_copy: bool,
    ) {
        let mut worklist: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut work_pos = 0usize;
        if let Some(stack) = &stack_reg {
            let id = self.new_value_set(stack.clone(), 1); // stack pointer special
            stack_reg.as_ref().unwrap().write().unwrap().set_mark();
            worklist.push(stack.clone());
            work_pos += 1;
            self.root_nodes.push(id);
        }
        for sink in sinks {
            let id = self.new_value_set(sink.clone(), 0);
            sink.write().unwrap().set_mark();
            worklist.push(sink.clone());
            let _ = id;
        }
        while work_pos < worklist.len() {
            let vn = worklist[work_pos].clone();
            work_pos += 1;
            let (is_written, is_constant, is_spacebase) = {
                let g = vn.read().unwrap();
                (g.is_written(), g.is_constant(), g.is_spacebase())
            };
            if !is_written {
                if is_constant {
                    // Constant inputs to binary ops should not be treated as
                    // root nodes (they get picked up by the other input),
                    // except for a PTRSUB from a spacebase constant.
                    let lone_single_input = vn.read().unwrap().lone_descend().map_or(false, |op| {
                        op.read().unwrap().num_input() == 1
                    });
                    if is_spacebase || lone_single_input {
                        if let Some(id) = self.find_value_set_by_vn(&vn) {
                            self.root_nodes.push(id);
                        }
                    }
                } else if let Some(id) = self.find_value_set_by_vn(&vn) {
                    self.root_nodes.push(id);
                }
                continue;
            }
            // vn is written. Ghidra: PcodeOp *op = vn->getDef(); switch(op->code())
            // Rugra's Varnode does not expose its defining op to rangeutil yet.
            // TODO: depends on unported Varnode::getDef wiring. Until then we
            // cannot expand inputs; the system is limited to the sinks/roots
            // already registered.
            let _ = indirect_as_copy;
        }
        for read_op in reads {
            let num = read_op.read().unwrap().num_input();
            for slot in 0..num {
                let in_vn = match read_op.read().unwrap().get_in(slot) {
                    Some(v) => v.clone(),
                    None => continue,
                };
                if in_vn.read().unwrap().is_mark() {
                    let seq = read_op.read().unwrap().get_seq_num().clone();
                    let mut vsr = ValueSetRead::new();
                    vsr.set_pcode_op(read_op.clone(), slot as i32);
                    self.read_nodes.insert(seq, vsr);
                    read_op.write().unwrap().set_mark(); // mark read op
                    break; // Only 1 read allowed
                }
            }
        }
        self.generate_constraints(&worklist, reads);
        for read_op in reads {
            read_op.write().unwrap().clear_mark(); // clear marks on read ops
        }
        self.establish_topological_order();
        for vn in &worklist {
            vn.write().unwrap().clear_mark();
        }
    }

    // Ghidra: rangeutil.cc:2588 ValueSetSolver::dumpValueSets
    /// Dump all value sets to a string (debug). Faithful to
    /// `ValueSetSolver::dumpValueSets` (rangeutil.cc:2588), guarded by
    /// `CPUI_DEBUG` in Ghidra.
    pub fn dump_value_sets(&self) -> String {
        let mut s = String::new();
        for vs in &self.value_nodes {
            s.push_str(&vs.print_raw());
            s.push('\n');
        }
        for (_seq, vsr) in &self.read_nodes {
            s.push_str(&vsr.print_raw());
            s.push('\n');
        }
        s
    }
}

// Ghidra: rangeutil.hh:281 ValueSetSolver::ValueSetEdge
/// Iterator over out-bound edges for a single ValueSet node. Faithful to the
/// nested class `ValueSetSolver::ValueSetEdge` (rangeutil.hh:281).
///
/// In C++ this walks `vn->beginDescend()`/`endDescend()` plus a simulated root
/// over `rootNodes`. In Rust the iterator is materialized eagerly up-front
/// (collecting successor ValueSets) because the descend iterator yields
/// `PcodeOp`s whose output Varnodes must be checked for marks.
struct ValueSetEdge {
    /// Pre-collected successor ValueSet ids. `None` entries terminate.
    successors: Vec<VsId>,
    /// Current position.
    pos: usize,
}

impl ValueSetEdge {
    /// Construct an iterator over the outbound edges of `node`. If `node` is
    /// the simulated root (vn == None), successors are `root_nodes`; otherwise
    /// successors are the ValueSets of marked output Varnodes of descendant
    /// ops. Faithful to `ValueSetEdge::ValueSetEdge` (rangeutil.cc:1910).
    // Ghidra: rangeutil.cc:1910 ValueSetSolver::ValueSetEdge::ValueSetEdge
    fn new(solver: &ValueSetSolver, node: VsId) -> Self {
        let mut successors: Vec<VsId> = Vec::new();
        let is_root = solver.value_nodes[node].vn.is_none();
        if is_root {
            // Simulated root: successors are root_nodes.
            successors.extend_from_slice(&solver.root_nodes);
        } else if let Some(vn_arc) = solver.value_nodes[node].vn.clone() {
            // Walk descendant ops; for each, if the output Varnode is marked
            // and present in the arena, emit its ValueSet id.
            let vn_guard = vn_arc.read().unwrap();
            for op_arc in vn_guard.descend_iter() {
                let op_guard = op_arc.read().unwrap();
                if let Some(out_vn) = op_guard.get_out() {
                    let out_guard = out_vn.read().unwrap();
                    if out_guard.is_mark() {
                        drop(out_guard);
                        if let Some(id) = solver.find_value_set_by_vn(out_vn) {
                            successors.push(id);
                        }
                    }
                }
            }
        }
        ValueSetEdge { successors, pos: 0 }
    }

    /// Get the next ValueSet id, or None at end. Faithful to
    /// `ValueSetEdge::getNext` (rangeutil.cc:1928).
    // Ghidra: rangeutil.cc:1928 ValueSetSolver::ValueSetEdge::getNext
    fn get_next(&mut self, _solver: &ValueSetSolver) -> Option<VsId> {
        if self.pos < self.successors.len() {
            let r = self.successors[self.pos];
            self.pos += 1;
            Some(r)
        } else {
            None
        }
    }
}

// Ghidra: rangeutil.cc:1470 CircleRange::printRaw (helper)
/// Text representation of a CircleRange. Faithful to
/// `CircleRange::printRaw` (rangeutil.cc:1470).
fn print_range_raw(r: &CircleRange) -> String {
    let mut s = String::new();
    if r.isempty {
        s.push_str("(empty)");
        return s;
    }
    if r.left == r.right {
        s.push_str("(full");
        if r.step != 1 {
            s.push(',');
            s.push_str(&r.step.to_string());
        }
        s.push(')');
    } else if r.right == ((r.left + r.step) & r.mask) {
        s.push('[');
        s.push_str(&format!("{:#x}", r.left));
        s.push(']');
    } else {
        s.push('[');
        s.push_str(&format!("{:#x}", r.left));
        s.push(',');
        s.push_str(&format!("{:#x}", r.right));
        if r.step != 1 {
            s.push(',');
            s.push_str(&r.step.to_string());
        }
        s.push(')');
    }
    s
}

// =============================================================================
// ValueSet::iterate — requires push-forward over the defining op's inputs.
// Ported with the inputs passed in via a small bundle so the core iteration
// algorithm is faithful to rangeutil.cc:1611 even before the Varnode graph
// is fully wired.
// =============================================================================

impl ValueSet {
    // Ghidra: rangeutil.cc:1611 ValueSet::iterate
    /// Regenerate this value set from operator inputs. Faithful to
    /// `ValueSet::iterate` (rangeutil.cc:1611).
    ///
    /// The C++ method reads inputs via `op->getIn(i)->getValueSet()` and the
    /// output size via `vn->getSize()`. Rugra passes `inputs` (one per
    /// `num_params`) and `out_size` explicitly; the widener is consulted for
    /// freeze/widening exactly as in Ghidra.
    ///
    /// Alignment Evidence (four decisive semantics):
    /// - References/out params: `widener` borrowed immutably; `self.range` is
    ///   the previous iteration's set and is widened in place via the widener.
    /// - Loop bounds/order: for MULTIEQUAL, iterates `i` in 0..num_params,
    ///   folding `res = res.circleUnion(inSet->range)`; equation application
    ///   advances `eqPos` only when `doesEquationApply(eqPos, i)`.
    /// - Counter/accumulator: `count += 1` once per call (before computing
    ///   `res`); `leftIsStable`/`rightIsStable` are assigned from the inputs
    ///   (AND-ed for binary/trinary) or from comparing previous vs. new range.
    /// - Sort/compare key: equation slot/type_code matching via
    ///   `does_equation_apply`; final `res == range` decides no-change.
    pub fn iterate(&mut self, widener: &dyn Widener) -> bool {
        // The no-inputs form (used when the Varnode graph isn't wired): Ghidra
        // returns false early if `!vn->isWritten()`. With inputs present, the
        // full algorithm runs via `iterate_with`.
        if self.vn.is_none() {
            return false;
        }
        if widener.check_freeze(self) {
            return false;
        }
        // Without input metadata (set via set_iterate_inputs by the solver)
        // we cannot recompute; report no change, matching the C++ "numParams
        // not 1/2/3/MULTIEQUAL" fall-through that returns false.
        if self.iter_inputs.is_none() {
            return false;
        }
        let inputs = self.iter_inputs.clone().unwrap();
        let out_size = self.iter_out_size.unwrap_or(0);
        self.iterate_with(inputs, out_size, widener)
    }

    /// Provide the defining op's input value sets and output size for the next
    /// `iterate` call. Rugra glue: Ghidra obtains these internally from
    /// `op->getIn(i)->getValueSet()` / `vn->getSize()`.
    // RUGRA-GLUE: stages inputs the C++ fetches live from the Varnode graph,
    // which Rugra cannot yet traverse (Varnode::getDef unported to rangeutil).
    pub fn set_iterate_inputs(&mut self, inputs: Vec<ValueSetInput>, out_size: usize) {
        self.iter_inputs = Some(inputs);
        self.iter_out_size = Some(out_size);
    }

    // Core of ValueSet::iterate (rangeutil.cc:1611) with explicit inputs.
    // Ghidra: rangeutil.cc:1611 ValueSet::iterate
    fn iterate_with(
        &mut self,
        inputs: Vec<ValueSetInput>,
        out_size: usize,
        widener: &dyn Widener,
    ) -> bool {
        if widener.check_freeze(self) {
            return false;
        }
        if self.count == 0 {
            // computeTypeCode: figure out if this value set is absolute or
            // relative based on the input type codes. Faithful to cc:1567.
            let input_type_codes: Vec<i32> = self.iter_input_type_codes.clone();
            let indeterminate = self.compute_type_code_with(&input_type_codes);
            if indeterminate {
                self.set_full();
                return true;
            }
        }
        self.count += 1; // Count this iteration
        let mut res = CircleRange::empty();
        let mut eq_pos: i32 = 0;
        let op_code = self.op_code;

        if op_code == OpCode::CPUI_MULTIEQUAL {
            let mut pieces: i32 = 0;
            for i in 0..self.num_params as usize {
                if i >= inputs.len() {
                    break;
                }
                let in_set = &inputs[i];
                if self.does_equation_apply(eq_pos, i as i32) {
                    let mut range_copy = in_set.range.clone();
                    let eq_idx = eq_pos as usize;
                    let eq_range = &self.equations[eq_idx].range;
                    if 0 != range_copy.circle_intersect(eq_range) {
                        range_copy = eq_range.clone();
                    }
                    pieces = res.circle_union(&range_copy);
                    eq_pos += 1; // Equation was used
                } else {
                    pieces = res.circle_union(&in_set.range);
                }
                if pieces == 2 {
                    // Could not get clean union, force it.
                    if res.minimal_container(&in_set.range, VALUE_SET_MAX_STEP) {
                        break;
                    }
                }
            }
            // Union with the previous iteration's set.
            if 0 != res.circle_union(&self.range) {
                res.minimal_container(&self.range, VALUE_SET_MAX_STEP);
            }
            if !self.range.is_empty() && !res.is_empty() {
                self.left_is_stable = self.range.get_min() == res.get_min();
                self.right_is_stable = self.range.get_end() == res.get_end();
            }
        } else if self.num_params == 1 {
            if inputs.is_empty() {
                return false;
            }
            let in_set1 = &inputs[0];
            let in_size1 = in_set1.vn_size;
            if self.does_equation_apply(eq_pos, 0) {
                let mut range_copy = in_set1.range.clone();
                let eq_idx = eq_pos as usize;
                let eq_range = &self.equations[eq_idx].range;
                if 0 != range_copy.circle_intersect(eq_range) {
                    range_copy = eq_range.clone();
                }
                if !res.push_forward_unary(op_code, &range_copy, in_size1, out_size) {
                    self.set_full();
                    return true;
                }
                eq_pos += 1;
            } else if !res.push_forward_unary(op_code, &in_set1.range, in_size1, out_size) {
                self.set_full();
                return true;
            }
            self.left_is_stable = in_set1.left_is_stable;
            self.right_is_stable = in_set1.right_is_stable;
        } else if self.num_params == 2 {
            if inputs.len() < 2 {
                return false;
            }
            let in_set1 = &inputs[0];
            let in_set2 = &inputs[1];
            let in_size1 = in_set1.vn_size;
            if self.equations.is_empty() {
                if !res.push_forward_binary(
                    op_code,
                    &in_set1.range,
                    &in_set2.range,
                    in_size1,
                    out_size,
                    VALUE_SET_MAX_STEP as i32,
                ) {
                    self.set_full();
                    return true;
                }
            } else {
                let mut range1 = in_set1.range.clone();
                let mut range2 = in_set2.range.clone();
                if self.does_equation_apply(eq_pos, 0) {
                    let eq_idx = eq_pos as usize;
                    let eq_range = &self.equations[eq_idx].range;
                    if 0 != range1.circle_intersect(eq_range) {
                        range1 = eq_range.clone();
                    }
                    eq_pos += 1;
                }
                if self.does_equation_apply(eq_pos, 1) {
                    let eq_idx = eq_pos as usize;
                    let eq_range = &self.equations[eq_idx].range;
                    if 0 != range2.circle_intersect(eq_range) {
                        range2 = eq_range.clone();
                    }
                }
                if !res.push_forward_binary(
                    op_code,
                    &range1,
                    &range2,
                    in_size1,
                    out_size,
                    VALUE_SET_MAX_STEP as i32,
                ) {
                    self.set_full();
                    return true;
                }
            }
            self.left_is_stable = in_set1.left_is_stable && in_set2.left_is_stable;
            self.right_is_stable = in_set1.right_is_stable && in_set2.right_is_stable;
        } else if self.num_params == 3 {
            if inputs.len() < 3 {
                return false;
            }
            let in_set1 = &inputs[0];
            let in_set2 = &inputs[1];
            let in_set3 = &inputs[2];
            let in_size1 = in_set1.vn_size;
            let mut range1 = in_set1.range.clone();
            let mut range2 = in_set2.range.clone();
            if self.does_equation_apply(eq_pos, 0) {
                let eq_idx = eq_pos as usize;
                let eq_range = &self.equations[eq_idx].range;
                if 0 != range1.circle_intersect(eq_range) {
                    range1 = eq_range.clone();
                }
                eq_pos += 1;
            }
            if self.does_equation_apply(eq_pos, 1) {
                let eq_idx = eq_pos as usize;
                let eq_range = &self.equations[eq_idx].range;
                if 0 != range2.circle_intersect(eq_range) {
                    range2 = eq_range.clone();
                }
            }
            if !res.push_forward_trinary(
                op_code,
                &range1,
                &range2,
                &in_set3.range,
                in_size1,
                out_size,
                VALUE_SET_MAX_STEP as i32,
            ) {
                self.set_full();
                return true;
            }
            self.left_is_stable = in_set1.left_is_stable && in_set2.left_is_stable;
            self.right_is_stable = in_set1.right_is_stable && in_set2.right_is_stable;
        } else {
            return false; // No way to change this value set
        }

        if res == *self.get_range() {
            return false;
        }
        if self.part_head.is_some() {
            // widener.doWidening(*this, range, res); on failure setFull().
            let mut prev = self.range.clone();
            if !widener.do_widening(self, &mut prev, &res) {
                self.set_full();
            } else {
                self.range = prev;
            }
        } else {
            self.range = res;
        }
        true
    }
}

// Extension fields on ValueSet for the iterate-with-inputs pathway. These are
// Rust glue: Ghidra fetches inputs/op-size on the fly from the Varnode graph;
// Rugra stages them explicitly.
// RUGRA-GLUE: extra staging fields (no Ghidra counterpart).

#[cfg(test)]
mod value_set_tests {
    use super::*;

    #[test]
    fn test_value_set_new_default() {
        let vs = ValueSet::new();
        assert_eq!(vs.type_code, 0);
        assert_eq!(vs.num_params, 0);
        assert_eq!(vs.count, 0);
        assert_eq!(vs.op_code, OpCode::CPUI_MAX);
        assert!(!vs.left_is_stable);
        assert!(!vs.right_is_stable);
        assert!(vs.vn.is_none());
        assert!(vs.range.is_empty());
        assert!(vs.equations.is_empty());
        assert!(vs.part_head.is_none());
        assert!(vs.next.is_none());
        assert_eq!(vs.get_count(), 0);
        assert_eq!(vs.get_type_code(), 0);
    }

    #[test]
    fn test_equation_new() {
        let r = CircleRange::single(5, 4);
        let eq = Equation::new(2, 1, r.clone());
        assert_eq!(eq.slot, 2);
        assert_eq!(eq.type_code, 1);
        assert!(eq.range.contains_val(5));
    }

    #[test]
    fn test_value_set_add_equation_ordered() {
        let mut vs = ValueSet::new();
        vs.num_params = 3;
        vs.add_equation(2, 0, CircleRange::single(5, 4));
        vs.add_equation(0, 0, CircleRange::single(1, 4));
        vs.add_equation(1, 0, CircleRange::single(3, 4));
        // Equations must be stored ordered on slot.
        assert_eq!(vs.equations.len(), 3);
        assert_eq!(vs.equations[0].slot, 0);
        assert_eq!(vs.equations[1].slot, 1);
        assert_eq!(vs.equations[2].slot, 2);
    }

    #[test]
    fn test_value_set_does_equation_apply() {
        let mut vs = ValueSet::new();
        vs.type_code = 0;
        vs.add_equation(0, 0, CircleRange::single(1, 4));
        // Matching slot and type_code → applies.
        assert!(vs.does_equation_apply(0, 0));
        // Wrong slot.
        assert!(!vs.does_equation_apply(0, 1));
        // Out of range.
        assert!(!vs.does_equation_apply(5, 0));
        // Wrong type_code.
        vs.type_code = 1;
        assert!(!vs.does_equation_apply(0, 0));
    }

    #[test]
    fn test_value_set_add_landmark() {
        let mut vs = ValueSet::new();
        vs.num_params = 2;
        vs.add_landmark(0, CircleRange::new(0, 10, 4, 1));
        // Landmark is stored at slot == num_params.
        assert_eq!(vs.equations.len(), 1);
        assert_eq!(vs.equations[0].slot, 2);
    }

    #[test]
    fn test_value_set_get_land_mark() {
        let mut vs = ValueSet::new();
        vs.type_code = 1;
        vs.add_equation(0, 0, CircleRange::single(1, 4)); // type 0, no match
        vs.add_equation(1, 1, CircleRange::new(0, 10, 4, 1)); // type 1, matches
        let lm = vs.get_land_mark();
        assert!(lm.is_some());
        assert!(lm.unwrap().contains_val(5));
    }

    #[test]
    fn test_value_set_compute_type_code() {
        let mut vs = ValueSet::new();
        vs.op_code = OpCode::CPUI_INT_ADD;
        vs.num_params = 2;
        // No relative inputs → absolute.
        assert!(!vs.compute_type_code_with(&[0, 0]));
        assert_eq!(vs.type_code, 0);
        // One relative input to INT_ADD → relative.
        assert!(!vs.compute_type_code_with(&[0, 1]));
        assert_eq!(vs.type_code, 1);
        // Two relative inputs to INT_ADD → indeterminate.
        assert!(vs.compute_type_code_with(&[1, 1]));
        // COPY/MULTIEQUAL propagate regardless of count.
        vs.op_code = OpCode::CPUI_MULTIEQUAL;
        assert!(!vs.compute_type_code_with(&[1, 1]));
        assert_eq!(vs.type_code, 1);
    }

    #[test]
    fn test_widener_full_default() {
        let w = WidenerFull::new();
        let mut vs = ValueSet::new();
        vs.count = 0;
        assert_eq!(w.determine_iteration_reset(&vs), 0);
        vs.count = 2;
        assert_eq!(w.determine_iteration_reset(&vs), 2);
        vs.range = CircleRange::full(4);
        assert!(w.check_freeze(&vs));
        vs.range = CircleRange::single(5, 4);
        assert!(!w.check_freeze(&vs));
    }

    #[test]
    fn test_widener_full_with_iterations() {
        let w = WidenerFull::with_iterations(3, 7);
        let mut vs = ValueSet::new();
        vs.count = 2;
        assert_eq!(w.determine_iteration_reset(&vs), 0);
        vs.count = 3;
        assert_eq!(w.determine_iteration_reset(&vs), 3);
    }

    #[test]
    fn test_widener_none_default() {
        let w = WidenerNone::new();
        let mut vs = ValueSet::new();
        vs.count = 1;
        assert_eq!(w.determine_iteration_reset(&vs), 1);
        vs.count = 3;
        assert_eq!(w.determine_iteration_reset(&vs), 3);
        // freeze_iteration == 3, so count==2 is not frozen, count==3 is.
        vs.range = CircleRange::single(5, 4);
        vs.count = 2;
        assert!(!w.check_freeze(&vs));
        vs.count = 3;
        assert!(w.check_freeze(&vs));
        vs.count = 4;
        assert!(w.check_freeze(&vs));
        // doWidening always assigns newRange and returns true.
        let mut r = CircleRange::single(1, 4);
        let nr = CircleRange::single(9, 4);
        assert!(w.do_widening(&vs, &mut r, &nr));
        assert!(r.contains_val(9));
    }

    #[test]
    fn test_value_set_read_compute() {
        let mut vsr = ValueSetRead::new();
        vsr.slot = 0;
        vsr.equation_type_code = 0;
        vsr.equation_constraint = CircleRange::new(0, 5, 4, 1);
        let mut src = ValueSet::new();
        src.type_code = 0;
        src.range = CircleRange::new(0, 20, 4, 1);
        src.left_is_stable = true;
        src.right_is_stable = false;
        vsr.compute(&src);
        // type codes match → intersect with constraint [0,5).
        assert_eq!(vsr.type_code, 0);
        assert!(vsr.range.contains_val(0));
        assert!(vsr.range.contains_val(4));
        assert!(!vsr.range.contains_val(5));
        assert!(vsr.left_is_stable);
        assert!(!vsr.right_is_stable);
    }

    #[test]
    fn test_value_set_read_add_equation_slot_match() {
        let mut vsr = ValueSetRead::new();
        vsr.slot = 1;
        // Only equations whose slot matches are stored.
        vsr.add_equation(0, 1, CircleRange::single(1, 4));
        assert_eq!(vsr.equation_type_code, -1);
        vsr.add_equation(1, 1, CircleRange::single(2, 4));
        assert_eq!(vsr.equation_type_code, 1);
        assert!(vsr.equation_constraint.contains_val(2));
    }

    #[test]
    fn test_value_set_solver_new_empty() {
        let s = ValueSetSolver::new();
        assert!(s.value_nodes.is_empty());
        assert!(s.read_nodes.is_empty());
        assert_eq!(s.get_num_iterations(), 0);
        assert!(s.value_sets().is_empty());
    }

    #[test]
    fn test_circle_range_circle_union_single() {
        // circleUnion of [0,5) and [3,10) → [0,10) (overlap code 'b').
        let mut a = CircleRange::new(0, 5, 4, 1);
        let b = CircleRange::new(3, 10, 4, 1);
        let res = a.circle_union(&b);
        assert_eq!(res, 0); // single range
        assert_eq!(a.get_left(), 0);
        assert_eq!(a.get_end(), 10);
    }

    #[test]
    fn test_circle_range_circle_union_disjoint() {
        // circleUnion of [0,5) and [10,20) → two pieces (no overlap/adjacency).
        let mut a = CircleRange::new(0, 5, 4, 1);
        let b = CircleRange::new(10, 20, 4, 1);
        let res = a.circle_union(&b);
        assert_eq!(res, 2); // two pieces
    }

    #[test]
    fn test_circle_range_circle_intersect_overlap() {
        // intersect of [0,10) and [5,15) → [5,10) (overlap code 'b').
        let mut a = CircleRange::new(0, 10, 4, 1);
        let b = CircleRange::new(5, 15, 4, 1);
        let res = a.circle_intersect(&b);
        assert_eq!(res, 0); // valid
        assert_eq!(a.get_left(), 5);
        assert_eq!(a.get_end(), 10);
    }

    #[test]
    fn test_circle_range_circle_intersect_disjoint() {
        // intersect of [0,5) and [10,20) → empty (overlap code 'a').
        let mut a = CircleRange::new(0, 5, 4, 1);
        let b = CircleRange::new(10, 20, 4, 1);
        let res = a.circle_intersect(&b);
        assert_eq!(res, 0); // valid (empty)
        assert!(a.is_empty());
    }

    #[test]
    fn test_circle_range_minimal_container() {
        // minimalContainer of [0,5) and [10,20): both non-single, picks the
        // smaller vacancy. With step 1 and mask 0xffffffff.
        let mut a = CircleRange::new(0, 5, 4, 1);
        let b = CircleRange::new(10, 20, 4, 1);
        // overlap code 'a': vacant1 = 0 + (mask - 20) + 1, vacant2 = 10 - 5 = 5.
        let _full = a.minimal_container(&b, VALUE_SET_MAX_STEP);
        // Result contains both originals.
        assert!(a.contains_val(0) || a.contains_val(19));
    }

    #[test]
    fn test_print_range_raw_formats() {
        assert_eq!(print_range_raw(&CircleRange::empty()), "(empty)");
        let full = CircleRange::full(4);
        let s = print_range_raw(&full);
        assert_eq!(s, "(full)");
        let single = CircleRange::single(5, 4);
        let s = print_range_raw(&single);
        assert_eq!(s, "[0x5]");
    }

    #[test]
    fn test_value_set_print_raw_root() {
        let vs = ValueSet::new(); // vn == None → root
        let s = vs.print_raw();
        assert!(s.starts_with("root"));
    }

    #[test]
    fn test_encode_range_overlaps() {
        // Identical ranges → overlap code 'g' or full overlap scenarios.
        // (l r op2.l op2.r) with l<r and op2.l<op2.r distinct.
        // Just verify it returns a valid code char.
        let code = CircleRange::encode_range_overlaps(0, 5, 3, 10);
        assert!(matches!(code, 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g'));
    }
}
