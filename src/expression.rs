//! Expression analysis infrastructure: TermOrder, AdditiveEdge, AddExpression.
//!
//! Corresponds to Ghidra's `expression.hh` / `expression.cc`.
//! Used by RuleCollectTerms (constant folding + factoring in additive trees),
//! RuleScarry/RuleSborrow (deep forms), and other rules that need to compare
//! or reorder additive expressions.

use std::sync::{Arc, RwLock};
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::address::calc_mask;
use crate::address::functional_equality;

/// A term in an additive expression. Corresponds to Ghidra's `AdditiveEdge`.
#[derive(Clone)]
pub struct AdditiveEdge {
    /// The op that reads this term
    pub op: Arc<RwLock<PcodeOp>>,
    /// The input slot of the term in that op
    pub slot: usize,
    /// The term Varnode
    pub vn: Arc<RwLock<Varnode>>,
    /// Optional multiplier op (INT_MULT) applied to the term
    pub mult: Option<Arc<RwLock<PcodeOp>>>,
}

impl AdditiveEdge {
    pub fn new(op: Arc<RwLock<PcodeOp>>, slot: usize, mult: Option<Arc<RwLock<PcodeOp>>>) -> Self {
        let vn = op.read().unwrap().inrefs.get(slot).cloned().unwrap();
        Self { op, slot, vn, mult }
    }
    pub fn get_multiplier(&self) -> &Option<Arc<RwLock<PcodeOp>>> { &self.mult }
    pub fn get_op(&self) -> &Arc<RwLock<PcodeOp>> { &self.op }
    pub fn get_slot(&self) -> usize { self.slot }
    pub fn get_varnode(&self) -> &Arc<RwLock<Varnode>> { &self.vn }
}

/// A class for ordering Varnode terms in an additive expression.
/// Corresponds to Ghidra's `TermOrder` (expression.hh:124).
pub struct TermOrder {
    root: Arc<RwLock<PcodeOp>>,
    terms: Vec<AdditiveEdge>,
    sorter: Vec<usize>, // indices into terms, sorted
}

impl TermOrder {
    pub fn new(root: Arc<RwLock<PcodeOp>>) -> Self {
        Self { root, terms: Vec::new(), sorter: Vec::new() }
    }

    pub fn get_size(&self) -> usize { self.terms.len() }

    /// Collect all the terms in the additive expression rooted at `root`.
    /// Faithful to `TermOrder::collect` (expression.cc:236-283).
    pub fn collect(&mut self) {
        let mut opstack: Vec<(Arc<RwLock<PcodeOp>>, Option<Arc<RwLock<PcodeOp>>>)> = Vec::new();
        opstack.push((self.root.clone(), None));
        while let Some((curop, multop)) = opstack.pop() {
            let num_input = curop.read().unwrap().inrefs.len();
            for i in 0..num_input {
                let curvn = curop.read().unwrap().inrefs[i].clone();
                let mult_clone = multop.clone();
                let is_written = curvn.read().unwrap().is_written();
                if !is_written {
                    self.terms.push(AdditiveEdge::new(curop.clone(), i, mult_clone));
                    continue;
                }
                let lone = curvn.read().unwrap().lone_descend().is_some();
                if !lone {
                    self.terms.push(AdditiveEdge::new(curop.clone(), i, mult_clone));
                    continue;
                }
                let subop = curvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                let subop = match subop { Some(a) => a, None => {
                    self.terms.push(AdditiveEdge::new(curop.clone(), i, mult_clone));
                    continue;
                }};
                let subopc = subop.read().unwrap().opcode;
                if subopc != OpCode::CPUI_INT_ADD {
                    if subopc == OpCode::CPUI_INT_MULT && subop.read().unwrap().inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                        let in0 = subop.read().unwrap().inrefs.get(0).cloned();
                        if let Some(in0_vn) = in0 {
                            let addop = in0_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                            if let Some(ao) = addop {
                                if ao.read().unwrap().opcode == OpCode::CPUI_INT_ADD {
                                    let out_lone = subop.read().unwrap().output.as_ref().map_or(false, |o| o.read().unwrap().lone_descend().is_some());
                                    if out_lone {
                                        opstack.push((ao, Some(subop.clone())));
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    self.terms.push(AdditiveEdge::new(curop.clone(), i, mult_clone));
                    continue;
                }
                opstack.push((subop, mult_clone));
            }
        }
    }

    /// Sort the terms using a comparison based on Varnode identity.
    /// Faithful to `TermOrder::sortTerms` (expression.cc:285-293).
    pub fn sort_terms(&mut self) {
        self.sorter = (0..self.terms.len()).collect();
        // Sort by whether the term is constant (constants last), then by
        // Arc identity (functional equality proxy).
        self.sorter.sort_by(|&a, &b| {
            let va = &self.terms[a].vn;
            let vb = &self.terms[b].vn;
            let a_const = va.read().unwrap().is_constant();
            let b_const = vb.read().unwrap().is_constant();
            if a_const != b_const {
                return b_const.cmp(&a_const); // constants last
            }
            // Use pointer identity for ordering (same as Ghidra's termOrder).
            (Arc::as_ptr(va) as usize).cmp(&(Arc::as_ptr(vb) as usize))
        });
    }

    /// Get the sorted list of term indices.
    pub fn get_sort(&self) -> &[usize] { &self.sorter }

    /// Get a term by index.
    pub fn get_term(&self, idx: usize) -> Option<&AdditiveEdge> {
        self.terms.get(idx)
    }
}

/// A term in an AddExpression.
#[derive(Clone)]
struct ExprTerm {
    vn: Arc<RwLock<Varnode>>,
    coeff: u64,
}

impl ExprTerm {
    fn is_equivalent(&self, op2: &ExprTerm) -> bool {
        if self.coeff != op2.coeff { return false; }
        functional_equality(&self.vn, &op2.vn)
    }
}

/// Lightweight matching of two additive expressions (up to 2 terms).
/// Corresponds to Ghidra's `AddExpression` (expression.hh:141).
pub struct AddExpression {
    constval: u64,
    num_terms: usize,
    terms: [Option<ExprTerm>; 2],
}

impl AddExpression {
    pub fn new() -> Self {
        Self { constval: 0, num_terms: 0, terms: [None, None] }
    }

    fn add(&mut self, vn: Arc<RwLock<Varnode>>, coeff: u64) {
        if self.num_terms < 2 {
            self.terms[self.num_terms] = Some(ExprTerm { vn, coeff });
            self.num_terms += 1;
        }
    }

    /// Recursively collect terms. Faithful to `AddExpression::gather`
    /// (expression.cc:333-363).
    fn gather(&mut self, vn: &Arc<RwLock<Varnode>>, coeff: u64, depth: i32) {
        let v = vn.read().unwrap();
        if v.is_constant() {
            self.constval = self.constval.wrapping_add(coeff.wrapping_mul(v.get_offset()));
            let mask = calc_mask(v.get_size());
            self.constval &= mask;
            return;
        }
        let is_written = v.is_written();
        let def = v.def.as_ref().and_then(|w| w.upgrade());
        drop(v);
        if is_written {
            if let Some(op) = def {
                let opc = op.read().unwrap().opcode;
                if opc == OpCode::CPUI_INT_ADD {
                    let in1_const = op.read().unwrap().inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant());
                    let new_depth = if !in1_const { depth - 1 } else { depth };
                    if new_depth >= 0 {
                        let in0 = op.read().unwrap().inrefs[0].clone();
                        let in1 = op.read().unwrap().inrefs[1].clone();
                        self.gather(&in0, coeff, new_depth);
                        self.gather(&in1, coeff, new_depth);
                        return;
                    }
                } else if opc == OpCode::CPUI_INT_MULT {
                    let in1_const = op.read().unwrap().inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant());
                    if in1_const {
                        let mult_val = op.read().unwrap().inrefs[1].read().unwrap().get_offset();
                        let vn_size = op.read().unwrap().inrefs[1].read().unwrap().get_size();
                        let new_coeff = coeff.wrapping_mul(mult_val) & calc_mask(vn_size);
                        let in0 = op.read().unwrap().inrefs[0].clone();
                        self.gather(&in0, new_coeff, depth);
                        return;
                    }
                }
            }
        }
        self.add(vn.clone(), coeff);
    }

    /// Gather terms from two roots being subtracted.
    pub fn gather_two_terms_subtract(&mut self, a: &Arc<RwLock<Varnode>>, b: &Arc<RwLock<Varnode>>) {
        let depth = if a.read().unwrap().is_constant() || b.read().unwrap().is_constant() { 1 } else { 0 };
        self.gather(a, 1, depth);
        let b_size = b.read().unwrap().get_size();
        self.gather(b, calc_mask(b_size), depth);
    }

    /// Gather terms from two roots being added.
    pub fn gather_two_terms_add(&mut self, a: &Arc<RwLock<Varnode>>, b: &Arc<RwLock<Varnode>>) {
        let depth = if a.read().unwrap().is_constant() || b.read().unwrap().is_constant() { 1 } else { 0 };
        self.gather(a, 1, depth);
        self.gather(b, 1, depth);
    }

    /// Gather up to 2 terms from a single root.
    pub fn gather_two_terms_root(&mut self, root: &Arc<RwLock<Varnode>>) {
        self.gather(root, 1, 1);
    }

    /// Determine if two expressions are equivalent.
    pub fn is_equivalent(&self, op2: &AddExpression) -> bool {
        if self.constval != op2.constval { return false; }
        if self.num_terms != op2.num_terms { return false; }
        if self.num_terms == 1 {
            if let (Some(t0), Some(o0)) = (&self.terms[0], &op2.terms[0]) {
                return t0.is_equivalent(o0);
            }
        } else if self.num_terms == 2 {
            if let (Some(t0), Some(t1), Some(o0), Some(o1)) = (&self.terms[0], &self.terms[1], &op2.terms[0], &op2.terms[1]) {
                if t0.is_equivalent(o0) && t1.is_equivalent(o1) { return true; }
                if t0.is_equivalent(o1) && t1.is_equivalent(o0) { return true; }
            }
        }
        false
    }
}

// ===========================================================================
// BooleanMatch — expression.cc:57-216
// ===========================================================================

/// Boolean value correlation codes. Faithful to the enum in
/// `BooleanMatch` (expression.hh:84-88).
pub mod boolean_match {
    /// Pair always holds the same value.
    pub const SAME: i32 = 1;
    /// Pair always holds complementary values.
    pub const COMPLEMENTARY: i32 = 2;
    /// Pair values are uncorrelated.
    pub const UNCORRELATED: i32 = 3;
}

/// Check if two comparison ops are complements via the `x < n, n-1 < x`
/// pattern. Faithful to `BooleanMatch::sameOpComplement`
/// (expression.cc:57-86).
fn same_op_complement(
    bin1op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    bin2op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
) -> bool {
    use crate::address::signbit_negative;
    let op1 = bin1op.read().unwrap();
    let op2 = bin2op.read().unwrap();
    let opcode = op1.opcode;
    if opcode == OpCode::CPUI_INT_SLESS || opcode == OpCode::CPUI_INT_LESS {
        // Find constant slot in op1.
        let constslot = if op1.inrefs.get(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            1
        } else {
            0
        };
        // op1.inrefs[constslot] must be constant.
        if !op1.inrefs.get(constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            return false;
        }
        // op2.inrefs[1-constslot] must be constant.
        if !op2.inrefs.get(1 - constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            return false;
        }
        // The non-constant inputs must match.
        let vn1 = &op1.inrefs[1 - constslot];
        let vn2 = &op2.inrefs[constslot];
        if !varnode_same(vn1, vn2) {
            return false;
        }
        let mut val1 = op1.inrefs[constslot].read().unwrap().get_offset();
        let mut val2 = op2.inrefs[1 - constslot].read().unwrap().get_offset();
        if constslot != 0 {
            std::mem::swap(&mut val2, &mut val1);
        }
        if val1.wrapping_add(1) != val2 {
            return false;
        }
        if val2 == 0 && opcode == OpCode::CPUI_INT_LESS {
            return false; // Corner case for unsigned.
        }
        if opcode == OpCode::CPUI_INT_SLESS {
            let sz = op1.inrefs[constslot].read().unwrap().get_size();
            if signbit_negative(val2, sz) && !signbit_negative(val1, sz) {
                return false;
            }
        }
        return true;
    }
    false
}

/// Check if two Varnodes hold the same value. Faithful to
/// `BooleanMatch::varnodeSame` (expression.cc:93-100).
fn varnode_same(
    a: &std::sync::Arc<std::sync::RwLock<Varnode>>,
    b: &std::sync::Arc<std::sync::RwLock<Varnode>>,
) -> bool {
    if std::sync::Arc::ptr_eq(a, b) {
        return true;
    }
    let ra = a.read().unwrap();
    let rb = b.read().unwrap();
    if ra.is_constant() && rb.is_constant() {
        return ra.get_offset() == rb.get_offset();
    }
    false
}

/// Determine if two boolean Varnodes hold related values. Faithful to
/// `BooleanMatch::evaluate` (expression.cc:111-216).
///
/// Returns `boolean_match::SAME`, `boolean_match::COMPLEMENTARY`, or
/// `boolean_match::UNCORRELATED`. Trees constructing each Varnode are
/// examined up to `depth` levels.
pub fn boolean_match_evaluate(
    vn1: &std::sync::Arc<std::sync::RwLock<Varnode>>,
    vn2: &std::sync::Arc<std::sync::RwLock<Varnode>>,
    depth: i32,
) -> i32 {
    use crate::opcodes::get_booleanflip;
    if std::sync::Arc::ptr_eq(vn1, vn2) {
        return boolean_match::SAME;
    }
    // Handle BOOL_NEGATE on vn1.
    let (op1, opc1) = {
        let r = vn1.read().unwrap();
        if r.is_written() {
            let (def, opc) = match r.get_def() {
                Some(d) => {
                    let opc = d.read().unwrap().opcode;
                    (d, opc)
                }
                None => return boolean_match::UNCORRELATED,
            };
            if opc == OpCode::CPUI_BOOL_NOT {
                // Recurse with flipped result.
                let in0 = def.read().unwrap().inrefs.get(0).cloned();
                drop(r);
                if let Some(in0) = in0 {
                    let res = boolean_match_evaluate(&in0, vn2, depth);
                    return if res == boolean_match::SAME {
                        boolean_match::COMPLEMENTARY
                    } else if res == boolean_match::COMPLEMENTARY {
                        boolean_match::SAME
                    } else {
                        res
                    };
                }
                return boolean_match::UNCORRELATED;
            }
            (Some(def), opc)
        } else {
            drop(r);
            (None, OpCode::CPUI_MAX)
        }
    };
    // Handle BOOL_NEGATE on vn2.
    let op2 = {
        let r = vn2.read().unwrap();
        if r.is_written() {
            let (def, opc) = match r.get_def() {
                Some(d) => {
                    let opc = d.read().unwrap().opcode;
                    (d, opc)
                }
                None => return boolean_match::UNCORRELATED,
            };
            if opc == OpCode::CPUI_BOOL_NOT {
                let in0 = def.read().unwrap().inrefs.get(0).cloned();
                drop(r);
                if let Some(in0) = in0 {
                    let res = boolean_match_evaluate(vn1, &in0, depth);
                    return if res == boolean_match::SAME {
                        boolean_match::COMPLEMENTARY
                    } else if res == boolean_match::COMPLEMENTARY {
                        boolean_match::SAME
                    } else {
                        res
                    };
                }
                return boolean_match::UNCORRELATED;
            }
            Some(def)
        } else {
            drop(r);
            return boolean_match::UNCORRELATED;
        }
    };
    let op1 = match op1 { Some(o) => o, None => return boolean_match::UNCORRELATED };
    let op2 = match op2 { Some(o) => o, None => return boolean_match::UNCORRELATED };
    let opc2 = op2.read().unwrap().opcode;

    // Both must be bool-output ops.
    if !op1.read().unwrap().is_bool_output() || !op2.read().unwrap().is_bool_output() {
        return boolean_match::UNCORRELATED;
    }

    // Check BOOL_AND/OR/XOR recursion.
    if depth != 0 && matches!(opc1, OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR) {
        if matches!(opc2, OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR) {
            if opc1 == opc2
                || (opc1 == OpCode::CPUI_BOOL_AND && opc2 == OpCode::CPUI_BOOL_OR)
                || (opc1 == OpCode::CPUI_BOOL_OR && opc2 == OpCode::CPUI_BOOL_AND)
            {
                let op1_in0 = op1.read().unwrap().inrefs.get(0).cloned();
                let op1_in1 = op1.read().unwrap().inrefs.get(1).cloned();
                let op2_in0 = op2.read().unwrap().inrefs.get(0).cloned();
                let op2_in1 = op2.read().unwrap().inrefs.get(1).cloned();
                let (Some(op1_in0), Some(op1_in1), Some(op2_in0), Some(op2_in1)) =
                    (op1_in0, op1_in1, op2_in0, op2_in1)
                else {
                    return boolean_match::UNCORRELATED;
                };
                let mut pair1 = boolean_match_evaluate(&op1_in0, &op2_in0, depth - 1);
                let pair2;
                if pair1 == boolean_match::UNCORRELATED {
                    pair1 = boolean_match_evaluate(&op1_in0, &op2_in1, depth - 1);
                    if pair1 == boolean_match::UNCORRELATED {
                        return boolean_match::UNCORRELATED;
                    }
                    pair2 = boolean_match_evaluate(&op1_in1, &op2_in0, depth - 1);
                } else {
                    let p2 = boolean_match_evaluate(&op1_in1, &op2_in1, depth - 1);
                    pair2 = p2;
                }
                if pair2 == boolean_match::UNCORRELATED {
                    return boolean_match::UNCORRELATED;
                }
                if opc1 == opc2 {
                    if pair1 == boolean_match::SAME && pair2 == boolean_match::SAME {
                        return boolean_match::SAME;
                    } else if opc1 == OpCode::CPUI_BOOL_XOR {
                        if pair1 == boolean_match::COMPLEMENTARY && pair2 == boolean_match::COMPLEMENTARY {
                            return boolean_match::SAME;
                        }
                        return boolean_match::COMPLEMENTARY;
                    }
                } else {
                    // Must be BOOL_AND and BOOL_OR.
                    if pair1 == boolean_match::COMPLEMENTARY && pair2 == boolean_match::COMPLEMENTARY {
                        return boolean_match::COMPLEMENTARY; // De Morgan's Law.
                    }
                }
            }
        }
    } else {
        // Two boolean output ops, compare directly.
        if opc1 == opc2 {
            let num_inputs = op1.read().unwrap().inrefs.len();
            let mut same_op = true;
            for i in 0..num_inputs {
                let in1 = &op1.read().unwrap().inrefs[i];
                let in2 = &op2.read().unwrap().inrefs[i];
                if !varnode_same(in1, in2) {
                    same_op = false;
                    break;
                }
            }
            if same_op {
                return boolean_match::SAME;
            }
            if same_op_complement(&op1, &op2) {
                return boolean_match::COMPLEMENTARY;
            }
            return boolean_match::UNCORRELATED;
        }
        // Check if binary ops are complements.
        let mut reorder = false;
        let flip_opc = get_booleanflip(opc2, &mut reorder);
        if opc1 != flip_opc {
            return boolean_match::UNCORRELATED;
        }
        let slot1 = 0;
        let slot2 = if reorder { 1 } else { 0 };
        let in1_0 = op1.read().unwrap().inrefs.get(slot1).cloned();
        let in2_slot2 = op2.read().unwrap().inrefs.get(slot2).cloned();
        let in1_1 = op1.read().unwrap().inrefs.get(1 - slot1).cloned();
        let in2_1ms = op2.read().unwrap().inrefs.get(1 - slot2).cloned();
        match (in1_0, in2_slot2, in1_1, in2_1ms) {
            (Some(a), Some(b), Some(c), Some(d)) => {
                if !varnode_same(&a, &b) {
                    return boolean_match::UNCORRELATED;
                }
                if !varnode_same(&c, &d) {
                    return boolean_match::UNCORRELATED;
                }
                return boolean_match::COMPLEMENTARY;
            }
            _ => return boolean_match::UNCORRELATED,
        }
    }
    boolean_match::UNCORRELATED
}

// ===========================================================================
// functionalEqualityLevel — expression.cc:404-512
// ===========================================================================

/// Level-0 functional equality test. Faithful to `functionalEqualityLevel0`
/// (expression.cc:404-417). Returns:
/// - 0 if vn1 and vn2 definitely hold the same value
/// - -1 if they do not (or cannot be immediately verified)
/// - 1 if the same value depends on ops writing to vn1 and vn2
fn functional_equality_level0(
    vn1: &Arc<RwLock<Varnode>>,
    vn2: &Arc<RwLock<Varnode>>,
) -> i32 {
    if Arc::ptr_eq(vn1, vn2) {
        return 0;
    }
    let v1 = vn1.read().unwrap();
    let v2 = vn2.read().unwrap();
    if v1.get_size() != v2.get_size() {
        return -1;
    }
    if v1.is_constant() {
        if v2.is_constant() {
            return if v1.get_offset() == v2.get_offset() { 0 } else { -1 };
        }
        return -1;
    }
    if v1.is_free() || v2.is_free() {
        return -1;
    }
    1
}

/// Result of `functional_equality_level`: the equality code plus up to two
/// Varnode pairs that must match for equality to hold.
#[derive(Debug, Clone)]
pub struct FunctionalEqualityResult {
    /// -1 = not equal, 0 = equal, >0 = contingent on `pairs`.
    pub code: i32,
    /// Pairs (vn1, vn2) that must hold the same value for equality.
    pub pairs: Vec<(Arc<RwLock<Varnode>>, Arc<RwLock<Varnode>>)>,
}

/// Try to determine if vn1 and vn2 contain the same value. Faithful to
/// `functionalEqualityLevel` (expression.cc:432-512).
///
/// Returns a `FunctionalEqualityResult` with:
/// - `code == -1`: not equal / cannot verify
/// - `code == 0`: definitely equal
/// - `code > 0`: contingent on `pairs` (code = number of pairs)
pub fn functional_equality_level(
    vn1: &Arc<RwLock<Varnode>>,
    vn2: &Arc<RwLock<Varnode>>,
) -> FunctionalEqualityResult {
    let testval = functional_equality_level0(vn1, vn2);
    if testval != 1 {
        return FunctionalEqualityResult { code: testval, pairs: Vec::new() };
    }
    // Both must be written for a deeper comparison.
    let (is_written1, is_written2, def1, def2) = {
        let v1 = vn1.read().unwrap();
        let v2 = vn2.read().unwrap();
        (v1.is_written(), v2.is_written(), v1.get_def(), v2.get_def())
    };
    if !is_written1 || !is_written2 {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    let Some(op1_arc) = def1 else {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    };
    let Some(op2_arc) = def2 else {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    };
    let op1 = op1_arc.read().unwrap();
    let op2 = op2_arc.read().unwrap();
    let opc = op1.opcode;
    if opc != op2.opcode {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    let mut num = op1.inrefs.len();
    if num != op2.inrefs.len() {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    if op1.is_marker() || op2.is_call() {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    if opc == OpCode::CPUI_LOAD {
        // Two loads produce the same result if same address and same instruction.
        if op1.get_addr() != op2.get_addr() {
            return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
        }
    }
    if num >= 3 {
        if opc != OpCode::CPUI_PTRADD {
            return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
        }
        // Check element-size constant (slot 2) is equal.
        let off1 = op1.get_in(2).map(|v| v.read().unwrap().get_offset());
        let off2 = op2.get_in(2).map(|v| v.read().unwrap().get_offset());
        if off1 != off2 {
            return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
        }
        num = 2;
    }
    // Gather the input pairs.
    let mut res1: Vec<Arc<RwLock<Varnode>>> = Vec::with_capacity(num);
    let mut res2: Vec<Arc<RwLock<Varnode>>> = Vec::with_capacity(num);
    for i in 0..num {
        res1.push(op1.inrefs[i].clone());
        res2.push(op2.inrefs[i].clone());
    }
    // Drop the op read guards before further reads.
    drop(op1);
    drop(op2);

    let testval = functional_equality_level0(&res1[0], &res2[0]);
    if testval == 0 {
        if num == 1 {
            return FunctionalEqualityResult { code: 0, pairs: Vec::new() };
        }
        let testval2 = functional_equality_level0(&res1[1], &res2[1]);
        if testval2 == 0 {
            return FunctionalEqualityResult { code: 0, pairs: Vec::new() };
        }
        if testval2 < 0 {
            return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
        }
        // Match is contingent on the second pair.
        return FunctionalEqualityResult {
            code: 1,
            pairs: vec![(res1[1].clone(), res2[1].clone())],
        };
    }
    if num == 1 {
        return FunctionalEqualityResult { code: testval, pairs: Vec::new() };
    }
    let testval2 = functional_equality_level0(&res1[1], &res2[1]);
    if testval2 == 0 {
        return FunctionalEqualityResult { code: testval, pairs: Vec::new() };
    }
    let unmatchsize = if testval == 1 && testval2 == 1 { 2 } else { -1 };

    // Check commutativity.
    let is_commutative = opc.is_commutative();
    if !is_commutative {
        return FunctionalEqualityResult { code: unmatchsize, pairs: Vec::new() };
    }
    // Try flipping for commutative operators.
    let comm1 = functional_equality_level0(&res1[0], &res2[1]);
    let comm2 = functional_equality_level0(&res1[1], &res2[0]);
    if comm1 == 0 && comm2 == 0 {
        return FunctionalEqualityResult { code: 0, pairs: Vec::new() };
    }
    if comm1 < 0 || comm2 < 0 {
        return FunctionalEqualityResult { code: unmatchsize, pairs: Vec::new() };
    }
    if comm1 == 0 {
        // Left-over unmatch is res1[1] and res2[0].
        return FunctionalEqualityResult {
            code: 1,
            pairs: vec![(res1[1].clone(), res2[0].clone())],
        };
    }
    if comm2 == 0 {
        // Left-over unmatch is res1[0] and res2[1].
        return FunctionalEqualityResult {
            code: 1,
            pairs: vec![(res1[0].clone(), res2[1].clone())],
        };
    }
    // comm1==1 AND comm2==1.
    if unmatchsize == 2 {
        // Prefer the original ordering.
        return FunctionalEqualityResult {
            code: 2,
            pairs: vec![
                (res1[0].clone(), res2[0].clone()),
                (res1[1].clone(), res2[1].clone()),
            ],
        };
    }
    // Swap the ordering.
    FunctionalEqualityResult {
        code: 2,
        pairs: vec![
            (res1[0].clone(), res2[1].clone()),
            (res1[1].clone(), res2[0].clone()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};
    use crate::space::AddressSpace;

    #[test]
    fn test_add_expression_constants() {
        // Two constants 3 + 5 → constval=8, 0 terms
        let mut expr = AddExpression::new();
        let a = Arc::new(RwLock::new(Varnode::new_constant(4, 3)));
        let b = Arc::new(RwLock::new(Varnode::new_constant(4, 5)));
        expr.gather_two_terms_add(&a, &b);
        assert_eq!(expr.constval, 8);
        assert_eq!(expr.num_terms, 0);
    }

    #[test]
    fn test_add_expression_equiv() {
        // V + 3 should be equivalent to V + 3
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let c3 = Arc::new(RwLock::new(Varnode::new_constant(4, 3)));
        let mut expr1 = AddExpression::new();
        expr1.gather_two_terms_add(&v, &c3);
        let mut expr2 = AddExpression::new();
        expr2.gather_two_terms_add(&v, &c3);
        assert!(expr1.is_equivalent(&expr2));
    }

    #[test]
    fn test_functional_equality_level_same_pointer() {
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let r = functional_equality_level(&v, &v);
        assert_eq!(r.code, 0);
    }

    #[test]
    fn test_boolean_match_same_pointer() {
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 1)));
        assert_eq!(boolean_match_evaluate(&v, &v, 1), boolean_match::SAME);
    }

    #[test]
    fn test_boolean_match_uncorrelated_constants() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(1, 1)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(0, 1)));
        // Two different constants, neither written → uncorrelated.
        assert_eq!(boolean_match_evaluate(&c1, &c2, 1), boolean_match::UNCORRELATED);
    }

    #[test]
    fn test_boolean_match_complement_via_flip() {
        // V == 5  and  V != 5  are complementary.
        use crate::address::SeqNum;
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let c5 = Arc::new(RwLock::new(Varnode::new_constant(5, 4)));
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_INT_EQUAL)));
        eq_op.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        eq_op.write().unwrap().flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
        let eq_out = Arc::new(RwLock::new(Varnode::new_register(0x20, 1)));
        eq_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        eq_op.write().unwrap().output = Some(eq_out.clone());
        eq_out.write().unwrap().def = Some(Arc::downgrade(&eq_op));

        let ne_op = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_INT_NOTEQUAL)));
        ne_op.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        ne_op.write().unwrap().flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
        let ne_out = Arc::new(RwLock::new(Varnode::new_register(0x21, 1)));
        ne_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        ne_op.write().unwrap().output = Some(ne_out.clone());
        ne_out.write().unwrap().def = Some(Arc::downgrade(&ne_op));

        assert_eq!(boolean_match_evaluate(&eq_out, &ne_out, 1), boolean_match::COMPLEMENTARY);
    }

    #[test]
    fn test_functional_equality_level_constants_equal() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let r = functional_equality_level(&c1, &c2);
        assert_eq!(r.code, 0);
    }

    #[test]
    fn test_functional_equality_level_constants_unequal() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(4, 99)));
        let r = functional_equality_level(&c1, &c2);
        assert_eq!(r.code, -1);
    }

    #[test]
    fn test_functional_equality_level_different_sizes() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(8, 42)));
        let r = functional_equality_level(&c1, &c2);
        assert_eq!(r.code, -1);
    }

    #[test]
    fn test_functional_equality_level_free_varnodes() {
        // Two distinct free (unwritten) register varnodes → code 1 (might be
        // equal, depends on ops). But since they're not written, the deeper
        // check returns -1.
        let v1 = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let v2 = Arc::new(RwLock::new(Varnode::new_register(0x20, 4)));
        let r = functional_equality_level(&v1, &v2);
        assert_eq!(r.code, -1); // Not written → -1.
    }
}
