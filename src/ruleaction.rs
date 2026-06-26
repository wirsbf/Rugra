//! Rule-based transformations for P-code operations
//!
//! Corresponds to Ghidra's `ruleaction.hh`. Rules are small, local
//! transformations that target specific opcodes to simplify the IR.

use crate::action::Rule;
use crate::opcodes::OpCode;
use crate::funcdata::Funcdata;
use crate::op::PcodeOp;
use crate::error::Result;
use crate::action::action_status;

/// Rule for collapsing constants in arithmetic operations
///
/// Corresponds to Ghidra's `RuleCollapseConstants`
pub struct RuleCollapseConstants;

impl RuleCollapseConstants {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleCollapseConstants {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let mut op = op_arc.write().unwrap();

        // 1. Check if all inputs are constants
        if op.inrefs.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }

        let mut vals = Vec::new();
        for in_vn_arc in &op.inrefs {
            let in_vn = in_vn_arc.read().unwrap();
            if !in_vn.is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            vals.push(in_vn.get_val());
        }

        // 2. Compute result
        let res = match op.opcode {
            OpCode::CPUI_INT_ADD => vals[0].wrapping_add(vals[1]),
            OpCode::CPUI_INT_SUB => vals[0].wrapping_sub(vals[1]),
            OpCode::CPUI_INT_MULT => vals[0].wrapping_mul(vals[1]),
            OpCode::CPUI_INT_AND => vals[0] & vals[1],
            OpCode::CPUI_INT_OR => vals[0] | vals[1],
            OpCode::CPUI_INT_XOR => vals[0] ^ vals[1],
            _ => return Ok(action_status::NO_CHANGE),
        };

        // 3. Replace with COPY of the constant result
        let size = op.output.as_ref().map(|v| v.read().unwrap().size).unwrap_or(4);
        let res_vn = fd.vbank.create_constant(size, res);

        op.opcode = OpCode::CPUI_COPY;
        op.inrefs = vec![res_vn];

        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "collapse_constants"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::CPUI_INT_ADD,
            OpCode::CPUI_INT_SUB,
            OpCode::CPUI_INT_MULT,
            OpCode::CPUI_INT_DIV,
            OpCode::CPUI_INT_AND,
            OpCode::CPUI_INT_OR,
            OpCode::CPUI_INT_XOR,
        ]
    }
}

/// Rule for simplifying trivial boolean identities (e.g., x && true -> x)
///
/// Corresponds to Ghidra's `RuleTrivialBool`
pub struct RuleTrivialBool;

impl RuleTrivialBool {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTrivialBool {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let mut op = op_arc.write().unwrap();
        if op.inrefs.len() != 2 {
            return Ok(action_status::NO_CHANGE);
        }

        let mut identity_slot = -1i32;
        let mut constant_val = 0u64;

        if op.inrefs[0].read().unwrap().is_constant() {
            constant_val = op.inrefs[0].read().unwrap().get_val();
            identity_slot = 1;
        } else if op.inrefs[1].read().unwrap().is_constant() {
            constant_val = op.inrefs[1].read().unwrap().get_val();
            identity_slot = 0;
        }

        if identity_slot == -1 {
            return Ok(action_status::NO_CHANGE);
        }

        let mut changed = false;
        match op.opcode {
            OpCode::CPUI_BOOL_AND => {
                if constant_val == 1 {
                    // x && 1 -> x
                    let identity_vn = op.inrefs[identity_slot as usize].clone();
                    op.opcode = OpCode::CPUI_COPY;
                    op.inrefs = vec![identity_vn];
                    changed = true;
                }
            }
            OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                if constant_val == 0 {
                    // x || 0 -> x, x ^^ 0 -> x
                    let identity_vn = op.inrefs[identity_slot as usize].clone();
                    op.opcode = OpCode::CPUI_COPY;
                    op.inrefs = vec![identity_vn];
                    changed = true;
                }
            }
            _ => {}
        }

        if changed {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "trivial_bool"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::CPUI_BOOL_AND,
            OpCode::CPUI_BOOL_OR,
            OpCode::CPUI_BOOL_XOR,
        ]
    }
}

/// Rule for propagating copies
///
/// Corresponds to Ghidra's `RulePropagateCopy`
pub struct RulePropagateCopy;

impl RulePropagateCopy {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RulePropagateCopy {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let op = op_arc.read().unwrap();
        if op.opcode != OpCode::CPUI_COPY {
            return Ok(action_status::NO_CHANGE);
        }

        let in_vn_arc = match op.inrefs.get(0) {
            Some(vn) => vn.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };

        let out_vn_arc = match &op.output {
            Some(vn) => vn.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };

        let mut changed = false;
        let mut to_update = Vec::new();

        {
            let out_vn = out_vn_arc.read().unwrap();
            for descendant_weak in &out_vn.descend {
                if let Some(descendant_arc) = descendant_weak.upgrade() {
                    to_update.push(descendant_arc);
                }
            }
        }

        for descendant_arc in to_update {
            let mut descendant = descendant_arc.write().unwrap();
            for i in 0..descendant.inrefs.len() {
                if std::sync::Arc::ptr_eq(&descendant.inrefs[i], &out_vn_arc) {
                    descendant.inrefs[i] = in_vn_arc.clone();
                    changed = true;

                    // Update descend list for the new input
                    in_vn_arc.write().unwrap().descend.push(std::sync::Arc::downgrade(&descendant_arc));
                }
            }
        }

        if changed {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "propagate_copy"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_COPY]
    }
}

/// Rule for eliminating redundant zero-extensions
///
/// Corresponds to Ghidra's `RuleZextEliminate`
pub struct RuleZextEliminate;

impl RuleZextEliminate {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleZextEliminate {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let mut op = op_arc.write().unwrap();
        if op.opcode != OpCode::CPUI_INT_ZEXT {
            return Ok(action_status::NO_CHANGE);
        }

        let in_vn_arc = &op.inrefs[0];
        let out_vn_arc = match &op.output {
            Some(vn) => vn,
            None => return Ok(action_status::NO_CHANGE),
        };

        let in_size = in_vn_arc.read().unwrap().size;
        let out_size = out_vn_arc.read().unwrap().size;

        if in_size == out_size {
            // zext to same size is just a COPY
            op.opcode = OpCode::CPUI_COPY;
            return Ok(action_status::CHANGE);
        }

        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str {
        "zext_eliminate"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_ZEXT]
    }
}

/// Rule for eliminating redundant sign-extensions
///
/// Corresponds to Ghidra's `RuleSextEliminate`.
/// Collapses `INT_SEXT(x)` to `COPY(x)` when input and output sizes match.
pub struct RuleSextEliminate;

impl RuleSextEliminate {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSextEliminate {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let mut op = op_arc.write().unwrap();
        if op.opcode != OpCode::CPUI_INT_SEXT {
            return Ok(action_status::NO_CHANGE);
        }

        let in_vn_arc = &op.inrefs[0];
        let out_vn_arc = match &op.output {
            Some(vn) => vn,
            None => return Ok(action_status::NO_CHANGE),
        };

        let in_size = in_vn_arc.read().unwrap().size;
        let out_size = out_vn_arc.read().unwrap().size;

        if in_size == out_size {
            // sext to same size is just a COPY
            op.opcode = OpCode::CPUI_COPY;
            return Ok(action_status::CHANGE);
        }

        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str {
        "sext_eliminate"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_SEXT]
    }
}

/// Rule for simplifying trivial arithmetic identities
///
/// Corresponds to Ghidra's `RuleTrivialArith`.
/// Simplifies: `x + 0 → x`, `x - 0 → x`, `x * 1 → x`,
/// `x ^ 0 → x`, `x | 0 → x`.
pub struct RuleTrivialArith;

impl RuleTrivialArith {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTrivialArith {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let mut op = op_arc.write().unwrap();
        if op.inrefs.len() != 2 {
            return Ok(action_status::NO_CHANGE);
        }

        // Determine which slot (if any) is a constant, and get its value
        let (const_slot, const_val, other_slot) = {
            let v0 = op.inrefs[0].read().unwrap();
            let v1 = op.inrefs[1].read().unwrap();
            if v0.is_constant() {
                (0usize, v0.get_val(), 1usize)
            } else if v1.is_constant() {
                (1, v1.get_val(), 0)
            } else {
                return Ok(action_status::NO_CHANGE);
            }
        };

        let is_identity = match op.opcode {
            // x + 0, 0 + x → x
            OpCode::CPUI_INT_ADD => const_val == 0,
            // x - 0 → x  (but NOT 0 - x)
            OpCode::CPUI_INT_SUB => const_val == 0 && const_slot == 1,
            // x * 1, 1 * x → x
            OpCode::CPUI_INT_MULT => const_val == 1,
            // x ^ 0, 0 ^ x → x
            OpCode::CPUI_INT_XOR => const_val == 0,
            // x | 0, 0 | x → x
            OpCode::CPUI_INT_OR => const_val == 0,
            _ => false,
        };

        if is_identity {
            let identity_vn = op.inrefs[other_slot].clone();
            op.opcode = OpCode::CPUI_COPY;
            op.inrefs = vec![identity_vn];
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "trivial_arith"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::CPUI_INT_ADD,
            OpCode::CPUI_INT_SUB,
            OpCode::CPUI_INT_MULT,
            OpCode::CPUI_INT_XOR,
            OpCode::CPUI_INT_OR,
        ]
    }
}

/// Rule for simplifying shift-by-zero operations
///
/// Corresponds to Ghidra's shift simplification rules.
/// Collapses `x << 0 → x`, `x >> 0 → x`, `x >>> 0 → x`.
pub struct RuleShiftBitops;

impl RuleShiftBitops {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleShiftBitops {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let mut op = op_arc.write().unwrap();
        if op.inrefs.len() != 2 {
            return Ok(action_status::NO_CHANGE);
        }

        // Shift amount is always input[1]
        let shift_val = {
            let v1 = op.inrefs[1].read().unwrap();
            if !v1.is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            v1.get_val()
        };

        let is_nop_shift = match op.opcode {
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => {
                shift_val == 0
            }
            _ => false,
        };

        if is_nop_shift {
            let identity_vn = op.inrefs[0].clone();
            op.opcode = OpCode::CPUI_COPY;
            op.inrefs = vec![identity_vn];
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "shift_bitops"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::CPUI_INT_LEFT,
            OpCode::CPUI_INT_RIGHT,
            OpCode::CPUI_INT_SRIGHT,
        ]
    }
}

/// Apply INT_NEGATE identities: `V & ~V => #0`, `V | ~V => #-1`, `V ^ ~V => #-1`.
///
/// Faithful to Ghidra's `RuleNegateIdentity` (ruleaction.cc:444-474). When an
/// `INT_NEGATE(V)` output feeds an `INT_AND`/`INT_OR`/`INT_XOR` whose other
/// operand is the original `V`, the logic op collapses to a `COPY` of the
/// all-zero (for AND) or all-ones (for OR/XOR) constant.
///
/// Note: Rugra names the bitwise-not opcode `CPUI_INT_NOT` (Ghidra's
/// `INT_NEGATE`); Ghidra's `INT_2COMP` (arithmetic negate) is `CPUI_INT_NEG`.
pub struct RuleNegateIdentity;

impl RuleNegateIdentity {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleNegateIdentity {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // op is INT_NOT(V) -> outVn (~V). Walk outVn's descendants looking
        // for a logic op whose other input is V.
        let out_vn = {
            let op = op_arc.read().unwrap();
            match op.output.clone() {
                Some(o) => o,
                None => return Ok(action_status::NO_CHANGE),
            }
        };
        let negated_vn = {
            let op = op_arc.read().unwrap();
            op.inrefs.first().cloned()
        };
        let negated_vn = match negated_vn {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };

        // Collect descendant ops (ops that read out_vn).
        let descendants: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = {
            let ov = out_vn.read().unwrap();
            ov.descend.iter().filter_map(|w| w.upgrade()).collect()
        };

        for logic_arc in descendants {
            let mut logic = logic_arc.write().unwrap();
            let opc = logic.opcode;
            if opc != OpCode::CPUI_INT_AND
                && opc != OpCode::CPUI_INT_OR
                && opc != OpCode::CPUI_INT_XOR
            {
                continue;
            }
            // Find the slot of out_vn; the other slot must equal negated_vn.
            let mut slot = -1i32;
            for (i, in_vn) in logic.inrefs.iter().enumerate() {
                if std::sync::Arc::ptr_eq(in_vn, &out_vn) {
                    slot = i as i32;
                    break;
                }
            }
            if slot < 0 {
                continue;
            }
            let other_slot = (1 - slot) as usize;
            let other_is_negated = logic
                .inrefs
                .get(other_slot)
                .map(|v| std::sync::Arc::ptr_eq(v, &negated_vn))
                .unwrap_or(false);
            if !other_is_negated {
                continue;
            }
            // Collapse: AND -> 0, OR/XOR -> all-ones.
            let size = {
                let nv = negated_vn.read().unwrap();
                nv.get_size()
            };
            let value = if opc == OpCode::CPUI_INT_AND {
                0u64
            } else {
                let mask = if size >= 64 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
                mask
            };
            let const_vn = fd.vbank.create_constant(size, value);
            // Ghidra: opSetInput(logicOp, const, 0); opRemoveInput(logicOp, 1);
            //         opSetOpcode(logicOp, COPY);
            logic.opcode = OpCode::CPUI_COPY;
            logic.inrefs = vec![const_vn];
            drop(logic);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str {
        "negate_identity"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        // Ghidra INT_NEGATE == Rugra CPUI_INT_NOT
        vec![OpCode::CPUI_INT_NOT]
    }
}

/// Distribute BOOL_NEGATE via De Morgan's law:
///   `!(V && W)  =>  !V || !W`
///   `!(V || W)  =>  !V && !W`
///
/// Faithful to Ghidra's `RuleNotDistribute` (ruleaction.cc:1139-1183). Creates
/// two new BOOL_NEGATE ops for the operands and rewrites the original op into
/// the dual logic op, using the Funcdata op-edit API.
pub struct RuleNotDistribute;

impl RuleNotDistribute {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleNotDistribute {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // op is BOOL_NEGATE(in0). in0 must be defined by a BOOL_AND/BOOL_OR.
        let compop_arc = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.first() {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let in0r = in0.read().unwrap();
            in0r.def.as_ref().and_then(|w| w.upgrade())
        };
        let compop_arc = match compop_arc {
            Some(a) => a,
            None => return Ok(action_status::NO_CHANGE),
        };
        let new_opcode = {
            let compop = compop_arc.read().unwrap();
            match compop.opcode {
                OpCode::CPUI_BOOL_AND => OpCode::CPUI_BOOL_OR,
                OpCode::CPUI_BOOL_OR => OpCode::CPUI_BOOL_AND,
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        // Capture the two operands of the comparison op.
        let in_v1 = compop_arc.read().unwrap().inrefs.get(0).cloned();
        let in_v2 = compop_arc.read().unwrap().inrefs.get(1).cloned();
        let (in_v1, in_v2) = match (in_v1, in_v2) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };

        let pc = {
            let op = op_arc.read().unwrap();
            op.start.get_addr()
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());

        // newneg1 = BOOL_NEGATE(in_v1) → newout1
        let newneg1 = fd.new_op(1, pc);
        fd.op_set_opcode(&newneg1, OpCode::CPUI_BOOL_NOT);
        let newout1 = fd.new_unique_out(1, &newneg1);
        fd.op_set_input(&newneg1, in_v1, 0);
        fd.op_insert_before(&newneg1, &follow);

        // newneg2 = BOOL_NEGATE(in_v2) → newout2
        let newneg2 = fd.new_op(1, pc);
        fd.op_set_opcode(&newneg2, OpCode::CPUI_BOOL_NOT);
        let newout2 = fd.new_unique_out(1, &newneg2);
        fd.op_set_input(&newneg2, in_v2, 0);
        fd.op_insert_before(&newneg2, &follow);

        // Rewrite the original op: opcode := dual, inputs := [newout1, newout2].
        fd.op_set_opcode(&follow, new_opcode);
        {
            let mut op = op_arc.write().unwrap();
            op.inrefs = vec![newout1, newout2];
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "not_distribute"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_BOOL_NOT]
    }
}

/// Simplify concatenation with zero: `concat(V, 0) => zext(V) << c`.
///
/// Faithful to Ghidra's `RuleConcatZero` (ruleaction.cc:4977-5002). When the
/// low (input 1) piece of a PIECE is an all-zero constant, the PIECE becomes
/// a left-shift of a zero-extension of the high piece.
pub struct RuleConcatZero;

impl RuleConcatZero {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleConcatZero {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // in1 must be a constant == 0.
        let (in0, in1, out_size, pc) = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let in1 = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let out_size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            (in0, in1, out_size, op.start.get_addr())
        };
        {
            let i1 = in1.read().unwrap();
            if !i1.is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            if i1.get_offset() != 0 {
                return Ok(action_status::NO_CHANGE);
            }
        }
        if out_size == 0 {
            return Ok(action_status::NO_CHANGE);
        }
        let low_size = in1.read().unwrap().get_size();
        let sa = 8 * low_size; // shift amount in bits

        // newop = INT_ZEXT(in0) → outvn (full output size)
        let newop = fd.new_op(1, pc);
        fd.op_set_opcode(&newop, OpCode::CPUI_INT_ZEXT);
        let outvn = fd.new_unique_out(out_size, &newop);
        fd.op_set_input(&newop, in0, 0);
        fd.op_insert_before(&newop, &crate::op::PcodeOpRef(op_arc.clone()));

        // Rewrite the original PIECE op into INT_LEFT(zext, sa).
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_LEFT);
        fd.op_set_input(&follow, outvn, 0);
        let shift_const = fd.new_constant(4, sa as u64);
        fd.op_set_input(&follow, shift_const, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "concat_zero"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_PIECE]
    }
}

/// Eliminate INT_XOR in comparisons: `(V ^ W) == 0 => V == W`,
/// `(V ^ c) == d => V == (c^d)`.
///
/// Faithful to Ghidra's `RuleXorCollapse` (ruleaction.cc:4058-4097).
pub struct RuleXorCollapse;

impl RuleXorCollapse {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleXorCollapse {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // in1 must be a constant.
        let (in0, coeff1) = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let in1 = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let i1 = in1.read().unwrap();
            if !i1.is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            (in0, i1.get_offset())
        };
        // in0 must be defined by an INT_XOR.
        let xorop_arc = {
            let in0r = in0.read().unwrap();
            in0r.def.as_ref().and_then(|w| w.upgrade())
        };
        let xorop_arc = match xorop_arc {
            Some(a) => a,
            None => return Ok(action_status::NO_CHANGE),
        };
        let is_xor = xorop_arc.read().unwrap().opcode == OpCode::CPUI_INT_XOR;
        if !is_xor {
            return Ok(action_status::NO_CHANGE);
        }
        // The xor output must have a lone descend (this op) for safe rewrite.
        let descend_count = {
            let xorout = xorop_arc.read().unwrap().output.as_ref().map(|o| o.clone());
            match xorout {
                Some(o) => o.read().unwrap().descend.iter().filter(|w| w.upgrade().is_some()).count(),
                None => 0,
            }
        };
        if descend_count != 1 {
            return Ok(action_status::NO_CHANGE);
        }
        let (xor_in0, xor_in1) = {
            let x = xorop_arc.read().unwrap();
            (
                x.inrefs.get(0).cloned(),
                x.inrefs.get(1).cloned(),
            )
        };
        let (xor_in0, xor_in1) = match (xor_in0, xor_in1) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };

        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if !xor_in1.read().unwrap().is_constant() {
            // (V ^ W) == c : only valid when c == 0 → move W to other side.
            if coeff1 != 0 {
                return Ok(action_status::NO_CHANGE);
            }
            fd.op_set_input(&follow, xor_in1, 1);
            fd.op_set_input(&follow, xor_in0, 0);
            return Ok(action_status::CHANGE);
        }
        // (V ^ c) == d → V == (c^d)
        let coeff2 = xor_in1.read().unwrap().get_offset();
        if coeff2 == 0 {
            return Ok(action_status::NO_CHANGE);
        }
        let size = in0.read().unwrap().get_size();
        let constvn = fd.new_constant(size, coeff1 ^ coeff2);
        fd.op_set_input(&follow, constvn, 1);
        fd.op_set_input(&follow, xor_in0, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "xor_collapse"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL]
    }
}

/// Collapse constants in an additive/multiplicative expression:
///   `((V + c) + d)  =>  V + (c+d)`
///   `((V * c) * d)  =>  V * (c*d)`
///
/// Faithful to Ghidra's `RuleAddMultCollapse` (ruleaction.cc:4099-4183). This
/// ports the primary form: when an INT_ADD/INT_MULT has a constant in slot 1
/// and its slot-0 input is defined by the same op-code with another constant,
/// fold the two constants together. The spacebase sub-case (4131-4169) is
/// deferred (requires isSpacebase/isInput tracking).
pub struct RuleAddMultCollapse;

impl RuleAddMultCollapse {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleAddMultCollapse {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // c[0] = in1 (must be constant), sub = in0.
        let (sub_arc, c0, opc) = {
            let op = op_arc.read().unwrap();
            let sub = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let c0 = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            if !c0.read().unwrap().is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            (sub, c0, op.opcode)
        };
        if opc != OpCode::CPUI_INT_ADD && opc != OpCode::CPUI_INT_MULT {
            return Ok(action_status::NO_CHANGE);
        }
        // sub must be defined by the same op-code.
        let subop_arc = {
            let sr = sub_arc.read().unwrap();
            sr.def.as_ref().and_then(|w| w.upgrade())
        };
        let subop_arc = match subop_arc {
            Some(a) => a,
            None => return Ok(action_status::NO_CHANGE),
        };
        if subop_arc.read().unwrap().opcode != opc {
            return Ok(action_status::NO_CHANGE);
        }
        // c[1] = subop->getIn(1) (must be constant).
        let (sub2, c1) = {
            let so = subop_arc.read().unwrap();
            let sub2 = match so.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let c1 = match so.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            if !c1.read().unwrap().is_constant() {
                // The spacebase sub-case is deferred; no change here.
                return Ok(action_status::NO_CHANGE);
            }
            (sub2, c1)
        };
        if sub2.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }

        // Fold: val = c[0] <opc> c[1].
        let size = c0.read().unwrap().get_size();
        let v0 = c0.read().unwrap().get_offset();
        let v1 = c1.read().unwrap().get_offset();
        let val = match opc {
            OpCode::CPUI_INT_ADD => v0.wrapping_add(v1),
            OpCode::CPUI_INT_MULT => v0.wrapping_mul(v1),
            _ => return Ok(action_status::NO_CHANGE),
        };
        let new_const = fd.new_constant(size, val);

        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, new_const, 1); // replace c[0] with folded constant
        fd.op_set_input(&follow, sub2, 0);      // replace sub with sub2
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "add_mult_collapse"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_ADD, OpCode::CPUI_INT_MULT]
    }
}

/// All-ones mask for a given byte size (Ghidra's `calc_mask`).
fn calc_mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// Simplify INT_LESS applied to extremal constants (0 or all-ones).
/// Faithful to Ghidra's `RuleLess2Zero` (ruleaction.cc:5557-5603).
///
/// Forms:
///   `0 < V   => 0 != V`
///   `V < 0   => false`
///   `ffff < V => false`
///   `V < ffff => V != ffff`
pub struct RuleLess2Zero;

impl RuleLess2Zero {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLess2Zero {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (lvn, rvn) = {
            let op = op_arc.read().unwrap();
            let l = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let r = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (l, r)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if lvn.read().unwrap().is_constant() {
            let lsize = lvn.read().unwrap().get_size();
            let loff = lvn.read().unwrap().get_offset();
            if loff == 0 {
                // 0 < V  =>  0 != V  (all values except 0 are true)
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_NOTEQUAL);
                return Ok(action_status::CHANGE);
            } else if loff == calc_mask(lsize) {
                // ffff < V  =>  false
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                fd.op_remove_input(&follow, 1);
                let c = fd.new_constant(1, 0);
                fd.op_set_input(&follow, c, 0);
                return Ok(action_status::CHANGE);
            }
        } else if rvn.read().unwrap().is_constant() {
            let rsize = rvn.read().unwrap().get_size();
            let roff = rvn.read().unwrap().get_offset();
            if roff == 0 {
                // V < 0  =>  false
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                fd.op_remove_input(&follow, 1);
                let c = fd.new_constant(1, 0);
                fd.op_set_input(&follow, c, 0);
                return Ok(action_status::CHANGE);
            } else if roff == calc_mask(rsize) {
                // V < ffff  =>  V != ffff
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_NOTEQUAL);
                return Ok(action_status::CHANGE);
            }
        }
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str {
        "less2_zero"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_LESS]
    }
}

/// Simplify INT_LESSEQUAL applied to extremal constants.
/// Faithful to Ghidra's `RuleLessEqual2Zero` (ruleaction.cc:5605-5651).
///
/// Forms:
///   `0 <= V   => true`
///   `V <= 0   => V == 0`
///   `ffff <= V => ffff == V`
///   `V <= ffff => true`
pub struct RuleLessEqual2Zero;

impl RuleLessEqual2Zero {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLessEqual2Zero {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (lvn, rvn) = {
            let op = op_arc.read().unwrap();
            let l = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let r = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (l, r)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if lvn.read().unwrap().is_constant() {
            let lsize = lvn.read().unwrap().get_size();
            let loff = lvn.read().unwrap().get_offset();
            if loff == 0 {
                // 0 <= V  =>  true
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                fd.op_remove_input(&follow, 1);
                let c = fd.new_constant(1, 1);
                fd.op_set_input(&follow, c, 0);
                return Ok(action_status::CHANGE);
            } else if loff == calc_mask(lsize) {
                // ffff <= V  =>  ffff == V
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_EQUAL);
                return Ok(action_status::CHANGE);
            }
        } else if rvn.read().unwrap().is_constant() {
            let rsize = rvn.read().unwrap().get_size();
            let roff = rvn.read().unwrap().get_offset();
            if roff == 0 {
                // V <= 0  =>  V == 0
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_EQUAL);
                return Ok(action_status::CHANGE);
            } else if roff == calc_mask(rsize) {
                // V <= ffff  =>  true
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                fd.op_remove_input(&follow, 1);
                let c = fd.new_constant(1, 1);
                fd.op_set_input(&follow, c, 0);
                return Ok(action_status::CHANGE);
            }
        }
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str {
        "lessequal2_zero"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_LESSEQUAL]
    }
}

/// Push boolean negation through a comparison:
///   `!!V  =>  V`
///   `!(V == W)  =>  V != W`
///   `!(V < W)   =>  W <= V`
///   `!(V <= W)  =>  W < V`
///   `!(V != W)  =>  V == W`
///
/// Faithful to Ghidra's `RuleBoolNegate` (ruleaction.cc:5516-5555). When a
/// BOOL_NOT wraps a comparison whose output is consumed ONLY by BOOL_NOT ops,
/// flip the comparison op to its complement (reordering operands if needed)
/// and turn every descendant BOOL_NOT into a COPY (removing the negations).
pub struct RuleBoolNegate;

impl RuleBoolNegate {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleBoolNegate {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // op is BOOL_NOT(in0). in0 must be defined by a flippable comparison.
        let (flipop_arc, descend_vn) = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.first() {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let in0r = in0.read().unwrap();
            let flip = in0r.def.as_ref().and_then(|w| w.upgrade());
            match flip {
                Some(f) => (f, in0.clone()),
                None => return Ok(action_status::NO_CHANGE),
            }
        };
        // ALL descendants of the comparison output must be BOOL_NOT.
        let descendants: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = {
            let dv = descend_vn.read().unwrap();
            dv.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        if descendants.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        for d in &descendants {
            if d.read().unwrap().opcode != OpCode::CPUI_BOOL_NOT {
                return Ok(action_status::NO_CHANGE);
            }
        }
        // Flip the comparison op.
        let flip_code = flipop_arc.read().unwrap().opcode;
        let mut reorder = false;
        let new_code = crate::opcodes::get_booleanflip(flip_code, &mut reorder);
        if new_code == OpCode::CPUI_MAX {
            return Ok(action_status::NO_CHANGE);
        }
        let flip_ref = crate::op::PcodeOpRef(flipop_arc.clone());
        fd.op_set_opcode(&flip_ref, new_code);
        if reorder {
            fd.op_swap_input(&flip_ref, 0, 1);
        }
        // Turn every descendant BOOL_NOT into a COPY.
        for d in descendants {
            fd.op_set_opcode(&crate::op::PcodeOpRef(d), OpCode::CPUI_COPY);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "bool_negate"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        // Ghidra BOOL_NEGATE == Rugra BOOL_NOT
        vec![OpCode::CPUI_BOOL_NOT]
    }
}

/// Simplify INT_OR with a full mask: `V = W | 0xffff  =>  V = #0xffff`.
///
/// Faithful to Ghidra's `RuleOrMask` (ruleaction.cc:276-300). When the OR
/// constant sets every bit of the output size, the result is just that
/// constant — rewrite as COPY(constant).
pub struct RuleOrMask;

impl RuleOrMask {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleOrMask {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (const_vn, size) = {
            let op = op_arc.read().unwrap();
            let out_size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            let const_vn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            (const_vn, out_size)
        };
        if size == 0 || size > 8 {
            return Ok(action_status::NO_CHANGE); // no output or uintb precision limit
        }
        let val = const_vn.read().unwrap().get_offset();
        let mask = calc_mask(size);
        if val & mask != mask {
            return Ok(action_status::NO_CHANGE);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        fd.op_set_input(&follow, const_vn, 0);
        fd.op_remove_input(&follow, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "or_mask"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_OR]
    }
}

/// Collapse constants in logical expressions:
///   `(V & c) & d  =>  V & (c & d)`
///   `(V | c) | d  =>  V | (c | d)`
///   `(V ^ c) ^ d  =>  V ^ (c ^ d)`
///
/// Faithful to Ghidra's `RuleAndOrLump` (ruleaction.cc:403-442). When a
/// bitwise op has a constant in slot 1 and its slot-0 input is defined by the
/// same op-code with another constant, fold the two constants.
pub struct RuleAndOrLump;

impl RuleAndOrLump {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleAndOrLump {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (base_vn, opc) = {
            let op = op_arc.read().unwrap();
            let in1 = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            // in1 const captured above; re-check in0 written by same opc.
            let _ = in1;
            if !matches!(op.opcode, OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR) {
                return Ok(action_status::NO_CHANGE);
            }
            (in0, op.opcode)
        };
        let op2_arc = {
            let b = base_vn.read().unwrap();
            b.def.as_ref().and_then(|w| w.upgrade())
        };
        let op2_arc = match op2_arc {
            Some(a) => a,
            None => return Ok(action_status::NO_CHANGE),
        };
        if op2_arc.read().unwrap().opcode != opc {
            return Ok(action_status::NO_CHANGE);
        }
        let (basevn, c1, c2_val) = {
            let o2 = op2_arc.read().unwrap();
            let basevn = match o2.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let c1 = match o2.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let c2 = op_arc.read().unwrap().inrefs[1].read().unwrap().get_offset();
            (basevn, c1, c2)
        };
        if basevn.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }
        let c1_val = c1.read().unwrap().get_offset();
        let val = match opc {
            OpCode::CPUI_INT_AND => c1_val & c2_val,
            OpCode::CPUI_INT_OR => c1_val | c2_val,
            OpCode::CPUI_INT_XOR => c1_val ^ c2_val,
            _ => return Ok(action_status::NO_CHANGE),
        };
        let size = basevn.read().unwrap().get_size();
        let new_const = fd.new_constant(size, val);
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, basevn, 0);
        fd.op_set_input(&follow, new_const, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "and_or_lump"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_AND, OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR]
    }
}

/// Concatenation with zero high bits becomes a zero-extension:
///   `concat(0, V)  =>  zext(V)`
///
/// Faithful to Ghidra's `RulePiece2Zext` (ruleaction.cc:207-230). When the
/// most-significant (input 0) piece of a PIECE is a constant 0, the PIECE
/// collapses into an INT_ZEXT of the low piece.
pub struct RulePiece2Zext;

impl RulePiece2Zext {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RulePiece2Zext {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let is_zero_high = {
            let op = op_arc.read().unwrap();
            let constvn = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            constvn.read().unwrap().is_constant() && constvn.read().unwrap().get_offset() == 0
        };
        if !is_zero_high {
            return Ok(action_status::NO_CHANGE);
        }
        {
            let mut op = op_arc.write().unwrap();
            op.inrefs.remove(0);
            op.opcode = OpCode::CPUI_INT_ZEXT;
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "piece2zext"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_PIECE]
    }
}

/// Concatenation with sign bits becomes a sign-extension:
///   `concat(V s>> #0x1f, V)  =>  sext(V)`
///
/// Faithful to Ghidra's `RulePiece2Sext` (ruleaction.cc:232-259). When the
/// high piece of a PIECE is a sign-bit shift (`V s>> (8*size-1)`) of the low
/// piece V, the PIECE collapses into an INT_SEXT of V.
pub struct RulePiece2Sext;

impl RulePiece2Sext {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RulePiece2Sext {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        let matches = {
            let op = op_arc.read().unwrap();
            let shiftout = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let low_vn = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let shiftop_arc = {
                let s = shiftout.read().unwrap();
                s.def.as_ref().and_then(|w| w.upgrade())
            };
            let shiftop_arc = match shiftop_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            let (is_sright, shift_n, shift_x) = {
                let so = shiftop_arc.read().unwrap();
                if so.opcode != OpCode::CPUI_INT_SRIGHT {
                    return Ok(action_status::NO_CHANGE);
                }
                let n_const = match so.inrefs.get(1) {
                    Some(v) if v.read().unwrap().is_constant() => v.read().unwrap().get_offset(),
                    _ => return Ok(action_status::NO_CHANGE),
                };
                let x = match so.inrefs.get(0) {
                    Some(v) => v.clone(),
                    None => return Ok(action_status::NO_CHANGE),
                };
                (true, n_const as i64, x)
            };
            if !is_sright {
                return Ok(action_status::NO_CHANGE);
            }
            if !std::sync::Arc::ptr_eq(&shift_x, &low_vn) {
                return Ok(action_status::NO_CHANGE);
            }
            let x_size = low_vn.read().unwrap().get_size() as i64;
            shift_n == 8 * x_size - 1
        };
        if !matches {
            return Ok(action_status::NO_CHANGE);
        }
        {
            let mut op = op_arc.write().unwrap();
            op.inrefs.remove(0);
            op.opcode = OpCode::CPUI_INT_SEXT;
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "piece2sext"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_PIECE]
    }
}

/// Eliminate BOOL_XOR: `V ^^ W  =>  V != W`.
///
/// Faithful to Ghidra's `RuleBxor2NotEqual` (ruleaction.cc:261-274). A
/// boolean XOR is semantically a boolean inequality, so rewrite it directly.
pub struct RuleBxor2NotEqual;

impl RuleBxor2NotEqual {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleBxor2NotEqual {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        op_arc.write().unwrap().opcode = OpCode::CPUI_INT_NOTEQUAL;
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "bxor2notequal"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_BOOL_XOR]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};
    use std::sync::{Arc, RwLock};

    /// Helper: create a PcodeOp with a given opcode, two inputs, and an output
    fn make_binary_op(
        opcode: OpCode,
        in0_space: crate::space::AddressSpace,
        in0_val: u64,
        in0_size: usize,
        in1_space: crate::space::AddressSpace,
        in1_val: u64,
        in1_size: usize,
        out_size: usize,
    ) -> (Arc<RwLock<PcodeOp>>, Funcdata) {
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        let in0 = if in0_space == crate::space::AddressSpace::Const {
            fd.vbank.create_constant(in0_size, in0_val)
        } else {
            fd.vbank.create_with_space(in0_size, in0_space, in0_val)
        };
        let in1 = if in1_space == crate::space::AddressSpace::Const {
            fd.vbank.create_constant(in1_size, in1_val)
        } else {
            fd.vbank.create_with_space(in1_size, in1_space, in1_val)
        };
        let out = fd.vbank.create_with_space(out_size, crate::space::AddressSpace::Register, 0x100);

        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, opcode);
        op.inrefs = vec![in0, in1];
        op.output = Some(out);

        let op_arc = Arc::new(RwLock::new(op));
        (op_arc, fd)
    }

    #[test]
    fn test_trivial_arith_add_zero() {
        let rule = RuleTrivialArith::new();
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_ADD,
            crate::space::AddressSpace::Register, 0x00, 8, // x = RAX
            crate::space::AddressSpace::Const, 0, 8,       // 0
            8,
        );

        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(op_arc.read().unwrap().inrefs.len(), 1);
    }

    #[test]
    fn test_trivial_arith_mult_one() {
        let rule = RuleTrivialArith::new();
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_MULT,
            crate::space::AddressSpace::Register, 0x00, 4,
            crate::space::AddressSpace::Const, 1, 4,
            4,
        );

        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_COPY);
    }

    #[test]
    fn test_trivial_arith_sub_zero() {
        let rule = RuleTrivialArith::new();
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_SUB,
            crate::space::AddressSpace::Register, 0x00, 8,
            crate::space::AddressSpace::Const, 0, 8,
            8,
        );
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
    }

    #[test]
    fn test_trivial_arith_sub_from_zero_not_identity() {
        // 0 - x should NOT be simplified
        let rule = RuleTrivialArith::new();
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_SUB,
            crate::space::AddressSpace::Const, 0, 8,
            crate::space::AddressSpace::Register, 0x00, 8,
            8,
        );
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    #[test]
    fn test_shift_by_zero() {
        let rule = RuleShiftBitops::new();
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_LEFT,
            crate::space::AddressSpace::Register, 0x00, 8,
            crate::space::AddressSpace::Const, 0, 8,
            8,
        );
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_COPY);
    }

    #[test]
    fn test_shift_by_nonzero_unchanged() {
        let rule = RuleShiftBitops::new();
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_LEFT,
            crate::space::AddressSpace::Register, 0x00, 8,
            crate::space::AddressSpace::Const, 3, 8,
            8,
        );
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleNegateIdentity (ruleaction.cc:444-474) ---

    /// Build INT_NEGATE(V) → tmp, then INT_AND(tmp, V) → out. The rule should
    /// collapse the AND into COPY(0).
    #[test]
    fn test_negate_identity_and_collapses_to_zero() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // V = a register varnode
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        // tmp = INT_NEGATE(V)
        let tmp = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let neg_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_NOT,
        )));
        {
            let mut o = neg_op.write().unwrap();
            o.inrefs = vec![v.clone()];
            o.output = Some(tmp.clone());
        }
        // out = INT_AND(tmp, V)
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut o = and_op.write().unwrap();
            o.inrefs = vec![tmp.clone(), v.clone()];
            o.output = Some(out);
        }
        // Wire descend: tmp is read by and_op.
        tmp.write().unwrap().descend.push(Arc::downgrade(&and_op));

        let rule = RuleNegateIdentity::new();
        let result = rule.apply_op(&neg_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // The AND op should now be COPY(0).
        let and = and_op.read().unwrap();
        assert_eq!(and.opcode, OpCode::CPUI_COPY);
        assert_eq!(and.inrefs.len(), 1);
        assert!(and.inrefs[0].read().unwrap().is_constant());
        assert_eq!(and.inrefs[0].read().unwrap().get_val(), 0);
    }

    #[test]
    fn test_negate_identity_or_collapses_to_ones() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let tmp = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let neg_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_NOT,
        )));
        {
            let mut o = neg_op.write().unwrap();
            o.inrefs = vec![v.clone()];
            o.output = Some(tmp.clone());
        }
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        // INT_OR(tmp, V) — order reversed to exercise the slot logic.
        let or_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut o = or_op.write().unwrap();
            o.inrefs = vec![v.clone(), tmp.clone()];
            o.output = Some(out);
        }
        tmp.write().unwrap().descend.push(Arc::downgrade(&or_op));

        let rule = RuleNegateIdentity::new();
        let result = rule.apply_op(&neg_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let or = or_op.read().unwrap();
        assert_eq!(or.opcode, OpCode::CPUI_COPY);
        // 4-byte all-ones = 0xffffffff
        assert_eq!(or.inrefs[0].read().unwrap().get_val(), 0xffffffff);
    }

    #[test]
    fn test_negate_identity_no_match() {
        // INT_NEGATE(V) feeding INT_AND(~V, W) where W != V → no change.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x50);
        let tmp = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let neg_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_NOT,
        )));
        {
            let mut o = neg_op.write().unwrap();
            o.inrefs = vec![v.clone()];
            o.output = Some(tmp.clone());
        }
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut o = and_op.write().unwrap();
            o.inrefs = vec![tmp.clone(), w.clone()];
            o.output = Some(out);
        }
        tmp.write().unwrap().descend.push(Arc::downgrade(&and_op));

        let rule = RuleNegateIdentity::new();
        let result = rule.apply_op(&neg_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- Funcdata op-edit API (funcdata.hh:281-479) ---

    #[test]
    fn test_funcdata_new_op_and_unique_out() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let op = fd.new_op(1, Address::new(0x1000));
        // newOp defaults opcode to COPY.
        assert_eq!(op.0.read().unwrap().opcode, OpCode::CPUI_COPY);
        let out = fd.new_unique_out(4, &op);
        // output is set, varnode is WRITTEN, def links back to op.
        assert!(op.0.read().unwrap().output.is_some());
        assert!(out.read().unwrap().is_written());
        assert!(out.read().unwrap().def.as_ref().and_then(|w| w.upgrade()).is_some());
    }

    #[test]
    fn test_funcdata_op_set_opcode_and_input() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
        assert_eq!(op.0.read().unwrap().opcode, OpCode::CPUI_INT_ADD);
        let in_vn = fd.new_constant(4, 0x10);
        fd.op_set_input(&op, in_vn, 0);
        assert_eq!(op.0.read().unwrap().inrefs.len(), 1);
    }

    #[test]
    fn test_funcdata_op_insert_and_remove_input() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let op = fd.new_op(2, Address::new(0x1000));
        let v1 = fd.new_constant(4, 1);
        let v2 = fd.new_constant(4, 2);
        fd.op_set_input(&op, v1, 0);
        fd.op_insert_input(&op, v2, 1);
        assert_eq!(op.0.read().unwrap().inrefs.len(), 2);
        fd.op_remove_input(&op, 1);
        assert_eq!(op.0.read().unwrap().inrefs.len(), 1);
    }

    // --- RuleNotDistribute (ruleaction.cc:1139-1183) De Morgan ---

    #[test]
    fn test_not_distribute_bool_and_to_or() {
        // BOOL_NOT(BOOL_AND(V, W)) → BOOL_OR(BOOL_NOT(V), BOOL_NOT(W))
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BOOL_AND,
        )));
        let and_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        {
            let mut a = and_op.write().unwrap();
            a.inrefs = vec![v, w];
            a.output = Some(and_out.clone());
        }
        and_out.write().unwrap().def = Some(Arc::downgrade(&and_op));
        let not_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_BOOL_NOT,
        )));
        not_op.write().unwrap().inrefs = vec![and_out];

        let rule = RuleNotDistribute::new();
        let result = rule.apply_op(&not_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // Original not_op is now BOOL_OR with 2 inputs.
        let n = not_op.read().unwrap();
        assert_eq!(n.opcode, OpCode::CPUI_BOOL_OR);
        assert_eq!(n.inrefs.len(), 2);
    }

    #[test]
    fn test_not_distribute_non_bool_inner_no_change() {
        // BOOL_NOT(INT_ADD(...)) → no change.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        let add_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        {
            let mut a = add_op.write().unwrap();
            a.inrefs = vec![v, w];
            a.output = Some(add_out.clone());
        }
        add_out.write().unwrap().def = Some(Arc::downgrade(&add_op));
        let not_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_BOOL_NOT,
        )));
        not_op.write().unwrap().inrefs = vec![add_out];

        let rule = RuleNotDistribute::new();
        let result = rule.apply_op(&not_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleConcatZero (ruleaction.cc:4977) ---

    #[test]
    fn test_concat_zero_collapses_to_shift() {
        // PIECE(V_high, 0) → INT_LEFT(INT_ZEXT(V_high), sa)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let high = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x10);
        let low_zero = fd.vbank.create_constant(2, 0);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let piece_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut p = piece_op.write().unwrap();
            p.inrefs = vec![high, low_zero];
            p.output = Some(out);
        }

        let rule = RuleConcatZero::new();
        let result = rule.apply_op(&piece_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let p = piece_op.read().unwrap();
        assert_eq!(p.opcode, OpCode::CPUI_INT_LEFT);
        assert_eq!(p.inrefs.len(), 2);
        // shift amount = 8 * low_size = 8 * 2 = 16
        assert_eq!(p.inrefs[1].read().unwrap().get_val(), 16);
    }

    #[test]
    fn test_concat_nonzero_no_change() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let high = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x10);
        let low_nz = fd.vbank.create_constant(2, 5);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let piece_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut p = piece_op.write().unwrap();
            p.inrefs = vec![high, low_nz];
            p.output = Some(out);
        }
        let rule = RuleConcatZero::new();
        let result = rule.apply_op(&piece_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleXorCollapse (ruleaction.cc:4058) ---

    #[test]
    fn test_xor_collapse_var_xor_const_eq_const() {
        // (V ^ 0x3) == 0x1  →  V == (0x3 ^ 0x1) == 0x2
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let c = fd.vbank.create_constant(4, 3);
        let xor_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let xor_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_XOR,
        )));
        {
            let mut x = xor_op.write().unwrap();
            x.inrefs = vec![v, c];
            x.output = Some(xor_out.clone());
        }
        xor_out.write().unwrap().def = Some(Arc::downgrade(&xor_op));
        let d = fd.vbank.create_constant(4, 1);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_EQUAL,
        )));
        {
            let mut e = eq_op.write().unwrap();
            e.inrefs = vec![xor_out.clone(), d];
        }
        // xor_out has a lone descend (eq_op).
        xor_out.write().unwrap().descend.push(Arc::downgrade(&eq_op));

        let rule = RuleXorCollapse::new();
        let result = rule.apply_op(&eq_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let e = eq_op.read().unwrap();
        // slot 1 should now be constant 0x3 ^ 0x1 = 2
        assert_eq!(e.inrefs[1].read().unwrap().get_val(), 2);
    }

    #[test]
    fn test_xor_collapse_var_xor_var_eq_zero() {
        // (V ^ W) == 0 → V == W  (move W to other side)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x12);
        let xor_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let xor_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_XOR,
        )));
        {
            let mut x = xor_op.write().unwrap();
            x.inrefs = vec![v.clone(), w.clone()];
            x.output = Some(xor_out.clone());
        }
        xor_out.write().unwrap().def = Some(Arc::downgrade(&xor_op));
        let zero = fd.vbank.create_constant(4, 0);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_EQUAL,
        )));
        {
            let mut e = eq_op.write().unwrap();
            e.inrefs = vec![xor_out.clone(), zero];
        }
        xor_out.write().unwrap().descend.push(Arc::downgrade(&eq_op));

        let rule = RuleXorCollapse::new();
        let result = rule.apply_op(&eq_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let e = eq_op.read().unwrap();
        // slot 0 should be V, slot 1 should be W
        assert!(Arc::ptr_eq(&e.inrefs[0], &v) || Arc::ptr_eq(&e.inrefs[0], &xor_op.read().unwrap().inrefs[0]));
    }

    // --- RuleAddMultCollapse (ruleaction.cc:4099) ---

    #[test]
    fn test_add_mult_collapse_double_add() {
        // ((V + 3) + 5)  =>  V + 8
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        // Mark V as an input (not free), as Ghidra would for a function input.
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c1 = fd.vbank.create_constant(4, 3);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner_add = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut a = inner_add.write().unwrap();
            a.inrefs = vec![v.clone(), c1];
            a.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner_add));
        let c0 = fd.vbank.create_constant(4, 5);
        let outer_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let outer_add = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut a = outer_add.write().unwrap();
            a.inrefs = vec![inner_out.clone(), c0];
            a.output = Some(outer_out);
        }

        let rule = RuleAddMultCollapse::new();
        let result = rule.apply_op(&outer_add, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let a = outer_add.read().unwrap();
        // slot 0 should now be V (sub2), slot 1 should be 3+5=8
        assert!(Arc::ptr_eq(&a.inrefs[0], &v));
        assert_eq!(a.inrefs[1].read().unwrap().get_val(), 8);
    }

    #[test]
    fn test_add_mult_collapse_double_mult() {
        // ((V * 2) * 3)  =>  V * 6
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c1 = fd.vbank.create_constant(4, 2);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner_mul = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_MULT,
        )));
        {
            let mut a = inner_mul.write().unwrap();
            a.inrefs = vec![v.clone(), c1];
            a.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner_mul));
        let c0 = fd.vbank.create_constant(4, 3);
        let outer_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let outer_mul = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_MULT,
        )));
        {
            let mut a = outer_mul.write().unwrap();
            a.inrefs = vec![inner_out, c0];
            a.output = Some(outer_out);
        }

        let rule = RuleAddMultCollapse::new();
        let result = rule.apply_op(&outer_mul, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let a = outer_mul.read().unwrap();
        assert!(Arc::ptr_eq(&a.inrefs[0], &v));
        assert_eq!(a.inrefs[1].read().unwrap().get_val(), 6);
    }

    // --- RuleLess2Zero (ruleaction.cc:5557) ---

    #[test]
    fn test_less2_zero_left_zero() {
        // 0 < V  =>  0 != V
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESS,
        )));
        op.write().unwrap().inrefs = vec![zero, v];
        let rule = RuleLess2Zero::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_INT_NOTEQUAL);
    }

    #[test]
    fn test_less2_zero_right_zero_false() {
        // V < 0  =>  false (COPY 0)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESS,
        )));
        op.write().unwrap().inrefs = vec![v, zero];
        let rule = RuleLess2Zero::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(op.read().unwrap().inrefs[0].read().unwrap().get_val(), 0);
    }

    // --- RuleLessEqual2Zero (ruleaction.cc:5605) ---

    #[test]
    fn test_lessequal2_zero_left_zero_true() {
        // 0 <= V  =>  true (COPY 1)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESSEQUAL,
        )));
        op.write().unwrap().inrefs = vec![zero, v];
        let rule = RuleLessEqual2Zero::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(op.read().unwrap().inrefs[0].read().unwrap().get_val(), 1);
    }

    #[test]
    fn test_lessequal2_zero_right_zero_equal() {
        // V <= 0  =>  V == 0
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESSEQUAL,
        )));
        op.write().unwrap().inrefs = vec![v, zero];
        let rule = RuleLessEqual2Zero::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_INT_EQUAL);
    }

    // --- RuleBoolNegate (ruleaction.cc:5516) ---

    #[test]
    fn test_bool_negate_double_negate() {
        // BOOL_NOT(BOOL_NOT(INT_EQUAL(V,W))) → INT_EQUAL(V,W) (the outer NOT
        // becomes COPY, the inner comparison stays). Actually the rule flips
        // the comparison and removes ALL descendant negates. For !!V:
        //   inner flip: INT_EQUAL → INT_NOTEQUAL, no reorder
        //   then the outer BOOL_NOT (the only descendant) → COPY
        // Result: INT_NOTEQUAL with a COPY wrapping. Let's test the !!V==W form:
        //   BOOL_NOT(BOOL_NOT(EQ)) where EQ's only consumer is BOOL_NOT.
        // flip EQ→NOTEQUAL, then the inner BOOL_NOT becomes COPY.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x12);
        let eq_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_EQUAL,
        )));
        {
            let mut e = eq_op.write().unwrap();
            e.inrefs = vec![v, w];
            e.output = Some(eq_out.clone());
        }
        eq_out.write().unwrap().def = Some(Arc::downgrade(&eq_op));
        // inner_not = BOOL_NOT(eq_out) → inner_out
        let inner_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x21);
        let inner_not = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_BOOL_NOT,
        )));
        {
            let mut n = inner_not.write().unwrap();
            n.inrefs = vec![eq_out.clone()];
            n.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner_not));
        // outer_not = BOOL_NOT(inner_out) — this is the op the rule fires on.
        let outer_not = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_BOOL_NOT,
        )));
        outer_not.write().unwrap().inrefs = vec![inner_out.clone()];
        // eq_out must have only BOOL_NOT descendants.
        eq_out.write().unwrap().descend.push(Arc::downgrade(&inner_not));
        // inner_out must have only BOOL_NOT descendants (the outer_not).
        inner_out.write().unwrap().descend.push(Arc::downgrade(&outer_not));

        let rule = RuleBoolNegate::new();
        let result = rule.apply_op(&outer_not, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // !!V==W: the inner BOOL_NOT (comparison's descendant) flips to COPY
        // (get_booleanflip(BOOL_NOT)=COPY), and the outer BOOL_NOT (the op the
        // rule fires on, which is inner_out's only descendant) also → COPY.
        // Net: !!V==W collapses to V==W.
        assert_eq!(inner_not.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(outer_not.read().unwrap().opcode, OpCode::CPUI_COPY);
        // The underlying comparison is untouched.
        assert_eq!(eq_op.read().unwrap().opcode, OpCode::CPUI_INT_EQUAL);
    }

    #[test]
    fn test_bool_negate_less_reorders() {
        // BOOL_NOT(INT_LESS(V,W)) where LESS's only consumer is this NOT.
        // flip LESS → LESSEQUAL, reorder=true (swap operands).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x12);
        let less_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let less_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESS,
        )));
        {
            let mut l = less_op.write().unwrap();
            l.inrefs = vec![v.clone(), w.clone()];
            l.output = Some(less_out.clone());
        }
        less_out.write().unwrap().def = Some(Arc::downgrade(&less_op));
        let not_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_BOOL_NOT,
        )));
        not_op.write().unwrap().inrefs = vec![less_out.clone()];
        less_out.write().unwrap().descend.push(Arc::downgrade(&not_op));

        let rule = RuleBoolNegate::new();
        let result = rule.apply_op(&not_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let l = less_op.read().unwrap();
        assert_eq!(l.opcode, OpCode::CPUI_INT_LESSEQUAL);
        // operands swapped: slot 0 now W, slot 1 now V
        assert!(Arc::ptr_eq(&l.inrefs[0], &w));
        assert!(Arc::ptr_eq(&l.inrefs[1], &v));
        // the NOT becomes COPY
        assert_eq!(not_op.read().unwrap().opcode, OpCode::CPUI_COPY);
    }

    #[test]
    fn test_bool_negate_non_bool_descendant_no_change() {
        // If the comparison output has a non-BOOL_NOT descendant → no change.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let eq_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_EQUAL,
        )));
        {
            let mut e = eq_op.write().unwrap();
            e.inrefs = vec![v, fd.vbank.create_constant(4, 0)];
            e.output = Some(eq_out.clone());
        }
        eq_out.write().unwrap().def = Some(Arc::downgrade(&eq_op));
        // A non-BOOL_NOT consumer (e.g. COPY) reads eq_out.
        let copy_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_COPY,
        )));
        copy_op.write().unwrap().inrefs = vec![eq_out.clone()];
        eq_out.write().unwrap().descend.push(Arc::downgrade(&copy_op));
        let not_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_BOOL_NOT,
        )));
        not_op.write().unwrap().inrefs = vec![eq_out.clone()];
        eq_out.write().unwrap().descend.push(Arc::downgrade(&not_op));

        let rule = RuleBoolNegate::new();
        let result = rule.apply_op(&not_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleOrMask (ruleaction.cc:276) ---

    #[test]
    fn test_or_mask_full_mask() {
        // V | 0xffffffff (size 4) => COPY(0xffffffff)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let full = fd.vbank.create_constant(4, 0xffffffff);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![v, full.clone()];
            o.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20));
        }
        let rule = RuleOrMask::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert_eq!(o.inrefs[0].read().unwrap().get_val(), 0xffffffff);
    }

    #[test]
    fn test_or_mask_partial_no_change() {
        // V | 0xf0 (not full mask) => no change
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let partial = fd.vbank.create_constant(4, 0xf0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![v, partial];
            o.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20));
        }
        let rule = RuleOrMask::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleAndOrLump (ruleaction.cc:403) ---

    #[test]
    fn test_and_or_lump_double_and() {
        // ((V & 0xf0) & 0x0f) => V & (0xf0 & 0x0f) = V & 0
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c1 = fd.vbank.create_constant(4, 0xf0);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut i = inner.write().unwrap();
            i.inrefs = vec![v.clone(), c1];
            i.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner));
        let c0 = fd.vbank.create_constant(4, 0x0f);
        let outer = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut o = outer.write().unwrap();
            o.inrefs = vec![inner_out, c0];
            o.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleAndOrLump::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = outer.read().unwrap();
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
        assert_eq!(o.inrefs[1].read().unwrap().get_val(), 0xf0 & 0x0f); // = 0
    }

    #[test]
    fn test_and_or_lump_double_or() {
        // ((V | 0x01) | 0x02) => V | 0x03
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c1 = fd.vbank.create_constant(4, 0x01);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut i = inner.write().unwrap();
            i.inrefs = vec![v.clone(), c1];
            i.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner));
        let c0 = fd.vbank.create_constant(4, 0x02);
        let outer = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut o = outer.write().unwrap();
            o.inrefs = vec![inner_out, c0];
            o.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleAndOrLump::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = outer.read().unwrap();
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
        assert_eq!(o.inrefs[1].read().unwrap().get_val(), 0x01 | 0x02); // = 3
    }

    // --- RulePiece2Zext (ruleaction.cc:207) ---

    #[test]
    fn test_piece2zext_zero_high() {
        // PIECE(0, V) => ZEXT(V)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let zero = fd.vbank.create_constant(2, 0);
        let v = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![zero, v.clone()];
            o.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20));
        }
        let rule = RulePiece2Zext::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_INT_ZEXT);
        assert_eq!(o.inrefs.len(), 1);
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
    }

    // --- RulePiece2Sext (ruleaction.cc:232) ---

    #[test]
    fn test_piece2sext_sign_shift() {
        // PIECE(V s>> (8*size-1), V) => SEXT(V). size=1 → shift by 7.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let shift_const = fd.vbank.create_constant(4, 7);
        let shift_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SRIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v.clone(), shift_const];
            s.output = Some(shift_out.clone());
        }
        shift_out.write().unwrap().def = Some(Arc::downgrade(&shift_op));
        let piece_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut p = piece_op.write().unwrap();
            p.inrefs = vec![shift_out, v.clone()];
            p.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RulePiece2Sext::new();
        let result = rule.apply_op(&piece_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let p = piece_op.read().unwrap();
        assert_eq!(p.opcode, OpCode::CPUI_INT_SEXT);
        assert_eq!(p.inrefs.len(), 1);
        assert!(Arc::ptr_eq(&p.inrefs[0], &v));
    }

    // --- RuleBxor2NotEqual (ruleaction.cc:261) ---

    #[test]
    fn test_bxor2notequal() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BOOL_XOR,
        )));
        op.write().unwrap().inrefs = vec![v, w];
        let rule = RuleBxor2NotEqual::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_INT_NOTEQUAL);
    }
}
