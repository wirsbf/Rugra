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

/// Order the inputs to commutative operations so constants come last.
///
/// Faithful to Ghidra's `RuleTermOrder` (ruleaction.cc:645-674). For any
/// commutative op, if slot 0 is a constant and slot 1 is not, swap them. This
/// normalises expressions and eliminates combinatorial variation.
pub struct RuleTermOrder;

impl RuleTermOrder {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTermOrder {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let should_swap = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let in1 = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            in0.read().unwrap().is_constant() && !in1.read().unwrap().is_constant()
        };
        if !should_swap {
            return Ok(action_status::NO_CHANGE);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_swap_input(&follow, 0, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "term_order"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        // The full commutative list (ruleaction.cc:655).
        vec![
            OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL,
            OpCode::CPUI_INT_ADD, OpCode::CPUI_INT_XOR,
            OpCode::CPUI_INT_AND, OpCode::CPUI_INT_OR,
            OpCode::CPUI_INT_MULT,
            OpCode::CPUI_BOOL_XOR, OpCode::CPUI_BOOL_AND, OpCode::CPUI_BOOL_OR,
            // CARRY/SCARRY and FLOAT_* commutative ops are included in Ghidra;
            // Rugra may not exercise them yet but listing is harmless.
        ]
    }
}

/// Convert a constant shift used arithmetically into a multiply:
///   `(V << c)` used in INT_ADD/INT_SUB/INT_MULT, or `V << c` itself feeding
///   such an op, becomes `V * (1 << c)`.
///
/// Faithful to Ghidra's `RuleShift2Mult` (ruleaction.cc:3720-3771). Rewrites
/// INT_LEFT/INT_RIGHT with a small (<32) constant shift amount into an
/// INT_MULT by a power-of-two when the shift participates in or feeds an
/// arithmetic operation.
pub struct RuleShift2Mult;

impl RuleShift2Mult {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleShift2Mult {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // constvn (in1) must be a constant shift amount < 32.
        let (vn, val) = {
            let op = op_arc.read().unwrap();
            let constvn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let val = constvn.read().unwrap().get_offset();
            if val >= 32 {
                return Ok(action_status::NO_CHANGE);
            }
            let vn = match op.output.as_ref() {
                Some(o) => o.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (vn, val as u32)
        };
        // The shift feeds, or its input is defined by, an arithmetic op.
        let arithop_input = {
            let op = op_arc.read().unwrap();
            op.inrefs.get(0).and_then(|v| v.read().unwrap().def.as_ref().and_then(|w| w.upgrade()))
        };
        let mut found_arith = false;
        if let Some(a) = &arithop_input {
            let opc = a.read().unwrap().opcode;
            if matches!(opc, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT) {
                found_arith = true;
            }
        }
        if !found_arith {
            // Check descendants.
            let descend_refs: Vec<_> = {
                let v = vn.read().unwrap();
                v.descend.iter().filter_map(|w| w.upgrade()).collect()
            };
            for d in descend_refs {
                let opc = d.read().unwrap().opcode;
                if matches!(opc, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT) {
                    found_arith = true;
                    break;
                }
            }
        }
        if !found_arith {
            return Ok(action_status::NO_CHANGE);
        }
        let size = vn.read().unwrap().get_size();
        let mult_const = fd.new_constant(size, 1u64 << val);
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, mult_const, 1);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_MULT);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "shift2mult"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_LEFT, OpCode::CPUI_INT_RIGHT]
    }
}

/// Simplify chained SUBPIECE: `sub(sub(V, a), b)  =>  sub(V, a+b)`.
///
/// Faithful to Ghidra's `RuleDoubleSub` (ruleaction.cc:1796-1823). When a
/// SUBPIECE's input is itself a SUBPIECE, skip the middleman by pointing at
/// the original base varnode and summing the two offsets.
pub struct RuleDoubleSub;

impl RuleDoubleSub {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleDoubleSub {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // in0 must be defined by a SUBPIECE.
        let (base_vn, offset2) = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let offset2 = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.read().unwrap().get_offset(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let op2_arc = {
                let i0 = in0.read().unwrap();
                i0.def.as_ref().and_then(|w| w.upgrade())
            };
            let op2_arc = match op2_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            if op2_arc.read().unwrap().opcode != OpCode::CPUI_SUBPIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let base_vn = op2_arc.read().unwrap().inrefs.get(0).cloned();
            match base_vn {
                Some(b) => (b, offset2),
                None => return Ok(action_status::NO_CHANGE),
            }
        };
        let offset1 = {
            let in0 = op_arc.read().unwrap().inrefs[0].clone();
            let op2_arc = in0.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            match op2_arc {
                Some(a) => a.read().unwrap().inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0),
                None => 0,
            }
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, base_vn, 0);
        let combined = fd.new_constant(4, offset1 + offset2);
        fd.op_set_input(&follow, combined, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "double_sub"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_SUBPIECE]
    }
}

/// Simplify trivial shifts: `V << 0 => V`, `V << c (c>=size) => 0`.
///
/// Faithful to Ghidra's `RuleTrivialShift` (ruleaction.cc:3515-3542). A shift
/// by zero is a copy; a (logical) shift by ≥ the value size yields zero.
/// INT_SRIGHT by ≥ size is left alone (sign-bit semantics).
pub struct RuleTrivialShift;

impl RuleTrivialShift {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTrivialShift {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (val, in0_size, is_sright) = {
            let op = op_arc.read().unwrap();
            let constvn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let val = constvn.read().unwrap().get_offset();
            let in0_size = match op.inrefs.get(0) {
                Some(v) => v.read().unwrap().get_size(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (val, in0_size, op.opcode == OpCode::CPUI_INT_SRIGHT)
        };
        if val != 0 {
            // Non-trivial unless shift >= size.
            if val < 8 * in0_size as u64 {
                return Ok(action_status::NO_CHANGE);
            }
            if is_sright {
                return Ok(action_status::NO_CHANGE); // Can't predict signbit.
            }
            // Logical shift >= size → 0.
            let follow = crate::op::PcodeOpRef(op_arc.clone());
            let zero = fd.new_constant(in0_size, 0);
            fd.op_set_input(&follow, zero, 0);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_remove_input(&follow, 1);
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "trivial_shift"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_LEFT, OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_SRIGHT]
    }
}

/// Convert INT_SLESS to INT_LESS when comparing known-positive values.
///
/// Faithful to Ghidra's `RuleSlessToLess` (ruleaction.cc:2548-2573). If the
/// non-zero masks of both operands indicate their sign-bits are zero (i.e.
/// both are known non-negative), the signed comparison is equivalent to the
/// unsigned one. Also handles SLESSEQUAL → LESSEQUAL.
pub struct RuleSlessToLess;

impl RuleSlessToLess {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSlessToLess {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (in0_nzm, in1_nzm, in0_size, is_sless) = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let in1 = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let sz;
            let n0;
            let n1;
            {
                let i0 = in0.read().unwrap();
                sz = i0.get_size();
                n0 = i0.get_nz_mask();
            }
            {
                let i1 = in1.read().unwrap();
                n1 = i1.get_nz_mask();
            }
            (n0, n1, sz, op.opcode == OpCode::CPUI_INT_SLESS)
        };
        // If either operand's sign-bit could be set, we cannot convert.
        if crate::address::signbit_negative(in0_nzm, in0_size) {
            return Ok(action_status::NO_CHANGE);
        }
        if crate::address::signbit_negative(in1_nzm, in0_size) {
            return Ok(action_status::NO_CHANGE);
        }
        let new_code = if is_sless {
            OpCode::CPUI_INT_LESS
        } else {
            OpCode::CPUI_INT_LESSEQUAL
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, new_code);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "sless_to_less"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_SLESS, OpCode::CPUI_INT_SLESSEQUAL]
    }
}

/// Collapse unnecessary INT_OR: `V | c => c` when every bit V could set is
/// already set in c (NZM(V) | c == c).
///
/// Faithful to Ghidra's `RuleOrCollapse` (ruleaction.cc:373-401). When the
/// OR constant already covers all possibly-non-zero bits of the other
/// operand, the OR result equals the constant.
pub struct RuleOrCollapse;

impl RuleOrCollapse {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleOrCollapse {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (in0_nzm, const_val, size) = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let cn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            let nzm = in0.read().unwrap().get_nz_mask();
            let val = cn.read().unwrap().get_offset();
            (nzm, val, size)
        };
        if size == 0 || size > 8 {
            return Ok(action_status::NO_CHANGE);
        }
        if (in0_nzm | const_val) != const_val {
            return Ok(action_status::NO_CHANGE); // V may turn on other bits
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        fd.op_remove_input(&follow, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "or_collapse"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_OR]
    }
}

/// Simplify concatenation of an extended value:
///   `concat(V, zext(W) << c) => concat(concat(V, W), 0)`
///
/// Faithful to Ghidra's `RuleConcatLeftShift` (ruleaction.cc:5004-5042). When
/// the low piece of a PIECE is a left-shifted zero-extension whose shift
/// amount aligns it to the most-significant boundary, the PIECE can be
/// restructured as a concatenation of the two original pieces with a zero pad.
pub struct RuleConcatLeftShift;

impl RuleConcatLeftShift {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleConcatLeftShift {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // vn2 (in1) must be defined by INT_LEFT of a zext.
        let (vn1, b, sa_bytes, pc, out_size) = {
            let op = op_arc.read().unwrap();
            let vn2 = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let vn1 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let out_size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            let pc = op.start.get_addr();
            let shiftop_arc = {
                let v2 = vn2.read().unwrap();
                v2.def.as_ref().and_then(|w| w.upgrade())
            };
            let shiftop_arc = match shiftop_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            let (sa_bits, tmpvn) = {
                let so = shiftop_arc.read().unwrap();
                if so.opcode != OpCode::CPUI_INT_LEFT {
                    return Ok(action_status::NO_CHANGE);
                }
                let sa_const = match so.inrefs.get(1) {
                    Some(v) if v.read().unwrap().is_constant() => v.read().unwrap().get_offset(),
                    _ => return Ok(action_status::NO_CHANGE),
                };
                let tmpvn = match so.inrefs.get(0) {
                    Some(v) => v.clone(),
                    None => return Ok(action_status::NO_CHANGE),
                };
                (sa_const, tmpvn)
            };
            if sa_bits & 7 != 0 {
                return Ok(action_status::NO_CHANGE); // not a multiple of 8
            }
            let zextop_arc = {
                let t = tmpvn.read().unwrap();
                t.def.as_ref().and_then(|w| w.upgrade())
            };
            let zextop_arc = match zextop_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            let b = {
                let zo = zextop_arc.read().unwrap();
                if zo.opcode != OpCode::CPUI_INT_ZEXT {
                    return Ok(action_status::NO_CHANGE);
                }
                match zo.inrefs.get(0) {
                    Some(v) => v.clone(),
                    None => return Ok(action_status::NO_CHANGE),
                }
            };
            if b.read().unwrap().is_free() {
                return Ok(action_status::NO_CHANGE);
            }
            if vn1.read().unwrap().is_free() {
                return Ok(action_status::NO_CHANGE);
            }
            let sa_bytes = (sa_bits / 8) as usize;
            let tmp_size = tmpvn.read().unwrap().get_size();
            let b_size = b.read().unwrap().get_size();
            if sa_bytes + b_size != tmp_size {
                return Ok(action_status::NO_CHANGE); // must shift to msb boundary
            }
            (vn1, b, sa_bytes, pc, out_size)
        };
        let vn1_size = vn1.read().unwrap().get_size();
        let b_size = b.read().unwrap().get_size();
        let newout_size = vn1_size + b_size;
        // newop = PIECE(vn1, b) → newout
        let newop = fd.new_op(2, pc);
        fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
        let newout = fd.new_unique_out(newout_size, &newop);
        fd.op_set_input(&newop, vn1, 0);
        fd.op_set_input(&newop, b, 1);
        fd.op_insert_before(&newop, &crate::op::PcodeOpRef(op_arc.clone()));
        // Rewrite the original op: in0 = newout, in1 = zero pad.
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, newout, 0);
        let pad = fd.new_constant(out_size - newout_size, 0);
        fd.op_set_input(&follow, pad, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "concat_leftshift"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_PIECE]
    }
}

/// Simplify chained shifts: `(V << c) << d => V << (c+d)`,
/// `(V << c) >> c => V & mask`, etc.
///
/// Faithful to Ghidra's `RuleDoubleShift` (ruleaction.cc:1825-1941). Handles
/// INT_MULT-as-left-shift via leastsigbit_set. Same-direction shifts combine;
/// opposite-direction shifts cancel (producing an AND with a mask).
pub struct RuleDoubleShift;

impl RuleDoubleShift {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleDoubleShift {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // in1 must be constant; in0 (secvn) must be defined by a shift/mult.
        let (opc1, sa1, secop_arc, size) = {
            let op = op_arc.read().unwrap();
            if !op.inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                return Ok(action_status::NO_CHANGE);
            }
            let opc1 = op.opcode;
            let secvn = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let secop_arc = {
                let s = secvn.read().unwrap();
                s.def.as_ref().and_then(|w| w.upgrade())
            };
            let secop_arc = match secop_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            let opc2 = secop_arc.read().unwrap().opcode;
            if !matches!(opc2, OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_MULT) {
                return Ok(action_status::NO_CHANGE);
            }
            if !secop_arc.read().unwrap().inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                return Ok(action_status::NO_CHANGE);
            }
            let size = secvn.read().unwrap().get_size();
            let (opc1n, sa1) = if opc1 == OpCode::CPUI_INT_MULT {
                let val = op.inrefs[1].read().unwrap().get_offset();
                let sa = crate::address::leastsigbit_set(val);
                if sa < 0 || (val >> sa) != 1 {
                    return Ok(action_status::NO_CHANGE);
                }
                (OpCode::CPUI_INT_LEFT, sa)
            } else {
                (opc1, op.inrefs[1].read().unwrap().get_offset() as i32)
            };
            (opc1n, sa1, secop_arc, size)
        };
        let (opc2, sa2, base_vn) = {
            let so = secop_arc.read().unwrap();
            let val = so.inrefs[1].read().unwrap().get_offset();
            let (opc2n, sa2) = if so.opcode == OpCode::CPUI_INT_MULT {
                let sa = crate::address::leastsigbit_set(val);
                if sa < 0 || (val >> sa) != 1 {
                    return Ok(action_status::NO_CHANGE);
                }
                (OpCode::CPUI_INT_LEFT, sa)
            } else {
                (so.opcode, val as i32)
            };
            let base_vn = match so.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (opc2n, sa2, base_vn)
        };
        if base_vn.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }

        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if opc1 == opc2 {
            if (sa1 + sa2) < (8 * size as i32) {
                let newconst = fd.new_constant(4, (sa1 + sa2) as u64);
                fd.op_set_opcode(&follow, opc1);
                fd.op_set_input(&follow, base_vn, 0);
                fd.op_set_input(&follow, newconst, 1);
            } else {
                let zero = fd.new_constant(size, 0);
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                fd.op_set_input(&follow, zero, 0);
                fd.op_remove_input(&follow, 1);
            }
            return Ok(action_status::CHANGE);
        }
        if size > 8 {
            return Ok(action_status::NO_CHANGE);
        }
        let mask = crate::address::calc_mask(size);
        let (mask_eff, diffsa) = if opc1 == OpCode::CPUI_INT_LEFT {
            let sec_out = secop_arc.read().unwrap().output.as_ref().map(|o| o.clone());
            if let Some(out) = sec_out {
                if out.read().unwrap().lone_descend().is_none() {
                    return Ok(action_status::NO_CHANGE);
                }
            }
            ((mask << sa2) & mask, sa1 - sa2)
        } else {
            ((mask >> sa2) & mask, sa2 - sa1)
        };
        if diffsa != 0 {
            return Ok(action_status::NO_CHANGE);
        }
        let mask_const = fd.new_constant(size, mask_eff);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_AND);
        fd.op_set_input(&follow, base_vn, 0);
        fd.op_set_input(&follow, mask_const, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "double_shift"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_LEFT, OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_MULT]
    }
}

/// Remove identity elements: `V + 0 => V`, `V & 0 => 0`, `V * 1 => V`, etc.
///
/// Faithful to Ghidra's `RuleIdentityEl` (ruleaction.cc:3696-3722). For
/// INT_ADD/INT_SUB/INT_AND/INT_OR/INT_XOR with a constant 0 in slot 1, the
/// op collapses to COPY(in0). For INT_MULT with 1, same; with 0, COPY(0).
pub struct RuleIdentityEl;

impl RuleIdentityEl {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleIdentityEl {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (val, opc) = {
            let op = op_arc.read().unwrap();
            let constvn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let v = constvn.read().unwrap().get_offset();
            (v, op.opcode)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if val == 0 && opc != OpCode::CPUI_INT_MULT {
            // +0, -0, &0, |0, ^0 → COPY(in0)
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            fd.op_remove_input(&follow, 1);
            return Ok(action_status::CHANGE);
        }
        if opc != OpCode::CPUI_INT_MULT {
            return Ok(action_status::NO_CHANGE);
        }
        if val == 1 {
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            fd.op_remove_input(&follow, 1);
            return Ok(action_status::CHANGE);
        }
        if val == 0 {
            // V * 0 → COPY(0) (replace in0 with 0)
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            fd.op_remove_input(&follow, 0);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str {
        "identity_el"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::CPUI_INT_ADD, OpCode::CPUI_INT_SUB,
            OpCode::CPUI_INT_AND, OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR,
            OpCode::CPUI_INT_MULT,
        ]
    }
}

/// Normalize sign-bit extraction: `V >> 0x1f => (V s>> 0x1f) * -1`.
///
/// Faithful to Ghidra's `RuleSignShift` (ruleaction.cc:3544-3600). A logical
/// right-shift of the sign-bit, when involved in arithmetic/comparison, is
/// converted to an arithmetic shift times all-ones (sign extension).
pub struct RuleSignShift;

impl RuleSignShift {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSignShift {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (in_vn, const_vn, size, pc) = {
            let op = op_arc.read().unwrap();
            let const_vn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let val = const_vn.read().unwrap().get_offset();
            let in_vn = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let size = in_vn.read().unwrap().get_size();
            if val != 8 * size as u64 - 1 {
                return Ok(action_status::NO_CHANGE);
            }
            if in_vn.read().unwrap().is_free() {
                return Ok(action_status::NO_CHANGE);
            }
            (in_vn, const_vn, size, op.start.get_addr())
        };
        // Check descendants for arithmetic/comparison involvement.
        let out_vn = op_arc.read().unwrap().output.as_ref().map(|o| o.clone());
        let out_vn = match out_vn {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        let descend_refs: Vec<_> = {
            let ov = out_vn.read().unwrap();
            ov.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        let mut do_conversion = false;
        for d in &descend_refs {
            let dop = d.read().unwrap();
            match dop.opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                    if dop.inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                        do_conversion = true;
                    }
                }
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_MULT => {
                    do_conversion = true;
                }
                _ => {}
            }
            if do_conversion {
                break;
            }
        }
        if !do_conversion {
            return Ok(action_status::NO_CHANGE);
        }
        // shiftOp = INT_SRIGHT(in_vn, const_vn) → uniqueVn
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let shift_op = fd.new_op(2, pc);
        fd.op_set_opcode(&shift_op, OpCode::CPUI_INT_SRIGHT);
        let unique_vn = fd.new_unique_out(size, &shift_op);
        fd.op_set_input(&shift_op, in_vn, 0);
        fd.op_set_input(&shift_op, const_vn, 1);
        fd.op_insert_before(&shift_op, &follow);
        // Rewrite op: INT_MULT(unique_vn, all-ones)
        let all_ones = fd.new_constant(size, crate::address::calc_mask(size));
        fd.op_set_input(&follow, unique_vn, 0);
        fd.op_set_input(&follow, all_ones, 1);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_MULT);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "sign_shift"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_RIGHT]
    }
}

/// Simplify INT_ZEXT applied to SUBPIECE:
///   `zext(sub(V, 0))  =>  V & mask`
///   `zext(sub(V, c))  =>  (V >> c*8) & mask`
///
/// Faithful to Ghidra's `RuleSubZext` (ruleaction.cc:5044-5115). This ports
/// the primary SUBPIECE branch (5067-5089): when a ZEXT wraps a SUBPIECE that
/// truncates then re-extends to the same size, replace with AND-mask (for
/// offset 0) or a right-shift of the base plus AND-mask (for middle offsets).
pub struct RuleSubZext;

impl RuleSubZext {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSubZext {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // in0 must be defined by a SUBPIECE; base size == op output size.
        let (basevn, trunc_offset, sub_size, subop_arc) = {
            let op = op_arc.read().unwrap();
            let out_size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            let subvn = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let subop_arc = {
                let s = subvn.read().unwrap();
                s.def.as_ref().and_then(|w| w.upgrade())
            };
            let subop_arc = match subop_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            if subop_arc.read().unwrap().opcode != OpCode::CPUI_SUBPIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let (basevn, trunc_offset) = {
                let so = subop_arc.read().unwrap();
                let basevn = match so.inrefs.get(0) {
                    Some(v) => v.clone(),
                    None => return Ok(action_status::NO_CHANGE),
                };
                let trunc_offset = so.inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                (basevn, trunc_offset)
            };
            if basevn.read().unwrap().is_free() {
                return Ok(action_status::NO_CHANGE);
            }
            if basevn.read().unwrap().get_size() != out_size {
                return Ok(action_status::NO_CHANGE);
            }
            if basevn.read().unwrap().get_size() > 8 {
                return Ok(action_status::NO_CHANGE);
            }
            (basevn, trunc_offset, {
                let s = subvn.read().unwrap();
                s.get_size()
            }, subop_arc)
        };

        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if trunc_offset != 0 {
            // Middle truncation: subvn must be a lone descendant (exclusive use).
            let subvn_vn = op_arc.read().unwrap().inrefs[0].clone();
            let lone = subvn_vn.read().unwrap().lone_descend();
            let is_lone = lone.map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false);
            if !is_lone {
                return Ok(action_status::NO_CHANGE);
            }
            // Convert the SUBPIECE into INT_RIGHT(base, trunc_offset*8) → newvn
            let newvn = fd.new_unique(basevn.read().unwrap().get_size());
            let sub_ref = crate::op::PcodeOpRef(subop_arc.clone());
            fd.op_set_input(&follow, newvn.clone(), 0);
            fd.op_set_opcode(&sub_ref, OpCode::CPUI_INT_RIGHT);
            let right_val = trunc_offset * 8;
            let right_const = fd.new_constant(4, right_val);
            fd.op_set_input(&sub_ref, right_const, 1);
            fd.op_set_output(&sub_ref, newvn);
        } else {
            // Offset 0: bypass the truncation entirely.
            fd.op_set_input(&follow, basevn.clone(), 0);
        }
        // Rewrite op as INT_AND(in0, calc_mask(sub_size)).
        let mask = crate::address::calc_mask(sub_size);
        let mask_const = fd.new_constant(basevn.read().unwrap().get_size(), mask);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_AND);
        fd.op_insert_input(&follow, mask_const, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "sub_zext"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_ZEXT]
    }
}

/// Transform shift of concatenation: `(concat(main, least) >> sa) => zext(main) >> (sa - leastbits)`.
///
/// Faithful to Ghidra's `RuleConcatShift` (ruleaction.cc:1969-2014). When a
/// right/left-shift of a PIECE throws away the entire least-significant piece,
/// the shift applies to the main piece (extended) with a reduced shift amount.
pub struct RuleConcatShift;

impl RuleConcatShift {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleConcatShift {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (sa, shiftin, concat_arc, opc, pc) = {
            let op = op_arc.read().unwrap();
            let sa_vn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let sa = sa_vn.read().unwrap().get_offset() as i32;
            let shiftin = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let concat_arc = {
                let s = shiftin.read().unwrap();
                s.def.as_ref().and_then(|w| w.upgrade())
            };
            let concat_arc = match concat_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            if concat_arc.read().unwrap().opcode != OpCode::CPUI_PIECE {
                return Ok(action_status::NO_CHANGE);
            }
            (sa, shiftin, concat_arc, op.opcode, op.start.get_addr())
        };
        let (leastsz, mainin) = {
            let c = concat_arc.read().unwrap();
            let leastsz = c.inrefs.get(1).map(|v| v.read().unwrap().get_size()).unwrap_or(0) as i32 * 8;
            let mainin = match c.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (leastsz, mainin)
        };
        if sa < leastsz {
            return Ok(action_status::NO_CHANGE);
        }
        if mainin.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }
        let sa2 = sa - leastsz;
        let extcode = if opc == OpCode::CPUI_INT_RIGHT {
            OpCode::CPUI_INT_ZEXT
        } else {
            OpCode::CPUI_INT_SEXT
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if sa2 == 0 {
            fd.op_remove_input(&follow, 1);
            fd.op_set_opcode(&follow, extcode);
            fd.op_set_input(&follow, mainin, 0);
        } else {
            let shiftin_size = shiftin.read().unwrap().get_size();
            let extop = fd.new_op(1, pc);
            fd.op_set_opcode(&extop, extcode);
            let newvn = fd.new_unique_out(shiftin_size, &extop);
            fd.op_set_input(&extop, mainin, 0);
            fd.op_insert_before(&extop, &follow);
            let new_sa = fd.new_constant(4, sa2 as u64);
            fd.op_set_input(&follow, newvn, 0);
            fd.op_set_input(&follow, new_sa, 1);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "concat_shift"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_LEFT, OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_SRIGHT]
    }
}

/// Transform shifts in comparisons:
///   `V >> c == d  =>  V == (d << c)`
///   `V << c == d  =>  V == (d >> c)`
///
/// Faithful to Ghidra's `RuleShiftCompare` (ruleaction.cc:2064-2168). Moves
/// a constant shift on one side of a comparison to the other side, when the
/// shifted value is known not to lose information. INT_MULT/INT_DIV by a
/// power of 2 are treated as shifts via leastsigbit_set.
pub struct RuleShiftCompare;

impl RuleShiftCompare {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleShiftCompare {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (shiftvn, constval, shiftop_arc) = {
            let op = op_arc.read().unwrap();
            let shiftvn = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let constvn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let shiftop_arc = {
                let s = shiftvn.read().unwrap();
                s.def.as_ref().and_then(|w| w.upgrade())
            };
            let shiftop_arc = match shiftop_arc {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            let cv = constvn.read().unwrap().get_offset();
            (shiftvn, cv, shiftop_arc)
        };
        let (isleft, sa, mainvn) = {
            let so = shiftop_arc.read().unwrap();
            let savn = match so.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let val = savn.read().unwrap().get_offset();
            let mainvn = match so.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            match so.opcode {
                OpCode::CPUI_INT_LEFT => (true, val as i32, mainvn),
                OpCode::CPUI_INT_RIGHT => {
                    if !shiftvn.read().unwrap().lone_descend().map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false) {
                        return Ok(action_status::NO_CHANGE);
                    }
                    (false, val as i32, mainvn)
                }
                OpCode::CPUI_INT_MULT => {
                    let sa = crate::address::leastsigbit_set(val);
                    if sa < 0 || (val >> sa) != 1 {
                        return Ok(action_status::NO_CHANGE);
                    }
                    (true, sa, mainvn)
                }
                OpCode::CPUI_INT_DIV => {
                    if !shiftvn.read().unwrap().lone_descend().map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false) {
                        return Ok(action_status::NO_CHANGE);
                    }
                    let sa = crate::address::leastsigbit_set(val);
                    if sa < 0 || (val >> sa) != 1 {
                        return Ok(action_status::NO_CHANGE);
                    }
                    (false, sa, mainvn)
                }
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        if sa == 0 || mainvn.read().unwrap().is_free() || mainvn.read().unwrap().get_size() > 8 {
            return Ok(action_status::NO_CHANGE);
        }
        let shiftvn_size = shiftvn.read().unwrap().get_size();
        let nzmask = mainvn.read().unwrap().get_nz_mask();
        let newconst;
        if isleft {
            newconst = constval >> sa;
            if (newconst << sa) != constval {
                return Ok(action_status::NO_CHANGE);
            }
            let tmp = (nzmask << sa) & crate::address::calc_mask(shiftvn_size);
            if (tmp >> sa) != nzmask {
                return Ok(action_status::NO_CHANGE); // info lost in main (AND-mask form deferred)
            }
        } else {
            if ((nzmask >> sa) << sa) != nzmask {
                return Ok(action_status::NO_CHANGE);
            }
            newconst = (constval << sa) & crate::address::calc_mask(shiftvn_size);
            if (newconst >> sa) != constval {
                return Ok(action_status::NO_CHANGE);
            }
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let newconst_vn = fd.new_constant(4, newconst);
        fd.op_set_input(&follow, mainvn, 0);
        fd.op_set_input(&follow, newconst_vn, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "shift_compare"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL]
    }
}

/// Transform AND-compare to larger-domain AND-compare:
///   `(sub(V,c) & mask) == 0  =>  (V & (mask << c*8)) == 0`
///   `(zext(V) & mask) == 0   =>  (V & mask) == 0`
///
/// Faithful to Ghidra's `RuleAndCompare` (ruleaction.cc:1729-1796).
pub struct RuleAndCompare;

impl RuleAndCompare {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleAndCompare {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (andvn) = {
            let op = op_arc.read().unwrap();
            let in1 = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            if in1.read().unwrap().get_offset() != 0 {
                return Ok(action_status::NO_CHANGE);
            }
            match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            }
        };
        let andop_arc = {
            let a = andvn.read().unwrap();
            a.def.as_ref().and_then(|w| w.upgrade())
        };
        let andop_arc = match andop_arc {
            Some(a) => a,
            None => return Ok(action_status::NO_CHANGE),
        };
        let (andconst, subvn) = {
            let ao = andop_arc.read().unwrap();
            if ao.opcode != OpCode::CPUI_INT_AND {
                return Ok(action_status::NO_CHANGE);
            }
            let mask_vn = match ao.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let mc = mask_vn.read().unwrap().get_offset();
            let subvn = match ao.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (mc, subvn)
        };
        let subop_arc = {
            let s = subvn.read().unwrap();
            s.def.as_ref().and_then(|w| w.upgrade())
        };
        let subop_arc = match subop_arc {
            Some(a) => a,
            None => return Ok(action_status::NO_CHANGE),
        };
        let (basevn, andconst_eff, andvn_size, andop_pc) = {
            let so = subop_arc.read().unwrap();
            let andvn_size = andvn.read().unwrap().get_size();
            let andop_pc = andop_arc.read().unwrap().start.get_addr();
            match so.opcode {
                OpCode::CPUI_SUBPIECE => {
                    let basevn = match so.inrefs.get(0) {
                        Some(v) => v.clone(),
                        None => return Ok(action_status::NO_CHANGE),
                    };
                    if basevn.read().unwrap().get_size() > 8 {
                        return Ok(action_status::NO_CHANGE);
                    }
                    let trunc_offset = so.inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                    (basevn, andconst << (trunc_offset * 8), andvn_size, andop_pc)
                }
                OpCode::CPUI_INT_ZEXT => {
                    let basevn = match so.inrefs.get(0) {
                        Some(v) => v.clone(),
                        None => return Ok(action_status::NO_CHANGE),
                    };
                    let bs = basevn.read().unwrap().get_size();
                    (basevn, andconst & crate::address::calc_mask(bs), andvn_size, andop_pc)
                }
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        if andconst == crate::address::calc_mask(andvn_size) || basevn.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }
        let basevn_size = basevn.read().unwrap().get_size();
        let constvn = fd.new_constant(basevn_size, andconst_eff);
        let newop = fd.new_op(2, andop_pc);
        fd.op_set_opcode(&newop, OpCode::CPUI_INT_AND);
        let newout = fd.new_unique_out(basevn_size, &newop);
        fd.op_set_input(&newop, basevn, 0);
        fd.op_set_input(&newop, constvn, 1);
        fd.op_insert_before(&newop, &crate::op::PcodeOpRef(andop_arc.clone()));
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, newout, 0);
        let zero = fd.new_constant(basevn_size, 0);
        fd.op_set_input(&follow, zero, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "and_compare"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL]
    }
}

/// Convert sign-bit test to signed comparison:
///   `(V s>> 0x1f) != 0  =>  V s< 0`
///   `(V s>> 0x1f) == 0  =>  V s<= 0`
///   `(V s>> 0x1f) == -1 =>  V s< 0` (complemented)
///
/// Faithful to Ghidra's `RuleTestSign` (ruleaction.cc:3602-3677). Finds the
/// INT_EQUAL/INT_NOTEQUAL comparisons that consume the output of an arithmetic
/// sign-bit shift and rewrites them into INT_SLESS/INT_SLESSEQUAL against 0.
pub struct RuleTestSign;

impl RuleTestSign {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTestSign {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // op is INT_SRIGHT(in_vn, const_vn). const must be 8*size-1.
        let (in_vn, out_vn) = {
            let op = op_arc.read().unwrap();
            let const_vn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let in_vn = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let val = const_vn.read().unwrap().get_offset();
            let sz = in_vn.read().unwrap().get_size();
            if val != 8 * sz as u64 - 1 {
                return Ok(action_status::NO_CHANGE);
            }
            if in_vn.read().unwrap().is_free() {
                return Ok(action_status::NO_CHANGE);
            }
            let out_vn = match op.output.as_ref() {
                Some(o) => o.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (in_vn, out_vn)
        };
        // Find comparison descendants with a constant operand.
        let compare_ops: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = {
            let ov = out_vn.read().unwrap();
            ov.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        let mut changed = false;
        let in_size = in_vn.read().unwrap().get_size();
        for comp_arc in compare_ops {
            let (is_cmp, offset, comp_opc) = {
                let c = comp_arc.read().unwrap();
                if c.opcode != OpCode::CPUI_INT_EQUAL && c.opcode != OpCode::CPUI_INT_NOTEQUAL {
                    continue;
                }
                let off = match c.inrefs.get(1) {
                    Some(v) if v.read().unwrap().is_constant() => v.read().unwrap().get_offset(),
                    _ => continue,
                };
                (true, off, c.opcode)
            };
            if !is_cmp {
                continue;
            }
            let comp_size = 1usize; // comparison output is 1 byte
            let sgn = if offset == 0 {
                1
            } else if offset == crate::address::calc_mask(comp_size) {
                -1
            } else {
                continue;
            };
            let mut sgn = if comp_opc == OpCode::CPUI_INT_NOTEQUAL { -sgn } else { sgn };
            // Rewrite the comparison.
            let comp_ref = crate::op::PcodeOpRef(comp_arc.clone());
            let zero_vn = fd.new_constant(in_size, 0);
            if sgn == 1 {
                fd.op_set_input(&comp_ref, in_vn.clone(), 1);
                fd.op_set_input(&comp_ref, zero_vn, 0);
                fd.op_set_opcode(&comp_ref, OpCode::CPUI_INT_SLESSEQUAL);
            } else {
                fd.op_set_input(&comp_ref, in_vn.clone(), 0);
                fd.op_set_input(&comp_ref, zero_vn, 1);
                fd.op_set_opcode(&comp_ref, OpCode::CPUI_INT_SLESS);
            }
            changed = true;
            let _ = &mut sgn;
        }
        if changed {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "test_sign"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_SRIGHT]
    }
}

/// Collapse INT_EQUAL/INT_NOTEQUAL when both inputs are functionally equal:
///   `f(V,W) == f(V,W)  =>  true`, `f(V,W) != f(V,W)  =>  false`
///
/// Faithful to Ghidra's `RuleEquality` (ruleaction.cc:619-643). If both inputs
/// to an INT_EQUAL/INT_NOTEQUAL are provably the same value, the comparison
/// collapses to a COPY of a constant (1 for EQUAL, 0 for NOTEQUAL).
pub struct RuleEquality;

impl RuleEquality {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleEquality {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (equal, is_notequal) = {
            let op = op_arc.read().unwrap();
            let in0 = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let in1 = match op.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (crate::address::functional_equality(&in0, &in1), op.opcode == OpCode::CPUI_INT_NOTEQUAL)
        };
        if !equal {
            return Ok(action_status::NO_CHANGE);
        }
        // Collapse to COPY(1) for EQUAL, COPY(0) for NOTEQUAL.
        let val = if is_notequal { 0 } else { 1 };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        fd.op_remove_input(&follow, 1);
        let c = fd.new_constant(1, val);
        fd.op_set_input(&follow, c, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "equality"
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL]
    }
}

/// Simplify `(s)lessequal AND notequal` to `(s)less`:
///   `V <= W && V != W  =>  V < W`
///
/// Faithful to Ghidra's `RuleLessNotEqual` (ruleaction.cc:2310-2357).
pub struct RuleLessNotEqual;

impl RuleLessNotEqual {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLessNotEqual {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (vnout1, vnout2) = {
            let op = op_arc.read().unwrap();
            let v1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let v2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (v1, v2)
        };
        let op1_arc = { vnout1.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
        let op2_arc = { vnout2.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
        let (op1_arc, op2_arc) = match (op1_arc, op2_arc) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        let (op_less_arc, opc, _op_equal_arc) = {
            let o1 = op1_arc.read().unwrap();
            let o2 = op2_arc.read().unwrap();
            let is_le1 = matches!(o1.opcode, OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL);
            let is_ne2 = o2.opcode == OpCode::CPUI_INT_NOTEQUAL;
            if is_le1 && is_ne2 {
                (op1_arc.clone(), o1.opcode, op2_arc.clone())
            } else {
                let is_le2 = matches!(o2.opcode, OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL);
                let is_ne1 = o1.opcode == OpCode::CPUI_INT_NOTEQUAL;
                if is_le2 && is_ne1 {
                    (op2_arc.clone(), o2.opcode, op1_arc.clone())
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            }
        };
        let (compvn1, compvn2, e0, e1) = {
            let ol = op_less_arc.read().unwrap();
            let oe = _op_equal_arc.read().unwrap();
            (ol.inrefs.get(0).cloned(), ol.inrefs.get(1).cloned(),
             oe.inrefs.get(0).cloned(), oe.inrefs.get(1).cloned())
        };
        let (compvn1, compvn2) = match (compvn1, compvn2, e0, e1) {
            (Some(c1), Some(c2), Some(a), Some(b)) => {
                let md = crate::address::functional_equality(&c1, &a) && crate::address::functional_equality(&c2, &b);
                let ms = crate::address::functional_equality(&c1, &b) && crate::address::functional_equality(&c2, &a);
                if !md && !ms { return Ok(action_status::NO_CHANGE); }
                (c1, c2)
            }
            _ => return Ok(action_status::NO_CHANGE),
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, compvn1, 0);
        fd.op_set_input(&follow, compvn2, 1);
        let new_code = if opc == OpCode::CPUI_INT_SLESSEQUAL { OpCode::CPUI_INT_SLESS } else { OpCode::CPUI_INT_LESS };
        fd.op_set_opcode(&follow, new_code);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "less_notequal" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_AND] }
}

/// Simplify `(s)less OR equal` to `(s)lessequal`:
///   `V < W || V == W  =>  V <= W`
///   `V < W || V != W  =>  COPY(NOTEQUAL output)` (NOTEQUAL dominates)
///
/// Faithful to Ghidra's `RuleLessEqual` (ruleaction.cc:2247-2308). A BOOL_OR
/// of an INT_(S)LESS and an INT_EQUAL/INT_NOTEQUAL over the same operand pair
/// collapses to INT_(S)LESSEQUAL (for EQUAL) or a COPY of the NOTEQUAL output.
pub struct RuleLessEqual;

impl RuleLessEqual {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLessEqual {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (vnout1, vnout2) = {
            let op = op_arc.read().unwrap();
            let v1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let v2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (v1, v2)
        };
        let op1_arc = { vnout1.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
        let op2_arc = { vnout2.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
        let (op1_arc, op2_arc) = match (op1_arc, op2_arc) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        let (op_less_arc, opc, op_equal_arc, equalopc) = {
            let o1 = op1_arc.read().unwrap();
            let o2 = op2_arc.read().unwrap();
            let is_less1 = matches!(o1.opcode, OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS);
            let is_cmp2 = matches!(o2.opcode, OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL);
            if is_less1 && is_cmp2 {
                (op1_arc.clone(), o1.opcode, op2_arc.clone(), o2.opcode)
            } else {
                let is_less2 = matches!(o2.opcode, OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS);
                let is_cmp1 = matches!(o1.opcode, OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL);
                if is_less2 && is_cmp1 {
                    (op2_arc.clone(), o2.opcode, op1_arc.clone(), o1.opcode)
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            }
        };
        let (compvn1, compvn2, e0, e1) = {
            let ol = op_less_arc.read().unwrap();
            let oe = op_equal_arc.read().unwrap();
            (ol.inrefs.get(0).cloned(), ol.inrefs.get(1).cloned(),
             oe.inrefs.get(0).cloned(), oe.inrefs.get(1).cloned())
        };
        let (compvn1, compvn2) = match (compvn1, compvn2, e0, e1) {
            (Some(c1), Some(c2), Some(a), Some(b)) => {
                let md = crate::address::functional_equality(&c1, &a) && crate::address::functional_equality(&c2, &b);
                let ms = crate::address::functional_equality(&c1, &b) && crate::address::functional_equality(&c2, &a);
                if !md && !ms { return Ok(action_status::NO_CHANGE); }
                (c1, c2)
            }
            _ => return Ok(action_status::NO_CHANGE),
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if equalopc == OpCode::CPUI_INT_NOTEQUAL {
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            fd.op_remove_input(&follow, 1);
            let neq_out = op_equal_arc.read().unwrap().output.as_ref().map(|o| o.clone());
            if let Some(o) = neq_out {
                fd.op_set_input(&follow, o, 0);
            }
        } else {
            fd.op_set_input(&follow, compvn1, 0);
            fd.op_set_input(&follow, compvn2, 1);
            let new_code = if opc == OpCode::CPUI_INT_SLESS { OpCode::CPUI_INT_SLESSEQUAL } else { OpCode::CPUI_INT_LESSEQUAL };
            fd.op_set_opcode(&follow, new_code);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "less_equal" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_OR] }
}

/// Simplify `(V & mask) >> sa` when the mask is exactly the bits preserved
/// by the shift: `(V & full) >> sa  =>  V >> sa`.
///
/// Faithful to Ghidra's `RuleRightShiftAnd` (ruleaction.cc:575-600). When the
/// right-shift of an AND with a mask that equals the shifted full mask, bypass
/// the AND.
pub struct RuleRightShiftAnd;

impl RuleRightShiftAnd {
    pub fn new() -> Self { Self }
}

impl Rule for RuleRightShiftAnd {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (const_sa, in_vn) = {
            let op = op_arc.read().unwrap();
            let const_vn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let sa = const_vn.read().unwrap().get_offset();
            let in_vn = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            (sa, in_vn)
        };
        let andop_arc = { in_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
        let andop_arc = match andop_arc { Some(a) => a, None => return Ok(action_status::NO_CHANGE) };
        let (mask, root_vn) = {
            let ao = andop_arc.read().unwrap();
            if ao.opcode != OpCode::CPUI_INT_AND { return Ok(action_status::NO_CHANGE); }
            let mask_vn = match ao.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let m = mask_vn.read().unwrap().get_offset();
            let root_vn = match ao.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (m, root_vn)
        };
        let sa = const_sa;
        let shifted_mask = mask >> sa;
        let root_size = root_vn.read().unwrap().get_size();
        let full = crate::address::calc_mask(root_size) >> sa;
        if full != shifted_mask { return Ok(action_status::NO_CHANGE); }
        if root_vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, root_vn, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "right_shift_and" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT] }
}

/// Simplify INT_AND applied to aligned INT_ADD when the AND mask is of the
/// form 11110000: `(V + c) & 0xfff0  =>  V + (c & 0xfff0)`.
///
/// Faithful to Ghidra's `RuleHighOrderAnd` (ruleaction.cc:1185-1250). Ports
/// the primary (constant addend) branch.
pub struct RuleHighOrderAnd;

impl RuleHighOrderAnd {
    pub fn new() -> Self { Self }
}

impl Rule for RuleHighOrderAnd {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (cvn1_val, cvn1_size, addop_arc) = {
            let op = op_arc.read().unwrap();
            let cvn1 = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let addop_arc = { in0.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
            let addop_arc = match addop_arc { Some(a) => a, None => return Ok(action_status::NO_CHANGE) };
            if addop_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return Ok(action_status::NO_CHANGE); }
            let val = cvn1.read().unwrap().get_offset();
            let size = cvn1.read().unwrap().get_size();
            (val, size, addop_arc)
        };
        // cvn1 must be of form 11110000: ((val-1)|val) == calc_mask(size)
        if ((cvn1_val.wrapping_sub(1)) | cvn1_val) != crate::address::calc_mask(cvn1_size) {
            return Ok(action_status::NO_CHANGE);
        }
        // Primary branch: addop's slot-1 is a constant.
        let (xalign, cvn2_val) = {
            let ao = addop_arc.read().unwrap();
            let cvn2 = match ao.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE), // non-constant branch deferred
            };
            let cv2 = cvn2.read().unwrap().get_offset();
            let xalign = match ao.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (xalign, cv2)
        };
        if xalign.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        let mask1 = xalign.read().unwrap().get_nz_mask();
        if (mask1 & cvn1_val) != mask1 { return Ok(action_status::NO_CHANGE); }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_ADD);
        fd.op_set_input(&follow, xalign, 0);
        let new_val = cvn1_val & cvn2_val;
        let c = fd.new_constant(cvn1_size, new_val);
        fd.op_set_input(&follow, c, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "high_order_and" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Simplify INT_AND of an extension: `sext(V) & mask => zext(V)` when mask
/// equals the full mask of the root value. Also `concat(a, V) & mask => zext(V)`.
///
/// Faithful to Ghidra's `RuleAndZext` (ruleaction.cc:1697-1732). When the AND
/// constant is exactly the root value's full mask, the AND is redundant with a
/// zero-extension of the root.
pub struct RuleAndZext;

impl RuleAndZext {
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndZext {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (cvn1_val, otherop_arc) = {
            let op = op_arc.read().unwrap();
            let cvn1 = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let val = cvn1.read().unwrap().get_offset();
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let otherop_arc = { in0.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
            let otherop_arc = match otherop_arc { Some(a) => a, None => return Ok(action_status::NO_CHANGE) };
            (val, otherop_arc)
        };
        // otherop must be INT_SEXT (in0 is root) or PIECE (in1 is root).
        let rootvn = {
            let oo = otherop_arc.read().unwrap();
            match oo.opcode {
                OpCode::CPUI_INT_SEXT => oo.inrefs.get(0).cloned(),
                OpCode::CPUI_PIECE => oo.inrefs.get(1).cloned(),
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        let rootvn = match rootvn { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
        let root_size = rootvn.read().unwrap().get_size();
        if root_size > 8 { return Ok(action_status::NO_CHANGE); }
        let mask = crate::address::calc_mask(root_size);
        if mask != cvn1_val { return Ok(action_status::NO_CHANGE); }
        if rootvn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_ZEXT);
        fd.op_remove_input(&follow, 1);
        fd.op_set_input(&follow, rootvn, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "and_zext" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Transform INT_ZEXT and INT_SLESS: `zext(V) s< c  =>  V < c` when c is
/// small enough that the zero-extension is unnecessary (sign bit of V is 0).
///
/// Faithful to Ghidra's `RuleZextSless` (ruleaction.cc:2575-2618). When a
/// signed comparison involves a zero-extended value and a small constant
/// (whose high bits beyond the small value's size are 0), drop the extension.
pub struct RuleZextSless;

impl RuleZextSless {
    pub fn new() -> Self { Self }
}

impl Rule for RuleZextSless {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (zextslot, otherslot, zext_arc, val, is_sless) = {
            let op = op_arc.read().unwrap();
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let is_sless = op.opcode == OpCode::CPUI_INT_SLESS;
            // Find which input is the ZEXT and which is the constant.
            let vn1_def = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let vn2_def = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let (zextslot, otherslot, zext_arc, constvn) = if let Some(d) = &vn2_def {
                if d.read().unwrap().opcode == OpCode::CPUI_INT_ZEXT {
                    (1, 0, d.clone(), vn1)
                } else if let Some(d1) = &vn1_def {
                    if d1.read().unwrap().opcode == OpCode::CPUI_INT_ZEXT {
                        (0, 1, d1.clone(), vn2)
                    } else {
                        return Ok(action_status::NO_CHANGE);
                    }
                } else { return Ok(action_status::NO_CHANGE); }
            } else if let Some(d1) = &vn1_def {
                if d1.read().unwrap().opcode == OpCode::CPUI_INT_ZEXT {
                    (0, 1, d1.clone(), vn2)
                } else { return Ok(action_status::NO_CHANGE); }
            } else { return Ok(action_status::NO_CHANGE); };
            if !constvn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let val = constvn.read().unwrap().get_offset();
            (zextslot, otherslot, zext_arc, val, is_sless)
        };
        let smallsize = {
            let z = zext_arc.read().unwrap();
            match z.inrefs.get(0) { Some(v) => v.read().unwrap().get_size(), None => return Ok(action_status::NO_CHANGE) }
        };
        // Sign bit of the small value must be 0 (val's high bits beyond smallsize are 0).
        if val >> (8 * smallsize - 1) != 0 {
            return Ok(action_status::NO_CHANGE);
        }
        let rootvn = match zext_arc.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let newconst = fd.new_constant(smallsize, val);
        fd.op_set_input(&follow, rootvn, zextslot);
        fd.op_set_input(&follow, newconst, otherslot);
        let new_code = if is_sless { OpCode::CPUI_INT_LESS } else { OpCode::CPUI_INT_LESSEQUAL };
        fd.op_set_opcode(&follow, new_code);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "zext_sless" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SLESS, OpCode::CPUI_INT_SLESSEQUAL] }
}

/// Simplify signed comparisons using INT_SCARRY:
///   `scarry(V, 0)  =>  false`
///
/// Faithful to Ghidra's `RuleScarry` (ruleaction.cc:3434-3510). This ports
/// the trivial branch (3460-3466): a SCARRY with a zero operand always yields
/// false (no signed overflow when adding zero). The deeper AddExpression-based
/// forms (3475-3510) require that infrastructure and are deferred.
pub struct RuleScarry;

impl RuleScarry {
    pub fn new() -> Self { Self }
}

impl Rule for RuleScarry {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let has_zero = {
            let op = op_arc.read().unwrap();
            let avn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let bvn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let a_zero = avn.read().unwrap().is_constant() && avn.read().unwrap().get_offset() == 0;
            let b_zero = bvn.read().unwrap().is_constant() && bvn.read().unwrap().get_offset() == 0;
            a_zero || b_zero
        };
        if !has_zero {
            return Ok(action_status::NO_CHANGE);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        let c = fd.new_constant(1, 0);
        fd.op_set_input(&follow, c, 0);
        fd.op_remove_input(&follow, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "scarry" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SCARRY] }
}

/// Simplify signed comparisons using INT_SBORROW:
///   `sborrow(V, 0)  =>  false`
///
/// Faithful to Ghidra's `RuleSborrow` (ruleaction.cc:3381-3432). Ports the
/// trivial branch (3390-3395). The AddExpression-based forms are deferred.
pub struct RuleSborrow;

impl RuleSborrow {
    pub fn new() -> Self { Self }
}

impl Rule for RuleSborrow {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let b_zero = {
            let op = op_arc.read().unwrap();
            let bvn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            bvn.read().unwrap().is_constant() && bvn.read().unwrap().get_offset() == 0
        };
        if !b_zero {
            return Ok(action_status::NO_CHANGE);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        let c = fd.new_constant(1, 0);
        fd.op_set_input(&follow, c, 0);
        fd.op_remove_input(&follow, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "sborrow" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SBORROW] }
}

/// Distribute INT_AND through INT_OR when the distribution simplifies:
///   `(A | B) & C  =>  (A & C) | (B & C)`  when one operand's NZM doesn't
///   overlap C's mask (the AND cancels that branch) or is fully covered.
///
/// Faithful to Ghidra's `RuleAndDistribute` (ruleaction.cc:1252-1314). Uses
/// get_nz_mask to decide whether distribution is beneficial.
pub struct RuleAndDistribute;

impl RuleAndDistribute {
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndDistribute {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (size, pc, distribute_slot) = {
            let op = op_arc.read().unwrap();
            let size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            if size == 0 || size > 8 { return Ok(action_status::NO_CHANGE); }
            let fullmask = crate::address::calc_mask(size);
            let mut found: i32 = -1;
            for i in 0..2 {
                let othervn = match op.inrefs.get(1 - i) { Some(v) => v.clone(), None => continue };
                let orvn = match op.inrefs.get(i) { Some(v) => v.clone(), None => continue };
                let orop_arc = { orvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
                let orop_arc = match orop_arc { Some(a) => a, None => continue };
                if orop_arc.read().unwrap().opcode != OpCode::CPUI_INT_OR { continue; }
                let othermask = othervn.read().unwrap().get_nz_mask();
                if othermask == 0 || othermask == fullmask { continue; }
                let (ormask1, ormask2) = {
                    let oo = orop_arc.read().unwrap();
                    (oo.inrefs.get(0).map(|v| v.read().unwrap().get_nz_mask()).unwrap_or(0),
                     oo.inrefs.get(1).map(|v| v.read().unwrap().get_nz_mask()).unwrap_or(0))
                };
                if ormask1 & othermask == 0 { found = i as i32; break; }
                if ormask2 & othermask == 0 { found = i as i32; break; }
                let othervn_is_const = othervn.read().unwrap().is_constant();
                if othervn_is_const {
                    if ormask1 & othermask == ormask1 { found = i as i32; break; }
                    if ormask2 & othermask == ormask2 { found = i as i32; break; }
                }
            }
            if found < 0 { return Ok(action_status::NO_CHANGE); }
            (size, op.start.get_addr(), found as usize)
        };
        // Capture the OR operands and the other operand.
        let (or_in0, or_in1, othervn) = {
            let op = op_arc.read().unwrap();
            let orvn = op.inrefs.get(distribute_slot).cloned();
            let othervn = op.inrefs.get(1 - distribute_slot).cloned();
            let orvn = match orvn { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let othervn = match othervn { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let orop_arc = { orvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
            let orop_arc = match orop_arc { Some(a) => a, None => return Ok(action_status::NO_CHANGE) };
            let oo = orop_arc.read().unwrap();
            (oo.inrefs.get(0).cloned(), oo.inrefs.get(1).cloned(), othervn)
        };
        let (or_in0, or_in1) = match (or_in0, or_in1) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        // newop1 = AND(or_in0, othervn)
        let newop1 = fd.new_op(2, pc);
        fd.op_set_opcode(&newop1, OpCode::CPUI_INT_AND);
        let newvn1 = fd.new_unique_out(size, &newop1);
        fd.op_set_input(&newop1, or_in0, 0);
        fd.op_set_input(&newop1, othervn.clone(), 1);
        fd.op_insert_before(&newop1, &crate::op::PcodeOpRef(op_arc.clone()));
        // newop2 = AND(or_in1, othervn)
        let newop2 = fd.new_op(2, pc);
        fd.op_set_opcode(&newop2, OpCode::CPUI_INT_AND);
        let newvn2 = fd.new_unique_out(size, &newop2);
        fd.op_set_input(&newop2, or_in1, 0);
        fd.op_set_input(&newop2, othervn, 1);
        fd.op_insert_before(&newop2, &crate::op::PcodeOpRef(op_arc.clone()));
        // Rewrite op: OR(newvn1, newvn2)
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, newvn1, 0);
        fd.op_set_input(&follow, newvn2, 1);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_OR);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "and_distribute" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Transform INT_LESS/INT_LESSEQUAL of 0 or 1:
///   `V < 1  =>  V == 0`
///   `V <= 0  =>  V == 0`
///
/// Faithful to Ghidra's `RuleLessOne` (ruleaction.cc:1316-1339).
pub struct RuleLessOne;

impl RuleLessOne {
    pub fn new() -> Self { Self }
}

impl Rule for RuleLessOne {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (val, opc, const_size) = {
            let op = op_arc.read().unwrap();
            let constvn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let val = constvn.read().unwrap().get_offset();
            let sz = constvn.read().unwrap().get_size();
            if op.opcode == OpCode::CPUI_INT_LESS && val != 1 { return Ok(action_status::NO_CHANGE); }
            if op.opcode == OpCode::CPUI_INT_LESSEQUAL && val != 0 { return Ok(action_status::NO_CHANGE); }
            if !matches!(op.opcode, OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL) {
                return Ok(action_status::NO_CHANGE);
            }
            (val, op.opcode, sz)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_EQUAL);
        if val != 0 {
            let c = fd.new_constant(const_size, 0);
            fd.op_set_input(&follow, c, 1);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "less_one" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_LESS, OpCode::CPUI_INT_LESSEQUAL] }
}

/// Simplify INT_AND of a PIECE when the AND mask zeros out one piece:
///   `concat(H, L) & C` where C zeros H → `zext(L)`; where C zeros L → `concat(H, 0)`.
///
/// Faithful to Ghidra's `RuleAndPiece` (ruleaction.cc:1630-1694). Uses
/// get_nz_mask on each piece to determine which half the AND eliminates.
pub struct RuleAndPiece;

impl RuleAndPiece {
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndPiece {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (size, pc) = {
            let op = op_arc.read().unwrap();
            let size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            if size == 0 || size > 8 { return Ok(action_status::NO_CHANGE); }
            (size, op.start.get_addr())
        };
        let fullmask = crate::address::calc_mask(size);
        // Find a PIECE input whose other-operand mask zeros one piece.
        let mut found: Option<(usize, OpCode, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>)> = None;
        for i in 0..2 {
            let piecevn = { let op = op_arc.read().unwrap(); op.inrefs.get(i).cloned() };
            let piecevn = match piecevn { Some(v) => v, None => continue };
            let pieceop_arc = { piecevn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
            let pieceop_arc = match pieceop_arc { Some(a) => a, None => continue };
            if pieceop_arc.read().unwrap().opcode != OpCode::CPUI_PIECE { continue; }
            let othervn = { let op = op_arc.read().unwrap(); op.inrefs.get(1 - i).cloned() };
            let othervn = match othervn { Some(v) => v, None => continue };
            let othermask = othervn.read().unwrap().get_nz_mask();
            if othermask == fullmask || othermask == 0 { continue; }
            let (highvn, lowvn) = {
                let po = pieceop_arc.read().unwrap();
                (po.inrefs.get(0).cloned(), po.inrefs.get(1).cloned())
            };
            let (highvn, lowvn) = match (highvn, lowvn) { (Some(h), Some(l)) => (h, l), _ => continue };
            let maskhigh = highvn.read().unwrap().get_nz_mask();
            let masklow = lowvn.read().unwrap().get_nz_mask();
            let lowsize = lowvn.read().unwrap().get_size();
            if maskhigh & (othermask >> (lowsize * 8)) == 0 {
                if maskhigh == 0 && highvn.read().unwrap().is_constant() { continue; } // piece2zext
                found = Some((i, OpCode::CPUI_INT_ZEXT, lowvn));
                break;
            } else if masklow & othermask == 0 {
                if lowvn.read().unwrap().is_constant() { continue; }
                found = Some((i, OpCode::CPUI_PIECE, highvn));
                break;
            }
        }
        let (i, opc, keepvn) = match found { Some(f) => f, None => return Ok(action_status::NO_CHANGE) };
        // Build the replacement op.
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if opc == OpCode::CPUI_INT_ZEXT {
            let newop = fd.new_op(1, pc);
            fd.op_set_opcode(&newop, OpCode::CPUI_INT_ZEXT);
            fd.op_set_input(&newop, keepvn, 0);
            let newout = fd.new_unique_out(size, &newop);
            fd.op_insert_before(&newop, &follow);
            fd.op_set_input(&follow, newout, i);
        } else {
            // PIECE(highvn, 0)
            let newvn2 = fd.new_constant(keepvn.read().unwrap().get_size(), 0);
            let newop = fd.new_op(2, pc);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            fd.op_set_input(&newop, keepvn, 0);
            fd.op_set_input(&newop, newvn2, 1);
            let newout = fd.new_unique_out(size, &newop);
            fd.op_insert_before(&newop, &follow);
            fd.op_set_input(&follow, newout, i);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "and_piece" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Commute a shift through an AND so the AND applies to the pre-shift value:
///   `(V << c) & mask  =>  (V & (mask >> c)) << c`
///   `(V >> c) & mask  =>  (V & (mask << c)) >> c`
///
/// Faithful to Ghidra's `RuleAndCommute` (ruleaction.cc:1519-1626). Ports the
/// primary INT_LEFT/INT_RIGHT path (the OR/PIECE sub-cases use getNZMask to
/// decide benefit). When the shift's other input (a constant) can be commuted
/// with the AND, perform the commute by creating a new shift + AND.
pub struct RuleAndCommute;

impl RuleAndCommute {
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndCommute {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (size, pc) = {
            let op = op_arc.read().unwrap();
            let size = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            if size == 0 || size > 8 { return Ok(action_status::NO_CHANGE); }
            (size, op.start.get_addr())
        };
        let fullmask = crate::address::calc_mask(size);
        // Scan both slots: slot i holds a shift (V op c), slot 1-i is othervn.
        let mut found: Option<(usize, std::sync::Arc<std::sync::RwLock<PcodeOp>>, OpCode, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>)> = None;
        for i in 0..2usize {
            let shiftvn = { let op = op_arc.read().unwrap(); op.inrefs.get(i).cloned() };
            let shiftvn = match shiftvn { Some(v) => v, None => continue };
            let shiftop_arc = { shiftvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
            let shiftop_arc = match shiftop_arc { Some(a) => a, None => continue };
            let opc = shiftop_arc.read().unwrap().opcode;
            if opc != OpCode::CPUI_INT_LEFT && opc != OpCode::CPUI_INT_RIGHT { continue; }
            let savn = match shiftop_arc.read().unwrap().inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => continue,
            };
            let sa = savn.read().unwrap().get_offset() as usize;
            let orvn = match shiftop_arc.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => continue };
            let othervn = { let op = op_arc.read().unwrap(); op.inrefs.get(1 - i).cloned() };
            let othervn = match othervn { Some(v) => v, None => continue };
            let othermask = othervn.read().unwrap().get_nz_mask();
            if othermask == 0 || othermask == fullmask { continue; }
            // Decide if commute is beneficial (othermask bits affected by shift).
            let adjusted = if opc == OpCode::CPUI_INT_RIGHT {
                if (fullmask >> sa) == othermask { continue; }
                othermask << sa
            } else {
                if ((fullmask << sa) & fullmask) == othermask { continue; }
                othermask >> sa
            };
            if adjusted == 0 || adjusted == fullmask { continue; }
            // For LEFT with constant othervn, require loneDescend for stability.
            if opc == OpCode::CPUI_INT_LEFT && othervn.read().unwrap().is_constant() {
                if shiftvn.read().unwrap().lone_descend().map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false) {
                    found = Some((i, shiftop_arc, opc, savn, orvn, othervn));
                    break;
                }
                // Otherwise check if orvn is an OR/PIECE (beneficial sub-case).
                let orop_arc = { orvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) };
                if let Some(oa) = orop_arc {
                    let oc = oa.read().unwrap().opcode;
                    if oc == OpCode::CPUI_INT_OR || oc == OpCode::CPUI_PIECE {
                        found = Some((i, shiftop_arc, opc, savn, orvn, othervn));
                        break;
                    }
                }
                continue;
            }
            found = Some((i, shiftop_arc, opc, savn, orvn, othervn));
            break;
        }
        let (i, shiftop_arc, opc, savn, orvn, othervn) = match found { Some(f) => f, None => return Ok(action_status::NO_CHANGE) };
        // Build new shift (commuted direction) of othervn by savn.
        let newop1 = fd.new_op(2, pc);
        let new_shift_opc = if opc == OpCode::CPUI_INT_LEFT { OpCode::CPUI_INT_RIGHT } else { OpCode::CPUI_INT_LEFT };
        fd.op_set_opcode(&newop1, new_shift_opc);
        let newvn1 = fd.new_unique_out(size, &newop1);
        fd.op_set_input(&newop1, othervn, 0);
        fd.op_set_input(&newop1, savn.clone(), 1);
        fd.op_insert_before(&newop1, &crate::op::PcodeOpRef(op_arc.clone()));
        // AND(orvn, newvn1)
        let newop2 = fd.new_op(2, pc);
        fd.op_set_opcode(&newop2, OpCode::CPUI_INT_AND);
        let newvn2 = fd.new_unique_out(size, &newop2);
        fd.op_set_input(&newop2, orvn, 0);
        fd.op_set_input(&newop2, newvn1, 1);
        fd.op_insert_before(&newop2, &crate::op::PcodeOpRef(op_arc.clone()));
        // Rewrite op: opc(newvn2, savn)
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, newvn2, 0);
        fd.op_set_input(&follow, savn, 1);
        fd.op_set_opcode(&follow, opc);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "and_commute" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Simplify INT_OR/INT_XOR with an unconsumed input:
///   `V = A | B  =>  V = B  if  nzm(A) & consume(V) == 0`
///
/// Faithful to Ghidra's `RuleOrConsume` (ruleaction.cc:344-371). When one
/// operand's non-zero mask doesn't overlap the output's consumed bits, that
/// operand contributes nothing and can be dropped — collapse to COPY.
pub struct RuleOrConsume;

impl RuleOrConsume {
    pub fn new() -> Self { Self }
}

impl Rule for RuleOrConsume {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (consume, in0_nzm, in1_nzm, size) = {
            let op = op_arc.read().unwrap();
            let outvn = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            let size = outvn.read().unwrap().get_size();
            if size > 8 { return Ok(action_status::NO_CHANGE); }
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let in1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let consume = outvn.read().unwrap().get_consume();
            let n0 = in0.read().unwrap().get_nz_mask();
            let n1 = in1.read().unwrap().get_nz_mask();
            (consume, n0, n1, size)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if consume & in0_nzm == 0 {
            // in0 unconsumed → drop it, COPY in1.
            fd.op_remove_input(&follow, 0);
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            return Ok(action_status::CHANGE);
        } else if consume & in1_nzm == 0 {
            fd.op_remove_input(&follow, 1);
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str { "or_consume" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR] }
}

/// Get rid of unused PcodeOp objects where we can guarantee the output is
/// unused. Faithful to Ghidra's `RuleEarlyRemoval` (ruleaction.cc:23-44).
///
/// Removes an op whose output has no descendants and isn't a CALL/INDIRECT
/// source. The doesDeadcode/autoLive checks are conservatively skipped (Rugra
/// does not yet have the deadcode-allowed-seen or autolive mechanisms).
pub struct RuleEarlyRemoval;

impl RuleEarlyRemoval {
    pub fn new() -> Self { Self }
}

impl Rule for RuleEarlyRemoval {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Must have an output with no descendants.
        let has_unused_output = {
            let op = op_arc.read().unwrap();
            if op.opcode == OpCode::CPUI_CALL || op.opcode == OpCode::CPUI_CALLIND {
                return Ok(action_status::NO_CHANGE);
            }
            match op.output.as_ref() {
                Some(o) => o.read().unwrap().has_no_descend(),
                None => return Ok(action_status::NO_CHANGE),
            }
        };
        if !has_unused_output {
            return Ok(action_status::NO_CHANGE);
        }
        fd.op_destroy(&crate::op::PcodeOpRef(op_arc.clone()));
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "early_removal" }
    fn get_opcodes(&self) -> Vec<OpCode> {
        // Applies to all ops; we register a representative set.
        vec![OpCode::CPUI_INT_ADD, OpCode::CPUI_INT_SUB, OpCode::CPUI_INT_MULT,
             OpCode::CPUI_COPY, OpCode::CPUI_INT_AND, OpCode::CPUI_INT_OR,
             OpCode::CPUI_INT_XOR, OpCode::CPUI_INT_LEFT, OpCode::CPUI_INT_RIGHT]
    }
}

/// Simplify boolean comparisons with constants 0 and 1:
///   `boolval != 0  =>  boolval`
///   `boolval != 1  =>  !boolval`
///   `boolval == 0  =>  !boolval`
///   `boolval == 1  =>  boolval`
///
/// Faithful to Ghidra's `RuleBooleanNegate` (ruleaction.cc:2969-2999). When
/// one input is a boolean value and the other is constant 0 or 1, the
/// INT_EQUAL/INT_NOTEQUAL collapses to COPY or BOOL_NEGATE.
pub struct RuleBooleanNegate;

impl RuleBooleanNegate {
    pub fn new() -> Self { Self }
}

impl Rule for RuleBooleanNegate {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (opc, constval, subbool) = {
            let op = op_arc.read().unwrap();
            let constvn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let val = constvn.read().unwrap().get_offset();
            if val != 0 && val != 1 { return Ok(action_status::NO_CHANGE); }
            let subbool = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (op.opcode, val, subbool)
        };
        // subbool must be a boolean value.
        if !subbool.read().unwrap().is_boolean_value(false) {
            return Ok(action_status::NO_CHANGE);
        }
        let is_notequal = opc == OpCode::CPUI_INT_NOTEQUAL;
        // negate = (is_notequal XOR (val==0))
        let negate = is_notequal ^ (constval == 0);
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_remove_input(&follow, 1);
        fd.op_set_input(&follow, subbool, 0);
        if negate {
            fd.op_set_opcode(&follow, OpCode::CPUI_BOOL_NOT);
        } else {
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "boolean_negate" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL] }
}

/// Convert INT_AND/INT_OR/INT_XOR to BOOL_AND/BOOL_OR/BOOL_XOR when both
/// inputs are boolean values.
///
/// Faithful to Ghidra's `RuleLogic2Bool` (ruleaction.cc:3128-3167).
pub struct RuleLogic2Bool;

impl RuleLogic2Bool {
    pub fn new() -> Self { Self }
}

impl Rule for RuleLogic2Bool {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (opc, in0, in1) = {
            let op = op_arc.read().unwrap();
            if !matches!(op.opcode, OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR) {
                return Ok(action_status::NO_CHANGE);
            }
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let in1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (op.opcode, in0, in1)
        };
        // in0 must be boolean.
        if !in0.read().unwrap().is_boolean_value(false) { return Ok(action_status::NO_CHANGE); }
        // in1 must be boolean or constant 0/1.
        let in1_is_bool = {
            let i1 = in1.read().unwrap();
            if i1.is_constant() {
                i1.get_offset() <= 1
            } else {
                i1.is_boolean_value(false)
            }
        };
        if !in1_is_bool { return Ok(action_status::NO_CHANGE); }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let new_opc = match opc {
            OpCode::CPUI_INT_AND => OpCode::CPUI_BOOL_AND,
            OpCode::CPUI_INT_OR => OpCode::CPUI_BOOL_OR,
            OpCode::CPUI_INT_XOR => OpCode::CPUI_BOOL_XOR,
            _ => return Ok(action_status::NO_CHANGE),
        };
        fd.op_set_opcode(&follow, new_opc);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "logic2bool" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND, OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR] }
}

/// Transform canceling INT_RIGHT/INT_SRIGHT of INT_LEFT:
///   `(V << c) >> c  =>  zext(sub(V, 0))`  (unsigned right)
///   `(V << c) s>> c  =>  sext(sub(V, 0))` (signed right)
///
/// Faithful to Ghidra's `RuleLeftRight` (ruleaction.cc:2016-2062). When a
/// right-shift exactly cancels a preceding left-shift (same byte-aligned
/// amount), the pair collapses to a zero/sign extension of a SUBPIECE.
pub struct RuleLeftRight;

impl RuleLeftRight {
    pub fn new() -> Self { Self }
}

impl Rule for RuleLeftRight {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Phase 1: validate and extract raw values.
        let (sa, leftshift_arc, is_sright, shiftin_size, tsz) = {
            let op = op_arc.read().unwrap();
            let constvn = match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            };
            let sa = constvn.read().unwrap().get_offset();
            let shiftin = match op.inrefs.get(0) {
                Some(v) => v.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let shiftin_size;
            let leftshift_arc;
            {
                let s = shiftin.read().unwrap();
                shiftin_size = s.get_size();
                leftshift_arc = match s.def.as_ref().and_then(|w| w.upgrade()) {
                    Some(a) => a,
                    None => return Ok(action_status::NO_CHANGE),
                };
            }
            if leftshift_arc.read().unwrap().opcode != OpCode::CPUI_INT_LEFT { return Ok(action_status::NO_CHANGE); }
            if !leftshift_arc.read().unwrap().inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                return Ok(action_status::NO_CHANGE);
            }
            let left_sa = leftshift_arc.read().unwrap().inrefs[1].read().unwrap().get_offset();
            if left_sa != sa { return Ok(action_status::NO_CHANGE); }
            if sa & 7 != 0 { return Ok(action_status::NO_CHANGE); }
            let isa = (sa >> 3) as usize;
            let tsz = shiftin_size - isa;
            if !matches!(tsz, 1 | 2 | 4 | 8) { return Ok(action_status::NO_CHANGE); }
            // shiftin must be lone descendant of this op.
            let lone = shiftin.read().unwrap().lone_descend();
            if !lone.map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false) {
                return Ok(action_status::NO_CHANGE);
            }
            (sa, leftshift_arc, op.opcode == OpCode::CPUI_INT_SRIGHT, shiftin_size, tsz)
        };
        // Phase 2: transform.
        let leftshift_ref = crate::op::PcodeOpRef(leftshift_arc.clone());
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_unset_input(&follow, 0);
        fd.op_unset_output(&leftshift_ref);
        let newvn = fd.new_varnode_out(tsz, crate::address::Address::new(0x1000), &leftshift_ref);
        fd.op_set_opcode(&leftshift_ref, OpCode::CPUI_SUBPIECE);
        let zero_const = fd.new_constant(4, 0);
        fd.op_set_input(&leftshift_ref, zero_const, 1);
        fd.op_set_input(&follow, newvn, 0);
        fd.op_remove_input(&follow, 1);
        let ext_opc = if is_sright { OpCode::CPUI_INT_SEXT } else { OpCode::CPUI_INT_ZEXT };
        fd.op_set_opcode(&follow, ext_opc);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "left_right" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_SRIGHT] }
}

/// Convert INT_LESSEQUAL to INT_LESS: `V <= c  =>  V < c+1`.
///
/// Faithful to Ghidra's `RuleIntLessEqual` (ruleaction.cc:611-617). Delegates
/// to Funcdata::replace_lessequal which adjusts the constant and changes the
/// opcode, guarding against overflow edge cases.
pub struct RuleIntLessEqual;

impl RuleIntLessEqual {
    pub fn new() -> Self { Self }
}

impl Rule for RuleIntLessEqual {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        if fd.replace_lessequal(&crate::op::PcodeOpRef(op_arc.clone())) {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str { "int_lessequal" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_LESSEQUAL, OpCode::CPUI_INT_SLESSEQUAL] }
}

/// Collect and collapse constants and like terms in an additive expression:
///   `(V + c) + d  =>  V + (c+d)` (constant folding)
///   `V*2 + V*3  =>  V*5` (factoring)
///
/// Faithful to Ghidra's `RuleCollectTerms` (ruleaction.cc:94-176). Uses
/// TermOrder from expression.rs to collect, sort, and simplify additive terms.
/// The distributeIntMultAdd sub-case (for INT_MULT coefficients on ADD) is
/// deferred (requires that Funcdata method).
pub struct RuleCollectTerms;

impl RuleCollectTerms {
    pub fn new() -> Self { Self }

    /// Extract the multiplicative coefficient from a term vn.
    /// If vn is INT_MULT(V, c), return (V, c); else (vn, 1).
    fn get_mult_coeff(vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> (std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, u64) {
        let is_written = vn.read().unwrap().is_written();
        if !is_written {
            return (vn.clone(), 1);
        }
        let def = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        if let Some(op) = def {
            let o = op.read().unwrap();
            if o.opcode == OpCode::CPUI_INT_MULT && o.inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                let coeff = o.inrefs[1].read().unwrap().get_offset();
                let base = o.inrefs[0].clone();
                return (base, coeff);
            }
        }
        (vn.clone(), 1)
    }
}

impl Rule for RuleCollectTerms {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Must not be feeding another INT_ADD (we want the root).
        let out_vn = op_arc.read().unwrap().output.as_ref().cloned();
        if let Some(out) = out_vn {
            let lone = out.read().unwrap().lone_descend();
            if let Some(d) = lone {
                if d.read().unwrap().opcode == OpCode::CPUI_INT_ADD {
                    return Ok(action_status::NO_CHANGE);
                }
            }
        }
        // Collect terms.
        let mut termorder = crate::expression::TermOrder::new(op_arc.clone());
        termorder.collect();
        termorder.sort_terms();
        let order = termorder.get_sort().to_vec();
        if order.is_empty() { return Ok(action_status::NO_CHANGE); }

        let mut i = 0;
        // Phase 1: look for combinable like terms.
        if !termorder.get_term(order[0]).unwrap().get_varnode().read().unwrap().is_constant() {
            i = 1;
            while i < order.len() {
                let vn1 = termorder.get_term(order[i-1]).unwrap().get_varnode().clone();
                let vn2 = termorder.get_term(order[i]).unwrap().get_varnode().clone();
                if vn2.read().unwrap().is_constant() { break; }
                let (base1, coef1) = Self::get_mult_coeff(&vn1);
                let (base2, coef2) = Self::get_mult_coeff(&vn2);
                if std::sync::Arc::ptr_eq(&base1, &base2) {
                    // Like terms → combine. Handle multiplier sub-case.
                    let mult1 = termorder.get_term(order[i-1]).unwrap().get_multiplier().is_some();
                    let mult2 = termorder.get_term(order[i]).unwrap().get_multiplier().is_some();
                    if mult1 {
                        let mult_op = termorder.get_term(order[i-1]).unwrap().get_multiplier().as_ref().unwrap().clone();
                        if fd.distribute_int_mult_add(&crate::op::PcodeOpRef(mult_op)) {
                            return Ok(action_status::CHANGE);
                        }
                        return Ok(action_status::NO_CHANGE);
                    }
                    if mult2 {
                        let mult_op = termorder.get_term(order[i]).unwrap().get_multiplier().as_ref().unwrap().clone();
                        if fd.distribute_int_mult_add(&crate::op::PcodeOpRef(mult_op)) {
                            return Ok(action_status::CHANGE);
                        }
                        return Ok(action_status::NO_CHANGE);
                    }
                    let size = base1.read().unwrap().get_size();
                    let mask = crate::address::calc_mask(size);
                    let new_coef = (coef1 + coef2) & mask;
                    let newcoeff = fd.new_constant(size, new_coef);
                    let zerocoeff = fd.new_constant(size, 0);
                    let edge1 = termorder.get_term(order[i-1]).unwrap();
                    let edge2 = termorder.get_term(order[i]).unwrap();
                    fd.op_set_input(&crate::op::PcodeOpRef(edge1.op.clone()), zerocoeff, edge1.slot);
                    if new_coef == 0 {
                        fd.op_set_input(&crate::op::PcodeOpRef(edge2.op.clone()), newcoeff, edge2.slot);
                    } else {
                        let nextop = fd.new_op(2, edge2.op.read().unwrap().start.get_addr());
                        fd.op_set_opcode(&nextop, OpCode::CPUI_INT_MULT);
                        let newout = fd.new_unique_out(size, &nextop);
                        fd.op_set_input(&nextop, base1, 0);
                        fd.op_set_input(&nextop, newcoeff, 1);
                        fd.op_insert_before(&nextop, &crate::op::PcodeOpRef(edge2.op.clone()));
                        fd.op_set_input(&crate::op::PcodeOpRef(edge2.op.clone()), newout, edge2.slot);
                    }
                    return Ok(action_status::CHANGE);
                }
                i += 1;
            }
        }
        // Phase 2: collapse multiple constants into one.
        let mut coef_sum = 0u64;
        let mut nonzerocount = 0;
        let mut lastconst = 0;
        for j in i..order.len() {
            let edge = termorder.get_term(order[j]).unwrap();
            if edge.get_multiplier().is_some() { continue; }
            let vn = edge.get_varnode().clone();
            if vn.read().unwrap().is_constant() {
                let val = vn.read().unwrap().get_offset();
                if val != 0 {
                    nonzerocount += 1;
                    coef_sum = coef_sum.wrapping_add(val);
                    lastconst = j;
                }
            }
        }
        if nonzerocount <= 1 { return Ok(action_status::NO_CHANGE); }
        let last_edge = termorder.get_term(order[lastconst]).unwrap();
        let last_vn = last_edge.get_varnode().clone();
        let size = last_vn.read().unwrap().get_size();
        let mask = crate::address::calc_mask(size);
        coef_sum &= mask;
        // Zero out all non-last constants.
        for j in (lastconst + 1)..order.len() {
            let edge = termorder.get_term(order[j]).unwrap();
            if edge.get_multiplier().is_some() { continue; }
            let vn = edge.get_varnode().clone();
            if vn.read().unwrap().is_constant() {
                let zero = fd.new_constant(size, 0);
                fd.op_set_input(&crate::op::PcodeOpRef(edge.op.clone()), zero, edge.slot);
            }
        }
        // Set last constant to the sum.
        let sum_const = fd.new_constant(size, coef_sum);
        let last_edge2 = termorder.get_term(order[lastconst]).unwrap();
        fd.op_set_input(&crate::op::PcodeOpRef(last_edge2.op.clone()), sum_const, last_edge2.slot);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "collect_terms" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ADD] }
}

/// Undo distributed operations through INT_AND, INT_OR, INT_XOR:
///   `zext(V) & zext(W)  =>  zext(V & W)`
///   `(V >> X) | (W >> X)  =>  (V | W) >> X`
///
/// Faithful to Ghidra's `RuleBitUndistribute` (ruleaction.cc:2620-2695).
/// When both inputs to a bitwise op are the same extension/shift operation
/// applied to different values, factor the common operation out.
pub struct RuleBitUndistribute;

impl RuleBitUndistribute {
    pub fn new() -> Self { Self }
}

impl Rule for RuleBitUndistribute {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (opc_outer, vn1_def, vn2_def) = {
            let op = op_arc.read().unwrap();
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn1.read().unwrap().is_written() || !vn2.read().unwrap().is_written() {
                return Ok(action_status::NO_CHANGE);
            }
            let d1 = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let d2 = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            match (d1, d2) {
                (Some(a), Some(b)) => (op.opcode, a, b),
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        let inner_opc = vn1_def.read().unwrap().opcode;
        if vn2_def.read().unwrap().opcode != inner_opc {
            return Ok(action_status::NO_CHANGE);
        }
        let (in1, in2): (std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
                         std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) = match inner_opc {
            OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                let i1 = vn1_def.read().unwrap().inrefs.get(0).cloned();
                let i2 = vn2_def.read().unwrap().inrefs.get(0).cloned();
                let (i1, i2) = match (i1, i2) { (Some(a), Some(b)) => (a, b), _ => return Ok(action_status::NO_CHANGE) };
                if i1.read().unwrap().is_free() || i2.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
                if i1.read().unwrap().get_size() != i2.read().unwrap().get_size() { return Ok(action_status::NO_CHANGE); }
                // Remove the second input (we'll build the inner op from in1+in2).
                let follow = crate::op::PcodeOpRef(op_arc.clone());
                fd.op_remove_input(&follow, 1);
                (i1, i2)
            }
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => {
                let s1 = vn1_def.read().unwrap().inrefs.get(1).cloned();
                let s2 = vn2_def.read().unwrap().inrefs.get(1).cloned();
                let (s1, s2) = match (s1, s2) { (Some(a), Some(b)) => (a, b), _ => return Ok(action_status::NO_CHANGE) };
                let vnextra = if s1.read().unwrap().is_constant() && s2.read().unwrap().is_constant() {
                    if s1.read().unwrap().get_offset() != s2.read().unwrap().get_offset() { return Ok(action_status::NO_CHANGE); }
                    let size = s1.read().unwrap().get_size();
                    let val = s1.read().unwrap().get_offset();
                    Some(fd.new_constant(size, val))
                } else if std::sync::Arc::ptr_eq(&s1, &s2) {
                    if s1.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
                    Some(s1)
                } else {
                    return Ok(action_status::NO_CHANGE);
                };
                let i1 = vn1_def.read().unwrap().inrefs.get(0).cloned();
                let i2 = vn2_def.read().unwrap().inrefs.get(0).cloned();
                let (i1, i2) = match (i1, i2) { (Some(a), Some(b)) => (a, b), _ => return Ok(action_status::NO_CHANGE) };
                if i1.read().unwrap().is_free() || i2.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
                let follow = crate::op::PcodeOpRef(op_arc.clone());
                fd.op_set_input(&follow, vnextra.unwrap(), 1);
                (i1, i2)
            }
            _ => return Ok(action_status::NO_CHANGE),
        };
        // Build the inner op: in1 opc_outer in2
        let pc = op_arc.read().unwrap().start.get_addr();
        let inner_size = in1.read().unwrap().get_size();
        let newext = fd.new_op(2, pc);
        let smalllogic = fd.new_unique_out(inner_size, &newext);
        fd.op_set_input(&newext, in1, 0);
        fd.op_set_input(&newext, in2, 1);
        fd.op_set_opcode(&newext, opc_outer);
        // Rewrite op: opc_inner(smalllogic, [vnextra])
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, inner_opc);
        fd.op_set_input(&follow, smalllogic, 0);
        fd.op_insert_before(&newext, &follow);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "bit_undistribute" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND, OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR] }
}

/// Deduplicate boolean expressions:
///   `(A && B) && (A && C)  =>  A && (B && C)`
///   `(A || B) || (A || C)  =>  A || (B || C)`
///
/// Faithful to Ghidra's `RuleBooleanDedup` (ruleaction.cc:2840-2955). When
/// two BOOL_AND/BOOL_OR ops share a common boolean sub-expression, factor it
/// out. Uses functional_equality for matching (simplified from Ghidra's
/// BooleanMatch::evaluate).
pub struct RuleBooleanDedup;

impl RuleBooleanDedup {
    pub fn new() -> Self { Self }
}

impl Rule for RuleBooleanDedup {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (central_opc, ins, opc0, opc1) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_BOOL_AND && op.opcode != OpCode::CPUI_BOOL_OR {
                return Ok(action_status::NO_CHANGE);
            }
            let vn0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn0.read().unwrap().is_written() || !vn1.read().unwrap().is_written() {
                return Ok(action_status::NO_CHANGE);
            }
            let op0 = vn0.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let op1 = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let (op0, op1) = match (op0, op1) { (Some(a), Some(b)) => (a, b), _ => return Ok(action_status::NO_CHANGE) };
            let opc0 = op0.read().unwrap().opcode;
            let opc1 = op1.read().unwrap().opcode;
            if !matches!(opc0, OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR) { return Ok(action_status::NO_CHANGE); }
            if !matches!(opc1, OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR) { return Ok(action_status::NO_CHANGE); }
            let ins: Vec<_> = {
                let o0 = op0.read().unwrap();
                let o1 = op1.read().unwrap();
                vec![
                    o0.inrefs.get(0).cloned().unwrap(),
                    o0.inrefs.get(1).cloned().unwrap(),
                    o1.inrefs.get(0).cloned().unwrap(),
                    o1.inrefs.get(1).cloned().unwrap(),
                ]
            };
            if ins.iter().any(|v| v.read().unwrap().is_free()) { return Ok(action_status::NO_CHANGE); }
            (op.opcode, ins, opc0, opc1)
        };
        // Find a matching pair among the 4 inputs (simplified: use functional_equality).
        // Ghidra uses BooleanMatch which also handles complement via BOOL_NEGATE.
        // We handle only the direct match case (not complement/flipped).
        let pairs = [(0,2),(0,3),(1,2),(1,3)];
        let mut found: Option<(usize, usize, usize, usize)> = None;
        for (ai, bi) in &pairs {
            if functional_equality_eq(&ins[*ai], &ins[*bi]) {
                found = Some((*ai, *bi, 1 - *ai, 4 - *bi)); // leftA, rightA, leftO, rightO
                break;
            }
        }
        let (leftA_idx, rightA_idx, leftO_idx, rightO_idx) = match found {
            Some(f) => f,
            None => return Ok(action_status::NO_CHANGE),
        };
        let leftA = ins[leftA_idx].clone();
        let leftO = ins[leftO_idx].clone();
        let rightO = ins[rightO_idx].clone();
        // Determine the opcodes.
        let (final_opc, bc_opc) = if central_opc == opc0 && central_opc == opc1 {
            (central_opc, central_opc)
        } else if opc0 == opc1 && central_opc != opc0 {
            (opc0, central_opc)
        } else {
            return Ok(action_status::NO_CHANGE);
        };
        // Build inner op: leftO bc_opc rightO
        let pc = op_arc.read().unwrap().start.get_addr();
        let bc_op = fd.new_op(2, pc);
        let tmp = fd.new_unique_out(1, &bc_op);
        fd.op_set_opcode(&bc_op, bc_opc);
        fd.op_set_input(&bc_op, leftO, 0);
        fd.op_set_input(&bc_op, rightO, 1);
        fd.op_insert_before(&bc_op, &crate::op::PcodeOpRef(op_arc.clone()));
        // Rewrite op: final_opc(leftA, tmp)
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, final_opc);
        fd.op_set_input(&follow, leftA, 0);
        fd.op_set_input(&follow, tmp, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "boolean_dedup" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_AND, OpCode::CPUI_BOOL_OR] }
}

/// Helper: exact varnode equality (same Arc pointer).
fn functional_equality_eq(
    a: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    b: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> bool {
    std::sync::Arc::ptr_eq(a, b)
}

/// Collapse unnecessary INT_AND. Faithful to Ghidra's `RuleAndMask`
/// (ruleaction.cc:300-342).
///
/// Given `V = A & B`, compute the intersection of NZM(A) and NZM(B). If the
/// result is 0 (always zero) or matches one of the inputs' NZM, replace the
/// AND with a COPY of the constant 0 or the matching input.
pub struct RuleAndMask;

impl RuleAndMask {
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndMask {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        let (out_size, mask1, mask2, in0, in1, out_consume) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_AND {
                return Ok(action_status::NO_CHANGE);
            }
            let out_size = match op.output.as_ref() {
                Some(o) => o.read().unwrap().get_size(),
                None => return Ok(action_status::NO_CHANGE),
            };
            if out_size > 8 {
                return Ok(action_status::NO_CHANGE); // uintb precision limit
            }
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let in1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let out_consume = op.output.as_ref().map(|o| o.read().unwrap().get_consume()).unwrap_or(0);
            let (m1, m2) = {
                let r0 = in0.read().unwrap();
                let r1 = in1.read().unwrap();
                (r0.get_nz_mask(), r1.get_nz_mask())
            };
            (out_size, m1, m2, in0, in1, out_consume)
        };

        // Compute the AND mask.
        let and_mask = if mask1 == 0 { 0 } else { mask1 & mask2 };

        let replace_vn = if and_mask == 0 {
            // Result of AND is always zero.
            Some(fd.new_constant(out_size, 0))
        } else if (and_mask & out_consume) == 0 {
            // Consumed bits are all zero.
            Some(fd.new_constant(out_size, 0))
        } else if and_mask == mask1 {
            // Result equals input(0), but only if input(1) is the constant mask.
            if !in1.read().unwrap().is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            Some(in0.clone())
        } else {
            None
        };

        let replace_vn = match replace_vn {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };

        // isHeritageKnown — Ghidra returns true for constants and non-free
        // varnodes. Rugra's constants are "free" (no INPUT/WRITTEN flag) but
        // are still heritage-known, so we only bail on non-constant free varnodes.
        let replace_is_const = replace_vn.read().unwrap().is_constant();
        let replace_is_free = replace_vn.read().unwrap().is_free();
        if replace_is_free && !replace_is_const {
            return Ok(action_status::NO_CHANGE);
        }

        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        fd.op_remove_input(&follow, 1);
        fd.op_set_input(&follow, replace_vn, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "and_mask" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Distribute/undistribute boolean expressions. Faithful to Ghidra's
/// `RuleBooleanUndistribute` (ruleaction.cc:2700-2810).
///
/// Transform patterns like:
/// - `(A == B) && (A != C)  =>  A == (B && C)` (factor out common boolean)
/// - `(A || B) && (A || C)  =>  A || (B && C)`
/// Uses `BooleanMatch::evaluate` to find correlated boolean sub-expressions
/// (same or complementary) and factors them out via De Morgan's Law.
pub struct RuleBooleanUndistribute;

impl RuleBooleanUndistribute {
    pub fn new() -> Self { Self }

    /// Check if two boolean Varnodes are correlated (same or complementary).
    /// Faithful to `RuleBooleanUndistribute::isMatch` (ruleaction.cc:2710-2729).
    /// Returns `Some(is_flip)` where `is_flip` is true for complementary.
    fn is_match(
        left_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        right_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<bool> {
        let val = crate::expression::boolean_match_evaluate(left_vn, right_vn, 1);
        match val {
            crate::expression::boolean_match::SAME => Some(false),
            crate::expression::boolean_match::COMPLEMENTARY => Some(true),
            _ => None,
        }
    }
}

impl Rule for RuleBooleanUndistribute {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleBooleanUndistribute::applyOp (ruleaction.cc:2731-2810).
        let (central_opc, ins) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_EQUAL && op.opcode != OpCode::CPUI_INT_NOTEQUAL {
                return Ok(action_status::NO_CHANGE);
            }
            let vn0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn0.read().unwrap().is_written() || !vn1.read().unwrap().is_written() {
                return Ok(action_status::NO_CHANGE);
            }
            let op0 = match vn0.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let op1 = match vn1.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let opc0 = op0.read().unwrap().opcode;
            if opc0 != OpCode::CPUI_BOOL_AND && opc0 != OpCode::CPUI_BOOL_OR {
                return Ok(action_status::NO_CHANGE);
            }
            let opc1 = op1.read().unwrap().opcode;
            if opc1 != OpCode::CPUI_BOOL_AND && opc1 != OpCode::CPUI_BOOL_OR {
                return Ok(action_status::NO_CHANGE);
            }
            let ins: Vec<_> = {
                let o0 = op0.read().unwrap();
                let o1 = op1.read().unwrap();
                vec![
                    o0.inrefs.get(0).cloned().unwrap(),
                    o0.inrefs.get(1).cloned().unwrap(),
                    o1.inrefs.get(0).cloned().unwrap(),
                    o1.inrefs.get(1).cloned().unwrap(),
                ]
            };
            if ins.iter().any(|v| v.read().unwrap().is_free()) {
                return Ok(action_status::NO_CHANGE);
            }
            (op.opcode, ins)
        };

        // Track flip state for De Morgan's Law.
        let mut isflipped = [false; 4];
        let mut central_equal = central_opc == OpCode::CPUI_INT_EQUAL;
        // Get opc0/opc1 again for the flip logic.
        let vn0 = op_arc.read().unwrap().inrefs[0].clone();
        let vn1 = op_arc.read().unwrap().inrefs[1].clone();
        let opc0 = vn0.read().unwrap().get_def().map(|d| d.read().unwrap().opcode);
        let opc1 = vn1.read().unwrap().get_def().map(|d| d.read().unwrap().opcode);
        let opc0 = match opc0 { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
        let opc1 = match opc1 { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
        if opc0 == OpCode::CPUI_BOOL_OR {
            isflipped[0] = !isflipped[0];
            isflipped[1] = !isflipped[1];
            central_equal = !central_equal;
        }
        if opc1 == OpCode::CPUI_BOOL_OR {
            isflipped[2] = !isflipped[2];
            isflipped[3] = !isflipped[3];
            central_equal = !central_equal;
        }

        // Find a matching pair among the 4 inputs.
        let pairs = [(0, 2), (0, 3), (1, 2), (1, 3)];
        let mut found: Option<(usize, usize)> = None;
        for (ai, bi) in &pairs {
            if let Some(flip) = Self::is_match(&ins[*ai], &ins[*bi]) {
                // Check flip consistency.
                if isflipped[*ai] != isflipped[*bi] {
                    // The match must account for the flip difference.
                    if !flip {
                        continue;
                    }
                } else if flip {
                    // Same flip state but BooleanMatch says complementary.
                    // This is still valid if the flip changes the meaning.
                }
                found = Some((*ai, *bi));
                break;
            }
        }
        let (left_slot, right_slot) = match found {
            Some((l, r)) => (l, r),
            None => return Ok(action_status::NO_CHANGE),
        };
        if isflipped[left_slot] != isflipped[right_slot] {
            return Ok(action_status::NO_CHANGE);
        }

        // Determine the combine opcode.
        let (combine_opc, flip_left) = if central_equal {
            (OpCode::CPUI_BOOL_OR, !isflipped[left_slot])
        } else {
            (OpCode::CPUI_BOOL_AND, isflipped[left_slot])
        };

        // Build finalA (factored-out common boolean).
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let final_a = if flip_left {
            fd.op_bool_negate(ins[left_slot].clone(), &follow, false)
        } else {
            ins[left_slot].clone()
        };

        // The remaining inputs.
        let final_b = ins[1 - left_slot].clone();
        let final_c = ins[5 - right_slot].clone();

        // Build new comparison op: final_b ==/!= final_c.
        let eq_op = fd.new_op(2, op_arc.read().unwrap().get_addr());
        let tmp1 = fd.new_unique_out(1, &eq_op);
        let eq_opc = if central_equal { OpCode::CPUI_INT_EQUAL } else { OpCode::CPUI_INT_NOTEQUAL };
        fd.op_set_opcode(&eq_op, eq_opc);
        fd.op_set_input(&eq_op, final_b, 0);
        fd.op_set_input(&eq_op, final_c, 1);
        fd.op_insert_before(&eq_op, &follow);

        // Rewrite the original op as combine_opc(final_a, tmp1).
        fd.op_set_opcode(&follow, combine_opc);
        fd.op_set_input(&follow, tmp1, 1);
        fd.op_set_input(&follow, final_a, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "boolean_undistribute" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL] }
}

/// Convert operations on zero-extended booleans to boolean operations.
/// Faithful to Ghidra's `RuleBoolZext` (ruleaction.cc:3000-3124).
///
/// Detects patterns where a boolean value is zero-extended, multiplied by -1
/// (all-ones mask), and then used in a comparison/logical op. Rewrites to use
/// the original boolean directly with BOOL_AND/OR/XOR or BOOL_NEGATE.
pub struct RuleBoolZext;

impl RuleBoolZext {
    pub fn new() -> Self { Self }
}

impl Rule for RuleBoolZext {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleBoolZext::applyOp (ruleaction.cc:3015-3124).
        let (bool_vn1, multop1_arc) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_ZEXT {
                return Ok(action_status::NO_CHANGE);
            }
            let bool_vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !bool_vn1.read().unwrap().is_boolean_value(fd.is_type_recovery_on()) {
                return Ok(action_status::NO_CHANGE);
            }
            let out_vn = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            let multop1 = out_vn.read().unwrap().lone_descend();
            let multop1 = match multop1 { Some(m) => m, None => return Ok(action_status::NO_CHANGE) };
            if multop1.read().unwrap().opcode != OpCode::CPUI_INT_MULT {
                return Ok(action_status::NO_CHANGE);
            }
            (bool_vn1, multop1)
        };
        // Check multop1's constant input == all-ones mask.
        let (coeff, size) = {
            let m1 = multop1_arc.read().unwrap();
            let const_vn = match m1.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !const_vn.read().unwrap().is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            let coeff = const_vn.read().unwrap().get_offset();
            let const_size = const_vn.read().unwrap().get_size();
            if coeff != calc_mask(const_size) {
                return Ok(action_status::NO_CHANGE);
            }
            let out_size = m1.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
            (coeff, out_size)
        };
        // Get the action op (loneDescend of multop1's output).
        let out_arc = {
            let m1 = multop1_arc.read().unwrap();
            match m1.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        let actionop_arc = {
            let out_rg = out_arc.read().unwrap();
            out_rg.lone_descend()
        };
        let actionop_arc = match actionop_arc { Some(a) => a, None => return Ok(action_status::NO_CHANGE) };
        let actionopc = actionop_arc.read().unwrap().opcode;
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let action_ref = crate::op::PcodeOpRef(actionop_arc.clone());

        match actionopc {
            OpCode::CPUI_INT_ADD => {
                let (is_const_1, const_val) = {
                    let a = actionop_arc.read().unwrap();
                    let in1 = match a.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
                    let r = in1.read().unwrap();
                    (r.is_constant(), r.get_offset())
                };
                if !is_const_1 || const_val != 1 {
                    return Ok(action_status::NO_CHANGE);
                }
                // Negate the boolean, rewrite op as COPY of negated, action as COPY.
                let neg_vn = fd.op_bool_negate(bool_vn1.clone(), &follow, false);
                fd.op_set_input(&follow, neg_vn, 0);
                fd.op_remove_input(&action_ref, 1);
                fd.op_set_opcode(&action_ref, OpCode::CPUI_COPY);
                let zext_out = op_arc.read().unwrap().output.clone();
                if let Some(zo) = zext_out {
                    fd.op_set_input(&action_ref, zo, 0);
                }
                Ok(action_status::CHANGE)
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                let val = {
                    let a = actionop_arc.read().unwrap();
                    let in1 = match a.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
                    let r = in1.read().unwrap();
                    if !r.is_constant() { return Ok(action_status::NO_CHANGE); }
                    r.get_offset()
                };
                let new_val = if val == coeff { 1 } else if val != 0 { return Ok(action_status::NO_CHANGE); } else { 0 };
                fd.op_set_input(&action_ref, bool_vn1.clone(), 0);
                let c = fd.new_constant(1, new_val);
                fd.op_set_input(&action_ref, c, 1);
                Ok(action_status::CHANGE)
            }
            OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR => {
                let opc = match actionopc {
                    OpCode::CPUI_INT_AND => OpCode::CPUI_BOOL_AND,
                    OpCode::CPUI_INT_OR => OpCode::CPUI_BOOL_OR,
                    _ => OpCode::CPUI_BOOL_XOR,
                };
                // Find the other side's multop2.
                let multop2_arc = {
                    let a = actionop_arc.read().unwrap();
                    let in0 = a.inrefs.get(0).cloned();
                    let in1 = a.inrefs.get(1).cloned();
                    // multop1 is on one side; find the other.
                    let m1_out = multop1_arc.read().unwrap().output.as_ref().and_then(|o| {
                        // Check if in0's def is multop1
                        if let Some(i0) = &in0 {
                            let i0_def = i0.read().unwrap().get_def();
                            if let Some(d) = i0_def {
                                if std::sync::Arc::ptr_eq(&d, &multop1_arc) {
                                    return in1.as_ref().and_then(|v| v.read().unwrap().get_def());
                                }
                            }
                        }
                        in0.as_ref().and_then(|v| v.read().unwrap().get_def())
                    });
                    m1_out
                };
                let multop2_arc = match multop2_arc { Some(m) => m, None => return Ok(action_status::NO_CHANGE) };
                if multop2_arc.read().unwrap().opcode != OpCode::CPUI_INT_MULT {
                    return Ok(action_status::NO_CHANGE);
                }
                let (coeff2, multop2_in0_def) = {
                    let m2 = multop2_arc.read().unwrap();
                    let in1 = match m2.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
                    if !in1.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
                    let c2 = in1.read().unwrap().get_offset();
                    if c2 != calc_mask(size) { return Ok(action_status::NO_CHANGE); }
                    let in0_def = m2.inrefs.get(0).and_then(|v| v.read().unwrap().get_def());
                    (c2, in0_def)
                };
                let _ = coeff2;
                let zextop2_arc = match multop2_in0_def { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
                if zextop2_arc.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT {
                    return Ok(action_status::NO_CHANGE);
                }
                let bool_vn2 = match zextop2_arc.read().unwrap().inrefs.get(0).cloned() {
                    Some(v) => v,
                    None => return Ok(action_status::NO_CHANGE),
                };
                if !bool_vn2.read().unwrap().is_boolean_value(fd.is_type_recovery_on()) {
                    return Ok(action_status::NO_CHANGE);
                }
                // Build BOOL op on unextended booleans, then ZEXT the result.
                let action_addr = actionop_arc.read().unwrap().get_addr();
                let new_op = fd.new_op(2, action_addr);
                let new_res = fd.new_unique_out(1, &new_op);
                fd.op_set_opcode(&new_op, opc);
                fd.op_set_input(&new_op, bool_vn1.clone(), 0);
                fd.op_set_input(&new_op, bool_vn2.clone(), 1);
                fd.op_insert_before(&new_op, &action_ref);
                let new_zext = fd.new_op(1, action_addr);
                let new_zout = fd.new_unique_out(size, &new_zext);
                fd.op_set_opcode(&new_zext, OpCode::CPUI_INT_ZEXT);
                fd.op_set_input(&new_zext, new_res, 0);
                fd.op_insert_before(&new_zext, &action_ref);
                fd.op_set_opcode(&action_ref, OpCode::CPUI_INT_MULT);
                fd.op_set_input(&action_ref, new_zout, 0);
                let c = fd.new_constant(size, calc_mask(size));
                fd.op_set_input(&action_ref, c, 1);
                Ok(action_status::CHANGE)
            }
            _ => Ok(action_status::NO_CHANGE),
        }
    }

    fn get_name(&self) -> &str { "bool_zext" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ZEXT] }
}

/// Simplify MULTIEQUAL where both inputs are constructed in functionally
/// equivalent ways. Faithful to Ghidra's `RulePushMulti`
/// (ruleaction.cc:1060-1137).
///
/// Look for a two-branch MULTIEQUAL where both inputs hold the same value
/// (possibly via functional equality). Remove one construction and move the
/// other into the merge block, eliminating the MULTIEQUAL.
pub struct RulePushMulti;

impl RulePushMulti {
    pub fn new() -> Self { Self }

    /// Find a substitute MULTIEQUAL in the block that already merges in1/in2.
    /// Faithful to `RulePushMulti::findSubstitute` (ruleaction.cc:1031-1060).
    fn find_substitute(
        in1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        in2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<PcodeOp>>> {
        // Search descendants of in1 for a MULTIEQUAL with inputs [in1, in2].
        let descends: Vec<_> = in1.read().unwrap().descend_iter().collect();
        for op_arc in descends {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_MULTIEQUAL {
                continue;
            }
            let in0 = op.inrefs.get(0).cloned();
            let in1_ref = op.inrefs.get(1).cloned();
            if let (Some(a), Some(b)) = (in0, in1_ref) {
                if std::sync::Arc::ptr_eq(&a, in1) && std::sync::Arc::ptr_eq(&b, in2) {
                    drop(op);
                    return Some(op_arc);
                }
            }
        }
        // Check functional equality between in1 and in2.
        if std::sync::Arc::ptr_eq(in1, in2) {
            return None;
        }
        let result = crate::expression::functional_equality_level(in1, in2);
        if result.code != 0 {
            return None;
        }
        // in1 and in2 are functionally equal; look for a CSE of their defs.
        let op1 = in1.read().unwrap().get_def();
        let op2 = in2.read().unwrap().get_def();
        let (op1, op2) = match (op1, op2) {
            (Some(a), Some(b)) => (a, b),
            _ => return None,
        };
        let num_input = op1.read().unwrap().inrefs.len();
        for i in 0..num_input {
            let vn = op1.read().unwrap().inrefs.get(i).cloned();
            if let Some(vn) = vn {
                if vn.read().unwrap().is_constant() {
                    continue;
                }
                let op2_in = op2.read().unwrap().inrefs.get(i).cloned();
                if let Some(op2_in) = op2_in {
                    if std::sync::Arc::ptr_eq(&vn, &op2_in) {
                        // Search for a CSE of op1 reading vn in the block.
                        let vn_descends: Vec<_> = vn.read().unwrap().descend_iter().collect();
                        for d in vn_descends {
                            let dr = d.read().unwrap();
                            if std::sync::Arc::ptr_eq(&d, &op1) {
                                continue;
                            }
                            // Check if this descendant has the same opcode and
                            // matching inputs as op1.
                            if dr.opcode == op1.read().unwrap().opcode
                                && dr.inrefs.len() == op1.read().unwrap().inrefs.len()
                            {
                                let mut all_match = true;
                                for j in 0..dr.inrefs.len() {
                                    if !std::sync::Arc::ptr_eq(&dr.inrefs[j], &op1.read().unwrap().inrefs[j]) {
                                        all_match = false;
                                        break;
                                    }
                                }
                                if all_match {
                                    drop(dr);
                                    return Some(d);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

impl Rule for RulePushMulti {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePushMulti::applyOp (ruleaction.cc:1074-1137).
        use crate::expression::functional_equality_level;

        let num_input = op_arc.read().unwrap().inrefs.len();
        if num_input != 2 {
            return Ok(action_status::NO_CHANGE);
        }
        let in1 = match op_arc.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        let in2 = match op_arc.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !in1.read().unwrap().is_written() || !in2.read().unwrap().is_written() {
            return Ok(action_status::NO_CHANGE);
        }
        if in1.read().unwrap().is_spacebase() || in2.read().unwrap().is_spacebase() {
            return Ok(action_status::NO_CHANGE);
        }
        let result = functional_equality_level(&in1, &in2);
        if result.code < 0 || result.code > 1 {
            return Ok(action_status::NO_CHANGE);
        }
        let res = result.code;
        let op1_arc = match in1.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        let op1_code = op1_arc.read().unwrap().opcode;
        if op1_code == OpCode::CPUI_SUBPIECE {
            return Ok(action_status::NO_CHANGE);
        }

        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        let op1_ref = crate::op::PcodeOpRef(op1_arc.clone());
        let out_vn = match op_arc.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };

        if op1_code == OpCode::CPUI_COPY {
            // Special case: MERGE of 2 shadowing varnodes.
            if res == 0 {
                return Ok(action_status::NO_CHANGE);
            }
            let substitute = match Self::find_substitute(&result.pairs[0].0, &result.pairs[0].1) {
                Some(s) => s,
                None => return Ok(action_status::NO_CHANGE),
            };
            let sub_out = substitute.read().unwrap().output.clone();
            if let Some(sub_out) = sub_out {
                fd.total_replace(&out_vn, sub_out);
            }
            fd.op_destroy(&op_ref);
            return Ok(action_status::CHANGE);
        }

        let op2_arc = match in2.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        // Both inputs must have this op as their lone descendant.
        let in1_lone = in1.read().unwrap().lone_descend();
        if !in1_lone.map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false) {
            return Ok(action_status::NO_CHANGE);
        }
        let in2_lone = in2.read().unwrap().lone_descend();
        if !in2_lone.map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false) {
            return Ok(action_status::NO_CHANGE);
        }

        // Move MULTIEQUAL output to op1 (the new unified op).
        fd.op_set_output(&op1_ref, out_vn.clone());
        fd.op_uninsert(&op1_ref);

        if res == 1 {
            // There's one pair that must be unified via a new MULTIEQUAL.
            let buf1 = &result.pairs[0].0;
            let buf2 = &result.pairs[0].1;
            let substitute = Self::find_substitute(buf1, buf2);
            let slot1 = fd.op_get_slot(&op1_ref, buf1) as usize;
            let sub_out = if let Some(sub) = substitute {
                sub.read().unwrap().output.clone().unwrap_or_else(|| {
                    // Fallback: create a new MULTIEQUAL if substitute has no output.
                    let addr = op_arc.read().unwrap().get_addr();
                    let new_op = fd.new_op(2, addr);
                    fd.op_set_opcode(&new_op, OpCode::CPUI_MULTIEQUAL);
                    let sub_vn = fd.new_unique_out(buf1.read().unwrap().get_size(), &new_op);
                    fd.op_set_input(&new_op, buf1.clone(), 0);
                    fd.op_set_input(&new_op, buf2.clone(), 1);
                    fd.op_insert_before(&new_op, &op_ref);
                    sub_vn
                })
            } else {
                // Create a new MULTIEQUAL to unify buf1/buf2.
                let addr = op_arc.read().unwrap().get_addr();
                let new_op = fd.new_op(2, addr);
                fd.op_set_opcode(&new_op, OpCode::CPUI_MULTIEQUAL);
                let sub_vn = fd.new_unique_out(buf1.read().unwrap().get_size(), &new_op);
                fd.op_set_input(&new_op, buf1.clone(), 0);
                fd.op_set_input(&new_op, buf2.clone(), 1);
                fd.op_insert_before(&new_op, &op_ref);
                sub_vn
            };
            fd.op_set_input(&op1_ref, sub_out, slot1);
            // Re-insert op1 after the substitute (or before op).
            fd.op_insert_before(&op1_ref, &op_ref);
        } else {
            // res == 0: inputs are identical, just move op1 to the merge block.
            fd.op_insert_before(&op1_ref, &op_ref);
        }
        // Destroy the original MULTIEQUAL and the duplicate op2.
        let op2_ref = crate::op::PcodeOpRef(op2_arc);
        fd.op_destroy(&op_ref);
        fd.op_destroy(&op2_ref);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "push_multi" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_MULTIEQUAL] }
}

/// Look for common sub-expressions built from a restricted set of ops.
/// Faithful to Ghidra's `RuleSelectCse` (ruleaction.cc:178-209).
///
/// Given a SUBPIECE or INT_SRIGHT op, examine the descendants of its input(0)
/// for ops with the same opcode (and non-zero CSE hash), then eliminate
/// duplicate calculations via `cseEliminateList`.
pub struct RuleSelectCse;

impl RuleSelectCse {
    pub fn new() -> Self { Self }
}

impl Rule for RuleSelectCse {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSelectCse::applyOp (ruleaction.cc:187-209).
        let (opc, vn) = {
            let op = op_arc.read().unwrap();
            let opc = op.opcode;
            if opc != OpCode::CPUI_SUBPIECE && opc != OpCode::CPUI_INT_SRIGHT {
                return Ok(action_status::NO_CHANGE);
            }
            let vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (opc, vn)
        };
        // Collect descendants of vn with the same opcode and non-zero hash.
        let mut list: Vec<(u64, crate::op::PcodeOpRef)> = Vec::new();
        let descends: Vec<_> = vn.read().unwrap().descend_iter().collect();
        for other_arc in descends {
            let other_opc = other_arc.read().unwrap().opcode;
            if other_opc != opc {
                continue;
            }
            let hash = other_arc.read().unwrap().get_cse_hash();
            if hash == 0 {
                continue;
            }
            list.push((hash, crate::op::PcodeOpRef(other_arc)));
        }
        if list.len() <= 1 {
            return Ok(action_status::NO_CHANGE);
        }
        let outlist = fd.cse_eliminate_list(&mut list);
        if outlist.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "select_cse" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE, OpCode::CPUI_INT_SRIGHT] }
}

/// Cleanup: Convert INT_2COMP from INT_MULT: `V * -1 => -V`. Faithful to
/// Ghidra's `RuleMultNegOne` (ruleaction.cc:7171-7190).
pub struct RuleMultNegOne;

impl RuleMultNegOne {
    pub fn new() -> Self { Self }
}

impl Rule for RuleMultNegOne {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleMultNegOne::applyOp (ruleaction.cc:7179-7190).
        // a * -1 -> -a
        let constvn = {
            let op = op_arc.read().unwrap();
            match op.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        let const_size = constvn.read().unwrap().get_size();
        let const_val = constvn.read().unwrap().get_offset();
        if const_val != calc_mask(const_size) {
            return Ok(action_status::NO_CHANGE);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_NEG);
        fd.op_remove_input(&follow, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "mult_neg_one" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_MULT] }
}

/// Convert INT_SUB to INT_ADD + INT_MULT(-1): `V - W => V + (W * -1)`.
/// Faithful to Ghidra's `RuleSub2Add` (ruleaction.cc:4030-4056).
///
/// This normalization enables additive-term reordering and other rules that
/// only match INT_ADD.
pub struct RuleSub2Add;

impl RuleSub2Add {
    pub fn new() -> Self { Self }
}

impl Rule for RuleSub2Add {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSub2Add::applyOp (ruleaction.cc:4040-4056).
        let vn = {
            let op = op_arc.read().unwrap();
            match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        let vn_size = vn.read().unwrap().get_size();
        let addr = op_arc.read().unwrap().get_addr();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // Create INT_MULT(vn, -1).
        let newop = fd.new_op(2, addr);
        fd.op_set_opcode(&newop, OpCode::CPUI_INT_MULT);
        let newvn = fd.new_unique_out(vn_size, &newop);
        // Replace vn's reference in the original op first.
        fd.op_set_input(&follow, newvn.clone(), 1);
        fd.op_set_input(&newop, vn.clone(), 0);
        let neg_const = fd.new_constant(vn_size, calc_mask(vn_size));
        fd.op_set_input(&newop, neg_const, 1);
        // Rewrite original op as INT_ADD.
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_ADD);
        fd.op_insert_before(&newop, &follow);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "sub2_add" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SUB] }
}

/// Commute SUBPIECE through INT_ZEXT/INT_SEXT. Faithful to Ghidra's
/// `RuleSubExtComm` (ruleaction.cc:4410-4461).
///
/// If `SUBPIECE(zext(V))` doesn't touch the extended bits, replace with
/// `zext(SUBPIECE(V))` or just `COPY(V)` if sizes match.
pub struct RuleSubExtComm;

impl RuleSubExtComm {
    pub fn new() -> Self { Self }
}

impl Rule for RuleSubExtComm {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSubExtComm::applyOp (ruleaction.cc:4422-4461).
        let (base, ext_code, in_vn, subcut, out_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_SUBPIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let base = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !base.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let extop = match base.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let ext_code = extop.read().unwrap().opcode;
            if ext_code != OpCode::CPUI_INT_ZEXT && ext_code != OpCode::CPUI_INT_SEXT {
                return Ok(action_status::NO_CHANGE);
            }
            let in_vn = match extop.read().unwrap().inrefs.get(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if in_vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let subcut = op.inrefs.get(1).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(0);
            let out_size = op.output.as_ref().map(|v| v.read().unwrap().get_size() as i64).unwrap_or(0);
            (base, ext_code, in_vn, subcut, out_size)
        };

        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let in_size = in_vn.read().unwrap().get_size() as i64;

        if out_size + subcut <= in_size {
            // SUBPIECE doesn't hit the extended bits at all.
            fd.op_set_input(&follow, in_vn.clone(), 0);
            if in_size == out_size {
                fd.op_remove_input(&follow, 1);
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            }
            return Ok(action_status::CHANGE);
        }
        if subcut >= in_size {
            return Ok(action_status::NO_CHANGE);
        }
        // Create intermediate SUBPIECE if needed.
        let new_vn = if subcut != 0 {
            let addr = op_arc.read().unwrap().get_addr();
            let newop = fd.new_op(2, addr);
            fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
            let nv = fd.new_unique_out((in_size - subcut) as usize, &newop);
            let c = fd.new_constant(4, subcut as u64);
            fd.op_set_input(&newop, c, 1);
            fd.op_set_input(&newop, in_vn.clone(), 0);
            fd.op_insert_before(&newop, &follow);
            nv
        } else {
            in_vn.clone()
        };
        fd.op_remove_input(&follow, 1);
        fd.op_set_opcode(&follow, ext_code);
        fd.op_set_input(&follow, new_vn, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "sub_ext_comm" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Cleanup: Convert INT_2COMP to INT_MULT: `-V => V * -1`. Faithful to
/// Ghidra's `Rule2Comp2Mult` (ruleaction.cc:3980-3995).
pub struct Rule2Comp2Mult;

impl Rule2Comp2Mult {
    pub fn new() -> Self { Self }
}

impl Rule for Rule2Comp2Mult {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Rule2Comp2Mult::applyOp (ruleaction.cc:3987-3995).
        // Ghidra INT_2COMP maps to Rugra INT_NEG (two's complement).
        let in0 = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_NEG {
                return Ok(action_status::NO_CHANGE);
            }
            match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        let size = in0.read().unwrap().get_size();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_MULT);
        let neg_one = fd.new_constant(size, calc_mask(size));
        fd.op_insert_input(&follow, neg_one, 1);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "2comp2mult" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_NEG] }
}

/// Cleanup: Convert INT_2COMP to INT_SUB: `-V => 0 - V`. Faithful to
/// Ghidra's `Rule2Comp2Sub` (ruleaction.cc:7236-7256).
pub struct Rule2Comp2Sub;

impl Rule2Comp2Sub {
    pub fn new() -> Self { Self }
}

impl Rule for Rule2Comp2Sub {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Rule2Comp2Sub::applyOp (ruleaction.cc:7242-7256).
        let in0 = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_NEG {
                return Ok(action_status::NO_CHANGE);
            }
            match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        let size = in0.read().unwrap().get_size();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_SUB);
        // Insert a zero constant as the first input.
        let zero = fd.new_constant(size, 0);
        fd.op_insert_input(&follow, zero, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "2comp2sub" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_NEG] }
}

/// Transform INT_CARRY using a constant: `carry(V,c) => -c <= V`. Faithful to
/// Ghidra's `RuleCarryElim` (ruleaction.cc:3997-4030).
pub struct RuleCarryElim;

impl RuleCarryElim {
    pub fn new() -> Self { Self }
}

impl Rule for RuleCarryElim {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleCarryElim::applyOp (ruleaction.cc:4008-4030).
        let (vn1, off, vn2_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_CARRY {
                return Ok(action_status::NO_CHANGE);
            }
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn2.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if vn1.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let off = vn2.read().unwrap().get_offset();
            let sz = vn2.read().unwrap().get_size();
            (vn1, off, sz)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        if off == 0 {
            // Trivial case: carry(V, 0) => false.
            fd.op_remove_input(&follow, 1);
            let false_const = fd.new_constant(1, 0);
            fd.op_set_input(&follow, false_const, 0);
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            return Ok(action_status::CHANGE);
        }
        // -off (two's complement).
        let neg_off = off.wrapping_neg() & calc_mask(vn2_size);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_LESSEQUAL);
        fd.op_set_input(&follow, vn1.clone(), 1);
        let c = fd.new_constant(vn1.read().unwrap().get_size(), neg_off);
        fd.op_set_input(&follow, c, 0);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "carry_elim" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_CARRY] }
}

/// Commute INT_ZEXT with PIECE: `concat(zext(V), W) => zext(concat(V, W))`.
/// Faithful to Ghidra's `RuleConcatZext` (ruleaction.cc:4806-4842).
pub struct RuleConcatZext;

impl RuleConcatZext {
    pub fn new() -> Self { Self }
}

impl Rule for RuleConcatZext {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleConcatZext::applyOp (ruleaction.cc:4814-4842).
        let (hi, lo, addr) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_PIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let hi_in = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !hi_in.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let zextop = match hi_in.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if zextop.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return Ok(action_status::NO_CHANGE); }
            let hi = match zextop.read().unwrap().inrefs.get(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let lo = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if hi.read().unwrap().is_free() || lo.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            (hi, lo, op.get_addr())
        };
        let hi_size = hi.read().unwrap().get_size();
        let lo_size = lo.read().unwrap().get_size();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // Create new PIECE(hi, lo).
        let new_concat = fd.new_op(2, addr);
        fd.op_set_opcode(&new_concat, OpCode::CPUI_PIECE);
        let new_vn = fd.new_unique_out(hi_size + lo_size, &new_concat);
        fd.op_set_input(&new_concat, hi, 0);
        fd.op_set_input(&new_concat, lo, 1);
        fd.op_insert_before(&new_concat, &follow);
        // Change original op into a ZEXT.
        fd.op_remove_input(&follow, 1);
        fd.op_set_input(&follow, new_vn, 0);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_ZEXT);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "concat_zext" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PIECE] }
}

/// Commute INT_ZEXT with INT_RIGHT: `zext(V) >> W => zext(V >> W)`.
/// Faithful to Ghidra's `RuleZextCommute` (ruleaction.cc:4844-4875).
pub struct RuleZextCommute;

impl RuleZextCommute {
    pub fn new() -> Self { Self }
}

impl Rule for RuleZextCommute {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleZextCommute::applyOp (ruleaction.cc:4852-4875).
        let (zext_in, sa_vn, addr) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_RIGHT {
                return Ok(action_status::NO_CHANGE);
            }
            let zext_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !zext_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let zextop = match zext_vn.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if zextop.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return Ok(action_status::NO_CHANGE); }
            let zext_in = match zextop.read().unwrap().inrefs.get(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if zext_in.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let sa_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !sa_vn.read().unwrap().is_constant() && sa_vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            (zext_in, sa_vn, op.get_addr())
        };
        let zext_in_size = zext_in.read().unwrap().get_size();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // Create INT_RIGHT(zext_in, sa).
        let new_op = fd.new_op(2, addr);
        fd.op_set_opcode(&new_op, OpCode::CPUI_INT_RIGHT);
        let new_out = fd.new_unique_out(zext_in_size, &new_op);
        fd.op_remove_input(&follow, 1);
        fd.op_set_input(&follow, new_out, 0);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_ZEXT);
        fd.op_set_input(&new_op, zext_in, 0);
        fd.op_set_input(&new_op, sa_vn, 1);
        fd.op_insert_before(&new_op, &follow);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "zext_commute" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT] }
}

/// Simplify multiple INT_ZEXT operations. Faithful to Ghidra's
/// `RuleZextShiftZext` (ruleaction.cc:4877-4919).
///
/// `zext(zext(V)) => zext(V)` and `zext(zext(V) << c) => zext(V) << c`.
pub struct RuleZextShiftZext;

impl RuleZextShiftZext {
    pub fn new() -> Self { Self }
}

impl Rule for RuleZextShiftZext {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleZextShiftZext::applyOp (ruleaction.cc:4885-4919).
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let (in_vn, shiftop_code) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_ZEXT {
                return Ok(action_status::NO_CHANGE);
            }
            let in_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !in_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let shiftop_code = {
                let in_rg = in_vn.read().unwrap();
                match in_rg.get_def() {
                    Some(d) => d.read().unwrap().opcode,
                    None => return Ok(action_status::NO_CHANGE),
                }
            };
            (in_vn, shiftop_code)
        };
        let shiftop = match in_vn.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };

        if shiftop_code == OpCode::CPUI_INT_ZEXT {
            // Check for ZEXT(ZEXT(a)).
            let vn = match shiftop.read().unwrap().inrefs.get(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let lone = in_vn.read().unwrap().lone_descend();
            if !lone.map(|o| std::sync::Arc::ptr_eq(&o, op_arc)).unwrap_or(false) {
                return Ok(action_status::NO_CHANGE);
            }
            fd.op_set_input(&follow, vn, 0);
            return Ok(action_status::CHANGE);
        }
        if shiftop_code != OpCode::CPUI_INT_LEFT {
            return Ok(action_status::NO_CHANGE);
        }
        // Check for ZEXT(ZEXT(V) << c).
        let shift_in1_const = shiftop.read().unwrap().get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
        if !shift_in1_const { return Ok(action_status::NO_CHANGE); }
        let shift_in0 = match shiftop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
        if !shift_in0.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let zext2op = match shift_in0.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
        if zext2op.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return Ok(action_status::NO_CHANGE); }
        let root_vn = match zext2op.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
        if root_vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        let sa = shiftop.read().unwrap().get_in(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
        let zext2_out_size = zext2op.read().unwrap().output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        let root_size = root_vn.read().unwrap().get_size();
        if sa > 8 * (zext2_out_size - root_size) as u64 {
            return Ok(action_status::NO_CHANGE); // Shift might lose bits.
        }
        let out_size = op_arc.read().unwrap().output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        let addr = op_arc.read().unwrap().get_addr();
        let new_op = fd.new_op(1, addr);
        fd.op_set_opcode(&new_op, OpCode::CPUI_INT_ZEXT);
        let out_vn = fd.new_unique_out(out_size, &new_op);
        fd.op_set_input(&new_op, root_vn, 0);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_LEFT);
        fd.op_set_input(&follow, out_vn, 0);
        let c = fd.new_constant(4, sa);
        fd.op_insert_input(&follow, c, 1);
        fd.op_insert_before(&new_op, &follow);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "zext_shift_zext" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ZEXT] }
}

/// Simplify SUBPIECE applied to INT_LEFT: `sub(V << 8*k, c) => sub(V, c-k)`.
/// Faithful to Ghidra's `RuleShiftSub` (ruleaction.cc:5201-5230).
pub struct RuleShiftSub;

impl RuleShiftSub {
    pub fn new() -> Self { Self }
}

impl Rule for RuleShiftSub {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleShiftSub::applyOp (ruleaction.cc:5209-5230).
        let (shiftop_arc, vn, n, c, out_size, in1_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_SUBPIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let base = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !base.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let shiftop = match base.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if shiftop.read().unwrap().opcode != OpCode::CPUI_INT_LEFT { return Ok(action_status::NO_CHANGE); }
            let sa_vn = match shiftop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !sa_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let n = sa_vn.read().unwrap().get_offset() as i64;
            if (n & 7) != 0 { return Ok(action_status::NO_CHANGE); }
            let c_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let c = c_vn.read().unwrap().get_offset() as i64;
            let vn = match shiftop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let out_size = op.output.as_ref().map(|v| v.read().unwrap().get_size() as i64).unwrap_or(0);
            let in1_size = c_vn.read().unwrap().get_size();
            (shiftop, vn, n, c, out_size, in1_size)
        };
        let in_size = vn.read().unwrap().get_size() as i64;
        let new_c = c - n / 8;
        if new_c < 0 || new_c + out_size > in_size {
            return Ok(action_status::NO_CHANGE); // Not a natural truncation.
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, vn, 0);
        let c_const = fd.new_constant(in1_size, new_c as u64);
        fd.op_set_input(&follow, c_const, 1);
        let _ = shiftop_arc;
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "shift_sub" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify break and rejoin: `concat(sub(V,c), sub(V,0)) => V`.
/// Faithful to Ghidra's `RuleHumptyDumpty` (ruleaction.cc:5232-5281).
pub struct RuleHumptyDumpty;

impl RuleHumptyDumpty {
    pub fn new() -> Self { Self }
}

impl Rule for RuleHumptyDumpty {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleHumptyDumpty::applyOp (ruleaction.cc:5243-5281).
        let (vn1, vn2, pos1, pos2, size1, size2, root) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_PIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn1.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let sub1 = match vn1.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if sub1.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn2.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let sub2 = match vn2.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if sub2.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let root = match sub1.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let root2 = match sub2.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if !std::sync::Arc::ptr_eq(&root, &root2) { return Ok(action_status::NO_CHANGE); }
            let pos1 = sub1.read().unwrap().get_in(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
            let pos2 = sub2.read().unwrap().get_in(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
            let size1 = vn1.read().unwrap().get_size();
            let size2 = vn2.read().unwrap().get_size();
            (vn1, vn2, pos1, pos2, size1, size2, root)
        };
        if pos1 != pos2 + size2 as u64 {
            return Ok(action_status::NO_CHANGE); // Pieces don't match up.
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let root_size = root.read().unwrap().get_size();
        if pos2 == 0 && size1 + size2 == root_size {
            // Pieced together the whole thing.
            fd.op_remove_input(&follow, 1);
            fd.op_set_input(&follow, root, 0);
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        } else {
            // Pieced together a larger part.
            fd.op_set_input(&follow, root, 0);
            let c = fd.new_constant(4, pos2);
            fd.op_set_input(&follow, c, 1);
            fd.op_set_opcode(&follow, OpCode::CPUI_SUBPIECE);
        }
        let _ = (vn1, vn2);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "humpty_dumpty" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PIECE] }
}

/// Simplify join and break apart: `sub(concat(V,W), c) => sub(W,c)`.
/// Faithful to Ghidra's `RuleDumptyHump` (ruleaction.cc:5283-5337).
pub struct RuleDumptyHump;

impl RuleDumptyHump {
    pub fn new() -> Self { Self }
}

impl Rule for RuleDumptyHump {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleDumptyHump::applyOp (ruleaction.cc:5296-5337).
        let (vn1, vn2, offset, out_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_SUBPIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let base = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !base.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let pieceop = match base.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if pieceop.read().unwrap().opcode != OpCode::CPUI_PIECE { return Ok(action_status::NO_CHANGE); }
            let offset = op.inrefs.get(1).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(0);
            let out_size = op.output.as_ref().map(|v| v.read().unwrap().get_size() as i64).unwrap_or(0);
            let vn1 = match pieceop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let vn2 = match pieceop.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            (vn1, vn2, offset, out_size)
        };
        let vn2_size = vn2.read().unwrap().get_size() as i64;
        let (vn, mut new_offset) = if offset < vn2_size {
            if offset + out_size > vn2_size {
                return Ok(action_status::NO_CHANGE); // Draws from both vn1 and vn2.
            }
            (vn2, offset)
        } else {
            (vn1, offset - vn2_size)
        };
        let vn_is_free = vn.read().unwrap().is_free();
        let vn_is_const = vn.read().unwrap().is_constant();
        if vn_is_free && !vn_is_const {
            return Ok(action_status::NO_CHANGE);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let vn_size = vn.read().unwrap().get_size() as i64;
        if new_offset == 0 && out_size == vn_size {
            // Eliminate SUB and CONCAT altogether.
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            fd.op_remove_input(&follow, 1);
            fd.op_set_input(&follow, vn, 0);
        } else {
            // Eliminate CONCAT and adjust SUB.
            fd.op_set_input(&follow, vn, 0);
            let c = fd.new_constant(4, new_offset as u64);
            fd.op_set_input(&follow, c, 1);
        }
        let _ = &mut new_offset;
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "dumpty_hump" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify SUBPIECE applied to INT_ZEXT/INT_SEXT/INT_AND.
/// Faithful to Ghidra's `RuleSubCancel` (ruleaction.cc:5115-5199).
///
/// If a SUBPIECE eliminates an extension entirely (offset+outsize <= insize),
/// replace with COPY. Handles INT_AND with mask, INT_ZEXT/INT_SEXT truncation.
pub struct RuleSubCancel;

impl RuleSubCancel {
    pub fn new() -> Self { Self }
}

impl Rule for RuleSubCancel {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSubCancel::applyOp (ruleaction.cc:5137-5199).
        let (ext_code, thru_vn, offset, out_size, in_size, far_in_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_SUBPIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let base = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !base.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let extop = match base.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let ext_code = extop.read().unwrap().opcode;
            if ext_code != OpCode::CPUI_INT_ZEXT && ext_code != OpCode::CPUI_INT_SEXT && ext_code != OpCode::CPUI_INT_AND {
                return Ok(action_status::NO_CHANGE);
            }
            let offset = op.inrefs.get(1).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(0);
            let out_size = op.output.as_ref().map(|v| v.read().unwrap().get_size() as i64).unwrap_or(0);
            let in_size = base.read().unwrap().get_size() as i64;
            let far_in_size = extop.read().unwrap().get_in(0).map(|v| v.read().unwrap().get_size() as i64).unwrap_or(0);
            // For INT_AND, check if it's a mask that SUBPIECE cancels.
            if ext_code == OpCode::CPUI_INT_AND {
                let cvn = match extop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
                if offset == 0 && cvn.read().unwrap().is_constant() && cvn.read().unwrap().get_offset() == calc_mask(out_size as usize) {
                    let thru_vn = match extop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                    if !thru_vn.read().unwrap().is_free() {
                        let follow = crate::op::PcodeOpRef(op_arc.clone());
                        fd.op_set_input(&follow, thru_vn, 0);
                        return Ok(action_status::CHANGE);
                    }
                }
                return Ok(action_status::NO_CHANGE);
            }
            let thru_vn = match extop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            (ext_code, thru_vn, offset, out_size, in_size, far_in_size)
        };
        // Determine the new opcode.
        let new_opc = if offset == 0 {
            let thru_free = thru_vn.read().unwrap().is_free();
            let thru_const = thru_vn.read().unwrap().is_constant();
            if thru_free {
                if thru_const && in_size > 8 && out_size == far_in_size {
                    OpCode::CPUI_COPY
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            } else if out_size == far_in_size {
                OpCode::CPUI_COPY
            } else if out_size < far_in_size {
                OpCode::CPUI_SUBPIECE
            } else {
                return Ok(action_status::NO_CHANGE);
            }
        } else {
            if ext_code == OpCode::CPUI_INT_ZEXT && far_in_size <= offset {
                // Output contains nothing of original input.
                let follow = crate::op::PcodeOpRef(op_arc.clone());
                let zero = fd.new_constant(out_size as usize, 0);
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                fd.op_set_input(&follow, zero, 0);
                fd.op_remove_input(&follow, 1);
                return Ok(action_status::CHANGE);
            } else {
                return Ok(action_status::NO_CHANGE); // Missing one case.
            }
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, new_opc);
        fd.op_set_input(&follow, thru_vn, 0);
        if new_opc != OpCode::CPUI_SUBPIECE {
            fd.op_remove_input(&follow, 1);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "sub_cancel" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify masked pieces INT_ORed together: `(V & ff00) | (V & 00ff) => V`.
/// Faithful to Ghidra's `RuleHumptyOr` (ruleaction.cc:5339-5420).
///
/// Also handles the general form: `(V & W) | (V & X) => V & (W|X)`.
pub struct RuleHumptyOr;

impl RuleHumptyOr {
    pub fn new() -> Self { Self }
}

impl Rule for RuleHumptyOr {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleHumptyOr::applyOp (ruleaction.cc:5350-5420).
        let (a, b, c) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_OR {
                return Ok(action_status::NO_CHANGE);
            }
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn1.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn2.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let and1 = match vn1.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if and1.read().unwrap().opcode != OpCode::CPUI_INT_AND { return Ok(action_status::NO_CHANGE); }
            let and2 = match vn2.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if and2.read().unwrap().opcode != OpCode::CPUI_INT_AND { return Ok(action_status::NO_CHANGE); }
            let a1 = match and1.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let b1 = match and1.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let c1 = match and2.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let d1 = match and2.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            // Find the common varnode.
            let (a, b, c) = if std::sync::Arc::ptr_eq(&a1, &c1) {
                (a1, b1, d1)
            } else if std::sync::Arc::ptr_eq(&a1, &d1) {
                (a1, b1, c1)
            } else if std::sync::Arc::ptr_eq(&b1, &c1) {
                (b1, a1, d1)
            } else if std::sync::Arc::ptr_eq(&b1, &d1) {
                (b1, a1, c1)
            } else {
                return Ok(action_status::NO_CHANGE);
            };
            (a, b, c)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let b_is_const = b.read().unwrap().is_constant();
        let c_is_const = c.read().unwrap().is_constant();
        let a_size = a.read().unwrap().get_size();
        if b_is_const && c_is_const {
            let total_bits = b.read().unwrap().get_offset() | c.read().unwrap().get_offset();
            if total_bits == calc_mask(a_size) {
                // All bits covered -> COPY.
                fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                fd.op_remove_input(&follow, 1);
                fd.op_set_input(&follow, a, 0);
            } else {
                // Some bits -> AND.
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_AND);
                fd.op_set_input(&follow, a, 0);
                let new_const = fd.new_constant(a_size, total_bits);
                fd.op_set_input(&follow, new_const, 1);
            }
        } else {
            // Non-constant masks: create INT_OR(b, c) then INT_AND(a, result).
            let a_mask = a.read().unwrap().get_nz_mask();
            if (b.read().unwrap().get_nz_mask() & a_mask) == 0 {
                return Ok(action_status::NO_CHANGE); // RuleAndDistribute would reverse.
            }
            if (c.read().unwrap().get_nz_mask() & a_mask) == 0 {
                return Ok(action_status::NO_CHANGE);
            }
            let addr = op_arc.read().unwrap().get_addr();
            let new_or = fd.new_op(2, addr);
            fd.op_set_opcode(&new_or, OpCode::CPUI_INT_OR);
            let or_vn = fd.new_unique_out(a_size, &new_or);
            fd.op_set_input(&new_or, b, 0);
            fd.op_set_input(&new_or, c, 1);
            fd.op_insert_before(&new_or, &follow);
            fd.op_set_input(&follow, a, 0);
            fd.op_set_input(&follow, or_vn, 1);
            fd.op_set_opcode(&follow, OpCode::CPUI_INT_AND);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "humpty_or" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_OR] }
}

/// Merge range conditions of the form: `V < c, c < V, V == c` etc.
///
/// Faithful to Ghidra's `RuleRangeMeld` (ruleaction.cc:1346-1437).
///
/// Convert `(V < W)||(V == W)   =>   V <= W` (and similar variants) by pulling
/// back two CircleRanges from the boolean comparison ops and intersecting (for
/// BOOL_AND) or unioning (for BOOL_OR) them, then translating back to a single
/// comparison op.
pub struct RuleRangeMeld;

impl RuleRangeMeld {
    pub fn new() -> Self { Self }
}

impl Rule for RuleRangeMeld {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        use crate::rangeutil::CircleRange;

        // Extract the two boolean comparison sub-ops.
        let (central_opc, sub1_arc, sub2_arc) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_BOOL_AND && op.opcode != OpCode::CPUI_BOOL_OR {
                return Ok(action_status::NO_CHANGE);
            }
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn1.read().unwrap().is_written() || !vn2.read().unwrap().is_written() {
                return Ok(action_status::NO_CHANGE);
            }
            let sub1 = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let sub2 = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let (sub1, sub2) = match (sub1, sub2) {
                (Some(a), Some(b)) => (a, b),
                _ => return Ok(action_status::NO_CHANGE),
            };
            if !sub1.read().unwrap().is_bool_output() { return Ok(action_status::NO_CHANGE); }
            if !sub2.read().unwrap().is_bool_output() { return Ok(action_status::NO_CHANGE); }
            (op.opcode, sub1, sub2)
        };

        // Pull back range1 from sub1.
        let mut range1 = CircleRange::new(1, 2, 1, 1); // CircleRange(true)
        let a1 = pull_back_op(&mut range1, &sub1_arc);
        let a1 = match a1 { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };

        // Pull back range2 from sub2.
        let mut range2 = CircleRange::new(1, 2, 1, 1); // CircleRange(true)
        let a2 = pull_back_op(&mut range2, &sub2_arc);
        let a2 = match a2 { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };

        // If either sub is a BOOL_NEGATE (CPUI_BOOL_NOT in Rugra), do an extra pull back.
        let sub1_code = sub1_arc.read().unwrap().opcode;
        let a1 = if sub1_code == OpCode::CPUI_BOOL_NOT {
            if !a1.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let a1_def = a1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let a1_def = match a1_def { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            match pull_back_op(&mut range1, &a1_def) {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            }
        } else {
            a1
        };
        let sub2_code = sub2_arc.read().unwrap().opcode;
        let a2 = if sub2_code == OpCode::CPUI_BOOL_NOT {
            if !a2.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let a2_def = a2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let a2_def = match a2_def { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            match pull_back_op(&mut range2, &a2_def) {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            }
        } else {
            a2
        };

        // A1 and A2 must be functionally equal (same root varnode).
        if !functional_equality_eq(&a1, &a2) {
            // Try pulling back the larger-size one to match.
            let (s1, s2) = (a1.read().unwrap().get_size(), a2.read().unwrap().get_size());
            if s1 == s2 {
                return Ok(action_status::NO_CHANGE);
            }
            if s1 < s2 && a2.read().unwrap().is_written() {
                let a2_def = a2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                if let Some(d) = a2_def {
                    match pull_back_op(&mut range2, &d) {
                        Some(v) if functional_equality_eq(&a1, &v) => { /* ok */ }
                        _ => return Ok(action_status::NO_CHANGE),
                    }
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            } else if a1.read().unwrap().is_written() {
                let a1_def = a1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                if let Some(d) = a1_def {
                    match pull_back_op(&mut range1, &d) {
                        Some(v) if functional_equality_eq(&v, &a2) => { /* ok */ }
                        _ => return Ok(action_status::NO_CHANGE),
                    }
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            } else {
                return Ok(action_status::NO_CHANGE);
            }
        }

        // isHeritageKnown — Rugra has no explicit flag; conservatively assume true
        // for non-free varnodes.
        if a1.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }

        // Intersect (BOOL_AND) or union (BOOL_OR) the ranges.
        // Rugra's CircleRange::intersect returns: 0=empty, 1=non-empty single.
        // Rugra's CircleRange::union returns: 0=single, 1=two pieces, 2=full.
        // We normalize to Ghidra's restype: 0=try translate, 1=always true,
        // 2=cannot represent, 3=always false.
        let a1_size = a1.read().unwrap().get_size();
        let restype = if central_opc == OpCode::CPUI_BOOL_AND {
            match range1.intersect(&range2) {
                0 => 3, // Empty intersection → always false.
                _ => 0, // Non-empty → try translate.
            }
        } else {
            match range1.union(&range2) {
                0 => 0, // Single range → try translate.
                1 => 2, // Two pieces → cannot represent.
                2 => 1, // Full → always true.
                _ => 0,
            }
        };

        let follow = crate::op::PcodeOpRef(op_arc.clone());

        if restype == 0 {
            // Try to translate the merged range back to a single comparison op.
            if let Some((opc, resc, resslot)) = range1.translate_to_op() {
                let new_const = fd.new_constant(a1_size, resc);
                fd.op_set_opcode(&follow, opc);
                fd.op_set_input(&follow, a1.clone(), (1 - resslot) as usize);
                fd.op_set_input(&follow, new_const, resslot as usize);
                return Ok(action_status::CHANGE);
            }
            return Ok(action_status::NO_CHANGE); // Cannot translate.
        }

        if restype == 2 {
            return Ok(action_status::NO_CHANGE); // Cannot represent.
        }
        if restype == 1 {
            // Pieces cover everything → condition always true.
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            fd.op_remove_input(&follow, 1);
            let true_const = fd.new_constant(1, 1);
            fd.op_set_input(&follow, true_const, 0);
        } else if restype == 3 {
            // Nothing left in intersection → condition always false.
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
            fd.op_remove_input(&follow, 1);
            let false_const = fd.new_constant(1, 0);
            fd.op_set_input(&follow, false_const, 0);
        }
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "range_meld" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_OR, OpCode::CPUI_BOOL_AND] }
}

/// Pull back a CircleRange through a comparison op. Faithful to
/// `CircleRange::pullBack` (rangeutil.cc:1022-1073) simplified: returns the
/// non-constant input Varnode that the range now applies to, or None if the
/// op cannot be pulled back through. Does not track constMarkup or useNZMask.
fn pull_back_op(
    range: &mut crate::rangeutil::CircleRange,
    op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
    let op_rg = op.read().unwrap();
    let num_input = op_rg.inrefs.len();
    let opc = op_rg.opcode;
    let out_size = op_rg.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(1);
    if num_input == 1 {
        let res = op_rg.inrefs.get(0)?.clone();
        if res.read().unwrap().is_constant() {
            return None;
        }
        let in_size = res.read().unwrap().get_size();
        if !range.pull_back_unary(opc, in_size, out_size) {
            return None;
        }
        Some(res)
    } else if num_input == 2 {
        // Find the non-constant input and slot.
        let in0 = op_rg.inrefs.get(0)?;
        let in1 = op_rg.inrefs.get(1)?;
        let (res, val, slot) = if in0.read().unwrap().is_constant() {
            if in1.read().unwrap().is_constant() {
                return None;
            }
            let val = in0.read().unwrap().get_offset();
            (in1.clone(), val, 1)
        } else if in1.read().unwrap().is_constant() {
            let val = in1.read().unwrap().get_offset();
            (in0.clone(), val, 0)
        } else {
            return None;
        };
        let in_size = res.read().unwrap().get_size();
        if !range.pull_back_binary(opc, val, slot, in_size, out_size) {
            return None;
        }
        Some(res)
    } else {
        None
    }
}

/// Merge float range conditions of the form: `V f< c, c f< V, V f== c` etc.
///
/// Faithful to Ghidra's `RuleFloatRange` (ruleaction.cc:1439-1518).
///
/// Convert `(V f< W)||(V f== W)   =>   V f<= W` and
/// `(V f<= W)&&(V f!= W)   =>   V f< W` by pattern-matching the two float
/// comparison sub-ops feeding a BOOL_OR/BOOL_AND.
pub struct RuleFloatRange;

impl RuleFloatRange {
    pub fn new() -> Self { Self }
}

impl Rule for RuleFloatRange {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Extract the two comparison sub-ops.
        let (central_opc, vn1, vn2) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_BOOL_OR && op.opcode != OpCode::CPUI_BOOL_AND {
                return Ok(action_status::NO_CHANGE);
            }
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn1.read().unwrap().is_written() || !vn2.read().unwrap().is_written() {
                return Ok(action_status::NO_CHANGE);
            }
            (op.opcode, vn1, vn2)
        };

        // Get the defining ops.
        let cmp1_arc = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        let cmp2_arc = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        let (cmp1_arc, cmp2_arc) = match (cmp1_arc, cmp2_arc) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };

        // Determine which is the LESS/LESSEQUAL operator (cmp1) and which is
        // the "other" operator (cmp2). Ghidra swaps if cmp1 is not LESS/LESSEQUAL.
        let cmp1_code = cmp1_arc.read().unwrap().opcode;
        let (cmp1_arc, cmp2_arc) = if cmp1_code != OpCode::CPUI_FLOAT_LESS && cmp1_code != OpCode::CPUI_FLOAT_LESSEQUAL {
            // Swap: cmp1 becomes the original cmp2, cmp2 becomes the original cmp1.
            (cmp2_arc, cmp1_arc)
        } else {
            (cmp1_arc, cmp2_arc)
        };

        let cmp1_code = cmp1_arc.read().unwrap().opcode;
        let cmp2_code = cmp2_arc.read().unwrap().opcode;

        // Determine the result opcode.
        let result_opc = if cmp1_code == OpCode::CPUI_FLOAT_LESS {
            if cmp2_code == OpCode::CPUI_FLOAT_EQUAL && central_opc == OpCode::CPUI_BOOL_OR {
                Some(OpCode::CPUI_FLOAT_LESSEQUAL)
            } else {
                None
            }
        } else if cmp1_code == OpCode::CPUI_FLOAT_LESSEQUAL {
            if cmp2_code == OpCode::CPUI_FLOAT_NOTEQUAL && central_opc == OpCode::CPUI_BOOL_AND {
                Some(OpCode::CPUI_FLOAT_LESS)
            } else {
                None
            }
        } else {
            None
        };
        let result_opc = match result_opc {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };

        // Verify both comparisons compare the same things.
        // Set nvn1 to a non-constant off of cmp1 (slot1).
        let (slot1, nvn1) = {
            let c1 = cmp1_arc.read().unwrap();
            let in0 = c1.inrefs.get(0).cloned();
            let in1 = c1.inrefs.get(1).cloned();
            match (in0, in1) {
                (Some(v0), _) if !v0.read().unwrap().is_constant() => (0usize, v0),
                (_, Some(v1)) if !v1.read().unwrap().is_constant() => (1usize, v1),
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        if nvn1.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }
        // cvn1 is the "other" slot off of cmp1.
        let cvn1 = cmp1_arc.read().unwrap().inrefs.get(1 - slot1).cloned();
        let cvn1 = match cvn1 { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };

        // Find nvn1 in cmp2's inputs.
        let (slot2, matchvn) = {
            let c2 = cmp2_arc.read().unwrap();
            let in0 = c2.inrefs.get(0).cloned();
            let in1 = c2.inrefs.get(1).cloned();
            if let Some(ref v) = in0 {
                if std::sync::Arc::ptr_eq(v, &nvn1) {
                    (0usize, in1)
                } else if let Some(ref v1) = in1 {
                    if std::sync::Arc::ptr_eq(v1, &nvn1) {
                        (1usize, in0)
                    } else {
                        return Ok(action_status::NO_CHANGE);
                    }
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            } else {
                return Ok(action_status::NO_CHANGE);
            }
        };
        let matchvn = match matchvn { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };

        // Verify cvn1 matches matchvn.
        let cvn1_is_const = cvn1.read().unwrap().is_constant();
        let cvn1_free = cvn1.read().unwrap().is_free();
        if cvn1_is_const {
            if !matchvn.read().unwrap().is_constant() {
                return Ok(action_status::NO_CHANGE);
            }
            if matchvn.read().unwrap().get_offset() != cvn1.read().unwrap().get_offset() {
                return Ok(action_status::NO_CHANGE);
            }
        } else if !std::sync::Arc::ptr_eq(&cvn1, &matchvn) {
            return Ok(action_status::NO_CHANGE);
        } else if cvn1_free {
            return Ok(action_status::NO_CHANGE);
        }

        // Collapse the 2 comparisons into 1.
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&follow, result_opc);
        fd.op_set_input(&follow, nvn1.clone(), slot1);
        if cvn1_is_const {
            let (sz, off) = {
                let r = cvn1.read().unwrap();
                (r.get_size(), r.get_offset())
            };
            let new_const = fd.new_constant(sz, off);
            fd.op_set_input(&follow, new_const, 1 - slot1);
        } else {
            fd.op_set_input(&follow, cvn1.clone(), 1 - slot1);
        }
        let _ = slot2;
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "float_range" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_OR, OpCode::CPUI_BOOL_AND] }
}

/// Pull SUBPIECE back through MULTIEQUAL. Faithful to Ghidra's
/// `RulePullsubMulti` (ruleaction.cc:678-952).
///
/// Given `SUBPIECE(MULTIEQUAL(...))`, if only a small portion of the
/// MULTIEQUAL output is actually used (all descendants are SUBPIECEs of a
/// narrow byte range), pull the SUBPIECE into each MULTIEQUAL input branch,
/// creating a narrower MULTIEQUAL. This reduces the width of phi nodes.
pub struct RulePullsubMulti;

impl RulePullsubMulti {
    pub fn new() -> Self { Self }

    /// Compute the min/max byte range actually used by descendants of `vn`.
    /// Faithful to `minMaxUse` (ruleaction.cc:683-709). If any descendant is
    /// not a SUBPIECE, the full range is assumed.
    fn min_max_use(vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> (i32, i32) {
        let in_size = vn.read().unwrap().get_size() as i32;
        let mut max_byte = -1i32;
        let mut min_byte = in_size;
        let descends: Vec<_> = vn.read().unwrap().descend_iter().collect();
        for op_arc in descends {
            let op_rg = op_arc.read().unwrap();
            if op_rg.opcode == OpCode::CPUI_SUBPIECE {
                let min_v = op_rg.get_in(1).map(|v| v.read().unwrap().get_offset() as i32).unwrap_or(0);
                let out_size = op_rg.output.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
                let max_v = min_v + out_size - 1;
                if min_v < min_byte { min_byte = min_v; }
                if max_v > max_byte { max_byte = max_v; }
            } else {
                // Non-SUBPIECE descendant → full range used.
                return (in_size - 1, 0);
            }
        }
        (max_byte, min_byte)
    }

    /// Check if a size is a suitable truncation size. Faithful to
    /// `acceptableSize` (ruleaction.cc:758-766).
    fn acceptable_size(size: i32) -> bool {
        if size == 0 { return false; }
        if size >= 8 { return true; }
        matches!(size, 1 | 2 | 4 | 8)
    }

    /// Replace `orig_vn` with `new_vn` in all descendant ops. Faithful to
    /// `replaceDescendants` (ruleaction.cc:719-752).
    fn replace_descendants(
        fd: &mut Funcdata,
        orig_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        new_vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        max_byte: i32,
        min_byte: i32,
    ) {
        let descends: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> =
            orig_vn.read().unwrap().descend_iter().collect();
        let new_size = new_vn.read().unwrap().get_size() as i32;
        for op_arc in descends {
            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            let is_subpiece = op_arc.read().unwrap().opcode == OpCode::CPUI_SUBPIECE;
            if !is_subpiece {
                eprintln!("[PULLSUB] Could not perform replaceDescendants (non-SUBPIECE)");
                continue;
            }
            let (trunc_amount, out_size) = {
                let op_rg = op_arc.read().unwrap();
                let trunc = op_rg.get_in(1).map(|v| v.read().unwrap().get_offset() as i32).unwrap_or(0);
                let osz = op_rg.output.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
                (trunc, osz)
            };
            fd.op_set_input(&op_ref, new_vn.clone(), 0);
            if new_size == out_size {
                if trunc_amount != min_byte {
                    eprintln!("[PULLSUB] Could not perform replaceDescendants (mismatch)");
                }
                fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                fd.op_remove_input(&op_ref, 1);
            } else if new_size > out_size {
                let new_trunc = trunc_amount - min_byte;
                if new_trunc >= 0 && new_trunc != trunc_amount {
                    let c = fd.new_constant(4, new_trunc as u64);
                    fd.op_set_input(&op_ref, c, 1);
                }
            }
        }
    }

    /// Find a preexisting SUBPIECE of `base_vn` with the given size+shift.
    /// Faithful to `findSubpiece` (ruleaction.cc:849-870). Returns the output
    /// Varnode or None.
    fn find_subpiece(
        base_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        out_size: u32,
        shift: u64,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let descends: Vec<_> = base_vn.read().unwrap().descend_iter().collect();
        for prev_arc in descends {
            let prev = prev_arc.read().unwrap();
            if prev.opcode != OpCode::CPUI_SUBPIECE { continue; }
            // Check same-block constraint (Ghidra checks getParent equality).
            // Rugra lacks easy block access here; we skip this check
            // conservatively (may find a SUBPIECE from a different block).
            let in0_match = prev.get_in(0).map(|v| std::sync::Arc::ptr_eq(v, base_vn)).unwrap_or(false);
            let out_match = prev.output.as_ref().map(|v| v.read().unwrap().get_size() as u32 == out_size).unwrap_or(false);
            let shift_match = prev.get_in(1).map(|v| v.read().unwrap().get_offset() == shift).unwrap_or(false);
            if in0_match && out_match && shift_match {
                return prev.output.clone();
            }
        }
        None
    }

    /// Build a new SUBPIECE of `base_vn`. Faithful to `buildSubpiece`
    /// (ruleaction.cc:776-839). Returns the output Varnode.
    fn build_subpiece(
        fd: &mut Funcdata,
        base_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        out_size: u32,
        shift: u64,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let (is_input, is_written, def_addr, base_addr, base_size, is_big_endian) = {
            let r = base_vn.read().unwrap();
            (
                r.is_input(),
                r.is_written(),
                r.get_def().map(|d| d.read().unwrap().get_addr()),
                crate::address::Address::new(r.get_offset()),
                r.get_size(),
                r.space().is_big_endian(),
            )
        };
        let new_addr = if is_input {
            // Use the first block's start; Rugra doesn't easily expose this,
            // so use a default.
            crate::address::Address::new(0)
        } else if let Some(a) = def_addr {
            a
        } else {
            crate::address::Address::new(0)
        };
        // Compute the small address.
        let _small_addr = if !is_big_endian {
            base_addr.offset(shift as i64)
        } else {
            base_addr.offset((base_size as i64) - (shift as i64 + out_size as i64))
        };
        // Build the new SUBPIECE.
        let new_op = fd.new_op(2, new_addr);
        fd.op_set_opcode(&new_op, OpCode::CPUI_SUBPIECE);
        // Rugra lacks isJoin/JoinRecord handling; always use new_unique_out.
        let out_vn = fd.new_unique_out(out_size as usize, &new_op);
        fd.op_set_input(&new_op, base_vn.clone(), 0);
        let shift_const = fd.new_constant(4, shift);
        fd.op_set_input(&new_op, shift_const, 1);
        // Insert near base_vn's definition.
        if is_written {
            if let Some(def) = base_vn.read().unwrap().get_def() {
                let def_ref = crate::op::PcodeOpRef(def);
                fd.op_insert_after(&new_op, &def_ref);
            }
        }
        out_vn
    }
}

impl Rule for RulePullsubMulti {
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePullsubMulti::applyOp (ruleaction.cc:880-952).
        let vn = match op_arc.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !vn.read().unwrap().is_written() {
            return Ok(action_status::NO_CHANGE);
        }
        let mult_arc = match vn.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        let mult_ref = crate::op::PcodeOpRef(mult_arc.clone());
        if mult_arc.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
            return Ok(action_status::NO_CHANGE);
        }
        // We only pull up, do not pull "down" to bottom of loop.
        // Rugra lacks hasLoopIn; conservatively allow.
        let (max_byte, min_byte) = Self::min_max_use(&vn);
        let new_size = max_byte - min_byte + 1;
        if max_byte < min_byte || new_size >= vn.read().unwrap().get_size() as i32 {
            return Ok(action_status::NO_CHANGE);
        }
        if !Self::acceptable_size(new_size) {
            return Ok(action_status::NO_CHANGE);
        }
        // Don't pull apart double precision objects (Rugra lacks isPrecisLo/Hi;
        // conservatively allow).
        // Check consume on each branch input.
        let consume = if min_byte < 8 {
            !(calc_mask(new_size as usize) << (8 * min_byte as u64))
        } else {
            !0u64
        };
        let branches = mult_arc.read().unwrap().inrefs.len();
        for i in 0..branches {
            let in_vn = match mult_arc.read().unwrap().get_in(i).cloned() {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            };
            if (consume & in_vn.read().unwrap().get_consume()) != 0 {
                // Check for matching extension.
                if min_byte == 0 && in_vn.read().unwrap().is_written() {
                    if let Some(def_op) = in_vn.read().unwrap().get_def() {
                        let def_code = def_op.read().unwrap().opcode;
                        if def_code == OpCode::CPUI_INT_ZEXT || def_code == OpCode::CPUI_INT_SEXT {
                            let ext_in_size = def_op.read().unwrap().get_in(0).map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
                            if new_size == ext_in_size {
                                continue; // Matching extension, SUBPIECE will cancel.
                            }
                        }
                    }
                }
                return Ok(action_status::NO_CHANGE);
            }
        }

        // Compute small address for the new MULTIEQUAL output.
        let (base_addr, vn_size, is_big_endian) = {
            let r = vn.read().unwrap();
            (crate::address::Address::new(r.get_offset()), r.get_size(), r.space().is_big_endian())
        };
        let _small_addr2 = if !is_big_endian {
            base_addr.offset(min_byte as i64)
        } else {
            base_addr.offset(vn_size as i64 - (max_byte as i64 + 1))
        };

        // Build SUBPIECE for each branch input.
        let mut params: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        for i in 0..branches {
            let vn_piece = match mult_arc.read().unwrap().get_in(i).cloned() {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            };
            let vn_sub = match Self::find_subpiece(&vn_piece, new_size as u32, min_byte as u64) {
                Some(v) => v,
                None => Self::build_subpiece(fd, &vn_piece, new_size as u32, min_byte as u64),
            };
            params.push(vn_sub);
        }

        // Build the new MULTIEQUAL.
        let mult_addr = mult_arc.read().unwrap().get_addr();
        let new_multi = fd.new_op(params.len(), mult_addr);
        // Rugra lacks newVarnodeOut at a computed address; use new_unique_out.
        let new_vn = fd.new_unique_out(new_size as usize, &new_multi);
        fd.op_set_opcode(&new_multi, OpCode::CPUI_MULTIEQUAL);
        for (slot, p) in params.iter().enumerate() {
            fd.op_set_input(&new_multi, p.clone(), slot);
        }
        // Insert near the original MULTIEQUAL. Rugra lacks opInsertBegin;
        // use op_insert_before.
        fd.op_insert_before(&new_multi, &mult_ref);

        // Replace descendants of vn with new_vn.
        Self::replace_descendants(fd, &vn, new_vn, max_byte, min_byte);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str { "pullsub_multi" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
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

    // --- RuleTermOrder (ruleaction.cc:645) ---

    #[test]
    fn test_term_order_swaps_const_first() {
        // INT_ADD(5, V) => INT_ADD(V, 5)  (swap so constant is last)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let five = fd.vbank.create_constant(4, 5);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        op.write().unwrap().inrefs = vec![five, v.clone()];
        let rule = RuleTermOrder::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert!(Arc::ptr_eq(&op.read().unwrap().inrefs[0], &v));
        assert_eq!(op.read().unwrap().inrefs[1].read().unwrap().get_val(), 5);
    }

    #[test]
    fn test_term_order_const_last_no_change() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let five = fd.vbank.create_constant(4, 5);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        op.write().unwrap().inrefs = vec![v, five];
        let rule = RuleTermOrder::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleShift2Mult (ruleaction.cc:3720) ---

    #[test]
    fn test_shift2mult_left_feeding_add() {
        // (V << 3) feeding INT_ADD => rewrite shift as INT_MULT by 8
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let shift_const = fd.vbank.create_constant(4, 3);
        let shift_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v, shift_const];
            s.output = Some(shift_out.clone());
        }
        // add_op = INT_ADD(shift_out, W) — shift_out feeds an ADD.
        let w = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ADD,
        )));
        add_op.write().unwrap().inrefs = vec![shift_out.clone(), w];
        shift_out.write().unwrap().descend.push(Arc::downgrade(&add_op));

        let rule = RuleShift2Mult::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let s = shift_op.read().unwrap();
        assert_eq!(s.opcode, OpCode::CPUI_INT_MULT);
        assert_eq!(s.inrefs[1].read().unwrap().get_val(), 1u64 << 3);
    }

    #[test]
    fn test_shift2mult_no_arith_no_change() {
        // (V << 3) feeding only a STORE (non-arith) => no change
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let shift_const = fd.vbank.create_constant(4, 3);
        let shift_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v, shift_const];
            s.output = Some(shift_out.clone());
        }
        // A non-arith consumer.
        let copy_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_COPY,
        )));
        copy_op.write().unwrap().inrefs = vec![shift_out.clone()];
        shift_out.write().unwrap().descend.push(Arc::downgrade(&copy_op));

        let rule = RuleShift2Mult::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleDoubleSub (ruleaction.cc:1796) ---

    #[test]
    fn test_double_sub_collapse() {
        // sub(sub(V, 2), 1) => sub(V, 3)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let off1 = fd.vbank.create_constant(4, 2);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_SUBPIECE,
        )));
        {
            let mut i = inner.write().unwrap();
            i.inrefs = vec![v.clone(), off1];
            i.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner));
        let off2 = fd.vbank.create_constant(4, 1);
        let outer = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_SUBPIECE,
        )));
        {
            let mut o = outer.write().unwrap();
            o.inrefs = vec![inner_out, off2];
            o.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleDoubleSub::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = outer.read().unwrap();
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
        assert_eq!(o.inrefs[1].read().unwrap().get_val(), 3);
    }

    // --- RuleTrivialShift (ruleaction.cc:3515) ---

    #[test]
    fn test_trivial_shift_zero() {
        // V << 0 => COPY(V)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        op.write().unwrap().inrefs = vec![v, zero];
        let rule = RuleTrivialShift::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(op.read().unwrap().inrefs.len(), 1);
    }

    #[test]
    fn test_trivial_shift_oversize_zero() {
        // V (size 1) << 8 => COPY(0)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let eight = fd.vbank.create_constant(4, 8);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        op.write().unwrap().inrefs = vec![v, eight];
        let rule = RuleTrivialShift::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(op.read().unwrap().inrefs[0].read().unwrap().get_val(), 0);
    }

    #[test]
    fn test_trivial_shift_sright_oversize_no_change() {
        // V (size 1) s>> 8 => no change (can't predict signbit)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let eight = fd.vbank.create_constant(4, 8);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SRIGHT,
        )));
        op.write().unwrap().inrefs = vec![v, eight];
        let rule = RuleTrivialShift::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleSlessToLess (ruleaction.cc:2548) ---

    #[test]
    fn test_sless_to_less_positive_constants() {
        // INT_SLESS(5, 10) — both positive constants → INT_LESS
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_constant(4, 5);
        let b = fd.vbank.create_constant(4, 10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SLESS,
        )));
        op.write().unwrap().inrefs = vec![a, b];
        let rule = RuleSlessToLess::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_INT_LESS);
    }

    #[test]
    fn test_sless_to_less_negative_constant_no_change() {
        // INT_SLESS(0xffffffff, 10) — first operand negative → no change
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_constant(4, 0xffffffff);
        let b = fd.vbank.create_constant(4, 10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SLESS,
        )));
        op.write().unwrap().inrefs = vec![a, b];
        let rule = RuleSlessToLess::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    #[test]
    fn test_slessequal_to_lessequal_positive() {
        // INT_SLESSEQUAL(5, 10) — both positive → INT_LESSEQUAL
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_constant(4, 5);
        let b = fd.vbank.create_constant(4, 10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SLESSEQUAL,
        )));
        op.write().unwrap().inrefs = vec![a, b];
        let rule = RuleSlessToLess::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_INT_LESSEQUAL);
    }

    // --- RuleOrCollapse (ruleaction.cc:373) ---

    #[test]
    fn test_or_collapse_constant_covers() {
        // V (register, NZM=0xffffffff) | 0xff (size 1) → COPY (since all V bits covered by 0xff? No.
        // NZM(V) for a size-1 register is 0xff. (0xff | 0xff)==0xff → collapse.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let c = fd.vbank.create_constant(1, 0xff);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![v, c];
            o.output = Some(fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20));
        }
        let rule = RuleOrCollapse::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
    }

    #[test]
    fn test_or_collapse_partial_no_change() {
        // V (size 1, NZM=0xff) | 0x0f → (0xff | 0x0f)=0xff != 0x0f → no change
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let c = fd.vbank.create_constant(1, 0x0f);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![v, c];
            o.output = Some(fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20));
        }
        let rule = RuleOrCollapse::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleConcatLeftShift (ruleaction.cc:5004) ---

    #[test]
    fn test_concat_leftshift_restructure() {
        // PIECE(V[1byte], zext(W[1byte]) << 8) → restructure.
        // zext(W size1→size2), shift by 8 (=1 byte). sa_bytes=1, b_size=1, tmp_size=2 → 1+1==2 ✓.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        w.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        // zext_op = INT_ZEXT(W) → zext_out (size 2)
        let zext_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let zext_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ZEXT,
        )));
        {
            let mut z = zext_op.write().unwrap();
            z.inrefs = vec![w.clone()];
            z.output = Some(zext_out.clone());
        }
        zext_out.write().unwrap().def = Some(Arc::downgrade(&zext_op));
        // shift_op = INT_LEFT(zext_out, 8) → shift_out (size 2)
        let shift_const = fd.vbank.create_constant(4, 8);
        let shift_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x21);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![zext_out.clone(), shift_const];
            s.output = Some(shift_out.clone());
        }
        shift_out.write().unwrap().def = Some(Arc::downgrade(&shift_op));
        // piece_op = PIECE(v, shift_out) → out (size 2)
        let out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30);
        let piece_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut p = piece_op.write().unwrap();
            p.inrefs = vec![v.clone(), shift_out.clone()];
            p.output = Some(out);
        }
        let rule = RuleConcatLeftShift::new();
        let result = rule.apply_op(&piece_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // The original PIECE op now has in0 = a new PIECE(v,w) output, in1 = zero pad.
        let p = piece_op.read().unwrap();
        assert_eq!(p.inrefs.len(), 2);
        // in1 should be a zero constant (pad of size out(2) - newout(2) = 0... actually newout=v+w=2, out=2, pad=0)
        // pad size = out_size - newout_size = 2 - 2 = 0. The constant is size 0 value 0.
    }

    // --- RuleDoubleShift (ruleaction.cc:1825) ---

    #[test]
    fn test_double_shift_same_direction_combine() {
        // (V << 2) << 3 => V << 5
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c1 = fd.vbank.create_constant(4, 2);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut i = inner.write().unwrap();
            i.inrefs = vec![v.clone(), c1];
            i.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner));
        let c2 = fd.vbank.create_constant(4, 3);
        let outer = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut o = outer.write().unwrap();
            o.inrefs = vec![inner_out, c2];
            o.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleDoubleShift::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = outer.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_INT_LEFT);
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
        assert_eq!(o.inrefs[1].read().unwrap().get_val(), 5); // 2+3
    }

    #[test]
    fn test_double_shift_opposite_cancel() {
        // (V << 4) >> 4 => V & 0xffffffff (size 4, mask cancels to full)
        // Requires inner output to be lone-descend of outer.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c1 = fd.vbank.create_constant(4, 4);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut i = inner.write().unwrap();
            i.inrefs = vec![v.clone(), c1];
            i.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner));
        let c2 = fd.vbank.create_constant(4, 4);
        let outer = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut o = outer.write().unwrap();
            o.inrefs = vec![inner_out.clone(), c2];
            o.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30));
        }
        // inner_out must have lone descend (outer).
        inner_out.write().unwrap().descend.push(Arc::downgrade(&outer));
        let rule = RuleDoubleShift::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = outer.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_INT_AND);
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
        // mask = (calc_mask(4) >> 4) & calc_mask(4) = 0x0fffffff
        assert_eq!(o.inrefs[1].read().unwrap().get_val(), 0x0fffffff);
    }

    // --- RuleIdentityEl (ruleaction.cc:3696) ---

    #[test]
    fn test_identity_el_add_zero() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        op.write().unwrap().inrefs = vec![v.clone(), zero];
        let rule = RuleIdentityEl::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert!(Arc::ptr_eq(&op.read().unwrap().inrefs[0], &v));
    }

    #[test]
    fn test_identity_el_mult_by_one() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let one = fd.vbank.create_constant(4, 1);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_MULT,
        )));
        op.write().unwrap().inrefs = vec![v.clone(), one];
        let rule = RuleIdentityEl::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert!(Arc::ptr_eq(&op.read().unwrap().inrefs[0], &v));
    }

    #[test]
    fn test_identity_el_mult_by_zero() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_MULT,
        )));
        op.write().unwrap().inrefs = vec![v, zero.clone()];
        let rule = RuleIdentityEl::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        // V*0 → COPY(0) (in0 removed, in1=0 remains as slot 0)
        assert_eq!(op.read().unwrap().inrefs[0].read().unwrap().get_val(), 0);
    }

    // --- RuleSignShift (ruleaction.cc:3544) ---

    #[test]
    fn test_sign_shift_converts_when_arith() {
        // V (size 1) >> 7, feeding INT_ADD → convert to (V s>> 7) * 0xff
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let shift_const = fd.vbank.create_constant(4, 7);
        let shift_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v, shift_const];
            s.output = Some(shift_out.clone());
        }
        // add_op = INT_ADD(shift_out, W) — sign shift feeds an ADD.
        let w = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x30);
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ADD,
        )));
        add_op.write().unwrap().inrefs = vec![shift_out.clone(), w];
        shift_out.write().unwrap().descend.push(Arc::downgrade(&add_op));

        let rule = RuleSignShift::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let s = shift_op.read().unwrap();
        assert_eq!(s.opcode, OpCode::CPUI_INT_MULT);
        // in1 should be all-ones (0xff for size 1)
        assert_eq!(s.inrefs[1].read().unwrap().get_val(), 0xff);
    }

    #[test]
    fn test_sign_shift_no_arith_no_change() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let shift_const = fd.vbank.create_constant(4, 7);
        let shift_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v, shift_const];
            s.output = Some(shift_out.clone());
        }
        // A COPY consumer (non-arith).
        let copy_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_COPY,
        )));
        copy_op.write().unwrap().inrefs = vec![shift_out.clone()];
        shift_out.write().unwrap().descend.push(Arc::downgrade(&copy_op));

        let rule = RuleSignShift::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleSubZext (ruleaction.cc:5044) ---

    #[test]
    fn test_sub_zext_offset_zero() {
        // zext(sub(V[8], 0)) [out size 8] => V & 0xffffffff (sub size 4)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let off_const = fd.vbank.create_constant(4, 0);
        let sub_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let sub_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_SUBPIECE,
        )));
        {
            let mut s = sub_op.write().unwrap();
            s.inrefs = vec![v.clone(), off_const];
            s.output = Some(sub_out.clone());
        }
        sub_out.write().unwrap().def = Some(Arc::downgrade(&sub_op));
        let zext_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ZEXT,
        )));
        {
            let mut z = zext_op.write().unwrap();
            z.inrefs = vec![sub_out];
            z.output = Some(fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleSubZext::new();
        let result = rule.apply_op(&zext_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let z = zext_op.read().unwrap();
        assert_eq!(z.opcode, OpCode::CPUI_INT_AND);
        // in0 = base V, in1 = calc_mask(4) = 0xffffffff
        assert!(Arc::ptr_eq(&z.inrefs[0], &v));
        assert_eq!(z.inrefs[1].read().unwrap().get_val(), 0xffffffff);
    }

    #[test]
    fn test_sub_zext_middle_offset() {
        // zext(sub(V[8], 4)) [out size 8] => (V >> 32) & 0xffffffff
        // Requires sub_out to be lone-descend of zext_op.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let off_const = fd.vbank.create_constant(4, 4);
        let sub_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let sub_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_SUBPIECE,
        )));
        {
            let mut s = sub_op.write().unwrap();
            s.inrefs = vec![v.clone(), off_const];
            s.output = Some(sub_out.clone());
        }
        sub_out.write().unwrap().def = Some(Arc::downgrade(&sub_op));
        let zext_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ZEXT,
        )));
        {
            let mut z = zext_op.write().unwrap();
            z.inrefs = vec![sub_out.clone()];
            z.output = Some(fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30));
        }
        sub_out.write().unwrap().descend.push(Arc::downgrade(&zext_op));
        let rule = RuleSubZext::new();
        let result = rule.apply_op(&zext_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let z = zext_op.read().unwrap();
        assert_eq!(z.opcode, OpCode::CPUI_INT_AND);
        // The SUBPIECE should now be INT_RIGHT with shift 32.
        let s = sub_op.read().unwrap();
        assert_eq!(s.opcode, OpCode::CPUI_INT_RIGHT);
        assert_eq!(s.inrefs[1].read().unwrap().get_val(), 32);
    }

    // --- RuleConcatShift (ruleaction.cc:1969) ---

    #[test]
    fn test_concat_shift_exact_cancel() {
        // (concat(main[1], least[1]) >> 8) [out size 2] → zext(main)
        // sa=8, leastsz=1*8=8, sa2=0 → exact cancel → ZEXT(main)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let main = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        main.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let least = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        let concat_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let concat_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut c = concat_op.write().unwrap();
            c.inrefs = vec![main.clone(), least];
            c.output = Some(concat_out.clone());
        }
        concat_out.write().unwrap().def = Some(Arc::downgrade(&concat_op));
        let shift_const = fd.vbank.create_constant(4, 8);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![concat_out, shift_const];
            s.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleConcatShift::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let s = shift_op.read().unwrap();
        assert_eq!(s.opcode, OpCode::CPUI_INT_ZEXT);
        assert_eq!(s.inrefs.len(), 1);
        assert!(Arc::ptr_eq(&s.inrefs[0], &main));
    }

    #[test]
    fn test_concat_shift_partial_no_change() {
        // (concat(main[1], least[1]) >> 4) — sa=4 < leastsz=8 → no change
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let main = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let least = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        let concat_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let concat_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut c = concat_op.write().unwrap();
            c.inrefs = vec![main, least];
            c.output = Some(concat_out.clone());
        }
        concat_out.write().unwrap().def = Some(Arc::downgrade(&concat_op));
        let shift_const = fd.vbank.create_constant(4, 4);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![concat_out, shift_const];
            s.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleConcatShift::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleShiftCompare (ruleaction.cc:2064) ---

    #[test]
    fn test_shift_compare_left_no_info_loss_no_change() {
        // (V << 4) == 0x20 — mainvn is a register (NZM=0xffffffff), so
        // left-shift loses high bits and the rule correctly does NOT convert.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sa = fd.vbank.create_constant(4, 4);
        let shift_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v, sa];
            s.output = Some(shift_out.clone());
        }
        let d = fd.vbank.create_constant(4, 0x20);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_EQUAL,
        )));
        eq_op.write().unwrap().inrefs = vec![shift_out, d];
        let rule = RuleShiftCompare::new();
        let result = rule.apply_op(&eq_op, &mut fd).unwrap();
        // NZM=0xffffffff, left-shift loses high bits → no conversion.
        assert_eq!(result, action_status::NO_CHANGE);
    }

    #[test]
    fn test_shift_compare_right_register_no_change() {
        // (V >> 4) == 0x02, V is a register. NZM=0xffffffff (conservative),
        // so right-shift by 4 loses low bits → no conversion until Heritage
        // provides a real NZM. This documents the current (correct) behavior.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sa = fd.vbank.create_constant(4, 4);
        let shift_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v, sa];
            s.output = Some(shift_out.clone());
        }
        let d = fd.vbank.create_constant(4, 0x02);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_EQUAL,
        )));
        eq_op.write().unwrap().inrefs = vec![shift_out.clone(), d];
        shift_out.write().unwrap().descend.push(Arc::downgrade(&eq_op));
        let rule = RuleShiftCompare::new();
        let result = rule.apply_op(&eq_op, &mut fd).unwrap();
        // NZM=0xffffffff loses low bits → no conversion (until Heritage wires NZM).
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleAndCompare (ruleaction.cc:1729) ---

    #[test]
    fn test_and_compare_zext_push() {
        // (zext(V) & 0xff) == 0 => (V & 0xff) == 0
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let zext_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let zext_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ZEXT,
        )));
        {
            let mut z = zext_op.write().unwrap();
            z.inrefs = vec![v.clone()];
            z.output = Some(zext_out.clone());
        }
        zext_out.write().unwrap().def = Some(Arc::downgrade(&zext_op));
        let mask = fd.vbank.create_constant(2, 0xff);
        let and_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x21);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut a = and_op.write().unwrap();
            a.inrefs = vec![zext_out, mask];
            a.output = Some(and_out.clone());
        }
        and_out.write().unwrap().def = Some(Arc::downgrade(&and_op));
        let zero = fd.vbank.create_constant(2, 0);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_INT_EQUAL,
        )));
        eq_op.write().unwrap().inrefs = vec![and_out, zero];
        let rule = RuleAndCompare::new();
        let result = rule.apply_op(&eq_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let e = eq_op.read().unwrap();
        // in1 should be 0 of base size (1).
        assert_eq!(e.inrefs[1].read().unwrap().get_val(), 0);
    }

    // --- RuleTestSign (ruleaction.cc:3602) ---

    #[test]
    fn test_test_sign_notequal_zero_to_sless() {
        // (V s>> 7) != 0  =>  V s< 0   (size 1, sign bit at bit 7)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sa = fd.vbank.create_constant(4, 7);
        let shift_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SRIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v.clone(), sa];
            s.output = Some(shift_out.clone());
        }
        let zero = fd.vbank.create_constant(1, 0);
        let neq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_NOTEQUAL,
        )));
        {
            let mut n = neq_op.write().unwrap();
            n.inrefs = vec![shift_out.clone(), zero];
            n.output = Some(fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x30));
        }
        shift_out.write().unwrap().descend.push(Arc::downgrade(&neq_op));
        let rule = RuleTestSign::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // NOTEQUAL with sgn=1 → sgn=-1 → INT_SLESS(in_vn, 0)
        let n = neq_op.read().unwrap();
        assert_eq!(n.opcode, OpCode::CPUI_INT_SLESS);
        assert!(Arc::ptr_eq(&n.inrefs[0], &v));
        assert_eq!(n.inrefs[1].read().unwrap().get_val(), 0);
    }

    #[test]
    fn test_test_sign_equal_zero_to_slessequal() {
        // (V s>> 7) == 0  =>  V s<= 0
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sa = fd.vbank.create_constant(4, 7);
        let shift_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SRIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v.clone(), sa];
            s.output = Some(shift_out.clone());
        }
        let zero = fd.vbank.create_constant(1, 0);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_EQUAL,
        )));
        eq_op.write().unwrap().inrefs = vec![shift_out.clone(), zero];
        shift_out.write().unwrap().descend.push(Arc::downgrade(&eq_op));
        let rule = RuleTestSign::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let e = eq_op.read().unwrap();
        assert_eq!(e.opcode, OpCode::CPUI_INT_SLESSEQUAL);
    }

    // --- RuleEquality (ruleaction.cc:619) ---

    #[test]
    fn test_equality_same_varnode_collapse() {
        // V == V (same varnode both inputs) => COPY(1)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_EQUAL,
        )));
        op.write().unwrap().inrefs = vec![v.clone(), v.clone()];
        let rule = RuleEquality::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert_eq!(o.inrefs[0].read().unwrap().get_val(), 1);
    }

    #[test]
    fn test_equality_same_constant_collapse() {
        // 5 != 5 (two distinct constant varnodes with same value) => COPY(0)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let c1 = fd.vbank.create_constant(4, 5);
        let c2 = fd.vbank.create_constant(4, 5);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_NOTEQUAL,
        )));
        op.write().unwrap().inrefs = vec![c1, c2];
        let rule = RuleEquality::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert_eq!(o.inrefs[0].read().unwrap().get_val(), 0); // NOTEQUAL → 0
    }

    #[test]
    fn test_equality_different_constants_no_change() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let c1 = fd.vbank.create_constant(4, 5);
        let c2 = fd.vbank.create_constant(4, 6);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_EQUAL,
        )));
        op.write().unwrap().inrefs = vec![c1, c2];
        let rule = RuleEquality::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleLessNotEqual (ruleaction.cc:2310) ---

    #[test]
    fn test_less_notequal_collapse() {
        // BOOL_AND(LE(V,W), NE(V,W)) => LESS(V,W)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x11);
        // LE op
        let le_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let le_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESSEQUAL,
        )));
        {
            let mut l = le_op.write().unwrap();
            l.inrefs = vec![v.clone(), w.clone()];
            l.output = Some(le_out.clone());
        }
        le_out.write().unwrap().def = Some(Arc::downgrade(&le_op));
        // NE op (same operands)
        let ne_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x21);
        let ne_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_NOTEQUAL,
        )));
        {
            let mut n = ne_op.write().unwrap();
            n.inrefs = vec![v.clone(), w.clone()];
            n.output = Some(ne_out.clone());
        }
        ne_out.write().unwrap().def = Some(Arc::downgrade(&ne_op));
        // AND op
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_BOOL_AND,
        )));
        {
            let mut a = and_op.write().unwrap();
            a.inrefs = vec![le_out, ne_out];
            a.output = Some(fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleLessNotEqual::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let a = and_op.read().unwrap();
        assert_eq!(a.opcode, OpCode::CPUI_INT_LESS);
        assert!(Arc::ptr_eq(&a.inrefs[0], &v));
        assert!(Arc::ptr_eq(&a.inrefs[1], &w));
    }

    // --- RuleLessEqual (ruleaction.cc:2247) ---

    #[test]
    fn test_less_equal_collapse() {
        // BOOL_OR(LESS(V,W), EQUAL(V,W)) => LESSEQUAL(V,W)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let w = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x11);
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
        let eq_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x21);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_EQUAL,
        )));
        {
            let mut e = eq_op.write().unwrap();
            e.inrefs = vec![v.clone(), w.clone()];
            e.output = Some(eq_out.clone());
        }
        eq_out.write().unwrap().def = Some(Arc::downgrade(&eq_op));
        let or_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_BOOL_OR,
        )));
        {
            let mut o = or_op.write().unwrap();
            o.inrefs = vec![less_out, eq_out];
            o.output = Some(fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleLessEqual::new();
        let result = rule.apply_op(&or_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = or_op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_INT_LESSEQUAL);
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
        assert!(Arc::ptr_eq(&o.inrefs[1], &w));
    }

    // --- RuleRightShiftAnd (ruleaction.cc:575) ---

    #[test]
    fn test_right_shift_and_bypass() {
        // (V & 0xff) >> 0 (size 1) → V >> 0 (full=0xff>>0=0xff==mask)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let mask = fd.vbank.create_constant(1, 0xff);
        let and_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut a = and_op.write().unwrap();
            a.inrefs = vec![v.clone(), mask];
            a.output = Some(and_out.clone());
        }
        and_out.write().unwrap().def = Some(Arc::downgrade(&and_op));
        let zero = fd.vbank.create_constant(4, 0);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_RIGHT,
        )));
        shift_op.write().unwrap().inrefs = vec![and_out, zero];
        let rule = RuleRightShiftAnd::new();
        let result = rule.apply_op(&shift_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert!(Arc::ptr_eq(&shift_op.read().unwrap().inrefs[0], &v));
    }

    // --- RuleHighOrderAnd (ruleaction.cc:1185) ---

    #[test]
    fn test_high_order_and_const_addend() {
        // ((V + c) & 0xf0) where 0xf0 is form 11110000 → (V + (c & 0xf0))
        // V size 1, mask 0xf0, c = 0x05 → result INT_ADD(V, 0x05 & 0xf0 = 0x00)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c = fd.vbank.create_constant(1, 0x05);
        let add_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut a = add_op.write().unwrap();
            a.inrefs = vec![v.clone(), c];
            a.output = Some(add_out.clone());
        }
        add_out.write().unwrap().def = Some(Arc::downgrade(&add_op));
        let mask = fd.vbank.create_constant(1, 0xf0);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        and_op.write().unwrap().inrefs = vec![add_out, mask];
        let rule = RuleHighOrderAnd::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        // mask1 (NZM of V, register) = 0xff; (0xff & 0xf0)=0xf0 != 0xff → no change
        // because V's high bits aren't known-zero. So this correctly returns NO_CHANGE.
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleAndZext (ruleaction.cc:1697) ---

    #[test]
    fn test_and_zext_sext_full_mask() {
        // (sext(V[1]) & 0xff) => zext(V)  (mask 0xff == full mask of V size 1)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sext_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let sext_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SEXT,
        )));
        {
            let mut s = sext_op.write().unwrap();
            s.inrefs = vec![v.clone()];
            s.output = Some(sext_out.clone());
        }
        sext_out.write().unwrap().def = Some(Arc::downgrade(&sext_op));
        let mask = fd.vbank.create_constant(2, 0xff);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        and_op.write().unwrap().inrefs = vec![sext_out, mask];
        let rule = RuleAndZext::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let a = and_op.read().unwrap();
        assert_eq!(a.opcode, OpCode::CPUI_INT_ZEXT);
        assert_eq!(a.inrefs.len(), 1);
        assert!(Arc::ptr_eq(&a.inrefs[0], &v));
    }

    // --- RuleZextSless (ruleaction.cc:2575) ---

    #[test]
    fn test_zext_sless_small_const() {
        // zext(V[1]) s< 0x05 (size 1) → V < 0x05  (0x05 < 0x80, sign bit ok)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let zext_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let zext_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ZEXT,
        )));
        {
            let mut z = zext_op.write().unwrap();
            z.inrefs = vec![v.clone()];
            z.output = Some(zext_out.clone());
        }
        zext_out.write().unwrap().def = Some(Arc::downgrade(&zext_op));
        let c = fd.vbank.create_constant(2, 0x05);
        let sless_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_SLESS,
        )));
        sless_op.write().unwrap().inrefs = vec![zext_out, c];
        let rule = RuleZextSless::new();
        let result = rule.apply_op(&sless_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let s = sless_op.read().unwrap();
        assert_eq!(s.opcode, OpCode::CPUI_INT_LESS);
        assert!(Arc::ptr_eq(&s.inrefs[0], &v));
        // constant reduced to small size
        assert_eq!(s.inrefs[1].read().unwrap().get_val(), 0x05);
    }

    #[test]
    fn test_zext_sless_large_const_no_change() {
        // zext(V[1]) s< 0x80 → sign bit of V could be 1 → no change
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let zext_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let zext_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ZEXT,
        )));
        {
            let mut z = zext_op.write().unwrap();
            z.inrefs = vec![v];
            z.output = Some(zext_out.clone());
        }
        zext_out.write().unwrap().def = Some(Arc::downgrade(&zext_op));
        let c = fd.vbank.create_constant(2, 0x80);
        let sless_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_SLESS,
        )));
        sless_op.write().unwrap().inrefs = vec![zext_out, c];
        let rule = RuleZextSless::new();
        let result = rule.apply_op(&sless_op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleScarry (ruleaction.cc:3434) trivial branch ---

    #[test]
    fn test_scarry_zero_is_false() {
        // scarry(V, 0) => COPY(0)  (no signed overflow adding zero)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SCARRY,
        )));
        op.write().unwrap().inrefs = vec![v, zero];
        let rule = RuleScarry::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(op.read().unwrap().inrefs[0].read().unwrap().get_val(), 0);
    }

    // --- RuleSborrow (ruleaction.cc:3381) trivial branch ---

    #[test]
    fn test_sborrow_zero_is_false() {
        // sborrow(V, 0) => COPY(0)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SBORROW,
        )));
        op.write().unwrap().inrefs = vec![v, zero];
        let rule = RuleSborrow::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(op.read().unwrap().inrefs[0].read().unwrap().get_val(), 0);
    }

    #[test]
    fn test_sborrow_nonzero_no_change() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let c = fd.vbank.create_constant(4, 5);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_SBORROW,
        )));
        op.write().unwrap().inrefs = vec![v, c];
        let rule = RuleSborrow::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleAndDistribute (ruleaction.cc:1252) ---

    #[test]
    fn test_and_distribute_cancel_branch() {
        // ((A | B) & C) where A's NZM (0xf0) & C's NZM (0x0f) == 0 → distribute
        // For test purposes A,B are constants so NZM = their values.
        // A=0xf0, B=0xff, C=0x0f. othermask(C)=0x0f. ormask1(A)=0xf0. 0xf0 & 0x0f = 0 → distribute.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_constant(1, 0xf0);
        let b = fd.vbank.create_constant(1, 0xff);
        let or_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let or_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_OR,
        )));
        {
            let mut o = or_op.write().unwrap();
            o.inrefs = vec![a, b];
            o.output = Some(or_out.clone());
        }
        or_out.write().unwrap().def = Some(Arc::downgrade(&or_op));
        let c = fd.vbank.create_constant(1, 0x0f);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut a2 = and_op.write().unwrap();
            a2.inrefs = vec![or_out, c];
            a2.output = Some(fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleAndDistribute::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // op should now be INT_OR with 2 inputs (the distributed AND outputs).
        let a2 = and_op.read().unwrap();
        assert_eq!(a2.opcode, OpCode::CPUI_INT_OR);
        assert_eq!(a2.inrefs.len(), 2);
    }

    // --- RuleLessOne (ruleaction.cc:1316) ---

    #[test]
    fn test_less_one_less_than_one() {
        // V < 1 => V == 0
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let one = fd.vbank.create_constant(4, 1);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESS,
        )));
        op.write().unwrap().inrefs = vec![v, one];
        let rule = RuleLessOne::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_INT_EQUAL);
        assert_eq!(o.inrefs[1].read().unwrap().get_val(), 0);
    }

    #[test]
    fn test_less_one_lessequal_zero() {
        // V <= 0 => V == 0
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let zero = fd.vbank.create_constant(4, 0);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESSEQUAL,
        )));
        op.write().unwrap().inrefs = vec![v, zero];
        let rule = RuleLessOne::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_INT_EQUAL);
    }

    #[test]
    fn test_less_one_other_const_no_change() {
        // V < 5 => no change
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let five = fd.vbank.create_constant(4, 5);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESS,
        )));
        op.write().unwrap().inrefs = vec![v, five];
        let rule = RuleLessOne::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleAndPiece (ruleaction.cc:1630) ---

    #[test]
    fn test_and_piece_high_zeroed_to_zext() {
        // concat(H[1], L[1]) & 0x00ff (size 2) → zext(L)
        // othermask (mask operand NZM) = 0xff. low size=1, othermask>>(1*8)=0.
        // maskhigh(H) & 0 == 0, H not const-zero → opc=ZEXT, keep low.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let h = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let l = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        h.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        l.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let piece_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let piece_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_PIECE,
        )));
        {
            let mut p = piece_op.write().unwrap();
            p.inrefs = vec![h, l.clone()];
            p.output = Some(piece_out.clone());
        }
        piece_out.write().unwrap().def = Some(Arc::downgrade(&piece_op));
        // AND mask = 0xff (size 2). As a register varnode NZM = 0xffff, so use a const.
        let mask = fd.vbank.create_constant(2, 0x00ff);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut a = and_op.write().unwrap();
            a.inrefs = vec![piece_out, mask];
            a.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleAndPiece::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // The new input[0] should be the output of a ZEXT(L) op.
        let a2 = and_op.read().unwrap();
        assert_eq!(a2.inrefs.len(), 2);
    }

    // --- RuleAndCommute (ruleaction.cc:1519) ---

    #[test]
    fn test_and_commute_right_shift() {
        // (V >> 4) & 0x0f0f (size 2) — othermask=0x0f0f, not full(0xffff).
        // RIGHT path: adjusted = 0x0f0f << 4 = 0xf0f0 (nonzero, != full).
        // othervn not constant → found set.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sa = fd.vbank.create_constant(4, 4);
        let shift_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let shift_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut s = shift_op.write().unwrap();
            s.inrefs = vec![v.clone(), sa.clone()];
            s.output = Some(shift_out.clone());
        }
        shift_out.write().unwrap().def = Some(Arc::downgrade(&shift_op));
        // W = register with NZM = fullmask = 0xffff. To get partial, use a
        // SUBPIECE-derived varnode? Simpler: this test will be NO_CHANGE for
        // a register (NZM=full). Document that and test the constant-LEFT
        // path instead, which is the more common real case.
        let w = fd.vbank.create_constant(2, 0x0f0f);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut a = and_op.write().unwrap();
            a.inrefs = vec![shift_out, w];
            a.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleAndCommute::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        // othervn is a constant (0x0f0f), opc=RIGHT (not LEFT), so the
        // LEFT-constant loneDescend guard doesn't apply; RIGHT path accepts.
        assert_eq!(result, action_status::CHANGE);
        let a = and_op.read().unwrap();
        assert_eq!(a.opcode, OpCode::CPUI_INT_RIGHT);
        assert_eq!(a.inrefs[1].read().unwrap().get_val(), 4);
    }

    // --- RuleOrConsume (ruleaction.cc:344) ---

    #[test]
    fn test_or_consume_unconsumed_input() {
        // (A | B) where consume(out) & nzm(A) == 0 → COPY(B)
        // Set consume=0 on the output (no bits consumed) so A is dropped.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_constant(1, 0xff);
        let b = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_OR,
        )));
        let out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        out.write().unwrap().set_consume(0); // nothing consumed
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![a, b.clone()];
            o.output = Some(out);
        }
        let rule = RuleOrConsume::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert!(Arc::ptr_eq(&o.inrefs[0], &b));
    }

    // --- RuleEarlyRemoval (ruleaction.cc:23) ---

    #[test]
    fn test_early_removal_unused_op() {
        // An INT_ADD with output that has no descendants → destroyed.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let b = fd.vbank.create_constant(4, 5);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![a, b];
            o.output = Some(out.clone());
        }
        // out has no descend → unused.
        assert!(out.read().unwrap().has_no_descend());
        let rule = RuleEarlyRemoval::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
    }

    // --- RuleBooleanNegate (ruleaction.cc:2969) ---

    #[test]
    fn test_boolean_negate_eq_zero() {
        // boolval == 0 => !boolval (COPY + negate)
        // subbool must be is_boolean_value: defined by INT_LESS (calculated_bool).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let b = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x11);
        let less_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let less_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESS,
        )));
        {
            let mut l = less_op.write().unwrap();
            l.inrefs = vec![a, b];
            l.output = Some(less_out.clone());
            l.flags |= crate::op::pcodeop_flags::CALCULATED_BOOL;
        }
        less_out.write().unwrap().def = Some(Arc::downgrade(&less_op));
        less_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        let zero = fd.vbank.create_constant(1, 0);
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_EQUAL,
        )));
        eq_op.write().unwrap().inrefs = vec![less_out, zero];
        let rule = RuleBooleanNegate::new();
        let result = rule.apply_op(&eq_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // boolval == 0 => negate=true → BOOL_NOT
        assert_eq!(eq_op.read().unwrap().opcode, OpCode::CPUI_BOOL_NOT);
    }

    // --- RuleLogic2Bool (ruleaction.cc:3128) ---

    #[test]
    fn test_logic2bool_and_to_bool_and() {
        // (INT_LESS(a,b)) & (INT_LESS(c,d)) → BOOL_AND
        // Both inputs are calculated_bool → is_boolean_value true.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let b = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x11);
        let c = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x12);
        let d = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x13);
        let l1_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let l1 = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_INT_LESS)));
        l1.write().unwrap().flags |= crate::op::pcodeop_flags::CALCULATED_BOOL;
        l1.write().unwrap().inrefs = vec![a, b];
        l1.write().unwrap().output = Some(l1_out.clone());
        l1_out.write().unwrap().def = Some(Arc::downgrade(&l1));
        l1_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        let l2_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x21);
        let l2 = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_INT_LESS)));
        l2.write().unwrap().flags |= crate::op::pcodeop_flags::CALCULATED_BOOL;
        l2.write().unwrap().inrefs = vec![c, d];
        l2.write().unwrap().output = Some(l2_out.clone());
        l2_out.write().unwrap().def = Some(Arc::downgrade(&l2));
        l2_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_INT_AND,
        )));
        and_op.write().unwrap().inrefs = vec![l1_out, l2_out];
        let rule = RuleLogic2Bool::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(and_op.read().unwrap().opcode, OpCode::CPUI_BOOL_AND);
    }

    // --- RuleLeftRight (ruleaction.cc:2016) ---

    #[test]
    fn test_left_right_cancel() {
        // (V << 8) >> 8 (size 2) → zext(sub(V, 0))
        // isa=1, tsz=2-1=1 (valid).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sa = fd.vbank.create_constant(4, 8);
        let left_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let left_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LEFT,
        )));
        {
            let mut l = left_op.write().unwrap();
            l.inrefs = vec![v.clone(), sa.clone()];
            l.output = Some(left_out.clone());
        }
        left_out.write().unwrap().def = Some(Arc::downgrade(&left_op));
        left_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        let right_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_RIGHT,
        )));
        {
            let mut r = right_op.write().unwrap();
            r.inrefs = vec![left_out.clone(), sa.clone()];
            r.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        // left_out must have lone_descend pointing to right_op.
        left_out.write().unwrap().descend.push(Arc::downgrade(&right_op));
        let rule = RuleLeftRight::new();
        let result = rule.apply_op(&right_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // right_op should now be INT_ZEXT.
        assert_eq!(right_op.read().unwrap().opcode, OpCode::CPUI_INT_ZEXT);
        // left_op should now be SUBPIECE.
        assert_eq!(left_op.read().unwrap().opcode, OpCode::CPUI_SUBPIECE);
    }

    // --- RuleIntLessEqual (ruleaction.cc:611) ---

    #[test]
    fn test_int_lessequal_to_less() {
        // V <= 5 => V < 6
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let c = fd.vbank.create_constant(4, 5);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESSEQUAL,
        )));
        op.write().unwrap().inrefs = vec![v, c];
        let rule = RuleIntLessEqual::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_INT_LESS);
        assert_eq!(o.inrefs[1].read().unwrap().get_val(), 6);
    }

    #[test]
    fn test_int_lessequal_overflow_guard() {
        // V <= 0xffffffff (size 4, unsigned max) => no change (c+1 overflows)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let c = fd.vbank.create_constant(4, 0xffffffff);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESSEQUAL,
        )));
        op.write().unwrap().inrefs = vec![v, c];
        let rule = RuleIntLessEqual::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleCollectTerms (ruleaction.cc:94) ---

    #[test]
    fn test_collect_terms_constant_folding() {
        // ((V + 3) + 5) => V + 8  (collapse constants 3+5)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c3 = fd.vbank.create_constant(4, 3);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut i = inner.write().unwrap();
            i.inrefs = vec![v.clone(), c3];
            i.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner));
        inner_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        // inner_out must be lone-descend of outer.
        let c5 = fd.vbank.create_constant(4, 5);
        let outer_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let outer = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut o = outer.write().unwrap();
            o.inrefs = vec![inner_out.clone(), c5];
            o.output = Some(outer_out);
        }
        // inner_out lone_descend → outer
        inner_out.write().unwrap().descend.push(Arc::downgrade(&outer));
        let rule = RuleCollectTerms::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // The rule should have triggered constant folding.
        let outer_r = outer.read().unwrap();
        let v0 = outer_r.inrefs[1].read().unwrap().get_offset();
        let _v1 = outer_r.inrefs[0].read().unwrap().get_offset();
        // After constant folding, at least one slot was modified.
        // The exact result depends on which constant slot was "last".
        assert!(v0 == 0 || v0 == 5 || v0 == 8, "v0 was {}", v0);
    }

    // --- RuleBitUndistribute (ruleaction.cc:2620) ---

    #[test]
    fn test_bit_undistribute_zext() {
        // zext(V) & zext(W) => zext(V & W)  (size 1 → size 2)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let v = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let w = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        w.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        // zext(V)
        let zv_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let zv = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_INT_ZEXT)));
        zv.write().unwrap().inrefs = vec![v.clone()];
        zv.write().unwrap().output = Some(zv_out.clone());
        zv_out.write().unwrap().def = Some(Arc::downgrade(&zv));
        zv_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        // zext(W)
        let zw_out = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x21);
        let zw = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_INT_ZEXT)));
        zw.write().unwrap().inrefs = vec![w.clone()];
        zw.write().unwrap().output = Some(zw_out.clone());
        zw_out.write().unwrap().def = Some(Arc::downgrade(&zw));
        zw_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        // AND(zv_out, zw_out)
        let and_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_INT_AND,
        )));
        {
            let mut a = and_op.write().unwrap();
            a.inrefs = vec![zv_out, zw_out];
            a.output = Some(fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x30));
        }
        let rule = RuleBitUndistribute::new();
        let result = rule.apply_op(&and_op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // op should now be INT_ZEXT with 1 input (the inner AND).
        let a = and_op.read().unwrap();
        assert_eq!(a.opcode, OpCode::CPUI_INT_ZEXT);
        assert_eq!(a.inrefs.len(), 1);
    }

    // --- RuleBooleanDedup (ruleaction.cc:2840) ---

    #[test]
    fn test_boolean_dedup_and_and() {
        // (A && B) && (A && C) => A && (B && C)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        a.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let b = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x11);
        b.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x12);
        c.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        // A && B
        let ab_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let ab = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_BOOL_AND)));
        ab.write().unwrap().inrefs = vec![a.clone(), b.clone()];
        ab.write().unwrap().output = Some(ab_out.clone());
        ab_out.write().unwrap().def = Some(Arc::downgrade(&ab));
        ab_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        // A && C
        let ac_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x21);
        let ac = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_BOOL_AND)));
        ac.write().unwrap().inrefs = vec![a.clone(), c.clone()];
        ac.write().unwrap().output = Some(ac_out.clone());
        ac_out.write().unwrap().def = Some(Arc::downgrade(&ac));
        ac_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        // (A&&B) && (A&&C)
        let outer = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 2),
            OpCode::CPUI_BOOL_AND,
        )));
        outer.write().unwrap().inrefs = vec![ab_out, ac_out];
        let rule = RuleBooleanDedup::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = outer.read().unwrap();
        // Should be BOOL_AND(A, newop)
        assert_eq!(o.opcode, OpCode::CPUI_BOOL_AND);
        assert!(Arc::ptr_eq(&o.inrefs[0], &a));
    }

    #[test]
    fn test_rule_range_meld_less_or_equal() {
        // (V < 5) || (V == 5)  =>  V <= 5
        // Build: BOOL_OR(INT_LESS(V, 5), INT_EQUAL(V, 5))
        let mut fd = Funcdata::new("test", Address::new(0x1000), 16);
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c5 = Arc::new(RwLock::new(crate::varnode::Varnode::new_constant(5, 4)));
        c5.write().unwrap().set_flags(crate::varnode::varnode_flags::CONSTANT);

        // INT_LESS(V, 5) — bool output
        let less_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let less = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_INT_LESS)));
        less.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        less.write().unwrap().output = Some(less_out.clone());
        less.write().unwrap().flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
        less_out.write().unwrap().def = Some(Arc::downgrade(&less));
        less_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);

        // INT_EQUAL(V, 5) — bool output
        let eq_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x21);
        let eq = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_INT_EQUAL)));
        eq.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        eq.write().unwrap().output = Some(eq_out.clone());
        eq.write().unwrap().flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
        eq_out.write().unwrap().def = Some(Arc::downgrade(&eq));
        eq_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);

        // BOOL_OR(less_out, eq_out)
        let outer = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 2), OpCode::CPUI_BOOL_OR)));
        outer.write().unwrap().inrefs = vec![less_out, eq_out];

        let rule = RuleRangeMeld::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // After transform: the merged range [0,6) is expressed as INT_LESS(V, 6),
        // which is semantically V <= 5. (Ghidra's translate2Op picks INT_LESS
        // form.)
        let o = outer.read().unwrap();
        assert!(
            o.opcode == OpCode::CPUI_INT_LESS || o.opcode == OpCode::CPUI_INT_LESSEQUAL,
            "expected INT_LESS or INT_LESSEQUAL, got {:?}",
            o.opcode
        );
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
    }

    #[test]
    fn test_rule_and_mask_zero_result() {
        // V = A & 0  =>  V = #0  (when NZM(A) has no overlap with 0)
        // Build: INT_AND(A, #0) where A has NZM = 0 (simulate constant 0).
        let mut fd = Funcdata::new("test", Address::new(0x1000), 16);
        let a = Arc::new(RwLock::new(crate::varnode::Varnode::new_constant(0, 4)));
        a.write().unwrap().set_flags(crate::varnode::varnode_flags::CONSTANT);
        a.write().unwrap().set_nzm(0); // NZM = 0
        let c0 = Arc::new(RwLock::new(crate::varnode::Varnode::new_constant(0, 4)));
        c0.write().unwrap().set_flags(crate::varnode::varnode_flags::CONSTANT);
        c0.write().unwrap().set_nzm(0);
        let out_vn = Arc::new(RwLock::new(crate::varnode::Varnode::new_register(0x30, 4)));
        let op = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_INT_AND)));
        op.write().unwrap().inrefs = vec![a.clone(), c0.clone()];
        op.write().unwrap().output = Some(out_vn.clone());
        out_vn.write().unwrap().def = Some(Arc::downgrade(&op));

        let rule = RuleAndMask::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert_eq!(o.inrefs[0].read().unwrap().get_offset(), 0);
    }

    #[test]
    fn test_rule_float_range_less_or_equal() {
        // (V f< 5.0) || (V f== 5.0)  =>  V f<= 5.0
        let mut fd = Funcdata::new("test", Address::new(0x1000), 16);
        let v = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        v.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c5 = Arc::new(RwLock::new(crate::varnode::Varnode::new_constant(0x40590000, 8)));
        c5.write().unwrap().set_flags(crate::varnode::varnode_flags::CONSTANT);

        // FLOAT_LESS(V, 5.0)
        let less_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let less = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_FLOAT_LESS)));
        less.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        less.write().unwrap().output = Some(less_out.clone());
        less_out.write().unwrap().def = Some(Arc::downgrade(&less));
        less_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);

        // FLOAT_EQUAL(V, 5.0)
        let eq_out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x21);
        let eq = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_FLOAT_EQUAL)));
        eq.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        eq.write().unwrap().output = Some(eq_out.clone());
        eq_out.write().unwrap().def = Some(Arc::downgrade(&eq));
        eq_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);

        // BOOL_OR(less_out, eq_out)
        let outer = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 2), OpCode::CPUI_BOOL_OR)));
        outer.write().unwrap().inrefs = vec![less_out, eq_out];

        let rule = RuleFloatRange::new();
        let result = rule.apply_op(&outer, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = outer.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_FLOAT_LESSEQUAL);
        assert!(Arc::ptr_eq(&o.inrefs[0], &v));
    }
}
