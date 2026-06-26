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
}
