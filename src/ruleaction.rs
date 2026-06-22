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
}
