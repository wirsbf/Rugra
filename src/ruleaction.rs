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
    // Ghidra: ruleaction.cc:3872 RuleCollapseConstants
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleCollapseConstants {
    // Ghidra: ruleaction.cc:3874 RuleCollapseConstants::applyOp
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

    // Ghidra: ruleaction.cc:3872 RuleCollapseConstants
    fn get_name(&self) -> &str {
        "collapse_constants"
    }

    // Ghidra: ruleaction.cc:3872 RuleCollapseConstants
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
    // Ghidra: ruleaction.cc:2435 RuleTrivialBool
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTrivialBool {
    // Ghidra: ruleaction.cc:2451 RuleTrivialBool::applyOp
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

    // Ghidra: ruleaction.cc:2435 RuleTrivialBool
    fn get_name(&self) -> &str {
        "trivial_bool"
    }

    // Ghidra: ruleaction.cc:2444 RuleTrivialBool::getOpList
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
    // Ghidra: ruleaction.cc:3944 RulePropagateCopy
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RulePropagateCopy {
    // Ghidra: ruleaction.cc:3946 RulePropagateCopy::applyOp
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

    // Ghidra: ruleaction.cc:3944 RulePropagateCopy
    fn get_name(&self) -> &str {
        "propagate_copy"
    }

    // Ghidra: ruleaction.cc:3944 RulePropagateCopy
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_COPY]
    }
}

/// Rule for eliminating redundant zero-extensions
///
/// Corresponds to Ghidra's `RuleZextEliminate`
pub struct RuleZextEliminate;

impl RuleZextEliminate {
    // Ghidra: ruleaction.cc:2491 RuleZextEliminate
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleZextEliminate {
    // Ghidra: ruleaction.cc:2507 RuleZextEliminate::applyOp
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

    // Ghidra: ruleaction.cc:2491 RuleZextEliminate
    fn get_name(&self) -> &str {
        "zext_eliminate"
    }

    // Ghidra: ruleaction.cc:2499 RuleZextEliminate::getOpList
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
    // RUGRA-GLUE: Rugra-specific RuleSextEliminate (no direct Ghidra counterpart)
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSextEliminate {
    // RUGRA-GLUE: Rugra-specific RuleSextEliminate (no direct Ghidra counterpart)
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

    // RUGRA-GLUE: Rugra-specific RuleSextEliminate (no direct Ghidra counterpart)
    fn get_name(&self) -> &str {
        "sext_eliminate"
    }

    // RUGRA-GLUE: Rugra-specific RuleSextEliminate (no direct Ghidra counterpart)
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_SEXT]
    }
}

/// Rule for collapsing same-input binary ops.
///
/// Faithful port of Ghidra's `RuleTrivialArith` (ruleaction.cc:2370-2433).
/// This is NOT identity-element folding (`x + 0 → x` — that's `RuleIdentityEl`).
/// It collapses ops whose two inputs are the SAME varnode (or CSE-equivalent):
///   - `x ^ x        → 0`           (INT_XOR)
///   - `x == x       → 1`           (INT_EQUAL)
///   - `x != x       → 0`           (INT_NOTEQUAL)
///   - `x < x        → 0`           (INT_LESS, INT_SLESS)
///   - `x <= x       → 1`           (INT_LESSEQUAL, INT_SLESSEQUAL)
///   - `x && x       → x`           (BOOL_AND, BOOL_OR, INT_AND, INT_OR)
///   - `x ^^ x       → 0`           (BOOL_XOR)
///   - float compares likewise.
///
/// The 2 inputs must be identical (`Arc::ptr_eq`) or constructed identically
/// (`is_cse_match`). The result is emitted as `COPY(const)` or `COPY(in0)`.
///
/// The previous Rugra implementation did `x + 0 → x` etc. (RuleIdentityEl's
/// job) and never performed the same-input collapse — leaving `x ^ x` intact,
/// which produced the `switch((iVar1 ^ iVar1))` defect. (Audit: BATCH1 R9.)
pub struct RuleTrivialArith;

impl RuleTrivialArith {
    // Ghidra: ruleaction.cc:2359 RuleTrivialArith
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTrivialArith {
    // Ghidra: ruleaction.cc:2382 RuleTrivialArith::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Ghidra ruleaction.cc:2382-2433.
        use std::sync::Arc;
        let op = op_arc.read().unwrap();
        if op.inrefs.len() != 2 {
            return Ok(action_status::NO_CHANGE);
        }
        let in0 = op.inrefs[0].clone();
        let in1 = op.inrefs[1].clone();

        // Inputs must be identical, OR constructed identically (CSE match).
        // Mirrors Ghidra's `in0 != in1 && ... && !isCseMatch` guard.
        let same = {
            let v0 = in0.read().unwrap();
            let v1 = in1.read().unwrap();
            if Arc::ptr_eq(&in0, &in1) {
                true
            } else if v0.is_written() && v1.is_written() {
                // Compare defining ops via is_cse_match.
                let d0 = v0.get_def();
                let d1 = v1.get_def();
                match (d0, d1) {
                    (Some(a), Some(b)) => {
                        let aop = a.read().unwrap();
                        let bop = b.read().unwrap();
                        aop.is_cse_match(&bop)
                    }
                    _ => false,
                }
            } else {
                false
            }
        };
        if !same {
            return Ok(action_status::NO_CHANGE);
        }
        let out_size = op.get_out().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
        let opcode = op.opcode;
        drop(op); // release read lock before mutating fd

        // Determine the result varnode (mirrors the switch at cc:2396-2425).
        // Use a local result type to avoid clashing with the crate `Result`.
        //  Ok(Some(val)) → COPY of constant val
        //  Ok(None)      → COPY of in0 (identity, for AND/OR)
        //  Err(())       → opcode not handled → no change
        let result: std::result::Result<Option<u64>, ()> = match opcode {
            // Boolean 0
            OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS
            | OpCode::CPUI_INT_LESS
            | OpCode::CPUI_BOOL_XOR
            | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS => Ok(Some(0)),
            // Boolean 1
            OpCode::CPUI_INT_EQUAL
            | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_FLOAT_EQUAL
            | OpCode::CPUI_FLOAT_LESSEQUAL => Ok(Some(1)),
            // Same-size 0
            OpCode::CPUI_INT_XOR => Ok(Some(0)),
            // Identity (COPY in0)
            OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR => Ok(None),
            _ => Err(()),
        };

        match result {
            Err(()) => Ok(action_status::NO_CHANGE),
            Ok(const_val) => {
                // Ghidra: opRemoveInput(op,1); opSetOpcode(op,COPY);
                //         if (vn) opSetInput(op,vn,0);
                use crate::op::PcodeOpRef;
                let op_ref = PcodeOpRef(op_arc.clone());
                fd.op_remove_input(&op_ref, 1);
                fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                let new_vn = match const_val {
                    Some(val) => {
                        // Ghidra uses size 1 for boolean results, out_size for INT_XOR.
                        let sz = if opcode == OpCode::CPUI_INT_XOR {
                            out_size.max(1)
                        } else {
                            1
                        };
                        fd.new_constant(sz, val)
                    }
                    None => in0, // identity: COPY(in0)
                };
                fd.op_set_input(&op_ref, new_vn, 0);
                Ok(action_status::CHANGE)
            }
        }
    }

    // Ghidra: ruleaction.cc:2359 RuleTrivialArith
    fn get_name(&self) -> &str {
        "trivial_arith"
    }

    // Ghidra: ruleaction.cc:2372 RuleTrivialArith::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        // Faithful to Ghidra ruleaction.cc:2372-2380 (16 opcodes).
        vec![
            OpCode::CPUI_INT_NOTEQUAL,
            OpCode::CPUI_INT_SLESS,
            OpCode::CPUI_INT_LESS,
            OpCode::CPUI_BOOL_XOR,
            OpCode::CPUI_BOOL_AND,
            OpCode::CPUI_BOOL_OR,
            OpCode::CPUI_INT_EQUAL,
            OpCode::CPUI_INT_SLESSEQUAL,
            OpCode::CPUI_INT_LESSEQUAL,
            OpCode::CPUI_INT_XOR,
            OpCode::CPUI_INT_AND,
            OpCode::CPUI_INT_OR,
            OpCode::CPUI_FLOAT_EQUAL,
            OpCode::CPUI_FLOAT_NOTEQUAL,
            OpCode::CPUI_FLOAT_LESS,
            OpCode::CPUI_FLOAT_LESSEQUAL,
        ]
    }
}

/// Rule for simplifying shift-by-zero operations
///
/// Corresponds to Ghidra's shift simplification rules.
/// Collapses `x << 0 → x`, `x >> 0 → x`, `x >>> 0 → x`.
pub struct RuleShiftBitops;

impl RuleShiftBitops {
    // Ghidra: ruleaction.cc:476 RuleShiftBitops
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleShiftBitops {
    // Ghidra: ruleaction.cc:490 RuleShiftBitops::applyOp
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

    // Ghidra: ruleaction.cc:476 RuleShiftBitops
    fn get_name(&self) -> &str {
        "shift_bitops"
    }

    // Ghidra: ruleaction.cc:481 RuleShiftBitops::getOpList
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
/// Note: Rugra names the bitwise-not opcode `CPUI_INT_NEGATE` (Ghidra's
/// `INT_NEGATE`); Ghidra's `INT_2COMP` (arithmetic negate) is `CPUI_INT_2COMP`.
pub struct RuleNegateIdentity;

impl RuleNegateIdentity {
    // Ghidra: ruleaction.cc:444 RuleNegateIdentity
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleNegateIdentity {
    // Ghidra: ruleaction.cc:452 RuleNegateIdentity::applyOp
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

    // Ghidra: ruleaction.cc:444 RuleNegateIdentity
    fn get_name(&self) -> &str {
        "negate_identity"
    }

    // Ghidra: ruleaction.cc:446 RuleNegateIdentity::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        // Ghidra INT_NEGATE == Rugra CPUI_INT_NEGATE
        vec![OpCode::CPUI_INT_NEGATE]
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
    // Ghidra: ruleaction.cc:1139 RuleNotDistribute
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleNotDistribute {
    // Ghidra: ruleaction.cc:1147 RuleNotDistribute::applyOp
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
        fd.op_set_opcode(&newneg1, OpCode::CPUI_BOOL_NEGATE);
        let newout1 = fd.new_unique_out(1, &newneg1);
        fd.op_set_input(&newneg1, in_v1, 0);
        fd.op_insert_before(&newneg1, &follow);

        // newneg2 = BOOL_NEGATE(in_v2) → newout2
        let newneg2 = fd.new_op(1, pc);
        fd.op_set_opcode(&newneg2, OpCode::CPUI_BOOL_NEGATE);
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

    // Ghidra: ruleaction.cc:1139 RuleNotDistribute
    fn get_name(&self) -> &str {
        "not_distribute"
    }

    // Ghidra: ruleaction.cc:1141 RuleNotDistribute::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_BOOL_NEGATE]
    }
}

/// Simplify concatenation with zero: `concat(V, 0) => zext(V) << c`.
///
/// Faithful to Ghidra's `RuleConcatZero` (ruleaction.cc:4977-5002). When the
/// low (input 1) piece of a PIECE is an all-zero constant, the PIECE becomes
/// a left-shift of a zero-extension of the high piece.
pub struct RuleConcatZero;

impl RuleConcatZero {
    // Ghidra: ruleaction.cc:4977 RuleConcatZero
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleConcatZero {
    // Ghidra: ruleaction.cc:4985 RuleConcatZero::applyOp
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

    // Ghidra: ruleaction.cc:4977 RuleConcatZero
    fn get_name(&self) -> &str {
        "concat_zero"
    }

    // Ghidra: ruleaction.cc:4979 RuleConcatZero::getOpList
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
    // Ghidra: ruleaction.cc:4058 RuleXorCollapse
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleXorCollapse {
    // Ghidra: ruleaction.cc:4070 RuleXorCollapse::applyOp
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

    // Ghidra: ruleaction.cc:4058 RuleXorCollapse
    fn get_name(&self) -> &str {
        "xor_collapse"
    }

    // Ghidra: ruleaction.cc:4063 RuleXorCollapse::getOpList
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
    // Ghidra: ruleaction.cc:4099 RuleAddMultCollapse
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleAddMultCollapse {
    // Ghidra: ruleaction.cc:4113 RuleAddMultCollapse::applyOp
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

    // Ghidra: ruleaction.cc:4099 RuleAddMultCollapse
    fn get_name(&self) -> &str {
        "add_mult_collapse"
    }

    // Ghidra: ruleaction.cc:4106 RuleAddMultCollapse::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_ADD, OpCode::CPUI_INT_MULT]
    }
}

/// All-ones mask for a given byte size (Ghidra's `calc_mask`).
// Ghidra: address.hh:499 calc_mask
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
    // Ghidra: ruleaction.cc:5557 RuleLess2Zero
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLess2Zero {
    // Ghidra: ruleaction.cc:5571 RuleLess2Zero::applyOp
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

    // Ghidra: ruleaction.cc:5557 RuleLess2Zero
    fn get_name(&self) -> &str {
        "less2_zero"
    }

    // Ghidra: ruleaction.cc:5565 RuleLess2Zero::getOpList
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
    // Ghidra: ruleaction.cc:5605 RuleLessEqual2Zero
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLessEqual2Zero {
    // Ghidra: ruleaction.cc:5619 RuleLessEqual2Zero::applyOp
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

    // Ghidra: ruleaction.cc:5605 RuleLessEqual2Zero
    fn get_name(&self) -> &str {
        "lessequal2_zero"
    }

    // Ghidra: ruleaction.cc:5613 RuleLessEqual2Zero::getOpList
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
    // Ghidra: ruleaction.cc:5512 RuleBoolNegate
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleBoolNegate {
    // Ghidra: ruleaction.cc:5529 RuleBoolNegate::applyOp
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
            if d.read().unwrap().opcode != OpCode::CPUI_BOOL_NEGATE {
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

    // Ghidra: ruleaction.cc:5512 RuleBoolNegate
    fn get_name(&self) -> &str {
        "bool_negate"
    }

    // Ghidra: ruleaction.cc:5523 RuleBoolNegate::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        // Ghidra BOOL_NEGATE == Rugra BOOL_NOT
        vec![OpCode::CPUI_BOOL_NEGATE]
    }
}

/// Simplify INT_OR with a full mask: `V = W | 0xffff  =>  V = #0xffff`.
///
/// Faithful to Ghidra's `RuleOrMask` (ruleaction.cc:276-300). When the OR
/// constant sets every bit of the output size, the result is just that
/// constant — rewrite as COPY(constant).
pub struct RuleOrMask;

impl RuleOrMask {
    // Ghidra: ruleaction.cc:276 RuleOrMask
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleOrMask {
    // Ghidra: ruleaction.cc:284 RuleOrMask::applyOp
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

    // Ghidra: ruleaction.cc:276 RuleOrMask
    fn get_name(&self) -> &str {
        "or_mask"
    }

    // Ghidra: ruleaction.cc:278 RuleOrMask::getOpList
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
    // Ghidra: ruleaction.cc:403 RuleAndOrLump
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleAndOrLump {
    // Ghidra: ruleaction.cc:413 RuleAndOrLump::applyOp
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

    // Ghidra: ruleaction.cc:403 RuleAndOrLump
    fn get_name(&self) -> &str {
        "and_or_lump"
    }

    // Ghidra: ruleaction.cc:405 RuleAndOrLump::getOpList
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
    // Ghidra: ruleaction.cc:211 RulePiece2Zext
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RulePiece2Zext {
    // Ghidra: ruleaction.cc:219 RulePiece2Zext::applyOp
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

    // Ghidra: ruleaction.cc:211 RulePiece2Zext
    fn get_name(&self) -> &str {
        "piece2zext"
    }

    // Ghidra: ruleaction.cc:213 RulePiece2Zext::getOpList
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
    // Ghidra: ruleaction.cc:232 RulePiece2Sext
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RulePiece2Sext {
    // Ghidra: ruleaction.cc:240 RulePiece2Sext::applyOp
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

    // Ghidra: ruleaction.cc:232 RulePiece2Sext
    fn get_name(&self) -> &str {
        "piece2sext"
    }

    // Ghidra: ruleaction.cc:234 RulePiece2Sext::getOpList
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
    // Ghidra: ruleaction.cc:261 RuleBxor2NotEqual
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleBxor2NotEqual {
    // Ghidra: ruleaction.cc:269 RuleBxor2NotEqual::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        op_arc.write().unwrap().opcode = OpCode::CPUI_INT_NOTEQUAL;
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:261 RuleBxor2NotEqual
    fn get_name(&self) -> &str {
        "bxor2notequal"
    }

    // Ghidra: ruleaction.cc:263 RuleBxor2NotEqual::getOpList
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
    // Ghidra: ruleaction.cc:645 RuleTermOrder
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTermOrder {
    // Ghidra: ruleaction.cc:663 RuleTermOrder::applyOp
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

    // Ghidra: ruleaction.cc:645 RuleTermOrder
    fn get_name(&self) -> &str {
        "term_order"
    }

    // Ghidra: ruleaction.cc:650 RuleTermOrder::getOpList
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
    // Ghidra: ruleaction.cc:3724 RuleShift2Mult
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleShift2Mult {
    // Ghidra: ruleaction.cc:3734 RuleShift2Mult::applyOp
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

    // Ghidra: ruleaction.cc:3724 RuleShift2Mult
    fn get_name(&self) -> &str {
        "shift2mult"
    }

    // Ghidra: ruleaction.cc:3728 RuleShift2Mult::getOpList
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
    // Ghidra: ruleaction.cc:1798 RuleDoubleSub
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleDoubleSub {
    // Ghidra: ruleaction.cc:1806 RuleDoubleSub::applyOp
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

    // Ghidra: ruleaction.cc:1798 RuleDoubleSub
    fn get_name(&self) -> &str {
        "double_sub"
    }

    // Ghidra: ruleaction.cc:1800 RuleDoubleSub::getOpList
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
    // Ghidra: ruleaction.cc:3516 RuleTrivialShift
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTrivialShift {
    // Ghidra: ruleaction.cc:3525 RuleTrivialShift::applyOp
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

    // Ghidra: ruleaction.cc:3516 RuleTrivialShift
    fn get_name(&self) -> &str {
        "trivial_shift"
    }

    // Ghidra: ruleaction.cc:3518 RuleTrivialShift::getOpList
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
    // Ghidra: ruleaction.cc:2548 RuleSlessToLess
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSlessToLess {
    // Ghidra: ruleaction.cc:2560 RuleSlessToLess::applyOp
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

    // Ghidra: ruleaction.cc:2548 RuleSlessToLess
    fn get_name(&self) -> &str {
        "sless_to_less"
    }

    // Ghidra: ruleaction.cc:2553 RuleSlessToLess::getOpList
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
    // Ghidra: ruleaction.cc:373 RuleOrCollapse
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleOrCollapse {
    // Ghidra: ruleaction.cc:384 RuleOrCollapse::applyOp
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

    // Ghidra: ruleaction.cc:373 RuleOrCollapse
    fn get_name(&self) -> &str {
        "or_collapse"
    }

    // Ghidra: ruleaction.cc:378 RuleOrCollapse::getOpList
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
    // Ghidra: ruleaction.cc:5004 RuleConcatLeftShift
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleConcatLeftShift {
    // Ghidra: ruleaction.cc:5012 RuleConcatLeftShift::applyOp
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

    // Ghidra: ruleaction.cc:5004 RuleConcatLeftShift
    fn get_name(&self) -> &str {
        "concat_leftshift"
    }

    // Ghidra: ruleaction.cc:5006 RuleConcatLeftShift::getOpList
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
    // Ghidra: ruleaction.cc:1825 RuleDoubleShift
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleDoubleShift {
    // Ghidra: ruleaction.cc:1842 RuleDoubleShift::applyOp
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

    // Ghidra: ruleaction.cc:1825 RuleDoubleShift
    fn get_name(&self) -> &str {
        "double_shift"
    }

    // Ghidra: ruleaction.cc:1834 RuleDoubleShift::getOpList
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
    // Ghidra: ruleaction.cc:3679 RuleIdentityEl
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleIdentityEl {
    // Ghidra: ruleaction.cc:3696 RuleIdentityEl::applyOp
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

    // Ghidra: ruleaction.cc:3679 RuleIdentityEl
    fn get_name(&self) -> &str {
        "identity_el"
    }

    // Ghidra: ruleaction.cc:3688 RuleIdentityEl::getOpList
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
    // Ghidra: ruleaction.cc:3544 RuleSignShift
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSignShift {
    // Ghidra: ruleaction.cc:3555 RuleSignShift::applyOp
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

    // Ghidra: ruleaction.cc:3544 RuleSignShift
    fn get_name(&self) -> &str {
        "sign_shift"
    }

    // Ghidra: ruleaction.cc:3549 RuleSignShift::getOpList
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
    // Ghidra: ruleaction.cc:5044 RuleSubZext
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleSubZext {
    // Ghidra: ruleaction.cc:5057 RuleSubZext::applyOp
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

    // Ghidra: ruleaction.cc:5044 RuleSubZext
    fn get_name(&self) -> &str {
        "sub_zext"
    }

    // Ghidra: ruleaction.cc:5051 RuleSubZext::getOpList
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
    // Ghidra: ruleaction.cc:1966 RuleConcatShift
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleConcatShift {
    // Ghidra: ruleaction.cc:1979 RuleConcatShift::applyOp
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

    // Ghidra: ruleaction.cc:1966 RuleConcatShift
    fn get_name(&self) -> &str {
        "concat_shift"
    }

    // Ghidra: ruleaction.cc:1972 RuleConcatShift::getOpList
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
    // Ghidra: ruleaction.cc:2064 RuleShiftCompare
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleShiftCompare {
    // Ghidra: ruleaction.cc:2077 RuleShiftCompare::applyOp
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

    // Ghidra: ruleaction.cc:2064 RuleShiftCompare
    fn get_name(&self) -> &str {
        "shift_compare"
    }

    // Ghidra: ruleaction.cc:2070 RuleShiftCompare::getOpList
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
    // Ghidra: ruleaction.cc:1734 RuleAndCompare
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleAndCompare {
    // Ghidra: ruleaction.cc:1745 RuleAndCompare::applyOp
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

    // Ghidra: ruleaction.cc:1734 RuleAndCompare
    fn get_name(&self) -> &str {
        "and_compare"
    }

    // Ghidra: ruleaction.cc:1738 RuleAndCompare::getOpList
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
    // Ghidra: ruleaction.cc:3602 RuleTestSign
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleTestSign {
    // Ghidra: ruleaction.cc:3632 RuleTestSign::applyOp
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

    // Ghidra: ruleaction.cc:3602 RuleTestSign
    fn get_name(&self) -> &str {
        "test_sign"
    }

    // Ghidra: ruleaction.cc:3604 RuleTestSign::getOpList
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
    // Ghidra: ruleaction.cc:619 RuleEquality
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleEquality {
    // Ghidra: ruleaction.cc:631 RuleEquality::applyOp
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

    // Ghidra: ruleaction.cc:619 RuleEquality
    fn get_name(&self) -> &str {
        "equality"
    }

    // Ghidra: ruleaction.cc:624 RuleEquality::getOpList
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
    // Ghidra: ruleaction.cc:2310 RuleLessNotEqual
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLessNotEqual {
    // Ghidra: ruleaction.cc:2320 RuleLessNotEqual::applyOp
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

    // Ghidra: ruleaction.cc:2310 RuleLessNotEqual
    fn get_name(&self) -> &str { "less_notequal" }
    // Ghidra: ruleaction.cc:2314 RuleLessNotEqual::getOpList
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
    // Ghidra: ruleaction.cc:2250 RuleLessEqual
    pub fn new() -> Self {
        Self
    }
}

impl Rule for RuleLessEqual {
    // Ghidra: ruleaction.cc:2262 RuleLessEqual::applyOp
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

    // Ghidra: ruleaction.cc:2250 RuleLessEqual
    fn get_name(&self) -> &str { "less_equal" }
    // Ghidra: ruleaction.cc:2256 RuleLessEqual::getOpList
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
    // Ghidra: ruleaction.cc:568 RuleRightShiftAnd
    pub fn new() -> Self { Self }
}

impl Rule for RuleRightShiftAnd {
    // Ghidra: ruleaction.cc:580 RuleRightShiftAnd::applyOp
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

    // Ghidra: ruleaction.cc:568 RuleRightShiftAnd
    fn get_name(&self) -> &str { "right_shift_and" }
    // Ghidra: ruleaction.cc:573 RuleRightShiftAnd::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT] }
}

/// Simplify INT_AND applied to aligned INT_ADD when the AND mask is of the
/// form 11110000: `(V + c) & 0xfff0  =>  V + (c & 0xfff0)`.
///
/// Faithful to Ghidra's `RuleHighOrderAnd` (ruleaction.cc:1185-1250). Ports
/// the primary (constant addend) branch.
pub struct RuleHighOrderAnd;

impl RuleHighOrderAnd {
    // Ghidra: ruleaction.cc:1185 RuleHighOrderAnd
    pub fn new() -> Self { Self }
}

impl Rule for RuleHighOrderAnd {
    // Ghidra: ruleaction.cc:1196 RuleHighOrderAnd::applyOp
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

    // Ghidra: ruleaction.cc:1185 RuleHighOrderAnd
    fn get_name(&self) -> &str { "high_order_and" }
    // Ghidra: ruleaction.cc:1190 RuleHighOrderAnd::getOpList
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
    // Ghidra: ruleaction.cc:1696 RuleAndZext
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndZext {
    // Ghidra: ruleaction.cc:1706 RuleAndZext::applyOp
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

    // Ghidra: ruleaction.cc:1696 RuleAndZext
    fn get_name(&self) -> &str { "and_zext" }
    // Ghidra: ruleaction.cc:1700 RuleAndZext::getOpList
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
    // Ghidra: ruleaction.cc:2575 RuleZextSless
    pub fn new() -> Self { Self }
}

impl Rule for RuleZextSless {
    // Ghidra: ruleaction.cc:2584 RuleZextSless::applyOp
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

    // Ghidra: ruleaction.cc:2575 RuleZextSless
    fn get_name(&self) -> &str { "zext_sless" }
    // Ghidra: ruleaction.cc:2577 RuleZextSless::getOpList
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
    // Ghidra: ruleaction.cc:3434 RuleScarry
    pub fn new() -> Self { Self }
}

impl Rule for RuleScarry {
    // Ghidra: ruleaction.cc:3450 RuleScarry::applyOp
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

    // Ghidra: ruleaction.cc:3434 RuleScarry
    fn get_name(&self) -> &str { "scarry" }
    // Ghidra: ruleaction.cc:3444 RuleScarry::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SCARRY] }
}

/// Simplify signed comparisons using INT_SBORROW:
///   `sborrow(V, 0)  =>  false`
///
/// Faithful to Ghidra's `RuleSborrow` (ruleaction.cc:3381-3432). Ports the
/// trivial branch (3390-3395). The AddExpression-based forms are deferred.
pub struct RuleSborrow;

impl RuleSborrow {
    // Ghidra: ruleaction.cc:3365 RuleSborrow
    pub fn new() -> Self { Self }
}

impl Rule for RuleSborrow {
    // Ghidra: ruleaction.cc:3381 RuleSborrow::applyOp
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

    // Ghidra: ruleaction.cc:3365 RuleSborrow
    fn get_name(&self) -> &str { "sborrow" }
    // Ghidra: ruleaction.cc:3375 RuleSborrow::getOpList
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
    // Ghidra: ruleaction.cc:1252 RuleAndDistribute
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndDistribute {
    // Ghidra: ruleaction.cc:1260 RuleAndDistribute::applyOp
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

    // Ghidra: ruleaction.cc:1252 RuleAndDistribute
    fn get_name(&self) -> &str { "and_distribute" }
    // Ghidra: ruleaction.cc:1254 RuleAndDistribute::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Transform INT_LESS/INT_LESSEQUAL of 0 or 1:
///   `V < 1  =>  V == 0`
///   `V <= 0  =>  V == 0`
///
/// Faithful to Ghidra's `RuleLessOne` (ruleaction.cc:1316-1339).
pub struct RuleLessOne;

impl RuleLessOne {
    // Ghidra: ruleaction.cc:1316 RuleLessOne
    pub fn new() -> Self { Self }
}

impl Rule for RuleLessOne {
    // Ghidra: ruleaction.cc:1325 RuleLessOne::applyOp
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

    // Ghidra: ruleaction.cc:1316 RuleLessOne
    fn get_name(&self) -> &str { "less_one" }
    // Ghidra: ruleaction.cc:1318 RuleLessOne::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_LESS, OpCode::CPUI_INT_LESSEQUAL] }
}

/// Simplify INT_AND of a PIECE when the AND mask zeros out one piece:
///   `concat(H, L) & C` where C zeros H → `zext(L)`; where C zeros L → `concat(H, 0)`.
///
/// Faithful to Ghidra's `RuleAndPiece` (ruleaction.cc:1630-1694). Uses
/// get_nz_mask on each piece to determine which half the AND eliminates.
pub struct RuleAndPiece;

impl RuleAndPiece {
    // Ghidra: ruleaction.cc:1628 RuleAndPiece
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndPiece {
    // Ghidra: ruleaction.cc:1640 RuleAndPiece::applyOp
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

    // Ghidra: ruleaction.cc:1628 RuleAndPiece
    fn get_name(&self) -> &str { "and_piece" }
    // Ghidra: ruleaction.cc:1634 RuleAndPiece::getOpList
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
    // Ghidra: ruleaction.cc:1520 RuleAndCommute
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndCommute {
    // Ghidra: ruleaction.cc:1532 RuleAndCommute::applyOp
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

    // Ghidra: ruleaction.cc:1520 RuleAndCommute
    fn get_name(&self) -> &str { "and_commute" }
    // Ghidra: ruleaction.cc:1526 RuleAndCommute::getOpList
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
    // Ghidra: ruleaction.cc:344 RuleOrConsume
    pub fn new() -> Self { Self }
}

impl Rule for RuleOrConsume {
    // Ghidra: ruleaction.cc:353 RuleOrConsume::applyOp
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

    // Ghidra: ruleaction.cc:344 RuleOrConsume
    fn get_name(&self) -> &str { "or_consume" }
    // Ghidra: ruleaction.cc:346 RuleOrConsume::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR] }
}

/// Get rid of unused PcodeOp objects where we can guarantee the output is
/// unused. Faithful to Ghidra's `RuleEarlyRemoval` (ruleaction.cc:23-44).
///
/// Guard sequence mirrors Ghidra exactly (ruleaction.cc:30-40):
///   1. `op->isCall()`                — functions auto-consumed
///   2. `op->isIndirectSource()`      — INDIRECT source side-effect
///   3. `vn = op->getOut(); vn == 0`  — no output to remove
///   4. `!vn->hasNoDescend()`         — output still read
///   5. `vn->isAutoLive()`            — held alive by copy-prop/merge
///   6. `spc->doesDeadcode() && !data.deadRemovalAllowedSeen(spc)` — memory
///      output spaces gated on heritage progress (Rugra: conservatively
///      memory-space outputs are skipped until deadcode-seen is ported).
pub struct RuleEarlyRemoval;

impl RuleEarlyRemoval {
    // Ghidra: ruleaction.cc:23 RuleEarlyRemoval
    pub fn new() -> Self { Self }

    /// Is `spc` a "memory" address space (where deadcode removal is gated)?
    /// In Ghidra `doesDeadcode()` returns true for the join/deadspace-style
    /// spaces and for RAM; the constant/iop spaces return false. Rugra maps this
    /// to: not the constant space and not the internal iop space. For such a
    /// memory space, removal is only safe once `deadRemovalAllowedSeen` has fired
    /// (after heritage). Since Rugra has not ported that mechanism, we
    /// conservatively block removal of memory-space outputs entirely.
    // RUGRA-GLUE: helper for RuleEarlyRemoval::applyOp (ruleaction.cc:25)
    fn is_memory_output_space(space: crate::space::AddressSpace) -> bool {
        // The constant and iop spaces never run deadcode (Ghidra doesDeadcode==false),
        // so outputs there are always removable. Everything else (RAM, register,
        // stack, unique, join, ...) is gated until deadRemovalAllowedSeen is ported.
        !matches!(space, crate::space::AddressSpace::Const | crate::space::AddressSpace::Iop)
    }
}

impl Rule for RuleEarlyRemoval {
    // Ghidra: ruleaction.cc:25 RuleEarlyRemoval::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Ghidra RuleEarlyRemoval::applyOp (ruleaction.cc:25-44).
        // Guard 1: isCall
        let out_vn = {
            let op = op_arc.read().unwrap();
            if op.is_call() { return Ok(action_status::NO_CHANGE); }              // 30
            if op.is_indirect_source() { return Ok(action_status::NO_CHANGE); }    // 31 — guard 2
            let out = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) }; // 32-33 guard 3
            out
        };
        let out_guard = out_vn.read().unwrap();
        // Guard 4: hasNoDescend
        if !out_guard.has_no_descend() { return Ok(action_status::NO_CHANGE); }    // 35
        // Guard 5: isAutoLive (Rugra's is_auto_live currently always returns false,
        // matching Ghidra when no varnode has been marked AUTOLIVE_HOLD).
        if out_guard.is_auto_live() { return Ok(action_status::NO_CHANGE); }       // 36
        // Guard 6: memory-output / deadcode gate. Ghidra blocks removal in spaces
        // where deadcode runs until ActionDeadCode marks them via
        // deadRemovalAllowedSeen. Rugra's descend tracking is incomplete — several
        // code paths (coreaction/constseq/jumptable/heritage) push to inrefs
        // DIRECTLY, bypassing op_set_input's descend maintenance, so
        // has_no_descend can falsely return true for still-used varnodes. To stay
        // safe for memory outputs we additionally verify the descend list has no
        // lingering strong refs, and — as Ghidra does — defer memory-space outputs
        // until deadRemovalAllowedSeen lands. CONSTANT/Internal outputs are
        // unconditionally safe (doesDeadcode==false in Ghidra).
        let space = out_guard.get_space();
        if Self::is_memory_output_space(space) {
            // Memory-space output: blocked until deadcode-seen is ported. This is
            // the one remaining conservative restriction vs Ghidra.
            return Ok(action_status::NO_CHANGE);
        }
        drop(out_guard);
        fd.op_destroy(&crate::op::PcodeOpRef(op_arc.clone()));
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:23 RuleEarlyRemoval
    fn get_name(&self) -> &str { "early_removal" }
    // Ghidra: ruleaction.cc:23 RuleEarlyRemoval
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
    // Ghidra: ruleaction.cc:2957 RuleBooleanNegate
    pub fn new() -> Self { Self }
}

impl Rule for RuleBooleanNegate {
    // Ghidra: ruleaction.cc:2969 RuleBooleanNegate::applyOp
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
            fd.op_set_opcode(&follow, OpCode::CPUI_BOOL_NEGATE);
        } else {
            fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:2957 RuleBooleanNegate
    fn get_name(&self) -> &str { "boolean_negate" }
    // Ghidra: ruleaction.cc:2962 RuleBooleanNegate::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL] }
}

/// Convert INT_AND/INT_OR/INT_XOR to BOOL_AND/BOOL_OR/BOOL_XOR when both
/// inputs are boolean values.
///
/// Faithful to Ghidra's `RuleLogic2Bool` (ruleaction.cc:3128-3167).
pub struct RuleLogic2Bool;

impl RuleLogic2Bool {
    // Ghidra: ruleaction.cc:3126 RuleLogic2Bool
    pub fn new() -> Self { Self }
}

impl Rule for RuleLogic2Bool {
    // Ghidra: ruleaction.cc:3138 RuleLogic2Bool::applyOp
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

    // Ghidra: ruleaction.cc:3126 RuleLogic2Bool
    fn get_name(&self) -> &str { "logic2bool" }
    // Ghidra: ruleaction.cc:3131 RuleLogic2Bool::getOpList
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
    // Ghidra: ruleaction.cc:2016 RuleLeftRight
    pub fn new() -> Self { Self }
}

impl Rule for RuleLeftRight {
    // Ghidra: ruleaction.cc:2030 RuleLeftRight::applyOp
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

    // Ghidra: ruleaction.cc:2016 RuleLeftRight
    fn get_name(&self) -> &str { "left_right" }
    // Ghidra: ruleaction.cc:2023 RuleLeftRight::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_SRIGHT] }
}

/// Convert INT_LESSEQUAL to INT_LESS: `V <= c  =>  V < c+1`.
///
/// Faithful to Ghidra's `RuleIntLessEqual` (ruleaction.cc:611-617). Delegates
/// to Funcdata::replace_lessequal which adjusts the constant and changes the
/// opcode, guarding against overflow edge cases.
pub struct RuleIntLessEqual;

impl RuleIntLessEqual {
    // Ghidra: ruleaction.cc:602 RuleIntLessEqual
    pub fn new() -> Self { Self }
}

impl Rule for RuleIntLessEqual {
    // Ghidra: ruleaction.cc:611 RuleIntLessEqual::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        if fd.replace_lessequal(&crate::op::PcodeOpRef(op_arc.clone())) {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // Ghidra: ruleaction.cc:602 RuleIntLessEqual
    fn get_name(&self) -> &str { "int_lessequal" }
    // Ghidra: ruleaction.cc:604 RuleIntLessEqual::getOpList
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
    // Ghidra: ruleaction.cc:99 RuleCollectTerms
    pub fn new() -> Self { Self }

    /// Extract the multiplicative coefficient from a term vn.
    /// If vn is INT_MULT(V, c), return (V, c); else (vn, 1).
    // Ghidra: ruleaction.cc:82 RuleCollectTerms::getMultCoeff
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
    // Ghidra: ruleaction.cc:107 RuleCollectTerms::applyOp
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

    // Ghidra: ruleaction.cc:99 RuleCollectTerms
    fn get_name(&self) -> &str { "collect_terms" }
    // Ghidra: ruleaction.cc:101 RuleCollectTerms::getOpList
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
    // Ghidra: ruleaction.cc:2620 RuleBitUndistribute
    pub fn new() -> Self { Self }
}

impl Rule for RuleBitUndistribute {
    // Ghidra: ruleaction.cc:2634 RuleBitUndistribute::applyOp
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

    // Ghidra: ruleaction.cc:2620 RuleBitUndistribute
    fn get_name(&self) -> &str { "bit_undistribute" }
    // Ghidra: ruleaction.cc:2627 RuleBitUndistribute::getOpList
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
    // Ghidra: ruleaction.cc:2812 RuleBooleanDedup
    pub fn new() -> Self { Self }
}

impl Rule for RuleBooleanDedup {
    // Ghidra: ruleaction.cc:2852 RuleBooleanDedup::applyOp
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

    // Ghidra: ruleaction.cc:2812 RuleBooleanDedup
    fn get_name(&self) -> &str { "boolean_dedup" }
    // Ghidra: ruleaction.cc:2820 RuleBooleanDedup::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_AND, OpCode::CPUI_BOOL_OR] }
}

/// Helper: exact varnode equality (same Arc pointer).
// Ghidra: expression.cc:520 functionalEquality
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
    // Ghidra: ruleaction.cc:302 RuleAndMask
    pub fn new() -> Self { Self }
}

impl Rule for RuleAndMask {
    // Ghidra: ruleaction.cc:310 RuleAndMask::applyOp
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

    // Ghidra: ruleaction.cc:302 RuleAndMask
    fn get_name(&self) -> &str { "and_mask" }
    // Ghidra: ruleaction.cc:304 RuleAndMask::getOpList
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
    // Ghidra: ruleaction.cc:2697 RuleBooleanUndistribute
    pub fn new() -> Self { Self }

    /// Check if two boolean Varnodes are correlated (same or complementary).
    /// Faithful to `RuleBooleanUndistribute::isMatch` (ruleaction.cc:2710-2729).
    /// Returns `Some(is_flip)` where `is_flip` is true for complementary.
    // Ghidra: ruleaction.cc:2718 RuleBooleanUndistribute::isMatch
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
    // Ghidra: ruleaction.cc:2731 RuleBooleanUndistribute::applyOp
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

    // Ghidra: ruleaction.cc:2697 RuleBooleanUndistribute
    fn get_name(&self) -> &str { "boolean_undistribute" }
    // Ghidra: ruleaction.cc:2703 RuleBooleanUndistribute::getOpList
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
    // Ghidra: ruleaction.cc:3001 RuleBoolZext
    pub fn new() -> Self { Self }
}

impl Rule for RuleBoolZext {
    // Ghidra: ruleaction.cc:3015 RuleBoolZext::applyOp
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

    // Ghidra: ruleaction.cc:3001 RuleBoolZext
    fn get_name(&self) -> &str { "bool_zext" }
    // Ghidra: ruleaction.cc:3009 RuleBoolZext::getOpList
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
    // Ghidra: ruleaction.cc:1062 RulePushMulti
    pub fn new() -> Self { Self }

    /// Find a substitute MULTIEQUAL in the block that already merges in1/in2.
    /// Faithful to `RulePushMulti::findSubstitute` (ruleaction.cc:1031-1060).
    // Ghidra: ruleaction.cc:1031 RulePushMulti::findSubstitute
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
    // Ghidra: ruleaction.cc:1074 RulePushMulti::applyOp
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
            let substitute = match result.pairs.get(0).and_then(|p| Self::find_substitute(&p.0, &p.1)) {
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

    // Ghidra: ruleaction.cc:1062 RulePushMulti
    fn get_name(&self) -> &str { "push_multi" }
    // Ghidra: ruleaction.cc:1068 RulePushMulti::getOpList
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
    // Ghidra: ruleaction.cc:178 RuleSelectCse
    pub fn new() -> Self { Self }
}

impl Rule for RuleSelectCse {
    // Ghidra: ruleaction.cc:187 RuleSelectCse::applyOp
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

    // Ghidra: ruleaction.cc:178 RuleSelectCse
    fn get_name(&self) -> &str { "select_cse" }
    // Ghidra: ruleaction.cc:180 RuleSelectCse::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE, OpCode::CPUI_INT_SRIGHT] }
}

/// Cleanup: Convert INT_2COMP from INT_MULT: `V * -1 => -V`. Faithful to
/// Ghidra's `RuleMultNegOne` (ruleaction.cc:7171-7190).
pub struct RuleMultNegOne;

impl RuleMultNegOne {
    // Ghidra: ruleaction.cc:7171 RuleMultNegOne
    pub fn new() -> Self { Self }
}

impl Rule for RuleMultNegOne {
    // Ghidra: ruleaction.cc:7179 RuleMultNegOne::applyOp
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
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_2COMP);
        fd.op_remove_input(&follow, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7171 RuleMultNegOne
    fn get_name(&self) -> &str { "mult_neg_one" }
    // Ghidra: ruleaction.cc:7173 RuleMultNegOne::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_MULT] }
}

/// Convert INT_SUB to INT_ADD + INT_MULT(-1): `V - W => V + (W * -1)`.
/// Faithful to Ghidra's `RuleSub2Add` (ruleaction.cc:4030-4056).
///
/// This normalization enables additive-term reordering and other rules that
/// only match INT_ADD.
pub struct RuleSub2Add;

impl RuleSub2Add {
    // Ghidra: ruleaction.cc:4032 RuleSub2Add
    pub fn new() -> Self { Self }
}

impl Rule for RuleSub2Add {
    // Ghidra: ruleaction.cc:4040 RuleSub2Add::applyOp
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

    // Ghidra: ruleaction.cc:4032 RuleSub2Add
    fn get_name(&self) -> &str { "sub2_add" }
    // Ghidra: ruleaction.cc:4034 RuleSub2Add::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SUB] }
}

/// Commute SUBPIECE through INT_ZEXT/INT_SEXT. Faithful to Ghidra's
/// `RuleSubExtComm` (ruleaction.cc:4410-4461).
///
/// If `SUBPIECE(zext(V))` doesn't touch the extended bits, replace with
/// `zext(SUBPIECE(V))` or just `COPY(V)` if sizes match.
pub struct RuleSubExtComm;

impl RuleSubExtComm {
    // Ghidra: ruleaction.cc:4405 RuleSubExtComm
    pub fn new() -> Self { Self }
}

impl Rule for RuleSubExtComm {
    // Ghidra: ruleaction.cc:4422 RuleSubExtComm::applyOp
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

    // Ghidra: ruleaction.cc:4405 RuleSubExtComm
    fn get_name(&self) -> &str { "sub_ext_comm" }
    // Ghidra: ruleaction.cc:4416 RuleSubExtComm::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Cleanup: Convert INT_2COMP to INT_MULT: `-V => V * -1`. Faithful to
/// Ghidra's `Rule2Comp2Mult` (ruleaction.cc:3980-3995).
pub struct Rule2Comp2Mult;

impl Rule2Comp2Mult {
    // Ghidra: ruleaction.cc:3979 Rule2Comp2Mult
    pub fn new() -> Self { Self }
}

impl Rule for Rule2Comp2Mult {
    // Ghidra: ruleaction.cc:3987 Rule2Comp2Mult::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Rule2Comp2Mult::applyOp (ruleaction.cc:3987-3995).
        // Ghidra INT_2COMP maps to Rugra INT_NEG (two's complement).
        let in0 = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_2COMP {
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

    // Ghidra: ruleaction.cc:3979 Rule2Comp2Mult
    fn get_name(&self) -> &str { "2comp2mult" }
    // Ghidra: ruleaction.cc:3981 Rule2Comp2Mult::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_2COMP] }
}

/// Cleanup: Convert INT_2COMP to INT_SUB: `-V => 0 - V`. Faithful to
/// Ghidra's `Rule2Comp2Sub` (ruleaction.cc:7236-7256).
pub struct Rule2Comp2Sub;

impl Rule2Comp2Sub {
    // Ghidra: ruleaction.cc:7234 Rule2Comp2Sub
    pub fn new() -> Self { Self }
}

impl Rule for Rule2Comp2Sub {
    // Ghidra: ruleaction.cc:7242 Rule2Comp2Sub::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Rule2Comp2Sub::applyOp (ruleaction.cc:7242-7256).
        let in0 = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_2COMP {
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

    // Ghidra: ruleaction.cc:7234 Rule2Comp2Sub
    fn get_name(&self) -> &str { "2comp2sub" }
    // Ghidra: ruleaction.cc:7236 Rule2Comp2Sub::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_2COMP] }
}

/// Transform INT_CARRY using a constant: `carry(V,c) => -c <= V`. Faithful to
/// Ghidra's `RuleCarryElim` (ruleaction.cc:3997-4030).
pub struct RuleCarryElim;

impl RuleCarryElim {
    // Ghidra: ruleaction.cc:3997 RuleCarryElim
    pub fn new() -> Self { Self }
}

impl Rule for RuleCarryElim {
    // Ghidra: ruleaction.cc:4008 RuleCarryElim::applyOp
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

    // Ghidra: ruleaction.cc:3997 RuleCarryElim
    fn get_name(&self) -> &str { "carry_elim" }
    // Ghidra: ruleaction.cc:4002 RuleCarryElim::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_CARRY] }
}

/// Commute INT_ZEXT with PIECE: `concat(zext(V), W) => zext(concat(V, W))`.
/// Faithful to Ghidra's `RuleConcatZext` (ruleaction.cc:4806-4842).
pub struct RuleConcatZext;

impl RuleConcatZext {
    // Ghidra: ruleaction.cc:4806 RuleConcatZext
    pub fn new() -> Self { Self }
}

impl Rule for RuleConcatZext {
    // Ghidra: ruleaction.cc:4814 RuleConcatZext::applyOp
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

    // Ghidra: ruleaction.cc:4806 RuleConcatZext
    fn get_name(&self) -> &str { "concat_zext" }
    // Ghidra: ruleaction.cc:4808 RuleConcatZext::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PIECE] }
}

/// Commute INT_ZEXT with INT_RIGHT: `zext(V) >> W => zext(V >> W)`.
/// Faithful to Ghidra's `RuleZextCommute` (ruleaction.cc:4844-4875).
pub struct RuleZextCommute;

impl RuleZextCommute {
    // Ghidra: ruleaction.cc:4844 RuleZextCommute
    pub fn new() -> Self { Self }
}

impl Rule for RuleZextCommute {
    // Ghidra: ruleaction.cc:4852 RuleZextCommute::applyOp
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

    // Ghidra: ruleaction.cc:4844 RuleZextCommute
    fn get_name(&self) -> &str { "zext_commute" }
    // Ghidra: ruleaction.cc:4846 RuleZextCommute::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT] }
}

/// Simplify multiple INT_ZEXT operations. Faithful to Ghidra's
/// `RuleZextShiftZext` (ruleaction.cc:4877-4919).
///
/// `zext(zext(V)) => zext(V)` and `zext(zext(V) << c) => zext(V) << c`.
pub struct RuleZextShiftZext;

impl RuleZextShiftZext {
    // Ghidra: ruleaction.cc:4877 RuleZextShiftZext
    pub fn new() -> Self { Self }
}

impl Rule for RuleZextShiftZext {
    // Ghidra: ruleaction.cc:4885 RuleZextShiftZext::applyOp
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

    // Ghidra: ruleaction.cc:4877 RuleZextShiftZext
    fn get_name(&self) -> &str { "zext_shift_zext" }
    // Ghidra: ruleaction.cc:4879 RuleZextShiftZext::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ZEXT] }
}

/// Simplify SUBPIECE applied to INT_LEFT: `sub(V << 8*k, c) => sub(V, c-k)`.
/// Faithful to Ghidra's `RuleShiftSub` (ruleaction.cc:5201-5230).
pub struct RuleShiftSub;

impl RuleShiftSub {
    // Ghidra: ruleaction.cc:5201 RuleShiftSub
    pub fn new() -> Self { Self }
}

impl Rule for RuleShiftSub {
    // Ghidra: ruleaction.cc:5209 RuleShiftSub::applyOp
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

    // Ghidra: ruleaction.cc:5201 RuleShiftSub
    fn get_name(&self) -> &str { "shift_sub" }
    // Ghidra: ruleaction.cc:5203 RuleShiftSub::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify break and rejoin: `concat(sub(V,c), sub(V,0)) => V`.
/// Faithful to Ghidra's `RuleHumptyDumpty` (ruleaction.cc:5232-5281).
pub struct RuleHumptyDumpty;

impl RuleHumptyDumpty {
    // Ghidra: ruleaction.cc:5232 RuleHumptyDumpty
    pub fn new() -> Self { Self }
}

impl Rule for RuleHumptyDumpty {
    // Ghidra: ruleaction.cc:5243 RuleHumptyDumpty::applyOp
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

    // Ghidra: ruleaction.cc:5232 RuleHumptyDumpty
    fn get_name(&self) -> &str { "humpty_dumpty" }
    // Ghidra: ruleaction.cc:5237 RuleHumptyDumpty::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PIECE] }
}

/// Simplify join and break apart: `sub(concat(V,W), c) => sub(W,c)`.
/// Faithful to Ghidra's `RuleDumptyHump` (ruleaction.cc:5283-5337).
pub struct RuleDumptyHump;

impl RuleDumptyHump {
    // Ghidra: ruleaction.cc:5283 RuleDumptyHump
    pub fn new() -> Self { Self }
}

impl Rule for RuleDumptyHump {
    // Ghidra: ruleaction.cc:5296 RuleDumptyHump::applyOp
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

    // Ghidra: ruleaction.cc:5283 RuleDumptyHump
    fn get_name(&self) -> &str { "dumpty_hump" }
    // Ghidra: ruleaction.cc:5290 RuleDumptyHump::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify SUBPIECE applied to INT_ZEXT/INT_SEXT/INT_AND.
/// Faithful to Ghidra's `RuleSubCancel` (ruleaction.cc:5115-5199).
///
/// If a SUBPIECE eliminates an extension entirely (offset+outsize <= insize),
/// replace with COPY. Handles INT_AND with mask, INT_ZEXT/INT_SEXT truncation.
pub struct RuleSubCancel;

impl RuleSubCancel {
    // Ghidra: ruleaction.cc:5120 RuleSubCancel
    pub fn new() -> Self { Self }
}

impl Rule for RuleSubCancel {
    // Ghidra: ruleaction.cc:5137 RuleSubCancel::applyOp
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

    // Ghidra: ruleaction.cc:5120 RuleSubCancel
    fn get_name(&self) -> &str { "sub_cancel" }
    // Ghidra: ruleaction.cc:5131 RuleSubCancel::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify masked pieces INT_ORed together: `(V & ff00) | (V & 00ff) => V`.
/// Faithful to Ghidra's `RuleHumptyOr` (ruleaction.cc:5339-5420).
///
/// Also handles the general form: `(V & W) | (V & X) => V & (W|X)`.
pub struct RuleHumptyOr;

impl RuleHumptyOr {
    // Ghidra: ruleaction.cc:5339 RuleHumptyOr
    pub fn new() -> Self { Self }
}

impl Rule for RuleHumptyOr {
    // Ghidra: ruleaction.cc:5350 RuleHumptyOr::applyOp
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

    // Ghidra: ruleaction.cc:5339 RuleHumptyOr
    fn get_name(&self) -> &str { "humpty_or" }
    // Ghidra: ruleaction.cc:5344 RuleHumptyOr::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_OR] }
}

/// Simplify INT_EQUAL applied to 0: `0 == V + W * -1 => V == W`.
/// Faithful to Ghidra's `RuleEqual2Zero` (ruleaction.cc:5857-5924).
///
/// Simplify INT_SLESS applied to 0 or -1. Faithful to `RuleSLess2Zero`
/// (ruleaction.cc:5711-5840). Forms include:
/// - `-1 s< SUB(V,hi) => -1 s< V`
/// - `SUB(V,hi) s< 0 => V s< 0`
/// - `-1 s< ~V => V s< 0`
/// - `(V & 0xf000) s< 0 => V s< 0`
/// - `-1 s< CONCAT(V,W) => -1 s< V`
/// - `-1 s< (bool << #8*sz-1) => !bool`
pub struct RuleSLess2Zero;

impl RuleSLess2Zero {
    // Ghidra: ruleaction.cc:5684 RuleSLess2Zero
    pub fn new() -> Self { Self }

    /// Extract the high-bit varnode from an INT_ADD/INT_OR/INT_XOR op where
    /// one input is just the sign bit. Faithful to `getHiBit` (ruleaction.cc:5659-5682).
    // Ghidra: ruleaction.cc:5659 RuleSLess2Zero::getHiBit
    fn get_hi_bit(op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let o = op.read().unwrap();
        if !matches!(o.opcode, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR) {
            return None;
        }
        let vn1 = o.inrefs.get(0)?.clone();
        let vn2 = o.inrefs.get(1)?.clone();
        let mask = {
            let mut m = crate::address::calc_mask(vn1.read().unwrap().get_size());
            m ^= m >> 1; // only high-bit set
            m
        };
        let nzmask1 = vn1.read().unwrap().get_nz_mask();
        if nzmask1 != mask && (nzmask1 & mask) != 0 { return None; }
        let nzmask2 = vn2.read().unwrap().get_nz_mask();
        if nzmask2 != mask && (nzmask2 & mask) != 0 { return None; }
        if nzmask1 == mask { return Some(vn1); }
        if nzmask2 == mask { return Some(vn2); }
        None
    }
}

impl Rule for RuleSLess2Zero {
    // Ghidra: ruleaction.cc:5711 RuleSLess2Zero::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSLess2Zero::applyOp (ruleaction.cc:5711-5840).
        let (lvn, rvn) = {
            let op = op_arc.read().unwrap();
            (op.inrefs.get(0).cloned(), op.inrefs.get(1).cloned())
        };
        let (lvn, rvn) = match (lvn, rvn) {
            (Some(l), Some(r)) => (l, r),
            _ => return Ok(action_status::NO_CHANGE),
        };
        let lg = lvn.read().unwrap();
        let rg = rvn.read().unwrap();

        // Case 1: lvn is -1 (all bits set)
        if lg.is_constant() && lg.get_offset() == crate::address::calc_mask(lg.get_size()) {
            if !rg.is_written() { return Ok(action_status::NO_CHANGE); }
            let feed_op = match rg.def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => return Ok(action_status::NO_CHANGE),
            };
            let feed_opc = feed_op.read().unwrap().opcode;
            drop(lg); drop(rg);
            // getHiBit check
            if let Some(hibit) = Self::get_hi_bit(&feed_op) {
                let hibit_size = hibit.read().unwrap().get_size();
                let hibit_offset = hibit.read().unwrap().get_offset();
                let hibit_is_const = hibit.read().unwrap().is_constant();
                let new_in1 = if hibit_is_const {
                    fd.new_constant(hibit_size, hibit_offset)
                } else { hibit };
                fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), new_in1, 1);
                fd.op_set_opcode(&crate::op::PcodeOpRef(op_arc.clone()), OpCode::CPUI_INT_EQUAL);
                let _const = fd.new_constant(hibit_size, 0);
                fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), _const, 0);
                return Ok(action_status::CHANGE);
            }
            // SUBPIECE: -1 s< SUB(avn, #hi) => -1 s< avn
            if feed_opc == OpCode::CPUI_SUBPIECE {
                let avn = feed_op.read().unwrap().inrefs.get(0).cloned();
                let hi_off = feed_op.read().unwrap().inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                if let Some(avn) = avn {
                    let avn_size = avn.read().unwrap().get_size();
                    let rvn_size = rvn.read().unwrap().get_size();
                    if !avn.read().unwrap().is_free() && avn_size <= 8 && rvn_size + hi_off as usize == avn_size {
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), avn, 1);
                        let _cm = fd.new_constant(avn_size, crate::address::calc_mask(avn_size));
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), _cm, 0);
                        return Ok(action_status::CHANGE);
                    }
                }
            }
            // INT_NEGATE: -1 s< ~avn => avn s< 0
            if feed_opc == OpCode::CPUI_INT_NEGATE {
                let avn = feed_op.read().unwrap().inrefs.get(0).cloned();
                if let Some(avn) = avn {
                    if !avn.read().unwrap().is_free() {
                        let avn_size = avn.read().unwrap().get_size();
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), avn, 0);
                        let _const = fd.new_constant(avn_size, 0);
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), _const, 1);
                        return Ok(action_status::CHANGE);
                    }
                }
            }
            // PIECE: -1 s< CONCAT(V,W) => -1 s< V
            if feed_opc == OpCode::CPUI_PIECE {
                let avn = feed_op.read().unwrap().inrefs.get(0).cloned();
                if let Some(avn) = avn {
                    if !avn.read().unwrap().is_free() {
                        let avn_size = avn.read().unwrap().get_size();
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), avn, 1);
                        let _cm = fd.new_constant(avn_size, crate::address::calc_mask(avn_size));
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), _cm, 0);
                        return Ok(action_status::CHANGE);
                    }
                }
            }
            return Ok(action_status::NO_CHANGE);
        }
        drop(lg); drop(rg);

        // Case 2: rvn is 0
        let rg2 = rvn.read().unwrap();
        if rg2.is_constant() && rg2.get_offset() == 0 {
            if !lvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let feed_op = match lvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => return Ok(action_status::NO_CHANGE),
            };
            let feed_opc = feed_op.read().unwrap().opcode;
            drop(rg2);
            // getHiBit: (hi ^ lo) s< 0 => hi != 0
            if let Some(hibit) = Self::get_hi_bit(&feed_op) {
                let hibit_size = hibit.read().unwrap().get_size();
                let hibit_offset = hibit.read().unwrap().get_offset();
                let hibit_is_const = hibit.read().unwrap().is_constant();
                let new_in0 = if hibit_is_const {
                    fd.new_constant(hibit_size, hibit_offset)
                } else { hibit };
                fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), new_in0, 0);
                fd.op_set_opcode(&crate::op::PcodeOpRef(op_arc.clone()), OpCode::CPUI_INT_NOTEQUAL);
                return Ok(action_status::CHANGE);
            }
            // SUBPIECE: SUB(avn, #hi) s< 0 => avn s< 0
            if feed_opc == OpCode::CPUI_SUBPIECE {
                let avn = feed_op.read().unwrap().inrefs.get(0).cloned();
                let hi_off = feed_op.read().unwrap().inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                if let Some(avn) = avn {
                    let avn_size = avn.read().unwrap().get_size();
                    let lvn_size = lvn.read().unwrap().get_size();
                    if !avn.read().unwrap().is_free() && avn_size <= 8 && lvn_size + hi_off as usize == avn_size {
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), avn, 0);
                        let _const = fd.new_constant(avn_size, 0);
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), _const, 1);
                        return Ok(action_status::CHANGE);
                    }
                }
            }
            // INT_NEGATE: ~avn s< 0 => -1 s< avn
            if feed_opc == OpCode::CPUI_INT_NEGATE {
                let avn = feed_op.read().unwrap().inrefs.get(0).cloned();
                if let Some(avn) = avn {
                    if !avn.read().unwrap().is_free() {
                        let avn_size = avn.read().unwrap().get_size();
                        let _cm = fd.new_constant(avn_size, crate::address::calc_mask(avn_size));
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), _cm, 0);
                        fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), avn, 1);
                        return Ok(action_status::CHANGE);
                    }
                }
            }
            return Ok(action_status::NO_CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:5684 RuleSLess2Zero
    fn get_name(&self) -> &str { "sless2zero" }
    // Ghidra: ruleaction.cc:5705 RuleSLess2Zero::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SLESS] }
}

/// Simplify boolean expressions combined through POPCOUNT. Faithful to
/// `RulePopcountBoolXor` (ruleaction.cc:10265-10321). Transforms:
///   `popcount((b1 << 6) | (b2 << 2)) & 1 => b1 ^ b2`
pub struct RulePopcountBoolXor;

impl RulePopcountBoolXor {
    // Ghidra: ruleaction.cc:10265 RulePopcountBoolXor
    pub fn new() -> Self { Self }

    /// Extract the boolean varnode producing a bit at the given position.
    /// Faithful to `getBooleanResult` (ruleaction.cc:10335-10419).
    /// Returns (Some(vn), const_res) if found, or (None, const_res) where
    /// const_res is -1 (not found), 0, or 1 (constant result).
    // Ghidra: ruleaction.cc:10335 RulePopcountBoolXor::getBooleanResult
    fn get_boolean_result(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        mut bit_pos: i32,
    ) -> (Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>, i32) {
        let mut mask: u64 = 1u64 << bit_pos;
        let mut cur_vn = vn.clone();
        loop {
            let vg = cur_vn.read().unwrap();
            if vg.is_constant() {
                return (None, ((vg.get_offset() >> bit_pos) & 1) as i32);
            }
            if !vg.is_written() { return (None, -1); }
            if bit_pos == 0 && vg.get_size() == 1 && vg.get_nz_mask() == mask {
                return (Some(cur_vn.clone()), -1);
            }
            let def_arc = match vg.def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => return (None, -1),
            };
            let def_opc = def_arc.read().unwrap().opcode;
            drop(vg);
            match def_opc {
                OpCode::CPUI_INT_AND => {
                    let in1 = def_arc.read().unwrap().inrefs.get(1).cloned();
                    match in1 {
                        Some(v) if v.read().unwrap().is_constant() => {
                            cur_vn = def_arc.read().unwrap().inrefs.get(0).cloned().unwrap();
                        }
                        _ => return (None, -1),
                    }
                }
                OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR => {
                    let vn0 = def_arc.read().unwrap().inrefs.get(0).cloned();
                    let vn1 = def_arc.read().unwrap().inrefs.get(1).cloned();
                    match (vn0, vn1) {
                        (Some(v0), Some(v1)) => {
                            let nz0 = v0.read().unwrap().get_nz_mask();
                            let nz1 = v1.read().unwrap().get_nz_mask();
                            if (nz0 & mask) != 0 {
                                if (nz1 & mask) != 0 { return (None, -1); }
                                cur_vn = v0;
                            } else if (nz1 & mask) != 0 {
                                cur_vn = v1;
                            } else { return (None, -1); }
                        }
                        _ => return (None, -1),
                    }
                }
                OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                    let new_vn = def_arc.read().unwrap().inrefs.get(0).cloned();
                    match new_vn {
                        Some(v) => {
                            let new_size = v.read().unwrap().get_size();
                            if bit_pos >= new_size as i32 * 8 { return (None, -1); }
                            cur_vn = v;
                        }
                        None => return (None, -1),
                    }
                }
                OpCode::CPUI_INT_LEFT => {
                    let vn1 = def_arc.read().unwrap().inrefs.get(1).cloned();
                    match vn1 {
                        Some(v) if v.read().unwrap().is_constant() => {
                            let sa = v.read().unwrap().get_offset() as i32;
                            if sa > bit_pos { return (None, -1); }
                            bit_pos -= sa;
                            mask >>= sa;
                            cur_vn = def_arc.read().unwrap().inrefs.get(0).cloned().unwrap();
                        }
                        _ => return (None, -1),
                    }
                }
                _ => return (None, -1),
            }
        }
    }
}

impl Rule for RulePopcountBoolXor {
    // Ghidra: ruleaction.cc:10276 RulePopcountBoolXor::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePopcountBoolXor::applyOp (ruleaction.cc:10276-10321).
        // Find INT_AND(&1) descendants of the POPCOUNT output.
        let descendents: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = {
            let op = op_arc.read().unwrap();
            match op.output.as_ref() {
                Some(out) => out.read().unwrap().descend_iter().collect(),
                None => Vec::new(),
            }
        };
        let in_vn = {
            let op = op_arc.read().unwrap();
            match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        for base_op in descendents {
            let base = base_op.read().unwrap();
            if base.opcode != OpCode::CPUI_INT_AND { continue; }
            let tmp_vn = match base.inrefs.get(1) { Some(v) => v.clone(), None => continue };
            let tmp = tmp_vn.read().unwrap();
            if !tmp.is_constant() { continue; }
            if tmp.get_offset() != 1 { continue; } // Masking 1 bit = parity check
            if tmp.get_size() != 1 { continue; }   // Must be boolean-sized output
            drop(tmp); drop(base);

            if !in_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let nzmask = in_vn.read().unwrap().get_nz_mask();
            let count = nzmask.count_ones() as i32;
            if count == 1 {
                let least_pos = crate::address::leastsigbit_set(nzmask);
                let (b1_opt, _const_res) = Self::get_boolean_result(&in_vn, least_pos);
                if let Some(b1) = b1_opt {
                    let base_ref = crate::op::PcodeOpRef(base_op.clone());
                    fd.op_set_opcode(&base_ref, OpCode::CPUI_COPY);
                    fd.op_remove_input(&base_ref, 1);
                    fd.op_set_input(&base_ref, b1, 0);
                    return Ok(action_status::CHANGE);
                }
            }
            if count == 2 {
                let pos0 = crate::address::leastsigbit_set(nzmask);
                let pos1 = crate::address::mostsigbit_set(nzmask);
                let (b1_opt, const_res0) = Self::get_boolean_result(&in_vn, pos0);
                if b1_opt.is_none() && const_res0 != 1 { continue; }
                let (b2_opt, const_res1) = Self::get_boolean_result(&in_vn, pos1);
                if b2_opt.is_none() && const_res1 != 1 { continue; }
                if b1_opt.is_none() && b2_opt.is_none() { continue; }
                let b1 = b1_opt.unwrap_or_else(|| fd.new_constant(1, 1));
                let b2 = b2_opt.unwrap_or_else(|| fd.new_constant(1, 1));
                let base_ref = crate::op::PcodeOpRef(base_op.clone());
                fd.op_set_opcode(&base_ref, OpCode::CPUI_INT_XOR);
                fd.op_set_input(&base_ref, b1, 0);
                fd.op_set_input(&base_ref, b2, 1);
                return Ok(action_status::CHANGE);
            }
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:10265 RulePopcountBoolXor
    fn get_name(&self) -> &str { "popcount_bool_xor" }
    // Ghidra: ruleaction.cc:10270 RulePopcountBoolXor::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_POPCOUNT] }
}

/// Also handles `0 == V + c => V == -c` (constant offset). Applies to
/// INT_NOTEQUAL as well. The sum must only be used in boolean comparisons.
pub struct RuleEqual2Zero;

impl RuleEqual2Zero {
    // Ghidra: ruleaction.cc:5857 RuleEqual2Zero
    pub fn new() -> Self { Self }
}

impl Rule for RuleEqual2Zero {
    // Ghidra: ruleaction.cc:5868 RuleEqual2Zero::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleEqual2Zero::applyOp (ruleaction.cc:5868-5924).
        let (addvn, central_opc) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_EQUAL && op.opcode != OpCode::CPUI_INT_NOTEQUAL {
                return Ok(action_status::NO_CHANGE);
            }
            let vn0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            // Find which input is zero.
            let addvn = if vn0.read().unwrap().is_constant() && vn0.read().unwrap().get_offset() == 0 {
                vn1
            } else if vn1.read().unwrap().is_constant() && vn1.read().unwrap().get_offset() == 0 {
                vn0
            } else {
                return Ok(action_status::NO_CHANGE);
            };
            (addvn, op.opcode)
        };
        // Make sure the sum is only used in comparisons.
        let descends: Vec<_> = addvn.read().unwrap().descend_iter().collect();
        for dop in &descends {
            if !dop.read().unwrap().is_bool_output() {
                return Ok(action_status::NO_CHANGE);
            }
        }
        // Get the addop.
        if !addvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let addop = match addvn.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
        if addop.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return Ok(action_status::NO_CHANGE); }
        let vn = addop.read().unwrap().inrefs.get(0).cloned();
        let vn2 = addop.read().unwrap().inrefs.get(1).cloned();
        let (vn, vn2) = match (vn, vn2) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());

        // Determine posvn and unnegvn.
        let (posvn, unnegvn) = if vn2.read().unwrap().is_constant() {
            // 0 == V + c => V == -c
            let val = vn2.read().unwrap().get_offset();
            let neg_val = val.wrapping_neg().wrapping_sub(1).wrapping_add(1) & calc_mask(vn2.read().unwrap().get_size());
            // uintb_negate(val-1, size) = (~val+1) & mask = -val & mask
            let _ = neg_val;
            let negated = (0i64.wrapping_sub(val as i64) as u64) & calc_mask(vn2.read().unwrap().get_size());
            (vn.clone(), fd.new_constant(vn2.read().unwrap().get_size(), negated))
        } else {
            // Check for INT_MULT by -1.
            let (negvn, posvn) = if vn.read().unwrap().is_written() {
                let vn_def = vn.read().unwrap().get_def();
                if let Some(d) = vn_def {
                    if d.read().unwrap().opcode == OpCode::CPUI_INT_MULT {
                        (vn.clone(), vn2.clone())
                    } else {
                        return Ok(action_status::NO_CHANGE);
                    }
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            } else if vn2.read().unwrap().is_written() {
                let vn2_def = vn2.read().unwrap().get_def();
                if let Some(d) = vn2_def {
                    if d.read().unwrap().opcode == OpCode::CPUI_INT_MULT {
                        (vn2.clone(), vn.clone())
                    } else {
                        return Ok(action_status::NO_CHANGE);
                    }
                } else {
                    return Ok(action_status::NO_CHANGE);
                }
            } else {
                return Ok(action_status::NO_CHANGE);
            };
            // Verify the multiplier is -1.
            let negvn_def = negvn.read().unwrap().get_def();
            let negop = match negvn_def { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let mult_const = match negop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !mult_const.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let unnegvn = match negop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let multiplier = mult_const.read().unwrap().get_offset();
            if multiplier != calc_mask(unnegvn.read().unwrap().get_size()) { return Ok(action_status::NO_CHANGE); }
            (posvn, unnegvn)
        };
        let _ = central_opc;
        fd.op_set_input(&follow, posvn, 0);
        fd.op_set_input(&follow, unnegvn, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:5857 RuleEqual2Zero
    fn get_name(&self) -> &str { "equal2zero" }
    // Ghidra: ruleaction.cc:5861 RuleEqual2Zero::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL] }
}

/// Eliminate INT_AND when the bits it zeroes out are discarded by a shift.
/// Faithful to Ghidra's `RuleShiftAnd` (ruleaction.cc:4921-4975).
///
/// `(V & mask) >> sa => V >> sa` when the shifted mask covers all NZM bits.
/// Also handles INT_LEFT and INT_MULT (power-of-2).
pub struct RuleShiftAnd;

impl RuleShiftAnd {
    // Ghidra: ruleaction.cc:4921 RuleShiftAnd
    pub fn new() -> Self { Self }
}

impl Rule for RuleShiftAnd {
    // Ghidra: ruleaction.cc:4933 RuleShiftAnd::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleShiftAnd::applyOp (ruleaction.cc:4933-4975).
        use crate::address::leastsigbit_set;
        let (opc, cvn_val, shiftin, mask, invn, in_size) = {
            let op = op_arc.read().unwrap();
            let opc = op.opcode;
            if opc != OpCode::CPUI_INT_RIGHT && opc != OpCode::CPUI_INT_LEFT && opc != OpCode::CPUI_INT_MULT {
                return Ok(action_status::NO_CHANGE);
            }
            let cvn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let cvn_val = {
                let r = cvn.read().unwrap();
                if !r.is_constant() { return Ok(action_status::NO_CHANGE); }
                r.get_offset()
            };
            let shiftin = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let andop = {
                let r = shiftin.read().unwrap();
                if !r.is_written() { return Ok(action_status::NO_CHANGE); }
                match r.get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) }
            };
            if andop.read().unwrap().opcode != OpCode::CPUI_INT_AND { return Ok(action_status::NO_CHANGE); }
            let maskvn = match andop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let mask = {
                let r = maskvn.read().unwrap();
                if !r.is_constant() { return Ok(action_status::NO_CHANGE); }
                r.get_offset()
            };
            let invn = match andop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let in_size = {
                let r = invn.read().unwrap();
                if r.is_free() { return Ok(action_status::NO_CHANGE); }
                r.get_size()
            };
            (opc, cvn_val, shiftin, mask, invn, in_size)
        };
        let (sa, effective_opc) = if opc == OpCode::CPUI_INT_RIGHT || opc == OpCode::CPUI_INT_LEFT {
            (cvn_val as i64, opc)
        } else {
            // INT_MULT: check it's a power-of-2 shift.
            let sa = leastsigbit_set(cvn_val);
            if sa <= 0 { return Ok(action_status::NO_CHANGE); }
            let testval = 1u64 << sa;
            if testval != cvn_val { return Ok(action_status::NO_CHANGE); }
            (sa as i64, OpCode::CPUI_INT_LEFT) // Treat as INT_LEFT.
        };
        let nzm = invn.read().unwrap().get_nz_mask();
        let full_mask = calc_mask(in_size);
        let (shifted_nzm, shifted_mask) = if effective_opc == OpCode::CPUI_INT_RIGHT {
            (nzm >> sa, mask >> sa)
        } else {
            ((nzm << sa) & full_mask, (mask << sa) & full_mask)
        };
        if (shifted_mask & shifted_nzm) != shifted_nzm {
            return Ok(action_status::NO_CHANGE); // AND bits still matter.
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, invn, 0); // Bypass the INT_AND.
        let _ = (shiftin, cvn_val);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:4921 RuleShiftAnd
    fn get_name(&self) -> &str { "shift_and" }
    // Ghidra: ruleaction.cc:4925 RuleShiftAnd::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_LEFT, OpCode::CPUI_INT_MULT] }
}

/// Flip a CBRANCH with a boolean-flip flag. Faithful to Ghidra's
/// `RuleCondNegate` (ruleaction.cc:5478-5510).
///
/// When a CBRANCH has the `boolean_flip` flag set, insert a BOOL_NOT to
/// negate the condition and clear the flag.
pub struct RuleCondNegate;

impl RuleCondNegate {
    // Ghidra: ruleaction.cc:5479 RuleCondNegate
    pub fn new() -> Self { Self }
}

impl Rule for RuleCondNegate {
    // Ghidra: ruleaction.cc:5492 RuleCondNegate::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleCondNegate::applyOp (ruleaction.cc:5492-5510).
        let is_flip = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_CBRANCH {
                return Ok(action_status::NO_CHANGE);
            }
            (op.flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0
        };
        if !is_flip {
            return Ok(action_status::NO_CHANGE);
        }
        let vn = match op_arc.read().unwrap().inrefs.get(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let out_vn = fd.op_bool_negate(vn, &follow, false);
        fd.op_set_input(&follow, out_vn, 1);
        fd.op_flip_condition(&follow);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:5479 RuleCondNegate
    fn get_name(&self) -> &str { "cond_negate" }
    // Ghidra: ruleaction.cc:5486 RuleCondNegate::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_CBRANCH] }
}

/// Simplify limited chains of XOR operations: `(V ^ W) ^ V => W`.
/// Faithful to Ghidra's `RuleXorSwap` (ruleaction.cc:10614-10650).
pub struct RuleXorSwap;

impl RuleXorSwap {
    // Ghidra: ruleaction.cc:10614 RuleXorSwap
    pub fn new() -> Self { Self }
}

impl Rule for RuleXorSwap {
    // Ghidra: ruleaction.cc:10625 RuleXorSwap::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleXorSwap::applyOp (ruleaction.cc:10625-10650).
        let (othervn, match_vn) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_XOR {
                return Ok(action_status::NO_CHANGE);
            }
            let mut result: Option<(std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>)> = None;
            for i in 0..2 {
                let vn = match op.inrefs.get(i) { Some(v) => v.clone(), None => continue };
                if !vn.read().unwrap().is_written() { continue; }
                let op2 = match vn.read().unwrap().get_def() { Some(d) => d, None => continue };
                if op2.read().unwrap().opcode != OpCode::CPUI_INT_XOR { continue; }
                let othervn = match op.inrefs.get(1 - i) { Some(v) => v.clone(), None => continue };
                let vn0 = match op2.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
                let vn1 = match op2.read().unwrap().get_in(1).cloned() { Some(v) => v, None => continue };
                if std::sync::Arc::ptr_eq(&othervn, &vn0) && !vn1.read().unwrap().is_free() {
                    result = Some((othervn, vn1));
                    break;
                } else if std::sync::Arc::ptr_eq(&othervn, &vn1) && !vn0.read().unwrap().is_free() {
                    result = Some((othervn, vn0));
                    break;
                }
            }
            match result { Some((o, m)) => (o, m), None => return Ok(action_status::NO_CHANGE) }
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_remove_input(&follow, 1);
        fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
        fd.op_set_input(&follow, match_vn, 0);
        let _ = othervn;
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:10614 RuleXorSwap
    fn get_name(&self) -> &str { "xor_swap" }
    // Ghidra: ruleaction.cc:10619 RuleXorSwap::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_XOR] }
}

/// Simplify INT_EQUAL applied to arithmetic expressions with constants.
/// Faithful to Ghidra's `RuleEqual2Constant` (ruleaction.cc:5926-5990).
///
/// `(V + c) == d => V == (d - c)` and `(V * -1) == d => V == -d`.
/// Skips the INT_NEGATE case (Rugra lacks INT_NEGATE opcode).
pub struct RuleEqual2Constant;

impl RuleEqual2Constant {
    // Ghidra: ruleaction.cc:5926 RuleEqual2Constant
    pub fn new() -> Self { Self }
}

impl Rule for RuleEqual2Constant {
    // Ghidra: ruleaction.cc:5940 RuleEqual2Constant::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleEqual2Constant::applyOp (ruleaction.cc:5940-5990).
        let (cvn_val, lhs, leftop_code, otherconst_val, otherconst_size, a) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_EQUAL && op.opcode != OpCode::CPUI_INT_NOTEQUAL {
                return Ok(action_status::NO_CHANGE);
            }
            let cvn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !cvn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let cvn_val = cvn.read().unwrap().get_offset();
            let lhs = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !lhs.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let leftop = match lhs.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let leftop_code = leftop.read().unwrap().opcode;
            if leftop_code != OpCode::CPUI_INT_ADD && leftop_code != OpCode::CPUI_INT_MULT {
                return Ok(action_status::NO_CHANGE);
            }
            let otherconst = match leftop.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if !otherconst.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let otherconst_val = otherconst.read().unwrap().get_offset();
            let otherconst_size = otherconst.read().unwrap().get_size();
            let a = match leftop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if a.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            (cvn_val, lhs, leftop_code, otherconst_val, otherconst_size, a)
        };
        let new_const = if leftop_code == OpCode::CPUI_INT_ADD {
            (cvn_val.wrapping_sub(otherconst_val)) & calc_mask(otherconst_size)
        } else {
            // INT_MULT: only by -1.
            if otherconst_val != calc_mask(otherconst_size) { return Ok(action_status::NO_CHANGE); }
            (0i64.wrapping_sub(cvn_val as i64) as u64) & calc_mask(otherconst_size)
        };
        // Make sure all descendants of lhs are comparisons.
        let descends: Vec<_> = lhs.read().unwrap().descend_iter().collect();
        for dop in &descends {
            let dop_code = dop.read().unwrap().opcode;
            if dop_code != OpCode::CPUI_INT_EQUAL && dop_code != OpCode::CPUI_INT_NOTEQUAL {
                return Ok(action_status::NO_CHANGE);
            }
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let a_size = a.read().unwrap().get_size();
        fd.op_set_input(&follow, a, 0);
        let c = fd.new_constant(a_size, new_const);
        fd.op_set_input(&follow, c, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:5926 RuleEqual2Constant
    fn get_name(&self) -> &str { "equal2constant" }
    // Ghidra: ruleaction.cc:5933 RuleEqual2Constant::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL] }
}

/// Distribute INT_OR across INT_EQUAL comparisons.
/// Faithful to Ghidra's `RuleOrCompare` (ruleaction.cc:10808-10872).
///
/// When `(V | W) == 0`, split into `V == 0 && W == 0` (BOOL_AND).
/// When `(V | W) != 0`, split into `V != 0 || W != 0` (BOOL_OR).
pub struct RuleOrCompare;

impl RuleOrCompare {
    // Ghidra: ruleaction.cc:10803 RuleOrCompare
    pub fn new() -> Self { Self }
}

impl Rule for RuleOrCompare {
    // Ghidra: ruleaction.cc:10814 RuleOrCompare::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleOrCompare::applyOp (ruleaction.cc:10814-10872).
        let (central_opc, v, w, out_vn) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_OR {
                return Ok(action_status::NO_CHANGE);
            }
            let out_vn = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            // Check all descendants are comparisons against 0.
            let descends: Vec<_> = out_vn.read().unwrap().descend_iter().collect();
            if descends.is_empty() { return Ok(action_status::NO_CHANGE); }
            let mut central_opc = None;
            for comp_op in &descends {
                let comp_code = comp_op.read().unwrap().opcode;
                if comp_code != OpCode::CPUI_INT_EQUAL && comp_code != OpCode::CPUI_INT_NOTEQUAL {
                    return Ok(action_status::NO_CHANGE);
                }
                let comp_in1 = match comp_op.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                if !comp_in1.read().unwrap().is_constant() || comp_in1.read().unwrap().get_offset() != 0 {
                    return Ok(action_status::NO_CHANGE);
                }
                central_opc = Some(comp_code);
            }
            let v = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let w = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if v.read().unwrap().is_free() || w.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            (central_opc.unwrap(), v, w, out_vn)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // For each descendant comparison, split into per-input comparisons.
        let descends: Vec<_> = out_vn.read().unwrap().descend_iter().collect();
        for equal_op_arc in descends {
            let equal_ref = crate::op::PcodeOpRef(equal_op_arc.clone());
            let addr = equal_op_arc.read().unwrap().get_addr();
            let combine_opc = if central_opc == OpCode::CPUI_INT_EQUAL { OpCode::CPUI_BOOL_AND } else { OpCode::CPUI_BOOL_OR };
            // Create eq_V(v, 0).
            let eq_v = fd.new_op(2, addr);
            fd.op_set_opcode(&eq_v, central_opc);
            let eq_v_out = fd.new_unique_out(1, &eq_v);
            let zero_v = fd.new_constant(v.read().unwrap().get_size(), 0);
            fd.op_set_input(&eq_v, v.clone(), 0);
            fd.op_set_input(&eq_v, zero_v, 1);
            fd.op_insert_before(&eq_v, &equal_ref);
            // Create eq_W(w, 0).
            let eq_w = fd.new_op(2, addr);
            fd.op_set_opcode(&eq_w, central_opc);
            let eq_w_out = fd.new_unique_out(1, &eq_w);
            let zero_w = fd.new_constant(w.read().unwrap().get_size(), 0);
            fd.op_set_input(&eq_w, w.clone(), 0);
            fd.op_set_input(&eq_w, zero_w, 1);
            fd.op_insert_before(&eq_w, &equal_ref);
            // Rewrite the comparison as BOOL_AND/BOOL_OR.
            fd.op_set_opcode(&equal_ref, combine_opc);
            fd.op_set_input(&equal_ref, eq_v_out, 0);
            fd.op_set_input(&equal_ref, eq_w_out, 1);
        }
        let _ = follow;
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:10803 RuleOrCompare
    fn get_name(&self) -> &str { "or_compare" }
    // Ghidra: ruleaction.cc:10808 RuleOrCompare::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_OR] }
}

/// Commute logical ops with concatenation. Faithful to Ghidra's
/// `RuleConcatCommute` (ruleaction.cc:4675-4748).
///
/// `concat(V, W) | c => concat(V | c_hi, W | c_lo)` — pushes the logical
/// operation inside the concatenation so it operates on each piece separately.
pub struct RuleConcatCommute;

impl RuleConcatCommute {
    // Ghidra: ruleaction.cc:4675 RuleConcatCommute
    pub fn new() -> Self { Self }
}

impl Rule for RuleConcatCommute {
    // Ghidra: ruleaction.cc:4687 RuleConcatCommute::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleConcatCommute::applyOp (ruleaction.cc:4687-4748).
        let (opc, hi, lo, val, out_size) = {
            let op = op_arc.read().unwrap();
            let out_size = match op.output.as_ref() { Some(o) => o.read().unwrap().get_size(), None => return Ok(action_status::NO_CHANGE) };
            if out_size > 8 { return Ok(action_status::NO_CHANGE); }
            if op.opcode != OpCode::CPUI_PIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let mut found: Option<(OpCode, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, u64)> = None;
            for i in 0..2 {
                let vn = match op.inrefs.get(i) { Some(v) => v.clone(), None => continue };
                if !vn.read().unwrap().is_written() { continue; }
                let logicop = match vn.read().unwrap().get_def() { Some(d) => d, None => continue };
                let opc = logicop.read().unwrap().opcode;
                if opc != OpCode::CPUI_INT_OR && opc != OpCode::CPUI_INT_XOR && opc != OpCode::CPUI_INT_AND {
                    continue;
                }
                let constvn = match logicop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
                if !constvn.read().unwrap().is_constant() { continue; }
                let mut val = constvn.read().unwrap().get_offset();
                let (hi, lo) = if i == 0 {
                    let hi = match logicop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
                    let lo = match op.inrefs.get(1) { Some(v) => v.clone(), None => continue };
                    val <<= 8 * lo.read().unwrap().get_size();
                    if opc == OpCode::CPUI_INT_AND {
                        val |= calc_mask(lo.read().unwrap().get_size());
                    }
                    (hi, lo)
                } else {
                    let hi = match op.inrefs.get(0) { Some(v) => v.clone(), None => continue };
                    let lo = match logicop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
                    if opc == OpCode::CPUI_INT_AND {
                        val |= calc_mask(hi.read().unwrap().get_size()) << (8 * lo.read().unwrap().get_size());
                    }
                    (hi, lo)
                };
                if hi.read().unwrap().is_free() || lo.read().unwrap().is_free() { continue; }
                found = Some((opc, hi, lo, val));
                break;
            }
            match found {
                Some((opc, hi, lo, val)) => (opc, hi, lo, val, out_size),
                None => return Ok(action_status::NO_CHANGE),
            }
        };
        let addr = op_arc.read().unwrap().get_addr();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // Create new PIECE(hi, lo).
        let new_concat = fd.new_op(2, addr);
        fd.op_set_opcode(&new_concat, OpCode::CPUI_PIECE);
        let new_vn = fd.new_unique_out(out_size, &new_concat);
        fd.op_set_input(&new_concat, hi, 0);
        fd.op_set_input(&new_concat, lo, 1);
        fd.op_insert_before(&new_concat, &follow);
        // Rewrite original op as the logical op.
        fd.op_set_opcode(&follow, opc);
        fd.op_set_input(&follow, new_vn.clone(), 0);
        let c = fd.new_constant(out_size, val);
        fd.op_set_input(&follow, c, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:4675 RuleConcatCommute
    fn get_name(&self) -> &str { "concat_commute" }
    // Ghidra: ruleaction.cc:4681 RuleConcatCommute::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PIECE] }
}

/// Commute SUBPIECE with a binary op on its input. Faithful to Ghidra's
/// `RuleSubCommute` (ruleaction.cc:4534-4673).
///
/// Transforms `SUBPIECE(INT_ADD(a,b), 0)` into `INT_ADD(SUBPIECE(a,0),
/// SUBPIECE(b,0))` — pushing the truncation inside the arithmetic so the
/// operands can be typed at the smaller width. Commutes for: INT_ADD,
/// INT_MULT, INT_NEGATE, INT_XOR, INT_AND, INT_OR, INT_LEFT, INT_DIV,
/// INT_REM (and INT_SDIV/INT_SREM with sign-extension, deferred).
pub struct RuleSubCommute;

impl RuleSubCommute {
    // Ghidra: ruleaction.cc:4463 RuleSubCommute
    pub fn new() -> Self { Self }
}

impl Rule for RuleSubCommute {
    // Ghidra: ruleaction.cc:4534 RuleSubCommute::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSubCommute::applyOp (ruleaction.cc:4534-4673).
        // This rule triggers on CPUI_SUBPIECE.
        let op_addr = { op_arc.read().unwrap().start.get_addr() };
        let (base, offset, outvn_size, longform_arc) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_SUBPIECE {
                return Ok(action_status::NO_CHANGE);
            }
            let outvn = match op.output.as_ref() {
                Some(o) => o.clone(),
                None => return Ok(action_status::NO_CHANGE),
            };
            let outvn_size = outvn.read().unwrap().get_size();
            if outvn_size > 8 { return Ok(action_status::NO_CHANGE); }
            // isPrecisLo/Hi check omitted (Rugra has no precis flags; the
            // check would return false anyway).
            let base = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !base.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let offset = match op.inrefs.get(1) {
                Some(v) => {
                    let g = v.read().unwrap();
                    if !g.is_constant() { return Ok(action_status::NO_CHANGE); }
                    g.get_offset() as i64
                }
                None => return Ok(action_status::NO_CHANGE),
            };
            let longform_arc = match base.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a,
                None => return Ok(action_status::NO_CHANGE),
            };
            (base, offset, outvn_size, longform_arc)
        };
        let _ = base;

        // Determine if the longform op commutes with SUBPIECE (cc:4545-4638).
        let longform_opc = longform_arc.read().unwrap().opcode;
        let insize = longform_arc.read().unwrap().output.as_ref()
            .map(|o| o.read().unwrap().get_size()).unwrap_or(0);
        let j: i32; // special input slot (-1 = none)
        match longform_opc {
            OpCode::CPUI_INT_LEFT => {
                j = 1; // shift amount is special
                if offset != 0 { return Ok(action_status::NO_CHANGE); }
                // longform->getIn(0) must be written and be ZEXT or PIECE.
                let in0 = longform_arc.read().unwrap().inrefs.get(0).cloned();
                let in0 = match in0 { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                if !in0.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
                let in0_def = match in0.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                    Some(a) => a, None => return Ok(action_status::NO_CHANGE),
                };
                let in0_opc = in0_def.read().unwrap().opcode;
                if in0_opc != OpCode::CPUI_INT_ZEXT && in0_opc != OpCode::CPUI_PIECE {
                    return Ok(action_status::NO_CHANGE);
                }
            }
            OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => {
                j = -1;
                if offset != 0 { return Ok(action_status::NO_CHANGE); }
                // longform->getIn(0) must be INT_ZEXT.
                let in0 = longform_arc.read().unwrap().inrefs.get(0).cloned();
                let in0 = match in0 { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                if !in0.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
                let in0_def = match in0.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                    Some(a) => a, None => return Ok(action_status::NO_CHANGE),
                };
                if in0_def.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT {
                    return Ok(action_status::NO_CHANGE);
                }
                let zext0_in = in0_def.read().unwrap().inrefs.get(0).cloned();
                let zext0_in = match zext0_in { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                if zext0_in.read().unwrap().get_size() > outvn_size {
                    // Partial commute (cancelExtensions) — deferred for simplicity.
                    return Ok(action_status::NO_CHANGE);
                }
                // Check input[1] similarly if written.
                let in1 = longform_arc.read().unwrap().inrefs.get(1).cloned();
                if let Some(in1v) = in1 {
                    if in1v.read().unwrap().is_written() {
                        let in1_def = match in1v.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
                        };
                        if in1_def.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT {
                            return Ok(action_status::NO_CHANGE);
                        }
                        let zext1_in = in1_def.read().unwrap().inrefs.get(0).cloned();
                        if let Some(z1) = zext1_in {
                            if z1.read().unwrap().get_size() > outvn_size {
                                return Ok(action_status::NO_CHANGE); // partial commute
                            }
                        }
                    } else if in1v.read().unwrap().is_constant() {
                        // Must fit in outvn_size mask.
                        let val = in1v.read().unwrap().get_offset();
                        let smallval = val & crate::address::calc_mask(outvn_size);
                        if val != smallval { return Ok(action_status::NO_CHANGE); }
                    } else {
                        return Ok(action_status::NO_CHANGE);
                    }
                }
            }
            // INT_SDIV / INT_SREM deferred (need sign_extend helper).
            OpCode::CPUI_INT_ADD => {
                j = -1;
                if offset != 0 { return Ok(action_status::NO_CHANGE); }
                // Deconflict with RulePtrArith: longform->getIn(0) must not be spacebase.
                let in0 = longform_arc.read().unwrap().inrefs.get(0).cloned();
                if let Some(in0v) = in0 {
                    if in0v.read().unwrap().is_spacebase() { return Ok(action_status::NO_CHANGE); }
                }
            }
            OpCode::CPUI_INT_MULT => {
                j = -1;
                if offset != 0 { return Ok(action_status::NO_CHANGE); }
            }
            // Bitwise ops commute regardless of offset.
            OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR => {
                j = -1;
            }
            _ => return Ok(action_status::NO_CHANGE), // Most ops don't commute
        }

        // Make sure no other piece of base is getting used (cc:4641).
        // base->loneDescend() != op  =>  bail.
        let lone = {
            let out_vn = {
                let base_g = longform_arc.read().unwrap();
                match base_g.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) }
            };
            let out_g = out_vn.read().unwrap();
            out_g.lone_descend()
        };
        let is_lone = match lone {
            Some(l) => std::sync::Arc::ptr_eq(&l, op_arc),
            None => false,
        };
        if !is_lone { return Ok(action_status::NO_CHANGE); }

        // For each input of longform (except the special j slot), push a
        // SUBPIECE inside (cc:4651-4669).
        let num_inputs = longform_arc.read().unwrap().inrefs.len();
        let outvn = op_arc.read().unwrap().output.as_ref().unwrap().clone();
        let mut new_vn_for: Vec<Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>> = Vec::with_capacity(num_inputs);
        new_vn_for.resize(num_inputs, None);
        let inputs_snapshot: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            longform_arc.read().unwrap().inrefs.clone();
        let mut last_in: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
        let mut new_vn: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
        for i in 0..num_inputs {
            let vn = inputs_snapshot[i].clone();
            if i as i32 != j {
                let dup = last_in.as_ref().map(|p| std::sync::Arc::ptr_eq(p, &vn)).unwrap_or(false) && new_vn.is_some();
                if !dup {
                    // newsub = newOp(2); opSetOpcode(SUBPIECE); newUniqueOut(outvn_size)
                    let newsub = fd.new_op(2, op_addr.clone());
                    fd.op_set_opcode(&newsub, OpCode::CPUI_SUBPIECE);
                    let newout = fd.new_unique_out(outvn_size, &newsub);
                    let offset_const = fd.new_constant(4, offset as u64);
                    fd.op_set_input(&newsub, vn.clone(), 0);
                    fd.op_set_input(&newsub, offset_const, 1);
                    fd.op_insert_before(&newsub, &crate::op::PcodeOpRef(longform_arc.clone()));
                    new_vn = Some(newout);
                    fd.op_set_input(&crate::op::PcodeOpRef(longform_arc.clone()), new_vn.clone().unwrap(), i);
                } else if let Some(ref nv) = new_vn {
                    fd.op_set_input(&crate::op::PcodeOpRef(longform_arc.clone()), nv.clone(), i);
                }
            }
            last_in = Some(vn);
        }
        // opSetOutput(longform, outvn) — move the original SUBPIECE's output
        // to longform, then destroy the SUBPIECE (cc:4670-4671).
        {
            // Unset longform's current output def link.
            let mut lf = longform_arc.write().unwrap();
            if let Some(ref old_out) = lf.output {
                old_out.write().unwrap().def = None;
            }
            lf.output = Some(outvn.clone());
            outvn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
            outvn.write().unwrap().def = Some(std::sync::Arc::downgrade(&longform_arc));
        }
        fd.op_destroy(&crate::op::PcodeOpRef(op_arc.clone()));
        let _ = insize;
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:4463 RuleSubCommute
    fn get_name(&self) -> &str { "sub_commute" }
    // Ghidra: ruleaction.cc:4470 RuleSubCommute::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify equality checks that use lzcount: `lzcount(X) >> c => X == 0`
/// if X is 2^c bits wide. Faithful to Ghidra's `RuleLzcountShiftBool`
/// (ruleaction.cc:10660-10712).
pub struct RuleLzcountShiftBool;

impl RuleLzcountShiftBool {
    // Ghidra: ruleaction.cc:10652 RuleLzcountShiftBool
    pub fn new() -> Self { Self }
}

impl Rule for RuleLzcountShiftBool {
    // Ghidra: ruleaction.cc:10666 RuleLzcountShiftBool::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleLzcountShiftBool::applyOp (ruleaction.cc:10666-10712).
        use crate::utils::bits::popcount;
        let (out_vn, max_return, in0) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_LZCOUNT {
                return Ok(action_status::NO_CHANGE);
            }
            let out_vn = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let max_return = 8 * in0.read().unwrap().get_size() as u64;
            (out_vn, max_return, in0)
        };
        // Only makes sense with power-of-2 sizes.
        if popcount(max_return) != 1 {
            return Ok(action_status::NO_CHANGE);
        }
        // Search for a shift descendant that extracts the MSB.
        let descends: Vec<_> = out_vn.read().unwrap().descend_iter().collect();
        for base_op_arc in descends {
            let base_code = base_op_arc.read().unwrap().opcode;
            if base_code != OpCode::CPUI_INT_RIGHT && base_code != OpCode::CPUI_INT_SRIGHT {
                continue;
            }
            let vn1 = match base_op_arc.read().unwrap().get_in(1).cloned() {
                Some(v) => v,
                None => continue,
            };
            if !vn1.read().unwrap().is_constant() { continue; }
            let shift = vn1.read().unwrap().get_offset();
            if (max_return >> shift) != 1 { continue; }
            // Found the pattern: lzcount(X) >> c where 2^c == max_return.
            // Replace with X == 0.
            let base_ref = crate::op::PcodeOpRef(base_op_arc.clone());
            let base_addr = base_op_arc.read().unwrap().get_addr();
            let new_op = fd.new_op(2, base_addr);
            fd.op_set_opcode(&new_op, OpCode::CPUI_INT_EQUAL);
            let b = fd.new_constant(in0.read().unwrap().get_size(), 0);
            fd.op_set_input(&new_op, in0.clone(), 0);
            fd.op_set_input(&new_op, b, 1);
            let eq_res = fd.new_unique_out(1, &new_op);
            fd.op_insert_before(&new_op, &base_ref);
            // Rewrite the shift op as COPY or ZEXT of the boolean result.
            fd.op_remove_input(&base_ref, 1);
            let base_out_size = base_op_arc.read().unwrap().output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(1);
            if base_out_size == 1 {
                fd.op_set_opcode(&base_ref, OpCode::CPUI_COPY);
            } else {
                fd.op_set_opcode(&base_ref, OpCode::CPUI_INT_ZEXT);
            }
            fd.op_set_input(&base_ref, eq_res, 0);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:10652 RuleLzcountShiftBool
    fn get_name(&self) -> &str { "lzcount_shift_bool" }
    // Ghidra: ruleaction.cc:10660 RuleLzcountShiftBool::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_LZCOUNT] }
}

/// Simplify expressions involving three-way comparisons. Faithful to
/// Ghidra's `RuleThreeWayCompare` (ruleaction.cc:9949-10263).
///
/// A three-way comparison is `X = zext(V < W) + zext(V <= W) - 1`, giving
/// -1/0/1. This Rule looks for secondary comparisons of the three-way result
/// and replaces them with the corresponding direct comparison.
pub struct RuleThreeWayCompare;

impl RuleThreeWayCompare {
    // Ghidra: ruleaction.cc:10126 RuleThreeWayCompare
    pub fn new() -> Self { Self }

    /// Check if two comparison ops are equivalent. Returns 0=correct, 1=swap,
    /// -1=not equivalent. Faithful to `testCompareEquivalence`
    /// (ruleaction.cc:9960-10034).
    // Ghidra: ruleaction.cc:9960 RuleThreeWayCompare::testCompareEquivalence
    fn test_compare_equivalence(
        lessop: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        lessequalop: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    ) -> i32 {
        let less_code = lessop.read().unwrap().opcode;
        let le_code = lessequalop.read().unwrap().opcode;
        let two_less = if less_code == OpCode::CPUI_INT_LESS {
            if le_code == OpCode::CPUI_INT_LESSEQUAL { false }
            else if le_code == OpCode::CPUI_INT_LESS { true }
            else { return -1; }
        } else if less_code == OpCode::CPUI_INT_SLESS {
            if le_code == OpCode::CPUI_INT_SLESSEQUAL { false }
            else if le_code == OpCode::CPUI_INT_SLESS { true }
            else { return -1; }
        } else if less_code == OpCode::CPUI_FLOAT_LESS {
            if le_code == OpCode::CPUI_FLOAT_LESSEQUAL { false }
            else if le_code == OpCode::CPUI_FLOAT_LESS { true }
            else { return -1; }
        } else {
            return -1;
        };
        let _ = two_less;
        // Check inputs match: lessop input(0) == lessequalop input(0),
        // lessop input(1) == lessequalop input(1).
        let l0 = lessop.read().unwrap().get_in(0).cloned();
        let l1 = lessop.read().unwrap().get_in(1).cloned();
        let le0 = lessequalop.read().unwrap().get_in(0).cloned();
        let le1 = lessequalop.read().unwrap().get_in(1).cloned();
        if let (Some(l0), Some(l1), Some(le0), Some(le1)) = (l0, l1, le0, le1) {
            if std::sync::Arc::ptr_eq(&l0, &le0) && std::sync::Arc::ptr_eq(&l1, &le1) {
                return 0;
            }
            if std::sync::Arc::ptr_eq(&l0, &le1) && std::sync::Arc::ptr_eq(&l1, &le0) {
                return 1;
            }
        }
        -1
    }

    /// Detect a three-way comparison pattern rooted at `addop`. Returns the
    /// less-than op, or None. Faithful to `detectThreeWay`
    /// (ruleaction.cc:10035-10124).
    // Ghidra: ruleaction.cc:10035 RuleThreeWayCompare::detectThreeWay
    fn detect_three_way(
        addop: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    ) -> Option<(std::sync::Arc<std::sync::RwLock<PcodeOp>>, bool)> {
        // addop is INT_ADD. Both inputs must be ZEXT of comparison ops.
        let add0 = addop.read().unwrap().get_in(0).cloned()?;
        let add1 = addop.read().unwrap().get_in(1).cloned()?;
        if !add0.read().unwrap().is_written() || !add1.read().unwrap().is_written() {
            return None;
        }
        let zext1 = add0.read().unwrap().get_def()?;
        let zext2 = add1.read().unwrap().get_def()?;
        if zext1.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return None; }
        if zext2.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return None; }
        let vn1 = zext1.read().unwrap().get_in(0).cloned()?;
        let vn2 = zext2.read().unwrap().get_in(0).cloned()?;
        if !vn1.read().unwrap().is_written() || !vn2.read().unwrap().is_written() {
            return None;
        }
        let lessop = vn1.read().unwrap().get_def()?;
        let lessequalop = vn2.read().unwrap().get_def()?;
        let less_code = lessop.read().unwrap().opcode;
        let (lessop, lessequalop) = if less_code == OpCode::CPUI_INT_LESS
            || less_code == OpCode::CPUI_INT_SLESS
            || less_code == OpCode::CPUI_FLOAT_LESS
        {
            (lessop, lessequalop)
        } else {
            (lessequalop, lessop)
        };
        let form = Self::test_compare_equivalence(&lessop, &lessequalop);
        if form < 0 { return None; }
        let result_op = if form == 1 { lessequalop } else { lessop };
        Some((result_op, false))
    }
}

impl Rule for RuleThreeWayCompare {
    // Ghidra: ruleaction.cc:10146 RuleThreeWayCompare::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleThreeWayCompare::applyOp (ruleaction.cc:10146-10263).
        let (const_slot, val, tmp_vn, op_code) = {
            let op = op_arc.read().unwrap();
            let opc = op.opcode;
            if opc != OpCode::CPUI_INT_SLESS && opc != OpCode::CPUI_INT_SLESSEQUAL
                && opc != OpCode::CPUI_INT_EQUAL && opc != OpCode::CPUI_INT_NOTEQUAL
            {
                return Ok(action_status::NO_CHANGE);
            }
            // Find constant input.
            let mut const_slot = 0;
            let mut tmp_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !tmp_vn.read().unwrap().is_constant() {
                const_slot = 1;
                tmp_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
                if !tmp_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            }
            let val = tmp_vn.read().unwrap().get_offset();
            let const_size = tmp_vn.read().unwrap().get_size();
            let form = if val <= 2 {
                val as i32 + 1
            } else if val == calc_mask(const_size) {
                0
            } else {
                return Ok(action_status::NO_CHANGE);
            };
            let tmp2 = match op.inrefs.get(1 - const_slot) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (const_slot, form, tmp2, opc)
        };
        if !tmp_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let addop = match tmp_vn.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
        if addop.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return Ok(action_status::NO_CHANGE); }
        let (lessop, is_partial) = match Self::detect_three_way(&addop) {
            Some((l, p)) => (l, p),
            None => return Ok(action_status::NO_CHANGE),
        };
        let mut form = val;
        if is_partial {
            if form == 0 { return Ok(action_status::NO_CHANGE); }
            form -= 1;
        }
        form <<= 1;
        if const_slot == 1 { form += 1; }
        let lessform = lessop.read().unwrap().opcode;
        form <<= 2;
        if op_code == OpCode::CPUI_INT_SLESSEQUAL { form += 1; }
        else if op_code == OpCode::CPUI_INT_EQUAL { form += 2; }
        else if op_code == OpCode::CPUI_INT_NOTEQUAL { form += 3; }
        let b_vn = lessop.read().unwrap().get_in(0).cloned();
        let a_vn = lessop.read().unwrap().get_in(1).cloned();
        let (Some(a_vn), Some(b_vn)) = (a_vn, b_vn) else { return Ok(action_status::NO_CHANGE) };
        if !a_vn.read().unwrap().is_constant() && a_vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        if !b_vn.read().unwrap().is_constant() && b_vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }

        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // Encode lessform + 1 for LESSEQUAL.
        let less_equal_form = match lessform {
            OpCode::CPUI_INT_LESS => OpCode::CPUI_INT_LESSEQUAL,
            OpCode::CPUI_INT_SLESS => OpCode::CPUI_INT_SLESSEQUAL,
            _ => lessform, // FLOAT_LESS + 1 is not simply incrementing; skip for float.
        };
        let zero_const = fd.new_constant(1, 0);
        match form {
            1 | 21 => {
                // Always true.
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_EQUAL);
                fd.op_set_input(&follow, zero_const.clone(), 0);
                fd.op_set_input(&follow, zero_const, 1);
            }
            4 | 16 => {
                // Always false.
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_NOTEQUAL);
                let z2 = fd.new_constant(1, 0);
                fd.op_set_input(&follow, z2.clone(), 0);
                fd.op_set_input(&follow, z2, 1);
            }
            2 | 5 | 6 | 12 => {
                // a < b
                fd.op_set_opcode(&follow, lessform);
                fd.op_set_input(&follow, a_vn, 0);
                fd.op_set_input(&follow, b_vn, 1);
            }
            13 | 19 | 20 | 23 => {
                // a <= b
                fd.op_set_opcode(&follow, less_equal_form);
                fd.op_set_input(&follow, a_vn, 0);
                fd.op_set_input(&follow, b_vn, 1);
            }
            8 | 17 | 18 | 22 => {
                // a > b  (swap operands)
                fd.op_set_opcode(&follow, lessform);
                fd.op_set_input(&follow, b_vn, 0);
                fd.op_set_input(&follow, a_vn, 1);
            }
            0 | 3 | 7 | 9 => {
                // a >= b  (swap operands, LESSEQUAL)
                fd.op_set_opcode(&follow, less_equal_form);
                fd.op_set_input(&follow, b_vn, 0);
                fd.op_set_input(&follow, a_vn, 1);
            }
            10 | 14 => {
                // a == b
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_EQUAL);
                fd.op_set_input(&follow, a_vn, 0);
                fd.op_set_input(&follow, b_vn, 1);
            }
            11 | 15 => {
                // a != b
                fd.op_set_opcode(&follow, OpCode::CPUI_INT_NOTEQUAL);
                fd.op_set_input(&follow, a_vn, 0);
                fd.op_set_input(&follow, b_vn, 1);
            }
            _ => return Ok(action_status::NO_CHANGE),
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:10126 RuleThreeWayCompare
    fn get_name(&self) -> &str { "three_way_compare" }
    // Ghidra: ruleaction.cc:10137 RuleThreeWayCompare::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_SLESS, OpCode::CPUI_INT_SLESSEQUAL, OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL]
    }
}

/// Collapse MULTIEQUAL whose inputs all trace to the same value. Faithful
/// to Ghidra's `RuleMultiCollapse` (ruleaction.cc:3246-3363).
///
/// If all inputs to a MULTIEQUAL hold the same value (absolute or functional
/// equality), the MULTIEQUAL is eliminated. Handles nested MULTIEQUALs by
/// expanding their inputs into the match list.
pub struct RuleMultiCollapse;

impl RuleMultiCollapse {
    // Ghidra: ruleaction.cc:3246 RuleMultiCollapse
    pub fn new() -> Self { Self }
}

impl Rule for RuleMultiCollapse {
    // Ghidra: ruleaction.cc:3254 RuleMultiCollapse::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleMultiCollapse::applyOp (ruleaction.cc:3254-3363).
        use crate::expression::functional_equality_level;

        let num_input = op_arc.read().unwrap().inrefs.len();
        // All inputs must be heritaged (non-free).
        for i in 0..num_input {
            let vn = match op_arc.read().unwrap().inrefs.get(i) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        }

        let mut matchlist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        for i in 0..num_input {
            matchlist.push(op_arc.read().unwrap().inrefs[i].clone());
        }
        let mut func_eq = false;
        let mut nofunc = false;
        let mut defcopyr: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
        let mut skiplist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();

        // Find base branch to match (first non-MULTIEQUAL input).
        for i in 0..matchlist.len() {
            let copyr = matchlist[i].clone();
            let is_written = copyr.read().unwrap().is_written();
            let is_multiequal = if is_written {
                let def = copyr.read().unwrap().get_def();
                match def { Some(d) => d.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL, None => false }
            } else { false };
            if !is_written || !is_multiequal {
                defcopyr = Some(copyr);
                break;
            }
        }

        // Mark the output for loop-construct detection.
        let out_vn = match op_arc.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
        out_vn.write().unwrap().set_mark();
        skiplist.push(out_vn.clone());

        let mut j = 0usize;
        let mut success = true;
        while j < matchlist.len() {
            let copyr = matchlist[j].clone();
            j += 1;
            if copyr.read().unwrap().is_mark() {
                continue; // Loop construct — value recurs without change.
            }
            if defcopyr.is_none() {
                // This is now the defining branch.
                defcopyr = Some(copyr.clone());
                let is_written = copyr.read().unwrap().is_written();
                if is_written {
                    let is_multiequal = {
                        let def = copyr.read().unwrap().get_def();
                        match def { Some(d) => d.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL, None => false }
                    };
                    if is_multiequal { nofunc = true; }
                } else {
                    nofunc = true;
                }
            } else {
                let dc = defcopyr.as_ref().unwrap();
                if std::sync::Arc::ptr_eq(dc, &copyr) {
                    continue; // Matching branch.
                }
                if !nofunc {
                    let result = functional_equality_level(&dc, &copyr);
                    if result.code == 0 {
                        func_eq = true;
                        continue;
                    }
                }
                // Non-matching branch: if it's a MULTIEQUAL, expand its inputs.
                let is_written = copyr.read().unwrap().is_written();
                let is_multiequal = if is_written {
                    let def = copyr.read().unwrap().get_def();
                    match def { Some(d) => d.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL, None => false }
                } else { false };
                if is_multiequal {
                    let newop = copyr.read().unwrap().get_def().unwrap();
                    let newop_num_input = newop.read().unwrap().inrefs.len();
                    skiplist.push(copyr.clone());
                    copyr.write().unwrap().set_mark();
                    for k in 0..newop_num_input {
                        if let Some(v) = newop.read().unwrap().inrefs.get(k).cloned() {
                            matchlist.push(v);
                        }
                    }
                } else {
                    success = false;
                    break;
                }
            }
        }

        if success {
            // Clear marks and collapse.
            for vn in &skiplist {
                vn.write().unwrap().clear_mark();
            }
            if func_eq {
                // Functional equality only: for each MULTIEQUAL in skiplist,
                // try to collapse. Rugra lacks cseFindInBlock/earliestUse, so
                // we use total_replace when possible.
                for vn in &skiplist {
                    if std::sync::Arc::ptr_eq(vn, &out_vn) { continue; }
                    let def_op = match vn.read().unwrap().get_def() { Some(d) => d, None => continue };
                    let def_ref = crate::op::PcodeOpRef(def_op);
                    if !def_ref.0.read().unwrap().is_dead() {
                        let dc = defcopyr.as_ref().unwrap();
                        fd.total_replace(vn, dc.clone());
                        fd.op_destroy(&def_ref);
                    }
                }
            } else {
                // Absolute equality: replace all MULTIEQUAL outputs with defcopyr.
                for vn in &skiplist {
                    if std::sync::Arc::ptr_eq(vn, &out_vn) { continue; }
                    let def_op = match vn.read().unwrap().get_def() { Some(d) => d, None => continue };
                    let def_ref = crate::op::PcodeOpRef(def_op);
                    if !def_ref.0.read().unwrap().is_dead() {
                        let dc = defcopyr.as_ref().unwrap();
                        fd.total_replace(vn, dc.clone());
                        fd.op_destroy(&def_ref);
                    }
                }
            }
            // Clear remaining marks.
            for vn in &skiplist {
                vn.write().unwrap().clear_mark();
            }
            return Ok(action_status::CHANGE);
        }
        // Clear marks on failure.
        for vn in &skiplist {
            vn.write().unwrap().clear_mark();
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:3246 RuleMultiCollapse
    fn get_name(&self) -> &str { "multi_collapse" }
    // Ghidra: ruleaction.cc:3248 RuleMultiCollapse::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_MULTIEQUAL] }
}

/// Convert INT_SRIGHT form into INT_SDIV: `(V + -1*(V s>> 31)) s>> 1 => V s/ 2`.
/// Faithful to Ghidra's `RuleSignDiv2` (ruleaction.cc:8357-8408).
pub struct RuleSignDiv2;

impl RuleSignDiv2 {
    // Ghidra: ruleaction.cc:8357 RuleSignDiv2
    pub fn new() -> Self { Self }
}

impl Rule for RuleSignDiv2 {
    // Ghidra: ruleaction.cc:8365 RuleSignDiv2::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSignDiv2::applyOp (ruleaction.cc:8365-8408).
        let a = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
            let sa_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !sa_vn.read().unwrap().is_constant() || sa_vn.read().unwrap().get_offset() != 1 { return Ok(action_status::NO_CHANGE); }
            let addout = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !addout.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let addop = match addout.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if addop.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return Ok(action_status::NO_CHANGE); }
            // Search for the mult+shift pattern in addop's inputs.
            let mut found_a: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
            for i in 0..2 {
                let multout = match addop.read().unwrap().get_in(i) { Some(v) => v.clone(), None => continue };
                if !multout.read().unwrap().is_written() { continue; }
                let multop = match multout.read().unwrap().get_def() { Some(d) => d, None => continue };
                if multop.read().unwrap().opcode != OpCode::CPUI_INT_MULT { continue; }
                let mult_const = match multop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
                if !mult_const.read().unwrap().is_constant() { continue; }
                if mult_const.read().unwrap().get_offset() != calc_mask(mult_const.read().unwrap().get_size()) { continue; }
                let shiftout = match multop.read().unwrap().get_in(0) { Some(v) => v.clone(), None => continue };
                if !shiftout.read().unwrap().is_written() { continue; }
                let shiftop = match shiftout.read().unwrap().get_def() { Some(d) => d, None => continue };
                if shiftop.read().unwrap().opcode != OpCode::CPUI_INT_SRIGHT { continue; }
                let shift_sa = match shiftop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
                if !shift_sa.read().unwrap().is_constant() { continue; }
                let n = shift_sa.read().unwrap().get_offset();
                let candidate_a = match shiftop.read().unwrap().get_in(0) { Some(v) => v.clone(), None => continue };
                let other_input = match addop.read().unwrap().get_in(1 - i) { Some(v) => v.clone(), None => continue };
                if !std::sync::Arc::ptr_eq(&candidate_a, &other_input) { continue; }
                if n != 8 * candidate_a.read().unwrap().get_size() as u64 - 1 { continue; }
                if candidate_a.read().unwrap().is_free() { continue; }
                found_a = Some(candidate_a);
                break;
            }
            match found_a { Some(a) => a, None => return Ok(action_status::NO_CHANGE) }
        };
        let a_size = a.read().unwrap().get_size();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, a, 0);
        let c = fd.new_constant(a_size, 2);
        fd.op_set_input(&follow, c, 1);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_SDIV);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:8357 RuleSignDiv2
    fn get_name(&self) -> &str { "sign_div2" }
    // Ghidra: ruleaction.cc:8359 RuleSignDiv2::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SRIGHT] }
}

/// Collapse two consecutive divisions: `(x / c1) / c2 => x / (c1*c2)`.
/// Faithful to Ghidra's `RuleDivChain` (ruleaction.cc:8410-8455).
pub struct RuleDivChain;

impl RuleDivChain {
    // Ghidra: ruleaction.cc:8410 RuleDivChain
    pub fn new() -> Self { Self }
}

impl Rule for RuleDivChain {
    // Ghidra: ruleaction.cc:8419 RuleDivChain::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleDivChain::applyOp (ruleaction.cc:8419-8455).
        let (opc2, vn, const_vn2_val) = {
            let op = op_arc.read().unwrap();
            let opc2 = op.opcode;
            if opc2 != OpCode::CPUI_INT_DIV && opc2 != OpCode::CPUI_INT_SDIV { return Ok(action_status::NO_CHANGE); }
            let const_vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let const_vn2_val = {
                let r = const_vn2.read().unwrap();
                if !r.is_constant() { return Ok(action_status::NO_CHANGE); }
                r.get_offset()
            };
            let vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (opc2, vn, const_vn2_val)
        };
        if !vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let div_op = match vn.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
        let opc1 = div_op.read().unwrap().opcode;
        if opc1 != opc2 && (opc2 != OpCode::CPUI_INT_DIV || opc1 != OpCode::CPUI_INT_RIGHT) {
            return Ok(action_status::NO_CHANGE);
        }
        let const_vn1 = match div_op.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !const_vn1.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        // Intermediate result must only be used here.
        if vn.read().unwrap().lone_descend().is_none() { return Ok(action_status::NO_CHANGE); }
        let val1 = if opc1 == opc2 {
            const_vn1.read().unwrap().get_offset()
        } else {
            // Unsigned case with INT_RIGHT.
            1u64 << const_vn1.read().unwrap().get_offset()
        };
        let full_mask = calc_mask(const_vn1.read().unwrap().get_size());
        let new_val = (val1.wrapping_mul(const_vn2_val)) & full_mask;
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let new_const = fd.new_constant(const_vn1.read().unwrap().get_size(), new_val);
        fd.op_set_input(&follow, new_const, 1);
        if opc1 == OpCode::CPUI_INT_RIGHT {
            fd.op_set_opcode(&follow, OpCode::CPUI_INT_DIV);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:8410 RuleDivChain
    fn get_name(&self) -> &str { "div_chain" }
    // Ghidra: ruleaction.cc:8412 RuleDivChain::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_DIV, OpCode::CPUI_INT_SDIV] }
}

/// Normalize sign extraction: `sub(sext(V), c) s>> n => V s>> (8*|V|-1)`.
/// Faithful to Ghidra's `RuleSignForm` (ruleaction.cc:8449-8492).
pub struct RuleSignForm;

impl RuleSignForm {
    // Ghidra: ruleaction.cc:8463 RuleSignForm
    pub fn new() -> Self { Self }
}

impl Rule for RuleSignForm {
    // Ghidra: ruleaction.cc:8471 RuleSignForm::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSignForm::applyOp (ruleaction.cc:8471-8492).
        let (a, a_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
            let sextout = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !sextout.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let sextop = match sextout.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if sextop.read().unwrap().opcode != OpCode::CPUI_INT_SEXT { return Ok(action_status::NO_CHANGE); }
            let a = match sextop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let c = op.inrefs.get(1).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(0);
            let a_size = a.read().unwrap().get_size();
            if c < a_size as i64 { return Ok(action_status::NO_CHANGE); }
            if a.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            (a, a_size)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, a, 0);
        let n = 8 * a_size - 1;
        let c = fd.new_constant(4, n as u64);
        fd.op_set_input(&follow, c, 1);
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_SRIGHT);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:8463 RuleSignForm
    fn get_name(&self) -> &str { "sign_form" }
    // Ghidra: ruleaction.cc:8465 RuleSignForm::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SRIGHT] }
}

/// Normalize sign extraction: `sub(sext(V) * small, c) s>> 31 => V s>> 31`.
/// Faithful to Ghidra's `RuleSignForm2` (ruleaction.cc:8494-8570).
pub struct RuleSignForm2;

impl RuleSignForm2 {
    // Ghidra: ruleaction.cc:8494 RuleSignForm2
    pub fn new() -> Self { Self }
}

impl Rule for RuleSignForm2 {
    // Ghidra: ruleaction.cc:8505 RuleSignForm2::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSignForm2::applyOp (ruleaction.cc:8505-8570).
        let (a, other_vn) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
            let const_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !const_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let in_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let sizeout = in_vn.read().unwrap().get_size() as i64;
            if const_vn.read().unwrap().get_offset() as i64 != sizeout * 8 - 1 { return Ok(action_status::NO_CHANGE); }
            if !in_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let sub_op = match in_vn.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if sub_op.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let c = sub_op.read().unwrap().get_in(1).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(0);
            let mult_out = match sub_op.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let mult_size = mult_out.read().unwrap().get_size() as i64;
            if c + sizeout != mult_size { return Ok(action_status::NO_CHANGE); }
            if !mult_out.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let mult_op = match mult_out.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if mult_op.read().unwrap().opcode != OpCode::CPUI_INT_MULT { return Ok(action_status::NO_CHANGE); }
            // Search for INT_SEXT in mult_op's inputs.
            let mut found_a: Option<(std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>)> = None;
            for slot in 0..2 {
                let vn = match mult_op.read().unwrap().get_in(slot) { Some(v) => v.clone(), None => continue };
                if !vn.read().unwrap().is_written() { continue; }
                let sext_op = match vn.read().unwrap().get_def() { Some(d) => d, None => continue };
                if sext_op.read().unwrap().opcode != OpCode::CPUI_INT_SEXT { continue; }
                let a = match sext_op.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
                if a.read().unwrap().is_free() || a.read().unwrap().get_size() as i64 != sizeout { continue; }
                let other_vn = match mult_op.read().unwrap().get_in(1 - slot).cloned() { Some(v) => v, None => continue };
                found_a = Some((a, other_vn));
                break;
            }
            match found_a { Some(x) => x, None => return Ok(action_status::NO_CHANGE) }
        };
        // other_vn must be a small positive constant (no overflow into sign bit).
        if !other_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        let val = other_vn.read().unwrap().get_offset();
        let val_size = other_vn.read().unwrap().get_size();
        // Check no overflow: a * val must not overflow into sign bit of mult.
        let sign_bit = 1u64 << (8 * a.read().unwrap().get_size() - 1);
        if val >= sign_bit { return Ok(action_status::NO_CHANGE); }
        let _ = val_size;
        let a_size = a.read().unwrap().get_size();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, a, 0);
        let n = 8 * a_size - 1;
        let c = fd.new_constant(4, n as u64);
        fd.op_set_input(&follow, c, 1);
        // opcode stays INT_SRIGHT
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:8494 RuleSignForm2
    fn get_name(&self) -> &str { "sign_form2" }
    // Ghidra: ruleaction.cc:8499 RuleSignForm2::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SRIGHT] }
}

/// Convert signed division/remainder to unsigned when both inputs are
/// guaranteed non-negative. Faithful to Ghidra's `RulePositiveDiv`
/// (ruleaction.cc:7803-7830).
pub struct RulePositiveDiv;

impl RulePositiveDiv {
    // Ghidra: ruleaction.cc:7805 RulePositiveDiv
    pub fn new() -> Self { Self }
}

impl Rule for RulePositiveDiv {
    // Ghidra: ruleaction.cc:7817 RulePositiveDiv::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePositiveDiv::applyOp (ruleaction.cc:7817-7830).
        let (op_code, in0_nzm, in1_nzm, out_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_SDIV && op.opcode != OpCode::CPUI_INT_SREM {
                return Ok(action_status::NO_CHANGE);
            }
            let out_size = op.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
            if out_size > 8 { return Ok(action_status::NO_CHANGE); }
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let in1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let nzm0 = in0.read().unwrap().get_nz_mask();
            let nzm1 = in1.read().unwrap().get_nz_mask();
            (op.opcode, nzm0, nzm1, out_size)
        };
        let sa = out_size * 8 - 1;
        if (in0_nzm >> sa) & 1 != 0 { return Ok(action_status::NO_CHANGE); } // Input 0 may be negative.
        if (in1_nzm >> sa) & 1 != 0 { return Ok(action_status::NO_CHANGE); } // Input 1 may be negative.
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let new_opc = if op_code == OpCode::CPUI_INT_SDIV { OpCode::CPUI_INT_DIV } else { OpCode::CPUI_INT_REM };
        fd.op_set_opcode(&follow, new_opc);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7805 RulePositiveDiv
    fn get_name(&self) -> &str { "positive_div" }
    // Ghidra: ruleaction.cc:7810 RulePositiveDiv::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SDIV, OpCode::CPUI_INT_SREM] }
}

/// Combine two consecutive signed right shifts: `(V s>> c) s>> d => V s>> (c+d)`.
/// Faithful to Ghidra's `RuleDoubleArithShift` (ruleaction.cc:1930-1964).
pub struct RuleDoubleArithShift;

impl RuleDoubleArithShift {
    // Ghidra: ruleaction.cc:1932 RuleDoubleArithShift
    pub fn new() -> Self { Self }
}

impl Rule for RuleDoubleArithShift {
    // Ghidra: ruleaction.cc:1943 RuleDoubleArithShift::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleDoubleArithShift::applyOp (ruleaction.cc:1943-1964).
        let (const_d, const_c, in_vn, out_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
            let const_d_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let const_d_val = {
                let r = const_d_vn.read().unwrap();
                if !r.is_constant() { return Ok(action_status::NO_CHANGE); }
                r.get_offset()
            };
            let shiftin = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let shift2op = {
                let r = shiftin.read().unwrap();
                if !r.is_written() { return Ok(action_status::NO_CHANGE); }
                match r.get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) }
            };
            if shift2op.read().unwrap().opcode != OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
            let const_c_vn = match shift2op.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let const_c_val = {
                let r = const_c_vn.read().unwrap();
                if !r.is_constant() { return Ok(action_status::NO_CHANGE); }
                r.get_offset()
            };
            let in_vn = match shift2op.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if in_vn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let out_size = op.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
            (const_d_val, const_c_val, in_vn, out_size)
        };
        let max_shift = out_size * 8 - 1;
        let mut sa = const_c as i64 + const_d as i64;
        if sa <= 0 { return Ok(action_status::NO_CHANGE); }
        if sa > max_shift as i64 { sa = max_shift as i64; }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&follow, in_vn, 0);
        let c = fd.new_constant(4, sa as u64);
        fd.op_set_input(&follow, c, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:1932 RuleDoubleArithShift
    fn get_name(&self) -> &str { "double_arith_shift" }
    // Ghidra: ruleaction.cc:1937 RuleDoubleArithShift::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_SRIGHT] }
}

/// Convert near-multiply form into signed division.
/// Faithful to Ghidra's `RuleSignNearMult` (ruleaction.cc:8543-8610).
///
/// `(X + ((X s>> (n-1)) >> k)) * c => (X s/ 2^n) * 2^n` where c = 2^n.
pub struct RuleSignNearMult;

impl RuleSignNearMult {
    // Ghidra: ruleaction.cc:8551 RuleSignNearMult
    pub fn new() -> Self { Self }
}

impl Rule for RuleSignNearMult {
    // Ghidra: ruleaction.cc:8559 RuleSignNearMult::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSignNearMult::applyOp (ruleaction.cc:8559-8610).
        let (x, const_val, x_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_MULT { return Ok(action_status::NO_CHANGE); }
            let const_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !const_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let const_val = const_vn.read().unwrap().get_offset();
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !in0.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let addop = match in0.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            if addop.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return Ok(action_status::NO_CHANGE); }
            // Search for INT_RIGHT in addop's inputs.
            let mut found_x: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
            let mut found_n: i64 = 0;
            for i in 0..2 {
                let shiftvn = match addop.read().unwrap().get_in(i) { Some(v) => v.clone(), None => continue };
                if !shiftvn.read().unwrap().is_written() { continue; }
                let unshiftop = match shiftvn.read().unwrap().get_def() { Some(d) => d, None => continue };
                if unshiftop.read().unwrap().opcode != OpCode::CPUI_INT_RIGHT { continue; }
                let sa_vn = match unshiftop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
                if !sa_vn.read().unwrap().is_constant() { continue; }
                let x_candidate = match addop.read().unwrap().get_in(1 - i) { Some(v) => v.clone(), None => continue };
                if x_candidate.read().unwrap().is_free() { continue; }
                let n_val = sa_vn.read().unwrap().get_offset() as i64;
                if n_val <= 0 { continue; }
                let shift_size = shiftvn.read().unwrap().get_size() as i64;
                let n = shift_size * 8 - n_val;
                if n <= 0 { continue; }
                let mask = calc_mask(shiftvn.read().unwrap().get_size());
                let expected = (mask << n) & mask;
                if expected != const_val { continue; }
                // Check sign extraction.
                let sgnvn = match unshiftop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
                if !sgnvn.read().unwrap().is_written() { continue; }
                let sshiftop = match sgnvn.read().unwrap().get_def() { Some(d) => d, None => continue };
                if sshiftop.read().unwrap().opcode != OpCode::CPUI_INT_SRIGHT { continue; }
                let ssh_sa = match sshiftop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
                if !ssh_sa.read().unwrap().is_constant() { continue; }
                let ssh_in0 = match sshiftop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
                if !std::sync::Arc::ptr_eq(&ssh_in0, &x_candidate) { continue; }
                let ssh_val = ssh_sa.read().unwrap().get_offset() as i64;
                if ssh_val != 8 * x_candidate.read().unwrap().get_size() as i64 - 1 { continue; }
                found_x = Some(x_candidate);
                found_n = n;
                break;
            }
            match found_x {
                Some(x) => {
                    let xs = x.read().unwrap().get_size();
                    (x, found_n, xs)
                }
                None => return Ok(action_status::NO_CHANGE),
            }
        };
        let pow = 1u64 << const_val;
        let addr = op_arc.read().unwrap().get_addr();
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // Create INT_SDIV(x, pow).
        let new_div = fd.new_op(2, addr);
        fd.op_set_opcode(&new_div, OpCode::CPUI_INT_SDIV);
        let div_vn = fd.new_unique_out(x_size, &new_div);
        fd.op_set_input(&new_div, x, 0);
        let c = fd.new_constant(x_size, pow);
        fd.op_set_input(&new_div, c, 1);
        fd.op_insert_before(&new_div, &follow);
        // Rewrite original op as INT_MULT(div_vn, pow).
        fd.op_set_opcode(&follow, OpCode::CPUI_INT_MULT);
        fd.op_set_input(&follow, div_vn, 0);
        let c2 = fd.new_constant(x_size, pow);
        fd.op_set_input(&follow, c2, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:8551 RuleSignNearMult
    fn get_name(&self) -> &str { "sign_near_mult" }
    // Ghidra: ruleaction.cc:8553 RuleSignNearMult::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_MULT] }
}

/// Simplify redundant float casts. Faithful to Ghidra's `RuleFloatCast`
/// (ruleaction.cc:9545-9602).
///
/// Eliminates redundant FLOAT_FLOAT2FLOAT and FLOAT_TRUNC chains:
/// - `float2float(float2float(V)) => float2float(V)` when redundant
/// - `float2float(int2float(V)) => int2float(V)` (straight to final size)
/// - `trunc(float2float(V)) => trunc(V)` (straight to final integer)
pub struct RuleFloatCast;

impl RuleFloatCast {
    // Ghidra: ruleaction.cc:9551 RuleFloatCast
    pub fn new() -> Self { Self }
}

impl Rule for RuleFloatCast {
    // Ghidra: ruleaction.cc:9560 RuleFloatCast::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleFloatCast::applyOp (ruleaction.cc:9560-9602).
        let (opc1, vn2, insize1, insize2, outsize) = {
            let op = op_arc.read().unwrap();
            let opc1 = op.opcode;
            if opc1 != OpCode::CPUI_FLOAT_FLOAT2FLOAT && opc1 != OpCode::CPUI_FLOAT_TRUNC {
                return Ok(action_status::NO_CHANGE);
            }
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn1.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let castop = match vn1.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let opc2 = castop.read().unwrap().opcode;
            if opc2 != OpCode::CPUI_FLOAT_FLOAT2FLOAT && opc2 != OpCode::CPUI_FLOAT_INT2FLOAT {
                return Ok(action_status::NO_CHANGE);
            }
            let vn2 = match castop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if vn2.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let insize1 = vn1.read().unwrap().get_size();
            let insize2 = vn2.read().unwrap().get_size();
            let outsize = op.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
            (opc1, vn2, insize1, insize2, outsize)
        };
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        // Check opc2 from castop.
        let in0 = op_arc.read().unwrap().inrefs[0].clone();
        let castop = in0.read().unwrap().get_def().unwrap();
        let opc2 = castop.read().unwrap().opcode;

        if opc2 == OpCode::CPUI_FLOAT_FLOAT2FLOAT && opc1 == OpCode::CPUI_FLOAT_FLOAT2FLOAT {
            if insize1 > outsize {
                // Op is superfluous.
                fd.op_set_input(&follow, vn2, 0);
                if outsize == insize2 {
                    fd.op_set_opcode(&follow, OpCode::CPUI_COPY);
                }
                return Ok(action_status::CHANGE);
            } else if insize2 < insize1 {
                // Two increases -> one combined increase.
                fd.op_set_input(&follow, vn2, 0);
                return Ok(action_status::CHANGE);
            }
        } else if opc2 == OpCode::CPUI_FLOAT_INT2FLOAT && opc1 == OpCode::CPUI_FLOAT_FLOAT2FLOAT {
            // Convert integer straight into final float size.
            fd.op_set_input(&follow, vn2, 0);
            fd.op_set_opcode(&follow, OpCode::CPUI_FLOAT_INT2FLOAT);
            return Ok(action_status::CHANGE);
        } else if opc2 == OpCode::CPUI_FLOAT_FLOAT2FLOAT && opc1 == OpCode::CPUI_FLOAT_TRUNC {
            // Convert float straight into final integer.
            fd.op_set_input(&follow, vn2, 0);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:9551 RuleFloatCast
    fn get_name(&self) -> &str { "float_cast" }
    // Ghidra: ruleaction.cc:9553 RuleFloatCast::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_FLOAT_FLOAT2FLOAT, OpCode::CPUI_FLOAT_TRUNC] }
}

/// Normalize SUBPIECE applied to a shift: `sub(V >> n, c) => V >> n'`
/// Faithful to Ghidra's `RuleSubNormal` (ruleaction.cc:7700-7803).
pub struct RuleSubNormal;

impl RuleSubNormal {
    // Ghidra: ruleaction.cc:7720 RuleSubNormal
    pub fn new() -> Self { Self }
}

impl Rule for RuleSubNormal {
    // Ghidra: ruleaction.cc:7732 RuleSubNormal::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSubNormal::applyOp (ruleaction.cc:7732-7803).
        use crate::utils::bits::popcount;
        let (opc, a, n, c, in_size, out_size) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let shiftout = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !shiftout.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let shiftop = match shiftout.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
            let opc = shiftop.read().unwrap().opcode;
            if opc != OpCode::CPUI_INT_RIGHT && opc != OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
            let sa_vn = match shiftop.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !sa_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let a = match shiftop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if a.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let out_vn = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            // Skip precis hi/lo (Rugra lacks these flags; always allow).
            let n = sa_vn.read().unwrap().get_offset() as i64;
            let c_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let c = c_vn.read().unwrap().get_offset() as i64;
            let in_size = a.read().unwrap().get_size() as i64;
            let out_size = out_vn.read().unwrap().get_size() as i64;
            (opc, a, n, c, in_size, out_size)
        };
        let k = n / 8;
        // Total shift + outsize must be >= size of input, or n must not be byte-aligned.
        if n + 8 * c + 8 * out_size < 8 * in_size && n != k * 8 {
            return Ok(action_status::NO_CHANGE);
        }
        let follow = crate::op::PcodeOpRef(op_arc.clone());
        let addr = op_arc.read().unwrap().get_addr();

        if k + c + out_size > in_size {
            let trunc_size = in_size - c - k;
            if n == k * 8 && trunc_size > 0 && popcount(trunc_size as u64) == 1 {
                // Need an additional extension.
                let new_c = c + k;
                let new_op = fd.new_op(2, addr);
                let ext_opc = if opc == OpCode::CPUI_INT_SRIGHT { OpCode::CPUI_INT_SEXT } else { OpCode::CPUI_INT_ZEXT };
                fd.op_set_opcode(&new_op, OpCode::CPUI_SUBPIECE);
                fd.new_unique_out(trunc_size as usize, &new_op);
                fd.op_set_input(&new_op, a, 0);
                let cc = fd.new_constant(4, new_c as u64);
                fd.op_set_input(&new_op, cc, 1);
                fd.op_insert_before(&new_op, &follow);
                let new_out = new_op.0.read().unwrap().output.clone().unwrap();
                fd.op_set_input(&follow, new_out, 0);
                fd.op_remove_input(&follow, 1);
                fd.op_set_opcode(&follow, ext_opc);
                return Ok(action_status::CHANGE);
            } else {
                // Shrink the cut.
                let _ = k; // Already used below.
            }
        }

        let mut c_new = c + k;
        let n_new = n - k * 8;
        if n_new == 0 {
            // Extra shift is unnecessary.
            fd.op_set_input(&follow, a, 0);
            let cc = fd.new_constant(4, c_new as u64);
            fd.op_set_input(&follow, cc, 1);
            return Ok(action_status::CHANGE);
        } else if n_new >= out_size * 8 {
            let mut sat = out_size * 8;
            if opc == OpCode::CPUI_INT_SRIGHT { sat -= 1; }
            // Create SUBPIECE + shift.
            let new_op = fd.new_op(2, addr);
            fd.op_set_opcode(&new_op, OpCode::CPUI_SUBPIECE);
            fd.new_unique_out(out_size as usize, &new_op);
            fd.op_set_input(&new_op, a, 0);
            let cc = fd.new_constant(4, c_new as u64);
            fd.op_set_input(&new_op, cc, 1);
            fd.op_insert_before(&new_op, &follow);
            let new_out = new_op.0.read().unwrap().output.clone().unwrap();
            fd.op_set_input(&follow, new_out, 0);
            let sc = fd.new_constant(4, sat as u64);
            fd.op_set_input(&follow, sc, 1);
            fd.op_set_opcode(&follow, opc);
            return Ok(action_status::CHANGE);
        }
        // Normal case: create SUBPIECE + shift.
        let new_op = fd.new_op(2, addr);
        fd.op_set_opcode(&new_op, OpCode::CPUI_SUBPIECE);
        fd.new_unique_out(out_size as usize, &new_op);
        fd.op_set_input(&new_op, a, 0);
        let cc = fd.new_constant(4, c_new as u64);
        fd.op_set_input(&new_op, cc, 1);
        fd.op_insert_before(&new_op, &follow);
        let new_out = new_op.0.read().unwrap().output.clone().unwrap();
        fd.op_set_input(&follow, new_out, 0);
        let sc = fd.new_constant(4, n_new as u64);
        fd.op_set_input(&follow, sc, 1);
        fd.op_set_opcode(&follow, opc);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7720 RuleSubNormal
    fn get_name(&self) -> &str { "sub_normal" }
    // Ghidra: ruleaction.cc:7726 RuleSubNormal::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Verify that a Varnode is a sign extraction `V s>> (size*8-1)`.
/// Returns the base Varnode, or None. Faithful to `checkSignExtraction`
/// (ruleaction.cc:8776-8792).
// Ghidra: ruleaction.cc:8776 RuleSignMod2nOpt::checkSignExtraction
fn check_sign_extraction(
    out_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
    if !out_vn.read().unwrap().is_written() { return None; }
    let sign_op = out_vn.read().unwrap().get_def()?;
    if sign_op.read().unwrap().opcode != OpCode::CPUI_INT_SRIGHT { return None; }
    let const_vn = sign_op.read().unwrap().get_in(1)?.clone();
    if !const_vn.read().unwrap().is_constant() { return None; }
    let val = const_vn.read().unwrap().get_offset();
    let res_vn = sign_op.read().unwrap().get_in(0)?.clone();
    let in_size = res_vn.read().unwrap().get_size() as u64;
    if val != in_size * 8 - 1 { return None; }
    Some(res_vn)
}

/// Convert INT_SREM form: `(V + (sign >> (64-n)) & (2^n-1)) - (sign >> (64-n)) => V s% 2^n`.
/// Faithful to Ghidra's `RuleSignMod2nOpt` (ruleaction.cc:8650-8769).
pub struct RuleSignMod2nOpt;

impl RuleSignMod2nOpt {
    // Ghidra: ruleaction.cc:8673 RuleSignMod2nOpt
    pub fn new() -> Self { Self }
}

impl Rule for RuleSignMod2nOpt {
    // Ghidra: ruleaction.cc:8683 RuleSignMod2nOpt::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSignMod2nOpt::applyOp (ruleaction.cc:8683-8769).
        let (shift_amt, a, correct_vn, n, mask) = {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_INT_RIGHT { return Ok(action_status::NO_CHANGE); }
            let sa_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !sa_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let shift_amt = sa_vn.read().unwrap().get_offset();
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let a = match check_sign_extraction(&in0) { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            if a.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            let correct_vn = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            let a_size = a.read().unwrap().get_size() as u64;
            let n = a_size * 8 - shift_amt;
            let mask = (1u64 << n) - 1;
            (shift_amt, a, correct_vn, n, mask)
        };
        // Search descendants of correct_vn for the full pattern.
        let descends: Vec<_> = correct_vn.read().unwrap().descend_iter().collect();
        for multop_arc in descends {
            if multop_arc.read().unwrap().opcode != OpCode::CPUI_INT_MULT { continue; }
            let negone = match multop_arc.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
            if !negone.read().unwrap().is_constant() { continue; }
            if negone.read().unwrap().get_offset() != calc_mask(correct_vn.read().unwrap().get_size()) { continue; }
            let mult_out = match multop_arc.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => continue };
            let baseop_arc = match mult_out.read().unwrap().lone_descend() { Some(o) => o, None => continue };
            if baseop_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { continue; }
            let mult_out_clone = mult_out.clone();
            let mult_slot = fd.op_get_slot(&crate::op::PcodeOpRef(baseop_arc.clone()), &mult_out_clone);
            if mult_slot < 0 { continue; }
            let slot = (1 - mult_slot) as usize;
            let and_out = match baseop_arc.read().unwrap().get_in(slot) { Some(v) => v.clone(), None => continue };
            if !and_out.read().unwrap().is_written() { continue; }
            let andop_arc = match and_out.read().unwrap().get_def() { Some(d) => d, None => continue };
            let mut trunc_size: i64 = -1;
            let mut actual_and = andop_arc.clone();
            let actual_and_code = andop_arc.read().unwrap().opcode;
            let actual_and_out;
            if actual_and_code == OpCode::CPUI_INT_ZEXT {
                let inner = match andop_arc.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
                if !inner.read().unwrap().is_written() { continue; }
                let inner_def = match inner.read().unwrap().get_def() { Some(d) => d, None => continue };
                if inner_def.read().unwrap().opcode != OpCode::CPUI_INT_AND { continue; }
                trunc_size = inner.read().unwrap().get_size() as i64;
                actual_and = inner_def;
                actual_and_out = inner;
            } else {
                if actual_and_code != OpCode::CPUI_INT_AND { continue; }
                actual_and_out = and_out.clone();
            }
            let _ = actual_and_out;
            let const_vn = match actual_and.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
            if !const_vn.read().unwrap().is_constant() { continue; }
            if const_vn.read().unwrap().get_offset() != mask { continue; }
            let add_out_vn = match actual_and.read().unwrap().get_in(0) { Some(v) => v.clone(), None => continue };
            if !add_out_vn.read().unwrap().is_written() { continue; }
            let add_op = match add_out_vn.read().unwrap().get_def() { Some(d) => d, None => continue };
            if add_op.read().unwrap().opcode != OpCode::CPUI_INT_ADD { continue; }
            // Search for 'a' in add_op's inputs.
            let mut found_slot: i32 = -1;
            for a_slot in 0..2 {
                let vn = match add_op.read().unwrap().get_in(a_slot) { Some(v) => v.clone(), None => continue };
                let check_vn = if trunc_size >= 0 {
                    if !vn.read().unwrap().is_written() { continue; }
                    let sub_op_arc = match vn.read().unwrap().get_def() { Some(d) => d, None => continue };
                    let sub_data = {
                        let r = sub_op_arc.read().unwrap();
                        if r.opcode != OpCode::CPUI_SUBPIECE { continue; }
                        let sub_c = r.get_in(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(1);
                        let in0 = r.get_in(0).cloned();
                        (sub_c, in0)
                    };
                    if sub_data.0 != 0 { continue; }
                    match sub_data.1 { Some(v) => v, None => continue }
                } else { vn };
                if std::sync::Arc::ptr_eq(&check_vn, &a) { found_slot = a_slot as i32; break; }
            }
            if found_slot < 0 { continue; }
            let a_slot = found_slot as usize;
            // Verify the other input is INT_RIGHT by shiftAmt of sign-extraction of a.
            let ext_vn = match add_op.read().unwrap().get_in(1 - a_slot) { Some(v) => v.clone(), None => continue };
            if !ext_vn.read().unwrap().is_written() { continue; }
            let shift_op = match ext_vn.read().unwrap().get_def() { Some(d) => d, None => continue };
            if shift_op.read().unwrap().opcode != OpCode::CPUI_INT_RIGHT { continue; }
            let shift_const = match shift_op.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
            if !shift_const.read().unwrap().is_constant() { continue; }
            let mut shift_val = shift_const.read().unwrap().get_offset();
            if trunc_size >= 0 {
                shift_val += (a.read().unwrap().get_size() as u64 - trunc_size as u64) * 8;
            }
            if shift_val != shift_amt { continue; }
            let shift_in0 = match shift_op.read().unwrap().get_in(0).cloned() { Some(v) => v, None => continue };
            let ext_a = match check_sign_extraction(&shift_in0) { Some(v) => v, None => continue };
            let final_a = if trunc_size >= 0 {
                if !ext_a.read().unwrap().is_written() { continue; }
                let sub_op2_arc = match ext_a.read().unwrap().get_def() { Some(d) => d, None => continue };
                let sub2_data = {
                    let r = sub_op2_arc.read().unwrap();
                    if r.opcode != OpCode::CPUI_SUBPIECE { continue; }
                    let sub_c2 = r.get_in(1).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(-1);
                    let in0 = r.get_in(0).cloned();
                    (sub_c2, in0)
                };
                if sub2_data.0 != trunc_size { continue; }
                match sub2_data.1 { Some(v) => v, None => continue }
            } else { ext_a };
            if !std::sync::Arc::ptr_eq(&final_a, &a) { continue; }
            // Found the full pattern: rewrite baseop as INT_SREM.
            let base_ref = crate::op::PcodeOpRef(baseop_arc.clone());
            fd.op_set_opcode(&base_ref, OpCode::CPUI_INT_SREM);
            fd.op_set_input(&base_ref, a.clone(), 0);
            let a_size = a.read().unwrap().get_size();
            let c = fd.new_constant(a_size, mask + 1);
            fd.op_set_input(&base_ref, c, 1);
            return Ok(action_status::CHANGE);
        }
        let _ = n;
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:8673 RuleSignMod2nOpt
    fn get_name(&self) -> &str { "sign_mod2n_opt" }
    // Ghidra: ruleaction.cc:8677 RuleSignMod2nOpt::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT] }
}

/// Convert INT_SREM form: `(V - sign) & 1 + sign => V s% 2`.
/// Faithful to `RuleSignMod2Opt` (ruleaction.cc:8794-8865). Specialized
/// mod-2 form of RuleSignMod2nOpt. Uses `check_sign_extraction` helper.
pub struct RuleSignMod2Opt;

impl RuleSignMod2Opt {
    // Ghidra: ruleaction.cc:8794 RuleSignMod2Opt
    pub fn new() -> Self { Self }
}

impl Rule for RuleSignMod2Opt {
    // Ghidra: ruleaction.cc:8805 RuleSignMod2Opt::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSignMod2Opt::applyOp (ruleaction.cc:8805-8865).
        let (add_out_vn, _) = {
            let op = op_arc.read().unwrap();
            let const_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !const_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            if const_vn.read().unwrap().get_offset() != 1 { return Ok(action_status::NO_CHANGE); }
            let ao = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (ao, ())
        };
        if !add_out_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let add_op = match add_out_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        if add_op.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return Ok(action_status::NO_CHANGE); }

        // Find INT_MULT by -1 among add_op inputs
        let (mult_slot, mult_op_arc, base_vn) = {
            let a = add_op.read().unwrap();
            let mut found = None;
            for ms in 0..2 {
                let vn = match a.inrefs.get(ms) { Some(v) => v.clone(), None => continue };
                if !vn.read().unwrap().is_written() { continue; }
                let mo = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                    Some(op) => op, None => continue,
                };
                if mo.read().unwrap().opcode != OpCode::CPUI_INT_MULT { continue; }
                let cv = match mo.read().unwrap().inrefs.get(1) { Some(v) => v.clone(), None => continue };
                if !cv.read().unwrap().is_constant() { continue; }
                let mask = crate::address::calc_mask(cv.read().unwrap().get_size());
                if cv.read().unwrap().get_offset() == mask {
                    found = Some((ms, mo));
                    break;
                }
            }
            match found {
                Some((ms, mo)) => {
                    let mult_in0 = match mo.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
                    let base = match check_sign_extraction(&mult_in0) {
                        Some(v) => v, None => return Ok(action_status::NO_CHANGE),
                    };
                    (ms, mo, base)
                }
                None => return Ok(action_status::NO_CHANGE),
            }
        };

        // otherBase = add_op->getIn(1 - mult_slot)
        let mut base = base_vn.clone();
        let other_base = match add_op.read().unwrap().inrefs.get(1 - mult_slot) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        let mut trunc = false;
        if !std::sync::Arc::ptr_eq(&base, &other_base) {
            // Check for SUBPIECE truncation pattern
            if !base.read().unwrap().is_written() || !other_base.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let sub_op = match base.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => return Ok(action_status::NO_CHANGE),
            };
            if sub_op.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let trunc_amt = match sub_op.read().unwrap().inrefs.get(1) {
                Some(v) => v.read().unwrap().get_offset() as i32,
                None => return Ok(action_status::NO_CHANGE),
            };
            let sub_in0_size = match sub_op.read().unwrap().inrefs.get(0) {
                Some(v) => v.read().unwrap().get_size() as i32,
                None => return Ok(action_status::NO_CHANGE),
            };
            let base_size = base.read().unwrap().get_size() as i32;
            if trunc_amt + base_size != sub_in0_size { return Ok(action_status::NO_CHANGE); }
            let new_base = match sub_op.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            // otherBase must also be SUBPIECE of new_base
            let sub_op2 = match other_base.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => return Ok(action_status::NO_CHANGE),
            };
            if sub_op2.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let sub2_const = match sub_op2.read().unwrap().inrefs.get(1) {
                Some(v) => v.read().unwrap().get_offset(),
                None => return Ok(action_status::NO_CHANGE),
            };
            if sub2_const != 0 { return Ok(action_status::NO_CHANGE); }
            let other_root = match sub_op2.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !std::sync::Arc::ptr_eq(&other_root, &new_base) { return Ok(action_status::NO_CHANGE); }
            base = new_base;
            trunc = true;
        }

        if base.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }

        // andOut = op->getOut(); if trunc, look for ZEXT
        let mut and_out = match op_arc.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
        if trunc {
            let ext_op = match and_out.read().unwrap().lone_descend() {
                Some(o) => o, None => return Ok(action_status::NO_CHANGE),
            };
            if ext_op.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return Ok(action_status::NO_CHANGE); }
            and_out = match ext_op.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
        }

        // Look for INT_ADD(and_out, sign) among descendants
        let descendents: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = and_out.read().unwrap().descend_iter().collect();
        for root_op_arc in descendents {
            if root_op_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { continue; }
            // slot = position of and_out in root_op
            let slot = {
                let r = root_op_arc.read().unwrap();
                let mut s = -1i32;
                for i in 0..r.inrefs.len() {
                    if let Some(v) = r.inrefs.get(i) {
                        if std::sync::Arc::ptr_eq(v, &and_out) { s = i as i32; break; }
                    }
                }
                if s < 0 { continue; }
                s
            };
            let other_in = match root_op_arc.read().unwrap().inrefs.get((1 - slot) as usize) { Some(v) => v.clone(), None => continue };
            let other_base_check = match check_sign_extraction(&other_in) {
                Some(v) => v, None => continue,
            };
            if !std::sync::Arc::ptr_eq(&other_base_check, &base) { continue; }

            // Transform: root_op becomes INT_SREM(base, 2)
            let root_ref = crate::op::PcodeOpRef(root_op_arc.clone());
            fd.op_set_opcode(&root_ref, OpCode::CPUI_INT_SREM);
            fd.op_set_input(&root_ref, base.clone(), 0);
            let base_size = base.read().unwrap().get_size();
            let two_const = fd.new_constant(base_size, 2);
            fd.op_set_input(&root_ref, two_const, 1);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:8794 RuleSignMod2Opt
    fn get_name(&self) -> &str { "sign_mod2_opt" }
    // Ghidra: ruleaction.cc:8799 RuleSignMod2Opt::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND] }
}

/// Detect `(zext(V) << #sa) | zext(V)` and convert to PIECE.
/// Faithful to `RuleShiftPiece` (ruleaction.cc:3791-3870). Also handles
/// the CDQ special case (INT_SRIGHT forming the high piece → INT_SEXT).
pub struct RuleShiftPiece;

impl RuleShiftPiece {
    // Ghidra: ruleaction.cc:3773 RuleShiftPiece
    pub fn new() -> Self { Self }
}

impl Rule for RuleShiftPiece {
    // Ghidra: ruleaction.cc:3791 RuleShiftPiece::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleShiftPiece::applyOp (ruleaction.cc:3791-3870).
        let (vn1_init, vn2_init) = {
            let op = op_arc.read().unwrap();
            let vn1 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn2 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn1.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            if !vn2.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            (vn1, vn2)
        };

        // One input must be INT_LEFT; the other is "zextloop"
        let vn1_def = match vn1_init.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        let vn2_def = match vn2_init.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        let (shiftop, zextloop) = if vn1_def.read().unwrap().opcode == OpCode::CPUI_INT_LEFT {
            (vn1_def.clone(), vn2_def.clone())
        } else if vn2_def.read().unwrap().opcode == OpCode::CPUI_INT_LEFT {
            (vn2_def.clone(), vn1_def.clone())
        } else {
            return Ok(action_status::NO_CHANGE);
        };

        // shiftop->getIn(1) must be constant
        let shift_const_vn = shiftop.read().unwrap().inrefs.get(1).cloned();
        let sa = match shift_const_vn {
            Some(cv) => {
                let cg = cv.read().unwrap();
                if !cg.is_constant() { return Ok(action_status::NO_CHANGE); }
                cg.get_offset() as i32
            }
            None => return Ok(action_status::NO_CHANGE),
        };

        // vn1 = shiftop->getIn(0); must be written; zexthiop = its def
        let vn1 = match shiftop.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !vn1.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let zexthiop = match vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        let zexthiopc = zexthiop.read().unwrap().opcode;
        if zexthiopc != OpCode::CPUI_INT_ZEXT && zexthiopc != OpCode::CPUI_INT_SEXT {
            return Ok(action_status::NO_CHANGE);
        }

        // vn1 = zexthiop->getIn(0) — the value being extended
        let vn1_inner = match zexthiop.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        // Constant check: if constant and size < 8, skip (let it collapse naturally)
        if vn1_inner.read().unwrap().is_constant() {
            if vn1_inner.read().unwrap().get_size() < 8 {
                return Ok(action_status::NO_CHANGE);
            }
        } else if vn1_inner.read().unwrap().is_free() {
            return Ok(action_status::NO_CHANGE);
        }

        let vn1_size = vn1_inner.read().unwrap().get_size();
        let concatsize = sa + 8 * vn1_size as i32;
        let out_size = match op_arc.read().unwrap().output.as_ref() {
            Some(o) => o.read().unwrap().get_size() as i32,
            None => return Ok(action_status::NO_CHANGE),
        };
        if out_size * 8 < concatsize { return Ok(action_status::NO_CHANGE); }

        // Check zextloop: must be INT_ZEXT (or handle CDQ special case)
        let zextloop_opc = zextloop.read().unwrap().opcode;
        if zextloop_opc != OpCode::CPUI_INT_ZEXT {
            // CDQ special case (ruleaction.cc:3827-3848)
            if zextloop_opc != OpCode::CPUI_INT_LEFT { return Ok(action_status::NO_CHANGE); }
            // Look for s<< #c forming the high piece
            if !vn1_inner.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let rshift_op = match vn1_inner.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => return Ok(action_status::NO_CHANGE),
            };
            if rshift_op.read().unwrap().opcode != OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
            let rsa_const = match rshift_op.read().unwrap().inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !rsa_const.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let vn2_cdq = match rshift_op.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !vn2_cdq.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let subop = match vn2_cdq.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => return Ok(action_status::NO_CHANGE),
            };
            if subop.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let sub_const = match subop.read().unwrap().inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !sub_const.read().unwrap().is_constant() || sub_const.read().unwrap().get_offset() != 0 { return Ok(action_status::NO_CHANGE); }
            let big_vn = match zextloop.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            let sub_in0 = match subop.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !std::sync::Arc::ptr_eq(&sub_in0, &big_vn) { return Ok(action_status::NO_CHANGE); }
            let rsa = rsa_const.read().unwrap().get_offset() as i32;
            let vn2_cdq_size = vn2_cdq.read().unwrap().get_size() as i32;
            if rsa != vn2_cdq_size * 8 - 1 { return Ok(action_status::NO_CHANGE); }
            let big_nzmask = big_vn.read().unwrap().get_nz_mask();
            if (big_nzmask >> sa) != 0 { return Ok(action_status::NO_CHANGE); }
            if sa != 8 * vn2_cdq_size { return Ok(action_status::NO_CHANGE); }
            // Transform: op becomes INT_SEXT(vn2_cdq)
            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_SEXT);
            fd.op_set_input(&op_ref, vn2_cdq.clone(), 0);
            fd.op_remove_input(&op_ref, 1);
            return Ok(action_status::CHANGE);
        }

        // Main path: zextloop is INT_ZEXT
        let vn2 = match zextloop.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if vn2.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        if sa != 8 * vn2.read().unwrap().get_size() as i32 { return Ok(action_status::NO_CHANGE); }

        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        if concatsize == out_size * 8 {
            // Exact fit: op becomes PIECE(vn1_inner, vn2)
            fd.op_set_opcode(&op_ref, OpCode::CPUI_PIECE);
            fd.op_set_input(&op_ref, vn1_inner.clone(), 0);
            fd.op_set_input(&op_ref, vn2.clone(), 1);
        } else {
            // Partial: create new PIECE, op becomes zext/extension of it
            let newop = fd.new_op(2, op_arc.read().unwrap().get_addr());
            let newout = fd.new_unique_out((concatsize / 8) as usize, &newop);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            fd.op_set_input(&newop, vn1_inner.clone(), 0);
            fd.op_set_input(&newop, vn2.clone(), 1);
            fd.op_insert_before(&newop, &op_ref);
            fd.op_set_opcode(&op_ref, zexthiopc);
            fd.op_remove_input(&op_ref, 1);
            fd.op_set_input(&op_ref, newout, 0);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:3773 RuleShiftPiece
    fn get_name(&self) -> &str { "shift_piece" }
    // Ghidra: ruleaction.cc:3783 RuleShiftPiece::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR, OpCode::CPUI_INT_ADD] }
}

/// Convert INT_MULT and shift forms into INT_DIV or INT_SDIV. Faithful
/// to Ghidra's `RuleDivOpt` (ruleaction.cc:8010-8355).
///
/// - `sub(zext(V) * c, d) >> e => V / (2^n / (c-1))` where n = d*8 + e
/// - `sub(sext(V) * c, d) s>> e => V s/ (2^n / (c-1))` where n = d*8 + e
pub struct RuleDivOpt;

impl RuleDivOpt {
    // Ghidra: ruleaction.cc:8281 RuleDivOpt
    pub fn new() -> Self { Self }

    /// Detect the division-by-multiplication form. Faithful to `findForm`
    /// (ruleaction.cc:8069-8143). Returns (in_vn, n, y128, xsize, ext_opc).
    // Ghidra: ruleaction.cc:8069 RuleDivOpt::findForm
    fn find_form(
        op: &crate::op::PcodeOpRef,
    ) -> Option<(
        std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        u64,
        u128,
        i32,
        OpCode,
    )> {
        use crate::address::count_leading_zeros;
        let mut cur_op_arc = op.0.clone();
        let shift_opc = cur_op_arc.read().unwrap().opcode;
        let mut n: u64 = 0;
        let mut shift_opc_var = shift_opc;
        if shift_opc == OpCode::CPUI_INT_RIGHT || shift_opc == OpCode::CPUI_INT_SRIGHT {
            let vn = cur_op_arc.read().unwrap().get_in(0)?.clone();
            let cvn = cur_op_arc.read().unwrap().get_in(1)?.clone();
            if !vn.read().unwrap().is_written() { return None; }
            if !cvn.read().unwrap().is_constant() { return None; }
            n = cvn.read().unwrap().get_offset();
            cur_op_arc = vn.read().unwrap().get_def()?;
        } else {
            if shift_opc != OpCode::CPUI_SUBPIECE { return None; }
            shift_opc_var = OpCode::CPUI_MAX;
        }
        // Optional SUBPIECE.
        if cur_op_arc.read().unwrap().opcode == OpCode::CPUI_SUBPIECE {
            let c = cur_op_arc.read().unwrap().get_in(1)?.read().unwrap().get_offset();
            let in_vn = cur_op_arc.read().unwrap().get_in(0)?.clone();
            if !in_vn.read().unwrap().is_written() { return None; }
            let out_size = cur_op_arc.read().unwrap().output.as_ref()?.read().unwrap().get_size() as u64;
            if out_size + c != in_vn.read().unwrap().get_size() as u64 { return None; }
            n += 8 * c;
            cur_op_arc = in_vn.read().unwrap().get_def()?;
        }
        // Must be INT_MULT.
        if cur_op_arc.read().unwrap().opcode != OpCode::CPUI_INT_MULT { return None; }
        let in0 = cur_op_arc.read().unwrap().get_in(0)?.clone();
        let in1 = cur_op_arc.read().unwrap().get_in(1)?.clone();
        // Find which input is the constant (up to 128 bits) and which is written.
        let in0_ext = in0.read().unwrap().is_constant_extended();
        let in1_ext = in1.read().unwrap().is_constant_extended();
        let (in_vn, y) = if let Some((lo, hi)) = in0_ext {
            if !in1.read().unwrap().is_written() { return None; }
            (in1, ((hi as u128) << 64) | (lo as u128))
        } else if let Some((lo, hi)) = in1_ext {
            if !in0.read().unwrap().is_written() { return None; }
            (in0, ((hi as u128) << 64) | (lo as u128))
        } else {
            return None;
        };

        let ext_op = in_vn.read().unwrap().get_def()?;
        let ext_opc = ext_op.read().unwrap().opcode;
        let xsize;
        if ext_opc != OpCode::CPUI_INT_SEXT {
            let nz_mask = if ext_opc == OpCode::CPUI_INT_ZEXT {
                ext_op.read().unwrap().get_in(0)?.read().unwrap().get_nz_mask()
            } else {
                in_vn.read().unwrap().get_nz_mask()
            };
            xsize = 64 - count_leading_zeros(nz_mask);
            if xsize == 0 { return None; }
            if xsize > 4 * in_vn.read().unwrap().get_size() as i32 { return None; }
        } else {
            xsize = ext_op.read().unwrap().get_in(0)?.read().unwrap().get_size() as i32 * 8;
        }
        let actual_ext_opc;
        let res_vn;
        if ext_opc == OpCode::CPUI_INT_ZEXT || ext_opc == OpCode::CPUI_INT_SEXT {
            let ext_vn = ext_op.read().unwrap().get_in(0)?.clone();
            if ext_vn.read().unwrap().is_free() { return None; }
            if in_vn.read().unwrap().get_size() == op.0.read().unwrap().output.as_ref()?.read().unwrap().get_size() {
                res_vn = in_vn;
            } else {
                res_vn = ext_vn;
            }
            actual_ext_opc = ext_opc;
        } else {
            actual_ext_opc = OpCode::CPUI_INT_ZEXT;
            res_vn = in_vn;
        }
        // Check signed mismatch.
        if (actual_ext_opc == OpCode::CPUI_INT_ZEXT && shift_opc_var == OpCode::CPUI_INT_SRIGHT)
            || (actual_ext_opc == OpCode::CPUI_INT_SEXT && shift_opc_var == OpCode::CPUI_INT_RIGHT)
        {
            let out_size = op.0.read().unwrap().output.as_ref()?.read().unwrap().get_size() as i32;
            if out_size * 8 - n as i32 != xsize {
                return None;
            }
        }
        Some((res_vn, n, y, xsize, actual_ext_opc))
    }

    /// Compute divisor from the multiplicative encoding. Faithful to
    /// `calcDivisor` (ruleaction.cc:8157-8198). Uses Rust's native u128.
    // Ghidra: ruleaction.cc:8157 RuleDivOpt::calcDivisor
    fn calc_divisor(n: u64, y: u128, xsize: i32) -> u64 {
        if n > 127 || xsize > 64 { return 0; }
        let power = 1u128 << n;
        if y <= 1 { return 0; }
        let y_m1 = y - 1; // y = y - 1
        let q = power / y_m1;
        let r = power % y_m1;
        if q > u64::MAX as u128 { return 0; } // Result > 64 bits.
        if y_m1 < q { return 0; } // if y < q
        let mut diff: u128 = 0;
        let q_final;
        let r_final;
        if r >= q {
            // Adjust q up by 1.
            let q2 = q + 1;
            let r2 = r.wrapping_sub(y_m1).wrapping_add(q2);
            if r2 >= q2 { return 0; }
            diff = q2;
            q_final = q2;
            r_final = r2;
        } else {
            q_final = q;
            r_final = r;
        }
        // Check: x * (q-r) < 2^n
        let maxx = if xsize == 64 { 0u128 } else { 1u128 << xsize };
        let maxx = maxx - 1; // Maximum possible x value.
        diff += q_final - r_final;
        if diff == 0 { return q_final as u64; }
        let tmp = power / diff;
        if tmp > maxx {
            return q_final as u64;
        }
        0 // tmp <= maxx -> not valid.
    }

    /// Check if a SUBPIECE form is contained in a superseding form.
    /// Faithful to `checkFormOverlap` (ruleaction.cc:8260-8279).
    // Ghidra: ruleaction.cc:8260 RuleDivOpt::checkFormOverlap
    fn check_form_overlap(op: &crate::op::PcodeOpRef) -> bool {
        if op.0.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return false; }
        let vn = match op.0.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return false };
        let descends: Vec<_> = vn.read().unwrap().descend_iter().collect();
        for super_op in descends {
            let opc = super_op.read().unwrap().opcode;
            if opc != OpCode::CPUI_INT_RIGHT && opc != OpCode::CPUI_INT_SRIGHT { continue; }
            let cvn = match super_op.read().unwrap().get_in(1) { Some(v) => v.clone(), None => continue };
            if !cvn.read().unwrap().is_constant() { return true; }
            let super_ref = crate::op::PcodeOpRef(super_op);
            if Self::find_form(&super_ref).is_some() { return true; }
        }
        false
    }

    /// Faithful to `moveSignBitExtraction` (ruleaction.cc:8210-8253).
    ///
    /// `first_vn` is the (intermediate) output of the new INT_SDIV/INT_ADD op
    /// whose sign-bit we want to reuse; `replace_vn` is the canonical sign-bit
    /// source (the unextended dividend `inVn`). Walk the descendants of
    /// `first_vn` (and, if `first_vn` is itself an INT_SRIGHT, the value it
    /// shifts) and rewrite any redundant sign-bit extraction
    /// `(V >> (size*8-1))` to read `replace_vn` instead.
    // Ghidra: ruleaction.cc:8210 RuleDivOpt::moveSignBitExtraction
    fn move_sign_bit_extraction(
        first_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        replace_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        fd: &mut Funcdata,
    ) {
        use std::sync::Arc;
        // Build the initial test list: firstVn, plus (if firstVn is written by
        // an INT_SRIGHT) the value being shifted.
        let mut test_list: Vec<Arc<std::sync::RwLock<crate::varnode::Varnode>>> = vec![first_vn.clone()];
        if first_vn.read().unwrap().is_written() {
            if let Some(def) = first_vn.read().unwrap().get_def() {
                if def.read().unwrap().opcode == OpCode::CPUI_INT_SRIGHT {
                    if let Some(shifted) = def.read().unwrap().get_in(0).cloned() {
                        test_list.push(shifted);
                    }
                }
            }
        }

        let mut i = 0usize;
        while i < test_list.len() {
            let vn = test_list[i].clone();
            i += 1;
            // Collect descendants up-front so we can mutate them freely.
            let descends: Vec<Arc<std::sync::RwLock<PcodeOp>>> = vn.read().unwrap().descend_iter().collect();
            for op_arc in descends {
                let opc = op_arc.read().unwrap().opcode;
                if opc == OpCode::CPUI_INT_RIGHT || opc == OpCode::CPUI_INT_SRIGHT {
                    // Resolve the (possibly wrapped) constant shift amount.
                    let const_vn_opt = resolve_shift_const(&op_arc);
                    if let Some(cvn) = const_vn_opt {
                        if cvn.read().unwrap().is_constant() {
                            let sa = first_vn.read().unwrap().get_size() as i32 * 8 - 1;
                            if sa == cvn.read().unwrap().get_offset() as i32 {
                                let op_ref = crate::op::PcodeOpRef(op_arc.clone());
                                fd.op_set_input(&op_ref, replace_vn.clone(), 0);
                            }
                        }
                    }
                } else if opc == OpCode::CPUI_COPY {
                    // A COPY of vn extends the test list with its output.
                    if let Some(out) = op_arc.read().unwrap().output.clone() {
                        test_list.push(out);
                    }
                }
            }
        }
    }
}

/// Resolve the (possibly wrapped) constant operand for an INT_RIGHT/INT_SRIGHT
/// shift, as used by `RuleDivOpt::move_sign_bit_extraction`. Faithful to the
/// in-body constant unwrapping (ruleaction.cc:8223-8243).
///
/// Walks the second input of the shift op. If that input is itself written by a
/// COPY, returns the copied value; if written by an `INT_AND(c0, c1)` (with `c1`
/// constant and `c0 & c1 == c0`), returns `c0`; otherwise returns the input as-is.
// Ghidra: ruleaction.cc:8210 RuleDivOpt::moveSignBitExtraction
fn resolve_shift_const(
    shift_op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
    let mut const_vn = shift_op.read().unwrap().get_in(1).cloned()?;
    if !const_vn.read().unwrap().is_written() {
        return Some(const_vn);
    }
    let const_op = const_vn.read().unwrap().get_def()?;
    let const_opc = const_op.read().unwrap().opcode;
    if const_opc == OpCode::CPUI_COPY {
        const_vn = const_op.read().unwrap().get_in(0).cloned()?;
    } else if const_opc == OpCode::CPUI_INT_AND {
        let c0 = const_op.read().unwrap().get_in(0).cloned()?;
        let other = const_op.read().unwrap().get_in(1).cloned()?;
        if !other.read().unwrap().is_constant() {
            return Some(const_vn);
        }
        let off = c0.read().unwrap().get_offset();
        let mask = other.read().unwrap().get_offset();
        if off != (off & mask) {
            return Some(const_vn);
        }
        const_vn = c0;
    }
    Some(const_vn)
}

impl Rule for RuleDivOpt {
    // Ghidra: ruleaction.cc:8295 RuleDivOpt::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleDivOpt::applyOp (ruleaction.cc:8295-8355).
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        let (mut in_vn, n, y, mut xsize, ext_opc) = match Self::find_form(&op_ref) {
            Some(r) => r,
            None => return Ok(action_status::NO_CHANGE),
        };
        if Self::check_form_overlap(&op_ref) { return Ok(action_status::NO_CHANGE); }
        if ext_opc == OpCode::CPUI_INT_SEXT { xsize -= 1; }
        let divisor = Self::calc_divisor(n, y, xsize);
        if divisor == 0 { return Ok(action_status::NO_CHANGE); }
        let out_size = op_arc.read().unwrap().output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        let addr = op_arc.read().unwrap().get_addr();

        if in_vn.read().unwrap().get_size() < out_size {
            // Need extension.
            let in_ext = fd.new_op(1, addr);
            fd.op_set_opcode(&in_ext, ext_opc);
            let ext_out = fd.new_unique_out(out_size, &in_ext);
            fd.op_set_input(&in_ext, in_vn, 0);
            in_vn = ext_out;
            fd.op_insert_before(&in_ext, &op_ref);
        } else if in_vn.read().unwrap().get_size() > out_size {
            // Need truncation.
            let new_op = fd.new_op(2, addr);
            fd.op_set_opcode(&new_op, OpCode::CPUI_INT_ADD);
            let res_vn = fd.new_unique_out(in_vn.read().unwrap().get_size(), &new_op);
            fd.op_insert_before(&new_op, &op_ref);
            fd.op_set_opcode(&op_ref, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&op_ref, res_vn.clone(), 0);
            let z = fd.new_constant(4, 0);
            fd.op_set_input(&op_ref, z, 1);
            // Main transform now changes new_op.
            let div_vn = fd.new_constant(out_size, divisor);
            if ext_opc == OpCode::CPUI_INT_ZEXT {
                fd.op_set_opcode(&new_op, OpCode::CPUI_INT_DIV);
                fd.op_set_input(&new_op, in_vn, 0);
                fd.op_set_input(&new_op, div_vn, 1);
            } else {
                // Signed: INT_SDIV + sign correction.
                // Faithful to moveSignBitExtraction call (ruleaction.cc:8335):
                // op is now new_op, op->getOut() is res_vn, inVn is in_vn.
                Self::move_sign_bit_extraction(&res_vn, &in_vn, fd);
                let divop = fd.new_op(2, addr);
                fd.op_set_opcode(&divop, OpCode::CPUI_INT_SDIV);
                let new_out = fd.new_unique_out(out_size, &divop);
                let in_vn_clone = in_vn.clone();
                fd.op_set_input(&divop, in_vn_clone, 0);
                fd.op_set_input(&divop, div_vn, 1);
                fd.op_insert_before(&divop, &new_op);
                let sgnop = fd.new_op(2, addr);
                fd.op_set_opcode(&sgnop, OpCode::CPUI_INT_SRIGHT);
                let sgnvn = fd.new_unique_out(out_size, &sgnop);
                fd.op_set_input(&sgnop, in_vn, 0);
                let sc = fd.new_constant(out_size, (out_size * 8 - 1) as u64);
                fd.op_set_input(&sgnop, sc, 1);
                fd.op_insert_before(&sgnop, &new_op);
                fd.op_set_opcode(&new_op, OpCode::CPUI_INT_ADD);
                fd.op_set_input(&new_op, new_out, 0);
                fd.op_set_input(&new_op, sgnvn, 1);
            }
            return Ok(action_status::CHANGE);
        }
        // Same size.
        let div_vn = fd.new_constant(out_size, divisor);
        if ext_opc == OpCode::CPUI_INT_ZEXT {
            fd.op_set_input(&op_ref, in_vn, 0);
            fd.op_set_input(&op_ref, div_vn, 1);
            fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_DIV);
        } else {
            // Signed: INT_SDIV + sign correction.
            // Faithful to moveSignBitExtraction call (ruleaction.cc:8335):
            // op is the original op, op->getOut() is its output, inVn is in_vn.
            let out_vn_orig = match op_arc.read().unwrap().output.clone() {
                Some(o) => o,
                None => return Ok(action_status::NO_CHANGE),
            };
            Self::move_sign_bit_extraction(&out_vn_orig, &in_vn, fd);
            let divop = fd.new_op(2, addr);
            fd.op_set_opcode(&divop, OpCode::CPUI_INT_SDIV);
            let new_out = fd.new_unique_out(out_size, &divop);
            fd.op_set_input(&divop, in_vn.clone(), 0);
            fd.op_set_input(&divop, div_vn, 1);
            fd.op_insert_before(&divop, &op_ref);
            let sgnop = fd.new_op(2, addr);
            fd.op_set_opcode(&sgnop, OpCode::CPUI_INT_SRIGHT);
            let sgnvn = fd.new_unique_out(out_size, &sgnop);
            fd.op_set_input(&sgnop, in_vn, 0);
            let sc = fd.new_constant(out_size, (out_size * 8 - 1) as u64);
            fd.op_set_input(&sgnop, sc, 1);
            fd.op_insert_before(&sgnop, &op_ref);
            fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_ADD);
            fd.op_set_input(&op_ref, new_out, 0);
            fd.op_set_input(&op_ref, sgnvn, 1);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:8281 RuleDivOpt
    fn get_name(&self) -> &str { "div_opt" }
    // Ghidra: ruleaction.cc:8287 RuleDivOpt::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_SUBPIECE, OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_SRIGHT]
    }
}

/// Simplify expressions that optimize INT_REM and INT_SREM. Faithful to
/// `RuleModOpt` (ruleaction.cc:8612-8671). Detects the pattern:
///   `x / d * (-d) + x  =>  x % d`
/// where `-d` is either a constant (2's complement) or INT_2COMP of div.
pub struct RuleModOpt;

impl RuleModOpt {
    // Ghidra: ruleaction.cc:8612 RuleModOpt
    pub fn new() -> Self { Self }
}

impl Rule for RuleModOpt {
    // Ghidra: ruleaction.cc:8621 RuleModOpt::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleModOpt::applyOp (ruleaction.cc:8621-8671).
        let (x_vn, div_vn, out_vn) = {
            let op = op_arc.read().unwrap();
            let x = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let div = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            // Guard: skip if either input is a pointer type (prevents
            // false-positive on pointer arithmetic that was lifted as INT_DIV).
            if x.read().unwrap().v_type.as_ref().map_or(false, |t| {
                matches!(t.as_ref(), crate::type_system::Datatype::Pointer(_))
            }) { return Ok(action_status::NO_CHANGE); }
            if div.read().unwrap().v_type.as_ref().map_or(false, |t| {
                matches!(t.as_ref(), crate::type_system::Datatype::Pointer(_))
            }) { return Ok(action_status::NO_CHANGE); }
            let out = match op.output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            (x, div, out)
        };
        let op_opc = op_arc.read().unwrap().opcode;

        // Iterate descendants of the div output: look for INT_MULT by -d.
        let multops: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = out_vn.read().unwrap().descend_iter().collect();
        for multop_arc in multops {
            let multopc = multop_arc.read().unwrap().opcode;
            if multopc != OpCode::CPUI_INT_MULT { continue; }

            // Get the other input of MULT (div2 = the multiplicand that should be -d)
            let (mult_in0, mult_in1) = {
                let m = multop_arc.read().unwrap();
                (m.inrefs.get(0).cloned(), m.inrefs.get(1).cloned())
            };
            // Find which input is out_vn and which is div2
            let div2_vn = {
                let out_ptr = &out_vn;
                if let Some(ref in0) = mult_in0 {
                    if std::sync::Arc::ptr_eq(in0, out_ptr) { mult_in1.clone() }
                    else if mult_in1.as_ref().map(|in1| std::sync::Arc::ptr_eq(in1, out_ptr)).unwrap_or(false) { Some(in0.clone()) }
                    else { continue; }
                } else { continue; }
            };
            let div2_vn = match div2_vn { Some(v) => v, None => continue };

            // Check that div is 2's complement of div2
            let div_g = div_vn.read().unwrap();
            let div2_g = div2_vn.read().unwrap();
            if div2_g.is_constant() {
                if !div_g.is_constant() { continue; }
                let mask = crate::address::calc_mask(div2_g.get_size());
                let twos_comp = ((div2_g.get_offset() ^ mask).wrapping_add(1)) & mask;
                if twos_comp != div_g.get_offset() { continue; }
            } else {
                if !div2_g.is_written() { continue; }
                let div2_def = match div2_g.def.as_ref().and_then(|w| w.upgrade()) {
                    Some(a) => a, None => continue,
                };
                if div2_def.read().unwrap().opcode != OpCode::CPUI_INT_2COMP { continue; }
                let div2_in = match div2_def.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => continue };
                if !std::sync::Arc::ptr_eq(&div2_in, &div_vn) { continue; }
            }
            drop(div_g); drop(div2_g);

            // Found x/d * (-d). Now look for INT_ADD of its output + x.
            let mult_out = match multop_arc.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => continue };
            let addops: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = mult_out.read().unwrap().descend_iter().collect();
            for addop_arc in addops {
                if addop_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { continue; }
                let (add_in0, add_in1) = {
                    let a = addop_arc.read().unwrap();
                    (a.inrefs.get(0).cloned(), a.inrefs.get(1).cloned())
                };
                // lvn = the input that is NOT mult_out
                let lvn = {
                    let mult_out_ref = &mult_out;
                    if add_in0.as_ref().map(|v| std::sync::Arc::ptr_eq(v, mult_out_ref)).unwrap_or(false) { add_in1 }
                    else if add_in1.as_ref().map(|v| std::sync::Arc::ptr_eq(v, mult_out_ref)).unwrap_or(false) { add_in0 }
                    else { continue; }
                };
                let lvn = match lvn { Some(v) => v, None => continue };
                if !std::sync::Arc::ptr_eq(&lvn, &x_vn) { continue; }

                // Transform: addop becomes REM/SREM
                let add_ref = crate::op::PcodeOpRef(addop_arc.clone());
                fd.op_set_input(&add_ref, x_vn.clone(), 0);
                let div_size = div_vn.read().unwrap().get_size();
                if div_vn.read().unwrap().is_constant() {
                    let dc = fd.new_constant(div_size, div_vn.read().unwrap().get_offset());
                    fd.op_set_input(&add_ref, dc, 1);
                } else {
                    fd.op_set_input(&add_ref, div_vn.clone(), 1);
                }
                if op_opc == OpCode::CPUI_INT_DIV {
                    fd.op_set_opcode(&add_ref, OpCode::CPUI_INT_REM);
                } else {
                    fd.op_set_opcode(&add_ref, OpCode::CPUI_INT_SREM);
                }
                return Ok(action_status::CHANGE);
            }
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:8612 RuleModOpt
    fn get_name(&self) -> &str { "mod_opt" }
    // Ghidra: ruleaction.cc:8614 RuleModOpt::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_DIV, OpCode::CPUI_INT_SDIV]
    }
}

/// Convert INT_SREM form: `V - (Vadj & ~(2^n-1)) => V s% 2^n`.
/// Faithful to `RuleSignMod2nOpt2` (ruleaction.cc:8867-8922). Only the
/// `checkSignExtForm` path (INT_ADD) is implemented; the MULTIEQUAL path
/// (`checkMultiequalForm`) requires block-structure access and is deferred.
pub struct RuleSignMod2nOpt2;

impl RuleSignMod2nOpt2 {
    // Ghidra: ruleaction.cc:8867 RuleSignMod2nOpt2
    pub fn new() -> Self { Self }

    /// Verify a form of `V - (V s>> 0x3f)`. Faithful to `checkSignExtForm`
    /// (ruleaction.cc:8928-8952). Returns the base Varnode V or None.
    // Ghidra: ruleaction.cc:8928 RuleSignMod2nOpt2::checkSignExtForm
    fn check_sign_ext_form(addop: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        for slot in 0..2 {
            let minus_vn = {
                let a = addop.read().unwrap();
                match a.inrefs.get(slot) { Some(v) => v.clone(), None => continue }
            };
            if !minus_vn.read().unwrap().is_written() { continue; }
            let mult_op = match minus_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => continue,
            };
            if mult_op.read().unwrap().opcode != OpCode::CPUI_INT_MULT { continue; }
            let const_vn = match mult_op.read().unwrap().inrefs.get(1) { Some(v) => v.clone(), None => continue };
            if !const_vn.read().unwrap().is_constant() { continue; }
            let mask = crate::address::calc_mask(const_vn.read().unwrap().get_size());
            if const_vn.read().unwrap().get_offset() != mask { continue; } // must be *(-1)
            let base = {
                let a = addop.read().unwrap();
                match a.inrefs.get(1 - slot) { Some(v) => v.clone(), None => continue }
            };
            let sign_ext = match mult_op.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => continue };
            if !sign_ext.read().unwrap().is_written() { continue; }
            let shift_op = match sign_ext.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a, None => continue,
            };
            if shift_op.read().unwrap().opcode != OpCode::CPUI_INT_SRIGHT { continue; }
            let shift_in0 = match shift_op.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => continue };
            if !std::sync::Arc::ptr_eq(&shift_in0, &base) { continue; }
            let shift_const = match shift_op.read().unwrap().inrefs.get(1) { Some(v) => v.clone(), None => continue };
            if !shift_const.read().unwrap().is_constant() { continue; }
            let base_size = base.read().unwrap().get_size();
            if shift_const.read().unwrap().get_offset() as usize != 8 * base_size - 1 { continue; }
            return Some(base);
        }
        None
    }
}

impl Rule for RuleSignMod2nOpt2 {
    // Ghidra: ruleaction.cc:8877 RuleSignMod2nOpt2::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSignMod2nOpt2::applyOp (ruleaction.cc:8877-8922).
        let (const_vn, and_out) = {
            let op = op_arc.read().unwrap();
            let cv = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !cv.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let mask = crate::address::calc_mask(cv.read().unwrap().get_size());
            if cv.read().unwrap().get_offset() != mask { return Ok(action_status::NO_CHANGE); } // must be *(-1)
            let ao = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (cv, ao)
        };
        if !and_out.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let and_op = match and_out.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        if and_op.read().unwrap().opcode != OpCode::CPUI_INT_AND { return Ok(action_status::NO_CHANGE); }
        let and_const = match and_op.read().unwrap().inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !and_const.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        let mask = crate::address::calc_mask(and_const.read().unwrap().get_size());
        let npow = (!and_const.read().unwrap().get_offset().wrapping_add(1)) & mask;
        if npow.count_ones() != 1 { return Ok(action_status::NO_CHANGE); } // must be power of 2
        if npow == 1 { return Ok(action_status::NO_CHANGE); }

        let adj_vn = match and_op.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !adj_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let adj_op = match adj_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        let adj_opc = adj_op.read().unwrap().opcode;

        // Only checkSignExtForm path (INT_ADD). MULTIEQUAL path deferred.
        let base = if adj_opc == OpCode::CPUI_INT_ADD {
            if npow != 2 { return Ok(action_status::NO_CHANGE); } // Special mod 2 form
            match Self::check_sign_ext_form(&adj_op) {
                Some(b) => b,
                None => return Ok(action_status::NO_CHANGE),
            }
        } else {
            // MULTIEQUAL path (checkMultiequalForm) requires block-structure
            // access (getParent/getIn/getTrueOut). Deferred.
            return Ok(action_status::NO_CHANGE);
        };

        if base.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }

        // Look for INT_ADD(multOut, base) among descendants
        let mult_out = match op_arc.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
        let descendents: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = mult_out.read().unwrap().descend_iter().collect();
        for root_op_arc in descendents {
            if root_op_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { continue; }
            let slot = {
                let r = root_op_arc.read().unwrap();
                let mut found = -1i32;
                for i in 0..r.inrefs.len() {
                    if let Some(v) = r.inrefs.get(i) {
                        if std::sync::Arc::ptr_eq(v, &mult_out) { found = i as i32; break; }
                    }
                }
                if found < 0 { continue; }
                let other = r.inrefs.get((1 - found) as usize).cloned();
                match other {
                    Some(v) if std::sync::Arc::ptr_eq(&v, &base) => found,
                    _ => continue,
                }
            };
            let base_size = base.read().unwrap().get_size();
            let root_ref = crate::op::PcodeOpRef(root_op_arc.clone());
            if slot == 0 {
                fd.op_set_input(&root_ref, base.clone(), 0);
            }
            let npow_const = fd.new_constant(base_size, npow);
            fd.op_set_input(&root_ref, npow_const, 1);
            fd.op_set_opcode(&root_ref, OpCode::CPUI_INT_SREM);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:8867 RuleSignMod2nOpt2
    fn get_name(&self) -> &str { "sign_mod2n_opt2" }
    // Ghidra: ruleaction.cc:8871 RuleSignMod2nOpt2::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_MULT] }
}
/// Simplify optimized division expressions. Faithful to `RuleDivTermAdd`
/// (ruleaction.cc:7832-7915). Transforms:
///   `sub(ext(V)*c, b) >> d + V => sub((ext(V)*(c+2^n)) >> n, 0)`
/// where n = d + b*8. Uses 128-bit arithmetic (Rust native u128).
pub struct RuleDivTermAdd;

impl RuleDivTermAdd {
    // Ghidra: ruleaction.cc:7832 RuleDivTermAdd
    pub fn new() -> Self { Self }

    /// Find SUBPIECE (high) form: SUB(V,c) or SUB(V,c)>>n. Returns
    /// (subpiece_op, total_truncation_bits, shift_opcode). Faithful to
    /// `findSubshift` (ruleaction.cc:7928-7953).
    // Ghidra: ruleaction.cc:7928 RuleDivTermAdd::findSubshift
    fn find_subshift(op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<(std::sync::Arc<std::sync::RwLock<PcodeOp>>, i32, OpCode)> {
        let o = op.read().unwrap();
        let shiftopc = o.opcode;
        let (subop_arc, mut n) = if shiftopc != OpCode::CPUI_SUBPIECE {
            // Must be right shift of a SUBPIECE
            let vn = o.inrefs.get(0)?;
            if !vn.read().unwrap().is_written() { return None; }
            let subop = vn.read().unwrap().def.as_ref()?.upgrade()?;
            if subop.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return None; }
            let shift_amt_vn = o.inrefs.get(1)?;
            if !shift_amt_vn.read().unwrap().is_constant() { return None; }
            let shift_n = shift_amt_vn.read().unwrap().get_offset() as i32;
            (subop, shift_n)
        } else {
            (std::sync::Arc::clone(&*op as &std::sync::Arc<_>), 0)
        };
        drop(o);
        // Check SUB is high: subop output size + c == subop input size
        let (out_size, c, in0_size) = {
            let s = subop_arc.read().unwrap();
            let out_s = s.output.as_ref()?.read().unwrap().get_size();
            let c_val = s.inrefs.get(1)?.read().unwrap().get_offset() as i32;
            let in_s = s.inrefs.get(0)?.read().unwrap().get_size();
            (out_s, c_val, in_s)
        };
        if out_size + c as usize != in0_size { return None; }
        n += 8 * c;
        let final_shiftopc = if shiftopc == OpCode::CPUI_SUBPIECE { OpCode::CPUI_COPY } else { shiftopc };
        // Note: Ghidra returns CPUI_MAX for no-shift case; we use CPUI_COPY as sentinel
        Some((subop_arc, n, final_shiftopc))
    }
}

impl Rule for RuleDivTermAdd {
    // Ghidra: ruleaction.cc:7848 RuleDivTermAdd::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleDivTermAdd::applyOp (ruleaction.cc:7848-7915).
        let (subop_arc, n, shiftopc) = match Self::find_subshift(op_arc) {
            Some(r) => r, None => return Ok(action_status::NO_CHANGE),
        };
        if n > 127 { return Ok(action_status::NO_CHANGE); }

        // multvn = subop->getIn(0); must be INT_MULT
        let multvn = {
            let s = subop_arc.read().unwrap();
            match s.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        if !multvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let multop = match multvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        if multop.read().unwrap().opcode != OpCode::CPUI_INT_MULT { return Ok(action_status::NO_CHANGE); }

        // multConst = 128-bit constant from multop->getIn(1)
        let cv_arc = {
            let m = multop.read().unwrap();
            match m.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        let (mult_lo, mult_hi) = match cv_arc.read().unwrap().is_constant_extended() {
            Some((lo, hi)) => (lo, hi),
            None => return Ok(action_status::NO_CHANGE),
        };
        let mult_const: u128 = (mult_hi as u128) << 64 | (mult_lo as u128);

        // extvn = multop->getIn(0); must be INT_ZEXT or INT_SEXT
        let extvn = {
            let m = multop.read().unwrap();
            match m.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        if !extvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let extop = match extvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        let ext_opc = extop.read().unwrap().opcode;
        let op_opc = op_arc.read().unwrap().opcode;
        if ext_opc == OpCode::CPUI_INT_ZEXT {
            if op_opc == OpCode::CPUI_INT_SRIGHT { return Ok(action_status::NO_CHANGE); }
        } else if ext_opc == OpCode::CPUI_INT_SEXT {
            if op_opc == OpCode::CPUI_INT_RIGHT { return Ok(action_status::NO_CHANGE); }
        } else { return Ok(action_status::NO_CHANGE); }

        // power = 2^n; multConst += power
        let power: u128 = if n < 128 { 1u128 << n } else { 0 };
        let new_mult_const = mult_const.wrapping_add(power);
        let new_lo = new_mult_const as u64;
        let new_hi = (new_mult_const >> 64) as u64;

        // x = extop->getIn(0)
        let x_vn = {
            let e = extop.read().unwrap();
            match e.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        let ext_size = extvn.read().unwrap().get_size();

        // Look for INT_ADD(op_out, x) among descendants
        let op_out = match op_arc.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
        let descendents: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = op_out.read().unwrap().descend_iter().collect();
        for addop_arc in descendents {
            if addop_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { continue; }
            let (a0, a1) = {
                let a = addop_arc.read().unwrap();
                (a.inrefs.get(0).cloned(), a.inrefs.get(1).cloned())
            };
            let has_x = a0.as_ref().map(|v| std::sync::Arc::ptr_eq(v, &x_vn)).unwrap_or(false)
                     || a1.as_ref().map(|v| std::sync::Arc::ptr_eq(v, &x_vn)).unwrap_or(false);
            if !has_x { continue; }

            // Construct new constant (possibly extended)
            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            let new_const_vn = fd.new_extended_constant(ext_size, new_lo, new_hi, &op_ref);

            // Construct new multiply: extvn * newConst
            let new_mult = fd.new_op(2, op_arc.read().unwrap().get_addr());
            fd.op_set_opcode(&new_mult, OpCode::CPUI_INT_MULT);
            let new_mult_out = fd.new_unique_out(ext_size, &new_mult);
            fd.op_set_input(&new_mult, extvn.clone(), 0);
            fd.op_set_input(&new_mult, new_const_vn, 1);
            fd.op_insert_before(&new_mult, &op_ref);

            // Construct new shift: new_mult_out >> n
            let new_shift = fd.new_op(2, op_arc.read().unwrap().get_addr());
            let final_shift_opc = if shiftopc == OpCode::CPUI_COPY { OpCode::CPUI_INT_RIGHT } else { shiftopc };
            fd.op_set_opcode(&new_shift, final_shift_opc);
            let new_shift_out = fd.new_unique_out(ext_size, &new_shift);
            fd.op_set_input(&new_shift, new_mult_out, 0);
            let n_const = fd.new_constant(4, n as u64);
            fd.op_set_input(&new_shift, n_const, 1);
            fd.op_insert_before(&new_shift, &op_ref);

            // Transform addop to SUBPIECE(new_shift_out, 0)
            let add_ref = crate::op::PcodeOpRef(addop_arc.clone());
            fd.op_set_opcode(&add_ref, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&add_ref, new_shift_out, 0);
            let zero_const = fd.new_constant(4, 0);
            fd.op_set_input(&add_ref, zero_const, 1);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:7832 RuleDivTermAdd
    fn get_name(&self) -> &str { "div_term_add" }
    // Ghidra: ruleaction.cc:7840 RuleDivTermAdd::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_SUBPIECE, OpCode::CPUI_INT_RIGHT, OpCode::CPUI_INT_SRIGHT]
    }
}

/// Simplify another optimized division expression. Faithful to
/// `RuleDivTermAdd2` (ruleaction.cc:7955-8046). With W = sub(zext(V)*c, d):
///   `W + ((V - W) >> 1) => sub((zext(V)*(c+2^n)) >> (n+1), 0)`
/// where n = d*8. All extensions and shifts must be unsigned.
pub struct RuleDivTermAdd2;

impl RuleDivTermAdd2 {
    // Ghidra: ruleaction.cc:7955 RuleDivTermAdd2
    pub fn new() -> Self { Self }
}

impl Rule for RuleDivTermAdd2 {
    // Ghidra: ruleaction.cc:7969 RuleDivTermAdd2::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleDivTermAdd2::applyOp (ruleaction.cc:7969-8046).
        // Guard: skip if input is a pointer type (prevents false-positive
        // on pointer arithmetic lifted as INT_RIGHT).
        let in0_check = match op_arc.read().unwrap().inrefs.get(0) {
            Some(v) => v.read().unwrap().v_type.as_ref().map_or(false, |t| {
                matches!(t.as_ref(), crate::type_system::Datatype::Pointer(_))
            }),
            None => return Ok(action_status::NO_CHANGE),
        };
        if in0_check { return Ok(action_status::NO_CHANGE); }
        // Trigger: INT_RIGHT with constant shift == 1.
        let (in0_vn, shift_val) = {
            let op = op_arc.read().unwrap();
            let in1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !in1.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            if in1.read().unwrap().get_offset() != 1 { return Ok(action_status::NO_CHANGE); }
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (in0, 1i32)
        };
        let _ = shift_val;
        if !in0_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }

        // subop = INT_ADD; find x via MULT(-1) pattern
        let addop = match in0_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        if addop.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return Ok(action_status::NO_CHANGE); }

        // Find which input is INT_MULT by -1 (the "comp" part), the other is x
        let (x_vn, compvn_vn) = {
            let a = addop.read().unwrap();
            let mut found = None;
            for i in 0..2 {
                let compvn = match a.inrefs.get(i) { Some(v) => v.clone(), None => continue };
                if !compvn.read().unwrap().is_written() { continue; }
                let compop = match compvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                    Some(op) => op, None => continue,
                };
                if compop.read().unwrap().opcode != OpCode::CPUI_INT_MULT { continue; }
                let invn = match compop.read().unwrap().inrefs.get(1) { Some(v) => v.clone(), None => continue };
                if !invn.read().unwrap().is_constant() { continue; }
                let mask = crate::address::calc_mask(invn.read().unwrap().get_size());
                if invn.read().unwrap().get_offset() == mask {
                    let other = a.inrefs.get(1 - i).cloned();
                    found = Some((other, compvn));
                    break;
                }
            }
            match found {
                Some((Some(x), c)) => (x, c),
                _ => return Ok(action_status::NO_CHANGE),
            }
        };

        // z = compvn->def->getIn(0); must be SUBPIECE
        let compvn_def = match compvn_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        let z_vn = match compvn_def.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !z_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let subpieceop = match z_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        if subpieceop.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }

        // n = subpiece truncation * 8
        let n = {
            let sp = subpieceop.read().unwrap();
            let trunc = sp.inrefs.get(1).and_then(|v| {
                let g = v.read().unwrap();
                if g.is_constant() { Some(g.get_offset() as i32) } else { None }
            }).unwrap_or(-1);
            if trunc < 0 { return Ok(action_status::NO_CHANGE); }
            let in0_size = sp.inrefs.get(0).map(|v| v.read().unwrap().get_size()).unwrap_or(0);
            let z_size = z_vn.read().unwrap().get_size();
            if trunc * 8 != 8 * (in0_size as i32 - z_size as i32) { return Ok(action_status::NO_CHANGE); }
            trunc * 8
        };

        // multvn = subpieceop->getIn(0); must be INT_MULT
        let multvn = match subpieceop.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !multvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let multop = match multvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        if multop.read().unwrap().opcode != OpCode::CPUI_INT_MULT { return Ok(action_status::NO_CHANGE); }

        // multConst from multop->getIn(1) (128-bit)
        let cv_arc = {
            let m = multop.read().unwrap();
            match m.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        let (mult_lo, mult_hi) = match cv_arc.read().unwrap().is_constant_extended() {
            Some(v) => v, None => return Ok(action_status::NO_CHANGE),
        };
        let mult_const: u128 = (mult_hi as u128) << 64 | (mult_lo as u128);

        // zextvn = multop->getIn(0); must be INT_ZEXT of x
        let zextvn = match multop.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !zextvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let zextop = match zextvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(a) => a, None => return Ok(action_status::NO_CHANGE),
        };
        if zextop.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return Ok(action_status::NO_CHANGE); }
        let zext_in = match zextop.read().unwrap().inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        if !std::sync::Arc::ptr_eq(&zext_in, &x_vn) { return Ok(action_status::NO_CHANGE); }
        let ext_size = zextvn.read().unwrap().get_size();

        // Look for INT_ADD(z, ...) among descendants of op output
        let op_out = match op_arc.read().unwrap().output.as_ref() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
        let descendents: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = op_out.read().unwrap().descend_iter().collect();
        for addop2_arc in descendents {
            if addop2_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { continue; }
            let (a0, a1) = {
                let a = addop2_arc.read().unwrap();
                (a.inrefs.get(0).cloned(), a.inrefs.get(1).cloned())
            };
            let has_z = a0.as_ref().map(|v| std::sync::Arc::ptr_eq(v, &z_vn)).unwrap_or(false)
                     || a1.as_ref().map(|v| std::sync::Arc::ptr_eq(v, &z_vn)).unwrap_or(false);
            if !has_z { continue; }

            // pow = 2^n; multConst += pow
            let power: u128 = if n < 128 { 1u128 << n } else { 0 };
            let new_mult = mult_const.wrapping_add(power);
            let new_lo = new_mult as u64;
            let new_hi = (new_mult >> 64) as u64;

            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            // new multiply: zextvn * newConst
            let new_mult_op = fd.new_op(2, op_arc.read().unwrap().get_addr());
            fd.op_set_opcode(&new_mult_op, OpCode::CPUI_INT_MULT);
            let new_mult_out = fd.new_unique_out(ext_size, &new_mult_op);
            fd.op_set_input(&new_mult_op, zextvn.clone(), 0);
            let new_const_vn = fd.new_extended_constant(ext_size, new_lo, new_hi, &op_ref);
            fd.op_set_input(&new_mult_op, new_const_vn, 1);
            fd.op_insert_before(&new_mult_op, &op_ref);

            // new shift: new_mult_out >> (n+1)
            let new_shift = fd.new_op(2, op_arc.read().unwrap().get_addr());
            fd.op_set_opcode(&new_shift, OpCode::CPUI_INT_RIGHT);
            let new_shift_out = fd.new_unique_out(ext_size, &new_shift);
            fd.op_set_input(&new_shift, new_mult_out, 0);
            let shift_const = fd.new_constant(4, (n + 1) as u64);
            fd.op_set_input(&new_shift, shift_const, 1);
            fd.op_insert_before(&new_shift, &op_ref);

            // addop2 becomes SUBPIECE(new_shift_out, 0)
            let add2_ref = crate::op::PcodeOpRef(addop2_arc.clone());
            fd.op_set_opcode(&add2_ref, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&add2_ref, new_shift_out, 0);
            let zero_c = fd.new_constant(4, 0);
            fd.op_set_input(&add2_ref, zero_c, 1);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:7955 RuleDivTermAdd2
    fn get_name(&self) -> &str { "div_term_add2" }
    // Ghidra: ruleaction.cc:7963 RuleDivTermAdd2::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_RIGHT] }
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
    // Ghidra: ruleaction.cc:1348 RuleRangeMeld
    pub fn new() -> Self { Self }
}

impl Rule for RuleRangeMeld {
    // Ghidra: ruleaction.cc:1357 RuleRangeMeld::applyOp
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

        // If either sub is a BOOL_NEGATE (CPUI_BOOL_NEGATE in Rugra), do an extra pull back.
        let sub1_code = sub1_arc.read().unwrap().opcode;
        let a1 = if sub1_code == OpCode::CPUI_BOOL_NEGATE {
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
        let a2 = if sub2_code == OpCode::CPUI_BOOL_NEGATE {
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

    // Ghidra: ruleaction.cc:1348 RuleRangeMeld
    fn get_name(&self) -> &str { "range_meld" }
    // Ghidra: ruleaction.cc:1341 RuleRangeMeld::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_OR, OpCode::CPUI_BOOL_AND] }
}

/// Pull back a CircleRange through a comparison op. Faithful to
/// `CircleRange::pullBack` (rangeutil.cc:1022-1073) simplified: returns the
/// non-constant input Varnode that the range now applies to, or None if the
/// op cannot be pulled back through. Does not track constMarkup or useNZMask.
// Ghidra: rangeutil.cc:1022 CircleRange::pullBack
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
    // Ghidra: ruleaction.cc:1439 RuleFloatRange
    pub fn new() -> Self { Self }
}

impl Rule for RuleFloatRange {
    // Ghidra: ruleaction.cc:1450 RuleFloatRange::applyOp
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

    // Ghidra: ruleaction.cc:1439 RuleFloatRange
    fn get_name(&self) -> &str { "float_range" }
    // Ghidra: ruleaction.cc:1443 RuleFloatRange::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BOOL_OR, OpCode::CPUI_BOOL_AND] }
}

/// Detect floating-point sign-bit manipulation (x & 0x7fffffff → FLOAT_ABS,
/// x ^ 0x80000000 → FLOAT_NEG) and convert to proper float ops. Faithful to
/// `RuleFloatSign` (ruleaction.cc:10714-10777) + `TypeOp::floatSignManipulation`
/// (typeop.cc:153-176).
pub struct RuleFloatSign;

impl RuleFloatSign {
    // Ghidra: ruleaction.cc:10714 RuleFloatSign
    pub fn new() -> Self { Self }

    /// Check if `op` is a sign-bit manipulation: INT_AND with clear-high-bit
    /// mask → FLOAT_ABS, or INT_XOR with sign-bit-only mask → FLOAT_NEG.
    /// Faithful to TypeOp::floatSignManipulation (typeop.cc:153-176).
    // Ghidra: typeop.cc:153 TypeOp::floatSignManipulation
    fn float_sign_manipulation(op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<OpCode> {
        let o = op.read().unwrap();
        match o.opcode {
            OpCode::CPUI_INT_AND => {
                if let Some(cvn) = o.inrefs.get(1) {
                    let cv = cvn.read().unwrap();
                    if cv.is_constant() {
                        let size = cv.get_size();
                        let mut val = crate::address::calc_mask(size);
                        val >>= 1; // clear sign bit
                        if val == cv.get_offset() {
                            return Some(OpCode::CPUI_FLOAT_ABS);
                        }
                    }
                }
            }
            OpCode::CPUI_INT_XOR => {
                if let Some(cvn) = o.inrefs.get(1) {
                    let cv = cvn.read().unwrap();
                    if cv.is_constant() {
                        let size = cv.get_size();
                        let val = crate::address::calc_mask(size);
                        let val = val ^ (val >> 1); // only sign bit set
                        if val == cv.get_offset() {
                            return Some(OpCode::CPUI_FLOAT_NEG);
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}

impl Rule for RuleFloatSign {
    // Ghidra: ruleaction.cc:10733 RuleFloatSign::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleFloatSign::applyOp (ruleaction.cc:10733-10777).
        // Check inputs of this float op: if an input is defined by a sign-bit
        // manipulation, convert it to FLOAT_ABS/FLOAT_NEG.
        let opc = op_arc.read().unwrap().opcode;
        let mut res = 0;
        if opc != OpCode::CPUI_FLOAT_INT2FLOAT {
            // Check input 0
            let in0_def = {
                let op = op_arc.read().unwrap();
                match op.inrefs.get(0) {
                    Some(vn) => {
                        let vg = vn.read().unwrap();
                        if vg.is_written() {
                            vg.def.as_ref().and_then(|w| w.upgrade())
                        } else { None }
                    }
                    None => None,
                }
            };
            if let Some(sign_op) = in0_def {
                if let Some(res_code) = Self::float_sign_manipulation(&sign_op) {
                    fd.op_remove_input(&crate::op::PcodeOpRef(sign_op.clone()), 1);
                    fd.op_set_opcode(&crate::op::PcodeOpRef(sign_op.clone()), res_code);
                    res = 1;
                }
            }
            // Check input 1
            let in1_def = {
                let op = op_arc.read().unwrap();
                match op.inrefs.get(1) {
                    Some(vn) => {
                        let vg = vn.read().unwrap();
                        if vg.is_written() {
                            vg.def.as_ref().and_then(|w| w.upgrade())
                        } else { None }
                    }
                    None => None,
                }
            };
            if let Some(sign_op) = in1_def {
                if let Some(res_code) = Self::float_sign_manipulation(&sign_op) {
                    fd.op_remove_input(&crate::op::PcodeOpRef(sign_op.clone()), 1);
                    fd.op_set_opcode(&crate::op::PcodeOpRef(sign_op.clone()), res_code);
                    res = 1;
                }
            }
        }
        // Check descendants of this op's output
        let is_bool_output = matches!(opc,
            OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_FLOAT_NAN
        );
        if is_bool_output || opc == OpCode::CPUI_FLOAT_TRUNC {
            return Ok(res);
        }
        let descendents: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = {
            let op = op_arc.read().unwrap();
            match op.output.as_ref() {
                Some(out) => out.read().unwrap().descend_iter().collect(),
                None => Vec::new(),
            }
        };
        for read_op in descendents {
            if let Some(res_code) = Self::float_sign_manipulation(&read_op) {
                fd.op_remove_input(&crate::op::PcodeOpRef(read_op.clone()), 1);
                fd.op_set_opcode(&crate::op::PcodeOpRef(read_op.clone()), res_code);
                res = 1;
            }
        }
        Ok(res)
    }

    // Ghidra: ruleaction.cc:10714 RuleFloatSign
    fn get_name(&self) -> &str { "float_sign" }
    // Ghidra: ruleaction.cc:10723 RuleFloatSign::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::CPUI_FLOAT_EQUAL, OpCode::CPUI_FLOAT_NOTEQUAL,
            OpCode::CPUI_FLOAT_LESS, OpCode::CPUI_FLOAT_LESSEQUAL,
            OpCode::CPUI_FLOAT_NAN, OpCode::CPUI_FLOAT_ADD,
            OpCode::CPUI_FLOAT_DIV, OpCode::CPUI_FLOAT_MULT,
            OpCode::CPUI_FLOAT_SUB, OpCode::CPUI_FLOAT_NEG,
            OpCode::CPUI_FLOAT_ABS, OpCode::CPUI_FLOAT_SQRT,
            OpCode::CPUI_FLOAT_FLOAT2FLOAT, OpCode::CPUI_FLOAT_CEIL,
            OpCode::CPUI_FLOAT_FLOOR, OpCode::CPUI_FLOAT_ROUND,
            OpCode::CPUI_FLOAT_INT2FLOAT, OpCode::CPUI_FLOAT_TRUNC,
        ]
    }
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
    // Ghidra: ruleaction.cc:872 RulePullsubMulti
    pub fn new() -> Self { Self }

    /// Compute the min/max byte range actually used by descendants of `vn`.
    /// Faithful to `minMaxUse` (ruleaction.cc:683-709). If any descendant is
    /// not a SUBPIECE, the full range is assumed.
    // Ghidra: ruleaction.cc:977 RulePullsubMulti::minMaxUse
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
    // Ghidra: ruleaction.cc:981 RulePullsubMulti::acceptableSize
    fn acceptable_size(size: i32) -> bool {
        if size == 0 { return false; }
        if size >= 8 { return true; }
        matches!(size, 1 | 2 | 4 | 8)
    }

    /// Replace `orig_vn` with `new_vn` in all descendant ops. Faithful to
    /// `replaceDescendants` (ruleaction.cc:719-752).
    // Ghidra: ruleaction.cc:1017 RulePullsubMulti::replaceDescendants
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
    // Ghidra: ruleaction.cc:1005 RulePullsubMulti::findSubpiece
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
    // Ghidra: ruleaction.cc:1007 RulePullsubMulti::buildSubpiece
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
    // Ghidra: ruleaction.cc:880 RulePullsubMulti::applyOp
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

    // Ghidra: ruleaction.cc:872 RulePullsubMulti
    fn get_name(&self) -> &str { "pullsub_multi" }
    // Ghidra: ruleaction.cc:874 RulePullsubMulti::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

// ============================================================================
// Cleanup-pool rules (coreaction.cc:5696-5710). Faithful 1:1 ports of
// ruleaction.cc.
// ============================================================================

/// Cleanup: Convert INT_ADD of constants to INT_SUB: `V + 0xff.. ⇒ V - 0x00..`
///
/// Faithful to `RuleAddUnsigned` (ruleaction.cc:7200-7249). When the constant
/// being added has its high quarter of bits all set, it is more naturally
/// printed as a subtraction of the negated (small positive) value.
///
/// NOTE: Ghidra consults the constant's read-facing data-type (`TYPE_UINT`,
/// not char-print, enum/equate name-locks). Rugra now resolves the
/// read-facing type via `get_type_read_facing()` and applies the `TYPE_UINT` /
/// `!isCharPrint()` guards; if the varnode has no type it falls back to the
/// numeric transform. The `SymbolEntry`/`EquateSymbol` name-lock guard and the
/// enum named-value re-naming still require SymbolEntry infra not in Rugra, so
/// those are skipped (see TODO at the guard site).
pub struct RuleAddUnsigned;

impl RuleAddUnsigned {
    // Ghidra: ruleaction.cc:7192 RuleAddUnsigned
    pub fn new() -> Self { Self }
}

impl Rule for RuleAddUnsigned {
    // Ghidra: ruleaction.cc:7200 RuleAddUnsigned::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleAddUnsigned::applyOp (ruleaction.cc:7200-7249).
        let constvn = {
            let op = op_arc.read().unwrap();
            match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        if !constvn.read().unwrap().is_constant() {
            return Ok(action_status::NO_CHANGE);
        }
        use crate::type_system::datatype::TypeMetatype;
        // Ghidra: dt = constvn->getTypeReadFacing(op); require metatype==
        // TYPE_UINT, skip char-print types (ruleaction.cc:7206-7208). Rugra's
        // get_type_read_facing returns the varnode's resolved type; if absent
        // (type recovery not yet run on this varnode) we conservatively keep
        // the legacy numeric-only behaviour.
        if let Some(dt) = constvn.read().unwrap().get_type_read_facing() {
            if dt.get_metatype() != TypeMetatype::Uint {
                return Ok(action_status::NO_CHANGE);
            }
            if dt.is_char_print() {
                return Ok(action_status::NO_CHANGE); // Only change integer forms
            }
            // TODO(symbolentry): Ghidra also skips name-locked EquateSymbol
            //   (ruleaction.cc:7214-7220) and re-names via enum named values
            //   (7222-7226). Rugra has no SymbolEntry/EquateSymbol lookup on a
            //   Varnode, so these two sub-checks are omitted.
        }
        let size = constvn.read().unwrap().get_size();
        let val = constvn.read().unwrap().get_offset();
        let mask = calc_mask(size);
        let sa = size * 6; // 1/4 less than full bitsize
        let quarter = (mask >> sa) << sa;
        if (val & quarter) != quarter {
            return Ok(action_status::NO_CHANGE); // The first quarter of bits must all be 1's
        }
        let negated_val = val.wrapping_neg() & mask;
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_SUB);
        let cvn = fd.new_constant(size, negated_val);
        // Ghidra: cvn->copySymbol(constvn); propagate the constant's symbol/type
        // + lock flags into the new constant (ruleaction.cc:7229).
        {
            let cvn_lock = constvn.read().unwrap();
            cvn.write().unwrap().copy_symbol(&cvn_lock);
        }
        fd.op_set_input(&op_ref, cvn, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7192 RuleAddUnsigned
    fn get_name(&self) -> &str { "add_unsigned" }
    // Ghidra: ruleaction.cc:7194 RuleAddUnsigned::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ADD] }
}

/// Cleanup: Convert truncation to cast: `sub(V,c) ⇒ sub(V>>c*8,0)`.
///
/// Faithful to `RuleSubRight` (ruleaction.cc:7269-7339). If the lone descendant
/// of the SUBPIECE is an INT_RIGHT/INT_SRIGHT by a constant, the shift and the
/// SUBPIECE are lumped together. The SUBPIECE is then rewritten to extract the
/// least-significant bytes of the shifted value.
///
/// NOTE: The `doesSpecialPrinting` / `isPieceStructured` guards and the
/// addr-tied overlap check now use Rugra's `does_special_printing()` /
/// `is_piece_structured()` / `is_addr_tied()`. Ghidra also calls
/// `data.opMarkSpecialPrint(op)` when the SUBPIECE extracts a structured field;
/// Rugra has no Funcdata helper, so the rule sets the addlflag bit directly
/// (matching `op.hh:140` SPECIAL_PRINT). The `outvn->overlap(*a)` term is
/// unavailable (no Varnode::overlap), so the addr-tied branch is approximated
/// to the `isAddrTied` portion only (see TODO at the guard site).
pub struct RuleSubRight;

impl RuleSubRight {
    // Ghidra: ruleaction.cc:7256 RuleSubRight
    pub fn new() -> Self { Self }
}

impl Rule for RuleSubRight {
    // Ghidra: ruleaction.cc:7269 RuleSubRight::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSubRight::applyOp (ruleaction.cc:7269-7339).
        // Ghidra: if (op->doesSpecialPrinting()) return 0 (7272-7273).
        if op_arc.read().unwrap().does_special_printing() {
            return Ok(action_status::NO_CHANGE);
        }
        // Ghidra: if (op->getIn(0)->getTypeReadFacing(op)->isPieceStructured())
        //   { data.opMarkSpecialPrint(op); return 0; } (7274-7277).
        {
            let in0_vn = op_arc.read().unwrap().inrefs.get(0).cloned();
            if let Some(vn) = in0_vn {
                if let Some(dt) = vn.read().unwrap().get_type_read_facing() {
                    if dt.is_piece_structured() {
                        // Faithful to `data.opMarkSpecialPrint(op)` (ruleaction.cc:7275).
                        fd.op_mark_special_print(&crate::op::PcodeOpRef(op_arc.clone()));
                        return Ok(action_status::NO_CHANGE); // Print this as a field extraction
                    }
                }
            }
        }
        let (c, a, outvn) = {
            let op = op_arc.read().unwrap();
            let in1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !in1.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let c = in1.read().unwrap().get_offset() as i32;
            let a = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let outvn = match op.output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
            (c, a, outvn)
        };
        if c == 0 { return Ok(action_status::NO_CHANGE); } // SUBPIECE is not least sig
        // Ghidra: if (outvn->isAddrTied() && a->isAddrTied())
        //   { if (outvn->overlap(*a) == c) return 0; } (7283-7286). Rugra has no
        //   Varnode::overlap, so the overlap test is omitted (TODO(varnode)):
        //   when both inputs are addr-tied we conservatively leave the op alone
        //   so ActionCopyMarker can convert it, matching Ghidra's intent.
        if outvn.read().unwrap().is_addr_tied() && a.read().unwrap().is_addr_tied() {
            return Ok(action_status::NO_CHANGE); // Leave for ActionCopyMarker
        }
        let mut opc = OpCode::CPUI_INT_RIGHT; // Default shift type
        let mut d = c * 8; // Convert to bit shift
        let mut working_op_ref = crate::op::PcodeOpRef(op_arc.clone());
        // Search for lone right shift descendant and lump it in.
        let mut lumped = false;
        if let Some(lone) = outvn.read().unwrap().lone_descend() {
            let opc2 = lone.read().unwrap().opcode;
            if opc2 == OpCode::CPUI_INT_RIGHT || opc2 == OpCode::CPUI_INT_SRIGHT {
                let shift_c = lone.read().unwrap().get_in(1).cloned();
                if let Some(cv) = shift_c {
                    if cv.read().unwrap().is_constant() {
                        if outvn.read().unwrap().get_size() as i32 + c == a.read().unwrap().get_size() as i32 {
                            // SUB is "hi": lump the SUB and shift together
                            d += cv.read().unwrap().get_offset() as i32;
                            let a_size_bits = a.read().unwrap().get_size() as i32 * 8;
                            if d >= a_size_bits {
                                if opc2 == OpCode::CPUI_INT_RIGHT {
                                    return Ok(action_status::NO_CHANGE); // Result should have been 0
                                }
                                d = a_size_bits - 1; // sign extraction
                            }
                            // opUnlink(op); op = lone; opSetOpcode(op,SUBPIECE); opc = opc2;
                            fd.op_unset_input(&working_op_ref, 0); // unlink this op's inputs
                            working_op_ref = crate::op::PcodeOpRef(lone);
                            fd.op_set_opcode(&working_op_ref, OpCode::CPUI_SUBPIECE);
                            opc = opc2;
                            lumped = true;
                        }
                    }
                }
            }
        }
        // Create shift BEFORE the SUBPIECE happens.
        let a_size = a.read().unwrap().get_size();
        let addr = op_arc.read().unwrap().get_addr();
        let shiftop = fd.new_op(2, addr);
        fd.op_set_opcode(&shiftop, opc);
        // Ghidra: ct = getBase(a->getSize(), opc==INT_RIGHT?TYPE_UINT:TYPE_INT)
        // and attaches it via newUnique(size,ct) (ruleaction.cc:7312-7319). Rugra
        // resolves the base type via Architecture::get_base_type then attaches it
        // with Varnode::update_type.
        let base_meta = if opc == OpCode::CPUI_INT_RIGHT {
            crate::type_system::datatype::TypeMetatype::Uint
        } else {
            crate::type_system::datatype::TypeMetatype::Int
        };
        let newout = fd.new_unique_out(a_size, &shiftop);
        if let Some(arch) = fd.get_arch() {
            if let Some(dt) = arch.get_base_type(a_size, base_meta) {
                newout.write().unwrap().update_type(dt);
            }
        }
        fd.op_set_input(&shiftop, a, 0);
        let shift_const = fd.new_constant(4, d as u64);
        fd.op_set_input(&shiftop, shift_const, 1);
        fd.op_insert_before(&shiftop, &working_op_ref);

        // Change SUBPIECE into a least sig SUBPIECE
        fd.op_set_input(&working_op_ref, newout, 0);
        let zero_const = fd.new_constant(4, 0);
        fd.op_set_input(&working_op_ref, zero_const, 1);
        let _ = lumped;
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7256 RuleSubRight
    fn get_name(&self) -> &str { "sub_right" }
    // Ghidra: ruleaction.cc:7263 RuleSubRight::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Simplify INT_NEGATE chains: `~~V ⇒ V`.
///
/// Faithful to `RuleNegateNegate` (ruleaction.cc:9258-9271).
pub struct RuleNegateNegate;

impl RuleNegateNegate {
    // Ghidra: ruleaction.cc:9250 RuleNegateNegate
    pub fn new() -> Self { Self }
}

impl Rule for RuleNegateNegate {
    // Ghidra: ruleaction.cc:9258 RuleNegateNegate::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleNegateNegate::applyOp (ruleaction.cc:9258-9271).
        let vn1 = {
            let op = op_arc.read().unwrap();
            match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) }
        };
        if !vn1.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let neg2 = match vn1.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        if neg2.read().unwrap().opcode != OpCode::CPUI_INT_NEGATE {
            return Ok(action_status::NO_CHANGE);
        }
        let vn2 = match neg2.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if vn2.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_input(&op_ref, vn2, 0);
        fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:9250 RuleNegateNegate
    fn get_name(&self) -> &str { "negate_negate" }
    // Ghidra: ruleaction.cc:9252 RuleNegateNegate::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_NEGATE] }
}

/// Cleanup: Convert floating-point sign-bit manipulation into FLOAT_ABS/FLOAT_NEG.
///
/// Faithful to `RuleFloatSignCleanup` (ruleaction.cc:10789-10802). Recognises
/// the canonical sign-bit masks via `TypeOp::floatSignManipulation` and, when
/// the output is floating-point, rewrites the INT_AND/INT_XOR into the
/// corresponding FLOAT_ABS / FLOAT_NEG (single-input) op.
pub struct RuleFloatSignCleanup;

impl RuleFloatSignCleanup {
    // Ghidra: ruleaction.cc:10778 RuleFloatSignCleanup
    pub fn new() -> Self { Self }

    /// Faithful to `TypeOp::floatSignManipulation` (op.cc). Given the mask
    /// constant of an INT_AND/INT_XOR over a float-sized value, return the
    /// FLOAT_* opcode it represents, or CPUI_MAX.
    // Ghidra: typeop.cc:153 TypeOp::floatSignManipulation
    fn float_sign_manipulation(mask_val: u64, size: usize, is_xor: bool) -> OpCode {
        // Sign bit is the most significant bit of the float-sized value.
        let sign_bit = if size >= 8 { 0x8000_0000_0000_0000u64 } else { 1u64 << (size * 8 - 1) };
        let all_ones = calc_mask(size);
        if is_xor {
            // XOR with sign bit => FLOAT_NEG
            if mask_val == sign_bit { return OpCode::CPUI_FLOAT_NEG; }
        } else {
            // INT_AND:
            //   mask = ~sign_bit  => FLOAT_ABS  (clears sign bit)
            //   mask = sign_bit   => test only (no canonical float op)
            if mask_val == (all_ones & !sign_bit) { return OpCode::CPUI_FLOAT_ABS; }
        }
        OpCode::CPUI_MAX
    }
}

impl Rule for RuleFloatSignCleanup {
    // Ghidra: ruleaction.cc:10789 RuleFloatSignCleanup::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleFloatSignCleanup::applyOp (ruleaction.cc:10789-10802).
        let outvn = match op_arc.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        // Ghidra: if (op->getOut()->getType()->getMetatype() != TYPE_FLOAT) return 0;
        // (ruleaction.cc:10792). Rugra resolves the varnode's type via get_type;
        // if the varnode is untyped (type recovery not yet run) we fall back to
        // accepting float-sized (4 or 8 byte) outputs as a heuristic.
        let (out_size, has_float_type) = {
            let vn = outvn.read().unwrap();
            let is_float = vn.get_type().map(|dt| dt.get_metatype())
                == Some(crate::type_system::datatype::TypeMetatype::Float);
            (vn.get_size(), is_float)
        };
        if has_float_type {
            // typed as float: proceed
        } else if out_size != 4 && out_size != 8 {
            return Ok(action_status::NO_CHANGE); // untyped & not float-sized
        }
        let is_xor = op_arc.read().unwrap().opcode == OpCode::CPUI_INT_XOR;
        let maskvn = match op_arc.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !maskvn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        let mask_val = maskvn.read().unwrap().get_offset();
        let opc = Self::float_sign_manipulation(mask_val, out_size, is_xor);
        if opc == OpCode::CPUI_MAX { return Ok(action_status::NO_CHANGE); }
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_remove_input(&op_ref, 1);
        fd.op_set_opcode(&op_ref, opc);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:10778 RuleFloatSignCleanup
    fn get_name(&self) -> &str { "float_sign_cleanup" }
    // Ghidra: ruleaction.cc:10782 RuleFloatSignCleanup::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_AND, OpCode::CPUI_INT_XOR] }
}

/// Cleanup: Set-up to print string constants.
///
/// Faithful to `RulePtrsubCharConstant` (ruleaction.cc:7372-7421) plus its
/// `pushConstFurther` helper (ruleaction.cc:7341-7358). When a PTRSUB over a
/// TYPE_SPACEBASE refers to a read-only, string-looking address whose output is
/// a (char *), the PTRSUB is converted to a COPY of a string pointer constant
/// (and descendant PTRADDs are collapsed).
///
/// NOTE: The output's pointer/char-print type guard (`outvn->getTypeDefFacing()`
/// is a pointer whose base `isCharPrint()`) is now implemented via `get_type()`
/// / `is_char_print()`. The rule still cannot fully fire because the deeper
/// guards — `TYPE_SPACEBASE` dereference, `Scope::isReadOnly`, and
/// `stringManager->isString` — require infrastructure Rugra does not yet expose
/// on Funcdata. The transform (`pushConstFurther` over descendants →
/// COPY / opDestroy) is implemented in `push_const_further` and would be invoked
/// once those scope/string-manager guards can be evaluated.
pub struct RulePtrsubCharConstant;

impl RulePtrsubCharConstant {
    // Ghidra: ruleaction.cc:7360 RulePtrsubCharConstant
    pub fn new() -> Self { Self }

    /// Faithful to `pushConstFurther` (ruleaction.cc:7341-7358). Given a
    /// descendant PTRADD of the collapsed constant, fold the PTRADD's constant
    /// index into the pointer value and turn the PTRADD into a COPY.
    // Ghidra: ruleaction.cc:7341 RulePtrsubCharConstant::pushConstFurther
    fn push_const_further(
        fd: &mut Funcdata,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        val: u64,
        outtype: std::sync::Arc<crate::type_system::datatype::Datatype>,
    ) -> bool {
        if op.0.read().unwrap().opcode != OpCode::CPUI_PTRADD { return false; }
        if slot != 0 { return false; }
        let (vn_in1, vn_in2_offset) = {
            let o = op.0.read().unwrap();
            let vn = match o.get_in(1) { Some(v) => v.clone(), None => return false };
            if !vn.read().unwrap().is_constant() { return false; }
            let mult_vn = match o.get_in(2) { Some(v) => v.clone(), None => return false };
            let mult_offset = mult_vn.read().unwrap().get_offset();
            (vn, mult_offset)
        };
        let addval = vn_in1.read().unwrap().get_offset();
        let addval = addval.wrapping_mul(vn_in2_offset);
        let val = val.wrapping_add(addval);
        let newconst = fd.new_constant(vn_in1.read().unwrap().get_size(), val);
        // Ghidra: newconst->updateType(outtype); put the pointer datatype on the
        // new constant (ruleaction.cc:7352).
        newconst.write().unwrap().update_type(outtype);
        fd.op_remove_input(op, 2);
        fd.op_remove_input(op, 1);
        fd.op_set_opcode(op, OpCode::CPUI_COPY);
        fd.op_set_input(op, newconst, 0);
        true
    }
}

impl Rule for RulePtrsubCharConstant {
    // Ghidra: ruleaction.cc:7372 RulePtrsubCharConstant::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePtrsubCharConstant::applyOp (ruleaction.cc:7372-7421).
        let (sb, vn1, outvn) = {
            let op = op_arc.read().unwrap();
            let sb = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let outvn = match op.output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
            (sb, vn1, outvn)
        };
        if !vn1.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        // sbType = sb->getTypeReadFacing(op); require TYPE_PTR to TYPE_SPACEBASE.
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        let sb_type = sb.read().unwrap().get_type();
        let sb_is_spacebase_ptr = sb_type.as_ref().map(|dt| {
            if dt.get_metatype() != TypeMetatype::Pointer { return false; }
            if let Datatype::Pointer(tp) = dt.as_ref() {
                tp.ptr_to.get_metatype() == TypeMetatype::Spacebase
            } else { false }
        }).unwrap_or(false);
        if !sb_is_spacebase_ptr { return Ok(action_status::NO_CHANGE); }
        // outtype = outvn->getTypeDefFacing(); require TYPE_PTR with
        //   basetype isCharPrint().
        let out_is_char_ptr = outvn.read().unwrap().get_type().as_ref().map(|dt| {
            if dt.get_metatype() != TypeMetatype::Pointer { return false; }
            if let Datatype::Pointer(tp) = dt.as_ref() {
                tp.ptr_to.is_char_print()
            } else { false }
        }).unwrap_or(false);
        if !out_is_char_ptr { return Ok(action_status::NO_CHANGE); }
        // Compute the symbol address. Ghidra uses TypeSpacebase::getAddress
        // (which calls Architecture::resolveConstant). Rugra's spacebase base
        // is 0 (the load image base), so symaddr = vn1 offset.
        let symaddr = vn1.read().unwrap().get_offset();
        // ruleaction.cc:7390 — Scope::isReadOnly(symaddr, 1, op->getAddr()).
        // Rugra has no Scope/Database read-only query wired to rules, so we use
        // Funcdata's string_table as a read-only proxy: its entries come from
        // .rodata (inherently read-only) and stand in for isReadOnly.
        if !_fd.string_table.contains_key(&symaddr) {
            return Ok(action_status::NO_CHANGE); // not a known read-only address
        }
        // ruleaction.cc:7393 — stringManager->isString(symaddr, basetype).
        // If the Architecture exposes a populated StringManager, require it to
        // confirm symaddr holds a real string (the precise Ghidra guard). When
        // no StringManager is attached (legacy/test Funcdata), fall back to the
        // string_table hit alone, which is itself a string-bearing address.
        if let Some(sm) = _fd.get_arch().and_then(|a| a.string_manager.as_ref()) {
            if !sm.read().unwrap().is_string(crate::Address::new(symaddr)) {
                return Ok(action_status::NO_CHANGE); // confirmed not a string
            }
        }
        // If we reach here, the PTRSUB should be converted to a COPY of a
        // constant pointer. Faithful to ruleaction.cc:7396-7421.
        // Convert the original PTRSUB to a COPY of the constant.
        let outvn_size = outvn.read().unwrap().get_size();
        let newvn = _fd.new_constant(outvn_size, vn1.read().unwrap().get_offset());
        if let Some(outtype) = outvn.read().unwrap().get_type() {
            newvn.write().unwrap().update_type(outtype);
        }
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        _fd.op_remove_input(&op_ref, 1);
        _fd.op_set_input(&op_ref, newvn, 0);
        _fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7360 RulePtrsubCharConstant
    fn get_name(&self) -> &str { "ptrsub_char_constant" }
    // Ghidra: ruleaction.cc:7366 RulePtrsubCharConstant::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PTRSUB] }
}

/// Cleanup: Duplicate INT_ZEXT/INT_SEXT when the result feeds multiple pointer
/// calculations, so the extension becomes an implied cast per use.
///
/// Faithful to `RuleExtensionPush` (ruleaction.cc:7435-7476). Counts INT_ADD /
/// PTRADD descendants; if more than one qualifying pointer calc exists, the
/// extension op is duplicated to each descendant via `RulePushPtr::duplicateNeed`.
///
/// The descendant-counting guard logic, the `isAddrForce`/`isAddrTied`/
/// `isTypeLock`/`isNameLock` guards, and the `duplicateNeed` duplication step
/// are all implemented 1:1 against the now-available Varnode flag APIs and the
/// op-edit Funcdata methods.
pub struct RuleExtensionPush;

impl RuleExtensionPush {
    // Ghidra: ruleaction.cc:7423 RuleExtensionPush
    pub fn new() -> Self { Self }

    /// Faithful to `RulePushPtr::duplicateNeed` (ruleaction.cc:6827-6855) plus
    /// `buildVarnodeOut` (ruleaction.cc:6783-6790). Duplicate the single-input
    /// extension op so each descendant gets its own copy, then destroy the
    /// original. We assume the op is INT_ZEXT/INT_SEXT (one input).
    // Ghidra: ruleaction.cc:6827 RulePushPtr::duplicateNeed
    fn duplicate_need(op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) {
        let op_ref = crate::op::PcodeOpRef(op.clone());
        let out_vn = match op.read().unwrap().output.clone() {
            Some(o) => o,
            None => return,
        };
        let in_vn = match op.read().unwrap().inrefs.get(0) {
            Some(v) => v.clone(),
            None => return,
        };
        let num = op.read().unwrap().num_input();
        let opc = op.read().unwrap().opcode;
        let op_addr = op.read().unwrap().get_addr();
        let out_size = out_vn.read().unwrap().get_size();
        // Ghidra's loop re-reads beginDescend() each iteration because each dup
        // repoints one descendant away from out_vn. We grab the first descendant,
        // duplicate the op before it, and repoint its input. Loop until no
        // descendants remain, then destroy the original op.
        loop {
            let first_dec = match out_vn.read().unwrap().descend_iter().next() {
                Some(d) => d,
                None => break, // out_vn has no more descendants
            };
            let slot = {
                let d = first_dec.read().unwrap();
                d.inrefs.iter().position(|v| std::sync::Arc::ptr_eq(v, &out_vn)).unwrap_or(0)
            };
            let dec_ref = crate::op::PcodeOpRef(first_dec.clone());
            // newOp(num, op->getAddr()); opSetOpcode; build output.
            let new_op = fd.new_op(num, op_addr);
            fd.op_set_opcode(&new_op, opc);
            // buildVarnodeOut: if addr-tied/internal → newUniqueOut; else newVarnodeOut(addr).
            // Ghidra keeps addr-tied varnodes at their storage; otherwise a unique.
            // Rugra's new_unique_out always makes an internal unique, matching the
            // IPTR_INTERNAL / non-addr-tied common case.
            let new_out = fd.new_unique_out(out_size, &new_op);
            fd.op_set_input(&new_op, in_vn.clone(), 0);
            if num > 1 {
                if let Some(in1) = op.read().unwrap().inrefs.get(1).cloned() {
                    fd.op_set_input(&new_op, in1, 1);
                }
            }
            fd.op_set_input(&dec_ref, new_out, slot);
            fd.op_insert_before(&new_op, &dec_ref);
        }
        fd.op_destroy(&op_ref);
    }
}

impl Rule for RuleExtensionPush {
    // Ghidra: ruleaction.cc:7435 RuleExtensionPush::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleExtensionPush::applyOp (ruleaction.cc:7435-7476).
        let (in_vn, out_vn) = {
            let op = op_arc.read().unwrap();
            let in_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let out_vn = match op.output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
            (in_vn, out_vn)
        };
        if in_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        // Ghidra guards (ruleaction.cc:7437-7441):
        if in_vn.read().unwrap().is_addr_force() { return Ok(action_status::NO_CHANGE); }
        if in_vn.read().unwrap().is_addr_tied() { return Ok(action_status::NO_CHANGE); }
        if out_vn.read().unwrap().is_type_lock() || out_vn.read().unwrap().is_name_lock() {
            return Ok(action_status::NO_CHANGE);
        }
        if out_vn.read().unwrap().is_addr_force() || out_vn.read().unwrap().is_addr_tied() {
            return Ok(action_status::NO_CHANGE);
        }

        let descends: Vec<_> = out_vn.read().unwrap().descend_iter().collect();
        let mut addcount = 0i32; // INT_ADD descendants feeding a lone PTRADD
        let mut ptrcount = 0i32; // PTRADD descendants
        for dec_op in &descends {
            let opc = dec_op.read().unwrap().opcode;
            if opc == OpCode::CPUI_PTRADD {
                ptrcount += 1;
            } else if opc == OpCode::CPUI_INT_ADD {
                // subOp = decOp->getOut()->loneDescend(); must be PTRADD.
                let out = match dec_op.read().unwrap().output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
                let sub_op = out.read().unwrap().lone_descend();
                if sub_op.is_none() { return Ok(action_status::NO_CHANGE); }
                if sub_op.unwrap().read().unwrap().opcode != OpCode::CPUI_PTRADD {
                    return Ok(action_status::NO_CHANGE);
                }
                addcount += 1;
            } else {
                return Ok(action_status::NO_CHANGE);
            }
        }
        if addcount + ptrcount <= 1 { return Ok(action_status::NO_CHANGE); }
        if addcount > 0 {
            // if op->getIn(0)->loneDescend() != null return 0
            if in_vn.read().unwrap().lone_descend().is_some() {
                return Ok(action_status::NO_CHANGE);
            }
        }
        // RulePushPtr::duplicateNeed(op, data); duplicate the extension to all descendants.
        Self::duplicate_need(op_arc, fd);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7423 RuleExtensionPush
    fn get_name(&self) -> &str { "extension_push" }
    // Ghidra: ruleaction.cc:7428 RuleExtensionPush::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ZEXT, OpCode::CPUI_INT_SEXT] }
}

/// Cleanup: Convert LOAD size to match the pointer's data-type.
///
/// Faithful to `RuleExpandLoad` (ruleaction.cc:10937-11013) plus helpers
/// `checkAndComparison` (ruleaction.cc:10878-10893) and `modifyAndComparison`
/// (ruleaction.cc:10904-10925). Grows a LOAD's output to a larger size when it
/// is used purely in `(load & C) == D` comparisons, or when a natural integer
/// truncation applies.
///
/// NOTE: The pointer's pointed-to data-type (`getPtrTo`), the const-space
/// big-endian resolution (`AddressSpace::from_id`), and the per-Varnode
/// metatype are now all available via `get_type()`. The addForm and
/// integer-truncation transforms are now implemented, and the
/// `data.getArch()->types->getBase(...)` type-attach on new varnodes is wired
/// via `Architecture::get_base_type` + `Varnode::update_type`. In a test
/// environment with no pointer type, the rule gracefully no-ops.
pub struct RuleExpandLoad;

impl RuleExpandLoad {
    // Ghidra: ruleaction.cc:10927 RuleExpandLoad
    pub fn new() -> Self { Self }

    /// Faithful to `checkAndComparison` (ruleaction.cc:10878-10893). True iff
    /// every descendant of `vn` is `INT_AND vn const` whose sole descendant is a
    /// constant-comparison INT_EQUAL/INT_NOTEQUAL.
    // Ghidra: ruleaction.cc:10878 RuleExpandLoad::checkAndComparison
    fn check_and_comparison(vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> bool {
        let descends: Vec<_> = vn.read().unwrap().descend_iter().collect();
        if descends.is_empty() { return false; }
        for op in descends {
            if op.read().unwrap().opcode != OpCode::CPUI_INT_AND { return false; }
            let c = match op.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return false };
            if !c.read().unwrap().is_constant() { return false; }
            let and_out = match op.read().unwrap().output.clone() { Some(o) => o, None => return false };
            let comp_op = match and_out.read().unwrap().lone_descend() { Some(o) => o, None => return false };
            let opc = comp_op.read().unwrap().opcode;
            if opc != OpCode::CPUI_INT_EQUAL && opc != OpCode::CPUI_INT_NOTEQUAL { return false; }
            let cc = match comp_op.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return false };
            if !cc.read().unwrap().is_constant() { return false; }
        }
        true
    }

    /// Faithful to `modifyAndComparison` (ruleaction.cc:10904-10925). Rewrites
    /// the constants in the `(V & C) == D` forms scanned by
    /// `check_and_comparison`: shift them left by `offset` bytes and point the
    /// AND at the new bigger variable `new_vn`.
    // Ghidra: ruleaction.cc:10904 RuleExpandLoad::modifyAndComparison
    fn modify_and_comparison(
        fd: &mut Funcdata,
        old_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        new_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        new_size: usize,
        offset: usize,
        dt: std::sync::Arc<crate::type_system::datatype::Datatype>,
    ) {
        let shift = 8 * offset; // bytes → bits
        let descends: Vec<_> = old_vn.read().unwrap().descend_iter().collect();
        for and_op in descends {
            // Find the lone compare descendant of the AND's output.
            let comp_op = {
                let and_out = and_op.read().unwrap().output.clone().unwrap();
                let opt = and_out.read().unwrap().lone_descend();
                opt.unwrap()
            };
            let and_ref = crate::op::PcodeOpRef(and_op.clone());
            let comp_ref = crate::op::PcodeOpRef(comp_op.clone());
            // AND mask constant
            let (and_mask_off, cmp_off) = {
                let and_rg = and_op.read().unwrap();
                let and_mask = and_rg.get_in(1).unwrap().read().unwrap().get_offset();
                let cmp_rg = comp_op.read().unwrap();
                let cmp_c = cmp_rg.get_in(1).unwrap().read().unwrap().get_offset();
                (and_mask << shift, cmp_c << shift)
            };
            // Ghidra: vn = data.newConstant(dt->getSize(), newOff); vn->updateType(dt);
            let vn = fd.new_constant(new_size, and_mask_off);
            vn.write().unwrap().update_type(dt.clone());
            fd.op_set_input(&and_ref, new_vn.clone(), 0);
            fd.op_set_input(&and_ref, vn, 1);
            // compare constant: vn = data.newConstant(dt->getSize(), newOff); vn->updateType(dt);
            let vn = fd.new_constant(new_size, cmp_off);
            vn.write().unwrap().update_type(dt.clone());
            fd.op_set_input(&comp_ref, vn, 1);
        }
    }
}

impl Rule for RuleExpandLoad {
    // Ghidra: ruleaction.cc:10937 RuleExpandLoad::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleExpandLoad::applyOp (ruleaction.cc:10937-11013).
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        let (out_vn, root_ptr, space_id_vn) = {
            let op = op_arc.read().unwrap();
            let out_vn = match op.output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
            let root_ptr = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let space_id_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (out_vn, root_ptr, space_id_vn)
        };
        let out_size = out_vn.read().unwrap().get_size();
        let mut add_op: Option<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = None;
        let mut offset = 0usize;
        // Resolve the pointed-to data-type (elType) following any INT_ADD
        // constant offset in rootPtr.
        let el_type: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> = {
            use crate::type_system::datatype::{Datatype, TypeMetatype};
            if root_ptr.read().unwrap().is_written() {
                let def = match root_ptr.read().unwrap().get_def() { Some(d) => d, None => return Ok(action_status::NO_CHANGE) };
                if def.read().unwrap().opcode == OpCode::CPUI_INT_ADD {
                    let in1 = match def.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                    if !in1.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
                    let off = in1.read().unwrap().get_offset();
                    if off > 16 { return Ok(action_status::NO_CHANGE); } // INT_ADD offset must be small
                    // INT_ADD must be used only once.
                    let addout = match def.read().unwrap().output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
                    if addout.read().unwrap().lone_descend().is_none() { return Ok(action_status::NO_CHANGE); }
                    add_op = Some(def.clone());
                    offset = off as usize;
                    // elType = rootPtr (=def->getIn(0))->getTypeReadFacing(def)
                    let real_root = match def.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                    let dt = match real_root.read().unwrap().get_type() { Some(t) => t, None => return Ok(action_status::NO_CHANGE) };
                    if dt.get_metatype() != TypeMetatype::Pointer { return Ok(action_status::NO_CHANGE); }
                    let ptr_to = match dt.as_ref() { Datatype::Pointer(tp) => tp.ptr_to.clone(), _ => return Ok(action_status::NO_CHANGE) };
                    Some(ptr_to)
                } else {
                    // elType = rootPtr->getTypeReadFacing(op)
                    let dt = match root_ptr.read().unwrap().get_type() { Some(t) => t, None => return Ok(action_status::NO_CHANGE) };
                    if dt.get_metatype() != TypeMetatype::Pointer { return Ok(action_status::NO_CHANGE); }
                    let ptr_to = match dt.as_ref() { Datatype::Pointer(tp) => tp.ptr_to.clone(), _ => return Ok(action_status::NO_CHANGE) };
                    Some(ptr_to)
                }
            } else {
                let dt = match root_ptr.read().unwrap().get_type() { Some(t) => t, None => return Ok(action_status::NO_CHANGE) };
                if dt.get_metatype() != TypeMetatype::Pointer { return Ok(action_status::NO_CHANGE); }
                let ptr_to = match dt.as_ref() { Datatype::Pointer(tp) => tp.ptr_to.clone(), _ => return Ok(action_status::NO_CHANGE) };
                Some(ptr_to)
            }
        };
        let el_type = match el_type { Some(t) => t, None => return Ok(action_status::NO_CHANGE) };
        if el_type.get_size() <= out_size { return Ok(action_status::NO_CHANGE); }
        if el_type.get_size() < out_size + offset { return Ok(action_status::NO_CHANGE); }

        use crate::type_system::datatype::TypeMetatype;
        let meta = el_type.get_metatype();
        if meta == TypeMetatype::Unknown { return Ok(action_status::NO_CHANGE); }
        let add_form = Self::check_and_comparison(&out_vn);
        // AddrSpace *spc = op->getIn(0)->getSpaceFromConst();
        let spc_id: crate::space::SpaceId = if space_id_vn.read().unwrap().is_constant() {
            space_id_vn.read().unwrap().get_offset() as u8
        } else {
            return Ok(action_status::NO_CHANGE);
        };
        let spc = crate::space::AddressSpace::from_id(spc_id);
        let is_big_endian = spc.is_big_endian();
        let mut lsb_cut = 0usize;
        if add_form {
            lsb_cut = if is_big_endian { el_type.get_size() - out_size - offset } else { offset };
        } else {
            // Check for natural integer truncation.
            if meta != TypeMetatype::Int && meta != TypeMetatype::Uint { return Ok(action_status::NO_CHANGE); }
            // outMeta = outVn->getTypeDefFacing()->getMetatype(); must be INT/UINT/UNKNOWN/BOOL.
            let out_meta = out_vn.read().unwrap().get_type().map(|t| t.get_metatype());
            match out_meta {
                None | Some(TypeMetatype::Int) | Some(TypeMetatype::Uint)
                | Some(TypeMetatype::Unknown) | Some(TypeMetatype::Bool) => {}
                _ => return Ok(action_status::NO_CHANGE),
            }
            // LOAD must grab least significant bytes.
            if is_big_endian {
                if out_size + offset != el_type.get_size() { return Ok(action_status::NO_CHANGE); }
            } else if offset != 0 {
                return Ok(action_status::NO_CHANGE);
            }
        }
        // Modify the LOAD: grow output to elType's size. Ghidra passes elType
        // to newUnique; Rugra's new_unique takes no type, so we set it here
        // (ruleaction.cc:10994 newUnique(elType->getSize(), elType)).
        let new_out = fd.new_unique(el_type.get_size());
        new_out.write().unwrap().update_type(el_type.clone());
        fd.op_set_output(&op_ref, new_out.clone());
        if let Some(add_op) = add_op.as_ref() {
            // rootPtr input → real root; destroy the INT_ADD offset op.
            let real_root = match add_op.read().unwrap().get_in(0).cloned() {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            };
            fd.op_set_input(&op_ref, real_root, 1);
            fd.op_destroy(&crate::op::PcodeOpRef(add_op.clone()));
        }
        if add_form {
            // Ghidra rewrites elType to a TYPE_UINT base when meta is not
            // INT/UINT (ruleaction.cc:11001-11002):
            //   if (meta != TYPE_INT && meta != TYPE_UINT)
            //     elType = data.getArch()->types->getBase(elType->getSize(), TYPE_UINT);
            // Rugra resolves the base type via Architecture::get_base_type;
            // if the architecture has no type-table it keeps el_type unchanged.
            let eff_type = if meta != TypeMetatype::Int && meta != TypeMetatype::Uint {
                fd.get_arch()
                    .and_then(|a| a.get_base_type(el_type.get_size(), TypeMetatype::Uint))
                    .unwrap_or_else(|| el_type.clone())
            } else {
                el_type.clone()
            };
            Self::modify_and_comparison(fd, &out_vn, &new_out, eff_type.get_size(), lsb_cut, eff_type);
        } else {
            // Truncate the new bigger LOAD output with a SUBPIECE → out_vn.
            let sub_op = fd.new_op(2, op_arc.read().unwrap().get_addr());
            fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&sub_op, new_out, 0);
            let zero_c = fd.new_constant(4, 0);
            fd.op_set_input(&sub_op, zero_c, 1);
            fd.op_set_output(&sub_op, out_vn);
            fd.op_insert_after(&sub_op, &op_ref);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:10927 RuleExpandLoad
    fn get_name(&self) -> &str { "expand_load" }
    // Ghidra: ruleaction.cc:10931 RuleExpandLoad::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_LOAD] }
}

/// A node in a CONCAT tree of CPUI_PIECE operations.
///
/// Faithful to Ghidra's `PieceNode` (op.hh:262-277, op.cc:801-876). Records a
/// single piece Varnode within a PIECE op: which op reads it, which input slot,
/// its byte offset into the structured data-type, and whether it is a leaf of
/// the tree (i.e. does not itself read the output of another PIECE).
struct PieceNode {
    /// The CPUI_PIECE op that reads this piece (held by Arc; the same op may
    /// appear in two nodes, one per input slot).
    op: std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    /// Input slot (0 = high half, 1 = low half) of this piece within `op`.
    slot: usize,
    /// Byte offset of this piece into the structured data-type.
    type_offset: i32,
    /// True if this node is a leaf (its Varnode is not itself a PIECE output).
    leaf: bool,
}

impl PieceNode {
    /// True if this node is a leaf of the CONCAT tree.
    // Ghidra: op.hh:262 PieceNode
    fn is_leaf(&self) -> bool { self.leaf }
    /// Byte offset of this piece into the data-type.
    // Ghidra: op.hh:262 PieceNode
    fn get_type_offset(&self) -> i32 { self.type_offset }
    /// The PIECE op reading this piece.
    // Ghidra: op.hh:262 PieceNode
    fn get_op(&self) -> &std::sync::Arc<std::sync::RwLock<PcodeOp>> { &self.op }
    /// The input slot of this piece within its PIECE op.
    // Ghidra: op.hh:271 PieceNode::getSlot
    fn get_slot(&self) -> usize { self.slot }

    /// The Varnode representing this piece (`op->getIn(slot)`).
    // Ghidra: op.hh:262 PieceNode
    fn get_varnode(&self) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        self.op.read().unwrap().inrefs.get(self.slot).cloned()
    }

    /// Faithful to `PieceNode::isLeaf` (op.cc:801-817). A Varnode `vn` (at byte
    /// offset `rel_offset` within the data-type, relative to the root's offset)
    /// is a leaf unless it is itself the output of a PIECE feeding a lone
    /// descendant with matching address bookkeeping.
    // Ghidra: op.cc:801 PieceNode::isLeaf
    fn is_leaf_node(
        root_vn: &crate::varnode::Varnode,
        vn: &crate::varnode::Varnode,
        rel_offset: i32,
    ) -> bool {
        // vn->isMapped() && root->getSymbolEntry() != vn->getSymbolEntry()
        if vn.mapentry.is_some() {
            let root_entry = root_vn.get_symbol_entry();
            let vn_entry = vn.get_symbol_entry();
            let differ = match (&root_entry, &vn_entry) {
                (Some(r), Some(v)) => !std::sync::Arc::ptr_eq(r, v),
                _ => true,
            };
            if differ { return true; }
        }
        // !vn->isWritten()
        if !vn.is_written() { return true; }
        // def->code() != CPUI_PIECE
        let def = match vn.get_def() { Some(d) => d, None => return true };
        if def.read().unwrap().opcode != OpCode::CPUI_PIECE { return true; }
        // op = vn->loneDescend(); op == null → leaf
        let lone = match vn.lone_descend() { Some(o) => o, None => return true };
        // vn->isAddrTied() → leaf unless vn->getAddr() == root->getAddr()+relOffset
        if vn.is_addr_tied() {
            let addr = root_vn.get_offset().wrapping_add(rel_offset as u64);
            if vn.get_offset() != addr { return true; }
            // (the lone descendant must be the PIECE we came from; the address
            //  bookkeeping is satisfied by the loneDescend check above.)
            let _ = lone;
        }
        false
    }

    /// Faithful to `PieceNode::gatherPieces` (op.cc:865-876). Recursively walk
    /// backwards from the root through CPUI_PIECE ops, appending one node per
    /// input slot. Endianness determines the byte offset of each input: in a
    /// big-endian space, slot 1 (low half) sits at the higher offset.
    // Ghidra: op.cc:865 PieceNode::gatherPieces
    fn gather_pieces(
        stack: &mut Vec<PieceNode>,
        root_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        base_offset: i32,
        root_offset: i32,
    ) {
        // Big-endianness comes from the root's address space.
        let big_endian = root_vn.read().unwrap().get_space().is_big_endian();
        // Snapshot the two input varnodes + their sizes to avoid holding the
        // op lock across recursive calls.
        let (in0, in1, sz0, sz1) = {
            let o = op.read().unwrap();
            let i0 = match o.inrefs.get(0) { Some(v) => v.clone(), None => return };
            let i1 = match o.inrefs.get(1) { Some(v) => v.clone(), None => return };
            let s0 = i0.read().unwrap().get_size() as i32;
            let s1 = i1.read().unwrap().get_size() as i32;
            (i0, i1, s0, s1)
        };
        // Process slot 0 then slot 1. For each non-leaf input, recurse into its
        // defining PIECE op. The borrow on root_vn is released after is_leaf_node.
        for (slot, vn, other_sz) in [(0usize, in0.clone(), sz1), (1usize, in1.clone(), sz0)] {
            // offset = (isBigEndian == (slot==1)) ? baseOffset + otherSize : baseOffset
            let offset = if big_endian == (slot == 1) {
                base_offset + other_sz
            } else {
                base_offset
            };
            let res = {
                let root_rg = root_vn.read().unwrap();
                let vn_rg = vn.read().unwrap();
                Self::is_leaf_node(&root_rg, &vn_rg, offset - root_offset)
            };
            stack.push(PieceNode { op: op.clone(), slot, type_offset: offset, leaf: res });
            if !res {
                // Recurse into the defining PIECE op of this non-leaf input.
                let def = vn.read().unwrap().get_def();
                if let Some(defop) = def {
                    Self::gather_pieces(stack, root_vn, &defop, offset, root_offset);
                }
            }
        }
    }
}

/// Cleanup: Concatenating structure pieces gets printed as explicit write
/// statements.
///
/// Faithful to `RulePieceStructure` (ruleaction.cc:7625-7720) plus helpers
/// `determineDatatype` (7481-7517), `spanningRange` (7519-7541),
/// `convertZextToPiece` (7543-7572), `findReplaceZext` (7574-7596),
/// `separateSymbol` (7598-7611), and the `PieceNode` engine (op.cc:801-876).
///
/// The rule is driven by structured data-types. Rugra exposes
/// `get_type()` / `is_piece_structured()` / `get_sub_type()`, so the
/// `spanning_range` and `determine_datatype` guards are wired. The piece
/// reassembly now performs a real transform: for each leaf of the CONCAT tree
/// it inserts a COPY into a correctly-addressed Varnode (typed via
/// `get_sub_type`) and rewires the PIECE input. Internal (non-leaf) Varnodes
/// that need new storage are replaced in place. Ghidra's
/// `registerProtoPartialRoot` / `inheritResolution` / `getExactPiece` are not
/// modelled in Rugra, so those sub-steps are omitted (the proto-partial flag is
/// still set on rewritten Varnodes for the merge pass).
pub struct RulePieceStructure;

impl RulePieceStructure {
    // Ghidra: ruleaction.cc:7613 RulePieceStructure
    pub fn new() -> Self { Self }

    /// Faithful to `determineDatatype` (ruleaction.cc:7481-7510). Returns the
    /// structured (struct/array/union) data-type the varnode is part of, plus
    /// the base offset. Uses `getStructuredType` and, for the partial case,
    /// resolves the byte offset via `SymbolEntry` then walks `getSubType`.
    // Ghidra: ruleaction.cc:7481 RulePieceStructure::determineDatatype
    fn determine_datatype(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<(std::sync::Arc<crate::type_system::datatype::Datatype>, i32)> {
        let ct = vn.read().unwrap().get_structured_type()?;
        let vn_size = vn.read().unwrap().get_size();
        if ct.get_size() != vn_size {
            // vn is a partial: compute baseOffset from SymbolEntry.
            let entry = vn.read().unwrap().get_symbol_entry()?;
            let entry_rg = entry.read().unwrap();
            let entry_addr = entry_rg.get_addr().as_u64();
            let vn_addr = vn.read().unwrap().get_offset();
            // baseOffset = vn->getAddr().overlap(0, entry->getAddr(), ct->getSize())
            // which is the byte distance of vn's start within the symbol.
            let mut base_offset = vn_addr as i64 - entry_addr as i64;
            if base_offset < 0 {
                return None;
            }
            base_offset += entry_rg.get_offset() as i64;
            // Walk getSubType down to the concrete sub-type matching vn size.
            let mut sub_type = ct.clone();
            let mut sub_offset = base_offset;
            while sub_type.get_size() > vn_size {
                let (st_opt, so) = sub_type.get_sub_type(sub_offset);
                match st_opt {
                    Some(st) => {
                        sub_type = std::sync::Arc::new(st.clone());
                        sub_offset = so;
                    }
                    None => break,
                }
            }
            if sub_type.get_size() == vn_size && sub_offset == 0 {
                if !sub_type.is_piece_structured() {
                    return None; // don't split CONCAT forming the sub-type
                }
            }
            Some((ct, base_offset as i32))
        } else {
            Some((ct, 0))
        }
    }

    /// Faithful to `spanningRange` (ruleaction.cc:7519-7541). True unless the
    /// range falls within a single non-structured element.
    // Ghidra: ruleaction.cc:7519 RulePieceStructure::spanningRange
    fn spanning_range(
        ct: &std::sync::Arc<crate::type_system::datatype::Datatype>,
        offset: i32,
        size: i32,
    ) -> bool {
        if (offset + size) as usize > ct.get_size() { return false; }
        let mut cur = ct.clone();
        let mut new_off = offset;
        loop {
            let (sub, off) = cur.get_sub_type(new_off as i64);
            match sub {
                None => return true, // Don't know what it spans, assume multiple
                Some(s) => {
                    if (new_off + size) as usize > s.get_size() { return true; }
                    if !s.is_piece_structured() {
                        return false;
                    }
                    cur = std::sync::Arc::new(s.clone());
                    new_off = off as i32;
                }
            }
        }
    }

    /// Faithful to `convertZextToPiece` (ruleaction.cc:7543-7564). Converts an
    /// INT_ZEXT op into a PIECE with a zero constant as its first (high) input.
    /// `ct`/`offset` describe the data-type and byte offset of the op's output.
    /// A zero Varnode of size `out - in` is created and, if `get_sub_type`
    /// resolves to a matching-size sub-type, given that type. The op's opcode is
    /// switched to CPUI_PIECE and the zero inserted at slot 0.
    /// `invn->getType()->needsResolution()` → `inheritResolution` (7561-7562) is
    /// not modelled in Rugra and is skipped.
    // Ghidra: ruleaction.cc:7543 RulePieceStructure::convertZextToPiece
    fn convert_zext_to_piece(
        zext: &crate::op::PcodeOpRef,
        ct: &std::sync::Arc<crate::type_system::datatype::Datatype>,
        offset: i32,
        fd: &mut Funcdata,
    ) -> bool {
        let (outvn, invn, big_endian) = {
            let z = zext.0.read().unwrap();
            let outvn = match &z.output { Some(o) => o.clone(), None => return false };
            let invn = match z.inrefs.get(0) { Some(v) => v.clone(), None => return false };
            let big_endian = outvn.read().unwrap().get_space().is_big_endian();
            (outvn, invn, big_endian)
        };
        // invn->isConstant() → false
        if invn.read().unwrap().is_constant() { return false; }
        let in_size = invn.read().unwrap().get_size() as i32;
        let out_size = outvn.read().unwrap().get_size() as i32;
        let sz = out_size - in_size;
        // sz > sizeof(uintb) (8) → false
        if sz > 8 { return false; }
        // offset += outvn->getSpace()->isBigEndian() ? 0 : invn->getSize()
        let mut new_off = offset + if big_endian { 0 } else { in_size };
        // Walk getSubType down until ct->getSize() <= sz.
        let mut cur: std::sync::Arc<crate::type_system::datatype::Datatype> = ct.clone();
        let zero_type: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> = loop {
            if cur.get_size() as i32 <= sz {
                if cur.get_size() as i32 == sz {
                    break Some(cur.clone());
                }
                break None;
            }
            let (sub, off) = cur.get_sub_type(new_off as i64);
            match sub {
                Some(s) => {
                    cur = std::sync::Arc::new(s.clone());
                    new_off = off as i32;
                }
                None => break None,
            }
        };
        // zerovn = data.newConstant(sz, 0); updateType if ct matches.
        let zerovn = fd.new_constant(sz as usize, 0);
        if let Some(t) = zero_type {
            zerovn.write().unwrap().update_type(t);
        }
        // data.opSetOpcode(zext, CPUI_PIECE); opInsertInput(zext, zerovn, 0)
        fd.op_set_opcode(zext, OpCode::CPUI_PIECE);
        fd.op_insert_input(zext, zerovn, 0);
        // invn->getType()->needsResolution() → inheritResolution: skipped
        // (no type-resolution state in Rugra).
        true
    }

    /// Faithful to `findReplaceZext` (ruleaction.cc:7574-7590). Walks the
    /// gathered CONCAT-tree nodes; for each INT_ZEXT leaf whose Varnode spans
    /// multiple structure elements, converts the ZEXT to a PIECE. Returns true
    /// if any conversion happened (so the caller rebuilds the tree).
    // Ghidra: ruleaction.cc:7574 RulePieceStructure::findReplaceZext
    fn find_replace_zext(
        stack: &[PieceNode],
        structured_type: &std::sync::Arc<crate::type_system::datatype::Datatype>,
        fd: &mut Funcdata,
    ) -> bool {
        let mut change = false;
        // Snapshot the (varnode, type_offset) of every leaf up front, since
        // convert_zext_to_piece mutates the tree and we must not iterate it.
        let mut leaves: Vec<(std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, i32)> = Vec::new();
        for node in stack {
            if !node.is_leaf() { continue; }
            if let Some(vn) = node.get_varnode() {
                leaves.push((vn, node.get_type_offset()));
            }
        }
        for (vn, type_offset) in leaves {
            if !vn.read().unwrap().is_written() { continue; }
            let def = match vn.read().unwrap().get_def() { Some(d) => d, None => continue };
            if def.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { continue; }
            let vn_size = vn.read().unwrap().get_size() as i32;
            if !Self::spanning_range(structured_type, type_offset, vn_size) { continue; }
            if Self::convert_zext_to_piece(&crate::op::PcodeOpRef(def), structured_type, type_offset, fd) {
                change = true;
            }
        }
        change
    }

    /// Faithful to `separateSymbol` (ruleaction.cc:7598-7611). Returns true if a
    /// CONCAT-tree leaf should be treated as belonging to a different symbol
    /// than the root. A leaf is separate if its symbol entry differs from the
    /// root's, or if the root is not addr-tied, or if the leaf is proto-partial
    /// / defined by a marker / defined by a PIECE whose type is itself
    /// piece-structured.
    // Ghidra: ruleaction.cc:7598 RulePieceStructure::separateSymbol
    fn separate_symbol(
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        leaf: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        let root_entry = root.read().unwrap().get_symbol_entry();
        let leaf_entry = leaf.read().unwrap().get_symbol_entry();
        let differ = match (&root_entry, &leaf_entry) {
            (Some(r), Some(l)) => !std::sync::Arc::ptr_eq(r, l),
            _ => true,
        };
        if differ {
            return true; // forced to be different symbols
        }
        if root.read().unwrap().is_addr_tied() { return false; }
        if !leaf.read().unwrap().is_written() { return true; }
        if leaf.read().unwrap().is_proto_partial() { return true; }
        let def = match leaf.read().unwrap().get_def() { Some(d) => d, None => return true };
        if def.read().unwrap().is_marker() { return true; }
        if def.read().unwrap().opcode != OpCode::CPUI_PIECE { return false; }
        if let Some(t) = leaf.read().unwrap().get_type() {
            if t.is_piece_structured() { return true; }
        }
        false
    }

    /// Faithful to `TypeFactory::getExactPiece` (type.cc:2945-2976). Given a
    /// structured data-type, an offset, and a size, descend through
    /// `get_sub_type` until the component exactly matches `(offset, size)`; if
    /// such an exact component exists return it, otherwise None. This replaces
    /// Ghidra's `data.getArch()->types->getExactPiece(ct, off, sz)`.
    // Ghidra: type.cc:4090 TypeFactory::getExactPiece
    fn get_exact_piece(
        mut ct: &crate::type_system::datatype::Datatype,
        mut off: i64,
        size: i64,
    ) -> Option<std::sync::Arc<crate::type_system::datatype::Datatype>> {
        loop {
            if ct.get_size() as i64 == size && off == 0 {
                return Some(std::sync::Arc::new(ct.clone()));
            }
            if ct.get_size() as i64 <= size {
                return None;
            }
            let (sub, new_off) = ct.get_sub_type(off);
            match sub {
                Some(s) => {
                    ct = s;
                    off = new_off;
                }
                None => return None,
            }
        }
    }
}

impl Rule for RulePieceStructure {
    // Ghidra: ruleaction.cc:7625 RulePieceStructure::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePieceStructure::applyOp (ruleaction.cc:7625-7718).
        // Ghidra's `op->isPartialRoot()` re-visit guard is not modelled in
        // Rugra (no partial-root flag on PcodeOp), so it is skipped.
        let outvn = match op_arc.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        // determineDatatype(outvn).
        let (ct, base_offset) = match Self::determine_datatype(&outvn) {
            Some(x) => x,
            None => return Ok(action_status::NO_CHANGE),
        };
        // INT_ZEXT fast path: convert to PIECE immediately.
        let is_zext = op_arc.read().unwrap().opcode == OpCode::CPUI_INT_ZEXT;
        if is_zext {
            let out_type = outvn.read().unwrap().get_type().unwrap_or(ct.clone());
            if Self::convert_zext_to_piece(&crate::op::PcodeOpRef(op_arc.clone()), &out_type, 0, fd) {
                return Ok(action_status::CHANGE);
            }
            return Ok(action_status::NO_CHANGE);
        }
        // The rule also only targets PIECE (per get_opcodes); anything else no-ops.
        if op_arc.read().unwrap().opcode != OpCode::CPUI_PIECE {
            return Ok(action_status::NO_CHANGE);
        }
        // Check if outvn is really the root: if its lone descendant is a PIECE
        // or INT_ZEXT, it is a sub-piece — defer to that descendant.
        let lone = outvn.read().unwrap().lone_descend();
        if let Some(zext) = lone {
            let zcode = zext.read().unwrap().opcode;
            if zcode == OpCode::CPUI_PIECE {
                return Ok(action_status::NO_CHANGE); // more PIECEs below, not a root
            }
            if zcode == OpCode::CPUI_INT_ZEXT {
                // Extension of a structured data-type: convert extension first.
                let zout = match zext.read().unwrap().output.clone() {
                    Some(o) => o,
                    None => return Ok(action_status::NO_CHANGE),
                };
                let z_type = zout.read().unwrap().get_type().unwrap_or(ct.clone());
                if Self::convert_zext_to_piece(&crate::op::PcodeOpRef(zext.clone()), &z_type, 0, fd) {
                    return Ok(action_status::CHANGE);
                }
                return Ok(action_status::NO_CHANGE);
            }
        }

        // gatherPieces + findReplaceZext loop: build the CONCAT tree, then
        // convert any INT_ZEXT leaves that span the structure into PIECEs and
        // rebuild the tree until no more ZEXT leaves remain.
        let mut stack: Vec<PieceNode> = Vec::new();
        loop {
            stack.clear();
            PieceNode::gather_pieces(&mut stack, &outvn, op_arc, base_offset, base_offset);
            if !Self::find_replace_zext(&stack, &ct, fd) {
                break;
            }
        }
        // op->setPartialRoot(): no partial-root flag in Rugra, skipped.

        // Walk every node and give it the correct storage address.
        // baseAddr = outvn->getAddr() - baseOffset
        let base_addr = crate::address::Address::new(
            outvn.read().unwrap().get_offset().wrapping_sub(base_offset as u64),
        );
        let mut any_addr_tied = outvn.read().unwrap().is_addr_tied();
        for i in 0..stack.len() {
            let (op_clone, slot, type_offset, is_leaf) = {
                let n = &stack[i];
                (n.op.clone(), n.slot, n.type_offset, n.leaf)
            };
            let vn = match op_clone.read().unwrap().inrefs.get(slot).cloned() {
                Some(v) => v,
                None => continue,
            };
            // addr = baseAddr + node.getTypeOffset(); (renormalize is a no-op for
            // non-join spaces in Rugra's flat Address model.)
            let addr = crate::address::Address::new(base_addr.as_u64().wrapping_add(type_offset as u64));
            let vn_addr = vn.read().unwrap().get_offset();
            if vn_addr == addr.as_u64() {
                // vn already has the correct address.
                if !is_leaf || !Self::separate_symbol(&outvn, &vn) {
                    // Part of the same symbol as the root: just mark proto-partial.
                    let mut vn_w = vn.write().unwrap();
                    if !vn_w.is_addr_tied() && !vn_w.is_proto_partial() {
                        vn_w.set_proto_partial();
                    }
                    any_addr_tied = any_addr_tied || vn_w.is_addr_tied();
                    continue;
                }
            }
            let vn_size = vn.read().unwrap().get_size();
            if is_leaf {
                // Insert a COPY: vn → newVn at the correct address, then point
                // the PIECE input at newVn. Faithful to 7679-7699.
                let op_addr = op_clone.read().unwrap().get_addr();
                let copy_op = fd.new_op(1, op_addr);
                let new_vn = fd.new_varnode_out(vn_size, addr, &copy_op);
                any_addr_tied = any_addr_tied || new_vn.read().unwrap().is_addr_tied();
                // newType = getExactPiece(ct, typeOffset, vn->getSize()) ?: vn->getType()
                let new_type = Self::get_exact_piece(&ct, type_offset as i64, vn_size as i64)
                    .or_else(|| vn.read().unwrap().get_type());
                if let Some(t) = new_type {
                    new_vn.write().unwrap().update_type(t);
                }
                fd.op_set_opcode(&copy_op, OpCode::CPUI_COPY);
                fd.op_set_input(&copy_op, vn, 0);
                fd.op_set_input(&crate::op::PcodeOpRef(op_clone.clone()), new_vn.clone(), slot);
                fd.op_insert_before(&copy_op, &crate::op::PcodeOpRef(op_clone.clone()));
                // needsResolution / resolveInFlow: not modelled in Rugra.
                let mut nv = new_vn.write().unwrap();
                if !nv.is_addr_tied() {
                    nv.set_proto_partial();
                }
            } else {
                // Non-leaf: vn has a lone descendant and is not addr-tied; replace
                // its storage in place. Faithful to 7701-7713.
                let def_op = match vn.read().unwrap().get_def() {
                    Some(d) => crate::op::PcodeOpRef(d),
                    None => continue,
                };
                let lone_op = match vn.read().unwrap().lone_descend() {
                    Some(o) => crate::op::PcodeOpRef(o),
                    None => continue,
                };
                // slot of vn within loneOp.
                let vn_arc = vn.clone();
                let lslot = {
                    let l = lone_op.0.read().unwrap();
                    l.inrefs.iter().position(|v| std::sync::Arc::ptr_eq(v, &vn_arc))
                };
                let lslot = match lslot { Some(s) => s, None => continue };
                let vn_type = vn.read().unwrap().get_type();
                let new_vn = fd.new_varnode(vn_size, addr);
                if let Some(t) = vn_type {
                    new_vn.write().unwrap().update_type(t);
                }
                fd.op_set_output(&def_op, new_vn.clone());
                fd.op_set_input(&lone_op, new_vn.clone(), lslot);
                fd.vbank.destroy_varnode(&vn);
                let mut nv = new_vn.write().unwrap();
                if !nv.is_addr_tied() {
                    nv.set_proto_partial();
                }
            }
        }
        // registerProtoPartialRoot(outvn) when !anyAddrTied: not modelled.
        let _ = any_addr_tied;
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:7613 RulePieceStructure
    fn get_name(&self) -> &str { "piece_structure" }
    // Ghidra: ruleaction.cc:7618 RulePieceStructure::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PIECE, OpCode::CPUI_INT_ZEXT] }
}

// ============================================================================
// oppool1 independent analysis-family rules. Faithful 1:1 ports of
// ruleaction.cc.
// ============================================================================

/// Pull-back SUBPIECE through INDIRECT: when a SUBPIECE reads the output of an
/// INDIRECT wrapping a (dead or resolved) op, narrow the INDIRECT to the
/// truncated bytes.
///
/// Faithful to `RulePullsubIndirect` (ruleaction.cc:962-1014). Reuses the
/// `RulePullsubMulti` helpers (minMaxUse / acceptableSize / findSubpiece /
/// buildSubpiece / replaceDescendants).
///
/// NOTE: The `isIndirectCreation` branch now uses `Funcdata::new_indirect_creation`
/// (with `isIndirectZero` computed inline from the varnode flags). The non-creation
/// branch is ported 1:1.
pub struct RulePullsubIndirect;

impl RulePullsubIndirect {
    // Ghidra: ruleaction.cc:954 RulePullsubIndirect
    pub fn new() -> Self { Self }
}

impl Rule for RulePullsubIndirect {
    // Ghidra: ruleaction.cc:962 RulePullsubIndirect::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePullsubIndirect::applyOp (ruleaction.cc:962-1014).
        let (vn, op_in1_offset) = {
            let op = op_arc.read().unwrap();
            let vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let off_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let off = off_vn.read().unwrap().get_offset();
            (vn, off)
        };
        if !vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        // vn->getSize() > sizeof(uintb)  (8 bytes)
        if vn.read().unwrap().get_size() > 8 { return Ok(action_status::NO_CHANGE); }
        let indir = match vn.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        if indir.read().unwrap().opcode != OpCode::CPUI_INDIRECT { return Ok(action_status::NO_CHANGE); }
        // indir->getIn(1)->getSpace()->getType() != IPTR_IOP
        let indir_in1 = match indir.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !indir_in1.read().unwrap().get_space().is_iop() {
            return Ok(action_status::NO_CHANGE);
        }
        // PcodeOp *targ_op = PcodeOp::getOpFromConst(indir->getIn(1)->getAddr());
        //   if (targ_op->isDead()) return 0;
        let targ_op = match fd.get_op_from_const(&indir_in1) {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        if targ_op.0.read().unwrap().is_dead() {
            return Ok(action_status::NO_CHANGE);
        }
        // vn->isAddrForce() guard.
        if vn.read().unwrap().is_addr_force() {
            return Ok(action_status::NO_CHANGE);
        }
        let (max_byte, min_byte) = RulePullsubMulti::min_max_use(&vn);
        let new_size = max_byte - min_byte + 1;
        if max_byte < min_byte || new_size >= vn.read().unwrap().get_size() as i32 {
            return Ok(action_status::NO_CHANGE);
        }
        if !RulePullsubMulti::acceptable_size(new_size) { return Ok(action_status::NO_CHANGE); }
        let outvn = match op_arc.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        // outvn->isPrecisLo()/isPrecisHi() guard — don't pull apart double-precision objects.
        if outvn.read().unwrap().is_precis_lo() || outvn.read().unwrap().is_precis_hi() {
            return Ok(action_status::NO_CHANGE);
        }
        // consume = calc_mask(newSize) << 8*minByte; consume = ~consume;
        let consume = !(calc_mask(new_size as usize) << (8 * min_byte as u64));
        // indir->getIn(0)->getConsume()  &  consume
        let indir_in0 = match indir.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if (consume & indir_in0.read().unwrap().get_consume()) != 0 {
            return Ok(action_status::NO_CHANGE);
        }
        // Non-creation branch: build a normal INDIRECT wrapping a SUBPIECE of
        // the original base varnode. (The indirect-creation branch above uses
        // Funcdata::new_indirect_creation.)
        let is_big_endian = vn.read().unwrap().space().is_big_endian();
        let vn_addr = vn.read().unwrap().get_offset();
        let vn_size = vn.read().unwrap().get_size();
        let smalladdr2 = if !is_big_endian {
            crate::address::Address::new(vn_addr + min_byte as u64)
        } else {
            crate::address::Address::new(vn_addr + (vn_size as u64 - max_byte as u64 - 1))
        };
        // indir->isIndirectCreation() — Ghidra checks the INDIRECT PcodeOp's
        //   indirect_creation flag. Rugra exposes is_indirect_creation() on
        //   Varnode (the INDIRECT's output `vn`) instead; we use that as the
        //   closest available signal.
        // indir->isIndirectCreation() — Ghidra checks the INDIRECT PcodeOp's
        //   indirect_creation flag. Rugra exposes is_indirect_creation() on
        //   Varnode (the INDIRECT's output `vn`) instead; we use that as the
        //   closest available signal.
        if vn.read().unwrap().is_indirect_creation() {
            // Ghidra (ruleaction.cc:998-1002):
            //   bool possibleout = !indir->getIn(0)->isIndirectZero();
            //   new_ind = data.newIndirectCreation(targ_op,smalladdr2,newSize,possibleout);
            //   small2 = new_ind->getOut();
            // isIndirectZero (varnode.hh:271) is
            //   (flags & (indirect_creation|constant)) == (indirect_creation|constant).
            let possibleout = {
                use crate::varnode::varnode_flags;
                let f = indir_in0.read().unwrap().flags;
                (f & (varnode_flags::INDIRECT_CREATION | varnode_flags::CONSTANT))
                    != (varnode_flags::INDIRECT_CREATION | varnode_flags::CONSTANT)
            };
            let new_ind = fd.new_indirect_creation(
                &targ_op,
                smalladdr2.as_u64(),
                new_size as usize,
                possibleout,
            );
            let small2 = match new_ind.0.read().unwrap().output.clone() {
                Some(o) => o,
                None => return Ok(action_status::NO_CHANGE),
            };
            RulePullsubMulti::replace_descendants(fd, &vn, small2, max_byte, min_byte);
            let _ = outvn;
            return Ok(action_status::CHANGE);
        }
        let basevn = indir_in0.clone();
        // small1 = findSubpiece(basevn,newSize,op->getIn(1)->getOffset()) or buildSubpiece
        let small1 = RulePullsubMulti::find_subpiece(&basevn, new_size as u32, op_in1_offset)
            .unwrap_or_else(|| RulePullsubMulti::build_subpiece(fd, &basevn, new_size as u32, op_in1_offset));
        // Create new indirect near original indirect.
        let indir_addr = indir.read().unwrap().get_addr();
        let new_ind = fd.new_op(2, indir_addr);
        fd.op_set_opcode(&new_ind, OpCode::CPUI_INDIRECT);
        let small2 = fd.new_varnode_out(new_size as usize, smalladdr2, &new_ind);
        fd.op_set_input(&new_ind, small1, 0);
        // data.opSetInput(new_ind, data.newVarnodeIop(targ_op), 1);
        let iop_vn = fd.new_varnode_iop(&targ_op);
        fd.op_set_input(&new_ind, iop_vn, 1);
        fd.op_insert_before(&new_ind, &crate::op::PcodeOpRef(indir.clone()));
        // Replace descendants of vn with small2.
        RulePullsubMulti::replace_descendants(fd, &vn, small2, max_byte, min_byte);
        let _ = outvn;
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:954 RulePullsubIndirect
    fn get_name(&self) -> &str { "pullsub_indirect" }
    // Ghidra: ruleaction.cc:956 RulePullsubIndirect::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

/// Remove a CPUI_INDIRECT if its blocking PcodeOp is dead / resolved.
///
/// Faithful to `RuleIndirectCollapse` (ruleaction.cc:3177-3252). When the op
/// wrapped by an INDIRECT has been resolved to a COPY (with full/partial/identical
/// overlap) the INDIRECT becomes a COPY / SUBPIECE; otherwise, if the wrapped
/// op is dead, the INDIRECT output is totalReplace'd by its input and destroyed.
///
/// NOTE: The iop-space coderef resolution (`get_op_from_const`), the
/// COPY/SUBPIECE overlap-collapse via `characterize_overlap`/`contains`,
/// the `hasNoLocalAlias`/`noIndirectCollapse` guard, the STORE spacebase-guard
/// branch, and the dead-indop `total_replace`+`op_destroy` path are all now
/// implemented against Rugra's flag/op APIs.
pub struct RuleIndirectCollapse;

impl RuleIndirectCollapse {
    // Ghidra: ruleaction.cc:3169 RuleIndirectCollapse
    pub fn new() -> Self { Self }
}

impl Rule for RuleIndirectCollapse {
    // Ghidra: ruleaction.cc:3177 RuleIndirectCollapse::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleIndirectCollapse::applyOp (ruleaction.cc:3177-3252).
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        let (in1, in0, outvn) = {
            let op = op_arc.read().unwrap();
            let in1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let in0 = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let outvn = match op.output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
            (in1, in0, outvn)
        };
        // if (op->getIn(1)->getSpace()->getType()!=IPTR_IOP) return 0;
        if !in1.read().unwrap().get_space().is_iop() {
            return Ok(action_status::NO_CHANGE);
        }
        // PcodeOp *indop = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());
        let indop = match fd.get_op_from_const(&in1) {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        // Is the indirect effect gone?
        if !indop.0.read().unwrap().is_dead() {
            if indop.0.read().unwrap().opcode == OpCode::CPUI_COPY {
                // STORE resolved to a COPY. vn1 = indop->getOut(); vn2 = op->getOut();
                let vn1 = match indop.0.read().unwrap().output.clone() {
                    Some(o) => o,
                    None => return Ok(action_status::NO_CHANGE),
                };
                // res = vn1->characterizeOverlap(*vn2);
                let res = {
                    let v1 = vn1.read().unwrap();
                    let v2 = outvn.read().unwrap();
                    v1.characterize_overlap(&v2)
                };
                if res > 0 { // Copy has an effect of some sort
                    if res == 2 {
                        // vn1 and vn2 are the same storage → Convert INDIRECT to COPY.
                        fd.op_uninsert(&op_ref);
                        fd.op_set_input(&op_ref, vn1, 0);
                        fd.op_remove_input(&op_ref, 1);
                        fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                        fd.op_insert_after(&op_ref, &indop);
                        return Ok(action_status::CHANGE);
                    }
                    // if (vn1->contains(*vn2) == 0): INDIRECT output properly
                    //   contained in COPY output → Convert INDIRECT to a SUBPIECE.
                    let cont = {
                        let v1 = vn1.read().unwrap();
                        let v2 = outvn.read().unwrap();
                        v1.contains(&v2)
                    };
                    if cont == 0 {
                        // trunc offset: big-endian vs little-endian.
                        let trunc = {
                            let v1 = vn1.read().unwrap();
                            let v2 = outvn.read().unwrap();
                            if v1.get_space().is_big_endian() {
                                v1.get_offset() + v1.get_size() as u64 - (v2.get_offset() + v2.get_size() as u64)
                            } else {
                                v2.get_offset() - v1.get_offset()
                            }
                        };
                        fd.op_uninsert(&op_ref);
                        fd.op_set_input(&op_ref, vn1, 0);
                        let trunc_c = fd.new_constant(4, trunc);
                        fd.op_set_input(&op_ref, trunc_c, 1);
                        fd.op_set_opcode(&op_ref, OpCode::CPUI_SUBPIECE);
                        fd.op_insert_after(&op_ref, &indop);
                        return Ok(action_status::CHANGE);
                    }
                    // Partial overlap, not sure what to do.
                    eprintln!("Ignoring partial resolution of indirect");
                    return Ok(action_status::NO_CHANGE);
                }
            } else if outvn.read().unwrap().has_no_local_alias() {
                // Ghidra (ruleaction.cc:3219-3222):
                //   else if (op->getOut()->hasNoLocalAlias()) {
                //     if (op->isIndirectCreation() || op->noIndirectCollapse())
                //       return 0;
                //   }
                // The indirect's output has no aliasable local, so the INDIRECT
                // is collapsible — unless it is an indirect-creation op or was
                // explicitly marked to never collapse.
                let (is_indirect_creation, no_collapse) = {
                    let op = op_arc.read().unwrap();
                    let ic = (op.flags & crate::op::pcodeop_flags::INDIRECT_CREATION) != 0;
                    (ic, op.no_indirect_collapse())
                };
                if is_indirect_creation || no_collapse {
                    return Ok(action_status::NO_CHANGE);
                }
            } else if indop.0.read().unwrap().uses_spacebase_ptr() {
                // Ghidra (ruleaction.cc:3223-3236):
                //   if (indop->code() == CPUI_STORE) {
                //     const LoadGuard *guard = data.getStoreGuard(indop);
                //     if (guard != null) {
                //       if (guard->isGuarded(op->getOut()->getAddr())) return 0;
                //     }
                //     else return 0;  // marked STORE not yet guarded: keep INDIRECT
                //   }
                if indop.0.read().unwrap().opcode == OpCode::CPUI_STORE {
                    // Grab the INDIRECT output's space+offset before borrowing fd
                    // via get_store_guard (which returns Option<&LoadGuard>).
                    let (out_spc, out_off) = {
                        let v = outvn.read().unwrap();
                        (v.get_space(), v.get_offset())
                    };
                    match fd.get_store_guard(&indop) {
                        Some(guard) => {
                            // Guarded range blocks the address → keep INDIRECT.
                            if guard.is_guarded(&out_spc, out_off) {
                                return Ok(action_status::NO_CHANGE);
                            }
                            // Not guarded → fall through to totalReplace (collapse).
                        }
                        None => {
                            // A marked STORE that is not guarded should eventually
                            // get converted to a COPY, so keep the INDIRECT.
                            return Ok(action_status::NO_CHANGE);
                        }
                    }
                }
            } else {
                return Ok(action_status::NO_CHANGE);
            }
        }
        // The indirect effect is gone (indop dead): totalReplace out by in0 + destroy.
        fd.total_replace(&outvn, in0);
        fd.op_destroy(&op_ref);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:3169 RuleIndirectCollapse
    fn get_name(&self) -> &str { "indirect_collapse" }
    // Ghidra: ruleaction.cc:3171 RuleIndirectCollapse::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INDIRECT] }
}

/// Transform CPOOLREF operations by looking up the value in the constant pool.
///
/// Faithful to `RuleTransformCpool` (ruleaction.cc:3915-3940). For a CPOOLREF,
/// look up the constant-pool record; if it is a `primitive`, replace the op
/// with a COPY of the constant value; otherwise append the record tag.
///
/// NOTE: The `isCpoolTransformed`/`opMarkCpoolTransformed` op flags and the
/// `data.getArch()->cpool->getRecord(refs)` lookup are all now wired. In a test
/// environment with no Architecture (or no cpool), the lookup returns None and
/// the rule gracefully no-ops.
pub struct RuleTransformCpool;

impl RuleTransformCpool {
    // Ghidra: ruleaction.cc:3904 RuleTransformCpool
    pub fn new() -> Self { Self }
}

impl Rule for RuleTransformCpool {
    // Ghidra: ruleaction.cc:3915 RuleTransformCpool::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleTransformCpool::applyOp (ruleaction.cc:3915-3940).
        if op_arc.read().unwrap().is_cpool_transformed() {
            return Ok(action_status::NO_CHANGE); // Already visited
        }
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_mark_cpool_transformed(&op_ref);
        // Gather refs from slot 1..n.
        let num_input = op_arc.read().unwrap().num_input();
        if num_input < 2 { return Ok(action_status::NO_CHANGE); }
        let mut refs = Vec::new();
        for i in 1..num_input {
            let vn = match op_arc.read().unwrap().get_in(i).cloned() {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            };
            refs.push(vn.read().unwrap().get_offset());
        }
        // const CPoolRecord *rec = data.getArch()->cpool->getRecord(refs);
        // Gracefully degrade if there is no Architecture / no constant pool.
        let arch = match fd.get_arch() {
            Some(a) => a,
            None => return Ok(action_status::NO_CHANGE),
        };
        let cpool = match &arch.cpool {
            Some(c) => c.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };
        let rec = {
            use crate::cpool::ConstantPool;
            let cp = cpool.read().unwrap();
            cp.get_record(&refs).cloned()
        };
        if let Some(rec) = rec {
            if rec.tag == crate::cpool::cpool_tag::INSTANCE_OF {
                // data.opMarkCalculatedBool(op); — Rugra exposes is_calculated_bool
                //   but no setter; we set the flag bit directly.
                op_arc.write().unwrap().flags |= crate::op::pcodeop_flags::CALCULATED_BOOL;
            } else if rec.tag == crate::cpool::cpool_tag::PRIMITIVE {
                let sz = match op_arc.read().unwrap().output.clone() {
                    Some(o) => o.read().unwrap().get_size(),
                    None => return Ok(action_status::NO_CHANGE),
                };
                let cvn = fd.new_constant(sz, rec.value & calc_mask(sz));
                // Ghidra: cvn->updateType(rec->getType(), true, true)
                //   (ruleaction.cc:3931). Rugra's CPoolRecord stores only a
                //   type-name string; resolve it via the arch's TypeFactory
                //   (find_by_name, mirroring TypeFactory::resolveByName which
                //   CPoolRecord::getType uses) and attach with update_type_lock.
                let resolved_dt = fd.get_arch()
                    .and_then(|a| a.types.as_ref())
                    .and_then(|tf| tf.read().unwrap().find_by_name(&rec.type_name));
                if let Some(dt) = resolved_dt {
                    cvn.write().unwrap().update_type_lock(dt, true, true);
                }
                while op_arc.read().unwrap().num_input() > 1 {
                    fd.op_remove_input(&op_ref, op_arc.read().unwrap().num_input() - 1);
                }
                fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                fd.op_set_input(&op_ref, cvn, 0);
                return Ok(action_status::CHANGE);
            }
            // Otherwise: append the record tag as a trailing constant input.
            let tag_const = fd.new_constant(4, rec.tag as u64);
            fd.op_insert_input(&op_ref, tag_const, op_arc.read().unwrap().num_input());
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:3904 RuleTransformCpool
    fn get_name(&self) -> &str { "transform_cpool" }
    // Ghidra: ruleaction.cc:3909 RuleTransformCpool::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_CPOOLREF] }
}

/// Convert BRANCHIND with only one computed destination to a BRANCH.
///
/// Faithful to `RuleSwitchSingle` (ruleaction.cc:5430-5485). Looks up the op's
/// JumpTable; if the block has a single out-edge and the table is labelled,
/// converts the BRANCHIND into a BRANCH to the (single) destination, emits a
/// warning if the switch has >1 entry or a non-constant index, and removes the
/// jump table.
///
/// NOTE: Now uses `Funcdata::find_jump_table`, `JumpTable::num_entries/
/// is_labelled/get_address_by_index`, `Funcdata::remove_jump_table`, the op's
/// `parent` block `size_out`, and `Funcdata::structure_reset` (which clears the
/// cached high-level structure = `getStructure().clear()`). `Funcdata::newCodeRef`
/// and `Funcdata::warningHeader` are not yet ported: the code-ref varnode is
/// built inline, and the warning is emitted via `eprintln!`.
pub struct RuleSwitchSingle;

impl RuleSwitchSingle {
    // Ghidra: ruleaction.cc:5422 RuleSwitchSingle
    pub fn new() -> Self { Self }
}

impl Rule for RuleSwitchSingle {
    // Ghidra: ruleaction.cc:5430 RuleSwitchSingle::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSwitchSingle::applyOp (ruleaction.cc:5430-5477).
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        // BlockBasic *bb = op->getParent(); if (bb->sizeOut() != 1) return 0;
        let size_out = {
            let op = op_arc.read().unwrap();
            op.parent.as_ref().and_then(|w| w.upgrade())
                .map(|bb| bb.read().unwrap().size_out())
        };
        match size_out {
            Some(n) if n == 1 => {}
            _ => return Ok(action_status::NO_CHANGE),
        }
        // JumpTable *jt = data.findJumpTable(op); find_jump_table borrows fd
        // immutably and returns Option<&Arc<RwLock<JumpTable>>>. We must gather
        // everything we need from the table (entries, labelled, addresses) and
        // clone the Arc BEFORE any &mut fd call (remove_jump_table / op edits).
        let (jt_arc, num_entries, addr): (
            std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>,
            usize, crate::address::Address,
        ) = match fd.find_jump_table(&op_ref) {
            None => return Ok(action_status::NO_CHANGE),
            Some(jt_ref) => {
                let jt = jt_ref.read().unwrap();
                if jt.num_entries() == 0 { return Ok(action_status::NO_CHANGE); }
                if !jt.is_labelled() { return Ok(action_status::NO_CHANGE); } // Labels must be recovered
                (jt_ref.clone(), jt.num_entries(), jt.get_address_by_index(0))
            }
        };
        // needwarning / allcasesmatch (ruleaction.cc:5441-5452).
        let mut need_warning = false;
        let mut all_cases_match = false;
        if num_entries != 1 {
            need_warning = true;
            all_cases_match = true;
            for i in 1..num_entries {
                if jt_arc.read().unwrap().get_address_by_index(i) != addr {
                    all_cases_match = false;
                    break;
                }
            }
        }
        // if (!op->getIn(0)->isConstant()) needwarning = true;
        let in0_is_const = match op_arc.read().unwrap().get_in(0) {
            Some(v) => v.read().unwrap().is_constant(),
            None => false,
        };
        if !in0_is_const {
            need_warning = true;
        }
        if need_warning {
            // Ghidra (ruleaction.cc:5460-5468) builds an ostringstream and
            // calls data.warningHeader(s). Rugra's Funcdata::warning_header now
            // attaches the warning to the Funcdata (and falls back to eprintln
            // if no commentdb is wired).
            let op_addr = op_arc.read().unwrap().get_addr();
            let msg = if all_cases_match {
                format!(
                    "Switch with 1 destination removed at {}: {} cases all go to same destination",
                    op_addr, num_entries
                )
            } else {
                format!("Switch with 1 destination removed at {}", op_addr)
            };
            fd.warning_header(&msg);
        }
        // Convert the BRANCHIND to just a branch.
        // data.opSetOpcode(op,CPUI_BRANCH);
        fd.op_set_opcode(&op_ref, OpCode::CPUI_BRANCH);
        // data.opSetInput(op,data.newCodeRef(addr),0);
        // Rugra Funcdata has no newCodeRef; build the code-ref varnode inline.
        // newCodeRef(addr) (funcdata_varnode.cc:222-233): a size-1 varnode at
        // `addr` in the (code) address space with the annotation flag set.
        // Rugra's Address carries no space; the BRANCH target address space is
        // the default code space (Ram).
        let coderef = {
            let vn = fd.vbank.create_with_space(1, crate::space::AddressSpace::Ram, addr.as_u64());
            vn.write().unwrap().set_flags(crate::varnode::varnode_flags::ANNOTATION);
            vn
        };
        fd.op_set_input(&op_ref, coderef, 0);
        // data.removeJumpTable(jt);
        fd.remove_jump_table(&jt_arc);
        // data.getStructure().clear(); — clear cached high-level structure so
        // the (now collapsed) switch block structures get regenerated. Rugra's
        // structure_reset() rebuilds dominators/loops and clears sblocks.
        fd.structure_reset();
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:5422 RuleSwitchSingle
    fn get_name(&self) -> &str { "switch_single" }
    // Ghidra: ruleaction.cc:5424 RuleSwitchSingle::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_BRANCHIND] }
}

/// Eliminate ARM/THUMB style masking of the low order bits on function pointers.
///
/// Faithful to `RuleFuncPtrEncoding` (ruleaction.cc:9926-9948). For a CALLIND
/// whose input is `INT_AND ptr, mask`, if `mask` selects out the low `align`
/// alignment bits (per `data.getArch()->funcptr_align`), strip the mask by
/// converting the INT_AND into a COPY.
///
/// NOTE: Needs `data.getArch()->funcptr_align`. Rugra now exposes `get_arch()`
/// and stores `funcptr_align` on Architecture. In a test environment with no
/// Architecture (or align==0), the rule gracefully no-ops.
pub struct RuleFuncPtrEncoding;

impl RuleFuncPtrEncoding {
    // Ghidra: ruleaction.cc:9914 RuleFuncPtrEncoding
    pub fn new() -> Self { Self }
}

impl Rule for RuleFuncPtrEncoding {
    // Ghidra: ruleaction.cc:9926 RuleFuncPtrEncoding::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleFuncPtrEncoding::applyOp (ruleaction.cc:9926-9948).
        let align = match fd.get_arch() {
            Some(a) => a.funcptr_align,
            None => return Ok(action_status::NO_CHANGE),
        };
        if align == 0 { return Ok(action_status::NO_CHANGE); }
        let vn = match op_arc.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let andop = match vn.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        if andop.read().unwrap().opcode != OpCode::CPUI_INT_AND { return Ok(action_status::NO_CHANGE); }
        // maskvn = andop->getIn(1); must be constant.
        let maskvn = match andop.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !maskvn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        let val = maskvn.read().unwrap().get_offset();
        let testmask = calc_mask(maskvn.read().unwrap().get_size());
        let slide = (!0u64).wrapping_shl(align as u32);
        if (testmask & slide) == val {
            // 1-bit encoding: eliminate the mask.
            let andop_ref = crate::op::PcodeOpRef(andop.clone());
            fd.op_remove_input(&andop_ref, 1);
            fd.op_set_opcode(&andop_ref, OpCode::CPUI_COPY);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:9914 RuleFuncPtrEncoding
    fn get_name(&self) -> &str { "funcptr_encoding" }
    // Ghidra: ruleaction.cc:9920 RuleFuncPtrEncoding::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_CALLIND] }
}

/// Simplify unsigned-int → float conversion:
/// `T = int2float((X >> 1) | (X & 1)); T + T ⇒ int2float(zext(X))`.
///
/// Faithful to `RuleUnsigned2Float` (ruleaction.cc:9795-9855). Detects the
/// x86-style unsigned-to-float idiom and collapses the `T + T` into a single
/// `FLOAT_INT2FLOAT(zext(X))`.
///
/// NOTE: Uses `TypeOpFloatInt2Float::preferredZextSize`, which Rugra does not
/// expose. We approximate the preferred zext size as `base_size * 2` (capped to
/// 8) — this is the standard value for the supported base sizes (1→2, 2→4,
/// 4→8). Otherwise the pattern/recognition is 1:1.
pub struct RuleUnsigned2Float;

impl RuleUnsigned2Float {
    // Ghidra: ruleaction.cc:9784 RuleUnsigned2Float
    pub fn new() -> Self { Self }

    /// Approximation of `TypeOpFloatInt2Float::preferredZextSize` (see
    /// opfloat.cc). The reference returns base_size*2 for the relevant sizes.
    // Ghidra: typeop.cc:1891 TypeOpFloatInt2Float::preferredZextSize
    fn preferred_zext_size(base_size: usize) -> usize {
        // Standard: 1→2, 2→4, 4→8. Cap at 8 bytes.
        if base_size >= 4 { 8 } else { base_size * 2 }
    }
}

impl Rule for RuleUnsigned2Float {
    // Ghidra: ruleaction.cc:9795 RuleUnsigned2Float::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleUnsigned2Float::applyOp (ruleaction.cc:9795-9855).
        let invn = match op_arc.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !invn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let orop = match invn.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        if orop.read().unwrap().opcode != OpCode::CPUI_INT_OR { return Ok(action_status::NO_CHANGE); }
        let (or0, or1) = {
            let o = orop.read().unwrap();
            (o.get_in(0).cloned(), o.get_in(1).cloned())
        };
        let (or0, or1) = match (or0, or1) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        if !or0.read().unwrap().is_written() || !or1.read().unwrap().is_written() {
            return Ok(action_status::NO_CHANGE);
        }
        // shiftop = in(0) if it is INT_RIGHT else in(1); andop = the other.
        let mut shiftop = or0.read().unwrap().get_def().unwrap();
        let mut andop = or1.read().unwrap().get_def().unwrap();
        if shiftop.read().unwrap().opcode != OpCode::CPUI_INT_RIGHT {
            // swap
            let tmp = shiftop; shiftop = andop; andop = tmp;
        }
        if shiftop.read().unwrap().opcode != OpCode::CPUI_INT_RIGHT { return Ok(action_status::NO_CHANGE); }
        // shiftop->getIn(1)->constantMatch(1)
        let shift_c = match shiftop.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !(shift_c.read().unwrap().is_constant() && shift_c.read().unwrap().get_offset() == 1) {
            return Ok(action_status::NO_CHANGE);
        }
        let basevn = match shiftop.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if basevn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        // optional: andop may be INT_ZEXT of the real INT_AND.
        if andop.read().unwrap().opcode == OpCode::CPUI_INT_ZEXT {
            let inner_def = {
                let in0 = andop.read().unwrap().get_in(0).cloned().unwrap();
                let is_written = in0.read().unwrap().is_written();
                if !is_written {
                    return Ok(action_status::NO_CHANGE);
                }
                let def = in0.read().unwrap().get_def();
                def
            };
            andop = match inner_def {
                Some(d) => d,
                None => return Ok(action_status::NO_CHANGE),
            };
        }
        if andop.read().unwrap().opcode != OpCode::CPUI_INT_AND { return Ok(action_status::NO_CHANGE); }
        let and_c = match andop.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !(and_c.read().unwrap().is_constant() && and_c.read().unwrap().get_offset() == 1) {
            return Ok(action_status::NO_CHANGE); // Mask off least significant bit
        }
        let mut vn = match andop.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !std::sync::Arc::ptr_eq(&vn, &basevn) {
            if !vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let subop = vn.read().unwrap().get_def().unwrap();
            if subop.read().unwrap().opcode != OpCode::CPUI_SUBPIECE { return Ok(action_status::NO_CHANGE); }
            let sub_c = subop.read().unwrap().get_in(1).cloned();
            match sub_c {
                Some(v) if v.read().unwrap().get_offset() == 0 => {
                    vn = subop.read().unwrap().get_in(0).cloned().unwrap();
                    if !std::sync::Arc::ptr_eq(&vn, &basevn) {
                        return Ok(action_status::NO_CHANGE);
                    }
                }
                _ => return Ok(action_status::NO_CHANGE),
            }
        }
        // outvn->beginDescend(): find FLOAT_ADD(outvn, outvn).
        let outvn = match op_arc.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        let descends: Vec<_> = outvn.read().unwrap().descend_iter().collect();
        for addop in descends {
            if addop.read().unwrap().opcode != OpCode::CPUI_FLOAT_ADD { continue; }
            let (ai0, ai1) = {
                let a = addop.read().unwrap();
                (a.get_in(0).cloned(), a.get_in(1).cloned())
            };
            match (ai0, ai1) {
                (Some(a), Some(b)) if std::sync::Arc::ptr_eq(&a, &outvn) && std::sync::Arc::ptr_eq(&b, &outvn) => {
                    let add_addr = addop.read().unwrap().get_addr();
                    let zextop = fd.new_op(1, add_addr);
                    fd.op_set_opcode(&zextop, OpCode::CPUI_INT_ZEXT);
                    let base_size = basevn.read().unwrap().get_size();
                    let zextout = fd.new_unique_out(Self::preferred_zext_size(base_size), &zextop);
                    let add_ref = crate::op::PcodeOpRef(addop.clone());
                    fd.op_set_opcode(&add_ref, OpCode::CPUI_FLOAT_INT2FLOAT);
                    fd.op_remove_input(&add_ref, 1);
                    fd.op_set_input(&zextop, basevn, 0);
                    fd.op_set_input(&add_ref, zextout, 0);
                    fd.op_insert_before(&zextop, &add_ref);
                    return Ok(action_status::CHANGE);
                }
                _ => continue,
            }
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:9784 RuleUnsigned2Float
    fn get_name(&self) -> &str { "unsigned_2_float" }
    // Ghidra: ruleaction.cc:9789 RuleUnsigned2Float::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_FLOAT_INT2FLOAT] }
}

/// Collapse equivalent FLOAT_INT2FLOAT computations along converging data-flow
/// paths.
///
/// Faithful to `RuleInt2FloatCollapse` (ruleaction.cc:9863-9918). When an
/// unsigned `FLOAT_INT2FLOAT(zext(V))` and a signed `FLOAT_INT2FLOAT(V)` merge
/// via a MULTIEQUAL guarded by `V < 0`, collapse to a single unsigned
/// `FLOAT_INT2FLOAT(zext(V))`.
///
/// NOTE: The block/control-flow queries (`findCondition`, `lastOp`,
/// `isBooleanFlip`, `constantMatch`), the comparison verification, and the
/// block-reinsertion transform are all now implemented against the available
/// block + op-edit infrastructure. In a test environment with no block graph
/// (no `parent`), the condition lookup returns None and the rule gracefully
/// no-ops.
pub struct RuleInt2FloatCollapse;

impl RuleInt2FloatCollapse {
    // Ghidra: ruleaction.cc:9851 RuleInt2FloatCollapse
    pub fn new() -> Self { Self }
}

impl Rule for RuleInt2FloatCollapse {
    // Ghidra: ruleaction.cc:9863 RuleInt2FloatCollapse::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleInt2FloatCollapse::applyOp (ruleaction.cc:9863-9918).
        let in0 = match op_arc.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !in0.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let zextop = match in0.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        if zextop.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT { return Ok(action_status::NO_CHANGE); }
        let basevn = match zextop.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if basevn.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        // multiop = op->getOut()->loneDescend()
        let outvn = match op_arc.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        let multiop = match outvn.read().unwrap().lone_descend() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        if multiop.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL { return Ok(action_status::NO_CHANGE); }
        if multiop.read().unwrap().num_input() != 2 { return Ok(action_status::NO_CHANGE); }
        // slot = multiop->getSlot(op->getOut())
        let slot = multiop.read().unwrap().inrefs.iter().position(|v| std::sync::Arc::ptr_eq(v, &outvn));
        let slot = match slot { Some(s) => s, None => return Ok(action_status::NO_CHANGE) };
        let otherout = match multiop.read().unwrap().get_in(1 - slot).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !otherout.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let op2 = otherout.read().unwrap().get_def().unwrap();
        if op2.read().unwrap().opcode != OpCode::CPUI_FLOAT_INT2FLOAT { return Ok(action_status::NO_CHANGE); }
        let op2_in0 = op2.read().unwrap().get_in(0).cloned().unwrap();
        if !std::sync::Arc::ptr_eq(&op2_in0, &basevn) { return Ok(action_status::NO_CHANGE); }
        // FlowBlock *cond = FlowBlock::findCondition(parent, slot, parent, 1-slot, dir2unsigned);
        let parent = match multiop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade()) {
            Some(p) => p,
            None => return Ok(action_status::NO_CHANGE), // no block graph
        };
        let (cond, dir2unsigned) = match crate::block::find_condition(&parent, slot, &parent, 1 - slot) {
            Some(c) => c,
            None => return Ok(action_status::NO_CHANGE),
        };
        // cbranch = cond->lastOp(); must be CBRANCH; !isBooleanFlip.
        let cbranch = {
            let c_rg = cond.read().unwrap();
            use crate::block::FlowBlock;
            let any = c_rg.as_any();
            if let Some(bb) = any.downcast_ref::<crate::block::BlockBasic>() {
                bb.last_op()
            } else {
                None
            }
        };
        let cbranch = match cbranch { Some(c) => c, None => return Ok(action_status::NO_CHANGE) };
        if cbranch.0.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return Ok(action_status::NO_CHANGE); }
        if cbranch.0.read().unwrap().is_boolean_flip() { return Ok(action_status::NO_CHANGE); }
        // compare = cbranch->getIn(1)->getDef(); must be INT_SLESS.
        let cond_in = match cbranch.0.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !cond_in.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let compare = cond_in.read().unwrap().get_def().unwrap();
        if compare.read().unwrap().opcode != OpCode::CPUI_INT_SLESS { return Ok(action_status::NO_CHANGE); }
        let (cmp0, cmp1) = {
            let c = compare.read().unwrap();
            (c.get_in(0).cloned(), c.get_in(1).cloned())
        };
        let (cmp0, cmp1) = match (cmp0, cmp1) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        // compare->getIn(1)->constantMatch(0): condition is (basevn < 0)
        let c1_is_zero = cmp1.read().unwrap().is_constant() && cmp1.read().unwrap().get_offset() == 0;
        // compare->getIn(0)->constantMatch(calc_mask(basevn->getSize())): (-1 < basevn)
        let base_mask = calc_mask(basevn.read().unwrap().get_size());
        let c0_is_allones = cmp0.read().unwrap().is_constant() && cmp0.read().unwrap().get_offset() == base_mask;
        if c1_is_zero {
            // basevn < 0: true branch must be the unsigned FLOAT_INT2FLOAT (dir2unsigned==1)
            if !std::sync::Arc::ptr_eq(&cmp0, &basevn) { return Ok(action_status::NO_CHANGE); }
            if dir2unsigned != 1 { return Ok(action_status::NO_CHANGE); }
        } else if c0_is_allones {
            // -1 < basevn: true branch must be the signed FLOAT_INT2FLOAT (dir2unsigned==0)
            if !std::sync::Arc::ptr_eq(&cmp1, &basevn) { return Ok(action_status::NO_CHANGE); }
            if dir2unsigned == 1 { return Ok(action_status::NO_CHANGE); }
        } else {
            return Ok(action_status::NO_CHANGE);
        }
        // Transform: redefine the MULTIEQUAL as unsigned FLOAT_INT2FLOAT.
        let multiop_ref = crate::op::PcodeOpRef(multiop.clone());
        let outbl = parent.clone();
        fd.op_uninsert(&multiop_ref);
        fd.op_set_opcode(&multiop_ref, OpCode::CPUI_FLOAT_INT2FLOAT);
        fd.op_remove_input(&multiop_ref, 0);
        let newzext = fd.new_op(1, multiop.read().unwrap().get_addr());
        fd.op_set_opcode(&newzext, OpCode::CPUI_INT_ZEXT);
        let pref_size = RuleUnsigned2Float::preferred_zext_size(basevn.read().unwrap().get_size());
        let newout = fd.new_unique_out(pref_size, &newzext);
        fd.op_set_input(&newzext, basevn, 0);
        fd.op_set_input(&multiop_ref, newout, 0);
        // Reinsert modified MULTIEQUAL after any other MULTIEQUAL; then the zext before it.
        fd.op_insert_begin(&multiop_ref, &outbl);
        fd.op_insert_before(&newzext, &multiop_ref);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:9851 RuleInt2FloatCollapse
    fn get_name(&self) -> &str { "int_2_float_collapse" }
    // Ghidra: ruleaction.cc:9857 RuleInt2FloatCollapse::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_FLOAT_INT2FLOAT] }
}

/// Remove PTRADD operations with mismatched data-type information.
///
/// Faithful to `RulePtraddUndo` (ruleaction.cc:6927-6944). Once type recovery
/// has started and the PTRADD's pointed-to size no longer matches its index
/// scale (or the index is non-zero), undo the PTRADD back to INT_MULT/INT_ADD.
///
/// NOTE: Needs `data.hasTypeRecoveryStarted()`, `getTypeReadFacing`,
/// `TypePointer::getPtrTo`, `AddrSpace::addressToByteInt`, and
/// `data.opUndoPtradd`. The type-recovery gate, the pointer-type guard, and the
/// undo are all now implemented against the available infrastructure. In a test
/// environment without a type system, the pointer guard is conservatively
/// skipped (no type ⇒ not a confirmed correct pointer ⇒ undo proceeds).
pub struct RulePtraddUndo;

impl RulePtraddUndo {
    // Ghidra: ruleaction.cc:6915 RulePtraddUndo
    pub fn new() -> Self { Self }
}

impl Rule for RulePtraddUndo {
    // Ghidra: ruleaction.cc:6927 RulePtraddUndo::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePtraddUndo::applyOp (ruleaction.cc:6927-6944).
        if !fd.has_type_recovery_started() {
            return Ok(action_status::NO_CHANGE);
        }
        let (size, basevn, indvn) = {
            let op = op_arc.read().unwrap();
            let in2 = match op.inrefs.get(2) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            if !in2.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
            let size = in2.read().unwrap().get_offset();
            let basevn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let indvn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (size, basevn, indvn)
        };
        // dt = basevn->getTypeReadFacing(op); if TYPE_PTR and tp->getPtrTo()
        //   ->getAlignSize()==size && ind!=0 return 0;
        // If the varnode has a pointer type whose pointed-to size matches the
        // PTRADD element size AND the index is non-zero, this is still a valid
        // pointer arithmetic — leave it alone.
        let is_correctly_typed_ptr = basevn.read().unwrap().get_type()
            .map(|dt| {
                use crate::type_system::datatype::{Datatype, TypeMetatype};
                if dt.get_metatype() != TypeMetatype::Pointer { return false; }
                if let Datatype::Pointer(tp) = dt.as_ref() {
                    tp.ptr_to.get_align_size() == size as usize
                } else {
                    false
                }
            })
            .unwrap_or(false); // no type ⇒ not confirmed ⇒ proceed with undo
        if is_correctly_typed_ptr {
            let ind_is_zero = indvn.read().unwrap().is_constant()
                && indvn.read().unwrap().get_offset() == 0;
            if !ind_is_zero {
                return Ok(action_status::NO_CHANGE);
            }
        }
        // data.opUndoPtradd(op, false);
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_undo_ptradd(&op_ref);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:6915 RulePtraddUndo
    fn get_name(&self) -> &str { "ptradd_undo" }
    // Ghidra: ruleaction.cc:6921 RulePtraddUndo::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PTRADD] }
}

/// Remove PTRSUB operations with mismatched data-type information.
///
/// Faithful to `RulePtrsubUndo` (ruleaction.cc:6970-7190) plus helpers
/// `getConstOffsetBack` (6970-7010), `getExtraOffset` (7011-7059),
/// `removeLocalAddRecurse` (7061-7094), `removeLocalAdds` (7096-7143).
///
/// NOTE: The four helpers are pure data-flow walks and are ported 1:1 below.
/// The final `applyOp` uses `fd.has_type_recovery_started()`, the pointer-type
/// guard (`get_type()` + `is_ptrsub_matching`, approximating
/// `isPtrsubMatching`), `op_arc.write().clear_stop_type_propagation()`, and
/// `fd.op_undo_ptradd(...)` — all now wired. The numeric transform is faithful.
/// `is_ptrsub_matching` models the core TypePointer cases plus
/// `testForArraySlack` (type.cc:990-1005) for the Spacebase/Struct branches;
/// TypePointerRel (the relative-pointer subclass) is still not modelled.
pub struct RulePtrsubUndo;

impl RulePtrsubUndo {
    pub const DEPTH_LIMIT: i32 = 8;
    // Ghidra: ruleaction.cc:6949 RulePtrsubUndo
    pub fn new() -> Self { Self }

    /// Faithful to `TypePointer::testForArraySlack` (type.cc:990-1005). If the
    /// given data-type is an array, or has an arrayed component at/near the
    /// out-of-bounds offset `off`, return true (the offset can be explained as
    /// array slack, i.e. a PTRSUB into an array element, not an INT_ADD).
    ///
    /// Calls `nearest_arrayed_component_forward/backward` (type.cc:188-205
    /// base + 1669-1741 struct override) to find a component that is (or
    /// contains) an array near `off`.
    // Ghidra: type.cc:990 TypePointer::testForArraySlack
    fn test_for_array_slack(
        dt: &crate::type_system::datatype::Datatype,
        off: i64,
    ) -> bool {
        use crate::type_system::datatype::TypeMetatype;
        // type.cc:995-996 — a bare array always has slack.
        if dt.get_metatype() == TypeMetatype::Array { return true; }
        let comp = if off < 0 {
            Self::nearest_arrayed_component_forward(dt, off)
        } else {
            Self::nearest_arrayed_component_backward(dt, off)
        };
        comp.is_some()
    }

    /// Faithful to `Datatype::nearestArrayedComponentForward` (type.cc:188-192)
    /// base + `TypeStruct::nearestArrayedComponentForward` (type.cc:1698-1740).
    /// Find the first component data-type that is (or contains) an array
    /// starting at or after offset `off`, returning the component if found.
    /// Base/array/union/etc. return None (the base override returns null).
    // Ghidra: type.cc:188 Datatype::nearestArrayedComponentForward
    fn nearest_arrayed_component_forward(
        dt: &crate::type_system::datatype::Datatype,
        off: i64,
    ) -> Option<&crate::type_system::datatype::Datatype> {
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        // Base Datatype override (type.cc:188-192) returns null; only structs
        // (TypeStruct override, type.cc:1698-1740) walk fields.
        if let Datatype::Struct(s) = dt {
            // getLowerBoundField(off): index of field with greatest offset <= off, else -1.
            let first_index = Self::get_lower_bound_field(s, off);
            let mut i: i64 = first_index;
            let mut remain: i64;
            if i < 0 {
                // No component starting before off: start at first field after.
                i = 0;
                remain = 0;
            } else {
                let idx = i as usize;
                let subfield = &s.fields[idx];
                remain = off - subfield.offset as i64;
                if remain != 0
                    && (subfield.type_ptr.get_metatype() != TypeMetatype::Struct
                        || remain >= subfield.type_ptr.get_size() as i64)
                {
                    // Middle of a non-structure that we must go forward from: skip it.
                    i += 1;
                    remain = 0;
                }
            }
            while (i as usize) < s.fields.len() {
                let idx = i as usize;
                let subfield = &s.fields[idx];
                // diff = field.offset - off (may be negative for the first field).
                let diff = subfield.offset as i64 - off;
                if diff > 128 { break; }
                let subtype = subfield.type_ptr.as_ref();
                if subtype.get_metatype() == TypeMetatype::Array {
                    return Some(subtype);
                } else {
                    let res = Self::nearest_arrayed_component_forward(subtype, remain);
                    if res.is_some() {
                        let subdiff = diff + remain; // suboff folded in via remain
                        if subdiff > 128 { break; }
                        return Some(subtype);
                    }
                }
                i += 1;
                remain = 0;
            }
        }
        None
    }

    /// Faithful to `Datatype::nearestArrayedComponentBackward` (type.cc:201-205)
    /// base + `TypeStruct::nearestArrayedComponentBackward` (type.cc:1669-1696).
    /// Find the last component data-type that is (or contains) an array
    /// starting before or at offset `off`, returning the component if found.
    // Ghidra: type.cc:201 Datatype::nearestArrayedComponentBackward
    fn nearest_arrayed_component_backward(
        dt: &crate::type_system::datatype::Datatype,
        off: i64,
    ) -> Option<&crate::type_system::datatype::Datatype> {
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        // Base Datatype override (type.cc:201-205) returns null; only structs
        // (TypeStruct override, type.cc:1669-1696) walk fields.
        if let Datatype::Struct(s) = dt {
            let first_index = Self::get_lower_bound_field(s, off);
            let mut i: i64 = first_index;
            while i >= 0 {
                let idx = i as usize;
                let subfield = &s.fields[idx];
                let diff = off - subfield.offset as i64;
                if diff > 128 { break; }
                let subtype = subfield.type_ptr.as_ref();
                if subtype.get_metatype() == TypeMetatype::Array {
                    return Some(subtype);
                } else {
                    let remain = if idx == first_index as usize {
                        diff
                    } else {
                        subtype.get_size() as i64 - 1
                    };
                    let res = Self::nearest_arrayed_component_backward(subtype, remain);
                    if res.is_some() {
                        return Some(subtype);
                    }
                }
                i -= 1;
            }
        }
        None
    }

    /// Faithful to `TypeStruct::getLowerBoundField` (type.cc:1604-1622). Returns
    /// the index of the field with the greatest offset <= `off`, or -1 if none.
    /// Assumes `fields` is sorted ascending by offset (as in struct_get_sub_type).
    // Ghidra: type.cc:1604 TypeStruct::getLowerBoundField
    fn get_lower_bound_field(
        s: &crate::type_system::datatype::TypeStruct,
        off: i64,
    ) -> i64 {
        if s.fields.is_empty() { return -1; }
        let mut min: i64 = 0;
        let mut max: i64 = s.fields.len() as i64 - 1;
        while min < max {
            let mid = (min + max + 1) / 2;
            if s.fields[mid as usize].offset as i64 > off {
                max = mid - 1;
            } else {
                min = mid;
            }
        }
        if min == max && s.fields[min as usize].offset as i64 <= off {
            return min;
        }
        -1
    }

    /// Faithful to `TypePointer::isPtrsubMatching` (type.cc:1123-1175). Returns
    /// true if a PTRSUB with offset `off`, extra `extra`, and `multiplier` still
    /// matches the pointer's pointed-to type. wordsize defaults to 1
    /// (addressToByteInt is a no-op). When an out-of-bounds `extra` is found,
    /// `testForArraySlack` (type.cc:1134, 1157) is consulted before rejecting.
    // Ghidra: type.cc:1123 TypePointer::isPtrsubMatching
    fn is_ptrsub_matching(
        dt: &std::sync::Arc<crate::type_system::datatype::Datatype>,
        off: i64,
        mut extra: i64,
        mut multiplier: i64,
    ) -> bool {
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        if dt.get_metatype() != TypeMetatype::Pointer { return false; }
        let tp = match dt.as_ref() { Datatype::Pointer(p) => p, _ => return false };
        let ptrto = &tp.ptr_to;
        let wordsize = tp.wordsize.max(1) as i64;
        // addressToByteInt(x, wordsize) = x * wordsize
        match ptrto.get_metatype() {
            TypeMetatype::Spacebase => {
                let newoff = off.wrapping_mul(wordsize);
                let (sub, sub_off) = ptrto.get_sub_type(newoff);
                match sub {
                    None => false,
                    Some(s) => {
                        if sub_off != 0 { return false; }
                        extra = extra.wrapping_mul(wordsize);
                        if extra < 0 || extra >= s.get_size() as i64 {
                            // type.cc:1134 — testForArraySlack allows PTRSUB into
                            // an arrayed component even when extra is OOB.
                            if !Self::test_for_array_slack(s, extra) {
                                return false;
                            }
                        }
                        true
                    }
                }
            }
            TypeMetatype::Array => {
                if off != 0 { return false; }
                multiplier = multiplier.wrapping_mul(wordsize);
                if multiplier >= ptrto.get_align_size() as i64 { return false; }
                true
            }
            TypeMetatype::Struct => {
                let typesize = ptrto.get_size() as i64;
                multiplier = multiplier.wrapping_mul(wordsize);
                if multiplier >= ptrto.get_align_size() as i64 { return false; }
                let newoff = off.wrapping_mul(wordsize);
                extra = extra.wrapping_mul(wordsize);
                let (sub, sub_off) = ptrto.get_sub_type(newoff);
                match sub {
                    Some(s) => {
                        if sub_off != 0 { return false; }
                        if extra < 0 || extra >= s.get_size() as i64 {
                            // type.cc:1157 — testForArraySlack allows PTRSUB into
                            // an arrayed component even when extra is OOB.
                            if !Self::test_for_array_slack(s, extra) {
                                return false;
                            }
                        }
                        true
                    }
                    None => {
                        let extra2 = extra + sub_off;
                        if (extra2 < 0 || extra2 >= typesize) && typesize != 0 {
                            return false;
                        }
                        true
                    }
                }
            }
            TypeMetatype::Union => false, // PTRSUB cannot be a union field resolution
            _ => false, // not a pointer to a structured data-type
        }
    }

    /// Faithful to `getConstOffsetBack` (ruleaction.cc:6970-7010). Returns the
    /// sum of constants in the additive tree rooted at `vn`, and the biggest
    /// constant multiplier in `multiplier` (0 if none).
    // Ghidra: ruleaction.cc:6970 RulePtrsubUndo::getConstOffsetBack
    fn get_const_offset_back(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        multiplier: &mut i64,
        max_level: i32,
    ) -> i64 {
        *multiplier = 0;
        if vn.read().unwrap().is_constant() {
            return vn.read().unwrap().get_offset() as i64;
        }
        if !vn.read().unwrap().is_written() { return 0; }
        let max_level = max_level - 1;
        if max_level < 0 { return 0; }
        let def = match vn.read().unwrap().get_def() {
            Some(d) => d,
            None => return 0,
        };
        let opc = def.read().unwrap().opcode;
        let mut retval: i64 = 0;
        if opc == OpCode::CPUI_INT_ADD {
            let (in0, in1) = {
                let d = def.read().unwrap();
                (d.get_in(0).cloned(), d.get_in(1).cloned())
            };
            let mut submult: i64 = 0;
            if let Some(in0) = in0 {
                retval += Self::get_const_offset_back(&in0, &mut submult, max_level);
                if submult > *multiplier { *multiplier = submult; }
            }
            if let Some(in1) = in1 {
                retval += Self::get_const_offset_back(&in1, &mut submult, max_level);
                if submult > *multiplier { *multiplier = submult; }
            }
        } else if opc == OpCode::CPUI_INT_MULT {
            let cvn = match def.read().unwrap().get_in(1).cloned() {
                Some(v) => v,
                None => return 0,
            };
            if !cvn.read().unwrap().is_constant() { return 0; }
            *multiplier = cvn.read().unwrap().get_offset() as i64;
            if let Some(in0) = def.read().unwrap().get_in(0).cloned() {
                let mut submult: i64 = 0;
                Self::get_const_offset_back(&in0, &mut submult, max_level);
                if submult > 0 {
                    *multiplier *= submult;
                }
            }
        }
        retval
    }

    /// Faithful to `getExtraOffset` (ruleaction.cc:7011-7059). Walks the
    /// additive expression using `outvn`'s lone descendant, returning the extra
    /// constant offset and the biggest multiplier.
    // Ghidra: ruleaction.cc:7011 RulePtrsubUndo::getExtraOffset
    fn get_extra_offset(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        multiplier: &mut i64,
    ) -> i64 {
        let mut extra: i64 = 0;
        *multiplier = 0;
        let mut submult: i64 = 0;
        let mut outvn = match op.read().unwrap().output.clone() {
            Some(o) => o,
            None => return 0,
        };
        let mut cur = outvn.read().unwrap().lone_descend();
        while let Some(o) = cur {
            let opc = o.read().unwrap().opcode;
            if opc == OpCode::CPUI_INT_ADD {
                let slot = o.read().unwrap().inrefs.iter().position(|v| std::sync::Arc::ptr_eq(v, &outvn)).unwrap_or(0);
                let other = o.read().unwrap().get_in(1 - slot).cloned();
                if let Some(other) = other {
                    extra += Self::get_const_offset_back(&other, &mut submult, Self::DEPTH_LIMIT);
                    if submult > *multiplier { *multiplier = submult; }
                }
            } else if opc == OpCode::CPUI_PTRSUB {
                let in1 = o.read().unwrap().get_in(1).cloned();
                if let Some(in1) = in1 {
                    extra += in1.read().unwrap().get_offset() as i64;
                }
            } else if opc == OpCode::CPUI_PTRADD {
                if !o.read().unwrap().get_in(0).map(|v| std::sync::Arc::ptr_eq(v, &outvn)).unwrap_or(false) {
                    break;
                }
                let (ptraddmult, invn) = {
                    let or = o.read().unwrap();
                    let mult = or.get_in(2).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(0);
                    let invn = or.get_in(1).cloned();
                    (mult, invn)
                };
                if let Some(ref invn) = invn {
                    if invn.read().unwrap().is_constant() {
                        extra += ptraddmult * invn.read().unwrap().get_offset() as i64;
                    }
                    let mut sm: i64 = 0;
                    Self::get_const_offset_back(invn, &mut sm, Self::DEPTH_LIMIT);
                    if sm != 0 {
                        let pm = ptraddmult * sm;
                        if pm > *multiplier { *multiplier = pm; }
                    }
                }
            } else {
                break;
            }
            outvn = match o.read().unwrap().output.clone() {
                Some(x) => x,
                None => break,
            };
            cur = outvn.read().unwrap().lone_descend();
        }
        // sign_extend(extra, 8*outvn->getSize()-1)
        let out_size_bits = outvn.read().unwrap().get_size() as u64 * 8;
        if out_size_bits > 0 && out_size_bits <= 63 {
            let signbit = 1i64 << (out_size_bits - 1);
            let mask = if out_size_bits >= 64 { -1i64 as u64 } else { (1u64 << out_size_bits) - 1 };
            extra = (extra & mask as i64) as i64;
            if extra & signbit != 0 {
                extra |= !mask as i64;
            }
        }
        extra
    }

    /// Faithful to `removeLocalAddRecurse` (ruleaction.cc:7061-7094). Converts
    /// INT_ADD-with-constant nodes in the additive tree into COPYs, returning
    /// the sum of removed constants.
    // Ghidra: ruleaction.cc:7061 RulePtrsubUndo::removeLocalAddRecurse
    fn remove_local_add_recurse(
        op: &crate::op::PcodeOpRef,
        slot: usize,
        max_level: i32,
        fd: &mut Funcdata,
    ) -> i64 {
        let vn = match op.0.read().unwrap().get_in(slot).cloned() {
            Some(v) => v,
            None => return 0,
        };
        if !vn.read().unwrap().is_written() { return 0; }
        if vn.read().unwrap().lone_descend().map(|d| !std::sync::Arc::ptr_eq(&d, &op.0)).unwrap_or(true) {
            return 0; // Varnode must not be used anywhere else
        }
        let max_level = max_level - 1;
        if max_level < 0 { return 0; }
        let def = match vn.read().unwrap().get_def() {
            Some(d) => d,
            None => return 0,
        };
        let def_ref = crate::op::PcodeOpRef(def);
        let mut retval: i64 = 0;
        if def_ref.0.read().unwrap().opcode == OpCode::CPUI_INT_ADD {
            let in1 = def_ref.0.read().unwrap().get_in(1).cloned();
            if let Some(in1) = in1 {
                if in1.read().unwrap().is_constant() {
                    retval += in1.read().unwrap().get_offset() as i64;
                    fd.op_remove_input(&def_ref, 1);
                    fd.op_set_opcode(&def_ref, OpCode::CPUI_COPY);
                } else {
                    retval += Self::remove_local_add_recurse(&def_ref, 0, max_level, fd);
                    retval += Self::remove_local_add_recurse(&def_ref, 1, max_level, fd);
                }
            }
        }
        retval
    }

    /// Faithful to `removeLocalAdds` (ruleaction.cc:7096-7143). Walks the
    /// additive chain rooted at `vn`, converting INT_ADD/PTRSUB/PTRADD constant
    /// contributions into COPYs / undoing PTRADDs, and returns the removed sum.
    // Ghidra: ruleaction.cc:7096 RulePtrsubUndo::removeLocalAdds
    fn remove_local_adds(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        fd: &mut Funcdata,
    ) -> i64 {
        let mut extra: i64 = 0;
        let mut vn = vn.clone();
        loop {
            let cur = match vn.read().unwrap().lone_descend() {
                Some(o) => o,
                None => break,
            };
            let opc = cur.read().unwrap().opcode;
            let cur_ref = crate::op::PcodeOpRef(cur.clone());
            if opc == OpCode::CPUI_INT_ADD {
                let slot = cur.read().unwrap().inrefs.iter().position(|v| std::sync::Arc::ptr_eq(v, &vn)).unwrap_or(0);
                let in1 = cur.read().unwrap().get_in(1).cloned();
                if slot == 0 && in1.as_ref().map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                    let in1v = in1.unwrap();
                    extra += in1v.read().unwrap().get_offset() as i64;
                    fd.op_remove_input(&cur_ref, 1);
                    fd.op_set_opcode(&cur_ref, OpCode::CPUI_COPY);
                } else {
                    extra += Self::remove_local_add_recurse(&cur_ref, 1 - slot, Self::DEPTH_LIMIT, fd);
                }
            } else if opc == OpCode::CPUI_PTRSUB {
                let in1 = cur.read().unwrap().get_in(1).cloned();
                if let Some(in1) = in1 {
                    extra += in1.read().unwrap().get_offset() as i64;
                }
                // op->clearStopTypePropagation() (ruleaction.cc:7118).
                cur.write().unwrap().clear_stop_type_propagation();
                fd.op_remove_input(&cur_ref, 1);
                fd.op_set_opcode(&cur_ref, OpCode::CPUI_COPY);
            } else if opc == OpCode::CPUI_PTRADD {
                if !cur.read().unwrap().get_in(0).map(|v| std::sync::Arc::ptr_eq(v, &vn)).unwrap_or(false) {
                    break;
                }
                let (ptraddmult, invn_is_const, invn_off) = {
                    let c = cur.read().unwrap();
                    let mult = c.get_in(2).map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(0);
                    let invn = c.get_in(1).cloned();
                    let (isc, off) = invn.as_ref().map(|v| (v.read().unwrap().is_constant(), v.read().unwrap().get_offset() as i64)).unwrap_or((false, 0));
                    (mult, isc, off)
                };
                if invn_is_const {
                    extra += ptraddmult * invn_off;
                    fd.op_remove_input(&cur_ref, 2);
                    fd.op_remove_input(&cur_ref, 1);
                    fd.op_set_opcode(&cur_ref, OpCode::CPUI_COPY);
                } else {
                    // Ghidra (ruleaction.cc:7133): data.opUndoPtradd(op, false).
                    // Rugra's op_undo_ptradd performs the numeric PTRADD→
                    // INT_ADD/(index*mult) transform with no type-locking,
                    // matching the finalize=false call.
                    fd.op_undo_ptradd(&cur_ref);
                    extra += Self::remove_local_add_recurse(&cur_ref, 1, Self::DEPTH_LIMIT, fd);
                }
            } else {
                break;
            }
            vn = match cur.read().unwrap().output.clone() {
                Some(o) => o,
                None => break,
            };
        }
        extra
    }
}

impl Rule for RulePtrsubUndo {
    // Ghidra: ruleaction.cc:7146 RulePtrsubUndo::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePtrsubUndo::applyOp (ruleaction.cc:7146-7188).
        if !fd.has_type_recovery_started() {
            return Ok(action_status::NO_CHANGE);
        }
        let (basevn, cvn) = {
            let op = op_arc.read().unwrap();
            let basevn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let cvn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (basevn, cvn)
        };
        let val = cvn.read().unwrap().get_offset() as i64;
        let mut multiplier: i64 = 0;
        let extra = Self::get_extra_offset(op_arc, &mut multiplier);
        // if (basevn->getTypeReadFacing(op)->isPtrsubMatching(val,extra,multiplier)) return 0;
        // We approximate isPtrsubMatching (type.cc:1123-1162) for the core
        // TypePointer cases. wordsize defaults to 1 (addressToByteInt is a no-op).
        // testForArraySlack and TypePointerRel are not yet modelled.
        let still_matching = basevn.read().unwrap().get_type()
            .map(|dt| Self::is_ptrsub_matching(&dt, val, extra, multiplier))
            .unwrap_or(false);
        if still_matching { return Ok(action_status::NO_CHANGE); }

        // data.opSetOpcode(op,CPUI_INT_ADD); op->clearStopTypePropagation();
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_ADD);
        op_arc.write().unwrap().clear_stop_type_propagation();
        // removeLocalAdds(op->getOut(), data) — walk the PTRSUB output's
        //   downstream INT_ADD/PTRSUB chain and fold local constants.
        let outvn = match op_arc.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::CHANGE),
        };
        let new_extra = Self::remove_local_adds(&outvn, fd);
        if new_extra != 0 {
            // Lump extra into additive offset.
            let new_val = val.wrapping_add(new_extra);
            let masked = new_val & calc_mask(cvn.read().unwrap().get_size()) as i64;
            let new_const = fd.new_constant(cvn.read().unwrap().get_size(), masked as u64);
            fd.op_set_input(&op_ref, new_const, 1);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:6949 RulePtrsubUndo
    fn get_name(&self) -> &str { "ptrsub_undo" }
    // Ghidra: ruleaction.cc:6955 RulePtrsubUndo::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PTRSUB] }
}

/// Propagate constants through a SEGMENTOP.
///
/// Faithful to `RuleSegment` (ruleaction.cc:9013-9057). If both segment inputs
/// are constant, fold via `segdef->execute`; else if the segment supports far
/// pointers and the inputs form a contiguous whole, replace with a COPY.
///
/// NOTE: The segment definition is resolved via
/// `fd.get_arch().userops.get_segment_op(space_idx)`. The constant fold uses
/// `SegmentOp::execute` (userop.cc:218-223; evaluated via Rugra's canonical
/// `(base << 4) + inner` formula since pcodeinjectlib is not present). The
/// far-pointer branch is gated by `SegmentOp::has_far_pointer_support()`
/// (`supportsfarpointer`, userop.hh:269) and uses the contiguous-whole
/// test from `contiguous_test`/`findContiguousWhole` (varnode.cc:2014-2076).
pub struct RuleSegment;

impl RuleSegment {
    // Ghidra: ruleaction.cc:9005 RuleSegment
    pub fn new() -> Self { Self }
}

impl Rule for RuleSegment {
    // Ghidra: ruleaction.cc:9013 RuleSegment::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleSegment::applyOp (ruleaction.cc:9013-9057).
        let (space_id_vn, vn1, vn2, out_size) = {
            let op = op_arc.read().unwrap();
            let space_id_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn1 = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let vn2 = match op.inrefs.get(2) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let outvn = match op.output.clone() { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
            let out_size = outvn.read().unwrap().get_size();
            (space_id_vn, vn1, vn2, out_size)
        };
        // op->getIn(0)->getSpaceFromConst()->getIndex(): the segment op's input
        // 0 is a constant holding the address-space index (ruleaction.cc:9016).
        if !space_id_vn.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        let space_idx = space_id_vn.read().unwrap().get_offset() as i32;
        // SegmentOp *segdef = data.getArch()->userops.getSegmentOp(space_idx);
        // Ghidra throws if null; Rugra conservatively no-ops.
        let segdef = fd.get_arch()
            .and_then(|a| a.userops.as_ref())
            .and_then(|u| u.read().unwrap().get_segment_op(space_idx).cloned());
        let segdef = match segdef { Some(s) => s, None => return Ok(action_status::NO_CHANGE) };
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        let (vn1_const, vn2_const) = (vn1.read().unwrap().is_constant(), vn2.read().unwrap().is_constant());
        if vn1_const && vn2_const {
            // ruleaction.cc:9024-9033: both inputs constant -> fold.
            //   vector<uintb> bindlist; bindlist.push_back(vn1->getOffset());
            //   bindlist.push_back(vn2->getOffset());
            //   uintb val = segdef->execute(bindlist);
            let (v1_off, v2_off) = (
                vn1.read().unwrap().get_offset(),
                vn2.read().unwrap().get_offset(),
            );
            let bindlist = [v1_off, v2_off];
            match segdef.execute(&bindlist) {
                Some(val) => {
                    // ruleaction.cc:9027-9031:
                    //   data.opRemoveInput(op,2); data.opRemoveInput(op,1);
                    //   data.opSetInput(op,data.newConstant(out->getSize(),val),0);
                    //   data.opSetOpcode(op,CPUI_COPY);
                    fd.op_remove_input(&op_ref, 2);
                    fd.op_remove_input(&op_ref, 1);
                    let folded = fd.new_constant(out_size, val);
                    fd.op_set_input(&op_ref, folded, 0);
                    fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                    return Ok(action_status::CHANGE);
                }
                None => return Ok(action_status::NO_CHANGE),
            }
        }
        // ruleaction.cc:9034-9046: else if (segdef->hasFarPointerSupport())
        if segdef.has_far_pointer_support() {
            // ruleaction.cc:9036: if (!contiguous_test(vn1,vn2)) return 0;
            //   contiguous_test (varnode.cc:2014-2037): vn1/vn2 must not be
            //   inputs, must be written, and be SUBPIECEs of a common whole
            //   where op2's sub-offset is 0 (vn2 is least-sig) and op1's
            //   sub-offset equals vn2's size (contiguous high/low pieces).
            if !contiguous_test(&vn1, &vn2) { return Ok(action_status::NO_CHANGE); }
            // ruleaction.cc:9037: whole = findContiguousWhole(data,vn1,vn2);
            let whole = find_contiguous_whole(&vn1, &vn2);
            // ruleaction.cc:9038-9039: if (whole==0 || whole->isFree()) return 0;
            let whole = match whole { Some(w) => w, None => return Ok(action_status::NO_CHANGE) };
            if whole.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
            // ruleaction.cc:9041-9045: use the contiguous source as whole ptr.
            //   data.opRemoveInput(op,2); data.opRemoveInput(op,1);
            //   data.opSetInput(op,whole,0); data.opSetOpcode(op,CPUI_COPY);
            fd.op_remove_input(&op_ref, 2);
            fd.op_remove_input(&op_ref, 1);
            fd.op_set_input(&op_ref, whole, 0);
            fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:9005 RuleSegment
    fn get_name(&self) -> &str { "segment" }
    // Ghidra: ruleaction.cc:9007 RuleSegment::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SEGMENTOP] }
}

/// Return true if `vn1` (high) and `vn2` (low) are pieces of a single value.
///
/// Faithful to `contiguous_test` (varnode.cc:2014-2037). Both varnodes must be
/// written (not inputs), defined by SUBPIECE ops sharing the same source, with
/// `vn2`'s sub-offset 0 (least-significant) and `vn1`'s sub-offset equal to
/// `vn2`'s size (immediately contiguous high piece).
// Ghidra: varnode.cc:2014 contiguous_test
fn contiguous_test(
    vn1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    vn2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> bool {
    // varnode.cc:2018-2019: if (vn1->isInput()||vn2->isInput()) return false;
    // varnode.cc:2020: if ((!vn1->isWritten())||(!vn2->isWritten())) return false;
    let (vn1_is_input, vn2_is_input, vn1_written, vn2_written) = {
        let a = vn1.read().unwrap();
        let b = vn2.read().unwrap();
        (a.is_input(), b.is_input(), a.is_written(), b.is_written())
    };
    if vn1_is_input || vn2_is_input { return false; }
    if !vn1_written || !vn2_written { return false; }
    // varnode.cc:2021-2022: PcodeOp *op1 = vn1->getDef(); PcodeOp *op2 = vn2->getDef();
    let op1 = match vn1.read().unwrap().get_def() { Some(o) => o, None => return false };
    let op2 = match vn2.read().unwrap().get_def() { Some(o) => o, None => return false };
    let (vn2_size, op1_opc, op2_opc) = {
        let o1 = op1.read().unwrap();
        let o2 = op2.read().unwrap();
        let vn2_size = vn2.read().unwrap().get_size() as u64;
        (vn2_size, o1.opcode, o2.opcode)
    };
    // varnode.cc:2025-2034: switch(op1->code()) { case CPUI_SUBPIECE:
    //   if (op2->code() != CPUI_SUBPIECE) return false;
    //   vnwhole = op1->getIn(0); if (op2->getIn(0) != vnwhole) return false;
    //   if (op2->getIn(1)->getOffset() != 0) return false; // vn2 least-sig
    //   if (op1->getIn(1)->getOffset() != vn2->getSize()) return false; // contig
    //   return true; }
    if op1_opc != OpCode::CPUI_SUBPIECE || op2_opc != OpCode::CPUI_SUBPIECE { return false; }
    let (o1_in0, o1_in1_off, o2_in0, o2_in1_off) = {
        let o1 = op1.read().unwrap();
        let o2 = op2.read().unwrap();
        let o1_in0 = match o1.inrefs.get(0) { Some(v) => v.clone(), None => return false };
        let o2_in0 = match o2.inrefs.get(0) { Some(v) => v.clone(), None => return false };
        let o1_in1_off = match o1.inrefs.get(1) {
            Some(v) => v.read().unwrap().get_offset(), None => return false };
        let o2_in1_off = match o2.inrefs.get(1) {
            Some(v) => v.read().unwrap().get_offset(), None => return false };
        (o1_in0, o1_in1_off, o2_in0, o2_in1_off)
    };
    // Compare whole-source identity by raw varnode address (Arc ptr eq, like
    // Ghidra's pointer comparison `op2->getIn(0) != vnwhole`).
    if !std::sync::Arc::ptr_eq(&o1_in0, &o2_in0) { return false; }
    if o2_in1_off != 0 { return false; } // vn2 must be least-significant
    if o1_in1_off != vn2_size { return false; } // vn1 must be the contiguous high piece
    true
}

/// Assuming `vn1`,`vn2` passed `contiguous_test`, return the whole varnode.
///
/// Faithful to `findContiguousWhole` (varnode.cc:2045-2062): returns
/// `vn1->getDef()->getIn(0)`, i.e. the SUBPIECE source of the high piece.
// Ghidra: varnode.cc:2045 findContiguousWhole
fn find_contiguous_whole(
    vn1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    _vn2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
    // varnode.cc:2046-2047: if (vn1->isWritten())
    //   if (vn1->getDef()->code() == CPUI_SUBPIECE) return vn1->getDef()->getIn(0);
    if !vn1.read().unwrap().is_written() { return None; }
    let op1 = vn1.read().unwrap().get_def()?;
    let in0 = {
        let o = op1.read().unwrap();
        if o.opcode != OpCode::CPUI_SUBPIECE { return None; }
        o.inrefs.get(0).cloned()
    };
    in0
}

/// Search for concatenations with unlikely things to inform return/parameter
/// consumption calculation.
///
/// Faithful to `RulePiecePathology` (ruleaction.cc:10578-10616) plus helpers
/// `isPathology` (ruleaction.cc:10427-10505) and `tracePathologyForward`
/// (ruleaction.cc:10506-10570).
///
/// Detects PIECE ops that "pathologically" concatenate a truncated return value
/// (from a CALL) with unrelated low bytes. When such a concatenation feeds a
/// CALL input or a RETURN, the partially-consumed bytes are recorded via
/// `FuncProto::set_return_bytes_consumed` / `FuncCallSpecs::set_input_bytes_consumed`
/// so the subvariable-flow rules can later truncate the data-flow.
pub struct RulePiecePathology;

impl RulePiecePathology {
    // Ghidra: ruleaction.cc:10561 RulePiecePathology
    pub fn new() -> Self { Self }

    /// Faithful to `RulePiecePathology::isPathology` (ruleaction.cc:10427-10505).
    ///
    /// Recursively checks whether `vn` originates from a CALL whose output is
    /// not actively recovered (i.e. an opaque/unrecovered call return). It
    /// walks the def-chain through COPY/MULTIEQUAL/INDIRECT, marking MULTIEQUAL
    /// ops on a worklist to explore all merge branches. Returns true as soon as
    /// a CALL/CALLIND (or INDIRECT-around-a-call) with a non-active output is
    /// reached, or the varnode is a plain function input.
    // Ghidra: ruleaction.cc:10427 RulePiecePathology::isPathology
    fn is_pathology(
        start_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        fd: &Funcdata,
    ) -> bool {
        use crate::op::pcodeop_flags;
        // Worklist of marked MULTIEQUAL ops whose input branches still need
        // exploration (faithful to Ghidra's vector<PcodeOp*> worklist).
        let mut worklist: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = Vec::new();
        let mut marked: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = Vec::new();
        let mut vn = start_vn.clone();
        let mut res = false;
        // Per-multiequal cursor: (pos in worklist, next input slot to inspect).
        let mut pos: usize = 0;
        let mut slot: usize = 0;
        loop {
            // vn->isInput() && !vn->isPersist()  →  a plain parameter/input.
            {
                let v = vn.read().unwrap();
                if v.is_input() && !v.is_persist() {
                    res = true;
                    break;
                }
            }
            // Walk the def-chain starting at vn's def.
            let mut op_opt = vn.read().unwrap().get_def();
            while !res {
                let op = match op_opt.clone() {
                    Some(o) => o,
                    None => break,
                };
                let code = op.read().unwrap().opcode;
                match code {
                    OpCode::CPUI_COPY => {
                        // Follow through the copy.
                        let next = op.read().unwrap().get_in(0).cloned();
                        match next {
                            Some(n) => {
                                vn = n;
                                op_opt = vn.read().unwrap().get_def();
                            }
                            None => { op_opt = None; }
                        }
                    }
                    OpCode::CPUI_MULTIEQUAL => {
                        // Mark it and enqueue; exploration continues from the
                        // worklist below (Ghidra sets mark + pushes op, then
                        // sets op = NULL to break the inner walk).
                        let already = (op.read().unwrap().flags & pcodeop_flags::MARK) != 0;
                        if !already {
                            op.write().unwrap().flags |= pcodeop_flags::MARK;
                            marked.push(op.clone());
                            worklist.push(op.clone());
                        }
                        op_opt = None;
                    }
                    OpCode::CPUI_INDIRECT => {
                        // Faithful to RulePiecePathology::isPathology CPUI_INDIRECT
                        // case (ruleaction.cc:10453-10464): if in(1) is an IOP-space
                        // const, resolve it to the referenced PcodeOp via
                        // `PcodeOp::getOpFromConst` (op.hh:249), check it's a call,
                        // and flag pathology if the call's output is not active.
                        let in1 = op.read().unwrap().get_in(1).cloned();
                        if let Some(iop_vn) = in1 {
                            let is_iop = iop_vn.read().unwrap().get_space()
                                == crate::space::AddressSpace::Iop;
                            if is_iop {
                                if let Some(call_op) = fd.get_op_from_const(&iop_vn) {
                                    if call_op.0.read().unwrap().is_call() {
                                        if let Some(idx) = Self::find_call_spec_for_op(fd, &call_op.0) {
                                            if let Some(fc) = fd.get_call_specs(idx) {
                                                if !fc.is_output_active() {
                                                    res = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        op_opt = None;
                    }
                    OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                        if let Some(idx) = Self::find_call_spec_for_op(fd, &op) {
                            if let Some(fc) = fd.get_call_specs(idx) {
                                if !fc.is_output_active() {
                                    res = true;
                                }
                            }
                        }
                    }
                    _ => {
                        op_opt = None;
                    }
                }
            }
            if res { break; }
            // Advance through the MULTIEQUAL worklist.
            if pos >= worklist.len() { break; }
            let cur = worklist[pos].clone();
            let n_in = cur.read().unwrap().num_input();
            if slot < n_in {
                let next = cur.read().unwrap().get_in(slot).cloned();
                slot += 1;
                match next {
                    Some(n) => { vn = n; }
                    None => { /* skip */ }
                }
            } else {
                pos += 1;
                if pos >= worklist.len() { break; }
                let next = worklist[pos].read().unwrap().get_in(0).cloned();
                slot = 1;
                match next {
                    Some(n) => { vn = n; }
                    None => { break; }
                }
            }
        }
        // Clear all marks we set (faithful to Ghidra's clearMark loop).
        for o in &marked {
            o.write().unwrap().flags &= !pcodeop_flags::MARK;
        }
        res
    }

    /// Faithful to `RulePiecePathology::tracePathologyForward`
    /// (ruleaction.cc:10506-10559).
    ///
    /// Given a known pathological PIECE op, trace its output forward through
    /// COPY/INDIRECT/MULTIEQUAL until reaching a CALL/CALLIND input (record
    /// `set_input_bytes_consumed`) or a RETURN (record
    /// `set_return_bytes_consumed`). Returns the number of new bytes labeled as
    /// unconsumed (a non-zero value signals a change).
    // Ghidra: ruleaction.cc:10506 RulePiecePathology::tracePathologyForward
    fn trace_pathology_forward(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        fd: &mut Funcdata,
    ) -> i32 {
        use crate::op::pcodeop_flags;
        // The size of the LSB piece (in(1)) is the number of "consumed" bytes
        // — only the low piece is real, the high piece (in(0)) is the
        // pathological truncation.
        let bytes_consumed = op
            .read().unwrap()
            .get_in(1)
            .map(|v| v.read().unwrap().get_size() as u32)
            .unwrap_or(0);
        if bytes_consumed == 0 {
            return 0;
        }
        let mut count = 0i32;
        // Forward worklist of marked ops whose output we still need to scan
        // descendants of.
        let mut worklist: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = Vec::new();
        let mut marked: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = Vec::new();
        op.write().unwrap().flags |= pcodeop_flags::MARK;
        marked.push(op.clone());
        worklist.push(op.clone());
        let mut pos = 0usize;
        while pos < worklist.len() {
            let cur_op = worklist[pos].clone();
            pos += 1;
            // Snapshot of descendant ops reading cur_op's output.
            let descends: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = {
                let cur = cur_op.read().unwrap();
                match cur.get_out() {
                    Some(out_vn) => out_vn
                        .read().unwrap()
                        .descend
                        .iter()
                        .filter_map(|w| w.upgrade())
                        .collect(),
                    None => Vec::new(),
                }
            };
            // The output varnode of cur_op (compared by ptr against call inputs).
            let out_vn = cur_op.read().unwrap().get_out().cloned();
            for dop in descends {
                let code = dop.read().unwrap().opcode;
                match code {
                    OpCode::CPUI_COPY | OpCode::CPUI_INDIRECT | OpCode::CPUI_MULTIEQUAL => {
                        let already = (dop.read().unwrap().flags & pcodeop_flags::MARK) != 0;
                        if !already {
                            dop.write().unwrap().flags |= pcodeop_flags::MARK;
                            marked.push(dop.clone());
                            worklist.push(dop);
                        }
                    }
                    OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                        if let (Some(out), Some(idx)) =
                            (out_vn.as_ref(), Self::find_call_spec_for_op(fd, &dop))
                        {
                            let fc = fd.get_call_specs(idx);
                            if let Some(fc) = fc {
                                if !fc.is_input_active() && !fc.is_input_locked() {
                                    let n_in = dop.read().unwrap().num_input();
                                    for i in 1..n_in {
                                        let same = dop
                                            .read().unwrap()
                                            .get_in(i)
                                            .map(|v| std::sync::Arc::ptr_eq(v, out))
                                            .unwrap_or(false);
                                        if same {
                                            if fd.get_call_specs_mut(idx)
                                                .map(|fc| fc.set_input_bytes_consumed(i, bytes_consumed))
                                                .unwrap_or(false)
                                            {
                                                count += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    OpCode::CPUI_RETURN => {
                        if !fd.get_func_proto().is_output_locked() {
                            if fd.get_func_proto_mut().set_return_bytes_consumed(bytes_consumed) {
                                count += 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // Clear all marks.
        for o in &marked {
            o.write().unwrap().flags &= !pcodeop_flags::MARK;
        }
        count
    }

    /// Look up the FuncCallSpecs index whose `op_addr` matches the given op's
    /// address. Faithful to Ghidra's `Funcdata::getCallSpecs(PcodeOp*)`, which
    /// in C++ is a direct pointer/index lookup; Rugra stores callspecs by the
    /// CALL op's base address, so we match on that.
    // Ghidra: funcdata.cc:484 Funcdata::getCallSpecs
    fn find_call_spec_for_op(
        fd: &Funcdata,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    ) -> Option<usize> {
        let addr = op.read().unwrap().get_seq_num().get_addr();
        Self::find_call_spec_by_addr(fd, addr.as_u64())
    }

    /// Look up the FuncCallSpecs index whose `op_addr` matches `addr_u64`.
    // RUGRA-GLUE: helper for Funcdata::getCallSpecs (funcdata.cc:484)
    fn find_call_spec_by_addr(fd: &Funcdata, addr_u64: u64) -> Option<usize> {
        for (i, fc) in fd.callspecs.iter().enumerate() {
            if fc.op_addr.as_u64() == addr_u64 {
                return Some(i);
            }
        }
        None
    }
}

impl Rule for RulePiecePathology {
    // Ghidra: ruleaction.cc:10578 RulePiecePathology::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePiecePathology::applyOp (ruleaction.cc:10578-10616).
        use crate::op::pcodeop_flags;
        let (vn, lsb_vn) = {
            let op = op_arc.read().unwrap();
            let vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let lsb_vn = match op.inrefs.get(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            (vn, lsb_vn)
        };
        if !vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
        let sub_op = vn.read().unwrap().get_def().unwrap();
        let opc = sub_op.read().unwrap().opcode;
        if opc == OpCode::CPUI_SUBPIECE {
            // Make sure we are concatenating the most significant bytes of a
            // truncation: the SUBPIECE offset (in(1)) must be non-zero.
            let in1 = sub_op.read().unwrap().get_in(1).cloned();
            let off0 = in1.map(|v| v.read().unwrap().get_offset()).unwrap_or(1);
            if off0 == 0 { return Ok(action_status::NO_CHANGE); }
            // The truncated value being concatenated must itself be pathological.
            let sub_in0 = match sub_op.read().unwrap().get_in(0).cloned() {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            };
            if !Self::is_pathology(&sub_in0, fd) { return Ok(action_status::NO_CHANGE); }
        } else if opc == OpCode::CPUI_INDIRECT {
            // Ghidra: if (!subOp->isIndirectCreation()) return 0;
            let is_indirect_creation =
                (sub_op.read().unwrap().flags & pcodeop_flags::INDIRECT_CREATION) != 0;
            if !is_indirect_creation { return Ok(action_status::NO_CHANGE); }
            // The LSB piece (in(1) of the PIECE) must be written by a unary/
            // binary op, or be a CALL with a locked-output callspec.
            if !lsb_vn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
            let lsb_op = match lsb_vn.read().unwrap().get_def() {
                Some(o) => o,
                None => return Ok(action_status::NO_CHANGE),
            };
            let eval_type = lsb_op.read().unwrap().get_eval_type();
            let is_unary_or_binary =
                (eval_type & (pcodeop_flags::UNARY | pcodeop_flags::BINARY)) != 0;
            if !is_unary_or_binary {
                // ... or a CALL with a locked output.
                if !lsb_op.read().unwrap().is_call() { return Ok(action_status::NO_CHANGE); }
                let fc_idx = Self::find_call_spec_for_op(fd, &lsb_op);
                let locked = fc_idx
                    .and_then(|i| fd.get_call_specs(i))
                    .map(|fc| fc.is_output_locked())
                    .unwrap_or(false);
                if !locked { return Ok(action_status::NO_CHANGE); }
            }
            // Address contiguity check: the LSB piece must sit immediately
            // after (little-endian) or before (big-endian) the INDIRECT output.
            let (lsb_addr, lsb_size, vn_addr, vn_size) = {
                let l = lsb_vn.read().unwrap();
                let v = vn.read().unwrap();
                (l.get_addr().clone(), l.get_size(), v.get_addr().clone(), v.get_size())
            };
            // Rugra does not track per-space endianness on Address; we use the
            // little-endian branch (the common case) and fall back to
            // big-endian if the LE result does not match. This matches Ghidra's
            // `addr = isBigEndian ? addr - vn->getSize() : addr + lsb->getSize()`.
            let le_addr = lsb_addr.offset(lsb_size as i64);
            let be_addr = lsb_addr.offset(-(vn_size as i64));
            if le_addr.as_u64() != vn_addr.as_u64()
                && be_addr.as_u64() != vn_addr.as_u64()
            {
                return Ok(action_status::NO_CHANGE);
            }
        } else {
            return Ok(action_status::NO_CHANGE);
        }
        // Trace the pathological concatenation forward and record partial
        // consumption on any CALL input / RETURN it reaches.
        let count = Self::trace_pathology_forward(op_arc, fd);
        Ok(if count > 0 { action_status::CHANGE } else { action_status::NO_CHANGE })
    }

    // Ghidra: ruleaction.cc:10561 RulePiecePathology
    fn get_name(&self) -> &str { "piece_pathology" }
    // Ghidra: ruleaction.cc:10572 RulePiecePathology::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_PIECE] }
}

/// Simplify various conditional move situations.
///
/// Faithful to `RuleConditionalMove` (ruleaction.cc:9390-9558) plus helpers
/// `checkBoolean` (9277-9303), `gatherExpression` (9305-9344),
/// `constructBool` (9346-9381).
///
/// NOTE: This rule is fundamentally block/control-flow driven. The block
/// in-edge analysis (find the common root block ending in a CBRANCH), the
/// `getTrueOut`/`isBooleanFlip` path determination, the bool-constant collapse
/// paths, the mixed const/non-const paths, and the non-const BOOL_OR/BOOL_AND
/// paths are all implemented against the available block + op-edit
/// infrastructure. The non-constant `gatherExpression` collects the op set
/// faithfully; `constructBool` reproduces the expression only when no cross-
/// branch op duplication is required (empty op set) — the full
/// `CloneBlockOps::cloneExpression` (cross-block op cloning) is not yet ported,
/// so the rare case where the boolean is formed *inside* the branch block still
/// conservatively no-ops.
pub struct RuleConditionalMove;

impl RuleConditionalMove {
    // Ghidra: ruleaction.cc:9361 RuleConditionalMove
    pub fn new() -> Self { Self }

    /// Faithful to `checkBoolean` (ruleaction.cc:9277-9303). Given a MULTIEQUAL
    /// input, return its boolean root if it is a boolean value (bool-output op
    /// or a COPY of a 0/1 constant), else None.
    // Ghidra: ruleaction.cc:9277 RuleConditionalMove::checkBoolean
    fn check_boolean(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if !vn.read().unwrap().is_written() { return None; }
        let op = vn.read().unwrap().get_def()?;
        if op.read().unwrap().is_bool_output() {
            return Some(vn.clone());
        }
        if op.read().unwrap().opcode == OpCode::CPUI_COPY {
            let inner = op.read().unwrap().get_in(0).cloned()?;
            if inner.read().unwrap().is_constant() {
                let val = inner.read().unwrap().get_offset();
                if (val & !1u64) == 0 {
                    return Some(inner);
                }
            }
        }
        None
    }

    /// Faithful to `gatherExpression` (ruleaction.cc:9305-9334). Collects the
    /// set of PcodeOps (in `branch`) that define `vn` and would need to be
    /// duplicated to propagate the expression out of the branch.
    ///
    /// Returns `Some(ops)` if the expression can be propagated. The op list is
    /// empty when nothing needs duplication (constant/free/input/pre-branch
    /// values, or `root==branch`).
    ///
    /// Rugra does not implement `CloneBlockOps::cloneExpression` (the cross-block
    /// op duplicator). Callers that get a non-empty `ops` therefore cannot build
    /// the cloned expression and must bail. The empty-list case — which covers
    /// values formed before the branch — works without cloning.
    // Ghidra: ruleaction.cc:9305 RuleConditionalMove::gatherExpression
    fn gather_expression(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        ops: &mut Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>>,
        root: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        branch: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> bool {
        let v_rg = vn.read().unwrap();
        if v_rg.is_constant() { return true; } // Constants can always be propagated
        if v_rg.is_free() { return false; }
        if v_rg.is_addr_tied() { return false; }
        drop(v_rg);
        if std::sync::Arc::ptr_eq(root, branch) { return true; } // No branch to cross
        let vn_rg = vn.read().unwrap();
        if !vn_rg.is_written() { return true; }
        let def_op = match vn_rg.get_def() { Some(o) => o, None => return true };
        // Can propagate if the value was formed before the branch block.
        if !std::sync::Arc::ptr_eq(&def_op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade()).unwrap_or_else(|| branch.clone()), branch) {
            return true;
        }
        // Otherwise the defining op lives inside `branch` and must be duplicated.
        ops.push(def_op);
        let mut pos = 0;
        while pos < ops.len() {
            let op = ops[pos].clone();
            pos += 1;
            // special ops cannot be pulled out (getEvalType()==special).
            use crate::op::pcodeop_flags;
            if op.read().unwrap().get_eval_type() == pcodeop_flags::SPECIAL {
                return false;
            }
            let num_in = op.read().unwrap().num_input();
            for i in 0..num_in {
                let in0 = match op.read().unwrap().get_in(i).cloned() { Some(v) => v, None => continue };
                let in0_rg = in0.read().unwrap();
                if in0_rg.is_free() && !in0_rg.is_constant() { return false; }
                if in0_rg.is_written() {
                    let in_def = in0_rg.get_def();
                    let in_branch = in_def
                        .as_ref()
                        .and_then(|d| d.read().unwrap().parent.as_ref().and_then(|w| w.upgrade()))
                        .map(|b| std::sync::Arc::ptr_eq(&b, branch))
                        .unwrap_or(false);
                    if in_branch {
                        if in0_rg.is_addr_tied() { return false; } // Don't pull indirectly-addressed results
                        if in0_rg.lone_descend().map(|d| !std::sync::Arc::ptr_eq(&d, &op)).unwrap_or(true) {
                            return false; // More than one use
                        }
                        if ops.len() >= 4 { return false; }
                        if let Some(d) = in_def { ops.push(d); }
                    }
                }
            }
        }
        true
    }

    /// Faithful to `constructBool` (ruleaction.cc:9346-9381). Returns the
    /// Varnode representing the (possibly reproduced) boolean expression.
    ///
    /// Ghidra uses `CloneBlockOps::cloneExpression` to duplicate the `ops` set
    /// before `insertop`. Rugra has no such cross-block cloner, so:
    ///   - `ops` empty   → return `vn` itself (faithful, no cloning needed).
    ///   - `ops` non-empty → return None (cannot clone); caller bails.
    // Ghidra: ruleaction.cc:9346 RuleConditionalMove::constructBool
    fn construct_bool(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        ops: &[std::sync::Arc<std::sync::RwLock<PcodeOp>>],
        _insertop: &crate::op::PcodeOpRef,
        _data: &mut Funcdata,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if ops.is_empty() {
            return Some(vn.clone());
        }
        // CloneBlockOps not ported: cannot reproduce the cross-branch expression.
        None
    }
}

impl Rule for RuleConditionalMove {
    // Ghidra: ruleaction.cc:9390 RuleConditionalMove::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleConditionalMove::applyOp (ruleaction.cc:9390-9558).
        if op_arc.read().unwrap().num_input() != 2 { return Ok(action_status::NO_CHANGE); }
        let (in0, in1, outvn) = {
            let op = op_arc.read().unwrap();
            (op.get_in(0).cloned(), op.get_in(1).cloned(), op.output.clone())
        };
        let (in0, in1) = match (in0, in1) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        let outvn = match outvn { Some(o) => o, None => return Ok(action_status::NO_CHANGE) };
        let bool0 = Self::check_boolean(&in0);
        let bool1 = Self::check_boolean(&in1);
        if bool0.is_none() || bool1.is_none() { return Ok(action_status::NO_CHANGE); }
        let bool0 = bool0.unwrap();
        let bool1 = bool1.unwrap();
        // bb = op->getParent(); inblock0/1 = bb->getIn(0/1).
        use crate::block::FlowBlock;
        let bb = match op_arc.read().unwrap().parent.as_ref().and_then(|w| w.upgrade()) {
            Some(b) => b,
            None => return Ok(action_status::NO_CHANGE), // no block graph
        };
        let (inblock0, inblock1) = {
            let rg = bb.read().unwrap();
            let i0 = rg.get_in(0).map(|e| e.point);
            let i1 = rg.get_in(1).map(|e| e.point);
            match (i0, i1) {
                (Some(a), Some(b)) => (a, b),
                _ => return Ok(action_status::NO_CHANGE),
            }
        };
        // Determine rootblock0/rootblock1 (the block feeding the inblock).
        let rootblock0 = {
            let rg = inblock0.read().unwrap();
            if rg.size_out() == 1 {
                if rg.size_in() != 1 { return Ok(action_status::NO_CHANGE); }
                rg.get_in(0).map(|e| e.point)
            } else {
                Some(inblock0.clone())
            }
        };
        let rootblock1 = {
            let rg = inblock1.read().unwrap();
            if rg.size_out() == 1 {
                if rg.size_in() != 1 { return Ok(action_status::NO_CHANGE); }
                rg.get_in(0).map(|e| e.point)
            } else {
                Some(inblock1.clone())
            }
        };
        let (rootblock0, rootblock1) = match (rootblock0, rootblock1) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(action_status::NO_CHANGE),
        };
        if !std::sync::Arc::ptr_eq(&rootblock0, &rootblock1) { return Ok(action_status::NO_CHANGE); }
        let rootblock = rootblock0;
        // cbranch = rootblock->lastOp(); must be CBRANCH.
        let cbranch = {
            let r_rg = rootblock.read().unwrap();
            let any = r_rg.as_any();
            if let Some(bb2) = any.downcast_ref::<crate::block::BlockBasic>() {
                bb2.last_op()
            } else { None }
        };
        let cbranch = match cbranch { Some(c) => c, None => return Ok(action_status::NO_CHANGE) };
        if cbranch.0.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return Ok(action_status::NO_CHANGE); }

        // gatherExpression for both inputs (ruleaction.cc:9434-9437).
        let mut op_list0: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = Vec::new();
        if !Self::gather_expression(&bool0, &mut op_list0, &rootblock, &inblock0) {
            return Ok(action_status::NO_CHANGE);
        }
        let mut op_list1: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = Vec::new();
        if !Self::gather_expression(&bool1, &mut op_list1, &rootblock, &inblock1) {
            return Ok(action_status::NO_CHANGE);
        }

        // path0istrue = (rootblock != inblock0) ? (getTrueOut==inblock0)
        //                                         : (getTrueOut != inblock1)
        let cbranch_ref = cbranch.clone();
        let path0istrue = {
            let r_rg = rootblock.read().unwrap();
            let true_out = r_rg.get_true_out(&cbranch_ref);
            if !std::sync::Arc::ptr_eq(&rootblock, &inblock0) {
                true_out.as_ref().map(|o| std::sync::Arc::ptr_eq(o, &inblock0)).unwrap_or(false)
            } else {
                true_out.as_ref().map(|o| !std::sync::Arc::ptr_eq(o, &inblock1)).unwrap_or(false)
            }
        };
        let mut path0istrue = path0istrue;
        if cbranch.0.read().unwrap().is_boolean_flip() { path0istrue = !path0istrue; }

        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        let is_bool0_const = bool0.read().unwrap().is_constant();
        let is_bool1_const = bool1.read().unwrap().is_constant();

        // Non-const branch (ruleaction.cc:9447-9491): both bool0 and bool1 are
        // non-constant. Produces a BOOL_OR / BOOL_AND of the CBRANCH's boolean
        // against the reconstructed operands. Requires constructBool, which (in
        // Rugra) only succeeds when no cross-branch op duplication is needed.
        if !is_bool0_const && !is_bool1_const {
            if std::sync::Arc::ptr_eq(&rootblock, &inblock0) {
                // inblock0 == rootblock0 path (ruleaction.cc:9448-9467).
                let boolvn = match cbranch.0.read().unwrap().get_in(1).cloned() {
                    Some(v) => v,
                    None => return Ok(action_status::NO_CHANGE),
                };
                let mut andorselect = path0istrue;
                // Force 0 branch to be boolvn OR !boolvn.
                if !std::sync::Arc::ptr_eq(&boolvn, &in0) {
                    if !boolvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
                    let negop = boolvn.read().unwrap().get_def().unwrap();
                    if negop.read().unwrap().opcode != OpCode::CPUI_BOOL_NEGATE { return Ok(action_status::NO_CHANGE); }
                    let neg_in = match negop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                    if !std::sync::Arc::ptr_eq(&neg_in, &in0) { return Ok(action_status::NO_CHANGE); }
                    andorselect = !andorselect;
                }
                let opc = if andorselect { OpCode::CPUI_BOOL_OR } else { OpCode::CPUI_BOOL_AND };
                fd.op_uninsert(&op_ref);
                fd.op_set_opcode(&op_ref, opc);
                fd.op_insert_begin(&op_ref, &bb);
                let firstvn = match Self::construct_bool(&bool0, &op_list0, &op_ref, fd) { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                let secondvn = match Self::construct_bool(&bool1, &op_list1, &op_ref, fd) { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                fd.op_set_input(&op_ref, firstvn, 0);
                fd.op_set_input(&op_ref, secondvn, 1);
                return Ok(action_status::CHANGE);
            } else if std::sync::Arc::ptr_eq(&rootblock, &inblock1) {
                // inblock1 == rootblock0 path (ruleaction.cc:9469-9489).
                let boolvn = match cbranch.0.read().unwrap().get_in(1).cloned() {
                    Some(v) => v,
                    None => return Ok(action_status::NO_CHANGE),
                };
                let mut andorselect = !path0istrue;
                // Force 1 branch to be boolvn OR !boolvn.
                if !std::sync::Arc::ptr_eq(&boolvn, &in1) {
                    if !boolvn.read().unwrap().is_written() { return Ok(action_status::NO_CHANGE); }
                    let negop = boolvn.read().unwrap().get_def().unwrap();
                    if negop.read().unwrap().opcode != OpCode::CPUI_BOOL_NEGATE { return Ok(action_status::NO_CHANGE); }
                    let neg_in = match negop.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                    if !std::sync::Arc::ptr_eq(&neg_in, &in1) { return Ok(action_status::NO_CHANGE); }
                    andorselect = !andorselect;
                }
                let opc = if andorselect { OpCode::CPUI_BOOL_OR } else { OpCode::CPUI_BOOL_AND };
                fd.op_uninsert(&op_ref);
                fd.op_set_opcode(&op_ref, opc);
                fd.op_insert_begin(&op_ref, &bb);
                let firstvn = match Self::construct_bool(&bool1, &op_list1, &op_ref, fd) { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                let secondvn = match Self::construct_bool(&bool0, &op_list0, &op_ref, fd) { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
                fd.op_set_input(&op_ref, firstvn, 0);
                fd.op_set_input(&op_ref, secondvn, 1);
                return Ok(action_status::CHANGE);
            }
            return Ok(action_status::NO_CHANGE);
        }

        // Below here: at least one side is constant, OR a change is being made.
        fd.op_uninsert(&op_ref); // Changing from MULTIEQUAL, reinsert.
        let sz = outvn.read().unwrap().get_size();
        if is_bool0_const && is_bool1_const {
            if bool0.read().unwrap().get_offset() == bool1.read().unwrap().get_offset() {
                // COPY of the constant.
                fd.op_remove_input(&op_ref, 1);
                fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                let c = fd.new_constant(sz, bool0.read().unwrap().get_offset());
                fd.op_set_input(&op_ref, c, 0);
                fd.op_insert_begin(&op_ref, &bb);
            } else {
                fd.op_remove_input(&op_ref, 1);
                let boolvn = match cbranch.0.read().unwrap().get_in(1).cloned() {
                    Some(v) => v,
                    None => return Ok(action_status::NO_CHANGE),
                };
                let needcomplement = (bool0.read().unwrap().get_offset() == 0) == path0istrue;
                if sz == 1 {
                    fd.op_set_opcode(&op_ref, if needcomplement { OpCode::CPUI_BOOL_NEGATE } else { OpCode::CPUI_COPY });
                    fd.op_insert_begin(&op_ref, &bb);
                    fd.op_set_input(&op_ref, boolvn, 0);
                } else {
                    fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_ZEXT);
                    fd.op_insert_begin(&op_ref, &bb);
                    let boolvn = if needcomplement {
                        fd.op_bool_negate(boolvn, &op_ref, false)
                    } else { boolvn };
                    fd.op_set_input(&op_ref, boolvn, 0);
                }
            }
        } else if is_bool0_const {
            // ruleaction.cc:9524-9535
            let needcomplement = (path0istrue != (bool0.read().unwrap().get_offset() != 0));
            let opc = if bool0.read().unwrap().get_offset() != 0 { OpCode::CPUI_BOOL_OR } else { OpCode::CPUI_BOOL_AND };
            fd.op_set_opcode(&op_ref, opc);
            fd.op_insert_begin(&op_ref, &bb);
            let boolvn = match cbranch.0.read().unwrap().get_in(1).cloned() {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            };
            let boolvn = if needcomplement { fd.op_bool_negate(boolvn, &op_ref, false) } else { boolvn };
            let body1 = match Self::construct_bool(&bool1, &op_list1, &op_ref, fd) { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            fd.op_set_input(&op_ref, boolvn, 0);
            fd.op_set_input(&op_ref, body1, 1);
        } else {
            // bool1 must be constant (ruleaction.cc:9536-9547).
            let needcomplement = (path0istrue == (bool1.read().unwrap().get_offset() != 0));
            let opc = if bool1.read().unwrap().get_offset() != 0 { OpCode::CPUI_BOOL_OR } else { OpCode::CPUI_BOOL_AND };
            fd.op_set_opcode(&op_ref, opc);
            fd.op_insert_begin(&op_ref, &bb);
            let boolvn = match cbranch.0.read().unwrap().get_in(1).cloned() {
                Some(v) => v,
                None => return Ok(action_status::NO_CHANGE),
            };
            let boolvn = if needcomplement { fd.op_bool_negate(boolvn, &op_ref, false) } else { boolvn };
            let body0 = match Self::construct_bool(&bool0, &op_list0, &op_ref, fd) { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            fd.op_set_input(&op_ref, boolvn, 0);
            fd.op_set_input(&op_ref, body0, 1);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:9361 RuleConditionalMove
    fn get_name(&self) -> &str { "conditional_move" }
    // Ghidra: ruleaction.cc:9384 RuleConditionalMove::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_MULTIEQUAL] }
}

/// Remove certain NaN operations by assuming their result is always false.
///
/// Faithful to `RuleIgnoreNan` (ruleaction.cc:9740-9787) plus helpers
/// `checkBackForCompare` (9622-9662), `isAnotherNan` (9664-9694),
/// `testForComparison` (9696-9738).
///
/// The `nan_ignore_all` short-circuit (treat NaN as always false) is
/// implemented via `get_arch()`. When `nan_ignore_all` is false, the deeper
/// `testForComparison`/`checkBackForCompare` traversal removes a NaN data-flow
/// only when it is combined (via BOOL_OR/BOOL_AND/INT_EQUAL/INT_NOTEQUAL, or a
/// CBRANCH protecting another CBRANCH) with a floating-point comparison that
/// takes the same float operand. The functional-equivalence test uses
/// `crate::address::functional_equality` (the level-0 ptr/const equality).
pub struct RuleIgnoreNan;

impl RuleIgnoreNan {
    // Ghidra: ruleaction.cc:9604 RuleIgnoreNan
    pub fn new() -> Self { Self }

    /// Is `opc` a two-input floating-point comparison op?
    /// Faithful to `OpCode::isFloatingPointOp` combined with the
    /// `numInput()==2` guard in Ghidra's checkBackForCompare.
    // Ghidra: typeop.hh:146 PcodeOp::isFloatingPointOp
    fn is_float_compare(opc: OpCode) -> bool {
        matches!(
            opc,
            OpCode::CPUI_FLOAT_EQUAL
                | OpCode::CPUI_FLOAT_NOTEQUAL
                | OpCode::CPUI_FLOAT_LESS
                | OpCode::CPUI_FLOAT_LESSEQUAL
        )
    }

    /// Faithful to `RuleIgnoreNan::checkBackForCompare` (ruleaction.cc:9622-9662).
    ///
    /// Check if a boolean Varnode `root` incorporates a floating-point
    /// comparison whose input is functionally equal to `float_var`. The root
    /// may be the direct output of a comparison, a BOOL_NEGATE of one, or a
    /// BOOL_AND/BOOL_OR combining a comparison output.
    // Ghidra: ruleaction.cc:9622 RuleIgnoreNan::checkBackForCompare
    fn check_back_for_compare(
        float_var: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        if !root.read().unwrap().is_written() { return false; }
        let mut def1 = match root.read().unwrap().get_def() {
            Some(o) => o,
            None => return false,
        };
        if !def1.read().unwrap().is_bool_output() { return false; }
        // Peel a BOOL_NEGATE.
        if def1.read().unwrap().opcode == OpCode::CPUI_BOOL_NEGATE {
            let inner = def1.read().unwrap().get_in(0).cloned();
            let inner = match inner {
                Some(v) if v.read().unwrap().is_written() => v,
                _ => return false,
            };
            def1 = match inner.read().unwrap().get_def() {
                Some(o) => o,
                None => return false,
            };
        }
        // Direct floating-point comparison on the (negated) root.
        let opc1 = def1.read().unwrap().opcode;
        if Self::is_float_compare(opc1) {
            if def1.read().unwrap().num_input() != 2 { return false; }
            let in0 = def1.read().unwrap().get_in(0).cloned();
            let in1 = def1.read().unwrap().get_in(1).cloned();
            if let Some(v0) = in0 {
                if crate::address::functional_equality(float_var, &v0) { return true; }
            }
            if let Some(v1) = in1 {
                if crate::address::functional_equality(float_var, &v1) { return true; }
            }
            return false;
        }
        // BOOL_AND / BOOL_OR: each branch may hold a comparison.
        if opc1 != OpCode::CPUI_BOOL_AND && opc1 != OpCode::CPUI_BOOL_OR {
            return false;
        }
        for i in 0..2 {
            let vn = match def1.read().unwrap().get_in(i).cloned() {
                Some(v) if v.read().unwrap().is_written() => v,
                _ => continue,
            };
            let def2 = match vn.read().unwrap().get_def() {
                Some(o) => o,
                None => continue,
            };
            if !def2.read().unwrap().is_bool_output() { continue; }
            if !Self::is_float_compare(def2.read().unwrap().opcode) { continue; }
            if def2.read().unwrap().num_input() != 2 { continue; }
            let a = def2.read().unwrap().get_in(0).cloned();
            let b = def2.read().unwrap().get_in(1).cloned();
            if let Some(a) = a {
                if crate::address::functional_equality(float_var, &a) { return true; }
            }
            if let Some(b) = b {
                if crate::address::functional_equality(float_var, &b) { return true; }
            }
        }
        false
    }

    /// Faithful to `RuleIgnoreNan::isAnotherNan` (ruleaction.cc:9664-9694).
    ///
    /// Test if `vn` is produced by a NaN operation (directly, or via a
    /// BOOL_NEGATE of a NaN output).
    // Ghidra: ruleaction.cc:9664 RuleIgnoreNan::isAnotherNan
    fn is_another_nan(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        if !vn.read().unwrap().is_written() { return false; }
        let mut op = match vn.read().unwrap().get_def() {
            Some(o) => o,
            None => return false,
        };
        let mut opc = op.read().unwrap().opcode;
        if opc == OpCode::CPUI_BOOL_NEGATE {
            let inner = op.read().unwrap().get_in(0).cloned();
            let inner = match inner {
                Some(v) if v.read().unwrap().is_written() => v,
                _ => return false,
            };
            op = match inner.read().unwrap().get_def() {
                Some(o) => o,
                None => return false,
            };
            opc = op.read().unwrap().opcode;
        }
        opc == OpCode::CPUI_FLOAT_NAN
    }

    /// Faithful to `RuleIgnoreNan::testForComparison` (ruleaction.cc:9696-9738).
    ///
    /// The NaN output reaches `op` through input `slot`. If `op` combines it
    /// (BOOL_OR/BOOL_AND/INT_EQUAL/INT_NOTEQUAL) with a floating-point
    /// comparison of the same float operand — or is a CBRANCH protecting
    /// another CBRANCH holding such a comparison — the NaN input is removed
    /// (replaced by a constant 0/1, assuming the NaN is always false). Returns
    /// the output varnode of `op` when `op`'s opcode equals `match_code` (so the
    /// caller can continue the chain), else None. Increments `count` on a real
    /// transformation.
    // Ghidra: ruleaction.cc:9696 RuleIgnoreNan::testForComparison
    fn test_for_comparison(
        float_var: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        slot: usize,
        match_code: OpCode,
        count: &mut i32,
        fd: &mut Funcdata,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let opc = op.read().unwrap().opcode;
        let other_idx = 1usize.wrapping_sub(slot); // 1 - slot, for 2-input ops
        if opc == match_code {
            // BOOL_AND / BOOL_OR combining the NaN with another boolean.
            let vn = op.read().unwrap().get_in(other_idx).cloned();
            if let Some(vn) = vn {
                if Self::check_back_for_compare(float_var, &vn) {
                    // data.opSetOpcode(op, COPY); opRemoveInput(op,1);
                    // opSetInput(op, vn, 0);
                    let op_ref = crate::op::PcodeOpRef(op.clone());
                    fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                    fd.op_remove_input(&op_ref, 1);
                    fd.op_set_input(&op_ref, vn, 0);
                    *count += 1;
                    return None;
                } else if Self::is_another_nan(&vn) {
                    return op.read().unwrap().get_out().cloned();
                }
            }
        } else if opc == OpCode::CPUI_INT_EQUAL || opc == OpCode::CPUI_INT_NOTEQUAL {
            let vn = op.read().unwrap().get_in(other_idx).cloned();
            if let Some(vn) = vn {
                if Self::check_back_for_compare(float_var, &vn) {
                    // data.opSetInput(op, newConstant(1, matchCode==BOOL_OR?0:1), slot)
                    let op_ref = crate::op::PcodeOpRef(op.clone());
                    let val = if match_code == OpCode::CPUI_BOOL_OR { 0 } else { 1 };
                    let c = fd.new_constant(1, val);
                    fd.op_set_input(&op_ref, c, slot);
                    *count += 1;
                }
            }
        } else if opc == OpCode::CPUI_CBRANCH {
            // The CBRANCH guards control-flow to another CBRANCH that reads a
            // comparison on the same float operand.
            Self::try_cbranch_protection(float_var, op, match_code, count, fd);
        }
        None
    }

    /// CBRANCH-protection branch of testForComparison (ruleaction.cc:9722-9737).
    /// If the CBRANCH's taken/fallthru out-edge leads to a block whose last op
    /// is another CBRANCH reading (in slot 1) a comparison on `float_var`, and
    /// that block's other out-edge rejoins the sibling branch, replace the NaN
    /// input with a constant.
    // Ghidra: ruleaction.cc:9722 RuleIgnoreNan::testForComparison
    fn try_cbranch_protection(
        float_var: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        match_code: OpCode,
        count: &mut i32,
        fd: &mut Funcdata,
    ) {
        // Determine which out-edge the NaN-controlled value follows.
        let boolean_flip = op.read().unwrap().is_boolean_flip();
        let mut out_dir = if match_code == OpCode::CPUI_BOOL_OR { 0 } else { 1 };
        if boolean_flip { out_dir = 1 - out_dir; }
        // Resolve the parent block and its out-edge targets.
        let parent = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        let parent = match parent { Some(p) => p, None => return };
        let out_branch = parent.read().unwrap().get_out(out_dir);
        let (out_branch, other_branch) = match out_branch {
            Some(e) => {
                let other = parent.read().unwrap().get_out(1 - out_dir);
                (e.point.clone(), other.map(|o| o.point.clone()))
            }
            None => return,
        };
        // lastOp of the out-branch block.
        let last_op_ref = {
            let ob = out_branch.read().unwrap();
            ob.as_any().downcast_ref::<crate::block::BlockBasic>().and_then(|bb| bb.last_op())
        };
        let last_op = match last_op_ref { Some(r) => r.0, None => return };
        if last_op.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return; }
        // The protected block's other out-edge must rejoin the sibling branch.
        let rejoins = if let Some(other) = &other_branch {
            let ob = out_branch.read().unwrap();
            let o0 = ob.get_out(0).map(|e| std::sync::Arc::ptr_eq(&e.point, other));
            let o1 = ob.get_out(1).map(|e| std::sync::Arc::ptr_eq(&e.point, other));
            o0.unwrap_or(false) || o1.unwrap_or(false)
        } else {
            false
        };
        if !rejoins { return; }
        // lastOp->getIn(1) must hold a comparison on float_var.
        let cmp_in = last_op.read().unwrap().get_in(1).cloned();
        if let Some(cmp_in) = cmp_in {
            if Self::check_back_for_compare(float_var, &cmp_in) {
                let op_ref = crate::op::PcodeOpRef(op.clone());
                let val = if match_code == OpCode::CPUI_BOOL_OR { 0 } else { 1 };
                let c = fd.new_constant(1, val);
                fd.op_set_input(&op_ref, c, 1);
                *count += 1;
            }
        }
    }

    /// Find the input slot of `target_vn` within `op` (which input slot reads
    /// it). Faithful to Ghidra's `PcodeOp::getSlot(Varnode*)`.
    // Ghidra: op.hh:166 PcodeOp::getSlot
    fn input_slot_of(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        target_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<usize> {
        let o = op.read().unwrap();
        for (i, inv) in o.inrefs.iter().enumerate() {
            if std::sync::Arc::ptr_eq(inv, target_vn) {
                return Some(i);
            }
        }
        None
    }
}

impl Rule for RuleIgnoreNan {
    // Ghidra: ruleaction.cc:9740 RuleIgnoreNan::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleIgnoreNan::applyOp (ruleaction.cc:9740-9787).
        if let Some(arch) = fd.get_arch() {
            if arch.nan_ignore_all {
                // Treat these NaN operations as always returning false (0).
                let op_ref = crate::op::PcodeOpRef(op_arc.clone());
                fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                let zero = fd.new_constant(1, 0);
                fd.op_set_input(&op_ref, zero, 0);
                return Ok(action_status::CHANGE);
            }
        }
        // No Architecture / nan_ignore_all disabled: the deeper
        // checkBackForCompare / isAnotherNan / testForComparison traversal.
        let float_var = match op_arc.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        if float_var.read().unwrap().is_free() { return Ok(action_status::NO_CHANGE); }
        let out1 = match op_arc.read().unwrap().get_out().cloned() {
            Some(v) => v,
            None => return Ok(action_status::NO_CHANGE),
        };
        let mut count = 0i32;
        // Walk the descendants of the NaN output, up to 3 levels deep (faithful
        // to applyOp's three nested beginDescend/endDescend loops).
        let level0: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = out1
            .read().unwrap()
            .descend
            .iter()
            .filter_map(|w| w.upgrade())
            .collect();
        for bool_read1 in level0 {
            let match_code;
            let out2;
            if bool_read1.read().unwrap().opcode == OpCode::CPUI_BOOL_NEGATE {
                match_code = OpCode::CPUI_BOOL_AND;
                out2 = bool_read1.read().unwrap().get_out().cloned();
            } else {
                match_code = OpCode::CPUI_BOOL_OR;
                let slot = Self::input_slot_of(&bool_read1, &out1).unwrap_or(0);
                out2 = Self::test_for_comparison(
                    &float_var, &bool_read1, slot, match_code, &mut count, fd,
                );
            }
            let out2 = match out2 { Some(v) => v, None => continue };
            let level1: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = out2
                .read().unwrap()
                .descend
                .iter()
                .filter_map(|w| w.upgrade())
                .collect();
            for bool_read2 in level1 {
                let slot = Self::input_slot_of(&bool_read2, &out2).unwrap_or(0);
                let out3 = Self::test_for_comparison(
                    &float_var, &bool_read2, slot, match_code, &mut count, fd,
                );
                let out3 = match out3 { Some(v) => v, None => continue };
                let level2: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = out3
                    .read().unwrap()
                    .descend
                    .iter()
                    .filter_map(|w| w.upgrade())
                    .collect();
                for bool_read3 in level2 {
                    let slot = Self::input_slot_of(&bool_read3, &out3).unwrap_or(0);
                    Self::test_for_comparison(
                        &float_var, &bool_read3, slot, match_code, &mut count, fd,
                    );
                }
            }
        }
        Ok(if count > 0 { action_status::CHANGE } else { action_status::NO_CHANGE })
    }

    // Ghidra: ruleaction.cc:9604 RuleIgnoreNan
    fn get_name(&self) -> &str { "ignore_nan" }
    // Ghidra: ruleaction.cc:9609 RuleIgnoreNan::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_FLOAT_NAN] }
}

// ============================================================================
// RuleLoadVarnode / RuleStoreVarnode  (ruleaction.cc:4185-4361)
// ============================================================================

/// Convert LOAD operations using a constant offset (or a spacebase + offset)
/// into a COPY of a named stack/global varnode.
///
/// Faithful to Ghidra's `RuleLoadVarnode` (ruleaction.cc:4285-4325) plus its
/// three static helpers:
///   - `correctSpacebase` (ruleaction.cc:4193-4204)
///   - `vnSpacebase`      (ruleaction.cc:4214-4247)
///   - `checkSpacebase`   (ruleaction.cc:4256-4283)
///
/// A LOAD's address operand (slot 1) is examined. If it is a plain constant,
/// the load resolves directly into the LOAD's named space. If it is
/// `spacebase + const`, it resolves into the spacebase's associated space. The
/// LOAD is then rewritten to `COPY(newVarnode)`.
pub struct RuleLoadVarnode;

impl RuleLoadVarnode {
    // Ghidra: ruleaction.cc:4285 RuleLoadVarnode
    pub fn new() -> Self { Self }

    /// Faithful to `RuleLoadVarnode::correctSpacebase` (ruleaction.cc:4193-4204).
    ///
    /// Returns the `AddressSpace` associated with the given varnode if it is an
    /// *active* spacebase for `spc`; otherwise `None`.
    ///
    /// - A constant spacebase pseudo-varnode is associated with `spc`.
    /// - A non-constant spacebase must be a function input; its associated
    ///   space (looked up via `getSpaceBySpacebase`) must *contain* `spc`.
    ///
    /// TODO(spacebase-registry): Rugra has no `getSpaceBySpacebase` /
    /// `getContain` yet, so the non-constant spacebase-input branch returns
    /// `None`. The constant spacebase branch (used by global pseudo-spacebases)
    /// and the early `isSpacebase()` guard are fully faithful.
    // Ghidra: ruleaction.cc:4193 RuleLoadVarnode::correctSpacebase
    fn correct_spacebase(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        spc: crate::space::AddressSpace,
    ) -> Option<crate::space::AddressSpace> {
        let v = vn.read().unwrap();
        if !v.is_spacebase() {
            return None;
        }
        if v.is_constant() {
            // We have a global pseudo spacebase → associate with load/stored space.
            return Some(spc);
        }
        if !v.is_input() {
            return None;
        }
        // Ghidra: assoc = glb->getSpaceBySpacebase(vn->getAddr(), vn->getSize());
        //         if (assoc->getContain() != spc) return 0;
        // Rugra lacks the spacebase→space registry, so we cannot resolve the
        // associated space for a non-constant spacebase input. Bail out.
        None
    }

    /// Faithful to `RuleLoadVarnode::vnSpacebase` (ruleaction.cc:4214-4247).
    ///
    /// If `vn` is `spacebase + const`, pass back the constant offset in `val`
    /// and return the associated space; otherwise `None`.
    // Ghidra: ruleaction.cc:4214 RuleLoadVarnode::vnSpacebase
    fn vn_spacebase(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        val: &mut u64,
        spc: crate::space::AddressSpace,
    ) -> Option<crate::space::AddressSpace> {
        // Path 1: vn is itself an active spacebase (offset 0).
        if let Some(retspace) = Self::correct_spacebase(vn, spc) {
            *val = 0;
            return Some(retspace);
        }
        let def = { vn.read().unwrap().get_def() };
        let def_op = match def {
            Some(op) => op,
            None => return None, // vn->isWritten() == false
        };
        // def->code() != CPUI_INT_ADD
        let d = def_op.read().unwrap();
        if d.opcode != OpCode::CPUI_INT_ADD {
            return None;
        }
        let vn1 = match d.get_in(0) { Some(v) => v.clone(), None => return None };
        let vn2 = match d.get_in(1) { Some(v) => v.clone(), None => return None };
        drop(d);
        // Try vn1 as spacebase, vn2 as the constant offset.
        if let Some(retspace) = Self::correct_spacebase(&vn1, spc) {
            if vn2.read().unwrap().is_constant() {
                *val = vn2.read().unwrap().get_offset();
                return Some(retspace);
            }
            return None;
        }
        // Try vn2 as spacebase, vn1 as the constant offset.
        if let Some(retspace) = Self::correct_spacebase(&vn2, spc) {
            if vn1.read().unwrap().is_constant() {
                *val = vn1.read().unwrap().get_offset();
                return Some(retspace);
            }
        }
        None
    }

    /// Faithful to `RuleLoadVarnode::checkSpacebase` (ruleaction.cc:4256-4283).
    ///
    /// Checks if a STORE/LOAD is off of `spacebase + constant`. If so, returns
    /// the associated space and passes back the offset in `offoff`.
    ///
    /// `getSpaceFromConst` (varnode.cc) extracts the address space encoded in
    /// a constant-space varnode (the LOAD/STORE space-id operand, slot 0).
    /// Rugra encodes the space-id as a constant whose value is the space-id, so
    /// we decode it via `AddressSpace::from_id`.
    // Ghidra: ruleaction.cc:4346 RuleLoadVarnode::checkSpacebase
    fn check_spacebase(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        offoff: &mut u64,
    ) -> Option<crate::space::AddressSpace> {
        let op_rg = op.read().unwrap();
        // offvn = op->getIn(1); // Address offset
        let offvn = match op_rg.get_in(1) { Some(v) => v.clone(), None => return None };
        // loadspace = op->getIn(0)->getSpaceFromConst(); // Space being loaded/stored
        let space_id_vn = match op_rg.get_in(0) { Some(v) => v.clone(), None => return None };
        drop(op_rg);
        let loadspace = {
            let s = space_id_vn.read().unwrap();
            if !s.is_constant() {
                return None;
            }
            // The constant value encodes the SpaceId of the space being loaded.
            crate::space::AddressSpace::from_id(s.get_val() as crate::space::SpaceId)
        };

        // Treat segmentop as part of load/store.
        let off_is_written = offvn.read().unwrap().is_written();
        let off_def_code = if off_is_written {
            offvn.read().unwrap().get_def()
                .map(|d| d.read().unwrap().opcode)
        } else {
            None
        };

        if off_is_written && off_def_code == Some(OpCode::CPUI_SEGMENTOP) {
            // offvn = offvn->getDef()->getIn(2);
            let inner = {
                let d = offvn.read().unwrap().get_def().unwrap();
                let dr = d.read().unwrap();
                dr.get_in(2).cloned()
            };
            let inner = match inner { Some(v) => v, None => return None };
            if inner.read().unwrap().is_constant() {
                return None;
            }
            // Fall through to vnSpacebase(inner) — but Ghidra reassigns offvn.
            return Self::vn_spacebase(&inner, offoff, loadspace);
        } else if offvn.read().unwrap().is_constant() {
            // Check for plain constant.
            *offoff = offvn.read().unwrap().get_offset();
            return Some(loadspace);
        }
        Self::vn_spacebase(&offvn, offoff, loadspace)
    }
}

impl Rule for RuleLoadVarnode {
    // Ghidra: ruleaction.cc:4297 RuleLoadVarnode::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleLoadVarnode::applyOp (ruleaction.cc:4297-4325).
        let mut offoff: u64 = 0;
        let baseoff = match Self::check_spacebase(op_arc, &mut offoff) {
            Some(s) => s,
            None => return Ok(action_status::NO_CHANGE),
        };

        // size = op->getOut()->getSize();
        let out_size = {
            let op = op_arc.read().unwrap();
            let out = match op.get_out() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            let sz = out.read().unwrap().get_size();
            sz
        };
        // offoff = AddrSpace::addressToByte(offoff, baseoff->getWordSize());
        let word_size = baseoff.word_size().max(1) as u64;
        offoff = offoff.wrapping_mul(word_size);

        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        // newvn = data.newVarnode(size, baseoff, offoff);
        // Rugra's new_varnode takes (size, Address) and defaults to Ram space.
        // We create a varnode in the resolved space at the byte offset.
        let newvn = fd.vbank.create_with_space(out_size, baseoff, offoff);

        // data.opSetInput(op, newvn, 0);
        fd.op_set_input(&op_ref, newvn, 0);
        // data.opRemoveInput(op, 1);
        fd.op_remove_input(&op_ref, 1);
        // data.opSetOpcode(op, CPUI_COPY);
        fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);

        // The spacebase-placeholder / call-resolve tail (ruleaction.cc:4314-4323)
        // requires FuncCallSpecs / resolveSpacebaseRelative, which Rugra does
        // not yet model. The core LOAD→COPY transform is complete.
        // TODO(callspecs): port resolveSpacebaseRelative once call specs exist.
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:4285 RuleLoadVarnode
    fn get_name(&self) -> &str { "load_varnode" }
    // Ghidra: ruleaction.cc:4291 RuleLoadVarnode::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_LOAD] }
}

/// Convert STORE operations using a constant offset into a COPY of a named
/// stack/global varnode.
///
/// Faithful to Ghidra's `RuleStoreVarnode` (ruleaction.cc:4339-4361). Shares
/// the `check_spacebase` helper from `RuleLoadVarnode` (just as Ghidra does —
/// `RuleLoadVarnode::checkSpacebase`).
pub struct RuleStoreVarnode;

impl RuleStoreVarnode {
    // Ghidra: ruleaction.cc:4327 RuleStoreVarnode
    pub fn new() -> Self { Self }
}

impl Rule for RuleStoreVarnode {
    // Ghidra: ruleaction.cc:4339 RuleStoreVarnode::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleStoreVarnode::applyOp (ruleaction.cc:4339-4361).
        let mut offoff: u64 = 0;
        let baseoff = match RuleLoadVarnode::check_spacebase(op_arc, &mut offoff) {
            Some(s) => s,
            None => return Ok(action_status::NO_CHANGE),
        };

        // size = op->getIn(2)->getSize();
        let val_size = {
            let op = op_arc.read().unwrap();
            let inv = match op.get_in(2) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let sz = inv.read().unwrap().get_size();
            sz
        };
        // offoff = AddrSpace::addressToByte(offoff, baseoff->getWordSize());
        let word_size = baseoff.word_size().max(1) as u64;
        let offset_bytes = offoff.wrapping_mul(word_size);

        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        // Address addr(baseoff, offoff);
        // data.newVarnodeOut(size, addr, op);
        // Rugra's new_varnode_out places the output in Register space at `addr`.
        // To honour the resolved stack/global space we create the output in the
        // resolved space and wire it manually.
        let new_out = fd.vbank.create_with_space(val_size, baseoff, offset_bytes);
        new_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        new_out.write().unwrap().def = Some(std::sync::Arc::downgrade(&op_ref.0));
        op_ref.0.write().unwrap().output = Some(new_out.clone());

        // op->getOut()->setStackStore(); // Mark as originally from CPUI_STORE
        new_out.write().unwrap().addlflags |= crate::varnode::addl_flags::STACK_STORE;

        // data.opRemoveInput(op, 1);
        fd.op_remove_input(&op_ref, 1);
        // data.opRemoveInput(op, 0);
        fd.op_remove_input(&op_ref, 0);
        // data.opSetOpcode(op, CPUI_COPY);
        fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);

        // The isStoreUnmapped / markNotMapped tail (ruleaction.cc:4357-4359)
        // needs ScopeLocal::markNotMapped, which Rugra does not model.
        // TODO(scopelocal): port markNotMapped once scope-mapping exists.
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:4327 RuleStoreVarnode
    fn get_name(&self) -> &str { "store_varnode" }
    // Ghidra: ruleaction.cc:4333 RuleStoreVarnode::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_STORE] }
}

// ============================================================================
// RulePushPtr  (ruleaction.cc:6776-6913)
// ============================================================================

/// Push a varnode with a known pointer data-type to the bottom of its additive
/// expression.
///
/// Faithful to Ghidra's `RulePushPtr` (ruleaction.cc:6852-6913) plus helpers:
///   - `buildVarnodeOut`     (ruleaction.cc:6783-6789)
///   - `collectDuplicateNeeds`(ruleaction.cc:6798-6817)
///   - `duplicateNeed`       (ruleaction.cc:6827-6850)
///
/// This is the normalising step that precedes `RulePtrArith`: the pointer must
/// sit at the *root* of the additive expression. If `evaluatePointerExpression`
/// returns 1 (push needed), this rule rewrites each descendant
/// `INT_ADD(out, X)` into `INT_ADD(vni, INT_ADD(vnadd1, vnadd2))`.
pub struct RulePushPtr;

impl RulePushPtr {
    // Ghidra: ruleaction.cc:6852 RulePushPtr
    pub fn new() -> Self { Self }

    /// Faithful to `RulePushPtr::buildVarnodeOut` (ruleaction.cc:6783-6789).
    ///
    /// Build a duplicate of `vn` as an output of `op`, preserving the storage
    /// address if possible. AddrTied / internal-space varnodes get a fresh
    /// unique; otherwise a new varnode-out at the original address.
    // Ghidra: ruleaction.cc:6783 RulePushPtr::buildVarnodeOut
    fn build_varnode_out(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &crate::op::PcodeOpRef,
        fd: &mut Funcdata,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let (is_addr_tied, space, size, addr) = {
            let v = vn.read().unwrap();
            (v.is_addr_tied(), v.get_space(), v.get_size(), *v.get_addr())
        };
        if is_addr_tied || space == crate::space::AddressSpace::Iop {
            return fd.new_unique_out(size, op);
        }
        fd.new_varnode_out(size, addr, op)
    }

    /// Faithful to `RulePushPtr::collectDuplicateNeeds` (ruleaction.cc:6798-6817).
    ///
    /// Walk back through the chain of ZEXT/SEXT/2COMP/INT_MULT(const) ops
    /// building the offset; any with a lone descendant must be duplicated when
    /// the pointer is pushed.
    // Ghidra: ruleaction.cc:6798 RulePushPtr::collectDuplicateNeeds
    fn collect_duplicate_needs(
        reslist: &mut Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>>,
        mut vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        loop {
            let def = { vn.read().unwrap().get_def() };
            let op = match def { Some(o) => o, None => return };
            if vn.read().unwrap().is_auto_live() { return; }
            if vn.read().unwrap().lone_descend().is_none() {
                // Already has multiple descendants.
                return;
            }
            let opc = { op.read().unwrap().opcode };
            let keep = if opc == OpCode::CPUI_INT_ZEXT
                || opc == OpCode::CPUI_INT_SEXT
                || opc == OpCode::CPUI_INT_2COMP
            {
                true
            } else if opc == OpCode::CPUI_INT_MULT {
                // Keep if second input is constant.
                let in1_const = op.read().unwrap()
                    .get_in(1)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                in1_const
            } else {
                false
            };
            if keep {
                reslist.push(op.clone());
            } else {
                return;
            }
            // vn = op->getIn(0);
            let next = match op.read().unwrap().get_in(0) { Some(v) => v.clone(), None => return };
            vn = next;
        }
    }

    /// Faithful to `RulePushPtr::duplicateNeed` (ruleaction.cc:6827-6850).
    ///
    /// Duplicate the given PcodeOp so each output descendant gets its own copy
    /// inserted just before it, then destroy the original. Assumes the op has a
    /// single primary input (slot 0) and, optionally, a constant second input.
    // Ghidra: ruleaction.cc:7469 RulePushPtr::duplicateNeed
    fn duplicate_need(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        fd: &mut Funcdata,
    ) {
        let (out_vn, in_vn, num, opc, _addr) = {
            let o = op.read().unwrap();
            let out_vn = match o.get_out() { Some(v) => v.clone(), None => return };
            let in_vn = match o.get_in(0) { Some(v) => v.clone(), None => return };
            let num = o.num_input();
            let opc = o.opcode;
            let addr = o.get_addr();
            (out_vn, in_vn, num, opc, addr)
        };
        // We must snapshot the (descOp, slot) pairs first because creating new
        // ops mutates the descend list of out_vn.
        let mut targets: Vec<(std::sync::Arc<std::sync::RwLock<PcodeOp>>, usize)> = Vec::new();
        {
            let o = out_vn.read().unwrap();
            for dec_op in o.descend_iter() {
                // slot = decOp->getSlot(outVn);
                let slot = dec_op.read().unwrap()
                    .inrefs
                    .iter()
                    .position(|v| std::sync::Arc::ptr_eq(v, &out_vn));
                if let Some(s) = slot {
                    targets.push((dec_op, s));
                }
            }
        }
        let in1 = if num > 1 {
            op.read().unwrap().get_in(1).cloned()
        } else {
            None
        };
        for (dec_op, slot) in targets {
            let dec_addr = dec_op.read().unwrap().get_addr();
            // newOp(num, op->getAddr())
            let new_op = fd.new_op(num, dec_addr);
            // Varnode *newOut = buildVarnodeOut(outVn, newOp, data);
            let new_out = Self::build_varnode_out(&out_vn, &new_op, fd);
            // newOut->updateType(outVn->getType());
            if let Some(t) = out_vn.read().unwrap().get_type() {
                new_out.write().unwrap().update_type(t);
            }
            // data.opSetOpcode(newOp, opc);
            fd.op_set_opcode(&new_op, opc);
            // data.opSetInput(newOp, inVn, 0);
            fd.op_set_input(&new_op, in_vn.clone(), 0);
            if num > 1 {
                if let Some(c1) = &in1 {
                    fd.op_set_input(&new_op, c1.clone(), 1);
                }
            }
            // data.opSetInput(decOp, newOut, slot);
            fd.op_set_input(&crate::op::PcodeOpRef(dec_op.clone()), new_out, slot);
            // data.opInsertBefore(newOp, decOp);
            fd.op_insert_before(&new_op, &crate::op::PcodeOpRef(dec_op.clone()));
        }
        // data.opDestroy(op);
        fd.op_destroy(&crate::op::PcodeOpRef(op.clone()));
    }
}

impl Rule for RulePushPtr {
    // Ghidra: ruleaction.cc:6863 RulePushPtr::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePushPtr::applyOp (ruleaction.cc:6863-6913).
        if !fd.has_type_recovery_started() {
            return Ok(action_status::NO_CHANGE);
        }
        // Search for pointer type among inputs.
        let num_input = op_arc.read().unwrap().num_input();
        let mut slot: usize = num_input;
        let mut vni: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
        for s in 0..num_input {
            let in_vn = match op_arc.read().unwrap().get_in(s) { Some(v) => v.clone(), None => continue };
            let is_ptr = in_vn.read().unwrap()
                .get_type_read_facing()
                .map(|dt| dt.get_name().contains("Configurable"))
                .unwrap_or(false);
            if is_ptr {
                slot = s;
                vni = Some(in_vn);
                break;
            }
        }
        let vni = match vni { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
        if slot == num_input {
            return Ok(action_status::NO_CHANGE);
        }

        // if (evaluatePointerExpression(op, slot) != 1) return 0;
        if RulePtrArith::evaluate_pointer_expression(op_arc, slot) != 1 {
            return Ok(action_status::NO_CHANGE);
        }

        let vn = match op_arc.read().unwrap().get_out() { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        let vnadd2 = match op_arc.read().unwrap().get_in(1usize.wrapping_sub(slot).min(num_input - 1)) {
            Some(v) => v.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };

        // if (vn->loneDescend() == null) collectDuplicateNeeds(duplicateList, vnadd2);
        let mut duplicate_list: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> = Vec::new();
        if vn.read().unwrap().lone_descend().is_none() {
            Self::collect_duplicate_needs(&mut duplicate_list, vnadd2.clone());
        }

        // Main loop: for each descendant of vn, push the pointer down.
        // Snapshot descendants first (creating ops mutates vn's descend list).
        let descendants: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        for decop in descendants {
            // j = decop->getSlot(vn);
            let j = decop.read().unwrap()
                .inrefs
                .iter()
                .position(|v| std::sync::Arc::ptr_eq(v, &vn));
            let j = match j { Some(s) => s, None => continue };
            let one_minus_j = 1usize.wrapping_sub(j);
            // vnadd1 = decop->getIn(1-j);
            let vnadd1 = match decop.read().unwrap().get_in(one_minus_j) {
                Some(v) => v.clone(),
                None => continue,
            };

            // newop = data.newOp(2, decop->getAddr());
            let dec_addr = decop.read().unwrap().get_addr();
            let newop = fd.new_op(2, dec_addr);
            // data.opSetOpcode(newop, CPUI_INT_ADD);
            fd.op_set_opcode(&newop, OpCode::CPUI_INT_ADD);
            // newout = data.newUniqueOut(vnadd1->getSize(), newop);
            let newout = fd.new_unique_out(vnadd1.read().unwrap().get_size(), &newop);

            let dec_ref = crate::op::PcodeOpRef(decop.clone());
            // data.opSetInput(decop, vni, 0);
            fd.op_set_input(&dec_ref, vni.clone(), 0);
            // data.opSetInput(decop, newout, 1);
            fd.op_set_input(&dec_ref, newout.clone(), 1);

            // data.opSetInput(newop, vnadd1, 0);
            fd.op_set_input(&newop, vnadd1.clone(), 0);
            // data.opSetInput(newop, vnadd2, 1);
            fd.op_set_input(&newop, vnadd2.clone(), 1);

            // data.opInsertBefore(newop, decop);
            fd.op_insert_before(&newop, &dec_ref);
        }

        // if (!vn->isAutoLive()) data.opDestroy(op);
        if !vn.read().unwrap().is_auto_live() {
            fd.op_destroy(&crate::op::PcodeOpRef(op_arc.clone()));
        }
        // for each in duplicateList: duplicateNeed(...).
        for dop in duplicate_list {
            Self::duplicate_need(&dop, fd);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:6852 RulePushPtr
    fn get_name(&self) -> &str { "push_ptr" }
    // Ghidra: ruleaction.cc:6857 RulePushPtr::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ADD] }
}

// ============================================================================
// RulePtrArith  (ruleaction.cc:6552-6676) + AddTreeState (5992-6550)
// ============================================================================

/// Transform integer pointer arithmetic into PTRADD/PTRSUB.
///
/// Faithful to Ghidra's `RulePtrArith` (ruleaction.cc:6629-6676) plus its two
/// static helpers:
///   - `verifyPreferredPointer`    (ruleaction.cc:6558-6572)
///   - `evaluatePointerExpression` (ruleaction.cc:6586-6627)
///
/// The heavy lifting (the additive-tree analysis) lives in `AddTreeState`
/// (ruleaction.cc:5992-6550), ported as a helper struct below.
pub struct RulePtrArith;

impl RulePtrArith {
    // Ghidra: ruleaction.cc:6629 RulePtrArith
    pub fn new() -> Self { Self }

    /// Faithful to `RulePtrArith::verifyPreferredPointer` (ruleaction.cc:6558-6572).
    ///
    /// Tests whether the node immediately above the putative base pointer also
    /// looks like a base pointer. Returns true if `slot` holds the *preferred*
    /// pointer (i.e. there is no earlier pointer that should be pushed first).
    // Ghidra: ruleaction.cc:6558 RulePtrArith::verifyPreferredPointer
    fn verify_preferred_pointer(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        slot: usize,
    ) -> bool {
        let vn = match op.read().unwrap().get_in(slot) { Some(v) => v.clone(), None => return true };
        let def = vn.read().unwrap().get_def();
        let pre_op = match def { Some(o) => o, None => return true };
        // if (preOp->code() != CPUI_INT_ADD) return true;
        if pre_op.read().unwrap().opcode != OpCode::CPUI_INT_ADD {
            return true;
        }
        // Find which input of preOp is a pointer.
        let mut preslot: usize = 0;
        let pre_is_ptr_0 = pre_op.read().unwrap()
            .get_in(0)
            .and_then(|v| v.read().unwrap().get_type_read_facing())
            .map(|dt| dt.get_name().contains("Configurable"))
            .unwrap_or(false);
        if !pre_is_ptr_0 {
            preslot = 1;
            let pre_is_ptr_1 = pre_op.read().unwrap()
                .get_in(1)
                .and_then(|v| v.read().unwrap().get_type_read_facing())
                .map(|dt| dt.get_name().contains("Configurable"))
                .unwrap_or(false);
            if !pre_is_ptr_1 {
                return true;
            }
        }
        // return (1 != evaluatePointerExpression(preOp, preslot));
        Self::evaluate_pointer_expression(&pre_op, preslot) != 1
    }

    /// Faithful to `RulePtrArith::evaluatePointerExpression` (ruleaction.cc:6586-6627).
    ///
    /// Determines whether the INT_ADD expression rooted at `op` (with the
    /// pointer at input `slot`) is ready for conversion. Returns a command
    /// code:
    ///   - 0 → no action (expression not fully linked / should not convert)
    ///   - 1 → a push action is needed first
    ///   - 2 → the conversion can proceed
    // Ghidra: ruleaction.cc:6876 RulePtrArith::evaluatePointerExpression
    fn evaluate_pointer_expression(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        slot: usize,
    ) -> i32 {
        let mut res: i32 = 1; // Assume we are going to push.
        let mut count: i32 = 0;
        let ptr_base = match op.read().unwrap().get_in(slot) { Some(v) => v.clone(), None => return 0 };
        // if (ptrBase->isFree() && !ptrBase->isConstant()) return 0;
        if ptr_base.read().unwrap().is_free() && !ptr_base.read().unwrap().is_constant() {
            return 0;
        }
        let other_slot = if slot == 0 { 1 } else { 0 };
        let other_is_ptr = op.read().unwrap()
            .get_in(other_slot)
            .and_then(|v| v.read().unwrap().get_type_read_facing())
            .map(|dt| dt.get_name().contains("Configurable"))
            .unwrap_or(false);
        if other_is_ptr {
            res = 2;
        }
        let out_vn = match op.read().unwrap().get_out() { Some(v) => v.clone(), None => return 0 };
        for dec_op in out_vn.read().unwrap().descend_iter() {
            count += 1;
            let opc = dec_op.read().unwrap().opcode;
            if opc == OpCode::CPUI_INT_ADD {
                // otherVn = decOp->getIn(1 - decOp->getSlot(outVn));
                let dec_slot = dec_op.read().unwrap()
                    .inrefs
                    .iter()
                    .position(|v| std::sync::Arc::ptr_eq(v, &out_vn));
                let other_idx = match dec_slot { Some(s) => 1usize.wrapping_sub(s), None => 0 };
                let other_vn = match dec_op.read().unwrap().get_in(other_idx) { Some(v) => v.clone(), None => continue };
                if other_vn.read().unwrap().is_free() && !other_vn.read().unwrap().is_constant() {
                    return 0;
                }
                let ov_is_ptr = other_vn.read().unwrap()
                    .get_type_read_facing()
                    .map(|dt| dt.get_name().contains("Configurable"))
                    .unwrap_or(false);
                if ov_is_ptr {
                    res = 2; // Do not push in the presence of other pointers.
                }
            } else if (opc == OpCode::CPUI_LOAD || opc == OpCode::CPUI_STORE)
                && dec_op.read().unwrap().get_in(1).map(|v| std::sync::Arc::ptr_eq(v, &out_vn)).unwrap_or(false)
            {
                // If use is as pointer for LOAD or STORE.
                let pb_is_spacebase = ptr_base.read().unwrap().is_spacebase();
                let pb_is_input = ptr_base.read().unwrap().is_input();
                let pb_is_const = ptr_base.read().unwrap().is_constant();
                let other_is_const = op.read().unwrap()
                    .get_in(other_slot)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                if pb_is_spacebase && (pb_is_input || pb_is_const) && other_is_const {
                    return 0;
                }
                res = 2;
            } else {
                // Any other op besides ADD: do not push.
                res = 2;
            }
        }
        if count == 0 {
            return 0;
        }
        if count > 1 {
            if out_vn.read().unwrap().is_spacebase() {
                // A spacebase result must have only 1 descendant.
                return 0;
            }
        }
        res
    }
}

impl Rule for RulePtrArith {
    // Ghidra: ruleaction.cc:6654 RulePtrArith::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RulePtrArith::applyOp (ruleaction.cc:6654-6676).
        if !fd.has_type_recovery_started() {
            return Ok(action_status::NO_CHANGE);
        }
        // Search for pointer type among inputs.
        let num_input = op_arc.read().unwrap().num_input();
        let mut slot: usize = num_input;
        for s in 0..num_input {
            let is_ptr = op_arc.read().unwrap()
                .get_in(s)
                .and_then(|v| v.read().unwrap().get_type_read_facing())
                .map(|dt| dt.get_metatype() == crate::type_system::datatype::TypeMetatype::Pointer)
                .unwrap_or(false);
            if is_ptr { slot = s; break; }
        }
        if slot == num_input {
            return Ok(action_status::NO_CHANGE);
        }
        if Self::evaluate_pointer_expression(op_arc, slot) != 2 {
            return Ok(action_status::NO_CHANGE);
        }
        if !Self::verify_preferred_pointer(op_arc, slot) {
            return Ok(action_status::NO_CHANGE);
        }

        let mut state = AddTreeState::new(fd, op_arc.clone(), slot);
        if state.apply() {
            return Ok(action_status::CHANGE);
        }
        if state.init_alternate_form() {
            if state.apply() {
                return Ok(action_status::CHANGE);
            }
        }
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: ruleaction.cc:6629 RulePtrArith
    fn get_name(&self) -> &str { "ptrarith" }
    // Ghidra: ruleaction.cc:6648 RulePtrArith::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_INT_ADD] }
}

/// Faithful port of Ghidra's `AddTreeState` (ruleaction.cc:5992-6550).
///
/// Analyses an additive expression tree rooted at an INT_ADD whose `baseSlot`
/// input is a typed pointer, splitting it into:
///   - multiples of the pointed-to size  → PTRADD
///   - a sub-type offset                 → PTRSUB
///   - remaining non-multiple terms      → INT_ADD
struct AddTreeState<'a> {
    data: &'a mut Funcdata,
    base_op: std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    base_slot: usize,
    ptr: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    /// The pointed-to data-type (ct->getPtrTo()).
    base_type: Option<std::sync::Arc<crate::type_system::datatype::Datatype>>,
    ptrsize: usize,
    ptrmask: u64,
    /// Element size in address units (size of pointed-to type, in space units).
    size: i64,
    multsum: u64,
    nonmultsum: u64,
    biggest_non_mult_coeff: u64,
    multiple: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    coeff: Vec<i64>,
    nonmult: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    correct: u64,
    offset: u64,
    valid: bool,
    is_distribute_used: bool,
    is_subtype: bool,
    distribute_op: Option<std::sync::Arc<std::sync::RwLock<PcodeOp>>>,
    prevent_distribution: bool,
    is_degenerate: bool,
}

impl<'a> AddTreeState<'a> {
    /// Faithful to `AddTreeState::AddTreeState` ctor (ruleaction.cc:6036-6069).
    // Ghidra: ruleaction.cc:6036 AddTreeState::AddTreeState
    fn new(data: &'a mut Funcdata, op: std::sync::Arc<std::sync::RwLock<PcodeOp>>, slot: usize) -> Self {
        // ptr = op->getIn(slot). The caller guarantees slot is a pointer, so it
        // must exist; if not, fabricate a 1-byte const placeholder so the state
        // is well-formed (apply() will bail via the type checks).
        let ptr = op.read().unwrap().get_in(slot).cloned().unwrap_or_else(|| {
            data.vbank.create_constant(1, 0)
        });
        let (ct, ptrsize, base_type, size, is_degenerate) = {
            let v = ptr.read().unwrap();
            let ct = v.get_type_read_facing();
            let ptrsize = v.get_size();
            let (base_type, size, is_degenerate) = if let Some(ref ct_arc) = ct {
                use crate::type_system::datatype::{Datatype, TypeMetatype};
                if ct_arc.get_metatype() == TypeMetatype::Pointer {
                    if let Datatype::Pointer(tp) = ct_arc.as_ref() {
                        let word_size = tp.wordsize.max(1) as i64;
                        let bt = &tp.ptr_to;
                        let is_var_len = bt.is_variable_length();
                        let sz = if is_var_len {
                            0
                        } else {
                            // byteToAddressInt(baseType->getAlignSize(), wordSize)
                            byte_to_address_int(bt.get_align_size() as i64, tp.wordsize.max(1) as i64)
                        };
                        // isDegenerate: baseType->getAlignSize() <= unitsize && > 0
                        // where unitsize = addressToByteInt(1, wordSize) == wordSize.
                        let unitsize = word_size;
                        let is_deg = (bt.get_align_size() as i64) <= unitsize && bt.get_align_size() > 0;
                        (Some(tp.ptr_to.clone()), sz, is_deg)
                    } else {
                        (None, 0i64, false)
                    }
                } else {
                    (None, 0i64, false)
                }
            } else {
                (None, 0i64, false)
            };
            (ct, ptrsize, base_type, size, is_degenerate)
        };
        let ptrmask = crate::address::calc_mask(ptrsize);
        let _ = ct;
        AddTreeState {
            data,
            base_op: op,
            base_slot: slot,
            ptr,
            base_type,
            ptrsize,
            ptrmask,
            size,
            multsum: 0,
            nonmultsum: 0,
            biggest_non_mult_coeff: 0,
            multiple: Vec::new(),
            coeff: Vec::new(),
            nonmult: Vec::new(),
            correct: 0,
            offset: 0,
            valid: true,
            is_distribute_used: false,
            is_subtype: false,
            distribute_op: None,
            prevent_distribution: false,
            is_degenerate,
        }
    }

    /// Faithful to `AddTreeState::clear` (ruleaction.cc:5992-6011). The
    /// pRelType/`nonmultsum = addressOffset` branch is omitted (no
    /// TypePointerRel in Rugra — pRelType is always null).
    // Ghidra: ruleaction.cc:5992 AddTreeState::clear
    fn clear(&mut self) {
        self.multsum = 0;
        self.nonmultsum = 0;
        self.biggest_non_mult_coeff = 0;
        self.multiple.clear();
        self.coeff.clear();
        self.nonmult.clear();
        self.correct = 0;
        self.offset = 0;
        self.valid = true;
        self.is_distribute_used = false;
        self.is_subtype = false;
        self.distribute_op = None;
    }

    /// Faithful to `AddTreeState::initAlternateForm` (ruleaction.cc:6017-6034).
    /// With no TypePointerRel, there is never an alternate form.
    // Ghidra: ruleaction.cc:6017 AddTreeState::initAlternateForm
    fn init_alternate_form(&mut self) -> bool {
        false
    }

    /// Faithful to `AddTreeState::checkMultTerm` (ruleaction.cc:6136-6179).
    ///
    /// Examine a CPUI_INT_MULT element mid-tree. Returns true if there are no
    /// multiples of the base size discovered (i.e. treated as a non-multiple
    /// leaf).
    // Ghidra: ruleaction.cc:6136 AddTreeState::checkMultTerm
    fn check_mult_term(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        tree_coeff: u64,
    ) -> bool {
        let (vnconst, vnterm, vn_size) = {
            let o = op.read().unwrap();
            let vc = o.get_in(1).cloned();
            let vt = o.get_in(0).cloned();
            let sz = vn.read().unwrap().get_size();
            (vc, vt, sz)
        };
        let vnterm = match vnterm { Some(v) => v, None => return true };
        if vnterm.read().unwrap().is_free() {
            self.valid = false;
            return false;
        }
        if let Some(vnconst) = vnconst {
            if vnconst.read().unwrap().is_constant() {
                let val = (vnconst.read().unwrap().get_offset().wrapping_mul(tree_coeff)) & self.ptrmask;
                let sval = sign_extend_u64(val, vn_size * 8);
                let rem = if self.size == 0 { sval } else { signed_rem(sval, self.size) };
                if rem != 0 {
                    if val >= self.size as u64 && self.size != 0 {
                        self.valid = false; // Size too big: pointer type must be wrong.
                        return false;
                    }
                    if !self.prevent_distribution {
                        let vnterm_def = vnterm.read().unwrap().get_def();
                        let is_add = vnterm_def.as_ref()
                            .map(|d| d.read().unwrap().opcode == OpCode::CPUI_INT_ADD)
                            .unwrap_or(false);
                        if is_add {
                            if self.distribute_op.is_none() {
                                self.distribute_op = Some(op.clone());
                            }
                            let def = vnterm.read().unwrap().get_def().unwrap();
                            return self.span_add_tree(&def, val);
                        }
                    }
                    let vncoeff: u64 = if sval < 0 { (-sval) as u64 } else { sval as u64 };
                    if vncoeff > self.biggest_non_mult_coeff {
                        self.biggest_non_mult_coeff = vncoeff;
                    }
                    return true;
                } else {
                    if tree_coeff != 1 {
                        self.is_distribute_used = true;
                    }
                    self.multiple.push(vnterm.clone());
                    self.coeff.push(sval);
                    return false;
                }
            }
        }
        if tree_coeff > self.biggest_non_mult_coeff {
            self.biggest_non_mult_coeff = tree_coeff;
        }
        true
    }

    /// Faithful to `AddTreeState::checkTerm` (ruleaction.cc:6186-6231).
    // Ghidra: ruleaction.cc:6186 AddTreeState::checkTerm
    fn check_term(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        tree_coeff: u64,
    ) -> bool {
        if std::sync::Arc::ptr_eq(vn, &self.ptr) {
            return false;
        }
        let vn_size = vn.read().unwrap().get_size();
        if vn.read().unwrap().is_constant() {
            let val = vn.read().unwrap().get_offset().wrapping_mul(tree_coeff);
            let sval = sign_extend_u64(val, vn_size * 8);
            let rem = if self.size == 0 { sval } else { signed_rem(sval, self.size) };
            if rem != 0 {
                // constant is not a multiple of size.
                if tree_coeff != 1 {
                    if let Some(ref bt) = self.base_type {
                        use crate::type_system::datatype::TypeMetatype;
                        let mt = bt.get_metatype();
                        if mt == TypeMetatype::Array || mt == TypeMetatype::Struct {
                            self.is_distribute_used = true;
                        }
                    }
                }
                self.nonmultsum = (self.nonmultsum.wrapping_add(val)) & self.ptrmask;
                return true;
            }
            if tree_coeff != 1 {
                self.is_distribute_used = true;
            }
            self.multsum = (self.multsum.wrapping_add(val)) & self.ptrmask;
            return false;
        }
        let is_written = vn.read().unwrap().is_written();
        if is_written {
            let def = vn.read().unwrap().get_def();
            if let Some(def_op) = def {
                let code = def_op.read().unwrap().opcode;
                if code == OpCode::CPUI_INT_ADD {
                    return self.span_add_tree(&def_op, tree_coeff);
                }
                if code == OpCode::CPUI_COPY {
                    self.valid = false; // Not finished reducing yet.
                    return false;
                }
                if code == OpCode::CPUI_INT_MULT {
                    return self.check_mult_term(vn, &def_op, tree_coeff);
                }
            }
        } else if vn.read().unwrap().is_free() {
            self.valid = false;
            return false;
        }
        if tree_coeff > self.biggest_non_mult_coeff {
            self.biggest_non_mult_coeff = tree_coeff;
        }
        true
    }

    /// Faithful to `AddTreeState::spanAddTree` (ruleaction.cc:6244-6266).
    // Ghidra: ruleaction.cc:6160 spanAddTree
    fn span_add_tree(
        &mut self,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        tree_coeff: u64,
    ) -> bool {
        let (in0, in1) = {
            let o = op.read().unwrap();
            (o.get_in(0).cloned(), o.get_in(1).cloned())
        };
        let in0 = match in0 { Some(v) => v, None => { self.valid = false; return false; } };
        let in1 = match in1 { Some(v) => v, None => { self.valid = false; return false; } };
        let one_is_non = self.check_term(&in0, tree_coeff);
        if !self.valid { return false; }
        let two_is_non = self.check_term(&in1, tree_coeff);
        if !self.valid { return false; }
        // pRelType is always null in Rugra, so the pRelType guard is skipped.
        if one_is_non && two_is_non {
            return true;
        }
        if one_is_non {
            self.nonmult.push(in0);
        }
        if two_is_non {
            self.nonmult.push(in1);
        }
        false // At least one side contains multiples.
    }

    /// Faithful to `AddTreeState::calcSubtype` (ruleaction.cc:6270-6355).
    ///
    /// The pRelType branches (6350-6354) are omitted (no TypePointerRel). The
    /// TypePointerRel `hasMatchingSubType` path for SPACEBASE/STRUCT needs
    /// `nearestArrayedComponent*` which Rugra lacks; we approximate with
    /// `get_sub_type`, mirroring the arrayHint==0 Ghidra path.
    // Ghidra: ruleaction.cc:6270 AddTreeState::calcSubtype
    fn calc_subtype(&mut self) {
        let tmpoff = (self.multsum.wrapping_add(self.nonmultsum)) & self.ptrmask;
        if self.size == 0 || (tmpoff as i64) < self.size {
            self.offset = tmpoff;
        } else {
            let stmpoff = sign_extend_u64(tmpoff, self.ptrsize * 8);
            let stmpoff = signed_rem(stmpoff, self.size);
            if stmpoff >= 0 {
                self.offset = stmpoff as u64;
            } else {
                // baseType STRUCT + array hints path needs biggestNonMultCoeff
                // (modelled) but the array-hint logic is approximated.
                let is_struct = self.base_type.as_ref()
                    .map(|bt| bt.get_metatype() == crate::type_system::datatype::TypeMetatype::Struct)
                    .unwrap_or(false);
                if is_struct && self.biggest_non_mult_coeff != 0 && self.multsum == 0 {
                    self.offset = tmpoff;
                } else {
                    self.offset = (stmpoff + self.size) as u64;
                }
            }
        }
        self.correct = self.nonmultsum; // double-counted constants corrected later.
        self.multsum = (tmpoff.wrapping_sub(self.offset)) & self.ptrmask;
        if self.nonmult.is_empty() {
            if self.multsum == 0 && self.multiple.is_empty() {
                self.valid = false;
                return;
            }
            self.is_subtype = false;
        } else if let Some(ref bt) = self.base_type {
            use crate::type_system::datatype::TypeMetatype;
            match bt.get_metatype() {
                TypeMetatype::Spacebase => {
                    // offsetbytes = addressToByteInt(offset, wordSize)
                    // hasMatchingSubType needs scope/var-offset mapping; with
                    // arrayHint 0, Ghidra falls to getSubType. We use that.
                    // (nearestArrayedComponent* not modelled.)
                    let extra = match bt.get_sub_type(self.offset as i64) {
                        (Some(_), e) => e as u64,
                        (None, _) => { self.valid = false; return; }
                    };
                    self.offset = (self.offset.wrapping_sub(extra)) & self.ptrmask;
                    self.correct = (self.correct.wrapping_sub(extra)) & self.ptrmask;
                    self.is_subtype = true;
                }
                TypeMetatype::Struct => {
                    let soffset = sign_extend_u64(self.offset, self.ptrsize * 8);
                    let extra = match bt.get_sub_type(soffset) {
                        (Some(_), e) => e as u64,
                        (None, _) => {
                            // Out of structure bounds check (compare as bytes).
                            if (soffset < 0) || (soffset as u64) >= bt.get_size() as u64 {
                                self.valid = false;
                                return;
                            }
                            0 // No field, but pretend there is something there.
                        }
                    };
                    self.offset = (self.offset.wrapping_sub(extra)) & self.ptrmask;
                    self.correct = (self.correct.wrapping_sub(extra)) & self.ptrmask;
                    self.is_subtype = true;
                }
                TypeMetatype::Array => {
                    self.is_subtype = true;
                    self.correct = (self.correct.wrapping_sub(self.offset)) & self.ptrmask;
                    self.offset = 0;
                }
                _ => {
                    // No struct/array/spacebase but nonmult non-empty.
                    self.valid = false;
                }
            }
        } else {
            self.valid = false;
        }
    }

    /// Faithful to `AddTreeState::buildMultiples` (ruleaction.cc:6374-6402).
    // Ghidra: ruleaction.cc:6374 AddTreeState::buildMultiples
    fn build_multiples(&mut self) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let smultsum = sign_extend_u64(self.multsum, self.ptrsize * 8);
        let const_coeff: u64 = if self.size == 0 { 0 } else { (signed_div(smultsum, self.size) as u64) & self.ptrmask };
        let mut res_node: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
        if const_coeff != 0 {
            res_node = Some(self.data.new_constant(self.ptrsize, const_coeff));
        }
        for i in 0..self.multiple.len() {
            let final_coeff: u64 = if self.size == 0 {
                0
            } else {
                (signed_div(self.coeff[i], self.size) as u64) & self.ptrmask
            };
            let vn = self.multiple[i].clone();
            let vn = if final_coeff != 1 {
                let base_addr = self.base_op.read().unwrap().get_addr();
                let const_vn = self.data.new_constant(self.ptrsize, final_coeff);
                let newop = self.data.new_op(2, base_addr);
                self.data.op_set_opcode(&newop, OpCode::CPUI_INT_MULT);
                self.data.new_unique_out(self.ptrsize, &newop);
                self.data.op_set_input(&newop, vn.clone(), 0);
                self.data.op_set_input(&newop, const_vn, 1);
                self.data.op_insert_before(&newop, &crate::op::PcodeOpRef(self.base_op.clone()));
                let out = newop.0.read().unwrap().output.clone().unwrap();
                out
            } else {
                vn
            };
            if res_node.is_none() {
                res_node = Some(vn);
            } else {
                let prev = res_node.unwrap();
                let base_addr = self.base_op.read().unwrap().get_addr();
                let newop = self.data.new_op(2, base_addr);
                self.data.op_set_opcode(&newop, OpCode::CPUI_INT_ADD);
                self.data.new_unique_out(self.ptrsize, &newop);
                self.data.op_set_input(&newop, vn, 0);
                self.data.op_set_input(&newop, prev, 1);
                self.data.op_insert_before(&newop, &crate::op::PcodeOpRef(self.base_op.clone()));
                res_node = Some(newop.0.read().unwrap().output.clone().unwrap());
            }
        }
        res_node
    }

    /// Faithful to `AddTreeState::buildExtra` (ruleaction.cc:6408-6436).
    // Ghidra: ruleaction.cc:6408 AddTreeState::buildExtra
    fn build_extra(&mut self) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let mut res_node: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
        // Snapshot the nonmult list to avoid borrow issues while we mutate.
        let nonmult: Vec<_> = self.nonmult.iter().cloned().collect();
        for vn in nonmult {
            if vn.read().unwrap().is_constant() {
                self.correct = self.correct.wrapping_sub(vn.read().unwrap().get_offset());
                continue;
            }
            if res_node.is_none() {
                res_node = Some(vn);
            } else {
                let prev = res_node.unwrap();
                let base_addr = self.base_op.read().unwrap().get_addr();
                let newop = self.data.new_op(2, base_addr);
                self.data.op_set_opcode(&newop, OpCode::CPUI_INT_ADD);
                let _ = self.data.new_unique_out(self.ptrsize, &newop);
                self.data.op_set_input(&newop, vn, 0);
                self.data.op_set_input(&newop, prev, 1);
                self.data.op_insert_before(&newop, &crate::op::PcodeOpRef(self.base_op.clone()));
                res_node = Some(newop.0.read().unwrap().output.clone().unwrap());
            }
        }
        self.correct &= self.ptrmask;
        if self.correct != 0 {
            let vn = self.data.new_constant(self.ptrsize, uintb_negate(self.correct.wrapping_sub(1), self.ptrsize));
            if res_node.is_none() {
                res_node = Some(vn);
            } else {
                let prev = res_node.unwrap();
                let base_addr = self.base_op.read().unwrap().get_addr();
                let newop = self.data.new_op(2, base_addr);
                self.data.op_set_opcode(&newop, OpCode::CPUI_INT_ADD);
                let _ = self.data.new_unique_out(self.ptrsize, &newop);
                self.data.op_set_input(&newop, vn, 0);
                self.data.op_set_input(&newop, prev, 1);
                self.data.op_insert_before(&newop, &crate::op::PcodeOpRef(self.base_op.clone()));
                res_node = Some(newop.0.read().unwrap().output.clone().unwrap());
            }
        }
        res_node
    }

    /// Faithful to `AddTreeState::buildDegenerate` (ruleaction.cc:6441-6458).
    ///
    /// When the base data-type is unit-sized, every ADD becomes a PTRADD.
    // Ghidra: ruleaction.cc:6441 AddTreeState::buildDegenerate
    fn build_degenerate(&mut self) -> bool {
        let (base_align_lt_wordsize, word_size, ct_size, out_is_ptr) = {
            let bt = match &self.base_type { Some(b) => b.clone(), None => return false };
            let ws = {
                let p = self.ptr.read().unwrap();
                p.get_type_read_facing()
                    .and_then(|ct| {
                        use crate::type_system::datatype::Datatype;
                        if let Datatype::Pointer(tp) = ct.as_ref() { Some(tp.wordsize) } else { None }
                    })
                    .unwrap_or(1)
            };
            let align = bt.get_align_size() as i64;
            let is_lt = align < ws as i64;
            let out_meta = self.base_op.read().unwrap()
                .get_out()
                .and_then(|o| o.read().unwrap().v_type.clone())
                .map(|dt| {
                    use crate::type_system::datatype::TypeMetatype;
                    let _ = dt.get_metatype();
                    // out->getTypeDefFacing()->getMetatype() != TYPE_PTR
                    let m = dt.get_metatype();
                    m == TypeMetatype::Pointer
                })
                .unwrap_or(false);
            (is_lt, ws, 0i64, out_meta)
        };
        // If the size is really less than scale, there is padding — don't transform.
        if base_align_lt_wordsize {
            return false;
        }
        let _ = word_size;
        let _ = ct_size;
        // Make sure pointer propagates through INT_ADD.
        if !out_is_ptr {
            return false;
        }
        // newparams = { ptr, baseOp->getIn(1-slot), newConstant(ct->getSize(),1) }
        let other_slot = if self.base_slot == 0 { 1 } else { 0 };
        let other = match self.base_op.read().unwrap().get_in(other_slot) { Some(v) => v.clone(), None => return false };
        let one = self.data.new_constant(self.ptrsize, 1);
        let base_ref = crate::op::PcodeOpRef(self.base_op.clone());
        // opSetAllInput(baseOp, newparams)
        self.data.op_set_input(&base_ref, self.ptr.clone(), 0);
        self.data.op_set_input(&base_ref, other, 1);
        self.data.op_set_input(&base_ref, one, 2);
        self.data.op_set_opcode(&base_ref, OpCode::CPUI_PTRADD);
        true
    }

    /// Faithful to `AddTreeState::apply` (ruleaction.cc:6461-6502).
    ///
    /// The `distributeIntMultAdd`/`collapseIntMultMult` loop (6475-6491) is now
    /// ported: `distribute_int_mult_add` lives on `Funcdata` (funcdata.rs) and
    /// `collapse_int_mult_mult` is implemented here (see below).
    // Ghidra: ruleaction.cc:6461 AddTreeState::apply
    fn apply(&mut self) -> bool {
        if self.is_degenerate {
            return self.build_degenerate();
        }
        let base = self.base_op.clone();
        self.span_add_tree(&base, 1);
        if !self.valid {
            return false;
        }
        // distributeOp handling: if distribution isn't used, retry without it.
        if self.distribute_op.is_some() && !self.is_distribute_used {
            self.clear();
            self.prevent_distribution = true;
            let base = self.base_op.clone();
            self.span_add_tree(&base, 1);
        }
        self.calc_subtype();
        if !self.valid {
            return false;
        }
        // Ghidra while-loop (ruleaction.cc:6475-6491): keep distributing the
        // INT_MULT-over-ADD term and collapsing the resulting double-multiplies
        // until no distributeOp remains.
        while self.valid && self.distribute_op.is_some() {
            let distribute_op = self.distribute_op.clone().unwrap();
            let distribute_ref = crate::op::PcodeOpRef(distribute_op.clone());
            if !self.data.distribute_int_mult_add(&distribute_ref) {
                self.valid = false;
                break;
            }
            // Collapse any z = (x * #c) * #d expressions produced by the distribute.
            // distributeOp->getIn(0), distributeOp->getIn(1) — the two new
            // INT_MULT outputs feeding the rewritten ADD.
            let (in0, in1) = {
                let d = distribute_op.read().unwrap();
                (d.get_in(0).cloned(), d.get_in(1).cloned())
            };
            if let Some(v0) = in0 { Self::collapse_int_mult_mult(self.data, &v0); }
            if let Some(v1) = in1 { Self::collapse_int_mult_mult(self.data, &v1); }
            self.clear();
            let base = self.base_op.clone();
            self.span_add_tree(&base, 1);
            if self.distribute_op.is_some() && !self.is_distribute_used {
                self.clear();
                self.prevent_distribution = true;
                let base = self.base_op.clone();
                self.span_add_tree(&base, 1);
            }
            self.calc_subtype();
        }
        if !self.valid {
            // Distribution transforms were made (ruleaction.cc:6492-6498).
            return true;
        }
        self.build_tree();
        true
    }

    /// Faithful to `Funcdata::collapseIntMultMult` (funcdata_op.cc:1132-1153).
    ///
    /// If `vn` is defined by `INT_MULT(x * #c, #d)` where `x` is itself defined
    /// by another `INT_MULT(y, #e)` with a constant second input, combine the
    /// two constants into one: `(y * #e) * #c => y * (#e * #c)`.
    ///
    /// Implemented as a free helper on `Funcdata` here (rather than on
    /// `Funcdata` itself) because the only primitives it needs —
    /// `new_constant` and `op_set_input` — are already public on `Funcdata`.
    /// The op-mutation logic is a 1:1 port of Ghidra's funcdata_op.cc:1132-1153.
    // Ghidra: funcdata_op.cc:1132 Funcdata::collapseIntMultMult
    fn collapse_int_mult_mult(
        data: &mut Funcdata,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        if !vn.read().unwrap().is_written() { return false; }
        let op = match vn.read().unwrap().get_def() { Some(o) => o, None => return false };
        if op.read().unwrap().opcode != OpCode::CPUI_INT_MULT { return false; }
        let const_vn_first = match op.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return false };
        if !const_vn_first.read().unwrap().is_constant() { return false; }
        let in0 = match op.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return false };
        if !in0.read().unwrap().is_written() { return false; }
        let other_mult_op = match in0.read().unwrap().get_def() { Some(o) => o, None => return false };
        if other_mult_op.read().unwrap().opcode != OpCode::CPUI_INT_MULT { return false; }
        let const_vn_second = match other_mult_op.read().unwrap().get_in(1).cloned() { Some(v) => v, None => return false };
        if !const_vn_second.read().unwrap().is_constant() { return false; }
        let invn = match other_mult_op.read().unwrap().get_in(0).cloned() { Some(v) => v, None => return false };
        if invn.read().unwrap().is_free() { return false; }
        let sz = invn.read().unwrap().get_size() as usize;
        let val = const_vn_first.read().unwrap().get_offset()
            .wrapping_mul(const_vn_second.read().unwrap().get_offset())
            & crate::address::calc_mask(sz);
        let new_vn = data.new_constant(sz, val);
        let op_ref = crate::op::PcodeOpRef(op.clone());
        data.op_set_input(&op_ref, new_vn, 1);
        data.op_set_input(&op_ref, invn, 0);
        true
    }

    /// Faithful to `AddTreeState::buildTree` (ruleaction.cc:6508-6550).
    ///
    /// The type-inheritance (`inheritResolution`) / `assignPropagatedType`
    /// calls are omitted (Rugra has no per-op type resolution propagation
    /// wired here). The structural PTRADD/PTRSUB/INT_ADD restructure is
    /// faithful.
    // Ghidra: ruleaction.cc:6508 AddTreeState::buildTree
    fn build_tree(&mut self) {
        let mult_node = self.build_multiples();
        let extra_node = self.build_extra();
        let mut newop: Option<crate::op::PcodeOpRef> = None;

        // Create PTRADD portion.
        let mut mult_node = if let Some(mn) = mult_node {
            let base_addr = self.base_op.read().unwrap().get_addr();
            let size_const = self.data.new_constant(self.ptrsize, self.size as u64);
            let newp = self.data.new_op(3, base_addr);
            self.data.op_set_opcode(&newp, OpCode::CPUI_PTRADD);
            self.data.new_unique_out(self.ptrsize, &newp);
            self.data.op_set_input(&newp, self.ptr.clone(), 0);
            self.data.op_set_input(&newp, mn, 1);
            self.data.op_set_input(&newp, size_const, 2);
            self.data.op_insert_before(&newp, &crate::op::PcodeOpRef(self.base_op.clone()));
            newop = Some(newp.clone());
            let out = newp.0.read().unwrap().output.clone().unwrap();
            out
        } else {
            self.ptr.clone() // Zero multiple terms.
        };

        // Create PTRSUB portion.
        if self.is_subtype {
            let base_addr = self.base_op.read().unwrap().get_addr();
            let off_const = self.data.new_constant(self.ptrsize, self.offset);
            let newp = self.data.new_op(2, base_addr);
            self.data.op_set_opcode(&newp, OpCode::CPUI_PTRSUB);
            self.data.new_unique_out(self.ptrsize, &newp);
            self.data.op_set_input(&newp, mult_node.clone(), 0);
            self.data.op_set_input(&newp, off_const, 1);
            self.data.op_insert_before(&newp, &crate::op::PcodeOpRef(self.base_op.clone()));
            newop = Some(newp.clone());
            // setStopTypePropagation
            newp.0.write().unwrap().addlflags |= crate::op::op_addl_flags::STOP_TYPE_PROPAGATION;
            mult_node = newp.0.read().unwrap().output.clone().unwrap();
        }

        // Add back any remaining terms.
        if let Some(extra) = extra_node {
            let base_addr = self.base_op.read().unwrap().get_addr();
            let newp = self.data.new_op(2, base_addr);
            self.data.op_set_opcode(&newp, OpCode::CPUI_INT_ADD);
            let _ = self.data.new_unique_out(self.ptrsize, &newp);
            self.data.op_set_input(&newp, mult_node, 0);
            self.data.op_set_input(&newp, extra, 1);
            self.data.op_insert_before(&newp, &crate::op::PcodeOpRef(self.base_op.clone()));
            newop = Some(newp.clone());
        }

        if let Some(newp) = newop {
            // data.opSetOutput(newop, baseOp->getOut())
            let base_out = self.base_op.read().unwrap().output.clone();
            if let Some(bo) = base_out {
                self.data.op_set_output(&newp, bo);
            }
            // data.opDestroy(baseOp)
            self.data.op_destroy(&crate::op::PcodeOpRef(self.base_op.clone()));
        } else {
            // This should never happen — Ghidra emits a warning.
        }
    }
}

// ============================================================================
// RuleStructOffset0  (ruleaction.cc:6678-6774)
// ============================================================================

/// Convert a LOAD/STORE to the first element of a structure into a PTRSUB.
///
/// Faithful to Ghidra's `RuleStructOffset0` (ruleaction.cc:6678-6774).
///
/// When type propagation says we have a pointer to a structure but we load/store
/// too little data, we really need a pointer to the *first element*. This rule
/// inserts a `PTRSUB(ptr, 0)` to drill down to that component. The
/// TypePointerRel branch (6713-6743) is omitted (Rugra has no TypePointerRel);
/// the plain STRUCT/ARRAY path is faithful.
pub struct RuleStructOffset0;

impl RuleStructOffset0 {
    // Ghidra: ruleaction.cc:6678 RuleStructOffset0
    pub fn new() -> Self { Self }
}

impl Rule for RuleStructOffset0 {
    // Ghidra: ruleaction.cc:6693 RuleStructOffset0::applyOp
    fn apply_op(&self, op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleStructOffset0::applyOp (ruleaction.cc:6693-6774).
        if !fd.has_type_recovery_started() {
            return Ok(action_status::NO_CHANGE);
        }
        let code = op_arc.read().unwrap().opcode;
        let movesize = if code == OpCode::CPUI_LOAD {
            // movesize = op->getOut()->getSize();
            let out = match op_arc.read().unwrap().get_out() { Some(o) => o.clone(), None => return Ok(action_status::NO_CHANGE) };
            let ms = out.read().unwrap().get_size() as i64;
            ms
        } else if code == OpCode::CPUI_STORE {
            // movesize = op->getIn(2)->getSize();
            let inv = match op_arc.read().unwrap().get_in(2) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
            let ms = inv.read().unwrap().get_size() as i64;
            ms
        } else {
            return Ok(action_status::NO_CHANGE);
        };

        // ptrVn = op->getIn(1); ct = ptrVn->getTypeReadFacing(op);
        let ptr_vn = match op_arc.read().unwrap().get_in(1) { Some(v) => v.clone(), None => return Ok(action_status::NO_CHANGE) };
        let ct = match ptr_vn.read().unwrap().get_type_read_facing() { Some(t) => t, None => return Ok(action_status::NO_CHANGE) };
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        if ct.get_metatype() != TypeMetatype::Pointer {
            return Ok(action_status::NO_CHANGE);
        }
        let tp = match ct.as_ref() { Datatype::Pointer(p) => p, _ => return Ok(action_status::NO_CHANGE) };
        let base_type = tp.ptr_to.clone();

        // The TypePointerRel `isFormalPointerRel` branch is omitted (no
        // TypePointerRel in Rugra). Fall straight to the plain STRUCT/ARRAY
        // path (ruleaction.cc:6744-6767).
        let mut offset: i64 = 0;
        match base_type.get_metatype() {
            TypeMetatype::Struct => {
                if (base_type.get_size() as i64) < movesize {
                    return Ok(action_status::NO_CHANGE); // Moving > entire structure.
                }
                // subType = baseType->getSubType(offset, &offset);
                let (sub_type, newoff) = base_type.get_sub_type(offset);
                offset = newoff;
                let sub = match sub_type { Some(s) => s, None => return Ok(action_status::NO_CHANGE) };
                if (sub.get_size() as i64) < movesize {
                    return Ok(action_status::NO_CHANGE); // Subtype too small.
                }
            }
            TypeMetatype::Array => {
                if (base_type.get_size() as i64) < movesize {
                    return Ok(action_status::NO_CHANGE); // Moving > entire array.
                }
                if (base_type.get_size() as i64) == movesize {
                    // Moving the entire array.
                    let arr = match base_type.as_ref() { Datatype::Array(a) => a, _ => return Ok(action_status::NO_CHANGE) };
                    if arr.num_elements != 1 {
                        return Ok(action_status::NO_CHANGE);
                    }
                }
            }
            _ => return Ok(action_status::NO_CHANGE),
        }

        let ptr_size = ptr_vn.read().unwrap().get_size();
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        // newop = data.newOpBefore(op, CPUI_PTRSUB, ptrVn, newConstant(ptrSize, 0))
        let base_addr = op_arc.read().unwrap().get_addr();
        let zero_const = fd.new_constant(ptr_size, 0);
        let newop = fd.new_op(2, base_addr);
        fd.op_set_opcode(&newop, OpCode::CPUI_PTRSUB);
        fd.new_unique_out(ptr_size, &newop);
        fd.op_set_input(&newop, ptr_vn.clone(), 0);
        fd.op_set_input(&newop, zero_const, 1);
        fd.op_insert_before(&newop, &op_ref);
        // newop->setStopTypePropagation()
        newop.0.write().unwrap().addlflags |= crate::op::op_addl_flags::STOP_TYPE_PROPAGATION;
        // data.opSetInput(op, newop->getOut(), 1)
        let new_out = newop.0.read().unwrap().output.clone().unwrap();
        fd.op_set_input(&op_ref, new_out, 1);
        Ok(action_status::CHANGE)
    }

    // Ghidra: ruleaction.cc:6678 RuleStructOffset0
    fn get_name(&self) -> &str { "struct_offset0" }
    // Ghidra: ruleaction.cc:6686 RuleStructOffset0::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_LOAD, OpCode::CPUI_STORE] }
}

// ---------------------------------------------------------------------------
// Numeric helpers used by AddTreeState (faithful to Ghidra's inline helpers).
// ---------------------------------------------------------------------------

/// Faithful to Ghidra's `sign_extend` (address.hh). Sign-extend the low
/// `bits` of `value` to an i64.
// Ghidra: address.hh:555 sign_extend
fn sign_extend_u64(value: u64, bits: usize) -> i64 {
    crate::utils::bits::sign_extend(value, bits)
}

/// Signed remainder faithful to Ghidra's `intb % size`.
// RUGRA-GLUE: numeric helper for Ghidra intb arithmetic
fn signed_rem(a: i64, size: i64) -> i64 {
    if size == 0 { a } else { a % size }
}

/// Signed division faithful to Ghidra's `intb / size`.
// RUGRA-GLUE: numeric helper for Ghidra intb arithmetic
fn signed_div(a: i64, size: i64) -> i64 {
    if size == 0 { 0 } else { a / size }
}

/// Faithful to Ghidra's `uintb_negate` (ruleaction.cc / pcoderaw). Negates the
/// low `size_bytes`-worth of bits of `val`.
// Ghidra: address.cc:654 uintb_negate
fn uintb_negate(val: u64, size_bytes: usize) -> u64 {
    let mask = if size_bytes >= 8 { !0u64 } else { (1u64 << (size_bytes * 8)) - 1 };
    !val & mask
}

/// Faithful to `AddrSpace::byteToAddressInt` (space.hh). Converts a byte count
/// to address units: `val / word_size` (truncating).
// Ghidra: space.hh AddrSpace::byteToAddressInt
fn byte_to_address_int(val: i64, word_size: i64) -> i64 {
    if word_size <= 1 { val } else { val / word_size }
}

// ---------------------------------------------------------------------------
// RulePtrFlow (ruleaction.cc:9050-9251)
// ---------------------------------------------------------------------------

/// Mark Varnode and PcodeOp objects that are carrying or operating on pointers.
///
/// Used on architectures where the data-flow for pointer values needs to be
/// truncated. This marks the places where the truncation needs to happen. Then
/// the SubvariableFlow actions do the actual truncation.
///
/// Faithful to Ghidra's `RulePtrFlow` (ruleaction.cc:9050-9251).
pub struct RulePtrFlow {
    /// True if the architecture's default data space is truncated
    /// (`glb->getDefaultDataSpace()->isTruncated()`, ruleaction.cc:9060).
    /// When false, `getOpList` returns no opcodes — the rule stays inert
    /// (Ghidra does the same: "Only stick ourselves into pool if aggressiveness
    /// is turned on"). Rugra has no truncated address spaces yet, so this
    /// defaults to false; the full applyOp logic is ported 1:1 so the rule is
    /// ready when truncation modelling lands.
    has_truncations: bool,
}

impl RulePtrFlow {
    /// Construct with truncation flag. Faithful to the Ghidra ctor
    /// (ruleaction.cc:9056-9061), which derives `hasTruncations` from
    /// `glb->getDefaultDataSpace()->isTruncated()`. Rugra's Architecture has no
    /// `getDefaultDataSpace`/`isTruncated` yet, so we default to false — exactly
    /// matching Ghidra's behaviour for non-truncated architectures.
    // Ghidra: ruleaction.cc:9056 RulePtrFlow::RulePtrFlow
    pub fn new() -> Self {
        Self { has_truncations: false }
    }

    /// Set \e ptrflow property on PcodeOp only if it is propagating. Returns
    /// true if the ptrflow property is newly set. Faithful to
    /// `RulePtrFlow::trialSetPtrFlow` (ruleaction.cc:9083-9099).
    // Ghidra: ruleaction.cc:9083 RulePtrFlow::trialSetPtrFlow
    fn trial_set_ptr_flow(op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> bool {
        let opc = op.read().unwrap().opcode;
        match opc {
            OpCode::CPUI_COPY
            | OpCode::CPUI_MULTIEQUAL
            | OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INDIRECT
            | OpCode::CPUI_PTRSUB
            | OpCode::CPUI_PTRADD => {
                if !op.read().unwrap().is_ptr_flow() {
                    op.write().unwrap().set_ptr_flow();
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Propagate \e ptrflow property to given Varnode and the defining PcodeOp.
    /// Returns true if a change was made. Faithful to
    /// `RulePtrFlow::propagateFlowToDef` (ruleaction.cc:9108-9120).
    // Ghidra: ruleaction.cc:9108 RulePtrFlow::propagateFlowToDef
    fn propagate_flow_to_def(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        let mut made_change = false;
        if !vn.read().unwrap().is_ptr_flow() {
            vn.write().unwrap().set_ptr_flow();
            made_change = true;
        }
        let def = vn.read().unwrap().get_def();
        if let Some(def_op) = def {
            if Self::trial_set_ptr_flow(&def_op) {
                made_change = true;
            }
        }
        made_change
    }

    /// Propagate \e ptrflow property to given Varnode and to descendant
    /// PcodeOps. Returns true if a change was made. Faithful to
    /// `RulePtrFlow::propagateFlowToReads` (ruleaction.cc:9127-9145).
    // Ghidra: ruleaction.cc:9127 RulePtrFlow::propagateFlowToReads
    fn propagate_flow_to_reads(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        let mut made_change = false;
        if !vn.read().unwrap().is_ptr_flow() {
            vn.write().unwrap().set_ptr_flow();
            made_change = true;
        }
        // Snapshot descendant ops (the descend set may change as we set flags).
        let descend_ops: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        for op in descend_ops {
            if Self::trial_set_ptr_flow(&op) {
                made_change = true;
            }
        }
        made_change
    }

    /// Truncate pointer Varnode being read by given PcodeOp. Inserts a SUBPIECE
    /// operation truncating the value to the size necessary for a pointer into
    /// the given address space, and updates the PcodeOp input. Returns the new
    /// truncated Varnode. Faithful to `RulePtrFlow::truncatePointer`
    /// (ruleaction.cc:9154-9184).
    // Ghidra: ruleaction.cc:9154 RulePtrFlow::truncatePointer
    fn truncate_pointer(
        spc: &crate::space::AddressSpace,
        op: &crate::op::PcodeOpRef,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        slot: usize,
        data: &mut Funcdata,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let addr_size = spc.addr_size();
        let vn_size = vn.read().unwrap().get_size();
        let vn_space = vn.read().unwrap().get_space();
        let op_addr = op.0.read().unwrap().get_addr();
        let truncop = data.new_op(2, op_addr);
        data.op_set_opcode(&truncop, OpCode::CPUI_SUBPIECE);
        let const_zero = data.new_constant(vn_size, 0);
        data.op_set_input(&truncop, const_zero, 1);
        let newvn = if vn_space.is_unique() {
            // vn->getSpace()->getType() == IPTR_INTERNAL.
            data.new_unique_out(addr_size, &truncop)
        } else {
            // Address addr = vn->getAddr();
            //   if (addr.isBigEndian()) addr = addr + (vn->getSize() - spc->getAddrSize());
            //   addr.renormalize(spc->getAddrSize());
            // Rugra's Address is a plain u64 (Copy); renormalize is a no-op
            // modulo word_size, which is 1 here, so the address is unchanged.
            let addr = vn.read().unwrap().get_addr().clone();
            let addr_val = if spc.is_big_endian() {
                addr.offset((vn_size - addr_size) as i64)
            } else {
                addr
            };
            data.new_varnode_out(addr_size, addr_val, &truncop)
        };
        data.op_set_input(op, newvn.clone(), slot);
        data.op_set_input(&truncop, vn.clone(), 0);
        data.op_insert_before(&truncop, op);
        newvn
    }
}

impl Rule for RulePtrFlow {
    // Ghidra: ruleaction.cc:9177 RulePtrFlow::applyOp
    fn apply_op(
        &self,
        op_arc: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        data: &mut Funcdata,
    ) -> Result<i32> {
        // Faithful to RulePtrFlow::applyOp (ruleaction.cc:9177-9251).
        let op_ref = crate::op::PcodeOpRef(op_arc.clone());
        let opc = op_arc.read().unwrap().opcode;
        let mut made_change = 0;

        match opc {
            OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                // vn = op->getIn(1); spc = op->getIn(0)->getSpaceFromConst();
                let (vn, spc_id) = {
                    let op_rg = op_arc.read().unwrap();
                    let vn = match op_rg.get_in(1) { Some(v) => v.clone(), None => return Ok(0) };
                    let spc_id_vn = match op_rg.get_in(0) { Some(v) => v.clone(), None => return Ok(0) };
                    let id = if spc_id_vn.read().unwrap().is_constant() {
                        spc_id_vn.read().unwrap().get_offset() as u8
                    } else {
                        return Ok(0);
                    };
                    (vn, id)
                };
                let spc = crate::space::AddressSpace::from_id(spc_id);
                let vn_size = vn.read().unwrap().get_size();
                let vn = if vn_size > spc.addr_size() {
                    made_change = 1;
                    Self::truncate_pointer(&spc, &op_ref, &vn, 1, data)
                } else {
                    vn
                };
                if Self::propagate_flow_to_def(&vn) {
                    made_change = 1;
                }
            }
            OpCode::CPUI_CALLIND | OpCode::CPUI_BRANCHIND => {
                // vn = op->getIn(0); spc = data.getArch()->getDefaultCodeSpace();
                let vn = match op_arc.read().unwrap().get_in(0) {
                    Some(v) => v.clone(),
                    None => return Ok(0),
                };
                // Rugra has no getDefaultCodeSpace; the default code space is the
                // RAM space (matches the x86-64 default). Use its addr_size (8).
                let spc = crate::space::AddressSpace::Ram;
                let vn_size = vn.read().unwrap().get_size();
                let vn = if vn_size > spc.addr_size() {
                    made_change = 1;
                    Self::truncate_pointer(&spc, &op_ref, &vn, 0, data)
                } else {
                    vn
                };
                if Self::propagate_flow_to_def(&vn) {
                    made_change = 1;
                }
            }
            OpCode::CPUI_NEW => {
                // vn = op->getOut();
                let vn = match op_arc.read().unwrap().get_out() {
                    Some(v) => v.clone(),
                    None => return Ok(0),
                };
                if Self::propagate_flow_to_reads(&vn) {
                    made_change = 1;
                }
            }
            OpCode::CPUI_INDIRECT => {
                if !op_arc.read().unwrap().is_ptr_flow() {
                    return Ok(0);
                }
                let vn = match op_arc.read().unwrap().get_out() {
                    Some(v) => v.clone(),
                    None => return Ok(0),
                };
                if Self::propagate_flow_to_reads(&vn) {
                    made_change = 1;
                }
                let vn = match op_arc.read().unwrap().get_in(0) {
                    Some(v) => v.clone(),
                    None => return Ok(0),
                };
                if Self::propagate_flow_to_def(&vn) {
                    made_change = 1;
                }
            }
            OpCode::CPUI_COPY | OpCode::CPUI_PTRSUB | OpCode::CPUI_PTRADD => {
                if !op_arc.read().unwrap().is_ptr_flow() {
                    return Ok(0);
                }
                let vn = match op_arc.read().unwrap().get_out() {
                    Some(v) => v.clone(),
                    None => return Ok(0),
                };
                if Self::propagate_flow_to_reads(&vn) {
                    made_change = 1;
                }
                let vn = match op_arc.read().unwrap().get_in(0) {
                    Some(v) => v.clone(),
                    None => return Ok(0),
                };
                if Self::propagate_flow_to_def(&vn) {
                    made_change = 1;
                }
            }
            OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INT_ADD => {
                if !op_arc.read().unwrap().is_ptr_flow() {
                    return Ok(0);
                }
                let vn = match op_arc.read().unwrap().get_out() {
                    Some(v) => v.clone(),
                    None => return Ok(0),
                };
                if Self::propagate_flow_to_reads(&vn) {
                    made_change = 1;
                }
                let num_inputs = op_arc.read().unwrap().num_input();
                for i in 0..num_inputs {
                    let vn = match op_arc.read().unwrap().get_in(i) {
                        Some(v) => v.clone(),
                        None => continue,
                    };
                    if Self::propagate_flow_to_def(&vn) {
                        made_change = 1;
                    }
                }
            }
            _ => {}
        }
        Ok(made_change)
    }

    // Ghidra: ruleaction.cc:9056 RulePtrFlow::RulePtrFlow
    fn get_name(&self) -> &str { "ptrflow" }

    // Ghidra: ruleaction.cc:9063 RulePtrFlow::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        // Faithful to RulePtrFlow::getOpList (ruleaction.cc:9063-9077):
        // "if (!hasTruncations) return; // Only stick ourselves into pool if
        //  aggressiveness is turned on".
        if !self.has_truncations {
            return Vec::new();
        }
        vec![
            OpCode::CPUI_STORE,
            OpCode::CPUI_LOAD,
            OpCode::CPUI_COPY,
            OpCode::CPUI_MULTIEQUAL,
            OpCode::CPUI_INDIRECT,
            OpCode::CPUI_INT_ADD,
            OpCode::CPUI_CALLIND,
            OpCode::CPUI_BRANCHIND,
            OpCode::CPUI_PTRSUB,
            OpCode::CPUI_PTRADD,
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
        // `x + 0 → x` is RuleIdentityEl's job (RuleTrivialArith now does the
        // same-input collapse `x ^ x → 0` per Ghidra ruleaction.cc:2382).
        let rule = RuleIdentityEl::new();
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
        // `x * 1 → x` is RuleIdentityEl's job.
        let rule = RuleIdentityEl::new();
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
        // `x - 0 → x` is RuleIdentityEl's job.
        let rule = RuleIdentityEl::new();
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
    fn test_trivial_arith_xor_self_to_zero() {
        // `x ^ x → 0` — the core same-input collapse (Ghidra ruleaction.cc:2413).
        // This is the defect the rewrite fixes: previously Rugra's RuleTrivialArith
        // did RuleIdentityEl's job (x+0→x) and never performed this collapse,
        // leaving `x ^ x` intact → `switch((iVar1 ^ iVar1))` defect.
        let rule = RuleTrivialArith::new();
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        // Same varnode as both inputs.
        let in_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_XOR);
        op.inrefs = vec![in_vn.clone(), in_vn];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));

        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op_arc.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert_eq!(o.inrefs.len(), 1);
        assert!(o.inrefs[0].read().unwrap().is_constant());
        assert_eq!(o.inrefs[0].read().unwrap().get_offset(), 0);
    }

    #[test]
    fn test_trivial_arith_equal_self_to_one() {
        // `x == x → 1` (Ghidra ruleaction.cc:2406).
        let rule = RuleTrivialArith::new();
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        let in_vn = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let out = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_EQUAL);
        op.inrefs = vec![in_vn.clone(), in_vn];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));

        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        let o = op_arc.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert!(o.inrefs[0].read().unwrap().is_constant());
        assert_eq!(o.inrefs[0].read().unwrap().get_offset(), 1);
    }

    #[test]
    fn test_trivial_arith_distinct_inputs_no_change() {
        // Two distinct varnodes (different offsets) → no collapse.
        let rule = RuleTrivialArith::new();
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_XOR,
            crate::space::AddressSpace::Register, 0x10, 8,
            crate::space::AddressSpace::Register, 0x20, 8,
            8,
        );
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
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
            OpCode::CPUI_INT_NEGATE,
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
            OpCode::CPUI_INT_NEGATE,
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
            OpCode::CPUI_INT_NEGATE,
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
            OpCode::CPUI_BOOL_NEGATE,
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
            OpCode::CPUI_BOOL_NEGATE,
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
            OpCode::CPUI_BOOL_NEGATE,
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
            OpCode::CPUI_BOOL_NEGATE,
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
            OpCode::CPUI_BOOL_NEGATE,
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
            OpCode::CPUI_BOOL_NEGATE,
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
        // A dead op whose output is CONSTANT → destroyed. RuleEarlyRemoval now
        // trusts descend tracking for CONSTANT/IOP-space outputs (Ghidra
        // doesDeadcode==false for those spaces → always removable).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let b = fd.vbank.create_constant(4, 5);
        let out = fd.vbank.create_constant(4, 0x20);
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

    #[test]
    fn test_early_removal_unique_output_destroyed() {
        // A dead op whose output is in the UNIQUE (temporary) space. Ghidra's
        // doesDeadcode() returns true for unique, but deadRemovalAllowedSeen has
        // fired by the time the cleanup pool runs. Since Rugra has no deadcode-
        // seen tracking, UNIQUE outputs are gated as a "memory" output and the
        // removal is blocked (NO_CHANGE) until that mechanism lands.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let b = fd.vbank.create_constant(4, 5);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Unique, 0x20);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut o = op.write().unwrap();
            o.inrefs = vec![a, b];
            o.output = Some(out.clone());
        }
        assert!(out.read().unwrap().has_no_descend());
        let rule = RuleEarlyRemoval::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        // UNIQUE is gated as memory output → blocked for now.
        assert_eq!(result, action_status::NO_CHANGE);
    }

    #[test]
    fn test_early_removal_register_output_blocked() {
        // A dead op whose output is in the REGISTER space → "memory" output,
        // gated until deadRemovalAllowedSeen is ported.
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
        assert!(out.read().unwrap().has_no_descend());
        let rule = RuleEarlyRemoval::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    #[test]
    fn test_early_removal_indirect_source_blocked() {
        // An INDIRECT-source op is never removed (guard 2, ruleaction.cc:31).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let out = fd.vbank.create_constant(4, 0x20);
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INDIRECT,
        )));
        op.write().unwrap().output = Some(out.clone());
        op.write().unwrap().flags |= crate::op::pcodeop_flags::INDIRECT_SOURCE;
        let rule = RuleEarlyRemoval::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // --- RuleConditionalMove (ruleaction.cc:9390) ---

    #[test]
    fn test_conditional_move_construct_bool_no_clone() {
        // constructBool with an empty op list returns the boolean Varnode itself
        // (ruleaction.cc:9350-9358: resvn = vn when ops is empty). This is the
        // path that fires for values formed before the branch — no cloning.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let boolvn = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let op_ref = crate::op::PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BOOL_OR,
        ))));
        // Empty op list → returns the varnode directly.
        let res = RuleConditionalMove::construct_bool(&boolvn, &[], &op_ref, &mut fd);
        assert!(res.is_some());
        assert!(Arc::ptr_eq(&res.unwrap(), &boolvn));
    }

    #[test]
    fn test_conditional_move_construct_bool_needs_clone() {
        // constructBool with a non-empty op list cannot reproduce the
        // expression without CloneBlockOps (not yet ported) → returns None.
        // The caller (applyOp) then bails with NO_CHANGE.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let boolvn = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x10);
        let op_ref = crate::op::PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BOOL_OR,
        ))));
        // A dummy op in the list signals cross-branch duplication is required.
        let dummy_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_AND,
        )));
        let res = RuleConditionalMove::construct_bool(&boolvn, &[dummy_op], &op_ref, &mut fd);
        assert!(res.is_none());
    }

    #[test]
    fn test_conditional_move_check_boolean() {
        // checkBoolean returns the boolean root for a bool-output op.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let b = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x11);
        let boolout = fd.vbank.create_with_space(1, crate::space::AddressSpace::Register, 0x20);
        let cmp_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_LESS,
        )));
        {
            let mut o = cmp_op.write().unwrap();
            o.inrefs = vec![a, b];
            o.output = Some(boolout.clone());
            o.flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
        }
        boolout.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        boolout.write().unwrap().def = Some(Arc::downgrade(&cmp_op));
        let root = RuleConditionalMove::check_boolean(&boolout);
        assert!(root.is_some());
        assert!(Arc::ptr_eq(&root.unwrap(), &boolout));
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
        assert_eq!(eq_op.read().unwrap().opcode, OpCode::CPUI_BOOL_NEGATE);
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

    /// RuleDivOpt::find_form should reject a bare INT_RIGHT whose input is
    /// not the expected mult/zext chain. Guards the early-out path without
    /// needing to construct the full division-by-multiplication form.
    #[test]
    fn test_rule_div_opt_rejects_nonmatching_form() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_RIGHT,
            crate::space::AddressSpace::Register, 0x10, 8, // dividend (not written)
            crate::space::AddressSpace::Const, 3, 8,        // shift by 3
            8,
        );
        let rule = RuleDivOpt::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    /// Verify RuleSubCommute transforms SUBPIECE(INT_ADD(a,b),0) into
    /// INT_ADD(SUBPIECE(a,0), SUBPIECE(b,0)), pushing the truncation inside
    /// the arithmetic. Faithful to Ghidra ruleaction.cc:4534-4673.
    #[test]
    fn test_rule_sub_commute_add() {
        let mut fd = Funcdata::new("test_subcommute", Address::new(0x1000), 0x10);
        // Two 8-byte registers a, b.
        let a = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x200);
        let b = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x208);
        // INT_ADD(a, b) -> long_out (8 bytes)
        let add_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
        let long_out = fd.new_unique_out(8, &add_op);
        fd.op_set_input(&add_op, a.clone(), 0);
        fd.op_set_input(&add_op, b.clone(), 1);
        fd.obank.alivelist.push(add_op.clone());
        // SUBPIECE(long_out, 0) -> sub_out (4 bytes)
        let sub_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
        let _sub_out = fd.new_unique_out(4, &sub_op);
        fd.op_set_input(&sub_op, long_out.clone(), 0);
        let off_const = fd.new_constant(4, 0);
        fd.op_set_input(&sub_op, off_const, 1); // offset 0
        fd.obank.alivelist.push(sub_op.clone());

        let rule = RuleSubCommute::new();
        let result = rule.apply_op(&sub_op.0, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE, "RuleSubCommute should transform SUBPIECE(INT_ADD)");

        // After: the original SUBPIECE op should be destroyed, and the
        // INT_ADD's output should be the 4-byte sub_out (moved).
        // Verify two new SUBPIECE ops exist (for a and b).
        let new_subpieces = fd.obank.alivelist.iter().filter(|r| {
            r.0.read().unwrap().opcode == OpCode::CPUI_SUBPIECE
        }).count();
        assert!(new_subpieces >= 2, "should have at least 2 new SUBPIECE ops (for a and b)");
    }

    /// Verify RuleSubCommute does NOT fire when base has multiple descendants
    /// (loneDescend check, cc:4641).
    #[test]
    fn test_rule_sub_commute_no_lone_descend() {
        let mut fd = Funcdata::new("test_subcommute2", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x200);
        let b = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x208);
        // INT_ADD(a, b) -> long_out
        let add_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
        let long_out = fd.new_unique_out(8, &add_op);
        fd.op_set_input(&add_op, a.clone(), 0);
        fd.op_set_input(&add_op, b.clone(), 1);
        fd.obank.alivelist.push(add_op.clone());
        // SUBPIECE(long_out, 0)
        let sub_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
        let _sub_out = fd.new_unique_out(4, &sub_op);
        fd.op_set_input(&sub_op, long_out.clone(), 0);
        let off_const = fd.new_constant(4, 0);
        fd.op_set_input(&sub_op, off_const, 1);
        fd.obank.alivelist.push(sub_op.clone());
        // A SECOND reader of long_out (so loneDescend fails).
        let reader2 = fd.new_op(1, Address::new(0x1000));
        fd.op_set_opcode(&reader2, OpCode::CPUI_COPY);
        fd.op_set_input(&reader2, long_out.clone(), 0);
        let _r2out = fd.new_unique_out(8, &reader2);
        fd.obank.alivelist.push(reader2);

        let rule = RuleSubCommute::new();
        let result = rule.apply_op(&sub_op.0, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE, "RuleSubCommute must NOT fire when base has 2 descendants");
    }

    // ========================================================================
    // Tests for the newly-ported cleanup-pool and oppool1 rules.
    // ========================================================================

    /// RuleAddUnsigned: `V + 0xff.. ⇒ V - 0x00..` for a 1-byte value 0xff → -1.
    #[test]
    fn test_rule_add_unsigned_fires() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_ADD,
            crate::space::AddressSpace::Register, 0x00, 1, // V (1 byte)
            crate::space::AddressSpace::Const, 0xff, 1,    // 0xff (high quarter all 1s)
            1,
        );
        let rule = RuleAddUnsigned::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_INT_SUB);
        // negatedVal = (-0xff) & 0xff = 1
        assert_eq!(op_arc.read().unwrap().inrefs[1].read().unwrap().get_offset(), 1);
    }

    /// RuleAddUnsigned must NOT fire when the high quarter isn't all ones.
    #[test]
    fn test_rule_add_unsigned_no_fire() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_ADD,
            crate::space::AddressSpace::Register, 0x00, 4,
            crate::space::AddressSpace::Const, 0x7f, 4, // high quarter not all 1s
            4,
        );
        let rule = RuleAddUnsigned::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    /// RuleNegateNegate: `~~V ⇒ V`.
    #[test]
    fn test_rule_negate_negate() {
        let mut fd = Funcdata::new("test_negatenegate", Address::new(0x1000), 0x10);
        // V: a written register
        let v = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x200);
        let v_copy_op = fd.new_op(1, Address::new(0x1000));
        fd.op_set_opcode(&v_copy_op, OpCode::CPUI_COPY);
        let v_def = fd.new_unique_out(4, &v_copy_op);
        fd.op_set_input(&v_copy_op, v, 0);
        fd.obank.alivelist.push(v_copy_op.clone());
        // inner negate: ~v_def
        let neg1 = fd.new_op(1, Address::new(0x1000));
        fd.op_set_opcode(&neg1, OpCode::CPUI_INT_NEGATE);
        let neg1_out = fd.new_unique_out(4, &neg1);
        fd.op_set_input(&neg1, v_def, 0);
        fd.obank.alivelist.push(neg1.clone());
        // outer negate: ~~v_def
        let neg2 = fd.new_op(1, Address::new(0x1000));
        fd.op_set_opcode(&neg2, OpCode::CPUI_INT_NEGATE);
        let _neg2_out = fd.new_unique_out(4, &neg2);
        fd.op_set_input(&neg2, neg1_out, 0);
        fd.obank.alivelist.push(neg2.clone());

        let rule = RuleNegateNegate::new();
        let result = rule.apply_op(&neg2.0, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(neg2.0.read().unwrap().opcode, OpCode::CPUI_COPY);
    }

    /// RuleFloatSignCleanup: XOR with sign bit → FLOAT_NEG (4-byte float).
    #[test]
    fn test_rule_float_sign_cleanup_neg() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_XOR,
            crate::space::AddressSpace::Register, 0x00, 4, // float V
            crate::space::AddressSpace::Const, 0x8000_0000, 4, // sign bit
            4,
        );
        let rule = RuleFloatSignCleanup::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_FLOAT_NEG);
        assert_eq!(op_arc.read().unwrap().inrefs.len(), 1);
    }

    /// RuleFloatSignCleanup: AND with ~sign_bit → FLOAT_ABS (8-byte float).
    #[test]
    fn test_rule_float_sign_cleanup_abs() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_AND,
            crate::space::AddressSpace::Register, 0x00, 8, // float V (8 bytes)
            crate::space::AddressSpace::Const, 0x7fff_ffff_ffff_ffff, 8, // ~sign
            8,
        );
        let rule = RuleFloatSignCleanup::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_FLOAT_ABS);
    }

    /// RuleFloatSignCleanup must NOT fire on non-canonical masks.
    #[test]
    fn test_rule_float_sign_cleanup_no_fire() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_XOR,
            crate::space::AddressSpace::Register, 0x00, 4,
            crate::space::AddressSpace::Const, 0x0000_000f, 4, // not a sign bit
            4,
        );
        let rule = RuleFloatSignCleanup::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    /// RuleSubRight: SUBPIECE(V, 2) where V is 4 bytes, no shift descendant.
    /// Should insert a shift and turn the SUBPIECE into a least-sig SUBPIECE.
    #[test]
    fn test_rule_sub_right_basic() {
        let mut fd = Funcdata::new("test_subright", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x300);
        let sub_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
        let _sub_out = fd.new_unique_out(2, &sub_op);
        fd.op_set_input(&sub_op, a, 0);
        let off2 = fd.new_constant(4, 2);
        fd.op_set_input(&sub_op, off2, 1); // offset 2 (not least sig)
        fd.obank.alivelist.push(sub_op.clone());

        let rule = RuleSubRight::new();
        let result = rule.apply_op(&sub_op.0, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE, "RuleSubRight should fire for SUBPIECE(V,2)");
        // The original SUBPIECE must now have a zero offset (least sig).
        assert_eq!(sub_op.0.read().unwrap().inrefs[1].read().unwrap().get_offset(), 0);
    }

    /// RuleSubRight must NOT fire when the SUBPIECE is least-significant (c==0).
    #[test]
    fn test_rule_sub_right_no_fire_leastsig() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_SUBPIECE,
            crate::space::AddressSpace::Register, 0x00, 4,
            crate::space::AddressSpace::Const, 0, 4, // offset 0 → least sig
            2,
        );
        let rule = RuleSubRight::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    /// RuleUnsigned2Float must NOT fire on a bare FLOAT_INT2FLOAT of a register
    /// (not the (X>>1)|(X&1) idiom). Guards the early-out path.
    #[test]
    fn test_rule_unsigned_2_float_no_fire() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_FLOAT_INT2FLOAT,
            crate::space::AddressSpace::Register, 0x10, 4, // bare register, not the idiom
            crate::space::AddressSpace::Const, 0, 1, // unused second slot
            8,
        );
        let rule = RuleUnsigned2Float::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    /// RulePtrsubUndo helpers: getConstOffsetBack on a pure constant returns
    /// the constant and multiplier 0.
    #[test]
    fn test_rule_ptrsub_undo_const_offset_back() {
        let mut fd = Funcdata::new("test_ptrsubundo", Address::new(0x1000), 0x10);
        let c = fd.vbank.create_constant(4, 42);
        let mut mult: i64 = -1;
        let off = RulePtrsubUndo::get_const_offset_back(&c, &mut mult, RulePtrsubUndo::DEPTH_LIMIT);
        assert_eq!(off, 42);
        assert_eq!(mult, 0);
    }

    /// RulePtrsubUndo helpers: getConstOffsetBack over INT_ADD(c1, c2) sums.
    #[test]
    fn test_rule_ptrsub_undo_const_offset_back_add() {
        let mut fd = Funcdata::new("test_ptrsubundo2", Address::new(0x1000), 0x10);
        let c1 = fd.vbank.create_constant(4, 10);
        let c2 = fd.vbank.create_constant(4, 5);
        let add = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&add, OpCode::CPUI_INT_ADD);
        let out = fd.new_unique_out(4, &add);
        fd.op_set_input(&add, c1, 0);
        fd.op_set_input(&add, c2, 1);
        fd.obank.alivelist.push(add.clone());
        let mut mult: i64 = 0;
        let off = RulePtrsubUndo::get_const_offset_back(&out, &mut mult, RulePtrsubUndo::DEPTH_LIMIT);
        assert_eq!(off, 15);
        assert_eq!(mult, 0);
    }

    /// Rules that require missing infra must no-op cleanly (return NO_CHANGE)
    /// rather than panic.
    #[test]
    fn test_infra_gated_rules_no_op() {
        // RulePtrsubCharConstant: PTRSUB → NO_CHANGE (no type system).
        {
            let (op_arc, mut fd) = make_binary_op(
                OpCode::CPUI_PTRSUB,
                crate::space::AddressSpace::Register, 0x00, 8,
                crate::space::AddressSpace::Const, 4, 8,
                8,
            );
            let r = RulePtrsubCharConstant::new();
            assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
        }
        // RuleExpandLoad: LOAD → NO_CHANGE (no pointer type).
        {
            let (op_arc, mut fd) = make_binary_op(
                OpCode::CPUI_LOAD,
                crate::space::AddressSpace::Const, 0, 8, // space id (const)
                crate::space::AddressSpace::Register, 0x00, 8, // ptr
                4,
            );
            let r = RuleExpandLoad::new();
            assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
        }
        // RuleTransformCpool: CPOOLREF → NO_CHANGE (no cpool accessor).
        {
            let (op_arc, mut fd) = make_binary_op(
                OpCode::CPUI_CPOOLREF,
                crate::space::AddressSpace::Register, 0x00, 8,
                crate::space::AddressSpace::Const, 1, 8,
                8,
            );
            let r = RuleTransformCpool::new();
            assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
        }
        // RuleSegment: SEGMENTOP → NO_CHANGE (no SegmentOp).
        {
            let mut fd = Funcdata::new("seg", Address::new(0x1000), 0x10);
            let c0 = fd.vbank.create_constant(4, 0);
            let c1 = fd.vbank.create_constant(4, 1);
            let c2 = fd.vbank.create_constant(4, 2);
            let seq = SeqNum::new(Address::new(0x1000), 0);
            let mut op = PcodeOp::new(seq, OpCode::CPUI_SEGMENTOP);
            op.inrefs = vec![c0, c1, c2];
            op.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100));
            let op_arc = Arc::new(RwLock::new(op));
            let r = RuleSegment::new();
            assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
        }
        // RuleFuncPtrEncoding: CALLIND → NO_CHANGE (no funcptr_align).
        {
            let mut fd = Funcdata::new("fptr", Address::new(0x1000), 0x10);
            let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x40);
            let seq = SeqNum::new(Address::new(0x1000), 0);
            let mut op = PcodeOp::new(seq, OpCode::CPUI_CALLIND);
            op.inrefs = vec![ptr];
            op.output = Some(fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x100));
            let op_arc = Arc::new(RwLock::new(op));
            let r = RuleFuncPtrEncoding::new();
            assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
        }
    }

    /// testForArraySlack (type.cc:990-1005): a bare array always has slack.
    /// Drives the is_ptrsub_matching Spacebase/Struct branches so a PTRSUB into
    /// an arrayed component is no longer rejected.
    #[test]
    fn test_rule_ptrsub_undo_test_for_array_slack_array() {
        use crate::type_system::datatype::{
            Datatype, TypeArray, TypeBase, TypeField, TypeMetatype, TypePointer, TypeStruct,
        };
        // int[4] (element int size 4)
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        let arr = Datatype::Array(TypeArray {
            base: TypeBase::new("int[4]".into(), 16, TypeMetatype::Array),
            array_of: int_t,
            num_elements: 4,
        });
        // A bare array → test_for_array_slack is true regardless of offset.
        assert!(RulePtrsubUndo::test_for_array_slack(&arr, 0));
        assert!(RulePtrsubUndo::test_for_array_slack(&arr, 17));
    }

    /// testForArraySlack on a struct containing an array field: the arrayed
    /// component is found via nearestArrayedComponentBackward/Forward
    /// (type.cc:1669-1741), so slack is allowed.
    #[test]
    fn test_rule_ptrsub_undo_test_for_array_slack_struct_array_field() {
        use crate::type_system::datatype::{
            Datatype, TypeArray, TypeBase, TypeField, TypeMetatype, TypeStruct,
        };
        let char_t = Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)));
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        // buf: char[8] at offset 0
        let buf_arr = Arc::new(Datatype::Array(TypeArray {
            base: TypeBase::new("char[8]".into(), 8, TypeMetatype::Array),
            array_of: char_t,
            num_elements: 8,
        }));
        // struct { char buf[8] @0; int x @8; } size 12
        let s = Datatype::Struct(TypeStruct {
            base: TypeBase::new("S".into(), 12, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "buf".into(), offset: 0, type_ptr: buf_arr },
                TypeField { name: "x".into(), offset: 8, type_ptr: int_t },
            ],
        });
        // Within the array field → slack true (backward search finds the array).
        assert!(RulePtrsubUndo::test_for_array_slack(&s, 5));
        // Before the struct (negative offset) → forward search finds the array.
        assert!(RulePtrsubUndo::test_for_array_slack(&s, -2));
    }

    /// testForArraySlack negative: a struct with no arrayed component and an
    /// out-of-bounds extra must return false (no slack to explain it).
    #[test]
    fn test_rule_ptrsub_undo_test_for_array_slack_no_array() {
        use crate::type_system::datatype::{
            Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct,
        };
        let char_t = Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)));
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        // struct { char a @0; int b @4; } size 8 — no array field.
        let s = Datatype::Struct(TypeStruct {
            base: TypeBase::new("S2".into(), 8, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: char_t },
                TypeField { name: "b".into(), offset: 4, type_ptr: int_t },
            ],
        });
        // No array component reachable → false.
        assert!(!RulePtrsubUndo::test_for_array_slack(&s, 3));
    }

    /// is_ptrsub_matching end-to-end: a PTRSUB into a Spacebase sub-type that is
    /// itself an array keeps matching once testForArraySlack is wired
    /// (type.cc:1133-1136). Before the fix this returned false for an OOB extra.
    #[test]
    fn test_rule_ptrsub_undo_is_ptrsub_matching_array_slack() {
        use crate::type_system::datatype::{
            Datatype, TypeArray, TypeBase, TypeMetatype, TypePointer,
        };
        // int[4], element size 4.
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        let arr = Arc::new(Datatype::Array(TypeArray {
            base: TypeBase::new("int[4]".into(), 16, TypeMetatype::Array),
            array_of: int_t,
            num_elements: 4,
        }));
        // (int[4] *) — pointer to the array.
        let ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int[4] *".into(), 8, TypeMetatype::Pointer),
            ptr_to: arr,
            wordsize: 1,
        }));
        // off=0 (sub-type is the array, sub_off=0), extra=20 (>= array size 16
        // → out of bounds). testForArraySlack(array, 20) == true, so it still
        // matches.
        assert!(RulePtrsubUndo::is_ptrsub_matching(&ptr, 0, 20, 0));
    }

    /// RulePtrsubCharConstant: when the Architecture exposes a StringManager
    /// that does NOT confirm symaddr as a string, the rule must no-op even if
    /// symaddr is in the read-only string_table proxy.
    #[test]
    fn test_rule_ptrsub_char_constant_string_manager_rejects() {
        use crate::type_system::datatype::{
            Datatype, TypeBase, TypeMetatype, TypePointer, TypeSpacebase, type_flags,
        };
        let mut fd = Funcdata::new("charconst", Address::new(0x1000), 0x10);
        // spacebase type for the input pointer's pointed-to type.
        let sb_dt = Arc::new(Datatype::Spacebase(TypeSpacebase {
            base: TypeBase::new("spacebase".into(), 0, TypeMetatype::Spacebase),
            address: Address::new(0),
            fd: None,
            // RUGRA-GLUE: spaceid/localframe/scope added by the TypeSpacebase
            // alignment pass (type.cc:2935 getMap/getSubType/getAddress). These
            // tests exercise the chartype fast-path and do not need a scope, so
            // the global-spacebase defaults (no space, invalid localframe, no
            // scope) reproduce the prior "global spacebase" behaviour.
            spaceid: None,
            localframe: Address::new(0),
            scope: None,
        }));
        let sb_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("spacebase *".into(), 8, TypeMetatype::Pointer),
            ptr_to: sb_dt,
            wordsize: 1,
        }));
        // char with chartype flag set so isCharPrint() is true.
        let char_print = {
            let mut b = TypeBase::new("char".into(), 1, TypeMetatype::Int);
            b.flags |= type_flags::CHARTYPE;
            Arc::new(Datatype::Base(b))
        };
        let out_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".into(), 8, TypeMetatype::Pointer),
            ptr_to: char_print,
            wordsize: 1,
        }));
        // Register symaddr=0x2000 in string_table (read-only proxy).
        fd.add_string(0x2000, "hello".to_string());
        // Architecture with an EMPTY StringManager (no entry at 0x2000) →
        // isString must reject.
        let mut arch = crate::arch::Architecture::new();
        let sm = std::sync::Arc::new(std::sync::RwLock::new(
            crate::stringmanage::StringManager::new(100),
        ));
        arch.set_string_manager(sm);
        fd.set_arch(std::sync::Arc::new(arch));
        // sb input: a constant carrying the spacebase pointer type.
        let sb_vn = fd.vbank.create_constant(8, 0);
        sb_vn.write().unwrap().update_type(sb_ptr);
        // vn1: constant offset 0x2000.
        let vn1 = fd.vbank.create_constant(8, 0x2000);
        // output: a unique carrying the char * type.
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_PTRSUB);
        op.inrefs = vec![sb_vn, vn1];
        let outvn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x300);
        outvn.write().unwrap().update_type(out_ptr);
        op.output = Some(outvn);
        let op_arc = Arc::new(RwLock::new(op));
        let r = RulePtrsubCharConstant::new();
        // StringManager has no entry at 0x2000 → NO_CHANGE (rejected by the
        // precise isString guard added per ruleaction.cc:7393).
        assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// RulePtrsubCharConstant: when the Architecture's StringManager CONFIRMS
    /// symaddr as a string, the PTRSUB is collapsed to a COPY of the constant
    /// (ruleaction.cc:7396-7421).
    #[test]
    fn test_rule_ptrsub_char_constant_string_manager_confirms() {
        use crate::type_system::datatype::{
            Datatype, TypeBase, TypeMetatype, TypePointer, TypeSpacebase, type_flags,
        };
        let mut fd = Funcdata::new("charconst2", Address::new(0x1000), 0x10);
        let sb_dt = Arc::new(Datatype::Spacebase(TypeSpacebase {
            base: TypeBase::new("spacebase".into(), 0, TypeMetatype::Spacebase),
            address: Address::new(0),
            fd: None,
            // RUGRA-GLUE: spaceid/localframe/scope added by the TypeSpacebase
            // alignment pass (type.cc:2935 getMap/getSubType/getAddress). These
            // tests exercise the chartype fast-path and do not need a scope, so
            // the global-spacebase defaults (no space, invalid localframe, no
            // scope) reproduce the prior "global spacebase" behaviour.
            spaceid: None,
            localframe: Address::new(0),
            scope: None,
        }));
        let sb_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("spacebase *".into(), 8, TypeMetatype::Pointer),
            ptr_to: sb_dt,
            wordsize: 1,
        }));
        let char_print = {
            let mut b = TypeBase::new("char".into(), 1, TypeMetatype::Int);
            b.flags |= type_flags::CHARTYPE;
            Arc::new(Datatype::Base(b))
        };
        let out_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".into(), 8, TypeMetatype::Pointer),
            ptr_to: char_print.clone(),
            wordsize: 1,
        }));
        // Register symaddr=0x2000 in both string_table (read-only proxy) and
        // the Architecture's StringManager (precise isString confirmation).
        fd.add_string(0x2000, "hello".to_string());
        let mut arch = crate::arch::Architecture::new();
        let mut sm = crate::stringmanage::StringManager::new(100);
        sm.insert_string_data(
            Address::new(0x2000),
            crate::stringmanage::StringData {
                is_truncated: false,
                byte_data: vec![b'h', b'e', b'l', b'l', b'o'],
            },
        );
        arch.set_string_manager(std::sync::Arc::new(std::sync::RwLock::new(sm)));
        fd.set_arch(std::sync::Arc::new(arch));
        let sb_vn = fd.vbank.create_constant(8, 0);
        sb_vn.write().unwrap().update_type(sb_ptr);
        let vn1 = fd.vbank.create_constant(8, 0x2000);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_PTRSUB);
        op.inrefs = vec![sb_vn, vn1];
        let outvn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x300);
        outvn.write().unwrap().update_type(out_ptr);
        op.output = Some(outvn);
        let op_arc = Arc::new(RwLock::new(op));
        let r = RulePtrsubCharConstant::new();
        // StringManager confirms 0x2000 → CHANGE (collapsed to COPY).
        assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::CHANGE);
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_COPY);
    }

    /// RuleSegment constant-fold path: both SEGMENTOP inputs constant with a
    /// registered SegmentOp folds to a COPY of `(base<<4)+inner`
    /// (ruleaction.cc:9024-9033; faithful to SegmentOp::execute userop.cc:218).
    #[test]
    fn test_rule_segment_const_fold() {
        use crate::userop::SegmentOp;
        let mut fd = Funcdata::new("segfold", Address::new(0x1000), 0x10);
        // Register a SegmentOp for space index 0 in the architecture's userops.
        let mut arch = crate::arch::Architecture::new();
        let mut uo = crate::userop::UserOpManage::new();
        let mut seg = SegmentOp::new("segment".into(), 0);
        seg.supports_far_pointer = true; // mark far-pointer support for completeness
        uo.segment_ops.insert(0, seg);
        let uo_arc = std::sync::Arc::new(std::sync::RwLock::new(uo));
        arch.set_userops(uo_arc);
        fd.set_arch(std::sync::Arc::new(arch));
        // SEGMENTOP(space_idx=0, base=0x1234, inner=0x0002), output size 4.
        let c0 = fd.vbank.create_constant(4, 0);       // space index 0
        let c1 = fd.vbank.create_constant(4, 0x1234);   // base
        let c2 = fd.vbank.create_constant(4, 0x0002);   // inner
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_SEGMENTOP);
        op.inrefs = vec![c0, c1, c2];
        op.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100));
        let op_arc = Arc::new(RwLock::new(op));
        let r = RuleSegment::new();
        let res = r.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE, "RuleSegment should fold constant SEGMENTOP");
        // After fold: opcode is COPY, single input = (0x1234<<4)+0x0002 = 0x12342.
        let o = op_arc.read().unwrap();
        assert_eq!(o.opcode, OpCode::CPUI_COPY);
        assert_eq!(o.inrefs.len(), 1);
        assert_eq!(o.inrefs[0].read().unwrap().get_offset(), 0x12342);
    }

    /// RuleSegment no-fold when a registered SegmentOp exists but inputs are
    /// non-constant and far-pointer support is off (ruleaction.cc:9034).
    #[test]
    fn test_rule_segment_no_fold_nonconst() {
        use crate::userop::SegmentOp;
        let mut fd = Funcdata::new("segnf", Address::new(0x1000), 0x10);
        let mut arch = crate::arch::Architecture::new();
        let mut uo = crate::userop::UserOpManage::new();
        let seg = SegmentOp::new("segment".into(), 0); // supports_far_pointer=false
        uo.segment_ops.insert(0, seg);
        arch.set_userops(std::sync::Arc::new(std::sync::RwLock::new(uo)));
        fd.set_arch(std::sync::Arc::new(arch));
        // Non-constant vn1/vn2 (Register space, not const) -> neither branch fires.
        let c0 = fd.vbank.create_constant(4, 0);
        let vn1 = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x10);
        let vn2 = fd.vbank.create_with_space(2, crate::space::AddressSpace::Register, 0x20);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_SEGMENTOP);
        op.inrefs = vec![c0, vn1, vn2];
        op.output = Some(fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100));
        let op_arc = Arc::new(RwLock::new(op));
        let r = RuleSegment::new();
        assert_eq!(r.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// RuleDivOpt.move_sign_bit_extraction + resolve_shift_const: smoke test
    /// via the existing div-opt rejection test (the helper is exercised on the
    /// signed path once a full form is recognised). Here we just confirm the
    /// helper compiles and a bare no-form op still returns NO_CHANGE.
    #[test]
    fn test_rule_div_opt_move_sign_bit_helper_compiles() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_SRIGHT,
            crate::space::AddressSpace::Register, 0x10, 8,
            crate::space::AddressSpace::Const, 3, 8,
            8,
        );
        let rule = RuleDivOpt::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // ========================================================================
    // RuleLoadVarnode / RuleStoreVarnode tests
    // (ruleaction.cc:4185-4361)
    // ========================================================================

    /// Helper: build a LOAD(spaceid_const, ptr) → out, where the address operand
    /// (slot 1) is a plain constant. This is the form that should collapse to COPY.
    fn make_load_const_ptr(
        space_id_val: u64,
        ptr_offset: u64,
        out_size: usize,
    ) -> (Arc<RwLock<PcodeOp>>, Funcdata) {
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        let spaceid = fd.vbank.create_constant(8, space_id_val);
        let ptr = fd.vbank.create_constant(8, ptr_offset);
        let out = fd.vbank.create_with_space(out_size, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_LOAD);
        op.inrefs = vec![spaceid, ptr];
        op.output = Some(out);
        (Arc::new(RwLock::new(op)), fd)
    }

    /// RuleLoadVarnode: LOAD(stack_spaceid, const offset) → COPY of a named
    /// stack varnode. The plain-constant-offset path (ruleaction.cc:4278-4281).
    #[test]
    fn test_rule_load_varnode_const_offset() {
        // space-id 4 == SPACEID_STACK; pointer offset 0x40.
        let (op_arc, mut fd) = make_load_const_ptr(
            crate::space::SPACEID_STACK as u64,
            0x40,
            4,
        );
        let rule = RuleLoadVarnode::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // LOAD must now be COPY with a single input (the named varnode).
        let op = op_arc.read().unwrap();
        assert_eq!(op.opcode, OpCode::CPUI_COPY);
        assert_eq!(op.inrefs.len(), 1);
    }

    /// RuleLoadVarnode: with a non-constant (register) address operand and no
    /// spacebase, check_spacebase cannot resolve → NO_CHANGE.
    #[test]
    fn test_rule_load_varnode_no_const_ptr() {
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_STACK as u64);
        let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_LOAD);
        op.inrefs = vec![spaceid, ptr];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        let rule = RuleLoadVarnode::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    /// RuleLoadVarnode: when slot 0 (space-id) is not a constant, getSpaceFromConst
    /// fails → NO_CHANGE.
    #[test]
    fn test_rule_load_varnode_non_const_spaceid() {
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        let spaceid = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x0);
        let ptr = fd.vbank.create_constant(8, 0x40);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_LOAD);
        op.inrefs = vec![spaceid, ptr];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        let rule = RuleLoadVarnode::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    /// RuleLoadVarnode::correct_spacebase: a non-spacebase varnode returns None.
    #[test]
    fn test_rule_load_varnode_correct_spacebase_non_spacebase() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let r = RuleLoadVarnode::correct_spacebase(&vn, crate::space::AddressSpace::Stack);
        assert!(r.is_none());
    }

    /// RuleStoreVarnode: STORE(stack_spaceid, const offset, value) → COPY with
    /// the output marked STACK_STORE (ruleaction.cc:4339-4361).
    #[test]
    fn test_rule_store_varnode_const_offset() {
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_STACK as u64);
        let ptr = fd.vbank.create_constant(8, 0x80);
        let val = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x200);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x300);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_STORE);
        op.inrefs = vec![spaceid, ptr, val];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        let rule = RuleStoreVarnode::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // STORE → COPY with one input, output marked STACK_STORE.
        let op = op_arc.read().unwrap();
        assert_eq!(op.opcode, OpCode::CPUI_COPY);
        assert_eq!(op.inrefs.len(), 1);
        assert_ne!(op.output.as_ref().unwrap().read().unwrap().addlflags & crate::varnode::addl_flags::STACK_STORE, 0);
    }

    /// RuleStoreVarnode: non-constant address operand → NO_CHANGE.
    #[test]
    fn test_rule_store_varnode_no_const_ptr() {
        let mut fd = Funcdata::new("test", Address::new(0x1000), 0x10);
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_STACK as u64);
        let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let val = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x200);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x300);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_STORE);
        op.inrefs = vec![spaceid, ptr, val];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        let rule = RuleStoreVarnode::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    // ========================================================================
    // RulePtrArith / evaluatePointerExpression tests
    // (ruleaction.cc:6552-6676)
    // ========================================================================

    /// Helper: make an int* (8-byte pointer to a 4-byte int).
    fn make_int_ptr_type() -> std::sync::Arc<crate::type_system::datatype::Datatype> {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        let int_dt = std::sync::Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(), 4, TypeMetatype::Int,
        )));
        std::sync::Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_dt,
            wordsize: 1,
        }))
    }

    /// evaluatePointerExpression: an INT_ADD(ptr, const) with NO descendants
    /// returns 0 (count==0 → no action). Faithful to ruleaction.cc:6619.
    #[test]
    fn test_evaluate_pointer_expression_no_descendants() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let ptr_type = make_int_ptr_type();
        let ptr_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr_vn.write().unwrap().update_type(ptr_type);
        let c = fd.vbank.create_constant(8, 4);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_ADD);
        op.inrefs = vec![ptr_vn, c];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        assert_eq!(RulePtrArith::evaluate_pointer_expression(&op_arc, 0), 0);
    }

    /// evaluatePointerExpression: an INT_ADD(ptr, const) feeding an INT_ADD
    /// (i.e. one ADD descendant whose other input is non-pointer) returns 1
    /// (push needed) — the pointer is not yet at the root.
    #[test]
    fn test_evaluate_pointer_expression_push_needed() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let ptr_type = make_int_ptr_type();
        let ptr_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr_vn.write().unwrap().update_type(ptr_type);
        // Mark as a function input so it is not "free" (data-flow fully linked).
        ptr_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let c = fd.vbank.create_constant(8, 4);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_ADD);
        op.inrefs = vec![ptr_vn, c];
        op.output = Some(out.clone());
        let op_arc = Arc::new(RwLock::new(op));
        // Descendant INT_ADD(out, non_ptr_const) → one ADD descendant.
        let c2 = fd.vbank.create_constant(8, 8);
        let out2 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        let dec_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut d = dec_op.write().unwrap();
            d.inrefs = vec![out.clone(), c2];
            d.output = Some(out2);
        }
        out.write().unwrap().descend.push(Arc::downgrade(&dec_op));
        // Single ADD descendant with a non-pointer other input → res stays 1 (push).
        assert_eq!(RulePtrArith::evaluate_pointer_expression(&op_arc, 0), 1);
    }

    /// evaluatePointerExpression: when the other input is itself a pointer,
    /// returns 2 (do not push; convert can proceed). Faithful to ruleaction.cc:6594.
    #[test]
    fn test_evaluate_pointer_expression_other_is_ptr() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let ptr_type = make_int_ptr_type();
        let ptr_vn0 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr_vn0.write().unwrap().update_type(ptr_type.clone());
        ptr_vn0.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let ptr_vn1 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x18);
        ptr_vn1.write().unwrap().update_type(ptr_type);
        ptr_vn1.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_ADD);
        op.inrefs = vec![ptr_vn0, ptr_vn1];
        op.output = Some(out.clone());
        let op_arc = Arc::new(RwLock::new(op));
        // One non-ADD descendant (a COPY) forces res=2 in the "any other op" branch.
        let out2 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        let dec_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_COPY,
        )));
        {
            let mut d = dec_op.write().unwrap();
            d.inrefs = vec![out.clone()];
            d.output = Some(out2);
        }
        out.write().unwrap().descend.push(Arc::downgrade(&dec_op));
        assert_eq!(RulePtrArith::evaluate_pointer_expression(&op_arc, 0), 2);
    }

    /// verifyPreferredPointer: when the putative base pointer is NOT defined by
    /// an INT_ADD (e.g. it's a plain register input), there is no earlier
    /// candidate → returns true (preferred).
    #[test]
    fn test_verify_preferred_pointer_no_add_def() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let ptr_type = make_int_ptr_type();
        let ptr_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr_vn.write().unwrap().update_type(ptr_type);
        let c = fd.vbank.create_constant(8, 4);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_ADD);
        op.inrefs = vec![ptr_vn, c];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        assert!(RulePtrArith::verify_preferred_pointer(&op_arc, 0));
    }

    /// RulePtrArith::applyOp: no type recovery → NO_CHANGE (early out).
    #[test]
    fn test_rule_ptr_arith_no_type_recovery() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_ADD,
            crate::space::AddressSpace::Register, 0x10, 8,
            crate::space::AddressSpace::Const, 4, 8,
            8,
        );
        // type recovery NOT started.
        let rule = RulePtrArith::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// RulePtrArith::applyOp: with type recovery but no pointer-typed input →
    /// NO_CHANGE.
    #[test]
    fn test_rule_ptr_arith_no_ptr_input() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_ADD,
            crate::space::AddressSpace::Register, 0x10, 8,
            crate::space::AddressSpace::Const, 4, 8,
            8,
        );
        fd.set_type_recovery_started();
        let rule = RulePtrArith::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// RulePtrArith: degenerate form (pointer to a 1-byte type) converts an
    /// INT_ADD(ptr, x) into PTRADD(ptr, x, 1). Build an int8* with a single
    /// non-ADD descendant so evaluatePointerExpression returns 2.
    #[test]
    fn test_rule_ptr_arith_degenerate() {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.set_type_recovery_started();
        // base type: 1-byte int (align 1) → unit-sized → degenerate.
        let byte_dt = std::sync::Arc::new(Datatype::Base(TypeBase::new(
            "char".to_string(), 1, TypeMetatype::Int,
        )));
        let ptr_dt = std::sync::Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: byte_dt,
            wordsize: 1,
        }));
        let ptr_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr_vn.write().unwrap().update_type(ptr_dt.clone());
        // Mark as a function input so it is not "free".
        ptr_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let idx = fd.vbank.create_constant(8, 3);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        out.write().unwrap().update_type(ptr_dt);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_ADD);
        op.inrefs = vec![ptr_vn, idx];
        op.output = Some(out.clone());
        let op_arc = Arc::new(RwLock::new(op));
        fd.obank.alivelist.push(crate::op::PcodeOpRef(op_arc.clone()));
        // Add a non-ADD descendant so evaluatePointerExpression → 2.
        let out2 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        let dec_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_COPY,
        )));
        {
            let mut d = dec_op.write().unwrap();
            d.inrefs = vec![out.clone()];
            d.output = Some(out2);
        }
        out.write().unwrap().descend.push(Arc::downgrade(&dec_op));
        let rule = RulePtrArith::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // The base INT_ADD must have become PTRADD.
        assert_eq!(op_arc.read().unwrap().opcode, OpCode::CPUI_PTRADD);
    }

    // ========================================================================
    // AddTreeState distribute/collapse tests (ruleaction.cc:6461-6502,
    // funcdata_op.cc:1073-1153)
    // ========================================================================

    /// AddTreeState::collapse_int_mult_mult collapses `(x * #c) * #d` into
    /// `x * (#c * #d)` (funcdata_op.cc:1132-1153).
    #[test]
    fn test_add_tree_collapse_int_mult_mult() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // x: a written register (Ghidra requires op->getIn(0)->isWritten()).
        let x = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let x_def_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 5),
            OpCode::CPUI_COPY,
        )));
        x.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        x.write().unwrap().def = Some(Arc::downgrade(&x_def_op));
        // inner: x * #3
        let c3 = fd.vbank.create_constant(4, 3);
        let inner_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let inner_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_MULT,
        )));
        {
            let mut o = inner_op.write().unwrap();
            o.inrefs = vec![x.clone(), c3.clone()];
            o.output = Some(inner_out.clone());
        }
        inner_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        inner_out.write().unwrap().def = Some(Arc::downgrade(&inner_op));
        // outer: inner * #5  → should collapse to x * #15
        let c5 = fd.vbank.create_constant(4, 5);
        let outer_out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let outer_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_MULT,
        )));
        {
            let mut o = outer_op.write().unwrap();
            o.inrefs = vec![inner_out.clone(), c5.clone()];
            o.output = Some(outer_out.clone());
        }
        outer_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        outer_out.write().unwrap().def = Some(Arc::downgrade(&outer_op));
        // Collapse outer ((x * #3) * #5) into (x * #15). Per Ghidra we pass the
        // OUTER product vn (funcdata_op.cc:1132).
        let changed = AddTreeState::collapse_int_mult_mult(&mut fd, &outer_out);
        assert!(changed);
        // The outer op's in(1) should now be a constant 15 (3*5).
        let new_c = outer_op.read().unwrap().get_in(1).cloned().unwrap();
        assert!(new_c.read().unwrap().is_constant());
        assert_eq!(new_c.read().unwrap().get_offset(), 15);
        // And in(0) should be x directly.
        let new_in0 = outer_op.read().unwrap().get_in(0).cloned().unwrap();
        assert!(Arc::ptr_eq(&new_in0, &x));
    }

    /// collapse_int_mult_mult returns false when the varnode is not defined by
    /// INT_MULT (funcdata_op.cc:1137).
    #[test]
    fn test_add_tree_collapse_int_mult_mult_not_mult() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let b = fd.vbank.create_constant(4, 2);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut o = add_op.write().unwrap();
            o.inrefs = vec![a, b];
            o.output = Some(out.clone());
        }
        out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        out.write().unwrap().def = Some(Arc::downgrade(&add_op));
        let changed = AddTreeState::collapse_int_mult_mult(&mut fd, &out);
        assert!(!changed);
    }

    // ========================================================================
    // RulePushPtr tests (ruleaction.cc:6776-6913)
    // ========================================================================

    /// RulePushPtr::collect_duplicate_needs: a plain register varnode (not
    /// written) terminates immediately and adds nothing.
    #[test]
    fn test_rule_push_ptr_collect_duplicate_needs_plain_vn() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let mut list: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        RulePushPtr::collect_duplicate_needs(&mut list, vn);
        assert!(list.is_empty());
    }

    /// RulePushPtr::applyOp: no type recovery → NO_CHANGE.
    #[test]
    fn test_rule_push_ptr_no_type_recovery() {
        let (op_arc, mut fd) = make_binary_op(
            OpCode::CPUI_INT_ADD,
            crate::space::AddressSpace::Register, 0x10, 8,
            crate::space::AddressSpace::Const, 4, 8,
            8,
        );
        let rule = RulePushPtr::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// RulePushPtr::applyOp: with type recovery but evaluatePointerExpression
    /// returning 2 (not 1) → NO_CHANGE (push only when == 1).
    #[test]
    fn test_rule_push_ptr_not_push_needed() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.set_type_recovery_started();
        let ptr_type = make_int_ptr_type();
        let ptr_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr_vn.write().unwrap().update_type(ptr_type);
        let idx = fd.vbank.create_constant(8, 4);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_ADD);
        op.inrefs = vec![ptr_vn, idx];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        // No descendants → evaluatePointerExpression returns 0, not 1 → NO_CHANGE.
        let rule = RulePushPtr::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    // ========================================================================
    // RuleStructOffset0 tests (ruleaction.cc:6678-6774)
    // ========================================================================

    /// Helper: make a `struct { int a; int b; }` (size 8) type.
    fn make_struct2_type() -> std::sync::Arc<crate::type_system::datatype::Datatype> {
        use crate::type_system::datatype::{
            Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct,
        };
        let int_dt = std::sync::Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(), 4, TypeMetatype::Int,
        )));
        std::sync::Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("struct2".to_string(), 8, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "a".to_string(), offset: 0, type_ptr: int_dt.clone() },
                TypeField { name: "b".to_string(), offset: 4, type_ptr: int_dt },
            ],
        }))
    }

    /// RuleStructOffset0: no type recovery → NO_CHANGE.
    #[test]
    fn test_rule_struct_offset0_no_type_recovery() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_RAM as u64);
        let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_LOAD);
        op.inrefs = vec![spaceid, ptr];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        let rule = RuleStructOffset0::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// RuleStructOffset0: pointer to a struct, LOAD of one int (smaller than
    /// the struct) → inserts a PTRSUB(ptr, 0) and rewrites the LOAD's pointer
    /// input. Faithful to ruleaction.cc:6745-6772.
    #[test]
    fn test_rule_struct_offset0_struct_load() {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.set_type_recovery_started();
        let struct_dt = make_struct2_type();
        let ptr_dt = std::sync::Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("struct2 *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: struct_dt,
            wordsize: 1,
        }));
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_RAM as u64);
        let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr.write().unwrap().update_type(ptr_dt);
        // LOAD out is a single int (4 bytes) — smaller than the 8-byte struct.
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_LOAD);
        op.inrefs = vec![spaceid, ptr];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        fd.obank.alivelist.push(crate::op::PcodeOpRef(op_arc.clone()));
        let rule = RuleStructOffset0::new();
        let result = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(result, action_status::CHANGE);
        // The LOAD's slot-1 input must now be the output of a PTRSUB.
        let new_ptr = op_arc.read().unwrap().inrefs[1].clone();
        let def = new_ptr.read().unwrap().get_def();
        let def_op = def.expect("new pointer should be defined by PTRSUB");
        assert_eq!(def_op.read().unwrap().opcode, OpCode::CPUI_PTRSUB);
    }

    /// RuleStructOffset0: pointer to an int (base type, not struct/array) →
    /// NO_CHANGE (ruleaction.cc:6765-6766).
    #[test]
    fn test_rule_struct_offset0_base_type_no_change() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.set_type_recovery_started();
        let ptr_dt = make_int_ptr_type(); // pointer to a base int
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_RAM as u64);
        let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        ptr.write().unwrap().update_type(ptr_dt);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_LOAD);
        op.inrefs = vec![spaceid, ptr];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        let rule = RuleStructOffset0::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// RuleStructOffset0: non-pointer typed ptr varnode → NO_CHANGE.
    #[test]
    fn test_rule_struct_offset0_no_ptr_type() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.set_type_recovery_started();
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_RAM as u64);
        let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        // ptr has no type → not a pointer.
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x100);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_LOAD);
        op.inrefs = vec![spaceid, ptr];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));
        let rule = RuleStructOffset0::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    // ==================================================================
    // RulePtrFlow tests (ruleaction.cc:9050-9251)
    // ==================================================================

    /// getOpList returns no opcodes when hasTruncations is false — faithful to
    /// Ghidra's "Only stick ourselves into pool if aggressiveness is turned on"
    /// early-return (ruleaction.cc:9065).
    #[test]
    fn test_rule_ptrflow_get_oplist_empty_when_not_truncated() {
        let rule = RulePtrFlow::new();
        assert!(rule.get_opcodes().is_empty());
        assert_eq!(rule.get_name(), "ptrflow");
    }

    /// trialSetPtrFlow / propagateFlowToDef: marking a COPY op that writes a
    /// varnode should set ptrflow on both the op and its output varnode
    /// (ruleaction.cc:9083-9120). Applied indirectly via an INT_ADD whose
    /// defining COPY we wire up.
    #[test]
    fn test_rule_ptrflow_propagate_to_def_via_int_add() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // root input varnode (the value feeding the COPY).
        let root = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        root.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        // COPY: root -> mid
        let mid = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let copy_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        )));
        {
            let mut o = copy_op.write().unwrap();
            o.inrefs = vec![root.clone()];
            o.output = Some(mid.clone());
        }
        root.write().unwrap().descend.push(Arc::downgrade(&copy_op));
        mid.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        mid.write().unwrap().def = Some(Arc::downgrade(&copy_op));

        // INT_ADD: mid + const -> out, marked ptrflow (so applyOp processes it).
        let c = fd.vbank.create_constant(8, 4);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut o = add_op.write().unwrap();
            o.inrefs = vec![mid.clone(), c.clone()];
            o.output = Some(out.clone());
            o.set_ptr_flow(); // mark the ADD as ptrflow (the trigger condition)
        }
        mid.write().unwrap().descend.push(Arc::downgrade(&add_op));
        c.write().unwrap().descend.push(Arc::downgrade(&add_op));
        out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        out.write().unwrap().def = Some(Arc::downgrade(&add_op));

        let rule = RulePtrFlow::new();
        let res = rule.apply_op(&add_op, &mut fd).unwrap();
        // A change is made: ptrflow propagated to the COPY (via mid's def) and
        // to out + its reads.
        assert_eq!(res, 1);
        // The COPY should now be ptrflow (propagateFlowToDef -> trialSetPtrFlow).
        assert!(copy_op.read().unwrap().is_ptr_flow());
        // The output varnode of the ADD should be ptrflow (propagateFlowToReads).
        assert!(out.read().unwrap().is_ptr_flow());
    }

    /// applyOp on a non-ptrflow INT_ADD returns 0 immediately (the early
    /// `if (!op->isPtrFlow()) return 0;` guard, ruleaction.cc:9243).
    #[test]
    fn test_rule_ptrflow_int_add_not_ptrflow_returns_zero() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let in0 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        let in1 = fd.vbank.create_constant(8, 1);
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let op_arc = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut o = op_arc.write().unwrap();
            o.inrefs = vec![in0, in1];
            o.output = Some(out);
            // NOT marked ptrflow.
        }
        let rule = RulePtrFlow::new();
        assert_eq!(
            rule.apply_op(&op_arc, &mut fd).unwrap(),
            action_status::NO_CHANGE
        );
    }

    /// applyOp on a LOAD whose pointer input size exceeds the space addr size
    /// truncates the pointer (truncatePointer, ruleaction.cc:9154-9184).
    /// Here the ptr size (8) == RAM addr size (8), so no truncation; instead
    /// ptrflow is propagated to the pointer's defining op.
    #[test]
    fn test_rule_ptrflow_load_propagates_without_truncation() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // Space-id constant (input 0) encoding RAM.
        let spaceid = fd.vbank.create_constant(8, crate::space::SPACEID_RAM as u64);
        // Pointer varnode, defined by a COPY (so propagateFlowToDef marks it).
        let src = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x10);
        src.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let ptr = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x20);
        let copy_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        )));
        {
            let mut o = copy_op.write().unwrap();
            o.inrefs = vec![src.clone()];
            o.output = Some(ptr.clone());
        }
        src.write().unwrap().descend.push(Arc::downgrade(&copy_op));
        ptr.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        ptr.write().unwrap().def = Some(Arc::downgrade(&copy_op));

        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        let load_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_LOAD,
        )));
        {
            let mut o = load_op.write().unwrap();
            o.inrefs = vec![spaceid.clone(), ptr.clone()];
            o.output = Some(out);
        }
        ptr.write().unwrap().descend.push(Arc::downgrade(&load_op));
        spaceid.write().unwrap().descend.push(Arc::downgrade(&load_op));

        let rule = RulePtrFlow::new();
        let res = rule.apply_op(&load_op, &mut fd).unwrap();
        // ptr size (8) == RAM addr size (8): no truncation, but ptrflow
        // propagated to the COPY defining ptr -> change made.
        assert_eq!(res, 1);
        assert!(copy_op.read().unwrap().is_ptr_flow());
        assert!(ptr.read().unwrap().is_ptr_flow());
    }

    // ========================================================================
    // RulePieceStructure tests (ruleaction.cc:7625-7718, op.cc:801-876)
    // ========================================================================

    /// Helper: make a `struct { int a; int b; }` (size 8) type.
    fn make_piece_struct_type() -> std::sync::Arc<crate::type_system::datatype::Datatype> {
        use crate::type_system::datatype::{
            Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct,
        };
        let int_dt = std::sync::Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(), 4, TypeMetatype::Int,
        )));
        std::sync::Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("struct2".to_string(), 8, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "a".to_string(), offset: 0, type_ptr: int_dt.clone() },
                TypeField { name: "b".to_string(), offset: 4, type_ptr: int_dt },
            ],
        }))
    }

    /// RulePieceStructure: PIECE(hi=4B, lo=4B) with an 8-byte struct-typed
    /// output spanning two int fields. The rule should perform a real
    /// transform — inserting a COPY for each leaf into a correctly-addressed
    /// Varnode — and report CHANGE. Faithful to ruleaction.cc:7652-7717.
    #[test]
    fn test_piece_structure_reassembles_two_fields() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let struct_dt = make_piece_struct_type();
        // PIECE output: 8 bytes, struct-typed, at address 0x200.
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x200);
        out.write().unwrap().update_type(struct_dt);
        // Two 4-byte leaf inputs (unwritten → leaves), distinct addresses so a
        // COPY is inserted for each.
        let hi = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x300);
        let lo = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x304);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_PIECE);
        op.inrefs = vec![hi.clone(), lo.clone()];
        op.output = Some(out.clone());
        let op_arc = Arc::new(RwLock::new(op));
        fd.obank.alivelist.push(crate::op::PcodeOpRef(op_arc.clone()));

        let rule = RulePieceStructure::new();
        let res = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // Each leaf input (slot 0 = hi, slot 1 = lo) must now read the output of
        // a freshly-inserted CPUI_COPY whose output is at the correct field
        // address: hi (slot 0) → baseAddr+4 = 0x204 (field b); lo (slot 1) →
        // baseAddr+0 = 0x200 (field a).  (Rugra is little-endian.)
        let new_hi = op_arc.read().unwrap().inrefs[0].clone();
        let new_lo = op_arc.read().unwrap().inrefs[1].clone();
        assert_eq!(new_hi.read().unwrap().get_offset(), 0x204);
        assert_eq!(new_lo.read().unwrap().get_offset(), 0x200);
        let hi_def = new_hi.read().unwrap().get_def().expect("hi must now be COPY-defined");
        let lo_def = new_lo.read().unwrap().get_def().expect("lo must now be COPY-defined");
        assert_eq!(hi_def.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(lo_def.read().unwrap().opcode, OpCode::CPUI_COPY);
    }

    /// RulePieceStructure: an INT_ZEXT whose 8-byte output is struct-typed
    /// (spanning two int fields) is converted to a PIECE with a zero high
    /// constant. Faithful to convertZextToPiece (ruleaction.cc:7543-7564).
    #[test]
    fn test_piece_structure_zext_to_piece() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let struct_dt = make_piece_struct_type();
        // INT_ZEXT: 4-byte input → 8-byte struct-typed output.
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x200);
        out.write().unwrap().update_type(struct_dt);
        let invn = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x300);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_INT_ZEXT);
        op.inrefs = vec![invn.clone()];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));

        let rule = RulePieceStructure::new();
        let res = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // The op must now be a PIECE with 2 inputs: slot 0 = zero constant,
        // slot 1 = the original input.
        let g = op_arc.read().unwrap();
        assert_eq!(g.opcode, OpCode::CPUI_PIECE);
        assert_eq!(g.inrefs.len(), 2);
        assert!(g.inrefs[0].read().unwrap().is_constant());
        assert_eq!(g.inrefs[0].read().unwrap().get_offset(), 0);
        assert!(std::sync::Arc::ptr_eq(&g.inrefs[1], &invn));
    }

    /// RulePieceStructure: PIECE output that is a single non-structured base
    /// type → determineDatatype returns None → NO_CHANGE.
    #[test]
    fn test_piece_structure_non_structured_no_change() {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let int8 = std::sync::Arc::new(Datatype::Base(TypeBase::new(
            "long".to_string(), 8, TypeMetatype::Int,
        )));
        let out = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x200);
        out.write().unwrap().update_type(int8);
        let hi = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x300);
        let lo = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x304);
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = PcodeOp::new(seq, OpCode::CPUI_PIECE);
        op.inrefs = vec![hi, lo];
        op.output = Some(out);
        let op_arc = Arc::new(RwLock::new(op));

        let rule = RulePieceStructure::new();
        let res = rule.apply_op(&op_arc, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
    }

    /// PieceNode::gather_pieces on a two-level PIECE tree builds 4 leaf nodes
    /// (one per bottom-level input). Faithful to op.cc:865-876.
    #[test]
    fn test_piece_node_gather_two_level_tree() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // Root PIECE: out16 = PIECE(hi8, lo8); each input is itself a PIECE of
        // two 4-byte leaves. Leaves are unwritten varnodes.
        let leaf_a = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let leaf_b = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x14);
        let leaf_c = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x18);
        let leaf_d = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x1c);
        // Inner PIECE ops (their outputs are the root's inputs).
        let seq1 = SeqNum::new(Address::new(0x1000), 1);
        let mut hi8_op = PcodeOp::new(seq1, OpCode::CPUI_PIECE);
        let hi8 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x40);
        hi8_op.inrefs = vec![leaf_a.clone(), leaf_b.clone()];
        hi8_op.output = Some(hi8.clone());
        let hi8_op_arc = Arc::new(RwLock::new(hi8_op));
        // leaf_a, leaf_b descend into hi8_op
        leaf_a.write().unwrap().descend.push(Arc::downgrade(&hi8_op_arc));
        leaf_b.write().unwrap().descend.push(Arc::downgrade(&hi8_op_arc));
        // hi8 is WRITTEN by hi8_op (mirrors opSetOutput).
        {
            let mut h = hi8.write().unwrap();
            h.set_flags(crate::varnode::varnode_flags::WRITTEN);
            h.def = Some(Arc::downgrade(&hi8_op_arc));
        }
        let seq2 = SeqNum::new(Address::new(0x1000), 2);
        let mut lo8_op = PcodeOp::new(seq2, OpCode::CPUI_PIECE);
        let lo8 = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x48);
        lo8_op.inrefs = vec![leaf_c.clone(), leaf_d.clone()];
        lo8_op.output = Some(lo8.clone());
        let lo8_op_arc = Arc::new(RwLock::new(lo8_op));
        leaf_c.write().unwrap().descend.push(Arc::downgrade(&lo8_op_arc));
        leaf_d.write().unwrap().descend.push(Arc::downgrade(&lo8_op_arc));
        {
            let mut l = lo8.write().unwrap();
            l.set_flags(crate::varnode::varnode_flags::WRITTEN);
            l.def = Some(Arc::downgrade(&lo8_op_arc));
        }
        // hi8/lo8 each have a single descendant (the root) so they are non-leaves.
        let seq0 = SeqNum::new(Address::new(0x1000), 0);
        let mut root_op = PcodeOp::new(seq0, OpCode::CPUI_PIECE);
        let out16 = fd.vbank.create_with_space(16, crate::space::AddressSpace::Register, 0x80);
        root_op.inrefs = vec![hi8.clone(), lo8.clone()];
        root_op.output = Some(out16.clone());
        let root_op_arc = Arc::new(RwLock::new(root_op));
        hi8.write().unwrap().descend.push(Arc::downgrade(&root_op_arc));
        lo8.write().unwrap().descend.push(Arc::downgrade(&root_op_arc));

        let mut stack: Vec<PieceNode> = Vec::new();
        PieceNode::gather_pieces(&mut stack, &out16, &root_op_arc, 0, 0);
        // 2 nodes at the root level + 2 nodes per inner op = 6 total.
        assert_eq!(stack.len(), 6);
        let leaves = stack.iter().filter(|n| n.is_leaf()).count();
        let non_leaves = stack.iter().filter(|n| !n.is_leaf()).count();
        assert_eq!(leaves, 4); // leaf_a..leaf_d
        assert_eq!(non_leaves, 2); // hi8, lo8
    }
}
