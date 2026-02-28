//! Constant folding rules
//!
//! Implements Ghidra's RuleConstant logic for folding operations with constant inputs.

use crate::pcode::{PcodeOp, Varnode, PcodeOperation, Program};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::FunctionAnalysis;
use super::{Rule, RuleResult};

/// Rule: Fold operations with constant inputs into a single constant copy
pub struct RuleConstantFolding;

impl Rule for RuleConstantFolding {
    fn name(&self) -> &'static str {
        "ConstantFolding"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        None // Generic rule that inspects opcode inside apply
    }

    fn apply(&self, op_idx: usize, program: &mut Program, _cfg: &ControlFlowGraph, _analysis: &FunctionAnalysis) -> RuleResult {
        let op = &program.operations()[op_idx];

        // Filter relevant opcodes
        match op.opcode() {
            PcodeOp::IntAdd | PcodeOp::IntSub | PcodeOp::IntMult | PcodeOp::IntDiv |
            PcodeOp::IntSDiv | PcodeOp::IntRem | PcodeOp::IntSRem |
            PcodeOp::IntAnd | PcodeOp::IntOr | PcodeOp::IntXor |
            PcodeOp::IntNot | PcodeOp::IntNeg |
            PcodeOp::IntLeft | PcodeOp::IntRight | PcodeOp::IntSRight |
            PcodeOp::IntEqual | PcodeOp::IntNotEqual |
            PcodeOp::IntLess | PcodeOp::IntSLess |
            PcodeOp::IntLessEqual | PcodeOp::IntSLessEqual |
            PcodeOp::IntZext | PcodeOp::IntSext => {},
            _ => return RuleResult::Skipped,
        }

        // Check if output exists
        let output = match op.output() {
            Some(o) => o.clone(),
            None => return RuleResult::Skipped,
        };

        // Check if all inputs are constant
        let inputs = op.inputs();
        if inputs.is_empty() || !inputs.iter().all(|vn| vn.is_constant()) {
            return RuleResult::Skipped;
        }

        // Calculate result
        if let Some(result) = evaluate_constant_op(op.opcode(), inputs) {
            // Replace with Copy
            let new_input = Varnode::new_constant(result, output.size());

            let operations = program.operations_mut();
            let op_mut = &mut operations[op_idx];

            let new_op = PcodeOperation::new(
                op_mut.id(),
                op_mut.seqnum(),
                PcodeOp::Copy,
                Some(output),
                vec![new_input]
            );

            *op_mut = new_op;
            return RuleResult::Applied;
        }

        RuleResult::Skipped
    }
}

/// Helper to sign extend a value based on its byte size
fn sign_extend(val: u64, size: usize) -> i64 {
    let bits = size * 8;
    if bits >= 64 {
        return val as i64;
    }
    let shift = 64 - bits;
    let shifted = (val as i64) << shift;
    shifted >> shift
}

/// Helper to evaluate constant operations
pub fn evaluate_constant_op(opcode: PcodeOp, inputs: &[Varnode]) -> Option<u64> {
    if inputs.is_empty() {
        return None;
    }

    let val1 = inputs[0].constant_value()?;
    let size1 = inputs[0].size();

    // Unary ops
    match opcode {
        PcodeOp::IntNot => return Some(!val1),
        PcodeOp::IntNeg => return Some((-(val1 as i64)) as u64),
        PcodeOp::IntZext => return Some(val1),
        PcodeOp::IntSext => {
            let extended = sign_extend(val1, size1);
            return Some(extended as u64);
        }
        _ => {}
    }

    // Binary ops
    if inputs.len() < 2 {
        return None;
    }
    let val2 = inputs[1].constant_value()?;
    let size2 = inputs[1].size();

    match opcode {
        PcodeOp::IntAdd => Some(val1.wrapping_add(val2)),
        PcodeOp::IntSub => Some(val1.wrapping_sub(val2)),
        PcodeOp::IntMult => Some(val1.wrapping_mul(val2)),
        PcodeOp::IntDiv => if val2 == 0 { None } else { Some(val1.wrapping_div(val2)) },
        PcodeOp::IntSDiv => {
            if val2 == 0 { None } else {
                let s1 = sign_extend(val1, size1);
                let s2 = sign_extend(val2, size2);
                Some(s1.wrapping_div(s2) as u64)
            }
        },
        PcodeOp::IntRem => if val2 == 0 { None } else { Some(val1.wrapping_rem(val2)) },
        PcodeOp::IntSRem => {
            if val2 == 0 { None } else {
                let s1 = sign_extend(val1, size1);
                let s2 = sign_extend(val2, size2);
                Some(s1.wrapping_rem(s2) as u64)
            }
        },
        PcodeOp::IntAnd => Some(val1 & val2),
        PcodeOp::IntOr => Some(val1 | val2),
        PcodeOp::IntXor => Some(val1 ^ val2),
        PcodeOp::IntLeft => Some(val1.wrapping_shl(val2 as u32)),
        PcodeOp::IntRight => Some(val1.wrapping_shr(val2 as u32)),
        PcodeOp::IntSRight => {
            let s1 = sign_extend(val1, size1);
            Some(s1.wrapping_shr(val2 as u32) as u64)
        },
        PcodeOp::IntEqual => Some(if val1 == val2 { 1 } else { 0 }),
        PcodeOp::IntNotEqual => Some(if val1 != val2 { 1 } else { 0 }),
        PcodeOp::IntLess => Some(if val1 < val2 { 1 } else { 0 }),
        PcodeOp::IntSLess => {
            let s1 = sign_extend(val1, size1);
            let s2 = sign_extend(val2, size2);
            Some(if s1 < s2 { 1 } else { 0 })
        },
        PcodeOp::IntLessEqual => Some(if val1 <= val2 { 1 } else { 0 }),
        PcodeOp::IntSLessEqual => {
            let s1 = sign_extend(val1, size1);
            let s2 = sign_extend(val2, size2);
            Some(if s1 <= s2 { 1 } else { 0 })
        },
        _ => None,
    }
}
