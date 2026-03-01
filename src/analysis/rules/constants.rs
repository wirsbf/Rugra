//! Constant folding rules
//!
//! Implements Ghidra's RuleConstant logic for folding operations with constant inputs.

use crate::opcodes::OpCode;
use crate::pcode::{ Varnode, PcodeOperation, Program};
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
        match op.opcode {
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV |
            OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM |
            OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR |
            OpCode::CPUI_INT_NOT | OpCode::CPUI_INT_NEG |
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT |
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL |
            OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS |
            OpCode::CPUI_INT_LESSEqual | OpCode::CPUI_INT_SLESSEqual |
            OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {},
            _ => return RuleResult::Skipped,
        }

        // Check if output exists
        let output = match op.output.as_ref() {
            Some(o) => o.clone(),
            None => return RuleResult::Skipped,
        };

        // Check if all inputs are constant
        let inputs = op.inputs.as_slice();
        if inputs.is_empty() || !inputs.iter().all(|vn| vn.is_constant()) {
            return RuleResult::Skipped;
        }

        // Calculate result
        if let Some(result) = evaluate_constant_op(op.opcode, inputs) {
            // Replace with Copy
            let new_input = Varnode::new_constant(result, output.size());

            let operations = program.operations_mut();
            let op_mut = &mut operations[op_idx];

            let new_op = PcodeOperation::new(
                op_mut.id(),
                op_mut.seqnum(),
                OpCode::CPUI_COPY,
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
        OpCode::CPUI_INT_NOT => return Some(!val1),
        OpCode::CPUI_INT_NEG => return Some((-(val1 as i64)) as u64),
        OpCode::CPUI_INT_ZEXT => return Some(val1),
        OpCode::CPUI_INT_SEXT => {
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
        OpCode::CPUI_INT_ADD => Some(val1.wrapping_add(val2)),
        OpCode::CPUI_INT_SUB => Some(val1.wrapping_sub(val2)),
        OpCode::CPUI_INT_MULT => Some(val1.wrapping_mul(val2)),
        OpCode::CPUI_INT_DIV => if val2 == 0 { None } else { Some(val1.wrapping_div(val2)) },
        OpCode::CPUI_INT_SDIV => {
            if val2 == 0 { None } else {
                let s1 = sign_extend(val1, size1);
                let s2 = sign_extend(val2, size2);
                Some(s1.wrapping_div(s2) as u64)
            }
        },
        OpCode::CPUI_INT_REM => if val2 == 0 { None } else { Some(val1.wrapping_rem(val2)) },
        OpCode::CPUI_INT_SREM => {
            if val2 == 0 { None } else {
                let s1 = sign_extend(val1, size1);
                let s2 = sign_extend(val2, size2);
                Some(s1.wrapping_rem(s2) as u64)
            }
        },
        OpCode::CPUI_INT_AND => Some(val1 & val2),
        OpCode::CPUI_INT_OR => Some(val1 | val2),
        OpCode::CPUI_INT_XOR => Some(val1 ^ val2),
        OpCode::CPUI_INT_LEFT => Some(val1.wrapping_shl(val2 as u32)),
        OpCode::CPUI_INT_RIGHT => Some(val1.wrapping_shr(val2 as u32)),
        OpCode::CPUI_INT_SRIGHT => {
            let s1 = sign_extend(val1, size1);
            Some(s1.wrapping_shr(val2 as u32) as u64)
        },
        OpCode::CPUI_INT_EQUAL => Some(if val1 == val2 { 1 } else { 0 }),
        OpCode::CPUI_INT_NOTEQUAL => Some(if val1 != val2 { 1 } else { 0 }),
        OpCode::CPUI_INT_LESS => Some(if val1 < val2 { 1 } else { 0 }),
        OpCode::CPUI_INT_SLESS => {
            let s1 = sign_extend(val1, size1);
            let s2 = sign_extend(val2, size2);
            Some(if s1 < s2 { 1 } else { 0 })
        },
        OpCode::CPUI_INT_LESSEqual => Some(if val1 <= val2 { 1 } else { 0 }),
        OpCode::CPUI_INT_SLESSEqual => {
            let s1 = sign_extend(val1, size1);
            let s2 = sign_extend(val2, size2);
            Some(if s1 <= s2 { 1 } else { 0 })
        },
        _ => None,
    }
}
