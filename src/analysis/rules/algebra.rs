//! Algebraic simplification rules
//!
//! Rules for simplifying algebraic expressions (identities, strength reduction, etc.)

use crate::pcode::{PcodeOp, Program, Varnode, PcodeOperation};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::FunctionAnalysis;
use super::{Rule, RuleResult};

/// Rule: Simplify algebraic expressions
///
/// Implements:
/// - Identity: x + 0 -> x, x * 1 -> x, ...
/// - Nullifying: x * 0 -> 0, x & 0 -> 0
/// - Idempotence: x | x -> x, x & x -> x
/// - Cancellation: x - x -> 0, x ^ x -> 0
pub struct RuleAlgebraicSimplification;

impl Rule for RuleAlgebraicSimplification {
    fn name(&self) -> &'static str {
        "AlgebraicSimplification"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        None // Targets multiple opcodes
    }

    fn apply(&self, op_idx: usize, program: &mut Program, _cfg: &ControlFlowGraph, _analysis: &FunctionAnalysis) -> RuleResult {
        let op = &program.operations()[op_idx];

        // We only care about binary operations with output
        if op.output().is_none() || op.inputs().len() != 2 {
            return RuleResult::Skipped;
        }

        let input1 = &op.inputs()[0];
        let input2 = &op.inputs()[1];

        // Helper to check for specific constant value
        let is_const = |vn: &Varnode, val: u64| {
            vn.is_constant() && vn.offset() == val
        };

        let mut replacement: Option<Varnode> = None;

        match op.opcode() {
            PcodeOp::IntAdd => {
                // x + 0 = x
                if is_const(input2, 0) { replacement = Some(input1.clone()); }
                else if is_const(input1, 0) { replacement = Some(input2.clone()); }
            },
            PcodeOp::IntSub => {
                // x - 0 = x
                if is_const(input2, 0) { replacement = Some(input1.clone()); }
                // x - x = 0
                else if input1 == input2 { replacement = Some(Varnode::new_constant(0, input1.size())); }
            },
            PcodeOp::IntMult => {
                // x * 1 = x
                if is_const(input2, 1) { replacement = Some(input1.clone()); }
                else if is_const(input1, 1) { replacement = Some(input2.clone()); }
                // x * 0 = 0
                else if is_const(input2, 0) || is_const(input1, 0) {
                    replacement = Some(Varnode::new_constant(0, input1.size()));
                }
            },
            PcodeOp::IntAnd => {
                // x & 0 = 0
                if is_const(input2, 0) || is_const(input1, 0) {
                    replacement = Some(Varnode::new_constant(0, input1.size()));
                }
                // x & x = x
                else if input1 == input2 { replacement = Some(input1.clone()); }
            },
            PcodeOp::IntOr => {
                // x | 0 = x
                if is_const(input2, 0) { replacement = Some(input1.clone()); }
                else if is_const(input1, 0) { replacement = Some(input2.clone()); }
                // x | x = x
                else if input1 == input2 { replacement = Some(input1.clone()); }
            },
            PcodeOp::IntXor => {
                // x ^ 0 = x
                if is_const(input2, 0) { replacement = Some(input1.clone()); }
                else if is_const(input1, 0) { replacement = Some(input2.clone()); }
                // x ^ x = 0
                else if input1 == input2 {
                    replacement = Some(Varnode::new_constant(0, input1.size()));
                }
            },
            _ => {}
        }

        if let Some(repl_input) = replacement {
            let operations = program.operations_mut();
            let op_mut = &mut operations[op_idx];
            let output = op_mut.output().unwrap().clone();

            let new_op = PcodeOperation::new(
                op_mut.id(),
                op_mut.seqnum(),
                PcodeOp::Copy,
                Some(output),
                vec![repl_input],
            );
            *op_mut = new_op;
            return RuleResult::Applied;
        }

        RuleResult::Skipped
    }
}
