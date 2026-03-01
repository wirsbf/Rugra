//! Optimization module for Rugra Decompiler (Phase 8)
//!
//! This module implements various optimization passes to simplify the P-code IR:
//! - Constant Folding: Evaluates expressions with constant operands at compile time.
//! - Algebraic Simplification: Simplifies expressions using algebraic identities.
//! - Dead Code Elimination: Removes operations whose results are not used (replaces with NOP).

use crate::opcodes::OpCode;
use crate::pcode::{ PcodeOperation, Program};
use crate::analysis::FunctionAnalysis;
use super::rules::{RuleController, Action, ActionSimplify};
use std::collections::HashSet;

/// Optimize the function by applying various simplification passes iteratively.
pub fn optimize_function(program: &mut Program, analysis: &FunctionAnalysis) {
    // 1. Build the Action Pipeline
    let mut pipeline: Vec<Box<dyn Action>> = Vec::new();

    // Standard simplification rules (Constant Folding, Algebraic, Type-based)
    pipeline.push(Box::new(ActionSimplify::new(RuleController::with_defaults())));

    // Global Dead Code Elimination
    pipeline.push(Box::new(ActionDeadCodeElimination));

    // 2. Execute Pipeline iteratively until convergence
    let mut changed = true;
    let mut pass_count = 0;
    const MAX_PASSES: usize = 10;

    while changed && pass_count < MAX_PASSES {
        changed = false;
        pass_count += 1;

        for action in &pipeline {
            if action.apply(program, analysis) {
                changed = true;
            }
        }
    }
}

/// Action: Global Dead Code Elimination
///
/// Removes operations whose results are not used anywhere in the function.
/// Leverages global SSA information if available for precision.
pub struct ActionDeadCodeElimination;

impl Action for ActionDeadCodeElimination {
    fn name(&self) -> &'static str {
        "Global Dead Code Elimination"
    }

    fn apply(&self, program: &mut Program, analysis: &FunctionAnalysis) -> bool {
        let nop_count = program.operations().iter().filter(|op| op.opcode == OpCode::CPUI_COPY /* NOP */).count();
        eprintln!("[DCE] Start: Found {} NOPs in program", nop_count);

        let cfg = match &analysis.cfg {
            Some(c) => c,
            None => return false,
        };

        // 1. Identify used varnodes
        let mut used_keys = HashSet::new();

        // Check SSA uses if available (Fast & Precise)
        if let Some(ssa) = &analysis.ssa {
            for (key, uses) in &ssa.uses {
                if !uses.is_empty() {
                    used_keys.insert(key.clone());
                }
            }
            eprintln!("[DCE] Found {} used variables from SSA", used_keys.len());
        } else {
            // Fallback: Full scan of operations (Slower)
            for op in program.operations() {
                if op.opcode == OpCode::CPUI_COPY /* NOP */ { continue; }
                for input in op.inputs.as_slice() {
                    // Unique space vars are SSA temps, or any varnode with version > 0
                    if input.is_unique() || input.version() > 0 {
                        used_keys.insert(format!("{:?}_{:x}_{}_{}", input.space(), input.offset(), input.size(), input.version()));
                    }
                }
            }
        }

        let mut changed = false;
        let op_count = program.operation_count();

        // 2. Mark dead operations as NOP
        for block in &cfg.blocks {
            for &op_idx in &block.operations {
                if op_idx >= op_count { continue; }

                let is_dead = {
                    let op = &program.operations()[op_idx];
                    if op.opcode == OpCode::CPUI_COPY /* NOP */ || op.has_side_effects() {
                        false
                    } else if let Some(output) = op.output.as_ref() {
                        // Eliminate dead temporaries (Unique) or SSA-versioned variables
                        if output.is_unique() || output.version() > 0 {
                            let key = format!("{:?}_{:x}_{}_{}", output.space(), output.offset(), output.size(), output.version());
                            !used_keys.contains(&key)
                        } else {
                            false
                        }
                    } else {
                        // No output and no side effects -> dead
                        true
                    }
                };

                if is_dead {
                    let op = &mut program.operations_mut()[op_idx];
                    let nop = PcodeOperation::new(op.id(), op.seqnum(), OpCode::CPUI_COPY /* NOP */, None, Vec::new());
                    *op = nop;
                    changed = true;
                }
            }
        }

        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::cfg::{BasicBlock, ControlFlowGraph};
    use crate::pcode::PcodeBuilder;
    use crate::Address;

    #[test]
    fn test_constant_folding() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));
        let r0 = Varnode::new_register(0, 4);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(r0), vec![
            Varnode::new_constant(10, 4),
            Varnode::new_constant(20, 4)
        ]);

        let mut program = builder.build();
        let mut analysis = FunctionAnalysis::new();
        let mut cfg = ControlFlowGraph::default();
        cfg.blocks.push(BasicBlock {
            index: 0,
            operations: vec![0],
            start_addr: Address::new(0x1000),
            end_addr: Address::new(0x1010),
            successors: Vec::new(),
            predecessors: Vec::new(),
        });
        analysis.cfg = Some(cfg);

        optimize_function(&mut program, &analysis);

        let op = &program.operations()[0];
        assert_eq!(op.opcode, OpCode::CPUI_COPY);
        assert_eq!(op.inputs.as_slice()[0].constant_value(), Some(30));
    }

    #[test]
    fn test_algebraic_simplification() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));
        builder.add_op(OpCode::CPUI_INT_ADD, Some(Varnode::new_register(0, 4)), vec![Varnode::new_register(1, 4), Varnode::new_constant(0, 4)]);
        builder.add_op(OpCode::CPUI_INT_MULT, Some(Varnode::new_register(2, 4)), vec![Varnode::new_register(3, 4), Varnode::new_constant(1, 4)]);
        builder.add_op(OpCode::CPUI_INT_XOR, Some(Varnode::new_register(4, 4)), vec![Varnode::new_register(5, 4), Varnode::new_register(5, 4)]);

        let mut program = builder.build();
        let mut analysis = FunctionAnalysis::new();
        let mut cfg = ControlFlowGraph::default();
        cfg.blocks.push(BasicBlock {
            index: 0,
            operations: vec![0, 1, 2],
            start_addr: Address::new(0x1000),
            end_addr: Address::new(0x1010),
            successors: Vec::new(),
            predecessors: Vec::new(),
        });
        analysis.cfg = Some(cfg);

        optimize_function(&mut program, &analysis);

        let ops = program.operations();
        assert_eq!(ops[0].opcode(), OpCode::CPUI_COPY);
        assert_eq!(ops[1].opcode(), OpCode::CPUI_COPY);
        assert_eq!(ops[2].opcode(), OpCode::CPUI_COPY);
    }

    #[test]
    fn test_dead_code_elimination() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));
        builder.add_op(OpCode::CPUI_INT_ADD, Some(Varnode::new_unique(10, 4)), vec![Varnode::new_register(1, 4), Varnode::new_register(2, 4)]);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(Varnode::new_unique(20, 4)), vec![Varnode::new_register(3, 4), Varnode::new_register(4, 4)]);
        builder.add_op(OpCode::CPUI_COPY, Some(Varnode::new_register(5, 4)), vec![Varnode::new_unique(20, 4)]);

        let mut program = builder.build();
        let mut analysis = FunctionAnalysis::new();
        let mut cfg = ControlFlowGraph::default();
        cfg.blocks.push(BasicBlock {
            index: 0,
            operations: vec![0, 1, 2],
            start_addr: Address::new(0x1000),
            end_addr: Address::new(0x1010),
            successors: Vec::new(),
            predecessors: Vec::new(),
        });
        analysis.cfg = Some(cfg);

        optimize_function(&mut program, &analysis);

        let ops = program.operations();
        assert_eq!(ops[0].opcode(), OpCode::CPUI_COPY /* NOP */);
        assert!(ops[1].opcode() != OpCode::CPUI_COPY /* NOP */);
    }
}
