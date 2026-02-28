//! Dataflow optimization rules
//!
//! Rules for dataflow-based optimizations like copy propagation and dead code elimination.

use crate::pcode::{PcodeOp, Program, Varnode, PcodeOperation};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::FunctionAnalysis;
use super::{Rule, RuleResult};

/// Rule: Propagate copies to uses
///
/// If A = COPY B, replaces uses of A with B (if safe).
pub struct RuleCopyPropagation;

impl Rule for RuleCopyPropagation {
    fn name(&self) -> &'static str {
        "CopyPropagation"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        Some(PcodeOp::Copy)
    }

    fn apply(&self, op_idx: usize, program: &mut Program, _cfg: &ControlFlowGraph, _analysis: &FunctionAnalysis) -> RuleResult {
        // This is a simplified local copy propagation.
        // Full global copy prop requires SSA-based def-use chains which are expensive to
        // recompute inside a rule loop.
        // We look for:
        // 1. A = COPY B
        // 2. Immediate use of A in same block

        // Since we don't have easy access to "next uses" without iterating,
        // we can check if 'A' is temporary (Unique) and replace forward.

        let op = &program.operations()[op_idx];

        let output = match op.output() {
            Some(out) => out.clone(),
            None => return RuleResult::Skipped,
        };

        let input = match op.inputs().get(0) {
            Some(inp) => inp.clone(),
            None => return RuleResult::Skipped,
        };

        // Only propagate if output is a temporary (Unique) variable or SSA register
        // Propagating non-SSA registers/globals requires careful liveness checks
        if !output.is_unique() && output.version() == 0 {
            return RuleResult::Skipped;
        }

        // Scan forward to find uses.
        // For aggressive propagation in optimized binaries like 'curl', we scan the rest of the function.
        let mut replaced = false;

        for i in (op_idx + 1)..program.operation_count() {
            let next_op = &mut program.operations_mut()[i];

            // Safety check: if next_op redefines 'input', we must stop propagation
            // e.g. A = COPY B; B = C; ... use A (cannot become use B)
            if let Some(next_out) = next_op.output() {
                if next_out == &input {
                    break;
                }
            }

            // Replace uses of 'output' with 'input'
            for inp in next_op.inputs_mut() {
                if inp == &output {
                    *inp = input.clone();
                    replaced = true;
                }
            }

            // If next_op redefines 'output', we stop (new value for A)
            if let Some(next_out) = next_op.output() {
                if next_out == &output {
                    break;
                }
            }
        }

        if replaced {
            RuleResult::Applied
        } else {
            RuleResult::Skipped
        }
    }
}

/// Rule: Eliminate dead code
///
/// Removes operations whose output is unused (and have no side effects).
pub struct RuleDeadCodeElimination;

impl Rule for RuleDeadCodeElimination {
    fn name(&self) -> &'static str {
        "DeadCodeElimination"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        None // Applies to all ops
    }

    fn apply(&self, op_idx: usize, program: &mut Program, cfg: &ControlFlowGraph, analysis: &FunctionAnalysis) -> RuleResult {
        // Scope the immutable borrow of program
        let output = {
            let op = &program.operations()[op_idx];
            if op.has_side_effects() {
                return RuleResult::Skipped;
            }
            match op.output() {
                Some(o) => o.clone(),
                None => return RuleResult::Skipped,
            }
        };

        // Conservative check: only remove Unique (temporary) variables.
        // Removing registers or RAM locations requires precise inter-procedural or aliasing analysis.
        if !output.is_unique() {
            return RuleResult::Skipped;
        }

        let mut is_used = false;

        if let Some(ssa) = analysis.ssa.as_ref() {
            let ssa_name = format!("{:?}_{:x}_{}_{}", output.space(), output.offset(), output.size(), output.version());
            if let Some(use_blocks) = ssa.uses.get(&ssa_name) {
                if !use_blocks.is_empty() {
                    is_used = true;
                }
            }
        } else {
            // Local fallback
            let limit = std::cmp::min(program.operation_count(), op_idx + 200);
            for i in (op_idx + 1)..limit {
                let next_op = &program.operations()[i];
                for inp in next_op.inputs() {
                    if inp == &output {
                        is_used = true;
                        break;
                    }
                }
                if is_used { break; }
            }
        }

        if !is_used {
            // Mark as NOP
            let op_mut = &mut program.operations_mut()[op_idx];
            let nop = crate::pcode::PcodeOperation::new(
                op_mut.id(),
                op_mut.seqnum(),
                PcodeOp::Nop,
                None,
                Vec::new()
            );
            *op_mut = nop;
            return RuleResult::Applied;
        }

        RuleResult::Skipped
    }
}

/// Rule: SSA-based Global Copy Propagation
///
/// Propagates copies across basic block boundaries using SSA form information.
/// If A = COPY B, replaces all uses of A with B throughout the program.
pub struct RuleGlobalPropagation;

impl Rule for RuleGlobalPropagation {
    fn name(&self) -> &'static str {
        "GlobalPropagation"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        Some(PcodeOp::Copy)
    }

    fn apply(&self, op_idx: usize, program: &mut Program, cfg: &ControlFlowGraph, _analysis: &FunctionAnalysis) -> RuleResult {
        // This rule leverages the fact that in SSA form, each variable is defined exactly once.
        // If we find A = COPY B, and both are SSA variables, we can safely replace all uses of A with B.

        let (output, input) = {
            let op = &program.operations()[op_idx];
            let out = match op.output() {
                Some(o) => o.clone(),
                None => return RuleResult::Skipped,
            };
            let inp = match op.inputs().get(0) {
                Some(i) => i.clone(),
                None => return RuleResult::Skipped,
            };
            (out, inp)
        };

        // Safety: Only propagate if output is an SSA temporary or uniquely versioned register.
        // In SSA form, we expect versioned varnodes (version > 0).
        if output.version()
 == 0 && !output.is_constant() {
            return RuleResult::Skipped;
        }

        let mut replaced = false;
        // Full scan to replace all uses. In a more optimized version,
        // we would use ssa.uses[output] to find exact locations.
        for block in &cfg.blocks {
            for &idx in &block.operations {
                // Skip the definition itself
                if idx == op_idx { continue; }

                let next_op = &mut program.operations_mut()[idx];
                for arg in next_op.inputs_mut() {
                    if arg == &output {
                        *arg = input.clone();
                        replaced = true;
                    }
                }
            }
        }

        if replaced {
            RuleResult::Applied
        } else {
            RuleResult::Skipped
        }
    }
}

/// Rule: Type-based simplification
///
/// Uses global type information to:
/// 1. Resolve redundant casts (IntSext, IntZext) when types already match.
pub struct RuleTypePropagation;

impl Rule for RuleTypePropagation {
    fn name(&self) -> &'static str {
        "TypePropagation"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        None // Targets multiple opcodes (casts, memory ops)
    }

    fn apply(&self, op_idx: usize, program: &mut Program, _cfg: &ControlFlowGraph, analysis: &FunctionAnalysis) -> RuleResult {
        let op = &program.operations()[op_idx];
        let solver = match analysis.type_solver.as_ref() {
            Some(s) => s,
            None => return RuleResult::Skipped,
        };

        match op.opcode() {
            PcodeOp::IntZext | PcodeOp::IntSext => {
                // If input and output are inferred to have the same type/size, this is a COPY
                if let (Some(out_vn), Some(in_vn)) = (op.output(), op.inputs().get(0)) {
                    let out_key = format!("{:?}_{:x}_{}_{}", out_vn.space(), out_vn.offset(), out_vn.size(), out_vn.version());
                    let in_key = format!("{:?}_{:x}_{}_{}", in_vn.space(), in_vn.offset(), in_vn.size(), in_vn.version());

                    if let (Some(out_t), Some(in_t)) = (solver.get_type(&out_key), solver.get_type(&in_key)) {
                        if out_t == in_t && out_vn.size() == in_vn.size() {
                            // Replace redundant cast with COPY
                            let output = out_vn.clone();
                            let input = in_vn.clone();
                            let op_mut = &mut program.operations_mut()[op_idx];
                            *op_mut = PcodeOperation::new(
                                op_mut.id(),
                                op_mut.seqnum(),
                                PcodeOp::Copy,
                                Some(output),
                                vec![input]
                            );
                            return RuleResult::Applied;
                        }
                    }
                }
            }
            _ => {}
        }

        RuleResult::Skipped
    }
}



/// Rule: Eliminate identity copies (x = x)
pub struct RuleIdentityCopy;

impl Rule for RuleIdentityCopy {
    fn name(&self) -> &'static str {
        "IdentityCopy"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        Some(PcodeOp::Copy)
    }

    fn apply(&self, op_idx: usize, program: &mut Program, _cfg: &ControlFlowGraph, _analysis: &FunctionAnalysis) -> RuleResult {
        let op = &program.operations()[op_idx];
        if let (Some(out), Some(inp)) = (op.output(), op.inputs().get(0)) {
            if out == inp {
                // Identity copy: replace with Nop
                let op_mut = &mut program.operations_mut()[op_idx];
                *op_mut = PcodeOperation::new(op_mut.id(), op_mut.seqnum(), PcodeOp::Nop, None, Vec::new());
                return RuleResult::Applied;
            }
        }
        RuleResult::Skipped
    }
}

/// Rule: Eliminate redundant truncations
pub struct RuleTruncationElimination;

impl Rule for RuleTruncationElimination {
    fn name(&self) -> &'static str {
        "TruncationElimination"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        Some(PcodeOp::Trunc)
    }

    fn apply(&self, op_idx: usize, program: &mut Program, _cfg: &ControlFlowGraph, _analysis: &FunctionAnalysis) -> RuleResult {
        let op = &program.operations()[op_idx];

        if let (Some(out_vn), Some(in_vn)) = (op.output(), op.inputs().get(0)) {
            // If output and input size are the same, it's a copy
            if out_vn.size() == in_vn.size() {
                let output = out_vn.clone();
                let input = in_vn.clone();
                let op_mut = &mut program.operations_mut()[op_idx];
                *op_mut = PcodeOperation::new(op_mut.id(), op_mut.seqnum(), PcodeOp::Copy, Some(output), vec![input]);
                return RuleResult::Applied;
            }
        }

        RuleResult::Skipped
    }
}

/// Rule: Resolve memory accesses to direct variable references
///
/// If a LOAD or STORE accesses a known local or global variable's storage,
/// it can sometimes be simplified to a direct access or COPY.
pub struct RuleLoadStorePropagation;

impl Rule for RuleLoadStorePropagation {
    fn name(&self) -> &'static str {
        "LoadStorePropagation"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        None // Targets multiple opcodes
    }

    fn apply(
        &self,
        op_idx: usize,
        program: &mut Program,
        _cfg: &ControlFlowGraph,
        analysis: &FunctionAnalysis,
    ) -> RuleResult {
        let op = &program.operations()[op_idx];
        let var_analysis = match &analysis.variables {
            Some(v) => v,
            None => return RuleResult::Skipped,
        };

        match op.opcode() {
            PcodeOp::Load => {
                if let (Some(out_vn), Some(addr_vn)) = (op.output(), op.inputs().get(1)) {
                    if let Some((space, offset)) = resolve_address_to_storage(addr_vn, program, analysis) {
                        if let Some(var) = var_analysis.resolve_storage(space, offset) {
                            let source = match var.storage {
                                crate::analysis::variables::VariableStorage::Stack(stk_off) => {
                                    Varnode::new_stack(stk_off as u64, var.size)
                                }
                                crate::analysis::variables::VariableStorage::Register(reg_off) => {
                                    Varnode::new_register(reg_off, var.size)
                                }
                                crate::analysis::variables::VariableStorage::Global(addr) => {
                                    Varnode::new_ram(addr.as_u64(), var.size)
                                }
                                _ => return RuleResult::Skipped,
                            };
                            let output = out_vn.clone();
                            let op_mut = &mut program.operations_mut()[op_idx];
                            *op_mut = PcodeOperation::new(op_mut.id(), op_mut.seqnum(), PcodeOp::Copy, Some(output), vec![source]);
                            return RuleResult::Applied;
                        }
                    }
                }
            }
            PcodeOp::Store => {
                if let (Some(addr_vn), Some(val_vn)) = (op.inputs().get(1), op.inputs().get(2)) {
                    if let Some((space, offset)) = resolve_address_to_storage(addr_vn, program, analysis) {
                        if let Some(var) = var_analysis.resolve_storage(space, offset) {
                            let dest = match var.storage {
                                crate::analysis::variables::VariableStorage::Stack(stk_off) => {
                                    Varnode::new_stack(stk_off as u64, var.size)
                                }
                                crate::analysis::variables::VariableStorage::Register(reg_off) => {
                                    Varnode::new_register(reg_off, var.size)
                                }
                                crate::analysis::variables::VariableStorage::Global(addr) => {
                                    Varnode::new_ram(addr.as_u64(), var.size)
                                }
                                _ => return RuleResult::Skipped,
                            };
                            let source = val_vn.clone();
                            let op_mut = &mut program.operations_mut()[op_idx];
                            *op_mut = PcodeOperation::new(op_mut.id(), op_mut.seqnum(), PcodeOp::Copy, Some(dest), vec![source]);
                            return RuleResult::Applied;
                        }
                    }
                }
            }
            _ => {}
        }

        RuleResult::Skipped
    }
}

/// Rule: Simplify control flow with constant targets/conditions
pub struct RuleControlFlowSimplification;

impl Rule for RuleControlFlowSimplification {
    fn name(&self) -> &'static str {
        "ControlFlowSimplification"
    }

    fn target_opcode(&self) -> Option<PcodeOp> {
        None // Targets CBranch, BranchInd, CallInd
    }

    fn apply(&self, op_idx: usize, program: &mut Program, _cfg: &ControlFlowGraph, _analysis: &FunctionAnalysis) -> RuleResult {
        // Extract needed info first to avoid borrow checker issues
        enum Replacement {
            CBranch { val: u64, target: Varnode },
            BranchInd { addr: u64, size: usize },
            CallInd { addr: u64, size: usize, output: Option<Varnode>, other_inputs: Vec<Varnode> },
        }

        let replacement = {
            let op = &program.operations()[op_idx];
            match op.opcode() {
                PcodeOp::CBranch => {
                    if let Some(condition) = op.inputs().get(1) {
                        if let Some(val) = condition.constant_value() {
                            Some(Replacement::CBranch {
                                val,
                                target: op.inputs()[0].clone(),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                PcodeOp::BranchInd => {
                    if let Some(target) = op.inputs().get(0) {
                        if let Some(addr) = target.constant_value() {
                            Some(Replacement::BranchInd {
                                addr,
                                size: target.size(),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                PcodeOp::CallInd => {
                    if let Some(target) = op.inputs().get(0) {
                        if let Some(addr) = target.constant_value() {
                            let output = op.output().cloned();
                            let other_inputs = op.inputs()[1..].to_vec();
                            Some(Replacement::CallInd {
                                addr,
                                size: target.size(),
                                output,
                                other_inputs,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };

        if let Some(rep) = replacement {
            let op_mut = &mut program.operations_mut()[op_idx];
            match rep {
                Replacement::CBranch { val, target } => {
                    if val != 0 {
                        // Always taken: CBranch -> Branch
                        *op_mut = PcodeOperation::new(
                            op_mut.id(),
                            op_mut.seqnum(),
                            PcodeOp::Branch,
                            None,
                            vec![target],
                        );
                    } else {
                        // Never taken: CBranch -> Nop
                        *op_mut = PcodeOperation::new(
                            op_mut.id(),
                            op_mut.seqnum(),
                            PcodeOp::Nop,
                            None,
                            Vec::new(),
                        );
                    }
                }
                Replacement::BranchInd { addr, size } => {
                    *op_mut = PcodeOperation::new(
                        op_mut.id(),
                        op_mut.seqnum(),
                        PcodeOp::Branch,
                        None,
                        vec![Varnode::new_constant(addr, size)],
                    );
                }
                Replacement::CallInd { addr, size, output, other_inputs } => {
                    let mut new_inputs = vec![Varnode::new_constant(addr, size)];
                    new_inputs.extend(other_inputs);
                    *op_mut = PcodeOperation::new(
                        op_mut.id(),
                        op_mut.seqnum(),
                        PcodeOp::Call,
                        output,
                        new_inputs,
                    );
                }
            }
            return RuleResult::Applied;
        }

        RuleResult::Skipped
    }
}

fn resolve_address_to_storage(
    vn: &Varnode,
    program:
 &Program,
    analysis: &FunctionAnalysis,
) -> Option<(crate::pcode::AddressSpace, u64)> {
    resolve_address_to_storage_rec(vn, program, analysis, 0)
}

fn resolve_address_to_storage_rec(
    vn: &Varnode,
    program: &Program,
    analysis: &FunctionAnalysis,
    depth: usize,
) -> Option<(crate::pcode::AddressSpace, u64)> {
    if depth > 5 { return None; }

    // 1. Direct constant (assume RAM)
    if let Some(val) = vn.constant_value() {
        return Some((crate::pcode::AddressSpace::Ram, val));
    }

    // 2. Direct stack reference
    if vn.space() == crate::pcode::AddressSpace::Stack {
        return Some((crate::pcode::AddressSpace::Stack, vn.offset()));
    }

    // 3. Definition analysis (SSA)
    if let Some(ssa) = &analysis.ssa {
        let ssa_name = format!("{:?}_{:x}_{}_{}", vn.space(), vn.offset(), vn.size(), vn.version());
        if let Some(&block_idx) = ssa.definitions.get(&ssa_name) {
            let block = &analysis.cfg.as_ref()?.blocks[block_idx];
            for &op_idx in &block.operations {
                if op_idx >= program.operation_count() { continue; }
                let op = &program.operations()[op_idx];
                if let Some(out) = op.output() {
                    if out == vn {
                        match op.opcode() {
                            PcodeOp::IntAdd => {
                                if op.inputs().len() >= 2 {
                                    let in1 = &op.inputs()[0];
                                    let in2 = &op.inputs()[1];
                                    // Check for RSP (32) or RBP (40) + offset
                                    if in1.is_register() && (in1.offset() == 32 || in1.offset() == 40) {
                                        if let Some(off) = in2.constant_value() {
                                            return Some((crate::pcode::AddressSpace::Stack, off));
                                        }
                                    }
                                }
                            }
                            PcodeOp::Copy => {
                                return resolve_address_to_storage_rec(&op.inputs()[0], program, analysis, depth + 1);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    None
}
