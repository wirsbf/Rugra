//! Rule-based optimization system
//!
//! This module implements a rule-based simplification engine inspired by Ghidra's
//! decompiler architecture. It allows defining small, focused optimization rules
//! that are applied iteratively until the P-code stabilizes.

use crate::pcode::{Program, PcodeOp};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::rules::dataflow::{
    RuleControlFlowSimplification, RuleCopyPropagation, RuleDeadCodeElimination,
    RuleGlobalPropagation, RuleIdentityCopy, RuleLoadStorePropagation, RuleTruncationElimination,
    RuleTypePropagation,
};
use crate::analysis::rules::constants::RuleConstantFolding;
use crate::analysis::rules::algebra::RuleAlgebraicSimplification;
use crate::analysis::FunctionAnalysis;
use std::collections::HashMap;

/// Result of applying a rule
#[derive(Debug, PartialEq, Eq)]
pub enum RuleResult {
    /// The rule was applied and the program was modified
    Applied,
    /// The rule did not apply
    Skipped,
}

/// A simplification rule that can be applied to a P-code operation
pub trait Rule {
    /// Get the name of the rule
    fn name(&self) -> &'static str;

    /// Get the opcode this rule targets (or None for all)
    fn target_opcode(&self) -> Option<PcodeOp>;

    /// Try to apply the rule to a specific operation
    ///
    /// # Arguments
    /// * `op_idx` - The operation index to inspect
    /// * `program` - The program containing the operation (for context and modification)
    /// * `cfg` - Control flow graph
    /// * `analysis` - Full analysis context (SSA, Types, Variables, etc.)
    ///
    /// # Returns
    /// * `RuleResult::Applied` if the rule modified the program
    /// * `RuleResult::Skipped` otherwise
    fn apply(&self, op_idx: usize, program: &mut Program, cfg: &ControlFlowGraph, analysis: &FunctionAnalysis) -> RuleResult;
}

/// Represents a major optimization pass or action
pub trait Action {
    /// Get the name of the action
    fn name(&self) -> &'static str;

    /// Apply the action to the program
    ///
    /// # Returns
    /// * `true` if the program was modified
    fn apply(&self, program: &mut Program, analysis: &FunctionAnalysis) -> bool;
}

/// Controller that manages and applies optimization rules
pub struct RuleController {
    rules: HashMap<PcodeOp, Vec<Box<dyn Rule>>>,
    generic_rules: Vec<Box<dyn Rule>>,
}

impl RuleController {
    /// Create a new rule controller
    pub fn new() -> Self {
        RuleController {
            rules: HashMap::new(),
            generic_rules: Vec::new(),
        }
    }

    /// Register a new rule
    pub fn add_rule<R: Rule + 'static>(&mut self, rule: R) {
        let boxed_rule = Box::new(rule);
        if let Some(op) = boxed_rule.target_opcode() {
            self.rules.entry(op).or_insert_with(Vec::new).push(boxed_rule);
        } else {
            self.generic_rules.push(boxed_rule);
        }
    }

    /// Apply all rules iteratively until convergence
    pub fn apply_rules(&self, program: &mut Program, cfg: &ControlFlowGraph, analysis: &FunctionAnalysis) -> bool {
        let mut global_changed = false;
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 20;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            for block in &cfg.blocks {
                let op_indices = block.operations.clone();

                for op_idx in op_indices {
                    if op_idx >= program.operation_count() {
                        continue;
                    }

                    let opcode = {
                        let op = &program.operations()[op_idx];
                        if op.opcode == OpCode::CPUI_COPY /* NOP */ {
                            continue;
                        }
                        op.opcode
                    };

                    let mut op_changed = false;

                    // 1. Apply specific rules
                    if let Some(rules) = self.rules.get(&opcode) {
                        for rule in rules {
                            if rule.apply(op_idx, program, cfg, analysis) == RuleResult::Applied {
                                op_changed = true;
                                break;
                            }
                        }
                    }

                    // 2. Apply generic rules
                    if !op_changed {
                        for rule in &self.generic_rules {
                            if rule.apply(op_idx, program, cfg, analysis) == RuleResult::Applied {
                                op_changed = true;
                                break;
                            }
                        }
                    }

                    if op_changed {
                        changed = true;
                        global_changed = true;
                    }
                }
            }
        }

        if iterations > 1 && global_changed {
            eprintln!("    [Rules] Simplified IR over {} iterations", iterations);
        }
        global_changed
    }
}

/// Action that applies a set of rules repeatedly
pub struct ActionSimplify {
    controller: RuleController,
}

impl ActionSimplify {
    pub fn new(controller: RuleController) -> Self {
        ActionSimplify { controller }
    }
}

impl Action for ActionSimplify {
    fn name(&self) -> &'static str {
        "Simplify IR"
    }

    fn apply(&self, program: &mut Program, analysis: &FunctionAnalysis) -> bool {
        if let Some(cfg) = &analysis.cfg {
            self.controller.apply_rules(program, cfg, analysis)
        } else {
            false
        }
    }
}

// Sub-modules for specific rule categories
pub mod constants;
pub mod algebra;
pub mod dataflow;

impl RuleController {
    /// Create a controller pre-populated with default optimization rules
    pub fn with_defaults() -> Self {
        let mut controller = Self::new();
        controller.add_rule(RuleConstantFolding);
        controller.add_rule(RuleAlgebraicSimplification);
        controller.add_rule(RuleCopyPropagation);
        controller.add_rule(RuleGlobalPropagation);
        controller.add_rule(RuleDeadCodeElimination);
        controller.add_rule(RuleTypePropagation);
        controller.add_rule(RuleIdentityCopy);
        controller.add_rule(RuleTruncationElimination);
        controller.add_rule(RuleLoadStorePropagation);
        controller.add_rule(RuleControlFlowSimplification);
        controller
    }
}
