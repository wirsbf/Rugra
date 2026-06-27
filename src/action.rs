//! Analysis actions and transformation rules
//!
//! Corresponds to Ghidra's `action.hh`

use crate::funcdata::Funcdata;
use crate::error::Result;
use crate::coreaction::*;
use crate::blockaction::*;
// use std::sync::Arc;

/// Base trait for all analysis actions
///
/// Corresponds to Ghidra's `Action` class. An action represents a high-level
/// analysis or transformation step performed on a function.
pub trait Action {
    /// Perform the action on the given function data
    ///
    /// # Returns
    /// 0 if no change occurred, positive if changes were made
    fn apply(&self, fd: &mut Funcdata) -> Result<i32>;

    /// Get the name of the action
    fn get_name(&self) -> &str;

    /// Reset the action state
    fn reset(&mut self) {}
}

/// Base trait for small-scale transformation rules
///
/// Corresponds to Ghidra's `Rule` class. A rule typically targets a specific
/// P-code opcode and performs a local simplification or optimization.
pub trait Rule {
    /// Apply the rule to a specific operation
    ///
    /// # Returns
    /// 0 if no change occurred, positive if changes were made
    fn apply_op(&self, op: &std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>, fd: &mut Funcdata) -> Result<i32>;

    /// Get the name of the rule
    fn get_name(&self) -> &str;

    /// Get the opcodes this rule applies to
    fn get_opcodes(&self) -> Vec<crate::opcodes::OpCode>;
}

/// A group of actions executed together
///
/// Corresponds to Ghidra's `ActionGroup` class
pub struct ActionGroup {
    name: String,
    actions: Vec<Box<dyn Action>>,
}

impl ActionGroup {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            actions: Vec::new(),
        }
    }

    pub fn add_action(&mut self, action: Box<dyn Action>) {
        self.actions.push(action);
    }
}

impl Action for ActionGroup {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut total_changes = 0;
        for action in &self.actions {
            total_changes += action.apply(fd)?;
        }
        Ok(total_changes)
    }

    fn get_name(&self) -> &str {
        &self.name
    }
}

/// A pool of Rules applied to every matching P-code op.
///
/// Corresponds to Ghidra's `ActionPool` (action.hh:262). It holds a set of
/// `Rule`s and, on `apply`, iterates over all live ops, dispatching each op
/// to the Rules whose `get_opcodes()` include the op's opcode. Repeats until
/// a full pass makes no change (mirrors Ghidra's `rule_repeatapply` group
/// semantics — the universal-action main loop reruns the pool until stable).
pub struct ActionPool {
    name: String,
    rules: Vec<Box<dyn Rule>>,
    /// Opcode → indices into `rules`, built on add_rule for O(1) dispatch.
    per_op: std::collections::HashMap<crate::opcodes::OpCode, Vec<usize>>,
}

impl ActionPool {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            rules: Vec::new(),
            per_op: std::collections::HashMap::new(),
        }
    }

    /// Register a Rule. Faithful to `ActionPool::addRule` — the rule's
    /// opcodes are indexed for fast per-op dispatch.
    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        let idx = self.rules.len();
        let opcodes = rule.get_opcodes();
        self.rules.push(rule);
        for opc in opcodes {
            self.per_op.entry(opc).or_default().push(idx);
        }
    }
}

impl Action for ActionPool {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionPool::apply + the universal main loop's
        // repeat-until-stable behaviour. We snapshot the live op list per
        // pass because applyOp may destroy/insert ops.
        let mut total = 0;
        loop {
            let mut pass_changes = 0;
            // Snapshot indices; the bank's alivelist may shift, so re-fetch
            // each op by current position defensively.
            let ops: Vec<crate::op::PcodeOpRef> = fd.obank.alivelist.clone();
            for op_ref in ops {
                // Skip dead ops (Ghidra's processOp checks isDead).
                let (is_dead, opc) = {
                    let o = op_ref.0.read().unwrap();
                    (o.is_dead(), o.opcode)
                };
                if is_dead {
                    continue;
                }
                if let Some(rule_idxs) = self.per_op.get(&opc) {
                    for &ridx in rule_idxs {
                        // Re-check dead after each rule (a prior rule may
                        // have destroyed this op).
                        let dead = op_ref.0.read().unwrap().is_dead();
                        if dead { break; }
                        let res = self.rules[ridx].apply_op(&op_ref.0, fd)?;
                        if res > 0 {
                            pass_changes += res;
                        }
                    }
                }
            }
            total += pass_changes;
            if pass_changes == 0 { break; }
        }
        Ok(total)
    }

    fn get_name(&self) -> &str {
        &self.name
    }
}

/// Build an `ActionPool` holding the core algebraic-simplification Rules.
///
/// Mirrors Ghidra's `oppool1` / `oppool2` rule groups (coreaction.cc:5511+)
/// that are part of the universal `actprop` simplifier. These Rules fold
/// redundant P-code (constant collapses, trivial identities, sign/zero
/// extension elimination, etc.) without altering control flow, so they are
/// safe to run repeatedly to a fixed point.
pub fn build_simplify_pool() -> ActionPool {
    use crate::ruleaction::*;
    let mut pool = ActionPool::new("simplifypool");
    // Pure algebraic identities & trivial foldings.
    pool.add_rule(Box::new(RuleCollapseConstants::new()));
    pool.add_rule(Box::new(RuleTrivialArith::new()));
    pool.add_rule(Box::new(RuleTrivialBool::new()));
    pool.add_rule(Box::new(RuleTrivialShift::new()));
    pool.add_rule(Box::new(RuleNegateIdentity::new()));
    pool.add_rule(Box::new(RuleAddMultCollapse::new()));
    pool.add_rule(Box::new(RuleXorCollapse::new()));
    pool.add_rule(Box::new(RuleOrCollapse::new()));
    pool.add_rule(Box::new(RuleIdentityEl::new()));
    pool.add_rule(Box::new(RuleDoubleSub::new()));
    pool.add_rule(Box::new(RuleDoubleShift::new()));
    // Zero/sign extension elimination.
    pool.add_rule(Box::new(RuleZextEliminate::new()));
    pool.add_rule(Box::new(RuleSextEliminate::new()));
    pool.add_rule(Box::new(RuleSubZext::new()));
    pool.add_rule(Box::new(RulePiece2Zext::new()));
    pool.add_rule(Box::new(RulePiece2Sext::new()));
    pool.add_rule(Box::new(RuleSignShift::new()));
    pool.add_rule(Box::new(RuleConcatZero::new()));
    pool.add_rule(Box::new(RuleAndZext::new()));
    // Boolean / comparison simplification.
    pool.add_rule(Box::new(RuleBoolNegate::new()));
    pool.add_rule(Box::new(RuleNotDistribute::new()));
    pool.add_rule(Box::new(RuleBxor2NotEqual::new()));
    pool.add_rule(Box::new(RuleLess2Zero::new()));
    pool.add_rule(Box::new(RuleLessEqual2Zero::new()));
    pool.add_rule(Box::new(RuleLessNotEqual::new()));
    pool.add_rule(Box::new(RuleEquality::new()));
    pool.add_rule(Box::new(RuleSlessToLess::new()));
    pool.add_rule(Box::new(RuleLessOne::new()));
    pool.add_rule(Box::new(RuleTestSign::new()));
    pool.add_rule(Box::new(RuleShiftCompare::new()));
    pool.add_rule(Box::new(RuleAndCompare::new()));
    // Bit manipulation.
    pool.add_rule(Box::new(RuleOrMask::new()));
    pool.add_rule(Box::new(RuleAndOrLump::new()));
    pool.add_rule(Box::new(RuleAndDistribute::new()));
    pool.add_rule(Box::new(RuleAndPiece::new()));
    pool.add_rule(Box::new(RuleAndCommute::new()));
    pool.add_rule(Box::new(RuleRightShiftAnd::new()));
    pool.add_rule(Box::new(RuleHighOrderAnd::new()));
    pool.add_rule(Box::new(RuleConcatLeftShift::new()));
    pool.add_rule(Box::new(RuleConcatShift::new()));
    pool.add_rule(Box::new(RuleShift2Mult::new()));
    pool.add_rule(Box::new(RuleOrConsume::new()));
    pool
}

///
/// Corresponds to Ghidra's `ActionDatabase` class
pub struct ActionDatabase {
    all_actions: Vec<Box<dyn Action>>,
    current_group: Option<String>,
}

impl ActionDatabase {
    pub fn new() -> Self {
        Self {
            all_actions: Vec::new(),
            current_group: None,
        }
    }

    pub fn register_action(&mut self, action: Box<dyn Action>) {
        self.all_actions.push(action);
    }

    pub fn get_action(&self, name: &str) -> Option<&dyn Action> {
        self.all_actions.iter()
            .find(|a| a.get_name() == name)
            .map(|a| a.as_ref())
    }

    /// Run all registered actions on the given function data
    pub fn apply_all(&self, fd: &mut crate::funcdata::Funcdata) -> crate::error::Result<i32> {
        let mut total = 0;
        for action in &self.all_actions {
            total += action.apply(fd)?;
        }
        Ok(total)
    }

    /// Set up default decompiler actions
    pub fn set_default_actions(&mut self) {
        let mut decompile_group = ActionGroup::new("decompile");

        decompile_group.add_action(Box::new(ActionStart::new()));
        decompile_group.add_action(Box::new(ActionHeritage::new()));
        decompile_group.add_action(Box::new(ActionInferParams::new())); // Early: before copy propagation removes Register varnodes
        decompile_group.add_action(Box::new(ActionConstantPtr::new()));
        decompile_group.add_action(Box::new(ActionCse::new()));
        decompile_group.add_action(Box::new(ActionSimplify::new()));
        // Rule-driven algebraic simplification pool (Ghidra oppool1/oppool2).
        // Runs the registered Rules to a fixed point, folding redundant
        // P-code. This is the first time Rugra actually dispatches its ~90
        // implemented Rules; previously none were wired into the pipeline.
        decompile_group.add_action(Box::new(build_simplify_pool()));
        // Merge BEFORE copy propagation: copy-merge needs the COPY ops to
        // still be alive, and DeadCode would otherwise remove them.
        decompile_group.add_action(Box::new(ActionMergeType::new()));
        // Type inference BEFORE copy propagation: ActionTypeInfer assigns
        // types to COPY ops' inputs/outputs. Then CopyPropagate propagates
        // those types along with use redirection, so surviving Register-space
        // varnodes inherit types from the Unique-space temporaries.
        decompile_group.add_action(Box::new(ActionTypeInfer::new()));
        decompile_group.add_action(Box::new(ActionCopyPropagate::new()));
        decompile_group.add_action(Box::new(ActionTypePropagate::new()));
        decompile_group.add_action(Box::new(ActionCallParams::new()));
        decompile_group.add_action(Box::new(ActionDeadCode::new()));
        // NOTE: ActionDeterminedBranch/Unreachable/DoNothing/RedundBranch are
        // implemented (coreaction.cc:3457-3528) and individually tested, but
        // NOT wired into the default pipeline. Ghidra runs them inside its
        // selectGoto->collapseInternal loop, where the structurer is designed
        // around block removal. Rugra's staged-phase structurer (collapse_loops
        // /collapse_conditions) relies on blocks that these actions remove, so
        // wiring them causes regressions (curl 24->11, goto 0->2). Re-enabling
        // needs the staged->collapseInternal architecture migration (G4 opt).
        // The apply() logic is complete and available for that migration.
        // Local variable recovery (coreaction.cc:5505 "localrecovery"): build
        // the stack-variable scope via ScopeLocal::restructure_varnode, which
        // printc's get_stack_variable_name queries to name stack slots instead
        // of emitting uVar fragments. Must run after DeadCode (so the scope
        // sees only live varnodes) and before block structuring.
        decompile_group.add_action(Box::new(crate::coreaction::ActionRestructureVarnode::new()));
        // Conditional-execution elimination (coreaction.cc:5675): collapse
        // redundant CBRANCH joins. Must run before block structuring.
        decompile_group.add_action(Box::new(crate::condexe::ActionConditionalExe::new()));
        decompile_group.add_action(Box::new(ActionBlockStructure::new()));
        decompile_group.add_action(Box::new(ActionNormalizeBranches::new()));
        decompile_group.add_action(Box::new(ActionFinalStructure::new()));

        self.register_action(Box::new(decompile_group));
    }
}

/// ActionTypePropagate: Conservative P-code struct pointer type propagation.
/// Marks varnodes used as base in >=2 distinct small (<256B, 8-byte-aligned)
/// offsets via INT_ADD → LOAD/STORE. Mirrors Ghidra's ActionTypePropagate.
pub struct ActionTypePropagate;

impl ActionTypePropagate {
    pub fn new() -> Self { Self }
}

impl Action for ActionTypePropagate {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        crate::analysis::type_infer::propagate_types(fd);
        Ok(0)
    }
    fn get_name(&self) -> &str { "typepropagate" }
}

/// Status codes for Action execution
pub mod action_status {
    pub const NO_CHANGE: i32 = 0;
    pub const CHANGE: i32 = 1;
    pub const RESTART: i32 = 2;
}
