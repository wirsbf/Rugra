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
    // Mirrors Ghidra's oppool1 (coreaction.cc:5511-5649) — the universal
    // simplification pool applied repeatedly to a fixed point. Rules are
    // registered in Ghidra's exact order so their interactions match.
    // Entries whose Rust port does not yet exist are noted as skipped.

    pool.add_rule(Box::new(RuleEarlyRemoval::new()));       // 5512
    pool.add_rule(Box::new(RuleTermOrder::new()));          // 5513
    pool.add_rule(Box::new(RuleSelectCse::new()));          // 5514
    pool.add_rule(Box::new(RuleCollectTerms::new()));       // 5515
    pool.add_rule(Box::new(RulePullsubMulti::new()));       // 5516
    // skip 5517 RulePullsubIndirect — not yet ported
    pool.add_rule(Box::new(RulePushMulti::new()));          // 5518
    pool.add_rule(Box::new(RuleSborrow::new()));            // 5519
    pool.add_rule(Box::new(RuleScarry::new()));             // 5520
    pool.add_rule(Box::new(RuleIntLessEqual::new()));       // 5521
    pool.add_rule(Box::new(RuleTrivialArith::new()));       // 5522
    pool.add_rule(Box::new(RuleTrivialBool::new()));        // 5523
    pool.add_rule(Box::new(RuleTrivialShift::new()));       // 5524
    pool.add_rule(Box::new(RuleSignShift::new()));          // 5525
    pool.add_rule(Box::new(RuleTestSign::new()));           // 5526
    pool.add_rule(Box::new(RuleIdentityEl::new()));         // 5527
    pool.add_rule(Box::new(RuleOrMask::new()));             // 5528
    pool.add_rule(Box::new(RuleAndMask::new()));            // 5529
    pool.add_rule(Box::new(RuleOrConsume::new()));          // 5530
    pool.add_rule(Box::new(RuleOrCollapse::new()));         // 5531
    pool.add_rule(Box::new(RuleAndOrLump::new()));          // 5532
    pool.add_rule(Box::new(RuleShiftBitops::new()));        // 5533
    pool.add_rule(Box::new(RuleRightShiftAnd::new()));      // 5534
    pool.add_rule(Box::new(RuleNotDistribute::new()));      // 5535
    pool.add_rule(Box::new(RuleHighOrderAnd::new()));       // 5536
    pool.add_rule(Box::new(RuleAndDistribute::new()));      // 5537
    pool.add_rule(Box::new(RuleAndCommute::new()));         // 5538
    pool.add_rule(Box::new(RuleAndPiece::new()));           // 5539
    pool.add_rule(Box::new(RuleAndZext::new()));            // 5540
    pool.add_rule(Box::new(RuleAndCompare::new()));         // 5541
    pool.add_rule(Box::new(RuleDoubleSub::new()));          // 5542
    pool.add_rule(Box::new(RuleDoubleShift::new()));        // 5543
    pool.add_rule(Box::new(RuleDoubleArithShift::new()));   // 5544
    pool.add_rule(Box::new(RuleConcatShift::new()));        // 5545
    pool.add_rule(Box::new(RuleLeftRight::new()));          // 5546
    pool.add_rule(Box::new(RuleShiftCompare::new()));       // 5547
    pool.add_rule(Box::new(RuleShift2Mult::new()));         // 5548
    // skip 5549 RuleShiftPiece — not yet ported
    pool.add_rule(Box::new(RuleMultiCollapse::new()));      // 5550
    // skip 5551 RuleIndirectCollapse — not yet ported
    pool.add_rule(Box::new(Rule2Comp2Mult::new()));         // 5552
    pool.add_rule(Box::new(RuleSub2Add::new()));            // 5553
    pool.add_rule(Box::new(RuleCarryElim::new()));          // 5554
    pool.add_rule(Box::new(RuleBxor2NotEqual::new()));      // 5555
    pool.add_rule(Box::new(RuleLess2Zero::new()));          // 5556
    pool.add_rule(Box::new(RuleLessEqual2Zero::new()));     // 5557
    // skip 5558 RuleSLess2Zero — not yet ported
    pool.add_rule(Box::new(RuleEqual2Zero::new()));         // 5559
    pool.add_rule(Box::new(RuleEqual2Constant::new()));     // 5560
    pool.add_rule(Box::new(RuleThreeWayCompare::new()));    // 5561
    pool.add_rule(Box::new(RuleXorCollapse::new()));        // 5562
    pool.add_rule(Box::new(RuleAddMultCollapse::new()));    // 5563
    pool.add_rule(Box::new(RuleCollapseConstants::new()));  // 5564
    // skip 5565 RuleTransformCpool — not yet ported
    pool.add_rule(Box::new(RulePropagateCopy::new()));      // 5566
    pool.add_rule(Box::new(RuleZextEliminate::new()));      // 5567
    pool.add_rule(Box::new(RuleSlessToLess::new()));        // 5568
    pool.add_rule(Box::new(RuleZextSless::new()));          // 5569
    pool.add_rule(Box::new(RuleBitUndistribute::new()));    // 5570
    pool.add_rule(Box::new(RuleBooleanUndistribute::new()));// 5571
    pool.add_rule(Box::new(RuleBooleanDedup::new()));       // 5572
    pool.add_rule(Box::new(RuleBoolZext::new()));           // 5573
    pool.add_rule(Box::new(RuleBooleanNegate::new()));      // 5574
    pool.add_rule(Box::new(RuleLogic2Bool::new()));         // 5575
    pool.add_rule(Box::new(RuleSubExtComm::new()));         // 5576
    // skip 5577 RuleSubCommute — not yet ported
    pool.add_rule(Box::new(RuleConcatCommute::new()));      // 5578
    pool.add_rule(Box::new(RuleConcatZext::new()));         // 5579
    pool.add_rule(Box::new(RuleZextCommute::new()));        // 5580
    pool.add_rule(Box::new(RuleZextShiftZext::new()));      // 5581
    pool.add_rule(Box::new(RuleShiftAnd::new()));           // 5582
    pool.add_rule(Box::new(RuleConcatZero::new()));         // 5583
    pool.add_rule(Box::new(RuleConcatLeftShift::new()));    // 5584
    pool.add_rule(Box::new(RuleSubZext::new()));            // 5585
    pool.add_rule(Box::new(RuleSubCancel::new()));          // 5586
    pool.add_rule(Box::new(RuleShiftSub::new()));           // 5587
    pool.add_rule(Box::new(RuleHumptyDumpty::new()));       // 5588
    pool.add_rule(Box::new(RuleDumptyHump::new()));         // 5589
    pool.add_rule(Box::new(RuleHumptyOr::new()));           // 5590
    pool.add_rule(Box::new(RuleNegateIdentity::new()));     // 5591
    pool.add_rule(Box::new(RuleSubNormal::new()));          // 5592
    pool.add_rule(Box::new(RulePositiveDiv::new()));        // 5593
    // skip 5594-5595 RuleDivTermAdd/2 — not yet ported
    pool.add_rule(Box::new(RuleDivOpt::new()));             // 5596
    pool.add_rule(Box::new(RuleSignForm::new()));           // 5597
    pool.add_rule(Box::new(RuleSignForm2::new()));          // 5598
    pool.add_rule(Box::new(RuleSignDiv2::new()));           // 5599
    pool.add_rule(Box::new(RuleDivChain::new()));           // 5600
    pool.add_rule(Box::new(RuleSignNearMult::new()));       // 5601
    // skip 5602 RuleModOpt — not yet ported
    pool.add_rule(Box::new(RuleSignMod2nOpt::new()));       // 5603
    // skip 5604-5605 RuleSignMod2nOpt2/SignMod2Opt — not yet ported
    // skip 5606 RuleSwitchSingle — not yet ported
    pool.add_rule(Box::new(RuleCondNegate::new()));         // 5607
    pool.add_rule(Box::new(RuleBoolNegate::new()));         // 5608
    pool.add_rule(Box::new(RuleLessEqual::new()));          // 5609
    pool.add_rule(Box::new(RuleLessNotEqual::new()));       // 5610
    pool.add_rule(Box::new(RuleLessOne::new()));            // 5611
    pool.add_rule(Box::new(RuleRangeMeld::new()));          // 5612
    pool.add_rule(Box::new(RuleFloatRange::new()));         // 5613
    pool.add_rule(Box::new(RulePiece2Zext::new()));         // 5614
    pool.add_rule(Box::new(RulePiece2Sext::new()));         // 5615
    // skip 5616 RulePopcountBoolXor — not yet ported
    pool.add_rule(Box::new(RuleXorSwap::new()));            // 5617
    pool.add_rule(Box::new(RuleLzcountShiftBool::new()));   // 5618
    // skip 5619 RuleFloatSign — not yet ported
    pool.add_rule(Box::new(RuleOrCompare::new()));          // 5620
    // Rules 5621-5648 (subvar/float/segment/ptr/double-load) not yet ported.

    // Rugra-local companions that complete RuleSub2Add (5553): it emits
    // x + (y * -1), RuleMultNegOne collapses y*-1 to INT_NEG(y), Rule2Comp2Sub
    // handles the 2's-complement form. Grouped after their parent so the pool
    // converges. RuleSextEliminate/Equality/FloatCast are Rugra-local extras.
    pool.add_rule(Box::new(RuleMultNegOne::new()));
    pool.add_rule(Box::new(Rule2Comp2Sub::new()));
    pool.add_rule(Box::new(RuleSextEliminate::new()));
    pool.add_rule(Box::new(RuleEquality::new()));
    pool.add_rule(Box::new(RuleFloatCast::new()));
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
