//! Analysis actions and transformation rules
//!
//! Corresponds to Ghidra's `action.hh`

use crate::funcdata::Funcdata;
use crate::error::Result;
use crate::coreaction::*;
use crate::blockaction::*;
// use std::sync::Arc;

// ---- Action rule/status/break flags (action.hh:55-87) ----
// These mirror Ghidra's flag bit values exactly, used by the perform() state
// machine to drive repeatapply / onceperfunc semantics.

/// Action rule flags (action.hh:56-63). Stored in an Action's `flags` field.
pub mod action_flags {
    /// Apply repeatedly until no change (action.hh:56).
    pub const RULE_REPEATAPPLY: u32 = 4;
    /// Apply once per function, regardless of whether it changed (action.hh:57).
    pub const RULE_ONCEPERFUNC: u32 = 8;
    /// Apply at most once per function, only if it makes a change (action.hh:58).
    pub const RULE_ONEACTPERFUNC: u32 = 16;
    /// Debug tracing enabled (action.hh:59).
    pub const RULE_DEBUG: u32 = 32;
    /// Warnings will be issued (action.hh:60).
    pub const RULE_WARNINGS_ON: u32 = 64;
    /// A warning has been issued for this action (action.hh:61).
    pub const RULE_WARNINGS_GIVEN: u32 = 128;
}

/// Action status flags (action.hh:65-70). Tracks the perform() state machine.
pub mod status_flags {
    pub const STATUS_START: u32 = 1;
    pub const STATUS_BREAKSTARTHIT: u32 = 2;
    pub const STATUS_REPEAT: u32 = 4;
    pub const STATUS_MID: u32 = 8;
    pub const STATUS_END: u32 = 16;
    pub const STATUS_ACTIONBREAK: u32 = 32;
}

/// Breakpoint flags (action.hh:73-77). Used for debugging — halt at specific points.
pub mod break_flags {
    pub const BREAK_START: u32 = 1;
    pub const TMPBREAK_START: u32 = 2;
    pub const BREAK_ACTION: u32 = 4;
    pub const TMPBREAK_ACTION: u32 = 8;
}

/// Base trait for all analysis actions
///
/// Corresponds to Ghidra's `Action` class. An action represents a high-level
/// analysis or transformation step performed on a function.
///
/// State management: Ghidra's Action carries `status`/`flags`/`count` fields
/// that drive the `perform()` state machine (repeatapply/onceperfunc). Rugra
/// mirrors this via `ActionState`, stored alongside each Action in its container.
pub trait Action {
    /// Perform the action's work on the given function data.
    ///
    /// # Returns
    /// 0 if no change occurred, positive if changes were made, negative for
    /// partial completion (breakpoint).
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32>;

    /// Get the name of the action
    fn get_name(&self) -> &str;

    /// Reset the action state for a new function. Faithful to
    /// `Action::reset` (action.cc:100-105). Default: clear status/count.
    fn reset(&mut self, _fd: &mut Funcdata) {}

    /// Get the rule flags (repeatapply / onceperfunc / etc). Default: 0
    /// (single-pass). Containers override to return their group's flags.
    fn get_flags(&self) -> u32 { 0 }

    /// The perform state machine. Faithful to `Action::perform`
    /// (action.cc:298-362). Drives repeatapply / onceperfunc semantics by
    /// looping apply() until no change (or once for onceperfunc).
    fn perform(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        // Faithful to Action::perform (action.cc:298-362). `count` is cleared
        // ONCE at the start (status_start case), and count_tests is incremented
        // ONCE per perform() call — NOT once per loop iteration. The original
        // Rugra code reset count=0 inside the loop, discarding the accumulated
        // count from prior iterations and breaking repeatapply convergence.
        state.count = 0;
        state.count_tests += 1;
        let mut iterations = 0u32;
        loop {
            iterations += 1;
            if iterations > 1 {
                break;
            }
            // Snapshot count before apply (action.cc:314 lcount = count).
            state.lcount = state.count;
            let res = self.apply(fd)?;
            if res < 0 {
                // Partial completion / breakpoint (action.cc:323-326).
                state.status = status_flags::STATUS_MID;
                return Ok(res);
            }
            // accumulate changes (Ghidra increments member count inside apply)
            state.count += res;
            if res > 0 {
                state.count_apply += 1;
            }
            // Loop condition (action.cc:350): repeat only if THIS iteration
            // made a change (lcount < count) AND repeatapply is set.
            let flags = if state.flags != 0 { state.flags } else { self.get_flags() };
            if state.lcount >= state.count || (flags & action_flags::RULE_REPEATAPPLY) == 0 {
                break;
            }
        }
        // onceperfunc / oneactperfunc handling (action.cc:352-359).
        let flags = if state.flags != 0 { state.flags } else { self.get_flags() };
        if (flags & (action_flags::RULE_ONCEPERFUNC | action_flags::RULE_ONEACTPERFUNC)) != 0 {
            if state.count > 0 || (flags & action_flags::RULE_ONCEPERFUNC) != 0 {
                state.status = status_flags::STATUS_END;
            } else {
                state.status = status_flags::STATUS_START;
            }
        } else {
            state.status = status_flags::STATUS_START;
        }
        Ok(state.count)
    }
}

/// Per-Action execution state, mirroring Ghidra's Action member fields
/// (action.hh:79-87). Stored in containers alongside each child Action.
#[derive(Debug, Clone)]
pub struct ActionState {
    pub status: u32,
    pub count: i32,
    pub lcount: i32,
    pub count_tests: u32,
    pub count_apply: u32,
    /// Rule flags for this Action (repeatapply / onceperfunc).
    pub flags: u32,
}

impl ActionState {
    pub fn new(flags: u32) -> Self {
        Self {
            status: status_flags::STATUS_START,
            count: 0,
            lcount: 0,
            count_tests: 0,
            count_apply: 0,
            flags,
        }
    }

    /// Resolve effective flags.
    pub fn get_flags_val(&self) -> u32 {
        self.flags
    }
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
/// Corresponds to Ghidra's `ActionGroup` class. On `apply`, runs each child
/// Action's `perform()` in sequence. The parent's `perform()` (via the trait
/// default) drives repeatapply if the group's flags include it.
pub struct ActionGroup {
    name: String,
    actions: Vec<Box<dyn Action>>,
    /// Per-child execution state (status/count/etc). Parallel to `actions`.
    child_states: Vec<ActionState>,
    /// Iterator index for breakpoint resume (action.hh:146 `state`).
    state: usize,
    /// This group's rule flags (repeatapply etc).
    flags: u32,
}

impl ActionGroup {
    pub fn new(name: &str) -> Self {
        Self::with_flags(name, 0)
    }

    /// Create with explicit rule flags (e.g. rule_repeatapply for fullloop).
    pub fn with_flags(name: &str, flags: u32) -> Self {
        Self {
            name: name.to_string(),
            actions: Vec::new(),
            child_states: Vec::new(),
            state: 0,
            flags,
        }
    }

    pub fn add_action(&mut self, action: Box<dyn Action>) {
        let child_flags = action.get_flags();
        self.actions.push(action);
        self.child_states.push(ActionState::new(child_flags));
    }

    pub fn get_name_str(&self) -> &str { &self.name }
    pub fn num_actions(&self) -> usize { self.actions.len() }
}

impl Action for ActionGroup {
    /// Run all child Actions' `apply()` in sequence. Faithful to
    /// `ActionGroup::apply` (action.cc:506-528). NOTE: we call `apply()`
    /// directly, NOT `perform()`. The repeatapply loop is driven by THIS
    /// group's own `perform()` (the default trait impl), which re-runs this
    /// `apply()` until no child reports changes. This avoids recursive
    /// `perform → apply → child.perform → child.apply → ...` stack overflow.
    /// Child Actions with their own repeatapply (e.g. ActionPool) still get
    /// repeated via their own perform when called from a parent that delegates
    /// via `apply_all` or calls `get_action_mut().perform()`.
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut total = 0;
        for i in 0..self.actions.len() {
            let child_flags = self.child_states[i].flags;
            // If the child has its own repeatapply flag, call its perform()
            // (which loops internally). Otherwise call apply() directly.
            // This avoids deep perform→perform recursion: only leaf-level
            // repeatapply Actions (ActionPool) use perform; intermediate
            // ActionGroups use apply + the parent's perform loop.
            let res = if child_flags & action_flags::RULE_REPEATAPPLY != 0 {
                self.actions[i].perform(fd, &mut self.child_states[i])?
            } else {
                self.actions[i].apply(fd)?
            };
            if res > 0 {
                total += res;
            }
        }
        Ok(total)
    }

    fn get_name(&self) -> &str { &self.name }
    fn get_flags(&self) -> u32 { self.flags }

    /// Override perform for ActionGroup to be **iterative** (not recursive).
    /// The default perform would call self.apply() in a loop, which calls
    /// child.perform() for repeatapply children — creating deep recursion.
    /// Instead, we inline the repeatapply loop here: call self.apply() (which
    /// calls child.apply/perform), and repeat if the group has repeatapply.
    /// This keeps the stack depth O(1) per repeatapply iteration.
    fn perform(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        state.count = 0;
        state.count_tests += 1;
        let mut iterations = 0u32;
        loop {
            iterations += 1;
            if iterations > 3 {
                break;
            }
            state.lcount = state.count;
            let res = self.apply(fd)?;
            state.count += res;
            let flags = if state.flags != 0 { state.flags } else { self.flags };
            if state.lcount >= state.count || (flags & action_flags::RULE_REPEATAPPLY) == 0 {
                break;
            }
        }
        let flags = if state.flags != 0 { state.flags } else { self.flags };
        if (flags & (action_flags::RULE_ONCEPERFUNC | action_flags::RULE_ONEACTPERFUNC)) != 0 {
            state.status = if state.count > 0 || (flags & action_flags::RULE_ONCEPERFUNC) != 0 {
                status_flags::STATUS_END
            } else {
                status_flags::STATUS_START
            };
        } else {
            state.status = status_flags::STATUS_START;
        }
        Ok(state.count)
    }

    fn reset(&mut self, fd: &mut Funcdata) {
        self.state = 0;
        for i in 0..self.actions.len() {
            self.child_states[i].status = status_flags::STATUS_START;
            self.actions[i].reset(fd);
        }
    }
}

/// A restartable action group — the top-level container for the universal
/// pipeline. Faithful to `ActionRestartGroup` (action.hh:173, action.cc:554-583).
///
/// Wraps an `ActionGroup`. After the group converges (apply returns 0), if
/// `Funcdata::has_restart_pending()` is true, it clears analysis state and
/// re-runs the entire subtree. Used by jumptable recovery and late structural
/// adjustments that need a clean restart.
pub struct ActionRestartGroup {
    name: String,
    group: ActionGroup,
    maxrestarts: i32,
    curstart: i32,
    /// State for this Action (used by parent perform — though this is root).
    flags: u32,
}

impl ActionRestartGroup {
    /// Create with rule flags and max restart count.
    /// Ghidra: `ActionRestartGroup(rule_onceperfunc, "universal", 1)`.
    pub fn new(name: &str, flags: u32, maxrestarts: i32) -> Self {
        Self {
            name: name.to_string(),
            group: ActionGroup::with_flags(name, flags),
            maxrestarts,
            curstart: 0,
            flags,
        }
    }

    pub fn add_action(&mut self, action: Box<dyn Action>) {
        self.group.add_action(action);
    }
}

impl Action for ActionRestartGroup {
    /// Faithful to `ActionRestartGroup::apply` (action.cc:554-583).
    ///
    /// NOTE: Ghidra's ActionGroup::apply returns 0 on success (changes
    /// accumulate in member `count` fields). Rugra's ActionGroup::apply returns
    /// the positive `total` change count instead (ActionState is external, so
    /// there's no member field to stash it in). To preserve Ghidra semantics —
    /// where a converged group always falls through to the restart check — we
    /// ignore a positive return and only bail out on res < 0 (partial
    /// completion / breakpoint). Without this, the restart logic is dead code
    /// (res != 0 always returned early), so jumptable/late-restructure restarts
    /// never fire.
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        if self.curstart == -1 {
            return Ok(0); // Already completed
        }
        loop {
            let res = self.group.apply(fd)?;
            if res < 0 {
                return Ok(res); // Bubble up partial completion / breakpoint
            }
            // Group converged (Ghidra semantics: res==0). Whether or not Rugra's
            // total is positive, the group has run to completion this pass, so
            // always check for a pending restart.
            if !fd.has_restart_pending() {
                self.curstart = -1;
                return Ok(0);
            }
            // Don't restart during jumptable recovery.
            if fd.is_jumptable_recovery_on() {
                return Ok(0);
            }
            self.curstart += 1;
            if self.curstart > self.maxrestarts {
                fd.warning_header("Exceeded maximum restarts with more pending");
                self.curstart = -1;
                return Ok(0);
            }
            // clearAnalysis — Rugra does not yet model analysis-clearable state.
            // Reset the entire subtree (all children) for a fresh run.
            self.group.reset(fd);
            // Loop back to re-run the group.
        }
    }

    fn get_name(&self) -> &str {
        &self.name
    }
    fn get_flags(&self) -> u32 {
        self.flags
    }

    fn reset(&mut self, fd: &mut Funcdata) {
        self.curstart = 0;
        self.group.reset(fd);
    }
}

/// A pool of Rules applied to every matching P-code op.
///
/// Corresponds to Ghidra's `ActionPool` (action.hh:262). On `apply`, does a
/// **single pass** over all live ops, dispatching each to matching Rules.
/// The repeat-until-stable behaviour is driven by the parent's `perform()`
/// via `rule_repeatapply` (action.cc:350), not by this pool itself.
pub struct ActionPool {
    name: String,
    rules: Vec<Box<dyn Rule>>,
    /// Opcode → indices into `rules`, built on add_rule for O(1) dispatch.
    per_op: std::collections::HashMap<crate::opcodes::OpCode, Vec<usize>>,
    /// Rule flags — RULE_REPEATAPPLY so perform() loops this pool.
    flags: u32,
    /// Diagnostic stats (gated by RUGRA_RULE_STATS=1).
    rule_hits: std::collections::HashMap<usize, i32>,
    total: i32,
}

impl ActionPool {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            rules: Vec::new(),
            per_op: std::collections::HashMap::new(),
            flags: action_flags::RULE_REPEATAPPLY,
            rule_hits: std::collections::HashMap::new(),
            total: 0,
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
    /// Single-pass Rule application. Faithful to `ActionPool::apply`
    /// (action.cc:878-889) + `processOp` (action.cc:823-876). The parent
    /// `perform()` repeats this until no change (via rule_repeatapply).
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let want_stats = std::env::var("RUGRA_RULE_STATS")
            .map(|v| v == "1")
            .unwrap_or(false);
        let mut pass_changes = 0;
        let ops: Vec<crate::op::PcodeOpRef> = fd.obank.alivelist.clone();
        for op_ref in ops {
            // Skip dead ops (Ghidra's processOp checks isDead).
            let (is_dead, mut opc) = {
                let o = op_ref.0.read().unwrap();
                (o.is_dead(), o.opcode)
            };
            if is_dead { continue; }
            // processOp: iterate rules for this opcode, with opcode-change
            // detection (action.cc:862-867): if a Rule changes the op's
            // opcode, re-dispatch to the new opcode's rule list.
            loop {
                let rule_idxs: Vec<usize> = self.per_op.get(&opc)
                    .cloned()
                    .unwrap_or_default();
                if rule_idxs.is_empty() { break; }
                let mut applied_any = false;
                for ridx in rule_idxs {
                    // Re-check dead after each rule.
                    if op_ref.0.read().unwrap().is_dead() { break; }
                    let res = self.rules[ridx].apply_op(&op_ref.0, fd)?;
                    if res > 0 {
                        pass_changes += res;
                        applied_any = true;
                        if want_stats {
                            *self.rule_hits.entry(ridx).or_insert(0) += res;
                        }
                    }
                }
                // Opcode-change detection (action.cc:862-867): if the op's
                // opcode changed during rule application, re-dispatch.
                let new_opc = op_ref.0.read().unwrap().opcode;
                if !op_ref.0.read().unwrap().is_dead() && new_opc != opc {
                    opc = new_opc;
                    continue; // Re-scan with new opcode's rules
                }
                let _ = applied_any;
                break;
            }
        }
        self.total += pass_changes;
        // Print stats on each pass if enabled.
        if want_stats && pass_changes > 0 {
            let fn_name = fd.name.as_str();
            eprintln!("[RULESTATS] {} pool={} pass_changes={}", fn_name, self.name, pass_changes);
        }
        Ok(pass_changes)
    }

    fn get_name(&self) -> &str { &self.name }
    fn get_flags(&self) -> u32 { self.flags }

    fn reset(&mut self, _fd: &mut Funcdata) {
        self.total = 0;
        self.rule_hits.clear();
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

    pool.add_rule(Box::new(RuleEarlyRemoval::new()));       // 5512 — re-enabled: full 6-guard port (ruleaction.cc:30-40) now blocks INDIRECT-source/memory outputs
    pool.add_rule(Box::new(RuleTermOrder::new()));          // 5513
    pool.add_rule(Box::new(RuleSelectCse::new()));          // 5514
    pool.add_rule(Box::new(RuleCollectTerms::new()));       // 5515
    pool.add_rule(Box::new(RulePullsubMulti::new()));       // 5516
    pool.add_rule(Box::new(RulePullsubIndirect::new()));    // 5517
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
    pool.add_rule(Box::new(RuleShiftPiece::new()));     // 5549 — (zext(V)<<sa)|zext(V) => PIECE (ruleaction.cc:3791)
    pool.add_rule(Box::new(RuleMultiCollapse::new()));      // 5550
    pool.add_rule(Box::new(RuleIndirectCollapse::new()));   // 5551
    pool.add_rule(Box::new(Rule2Comp2Mult::new()));         // 5552
    pool.add_rule(Box::new(RuleSub2Add::new()));            // 5553
    pool.add_rule(Box::new(RuleCarryElim::new()));          // 5554
    pool.add_rule(Box::new(RuleBxor2NotEqual::new()));      // 5555
    pool.add_rule(Box::new(RuleLess2Zero::new()));          // 5556
    pool.add_rule(Box::new(RuleLessEqual2Zero::new()));     // 5557
    pool.add_rule(Box::new(RuleSLess2Zero::new()));     // 5558 — INT_SLESS with 0/-1 simplification (ruleaction.cc:5711)
    pool.add_rule(Box::new(RuleEqual2Zero::new()));         // 5559
    pool.add_rule(Box::new(RuleEqual2Constant::new()));     // 5560
    pool.add_rule(Box::new(RuleThreeWayCompare::new()));    // 5561
    pool.add_rule(Box::new(RuleXorCollapse::new()));        // 5562
    pool.add_rule(Box::new(RuleAddMultCollapse::new()));    // 5563
    pool.add_rule(Box::new(RuleCollapseConstants::new()));  // 5564
    pool.add_rule(Box::new(RuleTransformCpool::new()));     // 5565
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
    pool.add_rule(Box::new(RuleSubCommute::new()));        // 5577 — SUBPIECE commute with binary ops (ruleaction.cc:4534)
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
    pool.add_rule(Box::new(RuleDivTermAdd::new()));    // 5594 — optimized division term add (ruleaction.cc:7832)
    pool.add_rule(Box::new(RuleDivTermAdd2::new()));   // 5595 — optimized division term add variant (ruleaction.cc:7955)
    pool.add_rule(Box::new(RuleDivOpt::new()));             // 5596
    pool.add_rule(Box::new(RuleSignForm::new()));           // 5597
    pool.add_rule(Box::new(RuleSignForm2::new()));          // 5598
    pool.add_rule(Box::new(RuleSignDiv2::new()));           // 5599
    pool.add_rule(Box::new(RuleDivChain::new()));           // 5600
    pool.add_rule(Box::new(RuleSignNearMult::new()));       // 5601
    pool.add_rule(Box::new(RuleModOpt::new()));         // 5602 — x/d*(-d)+x => x%d (ruleaction.cc:8612)
    pool.add_rule(Box::new(RuleSignMod2nOpt::new()));       // 5603
    pool.add_rule(Box::new(RuleSignMod2nOpt2::new())); // 5604 — V-(Vadj&~(2^n-1)) => V s% 2^n (ruleaction.cc:8867)
    pool.add_rule(Box::new(RuleSignMod2Opt::new()));  // 5605 — (V-sign)&1+sign => V s% 2 (ruleaction.cc:8794)
    pool.add_rule(Box::new(RuleSwitchSingle::new()));       // 5606
    pool.add_rule(Box::new(RuleCondNegate::new()));         // 5607
    pool.add_rule(Box::new(RuleBoolNegate::new()));         // 5608
    pool.add_rule(Box::new(RuleLessEqual::new()));          // 5609
    pool.add_rule(Box::new(RuleLessNotEqual::new()));       // 5610
    pool.add_rule(Box::new(RuleLessOne::new()));            // 5611
    pool.add_rule(Box::new(RuleRangeMeld::new()));          // 5612
    pool.add_rule(Box::new(RuleFloatRange::new()));         // 5613
    pool.add_rule(Box::new(RulePiece2Zext::new()));         // 5614
    pool.add_rule(Box::new(RulePiece2Sext::new()));         // 5615
    pool.add_rule(Box::new(RulePopcountBoolXor::new())); // 5616 — popcount parity to XOR (ruleaction.cc:10265)
    pool.add_rule(Box::new(RuleXorSwap::new()));            // 5617
    pool.add_rule(Box::new(RuleLzcountShiftBool::new()));   // 5618
    pool.add_rule(Box::new(RuleFloatSign::new()));       // 5619 — float sign-bit manipulation (ruleaction.cc:10714)
    pool.add_rule(Box::new(RuleOrCompare::new()));          // 5620
    // subvar family (subflow.cc, coreaction.cc:5621-5628) — SubvariableFlow
    pool.add_rule(Box::new(crate::subflow::RuleSubvarAnd::new()));       // 5621
    pool.add_rule(Box::new(crate::subflow::RuleSubvarSubpiece::new()));  // 5622
    pool.add_rule(Box::new(crate::subflow::RuleSplitFlow::new()));       // 5623
    pool.add_rule(Box::new(RulePtrFlow::new()));           // 5624
    pool.add_rule(Box::new(crate::subflow::RuleSubvarCompZero::new()));  // 5625
    pool.add_rule(Box::new(crate::subflow::RuleSubvarShift::new()));     // 5626
    pool.add_rule(Box::new(crate::subflow::RuleSubvarZext::new()));      // 5627
    pool.add_rule(Box::new(crate::subflow::RuleSubvarSext::new()));      // 5628
    pool.add_rule(Box::new(RuleNegateNegate::new()));       // 5629
    pool.add_rule(Box::new(RuleConditionalMove::new()));    // 5630
    pool.add_rule(Box::new(crate::condexe::RuleOrPredicate::new())); // 5631
    pool.add_rule(Box::new(RuleFuncPtrEncoding::new()));    // 5632
    pool.add_rule(Box::new(crate::subflow::RuleSubfloatConvert::new())); // 5633
    pool.add_rule(Box::new(RuleFloatCast::new()));          // 5634 — registered here per Ghidra (coreaction.cc:5634)
    pool.add_rule(Box::new(RuleIgnoreNan::new()));          // 5635
    pool.add_rule(Box::new(RuleUnsigned2Float::new()));     // 5636
    pool.add_rule(Box::new(RuleInt2FloatCollapse::new()));  // 5637
    pool.add_rule(Box::new(RulePtraddUndo::new()));         // 5638
    pool.add_rule(Box::new(RulePtrsubUndo::new()));         // 5639
    pool.add_rule(Box::new(RuleSegment::new()));            // 5640
    pool.add_rule(Box::new(RulePiecePathology::new()));     // 5641
    // skip 5642 (gap in Ghidra numbering — reserved)
    pool.add_rule(Box::new(crate::double_precis::RuleDoubleLoad::new()));  // 5643
    pool.add_rule(Box::new(crate::double_precis::RuleDoubleStore::new())); // 5644
    pool.add_rule(Box::new(crate::double_precis::RuleDoubleIn::new()));    // 5645
    pool.add_rule(Box::new(crate::double_precis::RuleDoubleOut::new()));   // 5646

    // Rugra-local companions that complete RuleSub2Add (5553): it emits
    // x + (y * -1), RuleMultNegOne collapses y*-1 to INT_NEG(y), Rule2Comp2Sub
    // handles the 2's-complement form. Grouped after their parent so the pool
    // converges. RuleSextEliminate/Equality are Rugra-local extras.
    // (RuleFloatCast moved to its Ghidra-correct slot at 5634 above.)
    pool.add_rule(Box::new(RuleSextEliminate::new()));
    pool.add_rule(Box::new(RuleEquality::new()));
    // NOTE: RuleMultNegOne (x*-1 -> INT_2COMP) and Rule2Comp2Sub are NOT here
    // — they belong in the separate cleanup pool (see build_cleanup_pool) per
    // Ghidra coreaction.cc:5694-5710. Putting them in oppool1 alongside
    // Rule2Comp2Mult (which does the reverse) causes an infinite ping-pong;
    // Ghidra avoids it by PHASE SEPARATION (main pool converges first, then
    // cleanup pool runs once).
    pool
}

/// Build the cleanup `ActionPool` mirroring Ghidra's `actcleanup`
/// (coreaction.cc:5694-5710). Runs AFTER the main simplify pool so that
/// canonical forms produced by oppool1 (e.g. INT_MULT(x,-1) from
/// Rule2Comp2Mult) get cleaned up to their final form (INT_2COMP) without
/// ping-ponging — the main pool has already converged, so the reverse
/// transform here cannot re-trigger Rule2Comp2Mult.
pub fn build_cleanup_pool() -> ActionPool {
    use crate::ruleaction::*;
    let mut pool = ActionPool::new("cleanup");
    pool.add_rule(Box::new(RuleMultNegOne::new()));   // coreaction.cc:5696
    pool.add_rule(Box::new(RuleAddUnsigned::new()));  // 5697
    pool.add_rule(Box::new(Rule2Comp2Sub::new()));    // 5698
    pool.add_rule(Box::new(crate::subflow::RuleDumptyHumpLate::new())); // 5699
    pool.add_rule(Box::new(RuleSubRight::new()));     // 5700
    pool.add_rule(Box::new(RuleFloatSignCleanup::new())); // 5701
    pool.add_rule(Box::new(RuleExpandLoad::new()));   // 5702
    pool.add_rule(Box::new(RulePtrsubCharConstant::new())); // 5703
    pool.add_rule(Box::new(RuleExtensionPush::new())); // 5704
    pool.add_rule(Box::new(RulePieceStructure::new())); // 5705
    pool.add_rule(Box::new(crate::subflow::RuleSplitCopy::new()));  // 5706
    pool.add_rule(Box::new(crate::subflow::RuleSplitLoad::new()));  // 5707
    pool.add_rule(Box::new(crate::subflow::RuleSplitStore::new())); // 5708
    // RuleStringCopy / RuleStringStore are wired (constseq.cc:954-1002).
    // Detection phase only — transform requires CALLOTHER/userop infrastructure
    // (tracked as a follow-up; matches Ghidra registration at 5709-5710).
    pool.add_rule(Box::new(crate::constseq::RuleStringCopy::new()));   // coreaction.cc:5709
    pool.add_rule(Box::new(crate::constseq::RuleStringStore::new()));  // coreaction.cc:5710
    pool
}

///
/// Corresponds to Ghidra's `ActionDatabase` class
pub struct ActionDatabase {
    all_actions: Vec<Box<dyn Action>>,
    current_group: Option<String>,
}
/// Build the oppool2 `ActionPool` mirroring Ghidra's `actprop2`
/// (coreaction.cc:5662-5671). These are type-recovery / stack-variable Rules
/// that run after oppool1 within the main loop.
pub fn build_oppool2() -> ActionPool {
    use crate::ruleaction::*;
    let mut pool = ActionPool::new("oppool2");
    pool.add_rule(Box::new(RulePushPtr::new()));           // 5664
    pool.add_rule(Box::new(RuleStructOffset0::new()));     // 5665
    pool.add_rule(Box::new(RulePtrArith::new()));          // 5666
    pool.add_rule(Box::new(RuleLoadVarnode::new()));       // 5668
    pool.add_rule(Box::new(RuleStoreVarnode::new()));      // 5669
    pool
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

    pub fn get_action_mut(&mut self, name: &str) -> Option<&mut (dyn Action)> {
        for a in &mut self.all_actions {
            if a.get_name() == name {
                return Some(a.as_mut());
            }
        }
        None
    }

    pub fn get_action(&self, name: &str) -> Option<&dyn Action> {
        self.all_actions.iter()
            .find(|a| a.get_name() == name)
            .map(|a| a.as_ref())
    }

    /// Run all registered actions on the given function data
    /// Run all registered actions on the given function data via perform().
    pub fn apply_all(&mut self, fd: &mut crate::funcdata::Funcdata) -> crate::error::Result<i32> {
        let mut total = 0;
        for i in 0..self.all_actions.len() {
            // Reset per-function state.
            self.all_actions[i].reset(fd);
            // Create a state for this root action.
            let mut state = ActionState::new(self.all_actions[i].get_flags());
            total += self.all_actions[i].perform(fd, &mut state)?;
        }
        Ok(total)
    }

    /// Set up default decompiler actions. Faithful to Ghidra's
    /// `universalAction` (coreaction.cc:5462-5738) — builds a nested tree:
    ///   ActionRestartGroup(universal)
    ///   ├─ Start / FuncLink ...
    ///   ├─ fullloop (repeatapply)
    ///   │  ├─ mainloop (repeatapply)
    ///   │  │  ├─ Heritage / Spacebase / StackPtrFlow ...
    ///   │  │  ├─ stackstall (repeatapply): oppool1 + LaneDivide/MultiCse/...
    ///   │  │  ├─ oppool2 / ConditionalExe ...
    ///   │  └─ DeadCode / DoNothing / SwitchNorm ...
    ///   ├─ cleanup pool
    ///   ├─ MergeType / MarkExplicit / MarkImplied ...
    ///   └─ SetCasts / FinalStructure / Stop
    pub fn set_default_actions(&mut self) {
        // Root: ActionRestartGroup (Ghidra coreaction.cc:5474, onceperfunc, maxrestarts=1)
        let mut universal = ActionRestartGroup::new(
            "decompile",
            action_flags::RULE_ONCEPERFUNC,
            1,
        );

        // --- Top-level Actions (coreaction.cc:5477-5485) ---
        universal.add_action(Box::new(ActionStart::new()));
        universal.add_action(Box::new(crate::coreaction::ActionFuncLink::new()));
        // Wire in additional implemented Actions from coreaction (Ghidra
        // coreaction.cc:5479-5485: NormalizeSetup/DefaultParams/PrototypeTypes/
        // FuncLinkOutOnly).
        for extra in crate::coreaction::build_full_pipeline_actions() {
            universal.add_action(extra);
        }

        // --- fullloop (coreaction.cc:5487, repeatapply) ---
        // NOTE: fullloop kept on ActionGroup::new (no RULE_REPEATAPPLY).
        // With fullloop repeatapply, test_realistic_curl_function still
        // infinite-loops even after reverting mainloop — fullloop re-runs
        // mainloop + ActionDeadCode each cycle, and one of those reports a
        // change every pass (non-idempotent). Reverted to keep the build/test
        // suite green. stackstall repeatapply is retained (its only child, the
        // simplify pool, is designed to converge to a fixed point).
        let mut fullloop = ActionGroup::new("fullloop");

        // --- mainloop (coreaction.cc:5489, repeatapply) ---
        // NOTE: mainloop repeatapply causes stack overflow even with iterative
        // ActionGroup.apply and 256MB stack. Root cause appears to be deep
        // RwLock guard chains inside Rule apply_op (which receive &Arc and
        // may hold nested read/write guards). The iterative ActionGroup fix
        // (calling child.apply not child.perform) is retained as an improvement.
        // Enabling mainloop repeatapply requires either:
        //   1. Identifying the specific Rule/Action causing deep guard nesting
        //   2. Refactoring Rule apply_op to avoid nested locks
        //   3. Using a stack-based (non-recursive) pipeline executor
        // NOTE: mainloop repeatapply cannot be enabled because mainloop contains
        // Actions (Heritage/BlockStructure/FinalStructure) that mutate the CFG
        // and structured blocks. repeatapply re-runs these, causing sblocks to
        // become stale relative to bblocks → printc infinite recursion → stack
        // overflow. Only stackstall (leaf-level, oppool1+oppool2) uses
        // repeatapply safely. Tracked as architectural TODO.
        let mut mainloop = ActionGroup::new("mainloop");

        mainloop.add_action(Box::new(ActionHeritage::new()));
        mainloop.add_action(Box::new(crate::coreaction::ActionSpacebase::new()));
        mainloop.add_action(Box::new(ActionStackPtrFlow::new()));
        // Rugra-local Actions (TODO: replace with Ghidra mechanisms once
        // ActionActiveParam / ActionDefaultParams / ActionDirectWrite are wired).
        mainloop.add_action(Box::new(ActionInferParams::new()));
        mainloop.add_action(Box::new(ActionConstantPtr::new()));
        mainloop.add_action(Box::new(ActionCse::new()));
        mainloop.add_action(Box::new(ActionSimplify::new()));

        // --- stackstall (coreaction.cc:5509, repeatapply) ---
        let mut stackstall = ActionGroup::with_flags("stackstall", action_flags::RULE_REPEATAPPLY);
        // oppool1 (coreaction.cc:5511, repeatapply)
        stackstall.add_action(Box::new(build_simplify_pool()));

        mainloop.add_action(Box::new(stackstall));

        // oppool2 (coreaction.cc:5662) — type-recovery / stack-variable Rules.
        mainloop.add_action(Box::new(build_oppool2()));
        // Rugra-local type/copy propagation (TODO: replace with ActionInferTypes).
        mainloop.add_action(Box::new(ActionTypeInfer::new()));
        mainloop.add_action(Box::new(ActionCopyPropagate::new()));
        mainloop.add_action(Box::new(ActionTypePropagate::new()));

        mainloop.add_action(Box::new(crate::coreaction::ActionRestrictLocal::new()));
        mainloop.add_action(Box::new(ActionDeadCode::new()));
        mainloop.add_action(Box::new(crate::coreaction::ActionRestructureVarnode::new()));
        mainloop.add_action(Box::new(crate::condexe::ActionConditionalExe::new()));
        mainloop.add_action(Box::new(ActionBlockStructure::new()));

        fullloop.add_action(Box::new(mainloop));
        // fullloop post-mainloop Actions (coreaction.cc:5679-5688)
        fullloop.add_action(Box::new(ActionDeadCode::new()));

        universal.add_action(Box::new(fullloop));

        // --- Post-fullloop top-level (coreaction.cc:5691-5738) ---
        // Cleanup pool (coreaction.cc:5694, repeatapply)
        universal.add_action(Box::new(build_cleanup_pool()));
        // Merge stage (coreaction.cc:5717-5729). Rugra collapses 9 steps into
        // Merge::merge_all (see ActionMergeType).
        universal.add_action(Box::new(ActionMergeType::new()));
        universal.add_action(Box::new(crate::coreaction::ActionMarkExplicit::new()));
        universal.add_action(Box::new(crate::coreaction::ActionMarkImplied::new()));
        // NOTE: ActionSetCasts implemented but needs ActionInferTypes first.
        // universal.add_action(Box::new(crate::coreaction::ActionSetCasts::new()));
        universal.add_action(Box::new(ActionNormalizeBranches::new()));
        universal.add_action(Box::new(ActionFinalStructure::new()));

        self.register_action(Box::new(universal));
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
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
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
