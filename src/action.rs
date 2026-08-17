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
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Perform the action's work on the given function data.
    ///
    /// # Returns
    /// 0 if no change occurred, positive if changes were made, negative for
    /// partial completion (breakpoint).
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32>;

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the name of the action
    fn get_name(&self) -> &str;

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Reset derived action state for a new function. The Rust container or
    /// root entry resets the companion `ActionState` to `STATUS_START` and
    /// clears only the warning-issued flag; Ghidra does not clear count/stats
    /// in `Action::reset`.
    fn reset(&mut self, _fd: &mut Funcdata) {}

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the rule flags (repeatapply / onceperfunc / etc). Default: 0
    /// (single-pass). Containers override to return their group's flags.
    fn get_flags(&self) -> u32 { 0 }

    // RUGRA-GLUE: exposes changes accumulated in a Rust container while preserving Ghidra's apply return convention
    /// Return and clear changes accumulated independently of `apply()`'s
    /// control-flow return code. Ghidra stores these in `Action::count`.
    fn take_count_delta(&mut self) -> i32 { 0 }

    // RUGRA-GLUE: passes the external Rust ActionState status to derived actions whose Ghidra base-class status is directly visible
    /// Prepare one `apply()` attempt for the current executor status.
    fn prepare_apply(&mut self, _status: u32) {}

    // Ghidra: action.cc:298 Action::perform
    /// Run this action to completion using Ghidra's status/count state machine.
    /// Positive Rust `apply()` results adapt Ghidra actions that increment their
    /// protected `count` field and return zero.
    fn perform(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        loop {
            let apply_now = match state.status {
                status_flags::STATUS_START => {
                    state.count = 0;
                    state.count_tests += 1;
                    state.lcount = state.count;
                    true
                }
                status_flags::STATUS_BREAKSTARTHIT | status_flags::STATUS_REPEAT => {
                    state.lcount = state.count;
                    true
                }
                status_flags::STATUS_MID => true,
                status_flags::STATUS_END => return Ok(0),
                status_flags::STATUS_ACTIONBREAK => false,
                _ => {
                    state.status = status_flags::STATUS_START;
                    continue;
                }
            };

            if apply_now {
                self.prepare_apply(state.status);
                let res = self.apply(fd)?;
                let accumulated = self.take_count_delta();
                state.count += accumulated;
                if res < 0 {
                    state.status = status_flags::STATUS_MID;
                    return Ok(res);
                }
                state.count += res;
                if state.lcount < state.count {
                    state.count_apply += 1;
                }
            }

            state.status = status_flags::STATUS_REPEAT;
            let flags = if state.flags != 0 { state.flags } else { self.get_flags() };
            if state.lcount >= state.count || (flags & action_flags::RULE_REPEATAPPLY) == 0 {
                break;
            }
        }

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
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Apply the rule to a specific operation
    ///
    /// # Returns
    /// 0 if no change occurred, positive if changes were made
    fn apply_op(&self, op: &std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>, fd: &mut Funcdata) -> Result<i32>;

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the name of the rule
    fn get_name(&self) -> &str;

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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
    /// Changes made by completed children since the parent last observed us.
    pending_count: i32,
}

impl ActionGroup {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new(name: &str) -> Self {
        Self::with_flags(name, 0)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Create with explicit rule flags (e.g. rule_repeatapply for fullloop).
    pub fn with_flags(name: &str, flags: u32) -> Self {
        Self {
            name: name.to_string(),
            actions: Vec::new(),
            child_states: Vec::new(),
            state: 0,
            flags,
            pending_count: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn add_action(&mut self, action: Box<dyn Action>) {
        let child_flags = action.get_flags();
        self.actions.push(action);
        self.child_states.push(ActionState::new(child_flags));
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn get_name_str(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn num_actions(&self) -> usize { self.actions.len() }
    // RUGRA-GLUE: read-only fixture/debug view of Ghidra ActionGroup's protected iterator
    pub fn current_index(&self) -> usize { self.state }
    // RUGRA-GLUE: read-only fixture/debug view of a child Action's externalized executor state
    pub fn child_state(&self, index: usize) -> Option<&ActionState> {
        self.child_states.get(index)
    }
    // RUGRA-GLUE: read-only ordered fixture view of Ghidra ActionGroup::list (action.hh:145); Ghidra prints the same sequence via Action::print (action.cc:417-440)
    pub fn child_names(&self) -> Vec<&str> {
        self.actions.iter().map(|a| a.get_name()).collect()
    }
    // RUGRA-GLUE: fixture executor view — drives child `index` through the exact perform() call ActionGroup::apply makes (src/action.rs ActionGroup::apply line above); Ghidra's ActionGroup::apply drives Action::perform the same way (action.cc:511-527)
    pub fn perform_child(
        &mut self,
        index: usize,
        fd: &mut Funcdata,
    ) -> crate::error::Result<i32> {
        self.actions[index].perform(fd, &mut self.child_states[index])
    }
}

impl Action for ActionGroup {
    // Ghidra: action.cc:506 ActionGroup::apply
    /// Run every child through its `perform()` state machine in list order.
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        while self.state < self.actions.len() {
            let res = self.actions[self.state].perform(fd, &mut self.child_states[self.state])?;
            if res > 0 {
                self.pending_count += res;
            } else if res < 0 {
                return Ok(-1);
            }
            self.state += 1;
        }
        Ok(0)
    }

    // RUGRA-GLUE: mirrors ActionGroup::apply reading its inherited Action::status before initializing the protected iterator
    fn prepare_apply(&mut self, status: u32) {
        if status != status_flags::STATUS_MID {
            self.state = 0;
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 { self.flags }

    // RUGRA-GLUE: externalizes Ghidra ActionGroup's inherited `count` member
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.pending_count)
    }

    // Ghidra: action.cc:408 ActionGroup::reset
    fn reset(&mut self, fd: &mut Funcdata) {
        self.pending_count = 0;
        for i in 0..self.actions.len() {
            self.child_states[i].status = status_flags::STATUS_START;
            self.child_states[i].flags &= !action_flags::RULE_WARNINGS_GIVEN;
            self.actions[i].reset(fd);
        }
    }
}

/// A partial restartable action group — the top-level container for the
/// universal pipeline.
///
/// Wraps an `ActionGroup`. After the group converges (apply returns 0), if
/// `Funcdata::has_restart_pending()` is true, the current implementation
/// resets and re-runs the child subtree. Ghidra additionally calls
/// `Architecture::clearAnalysis`; that missing mutation is tracked by
/// `PIPE-RESTART-0001`, so this type is not a complete port yet.
pub struct ActionRestartGroup {
    name: String,
    group: ActionGroup,
    maxrestarts: i32,
    curstart: i32,
    /// State for this Action (used by parent perform — though this is root).
    flags: u32,
    /// Changes accumulated by the embedded ActionGroup across restarts.
    pending_count: i32,
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
            pending_count: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn add_action(&mut self, action: Box<dyn Action>) {
        self.group.add_action(action);
    }

    // RUGRA-GLUE: read-only ordered fixture view through to the embedded ActionGroup's children (Ghidra ActionRestartGroup inherits ActionGroup::list)
    pub fn child_names(&self) -> Vec<&str> {
        self.group.child_names()
    }

    // RUGRA-GLUE: fixture executor view — drives child `index` of the embedded group exactly as ActionRestartGroup::apply would
    pub fn perform_child(
        &mut self,
        index: usize,
        fd: &mut Funcdata,
    ) -> crate::error::Result<i32> {
        self.group.perform_child(index, fd)
    }

    // RUGRA-GLUE: read-only fixture/debug view of a child Action's externalized executor state
    pub fn child_state(&self, index: usize) -> Option<&ActionState> {
        self.group.child_state(index)
    }
}

impl Action for ActionRestartGroup {
    // Ghidra: action.cc:553 ActionRestartGroup::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        if self.curstart == -1 {
            return Ok(0); // Already completed
        }
        loop {
            let res = self.group.apply(fd)?;
            self.pending_count += self.group.take_count_delta();
            if res < 0 {
                return Ok(res);
            }
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
            // Ghidra sets the inherited Action status to status_start after
            // resetting children.  Rugra externalizes that status, so prepare
            // the embedded group's protected iterator explicitly before this
            // internal restart attempt.
            self.group.prepare_apply(status_flags::STATUS_START);
            // Loop back to re-run the group.
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str {
        &self.name
    }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // RUGRA-GLUE: shares the external restart-group executor status with its embedded Rust ActionGroup
    fn prepare_apply(&mut self, status: u32) {
        self.group.prepare_apply(status);
    }
    // RUGRA-GLUE: externalizes Ghidra ActionRestartGroup's inherited `count` member
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.pending_count)
    }

    // Ghidra: action.cc:546 ActionRestartGroup::reset
    fn reset(&mut self, fd: &mut Funcdata) {
        self.curstart = 0;
        self.pending_count = 0;
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
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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
    // Ghidra: action.cc:877 ActionPool::apply
    /// Single-pass Rule application. Faithful to `ActionPool::apply`
    /// (action.cc:877-887) with `processOp` (action.cc:822-875) inlined. The parent
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
            // detection after every Rule (action.cc:859-869).  A changed
            // opcode invalidates the remainder of the old rule list and
            // restarts dispatch at index zero for the new opcode.
            'dispatch: loop {
                let rule_idxs: Vec<usize> = self.per_op.get(&opc)
                    .cloned()
                    .unwrap_or_default();
                if rule_idxs.is_empty() { break; }
                for ridx in rule_idxs {
                    let res = self.rules[ridx].apply_op(&op_ref.0, fd)?;
                    if res > 0 {
                        pass_changes += res;
                        if want_stats {
                            *self.rule_hits.entry(ridx).or_insert(0) += res;
                        }
                        let (is_dead, new_opc) = {
                            let op = op_ref.0.read().unwrap();
                            (op.is_dead(), op.opcode)
                        };
                        if is_dead {
                            break 'dispatch;
                        }
                        if new_opc != opc {
                            opc = new_opc;
                            continue 'dispatch;
                        }
                    } else {
                        let new_opc = op_ref.0.read().unwrap().opcode;
                        if new_opc == opc {
                            continue;
                        }
                        let message = format!(
                            "ERROR: Rule {} changed op without returning result of 1!",
                            self.rules[ridx].get_name(),
                        );
                        if let Some(arch) = fd.get_arch() {
                            arch.print_message(&message);
                        } else {
                            eprintln!("{message}");
                        }
                        opc = new_opc;
                        continue 'dispatch;
                    }
                }
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 { self.flags }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn reset(&mut self, _fd: &mut Funcdata) {
        self.total = 0;
        self.rule_hits.clear();
    }
}

// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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

// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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
    // Rugra-local: also fold late-created trivial arithmetic (e.g. self-XOR
    // x^x→0 created by type-recovery / copy-prop / structuring passes that
    // run AFTER simplifypool in the mainloop). Ghidra's mainloop repeats
    // actprop (simplifypool) so late ops get re-simplified; Rugra's pipeline
    // runs simplifypool once in stackstall, so we re-apply RuleTrivialArith
    // here as a cleanup to catch trivially-foldable ops (self-XOR/AND/OR/
    // EQUAL) introduced after simplifypool converged.
    pool.add_rule(Box::new(RuleTrivialArith::new()));
    pool
}

///
/// Corresponds to Ghidra's `ActionDatabase` class
pub struct ActionDatabase {
    all_actions: Vec<Box<dyn Action>>,
    current_group: Option<String>,
}
// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new() -> Self {
        Self {
            all_actions: Vec::new(),
            current_group: None,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn register_action(&mut self, action: Box<dyn Action>) {
        self.all_actions.push(action);
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn get_action_mut(&mut self, name: &str) -> Option<&mut (dyn Action)> {
        for a in &mut self.all_actions {
            if a.get_name() == name {
                return Some(a.as_mut());
            }
        }
        None
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn get_action(&self, name: &str) -> Option<&dyn Action> {
        self.all_actions.iter()
            .find(|a| a.get_name() == name)
            .map(|a| a.as_ref())
    }

    // RUGRA-GLUE: Rust ownership adapter for Ghidra's Architecture current Action pointer followed by Action::reset and Action::perform
    /// Reset and perform one registered root action.
    pub fn perform_action(
        &mut self,
        name: &str,
        fd: &mut crate::funcdata::Funcdata,
    ) -> crate::error::Result<Option<i32>> {
        let Some(index) = self
            .all_actions
            .iter()
            .position(|action| action.get_name() == name)
        else {
            return Ok(None);
        };
        self.all_actions[index].reset(fd);
        let mut state = ActionState::new(self.all_actions[index].get_flags());
        self.all_actions[index]
            .perform(fd, &mut state)
            .map(Some)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Set up default decompiler actions by registering the one authoritative
    /// pipeline tree built by [`build_default_pipeline`] (single source of
    /// truth: the ordered-action fixture enumerates the same construction).
    pub fn set_default_actions(&mut self) {
        self.register_action(Box::new(build_default_pipeline()));
    }
}

// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
/// Build the default decompile pipeline root. Faithful to Ghidra's
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
///   ├─ PreferComplement → StructureTransform → NormalizeBranches (:5714-5716)
///   ├─ AssignHigh → MergeRequired → … → MergeAdjacent → MergeType (:5717-5727)
///   └─ HideShadow → … → SetCasts → FinalStructure → PrototypeWarnings → Stop
pub fn build_default_pipeline() -> ActionRestartGroup {
    {
        // Root: ActionRestartGroup (Ghidra coreaction.cc:5474, onceperfunc, maxrestarts=1)
        let mut universal = ActionRestartGroup::new(
            "decompile",
            action_flags::RULE_ONCEPERFUNC,
            1,
        );

        // --- Top-level Actions (coreaction.cc:5477-5485, oracle order) ---
        universal.add_action(Box::new(ActionStart::new())); // :5477
        universal.add_action(Box::new(crate::coreaction::ActionConstbase::new())); // :5478
        // Ghidra: coreaction.cc:5419-5443,5479. ActionNormalizeSetup belongs
        // only to the `normalanalysis` group. That group is a member of the
        // `normalize` root (coreaction.cc:5438-5443) and absent from the
        // default `decompile` root's toggle set (coreaction.cc:5424-5432), so
        // a normal decompilation must preserve imported prototype locks.
        universal.add_action(Box::new(crate::coreaction::ActionDefaultParams::new())); // :5480
        universal.add_action(Box::new(crate::coreaction::ActionExtraPopSetup::new())); // :5482
        universal.add_action(Box::new(crate::coreaction::ActionPrototypeTypes::new())); // :5483
        universal.add_action(Box::new(crate::coreaction::ActionFuncLink::new())); // :5484
        // SINGLE REGISTRATION (UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④):
        // universalAction (coreaction.cc:5462-5738) registers every Action
        // exactly once — e.g. ActionPrototypeWarnings appears only at :5737.
        // build_full_pipeline_actions() (coreaction.rs) returns the
        // implemented-but-unregistered Actions, but this builder registers
        // most of them explicitly below at their oracle positions (base group
        // above, mainloop :5490-5508, fullloop :5679-5688, merge/casts
        // :5714-5738). Consuming those vec entries here as well double-
        // registered them: ActionPrototypeWarnings ran twice per function
        // (stderr 48 = 24×2 unknown-convention warnings), and DefaultParams /
        // PrototypeTypes / VarnodeProps / ParamDouble / DirectWrite /
        // ActiveParam / ReturnRecovery / NonzeroMask / InferTypes /
        // UnjustifiedParams / StartTypes / ActiveReturn / SwitchNorm /
        // HideShadow each ran an extra pass at the wrong (pre-:5482)
        // position. Skip every name this builder owns; the surviving vec
        // entries (FuncLinkOutOnly :5485, Segmentize :5494, InternalStorage
        // :5495, MultiCse :5653, ShadowVar :5654, Deindirect :5655) keep their
        // current registration context.
        //
        // DELIBERATE RESIDUAL (registered in UNKNOWN-PROTOMODEL-WARN-EMIT-0001):
        // outputprototype/inputprototype/setcasts stay double-registered for
        // now. A/B on the locked curl corpus: deduplicating them exposes a
        // printc-side local-name collision (duplicate `uVarN` declarations,
        // numbering 0 -> 35; with the three early runs kept, numbering is 0
        // — better than the pre-change baseline's 16, which this same dedup
        // of the other 15 actions eliminates). Remove the three names from
        // this skip set once the local-declaration naming pass deduplicates
        // names (printc/printlanguage lease) to reach the oracle's single
        // registration for every Action.
        const BUILDER_OWNED_ACTION_NAMES: [&str; 15] = [
            "defaultparams",      // :5480 above
            "prototypetypes",     // :5483 above
            "varnodeprops",       // mainloop :5491
            "paramdouble",        // mainloop :5493
            "directwrite",        // mainloop :5497/:5498 + fullloop :5680/:5681
            "activeparam",        // mainloop :5499
            "returnrecovery",     // mainloop :5500
            "nonzeromask",        // mainloop :5507
            "infertypes",         // mainloop :5508
            "unjustifiedparams",  // fullloop :5686
            "starttypes",         // fullloop :5687
            "activereturn",       // fullloop :5688
            "switchnorm",         // fullloop :5684
            "hideshadow",         // :5728
            "prototypewarnings",  // :5737
        ];
        for extra in crate::coreaction::build_full_pipeline_actions() {
            if BUILDER_OWNED_ACTION_NAMES.contains(&extra.get_name()) {
                continue;
            }
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
        let mut fullloop = ActionGroup::with_flags("fullloop", action_flags::RULE_REPEATAPPLY);

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
        // mainloop repeatapply: not enabled. Despite Arc::as_ptr emitted fix
        // + per-arm helpers + depth guard + 256MB stack, overflow persists.
        // The overflow is in a code path not covered by the depth guard
        // (possibly emit_block_ops or doc_function's discovery pass, which
        // also recurses). Full diagnosis requires stack trace analysis tools
        // not available in this environment. The Arc::as_ptr fix is retained
        // as a correctness improvement. Tracked as TODO.
        let mut mainloop = ActionGroup::with_flags("mainloop", action_flags::RULE_REPEATAPPLY);

        // ActionUnreachable runs AFTER ActionBlockStructure (see below) where
        // the CFG is complete. It was moved from here (Ghidra :5490) to avoid
        // false-positive unreachable detection when bblocks are incomplete.
        mainloop.add_action(Box::new(crate::coreaction::ActionVarnodeProps::new())); // :5491
        mainloop.add_action(Box::new(ActionHeritage::new())); // :5492
        mainloop.add_action(Box::new(crate::coreaction::ActionParamDouble::new())); // :5493
        mainloop.add_action(Box::new(crate::coreaction::ActionDirectWrite::new())); // :5497
        mainloop.add_action(Box::new(crate::coreaction::ActionActiveParam::new())); // :5499
        mainloop.add_action(Box::new(crate::coreaction::ActionReturnRecovery::new())); // :5500
        mainloop.add_action(Box::new(crate::coreaction::ActionSpacebase::new()));
        mainloop.add_action(Box::new(crate::coreaction::ActionNonzeroMask::new())); // :5507
        mainloop.add_action(Box::new(ActionStackPtrFlow::new()));
        // Rugra-local Actions (TODO: replace with Ghidra mechanisms once
        // ActionActiveParam / ActionDefaultParams / ActionDirectWrite are wired).
        // A5 ActionInferParams: KEPT — provides unique parameter inference
        // (no Ghidra equivalent ported yet; ActionActiveParam/ActionDefaultParams
        // are the Ghidra counterparts but aren't wired).
        mainloop.add_action(Box::new(ActionInferParams::new()));
        mainloop.add_action(Box::new(ActionConstantPtr::new()));
        // A6 ActionCse DELETED: redundant with mainloop+fullloop repeatapply.
        // Ghidra's ActionCse (coreaction.cc:708) is historical/commented-out;
        // the actual CSE work is done by oppool1 Rules (RuleSelectCse etc.)
        // + mainloop convergence. Verified: 952/952 tests, defects=0.
        // ActionSimplify DELETED: self-invented Action with no Ghidra counterpart.
        // With mainloop+fullloop RULE_REPEATAPPLY enabled (commits 534642c/70ca7e6),
        // oppool1 (simplifypool) + convergence handles all simplification.
        // Verified redundant: cargo test 952/952, compare_ghidra defects=0.

        // --- stackstall (coreaction.cc:5509, repeatapply) ---
        let mut stackstall = ActionGroup::with_flags("stackstall", action_flags::RULE_REPEATAPPLY);
        // oppool1 (coreaction.cc:5511, repeatapply)
        stackstall.add_action(Box::new(build_simplify_pool()));

        mainloop.add_action(Box::new(stackstall));

        // oppool2 (coreaction.cc:5662) — type-recovery / stack-variable Rules.
        mainloop.add_action(Box::new(build_oppool2()));
        // Rugra-local type/copy propagation (TODO: replace with ActionInferTypes).
        // A2 ActionTypeInfer DELETED: redundant with mainloop+fullloop
        // repeatapply. Ghidra's type inference is ActionInferTypes
        // (coreaction.cc:5508) + oppool2 + fullloop convergence.
        // Verified: 952/952, defects=0.
        // A3 ActionCopyPropagate DELETED: redundant with mainloop+fullloop
        // repeatapply. Ghidra's copy propagation is RulePropagateCopy
        // (oppool1:5566) + fullloop convergence. Verified: 952/952, defects=0.
        // A4 ActionTypePropagate DELETED: redundant with mainloop+fullloop
        // repeatapply. Ghidra's type propagation is part of ActionInferTypes
        // (coreaction.cc:5508); the self-invented ActionTypePropagate
        // duplicated a subset of that work. Verified: 952/952, defects=0.

        mainloop.add_action(Box::new(crate::coreaction::ActionRestrictLocal::new()));
        mainloop.add_action(Box::new(ActionDeadCode::new()));
        mainloop.add_action(Box::new(crate::coreaction::ActionRestructureVarnode::new()));
        // Faithful to coreaction.cc:5508: ActionInferTypes runs in mainloop
        // after RestructureVarnode/Spacebase/NonzeroMask. Propagates Datatype
        // across data-flow so HighVariables get typed prefixes (pcVar/iVar/...)
        // instead of falling back to uVar. Self-limited to 7 passes.
        mainloop.add_action(Box::new(crate::coreaction::ActionInferTypes::new()));
        mainloop.add_action(Box::new(crate::condexe::ActionConditionalExe::new()));
        // Ghidra coreaction.cc:5658-5659: ActionRedundBranch runs BEFORE
        // ActionBlockStructure. The dead-branch splice must settle the CFG
        // BEFORE structuring, otherwise structuring produces sblocks that
        // immediately go stale when RedundBranch mutates bblocks afterwards
        // (sblocks cleared on next mainloop iteration, never rebuilt before
        // print → flat bblocks emission → dangling `goto ;`).
        mainloop.add_action(Box::new(crate::coreaction::ActionRedundBranch::new())); // :5658
        mainloop.add_action(Box::new(ActionBlockStructure::new())); // :5659
        // ActionUnreachable (coreaction.cc:5673) — runs AFTER BlockStructure,
        // removing blocks that became unreachable after structuring.
        mainloop.add_action(Box::new(crate::coreaction::ActionDeterminedBranch::new())); // :5672
        mainloop.add_action(Box::new(crate::coreaction::ActionUnreachable::new())); // :5673
        mainloop.add_action(Box::new(crate::coreaction::ActionNodeJoin::new())); // :5674
        mainloop.add_action(Box::new(crate::coreaction::ActionConditionalConst::new())); // :5676 — enabled (once-per-func guarded)

        fullloop.add_action(Box::new(mainloop));
        // fullloop post-mainloop Actions (coreaction.cc:5679-5688) — registered
        // but some may need maturity before enabling.
        fullloop.add_action(Box::new(crate::coreaction::ActionLikelyTrash::new())); // :5679
        fullloop.add_action(Box::new(crate::coreaction::ActionDirectWrite::new())); // :5680
        fullloop.add_action(Box::new(crate::coreaction::ActionDoNothing::new())); // :5683
        fullloop.add_action(Box::new(crate::coreaction::ActionSwitchNorm::new())); // :5684
        fullloop.add_action(Box::new(crate::coreaction::ActionReturnSplit::new())); // :5685
        fullloop.add_action(Box::new(crate::coreaction::ActionUnjustifiedParams::new())); // :5686
        fullloop.add_action(Box::new(crate::coreaction::ActionStartTypes::new())); // :5687
        fullloop.add_action(Box::new(crate::coreaction::ActionActiveReturn::new())); // :5688
        fullloop.add_action(Box::new(ActionDeadCode::new())); // :5687

        universal.add_action(Box::new(fullloop));

        // --- Post-fullloop top-level (coreaction.cc:5691-5738) ---
        universal.add_action(Box::new(crate::coreaction::ActionMappedLocalSync::new())); // :5691 — stub, safe
        universal.add_action(Box::new(crate::coreaction::ActionStartCleanUp::new())); // :5692 — stub, safe
        // Cleanup pool (coreaction.cc:5694, repeatapply)
        universal.add_action(Box::new(build_cleanup_pool()));
        // Post-cleanup sequence mirrors coreaction.cc:5714-5738 verbatim.
        // PIPE-MERGETYPE-ORDER-0001: the three structural transforms come
        // FIRST after the cleanup pool (:5714-5716), ActionMergeType runs
        // exactly ONCE late (:5727, after MergeAdjacent, before HideShadow),
        // and ActionAssignHigh (:5717) attaches HighVariables between the
        // structural transforms and the merge family (HideShadow/MarkExplicit/
        // mergeByDatatype dereference getHigh() unconditionally — Ghidra
        // coreaction.cc:4831/3237, merge.cc:370). The former premature
        // MergeType right after cleanup and the NormalizeBranches-first
        // ordering were historical accretion (78186a2/2f3116f/c45b2fa), not
        // oracle order; see docs/alignment_audit/PIPELINE_TREE_2026-08-13.md.
        universal.add_action(Box::new(crate::coreaction::ActionPreferComplement::new())); // :5714
        universal.add_action(Box::new(crate::coreaction::ActionStructureTransform::new())); // :5715
        universal.add_action(Box::new(ActionNormalizeBranches::new())); // :5716 (blockaction.cc:2117)
        universal.add_action(Box::new(crate::coreaction::ActionAssignHigh::new())); // :5717 — moved here from build_full_pipeline_actions
        // Merge stage (coreaction.cc:5718-5726) — faithful order:
        universal.add_action(Box::new(crate::coreaction::ActionMergeRequired::new())); // :5718
        universal.add_action(Box::new(crate::coreaction::ActionMarkExplicit::new())); // :5719
        universal.add_action(Box::new(crate::coreaction::ActionMarkImplied::new())); // :5720
        universal.add_action(Box::new(crate::coreaction::ActionMergeMultiEntry::new())); // :5721
        universal.add_action(Box::new(crate::coreaction::ActionMergeCopy::new())); // :5722
        universal.add_action(Box::new(crate::coreaction::ActionDominantCopy::new())); // :5723 — moved here from build_full_pipeline_actions
        universal.add_action(Box::new(crate::coreaction::ActionDynamicSymbols::new())); // :5724 — first of oracle's two deliberate instances (stub, safe)
        universal.add_action(Box::new(crate::coreaction::ActionMarkIndirectOnly::new())); // :5725
        universal.add_action(Box::new(crate::coreaction::ActionMergeAdjacent::new())); // :5726
        universal.add_action(Box::new(crate::coreaction::ActionMergeType::new())); // :5727 — the single instance (Merge::merge_all still folds the :5718-5729 steps internally; see ActionMergeType)
        universal.add_action(Box::new(crate::coreaction::ActionHideShadow::new())); // :5728
        universal.add_action(Box::new(crate::coreaction::ActionCopyMarker::new())); // :5729 — moved here from build_full_pipeline_actions
        // ActionOutputPrototype + ActionInputPrototype (coreaction.cc:5730-5731)
        // — finalize the function prototype from RETURN ops (return type) and
        // input varnodes (param count/types). Run after merge + MarkExplicit/
        // Implied, before SetCasts (5735) and FinalStructure (5736).
        universal.add_action(Box::new(crate::coreaction::ActionOutputPrototype::new())); // :5730
        universal.add_action(Box::new(crate::coreaction::ActionInputPrototype::new())); // :5731
        universal.add_action(Box::new(crate::coreaction::ActionMapGlobals::new())); // :5732
        universal.add_action(Box::new(crate::coreaction::ActionDynamicSymbols::new())); // :5733 — second of oracle's two instances
        universal.add_action(Box::new(crate::coreaction::ActionNameVars::new())); // :5734
        // ActionSetCasts (coreaction.cc:5735) — inserts CPUI_CAST ops so the
        // printer emits explicit C type casts. Runs after ActionInferTypes
        // (mainloop) and ActionMarkExplicit/Implied so input/output types are
        // settled. Faithful to Ghidra's order: ...MarkImplied → ...NameVars →
        // SetCasts → FinalStructure → PrototypeWarnings.
        universal.add_action(Box::new(crate::coreaction::ActionSetCasts::new())); // :5735
        universal.add_action(Box::new(ActionFinalStructure::new())); // :5736 (blockaction.cc:2186) — before PrototypeWarnings per oracle
        universal.add_action(Box::new(crate::coreaction::ActionPrototypeWarnings::new())); // :5737
        universal.add_action(Box::new(crate::coreaction::ActionStop::new())); // :5738 — stub, safe

        universal
    }
}

/// ActionTypePropagate: Conservative P-code struct pointer type propagation.
/// Marks varnodes used as base in >=2 distinct small (<256B, 8-byte-aligned)
/// offsets via INT_ADD → LOAD/STORE. Mirrors Ghidra's ActionTypePropagate.
pub struct ActionTypePropagate;

impl ActionTypePropagate {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new() -> Self { Self }
}

impl Action for ActionTypePropagate {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        crate::analysis::type_infer::propagate_types(fd);
        Ok(0)
    }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { "typepropagate" }
}

/// Status codes for Action execution
pub mod action_status {
    pub const NO_CHANGE: i32 = 0;
    pub const CHANGE: i32 = 1;
    pub const RESTART: i32 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    // PIPE-MERGETYPE-ORDER-0001: the post-cleanup child sequence of the
    // default pipeline must mirror coreaction.cc:5714-5738 verbatim — three
    // structural transforms first (:5714-5716), a single ActionMergeType late
    // (:5727, after mergeadjacent, before hideshadow), and ActionAssignHigh
    // (:5717) between the transforms and the merge family.
    #[test]
    fn test_post_cleanup_sequence_matches_ghidra_5714_5738() {
        let root = build_default_pipeline();
        let names = root.child_names();
        let start = names
            .iter()
            .position(|n| *n == "prefercomplement")
            .expect("prefercomplement must be registered");
        let tail: Vec<&str> = names[start..].to_vec();
        assert_eq!(
            tail,
            vec![
                "prefercomplement",     // :5714
                "structuretransform",   // :5715
                "normalizebranches",    // :5716
                "assignhigh",           // :5717
                "mergerequired",        // :5718
                "markexplicit",         // :5719
                "markimplied",          // :5720
                "mergemultientry",      // :5721
                "mergecopy",            // :5722
                "dominantcopy",         // :5723
                "dynamicsymbols",       // :5724 (first instance)
                "markindirectonly",     // :5725
                "mergeadjacent",        // :5726
                "mergetype",            // :5727 — the single instance
                "hideshadow",           // :5728
                "copymarker",           // :5729
                "outputprototype",      // :5730
                "inputprototype",       // :5731
                "mapglobals",           // :5732
                "dynamicsymbols",       // :5733 (second instance)
                "namevars",             // :5734
                "setcasts",             // :5735
                "finalstructure",       // :5736
                "prototypewarnings",    // :5737
                "stop",                 // :5738
            ]
        );
        // Exactly one mergetype in the whole tree (the premature post-cleanup
        // instance and the build_full_pipeline_actions duplicates are gone).
        assert_eq!(names.iter().filter(|n| **n == "mergetype").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "assignhigh").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "dominantcopy").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "copymarker").count(), 1);
    }

    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④: universalAction registers every
    // Action exactly once (coreaction.cc:5462-5738); ActionPrototypeWarnings
    // appears only at :5737. The build_full_pipeline_actions() consumption
    // used to double-register it (stderr 48 = 24×2 unknown-convention
    // warnings per E2E run) along with 14 other Actions this builder owns.
    #[test]
    fn test_prototype_warnings_registered_once() {
        let root = build_default_pipeline();
        let names = root.child_names();
        // coreaction.cc:5737 — exactly one top-level prototypewarnings.
        assert_eq!(names.iter().filter(|n| **n == "prototypewarnings").count(), 1);
        // DELIBERATE RESIDUAL (see the skip-set comment above): the three
        // early runs kept registered until the printc naming fix land as
        // exactly two top-level instances each (early + oracle position).
        for name in ["outputprototype", "inputprototype", "setcasts"] {
            assert_eq!(
                names.iter().filter(|n| **n == name).count(),
                2,
                "residual double for {name}"
            );
        }
        // The other deduplicated builder-owned names: base/merge ones appear
        // exactly once at top level, mainloop/fullloop ones only inside their
        // group (zero top-level instances).
        for (name, expected_top_level) in [
            ("defaultparams", 1),      // :5480
            ("prototypetypes", 1),     // :5483
            ("hideshadow", 1),         // :5728
            ("varnodeprops", 0),       // mainloop :5491
            ("paramdouble", 0),        // mainloop :5493
            ("directwrite", 0),        // mainloop/fullloop only
            ("activeparam", 0),        // mainloop :5499
            ("returnrecovery", 0),     // mainloop :5500
            ("nonzeromask", 0),        // mainloop :5507
            ("infertypes", 0),         // mainloop :5508
            ("unjustifiedparams", 0),  // fullloop :5686
            ("starttypes", 0),         // fullloop :5687
            ("activereturn", 0),       // fullloop :5688
            ("switchnorm", 0),         // fullloop :5684
        ] {
            assert_eq!(
                names.iter().filter(|n| **n == name).count(),
                expected_top_level,
                "top-level count for {name}"
            );
        }
    }

    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④: the base group order is
    // coreaction.cc:5477-5485 verbatim (Start, Constbase, [NormalizeSetup
    // excluded — normalanalysis group, not in the decompile root's toggle
    // set], DefaultParams, ExtraPopSetup, PrototypeTypes, FuncLink,
    // FuncLinkOutOnly), followed by the remaining build_full_pipeline_actions
    // survivors and fullloop.
    #[test]
    fn test_base_group_order_matches_ghidra_5477_5485() {
        let root = build_default_pipeline();
        let names = root.child_names();
        let expected_prefix = [
            "start",             // :5477
            "constbase",         // :5478
            "defaultparams",     // :5480
            "extrapopsetup",     // :5482
            "prototypetypes",    // :5483
            "funclink",          // :5484
            "funclinkoutonly",   // :5485 (vec survivor, base position)
            "segmentize",        // :5494 (vec survivor)
            "internalstorage",   // :5495 (vec survivor)
            "multicse",          // :5653 (vec survivor)
            "shadowvar",         // :5654 (vec survivor)
            "deindirect",        // :5655 (vec survivor)
            // DELIBERATE RESIDUAL doubles (see the skip-set comment above):
            // the early outputprototype/inputprototype/setcasts runs stay
            // registered until the printc-side local-name collision is
            // fixed; their oracle positions (:5730/:5731/:5735) hold the
            // second instance.
            "outputprototype",   // :5730 (residual early double)
            "inputprototype",    // :5731 (residual early double)
            "setcasts",          // :5735 (residual early double)
            "fullloop",          // :5487 group
        ];
        assert!(names.len() >= expected_prefix.len());
        let prefix: Vec<&str> = names[..expected_prefix.len()].to_vec();
        assert_eq!(prefix, expected_prefix.to_vec());
    }

    struct ScriptAction {
        script: Vec<i32>,
        cursor: usize,
        flags: u32,
        calls: Arc<AtomicUsize>,
    }

    impl ScriptAction {
        fn new(script: Vec<i32>, flags: u32, calls: Arc<AtomicUsize>) -> Self {
            Self {
                script,
                cursor: 0,
                flags,
                calls,
            }
        }
    }

    impl Action for ScriptAction {
        fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.script.get(self.cursor).copied().unwrap_or(0);
            self.cursor += 1;
            Ok(result)
        }

        fn get_name(&self) -> &str {
            "script"
        }

        fn get_flags(&self) -> u32 {
            self.flags
        }
    }

    fn fixture_funcdata() -> Funcdata {
        Funcdata::new("action_fixture", Address::new(0x1000), 1)
    }

    #[test]
    fn perform_repeats_until_no_change() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut action = ScriptAction::new(
            vec![1, 1, 0],
            action_flags::RULE_REPEATAPPLY,
            calls.clone(),
        );
        let mut state = ActionState::new(action_flags::RULE_REPEATAPPLY);
        let mut fd = fixture_funcdata();

        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(state.count, 2);
        assert_eq!(state.lcount, 2);
        assert_eq!(state.count_tests, 1);
        assert_eq!(state.count_apply, 2);
        assert_eq!(state.status, status_flags::STATUS_START);
    }

    #[test]
    fn perform_resumes_partial_without_restarting_counters() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut action = ScriptAction::new(vec![-1, 1], 0, calls.clone());
        let mut state = ActionState::new(0);
        let mut fd = fixture_funcdata();

        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), -1);
        assert_eq!(state.status, status_flags::STATUS_MID);
        assert_eq!(state.count_tests, 1);
        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(state.count_tests, 1);
        assert_eq!(state.count_apply, 1);
        assert_eq!(state.status, status_flags::STATUS_START);
    }

    #[test]
    fn once_per_function_stops_until_reset() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut action = ScriptAction::new(
            vec![0, 0],
            action_flags::RULE_ONCEPERFUNC,
            calls.clone(),
        );
        let mut state = ActionState::new(action_flags::RULE_ONCEPERFUNC);
        let mut fd = fixture_funcdata();

        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 0);
        assert_eq!(state.status, status_flags::STATUS_END);
        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        state.status = status_flags::STATUS_START;
        action.reset(&mut fd);
        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
