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

    // RUGRA-GLUE: fixture-only nested tree view; Ghidra exposes the same nesting via Action::print (action.cc:417-440)
    /// Read-only downcast for tree-walking fixtures: returns the container
    /// view if this Action is an ActionGroup/ActionRestartGroup.
    fn as_action_group(&self) -> Option<&ActionGroup> { None }

    // RUGRA-GLUE: fixture-only mutable container view for subtree-driving fixtures
    /// Mutable downcast mirroring `as_action_group`.
    fn as_action_group_mut(&mut self) -> Option<&mut ActionGroup> { None }

    // RUGRA-GLUE: fixture-only pool view; Ghidra holds the same class identity via the virtual ActionPool (action.hh:262)
    /// Read-only downcast for tree-walking fixtures: returns the pool view
    /// if this Action is an ActionPool.
    fn as_action_pool(&self) -> Option<&ActionPool> { None }

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
    /// Ghidra: basegroup member of each child Action (action.hh:88). Ghidra
    /// stores the group inside every Action instance; Rugra records it at
    /// the registration slot in the parent (RUGRA-GLUE: per-instance storage
    /// would require touching Action classes owned by other write-sets).
    /// Observably identical for the default tree: every instance is
    /// registered exactly once at one fixed slot (coreaction.cc:5462-5738).
    child_groups: Vec<&'static str>,
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
            child_groups: Vec::new(),
            state: 0,
            flags,
            pending_count: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn add_action(&mut self, action: Box<dyn Action>) {
        self.add_action_in_group(action, "");
    }

    // RUGRA-GLUE: registration-site group record mirroring the basegroup string passed to each Ghidra Action ctor (coreaction.cc:5477-5738)
    /// Add a child together with the basegroup string its Ghidra ctor
    /// receives at this registration slot (`new ActionX(group)`).
    pub fn add_action_in_group(&mut self, action: Box<dyn Action>, group: &'static str) {
        let child_flags = action.get_flags();
        self.actions.push(action);
        self.child_states.push(ActionState::new(child_flags));
        self.child_groups.push(group);
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
    // RUGRA-GLUE: fixture-only read-only child view for tree-walking tests (Ghidra iterates the same protected list in Action::print)
    pub fn child_actions(&self) -> &[Box<dyn Action>] {
        &self.actions
    }
    // RUGRA-GLUE: fixture-only mutable child view for driving one subtree through the exact perform() sequence (Ghidra's ActionGroup::apply drives the same protected list)
    pub fn child_actions_mut(&mut self) -> &mut [Box<dyn Action>] {
        &mut self.actions
    }
    // RUGRA-GLUE: registration-site basegroup view for tree-walking fixtures (Ghidra Action::getGroup, action.hh:109)
    pub fn child_group(&self, index: usize) -> &'static str {
        self.child_groups[index]
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

    // RUGRA-GLUE: fixture-only nested tree view (see Action::as_action_group)
    fn as_action_group(&self) -> Option<&ActionGroup> { Some(self) }
    // RUGRA-GLUE: fixture-only mutable nested tree view for subtree-driving fixtures (Ghidra reaches the same list via protected ActionGroup::list)
    fn as_action_group_mut(&mut self) -> Option<&mut ActionGroup> { Some(self) }

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

    // RUGRA-GLUE: registration-site group record passthrough (see ActionGroup::add_action_in_group)
    pub fn add_action_in_group(&mut self, action: Box<dyn Action>, group: &'static str) {
        self.group.add_action_in_group(action, group);
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn num_actions(&self) -> usize {
        self.group.num_actions()
    }

    // RUGRA-GLUE: registration-site basegroup view passthrough (Ghidra Action::getGroup, action.hh:109)
    pub fn child_group(&self, index: usize) -> &'static str {
        self.group.child_group(index)
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
    // RUGRA-GLUE: fixture-only nested tree view (see Action::as_action_group)
    fn as_action_group(&self) -> Option<&ActionGroup> { Some(&self.group) }
    // RUGRA-GLUE: fixture-only mutable nested tree view for subtree-driving fixtures (Ghidra ActionRestartGroup inherits ActionGroup::list)
    fn as_action_group_mut(&mut self) -> Option<&mut ActionGroup> { Some(&mut self.group) }
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

    // RUGRA-GLUE: fixture-only rule registration view (pool purity fixture
    // tests/oracle/pool_purity_1204; the Ghidra fixture reads the same
    // sequence through the public virtual ActionPool::print, action.cc:
    // 753-775, which iterates allrules in registration order). No dispatch
    // state is exposed.
    pub fn rules(&self) -> &[Box<dyn Rule>] { &self.rules }
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

    // RUGRA-GLUE: fixture-only pool view (see Action::as_action_pool)
    fn as_action_pool(&self) -> Option<&ActionPool> { Some(self) }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn reset(&mut self, _fd: &mut Funcdata) {
        self.total = 0;
        self.rule_hits.clear();
    }
}

// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
/// Build the oppool1 `ActionPool` mirroring Ghidra's `actprop`
/// (coreaction.cc:5511-5649). Pool name is "oppool1" exactly as
/// `new ActionPool(Action::rule_repeatapply,"oppool1")` (:5511).
pub fn build_oppool1() -> ActionPool {
    use crate::ruleaction::*;
    let mut pool = ActionPool::new("oppool1");
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

    // Pool ends at RuleDoubleOut (5646), exactly as Ghidra's oppool1. The
    // remaining oracle loop (coreaction.cc:5647-5649) only absorbs
    // CPU-specific conf->extra_pool_rules, of which the x86-64 gcc spec
    // registers none. PIPE-POOL-LOCAL-RULES-0001 removed the former
    // Rugra-local registrations of RuleSextEliminate (no oracle class at
    // all) and RuleEquality (oracle class exists, ruleaction.hh:243, but
    // is never instantiated anywhere in the locked tree).
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
    // Pool ends at RuleStringStore (5710), exactly as Ghidra's actcleanup
    // (coreaction.cc:5694-5711). PIPE-POOL-LOCAL-RULES-0001 removed the
    // former Rugra-local re-registration of RuleTrivialArith here — the
    // oracle cleanup pool has no such entry; Ghidra registers
    // RuleTrivialArith exactly once, in oppool1 (coreaction.cc:5522).
    pool
}

/// Ghidra: action.hh:31-40 `ActionGroupList`
///
/// The set of group names steering a root-Action derivation. Any Rule or
/// leaf Action belongs to a group; the groups in this list together define
/// which children survive `ActionDatabase::deriveAction`'s selective clone.
#[derive(Debug, Clone)]
pub struct ActionGroupList {
    groups: std::collections::BTreeSet<&'static str>,
}

impl ActionGroupList {
    // RUGRA-GLUE: static-member constructor (Ghidra fills the same set via ActionDatabase::setGroup's argv, action.cc:1059-1070)
    pub fn from_members(members: &[&'static str]) -> Self {
        Self {
            groups: members.iter().copied().collect(),
        }
    }

    // Ghidra: action.hh:39 ActionGroupList::contains
    pub fn contains(&self, nm: &str) -> bool {
        self.groups.contains(nm)
    }
}

/// Ghidra: coreaction.cc:5419-5458 `ActionDatabase::buildDefaultGroups` —
/// the preconfigured root-Action grouplists, verbatim member order (set
/// semantics; order is not observable through `contains`).
pub mod default_groups {
    /// `setGroup("decompile", members)` — coreaction.cc:5424-5432. The
    /// default decompilation root. Note what is ABSENT: `normalanalysis`,
    /// `noproto`, `protorecovery_b`, `siganalysis`, `normalizebranches`.
    pub const DECOMPILE: &[&str] = &[
        "base", "protorecovery", "protorecovery_a", "deindirect", "localrecovery",
        "deadcode", "typerecovery", "stackptrflow",
        "blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
        "cleanup", "splitcopy", "splitpointer", "merge", "dynamic", "casts", "analysis",
        "fixateglobals", "fixateproto", "constsequence",
        "segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
        "unreachable", "subvar", "floatprecision",
        "conditionalexe",
    ];
    /// `setGroup("jumptable", jumptab)` — coreaction.cc:5434-5436.
    pub const JUMPTABLE: &[&str] = &[
        "base", "noproto", "localrecovery", "deadcode", "stackptrflow",
        "stackvars", "analysis", "segment", "subvar", "normalizebranches",
        "conditionalexe",
    ];
    /// `setGroup("normalize", normali)` — coreaction.cc:5438-5443.
    pub const NORMALIZE: &[&str] = &[
        "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
        "deadcode", "stackptrflow", "normalanalysis",
        "stackvars", "deadcontrolflow", "analysis", "fixateproto", "nodejoin",
        "unreachable", "subvar", "floatprecision", "normalizebranches",
        "conditionalexe",
    ];
    /// `setGroup("paramid", paramid)` — coreaction.cc:5445-5450.
    pub const PARAMID: &[&str] = &[
        "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
        "deadcode", "typerecovery", "stackptrflow", "siganalysis",
        "stackvars", "deadcontrolflow", "analysis", "fixateproto",
        "unreachable", "subvar", "floatprecision",
        "conditionalexe",
    ];
    /// `setGroup("register", regmemb)` — coreaction.cc:5452-5453.
    pub const REGISTER: &[&str] = &["base", "analysis", "subvar"];
    /// `setGroup("firstpass", firstmem)` — coreaction.cc:5455-5456.
    pub const FIRSTPASS: &[&str] = &["base"];
}

///
/// Corresponds to Ghidra's `ActionDatabase` class (action.hh:298-324)
pub struct ActionDatabase {
    /// Ghidra `actionmap` (action.hh:302): registered root Actions by name.
    actionmap: Vec<(String, Box<dyn Action>)>,
    /// Ghidra `groupmap` (action.hh:301): root name → steering grouplist.
    groupmap: Vec<(String, ActionGroupList)>,
    /// Ghidra `currentact` (action.hh:299): the current root Action.
    currentact: Option<usize>,
    /// Ghidra `currentactname` (action.hh:300).
    currentactname: String,
    /// Ghidra `isDefaultGroups` (action.hh:303).
    is_default_groups: bool,
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
    // Ghidra: action.hh:310 ActionDatabase::ActionDatabase
    pub fn new() -> Self {
        Self {
            actionmap: Vec::new(),
            groupmap: Vec::new(),
            currentact: None,
            currentactname: String::new(),
            is_default_groups: false,
        }
    }

    // Ghidra: action.cc:1126 ActionDatabase::registerAction
    /// Register a root Action under `nm`; the database takes ownership
    /// (Ghidra deletes a previously registered object of the same name).
    fn register_action_named(&mut self, nm: &str, act: Box<dyn Action>) {
        if let Some(idx) = self.actionmap.iter().position(|(key, _)| key == nm) {
            self.actionmap[idx].1 = act;
        } else {
            self.actionmap.push((nm.to_string(), act));
        }
    }

    // RUGRA-GLUE: legacy pub registration under the Action's own name (Ghidra registers roots by explicit key only)
    pub fn register_action(&mut self, action: Box<dyn Action>) {
        let nm = action.get_name().to_string();
        self.register_action_named(&nm, action);
    }

    // Ghidra: action.cc:1112 ActionDatabase::getAction (index lookup form)
    fn action_index(&self, nm: &str) -> Option<usize> {
        self.actionmap.iter().position(|(key, _)| key == nm)
    }

    // RUGRA-GLUE: pub lookup mirroring Ghidra getAction's throw as None
    pub fn get_action(&self, name: &str) -> Option<&dyn Action> {
        self.action_index(name).map(|idx| self.actionmap[idx].1.as_ref())
    }

    // RUGRA-GLUE: pub mutable lookup mirroring Ghidra getAction's throw as None
    pub fn get_action_mut(&mut self, name: &str) -> Option<&mut (dyn Action + '_)> {
        match self.action_index(name) {
            Some(idx) => Some(self.actionmap[idx].1.as_mut()),
            None => None,
        }
    }

    // Ghidra: action.cc:1059 ActionDatabase::setGroup (member-list form)
    fn set_group(&mut self, grp: &str, members: &[&'static str]) {
        let grouplist = ActionGroupList::from_members(members);
        if let Some(idx) = self.groupmap.iter().position(|(key, _)| key == grp) {
            self.groupmap[idx].1 = grouplist;
        } else {
            self.groupmap.push((grp.to_string(), grouplist));
        }
        self.is_default_groups = false;
    }

    // Ghidra: action.cc:1006 ActionDatabase::getGroup
    fn get_group(&self, grp: &str) -> Option<&ActionGroupList> {
        self.groupmap
            .iter()
            .find(|(key, _)| key == grp)
            .map(|(_, list)| list)
    }

    // Ghidra: coreaction.cc:5419 ActionDatabase::buildDefaultGroups
    fn build_default_groups(&mut self) {
        if self.is_default_groups {
            return;
        }
        self.groupmap.clear();
        self.set_group("decompile", default_groups::DECOMPILE);
        self.set_group("jumptable", default_groups::JUMPTABLE);
        self.set_group("normalize", default_groups::NORMALIZE);
        self.set_group("paramid", default_groups::PARAMID);
        self.set_group("register", default_groups::REGISTER);
        self.set_group("firstpass", default_groups::FIRSTPASS);
        self.is_default_groups = true;
    }

    // Ghidra: coreaction.cc:5462 ActionDatabase::universalAction
    /// Build the raw universal Action and register it under "universal"
    /// (Ghidra `registerAction(universalname, act)`, coreaction.cc:5475).
    pub fn universal_action(&mut self) {
        let act = universal_action(None).expect("universal root always survives");
        self.register_action_named("universal", Box::new(act));
    }

    // Ghidra: action.cc:986 ActionDatabase::resetDefaults
    /// Clear out (possibly altered) root Actions, reset the default groups,
    /// and set the default root action "decompile".
    pub fn reset_defaults(&mut self) {
        // Keep the registered universal; delete every other old root
        // (action.cc:991-999), then re-register universal in a cleared map.
        let universal = self
            .action_index("universal")
            .map(|idx| self.actionmap.remove(idx));
        self.actionmap.clear();
        if let Some((_, act)) = universal {
            self.actionmap.push(("universal".to_string(), act));
        }
        self.build_default_groups();
        self.set_current("decompile"); // The default root action (action.cc:1003)
    }

    // Ghidra: action.cc:1021 ActionDatabase::setCurrent
    pub fn set_current(&mut self, actname: &str) {
        self.currentactname = actname.to_string();
        self.derive_action("universal", actname);
        let index = self
            .action_index(actname)
            .expect("setCurrent: derived root must be registered");
        self.currentact = Some(index);
    }

    // Ghidra: action.cc:1145 ActionDatabase::deriveAction
    /// Build the Action object for root name `grp` by selectively copying
    /// components from `baseaction` based on `grp`'s grouplist. Ghidra
    /// deep-clones the registered base tree via `Action::clone`; Rugra
    /// rebuilds through the same construction filtered by the grouplist
    /// (RUGRA-GLUE: `Box<dyn Action>` is not `Clone`; at derive time every
    /// Ghidra clone also starts from freshly built state, so the resulting
    /// tree is observably identical).
    fn derive_action(&mut self, baseaction: &str, grp: &str) {
        if self.action_index(grp).is_some() {
            return; // Already derived this action (action.cc:1149-1151)
        }
        let grouplist = self
            .get_group(grp)
            .unwrap_or_else(|| panic!("Action group does not exist: {grp}"))
            .clone();
        let _ = baseaction; // base is always the registered "universal" tree
        let newact = universal_action(Some(&grouplist))
            .unwrap_or_else(|| panic!("derived root {grp} kept no children"));
        self.register_action_named(grp, Box::new(newact));
    }

    // Ghidra: action.hh:313 ActionDatabase::getCurrent
    pub fn get_current(&self) -> &dyn Action {
        self.actionmap[self.currentact.expect("no current root action")].1.as_ref()
    }

    // Ghidra: action.hh:314 ActionDatabase::getCurrentName
    pub fn get_current_name(&self) -> &str {
        &self.currentactname
    }

    // RUGRA-GLUE: Rust ownership adapter for Ghidra's Architecture current Action pointer followed by Action::reset and Action::perform
    /// Reset and perform one registered root action.
    pub fn perform_action(
        &mut self,
        name: &str,
        fd: &mut crate::funcdata::Funcdata,
    ) -> crate::error::Result<Option<i32>> {
        let Some(index) = self.action_index(name) else {
            return Ok(None);
        };
        self.actionmap[index].1.reset(fd);
        let flags = self.actionmap[index].1.get_flags();
        let mut state = ActionState::new(flags);
        self.actionmap[index].1.perform(fd, &mut state).map(Some)
    }

    // RUGRA-GLUE: mirrors the production driver (ghidra_process.cc:310 allacts.getCurrent()->perform(fd)); the former name is kept for the legacy callers
    /// Perform the current root Action (after a per-root reset) on the
    /// given function data.
    pub fn apply_all(&mut self, fd: &mut crate::funcdata::Funcdata) -> crate::error::Result<i32> {
        let index = self.currentact.expect("no current root action");
        self.actionmap[index].1.reset(fd);
        let flags = self.actionmap[index].1.get_flags();
        let mut state = ActionState::new(flags);
        self.actionmap[index].1.perform(fd, &mut state)
    }

    // RUGRA-GLUE: production entry mirroring Architecture::buildAction (architecture.cc:582-591: allacts.universalAction(this); allacts.resetDefaults();)
    /// Set up the default decompiler actions: build the raw universal tree,
    /// then derive the default "decompile" root through `resetDefaults`.
    pub fn set_default_actions(&mut self) {
        self.universal_action();
        self.reset_defaults();
    }
}

// Ghidra: coreaction.cc:5462-5738 ActionDatabase::universalAction
/// Build the universal Action tree containing every component at its exact
/// oracle slot. With `grouplist == None` the raw universal tree is built
/// (every Action registered). With `Some(list)` the construction mirrors
/// the survival semantics of `Action::clone` under `deriveAction`
/// (action.cc:1145-1158): a leaf is registered iff its basegroup is in the
/// list, and a group/pool node is registered iff at least one child
/// survived (ActionGroup::clone action.cc:391-406 / ActionPool::clone
/// action.cc:899-914 / ActionRestartGroup::clone action.cc:529-544).
/// Rule-level clone filtering inside the pools is scoped out: every rule
/// group registered below (deadcode/analysis/nodejoin/subvar/
/// conditionalexe/floatprecision/typerecovery/segment/protorecovery/
/// doubleload/doubleprecis/cleanup/splitcopy/splitpointer/constsequence/
/// stackvars) is a member of the default `decompile` grouplist, so the
/// derived default root is unaffected.
pub fn universal_action(grouplist: Option<&ActionGroupList>) -> Option<ActionRestartGroup> {
    // Ghidra clone survival: a leaf is registered iff its basegroup is in
    // the steering grouplist (action.cc:391-406 / 899-914 / 529-544).
    let keep = |group: &str| grouplist.map(|list| list.contains(group)).unwrap_or(true);
    // RUGRA-GLUE: call-site adapter applying the clone-survival check to
    // each addAction slot, keeping the flat coreaction.cc:5477-5738 shape.
    macro_rules! add {
        ($parent:expr, $group:expr, $action:expr) => {
            if keep($group) {
                $parent.add_action_in_group($action, $group);
            }
        };
    }
    // Root: ActionRestartGroup(Action::rule_onceperfunc,"universal",1) — coreaction.cc:5474
    let mut universal = ActionRestartGroup::new(
        "universal",
        action_flags::RULE_ONCEPERFUNC,
        1,
    );

    // --- Universal head (coreaction.cc:5477-5485) ---
    add!(universal, "base", Box::new(crate::coreaction::ActionStart::new())); // :5477
    add!(universal, "base", Box::new(crate::coreaction::ActionConstbase::new())); // :5478
    add!(universal, "normalanalysis", Box::new(crate::coreaction::ActionNormalizeSetup::new())); // :5479
    add!(universal, "base", Box::new(crate::coreaction::ActionDefaultParams::new())); // :5480
    add!(universal, "base", Box::new(crate::coreaction::ActionExtraPopSetup::new())); // :5482
    add!(universal, "protorecovery", Box::new(crate::coreaction::ActionPrototypeTypes::new())); // :5483
    add!(universal, "protorecovery", Box::new(crate::coreaction::ActionFuncLink::new())); // :5484
    add!(universal, "noproto", Box::new(crate::coreaction::ActionFuncLinkOutOnly::new())); // :5485

    // --- fullloop (coreaction.cc:5487, rule_repeatapply) ---
    let mut fullloop = ActionGroup::with_flags("fullloop", action_flags::RULE_REPEATAPPLY);
    {
        // --- mainloop (coreaction.cc:5489, rule_repeatapply) ---
        let mut mainloop = ActionGroup::with_flags("mainloop", action_flags::RULE_REPEATAPPLY);
        add!(mainloop, "base", Box::new(crate::coreaction::ActionUnreachable::new())); // :5490
        add!(mainloop, "base", Box::new(crate::coreaction::ActionVarnodeProps::new())); // :5491
        add!(mainloop, "base", Box::new(ActionHeritage::new())); // :5492
        add!(mainloop, "protorecovery", Box::new(crate::coreaction::ActionParamDouble::new())); // :5493
        add!(mainloop, "base", Box::new(crate::coreaction::ActionSegmentize::new())); // :5494
        add!(mainloop, "base", Box::new(crate::coreaction::ActionInternalStorage::new())); // :5495
        add!(mainloop, "blockrecovery", Box::new(crate::coreaction::ActionForceGoto::new())); // :5496
        add!(mainloop, "protorecovery_a", Box::new(crate::coreaction::ActionDirectWrite::new())); // :5497 (propagateIndirect=true)
        add!(mainloop, "protorecovery_b", Box::new(crate::coreaction::ActionDirectWrite::new())); // :5498 (propagateIndirect=false; filtered from the decompile root)
        add!(mainloop, "protorecovery", Box::new(crate::coreaction::ActionActiveParam::new())); // :5499
        add!(mainloop, "protorecovery", Box::new(crate::coreaction::ActionReturnRecovery::new())); // :5500
        add!(mainloop, "localrecovery", Box::new(crate::coreaction::ActionRestrictLocal::new())); // :5502
        add!(mainloop, "deadcode", Box::new(ActionDeadCode::new())); // :5503
        add!(mainloop, "dynamic", Box::new(crate::coreaction::ActionDynamicMapping::new())); // :5504
        add!(mainloop, "localrecovery", Box::new(crate::coreaction::ActionRestructureVarnode::new())); // :5505
        add!(mainloop, "base", Box::new(crate::coreaction::ActionSpacebase::new())); // :5506
        add!(mainloop, "analysis", Box::new(crate::coreaction::ActionNonzeroMask::new())); // :5507
        add!(mainloop, "typerecovery", Box::new(crate::coreaction::ActionInferTypes::new())); // :5508

        // --- stackstall (coreaction.cc:5509, rule_repeatapply) ---
        let mut stackstall = ActionGroup::with_flags("stackstall", action_flags::RULE_REPEATAPPLY);
        stackstall.add_action(Box::new(build_oppool1())); // :5511-5650 oppool1
        add!(stackstall, "base", Box::new(crate::coreaction::ActionLaneDivide::new())); // :5652
        add!(stackstall, "analysis", Box::new(crate::coreaction::ActionMultiCse::new())); // :5653
        add!(stackstall, "analysis", Box::new(crate::coreaction::ActionShadowVar::new())); // :5654
        add!(stackstall, "deindirect", Box::new(crate::coreaction::ActionDeindirect::new())); // :5655
        add!(stackstall, "stackptrflow", Box::new(ActionStackPtrFlow::new())); // :5656
        if stackstall.num_actions() > 0 {
            mainloop.add_action(Box::new(stackstall)); // :5657
        }

        add!(mainloop, "deadcontrolflow", Box::new(crate::coreaction::ActionRedundBranch::new())); // :5658
        add!(mainloop, "blockrecovery", Box::new(ActionBlockStructure::new())); // :5659
        add!(mainloop, "typerecovery", Box::new(crate::coreaction::ActionConstantPtr::new())); // :5660
        mainloop.add_action(Box::new(build_oppool2())); // :5662-5671 oppool2
        add!(mainloop, "unreachable", Box::new(crate::coreaction::ActionDeterminedBranch::new())); // :5672
        add!(mainloop, "unreachable", Box::new(crate::coreaction::ActionUnreachable::new())); // :5673
        add!(mainloop, "nodejoin", Box::new(crate::coreaction::ActionNodeJoin::new())); // :5674
        add!(mainloop, "conditionalexe", Box::new(crate::condexe::ActionConditionalExe::new())); // :5675
        add!(mainloop, "analysis", Box::new(crate::coreaction::ActionConditionalConst::new())); // :5676
        if mainloop.num_actions() > 0 {
            fullloop.add_action(Box::new(mainloop)); // :5678
        }

        // --- fullloop tail (coreaction.cc:5679-5688, after mainloop) ---
        add!(fullloop, "protorecovery", Box::new(crate::coreaction::ActionLikelyTrash::new())); // :5679
        add!(fullloop, "protorecovery_a", Box::new(crate::coreaction::ActionDirectWrite::new())); // :5680
        add!(fullloop, "protorecovery_b", Box::new(crate::coreaction::ActionDirectWrite::new())); // :5681 (filtered from the decompile root)
        add!(fullloop, "deadcode", Box::new(ActionDeadCode::new())); // :5682
        add!(fullloop, "deadcontrolflow", Box::new(crate::coreaction::ActionDoNothing::new())); // :5683
        add!(fullloop, "switchnorm", Box::new(crate::coreaction::ActionSwitchNorm::new())); // :5684
        add!(fullloop, "returnsplit", Box::new(crate::coreaction::ActionReturnSplit::new())); // :5685
        add!(fullloop, "protorecovery", Box::new(crate::coreaction::ActionUnjustifiedParams::new())); // :5686
        add!(fullloop, "typerecovery", Box::new(crate::coreaction::ActionStartTypes::new())); // :5687
        add!(fullloop, "protorecovery", Box::new(crate::coreaction::ActionActiveReturn::new())); // :5688
    }
    if fullloop.num_actions() > 0 {
        universal.add_action(Box::new(fullloop)); // :5690
    }

    // --- Post-fullloop top-level (coreaction.cc:5691-5738) ---
    add!(universal, "localrecovery", Box::new(crate::coreaction::ActionMappedLocalSync::new())); // :5691
    add!(universal, "cleanup", Box::new(crate::coreaction::ActionStartCleanUp::new())); // :5692
    universal.add_action(Box::new(build_cleanup_pool())); // :5694-5712 cleanup pool
    add!(universal, "blockrecovery", Box::new(crate::coreaction::ActionPreferComplement::new())); // :5714
    add!(universal, "blockrecovery", Box::new(crate::coreaction::ActionStructureTransform::new())); // :5715
    add!(universal, "normalizebranches", Box::new(ActionNormalizeBranches::new())); // :5716 (filtered from the decompile root — coreaction.cc:5424-5431)
    add!(universal, "merge", Box::new(crate::coreaction::ActionAssignHigh::new())); // :5717
    add!(universal, "merge", Box::new(crate::coreaction::ActionMergeRequired::new())); // :5718
    add!(universal, "merge", Box::new(crate::coreaction::ActionMarkExplicit::new())); // :5719
    add!(universal, "merge", Box::new(crate::coreaction::ActionMarkImplied::new())); // :5720
    add!(universal, "merge", Box::new(crate::coreaction::ActionMergeMultiEntry::new())); // :5721
    add!(universal, "merge", Box::new(crate::coreaction::ActionMergeCopy::new())); // :5722
    add!(universal, "merge", Box::new(crate::coreaction::ActionDominantCopy::new())); // :5723
    add!(universal, "dynamic", Box::new(crate::coreaction::ActionDynamicSymbols::new())); // :5724
    add!(universal, "merge", Box::new(crate::coreaction::ActionMarkIndirectOnly::new())); // :5725
    add!(universal, "merge", Box::new(crate::coreaction::ActionMergeAdjacent::new())); // :5726
    add!(universal, "merge", Box::new(crate::coreaction::ActionMergeType::new())); // :5727
    add!(universal, "merge", Box::new(crate::coreaction::ActionHideShadow::new())); // :5728
    add!(universal, "merge", Box::new(crate::coreaction::ActionCopyMarker::new())); // :5729
    add!(universal, "localrecovery", Box::new(crate::coreaction::ActionOutputPrototype::new())); // :5730
    add!(universal, "fixateproto", Box::new(crate::coreaction::ActionInputPrototype::new())); // :5731
    add!(universal, "fixateglobals", Box::new(crate::coreaction::ActionMapGlobals::new())); // :5732
    add!(universal, "dynamic", Box::new(crate::coreaction::ActionDynamicSymbols::new())); // :5733
    add!(universal, "merge", Box::new(crate::coreaction::ActionNameVars::new())); // :5734
    add!(universal, "casts", Box::new(crate::coreaction::ActionSetCasts::new())); // :5735
    add!(universal, "blockrecovery", Box::new(ActionFinalStructure::new())); // :5736
    add!(universal, "protorecovery", Box::new(crate::coreaction::ActionPrototypeWarnings::new())); // :5737
    add!(universal, "base", Box::new(crate::coreaction::ActionStop::new())); // :5738

    // Ghidra: action.cc:529-544 ActionRestartGroup::clone — a restart group
    // with no surviving children clones to null.
    if universal.num_actions() == 0 {
        return None;
    }
    Some(universal)
}

// RUGRA-GLUE: derived default root — mirrors ActionDatabase::resetDefaults + setCurrent("decompile") for callers that only need the tree
/// Build the derived default "decompile" pipeline root (the tree that
/// `ActionDatabase::set_default_actions` registers as the current root).
pub fn build_default_pipeline() -> ActionRestartGroup {
    universal_action(Some(&ActionGroupList::from_members(default_groups::DECOMPILE)))
        .expect("decompile grouplist keeps the universal head (base group)")
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

    // PIPE-MERGETYPE-ORDER-0001 + PIPE-DERIVED-TREE-0001: the post-cleanup
    // child sequence of the derived default pipeline must mirror the
    // coreaction.cc:5714-5738 slots after decompile-grouplist filtering —
    // ActionNormalizeBranches (:5716, group "normalizebranches") is NOT a
    // member of the decompile grouplist (coreaction.cc:5424-5431) and is
    // dropped by the derive clone, three structural transforms lead
    // (:5714-5715 + assignhigh :5717), a single ActionMergeType late
    // (:5727, after mergeadjacent, before hideshadow).
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
                // "normalizebranches" (:5716) filtered: group not in decompile
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
    // appears only at :5737. The former build_full_pipeline_actions()
    // consumption used to double-register it (stderr 48 = 24×2
    // unknown-convention warnings per E2E run) along with 16 other Actions
    // this builder owns; that vec path is now deleted outright
    // (PIPE-HEAD-FLAT-ACTIONS-0001).
    #[test]
    fn test_prototype_warnings_registered_once() {
        let root = build_default_pipeline();
        let names = root.child_names();
        // coreaction.cc:5737 — exactly one top-level prototypewarnings.
        assert_eq!(names.iter().filter(|n| **n == "prototypewarnings").count(), 1);
        // R2 closeout (unblocked by 533412a; see the SINGLE REGISTRATION
        // comment in build_default_pipeline): outputprototype/inputprototype
        // are sole-registered at their oracle positions — exactly one
        // top-level instance each, never in any pre-fullloop flat run.
        for name in ["outputprototype", "inputprototype"] {
            assert_eq!(
                names.iter().filter(|n| **n == name).count(),
                1,
                "sole registration for {name}"
            );
        }
        assert_eq!(
            names.iter().filter(|n| **n == "setcasts").count(),
            1,
            "setcasts must be sole-registered at the :5735 position"
        );
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

    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④ + PIPE-DERIVED-TREE-0001: the
    // derived decompile head is coreaction.cc:5477-5486 after grouplist
    // filtering — Start, Constbase, [NormalizeSetup filtered — group
    // "normalanalysis" is not in the decompile grouplist], DefaultParams,
    // ExtraPopSetup, PrototypeTypes, FuncLink, [FuncLinkOutOnly filtered —
    // group "noproto" is not in the decompile grouplist], immediately
    // followed by fullloop. The raw universal tree still registers both
    // filtered nodes at their head slots (see universal_action).
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
            "fullloop",          // :5487 group
        ];
        assert!(names.len() >= expected_prefix.len());
        let prefix: Vec<&str> = names[..expected_prefix.len()].to_vec();
        assert_eq!(prefix, expected_prefix.to_vec());
    }

    // PIPE-DERIVED-TREE-0001: the raw universal head keeps both filtered
    // nodes (normalizesetup :5479, funclink_outonly :5485) — derive only
    // drops them for roots whose grouplist lacks their groups.
    #[test]
    fn test_raw_universal_head_keeps_filtered_nodes() {
        let root = universal_action(None).expect("raw universal root");
        let names = root.child_names();
        let expected_prefix = [
            "start",              // :5477
            "constbase",          // :5478
            "normalizesetup",     // :5479 (normalanalysis)
            "defaultparams",      // :5480
            "extrapopsetup",      // :5482
            "prototypetypes",     // :5483
            "funclink",           // :5484
            "funclink_outonly",   // :5485 (noproto)
            "fullloop",           // :5487
        ];
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
