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

/// Rule property flags (action.hh:197-202). Stored in a `Rule`'s `flags` field
/// (mirrored in [`RuleState::flags`] for Rugra's trait-based Rules).
pub mod rule_flags {
    /// Rule is disabled and will be skipped by its pool (action.hh:198).
    pub const TYPE_DISABLE: u32 = 1;
    /// Per-rule debug tracing (action.hh:199).
    pub const RULE_DEBUG: u32 = 2;
    /// A warning is issued when this rule applies (action.hh:200).
    pub const WARNINGS_ON: u32 = 4;
    /// A warning has already been issued for this rule (action.hh:201).
    pub const WARNINGS_GIVEN: u32 = 8;
}

/// The list of basegroup names defining a \e root Action (action.hh:31-40).
///
/// Mirrors Ghidra's `ActionGroupList` -- a `set<string>` of group names. Any
/// leaf Action or Rule is cloned into a derived root Action only if its
/// `basegroup` is `contains()`-ed in this list (action.hh:35-39). Rugra uses a
/// `BTreeSet<String>` (sorted, deterministic) as the idiomatic equivalent.
pub type ActionGroupList = std::collections::BTreeSet<String>;

// ---- Per-name clone registries (Rugra equivalent of Ghidra virtual clone()) ----
//
// Ghidra implements `Action *clone(const ActionGroupList&) const` as a pure
// virtual on each concrete leaf class (action.hh:119, coreaction.hh:37-40
// etc.) -- each leaf knows how to re-construct itself. Rugra's `Box<dyn
// Action>` trait object cannot express a `Self: Clone` bound across the >100
// leaf types defined in other modules (coreaction.rs / blockaction.rs /
// ruleaction.rs / subflow.rs ...), so we cannot add a `clone_box` method
// requiring `Self: Clone` to the trait without editing every leaf. Instead --
// faithful to Ghidra's per-class virtual dispatch -- we centralise the
// per-name constructor in a registry that `set_default_actions()` populates
// (it is the single place that constructs every leaf and so knows each
// `T::new()`). An unregistered leaf name resolves to `None`, which
// `clone_action` treats exactly as Ghidra treats `clone()` returning NULL for
// a leaf whose group is not in the grouplist. Containers
// (ActionGroup/ActionPool/ActionRestartGroup) override `clone_action` to
// recurse, never consulting the registry.

/// Constructor entry for a leaf Action clone (Rugra analogue of Ghidra's
/// per-class `Action::clone`). `group` is the leaf's basegroup (e.g.
/// `"universal"`); `make` rebuilds the leaf in its reset state -- matching
/// Ghidra, whose `clone()` calls `new ConcreteAction(getGroup())`.
pub struct ActionCloneEntry {
    pub group: &'static str,
    pub make: fn() -> Box<dyn Action>,
}

/// Name -> [`ActionCloneEntry`] registry, populated once by
/// [`ActionDatabase::set_default_actions`]. Looked up by the default
/// [`Action::clone_action`] impl for leaf Actions.
pub static ACTION_CLONE_REGISTRY: std::sync::OnceLock<
    std::collections::HashMap<&'static str, ActionCloneEntry>,
> = std::sync::OnceLock::new();

/// Constructor entry for a leaf Rule clone (Rugra analogue of Ghidra's
/// per-class `Rule::clone`, action.hh:236 / ruleaction.hh:89+). Mirrors
/// [`ActionCloneEntry`].
pub struct RuleCloneEntry {
    pub group: &'static str,
    pub make: fn() -> Box<dyn Rule>,
}

/// Name -> [`RuleCloneEntry`] registry, populated once by
/// [`ActionDatabase::set_default_actions`]. Looked up by
/// [`Rule::clone_rule`] for each Rule.
pub static RULE_CLONE_REGISTRY: std::sync::OnceLock<
    std::collections::HashMap<&'static str, RuleCloneEntry>,
> = std::sync::OnceLock::new();

// RUGRA-GLUE: next_specifyterm helper mirrors Ghidra's static
// `next_specifyterm(string&,string&,const string&)` (action.cc:257-269), used
// by ActionGroup/ActionPool path-walking (`getSubAction`/`getSubRule`) to split
// a ':' separated name path into the next token and the remaining suffix.
fn next_specifyterm(specify: &str) -> (String, String) {
    match specify.find(':') {
        Some(idx) => (specify[..idx].to_string(), specify[idx + 1..].to_string()),
        None => (specify.to_string(), String::new()),
    }
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
    /// Reset the action state for a new function. Faithful to
    /// `Action::reset` (action.cc:100-105). Default: clear status/count.
    fn reset(&mut self, _fd: &mut Funcdata) {}

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the rule flags (repeatapply / onceperfunc / etc). Default: 0
    /// (single-pass). Containers override to return their group's flags.
    fn get_flags(&self) -> u32 { 0 }

    // Ghidra: action.hh:108 Action::getGroup
    /// Return the \e basegroup this Action belongs to (action.hh:108-109).
    ///
    /// Leaf Actions report the group they were constructed under (e.g.
    /// `"universal"`); container Actions (groups/pools) have no single group
    /// and return `None`, so group-membership filtering for them happens via
    /// the recursive `clone_action` walk (each child filters itself).
    /// Default `None` (matching Ghidra's empty-string `basegroup` for groups).
    fn get_group(&self) -> Option<&str> { None }

    // Ghidra: action.hh:119 Action::clone (virtual, pure)
    /// Clone  this Action if it (or, for containers, any descendant) belongs
    /// to one of the groups in `grouplist`. Faithful to
    /// `Action::clone(const ActionGroupList &)` (action.hh:113-119).
    ///
    /// Returns `Some(boxed_clone)` if a descendant should participate in the
    /// derived root Action, or `None` if not (Ghidra returns NULL). The default
    /// leaf impl resolves this leaf's constructor by name from
    /// [`ACTION_CLONE_REGISTRY`] and applies the group-membership filter
    /// (action.hh:35-39, coreaction.cc:37-40 `grouplist.contains(getGroup())`);
    /// a leaf whose name is not registered returns `None`, excluding it from
    /// the derived tree -- identical to Ghidra returning NULL. Container
    /// Actions override this to recurse over their children.
    fn clone_action(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        let name = self.get_name();
        let entry = ACTION_CLONE_REGISTRY
            .get()
            .and_then(|m| m.get(name))?;
        if !grouplist.contains(entry.group) {
            return None;
        }
        Some((entry.make)())
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Deep-clone  this Action and ALL descendants unconditionally (no
    /// group-membership filter). Rugra-specific: Ghidra never needs this
    /// because it builds the universal model once and derives filtered clones;
    /// Rugra needs an identical copy of the model to register the same tree
    /// under multiple names. The default leaf impl delegates to
    /// [`Self::clone_action`] with a grouplist containing `"universal"` (the
    /// only group Rugra leaves carry), so every registered leaf is included.
    /// Containers override this to recurse without filtering.
    fn clone_all(&self) -> Option<Box<dyn Action>> {
        let mut gl = ActionGroupList::new();
        gl.insert("universal".to_string());
        self.clone_action(&gl)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// The perform state machine. Faithful to `Action::perform`
    /// (action.cc:298-362). Drives repeatapply / onceperfunc semantics by
    /// looping apply() until no change (or once for onceperfunc), and honours
    /// the start/action breakpoints set via [`Action::set_break_point`].
    fn perform(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        // Faithful to Action::perform (action.cc:298-362). The C switch uses
        // fall-through; we model the same transitions explicitly. `count` is
        // cleared ONCE at the start (status_start case), and count_tests is
        // incremented ONCE per perform() call — NOT once per loop iteration.
        // The original Rugra code reset count=0 inside the loop, discarding the
        // accumulated count from prior iterations and breaking repeatapply
        // convergence.
        if state.status == status_flags::STATUS_START {
            // action.cc:306 `count = 0`.
            state.count = 0;
            // action.cc:307-310 — start breakpoint: halt before doing any work.
            // On the next perform() call status is BREAKSTARTHIT, so we fall
            // through to the apply loop without re-checking (Ghidra does NOT
            // re-check on resume).
            if state.check_start_break() {
                state.status = status_flags::STATUS_BREAKSTARTHIT;
                return Ok(-1); // Partial completion (start breakpoint hit)
            }
            // action.cc:311 `count_tests += 1` — only counted when we actually
            // begin work (past the start-break check).
            state.count_tests += 1;
        }
        // Faithful to Action::perform (action.cc:298-362): an UNBOUNDED
        // do-while that repeats only while this iteration made a change
        // (lcount < count) AND repeatapply is set. The previous Rugra code
        // hard-capped this to 1 iteration (`if iterations > 1 { break; }`),
        // which silently disabled repeatapply convergence — so multi-round
        // simplifications (e.g. fold `V^V→0` then propagate the `0` into a
        // RETURN) never converged, leaking `return iVar1 ^ iVar1` into output.
        // Per AGENTS.md §5, prior Rule-pool *cycles* were fixed by phase
        // separation (actcleanup), NOT by this iteration cap; the cap was
        // masking the real fix. Removed to match Ghidra (audit R73).
        loop {
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
            // action.cc:327-333 — if this iteration made a change, count it and
            // honour an action breakpoint. `lcount < count` is Ghidra's change
            // predicate (equivalent to `res > 0` here).
            if state.lcount < state.count {
                state.count_apply += 1;
                if state.check_action_break() {
                    // action.cc:331-333 — halt with actionbreak status; a
                    // subsequent perform() resumes the repeatapply loop.
                    state.status = status_flags::STATUS_ACTIONBREAK;
                    return Ok(-1);
                }
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

    // ---- Breakpoint & rule management (action.hh:103-107, action.cc:171-251) ----
    //
    // Rugra carries Ghidra's per-Action `breakpoint` field in the external
    // [`ActionState`], so these methods take a `&mut ActionState` argument
    // (where Ghidra mutates the in-object field directly). Leaf Actions use the
    // default implementations; container Actions (ActionGroup / ActionPool /
    // ActionRestartGroup) override to recurse by name path.

    // Ghidra: action.cc:171 Action::setBreakPoint
    /// Place a breakpoint of type `tp` on the Action/Rule named `specify`
    /// (a ':' separated path, relative to `this`). Returns `true` if a target
    /// matched. The base implementation only matches `this` Action's own name.
    fn set_break_point(
        &mut self,
        state: &mut ActionState,
        tp: u32,
        specify: &str,
    ) -> bool {
        if self.get_name() == specify {
            state.breakpoint |= tp;
            return true;
        }
        false
    }

    // Ghidra: action.hh:104 Action::clearBreakPoints (virtual, base form at action.cc:187)
    /// Clear all breakpoints on `this` Action. Base form just zeros `state`'s
    /// breakpoint field; containers recurse into their children first.
    fn clear_break_points(&mut self, state: &mut ActionState) {
        state.clear_break_points();
    }

    // Ghidra: action.cc:226 Action::disableRule
    /// Disable the Rule named `specify` (a ':' separated path) within `this`
    /// Action. Returns `true` if a matching Rule was found and disabled. Base
    /// Action holds no Rules, so this returns `false` unless overridden by a
    /// container (ActionGroup / ActionPool).
    fn disable_rule(&mut self, _specify: &str) -> bool { false }

    // Ghidra: action.cc:242 Action::enableRule
    /// Enable the Rule named `specify` (a ':' separated path) within `this`
    /// Action. Returns `true` if a matching Rule was found and re-enabled.
    fn enable_rule(&mut self, _specify: &str) -> bool { false }
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
    /// Breakpoint properties (action.hh:83 `uint4 breakpoint`). Set via
    /// [`Action::set_break_point`] and consulted by [`Self::check_start_break`]
    /// / [`Self::check_action_break`] inside the `perform()` state machine.
    pub breakpoint: u32,
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
            breakpoint: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Resolve effective flags.
    pub fn get_flags_val(&self) -> u32 {
        self.flags
    }

    // Ghidra: action.cc:52 Action::checkStartBreak
    /// Check if there was an active \e start breakpoint on this action.
    /// Clears a temporary start breakpoint (`tmpbreak_start`) if present,
    /// matching Ghidra's one-shot semantics. Returns `true` if the breakpoint
    /// was active (caller should return -1 for partial completion).
    pub fn check_start_break(&mut self) -> bool {
        if (self.breakpoint & (break_flags::BREAK_START | break_flags::TMPBREAK_START)) != 0 {
            // Ghidra: action.cc:56 `breakpoint &= ~(tmpbreak_start)` — clear
            // the temporary breakpoint after it fires.
            self.breakpoint &= !break_flags::TMPBREAK_START;
            true
        } else {
            false
        }
    }

    // Ghidra: action.cc:117 Action::checkActionBreak
    /// Check if there was an active \e action breakpoint on this action.
    /// Clears a temporary action breakpoint (`tmpbreak_action`) if present.
    /// Returns `true` if the breakpoint was active.
    pub fn check_action_break(&mut self) -> bool {
        if (self.breakpoint & (break_flags::BREAK_ACTION | break_flags::TMPBREAK_ACTION)) != 0 {
            // Ghidra: action.cc:121 `breakpoint &= ~(tmpbreak_action)`.
            self.breakpoint &= !break_flags::TMPBREAK_ACTION;
            true
        } else {
            false
        }
    }

    // Ghidra: action.cc:187 Action::clearBreakPoints (base)
    /// Clear all breakpoints set on this Action. Base Action form; container
    /// Actions override to recurse into their children first.
    pub fn clear_break_points(&mut self) {
        self.breakpoint = 0;
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

    // Ghidra: action.hh:216 Rule::getGroup
    /// Return the \e basegroup this Rule belongs to (action.hh:216). Rugra
    /// Rules are stateless traits with no in-object field, so the group is
    /// recovered from the per-name [`RULE_CLONE_REGISTRY`] via `clone_rule`.
    /// Default `None`; ActionPool overrides `clone_action` to consult the
    /// registry rather than calling this.
    fn get_group(&self) -> Option<&str> { None }

    // Ghidra: action.hh:236 Rule::clone (virtual, pure)
    /// Clone  this Rule if it belongs to one of the groups in `grouplist`.
    /// Faithful to `Rule::clone(const ActionGroupList&)` (action.hh:230-236,
    /// ruleaction.hh:89+). Rugra resolves the leaf constructor from
    /// [`RULE_CLONE_REGISTRY`] by name; an unregistered name returns `None`
    /// (Ghidra returns NULL). The group-membership filter
    /// (`grouplist.contains(getGroup())`) is applied here (ruleaction.hh:90).
    fn clone_rule(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Rule>> {
        // Ghidra: ruleaction.hh:89-92
        //   if (!grouplist.contains(getGroup())) return (Rule *)0;
        //   return new ConcreteRule(getGroup());
        let name = self.get_name();
        let entry = RULE_CLONE_REGISTRY
            .get()
            .and_then(|m| m.get(name))?;
        if !grouplist.contains(entry.group) {
            return None;
        }
        Some((entry.make)())
    }
}

/// Per-Rule state mirroring Ghidra's `Rule` member fields (action.hh:205-210):
/// `flags` (disable/warnings/debug) and `breakpoint`. Rugra Rules are stateless
/// traits, so this state is owned by the containing [`ActionPool`] (one entry
/// per Rule, parallel to `rules`), exactly mirroring how Ghidra's
/// `Rule::flags`/`Rule::breakpoint` are in-object fields mutated by
/// `Action::disableRule`/`Action::setBreakPoint` via `setDisable`/`setBreak`.
#[derive(Debug, Clone)]
pub struct RuleState {
    /// Rule property flags ([`rule_flags`]). Tracks disabled/warnings/debug.
    pub flags: u32,
    /// Breakpoint toggles ([`break_flags`]) set on this Rule.
    pub breakpoint: u32,
}

impl RuleState {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new() -> Self {
        Self { flags: 0, breakpoint: 0 }
    }

    // Ghidra: action.hh:219 Rule::setBreak
    /// Set a breakpoint on this Rule (`breakpoint |= tp`).
    pub fn set_break(&mut self, tp: u32) { self.breakpoint |= tp; }

    // Ghidra: action.hh:220 Rule::clearBreak
    /// Clear a specific breakpoint on this Rule (`breakpoint &= ~tp`).
    pub fn clear_break(&mut self, tp: u32) { self.breakpoint &= !tp; }

    // Ghidra: action.hh:221 Rule::clearBreakPoints
    /// Clear all breakpoints on this Rule (`breakpoint = 0`).
    pub fn clear_break_points(&mut self) { self.breakpoint = 0; }

    // Ghidra: action.hh:225 Rule::setDisable
    /// Disable this Rule within its pool (`flags |= type_disable`).
    pub fn set_disable(&mut self) { self.flags |= rule_flags::TYPE_DISABLE; }

    // Ghidra: action.hh:226 Rule::clearDisable
    /// Re-enable this Rule within its pool (`flags &= ~type_disable`).
    pub fn clear_disable(&mut self) { self.flags &= !rule_flags::TYPE_DISABLE; }

    // Ghidra: action.hh:224 Rule::isDisabled
    /// Return `true` if this Rule is disabled.
    pub fn is_disabled(&self) -> bool { (self.flags & rule_flags::TYPE_DISABLE) != 0 }

    // Ghidra: action.hh:228 Rule::getBreakPoint
    /// Return the breakpoint toggles.
    pub fn get_breakpoint(&self) -> u32 { self.breakpoint }

    // Ghidra: action.cc:719 Rule::checkActionBreak
    /// Check if an action breakpoint is active on this Rule, clearing a
    /// temporary action breakpoint (`tmpbreak_action`) if so. Returns `true`
    /// if the breakpoint fired (caller halts).
    pub fn check_action_break(&mut self) -> bool {
        if (self.breakpoint & (break_flags::BREAK_ACTION | break_flags::TMPBREAK_ACTION)) != 0 {
            self.breakpoint &= !break_flags::TMPBREAK_ACTION;
            true
        } else {
            false
        }
    }
}

impl Default for RuleState {
    fn default() -> Self { Self::new() }
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
}

impl Action for ActionGroup {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 { self.flags }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Override perform for ActionGroup to be **iterative** (not recursive).
    /// The default perform would call self.apply() in a loop, which calls
    /// child.perform() for repeatapply children — creating deep recursion.
    /// Instead, we inline the repeatapply loop here: call self.apply() (which
    /// calls child.apply/perform), and repeat if the group has repeatapply.
    /// This keeps the stack depth O(1) per repeatapply iteration.
    ///
    /// Faithful to Ghidra ActionGroup (which inherits the base `perform`
    /// do-while at action.cc:298-362): UNBOUNDED, terminating only when a
    /// pass makes no change (lcount >= count) or repeatapply is unset. The
    /// previous `iterations > 2` cap disabled group-level convergence
    /// (audit R73) and is removed; the `lcount >= count` guard prevents
    /// infinite loops for correctly-reporting Rules.
    fn perform(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        state.count = 0;
        state.count_tests += 1;
        loop {
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn reset(&mut self, fd: &mut Funcdata) {
        self.state = 0;
        for i in 0..self.actions.len() {
            self.child_states[i].status = status_flags::STATUS_START;
            self.actions[i].reset(fd);
        }
    }

    // Ghidra: action.cc:391 ActionGroup::clone
    /// Clone  this group by recursively cloning each child Action and keeping
    /// only those that clone (i.e. belong to a group in `grouplist`). Faithful
    /// to `ActionGroup::clone` (action.cc:391-406): a fresh `ActionGroup` is
    /// allocated lazily -- only once at least one child clones -- and each
    /// successful child is appended in order. If no child clones, returns
    /// `None` (Ghidra returns NULL). The group's own `flags` and `name` are
    /// preserved on the clone (action.cc:401 `new ActionGroup(flags,getName())`).
    fn clone_action(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        let mut res: Option<ActionGroup> = None;
        for child in &self.actions {
            if let Some(ac) = child.clone_action(grouplist) {
                let group = res.get_or_insert_with(|| {
                    ActionGroup::with_flags(&self.name, self.flags)
                });
                group.add_action(ac);
            }
        }
        res.map(|g| Box::new(g) as Box<dyn Action>)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Deep-clone this group with ALL children (no group filter). See
    /// [`Action::clone_all`].
    fn clone_all(&self) -> Option<Box<dyn Action>> {
        let mut res = ActionGroup::with_flags(&self.name, self.flags);
        let mut any = false;
        for child in &self.actions {
            if let Some(ac) = child.clone_all() {
                res.add_action(ac);
                any = true;
            }
        }
        if any { Some(Box::new(res)) } else { None }
    }

    // ---- Breakpoint / rule-management overrides (action.cc:382-504, 171-251) ----
    //
    // These faithfully mirror Ghidra's ActionGroup overrides, which walk the
    // child list and dispatch by name path (`':'` separated). Rugra passes the
    // matching child's `&mut ActionState` (from `child_states`) into the child
    // call, since state is external.

    // Ghidra: action.cc:382 ActionGroup::clearBreakPoints
    /// Recursively clear breakpoints on every child Action, then on `this`.
    fn clear_break_points(&mut self, state: &mut ActionState) {
        for i in 0..self.actions.len() {
            self.actions[i].clear_break_points(&mut self.child_states[i]);
        }
        state.clear_break_points();
    }

    // Ghidra: action.cc:171 Action::setBreakPoint + action.cc:456 ActionGroup::getSubAction
    //         + action.cc:481 ActionGroup::getSubRule
    /// Set a breakpoint by walking the ':' separated name path. First tries to
    /// match a sub-Action (via `getSubAction`-style descent); if no Action
    /// matches, tries a sub-Rule. Faithful to Ghidra: the path is split at the
    /// first ':'; if the leading token equals this group's name, the remainder
    /// is matched against children, otherwise the whole `specify` is matched.
    /// More than one match resolves to no match (ambiguous).
    fn set_break_point(
        &mut self,
        state: &mut ActionState,
        tp: u32,
        specify: &str,
    ) -> bool {
        // Fast path: exact name match (leaf-style) — set on this group's state.
        if self.name == specify {
            state.breakpoint |= tp;
            return true;
        }
        // Path descent (action.cc:456-479 getSubAction).
        let (token, remain) = next_specifyterm(specify);
        let effective = if self.name == token {
            // Leading token matched this group: walk children with the suffix.
            // If the suffix is empty, this is the group itself (handled above).
            &remain[..]
        } else {
            // Leading token did not match: children must still match the whole
            // `specify` (Ghidra: `remain = specify`).
            specify
        };
        let mut matched = false;
        for i in 0..self.actions.len() {
            if self.actions[i].set_break_point(&mut self.child_states[i], tp, effective) {
                // Ghidra returns immediately on the first match (getSubAction
                // collects all matches and bails if >1, but setBreakPoint calls
                // getSubAction which already collapses to one). We stop on the
                // first hit to match the single-target semantics.
                matched = true;
                break;
            }
        }
        matched
    }

    // Ghidra: action.cc:226 Action::disableRule + action.cc:481 ActionGroup::getSubRule
    /// Disable a Rule by name path within `this` group. Walks children; the
    /// first child whose `disable_rule` accepts the (possibly suffixed) name
    /// wins. ActionPool children match against their Rule list.
    fn disable_rule(&mut self, specify: &str) -> bool {
        let (token, remain) = next_specifyterm(specify);
        let effective = if self.name == token { &remain[..] } else { specify };
        for a in &mut self.actions {
            if a.disable_rule(effective) {
                return true;
            }
        }
        false
    }

    // Ghidra: action.cc:242 Action::enableRule + action.cc:481 ActionGroup::getSubRule
    /// Enable a Rule by name path within `this` group (mirror of disable_rule).
    fn enable_rule(&mut self, specify: &str) -> bool {
        let (token, remain) = next_specifyterm(specify);
        let effective = if self.name == token { &remain[..] } else { specify };
        for a in &mut self.actions {
            if a.enable_rule(effective) {
                return true;
            }
        }
        false
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
    /// Breakpoint/state slot for the inner `group` (action.hh:83 `breakpoint`).
    /// ActionRestartGroup delegates `set_break_point`/`clear_break_points` to
    /// its inner ActionGroup via this state, matching Ghidra's inheritance
    /// (ActionRestartGroup IS-A ActionGroup, so the breakpoint field is shared).
    group_state: ActionState,
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
            group_state: ActionState::new(flags),
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn add_action(&mut self, action: Box<dyn Action>) {
        self.group.add_action(action);
    }
}

impl Action for ActionRestartGroup {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str {
        &self.name
    }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 {
        self.flags
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn reset(&mut self, fd: &mut Funcdata) {
        self.curstart = 0;
        self.group.reset(fd);
    }

    // Ghidra: action.cc:530 ActionRestartGroup::clone
    /// Clone  this restart group. Faithful to
    /// `ActionRestartGroup::clone` (action.cc:530-545): identical to
    /// `ActionGroup::clone` except the lazily-allocated container is an
    /// `ActionRestartGroup` (preserving `maxrestarts`), and children are cloned
    /// via the inner group's recursive walk. Returns `None` if no child clones
    /// (Ghidra returns NULL).
    fn clone_action(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        let mut res: Option<ActionRestartGroup> = None;
        for child in &self.group.actions {
            if let Some(ac) = child.clone_action(grouplist) {
                let rg = res.get_or_insert_with(|| {
                    ActionRestartGroup::new(&self.name, self.flags, self.maxrestarts)
                });
                rg.add_action(ac);
            }
        }
        res.map(|rg| Box::new(rg) as Box<dyn Action>)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Deep-clone this restart group with ALL children (no group filter). See
    /// [`Action::clone_all`].
    fn clone_all(&self) -> Option<Box<dyn Action>> {
        let mut res = ActionRestartGroup::new(&self.name, self.flags, self.maxrestarts);
        let mut any = false;
        for child in &self.group.actions {
            if let Some(ac) = child.clone_all() {
                res.add_action(ac);
                any = true;
            }
        }
        if any { Some(Box::new(res)) } else { None }
    }

    // ---- Breakpoint / rule-management delegates ----
    //
    // Ghidra's ActionRestartGroup inherits ActionGroup's implementations
    // verbatim (it adds no overrides). Rugra wraps the ActionGroup, so we
    // forward to it via `group_state`.

    // Ghidra: inherited ActionGroup::clearBreakPoints (action.cc:382)
    fn clear_break_points(&mut self, state: &mut ActionState) {
        self.group.clear_break_points(&mut self.group_state);
        state.clear_break_points();
    }

    // Ghidra: inherited ActionGroup's setBreakPoint path (action.cc:171 + 456)
    fn set_break_point(
        &mut self,
        state: &mut ActionState,
        tp: u32,
        specify: &str,
    ) -> bool {
        // ActionRestartGroup's own name is `self.name`; the inner group shares
        // that name, so try the inner group first, then fall back to this
        // restart-group's own breakpoint slot.
        if self.group.set_break_point(&mut self.group_state, tp, specify) {
            return true;
        }
        if self.name == specify {
            state.breakpoint |= tp;
            return true;
        }
        false
    }

    // Ghidra: inherited ActionGroup::disableRule (action.cc:226, walks children)
    fn disable_rule(&mut self, specify: &str) -> bool {
        self.group.disable_rule(specify)
    }

    // Ghidra: inherited ActionGroup::enableRule (action.cc:242, walks children)
    fn enable_rule(&mut self, specify: &str) -> bool {
        self.group.enable_rule(specify)
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
    /// Per-Rule disable/breakpoint state (action.hh:205-210). Parallel to
    /// `rules`; mirrors Ghidra's in-object `Rule::flags`/`Rule::breakpoint`,
    /// mutated by `disable_rule`/`set_break_point`/`clear_break_points`.
    rule_states: Vec<RuleState>,
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
            rule_states: Vec::new(),
            per_op: std::collections::HashMap::new(),
            flags: action_flags::RULE_REPEATAPPLY,
            rule_hits: std::collections::HashMap::new(),
            total: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Construct with explicit rule flags and name. Mirrors Ghidra's
    /// `ActionPool(uint4 f, const string &nm)` (action.hh:269), which lets the
    /// `flags` (notably `rule_repeatapply`) be caller-supplied -- used by
    /// `ActionPool::clone` (action.cc:910) to preserve the source pool's flags
    /// rather than hard-coding RULE_REPEATAPPLY.
    pub fn with_flags_named(name: &str, flags: u32) -> Self {
        Self {
            name: name.to_string(),
            rules: Vec::new(),
            rule_states: Vec::new(),
            per_op: std::collections::HashMap::new(),
            flags,
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
        self.rule_states.push(RuleState::new());
        for opc in opcodes {
            self.per_op.entry(opc).or_default().push(idx);
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Borrow the per-Rule state slice (for diagnostics / external inspection).
    pub fn rule_states(&self) -> &[RuleState] { &self.rule_states }
}

impl Action for ActionPool {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Single-pass Rule application. Faithful to `ActionPool::apply`
    /// (action.cc:878-889) + `processOp` (action.cc:823-876). The parent
    /// `perform()` repeats this until no change (via rule_repeatapply). Honours
    /// per-Rule disable flags (action.cc:839) and per-Rule action breakpoints
    /// (action.cc:852): a fired breakpoint returns -1 (partial completion).
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
                    // action.cc:839 `if (rl->isDisabled()) continue;` — skip
                    // Rules disabled via `disable_rule`/`Action::disableRule`.
                    if self.rule_states[ridx].is_disabled() { continue; }
                    // Re-check dead after each rule.
                    if op_ref.0.read().unwrap().is_dead() { break; }
                    let res = self.rules[ridx].apply_op(&op_ref.0, fd)?;
                    if res > 0 {
                        pass_changes += res;
                        applied_any = true;
                        if want_stats {
                            *self.rule_hits.entry(ridx).or_insert(0) += res;
                        }
                        // action.cc:852 `if (rl->checkActionBreak()) return -1;`
                        // — a Rule-level action breakpoint halts this pass.
                        if self.rule_states[ridx].check_action_break() {
                            self.total += pass_changes;
                            return Ok(-1);
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

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 { self.flags }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn reset(&mut self, _fd: &mut Funcdata) {
        self.total = 0;
        self.rule_hits.clear();
    }

    // Ghidra: action.cc:900 ActionPool::clone
    /// Clone  this pool by recursively cloning each Rule and keeping only
    /// those whose group is in `grouplist`. Faithful to
    /// `ActionPool::clone` (action.cc:900-915): a fresh `ActionPool` is
    /// allocated lazily -- only once at least one Rule clones -- and each
    /// successful Rule is added in order. If no Rule clones, returns `None`
    /// (Ghidra returns NULL). The pool's own `flags` and `name` are preserved
    /// (action.cc:910 `new ActionPool(flags,getName())`); `add_rule` rebuilds
    /// the `per_op` opcode->Rule index on the clone.
    fn clone_action(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        let mut res: Option<ActionPool> = None;
        for rule in &self.rules {
            if let Some(rl) = rule.clone_rule(grouplist) {
                let pool = res.get_or_insert_with(|| {
                    ActionPool::with_flags_named(&self.name, self.flags)
                });
                pool.add_rule(rl);
            }
        }
        res.map(|p| Box::new(p) as Box<dyn Action>)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Deep-clone this pool with ALL rules (no group filter). See
    /// [`Action::clone_all`].
    fn clone_all(&self) -> Option<Box<dyn Action>> {
        let mut res = ActionPool::with_flags_named(&self.name, self.flags);
        let mut any = false;
        for rule in &self.rules {
            // Deep clone a rule: consult registry unconditionally.
            let name = rule.get_name();
            if let Some(entry) = RULE_CLONE_REGISTRY.get().and_then(|m| m.get(name)) {
                res.add_rule((entry.make)());
                any = true;
            }
        }
        if any { Some(Box::new(res)) } else { None }
    }

    // ---- Breakpoint / rule-management overrides (action.cc:790-813, 891-898) ----

    // Ghidra: action.cc:891 ActionPool::clearBreakPoints
    /// Clear breakpoints on every Rule, then on this pool's own state.
    fn clear_break_points(&mut self, state: &mut ActionState) {
        for rs in &mut self.rule_states {
            rs.clear_break_points();
        }
        state.clear_break_points();
    }

    // Ghidra: action.cc:171 Action::setBreakPoint + action.cc:790 ActionPool::getSubRule
    /// Set a breakpoint. If `specify` matches this pool's name it is applied to
    /// the pool's own state; otherwise the name (or ':' path suffix) is matched
    /// against the Rule list. More than one Rule matching resolves to no match
    /// (ambiguous), faithful to Ghidra's getSubRule matchcount guard.
    fn set_break_point(
        &mut self,
        state: &mut ActionState,
        tp: u32,
        specify: &str,
    ) -> bool {
        if self.name == specify {
            state.breakpoint |= tp;
            return true;
        }
        // action.cc:790-813 getSubRule: split path; if leading token is this
        // pool's name, match the remainder against Rule names.
        let (token, remain) = next_specifyterm(specify);
        let target = if self.name == token { &remain[..] } else { specify };
        let mut match_idx: Option<usize> = None;
        let mut matchcount = 0;
        for (i, r) in self.rules.iter().enumerate() {
            if r.get_name() == target {
                match_idx = Some(i);
                matchcount += 1;
                if matchcount > 1 {
                    return false; // Ambiguous — Ghidra returns NULL.
                }
            }
        }
        if let Some(i) = match_idx {
            self.rule_states[i].set_break(tp);
            return true;
        }
        false
    }

    // Ghidra: action.cc:226 Action::disableRule (dispatches to getSubRule → setDisable)
    /// Disable the Rule named `specify` within this pool. Name-path aware.
    fn disable_rule(&mut self, specify: &str) -> bool {
        let (token, remain) = next_specifyterm(specify);
        let target = if self.name == token { &remain[..] } else { specify };
        let mut match_idx: Option<usize> = None;
        let mut matchcount = 0;
        for (i, r) in self.rules.iter().enumerate() {
            if r.get_name() == target {
                match_idx = Some(i);
                matchcount += 1;
                if matchcount > 1 { return false; }
            }
        }
        if let Some(i) = match_idx {
            self.rule_states[i].set_disable();
            return true;
        }
        false
    }

    // Ghidra: action.cc:242 Action::enableRule (dispatches to getSubRule → clearDisable)
    /// Enable the Rule named `specify` within this pool. Name-path aware.
    fn enable_rule(&mut self, specify: &str) -> bool {
        let (token, remain) = next_specifyterm(specify);
        let target = if self.name == token { &remain[..] } else { specify };
        let mut match_idx: Option<usize> = None;
        let mut matchcount = 0;
        for (i, r) in self.rules.iter().enumerate() {
            if r.get_name() == target {
                match_idx = Some(i);
                matchcount += 1;
                if matchcount > 1 { return false; }
            }
        }
        if let Some(i) = match_idx {
            self.rule_states[i].clear_disable();
            return true;
        }
        false
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
// Ghidra: action.cc:975 ActionDatabase::universalname
/// The name of the \e universal root Action (action.cc:975
/// `const char ActionDatabase::universalname[] = "universal"`). The universal
/// Action is the model from which all other root Actions are derived via
/// `deriveAction` (action.cc:1146) / `toggleAction` (action.cc:1037).
pub const UNIVERSAL_ACTION_NAME: &str = "universal";

pub struct ActionDatabase {
    all_actions: Vec<Box<dyn Action>>,
    current_group: Option<String>,
    /// Map from \e root Action name to the set of group names it includes
    /// (action.hh:301 `map<string,ActionGroupList> groupmap`). Populated by
    /// [`Self::set_group`] / `set_default_groups`, consulted by future
    /// `deriveAction`/`toggleAction` clones.
    groupmap: std::collections::HashMap<String, std::collections::BTreeSet<String>>,
    /// `true` while only the built-in default groups are configured
    /// (action.hh:303 `bool isDefaultGroups`).
    is_default_groups: bool,
    /// Map from \e root Action name to the instantiated root Action object
    /// (action.hh:302 `map<string,Action *> actionmap`). The universal Action
    /// is stored under [`UNIVERSAL_ACTION_NAME`]; every other root Action is
    /// derived from it via [`Self::derive_action`] / [`Self::toggle_action`]
    /// and registered here. The database owns these objects.
    actionmap: std::collections::HashMap<String, Box<dyn Action>>,
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
            groupmap: std::collections::HashMap::new(),
            is_default_groups: false,
            actionmap: std::collections::HashMap::new(),
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Register a top-level (root) Action. The Action is owned by
    /// `all_actions` (so [`Self::apply_all`] runs it) and is findable by name
    /// via the linear scan in [`Self::get_action`]. The dedicated
    /// [`Self::register_action_named`] indexes a derived root into `actionmap`
    /// (action.hh:302) for clone/derive operations; this public API is for the
    /// model (universal) Action built directly by `set_default_actions`.
    pub fn register_action(&mut self, action: Box<dyn Action>) {
        self.all_actions.push(action);
    }

    // Ghidra: action.cc:1127 ActionDatabase::registerAction
    /// Internal: associate a \e root Action name with its Action object, taking
    /// ownership (action.cc:1127-1139). If `nm` is already registered, the old
    /// object is replaced (Ghidra `delete`s it). Used by [`Self::derive_action`]
    /// and [`Self::toggle_action`] to store a freshly-cloned root Action.
    fn register_action_named(&mut self, nm: &str, act: Box<dyn Action>) {
        self.actionmap.insert(nm.to_string(), act);
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

    // Ghidra: action.cc:1113 ActionDatabase::getAction
    /// Look up a \e root Action by name from `actionmap` (action.cc:1113-1121).
    /// Returns `None` if `nm` is not a registered root Action. Prefer this over
    /// [`Self::get_action`] for clone/derive operations, which consult
    /// `actionmap` (Ghidra's canonical store), not `all_actions`.
    pub fn get_action_by_name(&self, nm: &str) -> Option<&dyn Action> {
        self.actionmap.get(nm).map(|a| a.as_ref())
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
        universal.add_action(Box::new(crate::coreaction::ActionConstbase::new())); // :5478 — stub (NO_CHANGE), safe
        universal.add_action(Box::new(crate::coreaction::ActionFuncLink::new()));
        // Wire in additional implemented Actions from coreaction (Ghidra
        // coreaction.cc:5479-5485: NormalizeSetup/DefaultParams/PrototypeTypes/
        // FuncLinkOutOnly).
        for extra in crate::coreaction::build_full_pipeline_actions() {
            universal.add_action(extra);
        }
        universal.add_action(Box::new(crate::coreaction::ActionExtraPopSetup::new())); // :5482

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
        mainloop.add_action(Box::new(ActionHeritage::new()));
        mainloop.add_action(Box::new(crate::coreaction::ActionSpacebase::new()));
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
        // mainloop.add_action(Box::new(crate::coreaction::ActionNodeJoin::new())); // :5674 — stub, defer
        mainloop.add_action(Box::new(crate::coreaction::ActionConditionalConst::new())); // :5676 — stub, safe

        fullloop.add_action(Box::new(mainloop));
        // fullloop post-mainloop Actions (coreaction.cc:5679-5688) — registered
        // but some may need maturity before enabling.
        fullloop.add_action(Box::new(crate::coreaction::ActionLikelyTrash::new())); // :5679
        fullloop.add_action(Box::new(crate::coreaction::ActionDoNothing::new())); // :5683
        // fullloop.add_action(Box::new(crate::coreaction::ActionReturnSplit::new())); // :5685 — stub, defer
        fullloop.add_action(Box::new(ActionDeadCode::new())); // :5687

        universal.add_action(Box::new(fullloop));

        // --- Post-fullloop top-level (coreaction.cc:5691-5738) ---
        universal.add_action(Box::new(crate::coreaction::ActionMappedLocalSync::new())); // :5691 — stub, safe
        universal.add_action(Box::new(crate::coreaction::ActionStartCleanUp::new())); // :5692 — stub, safe
        // Cleanup pool (coreaction.cc:5694, repeatapply)
        universal.add_action(Box::new(build_cleanup_pool()));
        // Merge stage (coreaction.cc:5717-5729). Rugra collapses 9 steps into
        // Merge::merge_all (see ActionMergeType). ActionAssignHigh (:5717) is
        // already registered in build_full_pipeline_actions (line ~7084), runs
        // before the merge actions, assigning HighVariables to all Varnodes.
        universal.add_action(Box::new(ActionMergeType::new()));
        universal.add_action(Box::new(ActionNormalizeBranches::new()));
        // Post-normalize structure Actions (coreaction.cc:5714-5715, 5724-5733)
        // — disabled: cause regression. Need implementation maturity before enabling.
        universal.add_action(Box::new(crate::coreaction::ActionPreferComplement::new())); // :5714 — stub, safe
        universal.add_action(Box::new(crate::coreaction::ActionStructureTransform::new())); // :5715 — stub, safe
        // Merge stage (coreaction.cc:5717-5729). Rugra collapses 9 steps into
        // Merge::merge_all (see ActionMergeType). ActionAssignHigh (:5717) is
        // already registered in build_full_pipeline_actions (line ~7084), runs
        // before the merge actions, assigning HighVariables to all Varnodes.
        universal.add_action(Box::new(ActionMergeType::new()));
        universal.add_action(Box::new(crate::coreaction::ActionMarkExplicit::new()));
        universal.add_action(Box::new(crate::coreaction::ActionMarkImplied::new()));
        universal.add_action(Box::new(crate::coreaction::ActionMarkIndirectOnly::new())); // :5725
        // ActionOutputPrototype + ActionInputPrototype (coreaction.cc:5730-5731)
        // — finalize the function prototype from RETURN ops (return type) and
        // input varnodes (param count/types). Run after merge + MarkExplicit/
        // Implied, before SetCasts (5735) and FinalStructure (5736).
        universal.add_action(Box::new(crate::coreaction::ActionOutputPrototype::new()));
        universal.add_action(Box::new(crate::coreaction::ActionInputPrototype::new()));
        universal.add_action(Box::new(crate::coreaction::ActionMapGlobals::new())); // :5732 — stub, safe
        universal.add_action(Box::new(crate::coreaction::ActionDynamicSymbols::new())); // :5733 — stub, safe
        // ActionSetCasts (coreaction.cc:5735) — inserts CPUI_CAST ops so the
        // printer emits explicit C type casts. Runs after ActionInferTypes
        // (mainloop) and ActionMarkExplicit/Implied so input/output types are
        // settled. Faithful to Ghidra's order: ...MarkImplied → ...NameVars →
        // SetCasts → FinalStructure.
        universal.add_action(Box::new(crate::coreaction::ActionSetCasts::new()));
        universal.add_action(Box::new(crate::coreaction::ActionPrototypeWarnings::new())); // :5737
        universal.add_action(Box::new(ActionFinalStructure::new()));
        universal.add_action(Box::new(crate::coreaction::ActionStop::new())); // :5738 — stub, safe

        // Index the model (universal) Action into `actionmap` under
        // UNIVERSAL_ACTION_NAME (action.hh:304 `universalname`,
        // coreaction.cc:5474 builds it once) so that derive_action /
        // toggle_action can clone from it by name (action.cc:1155
        // `getAction(baseaction)`). Rugra's root is named "decompile" (the
        // Ghidra default current root, coreaction.cc:5738), but it IS the
        // universal model — registered under both names.
        self.register_action_named(UNIVERSAL_ACTION_NAME, Box::new(universal.clone_all()).expect("universal model must be cloneable"));
        // Also register under "decompile" so set_current("decompile") resolves
        // to the model directly (Ghidra's setCurrent calls deriveAction which
        // clones; here the model IS the default current root, so we register
        // the same object and let set_current's derive_action path clone it on
        // demand if a grouplist is configured).
        self.register_action_named("decompile", Box::new(universal.clone_all()).expect("universal model must be cloneable"));
        // register_action keeps the owned universal in all_actions for apply_all.
        self.register_action(Box::new(universal));

        // Populate the per-name clone registries once (Rugra's equivalent of
        // Ghidra's per-class virtual clone; see ACTION_CLONE_REGISTRY docs).
        // Idempotent: OnceLock::set returns Err if already populated, which we
        // ignore (re-calling set_default_actions is supported).
        Self::populate_clone_registries();
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Populate [`ACTION_CLONE_REGISTRY`] / [`RULE_CLONE_REGISTRY`] with a
    /// constructor for every leaf Action/Rule used by the universal pipeline.
    /// This is Rugra's analogue of Ghidra's per-class `Action::clone` /
    /// `Rule::clone` virtual methods (action.hh:119, 236): instead of each leaf
    /// carrying its own clone, we centralise `T::new()` constructors keyed by
    /// the leaf's `get_name()`. Called once from [`Self::set_default_actions`];
    /// idempotent via `OnceLock`.
    fn populate_clone_registries() {
            // Rules (coreaction.cc:5511-5710 build_simplify/cleanup/oppool2). Each
            // entry mirrors Ghidra's per-class Rule::clone (ruleaction.hh:89+): the
            // group is "universal" (Rugra uses a single universal pipeline, matching
            // Ghidra's coreaction.cc construction under group "universal").
            let mut rrules: std::collections::HashMap<&'static str, RuleCloneEntry> = std::collections::HashMap::new();
            rrules.insert("2comp2mult", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::Rule2Comp2Mult::new()) });
            rrules.insert("2comp2sub", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::Rule2Comp2Sub::new()) });
            rrules.insert("add_mult_collapse", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAddMultCollapse::new()) });
            rrules.insert("add_unsigned", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAddUnsigned::new()) });
            rrules.insert("and_commute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAndCommute::new()) });
            rrules.insert("and_compare", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAndCompare::new()) });
            rrules.insert("and_distribute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAndDistribute::new()) });
            rrules.insert("and_mask", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAndMask::new()) });
            rrules.insert("and_or_lump", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAndOrLump::new()) });
            rrules.insert("and_piece", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAndPiece::new()) });
            rrules.insert("and_zext", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleAndZext::new()) });
            rrules.insert("bit_undistribute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleBitUndistribute::new()) });
            rrules.insert("bool_negate", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleBoolNegate::new()) });
            rrules.insert("bool_zext", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleBoolZext::new()) });
            rrules.insert("boolean_dedup", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleBooleanDedup::new()) });
            rrules.insert("boolean_negate", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleBooleanNegate::new()) });
            rrules.insert("boolean_undistribute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleBooleanUndistribute::new()) });
            rrules.insert("bxor2notequal", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleBxor2NotEqual::new()) });
            rrules.insert("carry_elim", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleCarryElim::new()) });
            rrules.insert("collapse_constants", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleCollapseConstants::new()) });
            rrules.insert("collect_terms", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleCollectTerms::new()) });
            rrules.insert("concat_commute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleConcatCommute::new()) });
            rrules.insert("concat_leftshift", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleConcatLeftShift::new()) });
            rrules.insert("concat_shift", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleConcatShift::new()) });
            rrules.insert("concat_zero", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleConcatZero::new()) });
            rrules.insert("concat_zext", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleConcatZext::new()) });
            rrules.insert("cond_negate", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleCondNegate::new()) });
            rrules.insert("conditional_move", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleConditionalMove::new()) });
            rrules.insert("div_chain", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDivChain::new()) });
            rrules.insert("div_opt", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDivOpt::new()) });
            rrules.insert("div_term_add", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDivTermAdd::new()) });
            rrules.insert("div_term_add2", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDivTermAdd2::new()) });
            rrules.insert("double_arith_shift", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDoubleArithShift::new()) });
            rrules.insert("doublein", RuleCloneEntry { group: "universal", make: || Box::new(crate::double_precis::RuleDoubleIn::new()) });
            rrules.insert("doubleload", RuleCloneEntry { group: "universal", make: || Box::new(crate::double_precis::RuleDoubleLoad::new()) });
            rrules.insert("doubleout", RuleCloneEntry { group: "universal", make: || Box::new(crate::double_precis::RuleDoubleOut::new()) });
            rrules.insert("double_shift", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDoubleShift::new()) });
            rrules.insert("doublestore", RuleCloneEntry { group: "universal", make: || Box::new(crate::double_precis::RuleDoubleStore::new()) });
            rrules.insert("double_sub", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDoubleSub::new()) });
            rrules.insert("dumpty_hump", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleDumptyHump::new()) });
            rrules.insert("dumptyhump_late", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleDumptyHumpLate::new()) });
            rrules.insert("early_removal", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleEarlyRemoval::new()) });
            rrules.insert("equal2constant", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleEqual2Constant::new()) });
            rrules.insert("equal2zero", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleEqual2Zero::new()) });
            rrules.insert("equality", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleEquality::new()) });
            rrules.insert("expand_load", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleExpandLoad::new()) });
            rrules.insert("extension_push", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleExtensionPush::new()) });
            rrules.insert("float_cast", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleFloatCast::new()) });
            rrules.insert("float_range", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleFloatRange::new()) });
            rrules.insert("float_sign", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleFloatSign::new()) });
            rrules.insert("float_sign_cleanup", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleFloatSignCleanup::new()) });
            rrules.insert("funcptr_encoding", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleFuncPtrEncoding::new()) });
            rrules.insert("high_order_and", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleHighOrderAnd::new()) });
            rrules.insert("humpty_dumpty", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleHumptyDumpty::new()) });
            rrules.insert("humpty_or", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleHumptyOr::new()) });
            rrules.insert("identity_el", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleIdentityEl::new()) });
            rrules.insert("ignore_nan", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleIgnoreNan::new()) });
            rrules.insert("indirect_collapse", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleIndirectCollapse::new()) });
            rrules.insert("int_2_float_collapse", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleInt2FloatCollapse::new()) });
            rrules.insert("int_lessequal", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleIntLessEqual::new()) });
            rrules.insert("left_right", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLeftRight::new()) });
            rrules.insert("less2_zero", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLess2Zero::new()) });
            rrules.insert("less_equal", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLessEqual::new()) });
            rrules.insert("lessequal2_zero", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLessEqual2Zero::new()) });
            rrules.insert("less_notequal", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLessNotEqual::new()) });
            rrules.insert("less_one", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLessOne::new()) });
            rrules.insert("load_varnode", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLoadVarnode::new()) });
            rrules.insert("logic2bool", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLogic2Bool::new()) });
            rrules.insert("lzcount_shift_bool", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleLzcountShiftBool::new()) });
            rrules.insert("mod_opt", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleModOpt::new()) });
            rrules.insert("mult_neg_one", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleMultNegOne::new()) });
            rrules.insert("multi_collapse", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleMultiCollapse::new()) });
            rrules.insert("negate_identity", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleNegateIdentity::new()) });
            rrules.insert("negate_negate", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleNegateNegate::new()) });
            rrules.insert("not_distribute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleNotDistribute::new()) });
            rrules.insert("or_collapse", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleOrCollapse::new()) });
            rrules.insert("or_compare", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleOrCompare::new()) });
            rrules.insert("or_consume", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleOrConsume::new()) });
            rrules.insert("or_mask", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleOrMask::new()) });
            rrules.insert("or_predicate", RuleCloneEntry { group: "universal", make: || Box::new(crate::condexe::RuleOrPredicate::new()) });
            rrules.insert("piece2sext", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePiece2Sext::new()) });
            rrules.insert("piece2zext", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePiece2Zext::new()) });
            rrules.insert("piece_pathology", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePiecePathology::new()) });
            rrules.insert("piece_structure", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePieceStructure::new()) });
            rrules.insert("popcount_bool_xor", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePopcountBoolXor::new()) });
            rrules.insert("positive_div", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePositiveDiv::new()) });
            rrules.insert("propagate_copy", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePropagateCopy::new()) });
            rrules.insert("ptrarith", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePtrArith::new()) });
            rrules.insert("ptrflow", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePtrFlow::new()) });
            rrules.insert("ptradd_undo", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePtraddUndo::new()) });
            rrules.insert("ptrsub_char_constant", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePtrsubCharConstant::new()) });
            rrules.insert("ptrsub_undo", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePtrsubUndo::new()) });
            rrules.insert("pullsub_indirect", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePullsubIndirect::new()) });
            rrules.insert("pullsub_multi", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePullsubMulti::new()) });
            rrules.insert("push_multi", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePushMulti::new()) });
            rrules.insert("push_ptr", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RulePushPtr::new()) });
            rrules.insert("range_meld", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleRangeMeld::new()) });
            rrules.insert("right_shift_and", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleRightShiftAnd::new()) });
            rrules.insert("sless2zero", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSLess2Zero::new()) });
            rrules.insert("sborrow", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSborrow::new()) });
            rrules.insert("scarry", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleScarry::new()) });
            rrules.insert("segment", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSegment::new()) });
            rrules.insert("select_cse", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSelectCse::new()) });
            rrules.insert("sext_eliminate", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSextEliminate::new()) });
            rrules.insert("shift2mult", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleShift2Mult::new()) });
            rrules.insert("shift_and", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleShiftAnd::new()) });
            rrules.insert("shift_bitops", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleShiftBitops::new()) });
            rrules.insert("shift_compare", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleShiftCompare::new()) });
            rrules.insert("shift_piece", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleShiftPiece::new()) });
            rrules.insert("shift_sub", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleShiftSub::new()) });
            rrules.insert("sign_div2", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignDiv2::new()) });
            rrules.insert("sign_form", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignForm::new()) });
            rrules.insert("sign_form2", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignForm2::new()) });
            rrules.insert("sign_mod2_opt", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignMod2Opt::new()) });
            rrules.insert("sign_mod2n_opt", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignMod2nOpt::new()) });
            rrules.insert("sign_mod2n_opt2", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignMod2nOpt2::new()) });
            rrules.insert("sign_near_mult", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignNearMult::new()) });
            rrules.insert("sign_shift", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSignShift::new()) });
            rrules.insert("sless_to_less", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSlessToLess::new()) });
            rrules.insert("splitcopy", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSplitCopy::new()) });
            rrules.insert("splitflow", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSplitFlow::new()) });
            rrules.insert("splitload", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSplitLoad::new()) });
            rrules.insert("splitstore", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSplitStore::new()) });
            rrules.insert("store_varnode", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleStoreVarnode::new()) });
            rrules.insert("string_copy", RuleCloneEntry { group: "universal", make: || Box::new(crate::constseq::RuleStringCopy::new()) });
            rrules.insert("string_store", RuleCloneEntry { group: "universal", make: || Box::new(crate::constseq::RuleStringStore::new()) });
            rrules.insert("struct_offset0", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleStructOffset0::new()) });
            rrules.insert("sub2_add", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSub2Add::new()) });
            rrules.insert("sub_cancel", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSubCancel::new()) });
            rrules.insert("sub_commute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSubCommute::new()) });
            rrules.insert("sub_ext_comm", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSubExtComm::new()) });
            rrules.insert("sub_normal", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSubNormal::new()) });
            rrules.insert("sub_right", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSubRight::new()) });
            rrules.insert("sub_zext", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSubZext::new()) });
            rrules.insert("subfloat_convert", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSubfloatConvert::new()) });
            rrules.insert("subvar_and", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSubvarAnd::new()) });
            rrules.insert("subvar_compzero", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSubvarCompZero::new()) });
            rrules.insert("subvar_sext", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSubvarSext::new()) });
            rrules.insert("subvar_shift", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSubvarShift::new()) });
            rrules.insert("subvar_subpiece", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSubvarSubpiece::new()) });
            rrules.insert("subvar_zext", RuleCloneEntry { group: "universal", make: || Box::new(crate::subflow::RuleSubvarZext::new()) });
            rrules.insert("switch_single", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleSwitchSingle::new()) });
            rrules.insert("term_order", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleTermOrder::new()) });
            rrules.insert("test_sign", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleTestSign::new()) });
            rrules.insert("three_way_compare", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleThreeWayCompare::new()) });
            rrules.insert("transform_cpool", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleTransformCpool::new()) });
            rrules.insert("trivial_arith", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleTrivialArith::new()) });
            rrules.insert("trivial_bool", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleTrivialBool::new()) });
            rrules.insert("trivial_shift", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleTrivialShift::new()) });
            rrules.insert("unsigned_2_float", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleUnsigned2Float::new()) });
            rrules.insert("xor_collapse", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleXorCollapse::new()) });
            rrules.insert("xor_swap", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleXorSwap::new()) });
            rrules.insert("zext_commute", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleZextCommute::new()) });
            rrules.insert("zext_eliminate", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleZextEliminate::new()) });
            rrules.insert("zext_shift_zext", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleZextShiftZext::new()) });
            rrules.insert("zext_sless", RuleCloneEntry { group: "universal", make: || Box::new(crate::ruleaction::RuleZextSless::new()) });
            let _ = RULE_CLONE_REGISTRY.set(rrules);

            // Actions (coreaction.cc:5477-5738 universal tree leaves). Mirrors Ghidra's
            // per-class Action::clone (coreaction.hh:37+).
            let mut ractions: std::collections::HashMap<&'static str, ActionCloneEntry> = std::collections::HashMap::new();
            ractions.insert("blockstructure", ActionCloneEntry { group: "universal", make: || Box::new(crate::blockaction::ActionBlockStructure::new()) });
            ractions.insert("conditionalconst", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionConditionalConst::new()) });
            ractions.insert("conditionalexe", ActionCloneEntry { group: "universal", make: || Box::new(crate::condexe::ActionConditionalExe::new()) });
            ractions.insert("constantptr", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionConstantPtr::new()) });
            ractions.insert("constbase", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionConstbase::new()) });
            ractions.insert("deadcode", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionDeadCode::new()) });
            ractions.insert("determinedbranch", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionDeterminedBranch::new()) });
            ractions.insert("donothing", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionDoNothing::new()) });
            ractions.insert("dynamicsymbols", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionDynamicSymbols::new()) });
            ractions.insert("extrapopsetup", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionExtraPopSetup::new()) });
            ractions.insert("finalstructure", ActionCloneEntry { group: "universal", make: || Box::new(crate::blockaction::ActionFinalStructure::new()) });
            ractions.insert("funclink", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionFuncLink::new()) });
            ractions.insert("heritage", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionHeritage::new()) });
            ractions.insert("infer_params", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionInferParams::new()) });
            ractions.insert("infertypes", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionInferTypes::new()) });
            ractions.insert("inputprototype", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionInputPrototype::new()) });
            ractions.insert("likelytrash", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionLikelyTrash::new()) });
            ractions.insert("mapglobals", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionMapGlobals::new()) });
            ractions.insert("mappedlocalsync", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionMappedLocalSync::new()) });
            ractions.insert("markexplicit", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionMarkExplicit::new()) });
            ractions.insert("markimplied", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionMarkImplied::new()) });
            ractions.insert("markindirectonly", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionMarkIndirectOnly::new()) });
            ractions.insert("merge_type", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionMergeType::new()) });
            ractions.insert("nodejoin", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionNodeJoin::new()) });
            ractions.insert("normalizebranches", ActionCloneEntry { group: "universal", make: || Box::new(crate::blockaction::ActionNormalizeBranches::new()) });
            ractions.insert("outputprototype", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionOutputPrototype::new()) });
            ractions.insert("prefercomplement", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionPreferComplement::new()) });
            ractions.insert("prototypewarnings", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionPrototypeWarnings::new()) });
            ractions.insert("redundbranch", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionRedundBranch::new()) });
            ractions.insert("restrictlocal", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionRestrictLocal::new()) });
            ractions.insert("restructureVarnode", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionRestructureVarnode::new()) });
            ractions.insert("returnsplit", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionReturnSplit::new()) });
            ractions.insert("setcasts", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionSetCasts::new()) });
            ractions.insert("spacebase", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionSpacebase::new()) });
            ractions.insert("stackptrflow", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionStackPtrFlow::new()) });
            ractions.insert("start", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionStart::new()) });
            ractions.insert("startcleanup", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionStartCleanUp::new()) });
            ractions.insert("stop", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionStop::new()) });
            ractions.insert("structuretransform", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionStructureTransform::new()) });
            ractions.insert("unreachable", ActionCloneEntry { group: "universal", make: || Box::new(crate::coreaction::ActionUnreachable::new()) });
            let _ = ACTION_CLONE_REGISTRY.set(ractions);
    }

    // ---- Runtime group configuration (action.hh:312-322, action.cc:1007-1097) ----
    //
    // These mirror Ghidra's ActionDatabase group-management API, which backs
    // the decompiler command-line options `-trigger`/`-actionpath`. Rugra's
    // `set_default_actions` builds the universal tree directly (no clone), so
    // these methods currently manage the grouplist metadata that describes a
    // root Action; full derive/clone support (action.cc:1078-1104) is left as a
    // follow-up since Rugra's `Box<dyn Action>` is not `Clone`.

    // Ghidra: action.hh:313 getCurrent / action.hh:314 getCurrentName
    /// Get the current \e root Action (action.hh:313). Returns `None` until a
    /// root is registered and selected.
    pub fn get_current(&self) -> Option<&dyn Action> {
        let name = self.current_group.as_ref()?;
        self.get_action(name)
    }

    // Ghidra: action.hh:314 getCurrentName
    /// Get the name of the current \e root Action (action.hh:314).
    pub fn get_current_name(&self) -> Option<&str> {
        self.current_group.as_deref()
    }

    // Ghidra: action.cc:1146 ActionDatabase::deriveAction
    /// Internal: build (or return the cached) root Action corresponding to a
    /// grouplist name, by selectively cloning components from an existing
    /// model Action (action.cc:1141-1161). Faithful to
    /// `ActionDatabase::deriveAction`:
    ///   1. If `grp` is already in `actionmap`, return the cached object.
    ///   2. Otherwise look up the grouplist named `grp` (`getGroup`, throws if
    ///      unknown -- Rugra returns `None`).
    ///   3. `getAction(baseaction)` -- fetch the model (action.cc:1155).
    ///   4. `act->clone(curgrp)` -- clone filtered by the grouplist.
    ///   5. `registerAction(grp, newact)` -- cache under `grp`.
    /// Returns `Some(())` on success, `None` if the grouplist is unknown or the
    /// model is absent (so callers can degrade gracefully).
    fn derive_action(&mut self, baseaction: &str, grp: &str) -> Option<()> {
        // (1) already derived? (action.cc:1149-1152)
        if self.actionmap.contains_key(grp) {
            return Some(());
        }
        // (2) fetch the grouplist (action.cc:1154). getGroup throws on unknown;
        // Rugra returns None.
        let curgrp = self.groupmap.get(grp)?.clone();
        // (3)+(4) fetch the model and clone filtered by the grouplist. We borrow
        // the model immutably (via get_action_by_name) and produce an owned
        // Box<dyn Action> before any &mut self mutation.
        let newact = self.get_action_by_name(baseaction)
            .or_else(|| {
                // Fallback: model may live in all_actions under a different name
                // (e.g. "decompile"). get_action scans all_actions by name.
                if baseaction == UNIVERSAL_ACTION_NAME {
                    self.all_actions.first().map(|a| a.as_ref())
                } else {
                    self.get_action(baseaction)
                }
            })
            .and_then(|model| model.clone_action(&curgrp))?;
        // (5) cache the derived root under `grp` (action.cc:1159 registerAction).
        self.register_action_named(grp, newact);
        Some(())
    }

    // Ghidra: action.cc:1022 ActionDatabase::setCurrent
    /// Set the current \e root Action by name (action.hh:316). Faithful to
    /// `ActionDatabase::setCurrent` (action.cc:1022-1028): records the name in
    /// `currentactname` then derives the root Action from the universal model
    /// via [`Self::derive_action`] (which clones the model filtered by the
    /// grouplist named `actname`, caching the result in `actionmap`). Returns a
    /// reference to the newly-selected root.
    ///
    /// Rugra differs only in return type (`Option<&dyn Action>` vs Ghidra's raw
    /// `Action *`, which is never NULL because `deriveAction` throws on an
    /// unknown grouplist); we return `None` if the grouplist is unknown so
    /// callers can detect misconfiguration without panicking.
    pub fn set_current(&mut self, actname: &str) -> Option<&dyn Action> {
        // action.cc:1025-1027: currentactname = actname; currentact = deriveAction(universalname, actname)
        match self.derive_action(UNIVERSAL_ACTION_NAME, actname) {
            Some(()) => {
                self.current_group = Some(actname.to_string());
                self.actionmap.get(actname).map(|a| a.as_ref())
            }
            None => None,
        }
    }

    // Ghidra: action.hh:315 getGroup
    /// Get the grouplist (as a sorted set of basegroup names) for a named
    /// \e root Action (action.hh:315). Returns `None` if `grp` is unknown.
    pub fn get_group(&self, grp: &str) -> Option<&std::collections::BTreeSet<String>> {
        self.groupmap.get(grp)
    }

    // Ghidra: action.cc:1037 ActionDatabase::toggleAction
    /// Add (`val=true`) or remove (`val=false`) a basegroup from a root
    /// Action's grouplist, then re-derive the root Action from the universal
    /// model by cloning with the updated grouplist. Faithful to
    /// `ActionDatabase::toggleAction` (action.cc:1037-1054):
    ///   1. `getAction(universalname)` -- fetch the model.
    ///   2. `addToGroup`/`removeFromGroup` -- mutate the grouplist.
    ///   3. `act->clone(curgrp)` -- re-clone the model filtered by the new
    ///      grouplist.
    ///   4. `registerAction(grp, newact)` -- replace the cached derived root.
    ///   5. If `grp == currentactname`, update `currentact`.
    /// Returns `true` if the grouplist membership changed (Rugra's contract,
    /// matching the prior behaviour; Ghidra returns the new Action pointer).
    pub fn toggle_action(&mut self, grp: &str, basegrp: &str, val: bool) -> bool {
        self.is_default_groups = false;
        // (2) mutate the grouplist (action.cc:1041-1044).
        let entry = self.groupmap.entry(grp.to_string()).or_default();
        let changed = if val {
            entry.insert(basegrp.to_string())
        } else {
            entry.remove(basegrp)
        };
        if !changed {
            return false;
        }
        // (1)+(3) re-clone the model filtered by the new grouplist.
        // We snapshot the grouplist and clone via a &self borrow first, then
        // mutate actionmap (avoids holding a &mut while cloning from &self).
        let curgrp = self.groupmap.get(grp).cloned().unwrap_or_default();
        let newact = self.get_action_by_name(UNIVERSAL_ACTION_NAME)
            .and_then(|model| model.clone_action(&curgrp));
        // (4) register the re-derived root (action.cc:1048 registerAction).
        if let Some(act) = newact {
            self.register_action_named(grp, act);
        }
        // (5) if this is the current root, point currentact at the new object
        // (action.cc:1050-1051). Rugra's `current_group` is a name, so the next
        // get_current()/set_current() resolves to the refreshed actionmap entry.
        // No extra work needed: get_current() looks up by name each call.
        changed
    }

    // Ghidra: action.cc:1060 ActionDatabase::setGroup
    /// (Re)set the grouplist for a particular \e root Action (action.cc:1060).
    /// `groups` replaces any existing membership for `grp`. This is the core of
    /// Ghidra's command-line `-trigger`/`-actionpath` options: the caller
    /// supplies the set of basegroups that should participate in the named
    /// root Action. Does not redefine an already-instantiated root.
    ///
    /// NOTE: Ghidra takes a NULL-terminated `const char **argv`; Rugra takes an
    /// iterator of `&str`, which is the idiomatic equivalent.
    pub fn set_group<'a, I>(&mut self, grp: &str, groups: I)
    where
        I: IntoIterator<Item = &'a str>,
    {
        let entry = self.groupmap.entry(grp.to_string()).or_default();
        entry.clear();
        for g in groups {
            entry.insert(g.to_string());
        }
        self.is_default_groups = false;
    }

    // Ghidra: action.cc:1078 ActionDatabase::cloneGroup
    /// Copy an existing \e root Action's grouplist under a new name
    /// (action.cc:1078). Returns `true` if `oldname` existed and was copied.
    pub fn clone_group(&mut self, oldname: &str, newname: &str) -> bool {
        if let Some(src) = self.groupmap.get(oldname).cloned() {
            self.groupmap.insert(newname.to_string(), src);
            self.is_default_groups = false;
            true
        } else {
            false
        }
    }

    // Ghidra: action.cc:1091 ActionDatabase::addToGroup
    /// Add a basegroup to a root Action's grouplist (action.cc:1091). Returns
    /// `true` for a new addition, `false` if already present.
    pub fn add_to_group(&mut self, grp: &str, basegroup: &str) -> bool {
        self.is_default_groups = false;
        self.groupmap
            .entry(grp.to_string())
            .or_default()
            .insert(basegroup.to_string())
    }

    // Ghidra: action.cc:1104 ActionDatabase::removeFromGroup
    /// Remove a basegroup from a root Action's grouplist (action.cc:1104).
    /// Returns `true` if the group was present and removed.
    pub fn remove_from_group(&mut self, grp: &str, basegroup: &str) -> bool {
        self.is_default_groups = false;
        self.groupmap
            .get_mut(grp)
            .map(|set| set.remove(basegroup))
            .unwrap_or(false)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Whether only the built-in default groups are configured (action.hh:303
    /// `isDefaultGroups`). Returns `false` after any `set_group`/`toggle_action`
    /// /`add_to_group`/`remove_from_group`/`clone_group` call.
    pub fn is_default_groups(&self) -> bool { self.is_default_groups }
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
