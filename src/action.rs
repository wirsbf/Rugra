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

/// Database for managing all registered actions
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
