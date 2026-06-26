//! Unification-based pattern matching infrastructure.
//!
//! Corresponds to Ghidra's `unify.hh` / `unify.cc` (2358 lines).
//!
//! This module provides a framework for pattern matching on P-code data-flow
//! graphs. It is used by the "Dolphin" pattern-based rule system and by
//! user-defined rules. The core idea is a set of constraint objects that
//! match against ops, varnodes, and constants, building a unified state.
//!
//! Key classes:
//! - `UnifyState`: holds the current matching state (ops, varnodes, constants)
//! - `UnifyConstraint`: base trait for all constraints
//! - `ConstantNamed`/`ConstantAbsolute`/`ConstantNZMask` etc.: RHS constant types
//! - Various constraint types (OpEqual, VarnodeEqual, OpCodeConstraint, etc.)
//! - `UnifyCPrinter`: C code generation from unified patterns
//!
//! # Status
//! Skeleton with `UnifyState`, `RHSConstant` types, and basic constraint enum.
//! The full constraint system (50+ constraint types) and C printer are deferred.

use std::sync::{Arc, RwLock};
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;

/// Types of data that can be stored in a unify state slot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnifyDatatype {
    OpType,
    VarType,
    ConstType,
    BlockType,
}

/// The matching state: holds ops, varnodes, and constants matched so far.
/// Corresponds to Ghidra's `UnifyState`.
pub struct UnifyState {
    /// Stored ops by index
    pub ops: Vec<Option<Arc<RwLock<PcodeOp>>>>,
    /// Stored varnodes by index
    pub varnodes: Vec<Option<Arc<RwLock<Varnode>>>>,
    /// Stored constants by index
    pub constants: Vec<u64>,
    /// Stored blocks by index
    pub blocks: Vec<usize>,
    /// Datatypes for each slot
    pub datatypes: Vec<UnifyDatatype>,
}

impl UnifyState {
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            varnodes: Vec::new(),
            constants: Vec::new(),
            blocks: Vec::new(),
            datatypes: Vec::new(),
        }
    }

    /// Register a slot of the given type, returning its index.
    pub fn register_slot(&mut self, dt: UnifyDatatype) -> usize {
        match dt {
            UnifyDatatype::OpType => {
                let idx = self.ops.len();
                self.ops.push(None);
                self.datatypes.push(dt);
                idx
            }
            UnifyDatatype::VarType => {
                let idx = self.varnodes.len();
                self.varnodes.push(None);
                self.datatypes.push(dt);
                idx
            }
            UnifyDatatype::ConstType => {
                let idx = self.constants.len();
                self.constants.push(0);
                self.datatypes.push(dt);
                idx
            }
            UnifyDatatype::BlockType => {
                let idx = self.blocks.len();
                self.blocks.push(0);
                self.datatypes.push(dt);
                idx
            }
        }
    }

    /// Set an op at the given index.
    pub fn set_op(&mut self, idx: usize, op: Arc<RwLock<PcodeOp>>) {
        self.ops[idx] = Some(op);
    }

    /// Set a varnode at the given index.
    pub fn set_varnode(&mut self, idx: usize, vn: Arc<RwLock<Varnode>>) {
        self.varnodes[idx] = Some(vn);
    }

    /// Set a constant at the given index.
    pub fn set_constant(&mut self, idx: usize, val: u64) {
        if idx < self.constants.len() {
            self.constants[idx] = val;
        }
    }

    /// Get an op at the given index.
    pub fn get_op(&self, idx: usize) -> &Option<Arc<RwLock<PcodeOp>>> {
        &self.ops[idx]
    }

    /// Get a varnode at the given index.
    pub fn get_varnode(&self, idx: usize) -> &Option<Arc<RwLock<Varnode>>> {
        &self.varnodes[idx]
    }

    /// Get a constant at the given index.
    pub fn get_constant(&self, idx: usize) -> u64 {
        if idx < self.constants.len() { self.constants[idx] } else { 0 }
    }
}

/// A construction that results in a constant on the RHS of an expression.
/// Corresponds to Ghidra's `RHSConstant` (unify.hh:59).
#[derive(Debug, Clone)]
pub enum RHSConstant {
    /// A named constant slot index
    Named(usize),
    /// An absolute constant value
    Absolute(u64),
    /// A varnode's non-zero mask
    NZMask(usize),
    /// A varnode's consume mask
    Consumed(usize),
    /// A varnode's offset
    Offset(usize),
    /// Whether the varnode is constant (0 or 1)
    IsConstant(usize),
}

impl RHSConstant {
    /// Evaluate this constant against the given state.
    pub fn get_constant(&self, state: &UnifyState) -> u64 {
        match self {
            RHSConstant::Named(idx) => state.get_constant(*idx),
            RHSConstant::Absolute(val) => *val,
            RHSConstant::NZMask(idx) => {
                state.get_varnode(*idx).as_ref()
                    .map(|vn| vn.read().unwrap().get_nz_mask())
                    .unwrap_or(0)
            }
            RHSConstant::Consumed(idx) => {
                state.get_varnode(*idx).as_ref()
                    .map(|vn| vn.read().unwrap().get_consume())
                    .unwrap_or(0)
            }
            RHSConstant::Offset(idx) => {
                state.get_varnode(*idx).as_ref()
                    .map(|vn| vn.read().unwrap().get_offset())
                    .unwrap_or(0)
            }
            RHSConstant::IsConstant(idx) => {
                state.get_varnode(*idx).as_ref()
                    .map(|vn| if vn.read().unwrap().is_constant() { 1 } else { 0 })
                    .unwrap_or(0)
            }
        }
    }
}

/// Constraint types in the unify system.
/// Corresponds to the various `UnifyConstraint` subclasses in Ghidra.
#[derive(Debug, Clone)]
pub enum UnifyConstraint {
    /// Match a specific opcode on slot
    OpCode(usize, OpCode),
    /// Two ops must be the same
    OpEqual(usize, usize),
    /// Two varnodes must be the same
    VarnodeEqual(usize, usize),
    /// Check that an op has a specific number of inputs
    NumParams(usize, usize),
    /// Constant must equal a specific value
    ConstEqual(usize, u64),
    /// Check that a varnode has a specific size
    VarnodeSize(usize, usize),
    /// Copy varnode from one slot to another
    CopyVarnode(usize, usize),
    /// The constraint always succeeds (used for optional matches)
    AlwaysTrue,
}

impl UnifyConstraint {
    /// Evaluate this constraint against the given state and a set of ops.
    /// Returns true if the constraint is satisfied.
    pub fn evaluate(&self, state: &UnifyState) -> bool {
        match self {
            UnifyConstraint::AlwaysTrue => true,
            UnifyConstraint::OpEqual(a, b) => {
                let oa = state.get_op(*a);
                let ob = state.get_op(*b);
                match (oa, ob) {
                    (Some(x), Some(y)) => std::sync::Arc::ptr_eq(x, y),
                    _ => false,
                }
            }
            UnifyConstraint::VarnodeEqual(a, b) => {
                let va = state.get_varnode(*a);
                let vb = state.get_varnode(*b);
                match (va, vb) {
                    (Some(x), Some(y)) => std::sync::Arc::ptr_eq(x, y),
                    _ => false,
                }
            }
            UnifyConstraint::ConstEqual(idx, val) => {
                state.get_constant(*idx) == *val
            }
            UnifyConstraint::OpCode(idx, expected_opc) => {
                let op = state.get_op(*idx);
                match op {
                    Some(o) => o.read().unwrap().opcode == *expected_opc,
                    None => false,
                }
            }
            UnifyConstraint::NumParams(idx, expected) => {
                let op = state.get_op(*idx);
                match op {
                    Some(o) => o.read().unwrap().inrefs.len() == *expected,
                    None => false,
                }
            }
            UnifyConstraint::VarnodeSize(idx, expected) => {
                let vn = state.get_varnode(*idx);
                match vn {
                    Some(v) => v.read().unwrap().get_size() == *expected,
                    None => false,
                }
            }
            UnifyConstraint::CopyVarnode(_from, _to) => {
                // This is an action constraint, not a test — always succeeds.
                true
            }
        }
    }
}

/// A sequence of constraints that form a complete unify rule.
/// Corresponds to Ghidra's constraint vector in UnifyState.
#[derive(Debug, Clone, Default)]
pub struct ConstraintSequence {
    pub constraints: Vec<UnifyConstraint>,
}

impl ConstraintSequence {
    pub fn new() -> Self { Self::default() }

    /// Add a constraint to the sequence.
    pub fn add(&mut self, c: UnifyConstraint) {
        self.constraints.push(c);
    }

    /// Evaluate all constraints against the given state.
    pub fn evaluate_all(&self, state: &UnifyState) -> bool {
        self.constraints.iter().all(|c| c.evaluate(state))
    }

    /// Get the number of constraints.
    pub fn len(&self) -> usize { self.constraints.len() }

    /// Check if empty.
    pub fn is_empty(&self) -> bool { self.constraints.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unify_state_basic() {
        let mut state = UnifyState::new();
        let op_idx = state.register_slot(UnifyDatatype::OpType);
        let const_idx = state.register_slot(UnifyDatatype::ConstType);
        state.set_constant(const_idx, 42);
        assert_eq!(state.get_constant(const_idx), 42);
        assert!(state.get_op(op_idx).is_none());
    }

    #[test]
    fn test_rhs_constant_absolute() {
        let state = UnifyState::new();
        let rhs = RHSConstant::Absolute(99);
        assert_eq!(rhs.get_constant(&state), 99);
    }

    #[test]
    fn test_rhs_constant_named() {
        let mut state = UnifyState::new();
        let idx = state.register_slot(UnifyDatatype::ConstType);
        state.set_constant(idx, 7);
        let rhs = RHSConstant::Named(idx);
        assert_eq!(rhs.get_constant(&state), 7);
    }

    #[test]
    fn test_constraint_always_true() {
        let state = UnifyState::new();
        assert!(UnifyConstraint::AlwaysTrue.evaluate(&state));
    }

    #[test]
    fn test_constraint_const_equal() {
        let mut state = UnifyState::new();
        let idx = state.register_slot(UnifyDatatype::ConstType);
        state.set_constant(idx, 42);
        assert!(UnifyConstraint::ConstEqual(idx, 42).evaluate(&state));
        assert!(!UnifyConstraint::ConstEqual(idx, 99).evaluate(&state));
    }

    #[test]
    fn test_constraint_sequence() {
        let mut state = UnifyState::new();
        let idx = state.register_slot(UnifyDatatype::ConstType);
        state.set_constant(idx, 42);

        let mut seq = ConstraintSequence::new();
        seq.add(UnifyConstraint::AlwaysTrue);
        seq.add(UnifyConstraint::ConstEqual(idx, 42));
        assert!(seq.evaluate_all(&state));

        seq.add(UnifyConstraint::ConstEqual(idx, 99));
        assert!(!seq.evaluate_all(&state));
        assert_eq!(seq.len(), 3);
    }
}
