//! User-defined P-code operations (CALLOTHER) management.
//!
//! Corresponds to Ghidra's `userop.hh` / `userop.cc` (1009 lines).
//!
//! The CALLOTHER opcode represents user-defined operations. This module manages
//! the association between CALLOTHER constant ids and specialized behavior
//! classes (volatile read/write, segment ops, jump-table assist, string ops,
//! injected code, etc.).
//!
//! Key classes:
//! - `UserPcodeOp`: base class for user-defined op definitions
//! - `UnspecializedPcodeOp`: default for unmapped CALLOTHERs
//! - `UserOpManage`: manager holding all registered user ops
//!
//! # Status
//! Core data structures (UserPcodeOp, UserOpType, flags) and manager skeleton.
//! Specialized subclasses (VolatileRead/Write, SegmentOp, JumpAssist) deferred.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crate::op::PcodeOp;
use crate::type_system::Datatype;

/// User-op class encoded as an enum.
/// Corresponds to Ghidra's `UserPcodeOp::userop_type` (userop.hh:56).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserOpType {
    Unspecialized = 1,
    Injected = 2,
    VolatileRead = 3,
    VolatileWrite = 4,
    Segment = 5,
    JumpAssist = 6,
    StringData = 7,
    Datatype = 8,
}

/// Boolean properties for CALLOTHER ops.
/// Corresponds to Ghidra's `UserPcodeOp::userop_flags` (userop.hh:50).
pub mod userop_flags {
    pub const ANNOTATION_ASSIGNMENT: u32 = 1;
    pub const NO_OPERATOR: u32 = 2;
    pub const DISPLAY_STRING: u32 = 4;
}

/// Built-in CALLOTHER ids.
pub const BUILTIN_STRINGDATA: u32 = 1;
pub const BUILTIN_VOLATILE_READ: u32 = 2;
pub const BUILTIN_VOLATILE_WRITE: u32 = 3;
pub const BUILTIN_MEMCPY: u32 = 4;
pub const BUILTIN_STRNCPY: u32 = 5;
pub const BUILTIN_WCSNCPY: u32 = 6;

/// The base class for a detailed definition of a user-defined p-code operation.
/// Corresponds to Ghidra's `UserPcodeOp` (userop.hh:47).
#[derive(Debug, Clone)]
pub struct UserPcodeOp {
    /// Low-level name of the p-code operator
    pub name: String,
    /// Encoded class type
    pub op_type: UserOpType,
    /// Index passed in the CALLOTHER op (the constant id)
    pub userop_index: i32,
    /// Boolean attributes (userop_flags)
    pub flags: u32,
}

impl UserPcodeOp {
    pub fn new(name: String, op_type: UserOpType, index: i32) -> Self {
        Self { name, op_type, userop_index: index, flags: 0 }
    }

    pub fn get_name(&self) -> &str { &self.name }
    pub fn get_type(&self) -> UserOpType { self.op_type }
    pub fn get_index(&self) -> i32 { self.userop_index }
    pub fn get_display(&self) -> u32 {
        self.flags & (userop_flags::ANNOTATION_ASSIGNMENT | userop_flags::NO_OPERATOR | userop_flags::DISPLAY_STRING)
    }
}

/// Manager for all registered user-defined p-code operations.
/// Corresponds to Ghidra's `UserOpManage` (userop.hh).
pub struct UserOpManage {
    /// All registered user ops by index
    pub ops: Vec<UserPcodeOp>,
    /// Map from name to index
    pub name_map: HashMap<String, i32>,
}

impl UserOpManage {
    pub fn new() -> Self {
        Self { ops: Vec::new(), name_map: HashMap::new() }
    }

    /// Register a new user op, returning its index.
    pub fn register_op(&mut self, name: String, op_type: UserOpType) -> i32 {
        let index = self.ops.len() as i32;
        self.name_map.insert(name.clone(), index);
        self.ops.push(UserPcodeOp::new(name, op_type, index));
        index
    }

    /// Get a user op by its CALLOTHER index.
    pub fn get_op(&self, index: i32) -> Option<&UserPcodeOp> {
        if index >= 0 && (index as usize) < self.ops.len() {
            Some(&self.ops[index as usize])
        } else {
            None
        }
    }

    /// Get a user op index by name.
    pub fn get_index_by_name(&self, name: &str) -> Option<i32> {
        self.name_map.get(name).copied()
    }

    /// Get the number of registered ops.
    pub fn num_ops(&self) -> usize { self.ops.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_op_basic() {
        let op = UserPcodeOp::new("memcpy".into(), UserOpType::Unspecialized, 4);
        assert_eq!(op.get_name(), "memcpy");
        assert_eq!(op.get_index(), 4);
        assert_eq!(op.get_type(), UserOpType::Unspecialized);
    }

    #[test]
    fn test_user_op_manage() {
        let mut mgr = UserOpManage::new();
        let idx = mgr.register_op("memcpy".into(), UserOpType::Unspecialized);
        assert_eq!(idx, 0);
        assert_eq!(mgr.num_ops(), 1);
        assert!(mgr.get_op(0).is_some());
        assert_eq!(mgr.get_index_by_name("memcpy"), Some(0));
        assert!(mgr.get_index_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_builtin_ids() {
        assert_eq!(BUILTIN_MEMCPY, 4);
        assert_eq!(BUILTIN_VOLATILE_READ, 2);
    }
}
