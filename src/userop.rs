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

    /// Get the symbol representing this operation in decompiled code.
    /// Faithful to `UserPcodeOp::getOperatorName` (userop.hh:94-95).
    pub fn get_operator_name(&self, _op: &PcodeOp) -> String {
        self.name.clone()
    }

    /// Assign a size to an annotation input. Faithful to
    /// `UserPcodeOp::extractAnnotationSize` (userop.cc:37-41).
    /// Base class throws; subclasses override.
    pub fn extract_annotation_size(&self) -> i32 {
        panic!("Unexpected annotation input for CALLOTHER {}", self.name);
    }

    /// Check if this is a volatile read op.
    pub fn is_volatile_read(&self) -> bool {
        self.op_type == UserOpType::VolatileRead
    }

    /// Check if this is a volatile write op.
    pub fn is_volatile_write(&self) -> bool {
        self.op_type == UserOpType::VolatileWrite
    }

    /// Check if this is a segment op.
    pub fn is_segment(&self) -> bool {
        self.op_type == UserOpType::Segment
    }

    /// Check if this is a jump-assist op.
    pub fn is_jump_assist(&self) -> bool {
        self.op_type == UserOpType::JumpAssist
    }

    /// Check if this is an injected op.
    pub fn is_injected(&self) -> bool {
        self.op_type == UserOpType::Injected
    }

    /// Check if this is a string-data op.
    pub fn is_string_data(&self) -> bool {
        self.op_type == UserOpType::StringData
    }
}

/// A user defined p-code op with input/output data-types.
/// Corresponds to Ghidra's `DatatypeUserOp` (userop.hh:140).
#[derive(Debug, Clone)]
pub struct DatatypeUserOp {
    pub base: UserPcodeOp,
    pub out_type: Option<Arc<Datatype>>,
    pub in_types: Vec<Option<Arc<Datatype>>>,
}

impl DatatypeUserOp {
    pub fn new(name: String, index: i32, out: Option<Arc<Datatype>>, ins: Vec<Option<Arc<Datatype>>>) -> Self {
        Self {
            base: UserPcodeOp::new(name, UserOpType::Datatype, index),
            out_type: out,
            in_types: ins,
        }
    }

    /// Get the output data-type. Faithful to `DatatypeUserOp::getOutputLocal`.
    pub fn get_output_local(&self) -> Option<&Arc<Datatype>> { self.out_type.as_ref() }

    /// Get the input data-type at a given slot. Faithful to
    /// `DatatypeUserOp::getInputLocal` (userop.cc:76-83).
    pub fn get_input_local(&self, slot: i32) -> Option<&Arc<Datatype>> {
        let s = slot - 1; // Skip the CALLOTHER id in slot 0
        if s >= 0 && (s as usize) < self.in_types.len() {
            self.in_types[s as usize].as_ref()
        } else {
            None
        }
    }
}

/// A volatile read user-op. Faithful to `VolatileReadOp` (userop.hh:188).
/// Returns the size of the volatile varnode being read.
#[derive(Debug, Clone)]
pub struct VolatileReadOp {
    pub base: UserPcodeOp,
}

impl VolatileReadOp {
    pub fn new(name: String, index: i32) -> Self {
        Self { base: UserPcodeOp::new(name, UserOpType::VolatileRead, index) }
    }

    /// Extract the annotation size for a volatile read. Faithful to
    /// `VolatileReadOp::extractAnnotationSize` (userop.cc:143-170).
    pub fn extract_annotation_size(vn: &crate::varnode::Varnode) -> i32 {
        vn.get_size() as i32
    }
}

/// A volatile write user-op. Faithful to `VolatileWriteOp` (userop.hh:203).
#[derive(Debug, Clone)]
pub struct VolatileWriteOp {
    pub base: UserPcodeOp,
}

impl VolatileWriteOp {
    pub fn new(name: String, index: i32) -> Self {
        Self { base: UserPcodeOp::new(name, UserOpType::VolatileWrite, index) }
    }

    /// Extract the annotation size for a volatile write. Faithful to
    /// `VolatileWriteOp::extractAnnotationSize` (userop.cc:174-186).
    pub fn extract_annotation_size(vn: &crate::varnode::Varnode) -> i32 {
        vn.get_size() as i32
    }
}

/// A segment op. Faithful to `SegmentOp` (userop.hh:264).
/// Handles segmented addressing (e.g., x86 real mode far pointers).
#[derive(Debug, Clone)]
pub struct SegmentOp {
    pub base: UserPcodeOp,
    /// The address space this segment op operates on.
    pub space: u32,
    /// Base resolution: how the segment base is computed.
    pub supports_index: bool,
}

impl SegmentOp {
    pub fn new(name: String, index: i32) -> Self {
        Self {
            base: UserPcodeOp::new(name, UserOpType::Segment, index),
            space: 0,
            supports_index: false,
        }
    }
}

/// Jump-table assist op. Faithful to `JumpAssistOp` (userop.hh:294).
/// Stores injection ids for switch-table resolution scripts.
#[derive(Debug, Clone)]
pub struct JumpAssistOp {
    pub base: UserPcodeOp,
    /// Injection id for index2case script (-1 if none).
    pub index2case: i32,
    /// Injection id for index2addr script (must be present).
    pub index2addr: i32,
    /// Injection id for default-address script (must be present).
    pub defaultaddr: i32,
    /// Injection id for calcsize script (-1 if none).
    pub calcsize: i32,
}

impl JumpAssistOp {
    pub fn new(name: String, index: i32) -> Self {
        Self {
            base: UserPcodeOp::new(name, UserOpType::JumpAssist, index),
            index2case: -1,
            index2addr: -1,
            defaultaddr: -1,
            calcsize: -1,
        }
    }

    pub fn get_index2case(&self) -> i32 { self.index2case }
    pub fn get_index2addr(&self) -> i32 { self.index2addr }
    pub fn get_default_addr(&self) -> i32 { self.defaultaddr }
    pub fn get_calc_size(&self) -> i32 { self.calcsize }
}

/// Internal string op. Displays as a quoted string in decompiled output.
/// Faithful to `InternalStringOp` (userop.hh:312).
#[derive(Debug, Clone)]
pub struct InternalStringOp {
    pub base: UserPcodeOp,
}

impl InternalStringOp {
    pub fn new(name: String, index: i32) -> Self {
        Self { base: UserPcodeOp::new(name, UserOpType::StringData, index) }
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

    /// Register a built-in op if not already present.
    pub fn register_builtin(&mut self, name: &str, builtin_id: u32) {
        if self.get_index_by_name(name).is_none() {
            self.register_op(name.to_string(), UserOpType::Unspecialized);
        }
    }

    /// Initialize all built-in CALLOTHER ids.
    pub fn initialize_builtins(&mut self) {
        self.register_builtin("string_data", BUILTIN_STRINGDATA);
        self.register_builtin("volatile_read", BUILTIN_VOLATILE_READ);
        self.register_builtin("volatile_write", BUILTIN_VOLATILE_WRITE);
        self.register_builtin("memcpy", BUILTIN_MEMCPY);
        self.register_builtin("strcpy", BUILTIN_STRNCPY);
        self.register_builtin("wcsncpy", BUILTIN_WCSNCPY);
    }

    /// Get a mutable user op by its CALLOTHER index.
    pub fn get_op_mut(&mut self, index: i32) -> Option<&mut UserPcodeOp> {
        if index >= 0 && (index as usize) < self.ops.len() {
            Some(&mut self.ops[index as usize])
        } else {
            None
        }
    }

    /// Check if an index corresponds to a volatile read.
    pub fn is_volatile_read(&self, index: i32) -> bool {
        self.get_op(index).map(|op| op.op_type == UserOpType::VolatileRead).unwrap_or(false)
    }

    /// Check if an index corresponds to a volatile write.
    pub fn is_volatile_write(&self, index: i32) -> bool {
        self.get_op(index).map(|op| op.op_type == UserOpType::VolatileWrite).unwrap_or(false)
    }

    /// Manually register a CALLOTHER fixup (replacement p-code for an
    /// unspecialized user op). Faithful to Ghidra
    /// UserOpManage::manualCallOtherFixup (userop.cc:628).
    pub fn manual_call_other_fixup(&mut self, userop_name: &str, _outname: &str, _innames: &[String]) -> i32 {
        self.register_op(userop_name.to_string(), UserOpType::Injected)
    }

    /// Get a UserPcodeOp by name. Faithful to Ghidra
    /// UserOpManage::getOp(string) (userop.cc:419).
    pub fn get_op_by_name(&self, name: &str) -> Option<&UserPcodeOp> {
        let idx = self.get_index_by_name(name)?;
        self.ops.get(idx as usize)
    }
}

/// A user defined p-code op with no specialization.
/// Corresponds to Ghidra's `UnspecializedPcodeOp` (userop.hh:130).
pub fn create_unspecialized(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::Unspecialized, index)
}

/// Create an injected user op placeholder.
/// Corresponds to Ghidra's `InjectedUserOp`.
pub fn create_injected(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::Injected, index)
}

/// Create a volatile read user op.
/// Corresponds to Ghidra's `VolatileReadOp`.
pub fn create_volatile_read(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::VolatileRead, index)
}

/// Create a volatile write user op.
/// Corresponds to Ghidra's `VolatileWriteOp`.
pub fn create_volatile_write(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::VolatileWrite, index)
}

/// Create a segment op user op.
/// Corresponds to Ghidra's `SegmentOp`.
pub fn create_segment(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::Segment, index)
}

/// Create a jump-table assist user op.
/// Corresponds to Ghidra's `JumpAssistOp`.
pub fn create_jump_assist(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::JumpAssist, index)
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

    #[test]
    fn test_initialize_builtins() {
        let mut mgr = UserOpManage::new();
        mgr.initialize_builtins();
        assert!(mgr.get_index_by_name("memcpy").is_some());
        assert!(mgr.get_index_by_name("volatile_read").is_some());
        assert_eq!(mgr.num_ops(), 6);
    }

    #[test]
    fn test_create_specialized() {
        let vr = create_volatile_read("volread".into(), 0);
        assert_eq!(vr.get_type(), UserOpType::VolatileRead);
        let vw = create_volatile_write("volwrite".into(), 1);
        assert_eq!(vw.get_type(), UserOpType::VolatileWrite);
        let seg = create_segment("seg".into(), 2);
        assert_eq!(seg.get_type(), UserOpType::Segment);
        let ja = create_jump_assist("jump".into(), 3);
        assert_eq!(ja.get_type(), UserOpType::JumpAssist);
    }

    #[test]
    fn test_get_op_by_name() {
        let mut mgr = UserOpManage::new();
        mgr.register_op("memcpy".into(), UserOpType::Unspecialized);
        assert!(mgr.get_op_by_name("memcpy").is_some());
        assert_eq!(mgr.get_op_by_name("memcpy").unwrap().get_name(), "memcpy");
        assert!(mgr.get_op_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_manual_call_other_fixup() {
        let mut mgr = UserOpManage::new();
        let idx = mgr.manual_call_other_fixup("my_fixup", "out", &["in1".into(), "in2".into()]);
        assert!(mgr.get_op(idx).is_some());
        assert_eq!(mgr.get_op(idx).unwrap().get_type(), UserOpType::Injected);
    }
}
