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

/// Built-in CALLOTHER ids. Faithful to `UserPcodeOp::BUILTIN_*`
/// (userop.cc:30-35). These are large, distinct values used as the
/// CALLOTHER constant id passed in input[0] of a CPUI_CALLOTHER op.
pub const BUILTIN_STRINGDATA: u32 = 0x1000_0000;
pub const BUILTIN_VOLATILE_READ: u32 = 0x1000_0001;
pub const BUILTIN_VOLATILE_WRITE: u32 = 0x1000_0002;
/// Built-in id for `memcpy`. Used by RuleStringStore.
pub const BUILTIN_MEMCPY: u32 = 0x1000_0003;
/// Built-in id for `strncpy` (Ghidra names it "strcpy"). Used by
/// RuleStringCopy for 1-byte (char) elements.
pub const BUILTIN_STRNCPY: u32 = 0x1000_0004;
/// Built-in id for `wcsncpy`. Used by RuleStringCopy for 2-byte
/// (wchar_t) elements.
pub const BUILTIN_WCSNCPY: u32 = 0x1000_0005;

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
    /// The address space this segment op operates on. Faithful to the
    /// `spc` field (userop.hh:265).
    pub space: u32,
    /// Base resolution: how the segment base is computed.
    pub supports_index: bool,
    /// True if the joined pair base:near acts as a far pointer. Faithful to
    /// `supportsfarpointer` (userop.hh:269); set by the `farpointer="yes"`
    /// attribute in `<segmentop>` (userop.cc:240 `ATTRIB_FARPOINTER`).
    pub supports_far_pointer: bool,
}

impl SegmentOp {
    pub fn new(name: String, index: i32) -> Self {
        Self {
            base: UserPcodeOp::new(name, UserOpType::Segment, index),
            space: 0,
            supports_index: false,
            supports_far_pointer: false,
        }
    }

    /// Return true if this op supports far pointers. Faithful to
    /// `SegmentOp::hasFarPointerSupport` (userop.hh:274).
    pub fn has_far_pointer_support(&self) -> bool {
        self.supports_far_pointer
    }

    /// Constant-fold a SEGMENTOP given constant inputs.
    ///
    /// Faithful to `SegmentOp::execute` (userop.cc:218-223). Ghidra evaluates
    /// the `<pcode>` body of the `<segmentop>` via `pcodeinjectlib`:
    ///   `ExecutablePcode *script = getPayload(injectId); return script->evaluate(input);`
    /// Rugra has no pcode-inject engine, so we evaluate the canonical
    /// segmented-address formula directly. For the only architecture Rugra
    /// models a segment on (x86 16-bit real mode, see
    /// `x86-16-real.pspec`/`x86-16.pspec`), the injected p-code is:
    ///   `res = (zext(base) << 4) + zext(inner);`
    /// i.e. `linear = (selector << 4) + offset`. This is the general
    /// real-mode form `segment_base + offset` with a fixed `base << 4`
    /// shift, matching Ghidra's bundled cspec definitions.
    ///
    /// Inputs follow Ghidra's `bindlist` ordering (userop.cc:198-215): with a
    /// base term present, `[base, inner]`; with no base term, `[inner]` only.
    /// Returns `None` if the input arity does not match a recognised segment
    /// form (Ghidra always has 1 or 2 inputs, declared in `decode`,
    /// userop.cc:280-289).
    pub fn execute(&self, inputs: &[u64]) -> Option<u64> {
        match inputs.len() {
            // base term present: linear = (base << 4) + inner
            2 => Some((inputs[0] << 4).wrapping_add(inputs[1])),
            // no base term (near pointer): linear = inner
            1 => Some(inputs[0]),
            _ => None,
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
    /// Segment ops registered by space index. Faithful to the segment-op
    /// vector in Ghidra's UserOpManage (userop.hh:347 `getSegmentOp`).
    pub segment_ops: HashMap<i32, SegmentOp>,
    /// Built-in id (BUILTIN_*) → user op. Faithful to Ghidra's
    /// `UserOpManage::builtinmap` (userop.hh:342), populated by
    /// `registerBuiltin(uint4)` (userop.cc:432-484).
    pub builtin_map: HashMap<u32, UserPcodeOp>,
}

impl UserOpManage {
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            name_map: HashMap::new(),
            segment_ops: HashMap::new(),
            builtin_map: HashMap::new(),
        }
    }

    /// Look up the SegmentOp for the given space index. Faithful to
    /// `UserOpManage::getSegmentOp` (userop.hh:347).
    pub fn get_segment_op(&self, space_idx: i32) -> Option<&SegmentOp> {
        self.segment_ops.get(&space_idx)
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

    /// Ensure an active record exists for the given built-in op id. Faithful
    /// to Ghidra `UserOpManage::registerBuiltin(uint4)` (userop.cc:432-484).
    /// The built-in id (one of the `BUILTIN_*` constants) is stored in
    /// `builtin_map` and returned as the CALLOTHER constant index. Idempotent:
    /// repeated calls return the same id.
    pub fn register_builtin_by_id(&mut self, builtin_id: u32) -> u32 {
        if self.builtin_map.contains_key(&builtin_id) {
            return builtin_id;
        }
        let (name, op_type) = match builtin_id {
            BUILTIN_STRINGDATA => ("builtin_string_data", UserOpType::StringData),
            BUILTIN_VOLATILE_READ => ("read_volatile", UserOpType::VolatileRead),
            BUILTIN_VOLATILE_WRITE => ("write_volatile", UserOpType::VolatileWrite),
            BUILTIN_MEMCPY => ("builtin_memcpy", UserOpType::StringData),
            BUILTIN_STRNCPY => ("builtin_strncpy", UserOpType::StringData),
            BUILTIN_WCSNCPY => ("builtin_wcsncpy", UserOpType::StringData),
            _ => ("builtin_unknown", UserOpType::Unspecialized),
        };
        let op = UserPcodeOp::new(name.to_string(), op_type, builtin_id as i32);
        self.builtin_map.insert(builtin_id, op);
        builtin_id
    }

    /// Register the string-copy (`strncpy`/`wcsncpy`) CALLOTHER and return its
    /// CALLOTHER constant index. Used by RuleStringCopy. Faithful to the
    /// `glb->userops.registerBuiltin(BUILTIN_STRNCPY)` call embedded in
    /// `StringSequence::buildStringCopy` (constseq.cc:360).
    ///
    /// `char_size` selects the function: 1 → strncpy (BUILTIN_STRNCPY),
    /// 2 → wcsncpy (BUILTIN_WCSNCPY).
    pub fn register_string_copy_op(&mut self, char_size: i32) -> u32 {
        let builtin_id = if char_size == 2 { BUILTIN_WCSNCPY } else { BUILTIN_STRNCPY };
        self.register_builtin_by_id(builtin_id)
    }

    /// Register the string-store (`memcpy`) CALLOTHER and return its CALLOTHER
    /// constant index. Used by RuleStringStore. Faithful to the
    /// `registerBuiltin(BUILTIN_MEMCPY)` call embedded in
    /// `HeapSequence::buildStringCopy` (constseq.cc:751).
    pub fn register_string_store_op(&mut self) -> u32 {
        self.register_builtin_by_id(BUILTIN_MEMCPY)
    }

    /// Look up the CALLOTHER name for a given constant id. Faithful to
    /// `UserOpManage::getOp(uint4)->getName()`. Checks built-ins first, then
    /// the by-index list.
    pub fn get_call_other_name(&self, index: u32) -> Option<&str> {
        // Built-in ids are large sentinel values (0x1000_00xx); small values
        // index the registered list.
        if index >= 0x1000_0000 {
            return self.builtin_map.get(&index).map(|op| op.name.as_str());
        }
        self.get_op(index as i32).map(|op| op.name.as_str())
    }

    /// Register a built-in op if not already present.
    pub fn register_builtin(&mut self, name: &str, builtin_id: u32) {
        if self.get_index_by_name(name).is_none() {
            self.register_op(name.to_string(), UserOpType::Unspecialized);
        }
        // Also keep the faithful by-id record in sync.
        self.register_builtin_by_id(builtin_id);
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
        // Faithful to Ghidra userop.cc:30-35.
        assert_eq!(BUILTIN_MEMCPY, 0x1000_0003);
        assert_eq!(BUILTIN_VOLATILE_READ, 0x1000_0001);
        assert_eq!(BUILTIN_STRNCPY, 0x1000_0004);
        assert_eq!(BUILTIN_WCSNCPY, 0x1000_0005);
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
    fn test_register_builtin_by_id() {
        let mut mgr = UserOpManage::new();
        // Faithful to Ghidra registerBuiltin (userop.cc:432-484).
        let id = mgr.register_builtin_by_id(BUILTIN_STRNCPY);
        assert_eq!(id, BUILTIN_STRNCPY);
        // Idempotent.
        let id2 = mgr.register_builtin_by_id(BUILTIN_STRNCPY);
        assert_eq!(id2, BUILTIN_STRNCPY);
        // Name lookup.
        assert_eq!(mgr.get_call_other_name(BUILTIN_STRNCPY), Some("builtin_strncpy"));
        assert_eq!(mgr.get_call_other_name(BUILTIN_MEMCPY), None);
    }

    #[test]
    fn test_register_string_copy_store_op() {
        let mut mgr = UserOpManage::new();
        // RuleStringCopy selects strncpy for 1-byte chars, wcsncpy for 2-byte.
        let sc1 = mgr.register_string_copy_op(1);
        assert_eq!(sc1, BUILTIN_STRNCPY);
        assert_eq!(mgr.get_call_other_name(sc1), Some("builtin_strncpy"));
        let sc2 = mgr.register_string_copy_op(2);
        assert_eq!(sc2, BUILTIN_WCSNCPY);
        assert_eq!(mgr.get_call_other_name(sc2), Some("builtin_wcsncpy"));
        // RuleStringStore selects memcpy.
        let ss = mgr.register_string_store_op();
        assert_eq!(ss, BUILTIN_MEMCPY);
        assert_eq!(mgr.get_call_other_name(ss), Some("builtin_memcpy"));
    }

    #[test]
    fn test_get_call_other_name_indexed() {
        let mut mgr = UserOpManage::new();
        let idx = mgr.register_op("custom_op".into(), UserOpType::Unspecialized);
        // Small ids index the registered list.
        assert_eq!(mgr.get_call_other_name(idx as u32), Some("custom_op"));
        // Large sentinel ids check the builtin map.
        assert_eq!(mgr.get_call_other_name(BUILTIN_VOLATILE_WRITE), None);
        mgr.register_builtin_by_id(BUILTIN_VOLATILE_WRITE);
        assert_eq!(mgr.get_call_other_name(BUILTIN_VOLATILE_WRITE), Some("write_volatile"));
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

    #[test]
    fn test_segment_op_execute() {
        // Faithful to SegmentOp::execute (userop.cc:218-223) via the canonical
        // x86-16 real-mode formula res = (base << 4) + inner, matching the
        // injected p-code in x86-16-real.pspec / x86-16.pspec.
        let seg = SegmentOp::new("segment".into(), 0);
        // base=0x1234, inner=0x0002 -> (0x1234 << 4) + 2 = 0x12342.
        assert_eq!(seg.execute(&[0x1234, 0x0002]), Some(0x12342));
        // base=0x2000, inner=0x0010 -> 0x20010.
        assert_eq!(seg.execute(&[0x2000, 0x0010]), Some(0x20010));
        // base=0, inner=5 -> 5 (zero segment).
        assert_eq!(seg.execute(&[0, 5]), Some(5));
        // Near-pointer form (no base term): linear = inner.
        assert_eq!(seg.execute(&[0x1234]), Some(0x1234));
        // Wrapping arithmetic: (0xFFF...F << 4) + 0x10 overflows u64 to 0.
        assert_eq!(seg.execute(&[u64::MAX >> 4, 0x10]), Some(0));
        // Unrecognised arity -> None (Ghidra always declares 1 or 2 inputs).
        assert_eq!(seg.execute(&[]), None);
        assert_eq!(seg.execute(&[1, 2, 3]), None);
    }

    #[test]
    fn test_segment_op_far_pointer_support() {
        // Faithful to SegmentOp::hasFarPointerSupport (userop.hh:274) and the
        // `supportsfarpointer` field (userop.hh:269).
        let mut seg = SegmentOp::new("segment".into(), 0);
        assert!(!seg.has_far_pointer_support());
        seg.supports_far_pointer = true; // set by farpointer="yes" attribute
        assert!(seg.has_far_pointer_support());
    }
}
