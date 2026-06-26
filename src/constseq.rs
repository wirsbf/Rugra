//! Constant sequence analysis: combining COPY/STORE ops into string copies.
//!
//! Corresponds to Ghidra's `constseq.hh` / `constseq.cc` (1146 lines).
//!
//! This module detects sequences of COPY or STORE operations that write
//! constant characters to a contiguous memory region, and replaces them
//! with a single `strncpy`/`wcsncpy`/`memcpy` CALLOTHER.
//!
//! Key classes:
//! - `ArraySequence`: base class collecting a maximal set of sequential ops
//! - `StringSequence`: for COPY ops writing to a stack/local array
//! - `HeapSequence`: for STORE ops writing through a heap pointer
//! - `RuleStringCopy`: rule triggering on COPY ops
//! - `RuleStringStore`: rule triggering on STORE ops
//!
//! # Status
//! Skeleton with data structures (WriteNode, ArraySequence, StringSequence,
//! HeapSequence). The full analysis (collectCopyOps/collectStoreOps/
//! transform) requires Symbol/SymbolEntry infrastructure.

use std::sync::{Arc, RwLock};
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::funcdata::Funcdata;
use crate::type_system::Datatype;
use crate::action::{Rule, action_status};
use crate::error::Result;

/// Minimum number of sequential characters to trigger replacement.
pub const MINIMUM_SEQUENCE_LENGTH: i32 = 4;
/// Maximum number of characters in replacement string.
pub const MAXIMUM_SEQUENCE_LENGTH: i32 = 1024;

/// Helper class holding a data-flow edge and optionally a memory offset.
/// Corresponds to Ghidra's `ArraySequence::WriteNode` (constseq.hh:34).
#[derive(Clone, Debug)]
pub struct WriteNode {
    /// Offset into the memory region
    pub offset: u64,
    /// PcodeOp moving into/out of memory region
    pub op: Arc<RwLock<PcodeOp>>,
    /// Input slot (>=0) or output (-1)
    pub slot: i32,
}

impl WriteNode {
    pub fn new(offset: u64, op: Arc<RwLock<PcodeOp>>, slot: i32) -> Self {
        Self { offset, op, slot }
    }
}

/// A sequence of PcodeOps that move data into/out of an array data-type.
/// Corresponds to Ghidra's `ArraySequence` (constseq.hh:29).
pub struct ArraySequence {
    /// The function containing the sequence
    pub fd: *mut Funcdata,
    /// The root PcodeOp
    pub root_op: Arc<RwLock<PcodeOp>>,
    /// Element data-type
    pub char_type: Option<Arc<Datatype>>,
    /// Number of elements in the final sequence (0 = not found)
    pub num_elements: i32,
    /// COPY/STORE ops into the array memory region
    pub move_ops: Vec<WriteNode>,
    /// Constants collected in a single byte array
    pub byte_array: Vec<u8>,
}

impl ArraySequence {
    /// Return true if a valid sequence was found.
    pub fn is_valid(&self) -> bool {
        self.num_elements != 0
    }
}

/// A class for collecting sequences of COPY ops writing characters to a string.
/// Corresponds to Ghidra's `StringSequence` (constseq.hh:66).
pub struct StringSequence {
    /// Base ArraySequence
    pub base: ArraySequence,
}

/// A sequence of STORE operations writing characters through a string pointer.
/// Corresponds to Ghidra's `HeapSequence` (constseq.hh:86).
pub struct HeapSequence {
    /// Base ArraySequence
    pub base: ArraySequence,
    /// Pointer that sequence is stored to
    pub base_pointer: Option<Arc<RwLock<Varnode>>>,
    /// Offset relative to pointer to root STORE
    pub base_offset: u64,
}

/// Rule triggering on COPY ops to detect string copy sequences.
/// Corresponds to Ghidra's `RuleStringCopy` (constseq.hh:119).
pub struct RuleStringCopy;

impl RuleStringCopy {
    pub fn new() -> Self { Self }
}

impl Rule for RuleStringCopy {
    fn apply_op(&self, _op: &Arc<RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        // TODO: requires Symbol/SymbolEntry infrastructure to detect
        // character array writes and build the string copy CALLOTHER.
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str { "string_copy" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_COPY] }
}

/// Rule triggering on STORE ops to detect heap string store sequences.
/// Corresponds to Ghidra's `RuleStringStore` (constseq.hh:130).
pub struct RuleStringStore;

impl RuleStringStore {
    pub fn new() -> Self { Self }
}

impl Rule for RuleStringStore {
    fn apply_op(&self, _op: &Arc<RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        // TODO: requires heap pointer analysis + INDIRECT pair tracking.
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str { "string_store" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_STORE] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MINIMUM_SEQUENCE_LENGTH, 4);
        assert!(MAXIMUM_SEQUENCE_LENGTH > 100);
    }

    #[test]
    fn test_rule_names() {
        assert_eq!(RuleStringCopy::new().get_name(), "string_copy");
        assert_eq!(RuleStringStore::new().get_name(), "string_store");
    }
}
