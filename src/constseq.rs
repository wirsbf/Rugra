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

    /// Construct from a root op.
    pub fn new(root_op: Arc<RwLock<PcodeOp>>) -> Self {
        Self {
            fd: std::ptr::null_mut(),
            root_op,
            char_type: None,
            num_elements: 0,
            move_ops: Vec::new(),
            byte_array: Vec::new(),
        }
    }

    /// Sort move_ops by their op's sequence order.
    pub fn sort_ops(&mut self) {
        self.move_ops.sort_by(|a, b| {
            let a_order = a.op.read().unwrap().start.get_order() as u64;
            let b_order = b.op.read().unwrap().start.get_order() as u64;
            a_order.cmp(&b_order)
        });
    }

    /// Form a byte array from constant COPYs in move_ops.
    /// Corresponds to `ArraySequence::formByteArray` (constseq.cc).
    pub fn form_byte_array(&mut self) -> i32 {
        self.byte_array.clear();
        for node in &self.move_ops {
            let op = node.op.read().unwrap();
            // COPY of a constant into the array region
            if op.opcode == OpCode::CPUI_COPY {
                if let Some(in0) = op.inrefs.first() {
                    let vn = in0.read().unwrap();
                    if vn.is_constant() {
                        let val = vn.get_offset();
                        // Only take the low byte (char type)
                        self.byte_array.push((val & 0xff) as u8);
                    } else {
                        return 0; // Non-constant, can't form byte array
                    }
                }
            } else {
                return 0; // Non-COPY op, can't form byte array
            }
        }
        self.byte_array.len() as i32
    }

    /// Check if the byte array represents a valid string (null-terminated).
    pub fn is_valid_string(&self) -> bool {
        if self.byte_array.is_empty() { return false; }
        if self.byte_array.len() < MINIMUM_SEQUENCE_LENGTH as usize { return false; }
        // Must have at least one null terminator
        self.byte_array.contains(&0)
    }

    /// Get the string content (up to first null).
    pub fn get_string(&self) -> Option<&[u8]> {
        let pos = self.byte_array.iter().position(|&b| b == 0)?;
        Some(&self.byte_array[..pos])
    }

    /// Select the appropriate string copy function based on element size.
    /// Corresponds to `ArraySequence::selectStringCopyFunction` (constseq.cc).
    pub fn select_string_copy_function(&self) -> &'static str {
        let char_size = self.char_type.as_ref().map(|t| t.get_size()).unwrap_or(1);
        match char_size {
            1 => "strncpy",
            2 => "wcsncpy",
            _ => "memcpy",
        }
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

    #[test]
    fn test_array_sequence_byte_array() {
        use crate::address::{Address, SeqNum};
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_COPY,
        ))));
        // Add 5 COPY ops with constant inputs "Hello"
        for (i, &ch) in b"Hello\0".iter().enumerate() {
            let op = Arc::new(RwLock::new(PcodeOp::new(
                SeqNum::new(Address::new(0x1000 + i as u64), 0), OpCode::CPUI_COPY,
            )));
            let const_vn = Arc::new(RwLock::new(crate::varnode::Varnode::new_constant(ch as u64, 1)));
            op.write().unwrap().inrefs.push(const_vn);
            seq.move_ops.push(WriteNode::new(i as u64, op, 0));
        }
        let count = seq.form_byte_array();
        assert_eq!(count, 6);
        assert!(seq.is_valid_string());
        assert_eq!(seq.get_string().unwrap(), b"Hello");
    }

    #[test]
    fn test_select_string_copy_function() {
        let seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        ))));
        assert_eq!(seq.select_string_copy_function(), "strncpy"); // default char size = 1
    }
}
