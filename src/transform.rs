//! Large-scale data-flow transforms: lane splitting and Dolphin transforms.
//!
//! Corresponds to Ghidra's `transform.hh` / `transform.cc` (1023 lines).
//!
//! This module provides the infrastructure for building large-scale transforms
//! of function data-flow. The main use case is lane splitting — decomposing
//! large register operations into smaller logical "lanes".
//!
//! Key classes:
//! - `LanedRegister`: describes how a register can be split into lane sizes
//! - `LaneDescription`: specific lane layout within a varnode
//! - `TransformVar`: placeholder for a varnode that will exist after transform
//! - `TransformOp`: placeholder for a pcode op that will exist after transform
//! - `TransformManager`: orchestrates the transform lifecycle
//!
//! # Status
//! Skeleton with `LanedRegister`, `LaneDescription`, and basic data structures.
//! The full `TransformManager` (createOps/createVarnodes/apply) requires
//! Funcdata op-edit integration which is now available.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::funcdata::Funcdata;
use crate::address::Address;

/// Describes a register storage location and the ways it might be split into lanes.
/// Corresponds to Ghidra's `LanedRegister` (transform.hh:94).
#[derive(Debug, Clone)]
pub struct LanedRegister {
    /// Size of the whole register in bytes
    pub whole_size: i32,
    /// Bit mask: bit N set means size N is an allowed lane size
    pub size_bit_mask: u32,
}

impl LanedRegister {
    pub fn new() -> Self {
        Self { whole_size: 0, size_bit_mask: 0 }
    }

    pub fn with_sizes(sz: i32, mask: u32) -> Self {
        Self { whole_size: sz, size_bit_mask: mask }
    }

    /// Add a new lane size to the allowed list.
    pub fn add_lane_size(&mut self, size: i32) {
        self.size_bit_mask |= 1u32 << size;
    }

    /// Is `size` among the allowed lane sizes?
    pub fn allowed_lane(&self, size: i32) -> bool {
        (self.size_bit_mask >> size) & 1 != 0
    }

    /// Get the whole register size.
    pub fn get_whole_size(&self) -> i32 { self.whole_size }

    /// Get the bit mask of possible lane sizes.
    pub fn get_size_bit_mask(&self) -> u32 { self.size_bit_mask }

    /// Iterate over all allowed lane sizes.
    pub fn lane_sizes(&self) -> Vec<i32> {
        let mut result = Vec::new();
        let mut mask = self.size_bit_mask;
        let mut size = 0i32;
        while mask != 0 {
            if mask & 1 != 0 {
                result.push(size);
            }
            mask >>= 1;
            size += 1;
        }
        result
    }
}

/// Description of logical lanes within a big Varnode.
/// Corresponds to Ghidra's `LaneDescription` (transform.hh:132).
#[derive(Debug, Clone)]
pub struct LaneDescription {
    /// Size of the region being split in bytes
    pub whole_size: i32,
    /// Size of each lane in bytes
    pub lane_size: Vec<i32>,
    /// Byte position of each lane
    pub lane_position: Vec<i32>,
}

impl LaneDescription {
    /// Construct uniform lanes: split `orig_size` into lanes of size `sz`.
    pub fn uniform(orig_size: i32, sz: i32) -> Self {
        let num = orig_size / sz;
        let mut positions = Vec::with_capacity(num as usize);
        for i in 0..num {
            positions.push(i * sz);
        }
        Self {
            whole_size: orig_size,
            lane_size: vec![sz; num as usize],
            lane_position: positions,
        }
    }

    /// Construct two lanes of arbitrary sizes (lo and hi).
    pub fn two_lane(orig_size: i32, lo: i32, hi: i32) -> Self {
        Self {
            whole_size: orig_size,
            lane_size: vec![lo, hi],
            lane_position: vec![0, lo],
        }
    }

    /// Get the total number of lanes.
    pub fn get_num_lanes(&self) -> usize { self.lane_size.len() }

    /// Get the size of the i-th lane.
    pub fn get_size(&self, i: usize) -> i32 { self.lane_size[i] }

    /// Get the position of the i-th lane.
    pub fn get_position(&self, i: usize) -> i32 { self.lane_position[i] }

    /// Get the size of the whole region.
    pub fn get_whole_size(&self) -> i32 { self.whole_size }
}

/// Types of replacement Varnodes (transform.hh:36-43).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransformVarType {
    /// New Varnode is a piece of an original Varnode
    Piece,
    /// Varnode preexisted in the original data-flow
    Preexisting,
    /// A new temporary (unique space) Varnode
    NormalTemp,
    /// A temporary representing a piece of an original Varnode
    PieceTemp,
    /// A new constant Varnode
    Constant,
    /// Special iop constant encoding a PcodeOp reference
    ConstantIop,
}

/// Placeholder for a Varnode that will exist after a transform is applied.
/// Corresponds to Ghidra's `TransformVar`.
#[derive(Debug)]
pub struct TransformVar {
    /// Original big Varnode of which this is a component
    pub original: Option<Arc<RwLock<Varnode>>>,
    /// The new replacement Varnode
    pub replacement: Option<Arc<RwLock<Varnode>>>,
    /// Type of new Varnode
    pub var_type: TransformVarType,
    /// Byte size of the lane Varnode
    pub byte_size: i32,
    /// Bit position within the original big Varnode
    pub val: u64,
    /// Byte offset within the original Varnode
    pub lsb_offset: i32,
}

impl TransformVar {
    pub fn new_preexisting(vn: Arc<RwLock<Varnode>>) -> Self {
        Self {
            original: Some(vn),
            replacement: None,
            var_type: TransformVarType::Preexisting,
            byte_size: 0,
            val: 0,
            lsb_offset: 0,
        }
    }

    pub fn new_unique(size: i32) -> Self {
        Self {
            original: None,
            replacement: None,
            var_type: TransformVarType::NormalTemp,
            byte_size: size,
            val: 0,
            lsb_offset: 0,
        }
    }

    pub fn new_constant(size: i32, lsb_offset: i32, val: u64) -> Self {
        Self {
            original: None,
            replacement: None,
            var_type: TransformVarType::Constant,
            byte_size: size,
            val,
            lsb_offset,
        }
    }

    pub fn new_piece(vn: Arc<RwLock<Varnode>>, byte_size: i32, lsb_offset: i32) -> Self {
        Self {
            original: Some(vn),
            replacement: None,
            var_type: TransformVarType::Piece,
            byte_size,
            val: 0,
            lsb_offset,
        }
    }
}

/// Placeholder for a PcodeOp that will exist after a transform.
/// Corresponds to Ghidra's `TransformOp`.
#[derive(Debug)]
pub struct TransformOp {
    /// Original op which this is splitting (or None)
    pub original: Option<Arc<RwLock<PcodeOp>>>,
    /// Opcode of the new op
    pub opc: OpCode,
    /// Output placeholder variable
    pub output: Option<Box<TransformVar>>,
    /// Input placeholder variables
    pub inputs: Vec<TransformVar>,
    /// The following op (for insertion ordering)
    pub follow: Option<Arc<RwLock<PcodeOp>>>,
}

impl TransformOp {
    pub fn new(num_params: usize, opc: OpCode) -> Self {
        Self {
            original: None,
            opc,
            output: None,
            inputs: Vec::with_capacity(num_params),
            follow: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laned_register() {
        let lr = LanedRegister::with_sizes(16, 0b1010); // sizes 1 and 3
        assert!(lr.allowed_lane(1));
        assert!(lr.allowed_lane(3));
        assert!(!lr.allowed_lane(2));
        assert_eq!(lr.lane_sizes(), vec![1, 3]);
    }

    #[test]
    fn test_lane_description_uniform() {
        let ld = LaneDescription::uniform(8, 2);
        assert_eq!(ld.get_num_lanes(), 4);
        assert_eq!(ld.get_size(0), 2);
        assert_eq!(ld.get_position(2), 4);
    }

    #[test]
    fn test_lane_description_two_lane() {
        let ld = LaneDescription::two_lane(4, 1, 3);
        assert_eq!(ld.get_num_lanes(), 2);
        assert_eq!(ld.get_size(0), 1);
        assert_eq!(ld.get_size(1), 3);
        assert_eq!(ld.get_position(1), 1);
    }
}
