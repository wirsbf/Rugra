//! Subflow analysis: shrinking big Varnodes carrying smaller logical values.
//!
//! Corresponds to Ghidra's `subflow.hh` / `subflow.cc` (4589 lines).
//!
//! Given a root Varnode and a logical variable size, this class traces the
//! flow of the logical variable through the data-flow graph, building a
//! subgraph that can replace the operations on the container Varnode with
//! operations on the smaller logical value.
//!
//! Key class: `SubvariableFlow` — the analysis engine.
//!
//! # Status
//! Skeleton with data structures (ReplaceVarnode/ReplaceOp/PatchRecord).
//! The full analysis (traceForward/traceBackward/doReplacement) requires
//! Funcdata op-edit integration which is now available.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::funcdata::Funcdata;

/// Placeholder for a Varnode holding a smaller logical value.
/// Corresponds to Ghidra's `SubvariableFlow::ReplaceVarnode`.
#[derive(Debug)]
pub struct ReplaceVarnode {
    /// Varnode being shrunk (None for constants)
    pub vn: Option<Arc<RwLock<Varnode>>>,
    /// The new smaller replacement Varnode
    pub replacement: Option<Arc<RwLock<Varnode>>>,
    /// Bits making up the logical sub-variable
    pub mask: u64,
    /// Value of constant (when vn is None)
    pub val: u64,
}

/// Placeholder for a PcodeOp operating on smaller logical values.
/// Corresponds to Ghidra's `SubvariableFlow::ReplaceOp`.
#[derive(Debug)]
pub struct ReplaceOp {
    /// Op getting paralleled
    pub op: Option<Arc<RwLock<PcodeOp>>>,
    /// The new replacement op
    pub replacement: Option<Arc<RwLock<PcodeOp>>>,
    /// Opcode of the new op
    pub opc: OpCode,
    /// Number of parameters in the new op
    pub num_params: usize,
    /// Varnode output
    pub output: Option<Box<ReplaceVarnode>>,
    /// Varnode inputs
    pub inputs: Vec<ReplaceVarnode>,
}

/// Types of patches on ops being performed.
/// Corresponds to Ghidra's `SubvariableFlow::PatchRecord::patchtype`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatchType {
    /// Turn op into a COPY of the logical value
    CopyPatch,
    /// Turn compare op inputs into logical values
    ComparePatch,
    /// Convert a CALL/CALLIND/RETURN/BRANCHIND parameter
    ParameterPatch,
    /// Convert op into something that copies/extends logical value
    ExtensionPatch,
    /// Convert an operator output to the logical value
    PushPatch,
    /// Zero extend logical value into FLOAT_INT2FLOAT operator
    Int2FloatPatch,
}

/// Operation with a new logical value as input, but output is unchanged.
/// Corresponds to Ghidra's `SubvariableFlow::PatchRecord`.
#[derive(Debug)]
pub struct PatchRecord {
    pub patch_type: PatchType,
    pub patch_op: Arc<RwLock<PcodeOp>>,
    pub in1: Option<ReplaceVarnode>,
    pub in2: Option<ReplaceVarnode>,
    pub slot: i32,
}

/// Class for shrinking big Varnodes carrying smaller logical values.
/// Corresponds to Ghidra's `SubvariableFlow` (subflow.hh:42).
pub struct SubvariableFlow {
    /// Size of the logical data-flow in bytes
    pub flow_size: i32,
    /// Number of bits in logical variable
    pub bit_size: i32,
    /// Have we tried to flow across RETURNs
    pub returns_traversed: bool,
    /// Do we "know" the seed point must be a sub variable
    pub aggressive: bool,
    /// Check for sign-extended logical variables
    pub sext_restrictions: bool,
    /// Number of instructions pulling out the logical value
    pub pull_count: i32,
    /// Map from original Varnode Arc ptr to ReplaceVarnode index
    var_map: BTreeMap<usize, usize>,
    /// Storage for subgraph variable nodes
    new_vars: Vec<ReplaceVarnode>,
    /// Storage for subgraph op nodes
    new_ops: Vec<ReplaceOp>,
    /// Operations getting patched
    patch_list: Vec<PatchRecord>,
}

impl SubvariableFlow {
    /// Construct with the given logical variable size.
    pub fn new(flow_size: i32, aggressive: bool, sext: bool) -> Self {
        Self {
            flow_size,
            bit_size: flow_size * 8,
            returns_traversed: false,
            aggressive,
            sext_restrictions: sext,
            pull_count: 0,
            var_map: BTreeMap::new(),
            new_vars: Vec::new(),
            new_ops: Vec::new(),
            patch_list: Vec::new(),
        }
    }

    /// Get the flow size.
    pub fn get_flow_size(&self) -> i32 { self.flow_size }

    /// Get the bit size.
    pub fn get_bit_size(&self) -> i32 { self.bit_size }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subvariable_flow_creation() {
        let sf = SubvariableFlow::new(1, false, false);
        assert_eq!(sf.get_flow_size(), 1);
        assert_eq!(sf.get_bit_size(), 8);
    }

    #[test]
    fn test_patch_type_variants() {
        assert_ne!(PatchType::CopyPatch, PatchType::ComparePatch);
        assert_ne!(PatchType::PushPatch, PatchType::ExtensionPatch);
    }
}
