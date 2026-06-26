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
#[derive(Debug, Clone)]
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

    /// Register a new sub-variable overlay for the given Varnode.
    /// Corresponds to `SubvariableFlow::setReplacement` (subflow.cc).
    pub fn set_replacement(&mut self, vn: Arc<RwLock<Varnode>>, mask: u64) -> usize {
        let ptr = Arc::as_ptr(&vn) as usize;
        if let Some(&idx) = self.var_map.get(&ptr) {
            return idx;
        }
        let idx = self.new_vars.len();
        self.new_vars.push(ReplaceVarnode {
            vn: Some(vn),
            replacement: None,
            mask,
            val: 0,
        });
        self.var_map.insert(ptr, idx);
        idx
    }

    /// Check if a Varnode already has a replacement registered.
    pub fn has_replacement(&self, vn: &Arc<RwLock<Varnode>>) -> bool {
        let ptr = Arc::as_ptr(vn) as usize;
        self.var_map.contains_key(&ptr)
    }

    /// Get the replacement index for a Varnode, if any.
    pub fn get_replacement_index(&self, vn: &Arc<RwLock<Varnode>>) -> Option<usize> {
        let ptr = Arc::as_ptr(vn) as usize;
        self.var_map.get(&ptr).copied()
    }

    /// Create a new op in the subgraph.
    pub fn create_op(&mut self, opc: OpCode, num_params: usize) -> usize {
        let idx = self.new_ops.len();
        self.new_ops.push(ReplaceOp {
            op: None,
            replacement: None,
            opc,
            num_params,
            output: None,
            inputs: Vec::new(),
        });
        idx
    }

    /// Create a new op linked to an existing PcodeOp.
    pub fn create_op_down(&mut self, opc: OpCode, num_params: usize, op: Arc<RwLock<PcodeOp>>) -> usize {
        let idx = self.new_ops.len();
        self.new_ops.push(ReplaceOp {
            op: Some(op),
            replacement: None,
            opc,
            num_params,
            output: None,
            inputs: Vec::new(),
        });
        idx
    }

    /// Add a push patch (op outputs the logical value).
    pub fn add_push(&mut self, push_op: Arc<RwLock<PcodeOp>>, rvn_idx: usize) {
        self.patch_list.push(PatchRecord {
            patch_type: PatchType::PushPatch,
            patch_op: push_op,
            in1: self.new_vars.get(rvn_idx).cloned(),
            in2: None,
            slot: -1,
        });
        self.pull_count += 1;
    }

    /// Add a terminal patch (op reads the logical value).
    pub fn add_terminal_patch(&mut self, pull_op: Arc<RwLock<PcodeOp>>, rvn_idx: usize) {
        self.patch_list.push(PatchRecord {
            patch_type: PatchType::CopyPatch,
            patch_op: pull_op,
            in1: self.new_vars.get(rvn_idx).cloned(),
            in2: None,
            slot: 0,
        });
        self.pull_count += 1;
    }

    /// Add a compare patch.
    pub fn add_compare_patch(&mut self, rvn1_idx: usize, rvn2_idx: usize, op: Arc<RwLock<PcodeOp>>) {
        self.patch_list.push(PatchRecord {
            patch_type: PatchType::ComparePatch,
            patch_op: op,
            in1: self.new_vars.get(rvn1_idx).cloned(),
            in2: self.new_vars.get(rvn2_idx).cloned(),
            slot: 0,
        });
    }

    /// Get the number of new vars.
    pub fn num_new_vars(&self) -> usize { self.new_vars.len() }

    /// Get the number of new ops.
    pub fn num_new_ops(&self) -> usize { self.new_ops.len() }

    /// Get the number of patches.
    pub fn num_patches(&self) -> usize { self.patch_list.len() }

    /// Check if the analysis found enough pull operations to be worthwhile.
    /// Corresponds to the decision in `SubvariableFlow::doReplacement`.
    pub fn is_worthwhile(&self) -> bool {
        self.pull_count >= 2
    }

    /// Check if a mask represents a valid sub-variable of the given size.
    /// Corresponds to `doesOrSet` / `doesAndClear` checks.
    pub fn check_mask(mask: u64, flow_bits: i32) -> bool {
        let flow_mask = if flow_bits >= 64 { u64::MAX } else { (1u64 << flow_bits) - 1 };
        mask != 0 && mask != u64::MAX && (mask & flow_mask) == mask
    }
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

    #[test]
    fn test_set_replacement() {
        let mut sf = SubvariableFlow::new(1, false, false);
        let vn = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let idx = sf.set_replacement(vn.clone(), 0xff);
        assert!(sf.has_replacement(&vn));
        assert_eq!(sf.get_replacement_index(&vn), Some(idx));
        assert_eq!(sf.num_new_vars(), 1);
    }

    #[test]
    fn test_create_op() {
        let mut sf = SubvariableFlow::new(1, false, false);
        let op_idx = sf.create_op(OpCode::CPUI_INT_ADD, 2);
        assert_eq!(sf.num_new_ops(), 1);
        assert_eq!(sf.new_ops[op_idx].opc, OpCode::CPUI_INT_ADD);
    }

    #[test]
    fn test_patches_and_worthwhile() {
        let mut sf = SubvariableFlow::new(1, false, false);
        let vn = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let idx = sf.set_replacement(vn.clone(), 0xff);
        let dummy_op = Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        )));
        sf.add_push(dummy_op.clone(), idx);
        sf.add_terminal_patch(dummy_op, idx);
        assert_eq!(sf.num_patches(), 2);
        assert!(sf.is_worthwhile());
    }

    #[test]
    fn test_check_mask() {
        assert!(SubvariableFlow::check_mask(0xff, 8));
        assert!(!SubvariableFlow::check_mask(0, 8));
        assert!(!SubvariableFlow::check_mask(u64::MAX, 8));
        assert!(SubvariableFlow::check_mask(0x0f, 8));
    }
}
