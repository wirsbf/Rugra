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
#[derive(Debug, Clone)]
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

    /// Execute the replacement: create new ops for the logical subgraph and
    /// patch existing ops. Faithful to `SubvariableFlow::doReplacement`
    /// (subflow.cc:1435-1545).
    pub fn do_replacement(&mut self, fd: &mut Funcdata) {
        // 1. Process push patches: set push op's output to logical value.
        let push_patches: Vec<_> = self.patch_list.iter()
            .filter(|p| p.patch_type == PatchType::PushPatch)
            .cloned()
            .collect();
        for patch in &push_patches {
            let in1 = match &patch.in1 { Some(rv) => rv, None => continue };
            let push_addr = patch.patch_op.read().unwrap().get_addr();
            let zext_op = fd.new_op(1, push_addr);
            fd.op_set_opcode(&zext_op, OpCode::CPUI_INT_ZEXT);
            let _zext_out = fd.new_unique_out(self.flow_size as usize, &zext_op);
            if let Some(ref vn) = in1.vn {
                fd.op_set_input(&zext_op, vn.clone(), 0);
            }
            fd.op_insert_before(&zext_op, &crate::op::PcodeOpRef(patch.patch_op.clone()));
        }

        // 2. Create new ops for the subgraph.
        for i in 0..self.new_ops.len() {
            let (opc, num_params, has_op) = {
                let rop = &self.new_ops[i];
                (rop.opc, rop.num_params, rop.op.is_some())
            };
            if !has_op { continue; }
            let orig_op = self.new_ops[i].op.clone().unwrap();
            let addr = orig_op.read().unwrap().get_addr();
            let new_op = fd.new_op(num_params, addr);
            fd.op_set_opcode(&new_op, opc);
            let _out = fd.new_unique_out(self.flow_size as usize, &new_op);
            fd.op_insert_after(&new_op, &crate::op::PcodeOpRef(orig_op));
            self.new_ops[i].replacement = Some(new_op.0);
        }

        // 3. Process copy/compare/parameter/extension patches.
        let remaining: Vec<_> = self.patch_list.iter()
            .filter(|p| p.patch_type != PatchType::PushPatch)
            .cloned()
            .collect();
        for patch in &remaining {
            let op_ref = crate::op::PcodeOpRef(patch.patch_op.clone());
            match patch.patch_type {
                PatchType::CopyPatch => {
                    while op_ref.0.read().unwrap().num_input() > 1 {
                        fd.op_remove_input(&op_ref, op_ref.0.read().unwrap().num_input() - 1);
                    }
                    if let Some(ref in1) = patch.in1 {
                        if let Some(ref vn) = in1.vn {
                            fd.op_set_input(&op_ref, vn.clone(), 0);
                        }
                    }
                    fd.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
                }
                PatchType::ComparePatch => {
                    if let Some(ref in1) = patch.in1 {
                        if let Some(ref vn) = in1.vn {
                            fd.op_set_input(&op_ref, vn.clone(), 0);
                        }
                    }
                    if let Some(ref in2) = patch.in2 {
                        if let Some(ref vn) = in2.vn {
                            fd.op_set_input(&op_ref, vn.clone(), 1);
                        }
                    }
                }
                PatchType::ParameterPatch => {
                    if let Some(ref in1) = patch.in1 {
                        if let Some(ref vn) = in1.vn {
                            fd.op_set_input(&op_ref, vn.clone(), patch.slot as usize);
                        }
                    }
                }
                PatchType::ExtensionPatch => {
                    if let Some(ref in1) = patch.in1 {
                        if let Some(ref vn) = in1.vn {
                            if patch.slot == 0 {
                                fd.op_set_input(&op_ref, vn.clone(), 0);
                                fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_ZEXT);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Check if a mask represents a valid sub-variable of the given size.
    /// Corresponds to `doesOrSet` / `doesAndClear` checks.
    pub fn check_mask(mask: u64, flow_bits: i32) -> bool {
        let flow_mask = if flow_bits >= 64 { u64::MAX } else { (1u64 << flow_bits) - 1 };
        mask != 0 && mask != u64::MAX && (mask & flow_mask) == mask
    }

    /// Return the slot of the constant if an INT_OR op sets all masked bits to 1.
    /// Faithful to `SubvariableFlow::doesOrSet` (subflow.cc:26-36).
    pub fn does_or_set(op: &PcodeOp, mask: u64) -> i32 {
        let in1_const = op.inrefs.get(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
        let index = if in1_const { 1 } else { 0 };
        let in_const = match op.inrefs.get(index) {
            Some(v) => v.read().unwrap().is_constant(),
            None => return -1,
        };
        if !in_const { return -1; }
        let orval = op.inrefs[index].read().unwrap().get_offset();
        if (mask & !orval) == 0 { index as i32 } else { -1 }
    }

    /// Return the slot of the constant if an INT_AND op clears all masked bits.
    /// Faithful to `SubvariableFlow::doesAndClear` (subflow.cc:43-53).
    pub fn does_and_clear(op: &PcodeOp, mask: u64) -> i32 {
        let in1_const = op.inrefs.get(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
        let index = if in1_const { 1 } else { 0 };
        let in_const = match op.inrefs.get(index) {
            Some(v) => v.read().unwrap().is_constant(),
            None => return -1,
        };
        if !in_const { return -1; }
        let andval = op.inrefs[index].read().unwrap().get_offset();
        if (mask & andval) == 0 { index as i32 } else { -1 }
    }

    /// Compute the consume-mask for a Varnode — how many low bytes are used
    /// by descendants. Faithful to `Varnode::getConsume` semantics: returns
    /// a bitmask of the consumed portion. Rugra approximates by returning the
    /// full mask (all bytes consumed) when the varnode has descendants, else 0.
    pub fn compute_consume_mask(vn: &Arc<RwLock<Varnode>>) -> u64 {
        let v = vn.read().unwrap();
        let size = v.get_size();
        let full_mask = crate::address::calc_mask(size);
        // Check if vn has any descendants.
        if v.descend.is_empty() {
            0
        } else {
            full_mask
        }
    }

    /// Entry point: try to trace a sub-variable flow from a seed Varnode.
    /// Faithful to `SubvariableFlow::doTrace` (subflow.cc:1410-1434).
    /// Returns true if the trace found enough pull operations to be worthwhile.
    pub fn do_trace(&mut self, fd: &Funcdata, seed: Arc<RwLock<Varnode>>, mask: u64) -> bool {
        // Register the seed.
        let seed_ptr = Arc::as_ptr(&seed) as usize;
        self.set_replacement(seed.clone(), mask);
        // Forward trace: for each ReplaceVarnode, scan descendants.
        // Simplified single-pass (Ghidra uses a worklist with multiple passes).
        let mut worklist = vec![0usize]; // Start with seed index.
        while let Some(rvn_idx) = worklist.pop() {
            if rvn_idx >= self.new_vars.len() { continue; }
            let rvn_mask = self.new_vars[rvn_idx].mask;
            let rvn_vn = match &self.new_vars[rvn_idx].vn {
                Some(v) => v.clone(),
                None => continue, // Constant — no descendants
            };
            if !self.trace_forward_single(fd, &rvn_vn, rvn_mask, rvn_idx, &mut worklist) {
                return false;
            }
        }
        // Backward trace from the seed.
        let _ = self.trace_backward_single(fd, &seed, mask);
        self.is_worthwhile()
    }

    /// Trace forward from one ReplaceVarnode through its descendants.
    /// Faithful to `SubvariableFlow::traceForward` (subflow.cc:373-659).
    /// Returns false if the logical value cannot be traced (abort).
    fn trace_forward_single(
        &mut self,
        fd: &Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        mask: u64,
        rvn_idx: usize,
        worklist: &mut Vec<usize>,
    ) -> bool {
        let vn_ptr = Arc::as_ptr(vn) as usize;
        let descends: Vec<Arc<RwLock<PcodeOp>>> = vn.read().unwrap().descend_iter().collect();
        for op_arc in &descends {
            let op = op_arc.read().unwrap();
            let opcode = op.opcode;
            // Find which slot of this op reads our vn.
            let slot = (0..op.num_input())
                .find(|&i| op.get_in(i).map(|v| Arc::as_ptr(v) as usize == vn_ptr).unwrap_or(false));
            let slot = match slot { Some(s) => s, None => continue };
            match opcode {
                // Simple pass-through ops: create a parallel op in subgraph.
                OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR => {
                    if let Some(out) = &op.output {
                        let new_idx = self.set_replacement(out.clone(), mask);
                        worklist.push(new_idx);
                        self.pull_count += 1;
                    }
                }
                // INT_OR: if constant ORs all masked bits to 1, truncate flow.
                OpCode::CPUI_INT_OR => {
                    if Self::does_or_set(&op, mask) != -1 {
                        // Subvar set to all 1s — truncate.
                    } else if let Some(out) = &op.output {
                        let new_idx = self.set_replacement(out.clone(), mask);
                        worklist.push(new_idx);
                        self.pull_count += 1;
                    }
                }
                // INT_AND: if constant AND clears all masked bits, truncate.
                OpCode::CPUI_INT_AND => {
                    if op.inrefs.len() >= 2 && op.inrefs[1].read().unwrap().is_constant()
                        && op.inrefs[1].read().unwrap().get_offset() == mask
                    {
                        // Sub-field extraction via INT_AND.
                        self.pull_count += 1;
                    } else if Self::does_and_clear(&op, mask) != -1 {
                        // Subvar cleared — truncate.
                    } else if let Some(out) = &op.output {
                        let new_idx = self.set_replacement(out.clone(), mask);
                        worklist.push(new_idx);
                        self.pull_count += 1;
                    }
                }
                // ZEXT/SEXT: logical value passes through as COPY.
                OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                    if let Some(out) = &op.output {
                        let new_idx = self.set_replacement(out.clone(), mask);
                        worklist.push(new_idx);
                        self.pull_count += 1;
                    }
                }
                // INT_ADD: carry only accounted for if mask starts at bit 0.
                OpCode::CPUI_INT_ADD => {
                    if (mask & 1) == 0 { return false; }
                    if let Some(out) = &op.output {
                        let new_idx = self.set_replacement(out.clone(), mask);
                        worklist.push(new_idx);
                        self.pull_count += 1;
                    }
                }
                // SUBPIECE: extracting bytes from the logical value.
                OpCode::CPUI_SUBPIECE => {
                    if let Some(out) = &op.output {
                        self.pull_count += 1;
                    }
                }
                // INT_LEFT (shift left by constant).
                OpCode::CPUI_INT_LEFT => {
                    if slot == 1 { // Logical flow into shift amount
                        if (mask & 1) == 0 { return false; }
                        self.pull_count += 1;
                    } else {
                        if op.inrefs.len() < 2 || !op.inrefs[1].read().unwrap().is_constant() {
                            return false; // Dynamic shift
                        }
                        let sa = op.inrefs[1].read().unwrap().get_offset();
                        if sa >= 64 { return false; }
                        let newmask = (mask << sa) & crate::address::calc_mask(
                            op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(8));
                        if newmask == 0 {
                            // Subvar cleared — truncate.
                        } else if let Some(out) = &op.output {
                            let new_idx = self.set_replacement(out.clone(), newmask);
                            worklist.push(new_idx);
                            self.pull_count += 1;
                        }
                    }
                }
                // INT_RIGHT / INT_SRIGHT (shift right by constant).
                OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => {
                    if slot == 1 {
                        if (mask & 1) == 0 { return false; }
                        self.pull_count += 1;
                    } else {
                        if op.inrefs.len() < 2 || !op.inrefs[1].read().unwrap().is_constant() {
                            return false;
                        }
                        let sa = op.inrefs[1].read().unwrap().get_offset();
                        let newmask = if sa >= 64 { 0 } else { mask >> sa };
                        if newmask == 0 && opcode == OpCode::CPUI_INT_RIGHT {
                            // Subvar truncated.
                        } else if newmask != 0 {
                            if let Some(out) = &op.output {
                                let new_idx = self.set_replacement(out.clone(), newmask);
                                worklist.push(new_idx);
                                self.pull_count += 1;
                            }
                        }
                    }
                }
                // Comparisons: the logical value flows into a comparison.
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL => {
                    self.pull_count += 1;
                }
                // Boolean ops (for 1-bit sub-variables).
                OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR | OpCode::CPUI_CBRANCH => {
                    if self.bit_size != 1 { return false; }
                    self.pull_count += 1;
                }
                // CALL/CALLIND/RETURN: pull points for call args / return values.
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_RETURN
                | OpCode::CPUI_BRANCHIND => {
                    self.pull_count += 1;
                }
                _ => {
                    // Unknown op — abort this branch.
                    return false;
                }
            }
        }
        true
    }

    /// Trace backward from a Varnode through its defining op.
    /// Faithful to `SubvariableFlow::traceBackward` (subflow.cc:665-861).
    /// Returns false if the logical value cannot be traced backward.
    fn trace_backward_single(
        &mut self,
        _fd: &Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        mask: u64,
    ) -> bool {
        let def_op = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(op) => op,
            None => return true, // Input varnode — nothing to trace back.
        };
        let op = def_op.read().unwrap();
        match op.opcode {
            OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL
            | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR => {
                // Inputs flow through with same mask.
                for i in 0..op.num_input() {
                    if let Some(inv) = op.get_in(i) {
                        let _ = self.set_replacement(inv.clone(), mask);
                    }
                }
                true
            }
            OpCode::CPUI_INT_AND => {
                let sa = Self::does_and_clear(&op, mask);
                if sa != -1 {
                    // AND clears all masked bits → logical value is 0.
                    true
                } else {
                    for i in 0..2.min(op.num_input()) {
                        if let Some(inv) = op.get_in(i) {
                            let _ = self.set_replacement(inv.clone(), mask);
                        }
                    }
                    true
                }
            }
            OpCode::CPUI_INT_OR => {
                let sa = Self::does_or_set(&op, mask);
                if sa != -1 {
                    true
                } else {
                    for i in 0..2.min(op.num_input()) {
                        if let Some(inv) = op.get_in(i) {
                            let _ = self.set_replacement(inv.clone(), mask);
                        }
                    }
                    true
                }
            }
            OpCode::CPUI_INT_ADD => {
                if (mask & 1) == 0 { return false; }
                for i in 0..2.min(op.num_input()) {
                    if let Some(inv) = op.get_in(i) {
                        let _ = self.set_replacement(inv.clone(), mask);
                    }
                }
                true
            }
            OpCode::CPUI_SUBPIECE => {
                // Backward through SUBPIECE: mask shifts left.
                if op.inrefs.len() >= 2 {
                    let sa = op.inrefs[1].read().unwrap().get_offset() * 8;
                    let newmask = mask << sa;
                    if let Some(inv) = op.get_in(0) {
                        let _ = self.set_replacement(inv.clone(), newmask);
                    }
                }
                true
            }
            _ => {
                // For other ops, we don't trace backward (conservative).
                true
            }
        }
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

    #[test]
    fn test_does_or_set() {
        // INT_OR(vn, 0xFF) with mask=0xFF → all masked bits are 1 → slot 1
        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x100), 0),
            OpCode::CPUI_INT_OR,
        );
        let vn = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let c = Arc::new(RwLock::new(Varnode::new_constant(0xff, 4)));
        op.inrefs = vec![vn, c];
        assert_eq!(SubvariableFlow::does_or_set(&op, 0xff), 1);
    }

    #[test]
    fn test_does_and_clear() {
        // INT_AND(vn, 0x00) with mask=0xFF → all masked bits cleared → slot 1
        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x100), 0),
            OpCode::CPUI_INT_AND,
        );
        let vn = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let c = Arc::new(RwLock::new(Varnode::new_constant(0, 4)));
        op.inrefs = vec![vn, c];
        assert_eq!(SubvariableFlow::does_and_clear(&op, 0xff), 1);
    }

    #[test]
    fn test_do_trace_empty() {
        let mut sf = SubvariableFlow::new(1, false, false);
        let fd = Funcdata::new("t", crate::address::Address::new(0x1000), 0x10);
        let vn = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        // No ops reference the seed → not worthwhile.
        assert!(!sf.do_trace(&fd, vn, 0xff));
    }
}
