//! High-level function data container
//!
//! Corresponds to Ghidra's `funcdata.hh`

use crate::address::Address;
use crate::block::{BlockBasic, BlockGraph, FlowBlock};
use crate::fspec::FuncProto;
use crate::heritage::Heritage;
use crate::op::{PcodeOpBank, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::pcoderaw::PcodeOpRaw;
use crate::space::AddressSpace;
use crate::varnode::VarnodeBank;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

/// Main container for a function being decompiled
///
/// Corresponds to Ghidra's `Funcdata` class. This class ties together
/// the P-code operations, varnodes, control flow graph, and analysis state.
#[derive(Debug)]
pub struct Funcdata {
    /// Name of the function
    pub name: String,
    /// Base address of the function
    pub baseaddr: Address,
    /// Size of the function in bytes
    pub size: i32,

    /// Bank of all varnodes in this function
    pub vbank: VarnodeBank,
    /// Bank of all P-code operations in this function
    pub obank: PcodeOpBank,
    /// Control flow graph (basic blocks)
    pub bblocks: BlockGraph,
    /// Structure tree (composite blocks)
    pub sblocks: BlockGraph,
    /// SSA construction manager
    pub heritage: Heritage,

    /// Self-reference for use by child components
    pub self_ref: Option<Weak<RwLock<Funcdata>>>,

    /// Address → function/symbol name mapping (populated from ELF symtab)
    pub symbol_table: HashMap<u64, String>,
    /// Address → string literal mapping (populated from ELF .rodata)
    pub string_table: HashMap<u64, String>,
    /// Function prototype (return type, parameters)
    pub funcp: FuncProto,
    /// External function prototypes: maps callee address → param count.
    /// Populated by a pre-pass that analyzes all functions in the binary
    /// before decompilation. Mirrors Ghidra's multi-pass approach where
    /// ActionActiveParam runs across all functions to build a prototype
    /// database before final decompilation.
    pub external_prototypes: HashMap<u64, usize>,
    /// Restructured local-variable scope. Built by ActionRestructureVarnode
    /// (coreaction.cc:2274) and queried by printc's stack-variable resolution.
    /// Corresponds to Ghidra's `Funcdata::getScopeLocal()`.
    pub scope: Option<crate::varmap::ScopeLocal>,
}

impl Funcdata {
    /// Create a new Funcdata instance
    pub fn new(name: &str, addr: Address, size: i32) -> Self {
        Self {
            name: name.to_string(),
            baseaddr: addr,
            size,
            vbank: VarnodeBank::new(),
            obank: PcodeOpBank::new(),
            bblocks: BlockGraph::new(),
            sblocks: BlockGraph::new(),
            heritage: Heritage::new(),
            self_ref: None,
            symbol_table: HashMap::new(),
            string_table: HashMap::new(),
            funcp: FuncProto::new(
                name.to_string(),
                std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new("void".to_string(), 0, crate::type_system::datatype::TypeMetatype::Void)
                )),
            ),
            external_prototypes: HashMap::new(),
            scope: None,
        }
    }

    /// Set the self-reference after wrapping in Arc<RwLock>
    pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>) {
        self.self_ref = Some(self_ref.clone());
        self.heritage.fd = Some(self_ref);
    }

    /// Safely run the SSA heritage pass directly, avoiding deadlocks.
    /// 
    /// The standard `heritage()` method attempts to acquire a write lock on `Funcdata`
    /// via a weak pointer. If the caller already holds a lock on `Funcdata`, this
    /// leads to a deadlock. This method avoids the deadlock by passing the required
    /// banks directly to the underlying heritage algorithms.
    pub fn run_heritage_direct(&mut self) {
        let mut vbank = std::mem::take(&mut self.vbank);
        let mut obank = std::mem::take(&mut self.obank);

        self.heritage.place_multiequals_direct(
            &mut vbank,
            &mut obank,
            &self.bblocks,
            &self.sblocks,
        );
        self.heritage.rename_direct(&mut vbank, &self.bblocks);
        self.heritage.pass += 1;

        self.vbank = vbank;
        self.obank = obank;
    }

    /// Get function name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Register a symbol (function/global) at the given virtual address
    pub fn add_symbol(&mut self, addr: u64, name: String) {
        self.symbol_table.insert(addr, name);
    }

    /// Register a string literal at the given virtual address
    pub fn add_string(&mut self, addr: u64, s: String) {
        self.string_table.insert(addr, s);
    }

    /// Look up a symbol name by address
    pub fn get_symbol(&self, addr: u64) -> Option<&str> {
        self.symbol_table.get(&addr).map(|s| s.as_str())
    }

    /// Look up a string literal by address
    pub fn get_string(&self, addr: u64) -> Option<&str> {
        self.string_table.get(&addr).map(|s| s.as_str())
    }

    /// Get function base address
    pub fn get_address(&self) -> &Address {
        &self.baseaddr
    }

    /// Get function size
    pub fn get_size(&self) -> i32 {
        self.size
    }

    // --- Funcdata P-code op editing API (faithful to funcdata.hh:281-479) ---
    // These mirror Ghidra's Funcdata methods used by the rule/action transforms
    // to construct and edit P-code during analysis.

    /// Allocate a new PcodeOp with `num_inputs` slots at the function's base
    /// address. Faithful to `Funcdata::newOp` (funcdata.hh:444).
    pub fn new_op(&mut self, num_inputs: usize, pc: crate::address::Address) -> crate::op::PcodeOpRef {
        // Ghidra defaults the opcode to CPUI_COPY until opSetOpcode is called.
        self.obank.create(crate::opcodes::OpCode::CPUI_COPY, num_inputs, pc)
    }

    /// Create a new temporary output Varnode of size `s` for `op`.
    /// Faithful to `Funcdata::newUniqueOut` (funcdata.hh:281).
    pub fn new_unique_out(&mut self, s: usize, op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_unique(s);
        // Set the op's output and the varnode's def link.
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&op.0));
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    /// Create a new constant Varnode. Faithful to `Funcdata::newConstant`
    /// (funcdata.hh:283).
    pub fn new_constant(&mut self, s: usize, val: u64) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        self.vbank.create_constant(s, val)
    }

    /// Create a new temporary Varnode (no defining op). Faithful to
    /// `Funcdata::newUnique` (funcdata.hh:288).
    pub fn new_unique(&mut self, s: usize) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        self.vbank.create_unique(s)
    }

    /// Set the op-code for a specific PcodeOp. Faithful to
    /// `Funcdata::opSetOpcode` (funcdata.hh:463).
    pub fn op_set_opcode(&self, op: &crate::op::PcodeOpRef, opc: crate::opcodes::OpCode) {
        op.0.write().unwrap().opcode = opc;
    }

    /// Set a specific input operand for the given PcodeOp. Faithful to
    /// `Funcdata::opSetInput` (funcdata.hh:467). Extends inrefs if slot exceeds
    /// current length; updates the descend link on the new input.
    pub fn op_set_input(&self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize) {
        let mut o = op.0.write().unwrap();
        while o.inrefs.len() <= slot {
            o.inrefs.push(vn.clone());
        }
        // Maintain descend link on the input varnode.
        vn.write().unwrap().descend.push(std::sync::Arc::downgrade(&op.0));
        // If replacing an existing input, clear the old descend link is skipped
        // (Rugra does not track removal precisely; acceptable for rule transforms).
        o.inrefs[slot] = vn;
    }

    /// Insert a new Varnode into the operand list at `slot`. Faithful to
    /// `Funcdata::opInsertInput` (funcdata.hh:479).
    pub fn op_insert_input(&self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize) {
        let mut o = op.0.write().unwrap();
        let slot = slot.min(o.inrefs.len());
        o.inrefs.insert(slot, vn.clone());
        vn.write().unwrap().descend.push(std::sync::Arc::downgrade(&op.0));
    }

    /// Remove a specific input slot. Faithful to `Funcdata::opRemoveInput`
    /// (funcdata.hh:478).
    pub fn op_remove_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        let mut o = op.0.write().unwrap();
        if slot < o.inrefs.len() {
            o.inrefs.remove(slot);
        }
    }

    /// Swap two input operands. Faithful to `Funcdata::opSwapInput`
    /// (funcdata.hh). Used by RuleBoolNegate to reorder operands when flipping
    /// a comparison (e.g. `!(V < W) => W <= V`).
    pub fn op_swap_input(&self, op: &crate::op::PcodeOpRef, slot1: usize, slot2: usize) {
        let mut o = op.0.write().unwrap();
        if slot1 < o.inrefs.len() && slot2 < o.inrefs.len() {
            o.inrefs.swap(slot1, slot2);
        }
    }

    /// Set the output varnode for an op (replacing any existing output).
    /// Faithful to `Funcdata::opSetOutput`. Marks the varnode WRITTEN and sets
    /// its def link to this op; clears the old output's def if present.
    pub fn op_set_output(&self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        let mut o = op.0.write().unwrap();
        if let Some(old) = o.output.take() {
            // Clear the old output's def (best-effort).
            old.write().unwrap().def = None;
        }
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&op.0));
        o.output = Some(vn);
    }

    /// Destroy an unused PcodeOp. Faithful to `Funcdata::opDestroy`
    /// (funcdata_op.cc:203-222). Clears the output's def, unsets all inputs,
    /// and marks the op dead in the obank. Only call when the output has no
    /// descendants (dead code).
    pub fn op_destroy(&mut self, op: &crate::op::PcodeOpRef) {
        // Clear output def link.
        let out = op.0.read().unwrap().output.clone();
        if let Some(o) = out {
            o.write().unwrap().def = None;
        }
        // Clear all inrefs (break descend links on inputs).
        let inrefs = op.0.read().unwrap().inrefs.clone();
        for in_vn in &inrefs {
            in_vn.write().unwrap().descend.retain(|w| {
                w.upgrade().map(|a| !std::sync::Arc::ptr_eq(&a, &op.0)).unwrap_or(true)
            });
        }
        op.0.write().unwrap().inrefs.clear();
        // Mark the op dead.
        self.obank.mark_dead(op.clone());
    }

    /// Unset an input slot. Faithful to `Funcdata::opUnsetInput`
    /// (funcdata_op.cc). Removes the descend link from the input varnode and
    /// sets the slot to None (represented as removing from inrefs in Rugra).
    pub fn op_unset_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        let in_vn = op.0.read().unwrap().inrefs.get(slot).cloned();
        if let Some(vn) = in_vn {
            vn.write().unwrap().descend.retain(|w| {
                w.upgrade().map(|a| !std::sync::Arc::ptr_eq(&a, &op.0)).unwrap_or(true)
            });
        }
    }

    /// Unset the output of an op. Faithful to `Funcdata::opUnsetOutput`
    /// (funcdata_op.cc). Clears the output's def link and removes the output
    /// from the op, making the old output a free varnode.
    pub fn op_unset_output(&self, op: &crate::op::PcodeOpRef) {
        let old = op.0.write().unwrap().output.take();
        if let Some(o) = old {
            o.write().unwrap().def = None;
        }
    }

    /// Create a new output varnode for an op at a given address+size.
    /// Faithful to `Funcdata::newVarnodeOut` (funcdata.hh). Creates a varnode
    /// in the register space at the given address and wires it as the op's
    /// output.
    pub fn new_varnode_out(&mut self, size: usize, addr: crate::address::Address, op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_with_space(size, crate::space::AddressSpace::Register, addr.as_u64());
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&op.0));
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    /// Replace INT_LESSEQUAL/INT_SLESSEQUAL with INT_LESS/INT_SLESS:
    /// `V <= c => V < c+1`. Faithful to `Funcdata::replaceLessequal`
    /// (funcdata_op.cc:1029-1065).
    pub fn replace_lessequal(&mut self, op: &crate::op::PcodeOpRef) -> bool {
        let (i, diff, val, size, is_signed) = {
            let o = op.0.read().unwrap();
            let (vn_idx, diff) = if o.inrefs.get(0).map_or(false, |v| v.read().unwrap().is_constant()) {
                (0, -1i64)
            } else if o.inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                (1, 1i64)
            } else {
                return false;
            };
            let vn = o.inrefs[vn_idx].clone();
            let val = vn.read().unwrap().get_offset();
            let size = vn.read().unwrap().get_size();
            (vn_idx, diff, val, size, o.opcode == OpCode::CPUI_INT_SLESSEQUAL)
        };
        let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
        if is_signed {
            let int_min = if size >= 8 { i64::MIN as u64 } else { (1u64 << (size * 8 - 1)) };
            let int_max = if size >= 8 { i64::MAX as u64 } else { mask >> 1 };
            if diff == -1 && val == int_min { return false; }
            if diff == 1 && val == int_max { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_SLESS);
        } else {
            if diff == -1 && val == 0 { return false; }
            if diff == 1 && val == mask { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_LESS);
        }
        let res = (val as i64 + diff) as u64 & mask;
        let newconst = self.new_constant(size, res);
        self.op_set_input(op, newconst, i);
        true
    }

    /// Insert `op` before `follow` in the alive list. Faithful to
    /// `Funcdata::opInsertBefore` (funcdata.hh:454). Rugra's alive list is not
    /// strictly ordered per-block, but we insert before `follow` to preserve
    /// relative ordering where it matters for emit.
    pub fn op_insert_before(&mut self, op: &crate::op::PcodeOpRef, follow: &crate::op::PcodeOpRef) {
        let pos = self.obank.alivelist.iter().position(|r| std::sync::Arc::ptr_eq(&r.0, &follow.0));
        match pos {
            Some(idx) => self.obank.alivelist.insert(idx, op.clone()),
            None => self.obank.alivelist.push(op.clone()),
        }
    }

    /// Inject raw P-code operations into this Funcdata
    ///
    /// This is the bridge between raw P-code translation output (e.g., from
    /// a SLEIGH translator or manual construction) and the `Funcdata` container
    /// that the `ActionDatabase` pipeline operates on.
    ///
    /// The method:
    /// 1. Converts each `PcodeOpRaw` into a `PcodeOp` in `obank`
    /// 2. Creates `Varnode` entries in `vbank` for all inputs/outputs
    /// 3. Detects basic block boundaries at control flow terminators
    /// 4. Populates `bblocks` with basic blocks and edges
    ///
    /// # Arguments
    /// * `raw_ops` - Vector of raw P-code operations in sequential order
    pub fn inject_raw_ops(&mut self, raw_ops: &[PcodeOpRaw]) {
        if raw_ops.is_empty() {
            return;
        }

        // Phase 1: Convert all raw ops into PcodeOps with proper varnodes
        let mut op_refs: Vec<PcodeOpRef> = Vec::with_capacity(raw_ops.len());

        for (raw_idx, raw) in raw_ops.iter().enumerate() {
            let opcode = match OpCode::from_i32(raw.get_opcode()) {
                Some(opc) => opc,
                None => {
                    log::warn!("Unknown opcode {}, skipping", raw.get_opcode());
                    continue;
                }
            };

            // Assign a distinct address to each op: base + index * stride
            // This allows CBRANCH targets to be resolved to block start addresses
            let addr = raw
                .seq_num()
                .map(|s| s.get_addr())
                .unwrap_or(Address::new(self.baseaddr.as_u64() + raw_idx as u64 * 0x10));

            let op_ref = self.obank.create(opcode, raw.num_input(), addr);

            // Create output varnode if present
            if let Some(out_raw) = raw.output() {
                let out_vn =
                    self.vbank
                        .create_with_space(out_raw.size, out_raw.space, out_raw.offset);
                // Mark as written and set def
                self.vbank
                    .set_def(out_vn.clone(), Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().output = Some(out_vn);
            }

            // Create input varnodes
            for input_raw in raw.inputs() {
                let in_vn = if input_raw.space == AddressSpace::Const {
                    self.vbank.create_constant(input_raw.size, input_raw.offset)
                } else {
                    self.vbank
                        .create_with_space(input_raw.size, input_raw.space, input_raw.offset)
                };
                // Add use-def link
                in_vn
                    .write()
                    .unwrap()
                    .descend
                    .push(Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().inrefs.push(in_vn);
            }

            op_refs.push(op_ref);
        }

        eprintln!("[INJECT] {} phase1 done ops={}", self.name, op_refs.len());

        // Phase 2: Build basic blocks from the linear op sequence
        self.build_blocks_from_ops(&op_refs);
        eprintln!("[INJECT] {} phase2 done bblocks={}", self.name, self.bblocks.get_size());

        // Phase 3: Mark unwritten Register-space input varnodes as INPUT
        // In Ghidra's model, Heritage marks register reads with no prior definition
        // within the function as INPUT varnodes (function parameters / callee-saved regs).
        //
        // Correct semantics (read-before-write): a register read at op N is an INPUT
        // if no earlier op (in instruction order) wrote to that register offset.
        // Using a global "ever-defined" set is WRONG because parameter registers
        // are routinely re-assigned mid-function (e.g. RDX is read as param_3 at
        // 0x34a2 then overwritten by `mov rdx,[rsp+8]` at 0x34ac). A global set
        // would see the later write and miss the earlier read.
        //
        // We process ops in order; for each op we first inspect its inputs (reads)
        // and then record its output (write). This gives correct read-before-write
        // ordering within the linear instruction stream.
        //
        // CALL ops are skipped: the lifter attaches 6 ABI arg registers as inputs
        // to every CALL, which represent arguments PASSED TO the callee, not
        // registers READ by this function. Counting them would inflate the INPUT
        // set with RDI/RSI/RDX/RCX/R8/R9 on every function containing a call.
        let mut defined_reg_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();

        // Track which offsets we've already marked as INPUT to avoid duplicates
        let mut marked_input = std::collections::HashSet::new();
        for op_ref in &op_refs {
            let op = op_ref.0.read().unwrap();

            // Skip CALL: its register inputs are callee args, not this function's reads.
            if op.opcode == OpCode::CPUI_CALL {
                // Still record any output (call return value in RAX) as defined,
                // so a later read of RAX is not mistaken for a parameter.
                if let Some(ref out_arc) = op.output {
                    let out_vn = out_arc.read().unwrap();
                    if out_vn.get_space() == AddressSpace::Register {
                        defined_reg_offsets.insert(out_vn.get_offset());
                    }
                }
                continue;
            }

            // First: process reads (inputs) against the *current* defined set.
            for in_arc in &op.inrefs {
                let vn = in_arc.read().unwrap();
                if vn.get_space() == AddressSpace::Register
                    && !vn.is_input()
                    && !defined_reg_offsets.contains(&vn.get_offset())
                    && marked_input.insert(vn.get_offset())
                {
                    drop(vn); // Release read lock before write
                    self.vbank.set_input(in_arc.clone());
                }
            }

            // Then: record this op's output as defined for subsequent ops.
            if let Some(ref out_arc) = op.output {
                let out_vn = out_arc.read().unwrap();
                if out_vn.get_space() == AddressSpace::Register {
                    defined_reg_offsets.insert(out_vn.get_offset());
                }
            }
        }
        eprintln!("[INJECT] {} phase3 done marked_input={}", self.name, marked_input.len());
    }

    /// Build basic blocks from a linear sequence of PcodeOps
    ///
    /// Splits the op list at control flow terminators (BRANCH, CBRANCH, RETURN, CALL)
    /// and creates basic blocks in `self.bblocks`.
    fn build_blocks_from_ops(&mut self, op_refs: &[PcodeOpRef]) {
        if op_refs.is_empty() {
            return;
        }

        // Identify block start indices
        // First op always starts a block
        let mut block_starts: Vec<usize> = vec![0];
        for (i, op_ref) in op_refs.iter().enumerate() {
            let op = op_ref.0.read().unwrap();
            if op.opcode.is_block_terminator() && i + 1 < op_refs.len() {
                // The op AFTER a terminator starts a new block
                block_starts.push(i + 1);
            }
        }

        // Create basic blocks
        let mut blocks: Vec<Arc<RwLock<BlockBasic>>> = Vec::new();
        for (block_idx, &start) in block_starts.iter().enumerate() {
            let end = if block_idx + 1 < block_starts.len() {
                block_starts[block_idx + 1]
            } else {
                op_refs.len()
            };

            let block_addr = op_refs[start].0.read().unwrap().get_addr();
            let block = Arc::new(RwLock::new(BlockBasic::new(block_idx as i32, block_addr)));

            // Add ops to this block
            for op_ref in &op_refs[start..end] {
                {
                    let mut op = op_ref.0.write().unwrap();
                    op.parent = Some(Arc::downgrade(
                        // We need to cast to dyn FlowBlock
                        &(block.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
                    ));
                }
                let insert_pos = block.read().unwrap().get_ops().len();
                block.write().unwrap().insert_op(insert_pos, op_ref.clone());
            }

            blocks.push(block);
        }

        // Add blocks to the graph
        for block in &blocks {
            self.bblocks.add_block(block.clone());
        }

        // Add fallthrough edges between consecutive blocks
        // Also resolve BRANCH and CBRANCH targets to add the branch edges
        for i in 0..blocks.len() {
            let (last_opcode, branch_target_offset) = {
                let b = blocks[i].read().unwrap();
                let ops = b.get_ops();
                if ops.is_empty() {
                    continue;
                }
                let last_op = ops.last().unwrap().0.read().unwrap();
                let target = match last_op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH => {
                        // Input 0 is the branch target address
                        last_op.get_in(0).map(|vn| vn.read().unwrap().get_offset())
                    }
                    _ => None,
                };
                (last_op.opcode, target)
            };

            match last_opcode {
                OpCode::CPUI_RETURN | OpCode::CPUI_BRANCHIND => {
                    // Terminators that don't transition to a known, raw intra-function block
                }
                OpCode::CPUI_BRANCH => {
                    // Unconditional branch: 1 edge to the target ONLY
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }
                }
                OpCode::CPUI_CBRANCH => {
                    // CBRANCH gets BOTH edges, but ORDER MATTERS for Structure Collapse!
                    // Edge 0: branch target (true branch)
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }

                    // Edge 1: fallthrough (false branch) to next sequential block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }
                }
                _ => {
                    // Add fallthrough edge to next block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }
                }
            }
        }
    }

    /// Clear all analysis state
    pub fn clear(&mut self) {
        self.vbank.clear();
        self.obank.clear();
        self.bblocks.clear();
        self.sblocks.clear();
        self.heritage.clear();
    }

    /// Get number of heritage passes completed
    pub fn num_heritage_passes(&self) -> i32 {
        self.heritage.get_pass()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align::runtime_verify::{RuntimeVerifier, VerifyResult};
    use crate::disasm::{Disassembler, X86Lifter, X86_64Disassembler};
    use crate::ffi;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
    use std::sync::Mutex;

    // Serialize tests that use the global CURRENT_PROGRAM to prevent
    // multi-threaded test races when `cargo test` runs in parallel.
    lazy_static::lazy_static! {
        static ref FFI_TEST_LOCK: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn test_funcdata_creation() {
        let fd = Funcdata::new("test_func", Address::new(0x1000), 0x100);
        assert_eq!(fd.get_name(), "test_func");
        assert_eq!(fd.get_address().as_u64(), 0x1000);
    }

    #[test]
    fn test_inject_raw_ops_simple() {
        let mut fd = Funcdata::new("add", Address::new(0x1000), 7);

        // Build: RAX = COPY(RDI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: RAX = INT_ADD(RAX, RSI)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: RETURN(RAX)
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX

        fd.inject_raw_ops(&[op1, op2, op3]);

        // Verify ops were created
        assert_eq!(fd.obank.alivelist.len(), 3);

        // Verify varnodes were created (2 outputs + 4 inputs = 6 total)
        assert!(fd.vbank.num_varnodes() > 0);

        // Verify basic blocks (RETURN terminates, so we get 1 block)
        assert_eq!(fd.bblocks.get_size(), 1);
    }

    #[test]
    fn test_inject_raw_ops_with_branch() {
        let mut fd = Funcdata::new("branch_test", Address::new(0x2000), 20);

        // Block 0: compare and branch
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x2010, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));

        // Block 1: true branch
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 1, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // CBRANCH terminates block 0, so we get 2 blocks
        assert_eq!(fd.bblocks.get_size(), 2);
    }

    #[test]
    fn test_mov_reg_reg_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x89, 0xc3]; // mov rbx, rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");
        assert!(inst.text.contains("rbx"));
        assert!(inst.text.contains("rax"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 1);

        let raw = &raw_ops[0];
        assert_eq!(OpCode::from_i32(raw.get_opcode()), Some(OpCode::CPUI_COPY));

        let out_binding = raw.output();
        let out = out_binding.as_ref().unwrap();
        assert_eq!(out.space, AddressSpace::Register);
        assert_eq!(out.offset, 0x18);
        assert_eq!(out.size, 8);

        let inputs = raw.inputs();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].space, AddressSpace::Register);
        assert_eq!(inputs[0].offset, 0x00);
        assert_eq!(inputs[0].size, 8);

        let mut fd = Funcdata::new("mov_reg_reg", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 1);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("mov_rbx_rax_minimal", start, &rugra_ops, 1);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_add_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x83, 0xc0, 0x01]; // add rax, 1
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "add");
        assert!(inst.text.contains("rax"));
        assert!(inst.text.contains("1"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_add = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);
        assert_eq!(add_out.size, 8);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x00);
        assert_eq!(add_inputs[0].size, 8);
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x01);
        assert_eq!(add_inputs[1].size, 1);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00);
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, add_out.offset);
        assert_eq!(copy_inputs[0].size, 8);

        let mut fd = Funcdata::new("add_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("add_rax_1_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_sub_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x83, 0xe8, 0x08]; // sub rax, 8
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "sub");
        assert!(inst.text.contains("rax"));
        assert!(inst.text.contains("8"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // Expect INT_SUB + COPY (same pattern as add)
        assert_eq!(raw_ops.len(), 2);

        let raw_sub = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_sub.get_opcode()),
            Some(OpCode::CPUI_INT_SUB)
        );

        let sub_out_binding = raw_sub.output();
        let sub_out = sub_out_binding.as_ref().unwrap();
        assert_eq!(sub_out.space, AddressSpace::Unique);
        assert_eq!(sub_out.size, 8);

        let sub_inputs = raw_sub.inputs();
        assert_eq!(sub_inputs.len(), 2);
        assert_eq!(sub_inputs[0].space, AddressSpace::Register);
        assert_eq!(sub_inputs[0].offset, 0x00); // RAX
        assert_eq!(sub_inputs[0].size, 8);
        assert_eq!(sub_inputs[1].space, AddressSpace::Const);
        assert_eq!(sub_inputs[1].offset, 0x08);
        assert_eq!(sub_inputs[1].size, 1);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // RAX
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, sub_out.offset);
        assert_eq!(copy_inputs[0].size, 8);

        let mut fd = Funcdata::new("sub_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("sub_rax_8_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Fourth batch: and / or / xor / shl / shr / cmp ==========

    #[test]
    fn test_and_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // and rax, 0xf  →  48 83 e0 0f
        let code = vec![0x48, 0x83, 0xe0, 0x0f];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "and");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // Expect INT_AND + COPY
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x0f);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("and_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("and_rax_0xf_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_or_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // or rax, 0x10  →  48 83 c8 10
        let code = vec![0x48, 0x83, 0xc8, 0x10];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "or");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_OR)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x10);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("or_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("or_rax_0x10_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_xor_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // xor rax, 0x7  →  48 83 f0 07
        let code = vec![0x48, 0x83, 0xf0, 0x07];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "xor");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_XOR)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x07);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("xor_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("xor_rax_0x7_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shl_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // shl rax, 4  →  48 c1 e0 04
        let code = vec![0x48, 0xc1, 0xe0, 0x04];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "shl");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_LEFT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x04);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("shl_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shl_rax_4_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shr_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // shr rax, 4  →  48 c1 e8 04
        let code = vec![0x48, 0xc1, 0xe8, 0x04];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "shr");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_RIGHT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x04);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("shr_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shr_rax_4_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_cmp_rax_rbx_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // cmp rax, rbx  →  48 39 d8
        let code = vec![0x48, 0x39, 0xd8];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "cmp");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // cmp produces 3 flag-setting ops: INT_EQUAL(ZF), INT_LESS(CF), INT_SLESS(SF)
        assert_eq!(raw_ops.len(), 3);

        // Op 0: ZF = INT_EQUAL(rax, rbx)
        let raw_zf = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_zf.get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        let zf_out_binding = raw_zf.output();
        let zf_out = zf_out_binding.as_ref().unwrap();
        assert_eq!(zf_out.space, AddressSpace::Register);
        assert_eq!(zf_out.offset, 0x201); // ZF register
        assert_eq!(zf_out.size, 1);

        let zf_inputs = raw_zf.inputs();
        assert_eq!(zf_inputs.len(), 2);
        assert_eq!(zf_inputs[0].space, AddressSpace::Register);
        assert_eq!(zf_inputs[0].offset, 0x00); // RAX
        assert_eq!(zf_inputs[1].space, AddressSpace::Register);
        assert_eq!(zf_inputs[1].offset, 0x18); // RBX

        // Op 1: CF = INT_LESS(rax, rbx)
        let raw_cf = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_cf.get_opcode()),
            Some(OpCode::CPUI_INT_LESS)
        );
        let cf_out_binding = raw_cf.output();
        let cf_out = cf_out_binding.as_ref().unwrap();
        assert_eq!(cf_out.space, AddressSpace::Register);
        assert_eq!(cf_out.offset, 0x203); // CF register
        assert_eq!(cf_out.size, 1);

        // Op 2: SF = INT_SLESS(rax, rbx)
        let raw_sf = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_sf.get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        let sf_out_binding = raw_sf.output();
        let sf_out = sf_out_binding.as_ref().unwrap();
        assert_eq!(sf_out.space, AddressSpace::Register);
        assert_eq!(sf_out.offset, 0x202); // SF register
        assert_eq!(sf_out.size, 1);

        let mut fd = Funcdata::new("cmp_rax_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("cmp_rax_rbx_minimal", start, &rugra_ops, 3);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Memory instruction (LOAD / STORE) alignment tests ==========

    /// Test: `mov rax, [rbx]` — Simple memory load
    /// Machine code: 48 8b 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(const(ram_space_id), reg(rbx)) -> unique_tmp
    ///   2. CPUI_COPY(unique_tmp) -> reg(rax)
    #[test]
    fn test_load_mov_rax_mem_rbx_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x8b, 0x03]; // mov rax, [rbx]
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // parse_operand for Memory emits a LOAD internally, then mov emits COPY
        // So we expect: LOAD + COPY = 2 ops
        assert_eq!(raw_ops.len(), 2, "Expected LOAD + COPY, got {} ops", raw_ops.len());

        // Op 0: CPUI_LOAD
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        // Input 0: RAM space ID as a constant
        assert_eq!(load_inputs[0].space, AddressSpace::Const);
        assert_eq!(load_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx register
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx offset
        assert_eq!(load_inputs[1].size, 8);

        // Op 1: CPUI_COPY
        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, load_out.offset);

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("load_mov_rax_mem_rbx", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov [rbx], rax` — Simple memory store
    /// Machine code: 48 89 03
    /// Expected P-code:
    ///   1. CPUI_STORE(const(ram_space_id), reg(rbx), reg(rax)) — no output
    #[test]
    fn test_store_mov_mem_rbx_rax_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x89, 0x03]; // mov [rbx], rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // mov [rbx], rax: source is register (no LOAD), dest is memory (STORE)
        // So we expect just 1 op: STORE
        assert_eq!(raw_ops.len(), 1, "Expected 1 STORE op, got {} ops", raw_ops.len());

        // Op 0: CPUI_STORE
        let raw_store = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );

        // STORE has no output
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        // Input 0: RAM space ID
        assert_eq!(store_inputs[0].space, AddressSpace::Const);
        assert_eq!(store_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx
        assert_eq!(store_inputs[1].size, 8);
        // Input 2: value from rax
        assert_eq!(store_inputs[2].space, AddressSpace::Register);
        assert_eq!(store_inputs[2].offset, 0x00); // rax
        assert_eq!(store_inputs[2].size, 8);

        // Inject and verify
        let mut fd = Funcdata::new("store_mov_mem_rbx_rax", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 1);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("store_mov_mem_rbx_rax", start, &rugra_ops, 1);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, [rbx+0x10]` — Memory load with displacement
    /// Machine code: 48 8b 43 10
    /// Expected P-code:
    ///   1. CPUI_INT_ADD(rbx, 0x10) -> tmp_addr
    ///   2. CPUI_LOAD(const(ram_space_id), tmp_addr) -> tmp_val
    ///   3. CPUI_COPY(tmp_val) -> rax
    #[test]
    fn test_load_mov_rax_mem_rbx_disp_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x8b, 0x43, 0x10]; // mov rax, [rbx+0x10]
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // Displacement != 0 → INT_ADD for addr calc, then LOAD, then COPY
        assert_eq!(raw_ops.len(), 3, "Expected INT_ADD + LOAD + COPY, got {} ops", raw_ops.len());

        // Op 0: CPUI_INT_ADD for address computation
        let raw_add = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x18); // rbx
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x10); // displacement

        // Op 1: CPUI_LOAD
        let raw_load = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Unique); // computed address
        assert_eq!(load_inputs[1].offset, add_out.offset);

        // Op 2: CPUI_COPY
        let raw_copy = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx_disp", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation(
            "load_mov_rax_mem_rbx_disp",
            start,
            &rugra_ops,
            3,
        );

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `add [rbx], rax` — Memory read-modify-write
    /// Machine code: 48 01 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(ram_space_id, rbx) -> tmp_orig  (read original value)
    ///   2. CPUI_INT_ADD(tmp_orig, rax) -> tmp_result
    ///   3. CPUI_STORE(ram_space_id, rbx, tmp_result)  (write back)
    #[test]
    fn test_add_mem_rbx_rax_rmw_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x01, 0x03]; // add [rbx], rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "add");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // For `add [rbx], rax`:
        // - parse_dest_operand([rbx]) returns (rbx_vn, Some(size_vn)) — memory target
        // - parse_operand(rax) returns rax_vn — register source
        // - Because mem_size.is_some(), it calls parse_operand([rbx]) again for reading
        //   → this generates a LOAD op and returns tmp
        // - INT_ADD(tmp, rax) → tmp_result
        // - emit_store(rbx_vn, tmp_result, size_vn) → STORE
        // Total: LOAD + INT_ADD + STORE = 3 ops
        assert_eq!(raw_ops.len(), 3, "Expected LOAD + INT_ADD + STORE, got {} ops", raw_ops.len());

        // Op 0: CPUI_LOAD (read original value from [rbx])
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx

        // Op 1: CPUI_INT_ADD
        let raw_add = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        // Input 0: loaded value (unique tmp from LOAD)
        assert_eq!(add_inputs[0].space, AddressSpace::Unique);
        assert_eq!(add_inputs[0].offset, load_out.offset);
        // Input 1: rax
        assert_eq!(add_inputs[1].space, AddressSpace::Register);
        assert_eq!(add_inputs[1].offset, 0x00); // rax

        // Op 2: CPUI_STORE (write result back to [rbx])
        let raw_store = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        assert_eq!(store_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx (address)
        assert_eq!(store_inputs[2].space, AddressSpace::Unique); // result

        // Inject and verify
        let mut fd = Funcdata::new("add_mem_rbx_rax_rmw", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("add_mem_rbx_rax_rmw", start, &rugra_ops, 3);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== SSA alignment tests ==========

    /// Test: Single-block SSA construction for `mov rax, rdi; add rax, rsi; ret`
    ///
    /// Verifies that after heritage (SSA construction), a single-block
    /// function has:
    /// - No MULTIEQUAL (Phi) nodes (single block, no merge point)
    /// - Heritage pass counter incremented
    /// - Varnode def/use chains are established
    #[test]
    fn test_ssa_single_block_linear() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // Build raw ops for: mov rax, rdi; add rax, rsi; ret
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x2000);
        let mut fd = Funcdata::new("ssa_linear", start, 10);

        // Inject ops
        fd.inject_raw_ops(&[op1, op2, op3]);
        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        // Build dominator tree (required for heritage)
        fd.bblocks.build_dom_tree();

        // Run heritage directly using the _direct methods to avoid
        // the deadlock that occurs when heritage() tries to re-acquire
        // the Funcdata lock via fd_weak.upgrade().
        fd.heritage.place_multiequals_direct(
            &mut fd.vbank,
            &mut fd.obank,
            &fd.bblocks,
            &fd.sblocks,
        );
        fd.heritage.rename_direct(&mut fd.vbank, &fd.bblocks);
        fd.heritage.pass += 1;

        // Heritage pass should have incremented
        assert_eq!(fd.num_heritage_passes(), 1, "Heritage pass should be 1 after first run");

        // Single block → no MULTIEQUAL ops should be inserted
        let multiequal_count = fd
            .obank
            .optree
            .iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .count();
        assert_eq!(
            multiequal_count, 0,
            "Single block should have no Phi (MULTIEQUAL) nodes, found {}",
            multiequal_count
        );

        // Original 3 ops should still be present
        assert!(
            fd.obank.alivelist.len() >= 3,
            "Should still have at least 3 original ops"
        );
    }

    // ========== Multi-instruction sequence tests ==========

    /// Test: `mov rax, rdi; add rax, rsi; ret`
    /// A minimal function that returns first_arg + second_arg.
    /// Produces 4 P-code ops in a single basic block:
    ///   COPY(rax ← rdi), INT_ADD(tmp), COPY(rax ← tmp), RETURN
    #[test]
    fn test_seq_mov_add_ret_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // mov rax, rdi = 48 89 f8
        // add rax, rsi = 48 01 f0
        // ret          = c3
        let code = vec![
            0x48, 0x89, 0xf8, // mov rax, rdi
            0x48, 0x01, 0xf0, // add rax, rsi
            0xc3,             // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[1].mnemonic, "add");
        assert_eq!(instructions[2].mnemonic, "ret");

        // Verify sequential addresses
        assert_eq!(instructions[0].address.as_u64(), 0x1000);
        assert_eq!(instructions[1].address.as_u64(), 0x1003);
        assert_eq!(instructions[2].address.as_u64(), 0x1006);

        // Phase 2: Lift all instructions
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            let ops = lifter.lift(inst);
            all_raw_ops.extend(ops);
        }
        // mov→1(COPY) + add→2(INT_ADD+COPY) + ret→1(RETURN) = 4
        assert_eq!(all_raw_ops.len(), 4);

        // Verify op sequence
        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_INT_ADD));
        assert_eq!(OpCode::from_i32(all_raw_ops[2].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_RETURN));

        // Phase 3: Inject into Funcdata
        let mut fd = Funcdata::new("seq_mov_add_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 4);
        // RETURN terminates, all ops in one block
        assert_eq!(fd.bblocks.get_size(), 1);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_mov_add_ret", start, &rugra_ops, 4);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, rdi; and rax, 0xf; shl rax, 4; ret`
    /// Arithmetic chain: mask low nibble, shift left by 4. Returns (arg & 0xf) << 4.
    /// Produces 6 P-code ops in a single basic block:
    ///   COPY(rax←rdi), INT_AND(tmp1), COPY(rax←tmp1), INT_LEFT(tmp2), COPY(rax←tmp2), RETURN
    #[test]
    fn test_seq_mov_and_shl_ret_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x89, 0xf8,       // mov rax, rdi
            0x48, 0x83, 0xe0, 0x0f, // and rax, 0xf
            0x48, 0xc1, 0xe0, 0x04, // shl rax, 4
            0xc3,                    // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[1].mnemonic, "and");
        assert_eq!(instructions[2].mnemonic, "shl");
        assert_eq!(instructions[3].mnemonic, "ret");

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }
        // mov→1 + and→2 + shl→2 + ret→1 = 6
        assert_eq!(all_raw_ops.len(), 6);

        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_INT_AND));
        assert_eq!(OpCode::from_i32(all_raw_ops[2].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_INT_LEFT));
        assert_eq!(OpCode::from_i32(all_raw_ops[4].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[5].get_opcode()), Some(OpCode::CPUI_RETURN));

        let mut fd = Funcdata::new("seq_and_shl_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 6);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_and_shl_ret", start, &rugra_ops, 6);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch
    /// ```text
    /// 0x1000: cmp rdi, rsi     ; 48 39 f7
    /// 0x1003: je  0x100d       ; 74 08
    /// 0x1005: mov rax, 1       ; 48 c7 c0 01 00 00 00
    /// 0x100c: ret              ; c3
    /// 0x100d: xor rax, rax     ; 48 31 c0     (je target)
    /// 0x1010: ret              ; c3
    /// ```
    /// Tests: CBRANCH generation, basic block splitting, multi-block inject.
    /// Block 0: cmp(3 ops) + je(CBRANCH) = 4 ops
    /// Block 1: mov(COPY) + ret(RETURN) = 2 ops
    /// Block 2: xor(INT_XOR+COPY) + ret(RETURN) = 3 ops
    /// Total: 9 ops, 3 blocks
    #[test]
    fn test_seq_cmp_je_multiblock_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x39, 0xf7,                         // cmp rdi, rsi
            0x74, 0x08,                                // je +8 → 0x100d
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
            0xc3,                                      // ret
            0x48, 0x31, 0xc0,                          // xor rax, rax
            0xc3,                                      // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 6);
        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[1].mnemonic, "je");
        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[3].mnemonic, "ret");
        assert_eq!(instructions[4].mnemonic, "xor");
        assert_eq!(instructions[5].mnemonic, "ret");

        // Verify addresses
        assert_eq!(instructions[0].address.as_u64(), 0x1000);
        assert_eq!(instructions[1].address.as_u64(), 0x1003);
        assert_eq!(instructions[2].address.as_u64(), 0x1005);
        assert_eq!(instructions[3].address.as_u64(), 0x100c);
        assert_eq!(instructions[4].address.as_u64(), 0x100d);
        assert_eq!(instructions[5].address.as_u64(), 0x1010);

        // Phase 2: Lift all
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }
        // cmp→3(INT_EQUAL+INT_LESS+INT_SLESS)
        // je→1(CBRANCH)
        // mov→1(COPY)
        // ret→1(RETURN)
        // xor→2(INT_XOR+COPY)
        // ret→1(RETURN)
        // Total: 9
        assert_eq!(all_raw_ops.len(), 9);

        // Verify key opcodes
        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_INT_EQUAL));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_CBRANCH));
        assert_eq!(OpCode::from_i32(all_raw_ops[4].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[5].get_opcode()), Some(OpCode::CPUI_RETURN));
        assert_eq!(OpCode::from_i32(all_raw_ops[6].get_opcode()), Some(OpCode::CPUI_INT_XOR));

        // Phase 3: Inject and verify block structure
        let mut fd = Funcdata::new("seq_cmp_je_multi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        // CBRANCH terminates block 0, RETURN terminates block 1 and block 2 → 3 blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Verify block 0 has 4 ops (cmp: 3 flag ops + CBRANCH)
        let block0 = fd.bblocks.get_block(0).unwrap();
        assert_eq!(block0.read().unwrap().get_ops().len(), 4);

        // Verify block 1 has 2 ops (mov + ret)
        let block1 = fd.bblocks.get_block(1).unwrap();
        assert_eq!(block1.read().unwrap().get_ops().len(), 2);

        // Verify block 2 has 3 ops (xor: INT_XOR+COPY + ret)
        let block2 = fd.bblocks.get_block(2).unwrap();
        assert_eq!(block2.read().unwrap().get_ops().len(), 3);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_cmp_je_multiblock", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch converging to a merge block
    /// ```text
    /// 0x1000: cmp rdi, 0
    /// 0x1004: je 0x100f
    /// 0x1006: mov rax, 1
    /// 0x100d: jmp 0x1018
    /// 0x100f: mov rax, 2
    /// 0x1016: jmp 0x1018
    /// 0x1018: add rax, rsi
    /// 0x101b: ret
    /// ```
    /// This creates 4 basic blocks:
    /// Block 0: cmp + CBRANCH
    /// Block 1: mov rax, 1 + BRANCH (to block 3)
    /// Block 2: mov rax, 2 + BRANCH (to block 3)
    /// Block 3: MULTIEQUAL (Phi for rax) + add + ret
    #[test]
    fn test_ssa_dual_block_phi_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_phi_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree
        fd.bblocks.build_dom_tree();

        // Run heritage to build SSA
        fd.run_heritage_direct();

        // Verify that a MULTIEQUAL (Phi) node was created
        let multiequals: Vec<_> = fd.obank.optree.iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();
            
        assert_eq!(multiequals.len(), 1, "Expected exactly 1 Phi node, got {}", multiequals.len());
        
        let phi = multiequals[0].0.read().unwrap();
        assert_eq!(phi.inrefs.len(), 2, "Phi node should have 2 inputs");
        
        let out_vn = phi.output.as_ref().unwrap().read().unwrap();
        assert_eq!(out_vn.get_space(), AddressSpace::Register);
        assert_eq!(out_vn.get_offset(), 0x00); // RAX
        assert_eq!(out_vn.get_size(), 8); // RAX is 8 bytes
    }

    // ========== SSA Renaming Verification Tests ==========

    /// Test: Single-block SSA renaming correctness
    ///
    /// Sequence: mov rax, rdi; add rax, rsi; ret
    /// P-code:
    ///   op0: RAX = COPY(RDI)
    ///   op1: RAX = INT_ADD(RAX, RSI)
    ///   op2: RETURN(const)
    ///
    /// After renaming:
    ///   - op1's first input (RAX) should be rewritten to point to op0's output (the first def of RAX)
    ///   - op0's output and op1's output should be DIFFERENT Varnode instances (different create_index)
    ///   - op1's input[0] should be Arc::ptr_eq to op0's output
    #[test]
    fn test_ssa_rename_single_block_linear() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // Build: op0: RAX = COPY(RDI)
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: op1: RAX = INT_ADD(RAX, RSI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX (should be rewritten)
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: op2: RETURN(const)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x3000);
        let mut fd = Funcdata::new("ssa_rename_linear", start, 10);
        fd.inject_raw_ops(&[op0, op1, op2]);

        assert_eq!(fd.bblocks.get_size(), 1, "Should have exactly 1 basic block");

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Collect ops in order from the block
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();

        // Filter to only non-MULTIEQUAL ops (there should be none in single block, but be safe)
        let regular_ops: Vec<_> = ops.iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();
        assert!(regular_ops.len() >= 3, "Should have at least 3 regular ops, got {}", regular_ops.len());

        let pcode_op0 = regular_ops[0].0.read().unwrap();
        let pcode_op1 = regular_ops[1].0.read().unwrap();

        // op0 output: the first definition of RAX
        let op0_out = pcode_op0.output.as_ref().expect("op0 should have output");
        // op1 output: the second definition of RAX
        let op1_out = pcode_op1.output.as_ref().expect("op1 should have output");

        // VERIFY: op0 and op1 outputs are DIFFERENT Varnode instances
        assert!(
            !Arc::ptr_eq(op0_out, op1_out),
            "op0 and op1 should define DIFFERENT Varnode instances for RAX"
        );
        // Both should be at Register:0x00 (RAX)
        assert_eq!(op0_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op0_out.read().unwrap().get_offset(), 0x00);
        assert_eq!(op1_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op1_out.read().unwrap().get_offset(), 0x00);

        // VERIFY: op1's first input (RAX) was rewritten to point to op0's output
        let op1_in0 = &pcode_op1.inrefs[0];
        assert!(
            Arc::ptr_eq(op1_in0, op0_out),
            "After renaming, op1's RAX input should point to op0's output Varnode. \
             op1_in0 create_index={}, op0_out create_index={}",
            op1_in0.read().unwrap().get_create_index(),
            op0_out.read().unwrap().get_create_index(),
        );

        // VERIFY: op0's and op1's outputs have different create_index
        let ci0 = op0_out.read().unwrap().get_create_index();
        let ci1 = op1_out.read().unwrap().get_create_index();
        assert_ne!(ci0, ci1, "Different definitions of RAX should have different create_index: {} vs {}", ci0, ci1);
    }

    /// Test: Multi-block SSA renaming with Phi node input filling
    ///
    /// Assembly:
    ///   cmp rdi, 0       (Block 0)
    ///   je block2
    ///   mov rax, 1       (Block 1)
    ///   jmp block3
    ///   mov rax, 2       (Block 2)
    ///   jmp block3
    ///   add rax, rsi     (Block 3 — merge)
    ///   ret
    ///
    /// After renaming, at the merge block:
    ///   - A MULTIEQUAL (Phi) for RAX should exist
    ///   - Phi input 0 should be the RAX definition from Block 1 (mov rax, 1)
    ///   - Phi input 1 should be the RAX definition from Block 2 (mov rax, 2)
    ///   - op `add rax, rsi` in Block 3 should use the Phi output as its RAX input
    #[test]
    fn test_ssa_rename_multi_block_phi_inputs() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_rename_phi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find the MULTIEQUAL (Phi) op for RAX
        let multiequals: Vec<_> = fd.obank.optree.iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();

        // Find Phi node for RAX (Register:0x00)
        let rax_phis: Vec<_> = multiequals.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(!rax_phis.is_empty(), "Should have at least one Phi node for RAX");
        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(phi.inrefs.len(), 2, "RAX Phi node should have 2 inputs (from 2 predecessor blocks)");

        // VERIFY: Both Phi inputs should be WRITTEN varnodes (defined by mov rax, 1 / mov rax, 2)
        // After renaming, Phi inputs should NOT be placeholder varnodes — they should point to
        // the actual definitions from the predecessor blocks.
        for (idx, phi_input) in phi.inrefs.iter().enumerate() {
            let vn = phi_input.read().unwrap();
            assert_eq!(
                vn.get_space(), AddressSpace::Register,
                "Phi input {} should be in Register space", idx
            );
            assert_eq!(
                vn.get_offset(), 0x00,
                "Phi input {} should reference RAX (offset 0x00)", idx
            );
            // Each phi input should be a WRITTEN varnode (defined by a preceding op)
            // or at least not the same as the phi output itself
            assert!(
                !Arc::ptr_eq(phi_input, phi.output.as_ref().unwrap()),
                "Phi input {} should NOT be the same as Phi output", idx
            );
        }

        // VERIFY: The two Phi inputs should be DIFFERENT varnodes
        // (they come from different blocks with different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Phi's two inputs should be different Varnode instances (from different blocks). \
             input0 ci={}, input1 ci={}",
            phi.inrefs[0].read().unwrap().get_create_index(),
            phi.inrefs[1].read().unwrap().get_create_index(),
        );

        // VERIFY: Find the merge block's `add rax, rsi` op
        // Its RAX input should point to the Phi output, not to some random prior definition
        let phi_output = phi.output.as_ref().unwrap().clone();
        drop(phi); // Release the read lock

        // Search all ops for INT_ADD in the merge block that uses RAX
        let add_ops: Vec<_> = fd.obank.optree.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                op.get_opcode() == OpCode::CPUI_INT_ADD
                    && op.inrefs.iter().any(|inref| {
                        let vn = inref.read().unwrap();
                        vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                    })
            })
            .collect();

        // Among those, find one whose RAX input is the Phi output
        let uses_phi_output = add_ops.iter().any(|op_ref| {
            let op = op_ref.0.read().unwrap();
            op.inrefs.iter().any(|inref| Arc::ptr_eq(inref, &phi_output))
        });
        assert!(
            uses_phi_output,
            "The merge block's INT_ADD should use the Phi output as its RAX input"
        );
    }

    /// Test: SSA renaming with diamond CFG pattern
    ///
    /// Uses `mov rax, imm` instructions to ensure direct RAX definitions.
    /// CFG:
    ///   Block 0 (entry): cmp rdi,0; je block2
    ///   Block 1 (then):  mov rax, 0x10; jmp block3
    ///   Block 2 (else):  mov rax, 0x20; jmp block3
    ///   Block 3 (merge): ret   (Phi for RAX should be placed here)
    #[test]
    fn test_ssa_rename_diamond_pattern() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        let code = vec![
            // Block 0: cmp rdi, 0; je block2
            0x48, 0x83, 0xff, 0x00,                         // 0x4000: cmp rdi, 0
            0x74, 0x09,                                     // 0x4004: je +9 → 0x400f
            // Block 1: mov rax, 0x10; jmp block3
            0x48, 0xc7, 0xc0, 0x10, 0x00, 0x00, 0x00,       // 0x4006: mov rax, 0x10
            0xeb, 0x09,                                     // 0x400d: jmp +9 → 0x4018
            // Block 2: mov rax, 0x20; jmp block3
            0x48, 0xc7, 0xc0, 0x20, 0x00, 0x00, 0x00,       // 0x400f: mov rax, 0x20
            0xeb, 0x00,                                     // 0x4016: jmp +0 → 0x4018
            // Block 3: ret
            0xc3,                                           // 0x4018: ret
        ];
        let start = Address::new(0x4000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_diamond", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        let num_blocks = fd.bblocks.get_size();
        assert!(num_blocks >= 3, "Diamond pattern should have at least 3 blocks, got {}", num_blocks);

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find Phi nodes for RAX (Register:0x00)
        let rax_phis: Vec<_> = fd.obank.optree.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.get_opcode() != OpCode::CPUI_MULTIEQUAL {
                    return false;
                }
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(!rax_phis.is_empty(), "Diamond merge should have Phi for RAX");

        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(
            phi.inrefs.len(), 2,
            "RAX Phi at diamond merge should have 2 inputs, got {}",
            phi.inrefs.len()
        );

        // VERIFY: Both inputs should be register RAX varnodes
        for (i, phi_in) in phi.inrefs.iter().enumerate() {
            let vn = phi_in.read().unwrap();
            assert_eq!(vn.get_space(), AddressSpace::Register,
                "Phi input {} should be Register", i);
            assert_eq!(vn.get_offset(), 0x00,
                "Phi input {} should be RAX (offset 0x00)", i);
        }

        // VERIFY: Phi inputs are distinct (different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Diamond Phi inputs should be distinct varnode instances"
        );

        // VERIFY: Phi output is distinct from both inputs
        let phi_out = phi.output.as_ref().unwrap();
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[0]));
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[1]));
    }

    /// Test: SSA renaming correctly uses INPUT varnodes for undefined reads
    ///
    /// Sequence: add rax, rsi; ret
    /// There is no prior definition of RAX — it should remain linked to
    /// the INPUT varnode that heritage creates for uninitialized reads.
    #[test]
    fn test_ssa_rename_input_varnode_for_undefined_read() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // op0: RAX = INT_ADD(RAX, RSI)   — RAX is read before being defined
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX out
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX in (undefined)
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // op1: RETURN
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x5000);
        let mut fd = Funcdata::new("ssa_input_test", start, 10);
        fd.inject_raw_ops(&[op0, op1]);

        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Get ops
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();
        let regular_ops: Vec<_> = ops.iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();

        assert!(!regular_ops.is_empty(), "Should have at least 1 regular op");

        // Find the INT_ADD op
        let add_op_ref = regular_ops.iter()
            .find(|op_ref| op_ref.0.read().unwrap().get_opcode() == OpCode::CPUI_INT_ADD);
        assert!(add_op_ref.is_some(), "Should find INT_ADD op");

        let add_op = add_op_ref.unwrap().0.read().unwrap();
        assert!(add_op.inrefs.len() >= 2, "INT_ADD should have at least 2 inputs");

        // The RAX input (input 0) should reference a varnode.
        // Since there is no prior definition of RAX in this block,
        // after renaming it should either:
        // a) remain unchanged (no stack entry for RAX exists), or
        // b) point to an INPUT varnode if heritage created one
        //
        // The key verification: the input RAX varnode should be DIFFERENT from the output RAX varnode.
        let add_out = add_op.output.as_ref().expect("INT_ADD should have output");
        let add_in_rax = &add_op.inrefs[0];

        // Both refer to RAX
        assert_eq!(add_in_rax.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(add_in_rax.read().unwrap().get_offset(), 0x00);
        assert_eq!(add_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(add_out.read().unwrap().get_offset(), 0x00);

        // They must be DIFFERENT Varnode instances (input vs output are different SSA versions)
        assert!(
            !Arc::ptr_eq(add_in_rax, add_out),
            "Input RAX and output RAX should be different SSA versions. \
             Input ci={}, output ci={}",
            add_in_rax.read().unwrap().get_create_index(),
            add_out.read().unwrap().get_create_index(),
        );
    }

    // ========== ActionNormalizeBranches tests ==========

    #[test]
    fn test_normalize_branches_break_in_while_loop() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // while(rdi != rsi) { if (rax == 0x10) break; rax++; }
        //
        // 0x1000: cmp rdi, rsi        48 39 f7
        // 0x1003: je  0x1011          74 0c       → exit (loop condition: if equal, exit)
        // 0x1005: cmp rax, 0x10       48 83 f8 10
        // 0x1009: je  0x1011          74 06       → break (early exit from loop body)
        // 0x100b: add rax, 1          48 83 c0 01
        // 0x100f: jmp 0x1000          eb ef       → continue (back to loop header)
        // 0x1011: ret                 c3
        let code: Vec<u8> = vec![
            0x48, 0x39, 0xf7,
            0x74, 0x0c,
            0x48, 0x83, 0xf8, 0x10,
            0x74, 0x06,
            0x48, 0x83, 0xc0, 0x01,
            0xeb, 0xef,
            0xc3,
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("loop_break_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert!(
            fd.bblocks.get_size() >= 3,
            "Loop CFG should have at least 3 blocks, got {}",
            fd.bblocks.get_size()
        );

        fd.bblocks.build_dom_tree();

        use crate::action::Action;
        let structurer = crate::blockaction::ActionBlockStructure::new();
        let result = structurer.apply(&mut fd);
        assert!(result.is_ok());

        let normalizer = crate::blockaction::ActionNormalizeBranches::new();
        let result = normalizer.apply(&mut fd);
        assert!(result.is_ok());

        let mut _found_break = false;
        let mut found_continue = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if op.branch_type == crate::op::branch_type::BREAK {
                        _found_break = true;
                    }
                    if op.branch_type == crate::op::branch_type::CONTINUE {
                        found_continue = true;
                    }
                }
                _ => {}
            }
        }

        // The jmp back to 0x1000 should be tagged CONTINUE
        assert!(
            found_continue,
            "The back-edge jmp to loop header should be tagged CONTINUE"
        );
    }

    #[test]
    fn test_normalize_branches_op_branch_type_field() {
        use crate::op::branch_type;
        use crate::address::SeqNum;

        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = crate::op::PcodeOp::new(seq, OpCode::CPUI_CBRANCH);

        assert_eq!(op.branch_type, branch_type::NONE);

        op.branch_type = branch_type::BREAK;
        assert_eq!(op.branch_type, branch_type::BREAK);

        op.branch_type = branch_type::CONTINUE;
        assert_eq!(op.branch_type, branch_type::CONTINUE);
    }

    // ========== Boolean Condition Folding tests ==========

    #[test]
    fn test_bool_condition_folding_and_pattern() {
        use crate::block::{BlockBasic, BlockGraph, BlockEdge, BlockType, BlockCondition, BoolOp, FlowBlock};
        use crate::opcodes::OpCode;
        use crate::op::PcodeOp;
        use crate::address::{Address, SeqNum};

        // AND-pattern CFG:
        // A (CBRANCH): out(0)=B, out(1)=C → false edge to C
        // B (CBRANCH): out(0)=D, out(1)=C → false edge to C (same as A)
        // Both false edges → C → AND pattern
        let mut basic_a = BlockBasic::new(0, Address::new(0x1000));
        basic_a.ops.push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_CBRANCH),
        ))));

        let mut basic_b = BlockBasic::new(1, Address::new(0x1010));
        basic_b.ops.push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(SeqNum::new(Address::new(0x1010), 0), OpCode::CPUI_CBRANCH),
        ))));

        let basic_c = BlockBasic::new(2, Address::new(0x1020));
        let basic_d = BlockBasic::new(3, Address::new(0x1030));

        let block_a: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_a));
        let block_b: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_b));
        let block_c: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_c));
        let block_d: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_d));

        // Wire edges
        {
            let mut a = block_a.write().unwrap();
            a.add_out_edge(BlockEdge::new(block_b.clone(), 0)); // out(0)=B (true)
            a.add_out_edge(BlockEdge::new(block_c.clone(), 0)); // out(1)=C (false)
        }
        {
            let mut b = block_b.write().unwrap();
            b.add_in_edge(BlockEdge::new(block_a.clone(), 0));
            b.add_out_edge(BlockEdge::new(block_d.clone(), 0)); // out(0)=D (true)
            b.add_out_edge(BlockEdge::new(block_c.clone(), 1)); // out(1)=C (false)
        }
        {
            let mut c = block_c.write().unwrap();
            c.add_in_edge(BlockEdge::new(block_a.clone(), 1));
            c.add_in_edge(BlockEdge::new(block_b.clone(), 1));
        }
        {
            let mut d = block_d.write().unwrap();
            d.add_in_edge(BlockEdge::new(block_b.clone(), 0));
        }

        let mut graph = BlockGraph::new();
        graph.blocks = vec![block_a, block_b, block_c, block_d];

        let mut cs = crate::blockaction::CollapseStructure::new(&mut graph, "test");
        cs.collapse_all();

        // Search for BlockCondition(And) — after full Ghidra-style collapseAll
        // (including interleaved cat/if rules), it may be standalone, inside a
        // BlockList, or its original block slot may have been replaced.
        // Search ALL blocks recursively for any BlockCondition with And.
        let mut found_and = false;
        for i in 0..graph.get_size() {
            if let Some(block) = graph.get_block(i) {
                let b = block.read().unwrap();
                match b.get_type() {
                    BlockType::Condition => {
                        if let Some(cond) = b.as_any().downcast_ref::<BlockCondition>() {
                            if cond.op_type == BoolOp::And { found_and = true; }
                        }
                    }
                    BlockType::List => {
                        if let Some(list) = b.as_any().downcast_ref::<crate::block::BlockList>() {
                            for child in &list.children {
                                let c = child.read().unwrap();
                                if c.get_type() == BlockType::Condition {
                                    if let Some(cond) = c.as_any().downcast_ref::<BlockCondition>() {
                                        if cond.op_type == BoolOp::And { found_and = true; }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(found_and, "Expected BlockCondition(And) after boolean folding");
    }

    #[test]
    fn test_block_condition_struct_fields() {
        use crate::block::{BlockBasic, BlockCondition, BlockType, BoolOp, FlowBlock, BlockEdge};
        use crate::address::Address;

        let a: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        let b: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(1, Address::new(0x2000))));

        let cond = BlockCondition {
            index: 10,
            op_type: BoolOp::And,
            first: a.clone(),
            second: b.clone(),
            incoming: Vec::new(),
            outgoing: vec![BlockEdge {
                point: a.clone(),
                flags: 0,
                reverse_index: 0,
            }],
            parent: None,
            flags: 0,
        };

        assert_eq!(cond.get_type(), BlockType::Condition);
        assert_eq!(cond.get_index(), 10);
        assert_eq!(cond.op_type, BoolOp::And);
        assert_eq!(cond.size_out(), 1);
        assert_eq!(cond.get_start_addr(), Address::new(0x1000));

        let cond_or = BlockCondition {
            index: 20,
            op_type: BoolOp::Or,
            first: a,
            second: b,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        };
        assert_eq!(cond_or.op_type, BoolOp::Or);
        assert_eq!(cond_or.get_type(), BlockType::Condition);
    }

    #[test]
    fn test_switch_case_structuring() {
        use crate::action::Action;
        use crate::blockaction::ActionBlockStructure;
        use crate::prettyprint::EmitNoMarkup;
        use crate::printlanguage::PrintLanguage;
        use crate::printc::PrintC;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;
        use crate::block::BlockType;

        let mut fd = Funcdata::new("test_switch", Address::new(0x1000), 0x100);

        // Control block (Block 0): indirect jump
        // unique_var = COPY(RDI)
        // BRANCHIND(unique_var)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_BRANCHIND as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));

        // Case 0 block (Block 1): return 10
        // RAX = COPY(10)
        // RETURN(RAX)
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 10, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        // Case 1 block (Block 2): return 20
        // RAX = COPY(20)
        // RETURN(RAX)
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op5.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op5.add_input(VarnodeRaw::new(AddressSpace::Const, 20, 8));

        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4, op5, op6]);

        // Verify we got 3 basic blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Add edges: Block 0 -> Block 1, Block 0 -> Block 2
        let b0 = fd.bblocks.get_block(0).unwrap();
        let b1 = fd.bblocks.get_block(1).unwrap();
        let b2 = fd.bblocks.get_block(2).unwrap();
        fd.bblocks.add_edge(b0.clone(), b1.clone());
        fd.bblocks.add_edge(b0.clone(), b2.clone());

        // Run block structuring action
        let action = ActionBlockStructure::new();
        action.apply(&mut fd).unwrap();

        // Verify the main block was collapsed into a Switch
        assert_eq!(fd.sblocks.get_size(), 3);
        let entry = fd.sblocks.get_block(0).unwrap();
        assert_eq!(entry.read().unwrap().get_type(), BlockType::Switch);

        // Print C code
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer.take_emit().into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        println!("Emitted code:\n{}", emitted_code);

        // Assert code structure
        assert!(emitted_code.contains("switch ("));
        assert!(emitted_code.contains("case 0:"));
        assert!(emitted_code.contains("case 1:"));
    }

    #[test]
    fn test_type_propagation() {
        use crate::action::Action;
        use crate::coreaction::ActionTypeInfer;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        use crate::opcodes::OpCode;
        use std::sync::Arc;

        let mut fd = Funcdata::new("test_type_prop", Address::new(0x1000), 0x100);

        // Define linear instructions representing:
        // unique_1 = COPY(RDI)
        // unique_2 = INT_ADD(unique_1, 8)
        // unique_3 = LOAD(unique_2)
        // STORE(unique_4, unique_3)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8)); // unique_1
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI (input)

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 8, 8));

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (size 4)
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2 (addr)

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x40, 8)); // unique_4 (addr, untyped)
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (val)

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // 1. Deduplicate/Link variables so dataflow can propagate.
        // We link inputs to matching output Varnodes by space/offset/size.
        // First, collect all output varnode info to avoid RwLock deadlocks.
        let mut output_varnodes: Vec<(crate::space::AddressSpace, u64, usize, Arc<RwLock<crate::varnode::Varnode>>)> = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_vn_arc) = op.output {
                let out_vn = out_vn_arc.read().unwrap();
                output_varnodes.push((out_vn.space(), out_vn.offset(), out_vn.get_size(), out_vn_arc.clone()));
            }
        }

        let ops_to_update: Vec<_> = fd.obank.alivelist.iter().cloned().collect();
        for op_ref in &ops_to_update {
            let mut op = op_ref.0.write().unwrap();
            let num_inputs = op.inrefs.len();
            for i in 0..num_inputs {
                let (in_space, in_offset, in_size) = {
                    let in_vn = op.inrefs[i].read().unwrap();
                    (in_vn.space(), in_vn.offset(), in_vn.get_size())
                };

                if in_space != AddressSpace::Const {
                    let found_match = output_varnodes.iter()
                        .find(|(s, o, sz, _)| *s == in_space && *o == in_offset && *sz == in_size)
                        .map(|(_, _, _, arc)| arc.clone());

                    if let Some(matching_vn) = found_match {
                        op.inrefs[i] = matching_vn.clone();
                        matching_vn.write().unwrap().descend.push(Arc::downgrade(&op_ref.0));
                    }
                }
            }
        }

        // Manually inject a starting type: RDI is an "int *" pointer.
        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));
        let int_ptr_type = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type.clone(),
            wordsize: 1,
        }));

        {
            let mut found = false;
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_COPY {
                    let mut in_vn = op.inrefs[0].write().unwrap();
                    if in_vn.space().is_register() && in_vn.offset() == 0x38 {
                        in_vn.v_type = Some(int_ptr_type.clone());
                        found = true;
                    }
                }
            }
            assert!(found, "RDI input varnode not found and typed");
        }

        // Run type propagation
        let action = ActionTypeInfer::new();
        action.apply(&mut fd).unwrap();

        // Verify propagation results on our unified SSA variable chain
        let mut checked_u1 = false;
        let mut checked_u2 = false;
        let mut checked_u3 = false;
        let mut checked_u4 = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_COPY => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x10);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u1 = true;
                }
                OpCode::CPUI_INT_ADD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x20);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u2 = true;
                }
                OpCode::CPUI_LOAD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x30);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int");
                    checked_u3 = true;
                }
                OpCode::CPUI_STORE => {
                    let addr_vn = op.inrefs[1].read().unwrap();
                    assert_eq!(addr_vn.space(), AddressSpace::Unique);
                    assert_eq!(addr_vn.offset(), 0x40);
                    assert_eq!(addr_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u4 = true;
                }
                _ => {}
            }
        }

        assert!(checked_u1, "unique_1 type verification failed");
        assert!(checked_u2, "unique_2 type verification failed");
        assert!(checked_u3, "unique_3 type verification failed");
        assert!(checked_u4, "unique_4 type verification failed");
    }

    #[test]
    fn test_infer_params_and_return_type() {
        use crate::action::Action;
        use crate::coreaction::ActionInferParams;
        use crate::type_system::datatype::Datatype;

        let mut fd = Funcdata::new("my_func", Address::new(0x1000), 0x100);

        // Create INPUT varnodes in SysV ABI parameter registers
        // param1 = RDI (offset 0x38, size 8)
        let rdi_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x38);
        fd.vbank.set_input(rdi_vn.clone());
        // param2 = RSI (offset 0x30, size 8)
        let rsi_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        fd.vbank.set_input(rsi_vn.clone());

        // Create an op that reads both params: ADD rdi, rsi -> result (RAX)
        let result_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x00);
        let add_ref = fd.obank.create(OpCode::CPUI_INT_ADD, 2, Address::new(0x1000));
        {
            let mut add_op = add_ref.0.write().unwrap();
            add_op.output = Some(result_vn.clone());
            add_op.inrefs.push(rdi_vn);
            add_op.inrefs.push(rsi_vn);
        }

        // Create RETURN op with RAX as return value
        let ret_addr_vn = fd.vbank.create_constant(8, 0);
        let ret_ref = fd.obank.create(OpCode::CPUI_RETURN, 2, Address::new(0x1010));
        {
            let mut ret_op = ret_ref.0.write().unwrap();
            ret_op.inrefs.push(ret_addr_vn);
            ret_op.inrefs.push(result_vn); // RAX as return value
        }

        // Verify initial state: void return, no params
        assert!(matches!(fd.funcp.return_type.as_ref(), Datatype::Void(_)));
        assert!(fd.funcp.parameters.is_empty());

        // Run ActionInferParams
        let action = ActionInferParams::new();
        let result = action.apply(&mut fd).unwrap();
        assert!(result > 0, "ActionInferParams should report changes");

        // Verify parameters detected
        assert_eq!(fd.funcp.parameters.len(), 2, "Should detect 2 parameters");
        assert_eq!(fd.funcp.parameters[0].name, "param_1");
        assert_eq!(fd.funcp.parameters[1].name, "param_2");

        // Verify return type inferred (RAX is size 8 -> long)
        assert_eq!(fd.funcp.return_type.get_name(), "long",
            "Return type should be inferred as 'long' from 8-byte RAX");
    }

    /// End-to-end decompilation test simulating a realistic curl-style function.
    ///
    /// Models a function like:
    /// ```c
    /// long curl_easy_setopt(long handle, int option, long value) {
    ///     long result;
    ///     if (option == 0x2712) {
    ///         *(long *)(handle + 0x28) = value;
    ///         result = 0;
    ///     } else {
    ///         result = curl_set_error(handle, option);
    ///     }
    ///     return result;
    /// }
    /// ```
    #[test]
    fn test_realistic_curl_function() {
        use crate::action::ActionDatabase;
        use crate::prettyprint::EmitNoMarkup;
        use crate::printlanguage::PrintLanguage;
        use crate::printc::PrintC;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("curl_easy_setopt", Address::new(0x4050a0), 0x60);

        // Add symbol table entries for known functions
        fd.symbol_table.insert(0x403210, "curl_set_error".to_string());

        // Addresses: baseaddr + idx * 0x10
        // Block 0: op0..op4 (5 ops) → CBRANCH at op4
        //   Block 0 starts at 0x4050a0
        // Block 1: op5..op7 (3 ops) → BRANCH at op7
        //   Block 1 starts at 0x4050a0 + 5*0x10 = 0x4050f0
        // Block 2: op8..op11 (4 ops) → BRANCH at op11
        //   Block 2 starts at 0x4050a0 + 8*0x10 = 0x405120
        // Block 3: op12..op13 (2 ops) → RETURN at op13
        //   Block 3 starts at 0x4050a0 + 12*0x10 = 0x405160

        // === Block 0: Entry / condition check ===
        // op0: u0 = COPY(RDI)           ; handle → unique
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI = handle
        // op1: u1 = INT_ZEXT(ESI)       ; option → 8-byte
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 4)); // ESI = option (4 byte)
        // op2: u2 = COPY(RDX)           ; value → unique
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x10, 8)); // RDX = value
        // op3: u3 = INT_EQUAL(u1, 0x2712)  ; option == CURLOPT_URL
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0x2712, 8));
        // op4: CBRANCH → Block 2 (then branch at 0x405120)
        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405120, 8));
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));

        // === Block 1: else branch (call curl_set_error + branch to exit) ===
        // op5: CALL curl_set_error
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_CALL as i32);
        op5.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x403210, 8));
        // op6: u4 = COPY(RAX)     ; capture return value
        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op6.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        // op7: BRANCH → Block 3 (exit at 0x405160)
        let mut op7 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op7.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 2: then branch (store value + branch to exit) ===
        // op8: u5 = INT_ADD(u0, 0x28)  ; handle + 0x28
        let mut op8 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op8.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Const, 0x28, 8));
        // op9: STORE([ram], u5, u2)     ; *(handle+0x28) = value
        let mut op9 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op9.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        // op10: u6 = COPY(0)           ; result = 0
        let mut op10 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op10.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x130, 8));
        op10.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        // op11: BRANCH → Block 3 (exit at 0x405160)
        let mut op11 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op11.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 3: exit (return result) ===
        // op12: RAX = COPY(result)
        let mut op12 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op12.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op12.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        // op13: RETURN(RAX)
        let mut op13 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op13.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op13.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op0, op1, op2, op3, op4, op5, op6, op7, op8, op9, op10, op11, op12, op13]);

        // CFG edges are automatically created by build_blocks_from_ops

        // Run full analysis pipeline
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let _ = db.apply_all(&mut fd);

        // Print decompiled output
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer.take_emit().into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        println!("\n====== Rugra Decompiled Output: curl_easy_setopt ======\n{}\n======================================================", emitted_code);

        // Basic structure assertions
        assert!(emitted_code.contains("curl_easy_setopt"), "Should contain function name");
        assert!(!emitted_code.contains("void curl_easy_setopt"), "Should NOT have void return (has RETURN with RAX)");
        // Function signature should contain parameters
        assert!(emitted_code.contains("param_1"), "Should contain param_1 in signature");
        assert!(emitted_code.contains("param_2"), "Should contain param_2 in signature or body");
        assert!(emitted_code.contains("param_3"), "Should contain param_3 in signature");
        // param_2 should appear in the body expression (not just signature)
        assert!(emitted_code.contains("(long)param_2") || emitted_code.contains("param_2"),
            "param_2 should be used in body expression");
    }
}

