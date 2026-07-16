//! P-code operation structures
//!
//! Corresponds to Ghidra's `op.hh`

use crate::address::{Address, SeqNum};
use crate::opcodes::OpCode;
use crate::varnode::Varnode;
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock, Weak};

use crate::block::FlowBlock;

// Forward declarations/Stubs
pub mod stubs {
// use super::*;
    #[derive(Debug)]
    pub struct TypeOp;
}



/// Flags for PcodeOp properties (pcodeop_flags in Ghidra)
pub mod pcodeop_flags {
    pub const STARTBASIC: u32 = 1 << 0;
    pub const BRANCH: u32 = 1 << 1;
    pub const CALL: u32 = 1 << 2;
    pub const RETURNS: u32 = 1 << 3;
    pub const NOCOLLAPSE: u32 = 1 << 4;
    pub const DEAD: u32 = 1 << 5;
    pub const MARKER: u32 = 1 << 6;
    pub const BOOLOUTPUT: u32 = 1 << 7;
    pub const BOOLEAN_FLIP: u32 = 1 << 8;
    pub const FALLTHRU_TRUE: u32 = 1 << 9;
    pub const INDIRECT_SOURCE: u32 = 1 << 10;
    pub const CODEREF: u32 = 1 << 11;
    pub const STARTMARK: u32 = 1 << 12;
    pub const MARK: u32 = 1 << 13;
    pub const COMMUTATIVE: u32 = 1 << 14;
    pub const UNARY: u32 = 1 << 15;
    pub const BINARY: u32 = 1 << 16;
    pub const SPECIAL: u32 = 1 << 17;
    pub const TERNARY: u32 = 1 << 18;
    pub const RETURN_COPY: u32 = 1 << 19;
    pub const NONPRINTING: u32 = 1 << 20;
    pub const HALT: u32 = 1 << 21;
    pub const BADINSTRUCTION: u32 = 1 << 22;
    pub const UNIMPLEMENTED: u32 = 1 << 23;
    pub const NORETURN: u32 = 1 << 24;
    pub const MISSING: u32 = 1 << 25;
    pub const SPACEBASE_PTR: u32 = 1 << 26;
    pub const INDIRECT_CREATION: u32 = 1 << 27;
    pub const CALCULATED_BOOL: u32 = 1 << 28;
    pub const HAS_CALLSPEC: u32 = 1 << 29;
    pub const PTRFLOW: u32 = 1 << 30;
    pub const INDIRECT_STORE: u32 = 1 << 31;
}

/// PcodeOp additional flags (Ghidra `op.hh:108-120`). Stored in the
/// `addlflags: u32` field. These mirror Ghidra's bit values exactly.
pub mod op_addl_flags {
    pub const SPECIAL_PRINT: u32 = 0x2;
    pub const MODIFIED: u32 = 0x4;
    pub const WARNING: u32 = 0x8;
    pub const INCIDENTAL_COPY: u32 = 0x10;
    /// is_cpool_transformed (already used via 0x20 in mark_cpool_transformed).
    pub const IS_CPOOL_TRANSFORMED: u32 = 0x20;
    pub const STOP_TYPE_PROPAGATION: u32 = 0x40;
    pub const HOLD_OUTPUT: u32 = 0x80;
    pub const CONCAT_ROOT: u32 = 0x100;
    pub const NO_INDIRECT_COLLAPSE: u32 = 0x200;
    pub const STORE_UNMAPPED: u32 = 0x400;
}

pub mod branch_type {
    pub const NONE: u8 = 0;
    pub const BREAK: u8 = 1;
    pub const CONTINUE: u8 = 2;
    pub const GOTO: u8 = 3;
}

/// Corresponds to Ghidra's `IopSpace` class in `op.hh`
pub struct IopSpace;

impl IopSpace {
    pub const NAME: &'static str = "iop";
}

/// Represents a single P-code operation in the data flow graph
///
/// Corresponds to Ghidra's `PcodeOp` class in `op.hh`
#[derive(Debug)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub flags: u32,
    pub addlflags: u32,
    pub start: SeqNum,
    pub parent: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub output: Option<Arc<RwLock<Varnode>>>,
    pub inrefs: Vec<Arc<RwLock<Varnode>>>,
    pub branch_type: u8,
}

impl PcodeOp {
    // RUGRA-GLUE: Rust ctor; Ghidra's PcodeOp constructor is private and only
    //   called via PcodeOpBank::create (op.hh:308). Rugra exposes PcodeOp::new
    //   because we don't have the same friend-class relationship to the bank.
    pub fn new(start: SeqNum, opcode: OpCode) -> Self {
        Self {
            opcode,
            flags: 0,
            addlflags: 0,
            start,
            parent: None,
            output: None,
            inrefs: Vec::new(),
            branch_type: branch_type::NONE,
        }
    }

    // Ghidra: op.hh:233 PcodeOp::code (returns the OpCode enum; Ghidra's
    //   getOpcode at :232 returns the TypeOp* behavior object).
    pub fn get_opcode(&self) -> OpCode {
        self.opcode
    }

    // Ghidra: op.hh:160 PcodeOp::getAddr
    pub fn get_addr(&self) -> Address {
        self.start.get_addr()
    }

    // Ghidra: op.hh:162 PcodeOp::getSeqNum
    pub fn get_seq_num(&self) -> &SeqNum {
        &self.start
    }

    // Ghidra: op.hh:153 PcodeOp::numInput
    pub fn num_input(&self) -> usize {
        self.inrefs.len()
    }

    // Ghidra: op.hh:156 PcodeOp::getIn
    pub fn get_in(&self, slot: usize) -> Option<&Arc<RwLock<Varnode>>> {
        self.inrefs.get(slot)
    }

    // Ghidra: op.hh:166 PcodeOp::getSlot
    /// Return the input slot holding the given Varnode, or None if not found.
    /// Faithful to `PcodeOp::getSlot(const Varnode *vn)` (op.hh:166):
    ///   int4 i,n; n=inrefs.size(); for(i=0;i<n;++i) if (inrefs[i]==vn) break; return i;
    /// Ghidra returns n (out-of-range) when not found; we return Option<usize>.
    pub fn slot_of_input(&self, vn: &Arc<RwLock<Varnode>>) -> Option<usize> {
        self.inrefs.iter().position(|v| std::sync::Arc::ptr_eq(v, vn))
    }

    // Ghidra: op.hh:154 PcodeOp::getOut
    pub fn get_out(&self) -> Option<&Arc<RwLock<Varnode>>> {
        self.output.as_ref()
    }

    // Ghidra: op.hh:173 PcodeOp::isDead
    pub fn is_dead(&self) -> bool {
        (self.flags & pcodeop_flags::DEAD) != 0
    }

    // Ghidra: op.hh:175 PcodeOp::isCall
    pub fn is_call(&self) -> bool {
        (self.flags & pcodeop_flags::CALL) != 0
    }

    /// Is this op a source of a CPUI_INDIRECT (its output feeds an INDIRECT
    /// that tracks a memory side-effect)? Faithful to `PcodeOp::isIndirectSource`
    /// (op.hh:180). RuleEarlyRemoval must not remove such ops, or the INDIRECT
    /// is left referencing a dead varnode.
    // Ghidra: op.hh:202 PcodeOp::isIndirectSource
    pub fn is_indirect_source(&self) -> bool {
        (self.flags & pcodeop_flags::INDIRECT_SOURCE) != 0
    }

    /// Is this a marker op (MULTIEQUAL/INDIRECT)? Faithful to
    /// `PcodeOp::isMarker` (op.hh:185).
    // Ghidra: op.hh:178 PcodeOp::isMarker
    pub fn is_marker(&self) -> bool {
        (self.flags & pcodeop_flags::MARKER) != 0
    }

    // Ghidra: op.hh:190 PcodeOp::isMark
    /// Has this op been visited by the current algorithm? Faithful to
    /// `PcodeOp::isMark` (op.hh:190). Used by ancestorOpUse to trim cycles in
    /// MULTIEQUAL chains.
    pub fn is_mark(&self) -> bool {
        (self.flags & pcodeop_flags::MARK) != 0
    }
    // Ghidra: op.hh:234 PcodeOp::setMark
    pub fn set_mark(&mut self) {
        self.flags |= pcodeop_flags::MARK;
    }
    // Ghidra: op.hh:235 PcodeOp::clearMark
    pub fn clear_mark(&mut self) {
        self.flags &= !pcodeop_flags::MARK;
    }

    /// Does this op use a spacebase pointer? Faithful to `PcodeOp::usesSpacebasePtr`
    /// (op.hh:228). Set by heritage's discoverIndexedStackPointers when a STORE
    /// reads a stack-pointer-derived address. guardStores checks this to decide
    /// whether to build a Stack-space INDIRECT.
    // Ghidra: op.hh:228 PcodeOp::usesSpacebasePtr
    pub fn uses_spacebase_ptr(&self) -> bool {
        (self.flags & pcodeop_flags::SPACEBASE_PTR) != 0
    }

    /// Mark this op as using a spacebase pointer. Faithful to
    /// `Funcdata::opMarkSpacebasePtr` (funcdata.hh:487).
    // Ghidra: op.hh:138 PcodeOp::setFlag(spacebase_ptr) (called by Funcdata::opMarkSpacebasePtr)
    pub fn mark_spacebase_ptr(&mut self) {
        self.flags |= pcodeop_flags::SPACEBASE_PTR;
    }

    /// Is this op's output a boolean? Faithful to `PcodeOp::isBoolOutput`
    /// (op.hh:190).
    // Ghidra: op.hh:184 PcodeOp::isBoolOutput
    pub fn is_bool_output(&self) -> bool {
        (self.flags & pcodeop_flags::BOOLOUTPUT) != 0
    }

    /// Is the CBRANCH's boolean sense flipped? Faithful to
    /// `PcodeOp::isBooleanFlip` (op.hh:210). When true, the CBRANCH takes
    /// the fallthru edge on a TRUE input (and branches on FALSE).
    // Ghidra: op.hh:191 PcodeOp::isBooleanFlip
    pub fn is_boolean_flip(&self) -> bool {
        (self.flags & pcodeop_flags::BOOLEAN_FLIP) != 0
    }

    /// Compare the control-flow order of this op and `bop`. Returns -1 if
    /// this op comes before bop, 1 if after, 0 if unordered. Faithful to
    /// `PcodeOp::compareOrder` (op.cc:778-790).
    // Ghidra: op.cc:778 PcodeOp::compareOrder
    pub fn compare_order(
        &self,
        bop: &PcodeOp,
    ) -> i32 {
        let p1 = self.parent.as_ref().and_then(|w| w.upgrade());
        let p2 = bop.parent.as_ref().and_then(|w| w.upgrade());
        match (p1, p2) {
            (Some(a), Some(b)) if Arc::ptr_eq(&a, &b) => {
                // Same block: compare SeqNum order.
                if self.start.get_order() < bop.start.get_order() { -1 } else { 1 }
            }
            (Some(a), Some(b)) => {
                let common = crate::block::BlockGraph::find_common_block(&a, &b);
                match common {
                    Some(c) if Arc::ptr_eq(&c, &a) => -1,
                    Some(c) if Arc::ptr_eq(&c, &b) => 1,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    /// Get the evaluation type flags (unary/binary/special/ternary). Faithful
    /// to `PcodeOp::getEvalType` (op.hh:169).
    // Ghidra: op.hh:169 PcodeOp::getEvalType
    pub fn get_eval_type(&self) -> u32 {
        self.flags
            & (pcodeop_flags::UNARY | pcodeop_flags::BINARY | pcodeop_flags::SPECIAL | pcodeop_flags::TERNARY)
    }

    /// Compute a hash for common-subexpression detection. Faithful to
    /// `PcodeOp::getCseHash` (op.cc:130-147). Returns 0 for non-unary/binary
    /// ops or COPY ops.
    // Ghidra: op.cc:130 PcodeOp::getCseHash
    pub fn get_cse_hash(&self) -> u64 {
        if (self.get_eval_type() & (pcodeop_flags::UNARY | pcodeop_flags::BINARY)) == 0 {
            return 0;
        }
        if self.opcode == OpCode::CPUI_COPY {
            return 0; // Let copy propagation deal with this.
        }
        let mut hash: u64 = ((self.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0) as u64) << 8)
            | self.opcode as u64;
        for i in 0..self.inrefs.len() {
            hash = (hash << 8) | (hash >> (std::mem::size_of::<u64>() * 8 - 8));
            let vn = &self.inrefs[i];
            let vn_rg = vn.read().unwrap();
            if vn_rg.is_constant() {
                hash ^= vn_rg.get_offset();
            } else {
                hash ^= vn_rg.create_index as u64;
            }
        }
        hash
    }

    /// Do these two ops represent a common subexpression? Faithful to
    /// `PcodeOp::isCseMatch` (op.cc:153-171).
    // Ghidra: op.cc:153 PcodeOp::isCseMatch
    pub fn is_cse_match(&self, other: &PcodeOp) -> bool {
        if (self.get_eval_type() & (pcodeop_flags::UNARY | pcodeop_flags::BINARY)) == 0 {
            return false;
        }
        if (other.get_eval_type() & (pcodeop_flags::UNARY | pcodeop_flags::BINARY)) == 0 {
            return false;
        }
        let self_out_size = self.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        let other_out_size = other.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        if self_out_size != other_out_size {
            return false;
        }
        if self.opcode != other.opcode {
            return false;
        }
        if self.opcode == OpCode::CPUI_COPY {
            return false; // Let copy propagation deal with this.
        }
        if self.inrefs.len() != other.inrefs.len() {
            return false;
        }
        for i in 0..self.inrefs.len() {
            let vn1 = &self.inrefs[i];
            let vn2 = &other.inrefs[i];
            if std::sync::Arc::ptr_eq(vn1, vn2) {
                continue;
            }
            let r1 = vn1.read().unwrap();
            let r2 = vn2.read().unwrap();
            if r1.is_constant() && r2.is_constant() && r1.get_offset() == r2.get_offset() {
                continue;
            }
            return false;
        }
        true
    }

    // Ghidra: op.hh:185 PcodeOp::isBranch
    pub fn is_branch(&self) -> bool {
        (self.flags & pcodeop_flags::BRANCH) != 0
    }

    /// Is this op's output a calculated boolean value? Faithful to
    /// `PcodeOp::isCalculatedBool` (op.hh:211).
    // Ghidra: op.hh:211 PcodeOp::isCalculatedBool
    pub fn is_calculated_bool(&self) -> bool {
        (self.flags & (pcodeop_flags::CALCULATED_BOOL | pcodeop_flags::BOOLOUTPUT)) != 0
    }

    /// Does this op consume/produce a pointer? Faithful to
    /// `PcodeOp::isPtrFlow` (op.hh:205).
    // Ghidra: op.hh:205 PcodeOp::isPtrFlow
    pub fn is_ptr_flow(&self) -> bool {
        (self.flags & pcodeop_flags::PTRFLOW) != 0
    }
    /// Mark this op as consuming/producing ptrs. Faithful to
    /// `PcodeOp::setPtrFlow` (op.hh:206).
    // Ghidra: op.hh:206 PcodeOp::setPtrFlow
    pub fn set_ptr_flow(&mut self) {
        self.flags |= pcodeop_flags::PTRFLOW;
    }

    /// Has this cpool op been checked for transforms? Faithful to
    /// `PcodeOp::isCpoolTransformed` (op.hh:213). Uses addlflags bit 0x20
    /// (Ghidra `is_cpool_transformed = 0x20`, op.hh:114).
    // Ghidra: op.hh:213 PcodeOp::isCpoolTransformed
    pub fn is_cpool_transformed(&self) -> bool {
        (self.addlflags & 0x20) != 0
    }
    /// Mark this cpool op as transformed. Faithful to
    /// `PcodeOp::setAdditionalFlag(is_cpool_transformed)` (op.hh:140/213).
    // Ghidra: op.hh:140 PcodeOp::setAdditionalFlag(is_cpool_transformed)
    pub fn mark_cpool_transformed(&mut self) {
        self.addlflags |= 0x20;
    }

    /// Does this op require special printing? (op.hh:208, addlflags 0x2)
    // Ghidra: op.hh:208 PcodeOp::doesSpecialPrinting
    pub fn does_special_printing(&self) -> bool {
        (self.addlflags & op_addl_flags::SPECIAL_PRINT) != 0
    }

    /// Clear the stop-type-propagation flag. (op.hh:217, addlflags 0x40)
    // Ghidra: op.hh:217 PcodeOp::clearStopTypePropagation
    pub fn clear_stop_type_propagation(&mut self) {
        self.addlflags &= !op_addl_flags::STOP_TYPE_PROPAGATION;
    }
    // Ghidra: op.hh:215 PcodeOp::stopsTypePropagation
    pub fn stops_type_propagation(&self) -> bool {
        (self.addlflags & op_addl_flags::STOP_TYPE_PROPAGATION) != 0
    }

    /// Is this op marked to never be indirect-collapsed? (op.hh:223, addlflags 0x200)
    // Ghidra: op.hh:223 PcodeOp::noIndirectCollapse
    pub fn no_indirect_collapse(&self) -> bool {
        (self.addlflags & op_addl_flags::NO_INDIRECT_COLLAPSE) != 0
    }
    // Ghidra: op.hh:224 PcodeOp::setNoIndirectCollapse
    pub fn set_no_indirect_collapse(&mut self) {
        self.addlflags |= op_addl_flags::NO_INDIRECT_COLLAPSE;
    }

    // Ghidra: op.hh:179 PcodeOp::isIndirectCreation
    /// Return true if this op creates a varnode indirectly (an INDIRECT op
    /// marked as indirect_creation). Faithful to `PcodeOp::isIndirectCreation`
    /// (op.hh:179): `(flags & indirect_creation) != 0`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to detect call
    /// output creation.
    pub fn is_indirect_creation(&self) -> bool {
        (self.flags & pcodeop_flags::INDIRECT_CREATION) != 0
    }

    // Ghidra: op.hh:180 PcodeOp::isIndirectStore
    /// Return true if this INDIRECT is caused by a STORE. Faithful to
    /// `PcodeOp::isIndirectStore` (op.hh:180):
    ///   `(flags & indirect_store) != 0`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to distinguish
    /// store-induced indirects from call-induced indirects.
    pub fn is_indirect_store(&self) -> bool {
        (self.flags & pcodeop_flags::INDIRECT_STORE) != 0
    }

    // Ghidra: op.hh:209 PcodeOp::isIncidentalCopy
    /// Return true if this COPY is incidental (a side-effect of a call).
    /// Faithful to `PcodeOp::isIncidentalCopy` (op.hh:209):
    ///   `(addlflags & incidental_copy) != 0`.
    /// Used by AncestorRealistic::enterNode (COPY/SUBPIECE cases) and
    /// onlyOpUse to treat incidental copies as transparent.
    pub fn is_incidental_copy(&self) -> bool {
        (self.addlflags & op_addl_flags::INCIDENTAL_COPY) != 0
    }

    // Ghidra: op.hh:225 PcodeOp::isStoreUnmapped
    /// Is this STORE location supposed to be unmapped? Faithful to
    /// `PcodeOp::isStoreUnmapped` (op.hh:225):
    ///   `(addlflags & store_unmapped) != 0`.
    /// Used by AncestorRealistic::enterNode (COPY case) to reject stores
    /// flagged as unmapped.
    pub fn is_store_unmapped(&self) -> bool {
        (self.addlflags & op_addl_flags::STORE_UNMAPPED) != 0
    }

    // Ghidra: op.hh:174 PcodeOp::isAssignment
    /// Return true if this op has an output (i.e. produces a value).
    /// Faithful to `isAssignment` (op.hh:174).
    pub fn is_assignment(&self) -> bool {
        self.output.is_some()
    }

    // Ghidra: op.hh:189 PcodeOp::isFlowBreak
    /// Return true if this op breaks the flow of a basic block (branch/return).
    /// Faithful to `isFlowBreak` (op.hh:189).
    pub fn is_flow_break(&self) -> bool {
        (self.flags & (pcodeop_flags::BRANCH | pcodeop_flags::RETURNS)) != 0
    }

    // Ghidra: op.hh:195 PcodeOp::isInstructionStart
    /// Return true if this op is the first in its machine instruction.
    /// Faithful to `isInstructionStart` (op.hh:195).
    pub fn is_instruction_start(&self) -> bool {
        (self.flags & pcodeop_flags::STARTMARK) != 0
    }

    // Ghidra: op.cc:115 PcodeOp::isCollapsible
    /// Can this op be collapsed to a copy of a constant? All inputs must be
    /// constants, the op must be an assignment, must not be marked nocollapse,
    /// and the output must fit in a uintb. Faithful to `isCollapsible`.
    pub fn is_collapsible(&self) -> bool {
        if (self.flags & pcodeop_flags::NOCOLLAPSE) != 0 {
            return false;
        }
        if !self.is_assignment() {
            return false;
        }
        if self.inrefs.is_empty() {
            return false;
        }
        // All inputs must be constants.
        for inref in &self.inrefs {
            if !inref.read().unwrap().is_constant() {
                return false;
            }
        }
        // Output size must fit in u64 (sizeof(uintb) on 64-bit Ghidra).
        if let Some(out) = &self.output {
            if out.read().unwrap().get_size() > 8 {
                return false;
            }
        }
        true
    }

    // Ghidra: op.cc:290 PcodeOp::setNumInputs
    /// Set the number of input slots. All slots are cleared (set to a sentinel).
    /// Faithful to `setNumInputs` (op.cc:290-296). Note: Rugra's inrefs Vec
    /// cannot hold null; we use a synthetic placeholder varnode via the caller
    /// (Funcdata layer fills slots immediately after). At the PcodeOp level,
    /// we resize and leave existing entries; callers must overwrite.
    pub fn set_num_inputs(&mut self, num: usize) {
        self.inrefs.resize(num, self.inrefs.get(0).cloned().unwrap_or_else(|| {
            // Cannot create a null varnode; panic is consistent with Ghidra's
            // contract that setNumInputs is followed by setInput on every slot.
            panic!("PcodeOp::set_num_inputs to {} requires caller to fill all slots", num);
        }));
    }

    // Ghidra: op.cc:301 PcodeOp::removeInput
    /// Remove the input Varnode at `slot`. Subsequent slots shift down.
    /// Faithful to `removeInput` (op.cc:301-307).
    pub fn remove_input(&mut self, slot: usize) {
        if slot < self.inrefs.len() {
            self.inrefs.remove(slot);
        }
    }

    // Ghidra: op.cc:311 PcodeOp::insertInput
    /// Insert a new input slot at `slot`, shifting subsequent slots up.
    /// The new slot holds a placeholder that the caller must fill.
    /// Faithful to `insertInput` (op.cc:311-318). Same null-placeholder caveat
    /// as `set_num_inputs`.
    pub fn insert_input_slot(&mut self, slot: usize, placeholder: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        let slot = slot.min(self.inrefs.len());
        self.inrefs.insert(slot, placeholder);
    }

    // Ghidra: op.cc:93 PcodeOp::getRepeatSlot
    /// Given a Varnode that appears in multiple input slots, find the specific
    /// slot corresponding to the `count`-th occurrence (1-based). Returns -1 if
    /// not found. Faithful to `getRepeatSlot` (op.cc:93-111).
    pub fn get_repeat_slot(&self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, first_slot: usize, count: usize) -> i32 {
        // Walk input slots from first_slot+1, find the (count)-th occurrence.
        let mut recount = 1;
        for i in (first_slot + 1)..self.inrefs.len() {
            if std::sync::Arc::ptr_eq(&self.inrefs[i], vn) {
                recount += 1;
                if recount == count {
                    return i as i32;
                }
            }
        }
        -1
    }

    // Ghidra: op.cc:376 PcodeOp::printDebug
    /// Print a debug representation (address + raw op) to a string.
    /// Faithful to `printDebug` (op.cc:376-384). Rugra returns a String
    /// instead of writing to ostream.
    pub fn print_debug(&self) -> String {
        let mut s = String::new();
        s += &format!("{:?}: ", self.start);
        if self.is_dead() || self.parent.is_none() {
            s += "**";
        } else {
            s += &format!("{:?}", self.opcode);
            if let Some(out) = &self.output {
                let o = out.read().unwrap();
                s += &format!(" v({:?},{:#x})", o.address_space, o.loc.as_u64());
            }
            for inref in &self.inrefs {
                let i = inref.read().unwrap();
                s += &format!(" ({:?},{:#x})", i.address_space, i.loc.as_u64());
            }
        }
        s
    }

    // Ghidra: op.cc:450 PcodeOp::collapse
    /// Collapse constant inputs into a single result. Faithful to
    /// `collapse` (op.cc:450-472). Uses opbehavior evaluate methods.
    /// Returns Some(result) or None if not collapsible.
    pub fn collapse(&self) -> Option<(u64, bool)> {
        use crate::opbehavior::{evaluate_unary, evaluate_binary};
        let eval_type = self.get_eval_type();
        let vn0 = self.inrefs.get(0)?;
        let vn0_r = vn0.read().unwrap();
        let marked_input = vn0_r.get_symbol_entry().is_some();
        let out_size = self.output.as_ref()?.read().unwrap().get_size();
        let vn0_size = vn0_r.get_size();
        let vn0_offset = vn0_r.get_offset();
        drop(vn0_r);
        match eval_type {
            x if (x & pcodeop_flags::UNARY) != 0 => {
                evaluate_unary(self.opcode, out_size, vn0_size, vn0_offset)
                    .map(|r| (r, marked_input))
            }
            x if (x & pcodeop_flags::BINARY) != 0 => {
                let vn1 = self.inrefs.get(1)?;
                let vn1_r = vn1.read().unwrap();
                let vn1_size = vn1_r.get_size();
                let vn1_offset = vn1_r.get_offset();
                let marked2 = vn1_r.get_symbol_entry().is_some();
                drop(vn1_r);
                evaluate_binary(self.opcode, out_size, vn0_size, vn0_offset, vn1_offset)
                    .map(|r| (r, marked_input || marked2))
            }
            _ => None,
        }
    }

    // Ghidra: op.cc:478 PcodeOp::executeSimple
    /// Execute the op on given input values. Faithful to `executeSimple`
    /// (op.cc:478-498). Returns Some(result) or None on eval error.
    pub fn execute_simple(&self, inputs: &[u64]) -> Option<u64> {
        use crate::opbehavior::{evaluate_unary, evaluate_binary, evaluate_ternary};
        let eval_type = self.get_eval_type();
        let out_size = self.output.as_ref()?.read().unwrap().get_size();
        let in0_size = self.inrefs.first()?.read().unwrap().get_size();
        match eval_type {
            x if (x & pcodeop_flags::UNARY) != 0 => {
                evaluate_unary(self.opcode, out_size, in0_size, inputs.get(0).copied()?)
            }
            x if (x & pcodeop_flags::BINARY) != 0 => {
                evaluate_binary(self.opcode, out_size, in0_size,
                    inputs.get(0).copied()?, inputs.get(1).copied()?)
            }
            x if (x & pcodeop_flags::TERNARY) != 0 => {
                evaluate_ternary(self.opcode, out_size, in0_size,
                    inputs.get(0).copied()?, inputs.get(1).copied()?, inputs.get(2).copied()?)
            }
            _ => None,
        }
    }

    // Ghidra: op.cc:547 PcodeOp::getNZMaskLocal
    /// Compute non-zero mask for this op's output given input masks.
    /// Faithful to `getNZMaskLocal` (op.cc:547-771). This is a large
    /// switch on opcode. Rugra delegates to Funcdata::calc_nz_mask for
    /// the per-opcode switch; this method is the per-op entry point.
    pub fn get_nz_mask_local(&self, _cliploop: bool) -> u64 {
        use crate::address::calc_mask;
        let out_size = match &self.output {
            Some(o) => o.read().unwrap().get_size(),
            None => return u64::MAX,
        };
        let full_mask = calc_mask(out_size);
        let get_in_nzm = |i: usize| -> u64 {
            self.inrefs.get(i)
                .map(|v| v.read().unwrap().get_nz_mask())
                .unwrap_or(full_mask)
        };
        let get_in_const = |i: usize| -> Option<u64> {
            let v = self.inrefs.get(i)?;
            let r = v.read().unwrap();
            if r.is_constant() { Some(r.get_offset()) } else { None }
        };
        match self.opcode {
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY
            | OpCode::CPUI_INT_SBORROW
            | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_XOR
            | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_FLOAT_NAN => 1,
            OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT => get_in_nzm(0),
            OpCode::CPUI_INT_SEXT => {
                let in_sz = self.inrefs.first().map(|v| v.read().unwrap().get_size()).unwrap_or(out_size);
                crate::rangeutil::sign_extend_size(get_in_nzm(0), in_sz, out_size)
            }
            OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR => {
                let m = get_in_nzm(0);
                if m != full_mask { m | get_in_nzm(1) } else { m }
            }
            OpCode::CPUI_INT_AND => {
                let m = get_in_nzm(0);
                if m != 0 { m & get_in_nzm(1) } else { 0 }
            }
            OpCode::CPUI_INT_LEFT => {
                match get_in_const(1) {
                    Some(sa) => {
                        let m = get_in_nzm(0);
                        m.wrapping_shl(sa as u32) & full_mask
                    }
                    None => full_mask,
                }
            }
            OpCode::CPUI_INT_RIGHT => {
                match get_in_const(1) {
                    Some(sa) => get_in_nzm(0).wrapping_shr(sa as u32),
                    None => full_mask,
                }
            }
            OpCode::CPUI_INT_SRIGHT => {
                match get_in_const(1) {
                    Some(sa) if out_size <= 8 => {
                        let m = get_in_nzm(0);
                        m.wrapping_shr(sa as u32)
                    }
                    _ => full_mask,
                }
            }
            OpCode::CPUI_SUBPIECE => {
                let sz1 = get_in_const(1).unwrap_or(0) as usize;
                let m = get_in_nzm(0);
                if sz1 < 8 { m.wrapping_shr((sz1 * 8) as u32) & full_mask } else { 0 }
            }
            OpCode::CPUI_PIECE => {
                let sa = self.inrefs.get(1).map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                let m0 = get_in_nzm(0);
                let shifted = if sa < 8 { m0 << (sa * 8) } else { 0 };
                shifted | get_in_nzm(1)
            }
            OpCode::CPUI_INT_ADD => {
                let m = get_in_nzm(0);
                if m != full_mask {
                    (m | get_in_nzm(1) | (m << 1)) & full_mask
                } else { m }
            }
            OpCode::CPUI_MULTIEQUAL => {
                if self.inrefs.is_empty() { full_mask }
                else {
                    let mut r = 0u64;
                    for i in 0..self.inrefs.len() {
                        r |= get_in_nzm(i);
                    }
                    r
                }
            }
            _ => full_mask,
        }
    }
}

/// Comparison for sorting PcodeOps in the bank
impl PartialEq for PcodeOp {
    // RUGRA-GLUE: Rust PartialEq impl; Ghidra orders PcodeOps by SeqNum via
    //   std::map<SeqNum,PcodeOp*> (PcodeOpTree, op.hh:280) and has no
    //   operator== on PcodeOp.
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl Eq for PcodeOp {}

impl PartialOrd for PcodeOp {
    // RUGRA-GLUE: delegates to Ord (see below).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcodeOp {
    // RUGRA-GLUE: Rust Ord impl mirroring Ghidra's SeqNum ordering used by
    //   PcodeOpTree (op.hh:280 std::map<SeqNum,PcodeOp*>).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

/// Wrapper for Arc<RwLock<PcodeOp>> for use in collections
#[derive(Debug, Clone)]
pub struct PcodeOpRef(pub Arc<RwLock<PcodeOp>>);

impl PartialEq for PcodeOpRef {
    // RUGRA-GLUE: Rust PartialEq impl for the Arc wrapper; Ghidra has no
    //   equivalent (uses raw PcodeOp* pointers).
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) { return true; }
        self.0.read().unwrap().eq(&other.0.read().unwrap())
    }
}

impl Eq for PcodeOpRef {}

impl PartialOrd for PcodeOpRef {
    // RUGRA-GLUE: delegates to Ord (see below).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcodeOpRef {
    // RUGRA-GLUE: Rust Ord impl for the Arc wrapper; delegates to the inner
    //   PcodeOp Ord (SeqNum ordering).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) { return std::cmp::Ordering::Equal; }
        self.0.read().unwrap().cmp(&other.0.read().unwrap())
    }
}

/// Corresponds to Ghidra's `PieceNode` class in `op.hh`
pub struct PieceNode {
    pub piece_op: Weak<RwLock<PcodeOp>>,
    pub slot: i32,
    pub type_offset: i32,
    pub leaf: bool,
}

impl PieceNode {
    // Ghidra: op.hh:268 PieceNode::PieceNode (ctor)
    pub fn new(op: Weak<RwLock<PcodeOp>>, slot: i32, offset: i32) -> Self {
        Self {
            piece_op: op,
            slot,
            type_offset: offset,
            leaf: false,
        }
    }

    // Ghidra: op.hh:269 PieceNode::isLeaf
    pub fn is_leaf(&self) -> bool {
        self.leaf
    }

    // Ghidra: op.hh:270 PieceNode::getTypeOffset
    pub fn get_type_offset(&self) -> i32 {
        self.type_offset
    }

    // Ghidra: op.hh:271 PieceNode::getSlot
    pub fn get_slot(&self) -> i32 {
        self.slot
    }
}

/// Container for managing P-code operations
///
/// Corresponds to Ghidra's `PcodeOpBank` class in `op.hh`
#[derive(Debug)]
pub struct PcodeOpBank {
    /// All operations sorted by sequence number (Ghidra optree).
    pub optree: BTreeSet<PcodeOpRef>,
    /// List of operations considered "alive" (Ghidra alivelist).
    pub alivelist: Vec<PcodeOpRef>,
    /// List of operations considered "dead" (Ghidra deadlist).
    pub deadlist: Vec<PcodeOpRef>,
    /// Lists of ops by specific opcode (Ghidra op.hh:293-296).
    /// Used for fast iteration over STORE/LOAD/RETURN/CALLOTHER ops.
    pub storelist: Vec<PcodeOpRef>,
    pub loadlist: Vec<PcodeOpRef>,
    pub returnlist: Vec<PcodeOpRef>,
    pub useroplist: Vec<PcodeOpRef>,

    /// Internal unique ID counter for sequence numbers (Ghidra uniqid).
    uniqid: u32,
}

impl PcodeOpBank {
    // Ghidra: op.hh:304 PcodeOpBank::PcodeOpBank (ctor; uniqid = 0)
    pub fn new() -> Self {
        Self {
            optree: BTreeSet::new(),
            alivelist: Vec::new(),
            deadlist: Vec::new(),
            storelist: Vec::new(),
            loadlist: Vec::new(),
            returnlist: Vec::new(),
            useroplist: Vec::new(),
            uniqid: 0,
        }
    }

    /// Create a new P-code operation and add it to the bank
    // Ghidra: op.hh:308 PcodeOpBank::create
    pub fn create(&mut self, opcode: OpCode, num_inputs: usize, addr: Address) -> PcodeOpRef {
        let seq = SeqNum::new(addr, self.uniqid);
        self.uniqid += 1;

        let mut op = PcodeOp::new(seq, opcode);
        // Inputs will be populated later
        op.inrefs.reserve(num_inputs);

        let op_ref = PcodeOpRef(Arc::new(RwLock::new(op)));
        self.optree.insert(op_ref.clone());
        self.alivelist.push(op_ref.clone());
        op_ref
    }

    // Ghidra: op.hh:313 PcodeOpBank::markAlive
    pub fn mark_alive(&mut self, op: PcodeOpRef) {
        let mut op_borrow = op.0.write().unwrap();
        if (op_borrow.flags & pcodeop_flags::DEAD) != 0 {
            op_borrow.flags &= !pcodeop_flags::DEAD;
            self.deadlist
                .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
            self.alivelist.push(op.clone());
        }
    }

    // Ghidra: op.hh:314 PcodeOpBank::markDead
    pub fn mark_dead(&mut self, op: PcodeOpRef) {
        let mut op_borrow = op.0.write().unwrap();
        if (op_borrow.flags & pcodeop_flags::DEAD) == 0 {
            op_borrow.flags |= pcodeop_flags::DEAD;
            self.alivelist
                .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
            self.deadlist.push(op.clone());
        }
    }

    // Ghidra: op.cc:881 PcodeOpBank::addToCodeList
    /// Add op to opcode-specific list (STORE/LOAD/RETURN/CALLOTHER).
    /// Faithful to `addToCodeList` (op.cc:881-900).
    pub fn add_to_code_list(&mut self, op: &PcodeOpRef) {
        let opc = op.0.read().unwrap().opcode;
        match opc {
            OpCode::CPUI_STORE => self.storelist.push(op.clone()),
            OpCode::CPUI_LOAD => self.loadlist.push(op.clone()),
            OpCode::CPUI_RETURN => self.returnlist.push(op.clone()),
            OpCode::CPUI_CALLOTHER => self.useroplist.push(op.clone()),
            _ => {}
        }
    }

    // Ghidra: op.cc:905 PcodeOpBank::removeFromCodeList
    /// Remove op from its opcode-specific list.
    /// Faithful to `removeFromCodeList` (op.cc:905-924).
    pub fn remove_from_code_list(&mut self, op: &PcodeOpRef) {
        let opc = op.0.read().unwrap().opcode;
        let ptr = Arc::as_ptr(&op.0);
        match opc {
            OpCode::CPUI_STORE => self.storelist.retain(|x| Arc::as_ptr(&x.0) != ptr),
            OpCode::CPUI_LOAD => self.loadlist.retain(|x| Arc::as_ptr(&x.0) != ptr),
            OpCode::CPUI_RETURN => self.returnlist.retain(|x| Arc::as_ptr(&x.0) != ptr),
            OpCode::CPUI_CALLOTHER => self.useroplist.retain(|x| Arc::as_ptr(&x.0) != ptr),
            _ => {}
        }
    }

    // Ghidra: op.cc:926 PcodeOpBank::clearCodeLists
    pub fn clear_code_lists(&mut self) {
        self.storelist.clear();
        self.loadlist.clear();
        self.returnlist.clear();
        self.useroplist.clear();
    }

    // Ghidra: op.hh:312 PcodeOpBank::changeOpcode
    /// Change opcode: remove from old code list, set new opcode, add to new list.
    /// Faithful to `changeOpcode` (op.cc:1005-1012).
    pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode) {
        let old_opc = op.0.read().unwrap().opcode;
        // cc:1008: if old opcode was in a code list, remove it.
        if old_opc != new_opc {
            self.remove_from_code_list(&op);
        }
        op.0.write().unwrap().opcode = new_opc;
        // cc:1011: add to new code list.
        self.add_to_code_list(&op);
    }

    // Ghidra: op.hh:311 PcodeOpBank::destroyDead
    pub fn destroy_dead(&mut self) {
        for op in &self.deadlist {
            self.optree.remove(op);
        }
        self.deadlist.clear();
    }

    // Ghidra: op.hh:310 PcodeOpBank::destroy
    pub fn destroy(&mut self, op: PcodeOpRef) {
        self.optree.remove(&op);
        self.alivelist
            .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
        self.deadlist
            .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
        self.remove_from_code_list(&op);
    }

    // Ghidra: op.hh:320 PcodeOpBank::findOp
    pub fn find_op(&self, seq: &SeqNum) -> Option<PcodeOpRef> {
        for op_ref in &self.optree {
            if &op_ref.0.read().unwrap().start == seq {
                return Some(op_ref.clone());
            }
        }
        None
    }

    // Ghidra: op.hh:303 PcodeOpBank::clear
    // Ghidra: op.cc:1194 PcodeOpBank::clear
    pub fn clear(&mut self) {
        self.optree.clear();
        self.alivelist.clear();
        self.deadlist.clear();
        self.clear_code_lists();
        self.uniqid = 0;
    }

    // Ghidra: op.hh:318 PcodeOpBank::empty
    pub fn is_empty(&self) -> bool {
        self.optree.is_empty()
    }

    // Ghidra: op.hh:307 PcodeOpBank::getUniqId
    pub fn get_uniqid(&self) -> u32 {
        self.uniqid
    }

    // Ghidra: op.cc:1039 PcodeOpBank::insertAfterDead
    /// Move op to right after prev in the dead list. Both must be dead.
    /// Faithful to `insertAfterDead` (op.cc:1039-1048).
    pub fn insert_after_dead(&mut self, op: &PcodeOpRef, prev: &PcodeOpRef) {
        // cc:1042: verify both are dead.
        if !op.0.read().unwrap().is_dead() || !prev.0.read().unwrap().is_dead() {
            eprintln!("[OP] WARN: insertAfterDead on non-dead op");
            return;
        }
        // Remove op from deadlist, reinsert after prev.
        let op_ptr = Arc::as_ptr(&op.0);
        let prev_pos = self.deadlist.iter().position(|r| Arc::as_ptr(&r.0) == Arc::as_ptr(&prev.0));
        if let Some(prev_idx) = prev_pos {
            self.deadlist.retain(|r| Arc::as_ptr(&r.0) != op_ptr);
            self.deadlist.insert(prev_idx + 1, op.clone());
        }
    }

    // Ghidra: op.cc:1056 PcodeOpBank::moveSequenceDead
    /// Move a sequence of ops to right after prev in the dead list.
    /// Faithful to `moveSequenceDead` (op.cc:1056-1065).
    pub fn move_sequence_dead(&mut self, firstop: &PcodeOpRef, lastop: &PcodeOpRef, prev: &PcodeOpRef) {
        let first_ptr = Arc::as_ptr(&firstop.0);
        let last_ptr = Arc::as_ptr(&lastop.0);
        let prev_ptr = Arc::as_ptr(&prev.0);

        // Find positions.
        let first_pos = self.deadlist.iter().position(|r| Arc::as_ptr(&r.0) == first_ptr);
        let last_pos = self.deadlist.iter().position(|r| Arc::as_ptr(&r.0) == last_ptr);
        let prev_pos = self.deadlist.iter().position(|r| Arc::as_ptr(&r.0) == prev_ptr);

        if let (Some(first_idx), Some(last_idx), Some(prev_idx)) = (first_pos, last_pos, prev_pos) {
            if last_idx < first_idx { return; } // Invalid range
            // Extract the sequence.
            let mut seq: Vec<PcodeOpRef> = self.deadlist.drain(first_idx..=last_idx).collect();
            // Adjust prev_idx if it was after the removed range.
            let prev_idx = if prev_idx > last_idx { prev_idx - (last_idx - first_idx + 1) } else { prev_idx };
            // Reinsert after prev.
            self.deadlist.splice(prev_idx + 1..prev_idx + 1, seq.drain(..));
        }
    }

    // Ghidra: op.cc:1071 PcodeOpBank::markIncidentalCopy
    /// Mark COPY ops in the dead list range [firstop, lastop] as incidental.
    /// Faithful to `markIncidentalCopy` (op.cc:1071-1083).
    pub fn mark_incidental_copy(&mut self, firstop: &PcodeOpRef, lastop: &PcodeOpRef) {
        let first_ptr = Arc::as_ptr(&firstop.0);
        let last_ptr = Arc::as_ptr(&lastop.0);
        let mut in_range = false;
        let mut done = false;
        for op_ref in &self.deadlist {
            let ptr = Arc::as_ptr(&op_ref.0);
            if ptr == first_ptr { in_range = true; }
            if in_range {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_COPY {
                    drop(op);
                    op_ref.0.write().unwrap().addlflags |= crate::op::op_addl_flags::INCIDENTAL_COPY;
                }
            }
            if ptr == last_ptr { done = true; break; }
        }
        let _ = done;
    }

    // Ghidra: op.cc:1089 PcodeOpBank::target
    /// Find the first PcodeOp at or after the given Address.
    /// Faithful to `target` (op.cc:1089-1097).
    pub fn target(&self, addr: crate::address::Address) -> Option<PcodeOpRef> {
        for op_ref in &self.optree {
            let op = op_ref.0.read().unwrap();
            if op.start.addr >= addr {
                return Some(op_ref.clone());
            }
        }
        None
    }

    // Ghidra: op.cc:1110 PcodeOpBank::fallthru
    /// Find the fall-through op (next op in alive list after the given op).
    /// Faithful to `fallthru` (op.cc:1110-1144).
    pub fn fallthru(&self, op: &PcodeOpRef) -> Option<PcodeOpRef> {
        let op_ptr = Arc::as_ptr(&op.0);
        let mut found = false;
        for next_ref in &self.alivelist {
            if found {
                return Some(next_ref.clone());
            }
            if Arc::as_ptr(&next_ref.0) == op_ptr {
                found = true;
            }
        }
        None
    }

    // Ghidra: op.hh:306 PcodeOpBank::setUniqId
    pub fn set_uniqid(&mut self, val: u32) {
        self.uniqid = val;
    }
}

impl Default for PcodeOpBank {
    // RUGRA-GLUE: Rust Default impl; Ghidra has no Default concept but the
    //   PcodeOpBank() ctor (op.hh:304) is the equivalent zero-initializer.
    fn default() -> Self {
        Self::new()
    }
}
