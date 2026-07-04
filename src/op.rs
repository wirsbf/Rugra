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

    /// Does this op use a spacebase pointer? Faithful to `PcodeOp::usesSpacebasePtr`
    /// (op.hh:432). Set by heritage's discoverIndexedStackPointers when a STORE
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
    /// All operations sorted by sequence number
    pub optree: BTreeSet<PcodeOpRef>,
    /// List of operations considered "alive"
    pub alivelist: Vec<PcodeOpRef>,
    /// List of operations considered "dead"
    pub deadlist: Vec<PcodeOpRef>,

    /// Internal unique ID counter for sequence numbers within a block
    uniqid: u32,
}

impl PcodeOpBank {
    // Ghidra: op.hh:304 PcodeOpBank::PcodeOpBank (ctor; uniqid = 0)
    pub fn new() -> Self {
        Self {
            optree: BTreeSet::new(),
            alivelist: Vec::new(),
            deadlist: Vec::new(),
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

    // Ghidra: op.hh:312 PcodeOpBank::changeOpcode
    pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode) {
        let mut op_borrow = op.0.write().unwrap();
        op_borrow.opcode = new_opc;
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
    pub fn clear(&mut self) {
        self.optree.clear();
        self.alivelist.clear();
        self.deadlist.clear();
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
