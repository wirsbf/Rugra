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

    pub fn get_opcode(&self) -> OpCode {
        self.opcode
    }

    pub fn get_addr(&self) -> Address {
        self.start.get_addr()
    }

    pub fn get_seq_num(&self) -> &SeqNum {
        &self.start
    }

    pub fn num_input(&self) -> usize {
        self.inrefs.len()
    }

    pub fn get_in(&self, slot: usize) -> Option<&Arc<RwLock<Varnode>>> {
        self.inrefs.get(slot)
    }

    pub fn get_out(&self) -> Option<&Arc<RwLock<Varnode>>> {
        self.output.as_ref()
    }

    pub fn is_dead(&self) -> bool {
        (self.flags & pcodeop_flags::DEAD) != 0
    }

    pub fn is_call(&self) -> bool {
        (self.flags & pcodeop_flags::CALL) != 0
    }

    /// Is this a marker op (MULTIEQUAL/INDIRECT)? Faithful to
    /// `PcodeOp::isMarker` (op.hh:185).
    pub fn is_marker(&self) -> bool {
        (self.flags & pcodeop_flags::MARKER) != 0
    }

    /// Is this op's output a boolean? Faithful to `PcodeOp::isBoolOutput`
    /// (op.hh:190).
    pub fn is_bool_output(&self) -> bool {
        (self.flags & pcodeop_flags::BOOLOUTPUT) != 0
    }

    /// Get the evaluation type flags (unary/binary/special/ternary). Faithful
    /// to `PcodeOp::getEvalType` (op.hh:169).
    pub fn get_eval_type(&self) -> u32 {
        self.flags
            & (pcodeop_flags::UNARY | pcodeop_flags::BINARY | pcodeop_flags::SPECIAL | pcodeop_flags::TERNARY)
    }

    /// Compute a hash for common-subexpression detection. Faithful to
    /// `PcodeOp::getCseHash` (op.cc:130-147). Returns 0 for non-unary/binary
    /// ops or COPY ops.
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

    pub fn is_branch(&self) -> bool {
        (self.flags & pcodeop_flags::BRANCH) != 0
    }

    /// Is this op's output a calculated boolean value? Faithful to
    /// `PcodeOp::isCalculatedBool` (op.hh:211).
    pub fn is_calculated_bool(&self) -> bool {
        (self.flags & (pcodeop_flags::CALCULATED_BOOL | pcodeop_flags::BOOLOUTPUT)) != 0
    }
}

/// Comparison for sorting PcodeOps in the bank
impl PartialEq for PcodeOp {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl Eq for PcodeOp {}

impl PartialOrd for PcodeOp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcodeOp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

/// Wrapper for Arc<RwLock<PcodeOp>> for use in collections
#[derive(Debug, Clone)]
pub struct PcodeOpRef(pub Arc<RwLock<PcodeOp>>);

impl PartialEq for PcodeOpRef {
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) { return true; }
        self.0.read().unwrap().eq(&other.0.read().unwrap())
    }
}

impl Eq for PcodeOpRef {}

impl PartialOrd for PcodeOpRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcodeOpRef {
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
    pub fn new(op: Weak<RwLock<PcodeOp>>, slot: i32, offset: i32) -> Self {
        Self {
            piece_op: op,
            slot,
            type_offset: offset,
            leaf: false,
        }
    }

    pub fn is_leaf(&self) -> bool {
        self.leaf
    }

    pub fn get_type_offset(&self) -> i32 {
        self.type_offset
    }

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
    pub fn new() -> Self {
        Self {
            optree: BTreeSet::new(),
            alivelist: Vec::new(),
            deadlist: Vec::new(),
            uniqid: 0,
        }
    }

    /// Create a new P-code operation and add it to the bank
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

    pub fn mark_alive(&mut self, op: PcodeOpRef) {
        let mut op_borrow = op.0.write().unwrap();
        if (op_borrow.flags & pcodeop_flags::DEAD) != 0 {
            op_borrow.flags &= !pcodeop_flags::DEAD;
            self.deadlist
                .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
            self.alivelist.push(op.clone());
        }
    }

    pub fn mark_dead(&mut self, op: PcodeOpRef) {
        let mut op_borrow = op.0.write().unwrap();
        if (op_borrow.flags & pcodeop_flags::DEAD) == 0 {
            op_borrow.flags |= pcodeop_flags::DEAD;
            self.alivelist
                .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
            self.deadlist.push(op.clone());
        }
    }

    pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode) {
        let mut op_borrow = op.0.write().unwrap();
        op_borrow.opcode = new_opc;
    }

    pub fn destroy_dead(&mut self) {
        for op in &self.deadlist {
            self.optree.remove(op);
        }
        self.deadlist.clear();
    }

    pub fn destroy(&mut self, op: PcodeOpRef) {
        self.optree.remove(&op);
        self.alivelist
            .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
        self.deadlist
            .retain(|x| Arc::as_ptr(&x.0) != Arc::as_ptr(&op.0));
    }

    pub fn find_op(&self, seq: &SeqNum) -> Option<PcodeOpRef> {
        for op_ref in &self.optree {
            if &op_ref.0.read().unwrap().start == seq {
                return Some(op_ref.clone());
            }
        }
        None
    }

    pub fn clear(&mut self) {
        self.optree.clear();
        self.alivelist.clear();
        self.deadlist.clear();
        self.uniqid = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.optree.is_empty()
    }

    pub fn get_uniqid(&self) -> u32 {
        self.uniqid
    }

    pub fn set_uniqid(&mut self, val: u32) {
        self.uniqid = val;
    }
}

impl Default for PcodeOpBank {
    fn default() -> Self {
        Self::new()
    }
}
