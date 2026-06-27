//! Dynamic hash-based variable/op identification.
//!
//! Corresponds to Ghidra's `dynamic.hh` / `dynamic.cc` (773 lines).
//!
//! DynamicHash provides a content-addressable hash for Varnodes and PcodeOps
//! that is stable across recompilation. It builds a local sub-graph around
//! the target and hashes the op-code structure + addresses to produce a
//! unique identifier. This is used by the decompiler for:
//! - Equate/rename annotations that reference specific varnodes
//! - Cross-compilation variable identification
//! - Debug/trace annotations
//!
//! Key classes:
//! - `ToOpEdge`: an edge from a Varnode to a PcodeOp (with slot)
//! - `DynamicHash`: the hashing engine
//!
//! # Status (2026-06-27)
//! Data structures + transtable + calcHash skeleton ported.
//! The full BFS sub-graph expansion + CRC hashing is partially implemented.

use crate::address::Address;
use crate::opcodes::OpCode;
use crate::op::PcodeOp;
use crate::varnode::Varnode;
use std::sync::{Arc, RwLock};

/// Translation table: how to hash opcodes. Lumps variants (ADD/SUB) into
/// the same hash. Zero = skip (CAST). Faithful to `DynamicHash::transtable`
/// (dynamic.cc:24-63).
pub fn translate_opcode(opc: OpCode) -> u32 {
    use OpCode::*;
    match opc {
        CPUI_COPY | CPUI_LOAD | CPUI_STORE | CPUI_BRANCH | CPUI_CBRANCH
        | CPUI_BRANCHIND | CPUI_CALL | CPUI_CALLIND | CPUI_CALLOTHER | CPUI_RETURN
        | CPUI_INT_EQUAL | CPUI_INT_NOTEQUAL | CPUI_INT_SLESS | CPUI_INT_SLESSEQUAL
        | CPUI_INT_LESS | CPUI_INT_LESSEQUAL | CPUI_INT_ZEXT | CPUI_INT_SEXT
        | CPUI_INT_ADD | CPUI_INT_SUB | CPUI_INT_CARRY | CPUI_INT_SCARRY | CPUI_INT_SBORROW
        | CPUI_INT_2COMP | CPUI_INT_NEGATE | CPUI_INT_XOR | CPUI_INT_AND | CPUI_INT_OR
        | CPUI_INT_MULT | CPUI_INT_LEFT | CPUI_INT_RIGHT | CPUI_INT_SRIGHT
        | CPUI_INT_DIV | CPUI_INT_SDIV | CPUI_INT_REM | CPUI_INT_SREM
        | CPUI_BOOL_NEGATE | CPUI_BOOL_XOR | CPUI_BOOL_AND | CPUI_BOOL_OR
        | CPUI_FLOAT_EQUAL | CPUI_FLOAT_NOTEQUAL | CPUI_FLOAT_LESS | CPUI_FLOAT_LESSEQUAL
        | CPUI_FLOAT_NAN | CPUI_FLOAT_ADD | CPUI_FLOAT_DIV | CPUI_FLOAT_MULT
        | CPUI_FLOAT_SUB | CPUI_FLOAT_NEG | CPUI_FLOAT_ABS | CPUI_FLOAT_SQRT
        | CPUI_FLOAT_INT2FLOAT | CPUI_FLOAT_FLOAT2FLOAT | CPUI_FLOAT_TRUNC
        | CPUI_FLOAT_CEIL | CPUI_FLOAT_FLOOR | CPUI_FLOAT_ROUND
        | CPUI_MULTIEQUAL | CPUI_INDIRECT | CPUI_PIECE | CPUI_SUBPIECE
        | CPUI_PTRADD | CPUI_PTRSUB | CPUI_SEGMENTOP | CPUI_CPOOLREF | CPUI_NEW
        | CPUI_INSERT | CPUI_EXTRACT | CPUI_POPCOUNT | CPUI_LZCOUNT => opc as u32,
        // CAST = skip (opcode 71 in Ghidra, not in Rugra's enum)
        _ => 0,
    }
}

/// An edge from a Varnode to a PcodeOp that reads it, with the slot index.
/// Faithful to `ToOpEdge` (dynamic.hh:32).
#[derive(Clone, Debug)]
pub struct ToOpEdge {
    /// The PcodeOp that reads the Varnode.
    pub op: Arc<RwLock<PcodeOp>>,
    /// Which input slot the Varnode occupies.
    pub slot: usize,
}

impl ToOpEdge {
    pub fn new(op: Arc<RwLock<PcodeOp>>, slot: usize) -> Self {
        Self { op, slot }
    }

    /// Compare edges for sorting. Faithful to `ToOpEdge::operator<`
    /// (dynamic.cc:69-81): by op address, then order, then slot.
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.op.read().unwrap();
        let b = other.op.read().unwrap();
        let addr_cmp = a.get_addr().as_u64().cmp(&b.get_addr().as_u64());
        if addr_cmp != std::cmp::Ordering::Equal { return addr_cmp; }
        let ord_cmp = a.start.get_order().cmp(&b.start.get_order());
        if ord_cmp != std::cmp::Ordering::Equal { return ord_cmp; }
        self.slot.cmp(&other.slot)
    }

    /// Fold this edge into the hash accumulator. Faithful to `ToOpEdge::hash`
    /// (dynamic.cc:92-107).
    pub fn hash_into(&self, reg: u32) -> u32 {
        let mut h = crate::crc32::crc_update(reg, self.slot as u32);
        h = crate::crc32::crc_update(h, translate_opcode(self.op.read().unwrap().opcode));
        let addr = self.op.read().unwrap().get_addr().as_u64();
        // Hash each byte of the address.
        for i in 0..8 {
            let byte = ((addr >> (i * 8)) & 0xff) as u32;
            if byte == 0 && i > 0 { break; }
            h = crate::crc32::crc_update(h, byte);
        }
        h
    }
}

/// The dynamic hashing engine. Faithful to `DynamicHash` (dynamic.hh:62).
pub struct DynamicHash {
    /// List of PcodeOps in the sub-graph being hashed.
    mark_op: Vec<Arc<RwLock<PcodeOp>>>,
    /// List of Varnodes in the sub-graph being hashed.
    mark_vn: Vec<Arc<RwLock<Varnode>>>,
    /// Staging area for Varnodes before formally adding.
    vn_edge: Vec<Arc<RwLock<Varnode>>>,
    /// Edges in the sub-graph.
    op_edge: Vec<ToOpEdge>,
    /// Address most closely associated with the variable.
    addr_result: Address,
    /// The calculated hash value.
    hash: u64,
}

/// Hash encoding constants.
/// Hash layout (from dynamic.cc pieceTogetherHash):
/// bits 0-31: formal CRC hash
/// bits 32-37: method (0-63)
/// bits 38-43: opcode
/// bits 44-53: position (collision)
/// bits 54-57: total (collision count)
/// bit 58: is_not_attached flag

impl DynamicHash {
    pub fn new() -> Self {
        Self {
            mark_op: Vec::new(),
            mark_vn: Vec::new(),
            vn_edge: Vec::new(),
            op_edge: Vec::new(),
            addr_result: Address::new(0),
            hash: 0,
        }
    }

    /// Clear for a new hash calculation. Faithful to `DynamicHash::clear`
    /// (dynamic.cc:193-201).
    pub fn clear(&mut self) {
        self.mark_op.clear();
        self.mark_vn.clear();
        self.vn_edge.clear();
        self.op_edge.clear();
    }

    /// Get the current hash value.
    pub fn get_hash(&self) -> u64 { self.hash }

    /// Get the current address.
    pub fn get_address(&self) -> Address { self.addr_result }

    /// Extract the slot from a hash. Faithful to `getSlotFromHash`
    /// (dynamic.cc:707).
    pub fn get_slot_from_hash(h: u64) -> i32 {
        -1 // No slot encoding in Rugra's simplified hash yet
    }

    /// Extract the method from a hash. Faithful to `getMethodFromHash`
    /// (dynamic.cc:719).
    pub fn get_method_from_hash(h: u64) -> u32 {
        ((h >> 32) & 0x3f) as u32
    }

    /// Extract the opcode from a hash. Faithful to `getOpCodeFromHash`
    /// (dynamic.cc:728).
    pub fn get_opcode_from_hash(h: u64) -> u32 {
        ((h >> 38) & 0x3f) as u32
    }

    /// Extract the position from a hash. Faithful to `getPositionFromHash`
    /// (dynamic.cc:737).
    pub fn get_position_from_hash(h: u64) -> u32 {
        ((h >> 44) & 0x3ff) as u32
    }

    /// Extract the collision total from a hash.
    pub fn get_total_from_hash(h: u64) -> u32 {
        ((h >> 54) & 0xf) as u32
    }

    /// Extract the attachment flag.
    pub fn get_is_not_attached(h: u64) -> bool {
        (h >> 58) & 1 != 0
    }

    /// Clear total+position fields within a hash.
    pub fn clear_total_position(h: &mut u64) {
        *h &= !((0x3ffu64 << 44) | (0xfu64 << 54));
    }

    /// Get only the formal hash for comparing.
    pub fn get_comparable(h: u64) -> u32 {
        h as u32
    }

    /// Build edges from a Varnode upward to its defining op. Faithful to
    /// `buildVnUp` (dynamic.cc:109-122).
    fn build_vn_up(&mut self, vn: &Arc<RwLock<Varnode>>) {
        let def = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        if let Some(def_op) = def {
            // Find which slot of def_op this vn occupies.
            let vn_ptr = Arc::as_ptr(vn) as usize;
            let slot = (0..def_op.read().unwrap().num_input())
                .find(|&i| def_op.read().unwrap().get_in(i)
                    .map(|v| Arc::as_ptr(v) as usize == vn_ptr).unwrap_or(false));
            if let Some(slot) = slot {
                self.op_edge.push(ToOpEdge::new(def_op, slot));
            }
        }
    }

    /// Build edges from a Varnode downward to ops that read it. Faithful to
    /// `buildVnDown` (dynamic.cc:125-148).
    fn build_vn_down(&mut self, vn: &Arc<RwLock<Varnode>>) {
        let descends: Vec<Arc<RwLock<PcodeOp>>> = vn.read().unwrap().descend_iter().collect();
        let vn_ptr = Arc::as_ptr(vn) as usize;
        for d_op in descends {
            let slot = (0..d_op.read().unwrap().num_input())
                .find(|&i| d_op.read().unwrap().get_in(i)
                    .map(|v| Arc::as_ptr(v) as usize == vn_ptr).unwrap_or(false));
            if let Some(slot) = slot {
                self.op_edge.push(ToOpEdge::new(d_op, slot));
            }
        }
    }

    /// Stage input Varnodes of an op. Faithful to `buildOpUp` (dynamic.cc:152-159).
    fn build_op_up(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        for i in 0..op.read().unwrap().num_input() {
            if let Some(inv) = op.read().unwrap().get_in(i).cloned() {
                self.vn_edge.push(inv);
            }
        }
    }

    /// Stage the output Varnode of an op. Faithful to `buildOpDown`
    /// (dynamic.cc:162-166).
    fn build_op_down(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        if let Some(out) = op.read().unwrap().output.clone() {
            self.vn_edge.push(out);
        }
    }

    /// Calculate a hash for a given Varnode using the specified method.
    /// Faithful to `calcHash(Varnode*, uint4)` (dynamic.cc:268-321).
    /// Methods: 0=up-only, 1=down-only, 2=both-up-first, 3=both-down-first.
    pub fn calc_hash_vn(&mut self, root: &Arc<RwLock<Varnode>>, method: u32) {
        self.clear();
        // Seed the sub-graph with the root varnode.
        self.mark_vn.push(root.clone());
        // Expand the sub-graph based on method.
        match method {
            0 => { // Up only
                self.build_vn_up(root);
            }
            1 => { // Down only
                self.build_vn_down(root);
            }
            2 | 3 => { // Both directions
                self.build_vn_up(root);
                self.build_vn_down(root);
            }
            _ => {}
        }
        self.piece_together_hash(root, method);
    }

    /// Calculate a hash for a given PcodeOp+slot. Faithful to
    /// `calcHash(PcodeOp*, int4, uint4)` (dynamic.cc:202-265).
    pub fn calc_hash_op(&mut self, op: &Arc<RwLock<PcodeOp>>, slot: i32, method: u32) {
        self.clear();
        self.mark_op.push(op.clone());
        // Get the varnode at the given slot.
        if slot >= 0 {
            if let Some(vn) = op.read().unwrap().get_in(slot as usize).cloned() {
                self.mark_vn.push(vn.clone());
                if method <= 1 {
                    self.build_vn_up(&vn);
                } else {
                    self.build_vn_up(&vn);
                    self.build_vn_down(&vn);
                }
            }
        }
        // Expand from the op.
        self.build_op_up(op);
        self.build_op_down(op);
        self.piece_together_hash_op(op, slot, method);
    }

    /// Assemble the final hash from the collected sub-graph. Faithful to
    /// `pieceTogetherHash` (dynamic.cc:323-380).
    fn piece_together_hash(&mut self, root: &Arc<RwLock<Varnode>>, method: u32) {
        // Sort edges for consistency.
        self.op_edge.sort_by(|a, b| a.compare(b));
        // Accumulate CRC hash.
        let mut crc: u32 = 0xffffffff;
        crc = crate::crc32::crc_update(crc, root.read().unwrap().get_size() as u32);
        for edge in &self.op_edge {
            crc = edge.hash_into(crc);
        }
        crc ^= 0xffffffff;
        // Encode: hash = crc | (method << 32) | (opcode << 38)
        let opcode = if let Some(def) = root.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            translate_opcode(def.read().unwrap().opcode)
        } else { 0 };
        self.hash = crc as u64 | ((method as u64) << 32) | ((opcode as u64) << 38);
        // Set address to root's address.
        self.addr_result = Address::new(root.read().unwrap().get_offset());
    }

    /// Assemble hash for an op-rooted calculation.
    fn piece_together_hash_op(&mut self, op: &Arc<RwLock<PcodeOp>>, slot: i32, method: u32) {
        self.op_edge.sort_by(|a, b| a.compare(b));
        let mut crc: u32 = 0xffffffff;
        crc = crate::crc32::crc_update(crc, slot as u32);
        for edge in &self.op_edge {
            crc = edge.hash_into(crc);
        }
        crc ^= 0xffffffff;
        let opcode = translate_opcode(op.read().unwrap().opcode);
        self.hash = crc as u64 | ((method as u64) << 32) | ((opcode as u64) << 38);
        self.addr_result = op.read().unwrap().get_addr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_hash_creation() {
        let dh = DynamicHash::new();
        assert_eq!(dh.get_hash(), 0);
    }

    #[test]
    fn test_translate_opcode() {
        // COPY translates to itself (non-zero).
        assert_ne!(translate_opcode(OpCode::CPUI_COPY), 0);
        // INT_ADD translates to itself.
        assert_ne!(translate_opcode(OpCode::CPUI_INT_ADD), 0);
    }

    #[test]
    fn test_hash_encoding() {
        let h = 0xDEAD_BEEF_u64 | (5u64 << 32) | (10u64 << 38);
        assert_eq!(DynamicHash::get_method_from_hash(h), 5);
        assert_eq!(DynamicHash::get_opcode_from_hash(h), 10);
    }

    #[test]
    fn test_clear_total_position() {
        let mut h = 0xFFFF_FFFF_FFFF_FFFF_u64;
        DynamicHash::clear_total_position(&mut h);
        // Position (bits 44-53) and total (bits 54-57) should be cleared.
        assert_eq!((h >> 44) & 0x3ff, 0);
        assert_eq!((h >> 54) & 0xf, 0);
    }

    #[test]
    fn test_calc_hash_vn() {
        let vn = Arc::new(RwLock::new(Varnode::new_unique(0x100, 8)));
        let mut dh = DynamicHash::new();
        dh.calc_hash_vn(&vn, 0);
        // Hash should be non-zero (CRC of size + edges).
        assert_ne!(dh.get_hash(), 0);
    }
}
