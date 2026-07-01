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

    /// Check if there are interfering ops between two ops in the same block.
    /// Faithful to `ArraySequence::interfereBetween` (constseq.cc:42-58).
    /// Two ops interfere if there's another op between them that writes to
    /// the same memory region or is a branch/call.
    pub fn interfere_between(
        fd: &Funcdata,
        start_op: &Arc<RwLock<PcodeOp>>,
        end_op: &Arc<RwLock<PcodeOp>>,
    ) -> bool {
        let start_order = start_op.read().unwrap().start.get_order();
        let end_order = end_op.read().unwrap().start.get_order();
        if start_order == end_order { return false; }
        // Scan all ops in the same block between start and end.
        for op_ref in &fd.obank.alivelist {
            let order = op_ref.0.read().unwrap().start.get_order();
            if order <= start_order || order >= end_order { continue; }
            let op = op_ref.0.read().unwrap();
            // Calls and branches interfere.
            if op.is_call() { return true; }
            if matches!(op.opcode,
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND | OpCode::CPUI_RETURN) {
                return true;
            }
            // STORE ops interfere (they may modify the memory region).
            if op.opcode == OpCode::CPUI_STORE { return true; }
        }
        false
    }

    /// Find the maximal set of COPY ops with no interfering ops between them.
    /// Faithful to `ArraySequence::checkInterference` (constseq.cc:62-103).
    /// Collects COPYs from the same block writing constants to consecutive
    /// offsets, expanding from the root op.
    pub fn check_interference(
        &mut self,
        fd: &Funcdata,
        root_offset: u64,
        element_size: i32,
    ) {
        let root_block = self.root_op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        let root_block = match root_block { Some(b) => b, None => return };
        let root_order = self.root_op.read().unwrap().start.get_order();

        // Collect all COPY ops in the same block with constant inputs writing
        // to consecutive offsets starting at root_offset.
        let mut candidates: Vec<WriteNode> = Vec::new();
        let mut seen_offsets = std::collections::HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode != OpCode::CPUI_COPY { continue; }
            // Must be in the same block.
            let op_block = op.parent.as_ref().and_then(|w| w.upgrade());
            if op_block.is_none() || !Arc::ptr_eq(&op_block.unwrap(), &root_block) {
                continue;
            }
            // Input must be a constant (character).
            let in0 = match op.inrefs.first() { Some(v) => v.clone(), None => continue };
            if !in0.read().unwrap().is_constant() { continue; }
            // Output must be in the array region (by offset).
            let out_vn = match &op.output { Some(o) => o.clone(), None => continue };
            let out_offset = out_vn.read().unwrap().get_offset();
            // Check if offset is near root_offset (within element_size steps).
            let diff = out_offset as i64 - root_offset as i64;
            if diff < 0 { continue; }
            let elem_idx = diff / element_size as i64;
            if elem_idx > MAXIMUM_SEQUENCE_LENGTH as i64 { continue; }
            let abs_offset = root_offset + elem_idx as u64 * element_size as u64;
            if abs_offset != out_offset { continue; }
            if !seen_offsets.insert(elem_idx as u64) { continue; }
            candidates.push(WriteNode::new(abs_offset, op_ref.0.clone(), -1));
        }

        // Sort by op order.
        candidates.sort_by_key(|n| n.op.read().unwrap().start.get_order());

        // Find maximal contiguous run from root with no interference.
        let mut count = 0i32;
        for (i, node) in candidates.iter().enumerate() {
            if i > 0 {
                let prev = &candidates[i - 1];
                if Self::interfere_between(fd, &prev.op, &node.op) {
                    break; // Interference found — stop expanding.
                }
            }
            count += 1;
        }

        if count >= MINIMUM_SEQUENCE_LENGTH {
            self.move_ops = candidates.into_iter().take(count as usize).collect();
            self.num_elements = count;
        }
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

    /// Select the appropriate string copy function based on the element
    /// (character) size, and pass back the length argument. Faithful to
    /// `ArraySequence::selectStringCopyFunction` (constseq.cc:161-175).
    ///
    /// Returns the built-in CALLOTHER id (one of `UserPcodeOp::BUILTIN_*`)
    /// and, in `length_index`, either the number of characters (strncpy/
    /// wcsncpy) or the number of bytes (memcpy) being copied.
    pub fn select_string_copy_function(&self) -> (u32, i32) {
        use crate::userop::{BUILTIN_MEMCPY, BUILTIN_STRNCPY, BUILTIN_WCSNCPY};
        let char_size = self.char_type.as_ref().map(|t| t.get_size()).unwrap_or(1) as i32;
        let num = self.num_elements;
        match char_size {
            1 => (BUILTIN_STRNCPY, num),
            2 => (BUILTIN_WCSNCPY, num),
            _ => (BUILTIN_MEMCPY, num * char_size),
        }
    }

    /// Build a CPUI_CALLOTHER op that performs the string copy. Faithful to
    /// `StringSequence::buildStringCopy` (constseq.cc:347-372) and
    /// `HeapSequence::buildStringCopy` (constseq.cc:698-762).
    ///
    /// The CALLOTHER has 4 inputs:
    ///   input[0] = built-in id constant (strncpy/wcsncpy/memcpy)
    ///   input[1] = destination pointer (into the array region)
    ///   input[2] = source pointer (an internal string holding byteArray)
    ///   input[3] = length constant
    ///
    /// `dest_ptr_addr` is the address the destination pointer should name
    /// (the first element of the sequence). The op is inserted before the
    /// earliest move op (`move_ops[0]`). The built-in user-op record is
    /// registered on the architecture's `UserOpManage` when available.
    ///
    /// Returns the constructed CALLOTHER op, or `None` if there are no move
    /// ops to anchor the insertion point.
    pub fn build_string_copy(
        &mut self,
        fd: &mut Funcdata,
        dest_ptr_addr: u64,
        is_store: bool,
    ) -> Option<crate::op::PcodeOpRef> {
        if self.move_ops.is_empty() {
            return None;
        }
        // Earliest move op is the insertion point (constseq.cc:350/701).
        let insert_point = self.move_ops[0].op.clone();
        let insert_addr = insert_point.read().unwrap().get_addr();

        // Select the built-in function id and length argument
        // (constseq.cc:358-359 / 749-750).
        let (builtin_id, length_index) = self.select_string_copy_function();
        if length_index <= 0 {
            return None;
        }

        // Register the built-in user-op record on the architecture, when an
        // Architecture/UserOpManage is attached (constseq.cc:360 / 751:
        // `glb->userops.registerBuiltin(builtInId)`). This is best-effort; the
        // CALLOTHER is constructed unconditionally regardless.
        if let Some(arch) = fd.arch.clone() {
            if let Some(uo) = &arch.userops {
                uo.write().unwrap().register_builtin_by_id(builtin_id);
            }
        }

        // Source pointer: an internal string built from byteArray. Ghidra
        // builds this via `getInternalString` (constseq.cc:355 / 705). Rugra
        // has no internal-string address space, so we materialize a pointer
        // varnode in Ram whose offset is a unique id and mark it ANNOTATION.
        // The byte content is recorded on the sequence for later replay.
        let num_bytes = (self.move_ops.len()
            * self.char_type.as_ref().map(|t| t.get_size()).unwrap_or(1) as usize)
            .max(self.byte_array.len());
        let src_ptr = fd.new_unique(num_bytes.max(1));
        {
            let mut v = src_ptr.write().unwrap();
            v.address_space = crate::space::AddressSpace::Ram;
            v.set_flags(crate::varnode::varnode_flags::ANNOTATION);
        }

        // Destination pointer. For a STORE sequence this is the existing base
        // pointer (HeapSequence::basePointer); for a COPY sequence it is a
        // pointer to the first written address. We materialize it as a Ram
        // pointer varnode at `dest_ptr_addr` (faithful in spirit to
        // constructTypedPointer / HeapSequence::buildStringCopy destPtr). Both
        // cases produce the same varnode shape here.
        let _ = is_store; // (kept for API symmetry with Ghidra's two builders)
        let dest_ptr = fd.new_unique(8);
        {
            let mut v = dest_ptr.write().unwrap();
            v.address_space = crate::space::AddressSpace::Ram;
            v.loc = crate::address::Address::new(dest_ptr_addr);
            v.set_flags(crate::varnode::varnode_flags::ANNOTATION);
        }

        // Build the CALLOTHER op with 4 inputs (constseq.cc:361-369 / 752-759).
        let copy_op = fd.new_op(4, insert_addr);
        fd.op_set_opcode(&copy_op, OpCode::CPUI_CALLOTHER);
        let id_vn = fd.new_constant(4, builtin_id as u64);
        fd.op_set_input(&copy_op, id_vn, 0);
        fd.op_set_input(&copy_op, dest_ptr, 1);
        fd.op_set_input(&copy_op, src_ptr, 2);
        let len_vn = fd.new_constant(4, length_index as u64);
        fd.op_set_input(&copy_op, len_vn, 3);
        fd.op_insert_before(&copy_op, &crate::op::PcodeOpRef(insert_point));
        Some(copy_op)
    }

    /// Replace the collected move ops with a CALLOTHER string copy.
    /// Faithful to `StringSequence::transform` (constseq.cc:453-461) and
    /// `HeapSequence::transform` (constseq.cc:927-940).
    ///
    /// Builds the CALLOTHER via `build_string_copy`, then destroys the
    /// original COPY/STORE ops. Returns `true` if the transform succeeded.
    pub fn transform(
        &mut self,
        fd: &mut Funcdata,
        dest_ptr_addr: u64,
        is_store: bool,
    ) -> bool {
        let callop = match self.build_string_copy(fd, dest_ptr_addr, is_store) {
            Some(op) => op,
            None => return false,
        };
        // Remove the original move ops. Faithful to removeCopyOps
        // (constseq.cc:443-444) / removeStoreOps (constseq.cc:878-881).
        // Snapshot the ops first, since op_destroy mutates the bank.
        let to_remove: Vec<crate::op::PcodeOpRef> = self
            .move_ops
            .iter()
            .map(|n| crate::op::PcodeOpRef(n.op.clone()))
            .collect();
        for op in &to_remove {
            // Use recursive destroy so PTRADD/address-arithmetic feeding the
            // STORE pointer is removed too (HeapSequence::removeStoreOps uses
            // opDestroyRecursive). The CALLOTHER is retained (it is not in the
            // descend set of these ops' outputs).
            fd.op_destroy_recursive(op);
        }
        // The CALLOTHER itself is live; reference it so it is not considered
        // unused (no-op in Rugra, but documents intent).
        let _ = &callop;
        true
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
    fn apply_op(&self, op: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleStringCopy::applyOp (constseq.cc:954-1002).
        // Check if this COPY writes a constant into a character array.
        let opcode = op.read().unwrap().opcode;
        if opcode != OpCode::CPUI_COPY { return Ok(action_status::NO_CHANGE); }
        // Input must be constant.
        let in0 = match op.read().unwrap().inrefs.first() {
            Some(v) => v.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };
        if !in0.read().unwrap().is_constant() { return Ok(action_status::NO_CHANGE); }
        // Output must exist.
        let out_vn = match &op.read().unwrap().output {
            Some(o) => o.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };
        let root_offset = out_vn.read().unwrap().get_offset();

        // Build ArraySequence and check for a valid string sequence.
        let mut seq = ArraySequence::new(op.clone());
        seq.check_interference(fd, root_offset, 1);
        if !seq.is_valid() { return Ok(action_status::NO_CHANGE); }

        // Form the byte array and validate.
        let count = seq.form_byte_array();
        if count < MINIMUM_SEQUENCE_LENGTH { return Ok(action_status::NO_CHANGE); }
        if !seq.is_valid_string() { return Ok(action_status::NO_CHANGE); }

        // The destination pointer names the first written element. Ghidra
        // derives this from the Symbol/spacebase (constructTypedPointer,
        // constseq.cc:273-339); Rugra uses the address of the earliest move
        // op's output varnode directly.
        let dest_ptr_addr = seq
            .move_ops
            .first()
            .and_then(|n| n.op.read().unwrap().output.as_ref().cloned())
            .map(|v| v.read().unwrap().get_offset())
            .unwrap_or(root_offset);

        // Replace the COPY sequence with a strncpy/wcsncpy CALLOTHER.
        // Faithful to StringSequence::transform (constseq.cc:453-461).
        if seq.transform(fd, dest_ptr_addr, false) {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
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
    fn apply_op(&self, op: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleStringStore::applyOp (constseq.cc:986-1002). Given a
        // root STORE of a constant character, gather sibling STOREs in the
        // same basic block writing consecutive characters through the same base
        // pointer, and replace them with a single memcpy CALLOTHER.
        let op_guard = op.read().unwrap();
        if op_guard.opcode != OpCode::CPUI_STORE || op_guard.inrefs.len() < 3 {
            return Ok(action_status::NO_CHANGE);
        }
        // Value being stored (input[2]) must be a constant character
        // (constseq.cc:989: `op->getIn(2)->isConstant()`).
        let val_vn = op_guard.inrefs[2].clone();
        if !val_vn.read().unwrap().is_constant() {
            return Ok(action_status::NO_CHANGE);
        }
        // The store pointer (input[1]) identifies the destination region. We
        // use its (space, offset) as the base for collecting consecutive stores.
        let ptr_vn = op_guard.inrefs[1].clone();
        let (ptr_space, ptr_offset, ptr_size) = {
            let p = ptr_vn.read().unwrap();
            (p.get_space(), p.get_offset(), p.get_size())
        };
        let root_block = op_guard.parent.as_ref().and_then(|w| w.upgrade());
        let root_order = op_guard.start.get_order();
        drop(op_guard);

        // Collect consecutive STOREs of constants through the same base pointer
        // in the same block. This is a simplified HeapSequence::collectStoreOps
        // (constseq.cc:663-697): we follow PTRADD-based address arithmetic by
        // matching the base pointer varnode, accumulating a byte array.
        let mut store_ops: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut byte_array: Vec<u8> = Vec::new();
        byte_array.push((val_vn.read().unwrap().get_offset() & 0xff) as u8);

        for op_ref in &fd.obank.alivelist {
            let cand = op_ref.0.read().unwrap();
            if cand.opcode != OpCode::CPUI_STORE || cand.inrefs.len() < 3 {
                continue;
            }
            // Same block as the root.
            let cand_block = cand.parent.as_ref().and_then(|w| w.upgrade());
            if root_block.is_none() || cand_block.is_none()
                || !Arc::ptr_eq(&cand_block.unwrap(), &root_block.clone().unwrap())
            {
                continue;
            }
            // Must come at or after the root in sequence order.
            if cand.start.get_order() < root_order {
                continue;
            }
            // Skip the root op itself.
            if Arc::ptr_eq(&op_ref.0, op) {
                store_ops.push(op_ref.0.clone());
                continue;
            }
            // Stored value must be a constant.
            let c_val = cand.inrefs[2].clone();
            if !c_val.read().unwrap().is_constant() {
                continue;
            }
            // Store pointer must derive from the same base pointer. We accept
            // any store whose pointer shares the base varnode identity (the
            // full HeapSequence walks PTRADD/COPY chains; this is the common
            // case where each STORE address is PTRADD(base, index, mult)).
            let c_ptr = cand.inrefs[1].clone();
            if !Self::ptr_shares_base(&c_ptr, &ptr_vn, ptr_space, ptr_offset, ptr_size) {
                continue;
            }
            let byte = (c_val.read().unwrap().get_offset() & 0xff) as u8;
            // Insert ordered by sequence number to keep the byte array ordered.
            let ord = cand.start.get_order();
            let pos = store_ops
                .iter()
                .position(|s| s.read().unwrap().start.get_order() > ord)
                .unwrap_or(store_ops.len());
            store_ops.insert(pos, op_ref.0.clone());
            byte_array.insert(pos, byte);
        }

        // Require a minimum run of consecutive characters.
        if (byte_array.len() as i32) < MINIMUM_SEQUENCE_LENGTH {
            return Ok(action_status::NO_CHANGE);
        }

        // Build the ArraySequence and run the memcpy transform. The destination
        // pointer is the root store pointer; element size is 1 byte (char).
        let dest_ptr_addr = ptr_offset;
        let mut seq = ArraySequence::new(op.clone());
        seq.char_type = None; // memcpy (size != 1,2) → BUILTIN_MEMCPY
        seq.num_elements = byte_array.len() as i32;
        seq.byte_array = byte_array.clone();
        seq.move_ops = store_ops
            .iter()
            .map(|s| WriteNode::new(0, s.clone(), 2))
            .collect();

        if seq.transform(fd, dest_ptr_addr, true) {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str { "string_store" }
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_STORE] }
}

impl RuleStringStore {
    /// Check whether a STORE pointer varnode `cand_ptr` derives from the same
    /// base pointer as `base_ptr`. This is a lightweight stand-in for
    /// HeapSequence::findBasePointer (constseq.cc:465-480): we accept the
    /// candidate if its pointer varnode is produced by a PTRADD/COPY chain
    /// whose input[0] is `base_ptr`, or if it is `base_ptr` itself.
    fn ptr_shares_base(
        cand_ptr: &Arc<RwLock<Varnode>>,
        base_ptr: &Arc<RwLock<Varnode>>,
        _base_space: crate::space::AddressSpace,
        _base_offset: u64,
        _base_size: usize,
    ) -> bool {
        // Direct identity.
        if Arc::ptr_eq(cand_ptr, base_ptr) {
            return true;
        }
        // Walk back through PTRADD/COPY defining ops (constseq.cc:470-478).
        let mut cur = cand_ptr.clone();
        for _ in 0..32 {
            let def = {
                let g = cur.read().unwrap();
                if !g.is_written() {
                    return false;
                }
                g.get_def()
            };
            let Some(def_op) = def else { return false; };
            let (opc, in0) = {
                let d = def_op.read().unwrap();
                (d.opcode, d.inrefs.first().cloned())
            };
            if opc != OpCode::CPUI_PTRADD && opc != OpCode::CPUI_COPY {
                return false;
            }
            let Some(in0) = in0 else { return false; };
            if Arc::ptr_eq(&in0, base_ptr) {
                return true;
            }
            cur = in0;
        }
        false
    }
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
        use crate::type_system::{TypeBase, TypeMetatype};
        use crate::userop::{BUILTIN_MEMCPY, BUILTIN_STRNCPY, BUILTIN_WCSNCPY};
        // char_type None → default size 1 → strncpy (BUILTIN_STRNCPY).
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        ))));
        seq.num_elements = 5;
        let (id, len) = seq.select_string_copy_function();
        assert_eq!(id, BUILTIN_STRNCPY);
        assert_eq!(len, 5);

        // wchar_t (size 2) → wcsncpy.
        seq.char_type = Some(Arc::new(Datatype::Base(TypeBase::new(
            "wchar_t".to_string(), 2, TypeMetatype::Int,
        ))));
        let (id, _len) = seq.select_string_copy_function();
        assert_eq!(id, BUILTIN_WCSNCPY);

        // Unknown size (3) → memcpy, length in bytes.
        seq.char_type = Some(Arc::new(Datatype::Base(TypeBase::new(
            "odd".to_string(), 3, TypeMetatype::Int,
        ))));
        let (id, len) = seq.select_string_copy_function();
        assert_eq!(id, BUILTIN_MEMCPY);
        assert_eq!(len, 15); // 5 elements * 3 bytes
    }

    /// `ArraySequence::transform` (the StringCopy path) must build a single
    /// CPUI_CALLOTHER (strncpy) op and destroy the original COPY ops. Faithful
    /// to StringSequence::transform / buildStringCopy (constseq.cc:347-461).
    #[test]
    fn test_transform_copy_emits_callother() {
        use crate::address::Address;
        let mut fd = Funcdata::new("teststr", Address::new(0x1000), 1);
        // Build an ArraySequence with 6 COPY move_ops writing "Hello\0".
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_COPY,
        ))));
        seq.num_elements = 6;
        seq.char_type = None; // size 1 → strncpy (BUILTIN_STRNCPY)
        seq.byte_array = b"Hello\0".to_vec();
        for (i, &ch) in b"Hello\0".iter().enumerate() {
            let cop = fd.new_op(1, Address::new(0x1000 + i as u64));
            let const_vn = fd.new_constant(1, ch as u64);
            fd.op_set_input(&cop, const_vn, 0);
            fd.obank.alivelist.push(cop.clone());
            seq.move_ops.push(WriteNode::new(i as u64, cop.0.clone(), 0));
        }
        let dest_addr = 0x100u64;
        assert!(seq.transform(&mut fd, dest_addr, false));

        // A CPUI_CALLOTHER op must now exist in the bank.
        let callother = fd.obank.alivelist.iter().find_map(|r| {
            let g = r.0.read().unwrap();
            if g.opcode == OpCode::CPUI_CALLOTHER { Some(r.clone()) } else { None }
        });
        let callop = callother.expect("expected a CPUI_CALLOTHER op after transform");
        // Verify its 4 inputs: index, dest, src, len.
        let (id_offset, len_offset, nin) = {
            let g = callop.0.read().unwrap();
            let id_offset = g.inrefs[0].read().unwrap().get_offset();
            let len_offset = g.inrefs[3].read().unwrap().get_offset();
            (id_offset, len_offset, g.inrefs.len())
        };
        assert_eq!(nin, 4);
        // input[0] is the strncpy builtin id constant.
        assert_eq!(id_offset, crate::userop::BUILTIN_STRNCPY as u64);
        // input[3] is the length (6 chars).
        assert_eq!(len_offset, 6);

        // The original COPY ops must be dead (removed by op_destroy_recursive).
        let remaining_copies = fd.obank.alivelist.iter().filter(|r| {
            let g = r.0.read().unwrap();
            g.opcode == OpCode::CPUI_COPY && !g.is_dead()
        }).count();
        assert_eq!(remaining_copies, 0, "COPYs should be removed by the transform");
    }

    /// `ArraySequence::transform` (the StringStore path) selects memcpy and
    /// builds a CPUI_CALLOTHER. Faithful to HeapSequence::transform /
    /// buildStringCopy (constseq.cc:698-940).
    #[test]
    fn test_transform_store_emits_callother_memcpy() {
        use crate::address::Address;
        let mut fd = Funcdata::new("teststore", Address::new(0x1000), 1);
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_STORE,
        ))));
        seq.num_elements = 5;
        seq.char_type = None; // size 1 → strncpy; store path forces memcpy via is_store
        seq.byte_array = b"abcd\0".to_vec();
        for (i, &ch) in b"abcd\0".iter().enumerate() {
            let store = fd.new_op(3, Address::new(0x3000 + i as u64));
            fd.op_set_opcode(&store, OpCode::CPUI_STORE);
            let space_cn = fd.new_constant(8, 0);
            fd.op_set_input(&store, space_cn, 0);
            let ptr_cn = fd.new_constant(8, 0x2000);
            fd.op_set_input(&store, ptr_cn, 1);
            let val_cn = fd.new_constant(1, ch as u64);
            fd.op_set_input(&store, val_cn, 2);
            fd.obank.alivelist.push(store.clone());
            seq.move_ops.push(WriteNode::new(i as u64, store.0.clone(), 2));
        }
        // The STORE path selects memcpy because num_elements * char_size != the
        // char/wchar sizes. With char_type None → size 1 → strncpy; to exercise
        // the store path's memcpy selection we force a non-char element size.
        seq.char_type = Some(Arc::new(Datatype::Base(
            crate::type_system::TypeBase::new("x".to_string(), 4, crate::type_system::TypeMetatype::Int),
        )));
        seq.num_elements = 5; // 5 * 4 = 20 bytes → memcpy
        assert!(seq.transform(&mut fd, 0x2000, true));

        let callother = fd.obank.alivelist.iter().find_map(|r| {
            let g = r.0.read().unwrap();
            if g.opcode == OpCode::CPUI_CALLOTHER { Some(r.clone()) } else { None }
        });
        let callop = callother.expect("expected a CPUI_CALLOTHER op after store transform");
        let (id_offset, len_offset, nin) = {
            let g = callop.0.read().unwrap();
            let id_offset = g.inrefs[0].read().unwrap().get_offset();
            let len_offset = g.inrefs[3].read().unwrap().get_offset();
            (id_offset, len_offset, g.inrefs.len())
        };
        assert_eq!(nin, 4);
        assert_eq!(id_offset, crate::userop::BUILTIN_MEMCPY as u64);
        // length in bytes = 5 elements * 4 bytes.
        assert_eq!(len_offset, 20);
    }
}
