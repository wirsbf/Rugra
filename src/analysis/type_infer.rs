//! ActionTypePropagate: Conservative P-code level type propagation.
//!
//! After copy propagation, scans all P-code ops for struct pointer patterns.
//! Only marks a varnode as struct pointer if it's used as base in >=2 distinct
//! small (<256B) 8-byte-aligned offsets via INT_ADD → LOAD/STORE.
//! This is conservative — avoids false positives on single-offset or large-offset access.

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use crate::funcdata::Funcdata;
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer, TypeStruct};

/// Run conservative type propagation. Marks varnodes that are struct pointers.
pub fn propagate_types(fd: &mut Funcdata) {
    // Phase 1: Collect base_var → set of offsets used in *(base + offset) patterns
    // Pattern: LOAD/STORE addr = INT_ADD(base, const) where const < 256 and const % 8 == 0
    let mut base_offsets: HashMap<(AddressSpace, u64), HashSet<u64>> = HashMap::new();

    for blk_i in 0..fd.bblocks.get_size() {
        let block_arc = match fd.bblocks.get_block(blk_i) { Some(b) => b, None => continue };
        let block = block_arc.read().unwrap();
        for op_ref in block.get_ops() {
            let op = op_ref.0.read().unwrap();
            if !matches!(op.opcode, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) { continue; }
            if op.inrefs.len() < 2 { continue; }

            let addr_vn = op.inrefs[1].read().unwrap();
            let addr_space = addr_vn.get_space();
            let addr_offset = addr_vn.get_offset();

            // Check if address is INT_ADD(base, const)
            if addr_space == AddressSpace::Unique {
                if let Some(def_arc) = addr_vn.def.as_ref().and_then(|d| d.upgrade()) {
                    let def_op = def_arc.read().unwrap();
                    if def_op.opcode == OpCode::CPUI_INT_ADD && def_op.inrefs.len() == 2 {
                        for in_idx in 0..2 {
                            let in_vn = def_op.inrefs[in_idx].read().unwrap();
                            let other_vn = def_op.inrefs[1 - in_idx].read().unwrap();
                            if other_vn.get_space() == AddressSpace::Const {
                                let off = other_vn.get_offset();
                                if off < 256 && off % 8 == 0 {
                                    let key = (in_vn.get_space(), in_vn.get_offset());
                                    base_offsets.entry(key).or_default().insert(off);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Phase 2: Conservative — only mark varnodes with >= 2 distinct offsets as struct ptr
    let struct_ptr_keys: Vec<_> = base_offsets.iter()
        .filter(|(_, offsets)| offsets.len() >= 2)
        .map(|(key, _)| *key)
        .collect();

    if struct_ptr_keys.is_empty() { return; }

    // Phase 3: Propagate through COPY chains (Unique → Register)
    let mut all_keys: HashSet<(AddressSpace, u64)> = struct_ptr_keys.iter().cloned().collect();
    let mut changed = true;
    while changed {
        changed = false;
        for blk_i in 0..fd.bblocks.get_size() {
            let block_arc = match fd.bblocks.get_block(blk_i) { Some(b) => b, None => continue };
            let block = block_arc.read().unwrap();
            for op_ref in block.get_ops() {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY || op.inrefs.len() != 1 { continue; }
                let in_vn = op.inrefs[0].read().unwrap();
                let in_key = (in_vn.get_space(), in_vn.get_offset());
                if all_keys.contains(&in_key) {
                    if let Some(out_arc) = &op.output {
                        let out_vn = out_arc.read().unwrap();
                        let out_key = (out_vn.get_space(), out_vn.get_offset());
                        if all_keys.insert(out_key) { changed = true; }
                    }
                }
            }
        }
    }

    // Phase 4: Set struct pointer type on matching varnodes
    let struct_type = Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("_struct".to_string(), 0, TypeMetatype::Struct),
        fields: Vec::new(),
    }));
    let ptr_type = Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new("_struct *".to_string(), 8, TypeMetatype::Pointer),
        ptr_to: struct_type,
        wordsize: 1,
    }));

    for vn_ref in &fd.vbank.loc_tree {
        let vn = vn_ref.0.read().unwrap();
        let key = (vn.get_space(), vn.get_offset());
        if all_keys.contains(&key) {
            drop(vn);
            vn_ref.0.write().unwrap().v_type = Some(ptr_type.clone());
        }
    }
}
