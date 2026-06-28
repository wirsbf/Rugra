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

/// Run type propagation. Faithful to Ghidra ActionInferTypes::apply
/// (coreaction.cc:5374-5416): multi-round iterative propagation until
/// convergence (or max 7 rounds).
pub fn propagate_types(fd: &mut Funcdata) {
    // Phase 0: Iterative type propagation (Ghidra ActionInferTypes core loop)
    for _round in 0..7 {
        let changed = propagate_one_round(fd);
        if !changed { break; }
    }

    // Phase 1-4: Struct pointer detection (existing logic)
    propagate_load_output_types(fd);

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

    if struct_ptr_keys.is_empty() {
        // Even without struct pointers, run LOAD output type inference
        // (Phase 5) — it propagates element types from pointer addresses.
        propagate_load_output_types(fd);
        return;
    }

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

    // Phase 5: LOAD output type inference (faithful to Ghidra propagateFromPointer,
    // typeop.cc:206). When a LOAD's address input is a pointer to T, the output
    // should be T (the element type), NOT a pointer. This fixes the root cause of
    // piVar92 = *(int*)piVar91 being typed as pointer — it should be int.
    //
    // Ghidra's algorithm: if addr vn's type is Pointer(ptr_to=T), and T's size
    // matches the LOAD output size, set LOAD output type to T.
    propagate_load_output_types(fd);
}

/// One round of iterative type propagation. Returns true if any type changed.
/// Faithful to Ghidra ActionInferTypes: buildLocaltypes + propagateOneType + writeBack.
fn propagate_one_round(fd: &mut Funcdata) -> bool {
    // Collect all (op_ref, opcode, in_types, out_type) for propagation decisions.
    // We process COPY (direct transfer) and LOAD (element inference) edges,
    // which are the most impactful for eliminating reconcile workarounds.
    let mut type_updates: Vec<(Arc<std::sync::RwLock<crate::varnode::Varnode>>, Arc<Datatype>)> = Vec::new();

    for blk_i in 0..fd.bblocks.get_size() {
        let block_arc = match fd.bblocks.get_block(blk_i) { Some(b) => b, None => continue };
        let block = block_arc.read().unwrap();
        for op_ref in block.get_ops() {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                // COPY: propagate input type to output (Ghidra TypeOpCopy::propagateType)
                OpCode::CPUI_COPY if op.inrefs.len() == 1 => {
                    let in_type = op.inrefs[0].read().unwrap().v_type.clone();
                    if let Some(ref vt) = in_type {
                        if vt.get_metatype() != TypeMetatype::Unknown {
                            if let Some(ref out_arc) = op.output {
                                let out_vn = out_arc.read().unwrap();
                                let needs_update = match &out_vn.v_type {
                                    None => true,
                                    Some(ref cur) => cur.get_metatype() == TypeMetatype::Unknown
                                        || &**cur as *const _ != &**vt as *const _,
                                };
                                if needs_update {
                                    type_updates.push((out_arc.clone(), vt.clone()));
                                }
                            }
                        }
                    }
                }
                // LOAD: propagate element type from pointer address (Ghidra propagateFromPointer)
                OpCode::CPUI_LOAD if op.inrefs.len() >= 2 => {
                    let addr_vn = op.inrefs[1].read().unwrap();
                    // Direct pointer on address
                    if let Some(ref vt) = addr_vn.v_type {
                        if let Datatype::Pointer(pt) = &**vt {
                            if let Some(ref out_arc) = op.output {
                                let out_size = out_arc.read().unwrap().get_size();
                                if pt.ptr_to.get_size() == out_size {
                                    type_updates.push((out_arc.clone(), pt.ptr_to.clone()));
                                }
                            }
                        }
                    }
                }
                // INT_ZEXT/INT_SEXT: propagate input type to output (like COPY but widening)
                OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT if op.inrefs.len() == 1 => {
                    let in_type = op.inrefs[0].read().unwrap().v_type.clone();
                    if let Some(ref vt) = in_type {
                        if vt.get_metatype() == TypeMetatype::Pointer {
                            if let Some(ref out_arc) = op.output {
                                type_updates.push((out_arc.clone(), vt.clone()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Apply updates and check if anything changed
    let mut changed = false;
    for (vn_arc, new_type) in type_updates {
        let mut vn = vn_arc.write().unwrap();
        let old_meta = vn.v_type.as_ref().map(|t| t.get_metatype()).unwrap_or(TypeMetatype::Unknown);
        let new_meta = new_type.get_metatype();
        // Only update if new type is "better" (Unknown → known, or different)
        if old_meta == TypeMetatype::Unknown || old_meta != new_meta {
            // Don't downgrade from Pointer to non-pointer unless current is Unknown
            if old_meta != TypeMetatype::Pointer || new_meta == TypeMetatype::Pointer {
                vn.v_type = Some(new_type.clone());
                if let Some(ref high_arc) = vn.high {
                    high_arc.write().unwrap().v_type = new_type;
                }
                changed = true;
            }
        }
    }
    changed
}

/// Propagate LOAD output types from pointer inputs.
/// Faithful to Ghidra's TypeOp::propagateFromPointer (typeop.cc:206).
fn propagate_load_output_types(fd: &mut Funcdata) {
    // Collect (op_ref, ptr_to_type, out_size) for LOADs whose address is a pointer.
    let mut load_fixups: Vec<(crate::op::PcodeOpRef, Arc<Datatype>)> = Vec::new();

    for blk_i in 0..fd.bblocks.get_size() {
        let block_arc = match fd.bblocks.get_block(blk_i) { Some(b) => b, None => continue };
        let block = block_arc.read().unwrap();
        for op_ref in block.get_ops() {
            let op = op_ref.0.read().unwrap();
            if op.opcode != OpCode::CPUI_LOAD || op.inrefs.len() < 2 { continue; }
            // LOAD input[1] is the address varnode.
            let addr_vn = op.inrefs[1].read().unwrap();
            // Check if addr varnode has a pointer type.
            if let Some(ref vt) = addr_vn.v_type {
                if let Datatype::Pointer(pt) = &**vt {
                    // ptr_to is the element type. Check size match with output.
                    if let Some(ref out_arc) = op.output {
                        let out_size = out_arc.read().unwrap().get_size();
                        if pt.ptr_to.get_size() == out_size {
                            // Output should be the element type, not pointer.
                            load_fixups.push((op_ref.clone(), pt.ptr_to.clone()));
                        }
                    }
                }
            }
            // Also check high-level type via def chain (COPY/ZEXT from pointer).
            if load_fixups.iter().all(|(r, _)| !Arc::ptr_eq(&r.0, &op_ref.0)) {
                if let Some(ref def_arc) = addr_vn.def.as_ref().and_then(|d| d.upgrade()) {
                    let def_op = def_arc.read().unwrap();
                    // Chase through COPY to find the original pointer type.
                    if def_op.opcode == OpCode::CPUI_COPY && def_op.inrefs.len() >= 1 {
                        let src_vn = def_op.inrefs[0].read().unwrap();
                        if let Some(ref vt) = src_vn.v_type {
                            if let Datatype::Pointer(pt) = &**vt {
                                if let Some(ref out_arc) = op.output {
                                    let out_size = out_arc.read().unwrap().get_size();
                                    if pt.ptr_to.get_size() == out_size {
                                        load_fixups.push((op_ref.clone(), pt.ptr_to.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Apply: set LOAD output varnode type to the element type.
    for (op_ref, elem_type) in load_fixups {
        let out_arc = {
            let op = op_ref.0.read().unwrap();
            op.output.clone()
        };
        if let Some(out_arc) = out_arc {
            let should_update = {
                let out_vn = out_arc.read().unwrap();
                match &out_vn.v_type {
                    None => true,
                    Some(ref cur) => {
                        matches!(&**cur, Datatype::Pointer(_))
                            || cur.get_metatype() == TypeMetatype::Unknown
                    }
                }
            };
            if should_update {
                let mut out_vn = out_arc.write().unwrap();
                out_vn.v_type = Some(elem_type.clone());
                // Also update the high-level variable's type so printc's
                // find_typed_instance sees the element type, not a stale pointer.
                if let Some(ref high_arc) = out_vn.high {
                    high_arc.write().unwrap().v_type = elem_type;
                }
            }
        }
    }
}
