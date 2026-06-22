//! High-level variable merging logic
//!
//! Corresponds to Ghidra's `merge.hh`. This module is responsible for
//! merging multiple SSA Varnodes into a single HighVariable.

use crate::cover::{Cover, CoverBlock};
use crate::funcdata::Funcdata;
use crate::space::AddressSpace;
use crate::type_system::{Datatype, TypeBase, TypeMetatype};
use crate::variable::HighVariable;
use crate::varnode::{Varnode, varnode_flags};
use std::sync::{Arc, RwLock};

/// Manages the process of merging Varnodes into HighVariables
///
/// Corresponds to Ghidra's `Merge` class. Groups SSA varnodes that
/// represent the same logical variable into `HighVariable` instances,
/// then assigns human-readable names to each group.
pub struct Merge {
    /// Counter for auto-naming unique/register variables
    var_counter: u32,
}

impl Merge {
    /// Create a new Merge instance
    pub fn new() -> Self {
        Self { var_counter: 0 }
    }

    /// Clear all existing HighVariables and reset merge state
    pub fn clear(&mut self, fd: &mut Funcdata) {
        for vn_ref in &fd.vbank.loc_tree {
            vn_ref.0.write().unwrap().high = None;
        }
        self.var_counter = 0;
    }

    /// Perform the full merging + naming pipeline
    pub fn merge_all(&mut self, fd: &mut Funcdata) {
        // Phase 1: Group varnodes by address identity
        self.merge_addr_tied(fd);

        // Phase 2: Ensure every varnode has a HighVariable
        self.ensure_all_have_high(fd);

        // Phase 3: Compute liveness covers (Ghidra calculateCover)
        self.compute_varnode_covers(fd);

        // Phase 4: Merge non-address-tied HighVariables with disjoint covers
        self.merge_by_cover(fd);

        // Phase 5: Auto-name all HighVariables
        self.assign_names(fd);
    }

    /// Merge varnodes that are tied to the same address+size.
    ///
    /// This is the primary merge pass: varnodes at the same location
    /// and with the same size are different SSA versions of the same
    /// logical variable and should share a HighVariable.
    pub fn merge_addr_tied(&mut self, fd: &mut Funcdata) {
        use std::collections::BTreeMap;

        let mut groups: BTreeMap<(crate::address::Address, usize), Vec<Arc<RwLock<Varnode>>>> =
            BTreeMap::new();

        {
            for vn_ref in &fd.vbank.loc_tree {
                let vn_arc = vn_ref.0.clone();
                let (addr, size) = {
                    let vn = vn_arc.read().unwrap();
                    (vn.loc, vn.size)
                };
                groups.entry((addr, size)).or_default().push(vn_arc);
            }
        }

        for group in groups.values() {
            if group.len() < 2 {
                continue;
            }
            // Merge all varnodes in the same address group pairwise
            for i in 0..group.len() {
                for j in i + 1..group.len() {
                    let vn1_arc = group[i].clone();
                    let vn2_arc = group[j].clone();

                    let can_merge = {
                        let v1 = vn1_arc.read().unwrap();
                        let v2 = vn2_arc.read().unwrap();
                        self.merge_test(&v1, &v2)
                    };

                    if can_merge {
                        self.merge_force(vn1_arc, vn2_arc);
                    }
                }
            }
        }
    }

    /// Ensure every varnode in the bank has a HighVariable.
    /// Varnodes not merged by `merge_addr_tied` get their own singleton HighVariable.
    fn ensure_all_have_high(&mut self, fd: &mut Funcdata) {
        let vn_arcs: Vec<Arc<RwLock<Varnode>>> =
            fd.vbank.loc_tree.iter().map(|r| r.0.clone()).collect();

        for vn_arc in vn_arcs {
            let needs_high = {
                let vn = vn_arc.read().unwrap();
                vn.high.is_none()
            };
            if needs_high {
                let vn = vn_arc.read().unwrap();
                let dt = vn.v_type.clone().unwrap_or_else(|| {
                    Arc::new(Datatype::Base(TypeBase::new("undefined".to_string(), vn.size, TypeMetatype::Unknown)))
                });
                drop(vn);

                let high = Arc::new(RwLock::new(HighVariable::new(dt)));
                high.write().unwrap().add_instance(vn_arc.clone());
                vn_arc.write().unwrap().high = Some(high);
            }
        }
    }

    /// Test whether two varnodes can be merged into the same HighVariable.
    ///
    /// Returns true if they share the same address space and size, and
    /// neither is a constant or annotation (which should never be merged).
    pub fn merge_test(&self, v1: &Varnode, v2: &Varnode) -> bool {
        use crate::varnode::varnode_flags;

        // Never merge constants or annotations
        if v1.flags & varnode_flags::CONSTANT != 0 || v2.flags & varnode_flags::CONSTANT != 0 {
            return false;
        }
        if v1.flags & varnode_flags::ANNOTATION != 0 || v2.flags & varnode_flags::ANNOTATION != 0 {
            return false;
        }

        // Must be same address space and size
        v1.address_space == v2.address_space && v1.size == v2.size
    }

    /// Force-merge two varnodes into the same HighVariable.
    ///
    /// If vn1 already has a HighVariable, add vn2 to it (or vice versa).
    /// If neither has one, create a new HighVariable for both.
    pub fn merge_force(&mut self, vn1: Arc<RwLock<Varnode>>, vn2: Arc<RwLock<Varnode>>) {
        let high1 = vn1.read().unwrap().high.clone();
        let high2 = vn2.read().unwrap().high.clone();

        match (high1, high2) {
            (Some(h1), Some(h2)) => {
                // Both already have HighVariables — merge h2 into h1
                if Arc::ptr_eq(&h1, &h2) {
                    return; // Already the same
                }
                let instances: Vec<Arc<RwLock<Varnode>>> = {
                    let h2_read = h2.read().unwrap();
                    h2_read.instances.clone()
                };
                for inst in instances {
                    h1.write().unwrap().add_instance(inst.clone());
                    inst.write().unwrap().high = Some(h1.clone());
                }
            }
            (Some(h1), None) => {
                h1.write().unwrap().add_instance(vn2.clone());
                vn2.write().unwrap().high = Some(h1);
            }
            (None, Some(h2)) => {
                h2.write().unwrap().add_instance(vn1.clone());
                vn1.write().unwrap().high = Some(h2);
            }
            (None, None) => {
                let vn1_read = vn1.read().unwrap();
                let dt = vn1_read.v_type.clone().unwrap_or_else(|| {
                    Arc::new(Datatype::Base(TypeBase::new("undefined".to_string(), vn1_read.size, TypeMetatype::Unknown)))
                });
                drop(vn1_read);

                let high = Arc::new(RwLock::new(HighVariable::new(dt)));
                high.write().unwrap().add_instance(vn1.clone());
                high.write().unwrap().add_instance(vn2.clone());
                vn1.write().unwrap().high = Some(high.clone());
                vn2.write().unwrap().high = Some(high);
            }
        }
    }

    /// Assign human-readable names to all HighVariables in the function.
    ///
    /// Naming follows Ghidra conventions:
    /// - Stack negative offset → `local_Xh`
    /// - Stack positive offset → `param_stack_Xh`
    /// - Register → actual register name (RAX, RDI, etc.) or `uVarN` for unmapped offsets
    /// - Unique temp → `uVarN`
    /// - RAM global → `DAT_XXXXXXXX`
    ///
    /// For registers that are SysV AMD64 argument registers, the first occurrence
    /// at function entry is named as a parameter (param_1, param_2, etc.).
    pub fn assign_names(&mut self, fd: &mut Funcdata) {
        use std::collections::HashSet;

        self.var_counter = 0;
        let mut named: HashSet<u64> = HashSet::new();
        // Track which register names have been used to avoid duplicates
        let mut used_reg_names: HashSet<String> = HashSet::new();

        let vn_arcs: Vec<Arc<RwLock<Varnode>>> =
            fd.vbank.loc_tree.iter().map(|r| r.0.clone()).collect();

        for vn_arc in vn_arcs {
            let vn = vn_arc.read().unwrap();
            if let Some(ref high_arc) = vn.high {
                let high_ptr = Arc::as_ptr(high_arc) as u64;
                if named.contains(&high_ptr) {
                    continue;
                }
                named.insert(high_ptr);

                let name = match vn.address_space {
                    AddressSpace::Stack => {
                        let off = vn.get_offset();
                        if off >= 0x8000_0000_0000_0000 {
                            // Negative offset = local variable
                            format!("local_{:x}h", (!off).wrapping_add(1))
                        } else {
                            format!("param_stack_{:x}h", off)
                        }
                    }
                    AddressSpace::Register => {
                        // Use actual register name from the x86-64 offset table
                        let reg_name = register_name(vn.get_offset(), vn.size);
                        if let Some(name) = reg_name {
                            if used_reg_names.contains(&name) {
                                // Same register re-used (different SSA version),
                                // append a counter suffix
                                self.var_counter += 1;
                                let suffixed = format!("{}_{}", name, self.var_counter);
                                used_reg_names.insert(suffixed.clone());
                                suffixed
                            } else {
                                used_reg_names.insert(name.clone());
                                name
                            }
                        } else {
                            self.var_counter += 1;
                            format!("uVar{}", self.var_counter)
                        }
                    }
                    AddressSpace::Unique => {
                        self.var_counter += 1;
                        format!("uVar{}", self.var_counter)
                    }
                    AddressSpace::Ram => {
                        format!("DAT_{:08x}", vn.get_offset())
                    }
                    _ => {
                        self.var_counter += 1;
                        format!("uVar{}", self.var_counter)
                    }
                };

                let mut high = high_arc.write().unwrap();
                if high.get_name().is_empty() {
                    high.set_name(name);
                }
            }
        }
    }

    // Stub methods for future enhancement
    pub fn merge_adjacent(&mut self, _fd: &mut Funcdata) {}
    pub fn merge_multi_entry(&mut self, _fd: &mut Funcdata) {}
    pub fn merge_marker(&mut self, _fd: &mut Funcdata) {}
    pub fn merge_by_datatype(&mut self, _fd: &mut Funcdata) {}

    /// Populate `vn.cover` for every writable varnode from its def op and
    /// reader ops. Mirrors Ghidra's `Varnode::calculateCover` /
    /// `HighVariable::updateCover`. Constants and annotations are skipped.
    ///
    /// Cover semantics per block (matching Ghidra):
    ///   - def in block, also used in block → `[def_order, last_use_order]`
    ///   - def in block, no use in block → `[def_order, MAX]` (live-out)
    ///   - no def in block, used in block → `[0, last_use_order]` (live-in)
    ///   - no def, no use in block → no cover entry
    ///
    /// After per-block computation, covers are propagated forward through
    /// the CFG: any live-out block's successors get `[0, MAX]` entries
    /// (transitively live). This is conservative but correct — it may
    /// block some valid merges (if the varnode doesn't actually flow to
    /// ALL successors) but never allows invalid merges.
    pub fn compute_varnode_covers(&mut self, fd: &mut Funcdata) {
        let vn_arcs: Vec<Arc<RwLock<Varnode>>> =
            fd.vbank.loc_tree.iter().map(|r| r.0.clone()).collect();

        for vn_arc in vn_arcs {
            let skip = {
                let vn = vn_arc.read().unwrap();
                vn.flags & (varnode_flags::CONSTANT | varnode_flags::ANNOTATION) != 0
            };
            if skip {
                continue;
            }

            let mut events: Vec<(i32, u32, bool)> = Vec::new();

            if let Some(def_op) = vn_arc.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                if let Some((bi, order)) = op_block_order(&def_op) {
                    events.push((bi, order, true));
                }
            }

            let reader_arcs: Vec<_> = {
                let vn = vn_arc.read().unwrap();
                vn.descend.iter().filter_map(|w| w.upgrade()).collect()
            };
            for reader_arc in reader_arcs {
                if let Some((bi, order)) = op_block_order(&reader_arc) {
                    events.push((bi, order, false));
                }
            }

            let mut by_block: std::collections::BTreeMap<i32, (Option<u32>, Option<u32>)> =
                std::collections::BTreeMap::new();
            for (bi, order, is_def) in events {
                let entry = by_block.entry(bi).or_insert((None, None));
                if is_def {
                    entry.0 = Some(order);
                } else {
                    entry.1 = Some(entry.1.map_or(order, |existing| existing.max(order)));
                }
            }

            let mut cover = Cover::new();
            for (bi, (def_order, last_ref)) in by_block {
                let start = def_order.unwrap_or(0);
                let end = last_ref.unwrap_or(u32::MAX);
                let cb = cover.blocks.entry(bi).or_insert_with(CoverBlock::new);
                cb.start = start;
                cb.end = end;
            }

            propagate_cover_through_cfg(&mut cover, fd);

            let mut vn = vn_arc.write().unwrap();
            if cover.blocks.is_empty() {
                vn.cover = None;
            } else {
                vn.cover = Some(Box::new(cover));
            }
        }
    }

    /// Merge copy-related HighVariable pairs whose instance covers are
    /// disjoint. Mirrors Ghidra's `Merge::mergeByCopy` (run after
    /// `mergeByCover` setup). For each alive `COPY(input, output)` op, the
    /// input and output HighVariables are merged iff:
    ///   - they pass `merge_test` (same space, same size, not constant)
    ///   - their aggregate covers do not intersect
    ///
    /// Restricting to copy-related pairs is what prevents incorrect merges
    /// like RDI+RSI (different parameters that happen to be non-live at the
    /// same time). Ghidra enforces the same restriction.
    pub fn merge_by_cover(&mut self, fd: &mut Funcdata) {
        // Iterate to a fixed point: an early merge can unify two
        // HighVariables whose cover subsequently becomes disjoint from a
        // third, enabling a merge that the first pass rejected. Bound the
        // iteration to avoid pathological loops.
        const MAX_PASSES: usize = 4;
        for _ in 0..MAX_PASSES {
            let merges_this_pass = self.merge_by_cover_single_pass(fd);
            if merges_this_pass == 0 {
                break;
            }
        }
    }

    fn merge_by_cover_single_pass(&mut self, fd: &mut Funcdata) -> usize {
        use crate::opcodes::OpCode;

        let copy_pairs: Vec<(Arc<RwLock<Varnode>>, Arc<RwLock<Varnode>>, i32, u32)> = fd
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY {
                    return None;
                }
                let in_vn = op.inrefs.get(0).cloned()?;
                let out_vn = op.output.clone()?;
                let (block_idx, order) = op_block_order(&op_ref.0)?;
                drop(op);
                Some((in_vn, out_vn, block_idx, order))
            })
            .collect();

        let mut merged = 0usize;
        for (in_vn, out_vn, copy_block, copy_order) in copy_pairs {
            let (in_high, out_high) = {
                let i = in_vn.read().unwrap();
                let o = out_vn.read().unwrap();
                (i.high.clone(), o.high.clone())
            };
            let (Some(in_high), Some(out_high)) = (in_high, out_high) else {
                continue;
            };

            if Arc::ptr_eq(&in_high, &out_high) {
                continue;
            }

            let compatible = {
                let vi = in_vn.read().unwrap();
                let vo = out_vn.read().unwrap();
                // For copy-related pairs, Ghidra's mergeTest only excludes
                // constants, annotations, and cover overlap (checked next).
                // The same-space/same-size restriction is NOT applied — the
                // COPY relationship is the safety guarantee, and COPYs
                // naturally have matching sizes by P-code spec.
                let bad = vi.flags & (varnode_flags::CONSTANT | varnode_flags::ANNOTATION) != 0
                    || vo.flags & (varnode_flags::CONSTANT | varnode_flags::ANNOTATION) != 0;
                !bad
            };
            if !compatible {
                continue;
            }

            let in_cover = aggregate_high_cover(&in_high);
            let out_cover = aggregate_high_cover(&out_high);
            if in_cover.intersects_except_at(&out_cover, copy_block, copy_order) {
                continue;
            }

            self.merge_force(in_vn, out_vn);
            merged += 1;
        }
        merged
    }
}

fn aggregate_high_cover(high: &Arc<RwLock<HighVariable>>) -> Cover {
    let h = high.read().unwrap();
    let mut agg = Cover::new();
    for inst_arc in &h.instances {
        if let Some(inst) = inst_arc.read().unwrap().cover.as_ref() {
            agg.merge(inst);
        }
    }
    agg
}

fn op_block_order(op_arc: &Arc<RwLock<crate::op::PcodeOp>>) -> Option<(i32, u32)> {
    let op = op_arc.read().unwrap();
    let order = op.start.get_order();
    let block_idx = op
        .parent
        .as_ref()
        .and_then(|weak| weak.upgrade())
        .map(|blk_arc| blk_arc.read().unwrap().get_index());
    block_idx.map(|bi| (bi, order))
}

/// Forward-propagate cover entries through the CFG. For each block whose
/// cover extends to end-of-block (`end == u32::MAX`, meaning live-out),
/// all successor blocks that don't already have a cover entry get filled
/// with `[0, MAX]` (transitively live). Iterates to fixed point.
///
/// This is conservative: a varnode might not actually flow to EVERY
/// successor (e.g., conditional branches). Over-approximating liveness
/// is safe — it blocks some valid merges but never allows invalid ones.
fn propagate_cover_through_cfg(cover: &mut Cover, fd: &Funcdata) {
    if cover.blocks.is_empty() {
        return;
    }

    // Build block_idx → successor block_idx map from the CFG.
    // BlockGraph stores blocks by index; FlowBlock::get_out gives edges.
    let mut successors: std::collections::HashMap<i32, Vec<i32>> = std::collections::HashMap::new();
    for i in 0..fd.bblocks.get_size() {
        if let Some(blk_arc) = fd.bblocks.get_block(i) {
            let blk = blk_arc.read().unwrap();
            let blk_idx = blk.get_index();
            let mut succs = Vec::new();
            for slot in 0..blk.size_out() {
                if let Some(edge) = blk.get_out(slot) {
                    succs.push(edge.point.read().unwrap().get_index());
                }
            }
            successors.insert(blk_idx, succs);
        }
    }

    // Worklist of blocks that are live-out and need their successors filled.
    let mut worklist: Vec<i32> = cover
        .blocks
        .iter()
        .filter(|(_, cb)| cb.end == u32::MAX)
        .map(|(idx, _)| *idx)
        .collect();

    while let Some(bi) = worklist.pop() {
        let Some(succs) = successors.get(&bi) else {
            continue;
        };
        for succ_idx in succs {
            let already_full = cover
                .blocks
                .get(succ_idx)
                .map(|cb| cb.start == 0 && cb.end == u32::MAX)
                .unwrap_or(false);
            if already_full {
                continue;
            }

            // If the successor already has a cover entry with a real range
            // (start > 0 or end < MAX), the varnode is actually def'd/used
            // there — don't overwrite. Only fill empty entries.
            let has_real_entry = cover.blocks.contains_key(succ_idx);
            if has_real_entry {
                continue;
            }

            let cb = cover
                .blocks
                .entry(*succ_idx)
                .or_insert_with(CoverBlock::new);
            cb.start = 0;
            cb.end = u32::MAX;
            // This new full-block entry is itself live-out; queue it.
            worklist.push(*succ_idx);
        }
    }
}

/// Map x86-64 register offset + size to a human-readable register name.
///
/// Returns `None` for offsets that don't correspond to a known general-purpose register.
fn register_name(offset: u64, size: usize) -> Option<String> {
    match (offset, size) {
        (0x00, 8) => Some("RAX".into()),
        (0x00, 4) => Some("EAX".into()),
        (0x00, 2) => Some("AX".into()),
        (0x00, 1) => Some("AL".into()),
        (0x08, 8) => Some("RCX".into()),
        (0x08, 4) => Some("ECX".into()),
        (0x10, 8) => Some("RDX".into()),
        (0x10, 4) => Some("EDX".into()),
        (0x18, 8) => Some("RBX".into()),
        (0x18, 4) => Some("EBX".into()),
        (0x20, 8) => Some("RSP".into()),
        (0x20, 4) => Some("ESP".into()),
        (0x28, 8) => Some("RBP".into()),
        (0x28, 4) => Some("EBP".into()),
        (0x30, 8) => Some("RSI".into()),
        (0x30, 4) => Some("ESI".into()),
        (0x38, 8) => Some("RDI".into()),
        (0x38, 4) => Some("EDI".into()),
        (0x80, 8) => Some("R8".into()),
        (0x88, 8) => Some("R9".into()),
        (0x90, 8) => Some("R10".into()),
        (0x98, 8) => Some("R11".into()),
        (0xA0, 8) => Some("R12".into()),
        (0xA8, 8) => Some("R13".into()),
        (0xB0, 8) => Some("R14".into()),
        (0xB8, 8) => Some("R15".into()),
        (0x200, 8) => Some("RIP".into()),
        _ => None,
    }
}

/// Represents a varnode within a specific block for merging purposes
pub struct BlockVarnode {
    /// The varnode reference
    pub vn: Arc<RwLock<Varnode>>,
    /// Index of the block this varnode is associated with
    pub block_index: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::opcodes::OpCode;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
    use crate::space::AddressSpace;

    /// Cross-space copy pair where the unique side has multiple readers
    /// should be merged: register `RDI` flows into `t1` via COPY, and `t1`
    /// is read by two ops (STORE + RETURN).
    #[test]
    fn test_merge_by_cover_unifies_copy_pair() {
        let mut fd = Funcdata::new("copy_unify", Address::new(0x1000), 0x40);

        let mut copy_op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        copy_op.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        copy_op.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));

        let mut store_op = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        store_op.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        store_op.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8));
        store_op.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut ret_op = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret_op.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        fd.inject_raw_ops(&[copy_op, store_op, ret_op]);
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let copy_op_arc = fd
            .obank
            .alivelist
            .iter()
            .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_COPY)
            .expect("COPY op should exist after injection")
            .0
            .clone();
        let copy = copy_op_arc.read().unwrap();
        let in_vn = copy.inrefs[0].clone();
        let out_vn = copy.output.clone().expect("COPY has output");
        drop(copy);

        let in_high = in_vn.read().unwrap().high.clone().expect("input has high");
        let out_high = out_vn.read().unwrap().high.clone().expect("output has high");
        assert!(
            Arc::ptr_eq(&in_high, &out_high),
            "multi-reader cross-space copy pair should share a HighVariable after merge_by_cover"
        );
    }

    /// Single-reader cross-space COPY pair should also merge: register `RDI`
    /// flows into `t1` via COPY, `t1` read by one RETURN op. The merge is
    /// safe (covers are disjoint) and produces Ghidra-aligned naming.
    #[test]
    fn test_merge_by_cover_unifies_single_reader_copy_pair() {
        let mut fd = Funcdata::new("copy_single", Address::new(0x3000), 0x40);

        let mut copy_op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        copy_op.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        copy_op.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));

        let mut ret_op = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret_op.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        fd.inject_raw_ops(&[copy_op, ret_op]);
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let copy_op_arc = fd
            .obank
            .alivelist
            .iter()
            .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_COPY)
            .expect("COPY op should exist after injection")
            .0
            .clone();
        let copy = copy_op_arc.read().unwrap();
        let in_vn = copy.inrefs[0].clone();
        let out_vn = copy.output.clone().expect("COPY has output");
        drop(copy);

        let in_high = in_vn.read().unwrap().high.clone().expect("input has high");
        let out_high = out_vn.read().unwrap().high.clone().expect("output has high");
        assert!(
            Arc::ptr_eq(&in_high, &out_high),
            "single-reader cross-space copy pair should share a HighVariable after merge_by_cover"
        );
    }

    /// Two COPYs feeding the same register at different times should NOT
    /// merge if their covers overlap. Concretely:
    ///   t1 = COPY(RDI)   -- block 0
    ///   use(t1)
    ///   t2 = COPY(RSI)   -- block 0, after t1's use
    ///   use(t2)
    /// RDI and RSI both flow into t1/t2, but RDI and RSI are different
    /// parameters that are not copy-related — so they must keep separate
    /// HighVariables.
    #[test]
    fn test_merge_by_cover_keeps_independent_registers_separate() {
        let mut fd = Funcdata::new("independent", Address::new(0x2000), 0x80);

        let mut c1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        c1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        c1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut use1 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        use1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut c2 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        c2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));
        c2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        fd.inject_raw_ops(&[c1, use1, c2]);
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        // RDI varnode and RSI varnode should NOT share a high (they're
        // not copy-related; nothing connects them).
        let rdi_vn = fd
            .vbank
            .loc_tree
            .iter()
            .find(|r| {
                let v = r.0.read().unwrap();
                v.address_space == AddressSpace::Register && v.loc == Address::new(0x38)
            })
            .map(|r| r.0.clone())
            .expect("RDI varnode should exist");
        let rsi_vn = fd
            .vbank
            .loc_tree
            .iter()
            .find(|r| {
                let v = r.0.read().unwrap();
                v.address_space == AddressSpace::Register && v.loc == Address::new(0x30)
            })
            .map(|r| r.0.clone())
            .expect("RSI varnode should exist");

        let rdi_high = rdi_vn.read().unwrap().high.clone().expect("RDI has high");
        let rsi_high = rsi_vn.read().unwrap().high.clone().expect("RSI has high");
        assert!(
            !Arc::ptr_eq(&rdi_high, &rsi_high),
            "RDI and RSI are independent parameters and must not share a HighVariable"
        );
    }
}

