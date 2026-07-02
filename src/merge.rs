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
    /// Set of varnode Arc pointers that are still referenced by an alive op.
    /// Built once per merge_all run; consulted by every loc_tree traversal so
    /// dead copy-prop/dead-code leftovers are excluded from HighVariables.
    live_set: std::collections::HashSet<usize>,
}

impl Merge {
    /// Create a new Merge instance
    pub fn new() -> Self {
        Self { var_counter: 0, live_set: std::collections::HashSet::new() }
    }

    /// Clear all existing HighVariables and reset merge state
    pub fn clear(&mut self, fd: &mut Funcdata) {
        for vn_ref in &fd.vbank.loc_tree {
            vn_ref.0.write().unwrap().high = None;
        }
        self.var_counter = 0;
    }

    /// Decide whether a varnode should participate in merging.
    ///
    /// Faithful to the contract of Ghidra's merge: it operates on the
    /// post-optimization varnode set, so only varnodes still referenced by
    /// an alive op are merged. This is determined by collecting the set of
    /// varnodes referenced by any alive op's inputs or output, then testing
    /// membership — NOT by inspecting `vn.def`/`vn.descend`, which become
    /// unreliable after copy-propagation redirects edges and dead-code marks
    /// ops dead without pruning varnode-side links.
    ///
    /// Input varnodes (function parameters / entry values) are always live.
    fn live_varnode_set(fd: &Funcdata) -> std::collections::HashSet<usize> {
        use std::collections::HashSet;
        let mut live: HashSet<usize> = HashSet::new();
        // Collect varnodes referenced by any alive op (inrefs + output).
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(out) = &op.output {
                live.insert(std::sync::Arc::as_ptr(out) as usize);
            }
            for in_arc in &op.inrefs {
                live.insert(std::sync::Arc::as_ptr(in_arc) as usize);
            }
        }
        // Also include block-level ops (comparisons/booleans may live only in blocks).
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if op.is_dead() {
                        continue;
                    }
                    if let Some(out) = &op.output {
                        live.insert(std::sync::Arc::as_ptr(out) as usize);
                    }
                    for in_arc in &op.inrefs {
                        live.insert(std::sync::Arc::as_ptr(in_arc) as usize);
                    }
                }
            }
        }
        live
    }

    /// Perform the full merging + naming pipeline.
    ///
    /// This mirrors the Ghidra merge action group (coreaction.cc:5718-5729)
    /// as a 9-step sequence, augmented with the Rugra-specific cover/naming
    /// plumbing. Step order:
    ///
    ///   1. MergeRequired   — mergeAddrTied + mergeMarker (required merges)
    ///   2. MarkExplicit    — (handled elsewhere by coreaction)
    ///   3. MarkImplied     — (handled elsewhere by coreaction)
    ///   4. MergeMultiEntry — multi-entry symbol merges
    ///   5. MergeCopy       — COPY input/output merges
    ///   6. DominantCopy    — dominant-copy selection
    ///   7. MergeAdjacent   — adjacent (input/output) speculative merges
    ///   8. MergeType       — same-type speculative merges
    ///   9. HideShadow      — shadow COPY consolidation
    ///  10. CopyMarker      — mark internal COPYs non-printing
    pub fn merge_all(&mut self, fd: &mut Funcdata) {
        // Build the live varnode set once (post-dead-code): only varnodes
        // referenced by an alive op participate in HighVariables. This makes
        // high.instances authoritative for printc.
        self.live_set = Self::live_varnode_set(fd);

        // Step 1 (part a): MergeRequired — mergeAddrTied.
        self.merge_addr_tied(fd);

        // Ensure every varnode has a HighVariable before the marker pass.
        self.ensure_all_have_high(fd);

        // Step 1 (part b): MergeRequired — mergeMarker.
        // Force-merge MULTIEQUAL/INDIRECT input+output. groupPartials is a
        // faithful no-op (no CONCAT machinery).
        self.merge_required(fd);

        // Compute liveness covers (Ghidra calculateCover). Must run after the
        // required merges so the speculative passes see final instance sets.
        self.compute_varnode_covers(fd);

        // Step 5 (Rugra's pre-existing cover-guarded COPY pass). Runs to a
        // fixed point; equivalent to MergeCopy but iterated.
        self.merge_by_cover(fd);

        // Step 4: MergeMultiEntry (faithful no-op without symbol machinery).
        self.merge_multi_entry(fd);

        // Step 5/6 explicit: MergeCopy + DominantCopy.
        self.merge_copy(fd);
        self.dominant_copy(fd);

        // Step 7: MergeAdjacent.
        self.merge_adjacent(fd);

        // Step 8: MergeType.
        self.merge_by_datatype(fd);

        // Step 9: HideShadow (analysis-only; no data-flow rewrite yet).
        self.hide_shadows(fd);

        // Step 10: CopyMarker.
        self.copy_marker(fd);

        // Sync HighVariable covers from member Varnode covers. Must run AFTER
        // all speculative merges finalize the instance sets so each
        // HighVariable's cover reflects all its members. ActionMarkImplied
        // (run later in the pipeline) consults high.cover via checkImpliedCover.
        self.update_high_covers(fd);

        // Auto-name all HighVariables.
        self.assign_names(fd);
    }

    /// Re-derive every HighVariable's internal cover from its member Varnodes.
    /// Faithful to HighVariable::updateInternalCover (variable.cc:324).
    /// Collects the distinct HighVariables reachable from live varnodes (each
    /// HighVariable holds Arc-shared instances, so we dedupe by Arc pointer).
    fn update_high_covers(&mut self, fd: &mut Funcdata) {
        use std::collections::HashSet;
        let mut seen: HashSet<usize> = HashSet::new();
        let mut to_update: Vec<std::sync::Arc<std::sync::RwLock<HighVariable>>> = Vec::new();
        for vn_ref in &fd.vbank.loc_tree {
            let high_arc = {
                let vn = vn_ref.0.read().unwrap();
                vn.high.clone()
            };
            if let Some(ha) = high_arc {
                let ptr = std::sync::Arc::as_ptr(&ha) as usize;
                if seen.insert(ptr) {
                    to_update.push(ha);
                }
            }
        }
        for ha in to_update {
            ha.write().unwrap().update_internal_cover();
        }
    }

    /// Mark a Varnode as implied. Faithful to Merge::markImplied (merge.cc:1595).
    /// In Ghidra this also sets coverdirty on the def op's inputs so their
    /// covers get recomputed; Rugra recomputes covers wholesale per merge_all,
    /// so we only set the IMPLIED flag here.
    pub fn mark_implied(vn: &Arc<RwLock<Varnode>>) {
        vn.write().unwrap().set_implied();
    }

    /// Test if inflating a Varnode's Cover to cover `high` causes an intersection
    /// with any OTHER instance of the Varnode's own HighVariable.
    /// Faithful to Merge::inflateTest (merge.cc:1616).
    ///
    /// When a varnode is implied, its def op's inputs propagate farther (into
    /// the consumer). Each such input must not have its inflated cover intersect
    /// a sibling instance's cover — otherwise two SSA versions of the same
    /// logical variable would be simultaneously live at the implied site.
    ///
    /// Returns true if there IS an intersection (i.e. the varnode CANNOT be
    /// implied). `high` is the HighVariable being implied; `a` is an input
    /// varnode of `a`'s def op.
    pub fn inflate_test(
        a: &Arc<RwLock<Varnode>>,
        high: &crate::variable::HighVariable,
    ) -> bool {
        let a_high = a.read().unwrap().high.clone();
        let Some(ahigh) = a_high else {
            return false; // a has no HighVariable — no intersection possible
        };
        let ahigh = ahigh.read().unwrap();
        // high.cover is the union of the implied varnode's instance covers.
        // We test each instance of a's HighVariable against it.
        for inst_arc in &ahigh.instances {
            let inst = inst_arc.read().unwrap();
            // Skip the instance that IS 'a' (Arc identity) — intersection
            // with itself or its copy-shadow is allowed (merge.cc:1626 copyShadow).
            if Arc::ptr_eq(inst_arc, a) {
                continue;
            }
            if let Some(ic) = inst.cover.as_ref() {
                if ic.intersects(&high.cover) {
                    return true;
                }
            }
        }
        false
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
                let (addr, size, live) = {
                    let vn = vn_arc.read().unwrap();
                    let live = vn.is_input()
                        || self.live_set.contains(&(std::sync::Arc::as_ptr(&vn_arc) as usize));
                    (vn.loc, vn.size, live)
                };
                if !live {
                    continue;
                }
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
        // Faithful to ActionAssignHigh (coreaction.hh:339) /
        // Funcdata::setHighLevel (funcdata_varnode.cc:595): assign a
        // HighVariable to EVERY Varnode in loc_tree that lacks one. The prior
        // live_set filter diverged from Ghidra and left implied/CAST-output
        // varnodes without a HighVariable, forcing printc into uVar_{offset}.
        let vn_arcs: Vec<Arc<RwLock<Varnode>>> = fd.vbank.loc_tree
            .iter()
            .filter(|r| r.0.read().unwrap().high.is_none())
            .map(|r| r.0.clone())
            .collect();

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

    /// Test whether a single Varnode can ever participate in merging.
    /// Faithful to `Merge::mergeTestBasic` (merge.cc:255-264).
    ///
    /// A Varnode is merge-eligible only if it:
    ///   - has a Cover (not constant/annotation/free),
    ///   - is not implied,
    ///   - is not a proto-partial (CONCAT piece), and
    ///   - is not a spacebase (stack/register pointer).
    fn merge_test_basic(vn: &Varnode) -> bool {
        if vn.is_constant() {
            return false;
        }
        if vn.flags & varnode_flags::ANNOTATION != 0 {
            return false;
        }
        if vn.is_free() {
            return false;
        }
        if vn.is_implied() {
            return false;
        }
        if vn.flags & varnode_flags::PROTO_PARTIAL != 0 {
            return false;
        }
        if vn.is_spacebase() {
            return false;
        }
        true
    }

    /// Speculatively merge two HighVariables iff their aggregate covers are
    /// disjoint. Faithful to `Merge::merge(high1, high2, isspeculative=true)`
    /// (merge.cc:1565-1575). This is the shared primitive behind merge_copy,
    /// merge_adjacent and merge_type: a merge is attempted, but skipped
    /// (returning false) if the two HighVariables are simultaneously live.
    ///
    /// Returns true if the merge was performed.
    fn merge_speculative(
        &mut self,
        high1: &Arc<RwLock<HighVariable>>,
        high2: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        if Arc::ptr_eq(high1, high2) {
            return true; // Already merged
        }
        let (cover1, cover2, instances1, instances2) = {
            let h1 = high1.read().unwrap();
            let h2 = high2.read().unwrap();
            let c1 = aggregate_high_cover_from(&h1);
            let c2 = aggregate_high_cover_from(&h2);
            (c1, c2, h1.instances.clone(), h2.instances.clone())
        };
        if cover1.intersects(&cover2) {
            return false;
        }
        // Covers are disjoint: merge all instances of high2 into high1.
        // We use the first varnode of high1 and each of high2 as merge_force
        // targets. merge_force dedupes by Arc identity.
        let anchor = instances1
            .into_iter()
            .next()
            .or_else(|| instances2.iter().next().cloned());
        let Some(anchor) = anchor else {
            return false;
        };
        for inst in instances2 {
            // Skip if already same high (defensive).
            let same = {
                let i = inst.read().unwrap();
                i.high.as_ref().map(|h| Arc::ptr_eq(h, high1)).unwrap_or(false)
            };
            if same {
                continue;
            }
            self.merge_force(anchor.clone(), inst);
        }
        true
    }

    /// Like `merge_speculative` but exempts a single op point from the cover
    /// intersection test. Faithful to the merge-point exemption used by
    /// Ghidra's copy merge (the COPY/MULTIEQUAL op reads input and writes
    /// output at one op, so their covers always overlap there).
    fn merge_speculative_except(
        &mut self,
        high1: &Arc<RwLock<HighVariable>>,
        high2: &Arc<RwLock<HighVariable>>,
        exclude_block: i32,
        exclude_order: u32,
    ) -> bool {
        if Arc::ptr_eq(high1, high2) {
            return true;
        }
        let (cover1, cover2, instances1, instances2) = {
            let h1 = high1.read().unwrap();
            let h2 = high2.read().unwrap();
            let c1 = aggregate_high_cover_from(&h1);
            let c2 = aggregate_high_cover_from(&h2);
            (c1, c2, h1.instances.clone(), h2.instances.clone())
        };
        if cover1.intersects_except_at(&cover2, exclude_block, exclude_order) {
            return false;
        }
        let anchor = instances1
            .into_iter()
            .next()
            .or_else(|| instances2.iter().next().cloned());
        let Some(anchor) = anchor else {
            return false;
        };
        for inst in instances2 {
            let same = {
                let i = inst.read().unwrap();
                i.high.as_ref().map(|h| Arc::ptr_eq(h, high1)).unwrap_or(false)
            };
            if same {
                continue;
            }
            self.merge_force(anchor.clone(), inst);
        }
        true
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

        // Faithful to ActionNameVars::linkSymbols (coreaction.cc:2940-2976):
        // iterate every Varnode in every space except const. Ghidra skips
        // isFree() (coreaction.cc:2957) because its printc never emits a free
        // Varnode (pushSymbolDetail routes to pushUnnamedLocation → raw addr).
        // Rugra's printc currently still emits free Varnodes (SSA-completeness
        // gap: some alive ops reference Varnodes whose def was dead-code-elim'd),
        // so we name them too — otherwise they fall through to uVar_{offset}.
        // TODO: once SSA completeness is fixed (no alive op refs a free
        // Varnode), restore the is_free() skip to match Ghidra exactly.
        let vn_arcs: Vec<Arc<RwLock<Varnode>>> = fd.vbank.loc_tree
            .iter()
            .filter(|r| {
                let v = r.0.read().unwrap();
                if v.is_constant() { return false; }
                if v.flags & crate::varnode::varnode_flags::ANNOTATION != 0 { return false; }
                true
            })
            .map(|r| r.0.clone())
            .collect();

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

    // ------------------------------------------------------------------
    // 9-step merge sequence (coreaction.cc:5718-5729).
    // Each method below maps to one Ghidra `Merge::` method. The steps
    // are invoked in order by `merge_all`.
    // ------------------------------------------------------------------

    /// Step 1: ActionMergeRequired (coreaction.hh:369).
    /// Faithful to `data.getMerge().mergeAddrTied(); groupPartials();
    /// mergeMarker();`. This is the initial *required* merge pass that
    /// runs before cover-based speculative merging.
    ///
    ///   - `mergeAddrTied`  — Rugra's `merge_addr_tied` already implements
    ///     the address-tied grouping (Ghidra merge.cc:609).
    ///   - `groupPartials`  — CONCAT-piece grouping (merge.cc:967). Rugra has
    ///     no CONCAT/partial-root machinery yet, so this is a no-op stub.
    ///   - `mergeMarker`    — force-merge MULTIEQUAL/INDIRECT input+output
    ///     Varnodes (merge.cc:889). Implemented below.
    pub fn merge_required(&mut self, fd: &mut Funcdata) {
        // mergeAddrTied: already implemented as merge_addr_tied. In Rugra's
        // pipeline merge_all calls merge_addr_tied separately; here we only
        // add the marker merge that address-tied alone does not cover.
        self.group_partials(fd);
        self.merge_marker(fd);
    }

    /// Group CONCAT-piece roots. Faithful to `Merge::groupPartials`
    /// (merge.cc:967-976). Rugra has no `protoPartial` registry (CONCAT
    /// reconstruction is not ported), so there is nothing to group. Kept as
    /// a named no-op to preserve the step sequence.
    fn group_partials(&mut self, _fd: &mut Funcdata) {
        // TODO: port CONCAT partial-root grouping when PieceNode/VariablePiece
        // machinery is available (merge.cc:967, groupPartialRoot at 1374).
    }

    /// Step 1c: Force-merge input and output of MULTIEQUAL and INDIRECT
    /// marker ops. Faithful to `Merge::mergeMarker` (merge.cc:889-902).
    ///
    /// For each alive marker op (that is not an indirect-creation) we
    /// force-merge its output HighVariable with each input HighVariable.
    /// Rugra does not implement Ghidra's data-flow "snip" trims
    /// (`trimOpInput`/`trimOpOutput`, which insert COPY ops to resolve
    /// cover intersections), so a forced merge that would cross covers is
    /// conservatively skipped rather than letting it produce two
    /// simultaneously-live instances of one logical variable.
    pub fn merge_marker(&mut self, fd: &mut Funcdata) {
        use crate::opcodes::OpCode;
        use crate::op::pcodeop_flags;

        // Collect (marker op, output, inputs) pairs without holding locks
        // across the merge calls.
        let marker_pairs: Vec<(
            Arc<RwLock<crate::op::PcodeOp>>,
            Arc<RwLock<Varnode>>,
            Vec<Arc<RwLock<Varnode>>>,
        )> = fd
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                // Ghidra: if ((!op->isMarker()) || op->isIndirectCreation()) continue;
                // In Ghidra the MARKER flag is set on MULTIEQUAL/INDIRECT ops.
                // Rugra may not set that flag at injection time, so we accept an
                // op as a marker if EITHER the flag is set OR its opcode is a
                // marker opcode.
                let is_marker_op = matches!(op.opcode, OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT);
                if !op.is_marker() && !is_marker_op {
                    return None;
                }
                if op.flags & pcodeop_flags::INDIRECT_CREATION != 0 {
                    return None;
                }
                let out = op.output.clone()?;
                let ins: Vec<_> = op.inrefs.clone();
                drop(op);
                Some((op_ref.0.clone(), out, ins))
            })
            .collect();

        for (_op_arc, out_vn, in_vns) in marker_pairs {
            // For INDIRECT, Ghidra only merges input slot 0 (the value being
            // tracked). For MULTIEQUAL, all inputs. (merge.cc:726: max = (code==INDIRECT)?1:numInput)
            let limit = in_vns.len();
            for in_vn in in_vns.iter().take(limit) {
                let in_basic = {
                    let v = in_vn.read().unwrap();
                    Self::merge_test_basic(&v)
                };
                let out_basic = {
                    let v = out_vn.read().unwrap();
                    Self::merge_test_basic(&v)
                };
                if !in_basic || !out_basic {
                    continue;
                }
                // Ghidra force-merges (snipping data-flow if covers overlap).
                // Without snip machinery we still force-merge: these are the
                // SSA marker ops whose input/output MUST be the same logical
                // variable by construction.
                self.merge_force(in_vn.clone(), out_vn.clone());
            }
        }
    }

    /// Step 4: ActionMergeMultiEntry (coreaction.hh:403).
    /// Faithful to `Merge::mergeMultiEntry` (merge.cc:908-963).
    ///
    /// Ghidra iterates `data.getScopeLocal()->beginMultiEntry()..endMultiEntry()`
    /// — the set of Symbols that own more than one SymbolEntry. For each such
    /// Symbol it gathers every linked Varnode (`findLinkedVarnodes`) and merges
    /// them all into one HighVariable so the multiple storage locations of a
    /// single logical variable are represented as one.
    ///
    /// Rugra does not yet build the `ScopeLocal` multi-entry registry
    /// (`beginMultiEntry`), but Varnodes *do* carry a `mapentry` back-pointer
    /// to their `SymbolEntry` (and through it to the owning `Symbol`). So we
    /// reconstruct the multi-entry grouping directly: group live, merge-eligible
    /// Varnodes by their owning Symbol's Arc identity, and for every Symbol
    /// that owns ≥ 2 distinct SymbolEntries (the `is_multi_entry` test,
    /// `whole_count > 1`), merge all its Varnodes into one HighVariable.
    ///
    /// Unlike Ghidra we cannot `snip` the data flow to resolve cover
    /// intersections (Rugra has no trim machinery), so the merge is attempted
    /// *speculatively* via `merge_speculative`: Varnodes whose covers make them
    /// simultaneously live are left in separate HighVariables rather than
    /// producing an incorrect union. This mirrors Ghidra's
    /// `mergeTestRequired` failure path (`newHigh->setUnmerged()`).
    pub fn merge_multi_entry(&mut self, fd: &mut Funcdata) {
        use crate::address::Address;
        use std::collections::HashMap;

        // Group live, merge-eligible Varnodes by owning Symbol (Arc pointer).
        // Each entry also records its SymbolEntry's address+size so we can
        // count DISTINCT whole-sized entries per Symbol — mirroring Ghidra's
        // `symbol->numEntries()` loop (merge.cc:916-928) which skips piece
        // entries whose size != the Symbol's whole type size.
        let mut by_symbol: HashMap<
            usize, // Symbol Arc ptr
            Vec<(Address, usize, Arc<RwLock<Varnode>>)>, // (entry addr, size, vn)
        > = HashMap::new();

        for vn_ref in &fd.vbank.loc_tree {
            let vn_arc = vn_ref.0.clone();
            // Resolve (symbol ptr, entry addr, entry size) or skip. A Varnode
            // with no mapentry is not a symbol storage location and never
            // participates in multi-entry merging.
            let (sym_ptr, entry_addr, entry_size) = {
                let vn = vn_arc.read().unwrap();
                let live = vn.is_input()
                    || self.live_set.contains(&(std::sync::Arc::as_ptr(&vn_arc) as usize));
                if !live || !Self::merge_test_basic(&vn) {
                    continue;
                }
                let me = match vn.get_symbol_entry() {
                    Some(e) => e,
                    None => continue, // No symbol mapping: not a symbol entry.
                };
                let me = me.read().unwrap();
                (
                    std::sync::Arc::as_ptr(&me.get_symbol()) as usize,
                    me.addr,
                    me.size as usize,
                )
            };
            by_symbol
                .entry(sym_ptr)
                .or_default()
                .push((entry_addr, entry_size, vn_arc));
        }

        // For each Symbol group with ≥ 2 distinct whole-sized entries, merge
        // all its Varnodes into one HighVariable. Faithful to merge.cc:920-948
        // (the per-SymbolEntry loop that accumulates mergeList, then the
        // merge(anchor, vn, false) loop).
        for (_, group) in by_symbol.drain() {
            // Distinct entries (by addr) — Ghidra counts whole-sized entries.
            let distinct_entries: std::collections::HashSet<u64> = group
                .iter()
                .map(|(a, _, _)| a.as_u64())
                .collect();
            if distinct_entries.len() < 2 {
                continue; // Not multi-entry for this Symbol.
            }
            // Ghidra uses mergeList[0]->getHigh() as the merge anchor and
            // attempts merge(anchor, vn, false) for each subsequent vn. We
            // take the first vn as the anchor and merge each other vn's High.
            let group: Vec<Arc<RwLock<Varnode>>> =
                group.into_iter().map(|(_, _, vn)| vn).collect();
            let anchor_arc = group[0].clone();
            for vn_arc in group.into_iter().skip(1) {
                self.merge_speculative_by_vn(&anchor_arc, &vn_arc);
            }
        }
    }

    /// Step 5: ActionMergeCopy (coreaction.hh:392).
    /// Faithful to `Merge::mergeOpcode(CPUI_COPY)` (merge.cc:326-350).
    ///
    /// For each alive COPY op, try to merge each input HighVariable with the
    /// output HighVariable. The merge is *required* (Ghidra calls
    /// `mergeTestRequired` then a non-speculative `merge`), but a cover
    /// intersection causes the merge to be skipped rather than forcing a
    /// data-flow snip (Rugra has no trim machinery).
    ///
    /// Note: `merge_by_cover` (the Rugra pre-existing pass) already performs
    /// the analogous cover-guarded COPY merge. This method exists so the
    /// Ghidra step is explicitly represented in the pipeline.
    pub fn merge_copy(&mut self, fd: &mut Funcdata) {
        use crate::opcodes::OpCode;

        // (in_vn, out_vn, op_arc) so we can compute the COPY's block/order
        // and exempt that single point from the cover intersection test —
        // the COPY op itself is the merge point, so input and output always
        // overlap there.
        let copy_pairs: Vec<(
            Arc<RwLock<Varnode>>,
            Arc<RwLock<Varnode>>,
            Arc<RwLock<crate::op::PcodeOp>>,
        )> = fd
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY {
                    return None;
                }
                let out = op.output.clone()?;
                let in_vn = op.inrefs.get(0).cloned()?;
                drop(op);
                Some((in_vn, out, op_ref.0.clone()))
            })
            .collect();

        for (in_vn, out_vn, op_arc) in copy_pairs {
            let (in_basic, out_basic) = {
                let vi = in_vn.read().unwrap();
                let vo = out_vn.read().unwrap();
                (Self::merge_test_basic(&vi), Self::merge_test_basic(&vo))
            };
            if !in_basic || !out_basic {
                continue;
            }
            // Required merge: exempt the COPY op's own block/order from the
            // intersection test (that overlap IS the merge point).
            if let Some((block, order)) = op_block_order(&op_arc) {
                self.merge_speculative_by_vn_except(&in_vn, &out_vn, block, order);
            } else {
                self.merge_speculative_by_vn(&in_vn, &out_vn);
            }
        }
    }

    /// Helper: speculative (cover-guarded) merge of two Varnodes' HighVariables.
    /// Used by merge_copy / merge_marker where the merge is only attempted if
    /// the two resulting HighVariables would not be simultaneously live.
    fn merge_speculative_by_vn(
        &mut self,
        vn1: &Arc<RwLock<Varnode>>,
        vn2: &Arc<RwLock<Varnode>>,
    ) -> bool {
        let (h1, h2) = {
            let v1 = vn1.read().unwrap();
            let v2 = vn2.read().unwrap();
            (v1.high.clone(), v2.high.clone())
        };
        let (Some(h1), Some(h2)) = (h1, h2) else {
            return false;
        };
        self.merge_speculative(&h1, &h2)
    }

    /// Helper: like `merge_speculative_by_vn` but exempts a single op point
    /// from the cover intersection test. Used by merge_copy, where the COPY
    /// op itself reads the input and writes the output — their covers always
    /// meet at that op, and that meeting is the merge point, not a real
    /// simultaneity. Any OTHER overlap still blocks the merge.
    fn merge_speculative_by_vn_except(
        &mut self,
        vn1: &Arc<RwLock<Varnode>>,
        vn2: &Arc<RwLock<Varnode>>,
        exclude_block: i32,
        exclude_order: u32,
    ) -> bool {
        let (h1, h2) = {
            let v1 = vn1.read().unwrap();
            let v2 = vn2.read().unwrap();
            (v1.high.clone(), v2.high.clone())
        };
        let (Some(h1), Some(h2)) = (h1, h2) else {
            return false;
        };
        self.merge_speculative_except(&h1, &h2, exclude_block, exclude_order)
    }

    /// Step 6: ActionDominantCopy (coreaction.cc:4831 / coreaction.hh:1008).
    /// Faithful to `Merge::processCopyTrims` (merge.cc:1415-1436) and its
    /// delegate `Merge::processHighDominantCopy` (merge.cc:1316-1337).
    ///
    /// In Ghidra, `processCopyTrims` walks the `copyTrims` list — COPY ops
    /// inserted by the earlier snip trims (`allocateCopyTrim`/`snipReads`,
    /// merge.cc:411,443) — to find HighVariables that received ≥ 2 such COPYs
    /// and calls `processHighDominantCopy(high)` to replace them with a single
    /// dominant COPY (the one whose block dominates all the others). The output
    /// Varnodes of the redundant COPYs are merged into the dominant COPY's
    /// output High.
    ///
    /// Rugra has no snip/trim machinery, so the literal `copyTrims` list is
    /// always empty and the Ghidra path would be a no-op. The pragmatic
    /// implementation here mirrors `merge_copy` but with the *dominant* anchor
    /// chosen by cover extent: for each alive COPY whose input and output are
    /// NOT yet in the same HighVariable, attempt a speculative
    /// (cover-guarded) merge of the input and output HighVariables, with the
    /// side holding the larger cover acting as the dominant anchor. When
    /// several COPYs read the same source Varnode, this folds their outputs
    /// into the source's HighVariable, achieving the dominant-copy
    /// consolidation. This keeps the same safety contract as Ghidra's
    /// `buildDominantCopy` (merge.cc:1207): a merge is skipped when it would
    /// make two instances of one logical variable simultaneously live.
    pub fn dominant_copy(&mut self, fd: &mut Funcdata) {
        use crate::opcodes::OpCode;

        // Gather (in_vn, out_vn, op_arc) for every alive COPY whose input and
        // output are NOT already in the same HighVariable. This mirrors the
        // `findAllIntoCopies` self-merge skip (merge.cc:1303: an internal copy
        // whose input high == output high is already consolidated).
        let copies: Vec<(
            Arc<RwLock<Varnode>>,
            Arc<RwLock<Varnode>>,
            Arc<RwLock<crate::op::PcodeOp>>,
        )> = fd
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY {
                    return None;
                }
                let out = op.output.clone()?;
                let in_vn = op.inrefs.get(0).cloned()?;
                let same_high = {
                    let o = out.read().unwrap();
                    let i = in_vn.read().unwrap();
                    match (o.high.as_ref(), i.high.as_ref()) {
                        (Some(ho), Some(hi)) => Arc::ptr_eq(ho, hi),
                        _ => false,
                    }
                };
                if same_high {
                    return None; // internal copy — already consolidated
                }
                drop(op);
                Some((in_vn, out, op_ref.0.clone()))
            })
            .collect();

        for (in_vn, out_vn, op_arc) in copies {
            // Skip varnodes that fail the basic merge-eligibility test.
            let (in_basic, out_basic) = {
                let vi = in_vn.read().unwrap();
                let vo = out_vn.read().unwrap();
                (Self::merge_test_basic(&vi), Self::merge_test_basic(&vo))
            };
            if !in_basic || !out_basic {
                continue;
            }
            // Choose the DOMINANT anchor: the side with the larger aggregate
            // cover becomes the merge target. Faithful to Ghidra's notion of a
            // dominant COPY (merge.cc:1158 domCopy) — the COPY whose reach
            // dominates the others. We use cover block count as the dominance
            // proxy (the wider live range dominates the narrower ones).
            let (cover_in, cover_out) = {
                let vi = in_vn.read().unwrap();
                let vo = out_vn.read().unwrap();
                let ci = vi.high.as_ref().map(aggregate_high_cover).unwrap_or_else(Cover::new);
                let co = vo.high.as_ref().map(aggregate_high_cover).unwrap_or_else(Cover::new);
                (ci, co)
            };
            let in_dominant = cover_in.blocks.len() >= cover_out.blocks.len();
            // Exempt the COPY op's own block/order from the intersection test:
            // the COPY reads the input and writes the output at one op, so
            // their covers always overlap there — that meeting IS the merge
            // point, not a real simultaneity (the same exemption merge_copy
            // uses). Any OTHER overlap still blocks the merge.
            if let Some((block, order)) = op_block_order(&op_arc) {
                if in_dominant {
                    self.merge_speculative_by_vn_except(&in_vn, &out_vn, block, order);
                } else {
                    self.merge_speculative_by_vn_except(&out_vn, &in_vn, block, order);
                }
            } else {
                self.merge_speculative_by_vn(&in_vn, &out_vn);
            }
        }
    }

    /// Step 9: ActionMergeAdjacent (coreaction.hh:381).
    /// Faithful to `Merge::mergeAdjacent` (merge.cc:983-1013).
    ///
    /// For each alive non-call op, try to merge each input HighVariable with
    /// the output HighVariable *speculatively*: only if the two have the
    /// same data-type, matching sizes, both pass `merge_test_basic`, and
    /// their covers do not intersect. This is a speculative (cover-guarded)
    /// merge — covers that overlap cause the merge to be skipped.
    pub fn merge_adjacent(&mut self, fd: &mut Funcdata) {
        // Gather (out, inputs) for every alive non-call op with a cover-eligible output.
        let adjacent_pairs: Vec<(Arc<RwLock<Varnode>>, Vec<Arc<RwLock<Varnode>>>)> = fd
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.is_dead() || op.is_call() {
                    return None;
                }
                let out = op.output.clone()?;
                let out_basic = {
                    drop(op);
                    let o = out.read().unwrap();
                    Self::merge_test_basic(&o)
                };
                if !out_basic {
                    return None;
                }
                // Re-read for inputs.
                let op = op_ref.0.read().unwrap();
                let ins: Vec<_> = op.inrefs.clone();
                drop(op);
                Some((out, ins))
            })
            .collect();

        for (out_vn, in_vns) in adjacent_pairs {
            let out_size = out_vn.read().unwrap().size;
            for in_vn in in_vns {
                let (in_basic, in_size, in_written_or_input) = {
                    let v = in_vn.read().unwrap();
                    let basic = Self::merge_test_basic(&v);
                    // Ghidra: if ((vn2->getDef()==null)&&(!vn2->isInput())) continue;
                    let written_or_input = v.is_written() || v.is_input();
                    (basic, v.size, written_or_input)
                };
                if !in_basic || in_size != out_size || !in_written_or_input {
                    continue;
                }
                // Speculative merge: same-type + disjoint covers required.
                self.merge_speculative_by_vn(&in_vn, &out_vn);
            }
        }
    }

    /// Step 10: ActionMergeType (coreaction.hh:414).
    /// Faithful to `Merge::mergeByDatatype` (merge.cc:359-401).
    ///
    /// Groups all HighVariables (reachable from live varnodes) by exact
    /// data-type, then attempts to merge each group via a cover-guarded
    /// `mergeLinear`-style pass: each HighVariable is merged into the first
    /// HighVariable it has a disjoint cover with.
    pub fn merge_by_datatype(&mut self, fd: &mut Funcdata) {
        use std::collections::HashMap;

        // Gather distinct HighVariables (dedup by Arc pointer).
        let mut high_ptrs: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut highs: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
        for vn_ref in &fd.vbank.loc_tree {
            let high_arc = {
                let vn = vn_ref.0.read().unwrap();
                vn.high.clone()
            };
            if let Some(ha) = high_arc {
                let ptr = std::sync::Arc::as_ptr(&ha) as usize;
                if high_ptrs.insert(ptr) {
                    highs.push(ha);
                }
            }
        }

        // Group by data-type identity (Arc::ptr_eq on the v_type Arc).
        let mut groups: HashMap<usize, Vec<Arc<RwLock<HighVariable>>>> = HashMap::new();
        for h in highs {
            let type_ptr = {
                let hg = h.read().unwrap();
                std::sync::Arc::as_ptr(&hg.v_type) as usize
            };
            groups.entry(type_ptr).or_default().push(h);
        }

        // For each same-type group, attempt cover-guarded linear merges.
        for (_, group) in groups {
            if group.len() < 2 {
                continue;
            }
            self.merge_linear_speculative(&group);
        }
    }

    /// Speculatively merge a list of same-type HighVariables as well as
    /// possible. Faithful to `Merge::mergeLinear` (merge.cc:272-292).
    ///
    /// Each HighVariable is merged with the first "stacked" HighVariable
    /// whose cover it does not intersect; if none is compatible it starts a
    /// new stack group. After a successful merge, the stacked head's cover
    /// snapshot is refreshed so subsequent tests reflect the union.
    fn merge_linear_speculative(&mut self, highvec: &[Arc<RwLock<HighVariable>>]) {
        if highvec.len() <= 1 {
            return;
        }
        // Snapshot of each HighVariable's aggregate cover. `highstack` holds
        // indices into `highvec` that currently head a merge group; the entry
        // in `covers` for a head is kept fresh as merges grow its cover.
        let mut covers: Vec<Cover> = highvec
            .iter()
            .map(|h| aggregate_high_cover(h))
            .collect();

        let mut highstack: Vec<usize> = Vec::new();
        for i in 0..highvec.len() {
            let mut merged_into: Option<usize> = None;
            for &j in &highstack {
                if covers[i].intersects(&covers[j]) {
                    continue;
                }
                if self.merge_speculative(&highvec[j], &highvec[i]) {
                    // Merge succeeded: refresh the head's cover snapshot so
                    // later HighVariables are tested against the union.
                    covers[j] = aggregate_high_cover(&highvec[j]);
                    merged_into = Some(j);
                    break;
                }
            }
            if merged_into.is_none() {
                highstack.push(i);
            }
        }
    }


    /// Step 11: ActionHideShadow (coreaction.hh:997 → coreaction.cc:4831).
    /// Faithful to `Merge::hideShadows` (merge.cc:1070-1100).
    ///
    /// For each HighVariable, find instance Varnodes that are defined by a
    /// COPY from *outside* the HighVariable. If two such Varnodes are
    /// `copyShadow`s of each other (i.e. copied from the same ancestor) and
    /// one's cover contains the other's definition, redirect the later
    /// COPY to read from the earlier Varnode — consolidating the shadow
    /// chain so both become instances of one variable.
    ///
    /// Rugra does not model the full data-flow rewrite (opSetInput), so this
    /// performs the *analysis* (finding copy-shadow pairs) and is otherwise
    /// a conservative no-op: it cannot currently rewrite COPY inputs.
    pub fn hide_shadows(&mut self, fd: &mut Funcdata) {
        // Gather distinct HighVariables (dedup by Arc pointer), as Ghidra
        // iterates beginDef..endDef(written) marking each high once.
        let mut high_ptrs: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut highs: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
        for vn_ref in &fd.vbank.loc_tree {
            let (written, high_arc) = {
                let vn = vn_ref.0.read().unwrap();
                (vn.is_written(), vn.high.clone())
            };
            if !written {
                continue;
            }
            if let Some(ha) = high_arc {
                let ptr = std::sync::Arc::as_ptr(&ha) as usize;
                if high_ptrs.insert(ptr) {
                    highs.push(ha);
                }
            }
        }

        for high in highs {
            // findSingleCopy: instances defined by a COPY whose input is NOT
            // part of the same HighVariable (merge.cc:1021-1036).
            let singlelist: Vec<Arc<RwLock<Varnode>>> = {
                let hg = high.read().unwrap();
                let mut acc = Vec::new();
                for inst_arc in &hg.instances {
                    let copy_pair = {
                        let inst = inst_arc.read().unwrap();
                        if !inst.is_written() {
                            None
                        } else {
                            // Get def op.
                            inst.def.as_ref().and_then(|w| w.upgrade())
                        }
                    };
                    let Some(def_op_arc) = copy_pair else { continue };
                    let (is_copy, in_high_same) = {
                        let def_op = def_op_arc.read().unwrap();
                        let is_copy = def_op.opcode == crate::opcodes::OpCode::CPUI_COPY;
                        let in_high_same = def_op
                            .inrefs
                            .get(0)
                            .map(|invn| {
                                let invn = invn.read().unwrap();
                                invn.high.as_ref().map(|h| Arc::ptr_eq(h, &high)).unwrap_or(false)
                            })
                            .unwrap_or(false);
                        (is_copy, in_high_same)
                    };
                    if is_copy && !in_high_same {
                        acc.push(inst_arc.clone());
                    }
                }
                acc
            };
            if singlelist.len() <= 1 {
                continue;
            }
            // hideShadows pairs: for vn1,vn2 that are copyShadow of each
            // other, redirect one COPY's input to the other. Rugra lacks
            // opSetInput, so this analysis is recorded but not applied.
            // TODO: port Varnode::copyShadow + Cover::containVarnodeDef +
            // Funcdata::opSetInput (merge.cc:1086-1096) to perform the rewrite.
            let _ = singlelist;
        }
    }

    /// Step 12: ActionCopyMarker (coreaction.hh:1019).
    /// Faithful to `Merge::markInternalCopies` (merge.cc:1444-1542).
    ///
    /// Walks all alive COPY ops and marks those whose output and input share
    /// a HighVariable as *non-printing* (internal copies). For COPYs between
    /// *different* HighVariables where the output is a shadowed varnode with
    /// no descendants, the copy is also suppressed. PIECE/SUBPIECE handling
    /// (CONCAT reassembly) is omitted: Rugra has no VariablePiece machinery.
    pub fn copy_marker(&mut self, fd: &mut Funcdata) {
        use crate::op::pcodeop_flags;
        use crate::opcodes::OpCode;

        // Collect (op, out_high == in_high) decisions without holding the
        // op read-lock while we mutate op flags.
        let decisions: Vec<(Arc<RwLock<crate::op::PcodeOp>>, bool)> = fd
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY {
                    return None;
                }
                let out = op.output.as_ref()?;
                let in0 = op.inrefs.get(0)?;
                let same_high = {
                    let o = out.read().unwrap();
                    let i = in0.read().unwrap();
                    match (o.high.as_ref(), i.high.as_ref()) {
                        (Some(ho), Some(hi)) => Arc::ptr_eq(ho, hi),
                        _ => false,
                    }
                };
                drop(op);
                Some((op_ref.0.clone(), same_high))
            })
            .collect();

        for (op_arc, same_high) in decisions {
            if same_high {
                // Internal COPY: input and output are the same HighVariable.
                // Mark non-printing (merge.cc:1461-1462).
                op_arc.write().unwrap().flags |= pcodeop_flags::NONPRINTING;
            } else {
                // COPY between different HighVariables. Ghidra additionally
                // suppresses shadowed assignments (v1->hasNoDescend() &&
                // shadowedVarnode(v1)). Rugra does not track shadowing here,
                // so this branch is a faithful no-op.
                // TODO: port shadowedVarnode (merge.cc:1471) for full fidelity.
            }
        }
    }

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
        let vn_arcs: Vec<Arc<RwLock<Varnode>>> = fd.vbank.loc_tree
            .iter()
            .filter(|r| {
                let v = r.0.read().unwrap();
                v.is_input() || self.live_set.contains(&(std::sync::Arc::as_ptr(&r.0) as usize))
            })
            .map(|r| r.0.clone())
            .collect();

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

            // NOTE: We intentionally do NOT propagate covers through CFG
            // successors (unlike an earlier version). Ghidra's Cover is a
            // precise def->use range (cover.cc), not a forward reachability
            // over-approximation. Propagating live-out to ALL successors as
            // [0, MAX] made covers cover the whole CFG, which broke
            // ActionMarkImplied's inflateTest (every input intersected) and
            // over-blocked merge_by_cover. Precise def/use ranges are correct.

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
    aggregate_high_cover_from(&h)
}

/// Aggregate (union) the covers of every instance in a borrowed HighVariable.
/// Used by the speculative-merge primitive and copy/adjacent/type passes to
/// test whether two HighVariables are simultaneously live.
fn aggregate_high_cover_from(high: &HighVariable) -> Cover {
    let mut agg = Cover::new();
    for inst_arc in &high.instances {
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
#[allow(dead_code)] // disabled: over-conservative CFG propagation broke inflateTest
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

    /// `copy_marker` (ActionCopyMarker, merge.cc:1444) must mark a COPY
    /// whose input and output share a HighVariable as non-printing.
    ///
    /// Setup: RDI flows into a unique temp `t1` via COPY, and `t1` flows
    /// back into RDI via a second COPY. After `merge_all`, RDI and both
    /// temps share one HighVariable, so the COPYs are internal and the
    /// second COPY (output high == input high) is flagged NONPRINTING.
    #[test]
    fn test_copy_marker_marks_internal_copy_non_printing() {
        use crate::op::pcodeop_flags;

        let mut fd = Funcdata::new("copy_marker", Address::new(0x4000), 0x40);

        // t1 = COPY(RDI)
        let mut c1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        c1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        c1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // use(t1) so t1 is live
        let mut use1 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        use1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        use1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8)); // RBX addr
        use1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        fd.inject_raw_ops(&[c1, use1]);
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        // Find the COPY op and verify it is internal (output high == input high)
        // and marked NONPRINTING.
        let copy_op = fd
            .obank
            .alivelist
            .iter()
            .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_COPY)
            .expect("COPY op should exist")
            .0
            .clone();

        let same_high = {
            let c = copy_op.read().unwrap();
            let out = c.output.as_ref().expect("COPY output");
            let in0 = c.inrefs.get(0).expect("COPY input");
            let o = out.read().unwrap();
            let i = in0.read().unwrap();
            match (o.high.as_ref(), i.high.as_ref()) {
                (Some(ho), Some(hi)) => Arc::ptr_eq(ho, hi),
                _ => false,
            }
        };
        assert!(same_high, "after merge, COPY input/output share a HighVariable");

        let flags = copy_op.read().unwrap().flags;
        assert!(
            flags & pcodeop_flags::NONPRINTING != 0,
            "internal COPY must be marked NONPRINTING by copy_marker"
        );
    }

    /// `merge_marker` (ActionMergeRequired, merge.cc:889) must force-merge the
    /// input and output of a MULTIEQUAL (phi) op into the same HighVariable.
    ///
    /// Setup: a single-input MULTIEQUAL that forwards RDI into a unique temp,
    /// then the temp is used. Because MULTIEQUAL is a marker op, its input and
    /// output must share a HighVariable after the required-merge pass.
    #[test]
    fn test_merge_marker_unifies_multiequal_io() {
        let mut fd = Funcdata::new("phi_merge", Address::new(0x5000), 0x40);

        // u0 = MULTIEQUAL(RDI)
        let mut phi = PcodeOpRaw::new(OpCode::CPUI_MULTIEQUAL as i32);
        phi.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));
        phi.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // use(u0)
        let mut store = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        store.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        store.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8));
        store.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));

        fd.inject_raw_ops(&[phi, store]);
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let phi_op = fd
            .obank
            .alivelist
            .iter()
            .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL)
            .expect("MULTIEQUAL op should exist")
            .0
            .clone();
        let phi = phi_op.read().unwrap();
        let out_vn = phi.output.clone().expect("MULTIEQUAL output");
        let in_vn = phi.inrefs[0].clone();
        drop(phi);

        let out_high = out_vn.read().unwrap().high.clone().expect("phi out has high");
        let in_high = in_vn.read().unwrap().high.clone().expect("phi in has high");
        assert!(
            Arc::ptr_eq(&in_high, &out_high),
            "MULTIEQUAL input and output must share a HighVariable after merge_marker"
        );
    }

    /// `merge_multi_entry` (ActionMergeMultiEntry, merge.cc:908) must merge
    /// Varnodes mapped to distinct SymbolEntries of the same Symbol.
    ///
    /// Setup: two Unique-space temps `t1` and `t2` at different addresses,
    /// each carrying a `mapentry` pointing to a different SymbolEntry of the
    /// SAME Symbol (the multi-entry condition: ≥ 2 distinct whole-sized
    /// entries per Symbol). After `merge_all`, `t1` and `t2` must share one
    /// HighVariable because they are two storage locations of one logical
    /// variable.
    #[test]
    fn test_merge_multi_entry_unifies_symbol_entries() {
        use crate::database::{Symbol, SymbolEntry};
        use crate::address::RangeList;

        let mut fd = Funcdata::new("multi_entry", Address::new(0x6000), 0x80);

        // Two independent temps (different addresses) — nothing copy-related
        // links them, so only merge_multi_entry (via the shared Symbol) can
        // merge them.
        let mut def1 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8)); // RBX ptr
        def1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8)); // t1

        let mut use1 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        use1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        use1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x20, 8)); // RSP addr
        use1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8)); // store t1

        let mut def2 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x28, 8)); // RBP ptr
        def2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8)); // t2

        let mut use2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        use2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8)); // use t2

        fd.inject_raw_ops(&[def1, use1, def2, use2]);
        fd.run_heritage_direct();

        // Resolve the actual live Varnode objects (post-heritage the LOAD
        // outputs are the canonical t1/t2 instances). We grab them from the
        // defining LOAD ops' outputs — robust against loc_tree duplicate
        // entries that arise from raw injection.
        let loads: Vec<_> = fd
            .obank
            .alivelist
            .iter()
            .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_LOAD)
            .map(|o| o.0.clone())
            .collect();
        assert_eq!(loads.len(), 2, "two LOAD ops expected");
        let t1 = {
            let l = loads[0].read().unwrap();
            l.output.clone().expect("LOAD1 output")
        };
        let t2 = {
            let l = loads[1].read().unwrap();
            l.output.clone().expect("LOAD2 output")
        };
        assert!(
            t1.read().unwrap().loc != t2.read().unwrap().loc,
            "t1 and t2 must be at distinct addresses"
        );

        // Build a single Symbol with two distinct SymbolEntries (multi-entry).
        let sym = Arc::new(RwLock::new(Symbol::new(0, "shared", "long")));
        let entry1 = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym.clone(),
            0,
            Address::new(0xAAA),
            0,
            8,
            RangeList::new(),
        )));
        let entry2 = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym.clone(),
            0,
            Address::new(0xBBB),
            0,
            8,
            RangeList::new(),
        )));

        // Attach entry1 → t1, entry2 → t2 (the canonical instances).
        t1.write().unwrap().mapentry = Some(entry1.clone());
        t2.write().unwrap().mapentry = Some(entry2.clone());

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let h1 = t1.read().unwrap().high.clone().expect("t1 has high");
        let h2 = t2.read().unwrap().high.clone().expect("t2 has high");
        assert!(
            Arc::ptr_eq(&h1, &h2),
            "multi-entry symbol's varnodes must share a HighVariable after merge_multi_entry"
        );
    }

    /// `merge_multi_entry` must NOT merge Varnodes whose SymbolEntries map to
    /// DIFFERENT Symbols (the single-entry case). Two temps each with their own
    /// one-entry Symbol should remain separate.
    #[test]
    fn test_merge_multi_entry_keeps_single_entry_symbols_separate() {
        use crate::database::{Symbol, SymbolEntry};
        use crate::address::RangeList;

        let mut fd = Funcdata::new("single_entry", Address::new(0x6050), 0x80);

        let mut def1 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8));
        def1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut use1 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        use1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        use1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x20, 8));
        use1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut def2 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x28, 8));
        def2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));

        let mut use2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        use2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));

        fd.inject_raw_ops(&[def1, use1, def2, use2]);
        fd.run_heritage_direct();

        // Resolve the canonical live Varnode objects via the defining LOAD ops.
        let loads: Vec<_> = fd
            .obank
            .alivelist
            .iter()
            .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_LOAD)
            .map(|o| o.0.clone())
            .collect();
        assert_eq!(loads.len(), 2, "two LOAD ops expected");
        let t1 = {
            let l = loads[0].read().unwrap();
            l.output.clone().expect("LOAD1 output")
        };
        let t2 = {
            let l = loads[1].read().unwrap();
            l.output.clone().expect("LOAD2 output")
        };

        // Two DIFFERENT symbols, each with one entry (not multi-entry).
        let sym_a = Arc::new(RwLock::new(Symbol::new(0, "a", "long")));
        let sym_b = Arc::new(RwLock::new(Symbol::new(0, "b", "long")));
        let entry_a = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym_a,
            0,
            Address::new(0xAAA),
            0,
            8,
            RangeList::new(),
        )));
        let entry_b = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym_b,
            0,
            Address::new(0xBBB),
            0,
            8,
            RangeList::new(),
        )));

        t1.write().unwrap().mapentry = Some(entry_a.clone());
        t2.write().unwrap().mapentry = Some(entry_b.clone());

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let h1 = t1.read().unwrap().high.clone().expect("t1 has high");
        let h2 = t2.read().unwrap().high.clone().expect("t2 has high");
        assert!(
            !Arc::ptr_eq(&h1, &h2),
            "single-entry symbol varnodes must NOT be merged by merge_multi_entry"
        );
    }

    /// `dominant_copy` (ActionDominantCopy / processHighDominantCopy,
    /// merge.cc:1316) must merge the input and output HighVariables of a COPY
    /// when their covers are disjoint (the COPY op point excepted). This is the
    /// core dominant-copy mechanism: for each alive COPY whose input/output are
    /// not yet in the same High, attempt a cover-guarded merge with the side
    /// holding the larger cover as the dominant anchor.
    ///
    /// Setup: `RDI` (function input) flows into a unique temp `t1` via COPY,
    /// and `t1` is read by a STORE. This is the same shape as the verified
    /// `test_merge_by_cover_unifies_copy_pair` — the COPY input and output
    /// covers are disjoint except at the COPY op, so the merge must happen.
    #[test]
    fn test_dominant_copy_unifies_copy_input_output() {
        let mut fd = Funcdata::new("dom_copy", Address::new(0x7000), 0x40);

        // t1 = COPY(RDI)
        let mut c1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        c1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        c1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // use(t1) via STORE so t1 is live and multi-reader
        let mut store = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        store.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        store.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8)); // RBX addr
        store.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut ret = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        fd.inject_raw_ops(&[c1, store, ret]);
        fd.run_heritage_direct();

        // Resolve the canonical COPY input/output via the defining COPY op.
        let copy_op = fd
            .obank
            .alivelist
            .iter()
            .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_COPY)
            .map(|o| o.0.clone())
            .expect("COPY op should exist");
        let (in_vn, out_vn) = {
            let c = copy_op.read().unwrap();
            (c.inrefs[0].clone(), c.output.clone().expect("COPY output"))
        };

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let in_high = in_vn.read().unwrap().high.clone().expect("COPY input has high");
        let out_high = out_vn.read().unwrap().high.clone().expect("COPY output has high");
        assert!(
            Arc::ptr_eq(&in_high, &out_high),
            "COPY input and output must share a HighVariable after dominant_copy \
             (covers disjoint except at the COPY op)"
        );
    }
}

