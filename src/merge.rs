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
    /// COPY ops inserted to facilitate forced merges (snip trims).
    /// Faithful to Ghidra `Merge::copyTrims` (merge.hh:87). Populated by
    /// `snip_reads` (via `unify_address`→`eliminate_intersect`) during the
    /// forced-merge path. Consumed by `process_copy_trims`.
    copy_trims: Vec<crate::op::PcodeOpRef>,
}

impl Merge {
    /// Create a new Merge instance
    pub fn new() -> Self {
        Self {
            var_counter: 0,
            live_set: std::collections::HashSet::new(),
            copy_trims: Vec::new(),
        }
    }

    /// Clear all existing HighVariables and reset merge state
    pub fn clear(&mut self, fd: &mut Funcdata) {
        for vn_ref in &fd.vbank.loc_tree {
            vn_ref.0.write().unwrap().high = None;
        }
        self.var_counter = 0;
        self.copy_trims.clear();
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

        // Step 4: MergeMultiEntry (faithful no-op without symbol machinery).
        self.merge_multi_entry(fd);

        // Step 5: MergeCopy — mergeOpcode(CPUI_COPY) (coreaction.cc:5722).
        // Required test + merge; cover intersection silently skips (no snip).
        self.merge_opcode(fd, crate::opcodes::OpCode::CPUI_COPY);

        // Step 6: DominantCopy — processCopyTrims (coreaction.cc:5723).
        // Faithful no-op: copyTrims is never populated (Rugra lacks the
        // snip/trim data-flow rewrite machinery that ActionMergeRequired's
        // forced-merge path uses to fill it). See process_copy_trims.
        self.process_copy_trims(fd);

        // Step 7: MergeAdjacent.
        self.merge_adjacent(fd);

        // Step 8: MergeType.
        self.merge_by_datatype(fd);

        // Step 9: HideShadow (analysis-only; no data-flow rewrite yet).
        self.hide_shadows(fd);

        // Step 10: CopyMarker.
        self.mark_internal_copies(fd);

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
            // Ghidra merge.cc:631-632: unifyAddress(startiter, bounds[max]) —
            // snip any cover intersections BEFORE the forced merge, inserting
            // COPY trims (recorded in copy_trims for process_copy_trims).
            self.unify_address(fd, group);
            // Forced merge: merge all varnodes in the group pairwise.
            // Ghidra uses mergeRangeMust (merge.cc:301), which calls
            // mergeTestMust(vn) per varnode (hasCover && !isImplied) then
            // merge(high, false). Rugra gates with merge_test_must, then
            // merge_force (cover already resolved by unify_address).
            for i in 0..group.len() {
                for j in i + 1..group.len() {
                    let vn1_arc = group[i].clone();
                    let vn2_arc = group[j].clone();

                    // mergeTestMust gate (merge.cc:308,313): both must have
                    // cover and not be implied, else skip (Ghidra throws;
                    // Rugra logs and skips).
                    let must_ok = {
                        let v1 = vn1_arc.read().unwrap();
                        let v2 = vn2_arc.read().unwrap();
                        Self::merge_test_must(&v1) && Self::merge_test_must(&v2)
                    };
                    if !must_ok {
                        continue;
                    }
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

    // Ghidra: merge.cc:102 Merge::mergeTestRequired
    /// Required-merge test between two HighVariables.
    /// Faithful to `Merge::mergeTestRequired` (merge.cc:102-166).
    ///
    /// This is a pure property test — it does NOT check Cover intersection
    /// (that is done by `merge()` itself, which returns false on overlap).
    /// It checks: typelock conflict, addrtied-different-address, input/persist
    /// conflicts, extrout, protopartial conflicts.
    ///
    /// VariablesPiece-group and Symbol-mapping checks (merge.cc:147-164) are
    /// omitted: Rugra has no VariablePiece/Symbol infrastructure yet. This is
    /// a conservative subset — it may allow merges Ghidra forbids (rare), but
    /// never forbids merges Ghidra allows based on the implemented checks.
    pub fn merge_test_required(
        &self,
        high_out: &Arc<RwLock<HighVariable>>,
        high_in: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        let ho = high_out.read().unwrap();
        let hi = high_in.read().unwrap();
        if Arc::ptr_eq(high_out, high_in) {
            return true; // Already merged
        }
        // typelock: if both locked, types must match (merge.cc:107-109)
        if hi.is_type_locked() && ho.is_type_locked() {
            if !Arc::ptr_eq(&hi.v_type, &ho.v_type) {
                return false;
            }
        }
        // addrtied: both addrtied but different address -> forbid (merge.cc:111-116)
        if ho.is_addr_tied() && hi.is_addr_tied() {
            // getTiedVarnode compare: representative instance loc (offset)
            let addr_out = ho.instances.first().map(|v| v.read().unwrap().loc);
            let addr_in = hi.instances.first().map(|v| v.read().unwrap().loc);
            if let (Some(a_out), Some(a_in)) = (addr_out, addr_in) {
                if a_out != a_in {
                    return false;
                }
            }
        }
        // input/persist/extrout conflicts (merge.cc:118-134)
        if hi.is_input() {
            if ho.is_persist() {
                return false;
            }
            if ho.is_addr_tied() && !hi.is_addr_tied() {
                return false;
            }
        } else if hi.is_extra_out() {
            return false;
        }
        if ho.is_input() {
            if hi.is_persist() {
                return false;
            }
            if hi.is_addr_tied() && !ho.is_addr_tied() {
                return false;
            }
        } else if ho.is_extra_out() {
            return false;
        }
        // protopartial conflicts (merge.cc:136-146)
        if hi.is_proto_partial() {
            if ho.is_proto_partial() {
                return false;
            }
            if ho.is_input() {
                return false;
            }
            if ho.is_addr_tied() {
                return false;
            }
            if ho.is_persist() {
                return false;
            }
        }
        if ho.is_proto_partial() {
            if hi.is_input() {
                return false;
            }
            if hi.is_addr_tied() {
                return false;
            }
            if hi.is_persist() {
                return false;
            }
        }
        // VariablePiece-group check (merge.cc:147-155) — omitted: no VariablePiece.
        // Symbol-mapping check (merge.cc:157-164) — omitted: no Symbol on HighVariable.
        true
    }

    // Ghidra: merge.cc:241 Merge::mergeTestMust
    /// Test if a Varnode that MUST be merged CAN be merged. Faithful to
    /// `Merge::mergeTestMust` (merge.cc:241-247). Returns true if the Varnode
    /// has a cover and is not implied (eligible for forced merge); false
    /// otherwise. Ghidra throws on failure; Rugra returns false (caller logs).
    fn merge_test_must(vn: &Varnode) -> bool {
        vn.has_cover() && !vn.is_implied()
    }

    // Ghidra: merge.cc:1657 Merge::mergeTest
    /// Test if `high` can be added to the merge group `testlist` without
    /// causing a cover intersection. Faithful to `Merge::mergeTest(high, tmplist)`
    /// (merge.cc:1657-1669). Returns true and pushes high to testlist if no
    /// intersection; false otherwise.
    ///
    /// Ghidra uses HighIntersectTest::intersection (cached, with shadow/block
    /// refinement). Rugra uses aggregate_high_cover + intersect_char directly
    /// (no cache, conservative — may report intersection where Ghidra's
    /// blockIntersection would rule it out via shadow analysis).
    fn merge_test_with_list(
        &self,
        high: &Arc<RwLock<HighVariable>>,
        testlist: &mut Vec<Arc<RwLock<HighVariable>>>,
    ) -> bool {
        // Ghidra: if (!high->hasCover()) return false;
        // Check any instance has cover.
        let has_cov = high.read().unwrap().instances.iter().any(|v| v.read().unwrap().has_cover());
        if !has_cov {
            return false;
        }
        let high_cover = aggregate_high_cover(high);
        for other in testlist.iter() {
            let other_cover = aggregate_high_cover(other);
            if high_cover.intersect_char(&other_cover) > 0 {
                return false;
            }
        }
        testlist.push(high.clone());
        true
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

        // Collect marker ops (merge.cc:894-896).
        let marker_ops: Vec<crate::op::PcodeOpRef> = fd
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                let is_marker_op = matches!(op.opcode, OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT);
                if !op.is_marker() && !is_marker_op {
                    return None;
                }
                if op.flags & pcodeop_flags::INDIRECT_CREATION != 0 {
                    return None;
                }
                drop(op);
                Some(crate::op::PcodeOpRef(op_ref.0.clone()))
            })
            .collect();

        // Ghidra merge.cc:897-901: INDIRECT → mergeIndirect, else → mergeOp.
        for op_ref in &marker_ops {
            let is_indirect = op_ref.0.read().unwrap().opcode == OpCode::CPUI_INDIRECT;
            if is_indirect {
                self.merge_indirect(fd, op_ref);
            } else {
                self.merge_op(fd, op_ref);
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
    // Ghidra: merge.cc:326 Merge::mergeOpcode
    /// Try to merge the input and output Varnodes of every op with the given
    /// opcode. Faithful to `Merge::mergeOpcode` (merge.cc:326-350).
    ///
    /// Walks basic blocks in linear order; for each op matching `opc`, if
    /// `mergeTestBasic` passes for output and each input, and
    /// `mergeTestRequired` passes for their HighVariables, calls
    /// `merge(high_out, high_in, false)`. Cover intersection causes the merge
    /// to be silently skipped (merge() returns false) — NO snip, NO copyTrims.
    pub fn merge_opcode(&mut self, fd: &mut Funcdata, opc: crate::opcodes::OpCode) {
        let n_blocks = fd.bblocks.get_size();
        for i in 0..n_blocks {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let ops: Vec<crate::op::PcodeOpRef> = {
                let bl_rg = bl.read().unwrap();
                bl_rg.get_ops()
            };
            for op_ref in &ops {
                let (vn1_arc, inputs): (Option<Arc<RwLock<Varnode>>>, Vec<Arc<RwLock<Varnode>>>) = {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode != opc {
                        continue;
                    }
                    let out = op.output.clone();
                    let ins: Vec<Arc<RwLock<Varnode>>> =
                        op.inrefs.iter().cloned().collect();
                    (out, ins)
                };
                let Some(vn1_arc) = vn1_arc else { continue };
                // mergeTestBasic on output (merge.cc:341)
                if !Self::merge_test_basic(&vn1_arc.read().unwrap()) {
                    continue;
                }
                let high_out = {
                    let vn1 = vn1_arc.read().unwrap();
                    vn1.high.clone()
                };
                let Some(high_out) = high_out else { continue };
                // For each input: mergeTestBasic + mergeTestRequired + merge
                for vn2_arc in &inputs {
                    if !Self::merge_test_basic(&vn2_arc.read().unwrap()) {
                        continue;
                    }
                    let high_in = {
                        let vn2 = vn2_arc.read().unwrap();
                        vn2.high.clone()
                    };
                    let Some(high_in) = high_in else { continue };
                    // mergeTestRequired — pure property test, no cover check
                    if !self.merge_test_required(&high_out, &high_in) {
                        continue;
                    }
                    // merge(high_out, high_in, false) — cover intersection
                    // returns false (skip), never snips (merge.cc:1565-1575).
                    // merge_speculative mirrors Merge::merge exactly:
                    // ptr_eq->true, cover intersect->false(skip), else merge.
                    let _ = self.merge_speculative(&high_out, &high_in);
                }
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

    // Ghidra: merge.cc:411 Merge::allocateCopyTrim
    /// Allocate a COPY op (with a unique-space output) that copies `in_vn`,
    /// inserted to facilitate a forced merge (a "copy trim"). The new COPY is
    /// recorded in `copy_trims` for later processing by `process_copy_trims`.
    /// Faithful to `Merge::allocateCopyTrim` (merge.cc:411-434).
    ///
    /// **Union resolution path omitted** (merge.cc:417-428): Ghidra resolves
    /// union field types via `inheritResolution`/`forceFacingType`/`getUnionField`.
    /// Rugra has no union-resolution infrastructure; this path is skipped
    /// (the COPY is created without union field forcing — conservative).
    fn allocate_copy_trim(
        &mut self,
        fd: &mut Funcdata,
        in_vn: &Arc<RwLock<Varnode>>,
        addr: crate::address::Address,
        _trim_op: &crate::op::PcodeOpRef,
    ) -> crate::op::PcodeOpRef {
        let copy_op = fd.new_op(1, addr);
        fd.op_set_opcode(&copy_op, crate::opcodes::OpCode::CPUI_COPY);
        let size = in_vn.read().unwrap().size;
        // new_unique returns a free Varnode; set as COPY output.
        let out_vn = fd.new_unique(size);
        fd.op_set_output(&copy_op, out_vn);
        fd.op_set_input(&copy_op, in_vn.clone(), 0);
        self.copy_trims.push(copy_op.clone());
        copy_op
    }

    // Ghidra: merge.cc:443 Merge::snipReads
    /// Truncate the data-flow for `vn` by creating a COPY from `vn` into a new
    /// temporary Varnode, then replacing the reads of `vn` in `marked_ops`
    /// with reads of the temporary.
    /// Faithful to `Merge::snipReads` (merge.cc:443-480).
    fn snip_reads(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        marked_ops: &[crate::op::PcodeOpRef],
    ) {
        if marked_ops.is_empty() {
            return;
        }
        // Figure out where the copy is inserted (merge.cc:453-467).
        let (insert_begin_bb, after_op) = {
            let vn_rg = vn.read().unwrap();
            if vn_rg.is_input() {
                // Input varnode: insert at begin of block 0.
                let bb0 = fd.bblocks.get_block(0);
                (bb0, None::<crate::op::PcodeOpRef>)
            } else {
                // Defined varnode: insert after its def op (or after the op
                // causing the effect if def is INDIRECT).
                let def_arc = vn_rg.def.as_ref().and_then(|w| w.upgrade());
                match def_arc {
                    Some(def) => {
                        let def_op = crate::op::PcodeOpRef(def.clone());
                        let after = {
                            let d = def.read().unwrap();
                            if d.opcode == crate::opcodes::OpCode::CPUI_INDIRECT {
                                // Snip must come after the op CAUSING the effect,
                                // not the INDIRECT itself (merge.cc:462-464).
                                // in(1) is an iop-space const varnode encoding the
                                // target op address; get_op_from_const resolves it.
                                d.get_in(1).and_then(|vn2| {
                                    fd.get_op_from_const(vn2)
                                })
                            } else {
                                Some(crate::op::PcodeOpRef(def.clone()))
                            }
                        };
                        (None, after.or(Some(def_op)))
                    }
                    None => {
                        // No def but not input: insert at block 0 begin.
                        let bb0 = fd.bblocks.get_block(0);
                        (bb0, None)
                    }
                }
            }
        };
        // pc = address of the insertion point.
        let pc = if let Some(ao) = &after_op {
            ao.0.read().unwrap().get_addr()
        } else {
            crate::address::Address::new(0)
        };
        let copyop = self.allocate_copy_trim(fd, vn, pc, &marked_ops[0]);
        // Insert the COPY into the P-code stream.
        if let Some(bb) = &insert_begin_bb {
            fd.op_insert_begin(&copyop, bb);
        } else if let Some(ao) = &after_op {
            fd.op_insert_after(&copyop, ao);
        }
        // Replace each marked op's read of vn with the COPY's output.
        let copy_out = copyop.0.read().unwrap().output.clone();
        let Some(copy_out) = copy_out else { return };
        for mop in marked_ops {
            let slot = {
                let m = mop.0.read().unwrap();
                // Find which input slot holds vn (by Arc ptr eq).
                m.inrefs.iter().position(|v| Arc::ptr_eq(v, vn))
            };
            if let Some(slot) = slot {
                fd.op_set_input(mop, copy_out.clone(), slot);
            }
        }
    }

    // Ghidra: merge.cc:489 Merge::eliminateIntersect
    /// For each reader of `vn`, check if its single-read cover intersects any
    /// other Varnode in `blocksort` (same storage). If so, mark the reader for
    /// snipping. Then call `snip_reads`.
    /// Faithful to `Merge::eliminateIntersect` (merge.cc:489-571).
    fn eliminate_intersect(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        blocksort: &[BlockVarnode],
    ) {
        let marked_ops: Vec<crate::op::PcodeOpRef> = {
            // Collect descendant (reader) ops of vn.
            let descend: Vec<crate::op::PcodeOpRef> = {
                let v = vn.read().unwrap();
                v.descend.iter().filter_map(|w| w.upgrade()).map(|a| crate::op::PcodeOpRef(a)).collect()
            };
            let mut marked = Vec::new();
            for op_ref in &descend {
                let mut insertop = false;
                // Build a single-read cover: addDefPoint(vn) + addRefPoint(op,vn)
                let mut single = Cover::new();
                let (vn_block, vn_order, vn_is_input) = varnode_def_loc(&vn.read().unwrap());
                if vn_is_input {
                    single.add_def_point(0, 2); // sentinel (merge.cc:448)
                } else {
                    single.add_def_point(vn_block, vn_order);
                }
                let (op_block, op_order) = {
                    let op = op_ref.0.read().unwrap();
                    op_loc(&op)
                };
                single.add_ref_point(op_block, op_order);
                // Iterate over each block in the single-read cover.
                for (&blocknum, _cb) in &single.blocks {
                    let Some(mut slot) = BlockVarnode::find_front(blocknum, blocksort) else {
                        continue;
                    };
                    while slot < blocksort.len() {
                        if blocksort[slot].block_index != blocknum {
                            break;
                        }
                        let vn2_arc = blocksort[slot].vn.clone();
                        slot += 1;
                        if Arc::ptr_eq(&vn2_arc, vn) {
                            continue;
                        }
                        // boundtype = single.containVarnodeDef(vn2)
                        let (blk2, ord2, is_in2) = varnode_def_loc(&vn2_arc.read().unwrap());
                        let boundtype = single.contain_varnode_def_at(is_in2, blk2, ord2);
                        if boundtype == 0 {
                            continue;
                        }
                        let overlaptype = {
                            let v = vn.read().unwrap();
                            let v2 = vn2_arc.read().unwrap();
                            v.characterize_overlap(&v2)
                        };
                        if overlaptype == 0 {
                            continue; // No storage overlap
                        }
                        if overlaptype == 1 {
                            // Partial overlap: check partialCopyShadow.
                            let off = {
                                let v = vn.read().unwrap();
                                let v2 = vn2_arc.read().unwrap();
                                (v.get_offset() as i64 - v2.get_offset() as i64) as i32
                            };
                            if vn.read().unwrap().partial_copy_shadow(&vn2_arc.read().unwrap(), off) {
                                continue;
                            }
                        }
                        // boundtype==2 / ==3 disambiguation (merge.cc:528-562):
                        // For boundtype==2, resolve same-place definitions by
                        // seqnum order; for boundtype==3 (tail), require
                        // addrforce + INDIRECT linkage. Conservative: treat as
                        // intersection (insertop=true) unless clearly not.
                        // This is a faithful-but-simplified subset; full
                        // disambiguation logic ported below.
                        if boundtype == 2 {
                            // merge.cc:528-541
                            let vn2_def = vn2_arc.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                            let vn_def = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                            let skip = match (vn2_def, vn_def) {
                                (None, None) => {
                                    // Both inputs: arbitrary order. Ghidra: if (vn < vn2) continue;
                                    // Compare by Arc pointer value as usize.
                                    (std::sync::Arc::as_ptr(vn) as usize)
                                        < (std::sync::Arc::as_ptr(&vn2_arc) as usize)
                                }
                                (None, Some(_)) => true,  // vn2 has no def, vn does → skip
                                (Some(_), None) => false,
                                (Some(d2), Some(d1)) => {
                                    d2.read().unwrap().get_seq_num().order
                                        < d1.read().unwrap().get_seq_num().order
                                }
                            };
                            if skip {
                                continue;
                            }
                        } else if boundtype == 3 {
                            // merge.cc:543-562
                            let v2 = vn2_arc.read().unwrap();
                            if !v2.is_addr_force() {
                                continue;
                            }
                            // Conservative: skip the full INDIRECT-linkage check;
                            // treat as intersection (insertop=true below).
                            drop(v2);
                        }
                        insertop = true;
                        break;
                    }
                    if insertop {
                        break;
                    }
                }
                if insertop {
                    marked.push(op_ref.clone());
                }
            }
            marked
        };
        self.snip_reads(fd, vn, &marked_ops);
    }

    // Ghidra: merge.cc:581 Merge::unifyAddress
    /// Make sure all Varnodes with the same storage address and size can be
    /// merged. Any discovered intersection is snipped.
    /// Faithful to `Merge::unifyAddress` (merge.cc:581-601).
    fn unify_address(&mut self, fd: &mut Funcdata, group: &[Arc<RwLock<Varnode>>]) {
        // Build blocksort: BlockVarnode per non-free vn, sorted by block index.
        let mut blocksort: Vec<BlockVarnode> =
            group.iter().map(|a| BlockVarnode::set(a.clone())).collect();
        blocksort.sort();
        // eliminateIntersect for each vn in the group.
        let vns: Vec<Arc<RwLock<Varnode>>> = group.to_vec();
        for vn in &vns {
            self.eliminate_intersect(fd, vn, &blocksort);
        }
    }

    // Ghidra: merge.cc:692 Merge::trimOpInput
    /// Trim the input HighVariable of the given op so its Cover is tiny.
    /// Faithful to `Merge::trimOpInput` (merge.cc:692-712). Inserts a COPY
    /// (via allocateCopyTrim → fills copy_trims) before the op, replacing the
    /// slot input with the COPY's output.
    fn trim_op_input(&mut self, fd: &mut Funcdata, op: &crate::op::PcodeOpRef, slot: usize) {
        use crate::opcodes::OpCode;
        // Determine pc (merge.cc:699-704).
        let (pc, multiequal_in_block) = {
            let o = op.0.read().unwrap();
            if o.opcode == OpCode::CPUI_MULTIEQUAL {
                // pc = parent->getIn(slot)->getStop()
                let in_block = o.parent.as_ref().and_then(|w| w.upgrade()).and_then(|parent| {
                    let p = parent.read().unwrap();
                    p.get_in(slot).and_then(|e| Some(e.point.clone()))
                });
                match &in_block {
                    Some(blk) => {
                        let rg = blk.read().unwrap();
                        match rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                            Some(bb) => (bb.get_stop_addr(), Some(blk.clone())),
                            None => (crate::address::Address::new(0), Some(blk.clone())),
                        }
                    }
                    None => (o.get_addr(), None),
                }
            } else {
                (o.get_addr(), None)
            }
        };
        let vn = {
            let o = op.0.read().unwrap();
            o.inrefs.get(slot).cloned()
        };
        let Some(vn) = vn else { return };
        let copyop = self.allocate_copy_trim(fd, &vn, pc, op);
        let copy_out = copyop.0.read().unwrap().output.clone();
        let Some(copy_out) = copy_out else { return };
        fd.op_set_input(op, copy_out, slot);
        if let Some(blk) = multiequal_in_block {
            fd.op_insert_end(&copyop, &blk);
        } else {
            fd.op_insert_before(&copyop, op);
        }
    }

    // Ghidra: merge.cc:656 Merge::trimOpOutput
    /// Trim the output HighVariable of the given op so its Cover is tiny.
    /// Faithful to `Merge::trimOpOutput` (merge.cc:656-682). Moves the op's
    /// output to a stubby unique, then creates a COPY after the op that
    /// reproduces the original output. Does NOT fill copy_trims (uses raw newOp).
    fn trim_op_output(&mut self, fd: &mut Funcdata, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::OpCode;
        // Determine afterop (merge.cc:663-666).
        let after_op = {
            let o = op.0.read().unwrap();
            if o.opcode == OpCode::CPUI_INDIRECT {
                o.get_in(1).and_then(|vn2| fd.get_op_from_const(vn2))
            } else {
                Some(crate::op::PcodeOpRef(op.0.clone()))
            }
        };
        let vn = {
            let o = op.0.read().unwrap();
            o.output.clone()
        };
        let Some(vn) = vn else { return };
        let op_addr = op.0.read().unwrap().get_addr();
        let copyop = fd.new_op(1, op_addr);
        fd.op_set_opcode(&copyop, OpCode::CPUI_COPY);
        let uniq = fd.new_unique(vn.read().unwrap().size);
        // op output → uniq; copyop output → original vn; copyop input → uniq.
        fd.op_set_output(op, uniq.clone());
        fd.op_set_output(&copyop, vn);
        fd.op_set_input(&copyop, uniq, 0);
        if let Some(ao) = &after_op {
            fd.op_insert_after(&copyop, ao);
        }
    }

    // Ghidra: merge.cc:719 Merge::mergeOp
    /// Force-merge all input and output Varnodes for the given op.
    /// Faithful to `Merge::mergeOp` (merge.cc:719-772). Snips data-flow via
    /// trimOpInput/trimOpOutput until cover restrictions are resolved, then
    /// force-merges.
    fn merge_op(&mut self, fd: &mut Funcdata, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::OpCode;
        let (max, high_out, inputs) = {
            let o = op.0.read().unwrap();
            let max = if o.opcode == OpCode::CPUI_INDIRECT { 1 } else { o.num_input() };
            let out_vn = o.output.clone();
            let ins: Vec<Arc<RwLock<Varnode>>> = o.inrefs.iter().cloned().collect();
            (max, out_vn, ins)
        };
        let Some(out_vn) = high_out else { return };
        let high_out_arc = out_vn.read().unwrap().high.clone();
        let Some(high_out_arc) = high_out_arc else { return };

        // Phase 1: non-cover mergeTestRequired restrictions (merge.cc:730-741).
        for i in 0..max {
            let high_in = inputs.get(i).and_then(|v| v.read().unwrap().high.clone());
            let Some(high_in) = high_in else { continue };
            if !self.merge_test_required(&high_out_arc, &high_in) {
                self.trim_op_input(fd, op, i);
                continue;
            }
            // Check against earlier inputs (merge.cc:736-740).
            let mut conflict = false;
            for j in 0..i {
                let high_j = inputs.get(j).and_then(|v| v.read().unwrap().high.clone());
                if let Some(hj) = high_j {
                    if !self.merge_test_required(&hj, &high_in) {
                        conflict = true;
                        break;
                    }
                }
            }
            if conflict {
                self.trim_op_input(fd, op, i);
            }
        }

        // Phase 2: cover restriction test (merge.cc:743-761).
        // Re-read inputs (may have changed after trims).
        let inputs2: Vec<Arc<RwLock<Varnode>>> = op.0.read().unwrap().inrefs.iter().cloned().collect();
        let high_out_arc2 = out_vn.read().unwrap().high.clone();
        if let Some(ho) = high_out_arc2 {
            let mut testlist: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
            self.merge_test_with_list(&ho, &mut testlist);
            let mut i = 0;
            for inp in inputs2.iter().take(max) {
                let high_in = inp.read().unwrap().high.clone();
                match high_in {
                    Some(hi) => {
                        if !self.merge_test_with_list(&hi, &mut testlist) {
                            break;
                        }
                    }
                    None => break,
                }
                i += 1;
            }
            if i != max {
                // Cover restrictions: iteratively trim inputs.
                let mut nexttrim = 0;
                while nexttrim < max {
                    self.trim_op_input(fd, op, nexttrim);
                    testlist.clear();
                    self.merge_test_with_list(&ho, &mut testlist);
                    let mut all_ok = true;
                    for k in 0..max {
                        let inp_k = op.0.read().unwrap().inrefs.get(k).cloned();
                        match inp_k {
                            Some(vn) => {
                                let hi = vn.read().unwrap().high.clone();
                                match hi {
                                    Some(h) => {
                                        if !self.merge_test_with_list(&h, &mut testlist) {
                                            all_ok = false;
                                        }
                                    }
                                    None => {}
                                }
                            }
                            None => {}
                        }
                    }
                    if all_ok {
                        break;
                    }
                    nexttrim += 1;
                }
                if nexttrim == max {
                    self.trim_op_output(fd, op);
                }
            }
        }

        // Phase 3: real merge (merge.cc:763-771).
        for i in 0..max {
            let (ho, hi) = {
                let o = op.0.read().unwrap();
                let out = o.output.as_ref().and_then(|v| v.read().unwrap().high.clone());
                let inp = o.inrefs.get(i).and_then(|v| v.read().unwrap().high.clone());
                (out, inp)
            };
            match (ho, hi) {
                (Some(ho_arc), Some(hi_arc)) => {
                    if !self.merge_test_required(&ho_arc, &hi_arc) {
                        eprintln!("[MERGE] non-cover restriction violated despite trims");
                        continue;
                    }
                    // merge(high_out, high_in, false) — cover intersect → skip.
                    let _ = self.merge_speculative(&ho_arc, &hi_arc);
                }
                _ => {}
            }
        }
    }

    // Ghidra: merge.cc:783 Merge::collectInputs
    /// Collect Varnode instances of `high` that are inputs to `op` or its
    /// predecessor chain (across INDIRECTs). Faithful to `Merge::collectInputs`
    /// (merge.cc:783-809). Used by snip_output_interference.
    fn collect_inputs(
        &self,
        fd: &Funcdata,
        high: &Arc<RwLock<HighVariable>>,
        op: &crate::op::PcodeOpRef,
    ) -> Vec<crate::op::PcodeOpRef> {
        let _ = fd;
        let mut oplist = Vec::new();
        // Ghidra walks previousOp chain. Simplified: just check op's inputs.
        let o = op.0.read().unwrap();
        for in_vn in &o.inrefs {
            let in_high = in_vn.read().unwrap().high.clone();
            if let Some(ih) = in_high {
                if Arc::ptr_eq(&ih, high) {
                    oplist.push(crate::op::PcodeOpRef(op.0.clone()));
                    break;
                }
            }
        }
        oplist
    }

    // Ghidra: merge.cc:811 Merge::snipOutputInterference
    /// Check if INDIRECT op's output interferes with inputs of the op causing
    /// the effect, and snip if so. Faithful to `Merge::snipOutputInterference`
    /// (merge.cc:811-844). Simplified: if interference detected, trimOpOutput.
    fn snip_output_interference(&mut self, fd: &mut Funcdata, indop: &crate::op::PcodeOpRef) -> bool {
        let out_high = {
            let o = indop.0.read().unwrap();
            o.output.as_ref().and_then(|v| v.read().unwrap().high.clone())
        };
        let Some(out_high) = out_high else { return false };
        // Get the op causing the INDIRECT effect (in(1) via getOpFromConst).
        let effect_op = {
            let o = indop.0.read().unwrap();
            o.get_in(1).and_then(|vn| fd.get_op_from_const(vn))
        };
        if let Some(eff) = effect_op {
            let inputs = self.collect_inputs(fd, &out_high, &eff);
            if !inputs.is_empty() {
                // Interference: the INDIRECT output's high is also an input to
                // the effect op. Trim the output to resolve.
                self.trim_op_output(fd, indop);
                return true;
            }
        }
        false
    }

    // Ghidra: merge.cc:846 Merge::mergeIndirect
    /// Force-merge the input and output of an INDIRECT op. Faithful to
    /// `Merge::mergeIndirect` (merge.cc:846-887). Checks for output
    /// interference (snipOutputInterference) then delegates to mergeOp logic.
    fn merge_indirect(&mut self, fd: &mut Funcdata, indop: &crate::op::PcodeOpRef) {
        // Ghidra: snipOutputInterference first (merge.cc:862).
        self.snip_output_interference(fd, indop);
        // Then mergeOp (handles input[0] with output).
        self.merge_op(fd, indop);
    }

    // Ghidra: merge.cc:1045 Merge::compareCopyByInVarnode
    /// Sort comparator for COPY ops: by input Varnode (create index), then
    /// by parent block index, then by seqnum order. Faithful to
    /// `Merge::compareCopyByInVarnode` (merge.cc:1045-1057).
    fn compare_copy_by_in_varnode(
        op1: &crate::op::PcodeOpRef,
        op2: &crate::op::PcodeOpRef,
    ) -> std::cmp::Ordering {
        let (in1_ci, in2_ci, idx1, idx2, ord1, ord2) = {
            let a = op1.0.read().unwrap();
            let b = op2.0.read().unwrap();
            let in1 = a.get_in(0).map(|v| v.read().unwrap().create_index).unwrap_or(0);
            let in2 = b.get_in(0).map(|v| v.read().unwrap().create_index).unwrap_or(0);
            let i1 = a.parent.as_ref().and_then(|w| w.upgrade()).map(|p| p.read().unwrap().get_index()).unwrap_or(0);
            let i2 = b.parent.as_ref().and_then(|w| w.upgrade()).map(|p| p.read().unwrap().get_index()).unwrap_or(0);
            (in1, in2, i1, i2, a.get_seq_num().order, b.get_seq_num().order)
        };
        in1_ci.cmp(&in2_ci)
            .then_with(|| idx1.cmp(&idx2))
            .then_with(|| ord1.cmp(&ord2))
    }

    // Ghidra: merge.cc:1295 Merge::findAllIntoCopies
    /// Collect all COPY ops whose output is an instance of `high` and whose
    /// input comes from a different HighVariable. Faithful to
    /// `Merge::findAllIntoCopies` (merge.cc:1295-1309). If `filter_temps`,
    /// only COPYs whose output is in the internal (unique) space are kept.
    /// Result is sorted by `compare_copy_by_in_varnode`.
    fn find_all_into_copies(
        &self,
        high: &Arc<RwLock<HighVariable>>,
        filter_temps: bool,
    ) -> Vec<crate::op::PcodeOpRef> {
        let h = high.read().unwrap();
        let n = h.num_instances();
        let mut copy_ins: Vec<crate::op::PcodeOpRef> = Vec::new();
        for i in 0..n {
            let vn_arc = match h.get_instance(i) { Some(a) => a, None => continue };
            let (is_written, def_code_copy, in_high_diff, out_is_unique) = {
                let vn = vn_arc.read().unwrap();
                let def_arc = vn.def.as_ref().and_then(|w| w.upgrade());
                match def_arc {
                    Some(d) => {
                        let def = d.read().unwrap();
                        let code_copy = def.opcode == crate::opcodes::OpCode::CPUI_COPY;
                        let in_high_diff = def.get_in(0).map(|inv| {
                            let inv_h = inv.read().unwrap().high.clone();
                            match inv_h {
                                Some(ih) => !Arc::ptr_eq(&ih, high),
                                None => true,
                            }
                        }).unwrap_or(true);
                        let out_unique = vn.address_space == crate::space::AddressSpace::Unique;
                        (true, code_copy, in_high_diff, out_unique)
                    }
                    None => (false, false, true, false),
                }
            };
            if !is_written || !def_code_copy || !in_high_diff {
                continue;
            }
            if filter_temps && !out_is_unique {
                continue;
            }
            // Get the def op as PcodeOpRef.
            let def_arc = vn_arc.read().unwrap().def.as_ref().and_then(|w| w.upgrade()).unwrap();
            copy_ins.push(crate::op::PcodeOpRef(def_arc));
        }
        drop(h);
        copy_ins.sort_by(Self::compare_copy_by_in_varnode);
        copy_ins
    }

    // Ghidra: merge.cc:1151 Merge::buildDominantCopy
    /// Replace a group of COPYs (from the same source) with a single dominant
    /// COPY at the common dominator block. Faithful to `buildDominantCopy`
    /// (merge.cc:1151-1238). Union-resolution path (:1170-1178) omitted.
    ///
    /// `high`: target HighVariable. `copy`: sorted COPY list. `pos`/`size`:
    /// the group of COPYs sharing the same input Varnode.
    fn build_dominant_copy(
        &mut self,
        fd: &mut Funcdata,
        high: &Arc<RwLock<HighVariable>>,
        copy: &[crate::op::PcodeOpRef],
        pos: usize,
        size: usize,
    ) {
        // Collect parent blocks of the COPY group.
        let block_set: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = (0..size)
            .filter_map(|i| {
                let op = copy[pos + i].0.read().unwrap();
                op.parent.as_ref().and_then(|w| w.upgrade())
            })
            .collect();
        let Some(dom_bl) = crate::block::BlockGraph::find_common_block_n(&block_set) else {
            return;
        };
        let dom_bl_bb = dom_bl.read().unwrap();
        let dom_bl_any = dom_bl_bb.as_any().downcast_ref::<crate::block::BlockBasic>();
        // domCopy = copy[pos]; rootVn = domCopy->getIn(0); domVn = domCopy->getOut()
        let (root_vn, dom_copy_out, dom_copy_parent_ptr) = {
            let dc = copy[pos].0.read().unwrap();
            let rv = dc.get_in(0).cloned();
            let dv = dc.output.clone();
            let dp = dc.parent.as_ref().and_then(|w| w.upgrade());
            (rv, dv, dp)
        };
        let Some(root_vn) = root_vn else { return };
        // Determine if domCopy is already in domBl.
        let dom_in_dombl = match (&dom_copy_parent_ptr, dom_bl_any) {
            (Some(p), _) => Arc::ptr_eq(p, &dom_bl),
            _ => false,
        };
        drop(dom_bl_bb);
        let mut dom_copy_is_new = false;
        let mut dom_vn = dom_copy_out;
        let mut new_dom_copy: Option<crate::op::PcodeOpRef> = None;
        if !dom_in_dombl {
            // Build a new COPY at domBl (merge.cc:1167-1183).
            dom_copy_is_new = true;
            let stop_addr = {
                let rg = dom_bl.read().unwrap();
                match rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    Some(bb) => bb.get_stop_addr(),
                    None => crate::address::Address::new(0),
                }
            };
            let new_op = fd.new_op(1, stop_addr);
            fd.op_set_opcode(&new_op, crate::opcodes::OpCode::CPUI_COPY);
            let sz = root_vn.read().unwrap().size;
            let uv = fd.new_unique(sz);
            fd.op_set_output(&new_op, uv.clone());
            fd.op_set_input(&new_op, root_vn.clone(), 0);
            fd.op_insert_end(&new_op, &dom_bl);
            dom_vn = Some(uv);
            new_dom_copy = Some(new_op);
        }
        let Some(dom_vn) = dom_vn else { return };
        // Build bCover = union of high's instances' covers, excluding COPY-from-shadow-of-rootVn.
        let mut b_cover = Cover::new();
        {
            let h = high.read().unwrap();
            for i in 0..h.num_instances() {
                let Some(vn_arc) = h.get_instance(i) else { continue };
                let skip = {
                    let vn = vn_arc.read().unwrap();
                    let def_arc = vn.def.as_ref().and_then(|w| w.upgrade());
                    match def_arc {
                        Some(d) => {
                            let def = d.read().unwrap();
                            if def.opcode == crate::opcodes::OpCode::CPUI_COPY {
                                let in0 = def.get_in(0);
                                match in0 {
                                    Some(inv) => inv.read().unwrap().copy_shadow(&root_vn.read().unwrap()),
                                    None => false,
                                }
                            } else { false }
                        }
                        None => false,
                    }
                };
                if skip { continue; }
                let vn = vn_arc.read().unwrap();
                if let Some(c) = &vn.cover {
                    b_cover.merge(c);
                }
            }
        }
        // For each non-dom COPY, check if removable (aCover vs bCover).
        // Mark un-removable ones (Ghidra uses op->setMark).
        let mut marked: Vec<bool> = vec![false; size];
        let mut count = size as i32;
        for i in 0..size {
            let is_dom = match &new_dom_copy {
                Some(nd) => Arc::ptr_eq(&nd.0, &copy[pos + i].0),
                None => i == 0, // copy[pos] is the domCopy when not new
            };
            if is_dom { continue; }
            let (out_vn_arc, descends) = {
                let op = copy[pos + i].0.read().unwrap();
                let ov = op.output.clone();
                let ds: Vec<crate::op::PcodeOpRef> = if let Some(ref ova) = ov {
                    ova.read().unwrap().descend.iter()
                        .filter_map(|w| w.upgrade())
                        .map(|a| crate::op::PcodeOpRef(a))
                        .collect()
                } else { Vec::new() };
                (ov, ds)
            };
            let Some(out_vn_arc) = out_vn_arc else { continue };
            // aCover: addDefPoint(domVn) + addRefPoint(each reader of outVn).
            let mut a_cover = Cover::new();
            // domVn def loc:
            let (dvn_blk, dvn_ord, dvn_is_input) = varnode_def_loc(&dom_vn.read().unwrap());
            if dvn_is_input {
                a_cover.add_def_point(0, 2);
            } else {
                a_cover.add_def_point(dvn_blk, dvn_ord);
            }
            for d_ref in &descends {
                let (rb, ro) = {
                    let op = d_ref.0.read().unwrap();
                    let blk = op.parent.as_ref().and_then(|w| w.upgrade()).map(|p| p.read().unwrap().get_index()).unwrap_or(0);
                    (blk, op.get_seq_num().order)
                };
                a_cover.add_ref_point(rb, ro);
            }
            if b_cover.intersect_char(&a_cover) > 1 {
                count -= 1;
                marked[i] = true;
            }
        }
        // If count <= 1, mark all to skip (and destroy new domCopy if new).
        if count <= 1 {
            for i in 0..size { marked[i] = true; }
            count = 0;
            if dom_copy_is_new {
                if let Some(nd) = &new_dom_copy {
                    fd.op_destroy(nd);
                }
            }
        }
        // Replace non-marked COPYs: totalReplace(outVn, domVn) + opDestroy.
        for i in 0..size {
            if marked[i] { continue; }
            let (out_vn_arc, op_ref) = {
                let op = copy[pos + i].0.read().unwrap();
                (op.output.clone(), crate::op::PcodeOpRef(copy[pos + i].0.clone()))
            };
            if let Some(out_vn) = out_vn_arc {
                // Skip if outVn == domVn.
                let same = Arc::ptr_eq(&out_vn, &dom_vn);
                if !same {
                    // outVn->getHigh()->remove(outVn)
                    let h_idx = out_vn.read().unwrap().high.as_ref().and_then(|h| {
                        h.read().unwrap().instance_index(&out_vn)
                    });
                    if let Some(idx) = h_idx {
                        out_vn.read().unwrap().high.as_ref().unwrap().write().unwrap().remove_instance(idx);
                    }
                    fd.total_replace(&out_vn, dom_vn.clone());
                    fd.op_destroy(&op_ref);
                }
            }
        }
        // If count > 0 and domCopy is new, merge domVn's high into target.
        if count > 0 && dom_copy_is_new {
            let dom_high = dom_vn.read().unwrap().high.clone();
            if let Some(dh) = dom_high {
                // high->merge(domVn->getHigh(), nullptr, true)
                // Use merge_speculative (cover-aware); domVn is a fresh temp.
                let _ = self.merge_speculative(high, &dh);
            }
        }
    }

    // Ghidra: merge.cc:1316 Merge::processHighDominantCopy
    /// For the given HighVariable, find groups of COPYs from the same source
    /// and replace each group with a single dominant COPY. Faithful to
    /// `processHighDominantCopy` (merge.cc:1316-1337).
    fn process_high_dominant_copy(&mut self, fd: &mut Funcdata, high: &Arc<RwLock<HighVariable>>) {
        let copy_ins = self.find_all_into_copies(high, true);
        if copy_ins.len() < 2 {
            return;
        }
        // Group by identical input Varnode (Arc ptr eq), call buildDominantCopy.
        let mut pos = 0usize;
        while pos < copy_ins.len() {
            let in_vn = {
                let op = copy_ins[pos].0.read().unwrap();
                op.get_in(0).cloned()
            };
            let Some(in_vn) = in_vn else { break; };
            let mut sz = 1usize;
            while pos + sz < copy_ins.len() {
                let next_in = {
                    let op = copy_ins[pos + sz].0.read().unwrap();
                    op.get_in(0).cloned()
                };
                match next_in {
                    Some(ni) if Arc::ptr_eq(&ni, &in_vn) => sz += 1,
                    _ => break,
                }
            }
            if sz > 1 {
                self.build_dominant_copy(fd, high, &copy_ins, pos, sz);
            }
            pos += sz;
        }
    }

    // Ghidra: merge.cc:1415 Merge::processCopyTrims
    /// Step 6: ActionDominantCopy (coreaction.cc:5723 / coreaction.hh:1008).
    /// Faithful to `Merge::processCopyTrims` (merge.cc:1415-1436).
    ///
    /// Walks the `copyTrims` list — COPY ops inserted by the earlier snip
    /// trims (`allocateCopyTrim`/`snipReads`, merge.cc:411,443) — to find
    /// HighVariables that received ≥ 2 such COPYs and calls
    /// `processHighDominantCopy(high)` to replace them with a single
    /// dominant COPY.
    ///
    /// **INFRASTRUCTURE GAP**: Rugra has no snip/trim data-flow rewrite
    /// machinery. `copyTrims` is never populated (the forced-merge path in
    /// ActionMergeRequired — mergeAddrTied/mergeMarker → unifyAddress →
    /// eliminateIntersect → snipReads → allocateCopyTrim — is not ported).
    /// Therefore this method is a faithful no-op: the list is empty, so
    /// nothing happens. To make it functional, port the snip/trim subsystem
    /// (snipReads/eliminateIntersect/allocateCopyTrim + the forced-merge
    /// callers in merge_addr_tied/merge_marker). Now ported (2026-07-04):
    /// unify_address/eliminate_intersect/snip_reads/allocate_copy_trim are
    /// wired into merge_addr_tied, so copy_trims is populated.
    ///
    /// This implementation walks copy_trims and counts COPYs per output High
    /// (faithful to merge.cc:1420-1434). The dominant-copy replacement
    /// (processHighDominantCopy, merge.cc:1316) is NOT yet ported — it
    /// requires findAllIntoCopies/buildDominantCopy. copy_trims is cleared
    /// after counting (faithful to merge.cc:1429).
    pub fn process_copy_trims(&mut self, fd: &mut Funcdata) {
        if self.copy_trims.is_empty() {
            return;
        }
        // Ghidra merge.cc:1420-1428: count COPYs into each output HighVariable.
        // Ghidra uses copy_in1/copy_in2 flags; we use a map keyed by HighVariable Arc ptr.
        let mut counts: std::collections::HashMap<
            usize,
            (Arc<RwLock<HighVariable>>, u32),
        > = std::collections::HashMap::new();
        for trim in &self.copy_trims {
            let out_high = {
                let t = trim.0.read().unwrap();
                t.output.as_ref().and_then(|o| {
                    let ov = o.read().unwrap();
                    ov.high.clone().map(|h| (std::sync::Arc::as_ptr(&h) as *const () as usize, h))
                })
            };
            if let Some((key, h)) = out_high {
                counts.entry(key).or_insert_with(|| (h, 0)).1 += 1;
            }
        }
        // Ghidra merge.cc:1430-1434: for each high with ≥2 COPYs, call processHighDominantCopy.
        let multi: Vec<Arc<RwLock<HighVariable>>> = counts
            .into_iter()
            .filter_map(|(_, (h, c))| if c >= 2 { Some(h) } else { None })
            .collect();
        for high in &multi {
            // Ghidra: high->hasCopyIn2() → processHighDominantCopy(high) (merge.cc:1432)
            self.process_high_dominant_copy(fd, high);
        }
        // Ghidra merge.cc:1429: copyTrims.clear()
        self.copy_trims.clear();
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
            self.merge_linear(&group);
        }
    }

    // Ghidra: merge.hh:110 Merge::mergeLinear
    /// Speculatively merge a list of same-type HighVariables as well as
    /// possible. Faithful to `Merge::mergeLinear` (merge.cc:272-292).
    ///
    /// Each HighVariable is merged with the first "stacked" HighVariable
    /// whose cover it does not intersect; if none is compatible it starts a
    /// new stack group. After a successful merge, the stacked head's cover
    /// snapshot is refreshed so subsequent tests reflect the union.
    fn merge_linear(&mut self, highvec: &[Arc<RwLock<HighVariable>>]) {
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


    // Ghidra: merge.cc:1070 Merge::hideShadows
    /// Hide shadow varnodes for a single HighVariable by redirecting COPY
    /// inputs. Faithful to `Merge::hideShadows(high)` (merge.cc:1070-1100).
    /// Returns true if any data-flow rewrite was applied.
    ///
    /// For the given HighVariable, find instance Varnodes defined by a COPY
    /// from *outside* the HighVariable. If two are copyShadow of each other
    /// and one's cover contains the other's def, redirect the COPY input
    /// (opSetInput) — consolidating the shadow chain.
    pub fn hide_shadows_of(&mut self, fd: &mut Funcdata, high: &Arc<RwLock<HighVariable>>) -> bool {
        let mut changed = false;
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
                return false;
            }
            // hideShadows pairs: for vn1,vn2 that are copyShadow of each
            // other, redirect one COPY's input to the other.
            // Faithful to merge.cc:1080-1098.
            let mut null_mask: Vec<bool> = vec![false; singlelist.len()];
            for i in 0..singlelist.len().saturating_sub(1) {
                if null_mask[i] {
                    continue;
                }
                let vn1 = &singlelist[i];
                for j in (i + 1)..singlelist.len() {
                    if null_mask[j] {
                        continue;
                    }
                    let vn2 = &singlelist[j];
                    // vn1->copyShadow(vn2) (merge.cc:1086)
                    let is_shadow = {
                        let v1 = vn1.read().unwrap();
                        let v2 = vn2.read().unwrap();
                        v1.copy_shadow(&v2)
                    };
                    if !is_shadow {
                        continue;
                    }
                    // vn2->getCover()->containVarnodeDef(vn1)==1 (merge.cc:1087)
                    let (v1_blk, v1_ord, v1_is_input) = varnode_def_loc(&vn1.read().unwrap());
                    let vn2_covers_vn1 = vn2.read().unwrap()
                        .cover.as_ref().map(|c| c.contain_varnode_def_at(v1_is_input, v1_blk, v1_ord) == 1)
                        .unwrap_or(false);
                    if vn2_covers_vn1 {
                        // data.opSetInput(vn1->getDef(), vn2, 0) (merge.cc:1088)
                        let vn1_def = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                        if let Some(def_op) = vn1_def {
                            fd.op_set_input(&crate::op::PcodeOpRef(def_op), vn2.clone(), 0);
                            changed = true;
                        }
                        break;
                    }
                    // vn1->getCover()->containVarnodeDef(vn2)==1 (merge.cc:1092)
                    let (v2_blk, v2_ord, v2_is_input) = varnode_def_loc(&vn2.read().unwrap());
                    let vn1_covers_vn2 = vn1.read().unwrap()
                        .cover.as_ref().map(|c| c.contain_varnode_def_at(v2_is_input, v2_blk, v2_ord) == 1)
                        .unwrap_or(false);
                    if vn1_covers_vn2 {
                        // data.opSetInput(vn2->getDef(), vn1, 0) (merge.cc:1093)
                        let vn2_def = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                        if let Some(def_op) = vn2_def {
                            fd.op_set_input(&crate::op::PcodeOpRef(def_op), vn1.clone(), 0);
                            changed = true;
                        }
                        null_mask[j] = true; // singlelist[j] = null (merge.cc:1094)
                    }
                }
            }
        changed
    }

    // RUGRA-GLUE: 遍历所有 HighVariable 调 hide_shadows_of。Ghidra 在
    // ActionHideShadow::apply (coreaction.cc:4831) 内联此遍历；Rugra 的
    // merge_all 也调用此方法，故提取为函数。
    /// Iterate all HighVariables and apply hide_shadows_of to each.
    /// Used by merge_all (Ghidra's ActionHideShadow does this via its own
    /// apply calling hideShadows per high).
    pub fn hide_shadows(&mut self, fd: &mut Funcdata) {
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
            self.hide_shadows_of(fd, &high);
        }
    }

    // Ghidra: merge.cc:1271 Merge::shadowedVarnode
    /// Determine if the given Varnode is shadowed by another Varnode in the
    /// same HighVariable. Faithful to `Merge::shadowedVarnode` (merge.cc:1271-1285).
    /// Returns true if any other instance's cover fully intersects (==2) vn's cover.
    fn shadowed_varnode(&self, vn: &Arc<RwLock<Varnode>>) -> bool {
        let high = vn.read().unwrap().high.clone();
        let Some(high) = high else { return false };
        let vn_cover = match &vn.read().unwrap().cover {
            Some(c) => c.clone(),
            None => return false,
        };
        let h = high.read().unwrap();
        for inst in &h.instances {
            if Arc::ptr_eq(inst, vn) {
                continue;
            }
            if let Some(ic) = &inst.read().unwrap().cover {
                if vn_cover.intersect_char(ic) == 2 {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: merge.cc:1112 Merge::checkCopyPair
    /// Check if the given COPY PcodeOps are redundant. Faithful to
    /// `Merge::checkCopyPair` (merge.cc:1112-1136). domOp must dominate subOp's
    /// block; constructs a range cover and checks for intervening writes.
    fn check_copy_pair(
        &self,
        high: &Arc<RwLock<HighVariable>>,
        dom_op: &crate::op::PcodeOpRef,
        sub_op: &crate::op::PcodeOpRef,
    ) -> bool {
        // domBlock->dominates(subBlock) (merge.cc:1117)
        let (dom_blk, sub_blk) = {
            let d = dom_op.0.read().unwrap();
            let s = sub_op.0.read().unwrap();
            let db = d.parent.as_ref().and_then(|w| w.upgrade());
            let sb = s.parent.as_ref().and_then(|w| w.upgrade());
            (db, sb)
        };
        match (&dom_blk, &sub_blk) {
            (Some(db), Some(sb)) => {
                // Check db dominates sb (db is ancestor in dom tree).
                if !db.read().unwrap().dominates(sb) {
                    return false;
                }
            }
            _ => return false,
        }
        // Build range cover: addDefPoint(domOp->getOut()) + addRefPoint(subOp, subOp->getIn(0)).
        let (dom_out, sub_in0, in_vn) = {
            let d = dom_op.0.read().unwrap();
            let s = sub_op.0.read().unwrap();
            (d.output.clone(), s.inrefs.get(0).cloned(), d.inrefs.get(0).cloned())
        };
        let mut range = Cover::new();
        if let Some(dov) = &dom_out {
            let (blk, ord, is_input) = varnode_def_loc(&dov.read().unwrap());
            if is_input {
                range.add_def_point(0, 2);
            } else {
                range.add_def_point(blk, ord);
            }
        }
        if let Some(siv) = &sub_in0 {
            // addRefPoint: sub_op reads sub_in0 at sub_op's loc.
            let (s_blk, s_ord) = {
                let s = sub_op.0.read().unwrap();
                let blk = s.parent.as_ref().and_then(|w| w.upgrade())
                    .map(|p| p.read().unwrap().get_index()).unwrap_or(0);
                (blk, s.get_seq_num().order)
            };
            range.add_ref_point(s_blk, s_ord);
        }
        // Look for high instances with intervening writes (merge.cc:1124-1134).
        let h = high.read().unwrap();
        for i in 0..h.num_instances() {
            let Some(inst) = h.get_instance(i) else { continue };
            let (written, def_code_copy, def_in_eq_invn, def_blk, def_ord) = {
                let vn = inst.read().unwrap();
                let def_arc = vn.def.as_ref().and_then(|w| w.upgrade());
                match def_arc {
                    Some(d) => {
                        let def = d.read().unwrap();
                        let cc = def.opcode == crate::opcodes::OpCode::CPUI_COPY;
                        let eq = def.inrefs.get(0).map(|v| {
                            match &in_vn {
                                Some(iv) => Arc::ptr_eq(v, iv),
                                None => false,
                            }
                        }).unwrap_or(false);
                        let blk = def.parent.as_ref().and_then(|w| w.upgrade())
                            .map(|p| p.read().unwrap().get_index()).unwrap_or(0);
                        (true, cc, eq, blk, def.get_seq_num().order)
                    }
                    None => (false, false, false, 0, 0),
                }
            };
            if !written {
                continue;
            }
            // If write is COPY from same Varnode as domOp → skip (merge.cc:1128-1130).
            if def_code_copy && def_in_eq_invn {
                continue;
            }
            // range.contain(op, 1) — check if def is in range (merge.cc:1131).
            if range.contain(def_blk, def_ord) {
                return false; // Intervening write → not redundant.
            }
        }
        true
    }

    // Ghidra: merge.cc:1249 Merge::markRedundantCopies
    /// Mark redundant COPY ops as non-printing. Faithful to
    /// `Merge::markRedundantCopies` (merge.cc:1249-1265).
    fn mark_redundant_copies(
        &mut self,
        fd: &mut Funcdata,
        high: &Arc<RwLock<HighVariable>>,
        copy: &[crate::op::PcodeOpRef],
        pos: usize,
        size: usize,
    ) {
        for i in (1..size).rev() {
            let sub_op = &copy[pos + i];
            if sub_op.0.read().unwrap().is_dead() {
                continue;
            }
            for j in (0..i).rev() {
                let dom_op = &copy[pos + j];
                if dom_op.0.read().unwrap().is_dead() {
                    continue;
                }
                if self.check_copy_pair(high, dom_op, sub_op) {
                    fd.op_mark_non_printing(sub_op);
                    break;
                }
            }
        }
    }

    // Ghidra: merge.cc:1345 Merge::processHighRedundantCopy
    /// Mark COPY ops into the given HighVariable that are redundant.
    /// Faithful to `Merge::processHighRedundantCopy` (merge.cc:1345-1367).
    fn process_high_redundant_copy(&mut self, fd: &mut Funcdata, high: &Arc<RwLock<HighVariable>>) {
        let copy_ins = self.find_all_into_copies(high, false);
        if copy_ins.len() < 2 {
            return;
        }
        let mut pos = 0usize;
        while pos < copy_ins.len() {
            let in_vn = copy_ins[pos].0.read().unwrap().inrefs.get(0).cloned();
            let Some(in_vn) = in_vn else { break; };
            let mut sz = 1usize;
            while pos + sz < copy_ins.len() {
                let next = copy_ins[pos + sz].0.read().unwrap().inrefs.get(0).cloned();
                match next {
                    Some(n) if Arc::ptr_eq(&n, &in_vn) => sz += 1,
                    _ => break,
                }
            }
            if sz > 1 {
                self.mark_redundant_copies(fd, high, &copy_ins, pos, sz);
            }
            pos += sz;
        }
    }

    // Ghidra: merge.hh:134 Merge::markInternalCopies
    /// Step 12: ActionCopyMarker (coreaction.hh:1019).
    /// Faithful to `Merge::markInternalCopies` (merge.cc:1444-1542).
    ///
    /// Walks all alive ops:
    /// - COPY: if output.high==input.high → nonprinting; else accumulate
    ///   multi-copy highs + check shadowedVarnode for no-descend outputs.
    /// - PIECE/SUBPIECE: VariablePiece CONCAT reassembly (omitted — no
    ///   VariablePiece infrastructure).
    /// Then processHighRedundantCopy for highs with ≥2 copy-ins.
    pub fn mark_internal_copies(&mut self, fd: &mut Funcdata) {
        use crate::op::pcodeop_flags;
        use crate::opcodes::OpCode;

        // Ghidra merge.cc:1455-1532: iterate alive ops.
        // Collect COPY decisions + track multi-copy highs.
        let mut multi_copy: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
        let mut multi_copy_seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let copy_ops: Vec<crate::op::PcodeOpRef> = fd.obank.alivelist.iter()
            .map(|r| crate::op::PcodeOpRef(r.0.clone()))
            .collect();
        for op_ref in &copy_ops {
            let opcode = op_ref.0.read().unwrap().opcode;
            match opcode {
                OpCode::CPUI_COPY => {
                    let (out_vn, in_vn, same_high, out_high) = {
                        let op = op_ref.0.read().unwrap();
                        let out = op.output.clone();
                        let in0 = op.inrefs.get(0).cloned();
                        let (sh, oh) = match (&out, &in0) {
                            (Some(o), Some(i)) => {
                                let o_rg = o.read().unwrap();
                                let i_rg = i.read().unwrap();
                                let sh = match (&o_rg.high, &i_rg.high) {
                                    (Some(ho), Some(hi)) => Arc::ptr_eq(ho, hi),
                                    _ => false,
                                };
                                (sh, o_rg.high.clone())
                            }
                            _ => (false, None),
                        };
                        (out, in0, sh, oh)
                    };
                    if same_high {
                        // merge.cc:1461-1462: internal COPY → nonprinting.
                        fd.op_mark_non_printing(op_ref);
                    } else if let Some(h1) = out_high {
                        // merge.cc:1465-1470: accumulate multi-copy tracking.
                        let ptr = Arc::as_ptr(&h1) as usize;
                        if !multi_copy_seen.contains(&ptr) {
                            multi_copy_seen.insert(ptr);
                            multi_copy.push(h1.clone());
                        }
                        // merge.cc:1471-1475: shadowed no-descend output → nonprinting.
                        if let Some(ov) = &out_vn {
                            let no_descend = ov.read().unwrap().has_no_descend();
                            if no_descend && self.shadowed_varnode(ov) {
                                fd.op_mark_non_printing(op_ref);
                            }
                        }
                    }
                    let _ = in_vn;
                }
                // PIECE/SUBPIECE: VariablePiece CONCAT reassembly (merge.cc:1478-1528).
                // Omitted — Rugra has no VariablePiece infrastructure.
                _ => {}
            }
        }
        // merge.cc:1533-1538: processHighRedundantCopy for multi-copy highs.
        // Ghidra checks hasCopyIn2 (≥2); we process all in multi_copy (they
        // all had ≥1, and processHighRedundantCopy internally checks ≥2 via
        // findAllIntoCopies + group size).
        for high in &multi_copy {
            self.process_high_redundant_copy(fd, high);
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

/// Represents a varnode within a specific block for merging purposes.
/// Faithful to Ghidra `BlockVarnode` (merge.hh:32-41). Stores a Varnode
/// with the index of the BlockBasic that defines it; if the Varnode has no
/// defining PcodeOp it is assigned index 0.
#[derive(Clone)]
pub struct BlockVarnode {
    /// The varnode reference
    pub vn: Arc<RwLock<Varnode>>,
    /// Index of the block defining this varnode (0 if no def op)
    pub block_index: i32,
}

impl BlockVarnode {
    // Ghidra: merge.cc:24 BlockVarnode::set
    /// Set this as representing the given Varnode, resolving its defining
    /// block index. Faithful to `BlockVarnode::set` (merge.cc:24-33).
    pub fn set(vn: Arc<RwLock<Varnode>>) -> Self {
        let block_index = {
            let v = vn.read().unwrap();
            let def_op = v.def.as_ref().and_then(|w| w.upgrade());
            match def_op {
                Some(op_arc) => {
                    let op = op_arc.read().unwrap();
                    match op.parent.as_ref().and_then(|w| w.upgrade()) {
                        Some(blk) => blk.read().unwrap().get_index(),
                        None => 0,
                    }
                }
                None => 0, // No def op (input varnode) → index 0
            }
        };
        Self { vn, block_index }
    }

    // Ghidra: merge.cc:43 BlockVarnode::findFront
    /// Find the first BlockVarnode defined in the block of the given index.
    /// Faithful to `BlockVarnode::findFront` (merge.cc:43-61) — binary search
    /// on a list sorted by block_index. Returns the list position or None.
    pub fn find_front(blocknum: i32, list: &[BlockVarnode]) -> Option<usize> {
        if list.is_empty() {
            return None;
        }
        let mut min = 0usize;
        let mut max = list.len() - 1;
        while min < max {
            let cur = (min + max) / 2;
            let curblock = list[cur].block_index;
            if curblock >= blocknum {
                max = cur;
            } else {
                min = cur + 1;
            }
        }
        if list[min].block_index == blocknum {
            Some(min)
        } else {
            None
        }
    }
}

// RUGRA-GLUE: trait impls for BlockVarnode ordering — Ghidra uses C++
// operator< (merge.hh:37) comparing by block_index; Rust requires
// PartialEq/Eq/PartialOrd/Ord derives for sort().
impl PartialEq for BlockVarnode {
    // RUGRA-GLUE: Rust trait method for == (Ghidra has no explicit eq).
    fn eq(&self, other: &Self) -> bool {
        self.block_index == other.block_index
    }
}
impl Eq for BlockVarnode {}
impl PartialOrd for BlockVarnode {
    // RUGRA-GLUE: Rust trait method (Ghidra operator< is in Ord::cmp below).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.block_index.cmp(&other.block_index))
    }
}
impl Ord for BlockVarnode {
    // RUGRA-GLUE: corresponds to Ghidra operator< (merge.hh:37) by block_index.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.block_index.cmp(&other.block_index)
    }
}

// RUGRA-GLUE: resolve Varnode→(block,order,is_input) for cover queries.
// Ghidra inlines this via vn->getDef()->getParent()->getIndex() etc.
// (merge.cc:452,519). Extracted as a helper for borrow-safety in Rust.
/// Resolve a Varnode's defining location: (block_index, order, is_input).
/// Used by `eliminate_intersect` to query cover containment. If the Varnode
/// has no defining op (is_input==true), returns (0, _, true).
fn varnode_def_loc(vn: &Varnode) -> (i32, u32, bool) {
    let def_arc = match vn.def.as_ref().and_then(|w| w.upgrade()) {
        Some(a) => a,
        None => return (0, 0, true), // input varnode
    };
    let def = def_arc.read().unwrap();
    let order = def.get_seq_num().order;
    let block = match def.parent.as_ref().and_then(|w| w.upgrade()) {
        Some(blk) => blk.read().unwrap().get_index(),
        None => 0,
    };
    (block, order, false)
}

// RUGRA-GLUE: resolve PcodeOp→(block,order) for cover ref-point queries.
// Ghidra inlines via op->getParent()->getIndex() + SeqNum::getOrder().
/// Resolve a PcodeOp's location: (block_index, order).
fn op_loc(op: &crate::op::PcodeOp) -> (i32, u32) {
    let order = op.get_seq_num().order;
    let block = match op.parent.as_ref().and_then(|w| w.upgrade()) {
        Some(blk) => blk.read().unwrap().get_index(),
        None => 0,
    };
    (block, order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::opcodes::OpCode;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
    use crate::space::AddressSpace;

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

}

