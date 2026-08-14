//! Liveness cover for varnodes
//!
//! Corresponds to Ghidra's `cover.hh`

use std::collections::BTreeMap;
use std::fmt;

/// Range of P-code ops within a single basic block where a varnode is alive
///
/// Corresponds to Ghidra's `CoverBlock` class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverBlock {
    /// Start of liveness (order in SeqNum)
    pub start: u32,
    /// End of liveness (order in SeqNum)
    pub end: u32,
}

impl CoverBlock {
    // Ghidra: cover.hh:75 CoverBlock::new
    /// Create an empty cover block
    pub fn new() -> Self {
        Self {
            start: u32::MAX,
            end: 0,
        }
    }

    // Ghidra: cover.hh:75 CoverBlock::clear
    /// Clear the cover block
    pub fn clear(&mut self) {
        self.start = u32::MAX;
        self.end = 0;
    }

    // Ghidra: cover.hh:75 CoverBlock::setBegin
    /// Set the start of liveness
    pub fn set_begin(&mut self, s: u32) {
        self.start = s;
    }

    // Ghidra: cover.hh:75 CoverBlock::setEnd
    /// Set the end of liveness
    pub fn set_end(&mut self, e: u32) {
        self.end = e;
    }

    // Ghidra: cover.hh:84 CoverBlock::setAll
    /// Mark the entire block as covered. Faithful to `CoverBlock::setAll`
    /// (cover.hh:84-85): Ghidra sets `start=(PcodeOp*)0` (begin-of-block
    /// sentinel) and `stop=(PcodeOp*)1` (end-of-block sentinel). In Rugra's
    /// u32-order model, begin-of-block is order 0 and end-of-block is
    /// `u32::MAX` (the `~((uintm)0)` value returned by `getUIndex` for the
    /// sentinel-1 stop).
    pub fn set_all(&mut self) {
        self.start = 0;
        self.end = u32::MAX;
    }

    // Ghidra: cover.hh:75 CoverBlock::empty
    /// Check if the cover block is empty
    pub fn empty(&self) -> bool {
        self.start > self.end
    }

    // Ghidra: cover.cc:29 CoverBlock::getUIndex
    /// Get the comparison index for a PcodeOp. Faithful to
    /// `CoverBlock::getUIndex` (cover.cc:29-49). PcodeOp objects and
    /// CoverBlock start/stop boundaries have a natural ordering used to tell
    /// if a PcodeOp falls between boundary points and if CoverBlocks
    /// intersect; ordering is determined by comparing the values returned
    /// here.
    ///
    /// Maps the four Ghidra sentinel/boundary encodings to comparable u32:
    ///   - sentinel 0 (begin-of-block)        -> 0
    ///   - sentinel 1 (end-of-block)          -> u32::MAX   (~0)
    ///   - sentinel 2 (function input)        -> 0
    ///   - MULTIEQUAL marker op               -> 0  (very beginning)
    ///   - INDIRECT marker op                 -> order of the op it is indirect
    ///                                            for (decoded via
    ///                                            `PcodeOp::getOpFromConst` on
    ///                                            its iop input)
    ///   - normal op                          -> SeqNum::order
    ///
    /// Rugra's `CoverBlock` stores raw u32 orders directly (rather than
    /// `PcodeOp*` pointers), so the sentinel-to-order translation has already
    /// happened at `set_begin`/`set_end` time. This method is provided as a
    /// bridge so that other modules (Funcdata, merge, varmap) which in Ghidra
    /// call `CoverBlock::getUIndex(op)` can resolve the comparison index for a
    /// live `PcodeOp` without duplicating the marker/sentinel logic.
    pub fn get_u_index(op: &crate::op::PcodeOp) -> u32 {
        // Ghidra: switch(switchval) { case 0: return 0; case 1: return ~0; case 2: return 0; }
        // Rugra stores orders directly; the sentinels are inlined into the
        // stored u32 values at insertion time, so for a live PcodeOp we only
        // need to handle the marker case (MULTIEQUAL / INDIRECT).
        if op.is_marker() {
            match op.get_opcode() {
                // Ghidra: MULTIEQUALs are considered very beginning
                crate::opcodes::OpCode::CPUI_MULTIEQUAL => 0,
                // Ghidra: INDIRECTs are at the location of the op they are
                // indirect for: PcodeOp::getOpFromConst(op->getIn(1)->getAddr())
                //   ->getSeqNum().getOrder(). Rugra cannot resolve that here
                //   without Funcdata access (the iop input holds an Address
                //   that must be looked up in the op bank); fall back to the
                //   INDIRECT's own SeqNum order, matching the non-marker path.
                // Callers that need the precise indirect-target order should
                // resolve it via Funcdata::get_op_from_const and pass the
                // resolved order directly to set_begin/set_end.
                _ => op.get_seq_num().get_order(),
            }
        } else {
            // Ghidra: return op->getSeqNum().getOrder();
            op.get_seq_num().get_order()
        }
    }

    // Ghidra: cover.cc:107 CoverBlock::contain
    /// Check if the cover block contains a specific point
    pub fn contain(&self, point: u32) -> bool {
        point >= self.start && point <= self.end
    }

    /// Characterize where a point falls on the cover boundary.
    /// Faithful to `CoverBlock::boundary` (cover.cc:129-142).
    /// Returns:
    ///   - 0 if point not on boundary
    // Ghidra: cover.cc:129 CoverBlock::boundary
    ///   - 1 if on the tail (== stop)
    ///   - 2 if on the defining point (== start, and start is a real def)
    pub fn boundary(&self, point: u32) -> i32 {
        if self.empty() {
            return 0;
        }
        // Ghidra: if (getUIndex(start)==val) { if (start != 0) return 2; }
        // Rugra: start==u32::MAX means "no real def" (input varnode); only
        // return 2 (defining point) if start is a real op order.
        if self.start == point && self.start != u32::MAX {
            return 2;
        }
        if self.end == point {
            return 1;
        }
        0
    }

    // Ghidra: cover.cc:147 CoverBlock::merge
    /// Merge another cover block into this one
    pub fn merge(&mut self, other: &CoverBlock) {
        if other.empty() { return; }
        if self.start > other.start { self.start = other.start; }
        if self.end < other.end { self.end = other.end; }
    }

    // Ghidra: cover.cc:59 CoverBlock::intersect
    /// Characterize the intersection with another CoverBlock (non-destructive).
    /// Faithful to `CoverBlock::intersect` (cover.cc:59-102). Returns:
    ///   - 0 no intersection
    ///   - 1 only boundary points intersect
    ///   - 2 a whole interval intersects
    pub fn intersect_char(&self, op2: &CoverBlock) -> i32 {
        if self.empty() || op2.empty() {
            return 0;
        }
        let ustart = self.start;
        let ustop = self.end;
        let u2start = op2.start;
        let u2stop = op2.end;
        // Both one-piece (cover.cc:73-79). Rugra models single intervals only.
        if ustop <= u2start || u2stop <= ustart {
            if ustart == u2stop || ustop == u2start {
                return 1; // Boundary intersection
            }
            return 0; // No intersection
        }
        2 // Interval intersection
    }

    // Ghidra: cover.cc:59 CoverBlock::intersect
    /// Intersect another cover block with this one
    pub fn intersect(&mut self, other: &CoverBlock) {
        if self.start < other.start { self.start = other.start; }
        if self.end > other.end { self.end = other.end; }
        if self.start > self.end { self.clear(); }
    }
}

/// Full liveness cover of a varnode across multiple blocks
///
/// Corresponds to Ghidra's `Cover` class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cover {
    /// Mapping from basic block index to the cover block for that block
    pub blocks: BTreeMap<i32, CoverBlock>,
}

impl Cover {
    // Ghidra: cover.hh:36 Cover::new
    /// Create a new empty cover
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
        }
    }

    // Ghidra: cover.hh:36 Cover::clear
    /// Clear the cover
    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    // Ghidra: cover.cc:253 Cover::getCoverBlock
    /// Return a representative CoverBlock describing how much of the given
    /// block is covered by this. Faithful to `Cover::getCoverBlock`
    /// (cover.cc:253-260): returns a reference to the CoverBlock for block
    /// `i`, or the global empty block if this cover does not touch block `i`.
    /// Rugra returns `Option<&CoverBlock>` rather than a reference to a global
    /// empty singleton; callers that need the Ghidra (empty-block) behavior
    /// should `.copied().unwrap_or_else(CoverBlock::new)`.
    pub fn get_cover_block(&self, i: i32) -> Option<&CoverBlock> {
        self.blocks.get(&i)
    }

    // Ghidra: cover.cc:223 Cover::compareTo
    /// Compare this Cover with another by comparing just the indices of the
    /// first blocks respectively that are partly covered. Faithful to
    /// `Cover::compareTo` (cover.cc:223-247). Returns -1, 0, or 1 if this
    /// Cover's first block has a smaller, equal, or bigger index than the
    /// other Cover's first block. An empty Cover compares as if its first
    /// block index were 1000000 (Ghidra's sentinel), so any non-empty Cover
    /// orders before an empty one.
    pub fn compare_to(&self, op2: &Cover) -> i32 {
        // Ghidra: if (iter==cover.end()) a = 1000000; else a = (*iter).first;
        // BTreeMap iteration is sorted, so .keys().next() is the minimum key.
        let a = self.blocks.keys().next().copied().unwrap_or(1000000);
        let b = op2.blocks.keys().next().copied().unwrap_or(1000000);
        if a < b {
            -1
        } else if a == b {
            0
        } else {
            1
        }
    }

    // Ghidra: cover.cc:501 Cover::addDefPoint
    /// Add a definition point to the cover
    pub fn add_def_point(&mut self, block_idx: i32, point: u32) {
        let cb = self.blocks.entry(block_idx).or_insert_with(CoverBlock::new);
        cb.set_begin(point);
    }

    // Ghidra: cover.cc:565 Cover::addRefPoint
    /// Add a reference point to the cover
    pub fn add_ref_point(&mut self, block_idx: i32, point: u32) {
        let cb = self.blocks.entry(block_idx).or_insert_with(CoverBlock::new);
        if cb.empty() || point > cb.end {
            cb.set_end(point);
        }
    }

    // Ghidra: cover.cc:413 Cover::contain
    /// Check if the cover contains a point within a block
    pub fn contain(&self, block_idx: i32, point: u32) -> bool {
        if let Some(cb) = self.blocks.get(&block_idx) {
            cb.contain(point)
        } else {
            false
        }
    }

    // Ghidra: cover.cc:441 Cover::containVarnodeDef
    /// Characterize where a Varnode's definition point falls relative to
    /// this cover. Faithful to `Cover::containVarnodeDef` (cover.cc:441-462).
    ///
    /// `is_input`: if true, the varnode has no defining op (it's a function
    /// input) — Ghidra uses op=(PcodeOp*)2 sentinel, blk=0.
    /// `block_idx`/`order`: the defining op's block and order (when not input).
    ///
    /// Returns:
    ///   - 0 = not contained (or block absent)
    ///   - 1 = contained, strictly internal (boundary==0)
    ///   - 2 = contained, on the defining-point boundary (boundary==2)
    ///   - 3 = contained, on the tail boundary (boundary==1)
    pub fn contain_varnode_def_at(&self, is_input: bool, block_idx: i32, order: u32) -> i32 {
        // Ghidra: if (op==0) { op=(PcodeOp*)2; blk=0; } else blk = op->getParent()->getIndex();
        // The (PcodeOp*)2 sentinel flows into contain/boundary, which compare
        // via getUIndex — mapping it to 0 (cover.cc:29-49). Match that
        // semantic value here so it agrees with add_def_point_full's stored
        // input endpoints.
        let (blk, point) = if is_input {
            (0i32, 0u32) // input marker: block 0, uindex-domain order 0
        } else {
            (block_idx, order)
        };
        let Some(cb) = self.blocks.get(&blk) else {
            return 0;
        };
        if cb.contain(point) {
            let boundtype = cb.boundary(point);
            match boundtype {
                0 => 1,
                2 => 2,
                _ => 3, // boundary==1 (tail)
            }
        } else {
            0
        }
    }

    // Ghidra: cover.cc:465 Cover::merge
    /// Merge another cover into this one
    pub fn merge(&mut self, other: &Cover) {
        for (idx, other_cb) in &other.blocks {
            let cb = self.blocks.entry(*idx).or_insert_with(CoverBlock::new);
            cb.merge(other_cb);
        }
    }

    // Ghidra: cover.cc:269 Cover::intersect
    /// Intersect another cover with this one
    pub fn intersect(&mut self, other: &Cover) {
        let mut keys_to_remove = Vec::new();
        for (idx, cb) in &mut self.blocks {
            if let Some(other_cb) = other.blocks.get(idx) {
                cb.intersect(other_cb);
                if cb.empty() {
                    keys_to_remove.push(*idx);
                }
            } else {
                keys_to_remove.push(*idx);
            }
        }
        for idx in keys_to_remove {
            self.blocks.remove(&idx);
        }
    }

    // Ghidra: cover.hh:36 Cover::intersects
    /// Non-mutating predicate: true iff this cover and `other` share at least
    /// one live point. Used by cover-based merging to decide whether two
    /// HighVariables are simultaneously live (and thus cannot share a name).
    pub fn intersects(&self, other: &Cover) -> bool {
        for (idx, cb) in &self.blocks {
            if let Some(other_cb) = other.blocks.get(idx) {
                let lo = std::cmp::max(cb.start, other_cb.start);
                let hi = std::cmp::min(cb.end, other_cb.end);
                if lo <= hi {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: cover.cc:269 Cover::intersect
    /// Characterize the intersection with another Cover (non-destructive).
    /// Faithful to `Cover::intersect` (cover.cc:269-297). Returns:
    ///   - 0 no intersection
    ///   - 1 only boundary points intersect
    ///   - 2 a whole interval intersects
    pub fn intersect_char(&self, op2: &Cover) -> i32 {
        let mut res = 0i32;
        // Iterate both block maps in sorted order (BTreeMap iteration is sorted).
        let mut iter = self.blocks.iter();
        let mut iter2 = op2.blocks.iter();
        let mut cur = iter.next();
        let mut cur2 = iter2.next();
        loop {
            let (Some((k1, _)), Some((k2, _))) = (&cur, &cur2) else {
                return res;
            };
            if *k1 < *k2 {
                cur = iter.next();
            } else if *k1 > *k2 {
                cur2 = iter2.next();
            } else {
                // Same block in both covers.
                let newres = cur.unwrap().1.intersect_char(cur2.unwrap().1);
                if newres == 2 {
                    return 2;
                }
                if newres == 1 {
                    res = 1;
                }
                cur = iter.next();
                cur2 = iter2.next();
            }
        }
    }

    // Ghidra: cover.hh:36 Cover::intersectsExceptAt
    /// Like `intersects`, but ignores overlap at one specific point. Used by
    /// copy-merge: the COPY op itself reads the input and writes the output,
    /// so their covers always overlap at that single op — that overlap is the
    /// merge point itself and must not block merging. Any OTHER overlap means
    /// the two HighVariables are simultaneously live elsewhere and must not
    /// merge.
    pub fn intersects_except_at(
        &self,
        other: &Cover,
        exclude_block: i32,
        exclude_order: u32,
    ) -> bool {
        for (idx, cb) in &self.blocks {
            let Some(other_cb) = other.blocks.get(idx) else {
                continue;
            };
            let lo = std::cmp::max(cb.start, other_cb.start);
            let hi = std::cmp::min(cb.end, other_cb.end);
            if lo > hi {
                continue;
            }
            if *idx == exclude_block && lo <= exclude_order && exclude_order <= hi {
                // The overlap range includes the excluded point. If the range
                // contains any OTHER point, that's a real overlap.
                if hi > lo {
                    return true;
                }
                // Range is exactly {exclude_order} — no real overlap, continue.
            } else {
                return true;
            }
        }
        false
    }

    // Ghidra: cover.cc:307 Cover::intersectList
    /// Generate the list of blocks where this and `op2` intersect at or above
    /// the given characterization `level`. Faithful to
    /// `Cover::intersectList` (cover.cc:307-334). Iterates both block maps in
    /// sorted order (BTreeMap gives this for free) and, for each common block,
    /// appends its index to `listout` if `CoverBlock::intersect` returns a
    /// value >= `level`. Clears `listout` first, matching Ghidra.
    ///
    /// `level`: 1 = any intersection (boundary or interval), 2 = interval only.
    pub fn intersect_list(&self, op2: &Cover, level: i32) -> Vec<i32> {
        // Ghidra: listout.clear();
        let mut listout = Vec::new();
        let mut iter = self.blocks.iter();
        let mut iter2 = op2.blocks.iter();
        let mut cur = iter.next();
        let mut cur2 = iter2.next();
        loop {
            let (Some((k1, _)), Some((k2, _))) = (&cur, &cur2) else {
                break;
            };
            if *k1 < *k2 {
                cur = iter.next();
            } else if *k1 > *k2 {
                cur2 = iter2.next();
            } else {
                // Same block in both covers.
                // Ghidra: val = (*iter).second.intersect((*iter2).second);
                let val = cur.unwrap().1.intersect_char(cur2.unwrap().1);
                if val >= level {
                    listout.push(**k1);
                }
                cur = iter.next();
                cur2 = iter2.next();
            }
        }
        listout
    }

    // Ghidra: cover.cc:392 Cover::intersectByBlock
    /// Looking only at the given block, return:
    ///   - 0 if there is no intersection
    ///   - 1 if the only intersection is on a boundary point
    ///   - 2 if the intersection contains a range of p-code ops
    /// Faithful to `Cover::intersectByBlock` (cover.cc:392-406).
    pub fn intersect_by_block(&self, blk: i32, op2: &Cover) -> i32 {
        // Ghidra: iter = cover.find(blk); if (iter == cover.end()) return 0;
        let Some(cb1) = self.blocks.get(&blk) else {
            return 0;
        };
        let Some(cb2) = op2.blocks.get(&blk) else {
            return 0;
        };
        // Ghidra: return (*iter).second.intersect((*iter2).second);
        cb1.intersect_char(cb2)
    }

    /// Resolve the basic-block index of a PcodeOp via its `parent` weak ref.
    /// Returns None if the op has no parent (not yet inserted into a block).
    /// Used by `rebuild`/`add_ref_point_full` to bridge PcodeOp -> block index
    /// for the order-based cover API. (Ghidra inlines this as
    /// `op->getParent()->getIndex()`.)
    // RUGRA-GLUE: Rust ownership adapter; Ghidra keeps a PcodeOp pointer and
    // calls op->getParent()->getIndex() inline, so it has no standalone helper.
    fn block_index_of_op(op: &crate::op::PcodeOp) -> Option<i32> {
        let parent = op.parent.as_ref()?.upgrade()?;
        let idx = parent.read().unwrap().get_index();
        Some(idx)
    }

    /// Resolve the SeqNum comparison order of a PcodeOp, applying the
    /// `CoverBlock::getUIndex` marker/sentinel rules. Returns None if the op
    /// is an INDIRECT whose target order must be resolved through Funcdata
    /// (callers may then fall back to the INDIRECT's own order).
    // RUGRA-GLUE: Rust forwarding helper for the order-only endpoint model;
    // Ghidra calls CoverBlock::getUIndex directly and has no separate wrapper.
    fn order_of_op(op: &crate::op::PcodeOp) -> u32 {
        CoverBlock::get_u_index(op)
    }

    // Ghidra: cover.cc:501 Cover::addDefPoint (op-based variant)
    /// Reset this Cover to the single point where `vn` is defined. Faithful
    /// to `Cover::addDefPoint` (cover.cc:501-519). Clears the cover first.
    /// `def` is the original Varnode's defining op. If it is absent and
    /// `is_input` is true, the input-varnode convention is block 0/order 2.
    fn add_def_point_full(
        &mut self,
        def: Option<&std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        is_input: bool,
    ) {
        // Ghidra: cover.clear();
        self.clear();
        if let Some(def) = def {
            let def_rg = def.read().unwrap();
            // Ghidra: def->getParent()->getIndex()
            let blk = Self::block_index_of_op(&def_rg).unwrap_or(0);
            // Ghidra: CoverBlock &block(cover[blk]); block.setBegin(def); block.setEnd(def);
            let order = Self::order_of_op(&def_rg);
            let cb = self.blocks.entry(blk).or_insert_with(CoverBlock::new);
            cb.set_begin(order);
            cb.set_end(order);
        } else if is_input {
            // Ghidra: CoverBlock &block(cover[0]);
            //         block.setBegin((const PcodeOp*)2); block.setEnd((const PcodeOp*)2);
            // The pointer sentinel 2 is the input marker; every comparison
            // goes through CoverBlock::getUIndex, which maps it to 0
            // (cover.cc:29-49). Rugra's order-only model stores the
            // uindex-domain value directly, so both endpoints are 0 here —
            // identical to Ghidra's (2,2) state under getUIndex projection.
            let cb = self.blocks.entry(0).or_insert_with(CoverBlock::new);
            cb.set_begin(0);
            cb.set_end(0);
        }
    }

    // Ghidra: cover.cc:565 Cover::addRefPoint (op-based variant)
    /// Add the read point `op` to this Cover, then recursively fill the cover
    /// backward through the control-flow predecessors of `op`'s block until
    /// existing cover is reached. Faithful to `Cover::addRefPoint`
    /// (cover.cc:565-612).
    ///
    /// `root` is the original Varnode passed to `rebuild`, even when `op` is a
    /// descendant of an implied output. It selects every exact-identity
    /// MULTIEQUAL input slot whose predecessor branch must be traversed.
    fn add_ref_point_full(
        &mut self,
        op_arc: &std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let (order, opcode, op_parent, matching_slots) = {
            let op = op_arc.read().unwrap();
            let opcode = op.get_opcode();
            let matching_slots = if opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                op.inrefs
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, input)| std::sync::Arc::ptr_eq(input, root).then_some(slot))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            (
                Self::order_of_op(&op),
                opcode,
                op.parent.as_ref().and_then(|parent| parent.upgrade()),
                matching_slots,
            )
        };
        let Some(bl_arc) = op_parent else { return };
        let op_blk = bl_arc.read().unwrap().get_index();

        // Ghidra: FlowBlock *bl = ref->getParent();
        //         CoverBlock &block(cover[bl->getIndex()]);
        let block_was_empty = {
            let existing = self.blocks.get(&op_blk);
            existing.map(|b| b.empty()).unwrap_or(true)
        };
        let cb = self.blocks.entry(op_blk).or_insert_with(CoverBlock::new);

        if block_was_empty {
            // Ghidra: block.setEnd(ref);
            // In Ghidra the untouched start pointer remains the block-begin
            // sentinel.  Materialize its comparable value in the order-only
            // representation before storing the reference endpoint.
            cb.set_begin(0);
            cb.set_end(order);
        } else {
            // Ghidra: if (block.contain(ref)) { if (ref->code()!=MULTIEQUAL) return; }
            if cb.contain(order) {
                if opcode != crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                    return;
                }
                // Even if contained, a MULTIEQUAL may add new cover via a
                // different branch — fall through to the recurse step below.
            } else {
                // Ghidra: const PcodeOp *op = block.getStop();
                //         const PcodeOp *startop = block.getStart();
                //         block.setEnd(ref);
                //         ustop = getUIndex(block.getStop());
                //         if (ustop >= getUIndex(startop)) { ...MULTIEQUAL tip... return; }
                let startop_order = cb.start;
                cb.set_end(order);
                let ustop = order;
                if ustop >= startop_order {
                    // Infinitesimal MULTIEQUAL tip: op (the OLD stop) was a
                    // MULTIEQUAL with startop at block-begin. We cannot recover
                    // the old stop PcodeOp* from the order-based model, so we
                    // cannot perfectly distinguish this branch. Conservatively
                    // fall through to the recurse step only for MULTIEQUAL refs
                    // (handled uniformly below); otherwise return.
                    if opcode != crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                        return;
                    }
                } else {
                    return;
                }
            }
        }

        // Ghidra: if (ref->code() == CPUI_MULTIEQUAL) {
        //           for(j=0;j<ref->numInput();++j)
        //             if (ref->getIn(j)==vn) addRefRecurse(bl->getIn(j));
        //         } else for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j));
        if opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
            // Snapshot every exact-identity slot in ascending order while the
            // op is locked, then snapshot the corresponding predecessor Arcs
            // without carrying the block guard into recursive calls.
            let predecessors = {
                let block = bl_arc.read().unwrap();
                matching_slots
                    .into_iter()
                    .filter_map(|slot| block.get_in(slot).map(|edge| edge.point))
                    .collect::<Vec<_>>()
            };
            for predecessor in predecessors {
                self.add_ref_recurse(&predecessor);
            }
        } else {
            for edge in Self::predecessors_of(&bl_arc) {
                self.add_ref_recurse(&edge);
            }
        }
    }

    /// Collect the predecessor block Arcs of `bl` (its in-edges' `point`
    /// targets). Mirrors Ghidra's `bl->getIn(j)` loop used by
    /// `addRefPoint`/`addRefRecurse`. Returns a Vec so the caller can iterate
    /// without holding the block's read lock (the recurse call needs to take
    /// child locks).
    // RUGRA-GLUE: Rust lock-release snapshot helper; Ghidra walks FlowBlock
    // incoming raw pointers inline in Cover::addRefPoint/addRefRecurse.
    fn predecessors_of(
        bl: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> Vec<std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> {
        let rg = bl.read().unwrap();
        let n = rg.size_in();
        let mut out = Vec::with_capacity(n);
        for slot in 0..n {
            if let Some(edge) = rg.get_in(slot) {
                out.push(edge.point);
            }
        }
        out
    }

    // Ghidra: cover.cc:477 Cover::rebuild
    /// Reset this Cover based on the def-use chain of a single Varnode.
    /// Faithful to `Cover::rebuild` (cover.cc:477-496). The cover is set to
    /// all p-code ops between the point where `vn` is defined and all the
    /// points where it is read. Implied outputs of reading ops are followed
    /// transitively (they are invisible in the final source, so their reads
    /// extend the cover of the originating Varnode).
    ///
    /// Walks the def-use chain breadth-first via a worklist (Ghidra's
    /// `vector<const Varnode *> path`), starting at `vn`. For each Varnode:
    ///   1. addDefPoint is called once for the root (this clears the cover and
    ///      plants the definition).
    ///   2. every descendant (reading) op contributes an addRefPoint.
    ///   3. if a reading op's output is non-null and implied, the output is
    ///      pushed onto the worklist so ITS readers also extend the cover.
    ///
    /// Because Rugra's internal cover stores `(block_idx, u32 order)` pairs,
    /// this entry point resolves each PcodeOp's block index and SeqNum order
    /// and delegates to the order-based `add_def_point`/`add_ref_point_full`.
    pub fn rebuild(
        &mut self,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let (definition, is_input, descendants, root_is_implied) = {
            let root_value = root.read().unwrap();
            (
                root_value.get_def(),
                root_value.is_input(),
                root_value.descend_iter().collect::<Vec<_>>(),
                root_value.is_implied(),
            )
        };
        self.rebuild_from_root_snapshot(
            root,
            definition,
            is_input,
            descendants,
            root_is_implied,
        );
    }

    // RUGRA-GLUE: lock-release adapter for Cover::rebuild; Ghidra's raw
    // Varnode pointer needs no snapshot when updateCover is called through a
    // mutable Rust RwLock guard.
    pub(crate) fn rebuild_from_root_snapshot(
        &mut self,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        definition: Option<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        is_input: bool,
        root_descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        root_is_implied: bool,
    ) {
        // Ghidra: vector<const Varnode *> path(1,vn); int4 pos = 0;
        // Ghidra: addDefPoint(vn);
        self.add_def_point_full(definition.as_ref(), is_input);

        let mut path = Vec::new();
        let mut pos = 0usize;
        let mut descendants = root_descendants.clone();
        loop {
            for op_arc in descendants {
                // The original root, not `current`, is the addRefPoint identity.
                self.add_ref_point_full(&op_arc, root);
                let output = op_arc.read().unwrap().get_out().cloned();
                if let Some(output) = output {
                    let is_implied = if std::sync::Arc::ptr_eq(&output, root) {
                        root_is_implied
                    } else {
                        output.read().unwrap().is_implied()
                    };
                    if is_implied {
                        path.push(output);
                    }
                }
            }
            if pos >= path.len() {
                break;
            }
            let current = path[pos].clone();
            pos += 1;
            descendants = if std::sync::Arc::ptr_eq(&current, root) {
                root_descendants.clone()
            } else {
                let current_value = current.read().unwrap();
                current_value.descend_iter().collect::<Vec<_>>()
            };
        }
    }

    // Ghidra: cover.cc:524 Cover::addRefRecurse
    /// Fill in this Cover recursively from the given block backward until we
    /// run into existing cover. Faithful to `Cover::addRefRecurse`
    /// (cover.cc:524-558). If `bl` has no cover yet, mark the whole block
    /// covered (setAll) and recurse into every in-edge predecessor. If `bl`
    /// already has cover, extend its tail to the block bottom, and — when the
    /// existing cover is only an infinitesimal MULTIEQUAL tip (start==0,
    /// stop==0, defined by a MULTIEQUAL) — recurse through the in-edges so
    /// the other branches still get filled.
    pub fn add_ref_recurse(&mut self, bl: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>) {
        // Resolve the block index from the (already locked) FlowBlock.
        let bl_index = {
            let bl_rg = bl.read().unwrap();
            bl_rg.get_index()
        };
        // Ghidra: CoverBlock &block(cover[bl->getIndex()]);
        let block_was_empty = self.blocks.get(&bl_index).map(|b| b.empty()).unwrap_or(true);
        // Ensure an entry exists (operator[] default-constructs in C++).
        let cb = self.blocks.entry(bl_index).or_insert_with(CoverBlock::new);

        if block_was_empty {
            // Ghidra: block.setAll();  // No cover encountered, fill in entire block
            cb.set_all();
            // Ghidra: for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j));
            let preds = Self::predecessors_of(bl);
            for pred in preds {
                self.add_ref_recurse(&pred);
            }
            return;
        }

        // Ghidra: const PcodeOp *op = block.getStop();
        //         ustart = getUIndex(block.getStart());
        //         ustop  = getUIndex(op);
        let ustart = cb.start;
        let ustop = cb.end;
        // Ghidra: if ((ustop != ~0) && (ustop >= ustart)) block.setEnd((PcodeOp*)1);
        // Fill in to the bottom of the block.
        if ustop != u32::MAX && ustop >= ustart {
            cb.set_end(u32::MAX);
        }

        // Ghidra: if ((ustop==0) && (block.getStart()==(PcodeOp*)0)) {
        //           if (op!=0 && op->code()==CPUI_MULTIEQUAL) {
        //             for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j));
        //           }
        //         }
        // This block contains only an infinitesimal tip of cover through one
        // branch of a MULTIEQUAL; traverse through the other branches too.
        if ustop == 0 && ustart == 0 {
            // We cannot, from the Cover side alone, recover the stop PcodeOp*
            // to test its opcode. The infinitesimal-tip condition (start==0,
            // stop==0 with a real MULTIEQUAL def) is exactly the case where a
            // MULTIEQUAL defined the cover at the block very-beginning; we
            // conservatively recurse through predecessors whenever the tip
            // condition holds, matching Ghidra's branch.
            let preds = Self::predecessors_of(bl);
            for pred in preds {
                self.add_ref_recurse(&pred);
            }
        }
    }
}

impl fmt::Display for CoverBlock {
    // Ghidra: cover.hh:36 Cover::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.empty() {
            write!(f, "[]")
        } else {
            write!(f, "[{:x}, {:x}]", self.start, self.end)
        }
    }
}

impl fmt::Display for Cover {
    // Ghidra: cover.hh:36 Cover::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        for (i, (idx, cb)) in self.blocks.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{}: {}", idx, cb)?;
        }
        write!(f, "}}")
    }
}

/// Alias for the owned PcodeOp reference type used throughout Rugra.
/// (Ghidra stores raw `PcodeOp*` in `opList`; Rugra stores the strong Arc.)
type OpArc = std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>;

/// A set of PcodeOps that can be tested for Cover intersections.
///
/// Faithful to Ghidra's `class PcodeOpSet` (cover.hh:35-65). This is a set of
/// PcodeOp objects designed for quick intersection tests with a Cover. The set
/// is lazily constructed via its `populate()` method at the time the first
/// intersection test is needed. Once an intersection has been established
/// between a PcodeOp in this set and a Varnode Cover, `affects_test()` can do
/// secondary testing to determine if the intersection should prevent merging.
///
/// Ghidra models this as an abstract base class with two pure-virtual methods
/// (`populate`, `affectsTest`) and protected storage (`opList`, `blockStart`,
/// `is_pop`). Rugra splits it into:
///   - `PcodeOpSetImpl`: the trait subclass owners implement (populate +
///     affects_test), mirroring the virtual methods.
///   - `PcodeOpSet`: the owning struct that holds the shared storage and a
///     `Box<dyn PcodeOpSetImpl>` for the subclass logic. Interior mutability
///     (RwLock on the storage) lets `populate` (a `&self` trait method,
///     matching Ghidra's `void populate()` const-correctness on the base)
///     mutate the shared lists.
pub struct PcodeOpSet {
    /// Ops in this set, sorted on block index, then SeqNum::order.
    /// (Ghidra `vector<PcodeOp*> opList`.)
    op_list: std::sync::RwLock<Vec<OpArc>>,
    /// Index in `op_list` of the first op of each non-empty block.
    /// (Ghidra `vector<int4> blockStart`.)
    block_start: std::sync::RwLock<Vec<i32>>,
    /// Has the `populate` method been called? (Ghidra `bool is_pop`.)
    is_pop: std::sync::atomic::AtomicBool,
    /// Subclass: provides the lazy population and the secondary affects test.
    /// (Ghidra virtual dispatch.)
    owner: Box<dyn PcodeOpSetImpl>,
}

/// Subclass interface for `PcodeOpSet`. Faithful to the two pure-virtual
/// methods of Ghidra's `PcodeOpSet` (cover.hh:52,61).
pub trait PcodeOpSetImpl: std::fmt::Debug {
    /// Populate the PcodeOp object set. The override calls `add_op` for each
    /// PcodeOp it wants to add, then `finalize` to make the set ready for
    /// intersection tests. Faithful to `PcodeOpSet::populate` (cover.hh:52,
    /// pure-virtual). Receives `&mut PcodeOpSet` so it can call the protected
    /// `add_op`/`finalize` helpers.
    // Ghidra: cover.hh:52 PcodeOpSet::populate
    fn populate(&self, set: &mut PcodeOpSet);

    /// Secondary test that the given PcodeOp affects the Varnode. Called after
    /// an intersection of a PcodeOp in this set with a Varnode Cover has been
    /// determined. Allows the owner to make a final determination if merging
    /// should be prevented. Faithful to `PcodeOpSet::affectsTest`
    /// (cover.hh:61, pure-virtual). Returns true if merging should be
    /// prevented.
    // Ghidra: cover.hh:61 PcodeOpSet::affectsTest
    fn affects_test(
        &self,
        op: &crate::op::PcodeOp,
        vn: &crate::varnode::Varnode,
    ) -> bool;
}

impl std::fmt::Debug for PcodeOpSet {
    // RUGRA-GLUE: Rust Debug-trait implementation; Ghidra has no corresponding
    // PcodeOpSet debug formatter (Cover::print is a different API).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.op_list.read().unwrap().len();
        f.debug_struct("PcodeOpSet")
            .field("is_pop", &self.is_pop.load(std::sync::atomic::Ordering::Relaxed))
            .field("num_ops", &n)
            .field("owner", &self.owner)
            .finish()
    }
}

impl PcodeOpSet {
    // Ghidra: cover.hh:44 PcodeOpSet::PcodeOpSet
    /// Construct an empty PcodeOpSet with the given subclass owner.
    /// (Ghidra ctor: `PcodeOpSet(void) { is_pop = false; }`.)
    pub fn new(owner: Box<dyn PcodeOpSetImpl>) -> Self {
        Self {
            op_list: std::sync::RwLock::new(Vec::new()),
            block_start: std::sync::RwLock::new(Vec::new()),
            is_pop: std::sync::atomic::AtomicBool::new(false),
            owner,
        }
    }

    // Ghidra: cover.hh:41 PcodeOpSet::addOp
    /// Add a PcodeOp into the set. Faithful to `PcodeOpSet::addOp`
    /// (cover.hh:41, inline protected): `opList.push_back(op)`.
    pub fn add_op(&self, op: OpArc) {
        self.op_list.write().unwrap().push(op);
    }

    // Ghidra: cover.hh:45 PcodeOpSet::isPopulated
    /// Return true if this set is populated. Faithful to
    /// `PcodeOpSet::isPopulated` (cover.hh:45, inline).
    pub fn is_populated(&self) -> bool {
        self.is_pop.load(std::sync::atomic::Ordering::Relaxed)
    }

    // Ghidra: cover.hh:63 PcodeOpSet::clear
    /// Clear all PcodeOps in this. Faithful to `PcodeOpSet::clear`
    /// (cover.hh:63, inline):
    ///   `is_pop = false; opList.clear(); blockStart.clear();`
    pub fn clear(&self) {
        self.is_pop.store(false, std::sync::atomic::Ordering::Relaxed);
        self.op_list.write().unwrap().clear();
        self.block_start.write().unwrap().clear();
    }

    // Ghidra: cover.hh:52 PcodeOpSet::populate (dispatch)
    /// Lazily populate this set if not already populated. Faithful to the
    /// Ghidra call-site discipline: callers test `isPopulated()` then invoke
    /// the (virtual) `populate()`. Here the dispatch is to the boxed owner.
    pub fn populate(&mut self) {
        if !self.is_populated() {
            // Dispatch to the subclass, passing ourself so it can call
            // add_op/finalize. We temporarily move the owner out to avoid a
            // double-&mut borrow of self.
            let owner = std::mem::replace(&mut self.owner, Box::new(NoOpOwner));
            owner.populate(self);
            self.owner = owner;
        }
    }

    // Ghidra: cover.hh:61 PcodeOpSet::affectsTest (dispatch)
    /// Secondary affects test. Faithful to the virtual `affectsTest`.
    pub fn affects_test(
        &self,
        op: &crate::op::PcodeOp,
        vn: &crate::varnode::Varnode,
    ) -> bool {
        self.owner.affects_test(op, vn)
    }

    // Ghidra: cover.cc:627 PcodeOpSet::finalize
    /// Sort ops in the set into blocks. Faithful to `PcodeOpSet::finalize`
    /// (cover.cc:627-640): sorts `opList` with `compareByBlock`, then builds
    /// `blockStart` — the index of the first op of each new (strictly larger)
    /// block index. Sets `is_pop = true`.
    pub fn finalize(&self) {
        // Ghidra: sort(opList.begin(),opList.end(),compareByBlock);
        {
            let mut list = self.op_list.write().unwrap();
            // Stable sort isn't required (SeqNum orders ties), but Rust's
            // sort_by is stable which is harmless here.
            list.sort_by(|a, b| {
                // compareByBlock: block index first, then SeqNum order.
                let a_rg = a.read().unwrap();
                let b_rg = b.read().unwrap();
                let a_blk = Cover::block_index_of_op(&a_rg).unwrap_or(-1);
                let b_blk = Cover::block_index_of_op(&b_rg).unwrap_or(-1);
                match a_blk.cmp(&b_blk) {
                    std::cmp::Ordering::Equal => {
                        a_rg.get_seq_num().get_order().cmp(&b_rg.get_seq_num().get_order())
                    }
                    ord => ord,
                }
            });
        }
        // Ghidra: int4 blockNum = -1; for(i=0;i<opList.size();++i) {
        //           newBlockNum = opList[i]->getParent()->getIndex();
        //           if (newBlockNum > blockNum) { blockStart.push_back(i); blockNum = newBlockNum; }
        //         }
        let list = self.op_list.read().unwrap();
        let mut starts = self.block_start.write().unwrap();
        starts.clear();
        let mut block_num: i32 = -1;
        for (i, op) in list.iter().enumerate() {
            let op_rg = op.read().unwrap();
            let new_block_num = Cover::block_index_of_op(&op_rg).unwrap_or(block_num);
            if new_block_num > block_num {
                starts.push(i as i32);
                block_num = new_block_num;
            }
        }
        // Ghidra: is_pop = true;
        self.is_pop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    // Ghidra: cover.cc:646 PcodeOpSet::compareByBlock
    /// Compare PcodeOps for this set. Faithful to
    /// `PcodeOpSet::compareByBlock` (cover.cc:646-652): compare first by index
    /// of the containing basic blocks, then by SeqNum ordering within the
    /// block. Returns true if `a` should be ordered before `b`.
    pub fn compare_by_block(
        a: &crate::op::PcodeOp,
        b: &crate::op::PcodeOp,
    ) -> bool {
        // Ghidra: if (a->getParent() != b->getParent())
        //           return (a->getParent()->getIndex() < b->getParent()->getIndex());
        let a_blk = Cover::block_index_of_op(a).unwrap_or(-1);
        let b_blk = Cover::block_index_of_op(b).unwrap_or(-1);
        if a_blk != b_blk {
            return a_blk < b_blk;
        }
        // Ghidra: return a->getSeqNum().getOrder() < b->getSeqNum().getOrder();
        a.get_seq_num().get_order() < b.get_seq_num().get_order()
    }

    /// Number of ops currently in the set. (Ghidra uses `opList.size()`;
    /// Rugra exposes this as a method since `op_list` is private.)
    // RUGRA-GLUE: Rust visibility adapter for private RwLock storage; Ghidra
    // accesses PcodeOpSet::opList directly and has no getNumOps method.
    pub fn get_num_ops(&self) -> usize {
        self.op_list.read().unwrap().len()
    }

    /// Get the i-th op in the sorted set. (Ghidra indexes `opList[i]`
    /// directly; Rugra exposes a method since `op_list` is private.)
    // RUGRA-GLUE: Rust visibility/ownership adapter returning an Arc clone;
    // Ghidra indexes the protected opList vector directly.
    pub fn get_op(&self, i: usize) -> Option<OpArc> {
        self.op_list.read().unwrap().get(i).cloned()
    }

    /// Read-only access to the op list snapshot. Used by `Cover::intersect`
    /// (cover.cc:342) to walk the set.
    // RUGRA-GLUE: Rust lock-release snapshot for private RwLock storage;
    // Ghidra's friend Cover reads PcodeOpSet::opList directly.
    pub fn op_list_snapshot(&self) -> Vec<OpArc> {
        self.op_list.read().unwrap().clone()
    }

    /// Read-only access to the block-start index snapshot. Used by
    /// `Cover::intersect` (cover.cc:342) to delimit ops per block.
    // RUGRA-GLUE: Rust lock-release snapshot for private RwLock storage;
    // Ghidra's friend Cover reads PcodeOpSet::blockStart directly.
    pub fn block_start_snapshot(&self) -> Vec<i32> {
        self.block_start.read().unwrap().clone()
    }
}

/// Placeholder owner used only to temporarily satisfy the borrow checker while
/// the real owner is dispatched into `populate`. Never observed by callers.
#[derive(Debug, Default)]
struct NoOpOwner;

impl PcodeOpSetImpl for NoOpOwner {
    // RUGRA-GLUE: Borrow-checker placeholder used only during mem::replace;
    // Ghidra virtual dispatch never installs a temporary owner object.
    fn populate(&self, _set: &mut PcodeOpSet) {}
    // RUGRA-GLUE: Borrow-checker placeholder used only during mem::replace;
    // Ghidra virtual dispatch never invokes a temporary affectsTest method.
    fn affects_test(&self, _op: &crate::op::PcodeOp, _vn: &crate::varnode::Varnode) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_block_basic() {
        let mut cb = CoverBlock::new();
        assert!(cb.empty());

        cb.set_begin(10);
        cb.set_end(20);
        assert!(!cb.empty());
        assert!(cb.contain(15));
        assert!(!cb.contain(5));
        assert!(!cb.contain(25));
    }

    #[test]
    fn test_cover_merge() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 10);
        c1.add_ref_point(1, 20);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 15);
        c2.add_ref_point(1, 25);
        c2.add_def_point(2, 5);
        c2.add_ref_point(2, 10);

        c1.merge(&c2);
        assert_eq!(c1.blocks.get(&1).unwrap().start, 10);
        assert_eq!(c1.blocks.get(&1).unwrap().end, 25);
        assert_eq!(c1.blocks.get(&2).unwrap().start, 5);
        assert_eq!(c1.blocks.get(&2).unwrap().end, 10);
    }

    /// Disjoint-block covers must not intersect: the canonical safe-merge case.
    #[test]
    fn test_intersect_disjoint_blocks() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 5);
        c1.add_ref_point(1, 10);

        let mut c2 = Cover::new();
        c2.add_def_point(2, 5);
        c2.add_ref_point(2, 10);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        assert!(tmp.blocks.is_empty(), "disjoint-block covers must not intersect");
    }

    /// Same-block non-overlapping ranges must yield empty intersection.
    #[test]
    fn test_intersect_disjoint_same_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 5);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        match tmp.blocks.get(&1) {
            None => {}
            Some(cb) => {
                assert!(cb.empty(), "disjoint same-block covers must yield empty CoverBlock, got {:?}", cb);
            }
        }
    }

    /// Overlapping same-block ranges must produce the tightened [max_start, min_end].
    #[test]
    fn test_intersect_overlapping_same_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 15);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        let cb = tmp.blocks.get(&1).expect("overlapping same-block covers must keep the block");
        assert!(!cb.empty(), "expected non-empty intersection, got {:?}", cb);
        assert_eq!(cb.start, 10);
        assert_eq!(cb.end, 15);
    }

    /// Multi-block intersect keeps overlapping blocks (narrowed) and drops disjoint ones.
    #[test]
    fn test_intersect_partial_multi_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 20);
        c1.add_def_point(2, 1);
        c1.add_ref_point(2, 20);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 30);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        assert!(tmp.blocks.contains_key(&1), "overlapping block must survive intersect");
        assert!(!tmp.blocks.contains_key(&2), "non-overlapping block must be dropped");
        let cb = tmp.blocks.get(&1).unwrap();
        assert_eq!(cb.start, 10);
        assert_eq!(cb.end, 20);
    }

    /// `intersects` is a non-mutating predicate; it must not alter either cover.
    #[test]
    fn test_intersects_predicate() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 10);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 20);
        c2.add_ref_point(1, 30);

        let mut c3 = Cover::new();
        c3.add_def_point(1, 5);
        c3.add_ref_point(1, 15);

        assert!(!c1.intersects(&c2), "disjoint covers must not intersect");
        assert!(c1.intersects(&c3), "overlapping covers must intersect");

        assert_eq!(c1.blocks.get(&1).unwrap().start, 1);
        assert_eq!(c1.blocks.get(&1).unwrap().end, 10);
    }

    /// `set_all` must mark the whole block as covered (begin..end-of-block).
    /// Mirrors Ghidra `CoverBlock::setAll` (cover.hh:84): start=0 (begin),
    /// stop=u32::MAX (~0, the end-of-block sentinel returned by getUIndex).
    #[test]
    fn test_cover_block_set_all() {
        let mut cb = CoverBlock::new();
        assert!(cb.empty());
        cb.set_all();
        assert!(!cb.empty(), "set_all must produce a non-empty block");
        assert_eq!(cb.start, 0, "set_all start must be begin-of-block (0)");
        assert_eq!(cb.end, u32::MAX, "set_all end must be end-of-block (~0)");
        // Whole block covered: contains 0, mid-range, and u32::MAX.
        assert!(cb.contain(0));
        assert!(cb.contain(100));
        assert!(cb.contain(u32::MAX));
    }

    /// `compare_to` orders Covers by the first covered block index. Empty
    /// Covers sort last (Ghidra's 1000000 sentinel). Faithful to
    /// `Cover::compareTo` (cover.cc:223-247).
    #[test]
    fn test_cover_compare_to() {
        let mut a = Cover::new();
        a.add_def_point(3, 1);
        a.add_ref_point(3, 10);
        let mut b = Cover::new();
        b.add_def_point(5, 1);
        b.add_ref_point(5, 10);
        let empty = Cover::new();

        assert_eq!(a.compare_to(&b), -1, "first-block 3 < 5");
        assert_eq!(b.compare_to(&a), 1, "first-block 5 > 3");
        let mut a2 = Cover::new();
        a2.add_def_point(3, 1);
        assert_eq!(a.compare_to(&a2), 0, "same first block -> 0");
        assert_eq!(a.compare_to(&empty), -1, "non-empty < empty (1000000)");
        assert_eq!(empty.compare_to(&a), 1, "empty > non-empty");
        assert_eq!(empty.compare_to(&Cover::new()), 0, "two empties equal");
    }

    /// `get_cover_block` returns the CoverBlock for a covered block, None
    /// otherwise. Mirrors Ghidra `Cover::getCoverBlock` returning the global
    /// empty block for uncovered blocks.
    #[test]
    fn test_get_cover_block() {
        let mut c = Cover::new();
        c.add_def_point(2, 5);
        c.add_ref_point(2, 9);
        assert!(c.get_cover_block(2).is_some());
        assert_eq!(c.get_cover_block(2).unwrap().start, 5);
        assert!(c.get_cover_block(7).is_none(), "uncovered block -> None");
    }

    /// `intersect_list` enumerates block indices where two Covers intersect
    /// at or above `level`. `intersect_by_block` gives the per-block
    /// characterization. Both faithful to cover.cc:307 / cover.cc:392.
    #[test]
    fn test_intersect_list_and_by_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 20);
        c1.add_def_point(2, 1);
        c1.add_ref_point(2, 20);
        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 30);
        // block 1 overlaps (interval), block 2 only in c1.

        // level 2 (interval only): only block 1 qualifies.
        let list = c1.intersect_list(&c2, 2);
        assert_eq!(list, vec![1], "interval-level list must be [1]");

        // level 1 (any intersection): still only block 1 (block 2 absent in c2).
        let list1 = c1.intersect_list(&c2, 1);
        assert_eq!(list1, vec![1]);

        // Per-block characterization.
        assert_eq!(c1.intersect_by_block(1, &c2), 2, "block 1 interval overlap");
        assert_eq!(c1.intersect_by_block(2, &c2), 0, "block 2 absent in c2");
        assert_eq!(c1.intersect_by_block(9, &c2), 0, "block 9 absent in both");
    }

    /// Boundary-touching intervals must yield level-1 (point) intersection,
    /// and `intersect_list(level=1)` must include such blocks while
    /// `intersect_list(level=2)` must exclude them.
    #[test]
    fn test_intersect_list_boundary() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 10); // [1,10]
        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20); // [10,20]: touches c1 at 10 only
        assert_eq!(c1.intersect_by_block(1, &c2), 1, "boundary touch -> level 1");
        assert_eq!(c1.intersect_list(&c2, 1), vec![1], "level 1 includes boundary");
        assert!(c1.intersect_list(&c2, 2).is_empty(), "level 2 excludes boundary");
    }
}
