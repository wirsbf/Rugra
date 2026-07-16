//! SSA construction and Heritage management
//!
//! Corresponds to Ghidra's `heritage.hh`

use crate::address::Address;
use crate::block::{BlockBasic, FlowBlock};
use crate::funcdata::Funcdata;
use crate::op::{PcodeOp, PcodeOpBank};
use crate::space::AddressSpace;
use crate::varnode::{Varnode, VarnodeBank};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock, Weak};

/// Mapping from Address to size and pass information
/// Corresponds to Ghidra's `LocationMap`
#[derive(Debug)]
pub struct LocationMap {
    pub themap: BTreeMap<Address, SizePass>,
}

#[derive(Debug, Clone, Copy)]
pub struct SizePass {
    pub size: i32,
    pub pass: i32,
}

impl LocationMap {
    // Ghidra: heritage.hh:38 LocationMap::new
    pub fn new() -> Self {
        Self {
            themap: BTreeMap::new(),
        }
    }

    // Ghidra: heritage.cc:34 LocationMap::add
    /// Add a range to the disjoint cover, merging overlapping entries.
    /// Faithful to `LocationMap::add` (heritage.cc:34-71).
    /// Returns the intersect code:
    ///   0 = no overlap with existing
    ///   1 = partial overlap (merged)
    ///   2 = completely contained in a previous (older) entry
    pub fn add(&mut self, mut addr: Address, mut size: i32, mut pass: i32) -> i32 {
        use crate::address::Address as A;
        // Ghidra cc:37-41: find the first entry that might overlap.
        // lower_bound(addr), back up one, then check overlap.
        let mut intersect = 0;
        let keys: Vec<Address> = self.themap.keys().cloned().collect();
        let start_idx = match keys.iter().position(|k| *k >= addr) {
            Some(i) => if i > 0 { i - 1 } else { 0 },
            None => keys.len().saturating_sub(1),
        };
        // Ghidra cc:45-57: check if the starting entry overlaps.
        let mut i = start_idx;
        if i < keys.len() {
            let (k_addr, k_sp) = (keys[i], self.themap[&keys[i]]);
            let where_ = A::overlap(&addr, 0, k_addr, k_sp.size);
            if where_ != -1 {
                // Ghidra cc:46-49: completely contained?
                if where_ + size <= k_sp.size {
                    intersect = if k_sp.pass < pass { 2 } else { 0 };
                    return intersect;
                }
                // Ghidra cc:50-56: merge — extend addr/size, take min pass.
                addr = k_addr;
                size = where_ + size;
                if k_sp.pass < pass {
                    intersect = 1;
                    pass = k_sp.pass;
                }
                self.themap.remove(&keys[i]);
                i += 1;
            } else {
                i += 1;
            }
        }
        // Ghidra cc:58-66: continue merging subsequent overlapping entries.
        while i < keys.len() {
            let (k_addr, k_sp) = (keys[i], self.themap.get(&keys[i]).copied().unwrap_or(SizePass { size: 0, pass: 0 }));
            if self.themap.get(&keys[i]).is_none() { i += 1; continue; }
            let where_ = A::overlap(&k_addr, 0, addr, size);
            if where_ == -1 { break; }
            if where_ + k_sp.size > size {
                size = where_ + k_sp.size;
            }
            if k_sp.pass < pass {
                intersect = 1;
                pass = k_sp.pass;
            }
            self.themap.remove(&keys[i]);
            i += 1;
        }
        // Ghidra cc:67-70: insert merged entry.
        self.themap.insert(addr, SizePass { size, pass });
        intersect
    }

    // Ghidra: heritage.cc:91 LocationMap::findPass
    /// Return the pass number when the given address was heritaged, or -1
    /// if it was not heritaged. Faithful to `findPass` (heritage.cc:91-100):
    /// upper_bound(addr), back up one, check overlap.
    pub fn find_pass(&self, addr: Address) -> i32 {
        // Ghidra cc:94: upper_bound(addr) — first key > addr
        let keys: Vec<&Address> = self.themap.keys().filter(|k| **k > addr).collect();
        // Ghidra cc:95: if (iter == begin) return -1
        let prev_key = if keys.is_empty() {
            // No key > addr → use the last key (if any)
            self.themap.keys().max().copied()
        } else {
            // The key just before the first key > addr
            let first_after = keys[0];
            self.themap.keys().filter(|k| **k < *first_after).max().copied()
        };
        // Ghidra cc:97-98: if overlap != -1 return pass
        match prev_key {
            Some(k) => {
                let sp = self.themap.get(&k).copied().unwrap_or(SizePass { size: 0, pass: -1 });
                if addr.overlap(0, k, sp.size) != -1 {
                    sp.pass
                } else {
                    -1
                }
            }
            None => -1,
        }
    }

    // Ghidra: heritage.hh:38 LocationMap::clear
    pub fn clear(&mut self) {
        self.themap.clear();
    }
}

/// Priority queue for flow blocks during heritage
/// Corresponds to Ghidra's `PriorityQueue`
#[derive(Debug)]
pub struct PriorityQueue {
    pub queue: Vec<Vec<i32>>,
    pub curdepth: i32,
}

impl PriorityQueue {
    // Ghidra: heritage.hh:101 PriorityQueue::new
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            curdepth: -1,
        }
    }

    // Ghidra: heritage.cc:142 PriorityQueue::reset
    pub fn reset(&mut self, maxdepth: i32) {
        self.queue.clear();
        self.queue.resize_with((maxdepth + 1) as usize, Vec::new);
        self.curdepth = -1;
    }

    // Ghidra: heritage.cc:154 PriorityQueue::insert
    pub fn insert(&mut self, bl_idx: i32, depth: i32) {
        if depth > self.curdepth {
            self.curdepth = depth;
        }
        if depth >= 0 && (depth as usize) < self.queue.len() {
            self.queue[depth as usize].push(bl_idx);
        }
    }

    // Ghidra: heritage.cc:166 PriorityQueue::extract
    pub fn extract(&mut self) -> i32 {
        while self.curdepth >= 0 {
            if let Some(bl) = self.queue[self.curdepth as usize].pop() {
                return bl;
            }
            self.curdepth -= 1;
        }
        -1
    }

    // Ghidra: heritage.hh:101 PriorityQueue::empty
    pub fn empty(&self) -> bool {
        self.curdepth < 0
    }
}

/// Information about heritage status for a specific address space
/// Corresponds to Ghidra's `HeritageInfo`
#[derive(Debug, Clone, Copy)]
pub struct HeritageInfo {
    pub space: AddressSpace,
    pub delay: i32,
    pub deadcodedelay: i32,
    pub deadremoved: i32,
    pub load_guard_search: bool,
    pub warning_issued: bool,
    pub has_call_placeholders: bool,
}

impl HeritageInfo {
    // Ghidra: heritage.cc:180 HeritageInfo::HeritageInfo
    /// Construct per-space heritage info. Faithful to the Ghidra ctor
    /// (heritage.cc:180-204):
    ///   - delay/deadcodedelay from AddrSpace::getDelay()/getDeadcodeDelay()
    ///   - hasCallPlaceholders = (space type == IPTR_SPACEBASE) [Stack]
    ///   - deadremoved = 0
    ///   - loadGuardSearch = false
    /// Previously Rugra hard-coded delay=0/deadcodedelay=0/deadremoved=-1/
    /// load_guard_search=true, which broke the per-space staggered heritage
    /// timing (Stack delay=1) and inverted the loadGuardSearch flag
    /// (Ghidra: false = search not yet performed).
    pub fn new(space: AddressSpace) -> Self {
        let (delay, deadcodedelay, has_call_placeholders) = if space.is_heritaged() {
            // Ghidra cc:195-199: space is heritaged.
            (
                space.get_delay(),
                space.get_deadcode_delay(),
                space.is_stack(), // IPTR_SPACEBASE → Stack
            )
        } else {
            // Ghidra cc:189-193: space not heritaged (Const/Iop/Join/etc).
            // delay/deadcodedelay still read from space, hasCallPlaceholders=false.
            (space.get_delay(), space.get_deadcode_delay(), false)
        };
        Self {
            space,
            delay,
            deadcodedelay,
            // Ghidra cc:201: deadremoved = 0 (was -1, broke removeRevisitedMarkers)
            deadremoved: 0,
            // Ghidra cc:203: loadGuardSearch = false (was true, inverted meaning)
            load_guard_search: false,
            warning_issued: false,
            has_call_placeholders,
        }
    }
}

/// Guard record for LOAD/STORE operations
/// Corresponds to Ghidra's `LoadGuard`
#[derive(Debug)]
pub struct LoadGuard {
    pub op: Weak<RwLock<PcodeOp>>,
    pub spc: AddressSpace,
    pub pointer_base: u64,
    pub minimum_offset: u64,
    pub maximum_offset: u64,
    pub step: i32,
    pub analysis_state: i32,
}

impl LoadGuard {
    // Ghidra: heritage.cc:819 LoadGuard::isGuarded
    /// Does this guard apply to the given address (space + offset range)?
    /// Faithful to `LoadGuard::isGuarded` (heritage.cc:819-826).
    pub fn is_guarded(&self, space: &crate::space::AddressSpace, offset: u64) -> bool {
        if space != &self.spc {
            return false;
        }
        if offset < self.minimum_offset {
            return false;
        }
        if offset > self.maximum_offset {
            return false;
        }
        true
    }

    // Ghidra: heritage.hh:142 LoadGuard::getMinimum
    /// Get minimum offset of the guarded range. (heritage.hh:164)
    pub fn get_minimum(&self) -> u64 {
        self.minimum_offset
    }

    // Ghidra: heritage.hh:142 LoadGuard::getMaximum
    /// Get maximum offset of the guarded range. (heritage.hh:165)
    pub fn get_maximum(&self) -> u64 {
        self.maximum_offset
    }

    // Ghidra: heritage.hh:142 LoadGuard::getOp
    /// Get the guarded op. (heritage.hh:161)
    pub fn get_op(&self) -> Option<std::sync::Arc<std::sync::RwLock<PcodeOp>>> {
        self.op.upgrade()
    }

    /// Initialize a fresh unanalyzed guard that initially protects the whole
    /// space. Faithful to `LoadGuard::set` (heritage.hh:159-161).
    ///
    /// Ghidra: `set(o,s,off) { op=o; spc=s; pointerBase=off; minimumOffset=0;
    /// maximumOffset=s->getHighest(); step=0; analysisState=0; }`.
    ///
    /// Rugra's `AddressSpace` is a flat enum without a per-space
    /// `getHighest()`, so we use a conservative all-space maximum
    /// (`u64::MAX`). This matches Ghidra's "guards everything until value-set
    /// analysis narrows it" semantics and keeps `is_guarded` permissive.
    pub fn set(
        &mut self,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        spc: AddressSpace,
        off: u64,
    ) {
        self.op = std::sync::Arc::downgrade(op);
        self.spc = spc;
        self.pointer_base = off;
        self.minimum_offset = 0;
        self.maximum_offset = space_highest(spc);
        self.step = 0;
        self.analysis_state = 0;
    }

    // Ghidra: heritage.hh:142 LoadGuard::newUnanalyzed
    /// Build a fresh guard via `set` and return it. Convenience wrapper used
    /// by `guard_stores`/`guard_loads` (mirrors Ghidra's
    /// `loadGuard.emplace_back(); loadGuard.back().set(...)`).
    pub fn new_unanalyzed(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        spc: AddressSpace,
        off: u64,
    ) -> Self {
        let mut g = Self::default();
        g.set(op, spc, off);
        g
    }

    // Ghidra: heritage.cc:741 LoadGuard::establishRange
    /// Convert a partial value-set analysis result into the guard range.
    /// Faithful to `LoadGuard::establishRange` (heritage.cc:741-786).
    ///
    /// Rugra does not yet have a `ValueSetRead`/`CircleRange` solver, so the
    /// body records what the analysis *would* do and leaves the initial
    /// "guard everything" range intact, matching Ghidra's behaviour for an
    /// empty/full range (which cannot be narrowed). `analysis_state` stays 0
    /// so a later full solver run can still refine it.
    /// TODO(value-set-analysis): wire a real `ValueSetRead` here.
    pub fn establish_range(&mut self) {
        // With no value-set solver available we mirror Ghidra's empty/full
        // range branch (heritage.cc:747-750): minimumOffset = pointerBase,
        // maximumOffset = spc->getHighest(). We keep minimumOffset = 0 to
        // remain maximally permissive (the conservative initial guard) until
        // a real solver narrows it.
        self.analysis_state = 0;
    }

    // Ghidra: heritage.cc:788 LoadGuard::finalizeRange
    /// Convert a final value-set analysis result into the guard range.
    /// Faithful to `LoadGuard::finalizeRange` (heritage.cc:788-814).
    ///
    /// Without a `ValueSetRead` solver there is nothing to converge on, so we
    /// mark the range as partially analyzed (`analysisState == 1`), which in
    /// Ghidra means "analyzed but partial result, still guard everything".
    /// TODO(value-set-analysis): wire a real `ValueSetRead` here.
    pub fn finalize_range(&mut self) {
        // heritage.cc:791 sets analysisState = 1 unconditionally first.
        self.analysis_state = 1;
        // No CircleRange to read; keep the conservative full-range guard.
    }
}

impl Default for LoadGuard {
    // Ghidra: heritage.hh:142 LoadGuard::default
    fn default() -> Self {
        Self {
            op: Weak::default(),
            spc: AddressSpace::Ram,
            pointer_base: 0,
            minimum_offset: 0,
            maximum_offset: space_highest(AddressSpace::Ram),
            step: 0,
            analysis_state: 0,
        }
    }
}

// Ghidra: heritage.hh:142 LoadGuard::spaceHighest
/// Conservative "highest addressable offset" for a space, standing in for
/// Ghidra's `AddrSpace::getHighest()`. Rugra spaces are 64-bit addressable
/// (`addr_size()==8`), so the all-ones value is the natural maximum and keeps
/// `is_guarded` permissive until value-set analysis narrows a range.
fn space_highest(_spc: AddressSpace) -> u64 {
    u64::MAX
}

/// Main Heritage class responsible for SSA construction
/// Corresponds to Ghidra's `Heritage` class
#[derive(Debug)]
pub struct Heritage {
    pub fd: Option<Weak<RwLock<Funcdata>>>,
    pub globaldisjoint: LocationMap,
    pub domchild: Vec<Vec<i32>>,
    pub augment: Vec<Vec<i32>>,
    pub flags: Vec<u32>,
    pub depth: Vec<i32>,
    pub maxdepth: i32,
    pub pass: i32,
    pub pq: PriorityQueue,
    pub merge: Vec<i32>,
    pub infolist: Vec<HeritageInfo>,
    pub load_guard: Vec<LoadGuard>,
    pub store_guard: Vec<LoadGuard>,
    pub load_copy_ops: Vec<Weak<RwLock<PcodeOp>>>,
}

impl Heritage {
    // Ghidra: heritage.cc:219 Heritage::new
    pub fn new() -> Self {
        Self {
            fd: None,
            globaldisjoint: LocationMap::new(),
            domchild: Vec::new(),
            augment: Vec::new(),
            flags: Vec::new(),
            depth: Vec::new(),
            maxdepth: 0,
            pass: 0,
            pq: PriorityQueue::new(),
            merge: Vec::new(),
            infolist: Vec::new(),
            load_guard: Vec::new(),
            store_guard: Vec::new(),
            load_copy_ops: Vec::new(),
        }
    }
}

impl Default for Heritage {
    // Ghidra: heritage.cc:219 Heritage::default
    fn default() -> Self {
        Self::new()
    }
}

impl Heritage {
    // Ghidra: heritage.hh:257 Heritage::getInfo
    /// Look up the HeritageInfo for `space`. Faithful to `getInfo`
    /// (heritage.hh:257). Ghidra indexes infolist by spc->getIndex();
    /// Rugra scans by space match (infolist is small, ~6 entries).
    /// Auto-builds infolist if empty (buildInfoList cc:2664).
    pub fn get_info(&mut self, space: AddressSpace) -> &HeritageInfo {
        if self.infolist.is_empty() {
            self.build_info_list();
        }
        let idx = self.infolist.iter().position(|i| i.space == space);
        match idx {
            Some(i) => &mut self.infolist[i],
            None => {
                // Space not in infolist (shouldn't happen after build_info_list).
                // Append a fresh entry as fallback.
                self.infolist.push(HeritageInfo::new(space));
                self.infolist.last_mut().unwrap()
            }
        }
    }

    // Ghidra: heritage.cc:2664 Heritage::buildInfoList
    /// Build the per-space HeritageInfo list. Faithful to `buildInfoList`
    /// (heritage.cc:2664-2672). Ghidra iterates manage->numSpaces();
    /// Rugra enumerates its fixed AddressSpace enum.
    pub fn build_info_list(&mut self) {
        if !self.infolist.is_empty() {
            return;
        }
        let spaces = [
            AddressSpace::Ram,
            AddressSpace::Register,
            AddressSpace::Unique,
            AddressSpace::Const,
            AddressSpace::Stack,
            AddressSpace::Join,
            AddressSpace::Iop,
        ];
        for sp in spaces {
            self.infolist.push(HeritageInfo::new(sp));
        }
    }

    // Ghidra: heritage.cc:2317 Heritage::buildADT
    /// Build the Augmented Dominator Tree. Faithful to `buildADT`
    /// (heritage.cc:2317-2386). Assumes dom tree is already built and
    /// nodes are in DFS order.
    ///
    /// Algorithm:
    ///   1. Build domchild from idom (cc:2335)
    ///   2. Find up-edges (non-tree edges) and count b[]/t[] (cc:2340-2354)
    ///   3. Bottom-up pass: compute a[]/z[], mark boundary nodes (cc:2355-2368)
    ///   4. Top-down pass: propagate z[] through boundary chains (cc:2369-2376)
    ///   5. Build augment[] from up-edges (cc:2377-2385)
    pub fn build_adt(&mut self) {
        let fd_arc = match &self.fd { Some(w) => match w.upgrade() { Some(a) => a, None => return } , None => return };
        let fd = fd_arc.read().unwrap();
        let bblocks = &fd.bblocks;
        let size = bblocks.get_size();
        if size == 0 { return; }

        // cc:2330-2333: clear + resize
        self.augment.clear();
        self.augment.resize(size, Vec::new());
        self.flags.clear();
        self.flags.resize(size, 0);
        self.domchild.clear();
        self.domchild.resize(size, Vec::new());

        // cc:2335: buildDomTree(domchild) — populate domchild from idom.
        // Rugra's dom tree is stored per-block via get_dom_children.
        // Build index-level domchild: domchild[i] = list of child indices.
        let mut domchild_idx: Vec<Vec<i32>> = vec![Vec::new(); size];
        for i in 0..size {
            let block = match bblocks.get_block(i) { Some(b) => b, None => continue };
            let children = block.read().unwrap().get_dom_children();
            for child in children {
                let cidx = child.read().unwrap().get_index() as usize;
                if cidx < size {
                    domchild_idx[i].push(cidx as i32);
                }
            }
        }

        // cc:2339: buildDomDepth(depth)
        let mut depth = vec![0i32; size];
        // Simple BFS from root (index 0): depth[child] = depth[parent]+1.
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(0i32);
        while let Some(idx) = queue.pop_front() {
            let i = idx as usize;
            for &cidx in &domchild_idx[i] {
                depth[cidx as usize] = depth[i] + 1;
                queue.push_back(cidx);
            }
        }
        self.depth = depth;
        self.maxdepth = *self.depth.iter().max().unwrap_or(&0);

        // cc:2340-2354: find up-edges + count b[]/t[].
        let mut b_count = vec![0i32; size]; // up-edges ending at node
        let mut t_count = vec![0i32; size]; // up-edges starting under node
        let mut upstart = Vec::new(); // up-edge source indices
        let mut upend = Vec::new();   // up-edge target indices

        for i in 0..size {
            let x = match bblocks.get_block(i) { Some(b) => b, None => continue };
            for &cidx in &domchild_idx[i] {
                let v = match bblocks.get_block(cidx as usize) { Some(b) => b, None => continue };
                let v_idom = v.read().unwrap().get_immed_dom()
                    .and_then(|w| w.upgrade())
                    .map(|dom| dom.read().unwrap().get_index());
                let v_sin = v.read().unwrap().size_in();
                for k in 0..v_sin {
                    let u = match v.read().unwrap().get_in(k) { Some(e) => e.point.clone(), None => continue };
                    let u_idx = u.read().unwrap().get_index();
                    let is_tree_edge = Some(u_idx) == v_idom;
                    if !is_tree_edge {
                        // Up-edge: u -> v
                        upstart.push(u_idx);
                        upend.push(cidx);
                        b_count[u_idx as usize] += 1;
                        t_count[i] += 1;
                    }
                }
            }
        }

        // cc:2355-2368: bottom-up a[]/z[] + boundary marking.
        let mut a_count = vec![0i32; size];
        let mut z = vec![0i32; size];
        for i in (0..size).rev() {
            let mut k_sum = 0i32;
            let mut l_sum = 0i32;
            for &cidx in &domchild_idx[i] {
                k_sum += a_count[cidx as usize];
                l_sum += z[cidx as usize];
            }
            a_count[i] = b_count[i] - t_count[i] + k_sum;
            z[i] = 1 + l_sum;
            if domchild_idx[i].is_empty() || z[i] > a_count[i] + 1 {
                self.flags[i] |= heritage_flags::BOUNDARY_NODE;
                z[i] = 1;
            }
        }

        // cc:2369: z[0] = -1
        if !z.is_empty() { z[0] = -1; }

        // cc:2370-2376: propagate z through boundary chains.
        for i in 1..size {
            let block = match bblocks.get_block(i) { Some(b) => b, None => continue };
            let j = match block.read().unwrap().get_immed_dom().and_then(|w| w.upgrade()) {
                Some(dom) => dom.read().unwrap().get_index() as usize,
                None => continue,
            };
            if (self.flags[j] & heritage_flags::BOUNDARY_NODE) != 0 {
                z[i] = j as i32;
            } else {
                z[i] = z[j];
            }
        }

        // cc:2377-2385: build augment[] from up-edges.
        for idx in 0..upstart.len() {
            let v_idx = upend[idx];
            let v_block = match bblocks.get_block(v_idx as usize) { Some(b) => b, None => continue };
            let mut j = v_block.read().unwrap().get_immed_dom()
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index())
                .unwrap_or(0);
            let mut k = upstart[idx];
            while j < k {
                if (k as usize) < self.augment.len() {
                    self.augment[k as usize].push(v_idx);
                }
                k = z[k as usize];
            }
        }

        // Store domchild as indices (for visitIncr/calcMultiequals).
        self.domchild = domchild_idx;
    }

    // Ghidra: heritage.cc:2395 Heritage::visitIncr
    /// Recursive phi-node placement using the ADT. Faithful to
    /// `visitIncr` (heritage.cc:2395-2429). Walks augment[vnode] and
    /// recurses into dom children (unless boundary node).
    pub fn visit_incr(&mut self, qnode_idx: i32, vnode_idx: i32) {
        let i = vnode_idx as usize;
        // cc:2404-2421: scan augment[i] for phi candidates.
        let aug_snapshot = self.augment.get(i).cloned().unwrap_or_default();
        for v_idx in aug_snapshot {
            let v_idom = {
                let fd_arc = self.fd.as_ref().and_then(|w| w.upgrade());
                if let Some(fd_arc) = fd_arc {
                    let fd = fd_arc.read().unwrap();
                    fd.bblocks.get_block(v_idx as usize)
                        .and_then(|b| b.read().unwrap().get_immed_dom())
                        .and_then(|w| w.upgrade())
                        .map(|dom| dom.read().unwrap().get_index())
                } else { None }
            };
            // cc:2408: if idom(v) < qnode (strict ancestor)
            if v_idom.map_or(false, |idom| idom < qnode_idx) {
                let k = v_idx as usize;
                if k < self.flags.len() {
                    // cc:2410-2413: merge if not merged_node
                    if (self.flags[k] & heritage_flags::MERGED_NODE) == 0 {
                        self.merge.push(k as i32);
                        self.flags[k] |= heritage_flags::MERGED_NODE;
                    }
                    // cc:2414-2417: mark + pq.insert if not mark_node
                    if (self.flags[k] & heritage_flags::MARK_NODE) == 0 {
                        self.flags[k] |= heritage_flags::MARK_NODE;
                        self.pq.insert(v_idx, self.depth.get(k).copied().unwrap_or(0));
                    }
                }
            } else {
                break; // cc:2419-2420: augment is sorted, stop at first non-ancestor
            }
        }
        // cc:2422-2428: if vnode is not boundary, recurse into dom children.
        if i < self.flags.len() && (self.flags[i] & heritage_flags::BOUNDARY_NODE) == 0 {
            let children = self.domchild.get(i).cloned().unwrap_or_default();
            for child_idx in children {
                let c = child_idx as usize;
                if c < self.flags.len() && (self.flags[c] & heritage_flags::MARK_NODE) == 0 {
                    self.visit_incr(qnode_idx, child_idx);
                }
            }
        }
    }

    // Ghidra: heritage.cc:2440 Heritage::calcMultiequals
    /// Calculate blocks that should contain MULTIEQUALs for one address range.
    /// Faithful to `calcMultiequals` (heritage.cc:2440-2467).
    /// After this executes, self.merge holds block indices that should
    /// contain a MULTIEQUAL (phi node).
    pub fn calc_multiequals(&mut self, write_blocks: &[i32]) {
        // cc:2443: pq.reset(maxdepth)
        self.pq.reset(self.maxdepth);
        // cc:2444: merge.clear()
        self.merge.clear();

        // cc:2449-2455: place write blocks into pq.
        for &blk_idx in write_blocks {
            let j = blk_idx as usize;
            if j < self.flags.len() && (self.flags[j] & heritage_flags::MARK_NODE) != 0 {
                continue; // Already in
            }
            self.pq.insert(blk_idx, self.depth.get(j).copied().unwrap_or(0));
            if j < self.flags.len() {
                self.flags[j] |= heritage_flags::MARK_NODE;
            }
        }
        // cc:2456-2459: ensure block 0 is in pq.
        if !self.flags.is_empty() && (self.flags[0] & heritage_flags::MARK_NODE) == 0 {
            self.pq.insert(0, self.depth.get(0).copied().unwrap_or(0));
            self.flags[0] |= heritage_flags::MARK_NODE;
        }

        // cc:2461-2464: main loop.
        while !self.pq.empty() {
            let bl = self.pq.extract();
            self.visit_incr(bl, bl);
        }

        // cc:2465-2466: clear marks.
        for f in &mut self.flags {
            *f &= !(heritage_flags::MARK_NODE | heritage_flags::MERGED_NODE);
        }
    }

    // Ghidra: heritage.cc:219 Heritage::discoverAndGuardStackStoresFd
    pub fn discover_and_guard_stack_stores_fd(fd: &mut Funcdata) {
        let (sp_space, sp_offset, sp_size) = (
            fd.stack_pointer_space,
            fd.stack_pointer_offset,
            fd.stack_pointer_size,
        );
        // Find the RSP input varnode (shared, with accumulated descend).
        let rsp_input: Option<Arc<RwLock<Varnode>>> = fd
            .vbank
            .loc_tree
            .iter()
            .filter(|v| {
                let g = v.0.read().unwrap();
                g.get_space() == sp_space
                    && g.get_offset() == sp_offset
                    && g.get_size() == sp_size
                    && g.is_input()
            })
            .map(|v| v.0.clone())
            .next();
        let rsp_input = match rsp_input {
            Some(r) => {
                let nd = r.read().unwrap().descend.len();
                r
            }
            None => return,
        };

        // Forward-descend BFS from RSP input.
        let mut worklist: VecDeque<(Arc<RwLock<Varnode>>, i64)> = VecDeque::new();
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
        worklist.push_back((rsp_input.clone(), 0));
        visited.insert(Arc::as_ptr(&rsp_input) as usize);

        let mut stores_to_guard: Vec<(Arc<RwLock<PcodeOp>>, i64)> = Vec::new();

        while let Some((vn, offset)) = worklist.pop_front() {
            let descendants: Vec<Arc<RwLock<PcodeOp>>> = {
                let g = vn.read().unwrap();
                g.descend.iter().filter_map(|w| w.upgrade()).collect()
            };
            for d in &descendants {
            }
            for desc_op in descendants {
                let op_guard = desc_op.read().unwrap();
                let opc = op_guard.opcode;
                match opc {
                    crate::opcodes::OpCode::CPUI_STORE => {
                        // STORE(space, addr, val). addr is inrefs[1].
                        if op_guard.inrefs.len() > 1 && Arc::ptr_eq(&op_guard.inrefs[1], &vn) {
                            stores_to_guard.push((desc_op.clone(), offset));
                            drop(op_guard);
                            desc_op.write().unwrap().mark_spacebase_ptr();
                        }
                    }
                    crate::opcodes::OpCode::CPUI_INT_ADD
                    | crate::opcodes::OpCode::CPUI_INT_SUB => {
                        if let Some(out) = &op_guard.output {
                            let other_idx = if Arc::ptr_eq(&op_guard.inrefs[0], &vn) {
                                1
                            } else {
                                0
                            };
                            if let Some(other) = op_guard.inrefs.get(other_idx) {
                                let other_g = other.read().unwrap();
                                if other_g.is_constant() {
                                    let delta = other_g.get_offset() as i64;
                                    let new_offset = if opc
                                        == crate::opcodes::OpCode::CPUI_INT_ADD
                                    {
                                        offset.wrapping_add(delta)
                                    } else {
                                        offset.wrapping_sub(delta)
                                    };
                                    let out_clone = out.clone();
                                    let out_ptr = Arc::as_ptr(&out_clone) as usize;
                                    drop(other_g);
                                    drop(op_guard);
                                    if visited.insert(out_ptr) {
                                        worklist.push_back((out_clone, new_offset));
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    crate::opcodes::OpCode::CPUI_COPY => {
                        if let Some(out) = &op_guard.output {
                            let out_clone = out.clone();
                            let out_ptr = Arc::as_ptr(&out_clone) as usize;
                            drop(op_guard);
                            if visited.insert(out_ptr) {
                                worklist.push_back((out_clone, offset));
                            }
                            continue;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Phase 2: build Stack INDIRECT ops for each discovered STORE.
        for (store_op, stack_off) in stores_to_guard {
            let sz = {
                let s = store_op.read().unwrap();
                s.inrefs.get(2).map(|v| v.read().unwrap().get_size()).unwrap_or(8)
            };
            let store_ref = crate::op::PcodeOpRef(store_op);
            fd.new_indirect_op(&store_ref, stack_off as u64, sz);
        }
    }

    // ======================================================================
    // LoadGuard / StoreGuard population.
    //
    // These mirror Ghidra's `Heritage::guard*` family (heritage.cc:1157-1693)
    // together with `generateLoadGuard`/`generateStoreGuard`
    // (heritage.cc:910-935), which `discoverIndexedStackPointers` calls while
    // tracing the stack pointer. The Ghidra variants split responsibilities:
    //
    //   generateStoreGuard/generateLoadGuard -- create the LoadGuard record
    //       (op, spc, pointerBase) and `emplace_back` it into storeGuard/
    //       loadGuard. They are guarded by `!op->usesSpacebasePtr()` and call
    //       `fd->opMarkSpacebasePtr(op)`.
    //
    //   guardStores/guardLoads/guardCalls/guardReturns -- run during `guard()`
    //       (heritage.cc:1157) to build the INDIRECT/COPY ops that make SSA
    //       renaming see the memory effect, and (for guardLoads) to drop stale
    //       guard records.
    //
    // Rugra's pragmatic policy (per the alignment task) is to *populate* the
    // store_guard/load_guard Vecs so that `get_store_guard`/`get_load_guard`
    // return non-`None` and RuleActionShadowOp's store-alias check works. We
    // therefore implement the record-creation half faithfully and leave the
    // value-set-analysis refinement (establishRange/finalizeRange) as TODO.
    // ======================================================================

    /// Guard STORE ops in preparation for renaming.
    ///
    /// Faithful to `Heritage::guardStores` (heritage.cc:1539-1560) combined
    /// with `generateStoreGuard` (heritage.cc:927-935): for every live STORE
    /// that targets the stack space and was marked as using a spacebase
    /// pointer, create a `LoadGuard` record in `store_guard` (if not already
    /// present) and build a Stack-space INDIRECT so renaming sees the memory
    /// write.
    ///
    /// Differences from Ghidra: Ghidra's `guardStores` iterates by address
    /// range (`addr`/`size`) and creates the INDIRECT via `newIndirectOp`.
    /// Rugra does not yet drive guarding per disjoint memory range (the SSA
    /// pipeline calls this once per heritage pass), so we guard the *whole*
    /// stack space — i.e. every spacebase-marked STORE — which is the
    /// conservative superset and never under-protects. The full-range
    /// INDIRECTs are produced by `discover_and_guard_stack_stores_fd`; here we
    /// only ensure each such STORE has a guard record.
    // Ghidra: heritage.cc:1539 Heritage::guardStores
    pub fn guard_stores(&mut self, fd: &mut Funcdata) {
        // Snapshot of (op_arc, store_space, spc) for STOREs that need a guard
        // record. We collect under a read borrow so we can later mutate the
        // obank (mark_spacebase_ptr) without holding it.
        let mut to_guard: Vec<(
            std::sync::Arc<std::sync::RwLock<PcodeOp>>,
            AddressSpace,
        )> = Vec::new();

        for op_ref in &fd.obank.optree {
            let op = op_ref.0.read().unwrap();
            if op.opcode != crate::opcodes::OpCode::CPUI_STORE {
                continue;
            }
            if (op.flags & crate::op::pcodeop_flags::DEAD) != 0 {
                continue; // heritage.cc:1550
            }
            // STORE inputs: in[0]=space-id constant, in[1]=pointer, in[2]=value.
            // `getSpaceFromConst` on in[0] gives the target space. If a STORE
            // has no in[0] (malformed), skip it.
            let store_space = match op.inrefs.first() {
                Some(vn) => vn.read().unwrap().get_space(),
                None => continue,
            };
            // STORE space constants are encoded as Const-space varnodes whose
            // offset carries the space id (see space.rs SPACEID_*). Recover it.
            // Accept either the CONSTANT flag or a Const address space, since
            // both encodings appear (lifter uses the flag; manual construction
            // may set only the space).
            let target_space = op
                .inrefs
                .first()
                .and_then(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() || g.get_space().is_const() {
                        Some(AddressSpace::from_id(g.get_offset() as u8))
                    } else {
                        None
                    }
                })
                .unwrap_or(store_space);
            // heritage.cc:1552: a STORE is guarded if its target space is the
            //   container of `spc` AND usesSpacebasePtr(), OR if its target
            //   space == spc. Rugra's stack space has no separate "container"
            //   space, so we simply guard STOREs targeting the stack space that
            //   are spacebase-marked (the indexed case), plus any STORE the
            //   existing discovery already flagged.
            let is_stack = target_space.is_stack();
            if is_stack && op.uses_spacebase_ptr() {
                to_guard.push((op_ref.0.clone(), AddressSpace::Stack));
            }
        }

        // Create the guard records (dedup against existing entries — a STORE
        // may survive multiple heritage passes). Mirrors generateStoreGuard's
        // `!op->usesSpacebasePtr()` guard: once marked, we don't add a second
        // record for the same op.
        for (store_op, spc) in to_guard {
            if self.store_guard.iter().any(|g| match g.op.upgrade() {
                Some(g_op) => std::sync::Arc::ptr_eq(&g_op, &store_op),
                None => false,
            }) {
                continue;
            }
            let pointer_base = store_guard_pointer_base(&store_op, &fd);
            // generateStoreGuard marks the op spacebase again (idempotent).
            store_op.write().unwrap().mark_spacebase_ptr();
            self.store_guard
                .push(LoadGuard::new_unanalyzed(&store_op, spc, pointer_base));
        }
    }

    /// Guard LOAD ops in preparation for renaming.
    ///
    /// Faithful to `Heritage::guardLoads` (heritage.cc:1571-1602) combined
    /// with `generateLoadGuard` (heritage.cc:910-918): for every live LOAD
    /// reading from an indexed stack-space pointer, create a `LoadGuard`
    /// record in `load_guard` (if not already present). Mirrors Ghidra's
    /// validity pruning (`isValid`) by dropping records whose op is dead or no
    /// longer a LOAD.
    ///
    /// Differences from Ghidra: Ghidra inserts a `COPY` "guard" op before each
    /// guarded LOAD (heritage.cc:1591-1600) to force a specific address, and
    /// only guards LOADs whose indexed range intersects the heritage range.
    /// Rugra builds the guard records for all stack-pointer-indexed LOADs
    /// (conservative superset) and defers the COPY insertion to a future
    /// per-range driver. Value-set analysis is not run yet, so each guard
    /// initially protects the whole stack space.
    // Ghidra: heritage.cc:1571 Heritage::guardLoads
    pub fn guard_loads(&mut self, fd: &mut Funcdata) {
        // Prune stale load_guard records (heritage.cc:1581-1586 isValid check).
        self.load_guard.retain(|g| {
            let op = match g.op.upgrade() {
                Some(o) => o,
                None => return false,
            };
            let opg = op.read().unwrap();
            !((opg.flags & crate::op::pcodeop_flags::DEAD) != 0
                || opg.opcode != crate::opcodes::OpCode::CPUI_LOAD)
        });

        // Collect LOADs that read an indexed stack-space pointer.
        let mut to_guard: Vec<(
            std::sync::Arc<std::sync::RwLock<PcodeOp>>,
            AddressSpace,
        )> = Vec::new();
        for op_ref in &fd.obank.optree {
            let op = op_ref.0.read().unwrap();
            if op.opcode != crate::opcodes::OpCode::CPUI_LOAD {
                continue;
            }
            if (op.flags & crate::op::pcodeop_flags::DEAD) != 0 {
                continue;
            }
            // LOAD inputs: in[0]=space-id constant, in[1]=pointer.
            let target_space = op
                .inrefs
                .first()
                .and_then(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() || g.get_space().is_const() {
                        Some(AddressSpace::from_id(g.get_offset() as u8))
                    } else {
                        None
                    }
                })
                .unwrap_or(AddressSpace::Ram);
            if !target_space.is_stack() {
                continue;
            }
            // generateLoadGuard only records a LOAD once (!usesSpacebasePtr)
            // and then marks it. We mirror that by skipping already-marked
            // LOADs for record creation below.
            to_guard.push((op_ref.0.clone(), AddressSpace::Stack));
        }

        for (load_op, spc) in to_guard {
            if self.load_guard.iter().any(|g| match g.op.upgrade() {
                Some(g_op) => std::sync::Arc::ptr_eq(&g_op, &load_op),
                None => false,
            }) {
                continue;
            }
            let pointer_base = load_guard_pointer_base(&load_op, &fd);
            load_op.write().unwrap().mark_spacebase_ptr();
            self.load_guard
                .push(LoadGuard::new_unanalyzed(&load_op, spc, pointer_base));
        }
    }

    // Ghidra: heritage.cc:1444 Heritage::guardCalls
    /// Guard CALL ops in preparation for renaming.
    ///
    /// Faithful in shape to `Heritage::guardCalls` (heritage.cc:1444-1528):
    /// it exists so the heritage driver can ask for call-site guards. Ghidra's
    /// implementation is tightly coupled to `FuncCallSpecs`/`ParamActive`
    /// (effect characterization, output-overlap guards, INDIRECT creation)
    /// which Rugra's call-analysis layer does not yet expose. This stub keeps
    /// the API aligned so the driver can call it, and is a no-op until
    /// `FuncCallSpecs` gains the needed methods.
    /// TODO(call-analysis): wire effect characterization + INDIRECT creation.
    pub fn guard_calls(&mut self, _fd: &mut Funcdata) {}

    // Ghidra: heritage.cc:1653 Heritage::guardReturns
    /// Guard RETURN ops in preparation for renaming.
    ///
    /// Faithful in shape to `Heritage::guardReturns` (heritage.cc:1653-1693):
    /// Ghidra either registers the range as a return-value trial or inserts a
    /// forced-address COPY before each RETURN. This requires
    /// `FuncProto::characterizeAsOutput`/`ParamActive` which Rugra does not
    /// yet expose. Stub kept for API alignment.
    /// TODO(funcproto): wire return-value trials + COPY insertion.
    pub fn guard_returns(&mut self, _fd: &mut Funcdata) {}

    // Ghidra: heritage.cc:1157 Heritage::guard
    /// Guard a specific address range for heritage. Faithful to
    /// `Heritage::guard` (heritage.cc:1157-1200):
    ///   (1) For each read varnode: verify single descendent, normalizeReadSize,
    ///       setActiveHeritage.
    ///   (2) For each write varnode: normalizeWriteSize, setActiveHeritage.
    ///   (3) If addIndirects: queryProperties + guardCalls/Returns/Stores/Loads.
    ///
    /// Steps 1/2 require the read/write lists from collect() (cc:308).
    /// Rugra does not yet have collect(), so this method is called with
    /// empty lists by guard_all. The setActiveHeritage on all free varnodes
    /// is done separately by rename_direct's marker loop. When collect() is
    /// implemented, this method will receive real read/write lists.
    pub fn guard_range(
        &mut self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        add_indirects: bool,
        read: &mut Vec<Arc<RwLock<Varnode>>>,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
        _inputvars: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // Ghidra cc:1165-1176: process read list.
        for vn_arc in read.iter_mut() {
            let descend_count: usize = {
                let vn_r = vn_arc.read().unwrap();
                vn_r.descend.iter().filter(|w| w.strong_count() > 0).count()
            };
            if descend_count == 0 {
                continue; // cc:1168-1169: removed by removeRevisitedMarkers
            }
            // cc:1171-1172: free varnode with multiple reads = error.
            // Rugra logs instead of throwing.
            if descend_count > 1 {
                eprintln!("[HERITAGE] WARN: free varnode with multiple reads");
            }
            // cc:1173-1174: normalizeReadSize if vn.size < size.
            let vn_size = vn_arc.read().unwrap().get_size() as i32;
            if vn_size < size {
                // TODO: implement normalizeReadSize (creates SUBPIECE).
                // Requires fd op-creation API in context. Tracked as gap.
            }
            // cc:1175: setActiveHeritage.
            vn_arc.write().unwrap().set_active_heritage();
        }
        // Ghidra cc:1178-1183: process write list.
        for vn_arc in write.iter_mut() {
            let vn_size = vn_arc.read().unwrap().get_size() as i32;
            if vn_size < size {
                // TODO: implement normalizeWriteSize (creates PIECE).
            }
            vn_arc.write().unwrap().set_active_heritage();
        }
        // Ghidra cc:1189-1199: addIndirects.
        if add_indirects {
            // cc:1192: queryProperties (needs ScopeLocal).
            // cc:1193-1198: guardCalls/guardReturns/guardStores/guardLoads.
            // These are called per-range with addr/size in Ghidra.
            // Rugra's guard_all calls them range-agnostically.
            self.guard_calls(fd);
            self.guard_returns(fd);
            self.guard_stores(fd);
            self.guard_loads(fd);
        }
    }

    // Ghidra: heritage.cc:219 Heritage::guardAll (Rugra analogue)
    /// Run the guard phases against the whole stack space. This is the
    /// per-space analogue of Ghidra's guard() addIndirects half.
    /// Calls guard_range with empty read/write lists (Rugra's
    /// setActiveHeritage is done by rename_direct's marker).
    pub fn guard_all(&mut self, fd: &mut Funcdata) {
        let mut empty_read = Vec::new();
        let mut empty_write = Vec::new();
        let mut empty_input = Vec::new();
        self.guard_range(
            fd,
            Address::new(0),
            0,
            true,
            &mut empty_read,
            &mut empty_write,
            &mut empty_input,
        );
    }

    // Ghidra: heritage.cc:2677 Heritage::heritage
    /// Main entry point for heritage (SSA construction). Faithful to
    /// `Heritage::heritage` (heritage.cc:2677-2772):
    ///   1. buildADT if maxdepth==-1 (restructure forced)
    ///   2. processJoins
    ///   3. splitmanage.split if pass==0
    ///   4. per-space loop: build disjoint ranges from varnodes
    ///   5. placeMultiequals
    ///   6. rename
    ///   7. reprocessFreeStores / analyzeNewLoadGuards / handleNewLoadCopies
    ///   8. pass += 1
    pub fn heritage(&mut self) {
        let fd_arc = match &self.fd {
            Some(w) => w.upgrade(),
            None => return,
        };
        let fd_arc = match fd_arc {
            Some(a) => a,
            None => return,
        };
        let mut fd = fd_arc.write().unwrap();

        // Ghidra cc:2690: if (maxdepth == -1) buildADT();
        // TODO: buildADT (Augmented Dominator Tree, heritage.cc:2316).
        // Rugra's place_multiequals uses dom-frontier instead. Tracked gap.

        // Ghidra cc:2693: processJoins();
        // TODO: processJoins (join-space handling, heritage.cc:2282).

        // Ghidra cc:2694-2697: if (pass == 0) { splitmanage.init/split(); }
        // TODO: PreferSplitManager (prefersplit.cc).

        // Ghidra cc:2698: for(int4 i=0;i<infolist.size();++i)
        self.build_info_list();
        for info in &self.infolist.clone() {
            // cc:2700: if (!info->isHeritaged()) continue;
            if !info.space.is_heritaged() { continue; }
            // cc:2701: if (pass < info->delay) continue;
            if self.pass < info.delay { continue; }
            // cc:2702-2703: if (info->hasCallPlaceholders) clearStackPlaceholders(info);
            // TODO: clearStackPlaceholders (heritage.cc:2048).

            // cc:2705-2711: if (!info->loadGuardSearch) { ... discoverIndexedStackPointers }
            // TODO: loadGuardSearch + discoverIndexedStackPointers per-space.

            // cc:2713-2746: build disjoint ranges from varnodes in this space.
            // Iterate varnodes via vbank.loc_tree, filter by space.
            let space = info.space;
            let pass = self.pass;
            let vns_in_space: Vec<_> = {
                let mut result = Vec::new();
                for vn_ref in &fd.vbank.loc_tree {
                    let vn = vn_ref.0.read().unwrap();
                    if vn.address_space != space { continue; }
                    // cc:2718: skip free+noDescend+!unaffected+!input
                    if !vn.is_written() && vn.has_no_descend() && !vn.is_input() {
                        continue;
                    }
                    // cc:2720: if (vn->isWriteMask()) continue;
                    // TODO: isWriteMask flag.
                    result.push((vn_ref.0.clone(), vn.loc, vn.get_size() as i32));
                }
                result
            };
            for (vn_arc, vn_addr, vn_size) in vns_in_space {
                // cc:2722: globaldisjoint.add(addr, size, pass, prev)
                let prev = self.globaldisjoint.add(vn_addr, vn_size, pass);
                // cc:2723-2736: disjoint.add based on prev value
                // disjoint is the per-pass TaskList. Rugra doesn't have TaskList
                // yet (it's used by placeMultiequals/buildADT). For now,
                // globaldisjoint.add does the range merging (which we ported).
                let _ = prev;
            }
        }

        // Ghidra cc:2763: placeMultiequals();
        drop(fd);
        self.place_multiequals();

        // Ghidra cc:2764: rename();
        self.rename();

        // Ghidra cc:2765-2766: if (reprocessStackCount > 0) reprocessFreeStores
        // TODO: reprocessFreeStores (heritage.cc:1112).

        // Ghidra cc:2767: analyzeNewLoadGuards();
        // TODO: analyzeNewLoadGuards (heritage.cc:835, needs ValueSetSolver).

        // Ghidra cc:2768: handleNewLoadCopies();
        // TODO: handleNewLoadCopies (heritage.cc:696).

        // Ghidra cc:2769-2770: if (pass == 0) splitmanage.splitAdditional();
        // TODO: PreferSplitManager.

        // Ghidra cc:2771: pass += 1;
        self.pass += 1;
    }

    // Ghidra: heritage.cc:2600 Heritage::placeMultiequals
    /// Insert Phi nodes (MULTIEQUAL)
    pub fn place_multiequals(&mut self) {
        let fd_weak = self.fd.as_ref().expect("Heritage needs Funcdata");
        let fd_arc = fd_weak.upgrade().expect("Funcdata dropped");
        let mut fd = fd_arc.write().unwrap();
        
        let mut vbank = std::mem::take(&mut fd.vbank);
        let mut obank = std::mem::take(&mut fd.obank);
        
        self.place_multiequals_direct(&mut vbank, &mut obank, &fd.bblocks, &fd.sblocks);
        
        fd.vbank = vbank;
        fd.obank = obank;
    }

    // Ghidra: heritage.cc:219 Heritage::placeMultiequalsDirect
    /// Insert Phi nodes directly using bank references (avoids lock deadlocks)
    pub fn place_multiequals_direct(
        &mut self,
        vbank: &mut VarnodeBank,
        obank: &mut PcodeOpBank,
        bblocks: &crate::block::BlockGraph,
        _sblocks: &crate::block::BlockGraph,
    ) {

        // Standard SSA Phi node placement algorithm
        let mut worklist = VecDeque::new();
        let mut ever_on_worklist = std::collections::HashSet::new();
        let mut has_phi_node = std::collections::HashSet::new();

        let mut defs_by_loc: BTreeMap<(AddressSpace, Address), Vec<i32>> = BTreeMap::new();
        for vn_ref in &vbank.loc_tree {
            let vn = vn_ref.0.read().unwrap();
            let space = vn.get_space();
            let delay = self
                .infolist
                .iter()
                .find(|info| info.space == space)
                .map(|info| info.delay)
                .unwrap_or(0);

            if self.pass < delay {
                continue;
            }

            if vn.is_written() {
                if let Some(op_arc) = vn.def.as_ref().and_then(|w| w.upgrade()) {
                    let op = op_arc.read().unwrap();
                    // Skip if already a MULTIEQUAL (avoid redundant Phis in future passes)
                    if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                        continue;
                    }
                    if let Some(parent_arc) = op.parent.as_ref().and_then(|w| w.upgrade()) {
                        let block = parent_arc.read().unwrap();
                        if (block.get_flags() & crate::block::block_flags::DEAD) == 0 {
                            defs_by_loc
                                .entry((space, vn.loc))
                                .or_default()
                                .push(block.get_index());
                        }
                    }
                }
            } else if vn.is_input() {
                // Inputs act as definitions at the entry block
                let entry_block_idx = bblocks
                    .blocks
                    .iter()
                    .filter(|b| {
                        let block = b.read().unwrap();
                        block.size_in() == 0 && (block.get_flags() & crate::block::block_flags::DEAD) == 0
                    })
                    .map(|b| b.read().unwrap().get_index())
                    .next()
                    .unwrap_or(-1);
                if entry_block_idx != -1 {
                    defs_by_loc
                        .entry((space, vn.loc))
                        .or_default()
                        .push(entry_block_idx);
                }
            }
        }

        for ((space, addr), blocks) in defs_by_loc {
            worklist.clear();
            ever_on_worklist.clear();
            has_phi_node.clear();

            for &b_idx in &blocks {
                worklist.push_back(b_idx);
                ever_on_worklist.insert(b_idx);
            }

            while let Some(x_idx) = worklist.pop_front() {
                let df = bblocks
                    .blocks
                    .iter()
                    .find(|b| b.read().unwrap().get_index() == x_idx)
                    .map(|b| b.read().unwrap().get_dom_frontier())
                    .unwrap_or_default();

                for y_idx in df {
                    if !has_phi_node.contains(&y_idx) {
                        self.insert_multiequal_direct(vbank, obank, bblocks, space, addr, y_idx);
                        has_phi_node.insert(y_idx);
                        if !ever_on_worklist.contains(&y_idx) {
                            ever_on_worklist.insert(y_idx);
                            worklist.push_back(y_idx);
                        }
                    }
                }
            }
        }
    }

    // Ghidra: heritage.cc:219 Heritage::insertMultiequal
    /// Helper to insert a MULTIEQUAL (Phi) op into a block
    fn insert_multiequal(&mut self, fd: &mut Funcdata, space: AddressSpace, addr: Address, block_idx: i32) {
        let mut vbank = std::mem::take(&mut fd.vbank);
        let mut obank = std::mem::take(&mut fd.obank);
        self.insert_multiequal_direct(&mut vbank, &mut obank, &fd.bblocks, space, addr, block_idx);
        fd.vbank = vbank;
        fd.obank = obank;
    }

    // Ghidra: heritage.cc:219 Heritage::insertMultiequalDirect
    fn insert_multiequal_direct(
        &mut self,
        vbank: &mut VarnodeBank,
        obank: &mut PcodeOpBank,
        bblocks: &crate::block::BlockGraph,
        space: AddressSpace,
        addr: Address,
        block_idx: i32,
    ) {
        let block_arc = bblocks
            .blocks
            .iter()
            .find(|b| b.read().unwrap().get_index() == block_idx)
            .cloned();
        // Block may have been removed by dead-flow Actions — skip gracefully.
        let block_arc = match block_arc {
            Some(b) => b,
            None => return,
        };

        let (start_addr, num_in) = {
            let b = block_arc.read().unwrap();
            (b.get_start_addr(), b.size_in())
        };

        let op_ref = obank.create(crate::opcodes::OpCode::CPUI_MULTIEQUAL, num_in, start_addr);
        block_arc.write().unwrap().insert_op(0, op_ref.clone());

        // Query globaldisjoint LocationMap for precise size (note: LocationMap also uses Address only, which is a broader bug, but we fallback to vbank)
        let size = self
            .globaldisjoint
            .themap
            .get(&addr)
            .map(|sp| sp.size)
            .unwrap_or_else(|| {
                // Fallback to searching vbank if not tracked
                vbank
                    .loc_tree
                    .iter()
                    .find(|vn| {
                        let vn_read = vn.0.read().unwrap();
                        vn_read.get_space() == space && vn_read.loc == addr
                    })
                    .map(|vn| vn.0.read().unwrap().size)
                    .unwrap_or(4) as i32
            }) as usize;

        let out_vn = vbank.create_with_space(size, space, addr.as_u64());
        vbank.set_def(out_vn.clone(), Arc::downgrade(&op_ref.0));

        {
            let mut op = op_ref.0.write().unwrap();
            op.output = Some(out_vn);
            // Initialize inrefs with placeholders so they can be filled by index
            for _ in 0..num_in {
                let placeholder = vbank.create_with_space(size, space, addr.as_u64());
                op.inrefs.push(placeholder);
            }
        }
    }

    // Ghidra: heritage.cc:2588 Heritage::rename
    /// Perform SSA renaming
    pub fn rename(&mut self) {
        let fd_weak = self.fd.as_ref().expect("Heritage needs Funcdata");
        let fd_arc = fd_weak.upgrade().expect("Funcdata dropped");
        let mut fd = fd_arc.write().unwrap();
        let mut vbank = std::mem::take(&mut fd.vbank);
        self.rename_direct(&mut vbank, &fd.bblocks);
        fd.vbank = vbank;
    }

    // Ghidra: heritage.cc:219 Heritage::renameDirect
    /// Perform SSA renaming directly using bank references.
    /// `vbank` is taken by &mut because heritage.cc:2502/2512 calls
    /// `fd->setInputVarnode` and cc:2521/2550 calls `fd->deleteVarnode`,
    /// both of which mutate the bank. Rugra ports these as
    /// `VarnodeBank::set_input_varnode` / `VarnodeBank::destroy_varnode`.
    pub fn rename_direct(&mut self, vbank: &mut VarnodeBank, bblocks: &crate::block::BlockGraph) {
        // Mark all read+write varnodes as active heritage, faithful to
        // Ghidra's guard() (heritage.cc:1175/1182) which calls
        // setActiveHeritage on every varnode in the read AND write lists
        // of the disjoint ranges being heritaged this pass.
        //
        // Ghidra's read/write lists (from collect()) include both free
        // varnodes AND written varnodes at heritaged addresses — a written
        // varnode is a def that rename must push onto the stack (cc:2527
        // pushes vnout if isActiveHeritage). Without activeHeritage on
        // writes, rename skips pushing them → stack stays empty → empty-stack
        // input promotion (cc:2500-2503) creates a single shared input →
        // diamond merges lose per-branch distinctness.
        //
        // Rugra approximates Ghidra's per-range guard by marking every
        // non-constant, non-annotation varnode in the bank (free + written
        // + input). Inputs are harmless to mark because rename's
        // isHeritageKnown check (cc:2496/2539) skips them before checking
        // isActiveHeritage.
        for vn_ref in &vbank.loc_tree {
            let mut vn = vn_ref.0.write().unwrap();
            let is_known_side_effect = vn.is_constant() || vn.is_annotation();
            if !is_known_side_effect {
                vn.set_active_heritage();
            }
        }

        let mut stacks: BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>> = BTreeMap::new();

        // Push initial/input varnodes to stacks
        for vn_ref in &vbank.def_tree {
            let vn = vn_ref.0.read().unwrap();
            if vn.is_input() {
                stacks.entry((vn.address_space, vn.loc)).or_default().push(vn_ref.0.clone());
            }
        }

        // Find entry blocks
        let entry_blocks: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = bblocks
            .blocks
            .iter()
            .filter(|b| b.read().unwrap().size_in() == 0)
            .cloned()
            .collect();

        for entry in entry_blocks {
            self.visit_rename_direct(vbank, entry, &mut stacks);
        }
    }

    // Ghidra: heritage.cc:219 Heritage::visitRename
    fn visit_rename(
        &mut self,
        fd: &mut Funcdata,
        block_arc: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        stacks: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
    ) {
        let mut vbank = std::mem::take(&mut fd.vbank);
        self.visit_rename_direct(&mut vbank, block_arc, stacks);
        fd.vbank = vbank;
    }

    // Ghidra: heritage.cc:2480 Heritage::renameRecurse
    /// Faithful port of `Heritage::renameRecurse(BlockBasic *bl, VariableStack &varstack)`
    /// (heritage.cc:2480-2563), structured as an iterative dominator-tree walk.
    ///
    /// **2026-07-05 修正**：补齐 3 个 load-bearing 语义（audit P0-4）：
    ///   (1) **empty-stack input promotion** (cc:2500-2503 / cc:2541-2544) —
    ///       当 stack 为空时，Ghidra 创建新 varnode 并 `setInputVarnode` 提升为
    ///       函数输入，push 到 stack。Rugra 此前静默跳过 → 自由读未被替换 →
    ///       SSA 不完整。
    ///   (2) **INDIRECT same-time stack-deepening** (cc:2507-2518) — 当 stack
    ///       顶的 vnnew 是 INDIRECT 写且其 target op 是当前 op 时，Ghidra 认为
    ///       "INDIRECT 和它的 op 同时发生"，深入 stack 一层（stack[size-2]）。
    ///       Rugra 此前完全缺失 → 栈指针 INDIRECT 配对的 op 得到错误的 SSA 名。
    ///   (3) **deleteVarnode of consumed frees** (cc:2520-2521 / cc:2549-2550) —
    ///       替换后若 `vnin->hasNoDescend()` 则 `fd->deleteVarnode(vnin)`。
    ///       Rugra 此前从不删除 → 死 varnode 留在 loc_tree，污染后续 pass。
    fn visit_rename_direct(
        &mut self,
        vbank: &mut VarnodeBank,
        block_arc: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        stacks: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
    ) {
        // Iterative dominator-tree traversal using an explicit work stack.
        // Each entry is (block_to_process, defined_keys_for_pop_after_children).
        // This avoids deep recursion in the dominator tree (which caused stack
        // overflow when mainloop repeatapply re-runs Heritage on complex functions).

        // Work item: (block, phase) where phase 0 = process ops, phase 1 = pop.
        // We store defined_here alongside so we can pop after children.
        enum WorkItem {
            Enter(Arc<RwLock<dyn FlowBlock + Send + Sync>>),
            Leave(Vec<(AddressSpace, Address)>),
        }

        let mut work: Vec<WorkItem> = vec![WorkItem::Enter(block_arc)];
        // Guard against dom-tree cycles (which would grow the work stack unboundedly).
        let max_work = 100000usize;

        while let Some(item) = work.pop() {
            if work.len() > max_work {
                eprintln!("[WARN] Heritage rename work stack exceeded {} items, aborting", max_work);
                break;
            }
            match item {
                WorkItem::Enter(block_arc) => {
                    // Skip dead blocks.
                    if (block_arc.read().unwrap().get_flags() & crate::block::block_flags::DEAD) != 0 {
                        continue;
                    }

                    let mut defined_here: Vec<(AddressSpace, Address)> = Vec::new();

                    // 1. Process Phis (MULTIEQUAL) - only their outputs.
                    // Ghidra cc:2525-2530: push output if isActiveHeritage, clear flag.
                    let ops = block_arc.read().unwrap().get_ops();
                    for op_ref in &ops {
                        let op = op_ref.0.write().unwrap();
                        if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                            if let Some(out_vn) = &op.output {
                                let should_push = {
                                    let vn_read = out_vn.read().unwrap();
                                    vn_read.is_active_heritage()
                                };
                                if should_push {
                                    out_vn.write().unwrap().clear_active_heritage();
                                    let vn_read = out_vn.read().unwrap();
                                    let key = (vn_read.address_space, vn_read.loc);
                                    drop(vn_read);
                                    stacks.entry(key).or_default().push(out_vn.clone());
                                    defined_here.push(key);
                                }
                            }
                        }
                    }

                    // 2. Process regular Ops: replace reads, then push writes.
                    // Ghidra cc:2490-2531.
                    for op_ref in &ops {
                        let mut op = op_ref.0.write().unwrap();
                        if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                            continue;
                        }

                        for i in 0..op.inrefs.len() {
                            let should_skip = {
                                let vn_read = op.inrefs[i].read().unwrap();
                                vn_read.is_heritage_known() || !vn_read.is_active_heritage()
                            };
                            if should_skip {
                                continue;
                            }
                            // Ghidra cc:2498: vnin->clearActiveHeritage();
                            let vnin_arc = op.inrefs[i].clone();
                            vnin_arc.write().unwrap().clear_active_heritage();
                            // Ghidra cc:2499: vector<Varnode *> &stack(varstack[vnin->getAddr()]);
                            let key = {
                                let vn_read = vnin_arc.read().unwrap();
                                (vn_read.address_space, vn_read.loc)
                            };
                            let stack = stacks.entry(key).or_default();
                            // Ghidra cc:2500-2506: empty-stack → promote to input.
                            // (SEMANTIC #1)
                            let mut vnnew: Arc<RwLock<Varnode>>;
                            if stack.is_empty() {
                                let (vnin_size, vnin_space, vnin_off) = {
                                    let r = vnin_arc.read().unwrap();
                                    (r.size, r.address_space, r.loc.as_u64())
                                };
                                let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                let promoted = vbank.set_input_varnode(new_vn);
                                stack.push(promoted.clone());
                                vnnew = promoted;
                            } else {
                                vnnew = stack.last().unwrap().clone();
                            }
                            // Ghidra cc:2507-2518: INDIRECT same-time deepening.
                            // (SEMANTIC #2) — vnnew is written by an INDIRECT
                            // whose iop-const input(1) points at the current op.
                            let indirect_target_is_cur = {
                                let vnnew_r = vnnew.read().unwrap();
                                let mut hit = false;
                                if vnnew_r.is_written() {
                                    if let Some(def_weak) = vnnew_r.def.as_ref().and_then(|w| w.upgrade()) {
                                        let def_r = def_weak.read().unwrap();
                                        if def_r.opcode == crate::opcodes::OpCode::CPUI_INDIRECT {
                                            if let Some(iop_vn) = def_r.get_in(1) {
                                                let iv = iop_vn.read().unwrap();
                                                if iv.get_space() == AddressSpace::Iop {
                                                    let ptr_addr = iv.get_offset() as usize;
                                                    let raw = ptr_addr as *const std::sync::RwLock<crate::op::PcodeOp>;
                                                    if raw as *const () == std::sync::Arc::as_ptr(&op_ref.0) as *const () {
                                                        hit = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                hit
                            };
                            if indirect_target_is_cur {
                                if stack.len() == 1 {
                                    // cc:2510-2513: stack has only the INDIRECT entry;
                                    // create new input and insert at bottom.
                                    let (vnin_size, vnin_space, vnin_off) = {
                                        let r = vnin_arc.read().unwrap();
                                        (r.size, r.address_space, r.loc.as_u64())
                                    };
                                    let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                    let promoted = vbank.set_input_varnode(new_vn);
                                    stack.insert(0, promoted.clone());
                                    vnnew = promoted;
                                } else {
                                    // cc:2515-2516: vnnew = stack[stack.size()-2]
                                    vnnew = stack[stack.len() - 2].clone();
                                }
                            }
                            // Ghidra cc:2519: fd->opSetInput(op, vnnew, slot);
                            op.inrefs[i] = vnnew.clone();
                            vnnew
                                .write()
                                .unwrap()
                                .descend
                                .push(Arc::downgrade(&op_ref.0));
                            // Ghidra cc:2520-2521: if (vnin->hasNoDescend()) fd->deleteVarnode(vnin);
                            // (SEMANTIC #3)
                            if vnin_arc.read().unwrap().has_no_descend() {
                                vbank.destroy_varnode(&vnin_arc);
                            }
                        }

                        // Ghidra cc:2524-2530: push output if activeHeritage.
                        if let Some(out_vn) = &op.output {
                            let should_push = {
                                let vn_read = out_vn.read().unwrap();
                                vn_read.is_active_heritage()
                            };
                            if should_push {
                                out_vn.write().unwrap().clear_active_heritage();
                                let vn_read = out_vn.read().unwrap();
                                let key = (vn_read.address_space, vn_read.loc);
                                drop(vn_read);
                                stacks.entry(key).or_default().push(out_vn.clone());
                                defined_here.push(key);
                            }
                        }
                    }

                    // 3. Fill Phi inputs in successors.
                    // Ghidra cc:2532-2553: for each out-edge, walk successor's
                    // leading MULTIEQUALs and replace the matching input slot.
                    let size_out = block_arc.read().unwrap().size_out();
                    for i in 0..size_out {
                        if let Some(edge) = block_arc.read().unwrap().get_out(i) {
                            let succ_arc = edge.point.clone();
                            let my_in_idx = edge.reverse_index as usize;

                            let succ_ops = succ_arc.read().unwrap().get_ops();
                            for op_ref in succ_ops {
                                let mut op = op_ref.0.write().unwrap();
                                if op.opcode != crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                                    break; // Ghidra cc:2537: stop at first non-MULTIEQUAL
                                }
                                if my_in_idx >= op.inrefs.len() {
                                    continue;
                                }
                                let vnin_arc = op.inrefs[my_in_idx].clone();
                                let should_skip = {
                                    let vn_read = vnin_arc.read().unwrap();
                                    vn_read.is_heritage_known()
                                };
                                if should_skip {
                                    continue;
                                }
                                // Ghidra cc:2540-2547: empty-stack → input promotion.
                                // (SEMANTIC #1, phi-input variant)
                                let key = {
                                    let vn_read = vnin_arc.read().unwrap();
                                    (vn_read.address_space, vn_read.loc)
                                };
                                let stack = stacks.entry(key).or_default();
                                let vnnew: Arc<RwLock<Varnode>>;
                                if stack.is_empty() {
                                    let (vnin_size, vnin_space, vnin_off) = {
                                        let r = vnin_arc.read().unwrap();
                                        (r.size, r.address_space, r.loc.as_u64())
                                    };
                                    let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                    let promoted = vbank.set_input_varnode(new_vn);
                                    stack.push(promoted.clone());
                                    vnnew = promoted;
                                } else {
                                    vnnew = stack.last().unwrap().clone();
                                }
                                // Ghidra cc:2548: opSetInput(multiop, vnnew, slot)
                                op.inrefs[my_in_idx] = vnnew.clone();
                                vnnew
                                    .write()
                                    .unwrap()
                                    .descend
                                    .push(Arc::downgrade(&op_ref.0));
                                // Ghidra cc:2549-2550: deleteVarnode if no descend.
                                // (SEMANTIC #3, phi-input variant)
                                if vnin_arc.read().unwrap().has_no_descend() {
                                    vbank.destroy_varnode(&vnin_arc);
                                }
                            }
                        }
                    }

                    // 4. Schedule: Leave (pop) AFTER all children.
                    // Push Leave first (it will execute last due to LIFO).
                    let children = block_arc.read().unwrap().get_dom_children();
                    work.push(WorkItem::Leave(defined_here));
                    // Push children in reverse order so they process in original order.
                    for child in children.into_iter().rev() {
                        work.push(WorkItem::Enter(child));
                    }
                }
                WorkItem::Leave(defined_here) => {
                    // 5. Pop stacks (Ghidra cc:2558-2562).
                    for key in defined_here {
                        if let Some(stack) = stacks.get_mut(&key) {
                            stack.pop();
                        }
                    }
                }
            }
        }
    }

    // Ghidra: heritage.cc:219 Heritage::getPass
    pub fn get_pass(&self) -> i32 {
        self.pass
    }

    // Ghidra: heritage.cc:2793 Heritage::numHeritagePasses
    /// Get the number of heritage passes performed for a space.
    /// Faithful to `numHeritagePasses` (heritage.cc:2793-2801):
    ///   `return pass - info->delay;`
    /// Previously Rugra returned `self.pass` (ignoring per-space delay),
    /// which over-reported the pass count for Stack (delay=1).
    pub fn num_heritage_passes(&self, space: AddressSpace) -> i32 {
        let info = self.infolist.iter().find(|i| i.space == space);
        let delay = info.map_or(0, |i| i.delay);
        self.pass - delay
    }

    // Ghidra: heritage.cc:2843 Heritage::deadRemovalAllowed
    /// Check if dead code removal is allowed for a space.
    /// Faithful to `deadRemovalAllowed` (heritage.cc:2843-2855):
    ///   `return pass > info->deadcodedelay;`
    /// Previously Rugra returned const `true`, allowing dead-code removal
    /// on every pass including pass 0 — exactly the "Heritage AFTER dead
    /// removal" warning condition Ghidra prevents (cc:2728-2744).
    pub fn dead_removal_allowed(&self, space: AddressSpace) -> bool {
        let info = self.infolist.iter().find(|i| i.space == space);
        let deadcodedelay = info.map_or(0, |i| i.deadcodedelay);
        self.pass > deadcodedelay
    }

    // Ghidra: heritage.cc:2829 Heritage::setDeadCodeDelay
    /// Set dead code delay for a space. Faithful to `setDeadCodeDelay`
    /// (heritage.cc:2829-2840). Used by bumpDeadcodeDelay to request a
    /// restart with higher delay.
    pub fn set_dead_code_delay(&mut self, space: AddressSpace, delay: i32) {
        let idx = self.infolist.iter().position(|i| i.space == space);
        if let Some(i) = idx {
            self.infolist[i].deadcodedelay = delay;
        }
    }

    // Ghidra: heritage.cc:2817 Heritage::getDeadCodeDelay
    /// Get dead code delay for a space. Faithful to `getDeadCodeDelay`
    /// (heritage.cc:2817-2827). Previously returned const 2.
    pub fn get_dead_code_delay(&self, space: AddressSpace) -> i32 {
        let info = self.infolist.iter().find(|i| i.space == space);
        info.map_or(space.get_deadcode_delay(), |i| i.deadcodedelay)
    }

    // Ghidra: heritage.cc:2805 Heritage::seenDeadCode
    /// Mark that dead code was seen (removed) for a space. Faithful to
    /// `seenDeadCode` (heritage.cc:2805-2815): `info->deadremoved = 1`.
    /// Previously Rugra was a no-op, so removeRevisitedMarkers/bumpDeadcodeDelay
    /// warning paths could never trigger.
    pub fn seen_dead_code(&mut self, space: AddressSpace) {
        let idx = self.infolist.iter().position(|i| i.space == space);
        if let Some(i) = idx {
            self.infolist[i].deadremoved = 1;
        }
    }

    // Ghidra: heritage.cc:2869 Heritage::clear
    /// Clear all non-permanent state. Faithful to `clear`
    /// (heritage.cc:2869-2884):
    ///   disjoint/globaldisjoint/domchild/augment/flags/depth/merge.clear()
    ///   clearInfoList(); loadGuard/storeGuard.clear();
    ///   maxdepth = -1; pass = 0;
    pub fn clear(&mut self) {
        // Ghidra cc:2872-2878
        self.globaldisjoint.clear();
        self.domchild.clear();
        self.augment.clear();
        self.flags.clear();
        self.depth.clear();
        self.merge.clear();
        // Ghidra cc:2879: clearInfoList()
        self.infolist.clear();
        // Ghidra cc:2880-2881
        self.load_guard.clear();
        self.store_guard.clear();
        // Ghidra cc:2882: maxdepth = -1
        self.maxdepth = -1;
        // Ghidra cc:2883: pass = 0
        self.pass = 0;
        // load_copy_ops is Rugra-specific (Ghidra's loadCopyOps, cleared
        // in handleNewLoadCopies, not in clear()). Keep cleared for safety.
        self.load_copy_ops.clear();
    }

    // Ghidra: heritage.cc:2776 Heritage::getStoreGuard
    /// Find the STORE guard matching `op`. Faithful to
    /// `Heritage::getStoreGuard` (heritage.hh:338). Linear scan of store_guard.
    pub fn get_store_guard(&self, op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<&LoadGuard> {
        self.store_guard.iter().find(|g| match g.op.upgrade() {
            Some(g_op) => std::sync::Arc::ptr_eq(&g_op, op),
            None => false,
        })
    }

    // Ghidra: heritage.cc:219 Heritage::getLoadGuard
    /// Find the LOAD guard matching `op`. Faithful to
    /// `Heritage::getLoadGuard` (heritage.hh:337).
    pub fn get_load_guard(&self, op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<&LoadGuard> {
        self.load_guard.iter().find(|g| match g.op.upgrade() {
            Some(g_op) => std::sync::Arc::ptr_eq(&g_op, op),
            None => false,
        })
    }
}

// Ghidra: heritage.cc:219 Heritage::storeGuardPointerBase
/// Compute the `pointerBase` (stack-pointer base offset) recorded for a STORE
/// guard, mirroring the `StackNode.offset` that Ghidra's
/// `discoverIndexedStackPointers` threads into `generateStoreGuard`
/// (heritage.cc:927-932, 1077-1090).
///
/// The STORE pointer is `in[1]`. We follow INT_ADD(const)/INT_SUB(const)/COPY
/// definitions backward and accumulate the constant offset. If we cannot
/// resolve a constant offset (non-constant add, multiequal, or a free
/// varnode), we return 0, which matches Ghidra's `StackNode(spInput,0,0)`
/// starting offset and yields a maximally conservative guard.
fn store_guard_pointer_base(
    store_op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    _fd: &Funcdata,
) -> u64 {
    let g = store_op.read().unwrap();
    let ptr = match g.inrefs.get(1) {
        Some(v) => v.clone(),
        None => return 0,
    };
    drop(g);
    trace_const_stack_offset(&ptr)
}

// Ghidra: heritage.cc:219 Heritage::loadGuardPointerBase
/// Compute the `pointerBase` recorded for a LOAD guard. The LOAD pointer is
/// `in[1]`; see `store_guard_pointer_base` for the tracing strategy.
fn load_guard_pointer_base(
    load_op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    _fd: &Funcdata,
) -> u64 {
    let g = load_op.read().unwrap();
    let ptr = match g.inrefs.get(1) {
        Some(v) => v.clone(),
        None => return 0,
    };
    drop(g);
    trace_const_stack_offset(&ptr)
}

// Ghidra: heritage.cc:219 Heritage::traceConstStackOffset
/// Follow INT_ADD(const)/INT_SUB(const)/COPY chains backward from a pointer
/// varnode and accumulate the constant offset added to the stack pointer.
/// Returns 0 if the offset cannot be resolved to a single constant (the
/// conservative default, matching Ghidra's initial `StackNode.offset == 0`).
fn trace_const_stack_offset(ptr: &std::sync::Arc<std::sync::RwLock<Varnode>>) -> u64 {
    let mut cur = ptr.clone();
    let mut offset: u64 = 0;
    let mut hops = 0;
    loop {
        // Guard against pathological cycles.
        hops += 1;
        if hops > 64 {
            break;
        }
        let next = {
            let vn = cur.read().unwrap();
            if !vn.is_written() {
                return offset;
            }
            let def = match vn.def.as_ref().and_then(|w| w.upgrade()) {
                Some(o) => o,
                None => return offset,
            };
            let defg = def.read().unwrap();
            match defg.opcode {
                crate::opcodes::OpCode::CPUI_COPY => defg.inrefs.first().cloned(),
                crate::opcodes::OpCode::CPUI_INT_ADD
                | crate::opcodes::OpCode::CPUI_INT_SUB => {
                    // The other operand must be a constant.
                    let (a, b) = (
                        defg.inrefs.first().cloned(),
                        defg.inrefs.get(1).cloned(),
                    );
                    let (other, _) = match (a, b) {
                        (Some(a), Some(b)) => {
                            if Arc::ptr_eq(&a, &cur) {
                                (Some(b), 0)
                            } else if Arc::ptr_eq(&b, &cur) {
                                (Some(a), 1)
                            } else {
                                return offset;
                            }
                        }
                        _ => return offset,
                    };
                    let other = match other {
                        Some(o) => o,
                        None => return offset,
                    };
                    let og = other.read().unwrap();
                    if !og.is_constant() {
                        return offset;
                    }
                    let delta = og.get_offset();
                    drop(og);
                    if defg.opcode == crate::opcodes::OpCode::CPUI_INT_ADD {
                        offset = offset.wrapping_add(delta);
                    } else {
                        offset = offset.wrapping_sub(delta);
                    }
                    defg.inrefs.first().filter(|v| !Arc::ptr_eq(v, &cur)).cloned()
                }
                _ => return offset,
            }
        };
        match next {
            Some(n) => cur = n,
            None => return offset,
        }
    }
    offset
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_map() {
        let mut lm = LocationMap::new();
        lm.add(Address::new(0x100), 4, 1);
        assert_eq!(lm.find_pass(Address::new(0x100)), 1);
        assert_eq!(lm.find_pass(Address::new(0x200)), -1);
    }

    #[test]
    fn test_priority_queue() {
        let mut pq = PriorityQueue::new();
        pq.reset(10);
        assert!(pq.empty());
    }

    #[test]
    fn test_heritage_creation() {
        let mut h = Heritage::new();
        assert_eq!(h.get_pass(), 0);
        // After alignment with Ghidra cc:2817/2843: Ram delay=0/deadcodedelay=0.
        // getDeadCodeDelay reads infolist; build_info_list populates it.
        h.build_info_list();
        assert_eq!(h.get_dead_code_delay(AddressSpace::Ram), 0);
        // deadRemovalAllowed = (pass > deadcodedelay) = (0 > 0) = false.
        // (Ghidra prevents dead-code removal before any heritage pass.)
        assert!(!h.dead_removal_allowed(AddressSpace::Ram));
        // Stack has delay=1.
        assert_eq!(h.get_dead_code_delay(AddressSpace::Stack), 1);
    }

    /// Build a STORE op targeting the stack space, mark it spacebase, and
    /// verify `guard_stores` records a `LoadGuard` for it. Mirrors Ghidra's
    /// `generateStoreGuard` (heritage.cc:927) + `guardStores` (heritage.cc:1539).
    #[test]
    fn test_guard_stores_populates_store_guard() {
        use crate::op::PcodeOpRef;
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let start = Address::new(0x1000);
        let mut fd = Funcdata::new("guard_stores", start, 0);

        // STORE(const(stack_space_id), ptr, val)
        let store = fd.obank.create(OpCode::CPUI_STORE, 3, start);
        // in[0]: const varnode carrying the Stack space id (getSpaceFromConst).
        // The lifter emits this with the CONSTANT flag + Const space.
        let space_const = fd.vbank.create_constant(8, AddressSpace::Stack.space_id() as u64);
        // in[1]: a (stack-pointer) pointer varnode.
        let ptr = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        // in[2]: the value varnode.
        let val = fd.vbank.create_with_space(8, AddressSpace::Ram, 0x1000);
        fd.op_set_input(&store, space_const, 0);
        fd.op_set_input(&store, ptr, 1);
        fd.op_set_input(&store, val, 2);
        // Mark the STORE as spacebase-indexed (as discoverIndexedStackPointers
        // would for an indexed stack STORE).
        store.0.write().unwrap().mark_spacebase_ptr();

        let mut h = Heritage::new();
        assert!(h.store_guard.is_empty());
        h.guard_stores(&mut fd);

        // Exactly one guard should be created.
        assert_eq!(h.store_guard.len(), 1, "guard_stores must record the STORE");
        let g = &h.store_guard[0];
        assert_eq!(g.spc, AddressSpace::Stack);
        assert_eq!(g.minimum_offset, 0); // initial guard protects the whole space
        assert_eq!(g.analysis_state, 0); // unanalyzed until value-set runs

        // get_store_guard must now return the record for this op.
        let found = h.get_store_guard(&store.0);
        assert!(found.is_some(), "get_store_guard must find the guarded STORE");

        // Calling guard_stores again must NOT duplicate the record.
        h.guard_stores(&mut fd);
        assert_eq!(h.store_guard.len(), 1, "guard_stores must dedup across passes");

        // A non-stack STORE (Ram target) must not be guarded.
        let ram_store = fd.obank.create(OpCode::CPUI_STORE, 3, start);
        let ram_const = fd.vbank.create_constant(8, AddressSpace::Ram.space_id() as u64);
        let ptr2 = fd.vbank.create_with_space(8, AddressSpace::Register, 0x28);
        let val2 = fd.vbank.create_with_space(8, AddressSpace::Ram, 0x2000);
        fd.op_set_input(&ram_store, ram_const, 0);
        fd.op_set_input(&ram_store, ptr2, 1);
        fd.op_set_input(&ram_store, val2, 2);
        ram_store.0.write().unwrap().mark_spacebase_ptr();
        let before = h.store_guard.len();
        h.guard_stores(&mut fd);
        assert_eq!(h.store_guard.len(), before, "non-stack STORE must not be guarded");
        // PcodeOpRef must outlive the borrow checker usage above.
        let _ = PcodeOpRef(store.0.clone());
    }

    /// Build a LOAD op from the stack space (spacebase-marked) and verify
    /// `guard_loads` records a `LoadGuard` for it. Mirrors Ghidra's
    /// `generateLoadGuard` (heritage.cc:910) + `guardLoads` (heritage.cc:1571).
    #[test]
    fn test_guard_loads_populates_load_guard() {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let start = Address::new(0x2000);
        let mut fd = Funcdata::new("guard_loads", start, 0);

        // LOAD(const(stack_space_id), ptr)
        let load = fd.obank.create(OpCode::CPUI_LOAD, 2, start);
        let space_const = fd.vbank.create_constant(8, AddressSpace::Stack.space_id() as u64);
        let ptr = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        fd.op_set_input(&load, space_const, 0);
        fd.op_set_input(&load, ptr, 1);
        load.0.write().unwrap().mark_spacebase_ptr();

        let mut h = Heritage::new();
        assert!(h.load_guard.is_empty());
        h.guard_loads(&mut fd);

        assert_eq!(h.load_guard.len(), 1, "guard_loads must record the LOAD");
        assert_eq!(h.load_guard[0].spc, AddressSpace::Stack);
        assert!(h.get_load_guard(&load.0).is_some());

        // Dedup: a second call must not re-add it.
        h.guard_loads(&mut fd);
        assert_eq!(h.load_guard.len(), 1);
    }

    /// `establish_range`/`finalize_range` must run without panicking and leave
    /// the guard in a valid (still-permissive) state, since no value-set
    /// solver is wired yet. TODO(value-set-analysis) will tighten this.
    #[test]
    fn test_load_guard_range_stubs() {
        use crate::space::AddressSpace;
        let mut g = LoadGuard::default();
        // Default guard protects the whole Ram space.
        assert_eq!(g.minimum_offset, 0);
        assert_eq!(g.maximum_offset, u64::MAX);
        assert_eq!(g.analysis_state, 0);

        g.establish_range(); // no-op refinement (no solver)
        assert_eq!(g.analysis_state, 0);
        assert!(g.is_guarded(&AddressSpace::Ram, 0x1234));

        g.finalize_range(); // marks partially analyzed (state==1), still permissive
        assert_eq!(g.analysis_state, 1);
        assert!(g.is_guarded(&AddressSpace::Ram, 0xffff));
        // A different space is never guarded.
        assert!(!g.is_guarded(&AddressSpace::Stack, 0x1234));
    }
}

/// Flags for Heritage node properties
pub mod heritage_flags {
    pub const BOUNDARY_NODE: u32 = 1 << 0;
    pub const MARK_NODE: u32 = 1 << 1;
    pub const MERGED_NODE: u32 = 1 << 2;
}

/// Node in the SSA renaming stack
/// Corresponds to Ghidra's `Heritage::StackNode`
#[derive(Debug)]
pub struct StackNode {
    pub vn: Arc<RwLock<Varnode>>,
    pub offset: u64,
    pub traversals: u32,
}
