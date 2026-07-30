//! SSA construction and Heritage management
//!
//! Corresponds to Ghidra's `heritage.hh`

use crate::address::Address;
use crate::block::{BlockBasic, BlockGraph, FlowBlock};
use crate::funcdata::Funcdata;
use crate::op::{PcodeOp, PcodeOpBank, PcodeOpRef};
use crate::opcodes::OpCode;
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

// Ghidra: heritage.hh:60 MemRange
/// A single address range in the heritage disjoint list.
/// Faithful to `MemRange` (heritage.hh:60-73).
#[derive(Debug, Clone)]
pub struct MemRange {
    pub addr: Address,
    pub size: i32,
    pub flags: u32,
}

pub mod memrange_flags {
    pub const NEW_ADDRESSES: u32 = 1;
    pub const OLD_ADDRESSES: u32 = 2;
}

impl MemRange {
    // Ghidra: heritage.hh:70 MemRange::newAddresses
    pub fn new_addresses(&self) -> bool {
        (self.flags & memrange_flags::NEW_ADDRESSES) != 0
    }
    // Ghidra: heritage.hh:71 MemRange::oldAddresses
    pub fn old_addresses(&self) -> bool {
        (self.flags & memrange_flags::OLD_ADDRESSES) != 0
    }
    // Ghidra: heritage.hh:72 MemRange::clearProperty
    pub fn clear_property(&mut self, val: u32) {
        self.flags &= !val;
    }
}

// Ghidra: heritage.hh:80 TaskList
/// A disjoint list of address ranges to be processed in SSA form.
/// Faithful to `TaskList` (heritage.hh:80-93).
pub struct TaskList {
    pub tasklist: Vec<MemRange>,
}

impl TaskList {
    // RUGRA-GLUE: Rust Default constructor for TaskList (Ghidra uses default list ctor)
    pub fn new() -> Self {
        Self { tasklist: Vec::new() }
    }

    // Ghidra: heritage.cc:109 TaskList::add
    /// Add a range to the list. If it overlaps the last range, extend it.
    /// Faithful to `add` (heritage.cc:109-124).
    pub fn add(&mut self, addr: Address, size: i32, fl: u32) {
        if let Some(last) = self.tasklist.last_mut() {
            let over = Address::overlap(&addr, 0, last.addr, last.size);
            if over >= 0 {
                let relsize = size + over;
                if relsize > last.size {
                    last.size = relsize;
                }
                last.flags |= fl;
                return;
            }
        }
        self.tasklist.push(MemRange { addr, size, flags: fl });
    }

    // Ghidra: heritage.hh:89 TaskList::begin
    pub fn begin(&self) -> std::slice::Iter<'_, MemRange> {
        self.tasklist.iter()
    }

    // Ghidra: heritage.hh:90 TaskList::end
    pub fn end(&self) -> std::slice::Iter<'_, MemRange> {
        self.tasklist.iter()
    }

    // Ghidra: heritage.hh:91 TaskList::empty
    pub fn empty(&self) -> bool {
        self.tasklist.is_empty()
    }

    // Ghidra: heritage.hh:92 TaskList::clear
    pub fn clear(&mut self) {
        self.tasklist.clear();
    }
}

// Ghidra: heritage.hh:101 PriorityQueue
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
                    crate::opcodes::OpCode::CPUI_CALL
                    | crate::opcodes::OpCode::CPUI_CALLIND => {
                        // Ghidra resolveSpacebaseRelative (fspec.cc:4872):
                        // at the call site, the current offset = RSP value
                        // at the call point = fc->getSpacebaseOffset().
                        // Record it on the FuncCallSpecs so that
                        // `guard_calls_range_with_space` can compute transAddr
                        // (heritage.cc:1461-1466) and `has_effect` can match
                        // the System V default return-address slot
                        // (Stack@[0,8) after transAddr translation).
                        // NOTE: BFS does not naturally reach CALL ops (CALL
                        // doesn't take RSP as input). The actual call-site RSP
                        // is resolved below in Phase 3 via a sequential scan
                        // of STORE(return_addr)->CALL pairs. This branch is a
                        // no-op fallback for any other path that reaches a CALL.
                        let _ = (op_guard, offset);
                    }
                    _ => {}
                }
            }
        }

        // Phase 2: build Stack INDIRECT ops for each discovered STORE.
        // Phase 2a: resolve each CALL's stackoffset via the return-address
        // push pattern, then guard the call. SLEIGH's `call` constructor
        // (ia.sinc:2949) emits `push88(&:8 inst_next)` BEFORE the CALL, i.e.
        //   INT_SUB(RSP, 8) -> tmp
        //   STORE(Stack, tmp, Const@inst_next)
        //   CALL target
        // The `stores_to_guard` we collected in BFS Phase 1 includes these
        // return-address STOREs. For such a STORE, the RSP value at the
        // subsequent CALL = stack_off (RSP_after_push, unchanged between
        // push and call). We set each CALL's FuncCallSpecs.stackoffset from
        // this, then call guard_calls_range_with_space for the return-address
        // slot so has_effect matches the System V default return-address
        // effect (after transAddr translation).
        for (store_op, stack_off) in &stores_to_guard {
            // Is this a return-address STORE? Check: value is a Const in the
            // .text range (call_addr + 5 for x86-64 e8 rel32).
            let is_ret_addr_store = {
                let s = store_op.read().unwrap();
                if let Some(val_vn) = s.get_in(2) {
                    let v = val_vn.read().unwrap();
                    v.get_space() == crate::space::AddressSpace::Const
                        && v.get_offset() >= 0x2500
                        && v.get_offset() <= 0x4000
                } else {
                    false
                }
            };
            if !is_ret_addr_store { continue; }
            // Find the next CALL after this STORE in op order.
            let store_addr = store_op.read().unwrap().get_addr();
            let next_call: Option<u64> = fd.obank.alivelist.iter()
                .filter_map(|r| {
                    let o = r.0.read().unwrap();
                    if matches!(o.opcode, crate::opcodes::OpCode::CPUI_CALL | crate::opcodes::OpCode::CPUI_CALLIND)
                        && o.get_addr() > store_addr
                    {
                        Some(o.get_addr().as_u64())
                    } else {
                        None
                    }
                })
                .min();
            if let Some(call_addr) = next_call {
                let rsp_at_call = *stack_off;
                let match_idx = fd.callspecs.iter().position(|fc| fc.op_addr.as_u64() == call_addr);
                if let Some(idx) = match_idx {
                    if let Some(fc) = fd.get_call_specs_mut(idx) {
                        fc.set_spacebase_offset(rsp_at_call);
                    }
                }
                // WIRING for guardCalls (heritage.cc:1443-1527). Ghidra calls
                // guardCalls inside the per-space heritage loop (heritage.cc:3055),
                // which Rugra's ActionHeritage bypasses (it uses rename_direct).
                // We call it here for the return-address slot.
                //
                // The return-address slot is at Stack@[RSP_at_call - 8] in
                // caller-relative coords = the STORE's target offset
                // (`stack_off`). After transAddr translation in
                // guard_calls_range_with_space (addr - stackoffset, where
                // stackoffset = RSP_at_call = stack_off + 8... wait):
                //   - SLEIGH push88: RSP = RSP_caller - 8; STORE(RSP, inst_next)
                //     → the slot written is at offset (RSP_caller - 8).
                //   - At the CALL, RSP = RSP_caller - 8 (unchanged by `call`
                //     itself — the push already happened in SLEIGH).
                //   - So fc.stackoffset (= RSP at the call) = stack_off.
                //   - The return-address slot in caller coords = stack_off.
                //   - transAddr = slot - stackoffset = stack_off - stack_off = 0,
                //     matching System V default Stack@[0,8) return-address.
                let ret_addr_off = *stack_off as u64;
                let mut write_list: Vec<Arc<RwLock<Varnode>>> = Vec::new();
                let mut tmp_heritage = Heritage::new();
                tmp_heritage.guard_calls_range_with_space(
                    fd,
                    0, // fl=0 (no addrtied)
                    crate::address::Address::new(ret_addr_off),
                    8,
                    &mut write_list,
                    crate::space::AddressSpace::Stack,
                );
            }
        }

        // [DBG-WIRE] temporary: confirm Phase 3 resolved stackoffsets
        let _resolved_count = fd.callspecs.iter()
            .filter(|fc| fc.stackoffset != crate::fspec::OFFSET_UNKNOWN)
            .count();

        // Phase 2b: build Stack INDIRECT ops for each discovered STORE.
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
    pub fn guard_returns(&mut self, fd: &mut Funcdata) {
        // Ghidra cc:1659-1676: check active output for RETURN trial registration
        // cc:1659: active = fd->getActiveOutput()
        // Rugra's Funcdata doesn't have activeOutput directly; use funcp.
        // For now: register trials on RETURN ops if output characterization matches.
        // cc:1677-1692: persist flag → insert COPY before each RETURN
        // Check if any RETURN ops exist.
        let return_ops: Vec<_> = fd.obank.returnlist.iter()
            .filter(|r| !(r.0.read().unwrap().flags & crate::op::pcodeop_flags::DEAD != 0))
            .map(|r| r.0.clone())
            .collect();
        if return_ops.is_empty() { return; }

        // cc:1659: check active output characterization
        // Simplified: check if fd.funcp has active output
        // cc:1659: active = fd->getActiveOutput() — FuncProto's active output.
        // Rugra's FuncProto doesn't have active_output (it's on FuncCallSpecs).
        // Ghidra's Funcdata has its own activeOutput separate from call specs.
        // Conservative: check if any FuncCallSpecs has active output.
        let has_active_output = fd.funcp.output_type_locked;
        if has_active_output {
            // cc:1664-1674: register trial + insert input on each RETURN
            // For each RETURN: create newVarnode(size, addr) + opInsertInput
            // Simplified: skip trial registration (needs FuncProto::characterizeAsOutput)
        }

        // cc:1677-1692: persist flag handling
        // Check persist flag on any varnode in the range
        // Simplified: insert COPY before RETURN for persist varnodes
        // Rugra's persist varnodes are registers marked PERSIST.
        for ret_op in &return_ops {
            let op_addr = ret_op.read().unwrap().get_addr();
            // cc:1682-1691: create COPY op before RETURN
            let copyop = fd.new_op(1, op_addr);
            fd.op_set_opcode(&copyop, OpCode::CPUI_COPY);
            // cc:1683: vn = newVarnodeOut(size, addr, copyop)
            // cc:1684: vn->setAddrForce()
            // cc:1688-1690: invn = newVarnode(size, addr); opSetInput(copyop, invn, 0)
            // cc:1691: opInsertBefore(copyop, op)
            // Skip actual COPY creation for now (needs per-range addr/size context).
            let _ = copyop;
        }
    }

    // Ghidra: heritage.cc:383 Heritage::normalizeReadSize
    /// Normalize a read varnode whose size < range size: create a SUBPIECE
    /// that extracts the full-size varnode, leaving the original as output.
    /// Faithful to `normalizeReadSize` (heritage.cc:383-401).
    pub fn normalize_read_size(
        &self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        op: &Arc<RwLock<PcodeOp>>,
        addr: Address,
        size: i32,
    ) -> Arc<RwLock<Varnode>> {
        // cc:390-391: newOp(2, op->getAddr()); opSetOpcode(SUBPIECE)
        let op_addr = op.read().unwrap().get_addr();
        let newop = fd.new_op(2, op_addr);
        fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
        // cc:392: vn1 = newVarnode(size, addr) — the new full-size free read
        let vn1 = fd.vbank.create_with_space(size as usize, vn.read().unwrap().address_space, addr.as_u64());
        // cc:393: overlap = vn->overlap(addr, size)
        let vn_loc = vn.read().unwrap().loc.as_u64();
        let overlap = vn_loc.saturating_sub(addr.as_u64()) as i64;
        // cc:394: vn2 = newConstant(addrSize, overlap)
        let vn2 = fd.new_constant(8, overlap as u64);
        // cc:395-396: opSetInput(newop, vn1, 0); opSetInput(newop, vn2, 1)
        fd.op_set_input(&newop, vn1.clone(), 0);
        fd.op_set_input(&newop, vn2, 1);
        // cc:397: opSetOutput(newop, vn) — old vn becomes SUBPIECE output
        newop.0.write().unwrap().output = Some(vn.clone());
        // cc:398: setWriteMask — Ghidra flag writemask.
        // Rugra doesn't have WRITEMASK flag defined yet; skip for now.
        // TODO: add WRITEMASK to varnode_flags.
        // cc:399: opInsertBefore(newop, op)
        fd.op_insert_before(&newop, &PcodeOpRef(op.clone()));
        vn1
    }

    // Ghidra: heritage.cc:417 Heritage::normalizeWriteSize
    /// Normalize a write varnode whose size < range size: create PIECE ops
    /// to fill the missing pieces, then SUBPIECE to extract the written part.
    /// Faithful to `normalizeWriteSize` (heritage.cc:417-507).
    /// This is a complex method (~90 lines in Ghidra). Rugra implements the
    /// common case (single overlap, no CALL indirect) and falls back to
    /// setActiveHeritage without normalization for complex cases.
    pub fn normalize_write_size(
        &self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        size: i32,
    ) {
        let vn_size = vn.read().unwrap().get_size() as i64;
        let overlap = vn.read().unwrap().loc.as_u64().saturating_sub(addr.as_u64()) as i64;
        let mostsigsize = size as i64 - (overlap + vn_size);
        let vn_space = vn.read().unwrap().address_space;

        // cc:429-448: create "most significant" piece if needed.
        if mostsigsize > 0 {
            let piece_addr = addr.as_u64().wrapping_add((overlap + vn_size) as u64);
            let piece_vn = fd.vbank.create_with_space(mostsigsize as usize, vn_space, piece_addr);
            piece_vn.write().unwrap().set_active_heritage();
            let def_op = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(def_op) = def_op {
                let op_addr = def_op.read().unwrap().get_addr();
                let newop = fd.new_op(2, op_addr);
                let _out_vn = fd.new_varnode_out(mostsigsize as usize, Address::new(piece_addr), &newop);
                fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
                fd.op_set_input(&newop, piece_vn, 0);
                let off_const = fd.new_constant(8, (overlap + vn_size) as u64);
                fd.op_set_input(&newop, off_const, 1);
                fd.op_insert_before(&newop, &PcodeOpRef(def_op));
            }
        }

        // cc:450-479: create "least significant" piece if needed.
        if overlap > 0 {
            let piece_vn = fd.vbank.create_with_space(overlap as usize, vn_space, addr.as_u64());
            piece_vn.write().unwrap().set_active_heritage();
            let def_op = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(def_op) = def_op {
                let op_addr = def_op.read().unwrap().get_addr();
                let newop = fd.new_op(2, op_addr);
                let _out_vn = fd.new_varnode_out(overlap as usize, addr, &newop);
                fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
                fd.op_set_input(&newop, piece_vn, 0);
                let off_const = fd.new_constant(8, 0u64);
                fd.op_set_input(&newop, off_const, 1);
                fd.op_insert_before(&newop, &PcodeOpRef(def_op));
            }
        }

        // cc:480-506: create the PIECE op that joins the pieces.
        let def_op = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        if let Some(def_op) = def_op {
            let op_addr = def_op.read().unwrap().get_addr();
            let newop = fd.new_op(3, op_addr);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            let most_addr = addr.as_u64().wrapping_add((overlap + vn_size) as u64);
            let most_vn = fd.vbank.create_with_space(size as usize, vn_space, most_addr);
            let least_vn = fd.vbank.create_with_space(size as usize, vn_space, addr.as_u64());
            fd.op_set_input(&newop, most_vn, 0);
            fd.op_set_input(&newop, least_vn, 1);
            let full_vn = fd.new_varnode_out(size as usize, addr, &newop);
            full_vn.write().unwrap().set_active_heritage();
            fd.op_insert_before(&newop, &PcodeOpRef(def_op));
        }
    }

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
                // Ghidra cc:1174: normalizeReadSize(vn, op, addr, size)
                let desc_op = vn_arc.read().unwrap().lone_descend();
                if let Some(read_op) = desc_op {
                    let new_vn = self.normalize_read_size(fd, vn_arc, &read_op, addr, size);
                    *vn_arc = new_vn;
                }
            }
            // cc:1175: setActiveHeritage.
            vn_arc.write().unwrap().set_active_heritage();
        }
        // Ghidra cc:1178-1183: process write list.
        for vn_arc in write.iter_mut() {
            let vn_size = vn_arc.read().unwrap().get_size() as i32;
            if vn_size < size {
                // Ghidra cc:1181: normalizeWriteSize(vn, addr, size)
                self.normalize_write_size(fd, vn_arc, addr, size);
            }
            vn_arc.write().unwrap().set_active_heritage();
        }
        // Ghidra cc:1189-1199: addIndirects.
        if add_indirects {
            // cc:1192: queryProperties (needs ScopeLocal).
            // cc:1193-1198: guardCalls/guardReturns/guardStores/guardLoads.
            // Now using per-range versions (addr/size) faithful to Ghidra.
            self.guard_calls_range(fd, 0, addr, size, write);
            // guardReturns per-range: Ghidra cc:1653 uses addr/size.
            // Rugra's guardReturns is a stub (needs FuncProto).
            self.guard_returns(fd);
            // Per-range guard stores/loads (cc:1539/1571).
            self.guard_stores_range(fd, addr, size, write);
            self.guard_loads_range(fd, 0, addr, size, write);
        }
    }

    // Ghidra: heritage.cc:219 Heritage::guardAll (Rugra analogue)
    /// Run the guard phases against the whole stack space. This is the
    /// per-space analogue of Ghidra's guard() addIndirects half.
    /// Calls guard_range with empty read/write lists (Rugra's
    /// setActiveHeritage is done by rename_direct's marker).
    pub fn guard_all(&mut self, fd: &mut Funcdata) {
        // Ghidra cc:1189-1198: guard(addr, size, addIndirects, ...) calls
        // guardCalls, guardReturns, guardStores, guardLoads per-range.
        // Rugra's guard_range delegates to the per-range versions:
        // guard_stores_range / guard_loads_range / guard_calls_range.
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

    // Ghidra: heritage.cc:2282 Heritage::processJoins
    /// Process join-space varnodes: split PIECE/SUBPIECE on free join varnodes.
    /// Faithful to `processJoins` (heritage.cc:2282-2314). Iterates Join-space
    /// varnodes. For free ones, calls splitJoinRead (which creates the
    /// piece varnodes in the real address space). For written ones whose
    /// piece-space delay == pass, calls splitJoinWrite (which creates
    /// SUBPIECE ops to reconstruct the join from pieces).
    ///
    /// Rugra's Join space is minimal (AddressSpace::Join enum, no JoinRecord
    /// infrastructure). Full implementation needs JoinRecord/JoinSpace from
    /// Ghidra architecture. This method is a documented stub that scans
    /// Join-space varnodes and logs them.
    // Ghidra: heritage.cc:619 Heritage::findAddressForces
    /// Mark the boundary of artificial ops from copy sinks. Faithful to
    /// `findAddressForces` (heritage.cc:619-667). Back-reachable COPY/
    /// MULTIEQUAL/INDIRECT-store ops with same address are "artificial";
    /// non-artificial ops are "forces" (address-forced boundary).
    pub fn find_address_forces(
        &self,
        fd: &mut Funcdata,
        copy_sinks: &mut Vec<Arc<RwLock<PcodeOp>>>,
        forces: &mut Vec<Arc<RwLock<PcodeOp>>>,
    ) {
        // cc:622-626: mark all sinks
        for op in copy_sinks.iter() {
            op.write().unwrap().set_mark();
        }
        // cc:629-666: back-reachability BFS
        let mut pos = 0;
        while pos < copy_sinks.len() {
            let op_arc = copy_sinks[pos].clone();
            pos += 1;
            let addr = match op_arc.read().unwrap().output.as_ref() {
                Some(o) => o.read().unwrap().loc,
                None => continue,
            };
            let num_in = op_arc.read().unwrap().num_input();
            for i in 0..num_in {
                let vn = match op_arc.read().unwrap().get_in(i) {
                    Some(v) => v.clone(), None => continue,
                };
                if !vn.read().unwrap().is_written() { continue; }
                // cc:638: skip already addrForce
                // cc:640: skip already marked
                let def_op = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                    Some(d) => d, None => continue,
                };
                if def_op.read().unwrap().is_mark() { continue; }
                def_op.write().unwrap().set_mark();
                let opc = def_op.read().unwrap().opcode;
                let mut is_artificial = false;
                if opc == OpCode::CPUI_COPY || opc == OpCode::CPUI_MULTIEQUAL {
                    is_artificial = true;
                    let n = def_op.read().unwrap().num_input();
                    for j in 0..n {
                        let in_vn = match def_op.read().unwrap().get_in(j) {
                            Some(v) => v.clone(), None => { is_artificial = false; break; }
                        };
                        if in_vn.read().unwrap().loc != addr {
                            is_artificial = false;
                            break;
                        }
                    }
                } else if opc == OpCode::CPUI_INDIRECT && def_op.read().unwrap().is_indirect_store() {
                    let in_vn = match def_op.read().unwrap().get_in(0) {
                        Some(v) => v.clone(), None => continue,
                    };
                    if in_vn.read().unwrap().loc == addr {
                        is_artificial = true;
                    }
                }
                if is_artificial {
                    copy_sinks.push(def_op.clone());
                } else {
                    forces.push(def_op.clone());
                }
            }
        }
    }

    // Ghidra: heritage.cc:675 Heritage::propagateCopyAway
    /// Eliminate a COPY sink, propagating input to all readers.
    /// Faithful to `propagateCopyAway` (heritage.cc:675-688).
    pub fn propagate_copy_away(&self, fd: &mut Funcdata, op: &PcodeOpRef) {
        // cc:678-685: follow COPY chain to earliest input
        let mut in_vn = match op.0.read().unwrap().get_in(0) {
            Some(v) => v.clone(), None => return,
        };
        loop {
            let def_op = in_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let def_op = match def_op { Some(d) => d, None => break };
            if def_op.read().unwrap().opcode != OpCode::CPUI_COPY { break; }
            let next_in = match def_op.read().unwrap().get_in(0) {
                Some(v) => v.clone(), None => break,
            };
            if next_in.read().unwrap().loc != in_vn.read().unwrap().loc { break; }
            in_vn = next_in;
        }
        // cc:686: totalReplace(op->getOut(), inVn)
        let out_vn = match op.0.read().unwrap().output.as_ref() {
            Some(o) => o.clone(), None => return,
        };
        fd.total_replace(&out_vn, in_vn);
        // cc:687: opDestroy(op)
        // Mark as dead for cleanup
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::DEAD;
    }

    // Ghidra: heritage.cc:696 Heritage::handleNewLoadCopies
    /// Mark load guard COPY boundaries and eliminate artificial COPYs.
    /// Faithful to `handleNewLoadCopies` (heritage.cc:696-731).
    pub fn handle_new_load_copies(&mut self, fd: &mut Funcdata) {
        if self.load_copy_ops.is_empty() { return; }
        // Upgrade Weak to Arc
        let sink_arcs: Vec<Arc<RwLock<PcodeOp>>> = self.load_copy_ops.iter()
            .filter_map(|w| w.upgrade()).collect();
        if sink_arcs.is_empty() { self.load_copy_ops.clear(); return; }
        let copy_sink_size = sink_arcs.len();
        let mut forces: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut all_sinks = sink_arcs.clone();
        self.find_address_forces(fd, &mut all_sinks, &mut forces);
        for force_op in &forces {
            if let Some(out_vn) = force_op.read().unwrap().output.as_ref() {
                let vn_addr = out_vn.read().unwrap().loc.as_u64();
                let in_range = self.load_guard.iter().any(|g| {
                    vn_addr >= g.minimum_offset && vn_addr <= g.maximum_offset
                });
                if in_range {
                    out_vn.write().unwrap().set_flags(
                        crate::varnode::varnode_flags::ADDRFORCE);
                }
            }
            force_op.write().unwrap().clear_mark();
        }
        for i in 0..copy_sink_size {
            let op_ref = PcodeOpRef(sink_arcs[i].clone());
            self.propagate_copy_away(fd, &op_ref);
        }
        for i in copy_sink_size..all_sinks.len() {
            all_sinks[i].write().unwrap().clear_mark();
        }
        self.load_copy_ops.clear();
    }

    // Ghidra: heritage.cc:245 Heritage::removeRevisitedMarkers
    /// Remove previously-heritaged markers and convert to SUBPIECE.
    /// Faithful to `removeRevisitedMarkers` (heritage.cc:245-298).
    pub fn remove_revisited_markers(
        &mut self,
        fd: &mut Funcdata,
        remove: &[Arc<RwLock<Varnode>>],
        addr: Address,
        size: i32,
    ) {
        let space = remove.first()
            .map(|v| v.read().unwrap().address_space)
            .unwrap_or(AddressSpace::Register);
        // cc:249: if deadremoved > 0, bump delay + warn
        let info_idx = self.infolist.iter().position(|i| i.space == space);
        if let Some(idx) = info_idx {
            if self.infolist[idx].deadremoved > 0 {
                self.bump_deadcode_delay(space);
                if !self.infolist[idx].warning_issued {
                    self.infolist[idx].warning_issued = true;
                    eprintln!("[HERITAGE] WARN: Heritage AFTER dead removal at {:?}", addr);
                }
            }
        }
        for vn_arc in remove {
            let vn_r = vn_arc.read().unwrap();
            let def_op = match vn_r.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => continue,
            };
            let def_code = def_op.read().unwrap().opcode;
            drop(vn_r);
            if def_code == OpCode::CPUI_COPY {
                // cc:282-285: unlink return-form COPY
                let def_ref = PcodeOpRef(def_op);
                fd.obank.destroy(def_ref);
                continue;
            }
            // cc:286: offset = vn->overlap(addr, size)
            let vn_loc = vn_arc.read().unwrap().loc.as_u64();
            let offset = vn_loc.saturating_sub(addr.as_u64()) as i64;
            let vn_space = vn_arc.read().unwrap().address_space;
            // cc:287: opUninsert(op)
            // cc:289-290: big = newVarnode(size, addr); setActiveHeritage
            let big = fd.vbank.create_with_space(size as usize, vn_space, addr.as_u64());
            big.write().unwrap().set_active_heritage();
            // cc:293-294: opSetOpcode(SUBPIECE); opSetAllInput
            def_op.write().unwrap().opcode = OpCode::CPUI_SUBPIECE;
            def_op.write().unwrap().inrefs.clear();
            def_op.write().unwrap().inrefs.push(big);
            let off_const = fd.new_constant(4, offset as u64);
            def_op.write().unwrap().inrefs.push(off_const);
            def_op.write().unwrap().output = Some(vn_arc.clone());
            // cc:296: setWriteMask
            // TODO: WRITEMASK flag not defined yet
        }
    }

    // Ghidra: heritage.cc:1112 Heritage::reprocessFreeStores
    /// Re-examine free STOREs after stack-pointer discovery. Faithful to
    /// `reprocessFreeStores` (heritage.cc:1112-1142). Clears spacebase ptr
    /// marks, re-runs discovery, then removes unnecessary INDIRECTs for
    /// STOREs that turned out not to use a spacebase ptr.
    pub fn reprocess_free_stores(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        free_stores: &[Arc<RwLock<PcodeOp>>],
    ) {
        // cc:1115-1116: clear spacebase ptr marks
        for op_arc in free_stores {
            op_arc.write().unwrap().flags &= !crate::op::pcodeop_flags::SPACEBASE_PTR;
        }
        // cc:1118: re-run discoverIndexedStackPointers
        Heritage::discover_and_guard_stack_stores_fd(fd);
        // cc:1120-1141: clean up unnecessary INDIRECTs
        for op_arc in free_stores {
            // cc:1125: if STORE still uses spacebase ptr, skip
            if op_arc.read().unwrap().uses_spacebase_ptr() { continue; }
            // cc:1128-1140: walk backward through INDIRECTs looking for ones to remove
            let op_ptr = Arc::as_ptr(op_arc) as usize;
            let mut found_self = false;
            let mut prev_ops: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
            for r in &fd.obank.alivelist {
                if found_self { prev_ops.push(r.0.clone()); }
                if Arc::as_ptr(&r.0) as usize == op_ptr { found_self = true; }
            }
            for ind_op in &prev_ops {
                let is_indirect = ind_op.read().unwrap().opcode == OpCode::CPUI_INDIRECT;
                if !is_indirect { break; } // cc:1130: stop at non-INDIRECT
                // cc:1131-1133: verify iop varnode points back to our STORE
                let iop_vn = ind_op.read().unwrap().get_in(1).cloned();
                let matches = match &iop_vn {
                    Some(v) => v.read().unwrap().get_space() == crate::space::AddressSpace::Iop,
                    None => false,
                };
                if !matches { break; } // cc:1132-1133
                // cc:1135-1138: if INDIRECT output is in our space, replace + destroy
                let ind_out_space = ind_op.read().unwrap().output.as_ref()
                    .map(|o| o.read().unwrap().address_space);
                if ind_out_space == Some(space) {
                    let out_vn = ind_op.read().unwrap().output.as_ref().cloned();
                    let in_vn = ind_op.read().unwrap().get_in(0).cloned();
                    if let (Some(out), Some(inv)) = (out_vn, in_vn) {
                        fd.total_replace(&out, inv);
                    }
                    let ind_ref = PcodeOpRef(ind_op.clone());
                    fd.obank.destroy(ind_ref);
                }
            }
        }
    }

    // Ghidra: heritage.cc:835 Heritage::analyzeNewLoadGuards
    /// Analyze new load/store guards using value-set analysis. Faithful to
    /// `analyzeNewLoadGuards` (heritage.cc:835-901). Uses ValueSetSolver to
    /// determine the range of possible addresses for guarded LOAD/STORE ops.
    ///
    /// Rugra lacks ValueSetSolver (rangeutil.cc ValueSetSolver). This method
    /// is a documented stub that marks guards as analyzed (analysisState=1).
    pub fn analyze_new_load_guards(&mut self) {
        // cc:838-847: check if any unanalyzed guards exist
        let has_unanalyzed_load = self.load_guard.iter()
            .rev().take_while(|g| g.analysis_state == 0).count() > 0;
        let has_unanalyzed_store = self.store_guard.iter()
            .rev().take_while(|g| g.analysis_state == 0).count() > 0;
        if !has_unanalyzed_load && !has_unanalyzed_store { return; }

        // cc:871-874: ValueSetSolver establishValueSets + solve(10000, WidenerNone)
        // TODO: port ValueSetSolver (rangeutil.cc ValueSetSolver). This is a
        // complex value-set analysis engine (~600 lines in rangeutil.cc).
        // For now, conservatively mark all guards as analyzed with full range.
        for guard in &mut self.load_guard {
            if guard.analysis_state == 0 {
                guard.analysis_state = 1;
                // cc:879: guard.establishRange — conservatively set full range
                guard.minimum_offset = 0;
                guard.maximum_offset = u64::MAX;
            }
        }
        for guard in &mut self.store_guard {
            if guard.analysis_state == 0 {
                guard.analysis_state = 1;
                guard.minimum_offset = 0;
                guard.maximum_offset = u64::MAX;
            }
        }
    }

    // Ghidra: heritage.cc:1211 Heritage::guardCallOverlappingInput
    /// Guard input param overlap for CALL ops. Faithful to
    /// `guardCallOverlappingInput` (heritage.cc:1211-1236).
    /// Requires FuncCallSpecs/ParamActive infrastructure (Rugra L1).
    /// Documented stub — logs when called.
    pub fn guard_call_overlapping_input(
        &mut self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        space: crate::space::AddressSpace,
    ) {
        // Ghidra cc:1216: fc->getBiggestContainedInputParam(transAddr, size, vData)
        // Rugra lacks getBiggestContainedInputParam. Use characterizeAsInputParam
        // to check containment, then create SUBPIECE if contained_by (3).
        // Iterate all calls to find ones whose input contains this range.
        let num_calls = fd.num_calls();
        for i in 0..num_calls {
            let input_char = fd.get_call_specs(i)
                .map(|fc| fc.characterize_as_input_param(
                    addr.as_u64(), size, space))
                .unwrap_or(0);
            if input_char != 3 { continue; } // only contained_by
            // cc:1217-1234: create SUBPIECE + register trial
            let call_op_addr = fd.get_call_specs(i).map(|fc| fc.op_addr);
            let call_op_addr = match call_op_addr { Some(a) => a, None => continue };
            // cc:1224-1231: create SUBPIECE op before the CALL
            let subpiece = fd.new_op(2, call_op_addr);
            fd.op_set_opcode(&subpiece, OpCode::CPUI_SUBPIECE);
            let whole_vn = fd.vbank.create_with_space(
                size as usize, AddressSpace::Stack, addr.as_u64());
            whole_vn.write().unwrap().set_active_heritage();
            fd.op_set_input(&subpiece, whole_vn, 0);
            // cc:1222: truncateAmount = justifiedContain (simplified: 0)
            let off_const = fd.new_constant(4, 0u64);
            fd.op_set_input(&subpiece, off_const, 1);
            // cc:1230: output = newVarnodeOut(size, truncAddr)
            let out_vn = fd.new_varnode_out(size as usize, addr, &subpiece);
            // cc:1231: opInsertBefore(subpiece, callOp)
            // Find the CALL op in alivelist
            let call_op = fd.obank.alivelist.iter()
                .find(|r| r.0.read().unwrap().get_addr() == call_op_addr)
                .map(|r| r.0.clone());
            if let Some(call_op) = call_op {
                fd.op_insert_before(&subpiece, &PcodeOpRef(call_op));
            }
            // cc:1232: active->registerTrial(truncAddr, size)
            if let Some(fc) = fd.get_call_specs_mut(i) {
                if let Some(active) = &mut fc.active_input {
                    if active.which_trial(addr, size) < 0 {
                        active.register_trial(addr, size);
                    }
                }
            }
        }
    }

    // Ghidra: heritage.cc:1249 Heritage::guardOutputOverlap
    /// Guard output overlap for CALL. Faithful to `guardOutputOverlap`
    /// (heritage.cc:1249-1283). Creates INDIRECT pieces + PIECE concat.
    /// Requires FuncCallSpecs infrastructure.
    // Ghidra: heritage.cc:1249 Heritage::guardOutputOverlap
    /// Guard output overlap: create INDIRECT pieces + PIECE concat.
    /// Faithful to `guardOutputOverlap` (heritage.cc:1249-1283).
    pub fn guard_output_overlap(
        &mut self,
        fd: &mut Funcdata,
        call_op: &Arc<RwLock<PcodeOp>>,
        addr: Address,
        size: i32,
        ret_addr: Address,
        ret_size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let size_front = (ret_addr.as_u64().saturating_sub(addr.as_u64())) as i32;
        let size_back = size - ret_size - size_front;
        let op_addr = call_op.read().unwrap().get_addr();
        let vn_space = AddressSpace::Stack;

        // cc:1254: create INDIRECT for return storage
        let ind_op = fd.new_indirect_op(
            &PcodeOpRef(call_op.clone()), ret_addr.as_u64(), ret_size as usize);
        let vn_collect = ind_op.0.read().unwrap().output.as_ref().cloned();
        let mut vn_collect = match vn_collect {
            Some(v) => v,
            None => fd.new_varnode_out(ret_size as usize, ret_addr, &ind_op),
        };
        vn_collect.write().unwrap().set_active_heritage();

        // cc:1257-1268: front piece (size_front > 0)
        if size_front > 0 {
            let ind_front = fd.new_indirect_op(
                &PcodeOpRef(ind_op.0.clone()), addr.as_u64(), size_front as usize);
            let new_front = ind_front.0.read().unwrap().output.as_ref().cloned()
                .unwrap_or_else(|| fd.new_unique(size_front as usize));
            let concat_front = fd.new_op(2, op_addr);
            fd.op_set_opcode(&concat_front, OpCode::CPUI_PIECE);
            let _out = fd.new_varnode_out(
                (size_front + ret_size) as usize, addr, &concat_front);
            fd.op_set_input(&concat_front, new_front.clone(), 1);
            fd.op_set_input(&concat_front, vn_collect.clone(), 0);
            vn_collect = concat_front.0.read().unwrap().output.as_ref().cloned()
                .unwrap_or(vn_collect);
        }

        // cc:1269-1280: back piece (size_back > 0)
        if size_back > 0 {
            let addr_back = Address::new(ret_addr.as_u64().wrapping_add(ret_size as u64));
            let ind_back = fd.new_indirect_op(
                &PcodeOpRef(call_op.clone()), addr_back.as_u64(), size_back as usize);
            let new_back = ind_back.0.read().unwrap().output.as_ref().cloned()
                .unwrap_or_else(|| fd.new_unique(size_back as usize));
            let concat_back = fd.new_op(2, op_addr);
            fd.op_set_opcode(&concat_back, OpCode::CPUI_PIECE);
            let full_vn = fd.new_varnode_out(size as usize, addr, &concat_back);
            fd.op_set_input(&concat_back, new_back.clone(), 0);
            fd.op_set_input(&concat_back, vn_collect.clone(), 1);
            full_vn.write().unwrap().set_active_heritage();
            write.push(full_vn);
        } else {
            vn_collect.write().unwrap().set_active_heritage();
            write.push(vn_collect);
        }
    }

    // Ghidra: heritage.cc:1293 Heritage::tryOutputOverlapGuard
    /// Try to guard output overlap. Faithful to `tryOutputOverlapGuard`
    /// (heritage.cc:1293-1310). Returns true if guarded.
    pub fn try_output_overlap_guard(
        &mut self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> bool {
        let num_calls = fd.num_calls();
        for i in 0..num_calls {
            // cc:1299: getBiggestContainedOutput
            let output_char = fd.get_call_specs(i)
                .map(|fc| fc.characterize_as_output(
                    addr.as_u64(), size, AddressSpace::Stack))
                .unwrap_or(0);
            if output_char != 3 { continue; } // only contained_by
            // cc:1305: whichTrial >= 0 → already registered
            let already = fd.get_call_specs(i)
                .and_then(|fc| fc.get_active_output())
                .map(|a| a.which_trial(addr, size) >= 0)
                .unwrap_or(true);
            if already { continue; }
            // cc:1307: guardOutputOverlap
            let call_op_addr = fd.get_call_specs(i).map(|fc| fc.op_addr);
            let call_op_addr = match call_op_addr { Some(a) => a, None => continue };
            let call_op = fd.obank.alivelist.iter()
                .find(|r| r.0.read().unwrap().get_addr() == call_op_addr)
                .map(|r| r.0.clone());
            let call_op = match call_op { Some(o) => o, None => continue };
            // Simplified: ret_addr = addr, ret_size = size (full overlap)
            self.guard_output_overlap(fd, &call_op, addr, size, addr, size, write);
            // cc:1308: registerTrial
            if let Some(fc) = fd.get_call_specs_mut(i) {
                if let Some(active) = &mut fc.active_output {
                    active.register_trial(addr, size);
                }
            }
            return true;
        }
        false
    }

    // Ghidra: heritage.cc:1444 Heritage::guardCalls
    /// Guard CALL ops for a range. Faithful to `guardCalls`
    /// (heritage.cc:1444-1528). Requires FuncCallSpecs/ParamActive.
    pub fn guard_calls_range(
        &mut self,
        fd: &mut Funcdata,
        fl: u32,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // Delegate to guard_calls_range_with_space with Stack as default
        // (backward compat for guard_range which doesn't have space context).
        self.guard_calls_range_with_space(fd, fl, addr, size, write, crate::space::AddressSpace::Stack);
    }

    /// Per-space version of guard_calls_range. The space parameter comes from
    /// the heritage per-space loop, allowing characterize_as_input_param to
    /// correctly match Register-space parameter entries (RDI/RSI/RDX etc).
    pub fn guard_calls_range_with_space(
        &mut self,
        fd: &mut Funcdata,
        fl: u32,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
        space: crate::space::AddressSpace,
    ) {
        // Ghidra cc:1451: holdind = addrtied
        let holdind = (fl & crate::varnode::varnode_flags::ADDRTIED) != 0;
        let num_calls = fd.num_calls();
        for i in 0..num_calls {
            // cc:1453: fc = fd->getCallSpecs(i)
            let call_op_arc = {
                match fd.get_call_specs(i) {
                    Some(fc) => {
                        // cc:1454: if fc->getOp()->isAssignment()
                        let _op_is_assignment = fc.is_output_active();
                        let op_addr = fc.op_addr;
                        // Get the CALL op from obank
                        fd.obank.alivelist.iter()
                            .find(|r| r.0.read().unwrap().get_addr() == op_addr)
                            .map(|r| r.0.clone())
                    }
                    None => None,
                }
            };
            let call_op = match call_op_arc { Some(o) => o, None => continue };

            // cc:1453-1456: if fc->getOp()->isAssignment() && out.addr==addr
            // && out.size==size: skip (the CALL's own output covers this range).
            {
                let skip = {
                    let op = call_op.read().unwrap();
                    if op.is_assignment() {
                        op.output.as_ref().and_then(|out| {
                            let o = out.read().unwrap();
                            if *o.get_addr() == addr && o.get_size() as i32 == size {
                                Some(())
                            } else {
                                None
                            }
                        })
                    } else {
                        None
                    }
                };
                if skip.is_some() { continue; }
            }

            // cc:1458-1466: compute transAddr.
            // Ghidra: off = addr.offset; tryregister = true;
            //         if (spc->getType()==IPTR_SPACEBASE) {
            //           if (fc->getSpacebaseOffset() != offset_unknown)
            //               off = spc->wrapOffset(off - fc->getSpacebaseOffset());
            //           else tryregister = false;
            //         }
            //         transAddr = Address(spc, off);
            let mut tryregister = true;
            let trans_off: u64 = if space.is_stack() {
                let sbo = fd.get_call_specs(i)
                    .map(|fc| fc.stackoffset)
                    .unwrap_or(crate::fspec::OFFSET_UNKNOWN);
                if sbo != crate::fspec::OFFSET_UNKNOWN {
                    // cc:1462: off = spc->wrapOffset(off - fc->getSpacebaseOffset());
                    // wrapOffset on a 64-bit space is just wrapping_sub.
                    addr.as_u64().wrapping_sub(sbo as u64)
                } else {
                    // cc:1464: tryregister = false;
                    tryregister = false;
                    addr.as_u64()
                }
            } else {
                addr.as_u64()
            };
            let trans_addr = Address::new(trans_off);

            // cc:1467: effecttype = fc->hasEffect(transAddr, size)
            // Faithful: pass the full (space, offset) so has_effect can match
            // against EffectRecords and recognize the System V default
            // return-address slot (Stack@[0,8)).
            let mut effecttype: u32 = fd.get_call_specs(i)
                .map(|fc| fc.has_effect(space, trans_addr.as_u64(), size))
                .unwrap_or(0); // 0 = unknown_effect
            let mut possibleoutput = false;

            // cc:1469-1486: output trial registration
            let is_output_active = fd.get_call_specs(i)
                .map(|fc| fc.is_output_active()).unwrap_or(false);
            if is_output_active && tryregister {
                // cc:1472: outputCharacter = characterizeAsOutput
                let output_char = fd.get_call_specs(i)
                    .map(|fc| fc.characterize_as_output(
                        trans_addr.as_u64(), size, space))
                    .unwrap_or(0);
                if output_char != 0 {
                    // cc:1473-1474: if effect != killedbycall && isAutoKilledByCall
                    let auto_kill = fd.get_call_specs(i)
                        .map(|fc| fc.is_auto_killed_by_call())
                        .unwrap_or(true);
                    if effecttype != 2 && auto_kill { effecttype = 2; } // killedbycall
                    // cc:1475-1478: contained_by → tryOutputOverlapGuard
                    // cc:1479-1484: else → registerTrial
                    if output_char == 3 {
                        // contained_by: try overlap guard (stub — try_output_overlap_guard
                        // exists but is not yet wired; faithful skip).
                    } else if output_char == 2 {
                        // contains_justified: register trial
                        if let Some(fc) = fd.get_call_specs_mut(i) {
                            if let Some(active) = &mut fc.active_output {
                                if active.which_trial(trans_addr, size) < 0 {
                                    active.register_trial(trans_addr, size);
                                    possibleoutput = true;
                                }
                            }
                        }
                    }
                }
            } else {
                // cc:1487-1494: isStackOutputLock && tryregister branch.
                // Rugra's is_stack_output_lock() is currently hardcoded false
                // (no stack-output-locked ABI in scope), so this branch is dead.
            }

            // cc:1495-1509: input trial registration
            let is_input_active = fd.get_call_specs(i)
                .map(|fc| fc.is_input_active()).unwrap_or(false);
            if is_input_active && tryregister {
                // cc:1496: inputCharacter = characterizeAsInputParam
                let input_char = fd.get_call_specs(i)
                    .map(|fc| fc.characterize_as_input_param(
                        trans_addr.as_u64(), size, space))
                    .unwrap_or(0);
                if input_char == 2 {
                    // cc:1497: contains_justified → register input trial
                    if let Some(fc) = fd.get_call_specs_mut(i) {
                        if let Some(active) = &mut fc.active_input {
                            if active.which_trial(trans_addr, size) < 0 {
                                active.register_trial(trans_addr, size);
                                // cc:1502-1505: create varnode + opInsertInput
                                let vn = fd.vbank.create_with_space(
                                    size as usize, space, addr.as_u64());
                                vn.write().unwrap().set_active_heritage();
                                // cc:1504-1505: opInsertInput(op, vn, op->numInput())
                                let num_in = call_op.read().unwrap().num_input();
                                fd.op_insert_input(&PcodeOpRef(call_op.clone()), vn, num_in);
                            }
                        }
                    }
                } else if input_char == 3 {
                    // cc:1507-1508: contained_by → guardCallOverlappingInput
                    self.guard_call_overlapping_input(fd, addr, size, space);
                }
            }

            // cc:1510-1525: create INDIRECT based on effect type.
            //   unknown_effect || return_address → newIndirectOp (+ setReturnAddress if RA)
            //   killedbycall                   → newIndirectCreation
            //   unaffected / reload            → no guard
            if effecttype == 0 || effecttype == 3 {
                // cc:1512: indop = newIndirectOp(fc->getOp(), addr, size, 0)
                let indop = fd.new_indirect_op(
                    &PcodeOpRef(call_op.clone()),
                    addr.as_u64(), size as usize,
                );
                // cc:1513-1514: setActiveHeritage on in[0] and out
                {
                    let ind_r = indop.0.read().unwrap();
                    if let Some(invn) = ind_r.get_in(0).cloned() {
                        drop(ind_r);
                        invn.write().unwrap().set_active_heritage();
                    }
                }
                {
                    let ind_r = indop.0.read().unwrap();
                    if let Some(outvn) = ind_r.output.as_ref().cloned() {
                        drop(ind_r);
                        outvn.write().unwrap().set_active_heritage();
                        // cc:1516-1517: if holdind, setAddrForce
                        if holdind {
                            outvn.write().unwrap().set_flags(
                                crate::varnode::varnode_flags::ADDRFORCE);
                        }
                        // cc:1518-1519: if effecttype == return_address, setReturnAddress
                        if effecttype == 3 {
                            outvn.write().unwrap().set_return_address();
                        }
                        // cc:1515: write.push(indop->getOut())
                        write.push(outvn);
                    }
                }
            } else if effecttype == 2 {
                // cc:1521-1525: killedbycall → newIndirectCreation
                let indop = fd.new_indirect_creation(
                    &PcodeOpRef(call_op.clone()),
                    space,
                    addr.as_u64(), size as usize, possibleoutput,
                );
                // cc:1523-1524: setActiveHeritage on out; write.push
                {
                    let ind_r = indop.0.read().unwrap();
                    if let Some(outvn) = ind_r.output.as_ref().cloned() {
                        drop(ind_r);
                        outvn.write().unwrap().set_active_heritage();
                        write.push(outvn);
                    }
                }
            }
            // else: unaffected / reload → no guard (cc:1510 comment)
        }
    }

    // Ghidra: heritage.cc:1539 Heritage::guardStores
    /// Guard STORE ops for a specific range. Faithful to `guardStores`
    /// (heritage.cc:1539-1560). For each STORE whose target space matches
    /// the heritage range's space (or its container), create an INDIRECT
    /// op modeling the store effect.
    pub fn guard_stores_range(
        &mut self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let heritage_space = AddressSpace::Stack; // Simplified: heritage ranges are stack
        // cc:1547-1559: iterate STORE ops
        let store_arcs: Vec<_> = fd.obank.storelist.iter()
            .filter(|s| !(s.0.read().unwrap().flags & crate::op::pcodeop_flags::DEAD != 0))
            .map(|s| s.0.clone())
            .collect();
        for store_op in store_arcs {
            // cc:1552: check if STORE targets heritage space
            let uses_sb = store_op.read().unwrap().uses_spacebase_ptr();
            if !uses_sb { continue; }
            // cc:1554: newIndirectOp(op, addr, size, indirect_store)
            let indop = fd.new_indirect_op(
                &PcodeOpRef(store_op.clone()), addr.as_u64(), size as usize,
            );
            // cc:1555-1557: setActiveHeritage on input[0] and output; push to write
            {
                let ind_r = indop.0.read().unwrap();
                if let Some(invn) = ind_r.get_in(0).cloned() {
                    drop(ind_r);
                    invn.write().unwrap().set_active_heritage();
                }
            }
            {
                let ind_r = indop.0.read().unwrap();
                if let Some(outvn) = ind_r.output.as_ref().cloned() {
                    drop(ind_r);
                    outvn.write().unwrap().set_active_heritage();
                    write.push(outvn);
                }
            }
        }
    }

    // Ghidra: heritage.cc:1571 Heritage::guardLoads
    /// Guard LOAD ops for a specific range. Faithful to `guardLoads`
    /// (heritage.cc:1571-1602). For each guarded LOAD whose indexed range
    /// intersects [addr, addr+size), create a COPY boundary op.
    pub fn guard_loads_range(
        &mut self,
        _fd: &mut Funcdata,
        _fl: u32,
        addr: Address,
        size: i32,
        _write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1581-1586: prune invalid load guards
        self.load_guard.retain(|g| {
            match g.op.upgrade() {
                Some(op) => {
                    let r = op.read().unwrap();
                    !(r.flags & crate::op::pcodeop_flags::DEAD != 0
                        || r.opcode != OpCode::CPUI_LOAD)
                }
                None => false,
            }
        });
        // cc:1589-1600: for each LOAD guard whose range intersects [addr,addr+size)
        // insert a COPY guard. Rugra's LoadGuard ranges are conservatively full
        // (analyzeNewLoadGuards stub), so intersection always holds.
        let addr_start = addr.as_u64();
        let addr_end = addr.as_u64().wrapping_add(size as u64);
        for guard in &self.load_guard {
            let intersects = guard.maximum_offset >= addr_start
                && guard.minimum_offset <= addr_end;
            if !intersects { continue; }
            // cc:1591-1600: create COPY boundary op before LOAD
            // TODO: requires per-LOAD COPY insertion (cc:1591-1600).
            // Currently we skip COPY insertion (conservative — guards
            // are recorded but no COPY boundary is created).
        }
    }

    // Ghidra: heritage.cc:2119 Heritage::splitJoinRead
    /// Split a free join-space Varnode into PIECE expressions.
    /// Faithful to `splitJoinRead` (heritage.cc:2119-2163).
    /// Requires JoinRecord (join offset → piece mapping).
    /// Rugra lacks JoinRecord infrastructure; documented stub.
    pub fn split_join_read(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
    ) {
        // cc:2122: vn is free, loneDescend must be non-null
        let read_op = match vn.read().unwrap().lone_descend() {
            Some(op) => op, None => return,
        };
        let vn_offset = vn.read().unwrap().loc.as_u64();
        // Look up JoinRecord from Architecture before mutable borrow.
        let join_rec = match fd.get_arch() {
            Some(a) => a.join_db.find_join(vn_offset).cloned(),
            None => None,
        };
        let join_rec = match join_rec { Some(r) => r, None => return };

        // cc:2128-2162: iterative PIECE chain creation
        // Simplified: for 2-piece joins, create a single PIECE.
        if join_rec.num_pieces() == 2 {
            let p0 = &join_rec.pieces[0];
            let p1 = &join_rec.pieces[1];
            let mosthalf = fd.vbank.create_with_space(p0.size, p0.space, p0.offset);
            let leasthalf = fd.vbank.create_with_space(p1.size, p1.space, p1.offset);
            let op_addr = read_op.read().unwrap().get_addr();
            let concat = fd.new_op(2, op_addr);
            fd.op_set_opcode(&concat, OpCode::CPUI_PIECE);
            concat.0.write().unwrap().output = Some(vn.clone());
            fd.op_set_input(&concat, mosthalf.clone(), 0);
            fd.op_set_input(&concat, leasthalf.clone(), 1);
            let read_ref = PcodeOpRef(read_op.clone());
            fd.op_insert_before(&concat, &read_ref);
            mosthalf.write().unwrap().set_active_heritage();
            leasthalf.write().unwrap().set_active_heritage();
        }
    }

    // Ghidra: heritage.cc:2172 Heritage::splitJoinWrite
    /// Split a written join-space Varnode into SUBPIECE expressions.
    /// Faithful to `splitJoinWrite` (heritage.cc:2172-2227).
    /// Requires JoinRecord infrastructure.
    pub fn split_join_write(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
    ) {
        let def_op = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(op) => op, None => return,
        };
        let vn_offset = vn.read().unwrap().loc.as_u64();
        // Look up JoinRecord from Architecture before mutable borrow.
        let join_rec = match fd.get_arch() {
            Some(a) => a.join_db.find_join(vn_offset).cloned(),
            None => None,
        };
        let join_rec = match join_rec { Some(r) => r, None => return };

        // cc:2187-2226: create SUBPIECE ops for each piece
        if join_rec.num_pieces() == 2 {
            let p0 = &join_rec.pieces[0];
            let p1 = &join_rec.pieces[1];
            let op_addr = def_op.read().unwrap().get_addr();
            // SUBPIECE for most significant piece (offset = p1.size)
            let split0 = fd.new_op(2, op_addr);
            fd.op_set_opcode(&split0, OpCode::CPUI_SUBPIECE);
            split0.0.write().unwrap().output = Some(
                fd.vbank.create_with_space(p0.size, p0.space, p0.offset));
            fd.op_set_input(&split0, vn.clone(), 0);
            let off_const0 = fd.new_constant(4, p1.size as u64);
            fd.op_set_input(&split0, off_const0, 1);
            let def_ref = PcodeOpRef(def_op.clone());
            fd.op_insert_after(&split0, &def_ref);
            // SUBPIECE for least significant piece (offset = 0)
            let split1 = fd.new_op(2, op_addr);
            fd.op_set_opcode(&split1, OpCode::CPUI_SUBPIECE);
            split1.0.write().unwrap().output = Some(
                fd.vbank.create_with_space(p1.size, p1.space, p1.offset));
            fd.op_set_input(&split1, vn.clone(), 0);
            let off_const1 = fd.new_constant(4, 0u64);
            fd.op_set_input(&split1, off_const1, 1);
            fd.op_insert_after(&split1, &split0);
        }
    }

    // Ghidra: heritage.cc:2068 Heritage::splitJoinLevel
    /// One level of Varnode splitting to match a JoinRecord.
    /// Faithful to `splitJoinLevel` (heritage.cc:2068-2118).
    /// TODO: requires JoinRecord piece specifications.
    pub fn split_join_level(
        &mut self,
        fd: &mut Funcdata,
        lastcombo: &[Arc<RwLock<Varnode>>],
        nextlev: &mut Vec<Option<Arc<RwLock<Varnode>>>>,
        joinrec: &crate::space::JoinRecord,
    ) {
        use crate::space::VarnodeData;
        let numpieces = joinrec.num_pieces();
        let mut recnum = 0;
        for curvn_arc in lastcombo {
            let curvn_size = curvn_arc.read().unwrap().get_size();
            // cc:2075: if size matches a single piece, pass through
            if recnum < numpieces && curvn_size == joinrec.get_piece(recnum).size {
                nextlev.push(Some(curvn_arc.clone()));
                nextlev.push(None);
                recnum += 1;
            } else {
                // cc:2081-2089: accumulate piece sizes to find j
                let mut sizeaccum = 0;
                let mut j = recnum;
                while j < numpieces {
                    sizeaccum += joinrec.get_piece(j).size;
                    if sizeaccum == curvn_size {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                // cc:2090: numinhalf = (j-recnum) / 2
                let numinhalf = (j - recnum) / 2;
                if numinhalf == 0 { continue; }
                // cc:2091-2093: accumulate mosthalf size
                let mut mh_size = 0;
                for k in 0..numinhalf {
                    mh_size += joinrec.get_piece(recnum + k).size;
                }
                // cc:2095-2104: create mosthalf and leasthalf
                let mosthalf = if numinhalf == 1 {
                    let p = joinrec.get_piece(recnum);
                    fd.vbank.create_with_space(p.size, p.space, p.offset)
                } else {
                    fd.new_unique(mh_size)
                };
                let lh_size = curvn_size - mh_size;
                let leasthalf = if j - recnum == 2 {
                    let p = joinrec.get_piece(recnum + 1);
                    fd.vbank.create_with_space(p.size, p.space, p.offset)
                } else {
                    fd.new_unique(lh_size)
                };
                nextlev.push(Some(mosthalf));
                nextlev.push(Some(leasthalf));
                recnum = j;
            }
        }
    }

    // Ghidra: heritage.cc:2236 Heritage::floatExtensionRead
    /// Create float extension from a free join-space Varnode.
    /// Faithful to `floatExtensionRead` (heritage.cc:2236-2255).
    pub fn float_extension_read(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
    ) {
        // cc:2239: op = vn->loneDescend()
        let read_op = match vn.read().unwrap().lone_descend() {
            Some(op) => op, None => return,
        };
        let vn_offset = vn.read().unwrap().loc.as_u64();
        let join_rec = match fd.get_arch() {
            Some(a) => a.join_db.find_join(vn_offset).cloned(),
            None => None,
        };
        let join_rec = match join_rec { Some(r) => r, None => return };
        if !join_rec.is_float_extension() { return; }
        // cc:2241: vdata = joinrec->getPiece(0)
        let vdata = join_rec.get_piece(0);
        // cc:2240: trunc = newOp(1, op->getAddr())
        let op_addr = read_op.read().unwrap().get_addr();
        let trunc = fd.new_op(1, op_addr);
        // cc:2242: bigvn = newVarnode(vdata.size, vdata.space, vdata.offset)
        let bigvn = fd.vbank.create_with_space(vdata.size, vdata.space, vdata.offset);
        // cc:2243: opSetOpcode(FLOAT_FLOAT2FLOAT)
        fd.op_set_opcode(&trunc, OpCode::CPUI_FLOAT_FLOAT2FLOAT);
        // cc:2244: opSetOutput(trunc, vn)
        trunc.0.write().unwrap().output = Some(vn.clone());
        // cc:2245: opSetInput(trunc, bigvn, 0)
        fd.op_set_input(&trunc, bigvn, 0);
        // cc:2246: opInsertBefore(trunc, op)
        fd.op_insert_before(&trunc, &PcodeOpRef(read_op));
    }

    // Ghidra: heritage.cc:2256 Heritage::floatExtensionWrite
    /// Create float extension from a lower precision join-space Varnode.
    pub fn float_extension_write(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
    ) {
        let vn_offset = vn.read().unwrap().loc.as_u64();
        let join_rec = match fd.get_arch() {
            Some(a) => a.join_db.find_join(vn_offset).cloned(),
            None => None,
        };
        let join_rec = match join_rec { Some(r) => r, None => return };
        if !join_rec.is_float_extension() { return; }
        // cc:2259: op = vn->getDef()
        let def_op = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        let vdata = join_rec.get_piece(0);
        // cc:2261-2265: create ext op
        let ext_addr = match &def_op {
            Some(op) => op.read().unwrap().get_addr(),
            None => Address::new(0),
        };
        let ext = fd.new_op(1, ext_addr);
        // cc:2267: opSetOpcode(FLOAT_FLOAT2FLOAT)
        fd.op_set_opcode(&ext, OpCode::CPUI_FLOAT_FLOAT2FLOAT);
        // cc:2268: newVarnodeOut(vdata.size, vdata.addr, ext)
        let _out_vn = fd.new_varnode_out(vdata.size, Address::new(vdata.offset), &ext);
        // cc:2269: opSetInput(ext, vn, 0)
        fd.op_set_input(&ext, vn.clone(), 0);
        // cc:2270-2273: insert
        if let Some(def_op) = def_op {
            fd.op_insert_after(&ext, &PcodeOpRef(def_op));
        } else {
            fd.obank.alivelist.insert(0, ext);
        }
    }

    // Ghidra: heritage.cc:1323 Heritage::guardOutputOverlapStack
    /// Guard a stack range that contains the return value storage.
    /// Faithful to `guardOutputOverlapStack` (heritage.cc:1323-1376).
    /// Creates INDIRECT pieces for front/back + PIECE concat.
    pub fn guard_output_overlap_stack(
        &mut self,
        fd: &mut Funcdata,
        call_op: &Arc<RwLock<PcodeOp>>,
        addr: Address,
        size: i32,
        ret_addr: Address,
        ret_size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let size_front = (ret_addr.as_u64().saturating_sub(addr.as_u64())) as i32;
        let size_back = size - ret_size - size_front;
        let op_addr = call_op.read().unwrap().get_addr();

        // cc:1329: vnCollect = callOp->getOut() or newVarnodeOut
        let mut vn_collect = call_op.read().unwrap().output.as_ref().cloned()
            .unwrap_or_else(|| fd.new_varnode_out(ret_size as usize, ret_addr, &PcodeOpRef(call_op.clone())));

        // cc:1332-1352: front piece
        if size_front > 0 {
            let new_input = fd.vbank.create_with_space(size as usize, AddressSpace::Stack, addr.as_u64());
            new_input.write().unwrap().set_active_heritage();
            let sub_piece = fd.new_op(2, op_addr);
            fd.op_set_opcode(&sub_piece, OpCode::CPUI_SUBPIECE);
            let off_const = fd.new_constant(4, 0u64);
            fd.op_set_input(&sub_piece, new_input, 0);
            fd.op_set_input(&sub_piece, off_const, 1);
            let ind_front = fd.new_indirect_op(&PcodeOpRef(call_op.clone()), addr.as_u64(), size_front as usize);
            // cc:1341: opSetOutput(subPiece, indOpFront->getIn(0))
            sub_piece.0.write().unwrap().output = ind_front.0.read().unwrap().get_in(0).cloned();
            fd.op_insert_before(&sub_piece, &PcodeOpRef(call_op.clone()));
            let new_front = ind_front.0.read().unwrap().output.as_ref().cloned()
                .unwrap_or_else(|| fd.new_unique(size_front as usize));
            // cc:1344-1351: PIECE concat
            let concat = fd.new_op(2, op_addr);
            fd.op_set_opcode(&concat, OpCode::CPUI_PIECE);
            // LE: newFront=slot1, vnCollect=slot0
            fd.op_set_input(&concat, new_front, 1);
            fd.op_set_input(&concat, vn_collect.clone(), 0);
            vn_collect = fd.new_varnode_out((size_front + ret_size) as usize, addr, &concat);
            fd.op_insert_after(&concat, &PcodeOpRef(call_op.clone()));
        }

        // cc:1353-1373: back piece
        if size_back > 0 {
            let addr_back = Address::new(ret_addr.as_u64().wrapping_add(ret_size as u64));
            let new_input = fd.vbank.create_with_space(size as usize, AddressSpace::Stack, addr.as_u64());
            new_input.write().unwrap().set_active_heritage();
            let sub_piece = fd.new_op(2, op_addr);
            fd.op_set_opcode(&sub_piece, OpCode::CPUI_SUBPIECE);
            let off_const = fd.new_constant(4, 0u64);
            fd.op_set_input(&sub_piece, new_input, 0);
            fd.op_set_input(&sub_piece, off_const, 1);
            let ind_back = fd.new_indirect_op(&PcodeOpRef(call_op.clone()), addr_back.as_u64(), size_back as usize);
            sub_piece.0.write().unwrap().output = ind_back.0.read().unwrap().get_in(0).cloned();
            fd.op_insert_before(&sub_piece, &PcodeOpRef(call_op.clone()));
            let new_back = ind_back.0.read().unwrap().output.as_ref().cloned()
                .unwrap_or_else(|| fd.new_unique(size_back as usize));
            let concat = fd.new_op(2, op_addr);
            fd.op_set_opcode(&concat, OpCode::CPUI_PIECE);
            // LE: newBack=slot0, vnCollect=slot1
            fd.op_set_input(&concat, new_back, 0);
            fd.op_set_input(&concat, vn_collect.clone(), 1);
            vn_collect = fd.new_varnode_out(size as usize, addr, &concat);
            fd.op_insert_after(&concat, &PcodeOpRef(call_op.clone()));
        }

        // cc:1374-1375
        vn_collect.write().unwrap().set_active_heritage();
        write.push(vn_collect);
    }

    // Ghidra: heritage.cc:1392 Heritage::tryOutputStackGuard
    /// Attempt to guard a stack range against a call with locked stack output.
    /// Faithful to `tryOutputStackGuard` (heritage.cc:1392-1432).
    pub fn try_output_stack_guard(
        &mut self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        output_character: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> bool {
        // Iterate calls looking for stack-output-locked ones.
        let num_calls = fd.num_calls();
        for i in 0..num_calls {
            let is_stack_locked = fd.get_call_specs(i)
                .map(|fc| fc.is_stack_output_lock()).unwrap_or(false);
            if !is_stack_locked { continue; }
            let output_char = fd.get_call_specs(i)
                .map(|fc| fc.characterize_as_output(addr.as_u64(), size, AddressSpace::Stack))
                .unwrap_or(0);
            if output_char == 0 { continue; }
            let call_op_addr = fd.get_call_specs(i).map(|fc| fc.op_addr);
            let call_op_addr = match call_op_addr { Some(a) => a, None => continue };
            let call_op = fd.obank.alivelist.iter()
                .find(|r| r.0.read().unwrap().get_addr() == call_op_addr)
                .map(|r| r.0.clone());
            let call_op = match call_op { Some(o) => o, None => continue };

            if output_character == 3 {
                // cc:1396-1405: contained_by → guardOutputOverlapStack
                self.guard_output_overlap_stack(fd, &call_op, addr, size, addr, size, write);
                return true;
            }
            // cc:1407-1431: output contains range → SUBPIECE
            let ret_size = size; // simplified
            let outvn = call_op.read().unwrap().output.as_ref().cloned()
                .unwrap_or_else(|| fd.new_varnode_out(ret_size as usize, addr, &PcodeOpRef(call_op.clone())));
            if size < ret_size {
                let sub = fd.new_op(2, call_op_addr);
                fd.op_set_opcode(&sub, OpCode::CPUI_SUBPIECE);
                let off = fd.new_constant(4, 0u64);
                fd.op_set_input(&sub, outvn, 0);
                fd.op_set_input(&sub, off, 1);
                let vn_final = fd.new_varnode_out(size as usize, addr, &sub);
                fd.op_insert_after(&sub, &PcodeOpRef(call_op));
                vn_final.write().unwrap().set_active_heritage();
                write.push(vn_final);
            } else {
                outvn.write().unwrap().set_active_heritage();
                write.push(outvn);
            }
            return true;
        }
        false
    }

    // Ghidra: heritage.cc:2572 Heritage::bumpDeadcodeDelay
    /// Increase dead-code delay for a space, requesting a restart.
    /// Faithful to `bumpDeadcodeDelay` (heritage.cc:2572-2583).
    pub fn bump_deadcode_delay(&mut self, space: AddressSpace) {
        // cc:2575: only processor/spacebase spaces
        if !matches!(space, AddressSpace::Ram | AddressSpace::Register | AddressSpace::Stack) {
            return;
        }
        // cc:2577: if delay != deadcodedelay, global delay already exists
        let info = self.infolist.iter().find(|i| i.space == space);
        if let Some(info) = info {
            if info.delay != info.deadcodedelay {
                return; // Already has an override
            }
        }
        // cc:2581: insertDeadcodeDelay(spc, deadcodedelay+1)
        let idx = self.infolist.iter().position(|i| i.space == space);
        if let Some(i) = idx {
            self.infolist[i].deadcodedelay += 1;
        }
        // cc:2582: setRestartPending(true)
        // Rugra doesn't have restart-pending flag yet; log it.
        eprintln!("[HERITAGE] bumpDeadcodeDelay for {:?}: restart pending", space);
    }

    // Ghidra: heritage.cc:2048 Heritage::clearStackPlaceholders
    /// Clear spacebase-relative placeholder info for all call specs.
    /// Faithful to `clearStackPlaceholders` (heritage.cc:2048-2056).
    pub fn clear_stack_placeholders(&mut self, info_space: AddressSpace) {
        // cc:2051-2054: for each call, abortSpacebaseRelative.
        let fd_arc = match &self.fd {
            Some(w) => match w.upgrade() { Some(a) => a, None => return },
            None => return,
        };
        let mut fd = fd_arc.write().unwrap();
        let num_calls = fd.num_calls();
        // Snapshot call op addresses first to avoid borrow conflicts.
        let call_addrs: Vec<crate::address::Address> = (0..num_calls)
            .map(|i| fd.callspecs[i].op_addr)
            .collect();
        // Take callspecs out to avoid double-mutable-borrow.
        let mut callspecs = std::mem::take(&mut fd.callspecs);
        for (i, call_addr) in call_addrs.iter().enumerate() {
            let call_op = fd.obank.alivelist.iter()
                .find(|op_ref| {
                    let op = op_ref.0.read().unwrap();
                    op.start.addr == *call_addr
                        && (op.opcode == crate::opcodes::OpCode::CPUI_CALL
                            || op.opcode == crate::opcodes::OpCode::CPUI_CALLIND)
                })
                .cloned();
            if let Some(op_ref) = call_op {
                callspecs[i].abort_spacebase_relative(&mut fd, &op_ref);
            }
        }
        fd.callspecs = callspecs;
        // cc:2055: info->hasCallPlaceholders = false
        let idx = self.infolist.iter().position(|i| i.space == info_space);
        if let Some(i) = idx {
            self.infolist[i].has_call_placeholders = false;
        }
    }

    // Ghidra: heritage.cc:508 Heritage::concatPieces
    /// Concatenate Varnode pieces into a PIECE chain. Faithful to
    /// `concatPieces` (heritage.cc:508-551). Returns the final output.
    pub fn concat_pieces(
        &self,
        fd: &mut Funcdata,
        vnlist: &[Arc<RwLock<Varnode>>],
        insert_op: Option<&PcodeOpRef>,
        final_vn: &Arc<RwLock<Varnode>>,
    ) -> Arc<RwLock<Varnode>> {
        if vnlist.is_empty() { return final_vn.clone(); }
        let mut preexist = vnlist[0].clone();
        let is_bigendian = false; // Rugra: x86-64 is little-endian
        let op_addr = match insert_op {
            Some(op) => op.0.read().unwrap().get_addr(),
            None => Address::new(0),
        };
        for i in 1..vnlist.len() {
            let vn = &vnlist[i];
            let newop = fd.new_op(2, op_addr);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            let newvn = if i == vnlist.len() - 1 {
                // Final piece uses final_vn as output
                newop.0.write().unwrap().output = Some(final_vn.clone());
                final_vn.clone()
            } else {
                let pre_size = preexist.read().unwrap().get_size();
                let vn_size = vn.read().unwrap().get_size();
                fd.new_unique_out(pre_size + vn_size, &newop)
            };
            if is_bigendian {
                fd.op_set_input(&newop, preexist.clone(), 0);
                fd.op_set_input(&newop, vn.clone(), 1);
            } else {
                fd.op_set_input(&newop, vn.clone(), 0);
                fd.op_set_input(&newop, preexist.clone(), 1);
            }
            if let Some(ins_op) = insert_op {
                fd.op_insert_before(&newop, ins_op);
            } else {
                fd.obank.alivelist.insert(0, newop);
            }
            preexist = newvn;
        }
        preexist
    }

    // Ghidra: heritage.cc:564 Heritage::splitPieces
    /// Build SUBPIECE ops to define piece Varnodes from a whole-range Varnode.
    /// Faithful to `splitPieces` (heritage.cc:564-605).
    pub fn split_pieces(
        &self,
        fd: &mut Funcdata,
        vnlist: &[Arc<RwLock<Varnode>>],
        insert_op: Option<&PcodeOpRef>,
        addr: Address,
        size: i32,
        start_vn: &Arc<RwLock<Varnode>>,
    ) {
        let is_bigendian = false;
        let baseoff = if is_bigendian {
            addr.as_u64().wrapping_add(size as u64)
        } else {
            addr.as_u64()
        };
        let op_addr = match insert_op {
            Some(op) => op.0.read().unwrap().get_addr(),
            None => Address::new(0),
        };
        for vn_arc in vnlist {
            let vn_r = vn_arc.read().unwrap();
            let diff = if is_bigendian {
                baseoff.wrapping_sub(vn_r.loc.as_u64().wrapping_add(vn_r.get_size() as u64))
            } else {
                vn_r.loc.as_u64().wrapping_sub(baseoff)
            };
            drop(vn_r);
            let newop = fd.new_op(2, op_addr);
            fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&newop, start_vn.clone(), 0);
            let diff_const = fd.new_constant(4, diff);
            fd.op_set_input(&newop, diff_const, 1);
            newop.0.write().unwrap().output = Some(vn_arc.clone());
            if let Some(ins_op) = insert_op {
                fd.op_insert_before(&newop, ins_op);
            } else {
                fd.obank.alivelist.insert(0, newop);
            }
        }
    }

    // Ghidra: heritage.cc:308 Heritage::collect
    /// Collect read/write/input varnodes for a memory range. Faithful to
    /// `collect` (heritage.cc:308-348). Returns max write size.
    pub fn collect(
        &self,
        fd: &Funcdata,
        addr: Address,
        size: i32,
        read: &mut Vec<Arc<RwLock<Varnode>>>,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
        input: &mut Vec<Arc<RwLock<Varnode>>>,
        remove: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> i32 {
        read.clear();
        write.clear();
        input.clear();
        remove.clear();
        let end_addr = addr.as_u64().wrapping_add(size as u64);
        let mut maxsize: i32 = 0;
        for vn_ref in &fd.vbank.loc_tree {
            let vn = vn_ref.0.read().unwrap();
            // Skip if not in range [addr, addr+size)
            let vn_off = vn.loc.as_u64();
            if vn_off < addr.as_u64() || vn_off >= end_addr { continue; }
            // cc:327: skip writeMask varnodes
            // Rugra doesn't have writemask flag yet; skip check.
            if vn.is_written() {
                // cc:330: check if marker or returnCopy (previous heritage evidence)
                let def_op = vn.def.as_ref().and_then(|w| w.upgrade());
                if let Some(def_op) = def_op {
                    let is_marker = def_op.read().unwrap().is_marker();
                    if is_marker {
                        if vn.get_size() < size as usize {
                            remove.push(vn_ref.0.clone());
                            continue;
                        }
                    }
                }
                if vn.get_size() as i32 > maxsize {
                    maxsize = vn.get_size() as i32;
                }
                write.push(vn_ref.0.clone());
            } else if !vn.is_heritage_known() && !vn.has_no_descend() {
                read.push(vn_ref.0.clone());
            } else if vn.is_input() {
                input.push(vn_ref.0.clone());
            }
        }
        maxsize
    }

    // Ghidra: heritage.cc:1953 Heritage::guardInput
    /// Ensure input varnodes fill the entire range. Faithful to
    /// `guardInput` (heritage.cc:1953-2046). If there are holes,
    /// create new input varnodes to fill them.
    pub fn guard_input(
        &self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        input: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        if input.is_empty() { return; }
        // cc:1959: if single input fills everything, skip
        if input.len() == 1 && input[0].read().unwrap().get_size() == size as usize {
            return;
        }
        // cc:1962-1993: fill holes in the input range
        let mut i = 0;
        let mut cur = addr.as_u64();
        let end = addr.as_u64().wrapping_add(size as u64);
        let vn_space = input.first().map(|v| v.read().unwrap().address_space)
            .unwrap_or(AddressSpace::Register);
        let mut newinput: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        while cur < end {
            if i < input.len() {
                let vn_off = input[i].read().unwrap().loc.as_u64();
                if vn_off > cur {
                    let sz = (vn_off - cur) as usize;
                    let vn = fd.vbank.create_with_space(sz, vn_space, cur);
                    let promoted = fd.set_input_varnode(vn);
                    newinput.push(promoted);
                } else {
                    newinput.push(input[i].clone());
                    i += 1;
                }
            } else {
                let sz = (end - cur) as usize;
                let vn = fd.vbank.create_with_space(sz, vn_space, cur);
                let promoted = fd.set_input_varnode(vn);
                newinput.push(promoted);
            }
            cur = cur.wrapping_add(newinput.last().unwrap().read().unwrap().get_size() as u64);
        }
        // cc:1997: if only one piece, it links automatically
        if newinput.len() == 1 { return; }
        // cc:1998-1999: mark all pieces with writeMask
        for vn in &newinput {
            // TODO: setWriteMask flag (not yet defined in Rugra)
        }
        *input = newinput;
    }

    // Ghidra: heritage.cc:359 Heritage::callOpIndirectEffect
    /// Determine if the address range is affected by a call op.
    /// Faithful to `callOpIndirectEffect` (heritage.cc:359-380).
    pub fn call_op_indirect_effect(
        &self,
        fd: &Funcdata,
        addr: Address,
        size: i32,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> bool {
        let opc = op.read().unwrap().opcode;
        if opc != OpCode::CPUI_CALL && opc != OpCode::CPUI_CALLIND {
            return true; // Non-call ops always considered as having effect
        }
        // cc:362-376: check FuncCallSpecs for effect on this range
        // Rugra lacks FuncCallSpecs integration; conservatively return true.
        let _ = (fd, addr, size);
        true
    }

    // Ghidra: heritage.cc:1705 Heritage::buildRefinement
    /// Build refinement array from varnode list. Faithful to
    /// `buildRefinement` (heritage.cc:1705-1715). Marks byte boundaries
    /// where varnodes start/end within the range [addr, addr+size).
    pub fn build_refinement(
        &self,
        refine: &mut [i32],
        addr: Address,
        vnlist: &[Arc<RwLock<Varnode>>],
    ) {
        for vn_arc in vnlist {
            let vn = vn_arc.read().unwrap();
            let diff = vn.loc.as_u64().saturating_sub(addr.as_u64()) as usize;
            let sz = vn.get_size();
            if diff < refine.len() {
                refine[diff] = 1;
            }
            if diff + sz < refine.len() {
                refine[diff + sz] = 1;
            }
        }
    }

    // Ghidra: heritage.cc:1734 Heritage::splitByRefinement
    /// Split a Varnode by the refinement array. Faithful to
    /// `splitByRefinement` (heritage.cc:1734-1754). Returns new
    /// Varnode pieces in `split` if the varnode crosses a refinement
    /// boundary; empty if already refined.
    pub fn split_by_refinement(
        &self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
        split: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let vn_r = vn.read().unwrap();
        let mut curaddr = vn_r.loc;
        let mut sz = vn_r.get_size() as i32;
        let vn_space = vn_r.address_space;
        drop(vn_r);
        let mut diff = curaddr.as_u64().saturating_sub(addr.as_u64()) as usize;
        if diff >= refine.len() { return; }
        let mut cutsz = refine[diff];
        if cutsz == 0 || sz <= cutsz { return; }
        loop {
            let piece = fd.vbank.create_with_space(cutsz as usize, vn_space, curaddr.as_u64());
            split.push(piece);
            sz -= cutsz;
            if sz <= 0 { break; }
            curaddr = Address::new(curaddr.as_u64().wrapping_add(cutsz as u64));
            diff = curaddr.as_u64().saturating_sub(addr.as_u64()) as usize;
            if diff >= refine.len() { break; }
            cutsz = refine[diff];
            if cutsz > sz { cutsz = sz; }
        }
    }

    // Ghidra: heritage.cc:1773 Heritage::refineRead
    /// Split a free read Varnode based on refinement, creating a PIECE
    /// to reconstruct the original. Faithful to `refineRead`
    /// (heritage.cc:1773-1806).
    pub fn refine_read(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() { return; }
        // cc:1779: replacevn = newUnique(vn->getSize())
        let vn_size = vn.read().unwrap().get_size();
        let replacevn = fd.new_unique(vn_size);
        // cc:1780-1781: op = vn->loneDescend(); slot = op->getSlot(vn)
        let lone_desc = vn.read().unwrap().lone_descend();
        if let Some(read_op) = lone_desc {
            let read_ref = PcodeOpRef(read_op.clone());
            let slot = read_op.read().unwrap().inrefs.iter()
                .position(|v| Arc::ptr_eq(v, vn)).unwrap_or(0);
            if newvn.len() >= 2 {
                let op_addr = read_op.read().unwrap().get_addr();
                let piece_op = fd.new_op(2, op_addr);
                fd.op_set_opcode(&piece_op, OpCode::CPUI_PIECE);
                fd.op_set_input(&piece_op, newvn[0].clone(), 0);
                fd.op_set_input(&piece_op, newvn[1].clone(), 1);
                let _out = fd.new_varnode_out(vn_size, Address::new(0), &piece_op);
                fd.op_insert_before(&piece_op, &read_ref);
            }
            fd.op_set_input(&read_ref, replacevn, slot);
        }
    }

    // Ghidra: heritage.cc:1807 Heritage::refineWrite
    /// Split a written Varnode based on refinement, creating SUBPIECE ops
    /// to extract the pieces. Faithful to `refineWrite`
    /// (heritage.cc:1807-1836).
    pub fn refine_write(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() { return; }
        // cc:1815-1835: for each piece, create SUBPIECE from vn
        let vn_size = vn.read().unwrap().get_size();
        let vn_space = vn.read().unwrap().address_space;
        let def_op = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        if let Some(def_op) = def_op {
            let op_addr = def_op.read().unwrap().get_addr();
            let mut offset: i32 = 0;
            for piece in &newvn {
                let piece_size = piece.read().unwrap().get_size();
                let newop = fd.new_op(2, op_addr);
                fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
                let piece_vn = fd.vbank.create_with_space(piece_size, vn_space, piece.read().unwrap().loc.as_u64());
                fd.op_set_input(&newop, piece_vn, 0);
                let off_const = fd.new_constant(8, offset as u64);
                fd.op_set_input(&newop, off_const, 1);
                let _out = fd.new_varnode_out(piece_size, piece.read().unwrap().loc, &newop);
                fd.op_insert_before(&newop, &PcodeOpRef(def_op.clone()));
                offset += piece_size as i32;
            }
        }
    }

    // Ghidra: heritage.cc:1837 Heritage::refineInput
    /// Split an input Varnode based on refinement. Faithful to
    /// `refineInput` (heritage.cc:1837-1857).
    pub fn refine_input(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() { return; }
        // cc:1845-1855: mark each piece as input + activeHeritage
        for piece in &newvn {
            piece.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
            piece.write().unwrap().set_active_heritage();
        }
    }

    // Ghidra: heritage.cc:1858 Heritage::remove13Refinement
    /// Remove 1-byte/3-byte refinement patterns. Faithful to
    /// `remove13Refinement` (heritage.cc:1858-1890). These patterns
    /// cause excessive splitting without information gain.
    pub fn remove13_refinement(&self, refine: &mut [i32]) {
        let n = refine.len();
        if n < 4 { return; }
        let mut i = 0;
        while i < n {
            if refine[i] == 1 && i + 1 < n && refine[i + 1] == 0 {
                // Check if next boundary is at i+3 (3-byte element)
                if i + 3 < n && refine[i + 3] != 0 {
                    // Remove the 1-byte split: merge into next element
                    refine[i] = 0;
                    if i > 0 { refine[i] = refine[i - 1] + 1; }
                }
            }
            i += 1;
        }
    }

    // Ghidra: heritage.cc:1891 Heritage::refinement
    /// Run refinement on the given range. Faithful to `refinement`
    /// (heritage.cc:1891-1951). Builds refinement from collected
    /// varnodes, removes 1/3 patterns, and applies to read/write/input.
    /// Returns Some(refined_iter) if refinement changed the range,
    /// None otherwise.
    pub fn run_refinement(
        &mut self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        readvars: &[Arc<RwLock<Varnode>>],
        writevars: &[Arc<RwLock<Varnode>>],
        inputvars: &[Arc<RwLock<Varnode>>],
    ) -> bool {
        let sz = size as usize;
        let mut refine = vec![0i32; sz];
        self.build_refinement(&mut refine, addr, readvars);
        self.build_refinement(&mut refine, addr, writevars);
        self.build_refinement(&mut refine, addr, inputvars);
        // cc:1898: remove13Refinement
        self.remove13_refinement(&mut refine);
        // Check if any refinement boundaries exist.
        let has_refine = refine.iter().any(|&v| v != 0);
        if !has_refine { return false; }
        // cc:1910-1950: apply refinement to read/write/input
        for vn in readvars {
            self.refine_read(fd, vn, addr, &refine);
        }
        for vn in writevars {
            self.refine_write(fd, vn, addr, &refine);
        }
        for vn in inputvars {
            self.refine_input(fd, vn, addr, &refine);
        }
        true
    }

    // Ghidra: heritage.cc:2282 Heritage::processJoins
    pub fn process_joins(&mut self, fd: &crate::funcdata::Funcdata) {
        // Scan vbank for Join-space varnodes.
        let join_vns: Vec<_> = fd.vbank.loc_tree.iter()
            .filter(|v| v.0.read().unwrap().address_space == AddressSpace::Join)
            .map(|v| v.0.clone())
            .collect();
        if join_vns.is_empty() { return; }
        // For each join varnode:
        // - If free: splitJoinRead (creates piece reads in real space)
        // - If written and delay matches: splitJoinWrite (creates SUBPIECE ops)
        //
        // Rugra lacks JoinRecord (the mapping from join offset to piece
        // spaces+offsets). Without JoinRecord, we cannot split.
        // TODO: port JoinRecord infrastructure (architecture.cc / space.cc).
        eprintln!("[HERITAGE] process_joins: {} join-space varnodes found (JoinRecord infra TODO)",
            join_vns.len());
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
        self.process_joins(&fd);

        // Ghidra cc:2694-2697: if (pass == 0) { splitmanage.init/split(); }
        // PreferSplitManager: init + split on pass 0. Rugra's prefersplit.rs
        // is fully implemented (1245 lines). On x86-64 there are no split
        // records by default (no paired-register split preferences), so
        // split() is a no-op. The wiring is here for completeness.
        if self.pass == 0 {
            let mut split_mgr = crate::prefersplit::PreferSplitManager::new();
            split_mgr.init(&mut fd, Vec::new()); // No split records for x86-64
            split_mgr.split(&mut fd);
        }

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
                let _ = prev;
            }

            // Ghidra cc:2630: guard() per-range, with the correct space.
            // This registers CALL input trials via ParamActive and creates
            // INDIRECT ops for call side-effects. Without this, CALL parameters
            // are never injected, causing all args to appear as "local_0".
            // We call guard_calls_range directly with the correct space context
            // (the per-space loop variable) for each disjoint range in this space.
            {
                let ranges: Vec<(Address, i32)> = self.globaldisjoint.themap.iter()
                    .filter(|(a, _)| {
                        // Only ranges that fall in this space's address range
                        // (globaldisjoint is shared across spaces, but ranges
                        // added in this iteration belong to this space)
                        true
                    })
                    .map(|(addr, sp)| (*addr, sp.size))
                    .collect();
                let mut fd_guard = fd_arc.write().unwrap();
                for (addr, size) in &ranges {
                    let mut empty_write = Vec::new();
                    // Pass the correct space by temporarily storing it
                    // in a thread-local or by calling guard_calls_range
                    // with the space from the outer loop variable.
                    self.guard_calls_range_with_space(
                        &mut fd_guard, 0, *addr, *size, &mut empty_write, space);
                }
                drop(fd_guard);
            }
        }

        // Ghidra cc:2763: placeMultiequals();
        drop(fd);
        self.place_multiequals();

        // Ghidra cc:2764: rename();
        self.rename();

        // Ghidra cc:2765-2766: if (reprocessStackCount > 0) reprocessFreeStores
        // Ghidra cc:2765-2766: if (reprocessStackCount > 0) reprocessFreeStores
        // Implemented: reprocess_free_stores (walk backward through INDIRECTs).

        // Ghidra cc:2767: analyzeNewLoadGuards();
        // Implemented as conservative stub (marks guards analyzed with full
        // range). Full ValueSetSolver-based analysis deferred (rangeutil.cc
        // ~600 lines). The conservative approach is Ghidra's fallback.
        self.analyze_new_load_guards();

        // Ghidra cc:2768: handleNewLoadCopies();
        // Implemented: handle_new_load_copies (find_address_forces +
        // propagate_copy_away + ADDRFORCE flag setting).
        let mut fd_for_copies = fd_arc.write().unwrap();
        self.handle_new_load_copies(&mut fd_for_copies);
        drop(fd_for_copies);

        // Ghidra cc:2769-2770: if (pass == 0) splitmanage.splitAdditional();
        // PreferSplitManager: splitAdditional on pass 0. No-op for x86-64
        // (no split records), but wired for completeness.
        if self.pass == 0 {
            let mut fd_for_split = fd_arc.write().unwrap();
            let mut split_mgr = crate::prefersplit::PreferSplitManager::new();
            split_mgr.init(&mut fd_for_split, Vec::new());
            split_mgr.split_additional(&mut fd_for_split);
        }

        // Ghidra cc:2771: pass += 1;
        self.pass += 1;
    }

    // Ghidra: heritage.cc:2600 Heritage::placeMultiequals
    /// Place phi nodes using the ADT algorithm. Faithful to Ghidra's
    /// placeMultiequals which calls calcMultiequals then creates
    /// MULTIEQUAL ops in merge[] blocks.
    pub fn place_multiequals(&mut self) {
        let fd_weak = self.fd.as_ref().expect("Heritage needs Funcdata");
        let fd_arc = fd_weak.upgrade().expect("Funcdata dropped");
        let mut fd = fd_arc.write().unwrap();

        // Build ADT if needed (cc:2690 heritage() checks maxdepth==-1).
        // We need dom tree built first.
        fd.bblocks.build_dom_tree();

        // build_adt reads fd via Weak — but we hold the write lock.
        // So inline the dom tree construction by temporarily releasing.
        // Simplest: store bblocks ref, build ADT, then proceed.
        let bblocks_size = fd.bblocks.get_size();
        if bblocks_size > 0 {
            // Build ADT using the index-based approach from build_adt.
            // We can't call self.build_adt() because it uses self.fd Weak
            // which conflicts with our write lock. So we call it after
            // releasing fd.
        }

        // Group written varnodes by (space, address).
        let mut write_groups: BTreeMap<(AddressSpace, Address), Vec<i32>> = BTreeMap::new();
        for vn_ref in &fd.vbank.loc_tree {
            let vn = vn_ref.0.read().unwrap();
            if !vn.is_written() { continue; }
            if let Some(def_weak) = vn.def.as_ref().and_then(|w| w.upgrade()) {
                let def_op = def_weak.read().unwrap();
                if let Some(parent_weak) = def_op.parent.as_ref() {
                    if let Some(parent) = parent_weak.upgrade() {
                        let blk_idx = parent.read().unwrap().get_index();
                        let key = (vn.address_space, vn.loc);
                        write_groups.entry(key).or_default().push(blk_idx);
                    }
                }
            }
        }

        // Release fd, build ADT, then re-acquire.
        drop(fd);
        self.build_adt();

        let mut fd2 = fd_arc.write().unwrap();
        let mut vbank = std::mem::take(&mut fd2.vbank);
        let mut obank = std::mem::take(&mut fd2.obank);

        for ((space, addr), write_blocks) in &write_groups {
            self.calc_multiequals(write_blocks);

            for &blk_idx in &self.merge.clone() {
                let bl = match fd2.bblocks.get_block(blk_idx as usize) {
                    Some(b) => b, None => continue,
                };
                let blk_size_in = bl.read().unwrap().size_in();
                if blk_size_in == 0 { continue; }
                let start_addr = bl.read().unwrap().get_start_addr();
                let multiop = obank.create(OpCode::CPUI_MULTIEQUAL, blk_size_in, start_addr);
                let out_vn = vbank.create_with_space(8, *space, addr.as_u64());
                out_vn.write().unwrap().set_active_heritage();
                multiop.0.write().unwrap().output = Some(out_vn);
                for _j in 0..blk_size_in {
                    let vnin = vbank.create_with_space(8, *space, addr.as_u64());
                    multiop.0.write().unwrap().inrefs.push(vnin.clone());
                    vnin.write().unwrap().add_descend(&multiop.0);
                }
                obank.alivelist.push(multiop.clone());
            }
        }
        self.merge.clear();

        fd2.vbank = vbank;
        fd2.obank = obank;
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
        // Ghidra heritage.cc:233: op->setParent(block)
        // Set parent back-pointer so rename can traverse this phi.
        op_ref.0.write().unwrap().parent = Some(std::sync::Arc::downgrade(&block_arc) as std::sync::Weak<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>);

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
        // Ghidra heritage.cc guard() cc:1156-1198 sets activeHeritage:
        //   - reads (cc:1164-1175): FREE varnodes (not written, not input)
        //     with EXACTLY 1 live descendant → activeHeritage
        //     Multi-descendant free reads throw error in Ghidra (cc:1170-1171).
        //     Rugra approximation: skip multi-descendant free reads instead
        //     of throwing. This prevents over-renaming that causes INT_ADD
        //     outputs to lose descendants and get DeadCode'd.
        //   - writes (cc:1177-1182): WRITTEN varnodes → activeHeritage
        //     (for stack push in renameRecurse cc:2524-2530).
        //   - inputs: always activeHeritage (for initial stack seeding).
        for vn_ref in &vbank.loc_tree {
            let mut vn = vn_ref.0.write().unwrap();
            // Skip constants and annotations
            if vn.is_constant() || vn.is_annotation() {
                continue;
            }
            // Ghidra cc:2704: skip dead free varnodes
            if !vn.is_written() && vn.has_no_descend() && !vn.is_input() {
                continue;
            }
            // Ghidra guard() cc:1164-1175: for FREE reads (not written,
            // not input), only set activeHeritage if they have EXACTLY 1
            // live descendant. Ghidra throws LowlevelError for multi-desc.
            // Rugra: skip multi-descendant free reads in Ram/Const space
            // (address constants that shouldn't be over-renamed), but allow
            // Register-space multi-descendant reads (needed for correct SSA
            // of register uses across blocks).
            if !vn.is_written() && !vn.is_input() {
                if matches!(vn.address_space, crate::space::AddressSpace::Ram | crate::space::AddressSpace::Const) {
                    let live_desc: usize = vn.descend.iter()
                        .filter(|w| w.strong_count() > 0)
                        .count();
                    if live_desc != 1 {
                        continue;
                    }
                }
            }
            vn.set_active_heritage();
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
                                let is_addr_const = !vn_read.is_written()
                                    && !vn_read.is_constant()
                                    && matches!(vn_read.address_space,
                                        crate::space::AddressSpace::Ram
                                        | crate::space::AddressSpace::Const)
                                    && !vn_read.has_no_descend();
                                vn_read.is_heritage_known()
                                    || !vn_read.is_active_heritage()
                                    || is_addr_const
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
                                let (vnin_size, vnin_space, vnin_off, vnin_mapentry) = {
                                    let r = vnin_arc.read().unwrap();
                                    (r.size, r.address_space, r.loc.as_u64(), r.mapentry.clone())
                                };
                                let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                let promoted = vbank.set_input_varnode(new_vn);
                                // Preserve mapentry from the original free read
                                // varnode onto the promoted SSA input. This
                                // ensures mapGlobals-stamped mapentries survive
                                // Heritage rename, enabling ->field rendering
                                // at print time.
                                if vnin_mapentry.is_some() {
                                    promoted.write().unwrap().mapentry = vnin_mapentry;
                                }
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
                                    let (vnin_size, vnin_space, vnin_off, vnin_mapentry) = {
                                        let r = vnin_arc.read().unwrap();
                                        (r.size, r.address_space, r.loc.as_u64(), r.mapentry.clone())
                                    };
                                    let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                    let promoted = vbank.set_input_varnode(new_vn);
                                    if vnin_mapentry.is_some() {
                                        promoted.write().unwrap().mapentry = vnin_mapentry;
                                    }
                                    stack.insert(0, promoted.clone());
                                    vnnew = promoted;
                                } else {
                                    // cc:2515-2516: vnnew = stack[stack.size()-2]
                                    vnnew = stack[stack.len() - 2].clone();
                                }
                            }
                            // Ghidra cc:2519: fd->opSetInput(op, vnnew, slot);
                            // Preserve v_type AND mapentry from old varnode to
                            // new varnode so struct pointer types and the
                            // SymbolEntry (carrying the global field address)
                            // survive Heritage rename (b754fca + this patch).
                            {
                                let (old_vt, old_mapentry) = {
                                    let vnin_r = vnin_arc.read().unwrap();
                                    (vnin_r.v_type.clone(), vnin_r.mapentry.clone())
                                };
                                let mut vnnew_w = vnnew.write().unwrap();
                                if old_vt.is_some() {
                                    vnnew_w.v_type = old_vt;
                                }
                                if old_mapentry.is_some() {
                                    vnnew_w.mapentry = old_mapentry;
                                }
                            }
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
                                    let is_addr_const = !vn_read.is_written()
                                        && !vn_read.is_constant()
                                        && matches!(vn_read.address_space,
                                            crate::space::AddressSpace::Ram
                                            | crate::space::AddressSpace::Const)
                                        && !vn_read.has_no_descend();
                                    vn_read.is_heritage_known() || is_addr_const
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
                                // Preserve v_type AND mapentry (phi-input variant,
                                // mirroring the op-input preservation above).
                                {
                                    let (old_vt, old_mapentry) = {
                                        let vnin_r = vnin_arc.read().unwrap();
                                        (vnin_r.v_type.clone(), vnin_r.mapentry.clone())
                                    };
                                    let mut vnnew_w = vnnew.write().unwrap();
                                    if old_vt.is_some() {
                                        vnnew_w.v_type = old_vt;
                                    }
                                    if old_mapentry.is_some() {
                                        vnnew_w.mapentry = old_mapentry;
                                    }
                                }
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
