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
    /// Heritaged addresses mapped to range size and pass number. Ghidra keys
    /// this map by a full `Address` (space + offset, heritage.hh:48
    /// `map<Address,SizePass>`; `Address::operator<` orders by space index
    /// then offset, and `Address::overlap` returns -1 for different spaces),
    /// so entries from different address spaces never merge or overlap.
    /// Rugra's `Address` is a bare offset, so the space identity is carried
    /// explicitly in the key tuple (HERITAGE-DRIVER-SWITCH-0001: cross-space
    /// offset collisions previously misclassified ranges as NEW/OLD).
    pub themap: BTreeMap<(AddressSpace, Address), SizePass>,
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
    /// Faithful to `LocationMap::add` (heritage.cc:34-71). Candidate entries
    /// are restricted to `space`'s contiguous sub-range, exactly mirroring
    /// Ghidra's `map<Address,...>` behaviour where `lower_bound`/`--iter` can
    /// land on another space's entry but `Address::overlap` then returns -1
    /// (different spaces never overlap) and the walk advances back into the
    /// query space.
    /// Returns the intersect code:
    ///   0 = no overlap with existing
    ///   1 = partial overlap (merged)
    ///   2 = completely contained in a previous (older) entry
    pub fn add(&mut self, space: AddressSpace, mut addr: Address, mut size: i32, mut pass: i32) -> i32 {
        use crate::address::Address as A;
        // Ghidra cc:37-41: iter = lower_bound(addr); if (iter != begin)
        // --iter; if the resulting entry does not overlap, ++iter. The
        // entry selected this way (possibly the lower_bound itself) is the
        // one the cc:43-57 containment/merge check runs on — advancing
        // past it into the merge loop instead lost the "completely
        // contained" classification for exact-start re-adds (prev must be
        // 2, not 1, so a later pass does not re-flag the range NEW).
        let mut intersect = 0;
        let keys: Vec<Address> = self
            .themap
            .keys()
            .filter(|k| k.0 == space)
            .map(|k| k.1)
            .collect();
        let lb = keys.iter().position(|k| *k >= addr);
        let mut i = match lb {
            Some(pos) if pos > 0 => pos - 1,
            Some(_) => 0,
            None => keys.len().saturating_sub(1),
        };
        if i < keys.len()
            && A::overlap(&addr, 0, keys[i], self.themap[&(space, keys[i])].size) == -1
        {
            i += 1;
        }
        // Ghidra cc:43-57: containment / first merge on the selected entry.
        if i < keys.len() {
            let k_addr = keys[i];
            let k_sp = self.themap[&(space, k_addr)];
            let where_ = A::overlap(&addr, 0, k_addr, k_sp.size);
            if where_ != -1 {
                // Ghidra cc:46-49: completely contained?
                if where_ + size <= k_sp.size {
                    return if k_sp.pass < pass { 2 } else { 0 };
                }
                // Ghidra cc:50-56: merge — extend addr/size, take min pass.
                addr = k_addr;
                size = where_ + size;
                if k_sp.pass < pass {
                    intersect = 1;
                    pass = k_sp.pass;
                }
                self.themap.remove(&(space, k_addr));
                i += 1;
            }
        }
        // Ghidra cc:58-66: continue merging subsequent overlapping entries.
        while i < keys.len() {
            let (k_addr, k_sp) = (keys[i], self.themap.get(&(space, keys[i])).copied().unwrap_or(SizePass { size: 0, pass: 0 }));
            if self.themap.get(&(space, keys[i])).is_none() { i += 1; continue; }
            let where_ = A::overlap(&k_addr, 0, addr, size);
            if where_ == -1 { break; }
            if where_ + k_sp.size > size {
                size = where_ + k_sp.size;
            }
            if k_sp.pass < pass {
                intersect = 1;
                pass = k_sp.pass;
            }
            self.themap.remove(&(space, keys[i]));
            i += 1;
        }
        // Ghidra cc:67-70: insert merged entry.
        self.themap.insert((space, addr), SizePass { size, pass });
        intersect
    }

    // Ghidra: heritage.cc:91 LocationMap::findPass
    /// Return the pass number when the given address was heritaged, or -1
    /// if it was not heritaged. Faithful to `findPass` (heritage.cc:91-100):
    /// upper_bound(addr), back up one, check overlap.
    pub fn find_pass(&self, space: AddressSpace, addr: Address) -> i32 {
        // Ghidra cc:94: upper_bound(addr) — first key > addr (within space;
        // entries of other spaces can never overlap this address).
        let keys: Vec<Address> = self
            .themap
            .keys()
            .filter(|k| k.0 == space && k.1 > addr)
            .map(|k| k.1)
            .collect();
        // Ghidra cc:95: if (iter == begin) return -1
        let prev_key = if keys.is_empty() {
            // No key > addr → use the last key (if any)
            self.themap
                .range((space, Address::new(0))..=(space, Address::new(u64::MAX)))
                .next_back()
                .map(|(k, _)| k.1)
        } else {
            // The key just before the first key > addr
            let first_after = keys[0];
            self.themap
                .range((space, Address::new(0))..(space, first_after))
                .next_back()
                .map(|(k, _)| k.1)
        };
        // Ghidra cc:97-98: if overlap != -1 return pass
        match prev_key {
            Some(k) => {
                let sp = self.themap.get(&(space, k)).copied().unwrap_or(SizePass { size: 0, pass: -1 });
                if addr.overlap(0, k, sp.size) != -1 {
                    sp.pass
                } else {
                    -1
                }
            }
            None => -1,
        }
    }

    // Ghidra: heritage.cc:34 LocationMap::add
    // RUGRA-GLUE: adapter for the iterator returned by LocationMap::add.
    /// Locate the map entry containing `addr`. Ghidra's `LocationMap::add`
    /// returns an iterator to the (possibly merged) entry covering the added
    /// range; the driver then reads `(*liter).first` / `(*liter).second.size`
    /// (heritage.cc:2710/2719/2722). Rugra's `add` returns only the intersect
    /// code, so this upper_bound/back-up lookup recovers the same entry.
    /// Scans only `space`'s sub-range — entries in other spaces can never
    /// contain this address (Ghidra `Address::overlap` is -1 cross-space).
    pub fn entry_containing(&self, space: AddressSpace, addr: Address) -> Option<(Address, i32)> {
        // upper_bound(addr): first key > addr (within space), then back up one.
        let prev_key = {
            let first_after = self
                .themap
                .range((space, addr)..=(space, Address::new(u64::MAX)))
                .find(|(k, _)| k.1 > addr);
            match first_after {
                Some((k, _)) => {
                    // First key > addr exists; the candidate is the key before it.
                    self.themap
                        .range((space, Address::new(0))..*k)
                        .next_back()
                        .map(|(k2, _)| k2.1)?
                }
                None => {
                    // No key > addr; the candidate is the last key of this space.
                    self.themap
                        .range((space, Address::new(0))..=(space, Address::new(u64::MAX)))
                        .next_back()
                        .map(|(k2, _)| k2.1)?
                }
            }
        };
        let sp = self.themap.get(&(space, prev_key))?;
        if addr.overlap(0, prev_key, sp.size) != -1 {
            Some((prev_key, sp.size))
        } else {
            None
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
    /// Address space of the range. Ghidra's `MemRange::addr` is a full
    /// space-carrying Address (heritage.hh:60); Rugra's `Address` is an
    /// offset-only scalar, so the space rides as an explicit field until
    /// ADDRESS-0001 lands.
    // RUGRA-GLUE: explicit-space mirror of the oracle Address identity.
    pub space: AddressSpace,
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
// RUGRA-GLUE: derive Debug for the Heritage Debug impl (Ghidra has no such need).
#[derive(Debug)]
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
    /// Faithful to `add` (heritage.cc:109-124). The explicit space parameter
    /// mirrors Ghidra's space-carrying Address key.
    pub fn add(&mut self, space: AddressSpace, addr: Address, size: i32, fl: u32) {
        if let Some(last) = self.tasklist.last_mut() {
            if last.space == space {
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
        }
        self.tasklist.push(MemRange { addr, size, flags: fl, space });
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
    // RUGRA-GLUE: Ghidra's `Funcdata *fd` (heritage.hh:249) is a non-owning raw
    // pointer used re-entrantly by every pass helper. Rust cannot store an
    // aliasing mutable handle inside an object that Funcdata itself owns
    // (the former `Weak<RwLock<Funcdata>>` field re-entered the write lock and
    // could deadlock, per HERITAGE-DRIVER-0001). The exclusive `&mut Funcdata`
    // is now threaded explicitly through every pass method; the persistent
    // object is temporarily moved out of `Funcdata::heritage` by
    // `Funcdata::op_heritage` (mem::take) for the duration of one pass.
    pub globaldisjoint: LocationMap,
    /// Current-pass disjoint cover; cleared by `rename` (cc:2592).
    pub disjoint: TaskList,
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
    // Ghidra: heritage.cc:218 Heritage::Heritage
    /// Construct the heritage manager. Faithful to the Ghidra constructor
    /// (heritage.cc:218-224): `fd = data; pass = 0; maxdepth = -1;`.
    /// `maxdepth = -1` is load-bearing: it is the sentinel that makes the
    /// first `Heritage::heritage` pass rebuild the augmented dominator tree
    /// (heritage.cc:2676-2677). (Previously Rugra initialized `maxdepth = 0`,
    /// so the rebuild condition could never fire.)
    pub fn new() -> Self {
        Self {
            globaldisjoint: LocationMap::new(),
            disjoint: TaskList::new(),
            domchild: Vec::new(),
            augment: Vec::new(),
            flags: Vec::new(),
            depth: Vec::new(),
            maxdepth: -1,
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

    // Ghidra: heritage.cc:2316 Heritage::buildADT
    /// Build the Augmented Dominator Tree. Faithful to `buildADT`
    /// (heritage.cc:2316-2385). Consumes the block dominator state populated
    /// upstream (Ghidra: `Funcdata::structureReset` -> `calcForwardDominator`;
    /// Rugra: `BlockGraph::build_dom_tree`) and constructs the Bilardi-Pingali
    /// augmentation.
    ///
    /// Algorithm (locked oracle lines):
    ///   1. cc:2329-2332 clear + resize augment/flags
    ///   2. cc:2334 buildDomTree(domchild) — assemble from immed_dom;
    ///      blocks with no immed_dom land in the dead bucket `size`
    ///   3. cc:2338 buildDomDepth(depth) — root depth 1, child = parent+1,
    ///      trailing sentinel depth[size]=0, maxdepth = maximum
    ///   4. cc:2339-2353 find up-edges (u != immed_dom(v)) and count b[]/t[]
    ///   5. cc:2354-2367 bottom-up pass: compute a[]/z[], mark boundary nodes
    ///   6. cc:2368-2374 z[0] = -1, then propagate z[] top-down
    ///   7. cc:2376-2384 build augment[] walking k = z[k]
    pub fn build_adt(&mut self, fd: &Funcdata) {
        let bblocks = &fd.bblocks;
        let size = bblocks.get_size();
        if size == 0 {
            return;
        }

        // cc:2329-2332: clear + resize (Ghidra leaves stale domchild to
        // buildDomTree, which clears/resizes itself).
        self.augment.clear();
        self.augment.resize(size, Vec::new());
        self.flags.clear();
        self.flags.resize(size, 0);

        // cc:2334: bblocks.buildDomTree(domchild). Faithful to
        // BlockGraph::buildDomTree (block.cc:2036-2051): child[immed_dom]
        // gets the block appended in list order; blocks whose immed_dom is
        // null land in the extra dead bucket at index `size`.
        self.domchild.clear();
        self.domchild.resize(size + 1, Vec::new());
        for i in 0..size {
            let block = match bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let idom_idx = block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index());
            match idom_idx {
                Some(idx) if (idx as usize) < size => {
                    self.domchild[idx as usize].push(i as i32);
                }
                _ => {
                    // Null (or out-of-range) immediate dominator: dead bucket.
                    self.domchild[size].push(i as i32);
                }
            }
        }

        // cc:2338: bblocks.buildDomDepth(depth). Faithful to
        // BlockGraph::buildDomDepth (block.cc:2056-2075): iterate blocks in
        // list order; depth[i] = depth[immed_dom]+1, or 1 when the immediate
        // dominator is null; trailing sentinel depth[size] = 0; return max.
        let mut depth = vec![0i32; size + 1];
        let mut maxdepth = 0i32;
        for i in 0..size {
            let block = match bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let idom_idx = block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index());
            depth[i] = match idom_idx {
                Some(idx) if (idx as usize) < size => depth[idx as usize] + 1,
                _ => 1,
            };
            if maxdepth < depth[i] {
                maxdepth = depth[i];
            }
        }
        depth[size] = 0;
        self.depth = depth;
        self.maxdepth = maxdepth;

        // cc:2339-2353: find up-edges + count b[]/t[].
        // For every dominator-tree child v of x, every in-edge u of v with
        // u != immed_dom(v) is an up-edge; b[u] counts edges ending at u,
        // t[x] counts edges starting under x.
        let mut b_count = vec![0i32; size]; // up-edges ending at node
        let mut t_count = vec![0i32; size]; // up-edges starting under node
        let mut upstart = Vec::new(); // up-edge source indices
        let mut upend = Vec::new(); // up-edge target indices

        for i in 0..size {
            for &cidx in &self.domchild[i] {
                let v = match bblocks.get_block(cidx as usize) {
                    Some(b) => b,
                    None => continue,
                };
                let v_guard = v.read().unwrap();
                let v_idom = v_guard
                    .get_immed_dom()
                    .and_then(|w| w.upgrade())
                    .map(|dom| dom.read().unwrap().get_index());
                let v_sin = v_guard.size_in();
                for k in 0..v_sin {
                    let u = match v_guard.get_in(k) {
                        Some(e) => e.point.clone(),
                        None => continue,
                    };
                    let u_idx = u.read().unwrap().get_index();
                    if Some(u_idx) != v_idom {
                        // Up-edge: u -> v (pointer identity in Ghidra;
                        // block indices are unique per graph in Rugra).
                        upstart.push(u_idx);
                        upend.push(cidx);
                        b_count[u_idx as usize] += 1;
                        t_count[i] += 1;
                    }
                }
            }
        }

        // cc:2354-2367: bottom-up a[]/z[] + boundary marking.
        let mut a_count = vec![0i32; size];
        let mut z = vec![0i32; size];
        for i in (0..size).rev() {
            let mut k_sum = 0i32;
            let mut l_sum = 0i32;
            for &cidx in &self.domchild[i] {
                let c = cidx as usize;
                if c < size {
                    k_sum += a_count[c];
                    l_sum += z[c];
                }
            }
            a_count[i] = b_count[i] - t_count[i] + k_sum;
            z[i] = 1 + l_sum;
            if self.domchild[i].is_empty() || z[i] > a_count[i] + 1 {
                self.flags[i] |= heritage_flags::BOUNDARY_NODE;
                z[i] = 1;
            }
        }

        // cc:2368: z[0] = -1
        if !z.is_empty() {
            z[0] = -1;
        }

        // cc:2369-2374: propagate z through boundary chains.
        for i in 1..size {
            let block = match bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let j = match block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
            {
                Some(dom) => dom.read().unwrap().get_index() as usize,
                None => continue,
            };
            if j < size && (self.flags[j] & heritage_flags::BOUNDARY_NODE) != 0 {
                z[i] = j as i32;
            } else if j < size {
                z[i] = z[j];
            }
        }

        // cc:2376-2384: build augment[] from up-edges.
        for idx in 0..upstart.len() {
            let v_idx = upend[idx];
            let v_block = match bblocks.get_block(v_idx as usize) {
                Some(b) => b,
                None => continue,
            };
            let mut j = v_block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index())
                .unwrap_or(0);
            let mut k = upstart[idx];
            while j < k {
                if (k as usize) < self.augment.len() {
                    self.augment[k as usize].push(v_idx);
                }
                let zk = z.get(k as usize).copied().unwrap_or(0);
                if zk <= 0 || zk >= k {
                    // Path compression must strictly decrease k toward j.
                    break;
                }
                k = zk;
            }
        }
    }

    // Ghidra: heritage.cc:2394 Heritage::visitIncr
    /// Recursive phi-node placement using the ADT. Faithful to
    /// `visitIncr` (heritage.cc:2394-2428). Walks augment[vnode] and
    /// recurses into dom children (unless boundary node).
    pub fn visit_incr(&mut self, fd: &Funcdata, qnode_idx: i32, vnode_idx: i32) {
        let i = vnode_idx as usize;
        // cc:2404-2421: scan augment[i] for phi candidates.
        let aug_snapshot = self.augment.get(i).cloned().unwrap_or_default();
        for v_idx in aug_snapshot {
            let v_idom = fd
                .bblocks
                .get_block(v_idx as usize)
                .and_then(|b| b.read().unwrap().get_immed_dom())
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index());
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
                    self.visit_incr(fd, qnode_idx, child_idx);
                }
            }
        }
    }

    // Ghidra: heritage.cc:2439 Heritage::calcMultiequals
    /// Calculate blocks that should contain MULTIEQUALs for one address range.
    /// Faithful to `calcMultiequals` (heritage.cc:2439-2466): consumes the
    /// normalized write Varnode list, derives each write's block from
    /// `write[i]->getDef()->getParent()` (cc:2449), always seeds block 0
    /// (cc:2455-2458), and clears mark/merged flags only after queue
    /// exhaustion (cc:2464-2465). A write whose defining op lost its parent
    /// block cannot occur in the locked oracle (cc:2449 would dereference
    /// it); Rust skips such an entry rather than indexing the flags array
    /// with an invalid block.
    pub fn calc_multiequals(&mut self, fd: &Funcdata, write: &[Arc<RwLock<Varnode>>]) {
        // cc:2442: pq.reset(maxdepth)
        self.pq.reset(self.maxdepth);
        // cc:2443: merge.clear()
        self.merge.clear();

        // cc:2448-2454: place write blocks into pq.
        for vn_arc in write {
            let vn = vn_arc.read().unwrap();
            let blk_idx = match vn
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .and_then(|def| def.read().unwrap().parent.as_ref().and_then(|p| p.upgrade()))
            {
                Some(parent) => parent.read().unwrap().get_index(),
                None => continue,
            };
            let j = blk_idx as usize;
            if j < self.flags.len() && (self.flags[j] & heritage_flags::MARK_NODE) != 0 {
                continue; // Already in
            }
            self.pq.insert(blk_idx, self.depth.get(j).copied().unwrap_or(0));
            if j < self.flags.len() {
                self.flags[j] |= heritage_flags::MARK_NODE;
            }
        }
        // cc:2455-2458: ensure block 0 is in pq.
        if !self.flags.is_empty() && (self.flags[0] & heritage_flags::MARK_NODE) == 0 {
            self.pq.insert(0, self.depth.get(0).copied().unwrap_or(0));
            self.flags[0] |= heritage_flags::MARK_NODE;
        }

        // cc:2460-2463: main loop.
        while !self.pq.empty() {
            let bl = self.pq.extract();
            self.visit_incr(fd, bl, bl);
        }

        // cc:2464-2465: clear marks.
        for f in &mut self.flags {
            *f &= !(heritage_flags::MARK_NODE | heritage_flags::MERGED_NODE);
        }
    }

    // RUGRA-GLUE: Rugra-specific stack-store discovery; no 1:1 Ghidra function.
    /// Forward-descend the stack-pointer input varnode, mark STOREs whose
    /// pointer reaches it as spacebase users, and materialize stack-space
    /// INDIRECT writes for them. This is Rugra's approximation of the
    /// marking half of `Heritage::discoverIndexedStackPointers`
    /// (heritage.cc:985-1108) + `protectFreeStores` (heritage.cc:943-968,
    /// `opMarkSpacebasePtr`); it does not implement the indexed-pointer
    /// traversal states (HERITAGE-CALLGUARD-0001 residual family).
    /// Since HERITAGE-DRIVER-SWITCH-0001 the production ActionHeritage no
    /// longer calls this between passes: canonical placeMultiequals runs
    /// its own guard/stores logic per range. Remaining callers are the
    /// reprocessFreeStores approximation and tests.
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
        // Mirrors guardStores' constructor call (heritage.cc:1553-1556):
        // newIndirectOp(op, addr, size, PcodeOp::indirect_store) followed by
        // setActiveHeritage on input[0] and output.
        for (store_op, stack_off) in stores_to_guard {
            let sz = {
                let s = store_op.read().unwrap();
                s.inrefs.get(2).map(|v| v.read().unwrap().get_size()).unwrap_or(8)
            };
            let store_ref = crate::op::PcodeOpRef(store_op);
            let indop = fd.new_indirect_op(
                &store_ref,
                AddressSpace::Stack,
                stack_off as u64,
                sz,
                crate::op::pcodeop_flags::INDIRECT_STORE,
            );
            let (in0, out) = {
                let r = indop.0.read().unwrap();
                (r.get_in(0).cloned(), r.output.as_ref().cloned())
            };
            if let Some(vn) = in0 { vn.write().unwrap().set_active_heritage(); }
            if let Some(vn) = out { vn.write().unwrap().set_active_heritage(); }
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

    // Ghidra: heritage.cc:1443 Heritage::guardCalls
    /// Guard CALL/CALLIND ops in preparation for the renaming algorithm.
    /// Faithful 1:1 port of `Heritage::guardCalls` (heritage.cc:1443-1527).
    ///
    /// For the given address range, decide what the data-flow effect is
    /// across each call site in the function. If an effect is unknown (or a
    /// return address), an INDIRECT op is added via `newIndirectOp`
    /// (prepopulating data-flow through the call); if the range is
    /// killed-by-call, an indirectly-created INDIRECT is added via
    /// `newIndirectCreation`. Any new INDIRECT output is appended to `write`
    /// in creation order — the same vector calcMultiequals consumes.
    ///
    /// Per cc:1451-1527 the loop order is callspec order (`i < numCalls`),
    /// and each callspec contributes at most one INDIRECT per range; the
    /// stack-spacebase translation (cc:1460-1465) rebases the query offset
    /// by the callspec's resolved stackoffset, disabling register trials
    /// entirely when the offset is unknown.
    pub fn guard_calls(
        &mut self,
        fd: &mut Funcdata,
        fl: u32,
        space: AddressSpace,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1450: holdind = ((fl & Varnode::addrtied) != 0)
        let holdind = (fl & crate::varnode::varnode_flags::ADDRTIED) != 0;
        // cc:1451: for(int4 i=0;i<fd->numCalls();++i)
        for i in 0..fd.num_calls() {
            // cc:1452: fc = fd->getCallSpecs(i);
            // cc:1453-1456: if the call op is an assignment whose output IS
            // this exact range, this range is already the return value — no
            // guard is added for it.
            let call_op = match fd.get_call_specs(i).and_then(|fc| fc.find_call_op(fd)) {
                Some(op) => op,
                None => continue,
            };
            {
                let is_assignment = call_op.0.read().unwrap().is_assignment();
                if is_assignment {
                    let out_match = call_op.0.read().unwrap().output.as_ref().map(|vn| {
                        let v = vn.read().unwrap();
                        v.address_space == space && v.loc == addr && v.get_size() as i32 == size
                    });
                    if out_match == Some(true) {
                        continue;
                    }
                }
            }
            // cc:1457-1466: compute the callee-perspective address.
            //   spc = addr.getSpace(); off = addr.getOffset();
            //   if SPACEBASE and spacebase offset known:
            //     off = spc->wrapOffset(off - fc->getSpacebaseOffset())
            //   else if SPACEBASE unknown: tryregister = false
            let mut off = addr.as_u64();
            let mut tryregister = true;
            if space == AddressSpace::Stack {
                match fd.get_call_specs(i).map(|fc| fc.get_spacebase_offset()) {
                    Some(sb) if sb != crate::fspec::OFFSET_UNKNOWN => {
                        off = ((off as i128 - sb as i128).rem_euclid(1i128 << 64)) as u64;
                    }
                    _ => {
                        // cc:1464: do not attempt to register this stack loc
                        tryregister = false;
                    }
                }
            }
            // cc:1466: transAddr = Address(spc, off)
            // cc:1467: effecttype = fc->hasEffect(transAddr, size)
            let mut effecttype = fd
                .get_call_specs(i)
                .map(|fc| fc.has_effect(space, off, size))
                .unwrap_or(crate::fspec::EffectType::UnknownEffect);
            // cc:1468-1486: output-trial half.
            let mut possibleoutput = false;
            let is_output_active = fd
                .get_call_specs(i)
                .map(|fc| fc.is_output_active())
                .unwrap_or(false);
            if is_output_active && tryregister {
                // cc:1471: outputCharacter = fc->characterizeAsOutput(transAddr, size)
                let output_character = fd
                    .get_call_specs(i)
                    .map(|fc| fc.characterize_as_output(space, off, size))
                    .unwrap_or(0);
                if output_character != crate::fspec::containment::NO_CONTAINMENT {
                    // cc:1473-1474: auto-killed-by-call upgrade
                    if effecttype != crate::fspec::EffectType::KilledByCall
                        && fd.get_call_specs(i)
                            .map(|fc| fc.is_auto_killed_by_call())
                            .unwrap_or(false)
                    {
                        effecttype = crate::fspec::EffectType::KilledByCall;
                    }
                    if output_character == crate::fspec::containment::CONTAINED_BY {
                        // cc:1476-1477: tryOutputOverlapGuard; if handled the
                        // range is unaffected — no additional guarding.
                        if self.try_output_overlap_guard(fd, i, space, addr, off, size, write) {
                            effecttype = crate::fspec::EffectType::Unaffected;
                        }
                    } else {
                        // cc:1480-1483: register as an output trial unless one
                        // already exists.
                        let already_trial = fd
                            .get_call_specs(i)
                            .and_then(|fc| fc.active_output.as_ref())
                            .map(|active| active.which_trial(Address::new(off), size) >= 0)
                            .unwrap_or(true);
                        if !already_trial {
                            if let Some(fc) = fd.get_call_specs_mut(i) {
                                if let Some(active) = &mut fc.active_output {
                                    active.register_trial(Address::new(off), size);
                                }
                            }
                            possibleoutput = true;
                        }
                    }
                }
            } else {
                // cc:1487-1494: stack-output-lock half.
                let is_stack_output_lock = fd
                    .get_call_specs(i)
                    .map(|fc| fc.is_stack_output_lock())
                    .unwrap_or(false);
                if is_stack_output_lock && tryregister {
                    let output_character = fd
                        .get_call_specs(i)
                        .map(|fc| fc.characterize_as_output(space, off, size))
                        .unwrap_or(0);
                    if output_character != crate::fspec::containment::NO_CONTAINMENT {
                        effecttype = crate::fspec::EffectType::UnknownEffect;
                        if self.try_output_stack_guard(fd, i, space, addr, off, size, output_character, write) {
                            effecttype = crate::fspec::EffectType::Unaffected;
                        }
                    }
                }
            }
            // cc:1495-1509: input-trial half.
            let is_input_active = fd
                .get_call_specs(i)
                .map(|fc| fc.is_input_active())
                .unwrap_or(false);
            if is_input_active && tryregister {
                // cc:1496: inputCharacter = fc->characterizeAsInputParam(transAddr, size)
                let input_character = fd
                    .get_call_specs(i)
                    .map(|fc| fc.characterize_as_input_param(space, off, size))
                    .unwrap_or(0);
                if input_character == crate::fspec::containment::CONTAINS_JUSTIFIED {
                    // cc:1498-1505: call could use this whole range as an
                    // input parameter — register the trial and append the
                    // varnode as the call's last input.
                    let already_trial = fd
                        .get_call_specs(i)
                        .and_then(|fc| fc.active_input.as_ref())
                        .map(|active| active.which_trial(Address::new(off), size) >= 0)
                        .unwrap_or(true);
                    if !already_trial {
                        if let Some(fc) = fd.get_call_specs_mut(i) {
                            if let Some(active) = &mut fc.active_input {
                                active.register_trial(Address::new(off), size);
                            }
                        }
                        // cc:1502-1504: vn = newVarnode(size, addr);
                        // setActiveHeritage; opInsertInput(op, vn, numInput())
                        let vn = fd
                            .vbank
                            .create_with_space(size as usize, space, addr.as_u64());
                        vn.write().unwrap().set_active_heritage();
                        let num_in = call_op.0.read().unwrap().num_input();
                        fd.op_insert_input(&call_op, vn, num_in);
                    }
                } else if input_character == crate::fspec::containment::CONTAINED_BY {
                    // cc:1507-1508: call may use part of this range as an
                    // input parameter.
                    self.guard_call_overlapping_input(fd, i, space, addr, off, size);
                }
            }
            // cc:1510-1525: the guard itself, by final effect type. Neither
            // "unaffected" nor "reload" gets an INDIRECT.
            if effecttype == crate::fspec::EffectType::UnknownEffect
                || effecttype == crate::fspec::EffectType::ReturnAddress
            {
                // cc:1512: indop = fd->newIndirectOp(fc->getOp(), addr, size, 0)
                let indop = fd.new_indirect_op(&call_op, space, addr.as_u64(), size as usize, 0);
                // cc:1513-1515: setActiveHeritage on in[0] and out; push out.
                let (in0, outvn) = {
                    let r = indop.0.read().unwrap();
                    (r.get_in(0).cloned(), r.output.as_ref().cloned())
                };
                if let Some(vn) = in0 {
                    vn.write().unwrap().set_active_heritage();
                }
                if let Some(vn) = outvn {
                    vn.write().unwrap().set_active_heritage();
                    // cc:1516-1517: if (holdind) out->setAddrForce()
                    if holdind {
                        vn.write().unwrap().set_addr_force();
                    }
                    // cc:1518-1519: if return_address -> setReturnAddress()
                    if effecttype == crate::fspec::EffectType::ReturnAddress {
                        vn.write().unwrap().set_return_address();
                    }
                    write.push(vn);
                }
            } else if effecttype == crate::fspec::EffectType::KilledByCall {
                // cc:1521-1524: indirectly created value.
                let indop = fd.new_indirect_creation_in_space(
                    &call_op,
                    space,
                    addr.as_u64(),
                    size as usize,
                    possibleoutput,
                );
                // cc:1522-1524: out setActiveHeritage; push.
                let outvn = indop.0.read().unwrap().output.as_ref().cloned();
                if let Some(vn) = outvn {
                    vn.write().unwrap().set_active_heritage();
                    write.push(vn);
                }
            }
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
        // cc:397: opSetOutput(newop, vn) — old vn becomes SUBPIECE output.
        // Must go through Funcdata::op_set_output (funcdata_op.cc:70): the
        // previous direct `output = Some(vn)` assignment left vn.def unset,
        // so the "normalized" varnode stayed FREE in the bank, the driver
        // re-collected it every pass, and each pass re-normalized it with a
        // fresh SUBPIECE — the Heritage/DeadCode ping-pong that kept the
        // mainloop from converging (HERITAGE-DRIVER-SWITCH-0001).
        fd.op_set_output(&newop, vn.clone());
        // cc:398: newop->getOut()->setWriteMask() — the driver skips
        // writemasked varnodes (cc:2706), so the SUBPIECE output is never
        // re-collected as a heritage candidate.
        vn.write().unwrap().set_write_mask();
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
        space: AddressSpace,
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
        // Ghidra cc:1189-1199: addIndirects half — queryProperties sets
        // `fl` from ScopeLocal range properties; Rugra has no ScopeLocal on
        // this path yet, so fl=0 (no addrtied, no persist), which only
        // suppresses the ADDRFORCE mark and the return-COPY suffix.
        if add_indirects {
            let fl: u32 = 0;
            // cc:1192: fd->getScopeLocal()->queryProperties(addr,size,Address(),fl)
            // cc:1193: guardCalls(fl,addr,size,write)
            self.guard_calls(fd, fl, space, addr, size, write);
            // cc:1194: guardReturns(fl,addr,size,write)
            // Not wired: needs FuncProto::activeoutput on the function's own
            // prototype (Ghidra fspec.hh:1656) and Funcdata::activeoutput
            // linkage; residual registered against the PARAM-BIND family.
            // cc:1195-1197: if highPtrPossible: guardStores/guardLoads.
            self.guard_stores_range(fd, space, addr, size, write);
            self.guard_loads_range(fd, fl, space, addr, size, write);
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
            AddressSpace::Stack,
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

    // Ghidra: heritage.cc:244 Heritage::removeRevisitedMarkers
    /// Remove previously-heritaged markers and convert them to SUBPIECE
    /// of a larger free Varnode. Faithful to `removeRevisitedMarkers`
    /// (heritage.cc:244-297): an INDIRECT marker is uninserted and
    /// reinserted AFTER the target of the INDIRECT (cc:265-273, the
    /// replacement INDIRECT keeps the address so the old output is
    /// addr-force cleared); a MULTIEQUAL marker is reinserted after ALL
    /// leading MULTIEQUALs in its block (cc:275-280); a return-form COPY
    /// is unlinked outright (cc:281-284). The converted op becomes
    /// SUBPIECE(big, offset) with a fresh active-heritage whole-range
    /// input (cc:285-294) and the original output is write-masked
    /// (cc:295).
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
        // cc:247-257: if deadremoved > 0, bump delay + one-time warning
        // header naming the revisited address in printRaw form.
        // AddrSpace::printRaw (space.cc:206-221): "0x" plus the offset
        // zero-filled to 2*addrsize hex digits, with the leading-zero
        // shrink rule (offset>>32==0 -> 4 bytes, else >>48==0 -> 6 for
        // 8-byte spaces); no space name.
        let info_idx = self.infolist.iter().position(|i| i.space == space);
        if let Some(idx) = info_idx {
            if self.infolist[idx].deadremoved > 0 {
                self.bump_deadcode_delay(space);
                if !self.infolist[idx].warning_issued {
                    self.infolist[idx].warning_issued = true;
                    let mut sz = space.addr_size();
                    let off = addr.as_u64();
                    if sz > 4 {
                        if (off >> 32) == 0 {
                            sz = 4;
                        } else if (off >> 48) == 0 {
                            sz = 6;
                        }
                    }
                    let mut errmsg = String::from("Heritage AFTER dead removal. Revisit: ");
                    errmsg.push_str(&format!("0x{:0width$x}", off, width = 2 * sz));
                    fd.warning_header(&errmsg);
                }
            }
        }
        for vn_arc in remove {
            let vn_r = vn_arc.read().unwrap();
            let def_op = match vn_r.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => continue,
            };
            let def_code = def_op.read().unwrap().opcode;
            let parent = def_op
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(|p| p.upgrade());
            let Some(bl) = parent else { continue };
            drop(vn_r);
            let def_ref = PcodeOpRef(def_op.clone());
            // cc:265-280 resolve the reinsertion position as an ELEMENT
            // anchor captured on the PRE-removal block list — Ghidra's
            // `pos` is a list iterator that keeps pointing at the anchor
            // element across the opUninsert at cc:286, and opInsert
            // (cc:294) inserts before it. A numeric index computed on the
            // pre-removal list shifts by one after the removal (and can
            // exceed the shrunken list at the block tail, tripping the
            // opInsert range assert).
            //   - INDIRECT, dead/unresolvable target: cc:268-269 the
            //     anchor is the element after the INDIRECT itself.
            //   - INDIRECT, alive target: cc:270-272 the anchor is the
            //     element after the target op.
            //   - MULTIEQUAL: cc:275-280 the anchor is the first
            //     non-MULTIEQUAL element after the leading ME group.
            let bl_ops = bl.read().unwrap().get_ops();
            let self_pos = bl_ops.iter().position(|c| Arc::ptr_eq(&c.0, &def_op));
            let anchor: Option<crate::op::PcodeOpRef>;
            if def_code == OpCode::CPUI_INDIRECT {
                let target = {
                    let def_r = def_op.read().unwrap();
                    def_r.get_in(1).and_then(|iop_vn| {
                        let iv = iop_vn.read().unwrap();
                        if iv.get_space() == AddressSpace::Iop {
                            let raw = iv.get_offset() as usize
                                as *const std::sync::RwLock<PcodeOp>;
                            // Recover the aliased target op from the bank
                            // (Ghidra's PcodeOp::getOpFromConst round-trip).
                            fd.obank
                                .optree
                                .iter()
                                .find(|candidate| {
                                    std::sync::Arc::as_ptr(&candidate.0) as *const ()
                                        == raw as *const ()
                                })
                                .cloned()
                        } else {
                            None
                        }
                    })
                };
                let target_alive_pos = target.as_ref().and_then(|target_op| {
                    let target_dead =
                        (target_op.0.read().unwrap().flags & crate::op::pcodeop_flags::DEAD) != 0;
                    if target_dead {
                        return None;
                    }
                    bl_ops.iter().position(|c| Arc::ptr_eq(&c.0, &target_op.0))
                });
                let Some(self_pos) = self_pos else {
                    // The op is not in its parent block; the locked oracle
                    // dereferences a stale iterator here. Skip the op.
                    continue;
                };
                let anchor_pos = match target_alive_pos {
                    // cc:270-272: ++targetOp->getBasicIter()
                    Some(tp) => {
                        // If the target's immediate successor is the
                        // INDIRECT itself (about to be uninserted), the
                        // anchor degenerates to the INDIRECT's own
                        // successor — the element after the removed slot.
                        if tp + 1 == self_pos {
                            self_pos + 1
                        } else {
                            tp + 1
                        }
                    }
                    // cc:268-269: ++op->getBasicIter()
                    None => self_pos + 1,
                };
                anchor = bl_ops.get(anchor_pos).map(|o| crate::op::PcodeOpRef(o.0.clone()));
                // cc:273: vn->clearAddrForce()
                vn_arc.write().unwrap().clear_addr_force();
            } else if def_code == OpCode::CPUI_MULTIEQUAL {
                let Some(self_pos) = self_pos else {
                    continue;
                };
                let mut pos = self_pos + 1;
                while pos < bl_ops.len()
                    && bl_ops[pos].0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL
                {
                    pos += 1;
                }
                anchor = bl_ops.get(pos).map(|o| crate::op::PcodeOpRef(o.0.clone()));
            } else {
                // cc:281-284: remove return form COPY
                fd.op_unlink(&def_ref);
                continue;
            }
            drop(bl_ops);
            // cc:285-286: offset = vn->overlap(addr,size); opUninsert(op)
            let vn_loc = vn_arc.read().unwrap().loc.as_u64();
            let offset = vn_loc.wrapping_sub(addr.as_u64());
            let vn_space = vn_arc.read().unwrap().address_space;
            fd.op_uninsert(&def_ref);
            // cc:288-291: big = newVarnode(size,addr); setActiveHeritage;
            // newInputs = [big, newConstant(4, offset)]
            let big = fd.vbank.create_with_space(size as usize, vn_space, addr.as_u64());
            big.write().unwrap().set_active_heritage();
            let off_const = fd.new_constant(4, offset);
            // cc:292-293: opSetOpcode(SUBPIECE) + opSetAllInput
            fd.op_set_opcode(&def_ref, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&def_ref, big, 0);
            fd.op_set_input(&def_ref, off_const, 1);
            // cc:294: opInsert(op, bl, pos) — before the captured anchor
            // element, or at the end when the anchor is the list end.
            match anchor {
                Some(a) => {
                    fd.op_insert_before(&def_ref, &a);
                }
                None => {
                    fd.op_insert(&def_ref, &bl, None);
                }
            }
            // cc:295: vn->setWriteMask()
            vn_arc.write().unwrap().set_write_mask();
        }
    }

    // Ghidra: heritage.cc:1111 Heritage::reprocessFreeStores
    /// Revisit STOREs with free pointers now that a heritage pass has
    /// completed. Faithful 1:1 port of `reprocessFreeStores`
    /// (heritage.cc:1111-1141): clear the spacebase marks, rediscover, then
    /// for every STORE that no longer uses a spacebase pointer walk the
    /// contiguous INDIRECT group immediately before it and remove exactly
    /// the guards whose IOP input aliases this STORE and whose output lives
    /// in the guarded space (`totalReplace` + `opDestroy`).
    pub fn reprocess_free_stores(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        free_stores: &[Arc<RwLock<PcodeOp>>],
    ) {
        // cc:1114-1115: fd->opClearSpacebasePtr(freeStores[i])
        for op_arc in free_stores {
            fd.op_clear_spacebase_ptr(&PcodeOpRef(op_arc.clone()));
        }
        // cc:1117: discoverIndexedStackPointers(spc, freeStores, false)
        // Re-run discovery. Rugra's discovery closure is the stack-store
        // approximation (the full indexed-stack-pointer trace belongs to the
        // load-guard/stack-delay residual family); the reprocess contract
        // here only needs the resulting usesSpacebasePtr marks.
        Heritage::discover_and_guard_stack_stores_fd(fd);
        // cc:1119-1140: remove the now-unnecessary INDIRECTs.
        for op_arc in free_stores {
            // cc:1124: if (op->usesSpacebasePtr()) continue
            if op_arc.read().unwrap().uses_spacebase_ptr() {
                continue;
            }
            // cc:1127-1128: indOp = op->previousOp() backward walk.
            let mut ind_op = op_arc
                .read()
                .unwrap()
                .previous_op_in_block(&fd.obank)
                .map(|r| r.0.clone());
            while let Some(ind_arc) = ind_op {
                // cc:1129: if (indOp->code() != CPUI_INDIRECT) break
                if ind_arc.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                    break;
                }
                // cc:1130-1131: iop input must be an Iop-space varnode.
                let iop_vn = ind_arc.read().unwrap().get_in(1).cloned();
                let iop_vn = match iop_vn {
                    Some(vn) if vn.read().unwrap().get_space() == AddressSpace::Iop => vn,
                    _ => break,
                };
                // cc:1132: if (op != PcodeOp::getOpFromConst(iopVn->getAddr())) break
                // — the IOP varnode must alias THIS store op.
                let aliased_op = fd.get_op_from_const(&iop_vn);
                let aliases_this = aliased_op
                    .as_ref()
                    .map(|r| Arc::ptr_eq(&r.0, op_arc))
                    .unwrap_or(false);
                if !aliases_this {
                    break;
                }
                // cc:1133: nextOp is read before any possible destroy.
                let next_op = ind_arc
                    .read()
                    .unwrap()
                    .previous_op_in_block(&fd.obank)
                    .map(|r| r.0.clone());
                // cc:1134-1137: remove guards whose output is in the space.
                let out_space = ind_arc
                    .read()
                    .unwrap()
                    .output
                    .as_ref()
                    .map(|o| o.read().unwrap().address_space);
                if out_space == Some(space) {
                    let (out_vn, in_vn) = {
                        let r = ind_arc.read().unwrap();
                        (r.output.as_ref().cloned(), r.get_in(0).cloned())
                    };
                    if let (Some(out), Some(inv)) = (out_vn, in_vn) {
                        fd.total_replace(&out, inv);
                    }
                    fd.op_destroy(&PcodeOpRef(ind_arc.clone()));
                }
                ind_op = next_op;
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

    // Ghidra: heritage.cc:1210 Heritage::guardCallOverlappingInput
    /// Guard an address range that is larger than any single input
    /// parameter for the given call: construct a SUBPIECE that pulls out
    /// the potential parameter. Faithful 1:1 port of
    /// `guardCallOverlappingInput` (heritage.cc:1210-1235), including the
    /// callee→caller truncAddr translation (cc:1218-1219) and the
    /// registerTrial-before-opInsertInput order (cc:1231-1232).
    pub fn guard_call_overlapping_input(
        &mut self,
        fd: &mut Funcdata,
        fc_idx: usize,
        space: AddressSpace,
        addr: Address,
        trans_offset: u64,
        size: i32,
    ) {
        // cc:1215: if (fc->getBiggestContainedInputParam(transAddr, size, vData))
        let v_data = match fd
            .get_call_specs(fc_idx)
            .and_then(|fc| {
                fc.prototype
                    .get_biggest_contained_input_param(space, trans_offset, size)
            }) {
            Some(v) => v,
            None => return,
        };
        let (_v_space, v_offset, v_size) = v_data;
        // cc:1218-1219: truncAddr in caller perspective.
        let diff = v_offset.wrapping_sub(trans_offset);
        let trunc_addr = Address::new(addr.as_u64().wrapping_add(diff));
        // cc:1220: if (active->whichTrial(truncAddr, size) < 0)
        let already_trial = fd
            .get_call_specs(fc_idx)
            .and_then(|fc| fc.active_input.as_ref())
            .map(|active| active.which_trial(trunc_addr, size) >= 0)
            .unwrap_or(true);
        if already_trial {
            return;
        }
        // cc:1221: truncateAmount = addr.justifiedContain(size, truncAddr, vData.size, false)
        let truncate_amount = crate::fspec::justified_contain_range(
            addr.as_u64(),
            size,
            trunc_addr.as_u64(),
            v_size,
            false,
        );
        // cc:1222-1223: subpieceOp = newOp(2, op->getAddr())
        let call_op = match fd.get_call_specs(fc_idx).and_then(|fc| fc.find_call_op(fd)) {
            Some(op) => op,
            None => return,
        };
        let op_addr = call_op.0.read().unwrap().get_addr();
        let subpiece_op = fd.new_op(2, op_addr);
        // cc:1224: opSetOpcode(subpieceOp, CPUI_SUBPIECE)
        fd.op_set_opcode(&subpiece_op, OpCode::CPUI_SUBPIECE);
        // cc:1225-1226: wholeVn = newVarnode(size, addr); setActiveHeritage
        let whole_vn = fd
            .vbank
            .create_with_space(size as usize, space, addr.as_u64());
        whole_vn.write().unwrap().set_active_heritage();
        fd.op_set_input(&subpiece_op, whole_vn, 0);
        // cc:1228: opSetInput(subpieceOp, newConstant(4, truncateAmount), 1)
        let off_const = fd.new_constant(4, truncate_amount as u64);
        fd.op_set_input(&subpiece_op, off_const, 1);
        // cc:1229: vn = newVarnodeOut(vData.size, truncAddr, subpieceOp)
        let vn = fd.new_varnode_out(v_size as usize, trunc_addr, &subpiece_op);
        // cc:1230: opInsertBefore(subpieceOp, op)
        fd.op_insert_before(&subpiece_op, &call_op);
        // cc:1231: active->registerTrial(truncAddr, vData.size)
        if let Some(fc) = fd.get_call_specs_mut(fc_idx) {
            if let Some(active) = &mut fc.active_input {
                active.register_trial(trunc_addr, v_size);
            }
        }
        // cc:1232: opInsertInput(op, vn, op->numInput())
        let num_in = call_op.0.read().unwrap().num_input();
        fd.op_insert_input(&call_op, vn, num_in);
    }

    // Ghidra: heritage.cc:1248 Heritage::guardOutputOverlap
    /// Insert created INDIRECT ops to guard the output of a call when the
    /// guarded range properly contains the return storage. Faithful 1:1
    /// port of `guardOutputOverlap` (heritage.cc:1248-1282): the return
    /// storage becomes an indirectly created value (`newIndirectCreation`
    /// with possibleout=true), the front piece aliases the return-storage
    /// INDIRECT (not the call), the back piece aliases the call, and the
    /// pieces are recombined with PIECE ops inserted after the call.
    pub fn guard_output_overlap(
        &mut self,
        fd: &mut Funcdata,
        call_op: &crate::op::PcodeOpRef,
        space: AddressSpace,
        addr: Address,
        size: i32,
        ret_addr: Address,
        ret_size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1251-1252: front/back split sizes.
        let size_front = (ret_addr.as_u64().saturating_sub(addr.as_u64())) as i32;
        let size_back = size - ret_size - size_front;
        // cc:1253: the return storage itself is an indirect creation with
        // possibleout=true (a possible call output).
        let ind_op = fd.new_indirect_creation_in_space(
            call_op, space, ret_addr.as_u64(), ret_size as usize, true,
        );
        // cc:1254: vnCollect = indOp->getOut()
        let mut vn_collect = ind_op.0.read().unwrap().output.as_ref().cloned();
        // cc:1273/1260 endianness: the locked oracle arch is x86:LE:64, so
        // retAddr.isBigEndian() == false (Rugra Address carries no space,
        // so the flag cannot be consulted dynamically; ADDRESS-0001).
        let big_endian = false;
        // cc:1256-1267: front piece (aliases the return-storage INDIRECT).
        if size_front != 0 {
            let ind_front = fd.new_indirect_creation_in_space(
                &ind_op, space, addr.as_u64(), size_front as usize, false,
            );
            let new_front = ind_front.0.read().unwrap().output.as_ref().cloned();
            let concat_front = fd.new_op(2, ret_addr);
            let slot_new = if big_endian { 0 } else { 1 };
            fd.op_set_opcode(&concat_front, OpCode::CPUI_PIECE);
            if let (Some(front_vn), Some(collect_vn)) = (&new_front, &vn_collect) {
                fd.op_set_input(&concat_front, front_vn.clone(), slot_new);
                fd.op_set_input(&concat_front, collect_vn.clone(), 1 - slot_new);
            }
            vn_collect = Some(fd.new_varnode_out(
                (size_front + ret_size) as usize,
                addr,
                &concat_front,
            ));
            // cc:1265-1266: opInsertAfter(concatFront, callOp)
            fd.op_insert_after(&concat_front, call_op);
        }
        // cc:1268-1279: back piece (aliases the call).
        if size_back != 0 {
            let addr_back = Address::new(ret_addr.as_u64().wrapping_add(ret_size as u64));
            let ind_back = fd.new_indirect_creation_in_space(
                call_op, space, addr_back.as_u64(), size_back as usize, false,
            );
            let new_back = ind_back.0.read().unwrap().output.as_ref().cloned();
            let concat_back = fd.new_op(2, ret_addr);
            let slot_new = if big_endian { 1 } else { 0 };
            fd.op_set_opcode(&concat_back, OpCode::CPUI_PIECE);
            if let (Some(back_vn), Some(collect_vn)) = (&new_back, &vn_collect) {
                fd.op_set_input(&concat_back, back_vn.clone(), slot_new);
                fd.op_set_input(&concat_back, collect_vn.clone(), 1 - slot_new);
            }
            vn_collect = Some(fd.new_varnode_out(size as usize, addr, &concat_back));
            // cc:1278: opInsertAfter(concatBack, insertPoint)
            // insertPoint is the call when no front piece ran, else the
            // front concat; the front concat was inserted directly after
            // the call, so inserting after the call keeps Ghidra's order
            // only for the no-front case. With a front piece Ghidra
            // inserts the back concat after concatFront.
            if size_front != 0 {
                // The front concat is the op immediately after the call.
                // Reuse op_insert_after chain: insert after concatFront.
                // (Resolve it as the op right after the call.)
                let next = {
                    let parent = call_op.0.read().unwrap()
                        .parent.as_ref().and_then(|w| w.upgrade());
                    match parent {
                        Some(blk) => {
                            let ops = blk.read().unwrap().get_ops();
                            let pos = ops.iter().position(|o| std::sync::Arc::ptr_eq(&o.0, &call_op.0));
                            pos.and_then(|p| ops.get(p + 1)).cloned()
                        }
                        None => None,
                    }
                };
                match next {
                    Some(follow) => fd.op_insert_after(&concat_back, &follow),
                    None => fd.op_insert_after(&concat_back, call_op),
                }
            } else {
                fd.op_insert_after(&concat_back, call_op);
            }
        }
        // cc:1280-1281: setActiveHeritage + append to write.
        if let Some(collect_vn) = vn_collect {
            collect_vn.write().unwrap().set_active_heritage();
            write.push(collect_vn);
        }
    }

    // Ghidra: heritage.cc:1292 Heritage::tryOutputOverlapGuard
    /// Try to guard an address range that is larger than the possible
    /// output storage for the given call. Faithful 1:1 port of
    /// `tryOutputOverlapGuard` (heritage.cc:1292-1309): the truncAddr
    /// translation, the trial lookup with the RANGE size (cc:1304) and the
    /// registration with the TRUNCATED size (cc:1307) are exact.
    pub fn try_output_overlap_guard(
        &mut self,
        fd: &mut Funcdata,
        fc_idx: usize,
        space: AddressSpace,
        addr: Address,
        trans_offset: u64,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> bool {
        // cc:1298: if (!fc->getBiggestContainedOutput(transAddr, size, vData))
        let v_data = match fd
            .get_call_specs(fc_idx)
            .and_then(|fc| fc.prototype.get_biggest_contained_output(space, trans_offset, size))
        {
            Some(v) => v,
            None => return false,
        };
        let (_v_space, v_offset, v_size) = v_data;
        // cc:1301-1303: truncAddr in caller perspective.
        let diff = v_offset.wrapping_sub(trans_offset);
        let trunc_addr = Address::new(addr.as_u64().wrapping_add(diff));
        // cc:1304: if (active->whichTrial(truncAddr, size) >= 0) return false
        let already_trial = fd
            .get_call_specs(fc_idx)
            .and_then(|fc| fc.active_output.as_ref())
            .map(|active| active.which_trial(trunc_addr, size) >= 0)
            .unwrap_or(true);
        if already_trial {
            return false;
        }
        // cc:1306: guardOutputOverlap(fc->getOp(), addr, size, truncAddr, vData.size, write)
        let call_op = match fd.get_call_specs(fc_idx).and_then(|fc| fc.find_call_op(fd)) {
            Some(op) => op,
            None => return false,
        };
        self.guard_output_overlap(
            fd, &call_op, space, addr, size, trunc_addr, v_size, write,
        );
        // cc:1307: active->registerTrial(truncAddr, vData.size)
        if let Some(fc) = fd.get_call_specs_mut(fc_idx) {
            if let Some(active) = &mut fc.active_output {
                active.register_trial(trunc_addr, v_size);
            }
        }
        true
    }

    // Ghidra: heritage.cc:1538 Heritage::guardStores
    /// Guard STORE ops in preparation for the renaming algorithm. Faithful
    /// port of `guardStores` (heritage.cc:1538-1559): iterate the STORE
    /// opcode list in bank order, skip dead ops, and match the STORE's
    /// constant target space against the heritage range's space or its
    /// container (with `usesSpacebasePtr` required for the container case,
    /// cc:1551-1552). Each match produces one INDIRECT with the
    /// `indirect_store` flag whose output joins `write` in iteration order.
    pub fn guard_stores_range(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1544: container = spc->getContain() — for the enum-space model
        // only the Stack (spacebase) space has a container, which is Ram.
        // RUGRA-GLUE: enum AddressSpace exposes no getContain; this mirrors
        // the locked x86:LE:64 oracle's contain graph.
        let container: Option<AddressSpace> = match space {
            AddressSpace::Stack => Some(AddressSpace::Ram),
            _ => None,
        };
        // cc:1547-1548: iter=fd->beginOp(CPUI_STORE) .. endOp
        let store_arcs: Vec<_> = fd.obank.storelist.iter()
            .filter(|s| !(s.0.read().unwrap().flags & crate::op::pcodeop_flags::DEAD != 0))
            .map(|s| s.0.clone())
            .collect();
        for store_op in store_arcs {
            // cc:1549: if (op->isDead()) continue;  (filtered above)
            // cc:1550: storeSpace = op->getIn(0)->getSpaceFromConst()
            let store_space = {
                let s = store_op.read().unwrap();
                s.get_in(0).map(|vn| {
                    let r = vn.read().unwrap();
                    if r.is_constant() {
                        AddressSpace::from_id(r.get_offset() as crate::space::SpaceId)
                    } else {
                        r.address_space
                    }
                })
            };
            let Some(store_space) = store_space else { continue };
            // cc:1551-1552: match against the range space or its container.
            let uses_sb = store_op.read().unwrap().uses_spacebase_ptr();
            let matches = store_space == space
                || (container == Some(store_space) && uses_sb);
            if !matches {
                continue;
            }
            // cc:1553: indop = fd->newIndirectOp(op,addr,size,indirect_store)
            let indop = fd.new_indirect_op(
                &PcodeOpRef(store_op.clone()),
                space,
                addr.as_u64(),
                size as usize,
                crate::op::pcodeop_flags::INDIRECT_STORE,
            );
            // cc:1554-1556: setActiveHeritage on input[0] and output; push.
            let (invn, outvn) = {
                let ind_r = indop.0.read().unwrap();
                (ind_r.get_in(0).cloned(), ind_r.output.as_ref().cloned())
            };
            if let Some(vn) = invn {
                vn.write().unwrap().set_active_heritage();
            }
            if let Some(vn) = outvn {
                vn.write().unwrap().set_active_heritage();
                write.push(vn);
            }
        }
    }

    // Ghidra: heritage.cc:1570 Heritage::guardLoads
    /// Guard LOAD ops for a specific range. Faithful to `guardLoads`
    /// (heritage.cc:1570-1601) up to the recorded residuals: the fl/addrtied
    /// gate and invalid-guard pruning are exact; the per-LOAD COPY boundary
    /// insertion (cc:1590-1599) is still a registered TODO because the
    /// LoadGuard range refinement (analyzeNewLoadGuards ValueSetSolver) is
    /// a stub.
    pub fn guard_loads_range(
        &mut self,
        fd: &mut Funcdata,
        fl: u32,
        space: AddressSpace,
        addr: Address,
        size: i32,
        _write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1576: if ((fl & Varnode::addrtied)==0) return
        if (fl & crate::varnode::varnode_flags::ADDRTIED) == 0 {
            return;
        }
        // cc:1577-1586: prune guards that are no longer valid LOADs.
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
        // cc:1587: if (guardRec.spc != addr.getSpace()) continue
        // cc:1588-1589: minimumOffset/maximumOffset window check.
        let addr_start = addr.as_u64();
        let addr_end = addr.as_u64().wrapping_add(size as u64);
        let _ = fd;
        for guard in &self.load_guard {
            if guard.spc != space { continue; }
            let intersects = guard.maximum_offset >= addr_start
                && guard.minimum_offset <= addr_end;
            if !intersects { continue; }
            // cc:1590-1599: COPY boundary insertion (registered TODO: needs
            // the ValueSetSolver-refined guard ranges first).
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
            let ind_front = fd.new_indirect_op(
                &PcodeOpRef(call_op.clone()), AddressSpace::Stack,
                addr.as_u64(), size_front as usize, 0,
            );
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
            let ind_back = fd.new_indirect_op(
                &PcodeOpRef(call_op.clone()), AddressSpace::Stack,
                addr_back.as_u64(), size_back as usize, 0,
            );
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

    // Ghidra: heritage.cc:1391 Heritage::tryOutputStackGuard
    /// Attempt to guard a stack range against a call with a locked stack
    /// output. Faithful port of the `contained_by` branch (cc:1395-1405):
    /// the biggest contained output is translated to the caller's
    /// perspective and guarded by `guard_output_overlap_stack`. The
    /// "output contains the range" branch (cc:1407-1430) needs the locked
    /// output parameter's own storage Address, which Rugra's FuncProto does
    /// not keep; it conservatively reports `false` so guardCalls falls back
    /// to the unknown_effect INDIRECT (never under-protects the range).
    pub fn try_output_stack_guard(
        &mut self,
        fd: &mut Funcdata,
        fc_idx: usize,
        space: AddressSpace,
        addr: Address,
        trans_offset: u64,
        size: i32,
        output_character: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> bool {
        if output_character == crate::fspec::containment::CONTAINED_BY {
            // cc:1396-1400: if (!fc->getBiggestContainedOutput(...)) return false
            let v_data = match fd.get_call_specs(fc_idx).and_then(|fc| {
                fc.prototype
                    .get_biggest_contained_output(space, trans_offset, size)
            }) {
                Some(v) => v,
                None => return false,
            };
            let (_v_space, v_offset, v_size) = v_data;
            // cc:1400-1403: truncAddr in caller perspective.
            let diff = v_offset.wrapping_sub(trans_offset);
            let trunc_addr = Address::new(addr.as_u64().wrapping_add(diff));
            // cc:1403: guardOutputOverlapStack(callOp, addr, size, truncAddr, vData.size, write)
            let call_op = match fd.get_call_specs(fc_idx).and_then(|fc| fc.find_call_op(fd)) {
                Some(op) => op,
                None => return false,
            };
            self.guard_output_overlap_stack(
                fd,
                &call_op.0,
                addr,
                size,
                trunc_addr,
                v_size,
                write,
            );
            return true;
        }
        // cc:1406-1430: output exists and contains the heritage range.
        // Requires the locked output parameter's storage (fc->getOutput()).
        // Rugra FuncProto keeps only the return data-type; conservative
        // false keeps the unknown_effect INDIRECT guard in guardCalls.
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
    pub fn clear_stack_placeholders(&mut self, fd: &mut Funcdata, info_space: AddressSpace) {
        // cc:2051-2054: for each call, abortSpacebaseRelative.
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
                callspecs[i].abort_spacebase_relative(&mut *fd, &op_ref);
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
        // cc:512-525: with a null insertop the expression goes to the
        // start block's beginning (getStartBlock + beginOp), and the ops
        // carry the function address; otherwise the ops insert before
        // insertop in its own block.
        //
        // cc:516-518/546 anchor semantics: insertiter = bl->beginOp() is
        // captured ONCE before the loop and is an ELEMENT anchor — the
        // block's original first op X. std::list::insert(insertiter, op)
        // inserts BEFORE that element every round, so the pieces keep
        // creation order [P1, P2, ..., X]; with an empty block the anchor
        // is endOp and every piece appends at the end in creation order.
        // A fixed numeric index 0 per round would REVERSE the pieces
        // (each later piece landing before the earlier ones).
        let (null_anchor, op_addr): (Option<crate::op::PcodeOpRef>, Address) = match insert_op {
            Some(op) => {
                let addr = op.0.read().unwrap().get_addr();
                (None, addr)
            }
            None => {
                let start = fd.bblocks.get_block(0);
                let has_entry = start
                    .as_ref()
                    .map(|b| {
                        (b.read().unwrap().get_flags() & crate::block::block_flags::ENTRY_POINT)
                            != 0
                    })
                    .unwrap_or(false);
                if !has_entry {
                    // Ghidra getStartBlock throws "No start block
                    // registered" (block.cc:1649-1655); keep the op
                    // unparented and surface the same condition.
                    eprintln!("[HERITAGE] WARN: No start block registered");
                }
                let anchor = if has_entry {
                    let bl = fd.bblocks.get_block(0).expect("entry checked above");
                    let first_op = bl.read().unwrap().get_ops().first().cloned();
                    first_op.map(|o| crate::op::PcodeOpRef(o.0.clone()))
                } else {
                    None
                };
                (anchor, *fd.get_address())
            }
        };
        for i in 1..vnlist.len() {
            let vn = &vnlist[i];
            let newop = fd.new_op(2, op_addr);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            let newvn = if i == vnlist.len() - 1 {
                // cc:532-535: final op outputs finalvn via opSetOutput
                fd.op_set_output(&newop, final_vn.clone());
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
            match insert_op {
                Some(ins_op) => fd.op_insert_before(&newop, ins_op),
                None => {
                    if let Some(anchor) = &null_anchor {
                        // cc:546: insert before the fixed first-op anchor
                        // so the pieces keep creation order before X.
                        fd.op_insert_before(&newop, anchor);
                    } else if fd.bblocks.get_block(0).is_some()
                        && (fd.bblocks.get_block(0).unwrap().read().unwrap().get_flags()
                            & crate::block::block_flags::ENTRY_POINT)
                            != 0
                    {
                        // cc:546 with an empty start block: the anchor is
                        // endOp; every piece appends at the end.
                        let bl = fd.bblocks.get_block(0).unwrap();
                        fd.op_insert(&newop, &bl, None);
                    }
                }
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
        // cc:567-588: with a null insertop the SUBPIECE ops go to the
        // start block's beginning (getStartBlock + beginOp) carrying the
        // function address; otherwise they insert AFTER the write
        // (++insertiter) in the write's own block, carrying its address.
        //
        // cc:582-587/602 anchor semantics: ++insertiter follows the
        // ELEMENT after the write (Y) — every piece inserts BEFORE Y, so
        // the order is [W, S1, S2, S3, Y] in creation order; if the write
        // is the block tail the anchor is endOp and pieces append at the
        // end. The null-insertop anchor is the start block's original
        // first op (same element-anchor rule as concatPieces cc:516-518).
        // A fixed numeric write-position+1 per round would REVERSE the
        // pieces (each later piece landing right after the write).
        enum InsertAnchor {
            /// cc:586 ++insertiter: insert before this element every round.
            Before(Option<crate::op::PcodeOpRef>, std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
            /// cc:579-581: null insertop — anchor on the start block's
            /// first element, or append at the end when it is empty.
            StartBlock,
            /// Unparented insertop (unreachable in the oracle, which
            /// dereferences getParent): no insertion.
            None,
        }
        let (anchor, op_addr) = match insert_op {
            Some(op) => {
                let (o_addr, parent) = {
                    let o = op.0.read().unwrap();
                    (o.get_addr(), o.parent.as_ref().and_then(|p| p.upgrade()))
                };
                match parent {
                    Some(bl) => {
                        let write_pos = {
                            let ops = bl.read().unwrap().get_ops();
                            ops.iter().position(|candidate| Arc::ptr_eq(&candidate.0, &op.0))
                        };
                        match write_pos {
                            Some(pos) => {
                                let next_elem = bl
                                    .read()
                                    .unwrap()
                                    .get_ops()
                                    .get(pos + 1)
                                    .map(|o| crate::op::PcodeOpRef(o.0.clone()));
                                (InsertAnchor::Before(next_elem, bl), o_addr)
                            }
                            // The locked oracle dereferences
                            // insertop->getParent() and reads its basic
                            // iterator; an op not in its own parent block
                            // cannot reach this path.
                            None => (InsertAnchor::None, o_addr),
                        }
                    }
                    None => (InsertAnchor::None, o_addr),
                }
            }
            None => {
                let start = fd.bblocks.get_block(0);
                let has_entry = start
                    .as_ref()
                    .map(|b| {
                        (b.read().unwrap().get_flags() & crate::block::block_flags::ENTRY_POINT)
                            != 0
                    })
                    .unwrap_or(false);
                if !has_entry {
                    eprintln!("[HERITAGE] WARN: No start block registered");
                }
                (InsertAnchor::StartBlock, *fd.get_address())
            }
        };
        // Resolve the start-block first-op element anchor once (M3: same
        // element-anchor rule as concatPieces; pieces keep creation order
        // before the original first op, or append at the end when empty).
        let start_anchor: Option<crate::op::PcodeOpRef> = match &anchor {
            InsertAnchor::StartBlock => fd.bblocks.get_block(0).and_then(|bl| {
                bl.read()
                    .unwrap()
                    .get_ops()
                    .first()
                    .map(|o| crate::op::PcodeOpRef(o.0.clone()))
            }),
            _ => None,
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
            // cc:601: fd->opSetOutput(newop, vn)
            fd.op_set_output(&newop, vn_arc.clone());
            match &anchor {
                InsertAnchor::Before(next_elem, bl) => match next_elem {
                    // cc:602: insert before the fixed element after the
                    // write — pieces keep creation order before Y.
                    Some(y) => {
                        fd.op_insert_before(&newop, y);
                    }
                    // Write is the block tail: the anchor is endOp, every
                    // piece appends at the end.
                    None => {
                        fd.op_insert(&newop, bl, None);
                    }
                },
                InsertAnchor::StartBlock => {
                    if let Some(y) = &start_anchor {
                        fd.op_insert_before(&newop, y);
                    } else if let Some(bl) = fd.bblocks.get_block(0) {
                        fd.op_insert(&newop, &bl, None);
                    }
                }
                InsertAnchor::None => {}
            }
        }
    }

    // Ghidra: heritage.cc:307 Heritage::collect
    /// Collect free reads, writes, and inputs in the given address range.
    /// Faithful to `collect` (heritage.cc:307-347): the four output
    /// vectors are cleared (cc:310-313), write-mask Varnodes are skipped
    /// (cc:326), a written Varnode whose def is a marker or return-form
    /// COPY is evidence of previous heritage — smaller than the range it
    /// goes to `remove` (cc:330-333), otherwise the range's
    /// new_addresses property is cleared (cc:334) — max write size is
    /// tracked (cc:336-337) and the written Varnode joins `write`
    /// (cc:338), a free Varnode with a descendant joins `read`
    /// (cc:340-341), and an input Varnode joins `input` (cc:342-343).
    ///
    /// Space-identity note: Ghidra scans beginLoc(memrange.addr) through
    /// endLoc(endaddr), which is confined to the MemRange's own address
    /// space (its Address carries the space); the probe-based live window
    /// below preserves exactly that — entries of other spaces never enter
    /// the iteration (HERITAGE-DRIVER-SWITCH-0001 space-key fix; the
    /// historical whole-bank offset filter misclassified cross-space
    /// collisions).
    pub fn collect(
        &self,
        fd: &Funcdata,
        memrange: &mut MemRange,
        read: &mut Vec<Arc<RwLock<Varnode>>>,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
        input: &mut Vec<Arc<RwLock<Varnode>>>,
        remove: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> i32 {
        read.clear();
        write.clear();
        input.clear();
        remove.clear();
        let addr = memrange.addr;
        let size = memrange.size;
        let end_addr = addr.as_u64().wrapping_add(size as u64);
        let mut maxsize: i32 = 0;
        // Ghidra cc:323-325: beginLoc(memrange.addr) .. endLoc(addr+size) —
        // LIVE ordered-window iteration over the bank's loc-set. Liveness is
        // load-bearing: refinement (refineRead/refineWrite/refineInput,
        // cc:1902-1906) creates piece varnodes earlier in this same
        // placeMultiequals walk, and the oracle's re-collect of the first
        // piece (cc:2615) plus every later piece's collect must see them —
        // an entry-frozen snapshot would hide the pieces for the whole pass
        // and, because the next pass classifies the range OLD
        // (addIndirects=false), the missed INDIRECTs would never be built
        // (review finding M1). Rugra's loc_tree is a
        // BTreeSet<VarnodeLocRef> whose Ord acquires varnode read locks
        // during comparison, so the RangeFrom bound is built from a
        // synthetic probe varnode: size 0 sorts before every same-offset
        // member, so `probe..` starts exactly at beginLoc(addr). The window
        // walk itself touches only window members (other spaces never
        // enter — space-major ordering mirrors VarnodeCompareLocDef), and
        // classification reads live flags, matching the oracle iterator.
        let probe = crate::varnode::VarnodeLocRef(std::sync::Arc::new(
            std::sync::RwLock::new(Varnode::new_with_space(
                0,
                memrange.space,
                addr.as_u64(),
            )),
        ));
        for entry in fd.vbank.loc_tree.range(probe..) {
            let vn_arc = entry.0.clone();
            let vn = vn_arc.read().unwrap();
            if vn.address_space != memrange.space || vn.loc.as_u64() >= end_addr {
                break;
            }
            // cc:326: if (!vn->isWriteMask()) gates every classification
            if vn.is_write_mask() {
                continue;
            }
            if vn.is_written() {
                // cc:329: marker or return-form COPY = previous heritage
                let def_op = vn.def.as_ref().and_then(|w| w.upgrade());
                if let Some(def_op) = def_op {
                    let def_r = def_op.read().unwrap();
                    let prior_heritage = def_r.is_marker()
                        || (def_r.flags & crate::op::pcodeop_flags::RETURN_COPY) != 0;
                    if prior_heritage {
                        if vn.get_size() < size as usize {
                            remove.push(vn_arc.clone());
                            continue;
                        }
                        // cc:334: previous pass covered everything
                        memrange.clear_property(memrange_flags::NEW_ADDRESSES);
                    }
                }
                if vn.get_size() as i32 > maxsize {
                    maxsize = vn.get_size() as i32;
                }
                write.push(vn_arc.clone());
            } else if !vn.is_heritage_known() && !vn.has_no_descend() {
                read.push(vn_arc.clone());
            } else if vn.is_input() {
                input.push(vn_arc.clone());
            }
        }
        maxsize
    }

    // Ghidra: heritage.cc:1952 Heritage::guardInput
    /// Ensure input varnodes fill the entire range. Faithful to
    /// `guardInput` (heritage.cc:1952-2010): a single full-range input
    /// links in automatically (cc:1958); otherwise holes are filled with
    /// freshly promoted inputs (cc:1969-1992), every piece is
    /// write-masked (cc:1997-1998) and a final unified free Varnode of
    /// the whole range is built with concatPieces at the start block
    /// beginning and marked active heritage (cc:2008-2009).
    pub fn guard_input(
        &self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        input: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        if input.is_empty() { return; }
        // cc:1958: if single input fills everything, skip
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
                    // cc:1973-1976: hole before this input — create the
                    // missing input piece.
                    let sz = (vn_off - cur) as usize;
                    let vn = fd.vbank.create_with_space(sz, vn_space, cur);
                    let promoted = fd.set_input_varnode(vn);
                    newinput.push(promoted);
                } else {
                    newinput.push(input[i].clone());
                    i += 1;
                }
            } else {
                // cc:1985-1988: tail hole after the last input.
                let sz = (end - cur) as usize;
                let vn = fd.vbank.create_with_space(sz, vn_space, cur);
                let promoted = fd.set_input_varnode(vn);
                newinput.push(promoted);
            }
            cur = cur.wrapping_add(newinput.last().unwrap().read().unwrap().get_size() as u64);
        }
        // cc:1996: if only one piece, it links automatically
        if newinput.len() == 1 { return; }
        // cc:1997-1998: all pieces carry the write mask
        for vn in &newinput {
            vn.write().unwrap().set_write_mask();
        }
        // cc:2008-2009: newout = newVarnode(size, addr);
        // concatPieces(newinput, (PcodeOp *)0, newout)->setActiveHeritage()
        let space = newinput
            .first()
            .map(|v| v.read().unwrap().address_space)
            .unwrap_or(vn_space);
        let newout = fd.vbank.create_with_space(size as usize, space, addr.as_u64());
        let unified = self.concat_pieces(fd, &newinput, None, &newout);
        unified.write().unwrap().set_active_heritage();
        // cc:1952-2010 never reassigns the caller's `input` vector; the
        // filled pieces live only in the local newinput consumed by the
        // concatenation above.
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

    // Ghidra: heritage.cc:1772 Heritage::refineRead
    /// Split a free read Varnode based on the refinement, replacing it
    /// with a concatenation expression whose final output is a temporary
    /// unique. Faithful to `refineRead` (heritage.cc:1772-1787):
    /// splitByRefinement, newUnique(vn->getSize()), loneDescend slot,
    /// concatPieces(newvn, op, replacevn), opSetInput, and
    /// deleteVarnode when the consumed free has no remaining descendant
    /// (cc:1783-1786 throws "Refining non-free varnode" otherwise; Rust
    /// keeps the varnode and reports the violation on stderr).
    pub fn refine_read(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() {
            return;
        }
        // cc:1778: replacevn = fd->newUnique(vn->getSize())
        let vn_size = vn.read().unwrap().get_size();
        let replacevn = fd.new_unique(vn_size);
        // cc:1779-1781: op = vn->loneDescend(); slot = op->getSlot(vn).
        // Bind the lone-descend result in its own statement: an `if let`
        // CONDITION temporary would hold vn's read guard for the whole
        // block, and op_set_input below re-locks the same Varnode for
        // write (opSetInput's eraseDescend path) — a same-thread
        // RwLock deadlock.
        let lone_desc = vn.read().unwrap().lone_descend();
        if let Some(read_op) = lone_desc {
            let read_ref = PcodeOpRef(read_op.clone());
            let num_input = read_op.read().unwrap().num_input();
            let slot = read_op
                .read()
                .unwrap()
                .inrefs
                .iter()
                .position(|v| Arc::ptr_eq(v, vn))
                .unwrap_or(num_input);
            // cc:1782: concatPieces(newvn, op, replacevn)
            self.concat_pieces(fd, &newvn, Some(&read_ref), &replacevn);
            // cc:1783: fd->opSetInput(op, replacevn, slot)
            if slot < num_input {
                fd.op_set_input(&read_ref, replacevn.clone(), slot);
            }
        }
        // cc:1784-1786: if (vn->hasNoDescend()) fd->deleteVarnode(vn);
        // else throw LowlevelError("Refining non-free varnode")
        if vn.read().unwrap().has_no_descend() {
            let _ = fd.delete_varnode(vn);
        } else {
            // Ghidra aborts the pass here; mirror the throw with the
            // oracle's exact text (mechanism-C M4 alignment).
            panic!("Refining non-free varnode");
        }
    }

    // Ghidra: heritage.cc:1806 Heritage::refineWrite
    /// Split a written Varnode based on the refinement: the write is
    /// redirected to a fresh temporary, SUBPIECE ops define each piece
    /// from that temporary, the original Varnode is total-replaced by
    /// the temporary and destroyed. Faithful to `refineWrite`
    /// (heritage.cc:1806-1818).
    pub fn refine_write(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() {
            return;
        }
        // cc:1812: replacevn = fd->newUnique(vn->getSize())
        let vn_size = vn.read().unwrap().get_size();
        let (vn_loc, def_op) = {
            let r = vn.read().unwrap();
            (r.loc, r.def.as_ref().and_then(|w| w.upgrade()))
        };
        let Some(def_op) = def_op else { return };
        let def_ref = PcodeOpRef(def_op);
        let replacevn = fd.new_unique(vn_size);
        // cc:1814: fd->opSetOutput(def, replacevn)
        fd.op_set_output(&def_ref, replacevn.clone());
        // cc:1815: splitPieces(newvn, def, vn->getAddr(), vn->getSize(), replacevn)
        self.split_pieces(
            fd,
            &newvn,
            Some(&def_ref),
            vn_loc,
            vn_size as i32,
            &replacevn,
        );
        // cc:1816-1817: totalReplace + deleteVarnode
        fd.total_replace(vn, replacevn.clone());
        let _ = fd.delete_varnode(vn);
    }

    // Ghidra: heritage.cc:1836 Heritage::refineInput
    /// Split a known input Varnode based on the refinement. Faithful to
    /// `refineInput` (heritage.cc:1836-1844): the pieces are defined by
    /// SUBPIECE ops reading the original input (inserted at the start
    /// block beginning because insertop is null, cc:578-581) and the
    /// original input is write-masked (cc:1843). No new inputs are
    /// created and no input flags are mutated here.
    pub fn refine_input(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() {
            return;
        }
        // cc:1842: splitPieces(newvn, (PcodeOp *)0, vn->getAddr(), vn->getSize(), vn)
        let (vn_loc, vn_size) = {
            let r = vn.read().unwrap();
            (r.loc, r.get_size() as i32)
        };
        self.split_pieces(fd, &newvn, None, vn_loc, vn_size, vn);
        // cc:1843: vn->setWriteMask()
        vn.write().unwrap().set_write_mask();
    }

    // Ghidra: heritage.cc:1857 Heritage::remove13Refinement
    /// Remove 1-byte/3-byte refinement patterns. Faithful to
    /// `remove13Refinement` (heritage.cc:1857-1880): walk the partition
    /// sizes left to right; a 1-3 or 3-1 adjacency is replaced by a
    /// single 4 at the position of the first element (the second
    /// element's start slot), and the walk continues from the end of the
    /// second element.
    pub fn remove13_refinement(&self, refine: &mut [i32]) {
        if refine.is_empty() {
            return;
        }
        let mut pos: usize = 0;
        let mut lastsize = refine[pos];
        pos = pos.saturating_add(lastsize.max(0) as usize);
        while pos < refine.len() {
            let cursize = refine[pos];
            if cursize == 0 {
                break;
            }
            if (lastsize == 1 && cursize == 3) || (lastsize == 3 && cursize == 1) {
                refine[pos - lastsize as usize] = 4;
                lastsize = 4;
                pos += cursize as usize;
            } else {
                lastsize = cursize;
                pos += lastsize as usize;
            }
        }
    }

    // Ghidra: heritage.cc:1890 Heritage::refinement
    /// Find the common refinement of all reads and writes in the address
    /// range, split them to match, and rewrite both the current-pass
    /// `disjoint` cover and the persistent `globaldisjoint` map.
    /// Faithful to `refinement` (heritage.cc:1890-1940):
    ///   - the refinement array carries the cc:1896 `size+1` fencepost,
    ///     which buildRefinement may mark at the range end and which is
    ///     popped (cc:1900) before the boundary-to-partition-size
    ///     conversion loop (cc:1901-1908);
    ///   - no non-trivial refinement (`lastpos == 0`, cc:1908) returns
    ///     `None` (Ghidra returns `disjoint.end()`);
    ///   - the original MemRange is erased and the pieces are spliced in
    ///     at the same position so the caller's index walk visits each
    ///     piece (cc:1921-1938); each piece is re-added to
    ///     `globaldisjoint` under the original entry's pass number
    ///     (cc:1922-1924);
    ///   - returns the index of the first inserted piece.
    pub fn refinement(
        &mut self,
        fd: &mut Funcdata,
        memidx: usize,
        readvars: &[Arc<RwLock<Varnode>>],
        writevars: &[Arc<RwLock<Varnode>>],
        inputvars: &[Arc<RwLock<Varnode>>],
    ) -> Option<usize> {
        let size = self.disjoint.tasklist[memidx].size;
        // cc:1894: if (size > 1024) return disjoint.end();
        if size > 1024 {
            return None;
        }
        let addr = self.disjoint.tasklist[memidx].addr;
        let space = self.disjoint.tasklist[memidx].space;
        // cc:1896: vector<int4> refine(size+1, 0) — with fencepost.
        let mut refine = vec![0i32; size as usize + 1];
        self.build_refinement(&mut refine, addr, readvars);
        self.build_refinement(&mut refine, addr, writevars);
        self.build_refinement(&mut refine, addr, inputvars);
        // cc:1900: refine.pop_back() — remove the fencepost.
        refine.pop();
        // cc:1901-1908: convert boundary points to partition sizes.
        let mut lastpos = 0usize;
        for curpos in 1..size as usize {
            if refine[curpos] != 0 {
                refine[lastpos] = (curpos - lastpos) as i32;
                lastpos = curpos;
            }
        }
        if lastpos == 0 {
            return None; // No non-trivial refinements
        }
        refine[lastpos] = size - lastpos as i32;
        // cc:1910: remove13Refinement(refine)
        self.remove13_refinement(&mut refine);
        // cc:1912-1917: split reads, writes, inputs along the refinement.
        for vn in readvars {
            self.refine_read(fd, vn, addr, &refine);
        }
        for vn in writevars {
            self.refine_write(fd, vn, addr, &refine);
        }
        for vn in inputvars {
            self.refine_input(fd, vn, addr, &refine);
        }
        // cc:1919-1938: alter the disjoint cover (locally and globally) to
        // reflect the refinement. The original entry is erased, the pieces
        // are inserted in its place, and each piece is re-added to
        // globaldisjoint under the erased entry's pass number.
        let flags = self.disjoint.tasklist[memidx].flags;
        let cur_pass = match self.globaldisjoint.themap.remove(&(space, addr)) {
            Some(sp) => sp.pass,
            // cc:1922-1923 dereferences globaldisjoint.find(addr); an
            // exact-key miss is unreachable for driver-fed ranges (the
            // driver adds the same (addr,size) to both structures before
            // placeMultiequals runs). Fall back to the current pass so a
            // drifted key cannot fabricate a wrong NEW classification.
            None => self.pass,
        };
        self.disjoint.tasklist.remove(memidx);
        let mut pieces: Vec<MemRange> = Vec::new();
        let mut cut = 0i32;
        let mut piece_addr = addr;
        while cut < size {
            let sz = refine[cut as usize];
            if sz <= 0 {
                // Partition walks always land on a partition start, where
                // the converted array holds a positive size; a zero here
                // means a corrupted refinement array, which the locked
                // oracle cannot produce (its cc:1926-1938 walk would
                // never terminate either). Terminate rather than spin.
                break;
            }
            pieces.push(MemRange {
                addr: piece_addr,
                size: sz,
                flags,
                space,
            });
            cut += sz;
            piece_addr = Address::new(piece_addr.as_u64().wrapping_add(sz as u64));
        }
        self.disjoint
            .tasklist
            .splice(memidx..memidx, pieces.into_iter());
        // cc:1929-1937: globaldisjoint.add per piece (same order). The
        // add() intersect code is discarded exactly as cc:1929-1935 does.
        cut = 0;
        piece_addr = addr;
        while cut < size {
            let sz = refine[cut as usize];
            if sz <= 0 {
                break;
            }
            let _ = self.globaldisjoint.add(space, piece_addr, sz, cur_pass);
            cut += sz;
            piece_addr = Address::new(piece_addr.as_u64().wrapping_add(sz as u64));
        }
        Some(memidx)
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

    // Ghidra: heritage.cc:2663 Heritage::heritage
    /// One canonical Heritage pass, faithful to `Heritage::heritage`
    /// (heritage.cc:2663-2758), driven through an exclusive `&mut Funcdata`:
    ///   1. cc:2676-2677 if maxdepth == -1 (restructure forced) buildADT()
    ///   2. cc:2679 processJoins()
    ///   3. cc:2680-2683 pass 0: one local PreferSplitManager init+split
    ///   4. cc:2684-2748 per-space loop (ascending infolist order):
    ///      placeholders, one-time discovery, ordered Varnode scan feeding
    ///      persistent globaldisjoint + current-pass disjoint, warnings
    ///   5. cc:2749 placeMultiequals()
    ///   6. cc:2750 rename()
    ///   7. cc:2751-2752 reprocessFreeStores when discovery requested it
    ///   8. cc:2753-2754 analyzeNewLoadGuards + handleNewLoadCopies
    ///   9. cc:2755-2756 pass 0: splitAdditional on the SAME manager
    ///   10. cc:2757 pass += 1 exactly once
    ///
    /// Ownership boundary (HERITAGE-OWNERSHIP-0001): the persistent Heritage
    /// object no longer stores a `Weak<RwLock<Funcdata>>`; the caller
    /// (`Funcdata::op_heritage`) temporarily moves `self.heritage` out via
    /// `mem::take`, invokes this pass against the same `&mut Funcdata`, and
    /// restores it, so no nested lock acquisition can occur.
    pub fn heritage(&mut self, fd: &mut Funcdata) {
        // Ghidra cc:2676-2677: if (maxdepth == -1) buildADT();
        // maxdepth == -1 is the ctor/clear sentinel meaning "restructure
        // forced" — exactly one rebuild on the first pass after (re)reset.
        // Ghidra's buildADT consumes the dominator state produced upstream by
        // Funcdata::structureReset (calcForwardDominator); Rugra's equivalent
        // producer is BlockGraph::build_dom_tree.
        if self.maxdepth == -1 {
            fd.bblocks.build_dom_tree();
            self.build_adt(fd);
        }

        // Ghidra cc:2679: processJoins();
        self.process_joins(fd);

        // Ghidra cc:2674-2683: one local PreferSplitManager shared by
        // split (pass 0) and splitAdditional (end of pass 0). Rugra has no
        // architecture split records on x86-64 (empty vec mirrors the locked
        // fixture architecture and the x86:LE:64:default oracle), but the
        // single-instance lifetime is preserved.
        let mut splitmanage = crate::prefersplit::PreferSplitManager::new();
        if self.pass == 0 {
            splitmanage.init(fd, Vec::new());
            splitmanage.split(fd);
        }

        // Ghidra cc:2671-2673: pass-local freeStores vector shared by
        // discovery and reprocessFreeStores.
        let mut free_stores: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut reprocess_stack_count = 0;
        let mut stack_space = AddressSpace::Stack;

        // Ghidra cc:2684: for(int4 i=0;i<infolist.size();++i)
        // NOTE (1:1 with the oracle): `Heritage::heritage` does NOT build
        // the info list. It is built exactly once by
        // `Funcdata::startProcessing` (funcdata.cc:166 -> buildInfoList)
        // before the first ActionHeritage pass; iterating an empty
        // infolist therefore performs zero per-space stages, on both sides.
        for i in 0..self.infolist.len() {
            // cc:2686: if (!info->isHeritaged()) continue;
            if !self.infolist[i].space.is_heritaged() {
                continue;
            }
            // cc:2687: if (pass < info->delay) continue;
            if self.pass < self.infolist[i].delay {
                continue;
            }
            let space = self.infolist[i].space;
            // cc:2688-2689: if (info->hasCallPlaceholders)
            //   clearStackPlaceholders(info);
            if self.infolist[i].has_call_placeholders {
                self.clear_stack_placeholders(fd, space);
            }

            // cc:2691-2697: if (!info->loadGuardSearch) {
            //   info->loadGuardSearch = true;
            //   if (discoverIndexedStackPointers(info->space,freeStores,true))
            //     { reprocessStackCount += 1; stackSpace = info->space; } }
            // GAP (HERITAGE-CALLGUARD-0001): discoverIndexedStackPointers is
            // not on this path yet, so reprocessStackCount stays 0 and the
            // cc:2751-2752 reprocessFreeStores call below cannot fire.
            if !self.infolist[i].load_guard_search {
                self.infolist[i].load_guard_search = true;
            }

            // cc:2698-2732: build disjoint ranges from this space's
            // Varnodes in VarnodeLocSet location order.
            let pass = self.pass;
            let deadremoved = self.infolist[i].deadremoved;
            let mut needwarning = false;
            let mut warnvn: Option<Arc<RwLock<Varnode>>> = None;
            let vns_in_space: Vec<(Arc<RwLock<Varnode>>, Address, i32)> = {
                let mut result = Vec::new();
                for vn_ref in &fd.vbank.loc_tree {
                    let vn = vn_ref.0.read().unwrap();
                    if vn.address_space != space {
                        continue;
                    }
                    // cc:2704: skip dead unused frees
                    if !vn.is_written()
                        && vn.has_no_descend()
                        && !vn.is_unaffected()
                        && !vn.is_input()
                    {
                        continue;
                    }
                    // cc:2706: if (vn->isWriteMask()) continue;
                    if vn.is_write_mask() {
                        continue;
                    }
                    result.push((vn_ref.0.clone(), vn.loc, vn.get_size() as i32));
                }
                result
            };
            for (vn_arc, vn_addr, vn_size) in vns_in_space {
                // cc:2708: LocationMap::iterator liter =
                //   globaldisjoint.add(vn->getAddr(),vn->getSize(),pass,prev);
                let prev = self.globaldisjoint.add(space, vn_addr, vn_size, pass);
                // (*liter).first / (*liter).second.size: the merged map
                // entry covering vn_addr (LocationMap::add returns the
                // iterator to the merged entry; Rugra's add returns only the
                // intersect code, so re-locate the containing entry).
                let (m_addr, m_size) = match self.globaldisjoint.entry_containing(space, vn_addr) {
                    Some(e) => e,
                    None => (vn_addr, vn_size),
                };
                if prev == 0 {
                    // cc:2709-2710: all-new location (or intersecting with
                    // something new)
                    self.disjoint
                        .add(space, m_addr, m_size, memrange_flags::NEW_ADDRESSES);
                } else if prev == 2 {
                    // cc:2711: completely contained in range from previous pass
                    // cc:2712: if (vn->isHeritageKnown()) continue;
                    if vn_arc.read().unwrap().is_heritage_known() {
                        continue;
                    }
                    // cc:2713: if (vn->hasNoDescend()) continue;
                    if vn_arc.read().unwrap().has_no_descend() {
                        continue;
                    }
                    // cc:2714-2718: first deadremoval warning
                    if !needwarning
                        && deadremoved > 0
                        && !fd.is_jumptable_recovery_on()
                    {
                        needwarning = true;
                        self.bump_deadcode_delay(vn_arc.read().unwrap().get_space());
                        warnvn = Some(vn_arc.clone());
                    }
                    // cc:2719
                    self.disjoint.add(space, m_addr, m_size, memrange_flags::OLD_ADDRESSES);
                } else {
                    // cc:2721-2722: partially contained in old range, but
                    // may contain new stuff
                    self.disjoint.add(
                        space,
                        m_addr,
                        m_size,
                        memrange_flags::OLD_ADDRESSES | memrange_flags::NEW_ADDRESSES,
                    );
                    // cc:2723-2730
                    if !needwarning
                        && deadremoved > 0
                        && !fd.is_jumptable_recovery_on()
                    {
                        if vn_arc.read().unwrap().is_heritage_known() {
                            continue;
                        }
                        needwarning = true;
                        self.bump_deadcode_delay(vn_arc.read().unwrap().get_space());
                        warnvn = Some(vn_arc.clone());
                    }
                }
            }

            // cc:2734-2747: warning header (issued once per space).
            if needwarning {
                if !self.infolist[i].warning_issued {
                    self.infolist[i].warning_issued = true;
                    let mut errmsg = String::from("Heritage AFTER dead removal. Example location: ");
                    let warn_ref = warnvn.expect("needwarning implies warnvn");
                    errmsg.push_str(&warn_ref.read().unwrap().print_raw());
                    if !warn_ref.read().unwrap().has_no_descend() {
                        let warnop = warn_ref
                            .read()
                            .unwrap()
                            .descend_iter()
                            .next()
                            .map(|op| op.read().unwrap().get_addr().as_u64());
                        if let Some(addr) = warnop {
                            errmsg.push_str(&format!(" : {addr:#x}"));
                        }
                    }
                    fd.warning_header(&errmsg);
                }
            }
        }

        // Ghidra cc:2749: placeMultiequals();
        self.place_multiequals(fd);

        // Ghidra cc:2750: rename();
        self.rename(fd);

        // Ghidra cc:2751-2752: if (reprocessStackCount > 0)
        //   reprocessFreeStores(stackSpace, freeStores);
        if reprocess_stack_count > 0 {
            self.reprocess_free_stores(fd, stack_space, &free_stores);
        }

        // Ghidra cc:2753: analyzeNewLoadGuards();
        self.analyze_new_load_guards();

        // Ghidra cc:2754: handleNewLoadCopies();
        self.handle_new_load_copies(fd);

        // Ghidra cc:2755-2756: if (pass == 0) splitmanage.splitAdditional();
        if self.pass == 0 {
            splitmanage.split_additional(fd);
        }

        // Ghidra cc:2757: pass += 1;
        self.pass += 1;
    }

    // Ghidra: heritage.cc:2599 Heritage::placeMultiequals
    /// Place phi nodes using the ADT algorithm, faithful to
    /// `placeMultiequals` (heritage.cc:2599-2645): it walks the current
    /// `disjoint` cover in order, consumes `collect` per range
    /// (cc:2609), optionally refines a range larger than four bytes when
    /// no write spans it (cc:2610-2616), removes revisited markers
    /// (cc:2626-2627), fills input holes (cc:2628), guards the range
    /// (cc:2629), calculates the merge blocks (cc:2630) and inserts each
    /// MULTIEQUAL at the beginning of its merge block via opInsertBegin
    /// (cc:2631-2642). The ADT itself is built by the driver
    /// (`heritage`, cc:2676-2677), never here.
    ///
    /// The four output vectors are declared once outside the loop and
    /// cleared/reused by every `collect` call, exactly as cc:2603-2609.
    /// After a refinement, Ghidra reassigns the iterator to the first
    /// refined piece (`iter = refiter`, cc:2613), re-collects it
    /// (cc:2614), and the loop's `++iter` then visits the remaining
    /// pieces; the index-based Rust loop reproduces this by replacing
    /// the tasklist entry with its pieces and continuing at the first
    /// piece index.
    pub fn place_multiequals(&mut self, fd: &mut Funcdata) {
        let mut readvars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut writevars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut inputvars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut removevars: Vec<Arc<RwLock<Varnode>>> = Vec::new();

        let mut idx = 0usize;
        while idx < self.disjoint.tasklist.len() {
            // Ghidra cc:2609: max = collect(*iter, read, write, input, remove).
            // collect() takes the MemRange by reference and may clear its
            // new_addresses property (cc:334); mirror that in-place list
            // mutation by cloning, collecting, and writing the entry back.
            let mut memrange = self.disjoint.tasklist[idx].clone();
            let mut max = self.collect(
                fd,
                &mut memrange,
                &mut readvars,
                &mut writevars,
                &mut inputvars,
                &mut removevars,
            );
            self.disjoint.tasklist[idx] = memrange.clone();
            // Ghidra cc:2610-2616: refine ranges bigger than 4 bytes that
            // no single write fully spans, then re-collect the first piece.
            // collect's loc_tree window is LIVE (probe-based beginLoc), so
            // the pieces refinement just created are visible here and to
            // every later piece — matching the oracle's iterators
            // (review finding M1: an entry-frozen snapshot hid them).
            if memrange.size > 4 && max < memrange.size {
                if let Some(first_piece) =
                    self.refinement(fd, idx, &readvars, &writevars, &inputvars)
                {
                    idx = first_piece;
                    memrange = self.disjoint.tasklist[idx].clone();
                    max = self.collect(
                        fd,
                        &mut memrange,
                        &mut readvars,
                        &mut writevars,
                        &mut inputvars,
                        &mut removevars,
                    );
                    self.disjoint.tasklist[idx] = memrange.clone();
                }
            }
            // Ghidra cc:2617: const MemRange &memrange(*iter);
            let size = memrange.size;
            // Ghidra cc:2619-2625: skip ranges with no reads when there is
            // nothing to merge, or when the space is internal (unique) or
            // the range was already covered by a previous pass.
            if readvars.is_empty() {
                if writevars.is_empty() && inputvars.is_empty() {
                    idx += 1;
                    continue;
                }
                if memrange.space == AddressSpace::Unique || memrange.old_addresses() {
                    idx += 1;
                    continue;
                }
            }
            // Ghidra cc:2626-2627: removeRevisitedMarkers(remove, addr, size)
            if !removevars.is_empty() {
                self.remove_revisited_markers(fd, &removevars, memrange.addr, size);
            }
            // Ghidra cc:2628: guardInput(addr, size, inputvars)
            self.guard_input(fd, memrange.addr, size, &mut inputvars);
            // Ghidra cc:2629: guard(addr, size, newAddresses(), read, write, input)
            self.guard_range(
                fd,
                memrange.space,
                memrange.addr,
                size,
                memrange.new_addresses(),
                &mut readvars,
                &mut writevars,
                &mut inputvars,
            );
            // Ghidra cc:2630: calcMultiequals(writevars)
            self.calc_multiequals(fd, &writevars);
            // Ghidra cc:2631-2642: create each MULTIEQUAL at the beginning
            // of its merge block. The op is allocated with sizeIn() inputs
            // at the block's start address, the output is a fresh
            // active-heritage write of the whole range, each input is a
            // fresh free Varnode of the range storage, and the op is
            // inserted at the block beginning (before any existing
            // leading MULTIEQUAL group only for non-MULTIEQUAL inserts —
            // funcdata_op.cc:413-421).
            for &blk_idx in self.merge.clone().iter() {
                let bl = match fd.bblocks.get_block(blk_idx as usize) {
                    Some(b) => b,
                    None => continue,
                };
                let (blk_size_in, start_addr) = {
                    let b = bl.read().unwrap();
                    (b.size_in(), b.get_start_addr())
                };
                let multiop = fd.new_op(blk_size_in, start_addr);
                // cc:2634-2635: newVarnodeOut(size, addr, multiop) +
                // setActiveHeritage (space-carrying Address adapter).
                let vnout = fd.vbank.create_def_with_space(
                    size as usize,
                    memrange.space,
                    memrange.addr.as_u64(),
                    &multiop.0,
                );
                multiop.0.write().unwrap().output = Some(vnout.clone());
                fd.set_varnode_properties(&vnout);
                vnout.write().unwrap().set_active_heritage();
                // cc:2636: opSetOpcode(multiop, CPUI_MULTIEQUAL)
                fd.op_set_opcode(&multiop, OpCode::CPUI_MULTIEQUAL);
                for j in 0..blk_size_in {
                    // cc:2638-2639: newVarnode(size, addr) + opSetInput
                    let vnin = fd
                        .vbank
                        .create_with_space(size as usize, memrange.space, memrange.addr.as_u64());
                    fd.op_set_input(&multiop, vnin, j);
                }
                // cc:2641: opInsertBegin(multiop, bl)
                fd.op_insert_begin(&multiop, &bl);
            }
            idx += 1;
        }
        // Ghidra cc:2644: merge.clear()
        self.merge.clear();
    }

    // RUGRA-GLUE: Rugra-specific dominance-frontier phi placement; Ghidra has no `placeMultiequalsDirect`.
    /// Insert Phi nodes directly using bank references. NOT the canonical
    /// algorithm: Ghidra's `placeMultiequals` (heritage.cc:2599-2645) derives
    /// merge blocks from the augmented dominator tree, not a dominance
    /// frontier. Since HERITAGE-DRIVER-SWITCH-0001 this is off the
    /// production path (ActionHeritage drives the canonical
    /// `Heritage::heritage`); it survives only for the legacy
    /// `Funcdata::run_heritage_direct` entry (example-side prototype
    /// estimation on throwaway Funcdata) and in-crate tests.
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

                // RUN-NONDETERM root cause: iterating the HashSet
                // directly makes the MULTIEQUAL creation order random per
                // process (std SipHash seeds). The canonical
                // Heritage::placeMultiequals does not use a dominance
                // frontier at all — it derives merge blocks through the
                // depth-ordered PriorityQueue/augment walk
                // (calcMultiequals cc:2439-2466 + visitIncr cc:2394-2428,
                // mirrored in calc_multiequals). Until the production
                // switch (HERITAGE-DRIVER-SWITCH-0001) replaces this
                // direct path, pin the iteration order deterministically
                // by block index (RUN-NONDETERM minimal fix, causally
                // verified 20/20 byte-identical).
                let mut df_sorted: Vec<i32> = df.into_iter().collect();
                df_sorted.sort_unstable();

                for y_idx in df_sorted {
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

    // RUGRA-GLUE: Borrow-safe extraction of one merge-block insertion from Heritage::placeMultiequals (heritage.cc:2631-2642).
    // (The former `insert_multiequal` Funcdata-bank adapter wrapper was removed with the production direct path in
    // HERITAGE-DRIVER-SWITCH-0001: it had no remaining callers.)

    // RUGRA-GLUE: Borrow-safe extraction of one merge-block insertion from Heritage::placeMultiequals (heritage.cc:2631-2642).
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
        // heritage.cc:2641 calls Funcdata::opInsertBegin
        // (funcdata_op.cc:413), which installs the parent/list membership.
        // This direct-bank adapter sets the equivalent parent back-pointer.
        op_ref.0.write().unwrap().parent = Some(std::sync::Arc::downgrade(&block_arc) as std::sync::Weak<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>);

        // Query globaldisjoint LocationMap for precise size (keyed by
        // (space, offset); falls back to a vbank lookup, then 4 — see the
        // direct-route residual note in the fn doc below).
        let size = self
            .globaldisjoint
            .themap
            .get(&(space, addr))
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
        let out_vn = vbank.set_def_prevalidated(out_vn, Arc::downgrade(&op_ref.0));

        {
            let mut op = op_ref.0.write().unwrap();
            op.output = Some(out_vn);
            // Initialize inrefs with placeholders so they can be filled by index
            for _ in 0..num_in {
                let placeholder = vbank.create_with_space(size, space, addr.as_u64());
                // heritage.cc:2638-2639 routes every placeholder through
                // Funcdata::opSetInput, so each slot contributes one
                // descendant entry before renameRecurse replaces it.
                placeholder.write().unwrap().add_descend(&op_ref.0);
                op.inrefs.push(placeholder);
            }
        }
    }

    // Ghidra: heritage.cc:2587 Heritage::rename
    /// Perform the renaming algorithm for the current set of address
    /// ranges. Faithful to `rename` (heritage.cc:2587-2593): one fresh
    /// VariableStack, renameRecurse rooted at block 0 ONLY (not "every
    /// entry-like block"), then `disjoint.clear()`.
    pub fn rename(&mut self, fd: &mut Funcdata) {
        let mut varstack: BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>> =
            BTreeMap::new();
        if let Some(bl0) = fd.bblocks.get_block(0) {
            self.rename_recurse(fd, bl0, &mut varstack);
        }
        // Ghidra cc:2592: disjoint.clear();
        self.disjoint.clear();
    }

    // Ghidra: heritage.cc:2479 Heritage::renameRecurse
    /// The heart of the renaming algorithm, faithful to `renameRecurse`
    /// (heritage.cc:2479-2562). From the given block, walk the dominance
    /// tree (iterative Enter/Leave work stack reproducing the recursive
    /// "children then pop" order). At each block:
    ///   - ONE pass over the ops in execution order (cc:2489): a
    ///     MULTIEQUAL skips only its input-replacement loop (cc:2491) but
    ///     still takes the common write-push tail (cc:2523-2529) at its
    ///     op position — no separate phi pre-pass;
    ///   - input slots ascending (cc:2493): skip heritage-known (cc:2495),
    ///     skip-and-keep non-active frees (cc:2496), clear active on
    ///     consumption (cc:2497), empty-stack input promotion
    ///     (cc:2499-2502), INDIRECT same-time stack deepening
    ///     (cc:2507-2516), replacement via Funcdata::opSetInput
    ///     (cc:2518) and deleteVarnode of the consumed free
    ///     (cc:2519-2520);
    ///   - write push (cc:2523-2529): output fetched after the op's read
    ///     replacement; active outputs are cleared and pushed;
    ///   - successor loop (cc:2531-2552): out-edges ascending, exact
    ///     reverse slot, successor's LEADING MULTIEQUAL group only
    ///     (cc:2536 break); phi inputs check isHeritageKnown ONLY
    ///     (cc:2538 — the old-marker skip that makes a phi cycle with an
    ///     already-written loop-carried input leave that input alone);
    ///     empty-stack promotion and deleteVarnode as above, with NO
    ///     activeHeritage check or clear on this path;
    ///   - dominator children in `domchild[index]` order (cc:2555);
    ///   - writelist popped in encounter order after all children
    ///     (cc:2558-2561).
    fn rename_recurse(
        &mut self,
        fd: &mut Funcdata,
        bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        varstack: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
    ) {
        // Iterative dominator-tree traversal using an explicit work stack:
        // Enter processes one block's ops/successors and schedules Leave
        // (pop) plus its dominator children; children are pushed in
        // reverse so they run in domchild order, and Leave runs after all
        // of them, reproducing the recursive cc:2553-2561 order without
        // unbounded Rust recursion.
        enum WorkItem {
            Enter(Arc<RwLock<dyn FlowBlock + Send + Sync>>),
            Leave(Vec<(AddressSpace, Address)>),
        }

        let mut work: Vec<WorkItem> = vec![WorkItem::Enter(bl)];
        // Guard against corrupt dominator graphs (which would grow the
        // work stack unboundedly); the locked oracle's domchild is a tree.
        let max_work = 100000usize;

        while let Some(item) = work.pop() {
            if work.len() > max_work {
                eprintln!(
                    "[WARN] Heritage rename work stack exceeded {} items, aborting",
                    max_work
                );
                break;
            }
            match item {
                WorkItem::Enter(block_arc) => {
                    let mut writelist: Vec<(AddressSpace, Address)> = Vec::new();

                    // cc:2489-2530: single pass over ops in execution order.
                    let ops = block_arc.read().unwrap().get_ops();
                    for op_ref in &ops {
                        let op_arc = op_ref.0.clone();
                        let op_is_multi =
                            op_arc.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL;
                        if !op_is_multi {
                            // cc:2493-2521: replace reads with the stack top.
                            let num_input = op_arc.read().unwrap().num_input();
                            for slot in 0..num_input {
                                let vnin_arc = {
                                    let op_r = op_arc.read().unwrap();
                                    match op_r.inrefs.get(slot) {
                                        Some(v) => v.clone(),
                                        None => continue,
                                    }
                                };
                                // cc:2495: not free
                                if vnin_arc.read().unwrap().is_heritage_known() {
                                    continue;
                                }
                                // cc:2496: not being heritaged this round
                                if !vnin_arc.read().unwrap().is_active_heritage() {
                                    continue;
                                }
                                // cc:2497: consume the active mark
                                vnin_arc.write().unwrap().clear_active_heritage();
                                let key = {
                                    let vn_r = vnin_arc.read().unwrap();
                                    (vn_r.address_space, vn_r.loc)
                                };
                                let stack = varstack.entry(key).or_default();
                                // cc:2499-2505: empty stack → promote a new input.
                                let mut vnnew: Arc<RwLock<Varnode>>;
                                if stack.is_empty() {
                                    let (vn_size, vn_space, vn_off) = {
                                        let r = vnin_arc.read().unwrap();
                                        (r.size, r.address_space, r.loc.as_u64())
                                    };
                                    let new_vn =
                                        fd.vbank.create_with_space(vn_size, vn_space, vn_off);
                                    let promoted = fd.set_input_varnode(new_vn);
                                    stack.push(promoted.clone());
                                    vnnew = promoted;
                                } else {
                                    vnnew = stack.last().unwrap().clone();
                                }
                                // cc:2506-2517: INDIRECTs and their op really
                                // happen AT SAME TIME — if the stack top was
                                // written by an INDIRECT guarding THIS op, use
                                // the value beneath it on the stack.
                                let indirect_target_is_cur = {
                                    let vnnew_r = vnnew.read().unwrap();
                                    let mut hit = false;
                                    if vnnew_r.is_written() {
                                        if let Some(def_weak) =
                                            vnnew_r.def.as_ref().and_then(|w| w.upgrade())
                                        {
                                            let def_r = def_weak.read().unwrap();
                                            if def_r.opcode == OpCode::CPUI_INDIRECT {
                                                if let Some(iop_vn) = def_r.get_in(1) {
                                                    let iv = iop_vn.read().unwrap();
                                                    if iv.get_space() == AddressSpace::Iop {
                                                        let ptr_addr = iv.get_offset() as usize;
                                                        let raw = ptr_addr
                                                            as *const std::sync::RwLock<PcodeOp>;
                                                        if raw as *const ()
                                                            == std::sync::Arc::as_ptr(&op_arc)
                                                                as *const ()
                                                        {
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
                                        // cc:2509-2512: only the INDIRECT entry
                                        // on the stack — create a new input and
                                        // insert it at the bottom.
                                        let (vn_size, vn_space, vn_off) = {
                                            let r = vnin_arc.read().unwrap();
                                            (r.size, r.address_space, r.loc.as_u64())
                                        };
                                        let new_vn = fd
                                            .vbank
                                            .create_with_space(vn_size, vn_space, vn_off);
                                        let promoted = fd.set_input_varnode(new_vn);
                                        stack.insert(0, promoted.clone());
                                        vnnew = promoted;
                                    } else {
                                        // cc:2515-2516: vnnew = stack[stack.size()-2]
                                        vnnew = stack[stack.len() - 2].clone();
                                    }
                                }
                                // cc:2518: fd->opSetInput(op, vnnew, slot)
                                fd.op_set_input(&PcodeOpRef(op_arc.clone()), vnnew, slot);
                                // cc:2519-2520: delete the consumed free
                                if vnin_arc.read().unwrap().has_no_descend() {
                                    let _ = fd.delete_varnode(&vnin_arc);
                                }
                            }
                        }
                        // cc:2523-2529: push this op's write onto the stack.
                        let out_vn = op_arc.read().unwrap().output.clone();
                        if let Some(vnout) = out_vn {
                            if !vnout.read().unwrap().is_active_heritage() {
                                continue; // cc:2526: not a normalized write
                            }
                            vnout.write().unwrap().clear_active_heritage();
                            let key = {
                                let r = vnout.read().unwrap();
                                (r.address_space, r.loc)
                            };
                            varstack.entry(key).or_default().push(vnout.clone());
                            writelist.push(key);
                        }
                    }

                    // cc:2531-2552: fill phi inputs in successors.
                    let size_out = block_arc.read().unwrap().size_out();
                    for i in 0..size_out {
                        let (succ_arc, my_in_idx) = {
                            let blk_r = block_arc.read().unwrap();
                            match blk_r.get_out(i) {
                                Some(edge) => (edge.point.clone(), edge.reverse_index as usize),
                                None => continue,
                            }
                        };
                        let succ_ops = succ_arc.read().unwrap().get_ops();
                        for op_ref in succ_ops {
                            let op_arc = op_ref.0.clone();
                            if op_arc.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
                                break; // cc:2536: leading MULTIEQUALs only
                            }
                            let vnin_arc = {
                                let op_r = op_arc.read().unwrap();
                                match op_r.inrefs.get(my_in_idx) {
                                    Some(v) => v.clone(),
                                    None => continue,
                                }
                            };
                            // cc:2538: heritage-known phi inputs are skipped
                            // (old marker skip — a phi cycle whose incoming
                            // edge value is already written keeps it).
                            if vnin_arc.read().unwrap().is_heritage_known() {
                                continue;
                            }
                            let key = {
                                let vn_r = vnin_arc.read().unwrap();
                                (vn_r.address_space, vn_r.loc)
                            };
                            let stack = varstack.entry(key).or_default();
                            // cc:2539-2546: empty stack → input promotion.
                            let vnnew: Arc<RwLock<Varnode>>;
                            if stack.is_empty() {
                                let (vn_size, vn_space, vn_off) = {
                                    let r = vnin_arc.read().unwrap();
                                    (r.size, r.address_space, r.loc.as_u64())
                                };
                                let new_vn =
                                    fd.vbank.create_with_space(vn_size, vn_space, vn_off);
                                let promoted = fd.set_input_varnode(new_vn);
                                stack.push(promoted.clone());
                                vnnew = promoted;
                            } else {
                                vnnew = stack.last().unwrap().clone();
                            }
                            // cc:2547: fd->opSetInput(multiop, vnnew, slot)
                            fd.op_set_input(&PcodeOpRef(op_arc.clone()), vnnew, my_in_idx);
                            // cc:2548-2549: delete the consumed free
                            if vnin_arc.read().unwrap().has_no_descend() {
                                let _ = fd.delete_varnode(&vnin_arc);
                            }
                        }
                    }

                    // cc:2553-2556: recurse to subtrees, in domchild order;
                    // cc:2557-2561: pop this block's writes after children.
                    let bl_idx = block_arc.read().unwrap().get_index();
                    work.push(WorkItem::Leave(writelist));
                    if let Some(children) = self.domchild.get(bl_idx as usize) {
                        for child in children.iter().rev() {
                            if let Some(child_arc) =
                                fd.bblocks.get_block(*child as usize)
                            {
                                work.push(WorkItem::Enter(child_arc));
                            }
                        }
                    }
                }
                WorkItem::Leave(writelist) => {
                    // cc:2558-2561: pop in encounter order.
                    for key in writelist {
                        if let Some(stack) = varstack.get_mut(&key) {
                            stack.pop();
                        }
                    }
                }
            }
        }
    }

    // RUGRA-GLUE: Direct-bank SSA driver around locked Heritage::rename/renameRecurse; it separates Rust-owned banks and its broader driver differences are documented.
    /// Perform SSA renaming directly using bank references.
    /// `vbank` is taken by &mut because heritage.cc:2501/2511 calls
    /// `fd->setInputVarnode` and cc:2520/2549 calls `fd->deleteVarnode`,
    /// both of which mutate the bank. Rugra ports these as
    /// `VarnodeBank::set_input_varnode` / `VarnodeBank::destroy_varnode`.
    /// Since HERITAGE-DRIVER-SWITCH-0001 this is off the production path
    /// (ActionHeritage drives canonical `Heritage::heritage`); remaining
    /// callers are `Funcdata::run_heritage_direct` (example-side prototype
    /// estimation on throwaway Funcdata) and in-crate tests.
    pub fn rename_direct(&mut self, vbank: &mut VarnodeBank, bblocks: &crate::block::BlockGraph) {
        // Mark all read+write varnodes as active heritage, faithful to
        // Ghidra's guard() (heritage.cc:1174/1181) which calls
        // setActiveHeritage on every varnode in the read AND write lists
        // of the disjoint ranges being heritaged this pass.
        //
        // Ghidra's read/write lists (from collect()) include both free
        // varnodes AND written varnodes at heritaged addresses — a written
        // varnode is a def that rename must push onto the stack (cc:2528
        // pushes vnout if isActiveHeritage). Without activeHeritage on
        // writes, rename skips pushing them → stack stays empty → empty-stack
        // input promotion (cc:2499-2502) creates a single shared input →
        // diamond merges lose per-branch distinctness.
        //
        // Rugra approximates Ghidra's per-range guard by marking every
        // non-constant, non-annotation varnode in the bank (free + written
        // + input). Inputs are harmless to mark because rename's
        // isHeritageKnown check (cc:2495/2538) skips them before checking
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

    // RUGRA-GLUE: Borrow-safe adapter that temporarily separates Funcdata::vbank before the iterative renameRecurse adapter below.
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

    // Ghidra: heritage.cc:2479 Heritage::renameRecurse
    /// Iterative mapping of `Heritage::renameRecurse(BlockBasic *bl,
    /// VariableStack &varstack)` (heritage.cc:2479-2562). Broader direct-driver,
    /// global-active marking, type-copy, and graph-model differences remain
    /// documented and are not claimed equivalent here.
    ///
    /// **2026-07-05 修正**：补齐 3 个 load-bearing 语义（audit P0-4）：
    ///   (1) **empty-stack input promotion** (cc:2499-2502 / cc:2540-2543) —
    ///       当 stack 为空时，Ghidra 创建新 varnode 并 `setInputVarnode` 提升为
    ///       函数输入，push 到 stack。Rugra 此前静默跳过 → 自由读未被替换 →
    ///       SSA 不完整。
    ///   (2) **INDIRECT same-time stack-deepening** (cc:2507-2516) — 当 stack
    ///       顶的 vnnew 是 INDIRECT 写且其 target op 是当前 op 时，Ghidra 认为
    ///       "INDIRECT 和它的 op 同时发生"，深入 stack 一层（stack[size-2]）。
    ///       Rugra 此前完全缺失 → 栈指针 INDIRECT 配对的 op 得到错误的 SSA 名。
    ///   (3) **deleteVarnode of consumed frees** (cc:2519-2520 / cc:2548-2549) —
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
                    // Ghidra cc:2489-2530.
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
                            // Ghidra cc:2497: vnin->clearActiveHeritage();
                            let vnin_arc = op.inrefs[i].clone();
                            vnin_arc.write().unwrap().clear_active_heritage();
                            // Ghidra cc:2498: vector<Varnode *> &stack(varstack[vnin->getAddr()]);
                            let key = {
                                let vn_read = vnin_arc.read().unwrap();
                                (vn_read.address_space, vn_read.loc)
                            };
                            let stack = stacks.entry(key).or_default();
                            // Ghidra cc:2499-2505: empty-stack → promote to input.
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
                            // Ghidra cc:2507-2516: INDIRECT same-time deepening.
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
                                    // cc:2509-2512: stack has only the INDIRECT entry;
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
                            // Ghidra cc:2518: fd->opSetInput(op, vnnew, slot);
                            // Preserve v_type from old varnode to new varnode
                            // so struct pointer types survive Heritage rename.
                            {
                                let old_vt = vnin_arc.read().unwrap().v_type.clone();
                                if old_vt.is_some() {
                                    vnnew.write().unwrap().v_type = old_vt;
                                }
                            }
                            if !Arc::ptr_eq(&vnin_arc, &vnnew) {
                                // funcdata_op.cc:120-124: opSetInput first
                                // consumes exactly this slot's old descendant,
                                // then adds the new edge before updating inrefs.
                                vnin_arc.write().unwrap().erase_descend(&op_ref.0);
                                vnnew.write().unwrap().add_descend(&op_ref.0);
                                op.inrefs[i] = vnnew.clone();
                            }
                            // Ghidra cc:2519-2520: if (vnin->hasNoDescend()) fd->deleteVarnode(vnin);
                            // (SEMANTIC #3)
                            if vnin_arc.read().unwrap().has_no_descend() {
                                // cc:2519 proves the value is detached; it was
                                // fetched from this bank's current SSA web.
                                vbank.destroy_varnode_prevalidated(&vnin_arc);
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
                    // Ghidra cc:2531-2552: for each out-edge, walk successor's
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
                                    break; // Ghidra cc:2536: stop at first non-MULTIEQUAL
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
                                // Ghidra cc:2539-2546: empty-stack → input promotion.
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
                                // Ghidra cc:2547: opSetInput(multiop, vnnew, slot)
                                if !Arc::ptr_eq(&vnin_arc, &vnnew) {
                                    vnin_arc.write().unwrap().erase_descend(&op_ref.0);
                                    vnnew.write().unwrap().add_descend(&op_ref.0);
                                    op.inrefs[my_in_idx] = vnnew.clone();
                                }
                                // Ghidra cc:2548-2549: deleteVarnode if no descend.
                                // (SEMANTIC #3, phi-input variant)
                                if vnin_arc.read().unwrap().has_no_descend() {
                                    // cc:2548 proves the value is detached;
                                    // the phi input is bank-owned by construction.
                                    vbank.destroy_varnode_prevalidated(&vnin_arc);
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
                    // 5. Pop stacks (Ghidra cc:2558-2561).
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
        self.disjoint.clear();
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
    fn test_rename_replaces_regular_input_and_retires_old_varnode() {
        use crate::address::SeqNum;

        let mut bank = VarnodeBank::new();
        let old = bank.create_with_space(4, AddressSpace::Register, 0x40);
        old.write().unwrap().set_active_heritage();
        let canonical = bank.create_with_space(4, AddressSpace::Register, 0x40);
        let canonical = bank.set_input(canonical).expect("fresh input");

        let operation = PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_COPY,
        ))));
        operation.0.write().unwrap().inrefs.push(old.clone());
        old.write().unwrap().add_descend(&operation.0);
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x1000)),
        ));
        block.write().unwrap().insert_op(0, operation.clone());

        let mut stacks = BTreeMap::new();
        stacks.insert(
            (AddressSpace::Register, Address::new(0x40)),
            vec![canonical.clone()],
        );
        Heritage::new().visit_rename_direct(&mut bank, block, &mut stacks);

        assert!(Arc::ptr_eq(
            &operation.0.read().unwrap().inrefs[0],
            &canonical,
        ));
        assert_eq!(canonical.read().unwrap().count_descends(), 1);
        assert!(old.read().unwrap().has_no_descend());
        assert!(!bank
            .loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, &old)));
    }

    #[test]
    fn test_rename_same_arc_input_is_an_exact_noop() {
        use crate::address::SeqNum;

        let mut bank = VarnodeBank::new();
        let value = bank.create_with_space(4, AddressSpace::Register, 0x44);
        value.write().unwrap().set_active_heritage();
        let operation = PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1010), 2),
            OpCode::CPUI_COPY,
        ))));
        operation.0.write().unwrap().inrefs.push(value.clone());
        value.write().unwrap().add_descend(&operation.0);
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x1010)),
        ));
        block.write().unwrap().insert_op(0, operation.clone());
        let mut stacks = BTreeMap::new();
        stacks.insert(
            (AddressSpace::Register, Address::new(0x44)),
            vec![value.clone()],
        );

        Heritage::new().visit_rename_direct(&mut bank, block, &mut stacks);

        assert!(Arc::ptr_eq(&operation.0.read().unwrap().inrefs[0], &value));
        assert_eq!(value.read().unwrap().count_descends(), 1);
        assert!(bank
            .loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, &value)));
    }

    #[test]
    fn test_inserted_phi_placeholders_have_edges_and_are_retired_per_slot() {
        let mut bank = VarnodeBank::new();
        let canonical = bank.create_with_space(4, AddressSpace::Register, 0x48);
        let canonical = bank.set_input(canonical).expect("fresh input");
        let mut op_bank = PcodeOpBank::new();
        let mut graph = BlockGraph::new();
        let pred0: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x2000)),
        ));
        let pred1: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(1, Address::new(0x2010)),
        ));
        let join: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(2, Address::new(0x2020)),
        ));
        graph.add_block(pred0.clone());
        graph.add_block(pred1.clone());
        graph.add_block(join.clone());
        graph.add_edge(pred0.clone(), join.clone());
        graph.add_edge(pred1.clone(), join.clone());

        let mut heritage = Heritage::new();
        heritage.insert_multiequal_direct(
            &mut bank,
            &mut op_bank,
            &graph,
            AddressSpace::Register,
            Address::new(0x48),
            2,
        );
        let phi = join.read().unwrap().get_ops()[0].clone();
        let placeholders = phi.0.read().unwrap().inrefs.clone();
        assert_eq!(placeholders.len(), 2);
        assert!(placeholders
            .iter()
            .all(|value| value.read().unwrap().count_descends() == 1));

        let mut stacks = BTreeMap::new();
        stacks.insert(
            (AddressSpace::Register, Address::new(0x48)),
            vec![canonical.clone()],
        );
        heritage.visit_rename_direct(&mut bank, pred0, &mut stacks);
        assert!(Arc::ptr_eq(&phi.0.read().unwrap().inrefs[0], &canonical));
        assert!(Arc::ptr_eq(
            &phi.0.read().unwrap().inrefs[1],
            &placeholders[1],
        ));
        assert!(placeholders[0].read().unwrap().has_no_descend());
        assert_eq!(placeholders[1].read().unwrap().count_descends(), 1);

        heritage.visit_rename_direct(&mut bank, pred1, &mut stacks);
        assert!(phi
            .0
            .read()
            .unwrap()
            .inrefs
            .iter()
            .all(|value| Arc::ptr_eq(value, &canonical)));
        assert_eq!(canonical.read().unwrap().count_descends(), 2);
        for placeholder in placeholders {
            assert!(placeholder.read().unwrap().has_no_descend());
            assert!(!bank
                .loc_tree
                .iter()
                .any(|entry| Arc::ptr_eq(&entry.0, &placeholder)));
        }
    }

    #[test]
    fn test_location_map() {
        let mut lm = LocationMap::new();
        lm.add(AddressSpace::Register, Address::new(0x100), 4, 1);
        assert_eq!(lm.find_pass(AddressSpace::Register, Address::new(0x100)), 1);
        assert_eq!(lm.find_pass(AddressSpace::Register, Address::new(0x200)), -1);
    }

    /// HERITAGE-DRIVER-SWITCH-0001: Ghidra's LocationMap is keyed by a full
    /// Address (space + offset, heritage.hh:48), and `Address::overlap`
    /// returns -1 across spaces, so equal offsets in different spaces are
    /// disjoint entries. The bare-offset key previously merged them and
    /// misclassified the second space's range as OLD (prev==2).
    #[test]
    fn test_location_map_cross_space_keys_are_disjoint() {
        use crate::space::AddressSpace;
        let mut lm = LocationMap::new();
        // Register 0x30 heritaged in pass 1.
        assert_eq!(lm.add(AddressSpace::Register, Address::new(0x30), 8, 1), 0);
        // A Stack varnode at the SAME offset must be NEW (prev==0), not
        // contained in the register entry (prev==2).
        assert_eq!(lm.add(AddressSpace::Stack, Address::new(0x30), 8, 2), 0);
        // Re-adding the register range at a later pass is contained (prev==2).
        assert_eq!(lm.add(AddressSpace::Register, Address::new(0x30), 8, 3), 2);
        // Each space queries its own entry only.
        assert_eq!(lm.find_pass(AddressSpace::Register, Address::new(0x30)), 1);
        assert_eq!(lm.find_pass(AddressSpace::Stack, Address::new(0x30)), 2);
        // entry_containing never crosses spaces either.
        assert_eq!(
            lm.entry_containing(AddressSpace::Stack, Address::new(0x33)),
            Some((Address::new(0x30), 8))
        );
        assert_eq!(lm.entry_containing(AddressSpace::Unique, Address::new(0x33)), None);
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

    // HERITAGE-OWNERSHIP-0001: shared synthetic-graph builder for the
    // ownership-boundary regression tests.
    struct OwnershipGraph {
        fd: Funcdata,
        next_pc: u64,
    }

    impl OwnershipGraph {
        fn new(name: &str, base: u64) -> Self {
            OwnershipGraph {
                fd: Funcdata::new(name, Address::new(base), 0x20),
                next_pc: 0,
            }
        }

        fn block(&mut self, index: i32) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
            let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
                BlockBasic::new(index, Address::new(0x6000)),
            ));
            self.fd.bblocks.add_block(block.clone());
            block
        }

        fn op(&mut self, opcode: OpCode, inputs: usize) -> PcodeOpRef {
            let pc = Address::new(0x6000 + self.next_pc);
            self.next_pc += 1;
            let op = self.fd.new_op(inputs, pc);
            self.fd.op_set_opcode(&op, opcode);
            op
        }

        fn constant(&mut self, size: usize, value: u64) -> Arc<RwLock<Varnode>> {
            self.fd.new_constant(size, value)
        }

        fn free_register(&mut self, offset: u64, size: usize) -> Arc<RwLock<Varnode>> {
            self.fd
                .vbank
                .create_with_space(size, AddressSpace::Register, offset)
        }

        /// Written varnode at an explicit register address (the SLEIGH-style
        /// direct register write), modeled with the bank's def transition.
        fn written_register(
            &mut self,
            offset: u64,
            size: usize,
            op: &PcodeOpRef,
        ) -> Arc<RwLock<Varnode>> {
            let vn = self
                .fd
                .vbank
                .create_with_space(size, AddressSpace::Register, offset);
            let vn = self
                .fd
                .vbank
                .set_def_prevalidated(vn, Arc::downgrade(&op.0));
            op.0.write().unwrap().output = Some(vn.clone());
            vn
        }

        fn set_input(&mut self, op: &PcodeOpRef, vn: &Arc<RwLock<Varnode>>, slot: usize) {
            self.fd.op_set_input(op, vn.clone(), slot);
        }

        fn insert_end(&mut self, op: &PcodeOpRef, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
            self.fd.op_insert_end(op, block);
        }
    }

    // HERITAGE-OWNERSHIP-0001: the phi self-reference cycle graph (the cover
    // fixture slot2 topology with a genuine loop-carried def-use cycle:
    // m_out -> r -> t3 -> m slot 1).
    fn build_phi_cycle_graph(name: &str) -> Funcdata {
        let mut g = OwnershipGraph::new(name, 0x6000);
        let b0 = g.block(0);
        let b1 = g.block(1);
        let b2 = g.block(2);
        let b3 = g.block(3);
        g.fd.bblocks.add_edge(b0.clone(), b1.clone());
        g.fd.bblocks.add_edge(b1.clone(), b2.clone());
        g.fd.bblocks.add_edge(b2.clone(), b1.clone());
        g.fd.bblocks.add_edge(b2.clone(), b3.clone());

        let c8 = g.constant(8, 5);
        let c4 = g.constant(4, 7);

        let d0 = g.op(OpCode::CPUI_COPY, 1);
        g.set_input(&d0, &c8, 0);
        let _t0 = g.fd.new_unique_out(8, &d0);
        g.insert_end(&d0, &b0);

        let free = g.free_register(0x28, 8);
        let m = g.op(OpCode::CPUI_MULTIEQUAL, 2);
        g.set_input(&m, &free, 0);
        let m_out = g.written_register(0x28, 8, &m);
        let _ = m_out;

        let r = g.op(OpCode::CPUI_INT_ADD, 2);
        let t3 = g.written_register(0x28, 8, &r);
        g.set_input(&r, &m_out, 0);
        g.set_input(&r, &c4, 1);
        g.set_input(&m, &t3, 1);
        g.insert_end(&m, &b1);
        g.insert_end(&r, &b2);

        let o = g.op(OpCode::CPUI_INT_OR, 2);
        g.set_input(&o, &m_out, 0);
        g.set_input(&o, &c4, 1);
        let _t4 = g.fd.new_unique_out(8, &o);
        g.insert_end(&o, &b3);

        g.fd
    }

    // HERITAGE-OWNERSHIP-0001: three consecutive `Funcdata::op_heritage`
    // boundary calls (pass 0->1->2->3) on the same `&mut Funcdata` must
    // complete on a phi self-reference cycle graph. The pre-refactor nominal
    // `Heritage::heritage` re-entered the Funcdata write lock (once via the
    // driver and again inside the guard-calls block), which self-deadlocks;
    // the explicit-ownership pass has no lock to re-enter. The watchdog
    // thread makes a hang fail the test instead of wedging the runner.
    #[test]
    fn test_op_heritage_three_passes_survive_phi_cycle_without_deadlock() {
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel::<(i32, i32)>();
        let handle = std::thread::spawn(move || {
            let mut fd = build_phi_cycle_graph("phi_cycle");
            fd.op_heritage();
            let p1 = fd.heritage.pass;
            let md1 = fd.heritage.maxdepth;
            fd.op_heritage();
            fd.op_heritage();
            let _ = tx.send((p1, md1));
            (fd.heritage.pass, fd.heritage.maxdepth)
        });

        let (p1, md1) = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("first op_heritage pass did not complete (deadlock regression)");
        let (pass, maxdepth) = handle
            .join()
            .expect("three op_heritage passes panicked (60s watchdog)");

        // One pass per boundary call: 0 -> 1 -> 2 -> 3.
        assert_eq!(p1, 1);
        assert_eq!(pass, 3);
        // Four-block dominator chain b0 > b1 > b2 > b3 has Ghidra depths
        // 1/2/3/4 (block.cc:2056 root depth 1), built exactly once (the
        // maxdepth == -1 rebuild fired on pass 1 only).
        assert_eq!(md1, 4);
        assert_eq!(maxdepth, 4);
    }

    // HERITAGE-OWNERSHIP-0001: explicit record of the behavioral difference
    // between the old production recipe (two direct place/rename passes with
    // an embedded ActionDeadCode sandwich and stack-store discovery between
    // them — src/coreaction.rs ActionHeritage::apply pre-refactor) and the
    // new canonical single-pass boundary. Ghidra runs ActionDeadCode as a
    // later sibling Action decided by the executor (coreaction.cc:5487-5504),
    // never inside Heritage; the new boundary therefore leaves an unread
    // (dead) write in place while the old recipe removes it. This test pins
    // that difference so the production switch (HERITAGE-DRIVER-SWITCH) must
    // account for DeadCode scheduling explicitly.
    #[test]
    fn test_op_heritage_leaves_deadcode_to_the_action_executor() {
        fn build(base: u64) -> Funcdata {
            let mut g = OwnershipGraph::new("deadcode_split", base);
            let b0 = g.block(0);
            let b1 = g.block(1);
            g.fd.bblocks.add_edge(b0.clone(), b1.clone());
            let c4 = g.constant(4, 7);

            // d1: writes register 0x30 from a free read (heritage work).
            let free = g.free_register(0x30, 8);
            let d1 = g.op(OpCode::CPUI_INT_ADD, 2);
            g.set_input(&d1, &free, 0);
            g.set_input(&d1, &c4, 1);
            let _d1out = g.written_register(0x30, 8, &d1);
            g.insert_end(&d1, &b0);

            // r1: reads the same free varnode in the successor block.
            let r1 = g.op(OpCode::CPUI_INT_OR, 2);
            g.set_input(&r1, &free, 0);
            g.set_input(&r1, &c4, 1);
            let _t3 = g.fd.new_unique_out(8, &r1);
            g.insert_end(&r1, &b1);

            // dead: an unread unique write that only a DeadCode action
            // removes.
            let dead = g.op(OpCode::CPUI_INT_MULT, 2);
            g.set_input(&dead, &c4, 0);
            g.set_input(&dead, &c4, 1);
            let _dead_out = g.fd.new_unique_out(8, &dead);
            g.insert_end(&dead, &b0);

            g.fd
        }

        let count_alive = |fd: &Funcdata| fd.obank.alivelist.len();

        // Old recipe: direct place/rename + embedded DeadCode + discovery +
        // a second direct pass (ActionHeritage::apply pre-refactor shape).
        let mut old_fd = build(0x6100);
        {
            let mut heritage = std::mem::take(&mut old_fd.heritage);
            heritage.place_multiequals_direct(
                &mut old_fd.vbank,
                &mut old_fd.obank,
                &old_fd.bblocks,
                &old_fd.sblocks,
            );
            heritage.rename_direct(&mut old_fd.vbank, &old_fd.bblocks);
            heritage.pass += 1;
            old_fd.heritage = heritage;
        }
        {
            use crate::action::Action;
            let mut dc = crate::coreaction::ActionDeadCode::new();
            let _ = dc.apply(&mut old_fd);
        }
        crate::heritage::Heritage::discover_and_guard_stack_stores_fd(&mut old_fd);
        {
            let mut heritage = std::mem::take(&mut old_fd.heritage);
            heritage.place_multiequals_direct(
                &mut old_fd.vbank,
                &mut old_fd.obank,
                &old_fd.bblocks,
                &old_fd.sblocks,
            );
            heritage.rename_direct(&mut old_fd.vbank, &old_fd.bblocks);
            heritage.pass += 1;
            old_fd.heritage = heritage;
        }

        // New boundary: three canonical single passes, no embedded DeadCode.
        let mut new_fd = build(0x6200);
        new_fd.op_heritage();
        new_fd.op_heritage();
        new_fd.op_heritage();

        // The recorded difference: the old sandwich removes the dead write,
        // the canonical boundary does not (DeadCode belongs to the executor).
        assert!(
            count_alive(&new_fd) > count_alive(&old_fd),
            "expected old embedded-DeadCode recipe to remove more ops than the canonical boundary: old={} new={}",
            count_alive(&old_fd),
            count_alive(&new_fd)
        );
        assert_eq!(new_fd.heritage.pass, 3);
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
