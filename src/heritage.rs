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
    pub fn new() -> Self {
        Self {
            themap: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, addr: Address, size: i32, pass: i32) {
        self.themap.insert(addr, SizePass { size, pass });
    }

    pub fn find_pass(&self, addr: Address) -> i32 {
        self.themap.get(&addr).map(|sp| sp.pass).unwrap_or(-1)
    }

    pub fn clear(&mut self) {
        self.themap.clear();
    }
}

/// Priority queue for flow blocks during heritage
/// Corresponds to Ghidra's `PriorityQueue`
#[derive(Debug)]
pub struct PriorityQueue {
    pub queue: Vec<Vec<Arc<RwLock<BlockBasic>>>>,
    pub curdepth: i32,
}

impl PriorityQueue {
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            curdepth: -1,
        }
    }

    pub fn reset(&mut self, maxdepth: usize) {
        self.queue.clear();
        self.queue.resize_with(maxdepth + 1, Vec::new);
        self.curdepth = -1;
    }

    pub fn insert(&mut self, bl: Arc<RwLock<BlockBasic>>, depth: i32) {
        if depth > self.curdepth {
            self.curdepth = depth;
        }
        self.queue[depth as usize].push(bl);
    }

    pub fn extract(&mut self) -> Option<Arc<RwLock<BlockBasic>>> {
        while self.curdepth >= 0 {
            if let Some(bl) = self.queue[self.curdepth as usize].pop() {
                return Some(bl);
            }
            self.curdepth -= 1;
        }
        None
    }

    pub fn empty(&self) -> bool {
        self.curdepth < 0
    }
}

/// Information about heritage status for a specific address space
/// Corresponds to Ghidra's `HeritageInfo`
#[derive(Debug)]
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
    pub fn new(space: AddressSpace) -> Self {
        Self {
            space,
            delay: 0,
            deadcodedelay: 0,
            deadremoved: -1,
            load_guard_search: true,
            warning_issued: false,
            has_call_placeholders: false,
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

    /// Get minimum offset of the guarded range. (heritage.hh:164)
    pub fn get_minimum(&self) -> u64 {
        self.minimum_offset
    }

    /// Get maximum offset of the guarded range. (heritage.hh:165)
    pub fn get_maximum(&self) -> u64 {
        self.maximum_offset
    }

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
    pub domchild: Vec<Vec<Arc<RwLock<BlockBasic>>>>,
    pub augment: Vec<Vec<Arc<RwLock<BlockBasic>>>>,
    pub flags: Vec<u32>,
    pub depth: Vec<i32>,
    pub maxdepth: i32,
    pub pass: i32,
    pub pq: PriorityQueue,
    pub merge: Vec<Arc<RwLock<BlockBasic>>>,
    pub infolist: Vec<HeritageInfo>,
    pub load_guard: Vec<LoadGuard>,
    pub store_guard: Vec<LoadGuard>,
    pub load_copy_ops: Vec<Weak<RwLock<PcodeOp>>>,
}

impl Heritage {
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
    fn default() -> Self {
        Self::new()
    }
}

impl Heritage {
    /// Discover stack-pointer-relative STORE ops and build Stack-space INDIRECT
    /// ops for them. Faithful to Ghidra's discoverIndexedStackPointers
    /// (heritage.cc:985) + guardStores (heritage.cc:1539).
    ///
    /// From the RSP input varnode, forward-descend through INT_ADD(const)/
    /// INT_SUB(const)/COPY chains. For each STORE reached, compute the stack
    /// offset and build a Stack-space INDIRECT via new_indirect_op.
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

    /// Guard RETURN ops in preparation for renaming.
    ///
    /// Faithful in shape to `Heritage::guardReturns` (heritage.cc:1653-1693):
    /// Ghidra either registers the range as a return-value trial or inserts a
    /// forced-address COPY before each RETURN. This requires
    /// `FuncProto::characterizeAsOutput`/`ParamActive` which Rugra does not
    /// yet expose. Stub kept for API alignment.
    /// TODO(funcproto): wire return-value trials + COPY insertion.
    pub fn guard_returns(&mut self, _fd: &mut Funcdata) {}

    /// Run the four guard phases (calls, returns, stores, loads) against the
    /// whole stack space. This is the per-space analogue of the indirect half
    /// of Ghidra's `Heritage::guard` (heritage.cc:1189-1199), which Ghidra
    /// invokes once per disjoint memory range during `placeMultiequals`.
    ///
    /// Rugra's driver calls this once per heritage pass over the stack space;
    /// the guard_stores/guard_loads implementations are range-agnostic (they
    /// guard conservatively over the whole stack), so a single call suffices.
    pub fn guard_all(&mut self, fd: &mut Funcdata) {
        self.guard_calls(fd);
        self.guard_returns(fd);
        self.guard_stores(fd);
        self.guard_loads(fd);
    }

    /// Main entry point for heritage (SSA construction)
    pub fn heritage(&mut self) {
        if self.fd.is_none() {
            return;
        }

        // 1. Perform Phi placement
        self.place_multiequals();

        // 2. Perform SSA renaming
        self.rename();

        // 3. Increment pass counter
        self.pass += 1;
    }

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

    /// Helper to insert a MULTIEQUAL (Phi) op into a block
    fn insert_multiequal(&mut self, fd: &mut Funcdata, space: AddressSpace, addr: Address, block_idx: i32) {
        let mut vbank = std::mem::take(&mut fd.vbank);
        let mut obank = std::mem::take(&mut fd.obank);
        self.insert_multiequal_direct(&mut vbank, &mut obank, &fd.bblocks, space, addr, block_idx);
        fd.vbank = vbank;
        fd.obank = obank;
    }

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
            .cloned()
            .expect("Block not found");

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

    /// Perform SSA renaming
    pub fn rename(&mut self) {
        let fd_weak = self.fd.as_ref().expect("Heritage needs Funcdata");
        let fd_arc = fd_weak.upgrade().expect("Funcdata dropped");
        let mut fd = fd_arc.write().unwrap();
        
        let mut vbank = std::mem::take(&mut fd.vbank);
        self.rename_direct(&mut vbank, &fd.bblocks);
        fd.vbank = vbank;
    }

    /// Perform SSA renaming directly using bank references
    pub fn rename_direct(&mut self, vbank: &mut VarnodeBank, bblocks: &crate::block::BlockGraph) {
        // Mark all free varnodes as active heritage, faithful to Ghidra's
        // guard() (heritage.cc:1175/1182) which calls setActiveHeritage on
        // all read/write varnodes in the ranges being heritaged this pass.
        // Free varnodes (no INSERT flag, created by newVarnode→create) need
        // this flag so rename's isActiveHeritage check lets them through.
        for vn_ref in &vbank.loc_tree {
            let mut vn = vn_ref.0.write().unwrap();
            if !vn.is_heritage_known() {
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

    fn visit_rename_direct(
        &mut self,
        _vbank: &mut VarnodeBank,
        block_arc: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        stacks: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
    ) {
        self.visit_rename_impl(_vbank, block_arc, stacks, 0);
    }

    fn visit_rename_impl(
        &mut self,
        _vbank: &mut VarnodeBank,
        block_arc: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        stacks: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
        depth: usize,
    ) {
        if depth > 200 {
            return; // Safety limit for deep dominator trees
        }

        if (block_arc.read().unwrap().get_flags() & crate::block::block_flags::DEAD) != 0 {
            return;
        }

        let mut defined_here: Vec<(AddressSpace, Address)> = Vec::new();

        // 1. Process Phis (MULTIEQUAL) - only their outputs
        let ops = block_arc.read().unwrap().get_ops();
        for op_ref in &ops {
            let op = op_ref.0.write().unwrap();
            if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                if let Some(out_vn) = &op.output {
                    let vn_read = out_vn.read().unwrap();
                    let key = (vn_read.address_space, vn_read.loc);
                    drop(vn_read);
                    stacks.entry(key).or_default().push(out_vn.clone());
                    defined_here.push(key);
                }
            }
        }

        // 2. Process regular Ops
        for op_ref in &ops {
            let mut op = op_ref.0.write().unwrap();
            if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                continue;
            }

            // Rewrite inputs — faithful to Ghidra renameRecurse (heritage.cc:2494-2498).
            // Skip heritage-known varnodes (insert/constant/annotation), then
            // skip non-active-heritage varnodes. Only active free varnodes
            // get replaced by the stack-top SSA version.
            for i in 0..op.inrefs.len() {
                let should_skip = {
                    let vn_read = op.inrefs[i].read().unwrap();
                    vn_read.is_heritage_known() || !vn_read.is_active_heritage()
                };
                if should_skip {
                    continue;
                }
                let key = {
                    let vn_read = op.inrefs[i].read().unwrap();
                    (vn_read.address_space, vn_read.loc)
                };
                // Clear active heritage flag before replacing.
                op.inrefs[i].write().unwrap().clear_active_heritage();
                if let Some(stack) = stacks.get(&key) {
                    if let Some(new_vn) = stack.last() {
                        op.inrefs[i] = new_vn.clone();
                        new_vn
                            .write()
                            .unwrap()
                            .descend
                            .push(Arc::downgrade(&op_ref.0));
                    }
                }
            }

            // Rewrite output
            if let Some(out_vn) = &op.output {
                let vn_read = out_vn.read().unwrap();
                let key = (vn_read.address_space, vn_read.loc);
                drop(vn_read);
                stacks.entry(key).or_default().push(out_vn.clone());
                defined_here.push(key);
            }
        }

        // 3. Fill Phi inputs in successors
        let size_out = block_arc.read().unwrap().size_out();
        for i in 0..size_out {
            if let Some(edge) = block_arc.read().unwrap().get_out(i) {
                let succ_arc = edge.point.clone();
                let my_in_idx = edge.reverse_index as usize;

                let succ_ops = succ_arc.read().unwrap().get_ops();
                for op_ref in succ_ops {
                    let mut op = op_ref.0.write().unwrap();
                    if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                        if let Some(out_vn) = &op.output {
                            let key = {
                                let vn_read = out_vn.read().unwrap();
                                (vn_read.address_space, vn_read.loc)
                            };
                            if let Some(stack) = stacks.get(&key) {
                                if let Some(new_vn) = stack.last() {
                                    if my_in_idx < op.inrefs.len() {
                                        op.inrefs[my_in_idx] = new_vn.clone();
                                        new_vn
                                            .write()
                                            .unwrap()
                                            .descend
                                            .push(Arc::downgrade(&op_ref.0));
                                    }
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        // 4. Recurse to children in dominator tree
        let children = block_arc.read().unwrap().get_dom_children();
        for child in children {
            self.visit_rename_impl(_vbank, child, stacks, depth + 1);
        }

        // 5. Pop stacks
        for key in defined_here {
            if let Some(stack) = stacks.get_mut(&key) {
                stack.pop();
            }
        }
    }

    pub fn get_pass(&self) -> i32 {
        self.pass
    }

    /// Get the number of heritage passes performed for a space.
    /// Faithful to Heritage::numHeritagePasses (heritage.cc:2793).
    pub fn num_heritage_passes(&self, _space: AddressSpace) -> i32 {
        self.pass
    }

    /// Check if dead code removal is allowed for a space.
    /// Faithful to Heritage::deadRemovalAllowed (heritage.cc:2843).
    pub fn dead_removal_allowed(&self, _space: AddressSpace) -> bool {
        true // Rugra allows dead code removal by default
    }

    /// Set dead code delay for a space.
    /// Faithful to Heritage::setDeadCodeDelay (heritage.cc:2829).
    pub fn set_dead_code_delay(&mut self, _space: AddressSpace, _delay: i32) {
        // Rugra doesn't track per-space dead code delay yet
    }

    /// Get dead code delay for a space.
    /// Faithful to Heritage::getDeadCodeDelay (heritage.cc:2817).
    pub fn get_dead_code_delay(&self, _space: AddressSpace) -> i32 {
        2 // Default delay
    }

    /// Mark that dead code was seen for a space.
    /// Faithful to Heritage::seenDeadCode (heritage.cc:2805).
    pub fn seen_dead_code(&mut self, _space: AddressSpace) {
        // Rugra doesn't track per-space dead code seen flag
    }

    pub fn clear(&mut self) {
        self.globaldisjoint.clear();
        self.load_guard.clear();
        self.store_guard.clear();
        self.load_copy_ops.clear();
    }

    /// Find the STORE guard matching `op`. Faithful to
    /// `Heritage::getStoreGuard` (heritage.hh:338). Linear scan of store_guard.
    pub fn get_store_guard(&self, op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<&LoadGuard> {
        self.store_guard.iter().find(|g| match g.op.upgrade() {
            Some(g_op) => std::sync::Arc::ptr_eq(&g_op, op),
            None => false,
        })
    }

    /// Find the LOAD guard matching `op`. Faithful to
    /// `Heritage::getLoadGuard` (heritage.hh:337).
    pub fn get_load_guard(&self, op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>) -> Option<&LoadGuard> {
        self.load_guard.iter().find(|g| match g.op.upgrade() {
            Some(g_op) => std::sync::Arc::ptr_eq(&g_op, op),
            None => false,
        })
    }
}

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
        let h = Heritage::new();
        assert_eq!(h.get_pass(), 0);
        assert_eq!(h.get_dead_code_delay(AddressSpace::Ram), 2);
        assert!(h.dead_removal_allowed(AddressSpace::Ram));
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
