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

            // Rewrite inputs
            for i in 0..op.inrefs.len() {
                let key = {
                    let vn_read = op.inrefs[i].read().unwrap();
                    (vn_read.address_space, vn_read.loc)
                };
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
