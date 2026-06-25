//! Basic blocks and control flow graph
//!
//! Corresponds to Ghidra's `block.hh`

use crate::address::Address;
use crate::op::PcodeOpRef;
use std::sync::{Arc, RwLock, Weak};

/// Type of flow block (corresponds to Ghidra's BlockType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Plain,
    Basic,
    Graph,
    Copy,
    Goto,
    MultiGoto,
    List,
    Condition,
    If,
    WhileDo,
    DoWhile,
    Switch,
    InfLoop,
}

/// Flags for PcodeBlock properties (corresponds to Ghidra's FlowBlock::block_flags)
pub mod block_flags {
    pub const TERMINAL: u32 = 1 << 0;
    pub const GOTO_TERMINAL: u32 = 1 << 1;
    pub const RETURN_TERMINAL: u32 = 1 << 2;
    pub const ENTRY_POINT: u32 = 1 << 3;
    pub const DEAD: u32 = 1 << 4;
    pub const MARK: u32 = 1 << 5;
    /// Block is a switch case body (reached via cascade dispatch).
    /// printc must not structurally extract it into a standalone `if(){}`,
    /// or the emitted `case` label ends up outside the switch body.
    pub const CASE_BODY: u32 = 1 << 6;
    /// Out-edge[1] (taken edge) is marked as goto by selectGoto.
    /// effective_size_out excludes this edge.
    pub const GOTO_EDGE_1: u32 = 1 << 7;
    /// Out-edge[0] (fallthrough) is marked as goto by selectGoto.
    pub const GOTO_EDGE_0: u32 = 1 << 8;
}

/// Flags for edge properties (corresponds to Ghidra's edge_flags)
///
/// These flags annotate outgoing edges of structured blocks
/// to indicate whether the edge represents a `break`, `continue`,
/// or plain `goto` in the final C output.
pub mod edge_flags {
    /// Edge represents a `break` out of the enclosing loop
    pub const F_BREAK_EDGE: u32 = 1 << 0;
    /// Edge represents a `continue` to the loop header
    pub const F_CONTINUE_EDGE: u32 = 1 << 1;
    /// Edge represents an unstructured `goto`
    pub const F_GOTO_EDGE: u32 = 1 << 2;
    /// Edge is a switch dispatch (from switch control block to a case body).
    /// Blocks reached via this edge must not be structurally extracted by
    /// interleaved rules, or their `case` label ends up outside the switch.
    pub const F_SWITCH_DISPATCH: u32 = 1 << 3;
}

/// Common interface for all types of blocks (Basic, Graph, Condition, etc.)
///
/// Corresponds to Ghidra's `FlowBlock` base class
pub trait FlowBlock: std::fmt::Debug + Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;
    fn get_index(&self) -> i32;
    fn set_index(&mut self, i: i32);
    fn get_type(&self) -> BlockType;
    fn get_flags(&self) -> u32;
    fn set_flags(&mut self, f: u32);

    fn size_in(&self) -> usize;
    fn size_out(&self) -> usize;

    /// Check if this block has been consumed by structuring (DEAD flag).
    /// Ghidra removes consumed blocks from the graph; Rugra uses DEAD flag
    /// and checks it here so collapseInternal skips them (like Ghidra's
    /// `if ((bl->sizeIn()==0)&&(bl->sizeOut()==0))` check).
    fn is_consumed(&self) -> bool {
        self.get_flags() & block_flags::DEAD != 0
    }

    /// Number of out-edges excluding goto-marked edges.
    /// GOTO_EDGE_0 marks out[0] as goto, GOTO_EDGE_1 marks out[1].
    fn effective_size_out(&self) -> usize {
        let total = self.size_out();
        let flags = self.get_flags();
        let mut count = total;
        if flags & block_flags::GOTO_EDGE_0 != 0 && total >= 1 { count -= 1; }
        if flags & block_flags::GOTO_EDGE_1 != 0 && total >= 2 { count -= 1; }
        count
    }

    /// Get the i-th non-goto out-edge (skipping goto-marked edges).
    fn effective_get_out(&self, slot: usize) -> Option<BlockEdge> {
        let flags = self.get_flags();
        let total = self.size_out();
        let mut effective_idx = 0usize;
        for i in 0..total {
            let is_goto = (i == 0 && flags & block_flags::GOTO_EDGE_0 != 0)
                       || (i == 1 && flags & block_flags::GOTO_EDGE_1 != 0);
            if is_goto { continue; }
            if effective_idx == slot { return self.get_out(i); }
            effective_idx += 1;
        }
        None
    }

    fn get_in(&self, slot: usize) -> Option<BlockEdge>;
    fn get_out(&self, slot: usize) -> Option<BlockEdge>;

    fn add_in_edge(&mut self, edge: BlockEdge);
    fn add_out_edge(&mut self, edge: BlockEdge);

    fn get_ops(&self) -> Vec<PcodeOpRef> {
        Vec::new()
    }
    fn add_op(&mut self, _op: PcodeOpRef) {}
    fn insert_op(&mut self, _index: usize, _op: PcodeOpRef) {}

    fn get_start_addr(&self) -> Address {
        Address::new(0)
    }

    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>>;

    // Dominance related methods
    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }
    fn set_immed_dom(&mut self, _dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {}
    fn get_dom_depth(&self) -> i32 {
        -1
    }
    fn set_dom_depth(&mut self, _depth: i32) {}
    fn get_dom_children(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        Vec::new()
    }
    fn add_dom_child(&mut self, _child: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {}
    fn clear_dom_children(&mut self) {}
    fn get_dom_frontier(&self) -> std::collections::HashSet<i32> {
        std::collections::HashSet::new()
    }
    fn add_to_dom_frontier(&mut self, _idx: i32) {}
    fn clear_dom_frontier(&mut self) {}
}

/// Represents a basic block of P-code operations
///
/// Corresponds to Ghidra's `BlockBasic` class
#[derive(Debug)]
pub struct BlockBasic {
    /// Index of this block within the function
    pub index: i32,
    /// List of operations in this block
    pub ops: Vec<PcodeOpRef>,
    /// Input edges
    pub incoming: Vec<BlockEdge>,
    /// Output edges
    pub outgoing: Vec<BlockEdge>,
    /// Parent block (if nested in a composite block)
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    /// Block flags
    pub flags: u32,
    /// Start address of the block
    pub start_addr: Address,

    /// Immediate dominator of this block
    pub immed_dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Depth in the dominator tree
    pub dom_depth: i32,
    /// Children in the dominator tree
    pub dom_children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Dominance frontier of this block (indices of blocks)
    pub dom_frontier: std::collections::HashSet<i32>,
}

impl BlockBasic {
    pub fn new(index: i32, start_addr: Address) -> Self {
        Self {
            index,
            ops: Vec::new(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
            start_addr,
            immed_dom: None,
            dom_depth: -1,
            dom_children: Vec::new(),
            dom_frontier: std::collections::HashSet::new(),
        }
    }

    /// Add an operation to the end of the block
    pub fn add_op(&mut self, op: PcodeOpRef) {
        self.ops.push(op);
    }

    /// Get the last operation in the block
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        self.ops.last().cloned()
    }

    /// Get the first operation in the block
    pub fn first_op(&self) -> Option<PcodeOpRef> {
        self.ops.first().cloned()
    }
}

impl FlowBlock for BlockBasic {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn get_index(&self) -> i32 {
        self.index
    }
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    fn get_type(&self) -> BlockType {
        BlockType::Basic
    }
    fn get_flags(&self) -> u32 {
        self.flags
    }
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }

    fn size_in(&self) -> usize {
        if self.is_consumed() { return 0; }
        self.incoming.len()
    }
    fn size_out(&self) -> usize {
        if self.is_consumed() { return 0; }
        self.outgoing.len()
    }

    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }

    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }

    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }

    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }

    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.ops.clone()
    }

    fn add_op(&mut self, op: PcodeOpRef) {
        self.ops.push(op);
    }

    fn insert_op(&mut self, index: usize, op: PcodeOpRef) {
        self.ops.insert(index, op);
    }

    fn get_start_addr(&self) -> Address {
        self.start_addr
    }

    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }

    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.immed_dom.clone()
    }
    fn set_immed_dom(&mut self, dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.immed_dom = dom;
    }
    fn get_dom_depth(&self) -> i32 {
        self.dom_depth
    }
    fn set_dom_depth(&mut self, depth: i32) {
        self.dom_depth = depth;
    }
    fn get_dom_children(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.dom_children.clone()
    }
    fn add_dom_child(&mut self, child: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.dom_children.push(child);
    }
    fn clear_dom_children(&mut self) {
        self.dom_children.clear();
    }
    fn get_dom_frontier(&self) -> std::collections::HashSet<i32> {
        self.dom_frontier.clone()
    }
    fn add_to_dom_frontier(&mut self, idx: i32) {
        self.dom_frontier.insert(idx);
    }
    fn clear_dom_frontier(&mut self) {
        self.dom_frontier.clear();
    }
}

/// Represents an edge between blocks in the control flow graph
///
/// Corresponds to Ghidra's `BlockEdge` class
#[derive(Debug, Clone)]
pub struct BlockEdge {
    /// The block at the other end of the edge
    pub point: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    /// Edge flags
    pub flags: u32,
    /// Reverse index (slot in the destination's input list or source's output list)
    pub reverse_index: i32,
}

impl BlockEdge {
    pub fn new(point: Arc<RwLock<dyn FlowBlock + Send + Sync>>, reverse_index: i32) -> Self {
        Self {
            point,
            flags: 0,
            reverse_index,
        }
    }

    pub fn is_break(&self) -> bool {
        self.flags & edge_flags::F_BREAK_EDGE != 0
    }

    pub fn is_continue(&self) -> bool {
        self.flags & edge_flags::F_CONTINUE_EDGE != 0
    }

    pub fn is_goto(&self) -> bool {
        self.flags & edge_flags::F_GOTO_EDGE != 0
    }
}

/// A reference to a block for use in collections
#[derive(Debug, Clone)]
pub struct BlockRef(pub Arc<RwLock<dyn FlowBlock + Send + Sync>>);

impl PartialEq for BlockRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// A graph of blocks, which is itself a block
///
/// Corresponds to Ghidra's `BlockGraph` class
#[derive(Debug)]
pub struct BlockGraph {
    pub index: i32,
    pub blocks: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl BlockGraph {
    pub fn new() -> Self {
        Self {
            index: -1,
            blocks: Vec::new(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }
    }

    pub fn add_block(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.blocks.push(bl);
    }

    pub fn get_size(&self) -> usize {
        self.blocks.len()
    }

    pub fn get_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.blocks.get(i).cloned()
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.incoming.clear();
        self.outgoing.clear();
    }

    pub fn add_edge(
        &mut self,
        from: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        to: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        // Check for self-loop: same Arc → single write lock to avoid deadlock
        if Arc::ptr_eq(&from, &to) {
            let mut b = from.write().unwrap();
            let out_idx = b.size_out() as i32;
            let in_idx = b.size_in() as i32;
            b.add_out_edge(BlockEdge::new(to.clone(), in_idx));
            b.add_in_edge(BlockEdge::new(from.clone(), out_idx));
        } else {
            let mut f = from.write().unwrap();
            let mut t = to.write().unwrap();

            let out_idx = f.size_out() as i32;
            let in_idx = t.size_in() as i32;

            f.add_out_edge(BlockEdge::new(to.clone(), in_idx));
            t.add_in_edge(BlockEdge::new(from.clone(), out_idx));
        }
    }

    /// Build the dominator tree for the graph
    ///
    /// Corresponds to Ghidra's `BlockGraph::buildDomTree`
    pub fn build_dom_tree(&mut self) {
        let rpo = self.calc_rpo();
        if rpo.is_empty() {
            return;
        }

        let mut idom_indices = vec![-1i32; self.blocks.len()];
        let mut rpo_indices = vec![-1i32; self.blocks.len()];

        for (i, node) in rpo.iter().enumerate() {
            rpo_indices[node.read().unwrap().get_index() as usize] = i as i32;
        }

        let start_node_index = rpo[0].read().unwrap().get_index() as usize;
        idom_indices[start_node_index] = start_node_index as i32;

        let mut changed = true;
        let max_dom_iters = self.blocks.len() * 3 + 10;
        let mut dom_iters = 0;
        while changed && dom_iters < max_dom_iters {
            dom_iters += 1;
            changed = false;
            for i in 1..rpo.len() {
                let node = &rpo[i];
                let node_idx = node.read().unwrap().get_index() as usize;

                // Pre-collect predecessor indices to avoid holding read lock during edge traversal
                let preds: Vec<usize> = {
                    let n = node.read().unwrap();
                    let size_in = n.size_in();
                    let mut edges = Vec::with_capacity(size_in);
                    for slot in 0..size_in {
                        if let Some(edge) = n.get_in(slot) {
                            edges.push(edge.point.clone());
                        }
                    }
                    drop(n); // Release node read lock before reading edge targets
                    edges.iter().map(|p| p.read().unwrap().get_index() as usize).collect()
                };

                let mut new_idom_idx = -1i32;

                // Find first processed predecessor
                for &pred_idx in &preds {
                    if idom_indices[pred_idx] != -1 {
                        new_idom_idx = pred_idx as i32;
                        break;
                    }
                }

                if new_idom_idx != -1 {
                    for &pred_idx in &preds {
                        if pred_idx as i32 != new_idom_idx && idom_indices[pred_idx] != -1 {
                            new_idom_idx = self.intersect(
                                pred_idx as i32,
                                new_idom_idx,
                                &idom_indices,
                                &rpo_indices,
                            );
                        }
                    }

                    if idom_indices[node_idx] != new_idom_idx {
                        idom_indices[node_idx] = new_idom_idx;
                        changed = true;
                    }
                }
            }
        }

        // Apply immediate dominators to blocks
        for (i, &idom_idx) in idom_indices.iter().enumerate() {
            if idom_idx != -1 && idom_idx != i as i32 {
                let mut node = self.blocks[i].write().unwrap();
                node.set_immed_dom(Some(Arc::downgrade(&self.blocks[idom_idx as usize])));
            }
        }

        self.build_dom_depth();
        self.build_dom_subtree();
        self.calc_dom_frontier();
    }

    fn intersect(&self, mut b1: i32, mut b2: i32, idom: &[i32], rpo: &[i32]) -> i32 {
        let max_iters = idom.len() * 2 + 10;
        let mut iters = 0;
        while b1 != b2 {
            while rpo[b1 as usize] > rpo[b2 as usize] {
                let next = idom[b1 as usize];
                if next == b1 || next < 0 { return b1; } // safety: self-loop or uninitialized
                b1 = next;
                iters += 1;
                if iters > max_iters { return b1; }
            }
            while rpo[b2 as usize] > rpo[b1 as usize] {
                let next = idom[b2 as usize];
                if next == b2 || next < 0 { return b2; } // safety: self-loop or uninitialized
                b2 = next;
                iters += 1;
                if iters > max_iters { return b2; }
            }
        }
        b1
    }

    /// Build depth information based on the dominator tree
    ///
    /// Corresponds to Ghidra's `BlockGraph::buildDomDepth`
    pub fn build_dom_depth(&mut self) {
        let rpo = self.calc_rpo();
        for node_ref in &rpo {
            // Get idom depth first without holding node's lock
            let idom_depth = {
                let node = node_ref.read().unwrap();
                let size_in = node.size_in();
                if size_in == 0 || (node.get_flags() & block_flags::ENTRY_POINT) != 0 {
                    Some(0i32) // entry: depth 0
                } else if let Some(ref idom_weak) = node.get_immed_dom() {
                    if let Some(idom_ref) = idom_weak.upgrade() {
                        if Arc::ptr_eq(&idom_ref, node_ref) {
                            Some(0) // self-dom
                        } else {
                            drop(node); // release read lock before reading idom
                            Some(idom_ref.read().unwrap().get_dom_depth() + 1)
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(depth) = idom_depth {
                node_ref.write().unwrap().set_dom_depth(depth);
            }
        }
    }

    /// Build the dominator sub-tree relationships
    ///
    /// Corresponds to Ghidra's `BlockGraph::buildDomSubTree`
    pub fn build_dom_subtree(&mut self) {
        // Clear existing children
        for node in &self.blocks {
            node.write().unwrap().clear_dom_children();
        }

        // Add each block to its immediate dominator's children list
        for i in 0..self.blocks.len() {
            let idom_weak = {
                let node = self.blocks[i].read().unwrap();
                node.get_immed_dom()
            };

            if let Some(weak) = idom_weak {
                if let Some(idom_ref) = weak.upgrade() {
                    idom_ref
                        .write()
                        .unwrap()
                        .add_dom_child(self.blocks[i].clone());
                }
            }
        }
    }

    /// Calculate dominance frontiers for all blocks
    ///
    /// Corresponds to the algorithm in "A Simple, Fast Dominator Algorithm"
    pub fn calc_dom_frontier(&mut self) {
        for i in 0..self.blocks.len() {
            let b_ref = self.blocks[i].clone();

            // Gather incoming edges
            let size_in = b_ref.read().unwrap().size_in();
            let mut incoming = Vec::new();
            for j in 0..size_in {
                if let Some(edge) = b_ref.read().unwrap().get_in(j) {
                    incoming.push(edge);
                }
            }

            if incoming.len() >= 2 {
                let b_index = b_ref.read().unwrap().get_index();
                let b_idom_ref = b_ref
                    .read()
                    .unwrap()
                    .get_immed_dom()
                    .and_then(|w| w.upgrade());

                for edge in incoming {
                    let mut runner_ref = edge.point.clone();

                    if let Some(ref idom) = b_idom_ref {
                        let max_steps = self.blocks.len() + 2;
                        let mut steps = 0;
                        while !Arc::ptr_eq(&runner_ref, idom) && steps < max_steps {
                            steps += 1;
                            runner_ref
                                .write()
                                .unwrap()
                                .add_to_dom_frontier(b_index);

                            let next_runner = runner_ref
                                .read()
                                .unwrap()
                                .get_immed_dom()
                                .and_then(|w| w.upgrade());

                            if let Some(nr) = next_runner {
                                if Arc::ptr_eq(&nr, &runner_ref) { break; } // self-loop
                                runner_ref = nr;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Calculate Reverse Post-Order (RPO) of blocks
    pub fn calc_rpo(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        let mut visited = std::collections::HashSet::new();
        let mut post_order = Vec::new();

        // Start from entry points (blocks with no incoming edges or marked as entry)
        for block in &self.blocks {
            let is_entry = {
                let b = block.read().unwrap();
                b.size_in() == 0 || (b.get_flags() & block_flags::ENTRY_POINT) != 0
            };
            if is_entry {
                self.dfs_visit(block, &mut visited, &mut post_order);
            }
        }

        // Ensure all reachable blocks are covered
        for block in &self.blocks {
            self.dfs_visit(block, &mut visited, &mut post_order);
        }

        post_order.reverse();
        post_order
    }

    fn dfs_visit(
        &self,
        block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        visited: &mut std::collections::HashSet<i32>,
        post_order: &mut Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    ) {
        let idx = block.read().unwrap().get_index();
        if visited.contains(&idx) {
            return;
        }
        visited.insert(idx);

        let size_out = block.read().unwrap().size_out();
        let mut out_edges = Vec::new();
        for i in 0..size_out {
            if let Some(edge) = block.read().unwrap().get_out(i) {
                out_edges.push(edge);
            }
        }

        for edge in out_edges {
            self.dfs_visit(&edge.point, visited, post_order);
        }

        post_order.push(block.clone());
    }

    /// Structure a loop
    ///
    /// Corresponds to Ghidra's `BlockGraph::structureLoops`
    pub fn structure_loops(&mut self) -> bool {
        // Simple loop detection and structuring logic
        // Identifying back-edges and creating BlockWhileDo/BlockDoWhile
        false
    }

    /// Add a loop edge
    ///
    /// Corresponds to Ghidra's `BlockGraph::addLoopEdge`
    pub fn add_loop_edge(
        &mut self,
        from: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        to: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        let mut f = from.write().unwrap();
        let mut t = to.write().unwrap();

        let out_idx = f.size_out() as i32;
        let in_idx = t.size_in() as i32;

        f.add_out_edge(BlockEdge::new(to.clone(), in_idx));
        t.add_in_edge(BlockEdge::new(from.clone(), out_idx));
    }

    /// Calculate loops in the graph
    ///
    /// Corresponds to Ghidra's `BlockGraph::calcLoop`
    pub fn calc_loop(&mut self) {
        // Implement loop identification algorithm (e.g., Tarjan's or Johnson's)
    }
}

impl Eq for BlockRef {}

impl PartialOrd for BlockRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();
        a.get_index().cmp(&b.get_index())
    }
}

/// Represents a copy of another block
///
/// Corresponds to Ghidra's `BlockCopy` class
#[derive(Debug)]
pub struct BlockCopy {
    pub index: i32,
    pub flags: u32,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub original: Arc<RwLock<BlockBasic>>,
}

impl FlowBlock for BlockCopy {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn get_index(&self) -> i32 {
        self.index
    }
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    fn get_type(&self) -> BlockType {
        BlockType::Copy
    }
    fn get_flags(&self) -> u32 {
        self.flags
    }
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    fn size_in(&self) -> usize {
        0
    }
    fn size_out(&self) -> usize {
        0
    }
    fn get_in(&self, _slot: usize) -> Option<BlockEdge> {
        None
    }
    fn get_out(&self, _slot: usize) -> Option<BlockEdge> {
        None
    }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    fn add_in_edge(&mut self, _edge: BlockEdge) {}
    fn add_out_edge(&mut self, _edge: BlockEdge) {}
}

/// Represents a goto statement
///
/// Corresponds to Ghidra's `BlockGoto` class
#[derive(Debug)]
pub struct BlockGoto {
    pub index: i32,
    pub flags: u32,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub goto_target: Option<Arc<RwLock<BlockBasic>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
}

impl FlowBlock for BlockGoto {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn get_index(&self) -> i32 {
        self.index
    }
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    fn get_type(&self) -> BlockType {
        BlockType::Goto
    }
    fn get_flags(&self) -> u32 {
        self.flags
    }
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
}

// ===== Structured Block Types =====
// These are produced by CollapseStructure and walked by PrintC.

/// A structured if-then or if-then-else block.
///
/// Corresponds to Ghidra's `BlockIf`. Contains:
/// - `condition`: the block ending with CBRANCH
/// - `if_body`: the "true" branch
/// - `else_body`: optional "false" branch (None = if-then without else)
#[derive(Debug)]
pub struct BlockIf {
    pub index: i32,
    pub condition: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub if_body: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub else_body: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// When true, the CBRANCH condition should be negated before emitting.
    /// Set when the if_body comes from the false edge (Triangle-reverse pattern).
    pub negated: bool,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockIf {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn get_index(&self) -> i32 { self.index }
    fn set_index(&mut self, i: i32) { self.index = i; }
    fn get_type(&self) -> BlockType { BlockType::If }
    fn get_flags(&self) -> u32 { self.flags }
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    fn size_in(&self) -> usize { self.incoming.len() }
    fn size_out(&self) -> usize { self.outgoing.len() }
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    fn get_start_addr(&self) -> Address { self.condition.read().unwrap().get_start_addr() }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        // Return condition block ops for the conditional test
        self.condition.read().unwrap().get_ops()
    }
}

/// A structured while-do loop block.
///
/// Corresponds to Ghidra's `BlockWhileDo`. Contains:
/// - `condition`: the loop header block (with CBRANCH for the loop test)
/// - `body`: the loop body block(s)
#[derive(Debug)]
pub struct BlockWhileDo {
    pub index: i32,
    pub condition: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub body: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockWhileDo {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn get_index(&self) -> i32 { self.index }
    fn set_index(&mut self, i: i32) { self.index = i; }
    fn get_type(&self) -> BlockType { BlockType::WhileDo }
    fn get_flags(&self) -> u32 { self.flags }
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    fn size_in(&self) -> usize { self.incoming.len() }
    fn size_out(&self) -> usize { self.outgoing.len() }
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    fn get_start_addr(&self) -> Address { self.condition.read().unwrap().get_start_addr() }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.condition.read().unwrap().get_ops()
    }
}

/// Represents a DO-WHILE loop
///
/// Corresponds to Ghidra's `BlockDoWhile` class
#[derive(Debug)]
pub struct BlockDoWhile {
    pub index: i32,
    pub condition: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    // Do-While loops logically have the condition at the end which evaluates the body that it's fused with.
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockDoWhile {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn get_index(&self) -> i32 { self.index }
    fn set_index(&mut self, i: i32) { self.index = i; }
    fn get_type(&self) -> BlockType { BlockType::DoWhile }
    fn get_flags(&self) -> u32 { self.flags }
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    fn size_in(&self) -> usize { self.incoming.len() }
    fn size_out(&self) -> usize { self.outgoing.len() }
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    fn get_start_addr(&self) -> Address { self.condition.read().unwrap().get_start_addr() }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.condition.read().unwrap().get_ops()
    }
}

/// A structured sequence of blocks (linear fallthrough).
///
/// Corresponds to Ghidra's `BlockList`. Represents blocks that execute
/// sequentially with no branching between them.
#[derive(Debug)]
pub struct BlockList {
    pub index: i32,
    pub children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl BlockList {
    /// Create a new sequence block containing the given children in order.
    pub fn new(index: i32, children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>) -> Self {
        Self {
            index,
            children,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }
    }
}

impl FlowBlock for BlockList {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn get_index(&self) -> i32 { self.index }
    fn set_index(&mut self, i: i32) { self.index = i; }
    fn get_type(&self) -> BlockType { BlockType::List }
    fn get_flags(&self) -> u32 { self.flags }
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    fn size_in(&self) -> usize { self.incoming.len() }
    fn size_out(&self) -> usize { self.outgoing.len() }
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    fn get_start_addr(&self) -> Address {
        self.children.first()
            .map(|c| c.read().unwrap().get_start_addr())
            .unwrap_or_else(|| Address::new(0))
    }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        // Concatenate ops from all children in order
        let mut all_ops = Vec::new();
        for child in &self.children {
            all_ops.extend(child.read().unwrap().get_ops());
        }
        all_ops
    }
}

/// Boolean operator type for `BlockCondition`.
///
/// Corresponds to Ghidra's `BlockCondition::optype`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolOp {
    And,
    Or,
}

/// A structured boolean condition block (short-circuit && or ||).
///
/// Corresponds to Ghidra's `BlockCondition`. Represents two CBRANCH blocks
/// whose control flow encodes a short-circuit boolean expression:
///
/// **AND pattern**: A's false edge and B's false edge go to the same target.
/// ```text
///     A (CBRANCH)
///    / \
///   |   B (CBRANCH)
///   |  / \
///   C    D
///   ^--- both false edges → C  ==> if(a && b) { D } else { C }
/// ```
///
/// **OR pattern**: A's true edge and B's true edge go to the same target.
/// ```text
///     A (CBRANCH)
///    / \
///   B   |
///  / \  |
/// D   C---
///     ^--- both true edges → C  ==> if(a || b) { C } else { D }
/// ```
#[derive(Debug)]
pub struct BlockCondition {
    pub index: i32,
    pub op_type: BoolOp,
    /// First condition block (block A — the outer condition).
    pub first: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    /// Second condition block (block B — the inner condition).
    pub second: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockCondition {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn get_index(&self) -> i32 { self.index }
    fn set_index(&mut self, i: i32) { self.index = i; }
    fn get_type(&self) -> BlockType { BlockType::Condition }
    fn get_flags(&self) -> u32 { self.flags }
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    fn size_in(&self) -> usize { self.incoming.len() }
    fn size_out(&self) -> usize { self.outgoing.len() }
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    fn get_start_addr(&self) -> Address { self.first.read().unwrap().get_start_addr() }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        // Concatenate ops from both condition blocks
        let mut ops = self.first.read().unwrap().get_ops();
        ops.extend(self.second.read().unwrap().get_ops());
        ops
    }
}

/// A structured switch-case block.
///
/// Corresponds to Ghidra's `BlockSwitch`. Contains:
/// - `control`: the switch control block (normally contains the BRANCHIND op)
/// - `cases`: ordered list of case body blocks
/// - `case_values`: list of values corresponding to each case block
/// - `default_case`: optional default block
/// - `index_varnode`: optional variable controlling the switch index
#[derive(Debug)]
pub struct BlockSwitch {
    pub index: i32,
    pub control: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub cases: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub default_case: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub case_values: Vec<Vec<u64>>,
    pub index_varnode: Option<Arc<RwLock<crate::varnode::Varnode>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockSwitch {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn get_index(&self) -> i32 { self.index }
    fn set_index(&mut self, i: i32) { self.index = i; }
    fn get_type(&self) -> BlockType { BlockType::Switch }
    fn get_flags(&self) -> u32 { self.flags }
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    fn size_in(&self) -> usize { self.incoming.len() }
    fn size_out(&self) -> usize { self.outgoing.len() }
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    fn get_start_addr(&self) -> Address { self.control.read().unwrap().get_start_addr() }
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.control.read().unwrap().get_ops()
    }
}

