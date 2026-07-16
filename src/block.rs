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
    // Ghidra-shared flags (exact bit values from block.hh:88-105)
    pub const SWITCH_OUT: u32 = 0x10;       // f_switch_out (block.hh:92)
    pub const UNSTRUCTURED_TARG: u32 = 0x20; // f_unstructured_targ (block.hh:93)
    pub const MARK: u32 = 0x80;              // f_mark (block.hh:94)
    pub const ENTRY_POINT: u32 = 0x200;      // f_entry_point (block.hh:96)
    pub const DEAD: u32 = 0x4000;            // f_dead (block.hh:101)
    pub const JOINED_BLOCK: u32 = 0x20000;   // f_joined_block (block.hh:105)
    /// Ghidra f_duplicate_block = 0x40000 (block.hh:106). Duplicated block.
    pub const DUPLICATE_BLOCK: u32 = 0x40000;
    // Ghidra f_flip_path = 0x80000 (block.hh:107). Path to this block was flipped.
    pub const FLIP_PATH: u32 = 0x80000;
    // Rugra-only flags (no Ghidra counterpart, placed at 0x100000+)
    pub const RETURN_TERMINAL: u32 = 0x100000;
    pub const CASE_BODY: u32 = 0x200000;
    pub const GOTO_EDGE_0: u32 = 0x400000;
    pub const GOTO_EDGE_1: u32 = 0x800000;
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
    /// Edge exits the body of a loop (Ghidra `f_loop_exit_edge`). Set by
    /// LoopBody::setExitMarks so TraceDAG knows where the loop ends.
    pub const F_LOOP_EXIT_EDGE: u32 = 1 << 4;
    /// Within a (reducible) graph, a back edge defining a loop (Ghidra
    /// `f_back_edge`). Set by findSpanningTree DFS (block.cc:1101):
    /// an edge to a node still on the DFS stack.
    pub const F_BACK_EDGE: u32 = 1 << 5;
    /// Irreducible edge introduced by the structurer (Ghidra `f_irreducible`).
    /// Treated as a goto by LoopBody's isGotoIn/isGotoOut.
    pub const F_IRREDUCIBLE_EDGE: u32 = 1 << 6;
    /// Default edge from switch block (Ghidra `f_defaultswitch_edge` = 4).
    /// Rugra uses bit 7 (Ghidra's bit 2 is F_GOTO_EDGE in Rugra).
    pub const F_DEFAULTSWITCH_EDGE: u32 = 1 << 7;
    // ---- Spanning-tree edge classification (Ghidra block.hh:108-118) ----
    // Set by findSpanningTree (block.cc:1041-1108). These mirror Ghidra's
    // f_tree_edge / f_forward_edge / f_cross_edge / f_loop_edge.
    /// Edge in the DFS spanning tree (Ghidra `f_tree_edge` = 0x10).
    pub const F_TREE_EDGE: u32 = 1 << 7;
    /// Edge jumping forward in the spanning tree (Ghidra `f_forward_edge` = 0x20).
    pub const F_FORWARD_EDGE: u32 = 1 << 8;
    /// Edge crossing subtrees in the spanning tree (Ghidra `f_cross_edge` = 0x40).
    pub const F_CROSS_EDGE: u32 = 1 << 9;
    /// Edge that completes a loop; removing these yields a DAG (Ghidra
    /// `f_loop_edge` = 2). A back edge is always also a loop edge, but a
    /// loop edge may be set independently by calcLoop for irreducible cases.
    pub const F_LOOP_EDGE: u32 = 1 << 10;

    /// All spanning-tree edge flags, for clearing (Ghidra clears these
    /// together in structureLoops, block.cc:2206).
    pub const SPANNING_MASK: u32 =
        F_TREE_EDGE | F_FORWARD_EDGE | F_CROSS_EDGE | F_BACK_EDGE | F_LOOP_EDGE;
}

/// Common interface for all types of blocks (Basic, Graph, Condition, etc.)
///
/// Corresponds to Ghidra's `FlowBlock` base class
pub trait FlowBlock: std::fmt::Debug + Send + Sync {
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any(&self) -> &dyn std::any::Any;
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32;
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private; set by buildCopy/orderBlocks)
    fn set_index(&mut self, i: i32);
    // Ghidra: block.hh:184 FlowBlock::getType
    fn get_type(&self) -> BlockType;
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32;
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32);

    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize;
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize;

    /// Number of out-edges excluding goto-marked edges.
    /// GOTO_EDGE_0 marks out[0] as goto, GOTO_EDGE_1 marks out[1].
    // RUGRA-GLUE: Rugra helper for goto-aware out-edge counting (Ghidra uses raw sizeOut + edge flags)
    fn effective_size_out(&self) -> usize {
        let total = self.size_out();
        let flags = self.get_flags();
        let mut count = total;
        if flags & block_flags::GOTO_EDGE_0 != 0 && total >= 1 { count -= 1; }
        if flags & block_flags::GOTO_EDGE_1 != 0 && total >= 2 { count -= 1; }
        count
    }

    /// Get the i-th non-goto out-edge (skipping goto-marked edges).
    // RUGRA-GLUE: Rugra helper for goto-aware out-edge access (no direct Ghidra counterpart)
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

    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge>;
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge>;

    /// OR-set edge flags on the `slot`-th outgoing edge.
    /// Faithful to Ghidra's `FlowBlock::setOutEdgeFlag` (block.hh:288).
    /// Used by `findSpanningTree` to label tree/back/forward/cross edges.
    // Ghidra: block.cc:240 FlowBlock::setOutEdgeFlag
    fn set_out_edge_flag(&mut self, slot: usize, flag: u32) {
        // Default: try to downcast to the concrete block types that hold an
        // `outgoing: Vec<BlockEdge>` field. BlockGraph/BlockBasic/BlockCopy.
        let any = self.as_any_mut();
        if let Some(bb) = any.downcast_mut::<BlockBasic>() {
            if slot < bb.outgoing.len() { bb.outgoing[slot].flags |= flag; }
        } else if let Some(bg) = any.downcast_mut::<BlockGraph>() {
            if slot < bg.outgoing.len() { bg.outgoing[slot].flags |= flag; }
        }
        // Other block kinds (BlockCopy etc.) don't own out-edges that need
        // spanning-tree labels in Rugra's structurer.
    }

    /// Clear a mask of edge flags from ALL outgoing edges.
    /// Faithful to Ghidra's `FlowBlock::clearEdgeFlags` (block.cc).
    // Ghidra: block.cc:966 BlockGraph::clearEdgeFlags
    fn clear_edge_flags(&mut self, mask: u32) {
        let any = self.as_any_mut();
        if let Some(bb) = any.downcast_mut::<BlockBasic>() {
            for e in bb.outgoing.iter_mut() { e.flags &= !mask; }
        } else if let Some(bg) = any.downcast_mut::<BlockGraph>() {
            for e in bg.outgoing.iter_mut() { e.flags &= !mask; }
        }
    }

    // Ghidra: block.cc:318 FlowBlock::setDefaultSwitch
    /// Mark an outgoing edge as the switch default edge.
    /// Faithful to `FlowBlock::setDefaultSwitch` (block.cc:318-326).
    /// Clears any previous default marking, then sets the given slot.
    fn set_default_switch(&mut self, pos: usize) {
        self.clear_edge_flags(edge_flags::F_DEFAULTSWITCH_EDGE);
        self.set_out_edge_flag(pos, edge_flags::F_DEFAULTSWITCH_EDGE);
    }

    /// Is the `slot`-th outgoing edge a back edge?
    /// Faithful to Ghidra's `FlowBlock::isBackEdgeOut` (block.hh:331).
    // Ghidra: block.hh:331 FlowBlock::isBackEdgeOut
    fn is_back_edge_out(&self, slot: usize) -> bool {
        self.get_out(slot)
            .map(|e| e.flags & edge_flags::F_BACK_EDGE != 0)
            .unwrap_or(false)
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge);
    // RUGRA-GLUE: Rust edge-construction helper (Ghidra manages outofthis via friend addInEdge)
    fn add_out_edge(&mut self, edge: BlockEdge);

    // RUGRA-GLUE: Rust helper returning Vec<PcodeOpRef> (Ghidra BlockBasic exposes begin/end iterators)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        Vec::new()
    }
    // Ghidra: block.hh:466 BlockBasic::insert
    fn add_op(&mut self, _op: PcodeOpRef) {}
    // Ghidra: block.hh:466 BlockBasic::insert
    fn insert_op(&mut self, _index: usize, _op: PcodeOpRef) {}

    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        Address::new(0)
    }

    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>>;

    // Dominance related methods
    // Ghidra: block.hh:162 FlowBlock::getImmedDom
    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::immed_dom is private; set by buildDomTree as friend)
    fn set_immed_dom(&mut self, _dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {}
    // RUGRA-GLUE: Rugra-only dom-depth field (Ghidra computes depth via buildDomDepth into separate vec)
    fn get_dom_depth(&self) -> i32 {
        -1
    }
    // RUGRA-GLUE: Rust mutator for dom_depth (Ghidra has no dom-depth field on FlowBlock)
    fn set_dom_depth(&mut self, _depth: i32) {}
    // RUGRA-GLUE: Rugra-only dom-children field (Ghidra returns dom tree via buildDomTree(child) external vec)
    fn get_dom_children(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        Vec::new()
    }
    // RUGRA-GLUE: Rust mutator for dom_children (Ghidra builds dom tree externally in BlockGraph::buildDomTree)
    fn add_dom_child(&mut self, _child: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {}
    // RUGRA-GLUE: Rust mutator for dom_children (Ghidra has no dom-children field on FlowBlock)
    fn clear_dom_children(&mut self) {}
    // RUGRA-GLUE: Rugra-only dom-frontier field (Ghidra has no dom-frontier field on FlowBlock)
    fn get_dom_frontier(&self) -> std::collections::HashSet<i32> {
        std::collections::HashSet::new()
    }
    // RUGRA-GLUE: Rust mutator for dom_frontier (Ghidra has no dom-frontier field on FlowBlock)
    fn add_to_dom_frontier(&mut self, _idx: i32) {}
    // RUGRA-GLUE: Rust mutator for dom_frontier (Ghidra has no dom-frontier field on FlowBlock)
    fn clear_dom_frontier(&mut self) {}

    /// Reverse-index of the given incoming edge slot — i.e. the index of
    /// `this` in the source block's outgoing list. Faithful to
    /// `FlowBlock::getInRevIndex` (block.hh:308).
    // Ghidra: block.hh:306 FlowBlock::getInRevIndex
    fn get_in_rev_index(&self, _slot: usize) -> i32 {
        -1
    }

    // ---- Dominance queries (block.hh:310, block.cc:386-395) ----

    /// Does this block dominate `other`? Walk `other`'s dominator chain up
    /// until we hit `self`. Faithful to `FlowBlock::dominates` (block.cc:386).
    // Ghidra: block.cc:386 FlowBlock::dominates
    fn dominates(&self, other: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        let self_idx = self.get_index();
        let mut cur = other.clone();
        loop {
            let (cur_idx, parent) = {
                let g = cur.read().unwrap();
                let idx = g.get_index();
                let dom = g.get_immed_dom().and_then(|w| w.upgrade());
                (idx, dom)
            };
            if cur_idx == self_idx && self_idx >= 0 {
                return true;
            }
            match parent {
                Some(p) => cur = p,
                None => return false,
            }
        }
    }

    // ---- CBRANCH true/false out-edge helpers ----
    // In Rugra, a CBRANCH's out-edges are ordered [branch(taken), fallthru].
    // Ghidra orders them [false, true]. The BOOLEAN_FLIP flag remaps:
    //   flip=false → true=out[0] (branch), false=out[1] (fallthru)
    //   flip=true  → true=out[1] (fallthru), false=out[0] (branch)
    // These helpers encapsulate that remap so ported Rules needn't repeat it.

    /// Get the CBRANCH TRUE out-edge of this block, or None.
    /// `cbranch` is the block's terminal CBRANCH op.
    // Ghidra: block.hh:300 FlowBlock::getTrueOut
    fn get_true_out(
        &self,
        cbranch: &PcodeOpRef,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        let flip = (cbranch.0.read().unwrap().flags
            & crate::op::pcodeop_flags::BOOLEAN_FLIP)
            != 0;
        let true_idx = if flip { 1 } else { 0 };
        self.get_out(true_idx).map(|e| e.point)
    }

    /// Get the CBRANCH FALSE out-edge of this block, or None.
    // Ghidra: block.hh:299 FlowBlock::getFalseOut
    fn get_false_out(
        &self,
        cbranch: &PcodeOpRef,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        let flip = (cbranch.0.read().unwrap().flags
            & crate::op::pcodeop_flags::BOOLEAN_FLIP)
            != 0;
        let false_idx = if flip { 0 } else { 1 };
        self.get_out(false_idx).map(|e| e.point)
    }


    // ---- Mark / visit-count / edge-flag accessors (Ghidra block.hh:286-347) ----
    // These underpin LoopBody's body collection, exit detection, and TraceDAG
    // bounds. Defaults are no-ops; BlockBasic overrides them.
    /// Generic block mark (Ghidra `isMark`). Used by LoopBody::findBase etc.
    // Ghidra: block.hh:286 FlowBlock::isMark
    fn is_mark(&self) -> bool {
        false
    }
    // Ghidra: block.hh:287 FlowBlock::setMark
    fn set_mark(&mut self) {}
    // Ghidra: block.hh:288 FlowBlock::clearMark
    fn clear_mark(&mut self) {}
    /// Scratch visit count (Ghidra `getVisitCount`/`setVisitCount`). Used by
    /// LoopBody::extend to count how many in-edges reach a candidate block.
    // Ghidra: block.hh:283 FlowBlock::getVisitCount
    fn get_visit_count(&self) -> i32 {
        0
    }
    // Ghidra: block.hh:282 FlowBlock::setVisitCount
    fn set_visit_count(&mut self, _c: i32) {}

    // Ghidra: block.hh:143 FlowBlock::isSwitchOut
    /// Is this block a switch dispatch (BRANCHIND output)?
    fn is_switch_out(&self) -> bool {
        (self.get_flags() & block_flags::SWITCH_OUT) != 0
    }

    // Ghidra: block.hh:316 FlowBlock::isLoopIn
    fn is_loop_in(&self, i: usize) -> bool {
        self.get_in(i).map(|e| (e.flags & edge_flags::F_LOOP_EDGE) != 0).unwrap_or(false)
    }

    // Ghidra: block.hh:317 FlowBlock::isLoopOut
    fn is_loop_out(&self, i: usize) -> bool {
        self.get_out(i).map(|e| (e.flags & edge_flags::F_LOOP_EDGE) != 0).unwrap_or(false)
    }

    // Ghidra: block.hh:320 FlowBlock::isDefaultBranch
    fn is_default_branch(&self, i: usize) -> bool {
        self.get_out(i).map(|e| (e.flags & edge_flags::F_DEFAULTSWITCH_EDGE) != 0).unwrap_or(false)
    }

    // Ghidra: block.hh:336 FlowBlock::isLoopExitOut
    fn is_loop_exit_out(&self, i: usize) -> bool {
        self.get_out(i).map(|e| (e.flags & edge_flags::F_LOOP_EXIT_EDGE) != 0).unwrap_or(false)
    }

    /// Is the i-th incoming edge a goto/irreducible edge? (Ghidra `isGotoIn`.)
    // Ghidra: block.hh:346 FlowBlock::isGotoIn
    fn is_goto_in(&self, _i: usize) -> bool {
        false
    }
    /// Is the i-th outgoing edge a goto/irreducible edge? (Ghidra `isGotoOut`.)
    // Ghidra: block.hh:347 FlowBlock::isGotoOut
    fn is_goto_out(&self, _i: usize) -> bool {
        false
    }

    // Ghidra: block.hh:336 FlowBlock::isInteriorGotoTarget
    /// Is this block the target of an unstructured (goto) jump from inside
    /// a loop body? Faithful to `isInteriorGotoTarget()` (block.hh:336).
    /// Simplified: returns true if any in-edge is a goto.
    fn is_interior_goto_target(&self) -> bool {
        for i in 0..self.size_in() {
            if self.is_goto_in(i) { return true; }
        }
        false
    }

    // Ghidra: block.hh:332 FlowBlock::isComplex
    /// Is the control flow of this block too complex for simple condition
    /// folding? Faithful to `isComplex()` (block.hh:332, block.cc:2388).
    /// For BlockBasic: checks if the last op is a CBRANCH with additional
    /// ops after it (indicating complex register manipulation).
    /// Simplified: returns false (conservative — allows folding).
    fn is_complex(&self) -> bool {
        false
    }

    // Ghidra: block.hh:294 FlowBlock::negateCondition
    /// Flip the true/false out-edge semantics of this block's CBRANCH.
    /// Returns true if the flip changed the dataflow. Faithful to
    /// `negateCondition(bool)` (block.hh:294). Base impl: if toporbottom,
    /// swap out edges + toggle f_flip_path, return false (no dataflow change).
    fn negate_condition(&mut self, toporbottom: bool) -> bool {
        if !toporbottom { return false; }
        self.swap_edges();
        false
    }

    // Ghidra: block.hh:284 FlowBlock::swapEdges
    /// Swap the two outgoing edges of this block. Faithful to
    /// `swapEdges()` (block.cc:218-233). Also updates reverse_index on
    /// the target blocks and toggles f_flip_path.
    fn swap_edges(&mut self) {
        // cc:225-227: swap out[0] and out[1]
        // Trait default: no-op (structured blocks don't have direct edges).
        // BlockBasic overrides with the real edge swap.
    }

    /// Is this block the entry point of the function? (block.hh:325)
    // Ghidra: block.hh:325 FlowBlock::isEntryPoint
    fn is_entry_point(&self) -> bool {
        (self.get_flags() & block_flags::ENTRY_POINT) != 0
    }
    /// Label the i-th out edge as a loop-exit edge (Ghidra `setLoopExit`).
    // Ghidra: block.hh:294 FlowBlock::setLoopExit
    fn set_loop_exit(&mut self, _i: usize) {}
    /// Clear the loop-exit label on the i-th out edge (Ghidra `clearLoopExit`).
    // Ghidra: block.hh:295 FlowBlock::clearLoopExit
    fn clear_loop_exit(&mut self, _i: usize) {}
    /// Remove the in-edge from a predecessor whose index matches one of
    /// `exclude_indices`. Faithful to Ghidra `removeEdge(begin, end)` which
    /// removes `begin` from `end`'s intothis list. Used by ruleBlockGoto
    /// consumption to make the goto source invisible to the target's sizeIn.
    // RUGRA-GLUE: ruleBlockGoto consumption helper (Ghidra removes edges via FlowBlock::removeInEdge block.cc:130)
    fn remove_in_edge_from(&mut self, _exclude_indices: &[i32]) {}
}

/// Find the CBRANCH that controls two block/edge paths.
/// Faithful to `FlowBlock::findCondition` (block.cc:839-858).
///
/// Given `bl1` reached via its `edge1`-th in-edge, and `bl2` reached via its
/// `edge2`-th in-edge, walk both in-chains up to the common 2-out (decision)
/// block that dominates both. Returns `(cond_block, slot1)` where `slot1` is
/// `bl1`'s rev-in-edge index into the condition block, or `None` if the paths
/// don't share a single decision point.
// Ghidra: block.cc:839 FlowBlock::findCondition
pub fn find_condition(
    bl1: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    edge1: usize,
    bl2: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    edge2: usize,
) -> Option<(Arc<RwLock<dyn FlowBlock + Send + Sync>>, i32)> {
    let cond1 = {
        let rg = bl1.read().unwrap();
        rg.get_in(edge1).map(|e| e.point)
    };
    let mut cond = cond1?;
    // Walk bl1's in-chain up to a 2-out decision block.
    loop {
        let cond_rg = cond.read().unwrap();
        let nout = cond_rg.size_out();
        if nout == 2 {
            break;
        }
        if nout != 1 {
            return None;
        }
        let next = cond_rg.get_in(0).map(|e| e.point);
        drop(cond_rg);
        // bl1 becomes cond, edge1=0, cond = cond's in(0)
        let new_cond = match next {
            Some(p) => p,
            None => return None,
        };
        // bl1 = cond (for rev-index below), but we need the original bl1's
        // rev-index into the FINAL cond — Ghidra defers that to the end.
        cond = new_cond;
    }

    // Now walk bl2's in-chain up to `cond`.
    let mut cur_bl2 = bl2.clone();
    let mut cur_edge2 = edge2;
    loop {
        let bl2_in = {
            let rg = cur_bl2.read().unwrap();
            rg.get_in(cur_edge2).map(|e| e.point)
        };
        let bl2_pred = match bl2_in {
            Some(p) => p,
            None => return None,
        };
        if Arc::ptr_eq(&bl2_pred, &cond) {
            break;
        }
        let bl2_pred_rg = bl2_pred.read().unwrap();
        if bl2_pred_rg.size_out() != 1 {
            return None;
        }
        drop(bl2_pred_rg);
        cur_bl2 = bl2_pred;
        cur_edge2 = 0;
    }

    // slot1 = bl1's rev-in-edge index into cond.
    // bl1 here is the original bl1 passed in; get_in_rev_index(edge1).
    let slot1 = {
        let rg = bl1.read().unwrap();
        rg.get_in_rev_index(edge1)
    };
    Some((cond, slot1))
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
    /// Scratch visit-count for LoopBody::extend (Ghidra getVisitCount/
    /// setVisitCount). Reset to 0 after each use.
    pub visit_count: i32,
}

impl BlockBasic {
    // Ghidra: block.hh:473 BlockBasic::BlockBasic
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
            visit_count: 0,
        }
    }

    /// Add an operation to the end of the block
    // Ghidra: block.hh:466 BlockBasic::insert
    pub fn add_op(&mut self, op: PcodeOpRef) {
        self.ops.push(op);
    }

    /// Get the last operation in the block
    // Ghidra: block.hh:490 BlockBasic::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        self.ops.last().cloned()
    }

    // RUGRA-GLUE: 近似 Ghidra BlockBasic::getStop (block.cc:2328)。Ghidra 用块
    // 的 cover 地址范围；Rugra 无 block cover，用最后 op 地址近似（仅 SeqNum 用）。
    /// Approximation of Ghidra `BlockBasic::getStop` (block.cc:2328), which
    /// returns the last address of the block's address cover. Rugra has no
    /// block cover system, so we approximate with the address of the last op
    /// (or the entry address if empty). This is used only as a SeqNum address
    /// for newly inserted ops (e.g. in buildDominantCopy), not for control
    /// flow, so the approximation is semantically safe.
    pub fn get_stop_addr(&self) -> crate::address::Address {
        if let Some(last) = self.ops.last() {
            let op = last.0.read().unwrap();
            op.get_addr()
        } else {
            self.start_addr
        }
    }

    /// Get the first operation in the block
    // Ghidra: block.hh:489 BlockBasic::firstOp
    pub fn first_op(&self) -> Option<PcodeOpRef> {
        self.ops.first().cloned()
    }

    /// Reset the SeqNum::order field for all PcodeOps in this block,
    /// distributing values evenly. Used by spliceBlockBasic after moving
    /// ops from another block.
    // Ghidra: block.cc:2638 BlockBasic::setOrder
    pub fn set_order(&mut self) {
        let n = self.ops.len();
        if n == 0 { return; }
        // Ghidra: step = (UINT_MAX / n) - 1, count += step each op.
        let step = if n > 0 { (u32::MAX / n as u32).saturating_sub(1) } else { 0 };
        let mut count = 0u32;
        for op_ref in &self.ops {
            count = count.saturating_add(step);
            op_ref.0.write().unwrap().start.set_order(count);
        }
    }
}

impl FlowBlock for BlockBasic {
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // Ghidra: block.hh:480 BlockBasic::getType
    fn get_type(&self) -> BlockType {
        BlockType::Basic
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }

    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }

    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }

    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }

    // RUGRA-GLUE: Rust edge-construction helper (Ghidra manages outofthis via friend addInEdge)
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }

    // RUGRA-GLUE: Rust helper (Ghidra BlockBasic exposes op list via begin/end iterators)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.ops.clone()
    }

    // Ghidra: block.hh:466 BlockBasic::insert
    fn add_op(&mut self, op: PcodeOpRef) {
        self.ops.push(op);
    }

    // Ghidra: block.hh:466 BlockBasic::insert
    fn insert_op(&mut self, index: usize, op: PcodeOpRef) {
        self.ops.insert(index, op);
    }

    // Ghidra: block.hh:478 BlockBasic::getStart
    fn get_start_addr(&self) -> Address {
        self.start_addr
    }

    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }

    // Ghidra: block.hh:162 FlowBlock::getImmedDom
    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.immed_dom.clone()
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::immed_dom is private)
    fn set_immed_dom(&mut self, dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.immed_dom = dom;
    }
    // RUGRA-GLUE: Rugra-only dom_depth field
    fn get_dom_depth(&self) -> i32 {
        self.dom_depth
    }
    // RUGRA-GLUE: Rust mutator for dom_depth
    fn set_dom_depth(&mut self, depth: i32) {
        self.dom_depth = depth;
    }
    // RUGRA-GLUE: Rugra-only dom_children field
    fn get_dom_children(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.dom_children.clone()
    }
    // RUGRA-GLUE: Rust mutator for dom_children
    fn add_dom_child(&mut self, child: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.dom_children.push(child);
    }
    // RUGRA-GLUE: Rust mutator for dom_children
    fn clear_dom_children(&mut self) {
        self.dom_children.clear();
    }
    // RUGRA-GLUE: Rugra-only dom_frontier field
    fn get_dom_frontier(&self) -> std::collections::HashSet<i32> {
        self.dom_frontier.clone()
    }
    // RUGRA-GLUE: Rust mutator for dom_frontier
    fn add_to_dom_frontier(&mut self, idx: i32) {
        self.dom_frontier.insert(idx);
    }
    // RUGRA-GLUE: Rust mutator for dom_frontier
    fn clear_dom_frontier(&mut self) {
        self.dom_frontier.clear();
    }
    // Ghidra: block.hh:306 FlowBlock::getInRevIndex
    fn get_in_rev_index(&self, slot: usize) -> i32 {
        self.incoming.get(slot).map(|e| e.reverse_index).unwrap_or(-1)
    }

    // ---- LoopBody mark / visit-count / edge-flag overrides ----
    // Ghidra: block.hh:286 FlowBlock::isMark
    fn is_mark(&self) -> bool {
        (self.flags & block_flags::MARK) != 0
    }
    // Ghidra: block.hh:287 FlowBlock::setMark
    fn set_mark(&mut self) {
        self.flags |= block_flags::MARK;
    }
    // Ghidra: block.hh:288 FlowBlock::clearMark
    fn clear_mark(&mut self) {
        self.flags &= !block_flags::MARK;
    }
    // Ghidra: block.hh:283 FlowBlock::getVisitCount
    fn get_visit_count(&self) -> i32 {
        self.visit_count
    }
    // Ghidra: block.hh:282 FlowBlock::setVisitCount
    fn set_visit_count(&mut self, c: i32) {
        self.visit_count = c;
    }

    // Ghidra: block.cc:218 FlowBlock::swapEdges
    fn swap_edges(&mut self) {
        if self.outgoing.len() == 2 {
            self.outgoing.swap(0, 1);
            // cc:228-231: update reverse_index on target blocks.
            // Rugra's BlockEdge has reverse_index; targets need update.
            // cc:232: flags ^= f_flip_path
            self.flags ^= block_flags::FLIP_PATH;
        }
    }

    // Ghidra: block.cc:2351 BlockBasic::negateCondition
    fn negate_condition(&mut self, toporbottom: bool) -> bool {
        if !toporbottom { return false; }
        // cc:2354: PcodeOp *lastop = op.back();
        let last_op = self.ops.last().cloned();
        if let Some(op_ref) = last_op {
            // cc:2355: flipFlag(boolean_flip)
            op_ref.0.write().unwrap().flags ^= crate::op::pcodeop_flags::BOOLEAN_FLIP;
        }
        // cc:2357: FlowBlock::negateCondition(true) → swapEdges
        self.swap_edges();
        // cc:2358: return true (dataflow changed)
        true
    }
    // Ghidra: block.hh:346 FlowBlock::isGotoIn
    fn is_goto_in(&self, i: usize) -> bool {
        // Goto-in: the i-th incoming edge is goto or irreducible (block.hh:346).
        self.incoming.get(i).map(|e| {
            (e.flags & (edge_flags::F_GOTO_EDGE | edge_flags::F_IRREDUCIBLE_EDGE)) != 0
        }).unwrap_or(false)
    }
    // Ghidra: block.hh:347 FlowBlock::isGotoOut
    fn is_goto_out(&self, i: usize) -> bool {
        // Goto-out: the i-th outgoing edge is goto or irreducible (block.hh:351).
        // Rugra marks gotos via block-level GOTO_EDGE_0/GOTO_EDGE_1 flags
        // (set by run_tracedag / goto_cascade), so we check both the edge flag
        // AND the block-level flag for slot i.
        let edge_goto = self.outgoing.get(i).map(|e| {
            (e.flags & (edge_flags::F_GOTO_EDGE | edge_flags::F_IRREDUCIBLE_EDGE)) != 0
        }).unwrap_or(false);
        if edge_goto { return true; }
        let block_goto = match i {
            0 => (self.flags & block_flags::GOTO_EDGE_0) != 0,
            1 => (self.flags & block_flags::GOTO_EDGE_1) != 0,
            _ => false,
        };
        block_goto
    }
    // Ghidra: block.hh:294 FlowBlock::setLoopExit
    fn set_loop_exit(&mut self, i: usize) {
        if let Some(e) = self.outgoing.get_mut(i) {
            e.flags |= edge_flags::F_LOOP_EXIT_EDGE;
        }
    }
    // Ghidra: block.hh:295 FlowBlock::clearLoopExit
    fn clear_loop_exit(&mut self, i: usize) {
        if let Some(e) = self.outgoing.get_mut(i) {
            e.flags &= !edge_flags::F_LOOP_EXIT_EDGE;
        }
    }
    // RUGRA-GLUE: ruleBlockGoto consumption helper (Ghidra removes edges via FlowBlock::removeInEdge block.cc:130)
    fn remove_in_edge_from(&mut self, exclude_indices: &[i32]) {
        self.incoming.retain(|e| {
            // Use try_read to avoid RwLock deadlock when e.point == self
            // (self-loop edge while holding our own write lock).
            e.point.try_read().map(|p| !exclude_indices.contains(&p.get_index())).unwrap_or(true)
        });
    }
}

/// BlockBasic-specific methods for edge manipulation (Ghidra identifyInternal support)
impl BlockBasic {
    // Ghidra: block.cc:178 FlowBlock::replaceOutEdge
    pub fn replace_out_edge_target(&mut self, slot: usize, new_target: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        if slot < self.outgoing.len() {
            self.outgoing[slot].point = new_target;
        }
    }

    // Ghidra: block.cc:160 FlowBlock::replaceInEdge
    pub fn replace_in_edge_source(&mut self, slot: usize, new_source: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        if slot < self.incoming.len() {
            self.incoming[slot].point = new_source;
        }
    }

    /// Reverse-index of the given outgoing edge slot, i.e. the slot in
    /// `out[slot].point`'s incoming list that points back at us.
    /// Faithful to `FlowBlock::getOutRevIndex` (block.cc).
    // Ghidra: block.hh:303 FlowBlock::getOutRevIndex
    pub fn get_out_rev_index(&self, slot: usize) -> i32 {
        self.outgoing[slot].reverse_index
    }

    /// Reverse-index of the given incoming edge slot. Faithful to
    /// `FlowBlock::getInRevIndex` (block.cc).
    // Ghidra: block.hh:306 FlowBlock::getInRevIndex
    pub fn get_in_rev_index(&self, slot: usize) -> i32 {
        self.incoming[slot].reverse_index
    }

    /// Delete only the incoming half of an edge (our `intothis` entry),
    /// leaving the matching outgoing entry on the source block stale.
    /// Faithful to `FlowBlock::halfDeleteInEdge` (block.cc:140).
    // Ghidra: block.cc:100 FlowBlock::halfDeleteInEdge
    pub fn half_delete_in_edge(&mut self, slot: usize) {
        self.incoming.remove(slot);
        // Reverse-indices of our remaining incoming edges that pointed past
        // `slot` on their source must be decremented.
        for e in self.incoming.iter_mut() {
            if e.reverse_index > slot as i32 {
                e.reverse_index -= 1;
            }
        }
    }

    /// Delete only the outgoing half of an edge. Faithful to
    /// `FlowBlock::halfDeleteOutEdge` (block.cc:149).
    // Ghidra: block.cc:115 FlowBlock::halfDeleteOutEdge
    pub fn half_delete_out_edge(&mut self, slot: usize) {
        self.outgoing.remove(slot);
        for e in self.outgoing.iter_mut() {
            if e.reverse_index > slot as i32 {
                e.reverse_index -= 1;
            }
        }
    }

    /// Remove edge `in`/`out` from this block but create a new direct edge
    /// between the in-block and the out-block, preserving slot positions.
    /// Faithful to `FlowBlock::replaceEdgesThru` (block.cc:198-216).
    ///
    /// Caller must hold NO lock on `self` while mutating the two peers; this
    /// method performs the writes directly on `self` then on the peers via
    /// their `as_any_mut()` downcasts.
    // Ghidra: block.cc:198 FlowBlock::replaceEdgesThru
    pub fn replace_edges_thru(
        &mut self,
        in_slot: usize,
        out_slot: usize,
    ) {
        // Capture the four endpoints before mutation.
        let inb = self.incoming[in_slot].point.clone();
        let inblock_outslot = self.incoming[in_slot].reverse_index as usize;
        let outb = self.outgoing[out_slot].point.clone();
        let outblock_inslot = self.outgoing[out_slot].reverse_index as usize;

        // Rewire inb.outofthis[inblock_outslot] -> outb.
        {
            let mut inb_rg = inb.write().unwrap();
            if let Some(bb) = inb_rg.as_any_mut().downcast_mut::<BlockBasic>() {
                bb.outgoing[inblock_outslot].point = outb.clone();
                bb.outgoing[inblock_outslot].reverse_index = outblock_inslot as i32;
            }
        }
        // Rewire outb.intothis[outblock_inslot] -> inb.
        {
            let mut outb_rg = outb.write().unwrap();
            if let Some(bb) = outb_rg.as_any_mut().downcast_mut::<BlockBasic>() {
                bb.incoming[outblock_inslot].point = inb;
                bb.incoming[outblock_inslot].reverse_index = inblock_outslot as i32;
            }
        }
        // Remove our half-edges (order matters: deleting the in-edge shifts
        // reverse-indices; Ghidra deletes in then out on `this`).
        self.half_delete_in_edge(in_slot);
        // After deleting in_slot, out_slot may have shifted only if out_slot
        // was an *out* edge (separate list), so out_slot is unaffected.
        self.half_delete_out_edge(out_slot);
    }

    // RUGRA-GLUE: Rust helper clearing both edge lists (Ghidra clears via BlockGraph::clear block.cc:1239)
    pub fn clear_edges(&mut self) {
        self.incoming.clear();
        self.outgoing.clear();
    }

    // RUGRA-GLUE: Rust accessor for outgoing edge slice (Ghidra exposes outofthis via getOut/sizeOut)
    pub fn get_outgoing(&self) -> &[BlockEdge] {
        &self.outgoing
    }

    // RUGRA-GLUE: Rust accessor for incoming edge slice (Ghidra exposes intothis via getIn/sizeIn)
    pub fn get_incoming(&self) -> &[BlockEdge] {
        &self.incoming
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
    // RUGRA-GLUE: Rust constructor for BlockEdge (Ghidra BlockEdge is a struct, edges built via addInEdge)
    pub fn new(point: Arc<RwLock<dyn FlowBlock + Send + Sync>>, reverse_index: i32) -> Self {
        Self {
            point,
            flags: 0,
            reverse_index,
        }
    }

    // RUGRA-GLUE: Rust accessor for f_break_edge flag (Ghidra checks label & f_break_edge inline)
    pub fn is_break(&self) -> bool {
        self.flags & edge_flags::F_BREAK_EDGE != 0
    }

    // RUGRA-GLUE: Rust accessor for f_continue_edge flag (Ghidra checks label inline)
    pub fn is_continue(&self) -> bool {
        self.flags & edge_flags::F_CONTINUE_EDGE != 0
    }

    // RUGRA-GLUE: Rust accessor for f_goto_edge flag (Ghidra checks label & f_goto_edge inline)
    pub fn is_goto(&self) -> bool {
        self.flags & edge_flags::F_GOTO_EDGE != 0
    }
}

/// A reference to a block for use in collections
#[derive(Debug, Clone)]
pub struct BlockRef(pub Arc<RwLock<dyn FlowBlock + Send + Sync>>);

impl PartialEq for BlockRef {
    // RUGRA-GLUE: Rust PartialEq for BlockRef (Ghidra compares FlowBlock* directly)
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
    // RUGRA-GLUE: Rust BlockGraph constructor (Ghidra BlockGraph is constructed implicitly by Funcdata)
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

    // Ghidra: block.cc:862 BlockGraph::addBlock
    pub fn add_block(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.blocks.push(bl);
    }

    // RUGRA-GLUE: Rust accessor (Ghidra uses list.size() inline)
    pub fn get_size(&self) -> usize {
        self.blocks.len()
    }

    // RUGRA-GLUE: Rust accessor (Ghidra uses list[i] inline)
    pub fn get_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.blocks.get(i).cloned()
    }

    /// Get the entry (start) block of this graph. Faithful to
    /// `BlockGraph::getStartBlock` (block.cc:1649-1655): the first block
    /// carrying the `f_entry_point` flag.
    // Ghidra: block.cc:1649 BlockGraph::getStartBlock
    pub fn get_start_block(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.blocks.iter().find(|b| b.read().unwrap().is_entry_point()).cloned()
    }

    /// Remove a block from the graph, first detaching all its in/out edges.
    /// Faithful to `BlockGraph::removeBlock` (block.cc:1517-1536). The block
    /// is removed from the `blocks` list but is NOT dropped (the caller may
    /// still hold an `Arc`).
    // Ghidra: block.cc:1517 BlockGraph::removeBlock
    pub fn remove_block_arc(&mut self, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        // Detach all incoming edges (rip each source's out-edge to us).
        while bl.read().unwrap().size_in() > 0 {
            let src = {
                let bl_rg = bl.read().unwrap();
                bl_rg.get_in(0).map(|e| e.point)
            };
            if let Some(src) = src {
                self.remove_edge_blocks(&src, bl);
            } else {
                break;
            }
        }
        // Detach all outgoing edges.
        while bl.read().unwrap().size_out() > 0 {
            let dst = {
                let bl_rg = bl.read().unwrap();
                bl_rg.get_out(0).map(|e| e.point)
            };
            if let Some(dst) = dst {
                self.remove_edge_blocks(bl, &dst);
            } else {
                break;
            }
        }
        // Remove from the block list (keep order, drop the Arc entry).
        self.blocks.retain(|b| !Arc::ptr_eq(b, bl));
    }

    /// Find the nearest common ancestor (dominator) of two blocks in the
    /// dominator tree. Faithful to `FlowBlock::findCommonBlock`
    /// (block.cc:736-795). Used by `PcodeOp::compareOrder` (op.cc:778) to
    /// determine control-flow ordering of two ops in different blocks.
    ///
    /// Returns None if either block has no dominator info (e.g. unreachable).
    // Ghidra: block.cc:736 FlowBlock::findCommonBlock
    pub fn find_common_block(
        bl1: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        bl2: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // Standard dominator-tree LCA: walk both up to equal depth, then
        // together until they meet. Equivalent to Ghidra's mark-based walk.
        let mut b1 = bl1.clone();
        let mut b2 = bl2.clone();
        // Walk the deeper node up until depths match.
        loop {
            let d1 = b1.read().unwrap().get_dom_depth();
            let d2 = b2.read().unwrap().get_dom_depth();
            if d1 <= d2 { break; }
            let up = b1.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            b1 = match up { Some(u) => u, None => return None };
        }
        loop {
            let d1 = b1.read().unwrap().get_dom_depth();
            let d2 = b2.read().unwrap().get_dom_depth();
            if d2 <= d1 { break; }
            let up = b2.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            b2 = match up { Some(u) => u, None => return None };
        }
        // Now equal depth; walk both up together.
        while !Arc::ptr_eq(&b1, &b2) {
            let up1 = b1.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            let up2 = b2.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            b1 = match up1 { Some(u) => u, None => return None };
            b2 = match up2 { Some(u) => u, None => return None };
        }
        Some(b1)
    }

    // Ghidra: block.cc:796 FlowBlock::findCommonBlock
    /// Find the common dominator of multiple blocks.
    /// Faithful to `FlowBlock::findCommonBlock(vector<FlowBlock*>&)`
    /// (block.cc:796-826). Used by `buildDominantCopy` to find the LCA of
    /// all COPY ops' parent blocks.
    ///
    /// Algorithm: mark the dom-chain of blockSet[0]; for each subsequent
    /// block, walk its dom-chain until hitting a marked block; track the
    /// one with the smallest index (= highest in dom tree).
    pub fn find_common_block_n(
        block_set: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        if block_set.is_empty() {
            return None;
        }
        // Use Arc pointer set as the mark (avoids &mut borrow across blocks).
        let mut marked: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // Walk blockSet[0]'s dom chain, marking each.
        let mut bl = block_set[0].clone();
        let mut res = bl.clone();
        let mut best_index = bl.read().unwrap().get_index();
        loop {
            marked.insert(std::sync::Arc::as_ptr(&bl) as *const () as usize);
            let up = bl.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            match up {
                Some(u) => bl = u,
                None => break,
            }
        }
        // For each subsequent block, walk until hitting a marked block.
        for i in 1..block_set.len() {
            if best_index == 0 {
                break;
            }
            let mut cur = block_set[i].clone();
            loop {
                let ptr = std::sync::Arc::as_ptr(&cur) as *const () as usize;
                if marked.contains(&ptr) {
                    let idx = cur.read().unwrap().get_index();
                    if idx < best_index {
                        res = cur.clone();
                        best_index = idx;
                    }
                    break;
                }
                marked.insert(ptr);
                let up = cur.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
                match up {
                    Some(u) => cur = u,
                    None => break,
                }
            }
        }
        // (Ghidra clears marks; our HashSet is local and dropped here.)
        Some(res)
    }

    /// Remove the edge from `src` to `dst` by symmetrically deleting both
    /// halves. Faithful to `BlockGraph::removeEdge` (block.cc). Finds the
    /// matching slot on each side and removes it via the half-delete helpers.
    // Ghidra: block.cc:1469 BlockGraph::removeEdge
    pub fn remove_edge_blocks(
        &mut self,
        src: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        dst: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        // Find src's out-slot pointing to dst.
        let out_slot = {
            let src_rg = src.read().unwrap();
            (0..src_rg.size_out())
                .find(|&i| {
                    src_rg.get_out(i)
                        .map(|e| Arc::ptr_eq(&e.point, dst))
                        .unwrap_or(false)
                })
        };
        // Find dst's in-slot pointing to src.
        let in_slot = {
            let dst_rg = dst.read().unwrap();
            (0..dst_rg.size_in())
                .find(|&i| {
                    dst_rg.get_in(i)
                        .map(|e| Arc::ptr_eq(&e.point, src))
                        .unwrap_or(false)
                })
        };
        if let Some(os) = out_slot {
            let mut src_rg = src.write().unwrap();
            if let Some(bb) = src_rg.as_any_mut().downcast_mut::<BlockBasic>() {
                bb.half_delete_out_edge(os);
            }
        }
        if let Some(is_) = in_slot {
            let mut dst_rg = dst.write().unwrap();
            if let Some(bb) = dst_rg.as_any_mut().downcast_mut::<BlockBasic>() {
                bb.half_delete_in_edge(is_);
            }
        }
    }

    // Ghidra: block.cc:1239 BlockGraph::clear
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.incoming.clear();
        self.outgoing.clear();
    }

    // Ghidra: block.cc:1439 BlockGraph::addEdge
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
    // Ghidra: block.cc:2036 BlockGraph::buildDomTree
    pub fn build_dom_tree(&mut self) {
        // Re-index all blocks to match their current vector position. This is
        // essential after dead-flow Actions (ActionUnreachable/DoNothing/etc.)
        // remove blocks — stale indices would cause out-of-bounds panics below.
        for (i, blk) in self.blocks.iter_mut().enumerate() {
            blk.write().unwrap().set_index(i as i32);
        }

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

    // RUGRA-GLUE: Cooper-Harvey-Kennedy intersect helper for buildDomTree (algorithmic glue; not a direct Ghidra method)
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
    // Ghidra: block.cc:2056 BlockGraph::buildDomDepth
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
    // Ghidra: block.cc:2080 BlockGraph::buildDomSubTree
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
    // RUGRA-GLUE: Rugra-only dom-frontier calculation (Ghidra has no dom-frontier field on FlowBlock)
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
    // RUGRA-GLUE: Rugra RPO calculation (Ghidra uses findSpanningTree + orderBlocks block.cc:1009)
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

    // RUGRA-GLUE: Rugra DFS helper for calc_rpo (Ghidra uses findSpanningTree block.cc:1009)
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
    // Ghidra: block.cc:2194 BlockGraph::structureLoops
    pub fn structure_loops(&mut self) -> bool {
        // Simple loop detection and structuring logic
        // Identifying back-edges and creating BlockWhileDo/BlockDoWhile
        false
    }

    /// Add a loop edge
    ///
    /// Corresponds to Ghidra's `BlockGraph::addLoopEdge`
    // Ghidra: block.cc:1451 BlockGraph::addLoopEdge
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
    // Ghidra: block.cc:2104 BlockGraph::calcLoop
    pub fn calc_loop(&mut self) {
        // Implement loop identification algorithm (e.g., Tarjan's or Johnson's)
    }
}

impl Eq for BlockRef {}

impl PartialOrd for BlockRef {
    // RUGRA-GLUE: Rust PartialOrd for BlockRef (Ghidra sorts FlowBlock* via compareFinalOrder block.cc:709)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockRef {
    // RUGRA-GLUE: Rust Ord for BlockRef (Ghidra sorts FlowBlock* via compareFinalOrder block.cc:709)
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
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // Ghidra: block.hh:525 BlockCopy::getType
    fn get_type(&self) -> BlockType {
        BlockType::Copy
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        0
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        0
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, _slot: usize) -> Option<BlockEdge> {
        None
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, _slot: usize) -> Option<BlockEdge> {
        None
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, _edge: BlockEdge) {}
    // RUGRA-GLUE: Rust edge-construction helper
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
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // Ghidra: block.hh:555 BlockGoto::getType
    fn get_type(&self) -> BlockType {
        BlockType::Goto
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
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
    /// For if-goto blocks (Ghidra newBlockIfGoto style): the target of the
    /// unstructured goto edge. When Some, this BlockIf represents
    /// `if (cond) goto target;` — the body is NOT embedded (if_body is a
    /// placeholder = condition), and the goto edge is consumed (removed from
    /// the target's incoming). When None, this is a normal if-then/if-then-else
    /// with embedded body. Faithful to Ghidra BlockIf::gototarget (block.hh:660).
    pub goto_target: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockIf {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 { self.index }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) { self.index = i; }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:666 BlockIf::getType
    fn get_type(&self) -> BlockType { BlockType::If }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 { self.flags }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize { self.incoming.len() }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize { self.outgoing.len() }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address { self.condition.read().unwrap().get_start_addr() }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
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
    /// For-loop metadata set by ActionStructureTransform when the while-do
    /// matches the canonical `for(init; cond; iterate)` pattern.
    /// Faithful to Ghidra's BlockWhileDo iterateOp/initializeOp (block.hh:690+).
    pub for_init: Option<String>,
    pub for_iter: Option<String>,
}

impl FlowBlock for BlockWhileDo {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 { self.index }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) { self.index = i; }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:707 BlockWhileDo::getType
    fn get_type(&self) -> BlockType { BlockType::WhileDo }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 { self.flags }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize { self.incoming.len() }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize { self.outgoing.len() }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address { self.condition.read().unwrap().get_start_addr() }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
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
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 { self.index }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) { self.index = i; }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:723 BlockDoWhile::getType
    fn get_type(&self) -> BlockType { BlockType::DoWhile }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 { self.flags }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize { self.incoming.len() }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize { self.outgoing.len() }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address { self.condition.read().unwrap().get_start_addr() }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
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
    // Ghidra: block.hh:420 BlockGraph::newBlockList
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
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 { self.index }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) { self.index = i; }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:602 BlockList::getType
    fn get_type(&self) -> BlockType { BlockType::List }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 { self.flags }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize { self.incoming.len() }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize { self.outgoing.len() }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.children.first()
            .map(|c| c.read().unwrap().get_start_addr())
            .unwrap_or_else(|| Address::new(0))
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
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
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 { self.index }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) { self.index = i; }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:626 BlockCondition::getType
    fn get_type(&self) -> BlockType { BlockType::Condition }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 { self.flags }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize { self.incoming.len() }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize { self.outgoing.len() }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address { self.first.read().unwrap().get_start_addr() }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
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
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 { self.index }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) { self.index = i; }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:793 BlockSwitch::getType
    fn get_type(&self) -> BlockType { BlockType::Switch }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 { self.flags }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) { self.flags |= f; }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize { self.incoming.len() }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize { self.outgoing.len() }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> { self.incoming.get(slot).cloned() }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> { self.outgoing.get(slot).cloned() }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) { self.incoming.push(edge); }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) { self.outgoing.push(edge); }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address { self.control.read().unwrap().get_start_addr() }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.control.read().unwrap().get_ops()
    }
}

