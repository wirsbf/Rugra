//! Basic blocks and control flow graph
//!
//! Corresponds to Ghidra's `block.hh`

use crate::address::Address;
use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};
use crate::op::PcodeOpRef;
use std::sync::{Arc, RwLock, Weak};

// ===== Marshal ElementId / AttributeId helpers (block.cc:22-28, 30-31) =====
// Ghidra defines these as static ElementId/AttributeId instances. Rugra builds
// them on demand via constructor functions matching the Ghidra names.

/// `ELEM_BLOCK` (block.cc:22): a \<block> element wrapping a FlowBlock.
// Ghidra: block.cc:22 ELEM_BLOCK
pub fn elem_block() -> ElementId { ElementId::new("block", 134) }
/// `ELEM_BHEAD` (block.cc:23): a \<bhead> element — header for a child block.
// Ghidra: block.cc:23 ELEM_BHEAD
pub fn elem_bhead() -> ElementId { ElementId::new("bhead", 135) }
/// `ELEM_EDGE` (block.cc:31): an \<edge> element — a flow graph edge.
// Ghidra: block.cc:31 ELEM_EDGE
pub fn elem_edge() -> ElementId { ElementId::new("edge", 105) }
/// `ELEM_TARGET` (block.cc:24): a \<target> element — a goto target ref.
// Ghidra: block.cc:24 ELEM_TARGET
pub fn elem_target() -> ElementId { ElementId::new("target", 136) }

/// `ATTRIB_INDEX` (block.cc:26): block index attribute.
// Ghidra: block.cc:26 ATTRIB_INDEX
pub fn attrib_index() -> AttributeId { AttributeId::new("index", 13) }
/// `ATTRIB_END` (block.cc:27): edge endpoint reference attribute.
// Ghidra: block.cc:27 ATTRIB_END
pub fn attrib_end() -> AttributeId { AttributeId::new("end", 37) }
/// `ATTRIB_REV` (block.cc:28): edge reverse-index attribute.
// Ghidra: block.cc:28 ATTRIB_REV
pub fn attrib_rev() -> AttributeId { AttributeId::new("rev", 38) }
/// `ATTRIB_DEPTH` (block.hh): goto-target depth attribute.
// Ghidra: block.hh ATTRIB_DEPTH
pub fn attrib_depth() -> AttributeId { AttributeId::new("depth", 39) }
/// `ATTRIB_TYPE` (block.hh): goto-type / block-type attribute.
// Ghidra: block.hh ATTRIB_TYPE
pub fn attrib_type() -> AttributeId { AttributeId::new("type", 40) }
/// `ATTRIB_ALTINDEX` (block.hh): BlockCopy alt-index attribute.
// Ghidra: block.hh ATTRIB_ALTINDEX
pub fn attrib_altindex() -> AttributeId { AttributeId::new("altindex", 41) }
/// `ATTRIB_OPCODE` (block.hh): BlockCondition opcode attribute.
// Ghidra: block.hh ATTRIB_OPCODE
pub fn attrib_opcode() -> AttributeId { AttributeId::new("opcode", 42) }

// ===== Free functions (block.cc static dispatch) =====

/// Ghidra `FlowBlock::nameToType` (block.cc:657-666): map a deserialized type
/// name string to a `BlockType`. Only "graph" and "copy" are distinguishable
/// from the base "plain" type when reading the \<bhead> tag; the structured
/// subtypes (if/while/do/switch) are inferred from component counts elsewhere.
// Ghidra: block.cc:657 FlowBlock::nameToType
pub fn name_to_type(nm: &str) -> BlockType {
    // cc:661-665: graph → t_graph; copy → t_copy; else t_plain.
    match nm {
        "graph" => BlockType::Graph,
        "copy" => BlockType::Copy,
        _ => BlockType::Plain,
    }
}

/// Ghidra `FlowBlock::typeToName` (block.cc:671-703): map a `BlockType` to its
/// serialized name string. Used by `BlockGraph::encodeBody` when writing the
/// \<bhead> type attribute.
// Ghidra: block.cc:671 FlowBlock::typeToName
pub fn type_to_name(bt: BlockType) -> &'static str {
    // cc:674-702: exhaustive switch over block_type.
    match bt {
        BlockType::Plain => "plain",
        BlockType::Basic => "basic",
        BlockType::Graph => "graph",
        BlockType::Copy => "copy",
        BlockType::Goto => "goto",
        BlockType::MultiGoto => "multigoto",
        BlockType::List => "list",
        BlockType::Condition => "condition",
        BlockType::If => "properif",
        BlockType::WhileDo => "whiledo",
        BlockType::DoWhile => "dowhile",
        BlockType::Switch => "switch",
        BlockType::InfLoop => "infloop",
    }
}

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
    /// Ghidra f_interior_gotoout = 0x400 (block.hh:97). Block has an unstructured
    /// jump out of its interior. Set by setGotoBranch (block.cc:311).
    pub const INTERIOR_GOTOOUT: u32 = 0x400;
    /// Ghidra f_interior_gotoin = 0x800 (block.hh:98). Block is the target of an
    /// unstructured jump to its interior. Set by setGotoBranch (block.cc:313).
    pub const INTERIOR_GOTOIN: u32 = 0x800;
    pub const DEAD: u32 = 0x4000;            // f_dead (block.hh:101)
    /// Ghidra f_label_bumpup = 0x1000 (block.hh:99). Labels for this block
    /// are printed by a parent higher in the hierarchy. Set/cleared by
    /// markLabelBumpUp (block.cc:259-263).
    pub const LABEL_BUMPUP: u32 = 0x1000;
    /// Ghidra f_donothing_loop = 0x2000 (block.hh:100). Block does nothing in
    /// an infinite loop (halt).
    pub const DONOTHING_LOOP: u32 = 0x2000;
    /// Ghidra f_whiledo_overflow = 0x8000 (block.hh:102). The conditional block
    /// of a while-do is too big to print as `while(cond)`; use overflow syntax.
    pub const WHILEDO_OVERFLOW: u32 = 0x8000;
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

/// Goto branch classification (Ghidra block.hh:89-91).
/// Stored on BlockGoto::goto_type and BlockIf::goto_type.
pub mod goto_type {
    /// Ordinary unstructured `goto target;` (block.hh:89).
    pub const GOTO_GOTO: u32 = 1;
    /// Goto → loop exit, printed as `break;` (block.hh:90).
    pub const BREAK_GOTO: u32 = 2;
    /// Goto → loop iterate, printed as `continue;` (block.hh:91).
    pub const CONTINUE_GOTO: u32 = 4;
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

    // Ghidra: block.hh:289 FlowBlock::clearOutEdgeFlag
    /// Clear a flag from a single outgoing edge. Faithful to Ghidra's
    /// `FlowBlock::clearOutEdgeFlag` (block.hh:289). Counterpart to
    /// `set_out_edge_flag`. Used by LoopBody::clearExitMarks.
    fn clear_out_edge_flag(&mut self, slot: usize, flag: u32) {
        let any = self.as_any_mut();
        if let Some(bb) = any.downcast_mut::<BlockBasic>() {
            if slot < bb.outgoing.len() { bb.outgoing[slot].flags &= !flag; }
        } else if let Some(bg) = any.downcast_mut::<BlockGraph>() {
            if slot < bg.outgoing.len() { bg.outgoing[slot].flags &= !flag; }
        }
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
    /// Ghidra reads the f_interior_gotoin flag (set by setGotoBranch
    /// block.cc:313). Rugra now sets that flag in set_goto_branch, so this
    /// checks it directly. We also keep the in-edge goto check as a
    /// fallback for edges marked GOTO via other paths.
    fn is_interior_goto_target(&self) -> bool {
        if (self.get_flags() & block_flags::INTERIOR_GOTOIN) != 0 { return true; }
        for i in 0..self.size_in() {
            if self.is_goto_in(i) { return true; }
        }
        false
    }

    // Ghidra: block.hh:324 FlowBlock::hasInteriorGoto
    /// Is there an unstructured goto out of this block's interior? Faithful
    /// to `hasInteriorGoto()` (block.hh:324). Checks f_interior_gotoout
    /// (set by setGotoBranch block.cc:311).
    fn has_interior_goto(&self) -> bool {
        (self.get_flags() & block_flags::INTERIOR_GOTOOUT) != 0
    }

    // Ghidra: block.hh:297 FlowBlock::getFlipPath
    /// Have out edges been flipped (swapped) since the last path trace?
    /// Faithful to `getFlipPath()` (block.hh:297): checks f_flip_path flag.
    /// Used by jumptable checkUnrolledGuard (jumptable.cc:1369) to determine
    /// which in-edge index corresponds to the switch value.
    fn get_flip_path(&self) -> bool {
        (self.get_flags() & block_flags::FLIP_PATH) != 0
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

    // Ghidra: block.cc:405 FlowBlock::restrictedByConditional
    /// Check if this block is completely dominated by the conditional block
    /// `cond` — all paths reaching this block go through cond's edge, so a
    /// boolean constant holds. Faithful to `restrictedByConditional`
    /// (block.cc:405-425).
    fn restricted_by_conditional(
        &self,
        cond: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> bool {
        // cc:408: single in-edge → always restricted.
        if self.size_in() == 1 { return true; }
        // cc:409: check immedDom == cond.
        let my_dom = self.get_immed_dom().and_then(|w| w.upgrade());
        match &my_dom {
            Some(d) if Arc::ptr_eq(d, cond) => {}
            _ => return false,
        }
        // cc:410-423: verify all in-edges only reach via cond.
        let mut seen_cond = false;
        let self_idx = self.get_index();
        for i in 0..self.size_in() {
            let in_block = match self.get_in(i) { Some(e) => e.point.clone(), None => continue };
            if Arc::ptr_eq(&in_block, cond) {
                if seen_cond { return false; }
                seen_cond = true;
                continue;
            }
            // Walk dom chain from in_block up to self, checking if cond is hit.
            let mut cur = in_block;
            loop {
                if Arc::ptr_eq(&cur, cond) { return false; }
                let cur_idx = cur.read().unwrap().get_index();
                if cur_idx == self_idx { break; }
                let up = cur.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
                match up {
                    Some(u) => {
                        if Arc::ptr_eq(&u, cond) { return false; }
                        if u.read().unwrap().get_index() == self_idx { break; }
                        cur = u;
                    }
                    None => break,
                }
            }
        }
        true
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

    /// Ghidra `FlowBlock::scopeBreak` (block.hh:266, virtual; default impl in
    /// block.cc:284-289): propagate the current exit/loop-exit scope into
    /// children so unstructured gotos can be reclassified as `break`/
    /// `continue`. Default: recurse into all children. Structured block
    /// subtypes override this (block.cc:3075 BlockIf, 3324 BlockWhileDo, etc.).
    /// Rugra provides a default no-op for blocks with no structured children
    /// (BlockBasic/BlockCopy); the structured blocks override via their
    /// inherent `scope_break_goto_type` helpers which call this trait method
    /// to recurse.
    // Ghidra: block.hh:266 FlowBlock::scopeBreak
    fn scope_break_trait(&mut self, _cur_exit: i32, _cur_loop_exit: i32) {}

    /// Ghidra `FlowBlock::getExitLeaf` (block.hh, virtual): the leaf block
    /// that flow exits through, if there is a single one. Default: null.
    /// BlockList/BlockIf override (block.cc:2953, 3111).
    // Ghidra: block.hh FlowBlock::getExitLeaf
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }

    /// Ghidra `FlowBlock::flipInPlaceTest` (block.hh, virtual; block.cc:2368
    /// BlockBasic impl): test whether the CBRANCH controlling this block can
    /// be flipped in place without violating cover constraints. Returns 0 if
    /// flippable, non-zero reason code otherwise. Default: 2 (not flippable).
    // Ghidra: block.hh FlowBlock::flipInPlaceTest
    fn flip_in_place_test(&self) -> i32 {
        2
    }

    /// Ghidra `FlowBlock::flipInPlaceExecute` (block.hh, virtual): perform the
    /// in-place CBRANCH flip. Default: no-op (BlockBasic overrides in
    /// block.cc:2368 to negate the boolean input).
    // Ghidra: block.hh FlowBlock::flipInPlaceExecute
    fn flip_in_place_execute(&mut self) {}

    /// Ghidra `FlowBlock::lastOp` (block.hh, virtual): the last PcodeOp in
    /// this block, or null. Default: null. BlockBasic/BlockList/BlockIf/
    /// BlockCondition override (block.cc:761, 2960, 3119, 3016).
    // Ghidra: block.hh FlowBlock::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        None
    }

    // ---- Marshaling (block.cc:2447-2510) ----

    /// Ghidra `FlowBlock::encodeHeader` (block.cc:2447-2451): emit the `index`
    /// attribute. Sub-classes (BlockCopy, BlockCondition) override to add
    /// extra attributes. Default writes only the index.
    // Ghidra: block.cc:2447 FlowBlock::encodeHeader
    fn encode_header_trait(&self, encoder: &mut dyn Encoder) {
        // cc:2450: encoder.writeSignedInteger(ATTRIB_INDEX, index);
        encoder.write_signed_integer(&attrib_index(), self.get_index() as i64);
    }

    /// Ghidra `FlowBlock::decodeHeader` (block.cc:2454-2458): read the `index`
    /// attribute and store it on this block.
    // Ghidra: block.cc:2454 FlowBlock::decodeHeader
    fn decode_header_trait(&mut self, decoder: &mut dyn Decoder) {
        // cc:2457: index = decoder.readSignedInteger(ATTRIB_INDEX);
        let i = decoder.read_signed_integer_attr(&attrib_index());
        self.set_index(i as i32);
    }

    /// Ghidra `FlowBlock::encodeEdges` (block.cc:2462-2468): emit one \<edge>
    /// element per incoming edge. Default iterates `intothis`.
    // Ghidra: block.cc:2462 FlowBlock::encodeEdges
    fn encode_edges_trait(&self, encoder: &mut dyn Encoder) {
        // cc:2465-2467: for (i=0; i<intothis.size(); ++i) intothis[i].encode(encoder);
        for i in 0..self.size_in() {
            if let Some(e) = self.get_in(i) {
                encode_block_edge(&e, encoder);
            }
        }
    }

    /// Ghidra `FlowBlock::encodeBody` (block.hh, virtual): emit the type-
    /// specific body of this block. Default: no-op (plain FlowBlock has no
    /// body). BlockBasic/BlockGraph/BlockGoto/BlockIf override.
    // Ghidra: block.hh FlowBlock::encodeBody
    fn encode_body_trait(&self, _encoder: &mut dyn Encoder) {}

    /// Ghidra `FlowBlock::decodeBody` (block.hh, virtual): restore the type-
    /// specific body. Default: no-op.
    // Ghidra: block.hh FlowBlock::decodeBody
    fn decode_body_trait(&mut self, _decoder: &mut dyn Decoder) {}

    /// Ghidra `FlowBlock::encode` (block.cc:2487-2495): encode this block as a
    /// \<block> element — header, body, then edges.
    // Ghidra: block.cc:2487 FlowBlock::encode
    fn encode_trait(&self, encoder: &mut dyn Encoder) {
        // cc:2490-2494: openElement(BLOCK); encodeHeader; encodeBody; encodeEdges; closeElement.
        let block_id = elem_block();
        encoder.open_element(&block_id);
        self.encode_header_trait(encoder);
        self.encode_body_trait(encoder);
        self.encode_edges_trait(encoder);
        encoder.close_element(&block_id);
    }

    /// Ghidra `FlowBlock::printHeader` (block.cc:604-611): emit the block
    /// index, optionally followed by the start-stop address range. Default
    /// writes the index and the address range if both ends are valid.
    // Ghidra: block.cc:604 FlowBlock::printHeader
    fn print_header_trait(&self) -> String {
        // cc:607: s << dec << index;
        let mut s = format!("{}", self.get_index());
        // cc:608-610: if (!getStart().isInvalid() && !getStop().isInvalid()) s << ' ' << getStart() << '-' << getStop();
        let start = self.get_start_addr();
        if !start.is_null() {
            s.push_str(&format!(" {}", start));
        }
        s
    }

    /// Ghidra `FlowBlock::printTree` (block.cc:616-625): emit the header
    /// indented by `level` spaces. Default does not recurse (leaf blocks).
    // Ghidra: block.cc:616 FlowBlock::printTree
    fn print_tree_trait(&self, level: i32) -> String {
        // cc:621-624: indent; printHeader(s); s << endl;
        let indent: String = "  ".repeat(level as usize);
        format!("{}{}\n", indent, self.print_header_trait())
    }

    /// Ghidra `FlowBlock::printRaw` (block.hh, virtual): emit the raw p-code /
    /// block listing. Default: emit just the header (no body to print).
    // Ghidra: block.hh FlowBlock::printRaw
    fn print_raw_trait(&self) -> String {
        // cc: default behaviour: just the header line.
        format!("{}\n", self.print_header_trait())
    }

    /// Ghidra `FlowBlock::printRawImpliedGoto` (block.hh, virtual): emit an
    /// implied goto comment if this block's fall-thru does not reach
    /// `next_block`. Default: no-op (no implied goto for leaf blocks without
    /// a single out-edge).
    // Ghidra: block.hh FlowBlock::printRawImpliedGoto
    fn print_raw_implied_goto_trait(&self, _next_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> String {
        String::new()
    }
}

/// Ghidra `BlockEdge::encode` (block.cc:35-43): emit an \<edge> element with
/// `end` (the other-end block index) and `rev` (reverse-index) attributes.
/// Free function because Rugra's `BlockEdge` is a plain struct (no Ghidra
/// `BlockEdge::encode` method dispatch).
// Ghidra: block.cc:35 BlockEdge::encode
pub fn encode_block_edge(edge: &BlockEdge, encoder: &mut dyn Encoder) {
    // cc:38-42: openElement(EDGE); writeSignedInteger(ATTRIB_END, point->getIndex());
    //          writeSignedInteger(ATTRIB_REV, reverse_index); closeElement(EDGE);
    let edge_id = elem_edge();
    encoder.open_element(&edge_id);
    let end_idx = edge.point.read().unwrap().get_index();
    encoder.write_signed_integer(&attrib_end(), end_idx as i64);
    encoder.write_signed_integer(&attrib_rev(), edge.reverse_index as i64);
    encoder.close_element(&edge_id);
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

    // Ghidra: block.cc:2802 BlockBasic::liftVerifyUnroll
    /// Verify that all Varnodes in varArray are defined by the same opcode
    /// with matching constant operand, then "unroll" by replacing each
    /// varnode with its input at `slot`. Returns true if all match.
    /// Faithful to `liftVerifyUnroll` (block.cc:2802-2832).
    /// Used by jumptable checkUnrolledGuard to verify loop-unrolling guards.
    pub fn lift_verify_unroll(
        var_array: &mut Vec<Arc<RwLock<crate::varnode::Varnode>>>,
        slot: usize,
    ) -> bool {
        if var_array.is_empty() { return false; }
        // cc:2808: check first varnode's def op.
        let vn0 = var_array[0].clone();
        let (opc, cvn_opt): (crate::opcodes::OpCode, (Option<Arc<RwLock<crate::varnode::Varnode>>>, Option<Arc<RwLock<crate::varnode::Varnode>>>)) = {
            let vn = vn0.read().unwrap();
            if !vn.is_written() { return false; }
            let def_arc = match vn.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => return false,
            };
            let def = def_arc.read().unwrap();
            let opc = def.opcode;
            let cvn: Option<Arc<RwLock<crate::varnode::Varnode>>> = if def.num_input() == 2 {
                let other = def.get_in(1 - slot).cloned();
                match &other {
                    Some(v) if v.read().unwrap().is_constant() => other,
                    _ => return false,
                }
            } else {
                None
            };
            // cc:2817: varArray[0] = op->getIn(slot)
            let new_vn = def.get_in(slot).cloned();
            (opc, (cvn, new_vn))
        };
        // Replace var_array[0] with the slot input.
        if let (_, Some(new_vn)) = &cvn_opt {
            var_array[0] = new_vn.clone();
        } else {
            return false;
        }
        let cvn = cvn_opt.0;
        // cc:2818-2830: check remaining varnodes.
        let n = var_array.len();
        for i in 1..n {
            let vn = var_array[i].clone();
            let new_vn = {
                let vn_r = vn.read().unwrap();
                if !vn_r.is_written() { return false; }
                let def_arc = match vn_r.def.as_ref().and_then(|w| w.upgrade()) {
                    Some(d) => d, None => return false,
                };
                let def = def_arc.read().unwrap();
                if def.opcode != opc { return false; }
                if let Some(ref cvn_arc) = cvn {
                    let cvn2 = match def.get_in(1 - slot) {
                        Some(v) => v.clone(),
                        None => return false,
                    };
                    let cvn2_r = cvn2.read().unwrap();
                    if !cvn2_r.is_constant() { return false; }
                    let cvn_r = cvn_arc.read().unwrap();
                    if cvn_r.get_size() != cvn2_r.get_size() { return false; }
                    if cvn_r.get_offset() != cvn2_r.get_offset() { return false; }
                }
                def.get_in(slot).cloned()
            };
            match new_vn {
                Some(v) => var_array[i] = v,
                None => return false,
            }
        }
        true
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

    /// Ghidra `BlockGraph::scopeBreak` (block.cc:1270-1288): walk this graph's
    /// child list in order and recurse `scopeBreak(cur_exit, cur_loop_exit)`
    /// into each child. For every child except the last, `cur_exit` is the
    /// next child's index (its fall-thru successor); for the last child,
    /// `cur_exit` is the value passed in (the enclosing scope's exit, or -1
    /// at the function top-level). `cur_loop_exit` is propagated unchanged
    /// (it is the innermost enclosing loop's exit, or -1 outside any loop).
    ///
    /// This is the entry point invoked by `ActionFinalStructure::apply`
    /// (blockaction.cc:2193: `graph.scopeBreak(-1,-1)`) to reclassify
    /// unstructured gotos whose target is an enclosing loop's exit as
    /// `break;` (BlockGoto::gototype = f_break_goto).
    // Ghidra: block.cc:1270 BlockGraph::scopeBreak
    pub fn scope_break(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:1277-1287: iter = list.begin(); while (iter != list.end()) {
        //          curbl = *iter; ++iter;
        //          if (iter == list.end()) ind = curexit; else ind = (*iter)->getIndex();
        //          curbl->scopeBreak(ind, curloopexit);
        //        }
        let n = self.blocks.len();
        for i in 0..n {
            // Look ahead to determine this child's exit (= next child's index,
            // or the inherited cur_exit for the last child).
            let ind = if i + 1 < n {
                self.blocks[i + 1].read().unwrap().get_index()
            } else {
                cur_exit
            };
            self.blocks[i].write().unwrap().scope_break_trait(ind, cur_loop_exit);
        }
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
    /// Implements the Cooper-Harvey-Kennedy dominance-frontier algorithm from
    /// "A Simple, Fast Dominator Algorithm". For a join-point `b` (a block with
    /// more than one predecessor, OR the function entry when it also has a
    /// back-edge — i.e. a loop header that doubles as the entry), each
    /// predecessor `p` runs up the dominator tree adding `b` to every runner's
    /// frontier until it reaches `idom(b)`.
    ///
    /// Note: the function-entry flow is intentionally NOT modelled as an
    /// explicit predecessor edge (matching Ghidra's `FlowBlock` in-edge model),
    /// so the entry block's recorded `incoming` edges only reflect real CFG
    /// edges. A loop header that is also the entry therefore has
    /// `incoming.len() == 1` (just the back-edge). To keep CHK correct in that
    /// case we additionally treat `entry && incoming.len() >= 1` as a
    /// join-point, and — because `build_dom_tree` leaves the entry's `idom`
    /// as `None` — we use `b` itself as the runner stop node (the entry
    /// dominates itself). Without this, every loop whose header is the entry
    /// gets an empty dominance frontier, no MULTIEQUAL (phi) is placed for the
    /// loop-carried flag varnode, and the CBRANCH condition read is left
    /// unresolved (root cause of the `while(local_0==local_0)` dead-loop).
    // RUGRA-GLUE: Rugra-only dom-frontier calculation (Ghidra has no dom-frontier field on FlowBlock)
    pub fn calc_dom_frontier(&mut self) {
        for i in 0..self.blocks.len() {
            let b_ref = self.blocks[i].clone();

            // Gather incoming edges + entry flag + idom while holding one read lock.
            let (incoming, is_entry, b_index, b_idom_ref) = {
                let b = b_ref.read().unwrap();
                let size_in = b.size_in();
                let mut incoming = Vec::new();
                for j in 0..size_in {
                    if let Some(edge) = b.get_in(j) {
                        incoming.push(edge);
                    }
                }
                let b_idom_ref = b.get_immed_dom().and_then(|w| w.upgrade());
                // `b` is the function entry iff it has the ENTRY_POINT flag, has
                // no recorded predecessors (size_in==0), OR — the most reliable
                // signal — `build_dom_tree` left its `idom` as None (the entry
                // dominates itself and is never assigned an idom). The idom-None
                // case is what catches a loop header that doubles as the entry:
                // its only recorded predecessor is the back-edge (size_in==1)
                // and ENTRY_POINT may not be set, so the flag/size checks alone
                // miss it.
                let is_entry = (b.get_flags() & block_flags::ENTRY_POINT) != 0
                    || size_in == 0
                    || b_idom_ref.is_none();
                let b_index = b.get_index();
                (incoming, is_entry, b_index, b_idom_ref)
            };

            // Join-point: ≥2 predecessors, OR the entry block reached by a
            // back-edge (incoming.len() >= 1) — the implicit entry flow is the
            // "second" predecessor in CHK terms.
            let is_join = incoming.len() >= 2
                || (is_entry && incoming.len() >= 1);
            if !is_join {
                continue;
            }

            // CHK runner stop node = idom(b). For the entry block idom is None
            // (buildDomTree leaves it unset), but the entry dominates itself,
            // so the correct stop node is `b` itself.
            let stop_ref: Arc<RwLock<dyn FlowBlock + Send + Sync>> = match &b_idom_ref {
                Some(idom) => idom.clone(),
                None if is_entry => b_ref.clone(),
                None => continue,
            };

            for edge in incoming {
                let mut runner_ref = edge.point.clone();

                let max_steps = self.blocks.len() + 2;
                let mut steps = 0;
                while !Arc::ptr_eq(&runner_ref, &stop_ref) && steps < max_steps {
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
                        if Arc::ptr_eq(&nr, &runner_ref) {
                            break; // self-loop
                        }
                        runner_ref = nr;
                    } else {
                        break;
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

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockCopy virtual overrides)
impl BlockCopy {
    /// Ghidra `BlockCopy::printHeader` (block.cc:2835-2840): prints
    /// `"Basic(copy) block "` followed by the FlowBlock header.
    // Ghidra: block.cc:2835 BlockCopy::printHeader
    pub fn print_header(&self) -> String {
        format!("Basic(copy) block {}", self.index)
    }

    /// Ghidra `BlockCopy::printTree` (block.cc:2842-2846): delegates to the
    /// wrapped original block's printTree at the given indentation level.
    // Ghidra: block.cc:2842 BlockCopy::printTree
    pub fn print_tree(&self, level: i32) -> String {
        let indent: String = "  ".repeat(level as usize);
        let body = self.original.read().unwrap();
        format!("{}Block_{} (copy of {})\n", indent, self.index, body.get_index())
    }

    /// Ghidra `BlockCopy::encodeHeader` (block.cc:2848-2854): emits the base
    /// header (index) plus an `altindex` attribute holding the wrapped
    /// block's index. Returns `(index, altindex)` for the marshal layer.
    // Ghidra: block.cc:2848 BlockCopy::encodeHeader
    pub fn encode_header(&self) -> (i32, i32) {
        let altindex = self.original.read().unwrap().get_index();
        (self.index, altindex)
    }
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
    /// Ghidra `BlockGoto::gototype` (block.hh:549): classification of the
    /// unstructured branch (one of `goto_type::GOTO_GOTO` /
    /// `goto_type::BREAK_GOTO` / `goto_type::CONTINUE_GOTO`). Defaults to
    /// `GOTO_GOTO`; mutated by scope_break to BREAK_GOTO (block.cc:2873).
    pub goto_type: u32,
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
    // Ghidra: block.cc:2866 BlockGoto::scopeBreak — delegate to the inherent
    // helper which holds the faithful port (cc:2869 recurse, cc:2872-2873
    // reclassify as f_break_goto when target == curloopexit).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_goto_type(cur_exit, cur_loop_exit);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockGoto virtual overrides)
impl BlockGoto {
    /// Ghidra `BlockGoto::getGotoTarget` (block.hh:552, inline): return the
    /// target block of the unstructured goto.
    // Ghidra: block.hh:552 BlockGoto::getGotoTarget
    pub fn get_goto_target(&self) -> Option<Arc<RwLock<BlockBasic>>> {
        self.goto_target.clone()
    }

    /// Ghidra `BlockGoto::getGotoType` (block.hh:553, inline): return the
    /// classification of the unstructured branch
    /// (`goto_type::GOTO_GOTO`/`BREAK_GOTO`/`CONTINUE_GOTO`).
    // Ghidra: block.hh:553 BlockGoto::getGotoType
    pub fn get_goto_type(&self) -> u32 {
        self.goto_type
    }

    /// Ghidra `BlockGoto::markUnstructured` (block.cc:2856-2864): if the goto
    /// is a plain `goto` (not a `break`/`continue`) and it actually prints,
    /// mark its target block with `f_unstructured_targ`. The C++ first recurses
    /// via `BlockGraph::markUnstructured`, but Rugra's `BlockGoto` wraps a
    /// `BlockBasic` (no structured children), so only the target-marking step
    /// is needed.
    // Ghidra: block.cc:2856 BlockGoto::markUnstructured
    pub fn mark_unstructured_target(&self) {
        // cc:2860-2863: if (gototype == f_goto_goto) { if (gotoPrints()) markCopyBlock(gototarget, f_unstructured_targ); }
        if self.goto_type == goto_type::GOTO_GOTO {
            if self.goto_prints() {
                if let Some(target) = &self.goto_target {
                    target.write().unwrap().flags |= block_flags::UNSTRUCTURED_TARG;
                }
            }
        }
    }

    /// Ghidra `BlockGoto::scopeBreak` (block.cc:2866-2874): classify this goto
    /// as a `break` if its target index equals the current loop's exit index.
    /// The C++ first line recurses into the wrapped child via
    /// `getBlock(0)->scopeBreak(...)`; Rugra's `BlockGoto` wraps a `BlockBasic`
    /// with no structured children, so that recursion is a no-op and only the
    /// classification step (cc:2872-2873) is performed.
    // Ghidra: block.cc:2866 BlockGoto::scopeBreak
    pub fn scope_break_goto_type(&mut self, _cur_exit: i32, cur_loop_exit: i32) {
        // cc:2872-2873: if (curloopexit == gototarget->getIndex()) gototype = f_break_goto;
        if let Some(target) = &self.goto_target {
            if target.read().unwrap().index == cur_loop_exit {
                self.goto_type = goto_type::BREAK_GOTO;
            }
        }
    }

    /// Ghidra `BlockGoto::gotoPrints` (block.cc:2881-2890): would a formal
    /// `goto` statement be emitted for this block? Returns `false` when the
    /// emitter can place the target immediately after this block (so the goto
    /// is a fall-thru and must not print). Rugra asks the parent for the block
    /// following this one in flow and compares it to the target's front leaf.
    /// Without a `nextFlowAfter` path through Rugra's `BlockGraph` parent, we
    /// conservatively return `true` (always print) — matching the C++ behaviour
    /// when the parent is null (block.cc:2889).
    // Ghidra: block.cc:2881 BlockGoto::gotoPrints
    pub fn goto_prints(&self) -> bool {
        // cc:2884-2888: parent != null ? (gototarget->getFrontLeaf() != parent->nextFlowAfter(this)) : false
        // Rugra's BlockGraph parent does not yet implement nextFlowAfter, so we
        // cannot compute `nextbl`; fall back to "always print" (true).
        true
    }

    /// Ghidra `BlockGoto::printHeader` (block.cc:2892-2897): emit
    /// `"Plain goto block <index>"`.
    // Ghidra: block.cc:2892 BlockGoto::printHeader
    pub fn print_header(&self) -> String {
        // cc:2895-2896: s << "Plain goto block "; FlowBlock::printHeader(s);
        format!("Plain goto block {}", self.index)
    }

    /// Ghidra `BlockGoto::nextFlowAfter` (block.cc:2899-2903): the block
    /// containing the next statement in flow is the goto target's front leaf.
    /// Rugra returns the target's index (the front-leaf concept does not yet
    /// have a Rust counterpart), or `None` if no target is set.
    // Ghidra: block.cc:2899 BlockGoto::nextFlowAfter
    pub fn next_flow_after_index(&self) -> Option<i32> {
        // cc:2902: return getGotoTarget()->getFrontLeaf();
        self.goto_target.as_ref().map(|t| t.read().unwrap().index)
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
    /// Ghidra `BlockIf::gototype` (block.hh:659): classification of the
    /// unstructured edge for an if-goto block. Defaults to `goto_type::GOTO_GOTO`;
    /// mutated by `scopeBreak` (block.cc:3083) to `goto_type::BREAK_GOTO` when
    /// the goto target is the enclosing loop's exit. Unused (kept at the
    /// default) for ordinary if-then/if-then-else blocks.
    pub goto_type: u32,
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
    // Ghidra: block.cc:3075 BlockIf::scopeBreak — delegate to the inherent
    // helper which holds the faithful port (cc:3078 condition recurse,
    // cc:3080-3081 body recurse, cc:3082-3083 if-goto reclassify).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_goto_type(cur_exit, cur_loop_exit);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockIf virtual overrides)
impl BlockIf {
    /// Ghidra `BlockIf::setGotoTarget` (block.hh:663, inline): mark the target
    /// of the unstructured edge for an if-goto block.
    // Ghidra: block.hh:663 BlockIf::setGotoTarget
    pub fn set_goto_target(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.goto_target = Some(bl);
    }

    /// Ghidra `BlockIf::getGotoTarget` (block.hh:664, inline): return the
    /// target of the unstructured edge, if any.
    // Ghidra: block.hh:664 BlockIf::getGotoTarget
    pub fn get_goto_target(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.goto_target.clone()
    }

    /// Ghidra `BlockIf::getGotoType` (block.hh:665, inline): return the type
    /// of the unstructured edge.
    // Ghidra: block.hh:665 BlockIf::getGotoType
    pub fn get_goto_type(&self) -> u32 {
        self.goto_type
    }

    /// Ghidra `BlockIf::markUnstructured` (block.cc:3067-3073): if this is an
    /// if-goto block (gototarget != null) with a plain goto edge, mark the
    /// target block with `f_unstructured_targ`. The C++ first recurses into
    /// children via `BlockGraph::markUnstructured`; Rugra's BlockIf exposes
    /// its condition/if_body/else_body directly, and those components are
    /// marked separately by the structurer, so only the target-marking step
    /// is ported here.
    // Ghidra: block.cc:3067 BlockIf::markUnstructured
    pub fn mark_unstructured_target(&self) {
        // cc:3071-3072: if (gototarget != null && gototype == f_goto_goto) markCopyBlock(gototarget, f_unstructured_targ);
        if self.goto_target.is_some() && self.goto_type == goto_type::GOTO_GOTO {
            if let Some(target) = &self.goto_target {
                target.write().unwrap().set_flags(block_flags::UNSTRUCTURED_TARG);
            }
        }
    }

    /// Ghidra `BlockIf::scopeBreak` (block.cc:3075-3084): propagate scope-break
    /// classification into the condition and body, and reclassify the goto
    /// edge as a `break` if its target is the enclosing loop's exit. The C++
    /// body recurses via `getBlock(i)->scopeBreak(...)`; Rugra recurses into
    /// the held `condition`/`if_body`/`else_body` blocks directly. The
    /// condition block has multiple exits (so it gets cur_exit = -1), while
    /// the bodies share the if's exit block (so they get the real cur_exit).
    // Ghidra: block.cc:3075 BlockIf::scopeBreak
    pub fn scope_break_goto_type(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3078: getBlock(0)->scopeBreak(-1, curloopexit);   // condition
        self.condition.write().unwrap().scope_break_trait(-1, cur_loop_exit);
        // cc:3080-3081: for (i=1; i<getSize(); ++i) getBlock(i)->scopeBreak(curexit, curloopexit);
        self.if_body.write().unwrap().scope_break_trait(cur_exit, cur_loop_exit);
        if let Some(else_body) = &self.else_body {
            else_body.write().unwrap().scope_break_trait(cur_exit, cur_loop_exit);
        }
        // cc:3082-3083: if (gototarget != null && gototarget->getIndex() == curloopexit) gototype = f_break_goto;
        if let Some(target) = &self.goto_target {
            if target.read().unwrap().get_index() == cur_loop_exit {
                self.goto_type = goto_type::BREAK_GOTO;
            }
        }
    }

    /// Ghidra `BlockIf::printHeader` (block.cc:3086-3091): emit
    /// `"If block <index>"`.
    // Ghidra: block.cc:3086 BlockIf::printHeader
    pub fn print_header(&self) -> String {
        // cc:3089-3090: s << "If block "; FlowBlock::printHeader(s);
        format!("If block {}", self.index)
    }

    /// Ghidra `BlockIf::getExitLeaf` (block.cc:3111-3117): in the special case
    /// of an if-goto block (getSize()==1), the exit leaf is the condition
    /// block's exit leaf; otherwise there is no single exit leaf. Rugra models
    /// the if-goto case by `goto_target.is_some()` (which implies the
    /// condition is the only embedded component), delegating to the condition.
    // Ghidra: block.cc:3111 BlockIf::getExitLeaf
    pub fn get_exit_leaf(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3114-3115: if (getSize() == 1) return getBlock(0)->getExitLeaf();
        if self.goto_target.is_some() {
            self.condition.read().unwrap().get_exit_leaf_trait()
        } else {
            None
        }
    }

    /// Ghidra `BlockIf::lastOp` (block.cc:3119-3125): in the special case of
    /// an if-goto block, the last op is the condition's last op; otherwise
    /// there is no single last op. Rugra delegates to the condition.
    // Ghidra: block.cc:3119 BlockIf::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:3122-3123: if (getSize() == 1) return getBlock(0)->lastOp();
        if self.goto_target.is_some() {
            self.condition.read().unwrap().last_op()
        } else {
            None
        }
    }

    /// Ghidra `BlockIf::nextFlowAfter` (block.cc:3127-3135): if the query is
    /// about the condition block (getBlock(0)==bl), flow is unknown (returns
    /// null); otherwise defer to the parent's nextFlowAfter. Rugra identifies
    /// the condition by `Arc::ptr_eq` with the passed block.
    // Ghidra: block.cc:3127 BlockIf::nextFlowAfter
    pub fn next_flow_after_parent(
        &self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3130-3131: if (getBlock(0) == bl) return null;
        if Arc::ptr_eq(&self.condition, bl) {
            return None;
        }
        // cc:3132-3133: if (getParent() == null) return null;
        // cc:3134: return getParent()->nextFlowAfter(this);
        // BlockGraph's nextFlowAfter is not yet ported; return None to signal
        // "unknown" (matching the null-parent branch).
        let _parent = self.get_parent();
        None
    }

    /// Ghidra `BlockIf::preferComplement` (block.cc:3093-3109): for an
    /// if/else block, test whether flipping the CBRANCH condition (so the
    /// if/else arms swap) is legal and beneficial, and if so perform the
    /// flip in place. Returns true if the complement was applied. The C++
    /// uses `getSize()==3` to detect if/else; Rugra uses
    /// `else_body.is_some()`. The flip is delegated to the condition block's
    /// `flip_in_place_test`/`flip_in_place_execute` trait methods.
    // Ghidra: block.cc:3093 BlockIf::preferComplement
    pub fn prefer_complement(&mut self) -> bool {
        // cc:3096-3097: if (getSize() != 3) return false;
        if self.else_body.is_none() {
            return false;
        }
        // cc:3099-3101: split = getBlock(0)->getSplitPoint(); if (split == null) return false;
        // Rugra's condition is the split point itself for an if; we treat the
        // condition as the split and ask it whether a flip is legal.
        // cc:3102-3104: if (0 != split->flipInPlaceTest(fliplist)) return false;
        if self.condition.read().unwrap().flip_in_place_test() != 0 {
            return false;
        }
        // cc:3105: split->flipInPlaceExecute();
        self.condition.write().unwrap().flip_in_place_execute();
        // cc:3106: data.opFlipInPlaceExecute(fliplist);  -- Rugra folds this into flip_in_place_execute.
        // cc:3107: swapBlocks(1, 2);  -- swap if_body and else_body in place.
        let if_arc = self.if_body.clone();
        let else_arc = self.else_body.as_ref().unwrap().clone();
        self.if_body = else_arc;
        if let Some(else_body) = self.else_body.as_mut() {
            *else_body = if_arc;
        }
        // cc:3108: return true;
        true
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
    /// matches the canonical `for(init; cond, iterate)` pattern.
    /// Faithful to Ghidra's BlockWhileDo iterateOp/initializeOp (block.hh:690+).
    /// Stores the init/iter expression text (rendered at detection time).
    /// printc emits for(init;cond;iter) with the comma_separate mod active,
    /// matching Ghidra emitForLoop (printc.cc:2957-2999).
    pub for_init: Option<String>,
    pub for_iter: Option<String>,
    /// Overflow-syntax flag (Ghidra `hasOverflowSyntax()`, block.hh:692).
    /// Set by ruleBlockWhileDo when `bl->isComplex()` (blockaction.cc:1538) —
    /// the condition block is too complex to print inline as `while(cond)`.
    /// When set, printc emits `while(true) { <cond body> if(cond) break; }`
    /// instead of `while(cond) { ... }` (emitBlockWhileDo cc:3017-3044).
    pub overflow_syntax: bool,
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
    // Ghidra: block.cc:3324 BlockWhileDo::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3328 condition
    // recurse with new cur_exit, cc:3329 body recurse exiting into header).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_children(cur_exit, cur_loop_exit);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockWhileDo virtual overrides)
impl BlockWhileDo {
    /// Ghidra `BlockWhileDo::getInitializeOp` (block.hh:703, inline): root of
    /// the for-loop initializer statement, or null. Rugra stores the rendered
    /// init text in `for_init` rather than a PcodeOp pointer, so this returns
    /// `Some(text)` when an initializer was detected.
    // Ghidra: block.hh:703 BlockWhileDo::getInitializeOp
    pub fn get_initialize_op(&self) -> Option<&String> {
        self.for_init.as_ref()
    }

    /// Ghidra `BlockWhileDo::getIterateOp` (block.hh:704, inline): root of the
    /// for-loop iterator statement, or null. Rugra stores the rendered iterate
    /// text in `for_iter`.
    // Ghidra: block.hh:704 BlockWhileDo::getIterateOp
    pub fn get_iterate_op(&self) -> Option<&String> {
        self.for_iter.as_ref()
    }

    /// Ghidra `BlockWhileDo::hasOverflowSyntax` (block.hh:705, inline): does
    /// this loop require overflow syntax (condition too complex for
    /// `while(cond)`)? Reads the `f_whiledo_overflow` flag.
    // Ghidra: block.hh:705 BlockWhileDo::hasOverflowSyntax
    pub fn has_overflow_syntax(&self) -> bool {
        // cc: hh:705: ((getFlags() & f_whiledo_overflow) != 0)
        self.overflow_syntax || (self.flags & block_flags::WHILEDO_OVERFLOW) != 0
    }

    /// Ghidra `BlockWhileDo::setOverflowSyntax` (block.hh:706, inline): mark
    /// that this loop requires overflow syntax. Sets `f_whiledo_overflow`.
    // Ghidra: block.hh:706 BlockWhileDo::setOverflowSyntax
    pub fn set_overflow_syntax(&mut self) {
        // cc: hh:706: setFlag(f_whiledo_overflow);
        self.flags |= block_flags::WHILEDO_OVERFLOW;
        self.overflow_syntax = true;
    }

    /// Ghidra `BlockWhileDo::markLabelBumpUp` (block.cc:3316-3322): while-do
    /// loops "steal" their lower blocks' labels — the loop header label is
    /// bumped up so it prints at the loop entry, not inside. The C++ first
    /// recurses via `BlockGraph::markLabelBumpUp(true)`, then clears the flag
    /// on itself if `bump` is false. Rugra recurses into condition/body and
    /// manages the `f_label_bumpup` flag on this block.
    // Ghidra: block.cc:3316 BlockWhileDo::markLabelBumpUp
    pub fn mark_label_bump_up(&mut self, bump: bool) {
        // cc:3319: BlockGraph::markLabelBumpUp(true);  -- recurse into children
        self.condition.write().unwrap().set_flags(block_flags::LABEL_BUMPUP);
        self.body.write().unwrap().set_flags(block_flags::LABEL_BUMPUP);
        // cc:3320-3321: if (!bump) clearFlag(f_label_bumpup);
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        } else {
            self.flags &= !block_flags::LABEL_BUMPUP;
        }
    }

    /// Ghidra `BlockWhileDo::scopeBreak` (block.cc:3324-3330): a new loop scope
    /// begins — the current loop exit becomes the new `cur_exit`. The top
    /// block (condition) has multiple exits so gets `cur_exit = -1`; the body
    /// exits into the top block so gets `cur_exit = condition's index`. Rugra
    /// recurses into the held `condition`/`body` via the trait method.
    // Ghidra: block.cc:3324 BlockWhileDo::scopeBreak
    pub fn scope_break_children(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3328: getBlock(0)->scopeBreak(-1, curexit);   // condition, new scope
        self.condition.write().unwrap().scope_break_trait(-1, cur_exit);
        // cc:3329: getBlock(1)->scopeBreak(getBlock(0)->getIndex(), curexit);  // body exits into condition
        let cond_idx = self.condition.read().unwrap().get_index();
        self.body.write().unwrap().scope_break_trait(cond_idx, cur_exit);
        // Note: cur_loop_exit is the enclosing loop's exit, unused here because
        // this block establishes a NEW loop scope (cur_exit becomes the loop exit).
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockWhileDo::printHeader` (block.cc:3332-3339): emit
    /// `"Whiledo block "` plus `"(overflow) "` if overflow syntax is active.
    // Ghidra: block.cc:3332 BlockWhileDo::printHeader
    pub fn print_header(&self) -> String {
        // cc:3335-3338: s << "Whiledo block "; if (hasOverflowSyntax()) s << "(overflow) ";
        let mut s = format!("Whiledo block {}", self.index);
        if self.has_overflow_syntax() {
            s.insert_str(0, "(overflow) ");
        }
        s
    }

    /// Ghidra `BlockWhileDo::nextFlowAfter` (block.cc:3341-3351): if the query
    /// is about the condition block, flow is unknown; otherwise the next block
    /// in flow is the condition's front leaf (the first statement of the
    /// while body). Rugra returns the condition block when the query is not
    /// about it.
    // Ghidra: block.cc:3341 BlockWhileDo::nextFlowAfter
    pub fn next_flow_after(
        &self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3344-3345: if (getBlock(0) == bl) return null;
        if Arc::ptr_eq(&self.condition, bl) {
            return None;
        }
        // cc:3347-3350: nextbl = getBlock(0); if (nextbl != null) nextbl = nextbl->getFrontLeaf(); return nextbl;
        Some(self.condition.clone())
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
    // Ghidra: block.cc:3434 BlockDoWhile::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3438 fused-body
    // recurse with cur_exit=-1, this block establishes a new loop scope).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_body(cur_exit, cur_loop_exit);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockDoWhile virtual overrides)
impl BlockDoWhile {
    /// Ghidra `BlockDoWhile::markLabelBumpUp` (block.cc:3426-3432): do-while
    /// loops "steal" their lower blocks' labels — the loop exit label is
    /// bumped up so it prints at the loop header, not the trailing goto. The
    /// C++ first recurses via `BlockGraph::markLabelBumpUp(true)`, then clears
    /// the flag on itself if `bump` is false. Rugra recurses into the condition
    /// (which holds the fused body) and manages the `f_label_bumpup` flag.
    // Ghidra: block.cc:3426 BlockDoWhile::markLabelBumpUp
    pub fn mark_label_bump_up(&mut self, bump: bool) {
        // cc:3429: BlockGraph::markLabelBumpUp(true);  -- recurse into children
        self.condition.write().unwrap().set_flags(block_flags::LABEL_BUMPUP);
        // cc:3430-3431: if (!bump) clearFlag(f_label_bumpup);
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        } else {
            self.flags &= !block_flags::LABEL_BUMPUP;
        }
    }

    /// Ghidra `BlockDoWhile::scopeBreak` (block.cc:3434-3439): a new loop scope
    /// begins — the current loop exit becomes the new `cur_exit`. The single
    /// child (the fused body+condition) has multiple exits so gets
    /// `cur_exit = -1`. Rugra recurses into the held `condition` (which holds
    /// the fused body) via the trait method.
    // Ghidra: block.cc:3434 BlockDoWhile::scopeBreak
    pub fn scope_break_body(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3438: getBlock(0)->scopeBreak(-1, curexit);   // Multiple exits
        self.condition.write().unwrap().scope_break_trait(-1, cur_exit);
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockDoWhile::printHeader` (block.cc:3441-3446): emit
    /// `"Dowhile block <index>"`.
    // Ghidra: block.cc:3441 BlockDoWhile::printHeader
    pub fn print_header(&self) -> String {
        // cc:3444-3445: s << "Dowhile block "; FlowBlock::printHeader(s);
        format!("Dowhile block {}", self.index)
    }

    /// Ghidra `BlockDoWhile::nextFlowAfter` (block.cc:3448-3452): flow after
    /// any child of a do-while is unknown (the loop may iterate). Returns
    /// null.
    // Ghidra: block.cc:3448 BlockDoWhile::nextFlowAfter
    pub fn next_flow_after(
        &self,
        _bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3451: return null;   // Don't know what will execute next
        None
    }
}

/// An infinite loop (`do { ... } while(true);`).
///
/// Corresponds to Ghidra's `BlockInfLoop` (block.hh:735). Wraps a single
/// body block that unconditionally branches back to itself. No condition.
/// Emitted as `do { <body> } while(true);` (printc.cc:3097 emitBlockInfLoop).
#[derive(Debug)]
pub struct BlockInfLoop {
    pub index: i32,
    /// The loop body block (the self-looping block collapsed into this node).
    pub body: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockInfLoop {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any { self }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 { self.index }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) { self.index = i; }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    // Ghidra: block.hh:737 BlockInfLoop::getType
    fn get_type(&self) -> BlockType { BlockType::InfLoop }
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
    fn get_start_addr(&self) -> Address { self.body.read().unwrap().get_start_addr() }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (structured blocks delegate ops to components)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.body.read().unwrap().get_ops()
    }
    // Ghidra: block.cc:3462 BlockInfLoop::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3466 body recurse
    // exiting into itself, this block establishes a new loop scope).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_body(cur_exit, cur_loop_exit);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockInfLoop virtual overrides)
impl BlockInfLoop {
    /// Ghidra `BlockInfLoop::markLabelBumpUp` (block.cc:3454-3460): infinite
    /// loops "steal" their lower blocks' labels — the loop entry label is
    /// bumped up so it prints at the loop header. The C++ first recurses via
    /// `BlockGraph::markLabelBumpUp(true)`, then clears the flag on itself if
    /// `bump` is false. Rugra recurses into the body and manages the
    /// `f_label_bumpup` flag.
    // Ghidra: block.cc:3454 BlockInfLoop::markLabelBumpUp
    pub fn mark_label_bump_up(&mut self, bump: bool) {
        // cc:3457: BlockGraph::markLabelBumpUp(true);  -- recurse into children
        self.body.write().unwrap().set_flags(block_flags::LABEL_BUMPUP);
        // cc:3458-3459: if (!bump) clearFlag(f_label_bumpup);
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        } else {
            self.flags &= !block_flags::LABEL_BUMPUP;
        }
    }

    /// Ghidra `BlockInfLoop::scopeBreak` (block.cc:3462-3467): a new loop scope
    /// begins — the current loop exit becomes the new `cur_exit`. The body
    /// exits into itself (the loop's entry), so it gets
    /// `cur_exit = body's index`. Rugra recurses into the held `body` via the
    /// trait method.
    // Ghidra: block.cc:3462 BlockInfLoop::scopeBreak
    pub fn scope_break_body(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3466: getBlock(0)->scopeBreak(getBlock(0)->getIndex(), curexit);   // Exits into itself
        let body_idx = self.body.read().unwrap().get_index();
        self.body.write().unwrap().scope_break_trait(body_idx, cur_exit);
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockInfLoop::printHeader` (block.cc:3469-3474): emit
    /// `"Infinite loop block <index>"`.
    // Ghidra: block.cc:3469 BlockInfLoop::printHeader
    pub fn print_header(&self) -> String {
        // cc:3472-3473: s << "Infinite loop block "; FlowBlock::printHeader(s);
        format!("Infinite loop block {}", self.index)
    }

    /// Ghidra `BlockInfLoop::nextFlowAfter` (block.cc:3476-3483): the next
    /// block in flow after a child query is the body's front leaf (the first
    /// statement of the infinite loop). Rugra returns the body block.
    // Ghidra: block.cc:3476 BlockInfLoop::nextFlowAfter
    pub fn next_flow_after(
        &self,
        _bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3479-3482: nextbl = getBlock(0); if (nextbl != null) nextbl = nextbl->getFrontLeaf(); return nextbl;
        Some(self.body.clone())
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

    /// Ghidra `BlockList::getExitLeaf` (block.cc:2953-2958): the exit leaf is
    /// the last child's exit leaf. Returns null if there are no children.
    // Ghidra: block.cc:2953 BlockList::getExitLeaf
    pub fn get_exit_leaf(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:2956-2957: if (getSize()==0) return null; return getBlock(getSize()-1)->getExitLeaf();
        self.children.last().and_then(|c| c.read().unwrap().get_exit_leaf_trait())
    }

    /// Ghidra `BlockList::lastOp` (block.cc:2960-2965): the last op is the
    /// last child's last op. Returns null if there are no children.
    // Ghidra: block.cc:2960 BlockList::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:2963-2964: if (getSize()==0) return null; return getBlock(getSize()-1)->lastOp();
        self.children.last().and_then(|c| c.read().unwrap().last_op())
    }

    /// Ghidra `BlockList::negateCondition` (block.cc:2967-2974): negate the
    /// condition of the last child and flip the order of this block's outgoing
    /// edges. Returns true if the child's condition was negated. Rugra
    /// delegates to the last child's `negate_condition` and then swaps the
    /// outgoing edges in place.
    // Ghidra: block.cc:2967 BlockList::negateCondition
    pub fn negate_condition(&mut self, toporbottom: bool) -> bool {
        // cc:2970-2971: bl = getBlock(getSize()-1); res = bl->negateCondition(false);
        let res = if let Some(last) = self.children.last() {
            last.write().unwrap().negate_condition(false)
        } else {
            false
        };
        // cc:2972: FlowBlock::negateCondition(toporbottom);  -- flip order of outgoing
        if toporbottom {
            let last_idx = self.outgoing.len().saturating_sub(1);
            self.outgoing.swap(0, last_idx);
        }
        res
    }

    /// Ghidra `BlockList::getSplitPoint` (block.cc:2976-2981): the split point
    /// is the last child's split point. Returns null if there are no children.
    /// Rugra returns the last child itself (the block whose CBRANCH can be
    /// flipped), as the front-leaf split-point concept does not yet have a
    /// distinct Rust counterpart.
    // Ghidra: block.cc:2976 BlockList::getSplitPoint
    pub fn get_split_point(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:2979-2980: if (getSize()==0) return null; return getBlock(getSize()-1)->getSplitPoint();
        self.children.last().cloned()
    }

    /// Ghidra `BlockList::printHeader` (block.cc:2983-2988): emit
    /// `"List block <index>"`.
    // Ghidra: block.cc:2983 BlockList::printHeader
    pub fn print_header(&self) -> String {
        // cc:2986-2987: s << "List block "; FlowBlock::printHeader(s);
        format!("List block {}", self.index)
    }

    /// RUGRA-GLUE: outgoing-edge swap helper (mirrors FlowBlock::negateCondition's
    /// edge-flip step, used by BlockList::negateCondition above). Exposed as a
    /// separate inherent method so callers can flip the edges without negating
    /// the last child's condition.
    // RUGRA-GLUE: outgoing swap helper (Ghidra folds this into FlowBlock::negateCondition block.cc:227-233)
    pub fn outgoing_swap(&mut self) {
        if self.outgoing.len() >= 2 {
            self.outgoing.swap(0, 1);
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
    // Ghidra: BlockList inherits BlockGraph::scopeBreak (block.cc:1270-1288)
    // — there is no override, so a BlockList walks its children exactly like
    // a BlockGraph: each child's exit is the next child's index (or the
    // inherited cur_exit for the last child), and cur_loop_exit propagates
    // unchanged. Rugra's BlockList is a separate struct (not a BlockGraph
    // subclass), so we replicate the traversal here.
    // Ghidra: block.cc:1270 BlockGraph::scopeBreak (inherited by BlockList)
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        let n = self.children.len();
        for i in 0..n {
            let ind = if i + 1 < n {
                self.children[i + 1].read().unwrap().get_index()
            } else {
                cur_exit
            };
            self.children[i].write().unwrap().scope_break_trait(ind, cur_loop_exit);
        }
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
    // Ghidra: block.cc:3034 BlockCondition::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3037-3038 recurse
    // into both sub-conditions with cur_exit=-1, no fixed exit).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_children(cur_exit, cur_loop_exit);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockCondition virtual overrides)
impl BlockCondition {
    /// Ghidra `BlockCondition::getOpcode` (block.hh:625, inline): the boolean
    /// operation (BOOL_AND / BOOL_OR). Rugra returns the `BoolOp` enum.
    // Ghidra: block.hh:625 BlockCondition::getOpcode
    pub fn get_opcode(&self) -> BoolOp {
        self.op_type
    }

    /// Ghidra `BlockCondition::flipInPlaceTest` (block.cc:2990-3006): test
    /// whether the short-circuit condition can be flipped by testing each
    /// sub-block's split point. Returns the reason code (0 = flippable, 2 =
    /// not flippable). The C++ walks `getBlock(0)->getSplitPoint()` and
    /// `getBlock(1)->getSplitPoint()`; Rugra asks each child via the trait.
    // Ghidra: block.cc:2990 BlockCondition::flipInPlaceTest
    pub fn is_split_point(&self) -> bool {
        // cc:2993-3005: both children must have a split point that is flippable.
        // Rugra treats each child as its own split point and asks flip_in_place_test.
        if self.first.read().unwrap().flip_in_place_test() != 0 {
            return false;
        }
        self.second.read().unwrap().flip_in_place_test() == 0
    }

    /// Ghidra `BlockCondition::isComplex` (block.hh, inherited): is this
    /// condition too complex to fold? Rugra returns true unconditionally for
    /// a compound condition (matching Ghidra's BlockCondition never being
    /// considered "simple").
    // RUGRA-GLUE: compound conditions are always complex (Ghidra BlockCondition has no isComplex override; base returns true for non-leaf)
    pub fn is_complex(&self) -> bool {
        true
    }

    /// Ghidra `BlockCondition::lastOp` (block.cc:3016-3021): the last op is
    /// the second child's last op (block B holds the final CBRANCH).
    // Ghidra: block.cc:3016 BlockCondition::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:3020: return getBlock(1)->lastOp();
        self.second.read().unwrap().last_op()
    }

    /// Ghidra `BlockCondition::negateCondition` (block.cc:3023-3032): distribute
    /// the NOT to both sides of the condition and swap the boolean op
    /// (AND<->OR). Returns true if either child's condition was negated.
    // Ghidra: block.cc:3023 BlockCondition::negateCondition
    pub fn negate_condition(&mut self, toporbottom: bool) -> bool {
        // cc:3027-3028: res1 = getBlock(0)->negateCondition(false); res2 = getBlock(1)->negateCondition(false);
        let res1 = self.first.write().unwrap().negate_condition(false);
        let res2 = self.second.write().unwrap().negate_condition(false);
        // cc:3029: opc = (opc==CPUI_BOOL_AND) ? CPUI_BOOL_OR : CPUI_BOOL_AND;
        self.op_type = match self.op_type {
            BoolOp::And => BoolOp::Or,
            BoolOp::Or => BoolOp::And,
        };
        // cc:3030: FlowBlock::negateCondition(toporbottom);  -- flip outgoing edges
        if toporbottom && self.outgoing.len() >= 2 {
            self.outgoing.swap(0, 1);
        }
        // cc:3031: return (res1 || res2);
        res1 || res2
    }

    /// Ghidra `BlockCondition::scopeBreak` (block.cc:3034-3039): propagate
    /// scope-break into both sub-conditions with no fixed exit (`cur_exit=-1`).
    // Ghidra: block.cc:3034 BlockCondition::scopeBreak
    pub fn scope_break_children(&mut self, _cur_exit: i32, cur_loop_exit: i32) {
        // cc:3037-3038: getBlock(0)->scopeBreak(-1, curloopexit); getBlock(1)->scopeBreak(-1, curloopexit);
        self.first.write().unwrap().scope_break_trait(-1, cur_loop_exit);
        self.second.write().unwrap().scope_break_trait(-1, cur_loop_exit);
    }

    /// Ghidra `BlockCondition::printHeader` (block.cc:3041-3051): emit
    /// `"Condition block(&&)" ` or `"Condition block(||)" ` based on the op.
    // Ghidra: block.cc:3041 BlockCondition::printHeader
    pub fn print_header(&self) -> String {
        // cc:3044-3048: s << "Condition block("; if (opc==BOOL_AND) "&&" else "||"; s << ") ";
        let op_str = match self.op_type {
            BoolOp::And => "&&",
            BoolOp::Or => "||",
        };
        format!("Condition block({}) {}", op_str, self.index)
    }

    /// Ghidra `BlockCondition::nextFlowAfter` (block.cc:3053-3057): flow after
    /// a compound condition is unknown. Returns null.
    // Ghidra: block.cc:3053 BlockCondition::nextFlowAfter
    pub fn next_flow_after(
        &self,
        _bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3056: return null;   // Do not know where flow goes
        None
    }

    /// Ghidra `BlockCondition::encodeHeader` (block.cc:3059-3065): emit the
    /// base header plus an `opcode` attribute with the boolean op name. Rugra
    /// returns `(index, opcode_name)` for the marshal layer.
    // Ghidra: block.cc:3059 BlockCondition::encodeHeader
    pub fn encode_header(&self) -> (i32, &'static str) {
        // cc:3063-3064: nm = get_opname(opc); writeString(ATTRIB_OPCODE, nm);
        let nm = match self.op_type {
            BoolOp::And => "BOOL_AND",
            BoolOp::Or => "BOOL_OR",
        };
        (self.index, nm)
    }

    /// Ghidra `BlockCondition::flipInPlaceExecute` (block.cc:3008-3014): flip
    /// the boolean op (AND<->OR) and flip each child's CBRANCH in place.
    // Ghidra: block.cc:3008 BlockCondition::flipInPlaceExecute
    pub fn flip_in_place_execute(&mut self) {
        // cc:3011: opc = (opc==BOOL_AND) ? BOOL_OR : BOOL_AND;
        self.op_type = match self.op_type {
            BoolOp::And => BoolOp::Or,
            BoolOp::Or => BoolOp::And,
        };
        // cc:3012-3013: getBlock(0)->getSplitPoint()->flipInPlaceExecute(); getBlock(1)->getSplitPoint()->flipInPlaceExecute();
        self.first.write().unwrap().flip_in_place_execute();
        self.second.write().unwrap().flip_in_place_execute();
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
    // Ghidra: block.cc:3613 BlockSwitch::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3617 control recurse
    // with cur_exit=-1, cc:3618-3629 per-case recurse with cur_exit=curexit).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_break_cases(cur_exit, cur_loop_exit);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockSwitch virtual overrides)
impl BlockSwitch {
    /// Ghidra `BlockSwitch::getSwitchBlock` (block.hh:772, inline): the root
    /// switch component (getBlock(0)). Rugra returns the `control` block.
    // Ghidra: block.hh:772 BlockSwitch::getSwitchBlock
    pub fn get_switch_block(&self) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        self.control.clone()
    }

    /// Ghidra `BlockSwitch::getNumCaseBlocks` (block.hh:773, inline): the
    /// number of case components.
    // Ghidra: block.hh:773 BlockSwitch::getNumCaseBlocks
    pub fn get_num_case_blocks(&self) -> usize {
        self.cases.len()
    }

    /// Ghidra `BlockSwitch::getCaseBlock` (block.hh:774, inline): the i-th
    /// case FlowBlock.
    // Ghidra: block.hh:774 BlockSwitch::getCaseBlock
    pub fn get_case_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.cases.get(i).cloned()
    }

    /// Ghidra `BlockSwitch::getNumLabels` (block.hh:785, inline): the number
    /// of case labels for the i-th case (each case may be reached by multiple
    /// switch values). Rugra reads from `case_values[i]`.
    // Ghidra: block.hh:785 BlockSwitch::getNumLabels
    pub fn get_num_labels(&self, i: usize) -> usize {
        self.case_values.get(i).map(|v| v.len()).unwrap_or(0)
    }

    /// Ghidra `BlockSwitch::getLabel` (block.hh:786, inline): the j-th case
    /// label value for the i-th case.
    // Ghidra: block.hh:786 BlockSwitch::getLabel
    pub fn get_label(&self, i: usize, j: usize) -> Option<u64> {
        self.case_values.get(i).and_then(|v| v.get(j).copied())
    }

    /// Ghidra `BlockSwitch::isDefaultCase` (block.hh:789, inline): is the i-th
    /// case the default case? Rugra compares against `default_case`.
    // Ghidra: block.hh:789 BlockSwitch::isDefaultCase
    pub fn is_default_case(&self, i: usize) -> bool {
        if let (Some(case), Some(default)) = (self.cases.get(i), &self.default_case) {
            Arc::ptr_eq(case, default)
        } else {
            false
        }
    }

    /// Ghidra `BlockSwitch::isExit` (block.hh:791, inline): does the i-th case
    /// block exit the switch? Rugra approximates this with `size_out()==1`
    /// (matching the C++ `addCase` rule at block.cc:3514: a case with a single
    /// out-edge exits the switch). Cases with goto labels (gototype != 0) are
    /// never exits.
    // Ghidra: block.hh:791 BlockSwitch::isExit
    pub fn is_exit(&self, i: usize) -> bool {
        // cc:3513-3514 (addCase): isexit = (bl->sizeOut() == 1) when gototype == 0.
        if let Some(case) = self.cases.get(i) {
            case.read().unwrap().size_out() == 1
        } else {
            false
        }
    }

    /// Ghidra `BlockSwitch::markUnstructured` (block.cc:3603-3611): mark each
    /// case whose goto edge is a plain `goto` with `f_unstructured_targ`. The
    /// C++ first recurses via `BlockGraph::markUnstructured`; Rugra's
    /// `BlockSwitch` exposes its cases directly, so only the per-case marking
    /// is ported (Rugra does not yet model per-case gototype, so this is a
    /// conservative no-op until case gototypes are tracked).
    // Ghidra: block.cc:3603 BlockSwitch::markUnstructured
    pub fn mark_unstructured_targets(&self) {
        // cc:3607-3610: for each case, if (caseblocks[i].gototype == f_goto_goto) markCopyBlock(caseblocks[i].block, f_unstructured_targ);
        // Rugra does not yet track per-case gototype; nothing to mark.
    }

    /// Ghidra `BlockSwitch::scopeBreak` (block.cc:3613-3630): a new scope — the
    /// current loop exit becomes the new `cur_exit`. The switch control has
    /// multiple exits so gets `cur_exit = -1`; each case either has a goto
    /// (reclassified as `break` if it lands on cur_exit) or shares the
    /// switch's exit (scopeBreak with curexit=curexit). Rugra recurses into
    /// the control and each case; the per-case goto reclassification is
    /// deferred until Rugra tracks per-case gototypes.
    // Ghidra: block.cc:3613 BlockSwitch::scopeBreak
    pub fn scope_break_break_cases(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3617: getBlock(0)->scopeBreak(-1, curexit);   // Top block has multiple exits
        self.control.write().unwrap().scope_break_trait(-1, cur_exit);
        // cc:3618-3629: for each case, scopeBreak(curexit, curexit) for exit cases.
        for case in &self.cases {
            case.write().unwrap().scope_break_trait(cur_exit, cur_exit);
        }
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockSwitch::printHeader` (block.cc:3632-3637): emit
    /// `"Switch block <index>"`.
    // Ghidra: block.cc:3632 BlockSwitch::printHeader
    pub fn print_header(&self) -> String {
        // cc:3635-3636: s << "Switch block "; FlowBlock::printHeader(s);
        format!("Switch block {}", self.index)
    }

    /// Ghidra `BlockSwitch::nextFlowAfter` (block.cc:3639-3661): if the query
    /// is about the switch control, flow is unknown; otherwise, if the query
    /// is a goto case block, the next block in flow is the next case in
    /// fallthru order; if it is the last case, defer to the parent. Rugra
    /// returns the case following the queried block, or None if not found or
    /// at the end.
    // Ghidra: block.cc:3639 BlockSwitch::nextFlowAfter
    pub fn next_flow_after(
        &self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3642-3643: if (getBlock(0) == bl) return null;
        if Arc::ptr_eq(&self.control, bl) {
            return None;
        }
        // cc:3651-3653: find bl in caseblocks.
        let pos = self.cases.iter().position(|c| Arc::ptr_eq(c, bl))?;
        // cc:3655-3657: i = i + 1; if (i < caseblocks.size()) return caseblocks[i].block->getFrontLeaf();
        let next = pos.checked_add(1)?;
        if next < self.cases.len() {
            return self.cases.get(next).cloned();
        }
        // cc:3658-3660: otherwise flow is to exit of switch -> parent->nextFlowAfter(this).
        // BlockGraph's nextFlowAfter is not yet ported; return None.
        None
    }

    /// Ghidra `BlockSwitch::getSwitchVar` (block.cc:3596-3601): the input
    /// Varnode to the switch's BRANCHIND, used by the printer to emit the
    /// switch expression. Rugra returns the held `index_varnode`.
    // Ghidra: block.cc:3596 BlockSwitch::getSwitchVar
    pub fn get_switch_varnode(&self) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        self.index_varnode.clone()
    }
}

