//! Control flow structuring actions
//!
//! Corresponds to Ghidra's `blockaction.hh`

use crate::action::{action_status, Action};
use crate::address::Address;
use crate::block::{BlockBasic, BlockCondition, BlockGraph, BlockIf, BlockList, BlockSwitch, BlockWhileDo, BoolOp, FlowBlock};
use crate::error::Result;
use crate::funcdata::Funcdata;
use crate::opcodes::OpCode;
use std::sync::{Arc, RwLock};

/// Action for recovering high-level control flow structures
///
/// Corresponds to Ghidra's `ActionBlockStructure`. This action transforms
/// a flat basic block graph into a hierarchical structure of if, while,
/// and other high-level blocks.
pub struct ActionBlockStructure;

impl ActionBlockStructure {
    /// Create a new ActionBlockStructure instance
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionBlockStructure {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Check if already structured
        if fd.sblocks.get_size() != 0 {
            return Ok(action_status::NO_CHANGE);
        }

        // Need at least 1 basic block to structure
        if fd.bblocks.get_size() == 0 {
            return Ok(action_status::NO_CHANGE);
        }

        // Build a copy of the basic block graph into the structure graph
        build_copy(&mut fd.sblocks, &fd.bblocks);
        eprintln!("[BLOCKSTRUCT] {} build_copy done sblocks={}", fd.name, fd.sblocks.get_size());

        // Collapse structured patterns iteratively
        let mut collapse = CollapseStructure::new(&mut fd.sblocks, &fd.name);
        collapse.collapse_all();
        eprintln!("[BLOCKSTRUCT] {} collapse_all done blocks={}", fd.name, fd.sblocks.get_size());

        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "blockstructure"
    }
}

/// Build a copy of the basic block graph into the structure graph
///
/// Corresponds to Ghidra's `BlockGraph::buildCopy`
fn build_copy(sblocks: &mut BlockGraph, bblocks: &BlockGraph) {
    // Clear existing structure blocks
    sblocks.clear();

    // Copy each basic block
    for i in 0..bblocks.get_size() {
        if let Some(bb) = bblocks.get_block(i) {
            let bb_read = bb.read().unwrap();
            let new_block = Arc::new(RwLock::new(BlockBasic::new(
                bb_read.get_index(),
                bb_read.get_start_addr(),
            )));

            // Copy operations
            {
                let mut new_block_write = new_block.write().unwrap();
                new_block_write.ops = bb_read.get_ops();
                new_block_write.flags = bb_read.get_flags();
            }

            sblocks.add_block(new_block);
        }
    }

    // Copy edges — collect first, then add (avoids borrow conflicts)
    let mut edges_to_add: Vec<(usize, usize)> = Vec::new();
    for i in 0..bblocks.get_size() {
        if let Some(bb) = bblocks.get_block(i) {
            let bb_read = bb.read().unwrap();
            let size_out = bb_read.size_out();
            for j in 0..size_out {
                if let Some(edge) = bb_read.get_out(j) {
                    let target_idx = edge.point.read().unwrap().get_index() as usize;
                    edges_to_add.push((i, target_idx));
                }
            }
        }
    }

    // Now add all edges without holding any read locks
    for (from_idx, to_idx) in edges_to_add {
        if let (Some(from), Some(to)) = (sblocks.get_block(from_idx), sblocks.get_block(to_idx)) {
            sblocks.add_edge(from, to);
        }
    }
}

/// An edge considered for unstructuring (goto) by the loop-ordering pass.
/// Faithful to Ghidra's `FloatingEdge` (blockaction.hh). Records a (from, to)
/// block pair; the structurer may later mark the `from` out-edge as a goto.
#[derive(Clone, Debug)]
pub struct FloatingEdge {
    pub from_idx: i32,
    pub to_idx: i32,
}

/// A natural loop detected during orderLoopBodies.
///
/// Faithful to Ghidra's `LoopBody` class (blockaction.cc:46-490). Holds the
/// loop head, tails (back-edge sources), exit block, exit edges, nesting
/// depth, and immediate container. The methods collect the loop body, pick a
/// single exit block, extend the body to dominated blocks, and label exit
/// edges for the TraceDAG pass.
pub struct LoopBody {
    /// Loop head (the back-edge target / loop entry).
    pub head: i32,
    /// Back-edge sources (tails). Multiple if the loop has several back-edges.
    pub tails: Vec<i32>,
    /// The chosen single exit block (may be -1 if none).
    pub exit_block: i32,
    /// Edges leaving the loop body (from, to) block indices.
    pub exit_edges: Vec<FloatingEdge>,
    /// Nesting depth (incremented by each containing loop).
    pub depth: i32,
    /// Immediate containing LoopBody index in the loop order (-1 = top-level).
    pub immed_container: i32,
    /// Number of head/tail nodes in the body (set by find_base).
    pub unique_count: usize,
}

impl LoopBody {
    pub fn new(head: i32, tail: i32) -> Self {
        Self {
            head,
            tails: vec![tail],
            exit_block: -1,
            exit_edges: Vec::new(),
            depth: 0,
            immed_container: -1,
            unique_count: 0,
        }
    }

    pub fn add_tail(&mut self, tail: i32) {
        self.tails.push(tail);
    }

    /// Collect all blocks reaching a tail without going through head.
    /// Faithful to `LoopBody::findBase` (blockaction.cc:119-144). Marks each
    /// collected block via set_mark. Returns the body block indices.
    pub fn find_base(&mut self, graph: &BlockGraph) -> Vec<i32> {
        let mut body: Vec<i32> = Vec::new();
        // Mark head.
        if let Some(h) = graph.get_block(self.head as usize) {
            h.write().unwrap().set_mark();
        }
        body.push(self.head);
        for &tail in &self.tails {
            if let Some(t) = graph.get_block(tail as usize) {
                if !t.read().unwrap().is_mark() {
                    t.write().unwrap().set_mark();
                    body.push(tail);
                }
            }
        }
        self.unique_count = body.len();
        // Walk backwards from each body node, marking reachable predecessors
        // (skipping goto/irreducible in-edges), until no new nodes.
        let mut i = 1;
        while i < body.len() {
            let cur = body[i];
            i += 1;
            if let Some(blk) = graph.get_block(cur as usize) {
                let preds: Vec<(usize, i32)> = {
                    let b = blk.read().unwrap();
                    let n = b.size_in();
                    (0..n)
                        .filter(|&k| !b.is_goto_in(k))
                        .filter_map(|k| b.get_in(k).map(|e| (k, e.point.read().unwrap().get_index())))
                        .collect()
                };
                for (_, pred_idx) in preds {
                    if let Some(pblk) = graph.get_block(pred_idx as usize) {
                        if !pblk.read().unwrap().is_mark() {
                            pblk.write().unwrap().set_mark();
                            body.push(pred_idx);
                        }
                    }
                }
            }
        }
        body
    }

    /// Extend the body to blocks reachable ONLY from head (dominated by the
    /// loop entry), excluding the exit block. Faithful to `LoopBody::extend`
    /// (blockaction.cc:150-176). Uses visit_count to count in-edges.
    pub fn extend(&self, body: &mut Vec<i32>, graph: &BlockGraph) {
        let mut trial: Vec<i32> = Vec::new();
        let mut i = 0;
        while i < body.len() {
            let bl = body[i];
            i += 1;
            let succs: Vec<(usize, i32)> = {
                if let Some(blk) = graph.get_block(bl as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&j| !b.is_goto_out(j))
                        .filter_map(|j| b.get_out(j).map(|e| (j, e.point.read().unwrap().get_index())))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for (_, succ_idx) in succs {
                if succ_idx == self.exit_block {
                    continue;
                }
                let marked = graph.get_block(succ_idx as usize)
                    .map(|b| b.read().unwrap().is_mark()).unwrap_or(false);
                if marked {
                    continue;
                }
                let count = graph.get_block(succ_idx as usize)
                    .map(|b| b.read().unwrap().get_visit_count()).unwrap_or(0);
                if count == 0 {
                    trial.push(succ_idx);
                }
                if let Some(sblk) = graph.get_block(succ_idx as usize) {
                    sblk.write().unwrap().set_visit_count(count + 1);
                    // If all in-edges now accounted for, absorb into body.
                    let total_in = sblk.read().unwrap().size_in() as i32;
                    if count + 1 == total_in {
                        sblk.write().unwrap().set_mark();
                        body.push(succ_idx);
                    }
                }
            }
        }
        // Clear visit counts.
        for &t in &trial {
            if let Some(tblk) = graph.get_block(t as usize) {
                tblk.write().unwrap().set_visit_count(0);
            }
        }
    }

    /// Pick a single exit block. Faithful to `LoopBody::findExit`
    /// (blockaction.cc:182-239). Prefers exits from tails, then head, then
    /// middle body nodes. If there's a container, the exit must be in it.
    pub fn find_exit(&mut self, body: &[i32], graph: &BlockGraph) {
        let mut trial_exit: Vec<i32> = Vec::new();
        // Exits from tails.
        for &tail in &self.tails {
            let outs: Vec<i32> = {
                if let Some(blk) = graph.get_block(tail as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&i| !b.is_goto_out(i))
                        .filter_map(|i| b.get_out(i).map(|e| e.point.read().unwrap().get_index()))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for cur in outs {
                let marked = graph.get_block(cur as usize)
                    .map(|b| b.read().unwrap().is_mark()).unwrap_or(false);
                if !marked {
                    if self.immed_container == -1 {
                        self.exit_block = cur;
                        return;
                    }
                    trial_exit.push(cur);
                }
            }
        }
        // Exits from middle body nodes (skip head/tail indices).
        for (i, &bl) in body.iter().enumerate() {
            if i > 0 && i < self.unique_count {
                continue;
            }
            let outs: Vec<i32> = {
                if let Some(blk) = graph.get_block(bl as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&j| !b.is_goto_out(j))
                        .filter_map(|j| b.get_out(j).map(|e| e.point.read().unwrap().get_index()))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for cur in outs {
                let marked = graph.get_block(cur as usize)
                    .map(|b| b.read().unwrap().is_mark()).unwrap_or(false);
                if !marked {
                    if self.immed_container == -1 {
                        self.exit_block = cur;
                        return;
                    }
                    trial_exit.push(cur);
                }
            }
        }
        self.exit_block = -1;
        if trial_exit.is_empty() {
            return;
        }
        // If there's a container, the exit must be marked in the container's body.
        // We approximate: pick the first trial exit (the container-constrained
        // selection requires the container's body marks, which are transient;
        // for now use the first trial exit).
        self.exit_block = trial_exit[0];
    }

    /// Reorder tails so a tail with an edge to exit_block is first.
    /// Faithful to `LoopBody::orderTails` (blockaction.cc:245-264).
    pub fn order_tails(&mut self, graph: &BlockGraph) {
        if self.tails.len() <= 1 || self.exit_block == -1 {
            return;
        }
        let mut pref = None;
        for (idx, &tail) in self.tails.iter().enumerate() {
            let outs: Vec<i32> = {
                if let Some(blk) = graph.get_block(tail as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n).filter_map(|j| b.get_out(j).map(|e| e.point.read().unwrap().get_index())).collect()
                } else {
                    Vec::new()
                }
            };
            if outs.iter().any(|&o| o == self.exit_block) {
                pref = Some(idx);
                break;
            }
        }
        if let Some(prefidx) = pref {
            if prefidx != 0 {
                self.tails.swap(0, prefidx);
            }
        }
    }

    /// Label edges leaving the body. Faithful to `LoopBody::labelExitEdges`
    /// (blockaction.cc:270-320). Priority: middle-exit edges first, then head,
    /// then tails (reverse), then edges-to-exitblock last.
    pub fn label_exit_edges(&mut self, body: &[i32], graph: &BlockGraph) {
        let mut to_exit_block: Vec<i32> = Vec::new();
        // Middle nodes (non-head/tail).
        for &bl in body.iter().skip(self.unique_count) {
            let outs: Vec<(i32, i32)> = {
                if let Some(blk) = graph.get_block(bl as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&k| !b.is_goto_out(k))
                        .filter_map(|k| b.get_out(k).map(|e| (e.point.read().unwrap().get_index(), k as i32)))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for (tgt, _slot) in outs {
                if tgt == self.exit_block {
                    to_exit_block.push(bl);
                } else {
                    let marked = graph.get_block(tgt as usize)
                        .map(|b| b.read().unwrap().is_mark()).unwrap_or(false);
                    if !marked {
                        self.exit_edges.push(FloatingEdge { from_idx: bl, to_idx: tgt });
                    }
                }
            }
        }
        // Head exits.
        let head_outs: Vec<(i32, i32)> = {
            if let Some(blk) = graph.get_block(self.head as usize) {
                let b = blk.read().unwrap();
                let n = b.size_out();
                (0..n)
                    .filter(|&k| !b.is_goto_out(k))
                    .filter_map(|k| b.get_out(k).map(|e| (e.point.read().unwrap().get_index(), k as i32)))
                    .collect()
            } else {
                Vec::new()
            }
        };
        for (tgt, _slot) in head_outs {
            if tgt == self.exit_block {
                to_exit_block.push(self.head);
            } else {
                let marked = graph.get_block(tgt as usize)
                    .map(|b| b.read().unwrap().is_mark()).unwrap_or(false);
                if !marked {
                    self.exit_edges.push(FloatingEdge { from_idx: self.head, to_idx: tgt });
                }
            }
        }
        // Tail exits (reverse order).
        for &tail in self.tails.iter().rev() {
            if tail == self.head {
                continue;
            }
            let outs: Vec<(i32, i32)> = {
                if let Some(blk) = graph.get_block(tail as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&k| !b.is_goto_out(k))
                        .filter_map(|k| b.get_out(k).map(|e| (e.point.read().unwrap().get_index(), k as i32)))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for (tgt, _slot) in outs {
                if tgt == self.exit_block {
                    to_exit_block.push(tail);
                } else {
                    let marked = graph.get_block(tgt as usize)
                        .map(|b| b.read().unwrap().is_mark()).unwrap_or(false);
                    if !marked {
                        self.exit_edges.push(FloatingEdge { from_idx: tail, to_idx: tgt });
                    }
                }
            }
        }
        // Edges to exit block go last.
        for bl in to_exit_block {
            self.exit_edges.push(FloatingEdge { from_idx: bl, to_idx: self.exit_block });
        }
    }

    /// Record contained subloops and set depth/immed_container.
    /// Faithful to `LoopBody::labelContainments` (blockaction.cc:327-358).
    pub fn label_containments(
        &mut self,
        body: &[i32],
        loop_order: &[LoopBody],
        self_idx: usize,
    ) {
        let mut contain: Vec<usize> = Vec::new();
        for &curblock in body {
            if curblock == self.head {
                continue;
            }
            // Find a subloop whose head == curblock.
            if let Some(sub_idx) = loop_order.iter().position(|lb| lb.head == curblock && lb.head != self.head) {
                // Avoid matching self.
                if sub_idx != self_idx {
                    contain.push(sub_idx);
                }
            }
        }
        // We can't mutate other LoopBodies here (borrow); the caller updates
        // depth/immed_container based on containment. This method records which
        // subloops are contained; the depth bookkeeping is done in order_loop_bodies.
        let _ = contain;
    }

    /// Emit edges that exit this loop body to a likely-goto list, with proper
    /// priority: exit edges first (official exit edge held last among them),
    /// then back-edges (tails→head) in reverse tail order. Faithful to
    /// `LoopBody::emitLikelyEdges` (blockaction.cc:364-412). The resulting list
    /// orders candidate goto edges so the structurer prefers keeping the
    /// official loop exit structured and marks the others as goto.
    pub fn emit_likely_edges(&self, likely: &mut Vec<FloatingEdge>, graph: &BlockGraph) {
        // Exit edges, holding off the official exit-to-exitblock edge until the
        // end (so it appears right before the final back-edge).
        let mut hold: Option<FloatingEdge> = None;
        let n = self.exit_edges.len();
        for (i, fe) in self.exit_edges.iter().enumerate() {
            if i == n.saturating_sub(1) && fe.to_idx == self.exit_block {
                hold = Some(fe.clone());
                continue;
            }
            likely.push(fe.clone());
        }
        // Back-edges in reverse tail order; the held exit edge goes right before
        // the final (first-tail) back-edge.
        let tails_len = self.tails.len();
        for (rev_i, &tail) in self.tails.iter().rev().enumerate() {
            if rev_i == tails_len - 1 {
                if let Some(h) = hold.take() {
                    likely.push(h);
                }
            }
            // Any out-edge from this tail back to head is a back-edge.
            if let Some(blk) = graph.get_block(tail as usize) {
                let outs: Vec<i32> = {
                    let b = blk.read().unwrap();
                    let nn = b.size_out();
                    (0..nn).filter_map(|j| b.get_out(j).map(|e| e.point.read().unwrap().get_index())).collect()
                };
                for tgt in outs {
                    if tgt == self.head {
                        likely.push(FloatingEdge { from_idx: tail, to_idx: self.head });
                    }
                }
            }
        }
    }
}

/// Merge LoopBodies sharing the same head. Faithful to
/// `LoopBody::mergeIdenticalHeads` (blockaction.cc:446-467). Bodies with the
/// same head have their tails merged; subsumed bodies are marked (head=-1).
pub fn merge_identical_heads(loop_order: &mut Vec<LoopBody>) {
    if loop_order.is_empty() {
        return;
    }
    let mut i = 0;
    let mut j = 1;
    while j < loop_order.len() {
        if loop_order[j].head == loop_order[i].head {
            // Merge tail[0] of j into i; mark j subsumed.
            let tail = loop_order[j].tails[0];
            loop_order[i].add_tail(tail);
            loop_order[j].head = -1; // subsumed
        } else {
            i = j;
        }
        j += 1;
    }
    loop_order.retain(|lb| lb.head != -1);
}

/// Clear marks on a set of blocks. Faithful to `LoopBody::clearMarks`
/// (blockaction.cc:1039).
pub fn clear_marks(body: &[i32], graph: &BlockGraph) {
    for &bl in body {
        if let Some(blk) = graph.get_block(bl as usize) {
            blk.write().unwrap().clear_mark();
        }
    }
}


/// Structure for iteratively collapsing control flow patterns
///
/// Corresponds to Ghidra's `CollapseStructure` class.
/// Corresponds to Ghidra's `CollapseStructure` class.
/// Detects if-then, if-then-else, sequence, and while-do patterns
/// from a flat CFG and replaces them with structured `BlockIf`,
/// `BlockWhileDo`, and `BlockList` nodes.
pub(crate) struct CollapseStructure<'a> {
    graph: &'a mut BlockGraph,
    change_count: i32,
    name: String,
    /// Immediate dominator map: idom[i] = index of i's immediate dominator.
    idom: std::collections::HashMap<i32, i32>,
    /// Loop bodies identified by orderLoopBodies: (head_idx, body_block_indices).
    /// Sorted by nesting depth (innermost first). Used by interleaved rules
    /// to prioritize structuring within loop bodies.
    loop_bodies: Vec<(i32, Vec<i32>)>,
    /// Block indices that are switch case bodies.
    /// from being pulled out of switch bodies.
    switch_case_indices: std::collections::HashSet<i32>,
    /// Rich loop analysis (Ghidra LoopBody), built by order_loop_bodies.
    /// Holds head/tails/exit_block/exit_edges/depth for each natural loop,
    /// sorted deepest-nesting-first. Used for nested-loop structuring and
    /// exit-edge labeling.
    loop_order: std::collections::VecDeque<LoopBody>,
}

impl<'a> CollapseStructure<'a> {
    pub(crate) fn new(graph: &'a mut BlockGraph, name: &str) -> Self {
        Self {
            graph,
            change_count: 0,
            name: name.to_string(),
            switch_case_indices: std::collections::HashSet::new(),
            idom: std::collections::HashMap::new(),
            loop_bodies: Vec::new(),
            loop_order: std::collections::VecDeque::new(),
        }
    }

    /// Collapse all structured patterns until fixpoint
    ///
    /// Corresponds to Ghidra's `CollapseStructure::collapseAll`
    pub(crate) fn collapse_all(&mut self) {
        // Step 1: Order loop bodies (Ghidra's orderLoopBodies)
        self.order_loop_bodies();
        // Step 1a: Apply LoopBody exit-edge marks (setExitMarks) so TraceDAG
        // respects loop bounds — this is how LoopBody analysis drives structuring
        // (Ghidra updateLoopBody blockaction.cc:1231).
        self.apply_loop_exit_marks();

        // Step 1b: Structure WhileDo loops (innermost-first) before phase1, so
        // loop heads are preserved as BlockWhileDo instead of being consumed
        // by phase1's collapse_conditions.
        self.structure_loops_first();

        // Step 1c: Run TraceDAG BEFORE phase1 to mark likely goto edges.
        // This must happen before switch detection so goto-marked edges prevent
        // switch formation, allowing the remaining control flow to be structured
        // as if/while instead of switch (matching Ghidra's approach).
        self.run_tracedag();

        let max_iterations = self.graph.get_size() * 3 + 4;
        let mut iterations = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // First pass: collapse sequences and conditions in the traditional
        // phase-based approach (existing behavior).
        let phase1_start = self.change_count;
        loop {
            if std::time::Instant::now() > deadline {
                eprintln!("[COLLAPSE] {} deadline hit iter={}", self.name, iterations);
                break;
            }
            let pre_count = self.change_count;

            self.collapse_loops();
            if std::time::Instant::now() > deadline { break; }
            // Faithful WhileDo rule (blockaction.cc:1518-1549): runs every
            // phase iteration like Ghidra's collapseInternal interleaves it.
            // Picks up loops whose break-edges were marked goto by TraceDAG.
            let size_snapshot = self.graph.get_size();
            for wi in 0..size_snapshot {
                if std::time::Instant::now() > deadline { break; }
                // Use try_rule_while_do (the interleaved-phase version that
                // accepts BlockList clauses via count_non_structural_in_edges),
                // not rule_block_while_do (which has stricter is_goto_out checks).
                self.try_rule_while_do(wi);
            }
            if std::time::Instant::now() > deadline { break; }
            self.collapse_conditions();
            if std::time::Instant::now() > deadline { break; }
            self.collapse_bool_conditions();
            // Switch detection LAST (after loops/conditions/sequences), matching
            // Ghidra's collapseInternal order where ruleBlockSwitch runs after
            // cat/proper_if/if_else/while_do/do_while. This lets loop/if structuring
            // consume blocks before switch detection, producing if/while instead of
            // switch when the control flow is structurable.
            self.collapse_cbranch_cascades();
            self.collapse_case_fallthru();
            self.collapse_sequences();
            self.collapse_switches();
            self.refresh_switch_cases();

            iterations += 1;
            if self.change_count == pre_count || iterations >= max_iterations {
                break;
            }
        }
        eprintln!("[COLLAPSE] {} phase1 done changes={} iter={}", self.name, self.change_count - phase1_start, iterations);

        // Second phase: Ghidra-style interleaved rule application.
        // Repeatedly try rules on each block until a full pass makes no change.
        // This handles cases where applying cat-merge to one pair unlocks a
        // condition match that was previously blocked by intermediate blocks.
        let pre_interleaved_count = self.change_count;
        let interleaved_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // Refresh switch case tracking — skip if no switches (saves time + avoids
        // dominator recomputation side-effects on simple test CFGs)
        let has_switch = (0..self.graph.get_size()).any(|i| {
            self.graph.get_block(i).map_or(false, |b| {
                b.read().unwrap().get_type() == crate::block::BlockType::Switch
            })
        });
        if has_switch {
            self.refresh_switch_cases();
        }
        // Detect if this function contains any BlockSwitch. if_no_exit is only
        // safe to enable when there are no switches (no case labels to extract).
        // Functions with switches (e.g. httpd main with 8 switches) keep
        // if_no_exit disabled to avoid case label extraction issues.
        let has_switch = {
            let mut found = false;
            for i in 0..self.graph.get_size() {
                if let Some(blk) = self.graph.get_block(i) {
                    if blk.read().unwrap().get_type() == crate::block::BlockType::Switch {
                        found = true;
                        break;
                    }
                }
            }
            found
        };
        loop {
            if std::time::Instant::now() > interleaved_deadline { break; }
            let pre_count = self.change_count;
            let size = self.graph.get_size();
            for i in 0..size {
                if std::time::Instant::now() > interleaved_deadline { break; }
                let block = match self.graph.get_block(i) {
                    Some(b) => b,
                    None => continue,
                };
                let bt = block.read().unwrap().get_type();

                // For Basic/Copy blocks: apply rules directly
                if bt == crate::block::BlockType::Basic || bt == crate::block::BlockType::Copy {
                    self.apply_rules_to_block(i);
                    continue;
                }

                // For BlockList: recursively apply rules to children
                if bt == crate::block::BlockType::List {
                    let children = {
                        let b = block.read().unwrap();
                        match b.as_any().downcast_ref::<BlockList>() {
                            Some(bl) => bl.children.clone(),
                            None => continue,
                        }
                    };
                    self.apply_rules_to_children(&children);
                    continue;
                }

                // For BlockSwitch: recursively apply rules to case bodies
                if bt == crate::block::BlockType::Switch {
                    let cases_and_default = {
                        let b = block.read().unwrap();
                        match b.as_any().downcast_ref::<BlockSwitch>() {
                            Some(sw) => {
                                let mut all = sw.cases.clone();
                                if let Some(ref dc) = sw.default_case { all.push(dc.clone()); }
                                all
                            }
                            None => continue,
                        }
                    };
                    self.apply_rules_to_children(&cases_and_default);
                    continue;
                }
            }
            iterations += 1;
            self.refresh_switch_cases();
            if self.change_count == pre_count || iterations >= max_iterations {
                break;
            }
        }
        eprintln!("[COLLAPSE] {} interleaved done blocks={} iter={}", self.name, self.graph.get_size(), iterations);
        self.run_goto_cascade();
    }

    /// Apply interleaved rules to a single block at graph index i.
    fn apply_rules_to_block(&mut self, i: usize) {
        // Skip blocks whose edges were already cleared by an earlier
        // identify_internal (consumed/orphaned but not yet marked DEAD). These
        // blocks have size_in==0 && size_out==0 but aren't the function entry,
        // so they can't match any rule — and matching them would corrupt the
        // graph (e.g. a loop head whose edges got cleared mid-structuring).
        {
            let b = match self.graph.get_block(i) { Some(b)=>b, None=>return };
            let r = b.read().unwrap();
            if r.get_flags() & crate::block::block_flags::DEAD != 0 { return; }
            if r.size_in() == 0 && r.size_out() == 0 {
                // Orphaned block (consumed but not DEAD-flagged). Skip it to
                // avoid corrupting the graph via spurious matches.
                return;
            }
        }
        // Ghidra collapseInternal order (blockaction.cc:1797-1828): goto FIRST,
        // then cat, proper_if, if_else, while_do, do_while, inf_loop, switch.
        // Running goto first ensures continue/break edges are consumed (wrapped
        // as BlockIfGoto/BlockGoto) BEFORE while_do tries to match the body,
        // which reduces clause size_in so WhileDo can form.
        if self.try_rule_if_goto(i) { return; }
        if self.try_rule_goto(i) { return; }
        if self.try_rule_cat(i) { return; }
        if self.try_rule_proper_if(i) { return; }
        if self.try_rule_if_else(i) { return; }
        if self.try_rule_while_do(i) { return; }
        if self.try_rule_do_while(i) { return; }
    }

    /// Apply interleaved rules recursively to children of a structured block.
    /// For each child: if it's Basic/Copy, find its graph index and apply rules.
    /// If it's BlockList, recurse into its children.
    fn apply_rules_to_children(&mut self, children: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>]) {
        for child in children {
            let bt = child.read().unwrap().get_type();
            match bt {
                crate::block::BlockType::Basic | crate::block::BlockType::Copy => {
                    let child_idx = child.read().unwrap().get_index() as usize;
                    if child_idx < self.graph.get_size() {
                        self.apply_rules_to_block(child_idx);
                    }
                }
                crate::block::BlockType::List => {
                    let sub_children = {
                        let b = child.read().unwrap();
                        match b.as_any().downcast_ref::<BlockList>() {
                            Some(bl) => bl.children.clone(),
                            None => continue,
                        }
                    };
                    self.apply_rules_to_children(&sub_children);
                }
                crate::block::BlockType::Switch => {
                    let sub_children = {
                        let b = child.read().unwrap();
                        match b.as_any().downcast_ref::<BlockSwitch>() {
                            Some(sw) => {
                                let mut all = sw.cases.clone();
                                if let Some(ref dc) = sw.default_case { all.push(dc.clone()); }
                                all
                            }
                            None => continue,
                        }
                    };
                    self.apply_rules_to_children(&sub_children);
                }
                _ => {}
            }
        }
    }

    // Ghidra-style selectGoto loop
    fn run_goto_cascade(&mut self) {
        eprintln!("[COLLAPSE] {} goto cascade enabled", self.name);
        let goto_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut goto_rounds = 0;
        // Hard cap on rounds to prevent runaway loops when clip/goto structuring
        // doesn't fully converge (e.g. mutually-irreducible roots). Ghidra's
        // selectGoto throws LowlevelError in this case; we cap instead.
        let max_goto_rounds = 40;
        loop {
            if std::time::Instant::now() > goto_deadline { break; }
            if goto_rounds >= max_goto_rounds { break; }
            let goto_marked = self.select_and_mark_goto();
            // Fallback: clip_extra_roots marks irreducible cross-over edges as
            // goto when select_and_mark_goto finds nothing. try_rule_goto then
            // consumes the marked blocks (newBlockGoto), preventing infinite loops.
            let clip_marked = if !goto_marked { self.clip_extra_roots() } else { false };
            // TraceDAG: when both select_and_mark_goto and clip_extra_roots find
            // nothing, run the TraceDAG algorithm (Ghidra's selectGoto main path).
            let tdag_marked = if !goto_marked && !clip_marked {
                self.run_tracedag()
            } else { false };
            if !goto_marked && !clip_marked && !tdag_marked { break; }
            goto_rounds += 1;
            let inner_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                if std::time::Instant::now() > inner_deadline { break; }
                let pre_count = self.change_count;
                let size = self.graph.get_size();
                for i in 0..size {
                    if std::time::Instant::now() > inner_deadline { break; }
                    if self.try_rule_cat(i) { continue; }
                    if self.try_rule_proper_if(i) { continue; }
                    if self.try_rule_if_goto(i) { continue; }
                    if self.try_rule_if_else(i) { continue; }
                    // Try loop structuring rules here too (aligns Ghidra's
                    // collapseInternal, which tries WhileDo/DoWhile in the SAME
                    // pass as Cat/ProperIf/IfElse, blockaction.cc:1813-1820).
                    // Without this, back-edges protected from goto never get
                    // structured after the cascade, leaving loops as flat
                    // if/break/return sequences.
                    if self.try_rule_while_do(i) { continue; }
                    if self.try_rule_do_while(i) { continue; }
                    if self.try_rule_goto(i) { continue; }
                }
                self.refresh_switch_cases();
                if self.change_count == pre_count { break; }
            }
        }
        eprintln!("[COLLAPSE] {} goto rounds={} blocks={}", self.name, goto_rounds, self.graph.get_size());
        // Monitoring: count block types after full structuring (permanent diagnostic,
        // uses standard [COLLAPSE] tag, stderr-only, does not pollute stdout).
        {
            let mut basic = 0usize; let mut dead = 0usize; let mut structured = 0usize;
            let sz = self.graph.get_size();
            for i in 0..sz {
                if let Some(blk) = self.graph.get_block(i) {
                    let b = blk.read().unwrap();
                    let flags = b.get_flags();
                    if flags & crate::block::block_flags::DEAD != 0 { dead += 1; }
                    else if b.get_type() == crate::block::BlockType::Basic
                         || b.get_type() == crate::block::BlockType::Copy { basic += 1; }
                    else { structured += 1; }
                }
            }
            eprintln!("[COLLAPSE] {} FINAL basic={} dead={} structured={}", self.name, basic, dead, structured);
            // Count structured block subtypes (WhileDo/DoWhile/If/etc)
            if structured > 0 {
                let mut wd = 0; let mut dw = 0; let mut ifs = 0; let mut lst = 0; let mut oth = 0;
                for i in 0..sz {
                    if let Some(blk) = self.graph.get_block(i) {
                        let b = blk.read().unwrap();
                        if b.get_flags() & crate::block::block_flags::DEAD != 0 { continue; }
                        match b.get_type() {
                            crate::block::BlockType::WhileDo => wd += 1,
                            crate::block::BlockType::DoWhile => dw += 1,
                            crate::block::BlockType::If => ifs += 1,
                            crate::block::BlockType::List => lst += 1,
                            crate::block::BlockType::Basic | crate::block::BlockType::Copy => {}
                            _ => oth += 1,
                        }
                    }
                }
                eprintln!("[COLLAPSE] {} TYPES whiledo={} dowhile={} if={} list={} other={}", self.name, wd, dw, ifs, lst, oth);
            }
            // Categorize unstructured CBRANCHes: loop-back-edge vs multi-in-edge
            if basic > 10 {
                let mut loop_cbr = 0; let mut multiin_cbr = 0; let mut single_cbr = 0;
                for i in 0..sz {
                    if let Some(blk) = self.graph.get_block(i) {
                        let b = blk.read().unwrap();
                        if b.get_flags() & crate::block::block_flags::DEAD != 0 { continue; }
                        if b.get_type() != crate::block::BlockType::Basic { continue; }
                        let has_cbranch = b.get_ops().last().map_or(false, |o| o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_CBRANCH);
                        if !has_cbranch || b.size_out() != 2 { continue; }
                        let idx = b.get_index();
                        let mut has_backedge = false;
                        for slot in 0..2 {
                            if let Some(e) = b.get_out(slot) {
                                if e.point.read().unwrap().get_index() == idx { has_backedge = true; }
                            }
                        }
                        if has_backedge { loop_cbr += 1; }
                        else if b.size_in() > 1 { multiin_cbr += 1; }
                        else { single_cbr += 1; }
                    }
                }
                eprintln!("[COLLAPSE] {} CBR-CAT loop={} multiin={} single={}", self.name, loop_cbr, multiin_cbr, single_cbr);
            }
        }
    }

    /// Identify all natural loops via back-edges and collect their body blocks.
    /// Mirrors Ghidra's labelLoops + orderLoopBodies (blockaction.cc:1126).
    /// A back-edge is an edge from block A to block B where B dominates A.
    /// The loop body is all blocks that can reach A without going through B.
    /// Results stored in self.loop_bodies, sorted by body size (smallest first
    /// = innermost loops first).
    fn order_loop_bodies(&mut self) {
        self.loop_bodies.clear();
        // Faithful to Ghidra: label back-edges via a DFS spanning tree
        // (BlockGraph::structureLoops → findSpanningTree), then detect loops
        // by scanning F_BACK_EDGE labels (CollapseStructure::labelLoops,
        // blockaction.cc:1126-1143). This replaces the earlier dominator-based
        // back-edge test, which silently failed on curl `main` (0 back-edges
        // found despite 25 candidate edges).
        self.find_spanning_tree();
        // Dominators are still needed elsewhere (switch-case detection,
        // LoopBody helpers), so keep them up to date.
        self.compute_dominators();
        let size = self.graph.get_size();

        // Diagnostic: dominator coverage + back-edge scan (RUGRA_LOOP_DEBUG=1)
        let loop_dbg = std::env::var("RUGRA_LOOP_DEBUG")
            .map(|v| v == "1").unwrap_or(false);
        if loop_dbg {
            let idom_count = self.idom.len();
            let entry = (0..size).find(|&i| {
                self.graph.get_block(i).map_or(false, |b| b.read().unwrap().size_in() == 0)
            });
            // Count F_BACK_EDGE-labelled edges (the spanning-tree result).
            let mut back_edges = 0;
            let mut back_examples: Vec<(i32,i32)> = Vec::new();
            for i in 0..size {
                let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
                let b = block.read().unwrap();
                let src = b.get_index();
                for slot in 0..b.size_out() {
                    if b.is_back_edge_out(slot) {
                        let tgt = b.get_out(slot).unwrap().point.read().unwrap().get_index();
                        back_edges += 1;
                        if back_examples.len() < 8 { back_examples.push((src, tgt)); }
                    }
                }
            }
            eprintln!("[LOOPDBG] {} size={} entry={:?} idom_entries={}/{} dfs_back_edges={} examples={:?}",
                self.name, size, entry, idom_count, size, back_edges, back_examples);
        }

        // Find all back-edges (via F_BACK_EDGE labels) and create loop bodies.
        // Faithful to labelLoops (blockaction.cc:1126-1142): for each block,
        // scan out-edges; a back edge `(src -> tgt)` makes `tgt` the loop
        // head and `src` a loop tail.
        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let (src_idx, back_targets): (i32, Vec<i32>) = {
                let b = block.read().unwrap();
                let src = b.get_index();
                let mut tgts = Vec::new();
                for slot in 0..b.size_out() {
                    if b.is_back_edge_out(slot) {
                        if let Some(e) = b.get_out(slot) {
                            tgts.push(e.point.read().unwrap().get_index());
                        }
                    }
                }
                (src, tgts)
            };
            for tgt_idx in back_targets {
                let body = self.collect_loop_body(tgt_idx, src_idx, size);
                if !body.is_empty() {
                    self.loop_bodies.push((tgt_idx, body));
                }
            }
        }

        // Sort by body size (smallest = innermost first)
        self.loop_bodies.sort_by_key(|(_, body)| body.len());
        eprintln!("[COLLAPSE] {} orderLoopBodies: {} loops found", self.name, self.loop_bodies.len());
        for (head, body) in &self.loop_bodies {
            eprintln!("[COLLAPSE] {} loop head={} bodysize={}", self.name, head, body.len());
        }

        // ---- Rich LoopBody pipeline (Ghidra blockaction.cc:1148-1188) ----
        // Build LoopBody records from the back-edges, then run the full
        // find_base / merge / label_containments / find_exit / order_tails /
        // extend / label_exit_edges pipeline. This populates self.loop_order
        // with nesting depth, exit blocks, and exit edges for nested-loop
        // structuring.
        self.run_order_loop_bodies_pipeline(size);
    }

    /// Run the full Ghidra LoopBody analysis pipeline on the detected
    /// back-edges. Faithful to `CollapseStructure::orderLoopBodies`
    /// (blockaction.cc:1148-1188).
    fn run_order_loop_bodies_pipeline(&mut self, size: usize) {
        // Step 1: build LoopBody records (one per back-edge), keyed by head.
        let mut loop_order: Vec<LoopBody> = Vec::new();
        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let (src_idx, back_targets): (i32, Vec<i32>) = {
                let b = block.read().unwrap();
                let src = b.get_index();
                let mut tgts = Vec::new();
                for slot in 0..b.size_out() {
                    if b.is_back_edge_out(slot) {
                        if let Some(edge) = b.get_out(slot) {
                            tgts.push(edge.point.read().unwrap().get_index());
                        }
                    }
                }
                (src, tgts)
            };
            for tgt in back_targets {
                if let Some(existing) = loop_order.iter_mut().find(|lb| lb.head == tgt) {
                    existing.add_tail(src_idx);
                } else {
                    loop_order.push(LoopBody::new(tgt, src_idx));
                }
            }
        }
        if loop_order.is_empty() {
            self.loop_order.clear();
            return;
        }
        // Step 2: merge identical heads (already deduped above, but run for
        // completeness — merge_identical_heads is idempotent on unique heads).
        merge_identical_heads(&mut loop_order);
        // Sort by (head index, first tail index) — Ghidra compare_ends.
        loop_order.sort_by(|a, b| {
            a.head.cmp(&b.head).then_with(|| a.tails[0].cmp(&b.tails[0]))
        });
        // Step 3: label containments (set depth + immed_container).
        // Snapshot head list for containment checks.
        let n = loop_order.len();
        for i in 0..n {
            let body = loop_order[i].find_base(self.graph);
            // Count contained subloops.
            let mut contain: Vec<usize> = Vec::new();
            for &curblock in &body {
                if curblock == loop_order[i].head {
                    continue;
                }
                if let Some(sub_idx) = loop_order.iter().position(|lb| lb.head == curblock) {
                    if sub_idx != i {
                        contain.push(sub_idx);
                    }
                }
            }
            // Increment depth of contained subloops.
            for &sub_idx in &contain {
                loop_order[sub_idx].depth += 1;
            }
            // Set immed_container to the deepest container seen so far.
            let my_depth = loop_order[i].depth;
            for &sub_idx in &contain {
                if loop_order[sub_idx].immed_container == -1
                    || loop_order[loop_order[sub_idx].immed_container as usize].depth < my_depth
                {
                    loop_order[sub_idx].immed_container = i as i32;
                }
            }
            clear_marks(&body, self.graph);
        }
        // Step 4: sort by nesting depth (deepest first). Ghidra uses stable
        // sort on depth.
        loop_order.sort_by(|a, b| b.depth.cmp(&a.depth));
        // Step 5: for each loop, find_base / find_exit / order_tails / extend /
        // label_exit_edges.
        for lb in loop_order.iter_mut() {
            let mut body = lb.find_base(self.graph);
            lb.find_exit(&body, self.graph);
            lb.order_tails(self.graph);
            lb.extend(&mut body, self.graph);
            lb.label_exit_edges(&body, self.graph);
            clear_marks(&body, self.graph);
        }
        // Store into the VecDeque for updateLoopBody-style iteration.
        self.loop_order = loop_order.into_iter().collect();
        eprintln!(
            "[COLLAPSE] {} LoopBody pipeline: {} loops, depths={}",
            self.name,
            self.loop_order.len(),
            self.loop_order.iter().map(|lb| lb.depth).collect::<Vec<_>>().iter()
                .map(|d| d.to_string()).collect::<Vec<_>>().join(",")
        );
    }

    /// Apply each LoopBody's exit-edge labels as `F_LOOP_EXIT_EDGE` marks on
    /// the graph. Faithful to Ghidra's `LoopBody::setExitMarks` /
    /// `CollapseStructure::updateLoopBody` (blockaction.cc:416-426, 1231):
    /// the exit edges bound where TraceDAG traces, so the structurer treats
    /// edges leaving a loop body as candidate gotos rather than tracing
    /// through them. This is how LoopBody analysis drives structuring.
    fn apply_loop_exit_marks(&mut self) {
        for lb in &self.loop_order {
            for fe in &lb.exit_edges {
                if let Some(blk) = self.graph.get_block(fe.from_idx as usize) {
                    // Find the out-slot to fe.to_idx and mark it loop-exit.
                    let slot = {
                        let b = blk.read().unwrap();
                        let n = b.size_out();
                        (0..n).find(|&k| {
                            b.get_out(k).map(|e| e.point.read().unwrap().get_index() == fe.to_idx).unwrap_or(false)
                        })
                    };
                    if let Some(slot) = slot {
                        blk.write().unwrap().set_loop_exit(slot);
                    }
                }
            }
        }
    }

    /// Collect all blocks in a natural loop body.
    /// Body = {head} + all blocks that can reach tail without going through head.
    fn collect_loop_body(&self, head: i32, tail: i32, size: usize) -> Vec<i32> {
        let mut body = std::collections::HashSet::new();
        body.insert(head);
        body.insert(tail);
        // BFS backward from tail, stopping at head
        let mut queue = vec![tail];
        while let Some(cur) = queue.pop() {
            if cur == head { continue; }
            let i = cur as usize;
            if i >= size { continue; }
            if let Some(blk) = self.graph.get_block(i) {
                let b = blk.read().unwrap();
                for slot in 0..b.size_in() {
                    if let Some(edge) = b.get_in(slot) {
                        let pred_idx = edge.point.read().unwrap().get_index();
                        if body.insert(pred_idx) {
                            queue.push(pred_idx);
                        }
                    }
                }
            }
        }
        body.into_iter().collect()
    }

    /// Check if a block index is inside any identified loop body.
    fn is_in_loop_body(&self, idx: i32) -> bool {
        self.loop_bodies.iter().any(|(_, body)| body.contains(&idx))
    }

    /// Structure detected WhileDo loops (innermost-first) BEFORE phase1 runs,
    /// so loop heads are preserved as BlockWhileDo instead of being consumed
    /// by phase1's collapse_conditions. Only the clean WhileDo pattern
    /// (head=CBR, body=Basic/Copy with single back-edge to head) is structured.
    fn structure_loops_first(&mut self) {
        if self.loop_bodies.is_empty() { return; }
        let loops = self.loop_bodies.clone();
        for (head_idx, _body) in &loops {
            let head_idx = *head_idx;
            let hi = head_idx as usize;
            if hi >= self.graph.get_size() { continue; }
            let head_blk = match self.graph.get_block(hi) { Some(b)=>b, None=>continue };
            {
                let h = head_blk.read().unwrap();
                if h.get_flags() & crate::block::block_flags::DEAD != 0 { continue; }
                if h.get_type() != crate::block::BlockType::Basic { continue; }
                if h.size_out() != 2 { continue; }
                let has_cbranch = h.get_ops().last().map_or(false, |o| {
                    o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_CBRANCH
                });
                if !has_cbranch { continue; }
            }
            let cond_idx = head_blk.read().unwrap().get_index();
            let is_dowhile = {
                let h = head_blk.read().unwrap();
                (0..h.size_out()).any(|s| {
                    h.get_out(s).map_or(false, |e| e.point.read().unwrap().get_index() == cond_idx)
                })
            };
            if is_dowhile { continue; }
            let body_info = {
                let h = head_blk.read().unwrap();
                let mut found = None;
                for s in 0..h.size_out() {
                    if let Some(e) = h.get_out(s) {
                        let body_blk = e.point.clone();
                        let body_idx = body_blk.read().unwrap().get_index();
                        if body_idx == cond_idx { continue; }
                        let loops_back = (0..body_blk.read().unwrap().size_out()).any(|bs| {
                            body_blk.read().unwrap().get_out(bs).map_or(false, |be| {
                                be.point.read().unwrap().get_index() == cond_idx
                            })
                        });
                        if loops_back { found = Some((body_blk, body_idx)); break; }
                    }
                }
                found
            };
            if let Some((body_blk, body_idx)) = body_info {
                let body_ok = {
                    let bd = body_blk.read().unwrap();
                    let bt = bd.get_type();
                    (bt == crate::block::BlockType::Basic || bt == crate::block::BlockType::Copy)
                        && bd.get_flags() & crate::block::block_flags::CASE_BODY == 0
                        && bd.get_flags() & crate::block::block_flags::DEAD == 0
                };
                if !body_ok { continue; }
                let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(crate::block::BlockWhileDo {
                        index: cond_idx,
                        condition: head_blk.clone(),
                        body: body_blk.clone(),
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                        parent: None,
                        flags: 0,
                    }));
                self.identify_internal(&while_block, &[body_idx], hi);
                self.change_count += 1;
                eprintln!("[COLLAPSE] {} structure_loops_first WhileDo head={} body={}", self.name, cond_idx, body_idx);
            }
        }
    }

    /// Check if a block index is a sub-component of any structured block
    /// (BlockCondition.first/second, BlockIf.condition/if_body/else_body,
    /// BlockWhileDo.condition/body, etc.). These blocks should not be
    /// processed by interleaved rules or goto cascade.
    fn is_structured_child(&self, idx: i32, size: usize) -> bool {
        use crate::block::{BlockIf, BlockCondition, BlockWhileDo, BlockDoWhile, BlockList};
        for i in 0..size {
            let blk = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let b = blk.read().unwrap();
            match b.get_type() {
                crate::block::BlockType::Condition => {
                    if let Some(bc) = b.as_any().downcast_ref::<BlockCondition>() {
                        if bc.first.read().unwrap().get_index() == idx { return true; }
                        if bc.second.read().unwrap().get_index() == idx { return true; }
                    }
                }
                crate::block::BlockType::If => {
                    if let Some(bi) = b.as_any().downcast_ref::<BlockIf>() {
                        if bi.condition.read().unwrap().get_index() == idx { return true; }
                        if bi.if_body.read().unwrap().get_index() == idx { return true; }
                        if let Some(ref eb) = bi.else_body {
                            if eb.read().unwrap().get_index() == idx { return true; }
                        }
                    }
                }
                crate::block::BlockType::WhileDo => {
                    if let Some(wd) = b.as_any().downcast_ref::<BlockWhileDo>() {
                        if wd.condition.read().unwrap().get_index() == idx { return true; }
                        if wd.body.read().unwrap().get_index() == idx { return true; }
                    }
                }
                crate::block::BlockType::DoWhile => {
                    if let Some(dw) = b.as_any().downcast_ref::<BlockDoWhile>() {
                        if dw.condition.read().unwrap().get_index() == idx { return true; }
                    }
                }
                crate::block::BlockType::List => {
                    if let Some(bl) = b.as_any().downcast_ref::<BlockList>() {
                        for child in &bl.children {
                            if child.read().unwrap().get_index() == idx { return true; }
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }


    /// can be marked as goto to break irreducible CFG patterns.
    fn select_and_mark_goto(&mut self) -> bool {
        let size = self.graph.get_size();
        // Collect ALL case body indices by scanning BlockSwitch nodes directly.
        // Also track how many switches reference each case body — if a body
        // is shared by multiple switches, goto marking on it would mix them.
        let mut all_case_bodies: std::collections::HashSet<i32> = std::collections::HashSet::new();
        let mut multi_switch_bodies: std::collections::HashSet<i32> = std::collections::HashSet::new();
        let mut case_ref_count: std::collections::HashMap<i32, i32> = std::collections::HashMap::new();
        for i in 0..size {
            if let Some(blk) = self.graph.get_block(i) {
                let b = blk.read().unwrap();
                if b.get_type() == crate::block::BlockType::Switch {
                    if let Some(bs) = b.as_any().downcast_ref::<crate::block::BlockSwitch>() {
                        for case in &bs.cases {
                            let cidx = case.read().unwrap().get_index();
                            all_case_bodies.insert(cidx);
                            let count = case_ref_count.entry(cidx).or_insert(0);
                            *count += 1;
                            if *count > 1 { multi_switch_bodies.insert(cidx); }
                        }
                        if let Some(ref dc) = bs.default_case {
                            let didx = dc.read().unwrap().get_index();
                            all_case_bodies.insert(didx);
                        }
                    }
                }
            }
        }
        // Also include switch_case_indices (cascade cases)
        for &idx in &self.switch_case_indices {
            all_case_bodies.insert(idx);
        }

        // Build switch ownership map: block_idx -> set of switch indices.
        // Covers both BlockSwitch nodes AND CBRANCH cascade chains.
        let mut switch_owners: std::collections::HashMap<i32, std::collections::HashSet<i32>> =
            std::collections::HashMap::new();
        // BlockSwitch ownership (forward BFS from each case body)
        for sw_idx in 0..size as i32 {
            let sw_blk = match self.graph.get_block(sw_idx as usize) { Some(b) => b, None => continue };
            let sw_b = sw_blk.read().unwrap();
            if sw_b.get_type() != crate::block::BlockType::Switch { continue; }
            if let Some(bs) = sw_b.as_any().downcast_ref::<crate::block::BlockSwitch>() {
                for case in &bs.cases {
                    let case_start = case.read().unwrap().get_index();
                    let mut queue = vec![case_start];
                    let mut visited = std::collections::HashSet::new();
                    while let Some(cur) = queue.pop() {
                        if !visited.insert(cur) { continue; }
                        switch_owners.entry(cur).or_default().insert(sw_idx);
                        if let Some(cb) = self.graph.get_block(cur as usize) {
                            let c = cb.read().unwrap();
                            for slot in 0..c.size_out() {
                                if let Some(e) = c.get_out(slot) {
                                    queue.push(e.point.read().unwrap().get_index());
                                }
                            }
                        }
                    }
                }
            }
        }
        // Cascade chain ownership: group all case bodies in the same cascade
        // chain under one virtual switch id (the cascade head's index).
        // This ensures cross-switch detection treats one cascade as one switch.
        for i in 0..size as i32 {
            let blk = match self.graph.get_block(i as usize) { Some(b) => b, None => continue };
            let b = blk.read().unwrap();
            if b.size_out() != 2 { continue; }
            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH);
            if !has_cbranch { continue; }
            // Check if this is a cascade member (fallthrough to another CBRANCH)
            let ft_is_cbranch = if let Some(ft_edge) = b.get_out(0) {
                let ft = ft_edge.point.read().unwrap();
                if ft.size_out() == 2 {
                    let ft_ops = ft.get_ops();
                    ft_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                } else { false }
            } else { false };
            if ft_is_cbranch {
                // Find cascade head: walk back via in-edges to find the first
                // CBRANCH whose predecessor is NOT a CBRANCH fallthrough.
                let mut head = i;
                let mut cur = i;
                let mut steps = 0;
                loop {
                    if steps > 200 { break; } // safety
                    let cur_blk = match self.graph.get_block(cur as usize) { Some(b) => b, None => break };
                    let cb = cur_blk.read().unwrap();
                    // Check if any predecessor is a CBRANCH that falls through to cur
                    let mut pred_is_cbranch_ft = false;
                    for slot in 0..cb.size_in() {
                        if let Some(in_edge) = cb.get_in(slot) {
                            let pred = in_edge.point.read().unwrap();
                            if pred.size_out() == 2 {
                                let pred_ops = pred.get_ops();
                                let pred_has_cbranch = pred_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH);
                                if pred_has_cbranch {
                                    // Check if pred's fallthrough (out[0]) leads to cur
                                    if let Some(ft) = pred.get_out(0) {
                                        if ft.point.read().unwrap().get_index() == cur {
                                            pred_is_cbranch_ft = true;
                                            head = pred.get_index();
                                            cur = pred.get_index();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !pred_is_cbranch_ft { break; }
                    steps += 1;
                }
                // Use cascade head as virtual switch id
                let virtual_sw = -(head + 1);
                if let Some(taken_edge) = b.get_out(1) {
                    let taken_idx = taken_edge.point.read().unwrap().get_index();
                    switch_owners.entry(taken_idx).or_default().insert(virtual_sw);
                    switch_owners.entry(b.get_index()).or_default().insert(virtual_sw);
                }
            }
        }

        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }
            if b.size_out() != 2 { continue; }

            // Skip blocks that are sub-components of structured blocks.
            let my_idx = b.get_index();
            if self.is_structured_child(my_idx, size) { continue; }

            let taken_target_idx = match b.get_out(1) {
                Some(e) => e.point.read().unwrap().get_index(),
                None => continue,
            };
            // Skip if this block's GOTO_EDGE_1 is already set
            if b.get_flags() & crate::block::block_flags::GOTO_EDGE_1 != 0 { continue; }

            // LOOP-BACK PROTECTION: do NOT mark a back edge as goto. A back
            // edge (F_BACK_EDGE, set by findSpanningTree) defines a loop and
            // must be preserved for ruleBlockWhileDo/ruleBlockDoWhile to
            // recognise the loop. Goto-marking it severs the loop, leaving the
            // body with no exit back to the header (observed: curl main loop
            // bodies ended up with sizeOut()==0 because their sole back-edge
            // was turned into a goto). This mirrors Ghidra's TraceDAG, which
            // skips loop edges when tracing structured paths.
            if b.is_back_edge_out(1) { continue; }

            // Skip if this block IS a switch case body (don't mark goto on case body blocks)
            let my_idx = b.get_index();
            if all_case_bodies.contains(&my_idx) { continue; }
            if b.get_flags() & crate::block::block_flags::CASE_BODY != 0 { continue; }
            // Skip if taken target is a switch case body
            if all_case_bodies.contains(&taken_target_idx) { continue; }
            // Skip if taken target is shared by multiple switches (would mix cases)
            if multi_switch_bodies.contains(&taken_target_idx) { continue; }

            // CROSS-SWITCH BOUNDARY DETECTION: Check if this block and its
            // taken target belong to different switches. If so, marking goto
            // would create a BlockIf spanning multiple switches, mixing cases.
            let my_switches = switch_owners.get(&my_idx);
            let target_switches = switch_owners.get(&taken_target_idx);
            if let (Some(ms), Some(ts)) = (my_switches, target_switches) {
                // Check if they share any common switch
                let shared = ms.intersection(ts).count();
                if shared == 0 {
                    // Block and target belong to entirely different switches
                    continue;
                }
            }

            // INTRA-CASCADE PROTECTION: Skip CBRANCH blocks that are part of
            // a cascade switch chain. goto marking within a cascade changes
            // case body emit order, causing case label issues.
            let ft_is_cbranch = if let Some(ft_edge) = b.get_out(0) {
                let ft = ft_edge.point.read().unwrap();
                if ft.size_out() == 2 {
                    let ft_ops = ft.get_ops();
                    ft_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                } else { false }
            } else { false };
            let pred_is_cbranch_ft = if b.size_in() >= 1 {
                (0..b.size_in()).any(|slot| {
                    if let Some(in_edge) = b.get_in(slot) {
                        let pred = in_edge.point.read().unwrap();
                        if pred.size_out() == 2 {
                            let pred_ops = pred.get_ops();
                            let pred_has_cbranch = pred_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH);
                            if pred_has_cbranch {
                                if let Some(ft) = pred.get_out(0) {
                                    return ft.point.read().unwrap().get_index() == my_idx;
                                }
                            }
                        }
                    }
                    false
                })
            } else { false };
            if ft_is_cbranch || pred_is_cbranch_ft { continue; }

            drop(b);
            // Mark out[1] (taken edge) as goto via block flag
            let mut block_w = block.write().unwrap();
            let cur_flags = block_w.get_flags();
            block_w.set_flags(cur_flags | crate::block::block_flags::GOTO_EDGE_1);
            drop(block_w);
            self.change_count += 1;
            eprintln!("[COLLAPSE] {} marked goto on block {} edge→{}", self.name, i, taken_target_idx);
            return true;
        }
        false
    }

    /// Ghidra's clipExtraRoots (blockaction.cc:1108): find distinct control-flow
    /// roots (size_in==0, index > 0), and for the subset of blocks ONLY reachable
    /// from that root, mark their exiting edges as goto. Handles irreducible
    /// cross-over edges. Returns true if any new edges were marked as goto.
    /// Pairs with try_rule_goto which consumes the marked blocks (newBlockGoto).
    fn clip_extra_roots(&mut self) -> bool {
        let size = self.graph.get_size();
        for root_idx in 1..size as i32 {
            let root_blk = match self.graph.get_block(root_idx as usize) { Some(b) => b, None => continue };
            {
                let r = root_blk.read().unwrap();
                if r.size_in() != 0 { continue; }
                // Skip already-structured blocks (BlockGoto, BlockIf, etc.) — they
                // are consumed/structured and shouldn't be re-processed by clip.
                let rt = r.get_type();
                if rt != crate::block::BlockType::Basic && rt != crate::block::BlockType::Copy { continue; }
            }
            // onlyReachableFromRoot: collect blocks reachable only from root.
            let mut body: Vec<i32> = vec![root_idx];
            let mut in_body: std::collections::HashSet<i32> = std::collections::HashSet::new();
            in_body.insert(root_idx);
            let mut visit_count: std::collections::HashMap<i32, i32> = std::collections::HashMap::new();
            let mut i = 0;
            while i < body.len() {
                let cur = body[i]; i += 1;
                let cur_blk = match self.graph.get_block(cur as usize) { Some(b) => b, None => continue };
                let c = cur_blk.read().unwrap();
                for slot in 0..c.size_out() {
                    if let Some(e) = c.get_out(slot) {
                        let nxt = e.point.read().unwrap().get_index();
                        if in_body.contains(&nxt) { continue; }
                        let count = visit_count.entry(nxt).or_insert(0);
                        *count += 1;
                        let nxt_in = e.point.read().unwrap().size_in() as i32;
                        if *count >= nxt_in {
                            in_body.insert(nxt);
                            body.push(nxt);
                        }
                    }
                }
            }
            // markExitsAsGotos: mark out-edges to non-body targets as goto.
            let mut changecount = 0;
            for &bidx in &body {
                let bb = match self.graph.get_block(bidx as usize) { Some(b) => b, None => continue };
                let exit_edges: Vec<usize> = {
                    let b = bb.read().unwrap();
                    let existing = b.get_flags();
                    let mut ex = Vec::new();
                    for slot in 0..b.size_out() {
                        if let Some(e) = b.get_out(slot) {
                            let t = e.point.read().unwrap().get_index();
                            if in_body.contains(&t) { continue; }
                            let already_goto = (slot == 0 && existing & crate::block::block_flags::GOTO_EDGE_0 != 0)
                                            || (slot == 1 && existing & crate::block::block_flags::GOTO_EDGE_1 != 0);
                            if already_goto { continue; }
                            ex.push(slot);
                        }
                    }
                    ex
                };
                if exit_edges.is_empty() { continue; }
                let mut bw = bb.write().unwrap();
                let mut cur_flags = bw.get_flags();
                for &slot in &exit_edges {
                    if slot == 0 { cur_flags |= crate::block::block_flags::GOTO_EDGE_0; }
                    if slot == 1 { cur_flags |= crate::block::block_flags::GOTO_EDGE_1; }
                }
                bw.set_flags(cur_flags);
                changecount += 1;
            }
            if changecount > 0 {
                eprintln!("[COLLAPSE] {} clipExtraRoots: root={} body={} gotos={}", self.name, root_idx, body.len(), changecount);
                self.change_count += changecount;
                return true;
            }
        }
        false
    }

    /// Run the TraceDAG algorithm (Ghidra's selectGoto main path) to find
    /// likely unstructured edges. When found, mark them as goto on the source
    /// block so try_rule_if_goto/try_rule_goto can consume them, allowing the
    /// remaining control flow to be structured as if/while.
    fn run_tracedag(&mut self) -> bool {
        let mut edges = crate::tracedag::generate_likely_gotos(self.graph);
        // Merge LoopBody-prioritized likely edges (emitLikelyEdges,
        // blockaction.cc:364-412): for each LoopBody, append its exit edges
        // and back-edges in priority order. This gives the structurer the
        // LoopBody's view of which edges should be gotos — the official loop
        // exit is held structured while the others are marked goto.
        {
            let mut lb_edges: Vec<FloatingEdge> = Vec::new();
            for lb in &self.loop_order {
                lb.emit_likely_edges(&mut lb_edges, self.graph);
            }
            // Convert blockaction::FloatingEdge -> tracedag::FloatingEdge.
            for fe in lb_edges {
                edges.push(crate::tracedag::FloatingEdge { top: fe.from_idx, bottom: fe.to_idx });
            }
        }
        if edges.is_empty() {
            return false;
        }
        let mut marked = 0;
        for fe in &edges {
            // Mark the source block's out-edge to dest as goto
            let src_i = fe.top as usize;
            if src_i < self.graph.get_size() {
                if let Some(blk) = self.graph.get_block(src_i) {
                    // Find which out-slot goes to fe.bottom
                    let dest_idx = fe.bottom;
                    let mut found_slot = None;
                    {
                        let b = blk.read().unwrap();
                        for slot in 0..b.size_out() {
                            if let Some(e) = b.get_out(slot) {
                                if e.point.read().unwrap().get_index() == dest_idx {
                                    found_slot = Some(slot);
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(slot) = found_slot {
                        let mut bw = blk.write().unwrap();
                        let cur_flags = bw.get_flags();
                        if slot == 0 {
                            bw.set_flags(cur_flags | crate::block::block_flags::GOTO_EDGE_0);
                        } else if slot == 1 {
                            bw.set_flags(cur_flags | crate::block::block_flags::GOTO_EDGE_1);
                        }
                        marked += 1;
                    }
                }
            }
        }
        if marked > 0 {
            eprintln!("[COLLAPSE] {} TraceDAG marked {} likely goto edges", self.name, marked);
            self.change_count += marked;
            true
        } else {
            false
        }
    }

    /// Compute immediate dominators using iterative dataflow (Cooper et al.
    /// 2001 simplified algorithm). Stores result in self.idom.
    /// DFS spanning-tree computation. Faithful to Ghidra's
    /// `BlockGraph::findSpanningTree` (block.cc:1009-1110) and
    /// `BlockGraph::structureLoops` (block.cc:2194-2215).
    ///
    /// Computes a DFS spanning tree and labels every out-edge as one of:
    ///   - `F_TREE_EDGE`    : edge to an unvisited child (spanning tree)
    ///   - `F_BACK_EDGE`|`F_LOOP_EDGE` : edge to a node still on the DFS stack
    ///     (this defines a loop — `order_loop_bodies` reads `F_BACK_EDGE`)
    ///   - `F_FORWARD_EDGE` : edge to an already-finished descendant
    ///   - `F_CROSS_EDGE`   : edge to an already-finished non-descendant
    ///
    /// Returns the list of roots (entry blocks) in visitation order.
    ///
    /// The back-edge labelling is what makes loop detection work: a back edge
    /// `(src -> tgt)` means `tgt` is a loop header and `src` is a loop tail.
    /// This replaces Rugra's earlier (buggy) dominator-based back-edge test,
    /// which failed to find any loop in curl `main` (102 blocks, 0 back-edges
    /// detected despite 25 candidate edges) due to a broken intersect step.
    ///
    /// IMPORTANT: this uses LOCAL DFS state (HashMaps), NOT the FlowBlock
    /// `index`/`visit_count` fields. In Rugra, `index` is the block's
    /// position in `BlockGraph.blocks` and is relied upon by
    /// `compute_dominators`, `collect_loop_body`, etc. Ghidra overloads
    /// `index` for rpostorder because its `getBlock(i)` is list-position
    /// indexed while `get_index()` is rpostorder — Rugra conflates these, so
    /// we keep them separate to avoid corrupting the dominator computation.
    fn find_spanning_tree(&mut self) -> Vec<i32> {
        use crate::block::edge_flags as ef;
        let size = self.graph.get_size();
        if size == 0 { return Vec::new(); }

        // Local DFS state, keyed by block position index (NOT rpostorder).
        // preorder_num: order first visited (-1 = unvisited)
        // rpost_num:    reverse-postorder finish number (-1 = on stack/unfinished)
        let mut preorder_num: std::collections::HashMap<i32, i32> =
            std::collections::HashMap::with_capacity(size);
        let mut rpost_num: std::collections::HashMap<i32, i32> =
            std::collections::HashMap::with_capacity(size);
        for i in 0..size {
            preorder_num.insert(i as i32, -1);
            rpost_num.insert(i as i32, -1);
        }

        // Collect root candidates (blocks with no in-edges). Ghidra swaps
        // first and last root so the "original head" is visited last (first
        // in reverse-post-order). We mirror this.
        let mut rootlist: Vec<i32> = Vec::new();
        for i in 0..size {
            if let Some(blk) = self.graph.get_block(i) {
                if blk.read().unwrap().size_in() == 0 {
                    rootlist.push(i as i32);
                }
            }
        }
        if rootlist.len() > 1 {
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        } else if rootlist.is_empty() {
            rootlist.push(0); // No obvious entry — assume block 0 (Ghidra: list[0]).
        }

        // Clear any prior spanning-tree labels on all out-edges.
        for i in 0..size {
            if let Some(blk) = self.graph.get_block(i) {
                blk.write().unwrap().clear_edge_flags(ef::SPANNING_MASK);
            }
        }

        // Iterative DFS (mirrors Ghidra's state/istate stacks). state holds
        // block position indices; istate holds the next child slot to try.
        let mut state: Vec<i32> = Vec::with_capacity(size);
        let mut istate: Vec<usize> = Vec::with_capacity(size);
        let mut preorder_count: i32 = 0;
        let mut rpostcount = size as i32;
        let mut rootindex: usize = 0;
        let mut usedroots: Vec<i32> = Vec::new();

        // Ghidra runs the DFS up to twice: the first pass may discover
        // unreachable blocks and promotes them to extra roots; the second
        // pass re-runs with the expanded root list.
        for _repeat in 0..2 {
            let mut extraroots = false;
            rpostcount = size as i32;
            rootindex = 0;
            preorder_count = 0;
            // Reset for a fresh traversal.
            for i in 0..size {
                preorder_num.insert(i as i32, -1);
                rpost_num.insert(i as i32, -1);
            }
            for i in 0..size {
                if let Some(blk) = self.graph.get_block(i) {
                    blk.write().unwrap().clear_edge_flags(ef::SPANNING_MASK);
                }
            }
            state.clear();
            istate.clear();
            usedroots.clear();

            while preorder_count < size as i32 {
                // Pick the next start block: prefer an unused root, else any
                // unvisited block (which becomes a new root).
                let mut startbl: i32 = -1;
                while rootindex < rootlist.len() {
                    let cand = rootlist[rootindex];
                    rootindex += 1;
                    if preorder_num[&cand] == -1 {
                        startbl = cand;
                        usedroots.push(cand);
                        break;
                    }
                }
                if startbl == -1 {
                    extraroots = true;
                    for i in 0..size {
                        if preorder_num[&(i as i32)] == -1 {
                            startbl = i as i32;
                            break;
                        }
                    }
                    if startbl == -1 { break; }
                    rootlist.push(startbl);
                    rootindex += 1;
                    usedroots.push(startbl);
                }

                state.push(startbl);
                istate.push(0);
                preorder_num.insert(startbl, preorder_count);
                preorder_count += 1;

                while !state.is_empty() {
                    let curbl = *state.last().unwrap();
                    let cur_block = self.graph.get_block(curbl as usize).unwrap();
                    let nout = cur_block.read().unwrap().size_out();
                    if nout <= *istate.last().unwrap() {
                        // All children visited: finish this node.
                        state.pop();
                        istate.pop();
                        rpostcount -= 1;
                        rpost_num.insert(curbl, rpostcount);
                    } else {
                        let edgenum = *istate.last().unwrap();
                        *istate.last_mut().unwrap() += 1;
                        // Child target of this out-edge (block position index).
                        let childbl = match cur_block.read().unwrap().get_out(edgenum) {
                            Some(e) => {
                                // The child's position index. Note: edge.point's
                                // get_index() returns the block's stored index,
                                // which (for BlockBasic) is its position in the
                                // graph's blocks list — same space we key on.
                                e.point.read().unwrap().get_index()
                            }
                            None => continue,
                        };
                        let child_pre = preorder_num.get(&childbl).copied().unwrap_or(-2);
                        let child_rpost = rpost_num.get(&childbl).copied().unwrap_or(-2);
                        let cur_pre = preorder_num[&curbl];

                        if child_pre == -1 {
                            // Unvisited: tree edge, descend.
                            cur_block.write().unwrap().set_out_edge_flag(edgenum, ef::F_TREE_EDGE);
                            state.push(childbl);
                            istate.push(0);
                            preorder_num.insert(childbl, preorder_count);
                            preorder_count += 1;
                        } else if child_rpost == -1 {
                            // Child still on the DFS stack → back edge (loop).
                            cur_block.write().unwrap()
                                .set_out_edge_flag(edgenum, ef::F_BACK_EDGE | ef::F_LOOP_EDGE);
                        } else if cur_pre >= 0 && cur_pre < child_pre {
                            // curbl visited before childbl, child finished → forward edge.
                            cur_block.write().unwrap().set_out_edge_flag(edgenum, ef::F_FORWARD_EDGE);
                        } else {
                            // Already finished, not forward → cross edge.
                            cur_block.write().unwrap().set_out_edge_flag(edgenum, ef::F_CROSS_EDGE);
                        }
                    }
                }
            }
            if !extraroots { break; }
        }

        usedroots
    }


    fn compute_dominators(&mut self) {
        self.idom.clear();
        let size = self.graph.get_size();
        if size == 0 { return; }

        // Find entry block (size_in == 0)
        let entry = (0..size).find(|&i| {
            self.graph.get_block(i).map_or(false, |b| b.read().unwrap().size_in() == 0)
        });
        let entry = match entry { Some(e) => e, None => return };

        // Build predecessor lists
        let mut preds: Vec<Vec<i32>> = vec![Vec::new(); size];
        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let b = block.read().unwrap();
            for slot in 0..b.size_out() {
                if let Some(edge) = b.get_out(slot) {
                    let tgt = edge.point.read().unwrap().get_index() as usize;
                    if tgt < size {
                        preds[tgt].push(i as i32);
                    }
                }
            }
        }

        // Initialize: idom[entry] = entry, all others = -1 (undefined)
        let mut idom_arr: Vec<i32> = vec![-1; size];
        idom_arr[entry] = entry as i32;

        // Iterative fixpoint
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..size {
                if i == entry { continue; }
                // Find first processed predecessor
                let mut new_idom = -1i32;
                for &p in &preds[i] {
                    if idom_arr[p as usize] != -1 {
                        if new_idom == -1 {
                            new_idom = p;
                        } else {
                            // intersect(p, new_idom)
                            let mut b1 = p;
                            let mut b2 = new_idom;
                            while b1 != b2 {
                                while b1 > b2 { b1 = idom_arr[b1 as usize]; if b1 == -1 { break; } }
                                while b2 > b1 { b2 = idom_arr[b2 as usize]; if b2 == -1 { break; } }
                                if b1 == -1 || b2 == -1 { break; }
                            }
                            new_idom = if b1 != -1 { b1 } else { new_idom };
                        }
                    }
                }
                if new_idom != -1 && new_idom != idom_arr[i] {
                    idom_arr[i] = new_idom;
                    changed = true;
                }
            }
        }

        for (i, &d) in idom_arr.iter().enumerate() {
            if d != -1 && d != i as i32 {
                self.idom.insert(i as i32, d);
            }
        }
    }

    /// Check if block index `a` dominates block index `b`.
    fn dominates_idx(&self, a: i32, b: i32) -> bool {
        if a == b { return true; }
        let mut cur = b;
        let mut steps = 0;
        while let Some(&d) = self.idom.get(&cur) {
            if d == a { return true; }
            cur = d;
            steps += 1;
            if steps > 10000 { break; } // safety
        }
        false
    }

    /// Collect indices of all switch case body blocks. Scans both BlockSwitch
    /// nodes and CBRANCH cascade chains (which produce switch-like structures
    /// using BlockIf nodes). Interleaved rules use this to avoid pulling case
    /// labels out of switch bodies.
    fn refresh_switch_cases(&mut self) {
        self.switch_case_indices.clear();
        self.compute_dominators(); // Build dominator tree for precise case body detection
        let size = self.graph.get_size();
        // Clear CASE_BODY flag on all blocks first
        for i in 0..size {
            if let Some(blk) = self.graph.get_block(i) {
                let mut b = blk.write().unwrap();
                let cur_flags = b.get_flags();
                b.set_flags(cur_flags & !crate::block::block_flags::CASE_BODY);
            }
        }
        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let b = block.read().unwrap();
            let bt = b.get_type();
            // BlockSwitch: collect its case + default bodies
            if bt == crate::block::BlockType::Switch {
                if let Some(bs) = b.as_any().downcast_ref::<crate::block::BlockSwitch>() {
                    for case in &bs.cases {
                        self.switch_case_indices.insert(case.read().unwrap().get_index());
                    }
                    if let Some(ref dc) = bs.default_case {
                        self.switch_case_indices.insert(dc.read().unwrap().get_index());
                    }
                }
            }
            drop(b);
            // CBRANCH cascade: detect by checking if this block is the head of a
            // chain of CBRANCH blocks where the taken target (out edge 1) is a
            // case body. Mark all such taken targets.
            // (This catches the cascade switches that collapse_cbranch_cascades
            // couldn't fully merge, or that were created as BlockIf chains.)
        }
        // Detect CBRANCH cascade chains: a sequence of CBRANCH blocks connected
        // via fallthrough (out[0]), where each has a taken target (out[1]).
        // A chain of 2+ such blocks is a cascade switch; all taken targets are
        // case bodies and must not be structurally extracted.
        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }
            if b.size_out() != 2 { continue; }
            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH);
            if !has_cbranch { continue; }
            // Check if fallthrough (out[0]) leads to another CBRANCH (cascade)
            let fallthrough = match b.get_out(0) { Some(e) => e.point.clone(), None => { continue; } };
            let ft_is_cbranch = {
                let ft = fallthrough.read().unwrap();
                if ft.size_out() != 2 { false }
                else {
                    let ft_ops = ft.get_ops();
                    ft_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                }
            };
            if !ft_is_cbranch { continue; }
            // This is a cascade head. Walk the chain and mark all taken targets.
            let mut current = block.clone();
            let mut visited = std::collections::HashSet::new();
            loop {
                let cur_idx = current.read().unwrap().get_index();
                if !visited.insert(cur_idx) { break; } // cycle guard
                let c = current.read().unwrap();
                if c.size_out() != 2 { break; }
                let c_ops = c.get_ops();
                let c_has_cbranch = c_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH);
                if !c_has_cbranch { break; }
                // Mark taken target (out[1]) as a case body
                if let Some(taken_edge) = c.get_out(1) {
                    let tidx = taken_edge.point.read().unwrap().get_index();
                    self.switch_case_indices.insert(tidx);
                    // CASE_BODY flag set after the loop to avoid write-in-read deadlock
                }
                // Follow fallthrough (out[0])
                let next = match c.get_out(0) { Some(e) => e.point.clone(), None => break };
                drop(c);
                current = next;
            }
        }
        // Dominator-based case body expansion: for each case body, add all
        // blocks it dominates (the case body sub-tree). This is precise —
        // only blocks truly inside the case body (on all paths from case entry)
        // are marked, unlike BFS which over-marks through fallthrough chains.
        let case_bodies: Vec<i32> = self.switch_case_indices.iter().copied().collect();
        for blk_idx in 0..size as i32 {
            // Check if this block is dominated by any case body
            for &case_idx in &case_bodies {
                if self.dominates_idx(case_idx, blk_idx) {
                    self.switch_case_indices.insert(blk_idx);
                    break;
                }
            }
        }
        // Set CASE_BODY flag on all collected case body blocks (batch, no
        // nested lock issues since we iterate by index)
        for &idx in &self.switch_case_indices {
            let i = idx as usize;
            if i < size {
                if let Some(blk) = self.graph.get_block(i) {
                    let mut b = blk.write().unwrap();
                    let new_flags = b.get_flags() | crate::block::block_flags::CASE_BODY;
                    b.set_flags(new_flags);
                }
            }
        }
    }

    /// Ghidra's identifyInternal: collapse consumed blocks into a structured block.
    /// Faithful port of BlockGraph::identifyInternal + selfIdentify (block.cc:940, 895).
    /// Steps:
    /// 1. Install new_block at install_idx (replaces the cond block).
    /// 2. self_identify: for each consumed block, copy its boundary edges
    ///    (edges to/from non-consumed blocks) onto new_block, and rewrite
    ///    external blocks' edges to point to new_block. This gives new_block
    ///    correct size_in/size_out so subsequent rules can match against it.
    /// 3. Dedup new_block's edges.
    /// 4. Clear consumed blocks' edges and mark DEAD (matching Ghidra's
    ///    list removal — consumed blocks become invisible).
    fn identify_internal(&mut self, new_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
                         consumed_indices: &[i32], install_idx: usize) {
        let size = self.graph.get_size();
        let consumed_set: std::collections::HashSet<i32> = consumed_indices.iter().copied().collect();

        // --- selfIdentify: capture boundary edges BEFORE overwriting install_idx ---
        // Ghidra's selfIdentify reads the consumed nodes' edges while they still
        // exist. We must read the cond block (at install_idx) before replacing it
        // with new_block, so capture all boundary edges first.
        let mut new_in: Vec<crate::block::BlockEdge> = Vec::new();
        let mut new_out: Vec<crate::block::BlockEdge> = Vec::new();

        // Capture external in-edges of the install_idx block (cond/head).
        // These are in-edges whose source is NOT in consumed_set AND NOT the
        // install_idx block itself (self-loop) AND NOT the new_block (avoid
        // double-counting). Without this, WhileDo loops whose head was at
        // install_idx become unreachable (only self-loop preds remain).
        // NOTE: do NOT capture out-edges of install_idx here — the head's
        // out-edges go to consumed clauses (internal) or merge blocks (already
        // captured via the consumed blocks' boundary out-edges). Capturing them
        // here would double-count and break httpd.
        if install_idx < size {
            if let Some(cb) = self.graph.get_block(install_idx) {
                let c = cb.read().unwrap();
                for slot in 0..c.size_in() {
                    if let Some(e) = c.get_in(slot) {
                        // Use try_read to avoid RwLock deadlock when the source
                        // block's lock is held (e.g. by a prior identify_internal
                        // edge rewrite on the same thread). Skip the edge if
                        // the lock can't be acquired.
                        let src_idx = match e.point.try_read() {
                            Ok(g) => g.get_index(),
                            Err(_) => continue,
                        };
                        // Exclude: consumed blocks, install_idx itself (self-loop),
                        // and the new_block (not yet installed, but guard anyway).
                        if !consumed_set.contains(&src_idx)
                            && src_idx != install_idx as i32 {
                            new_in.push(crate::block::BlockEdge::new(e.point.clone(), new_out.len() as i32));
                        }
                    }
                }
            }
        }

        for &c_idx in consumed_indices {
            let ci = c_idx as usize;
            if ci >= size { continue; }
            // Collect this consumed block's boundary edges.
            // IN-edges: source not in consumed set → boundary incoming.
            let (in_boundary, out_boundary) = {
                let cb = match self.graph.get_block(ci) { Some(b) => b, None => continue };
                let c = cb.read().unwrap();
                let mut ib = Vec::new();
                let mut ob = Vec::new();
                for slot in 0..c.size_in() {
                    if let Some(e) = c.get_in(slot) {
                        let src_idx = match e.point.try_read() {
                            Ok(g) => g.get_index(),
                            Err(_) => continue,
                        };
                        if !consumed_set.contains(&src_idx) {
                            ib.push(e.point.clone());
                        }
                    }
                }
                for slot in 0..c.size_out() {
                    if let Some(e) = c.get_out(slot) {
                        let dst_idx = match e.point.try_read() {
                            Ok(g) => g.get_index(),
                            Err(_) => continue,
                        };
                        if !consumed_set.contains(&dst_idx) {
                            ob.push(e.point.clone());
                        }
                    }
                }
                (ib, ob)
            };
            // Add boundary edges to new_block (record the external block).
            for src in &in_boundary {
                new_in.push(crate::block::BlockEdge::new(src.clone(), new_out.len() as i32));
            }
            for dst in &out_boundary {
                new_out.push(crate::block::BlockEdge::new(dst.clone(), new_in.len() as i32));
            }
            // Rewrite external blocks' edges to point to new_block, mirroring
            // Ghidra selfIdentify's replaceOutEdge/replaceInEdge. This keeps
            // parent CBRANCH out-edges consistent when their clause is consumed
            // elsewhere (otherwise the parent's edge points at a now-DEAD block).
            // Only Basic external blocks are rewritten (structured blocks keep
            // their own edge vectors and are handled when they are the parent).
            for src in &in_boundary {
                let s_any = src.clone();
                // Avoid self-loop: don't rewrite new_block's own edge
                if std::sync::Arc::ptr_eq(&s_any, new_block) { continue; }
                let mut sb = s_any.write().unwrap();
                let sref = sb.as_any_mut();
                if let Some(bb) = sref.downcast_mut::<crate::block::BlockBasic>() {
                    for eslot in 0..bb.outgoing.len() {
                        // Use try_read: we hold sb's write lock, and if
                        // outgoing[eslot].point IS sb (self-loop edge),
                        // read would deadlock. try_read returns Err, skip.
                        let t = match bb.outgoing[eslot].point.try_read() {
                            Ok(g) => g.get_index(),
                            Err(_) => continue,
                        };
                        if t == c_idx {
                            bb.outgoing[eslot].point = new_block.clone();
                        }
                    }
                }
            }
            for dst in &out_boundary {
                let d_any = dst.clone();
                if std::sync::Arc::ptr_eq(&d_any, new_block) { continue; }
                let mut db = d_any.write().unwrap();
                let dref = db.as_any_mut();
                if let Some(bb) = dref.downcast_mut::<crate::block::BlockBasic>() {
                    for dslot in 0..bb.incoming.len() {
                        // try_read: we hold db's write lock; if incoming[dslot].point
                        // IS db (self-loop), read would deadlock.
                        let s = match bb.incoming[dslot].point.try_read() {
                            Ok(g) => g.get_index(),
                            Err(_) => continue,
                        };
                        if s == c_idx {
                            bb.incoming[dslot].point = new_block.clone();
                        }
                    }
                }
            }
        }

        // Dedup new_block's edges (Ghidra selfIdentify ends with dedup()).
        let mut seen_in: Vec<std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        new_in.retain(|e| {
            let dup = seen_in.iter().any(|a| std::sync::Arc::ptr_eq(a, &e.point));
            if !dup { seen_in.push(e.point.clone()); }
            !dup
        });
        let mut seen_out: Vec<std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        new_out.retain(|e| {
            let dup = seen_out.iter().any(|a| std::sync::Arc::ptr_eq(a, &e.point));
            if !dup { seen_out.push(e.point.clone()); }
            !dup
        });
        // Fix reverse_index after dedup.
        for (i, e) in new_out.iter_mut().enumerate() {
            e.reverse_index = i as i32;
        }
        for (i, e) in new_in.iter_mut().enumerate() {
            e.reverse_index = i as i32;
        }

        // Install the collected boundary edges onto new_block (downcast to a
        // concrete block type that owns incoming/outgoing vectors).
        {
            let mut nb = new_block.write().unwrap();
            let nref = nb.as_any_mut();
            // BlockIf / BlockList / BlockWhileDo / BlockDoWhile / BlockGoto / BlockSwitch
            // all expose incoming/outgoing via as_any_mut. Try the common ones.
            if let Some(bif) = nref.downcast_mut::<crate::block::BlockIf>() {
                bif.incoming = new_in; bif.outgoing = new_out;
            } else if let Some(blist) = nref.downcast_mut::<crate::block::BlockList>() {
                blist.incoming = new_in; blist.outgoing = new_out;
            } else if let Some(bwd) = nref.downcast_mut::<crate::block::BlockWhileDo>() {
                bwd.incoming = new_in; bwd.outgoing = new_out;
            } else if let Some(bdw) = nref.downcast_mut::<crate::block::BlockDoWhile>() {
                bdw.incoming = new_in; bdw.outgoing = new_out;
            } else if let Some(bgt) = nref.downcast_mut::<crate::block::BlockGoto>() {
                bgt.incoming = new_in; bgt.outgoing = new_out;
            }
        }

        // NOW install new_block at install_idx (replaces the cond block).
        // Done AFTER self_identify captured the cond block's boundary edges.
        // IMPORTANT: capture the old block's Arc BEFORE replacing, then update
        // all other blocks' out-edges that pointed to the old block to point to
        // new_block. Without this, Arc-identity edges keep pointing at the old
        // (now-replaced) block, making the new structured block unreachable.
        if install_idx < size {
            let old_block = self.graph.blocks[install_idx].clone();
            self.graph.blocks[install_idx] = new_block.clone();
            // Scan all blocks; for any out-edge whose point Arc-matches old_block,
            // redirect it to new_block.
            for gi in 0..size {
                if gi == install_idx { continue; }
                let gb = match self.graph.get_block(gi) { Some(b) => b, None => continue };
                let mut gw = gb.write().unwrap();
                let gref = gw.as_any_mut();
                // BlockBasic edges:
                if let Some(bb) = gref.downcast_mut::<crate::block::BlockBasic>() {
                    for e in bb.outgoing.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                    for e in bb.incoming.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                } else if let Some(blist) = gref.downcast_mut::<crate::block::BlockList>() {
                    for e in blist.outgoing.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                    for e in blist.incoming.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                } else if let Some(bif) = gref.downcast_mut::<crate::block::BlockIf>() {
                    for e in bif.outgoing.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                    for e in bif.incoming.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                } else if let Some(bwd) = gref.downcast_mut::<crate::block::BlockWhileDo>() {
                    for e in bwd.outgoing.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                    for e in bwd.incoming.iter_mut() {
                        if std::sync::Arc::ptr_eq(&e.point, &old_block) {
                            e.point = new_block.clone();
                        }
                    }
                }
            }
        }

        // Clear consumed blocks' edges and mark DEAD (Ghidra removes them from list).
        for &idx in consumed_indices {
            let i = idx as usize;
            if i < size && i != install_idx {
                let mut b = self.graph.blocks[i].write().unwrap();
                let any_ref = b.as_any_mut();
                if let Some(bb) = any_ref.downcast_mut::<crate::block::BlockBasic>() {
                    bb.clear_edges();
                }
                b.set_flags(crate::block::block_flags::DEAD);
            }
        }
    }

    /// Ghidra's ruleBlockCat (blockaction.cc:1284): concatenate a chain of
    /// blocks into a single BlockList. Faithful port with chain extension.
    /// bl must have 1 out-edge to outblock, outblock has 1 in-edge, and bl must
    /// be the START of a chain (its in-edge source has >1 out OR bl has >1 in).
    /// Then extend the chain while each link has 1 out, 1 in, no switch, no goto.
    fn try_rule_cat(&mut self, i: usize) -> bool {
        let size = self.graph.get_size();
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return false,
        };
        // bl->sizeOut() != 1
        {
            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { return false; }
            if b.size_out() != 1 { return false; }
            // bl->isSwitchOut() — skip switch dispatch blocks
            if b.get_flags() & crate::block::block_flags::CASE_BODY != 0 { return false; }
            if b.get_type() == crate::block::BlockType::Condition { return false; }
        }
        // bl must be the START of a chain: (sizeIn==1 && getIn(0)->sizeOut==1) → false
        // i.e. bl is a chain start if it has multiple in-edges, OR its sole
        // predecessor has multiple out-edges (bl is a branch target).
        {
            let b = block.read().unwrap();
            let block_idx = b.get_index();
            if b.size_in() == 1 {
                if let Some(in_edge) = b.get_in(0) {
                    let pred_out = in_edge.point.read().unwrap().size_out();
                    if pred_out == 1 { return false; } // not start of chain
                }
            }
            // bl->getOut(0) == bl → no looping
            if let Some(out_edge) = b.get_out(0) {
                if out_edge.point.read().unwrap().get_index() == block_idx { return false; }
            }
        }

        // Build the cat chain starting with [block, outblock]
        let mut nodes: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        nodes.push(block.clone());

        // outblock = bl->getOut(0); checks: != bl, sizeIn==1, !isSwitchOut
        let mut cur = block.clone();
        loop {
            let cur_out = {
                let c = cur.read().unwrap();
                if c.size_out() != 1 { break; }
                c.get_out(0).map(|e| e.point.clone())
            };
            let next = match cur_out { Some(n) => n, None => break };
            let next_idx = next.read().unwrap().get_index();
            let cur_idx = cur.read().unwrap().get_index();
            // outblock == bl → no looping
            if next_idx == cur_idx { break; }
            let (n_in, n_out, n_type, n_flags) = {
                let n = next.read().unwrap();
                (n.size_in(), n.size_out(), n.get_type(), n.get_flags())
            };
            // outblock->sizeIn() != 1 → stop (something else hits outblock)
            if n_in != 1 { break; }
            // outblock->isSwitchOut() → stop
            if n_flags & crate::block::block_flags::CASE_BODY != 0 { break; }
            // Faithful to Ghidra ruleBlockCat (blockaction.cc:1296-1308): merge
            // ANY block type (Basic, BlockList, BlockIf, BlockCondition, etc.)
            // as long as it has sizeIn==1, sizeOut==1, not switch-out. The
            // earlier restriction to Basic/Copy prevented cat-chaining of
            // partially-structured loop bodies (e.g. an if-inside-loop that
            // became BlockIf), which blocked WhileDo formation.
            // Don't consume a loop head — it must remain available for
            // try_rule_while_do/try_rule_do_while.
            if self.loop_bodies.iter().any(|(h, _)| *h == next_idx) { break; }
            // Extend chain (Ghidra: nodes.push_back(outblock))
            nodes.push(next.clone());

            // Continue extending while outblock->sizeOut()==1 and conditions hold
            if n_out != 1 { break; }
            cur = next;
            // Safety: limit chain length
            if nodes.len() > 64 { break; }
        }

        // Need at least 2 nodes to form a cat
        if nodes.len() < 2 { return false; }

        // Consume all nodes except the first (block stays at install_idx=i).
        // Ghidra newBlockList(nodes) passes ALL nodes to identifyInternal; here
        // block sits at install_idx so we consume nodes[1..].
        let block_idx = block.read().unwrap().get_index();
        let consumed: Vec<i32> = nodes[1..].iter().map(|n| n.read().unwrap().get_index()).collect();
        let list_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockList::new(block_idx, nodes)));
        self.identify_internal(&list_block, &consumed, i);
        self.update_switch_case_reference(block_idx, &list_block);
        self.change_count += 1;
        true
    }

    /// Update any BlockSwitch that has `old_idx` as a case body to point to `new_block`.
    /// This ensures switch case bodies that get structured into BlockIf/BlockList
    /// are correctly referenced by their owning BlockSwitch.
    fn update_switch_case_reference(&mut self, old_idx: i32, new_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        let size = self.graph.get_size();
        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let bt = { let b = block.read().unwrap(); b.get_type() };
            if bt != crate::block::BlockType::Switch { continue; }
            let (sw_fields) = {
                let b = block.read().unwrap();
                let sw = match b.as_any().downcast_ref::<BlockSwitch>() { Some(s) => s, None => continue };
                let in_cases = sw.cases.iter().any(|c| c.read().unwrap().get_index() == old_idx);
                let in_default = sw.default_case.as_ref().map_or(false, |d| d.read().unwrap().get_index() == old_idx);
                if !in_cases && !in_default { continue; }
                (sw.index, sw.control.clone(), sw.cases.clone(),
                 sw.default_case.clone(), sw.case_values.clone(), sw.index_varnode.clone())
            };
            // Rebuild with updated references
            let mut new_cases = Vec::new();
            for case in &sw_fields.2 {
                if case.read().unwrap().get_index() == old_idx {
                    new_cases.push(new_block.clone());
                } else {
                    new_cases.push(case.clone());
                }
            }
            let new_default = sw_fields.3.as_ref().map(|d| {
                if d.read().unwrap().get_index() == old_idx { new_block.clone() } else { d.clone() }
            });
            let new_sw: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockSwitch {
                    index: sw_fields.0, control: sw_fields.1, cases: new_cases,
                    default_case: new_default, case_values: sw_fields.4,
                    index_varnode: sw_fields.5,
                    incoming: Vec::new(), outgoing: Vec::new(), parent: None, flags: 0,
                }));
            self.graph.blocks[i] = new_sw;
            eprintln!("[COLLAPSE] {} updated BlockSwitch case {} → BlockIf", self.name, old_idx);
            break;
        }
    }

    /// Count in-edges that are NOT from switch dispatch blocks.
    /// Switch dispatch edges come from BlockSwitch nodes or CBRANCH cascade
    /// members (blocks whose taken edge targets a CASE_BODY block).
    /// These structural edges should not prevent proper_if/if_else matching.
    fn count_non_structural_in_edges(&self, block: &std::sync::RwLockReadGuard<'_, dyn FlowBlock + Send + Sync>) -> usize {
        let total = block.size_in();
        let mut structural = 0;
        for slot in 0..total {
            if let Some(in_edge) = block.get_in(slot) {
                let pred = in_edge.point.read().unwrap();
                let pred_type = pred.get_type();
                // Edge from BlockSwitch control → structural
                if pred_type == crate::block::BlockType::Switch {
                    structural += 1;
                    continue;
                }
                // Edge from a CBRANCH cascade member → structural
                // (cascade members are blocks in switch_case_indices)
                if self.switch_case_indices.contains(&pred.get_index()) {
                    structural += 1;
                    continue;
                }
                // Edge from a DEAD block (already consumed by structuring) → structural
                if pred.get_flags() & crate::block::block_flags::DEAD != 0 {
                    structural += 1;
                    continue;
                }
            }
        }
        total - structural
    }

    /// ruleBlockProperIf: detect if-then pattern (generalized Triangle).
    /// A CBRANCH block with 2 out-edges, where one out-edge block (clause)
    /// has 1 in and 1 out, and its out-edge points to the other branch.
    fn try_rule_proper_if(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return false,
        };
        let b = block.read().unwrap();
        if b.size_out() != 2 { return false; }

        // Check that this block ends with a CBRANCH
        let ops = b.get_ops();
        let has_cbranch = ops.last().map_or(false, |op_ref| {
            op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
        });
        if !has_cbranch { return false; }

        let cond_idx = b.get_index();
        let true_edge = match b.get_out(0) { Some(e) => e, None => return false };
        let false_edge = match b.get_out(1) { Some(e) => e, None => return false };
        let true_block = true_edge.point.clone();
        let false_block = false_edge.point.clone();
        let true_idx = true_block.read().unwrap().get_index();
        let false_idx = false_block.read().unwrap().get_index();
        drop(b);

        // Protect: if either branch target is a switch case body, don't
        // structurally extract it — would pull `case` label out of switch.
        if self.switch_case_indices.contains(&true_idx)
            || self.switch_case_indices.contains(&false_idx) {
            return false;
        }

        // Try both directions (i=0: true clause, i=1: false clause)
        for dir in 0..2 {
            let clause = if dir == 0 { true_block.clone() } else { false_block.clone() };
            let merge = if dir == 0 { false_block.clone() } else { true_block.clone() };
            let merge_idx = if dir == 0 { false_idx } else { true_idx };

            let c = clause.read().unwrap();
            let c_idx = c.get_index();
            // Count non-structural in-edges: ignore edges from switch dispatch blocks.
            // Switch dispatch edges come from BlockSwitch control blocks or CBRANCH
            // cascade members. We check if any in-edge source is a BlockSwitch or
            // a block we know is a switch dispatch (marked CASE_BODY or is a cascade
            // member whose taken edge targets this clause).
            let non_structural_in = self.count_non_structural_in_edges(&c);
            if non_structural_in != 1 { continue; }
            if c.size_out() != 1 { continue; }
            // Note: we no longer skip switch case body blocks here — the DEAD flag
            // and orphan case label removal handle case label integrity at emit time.
            // Removing this guard allows CBRANCH blocks inside case bodies to be
            // structured into BlockIf, which is what we need for control-flow recovery.
            let clause_out = match c.get_out(0) { Some(e) => e, None => continue };
            let target_idx = clause_out.point.read().unwrap().get_index();
            drop(c);
            if target_idx != merge_idx { continue; }

            // Match found: clause → merge. Create BlockIf.
            let negated = dir == 1; // if clause is the false edge, negate
            let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockIf {
                    index: cond_idx,
                    condition: block.clone(),
                    if_body: clause.clone(),
                    else_body: None,
                    negated,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));
            let clause_idx = clause.read().unwrap().get_index();
            // self_identify captures the clause's boundary edges onto the new
            // BlockIf (installed at i). We pass only the clause index (not cond),
            // because cond sits at install_idx and is handled separately.
            self.identify_internal(&if_block, &[clause_idx], i);
            self.update_switch_case_reference(cond_idx, &if_block);
            self.change_count += 1;
            return true;
        }
        false
    }

    /// ruleBlockIfNoExit: detect if-then where the clause has NO out-edge
    /// (ends with RETURN/exit). The clause doesn't merge back — it exits.
    /// Mirrors Ghidra's ruleBlockIfNoExit (blockaction.cc:1481).
    /// Protected against switch case extraction via switch_case_indices.
    fn try_rule_if_no_exit(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return false,
        };
        let b = block.read().unwrap();
        if b.size_out() != 2 { return false; }

        let ops = b.get_ops();
        let has_cbranch = ops.last().map_or(false, |op_ref| {
            op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
        });
        if !has_cbranch { return false; }

        // Don't apply if this CBRANCH is part of a cascade chain. A cascade
        // member is detected by: (a) its fallthrough leads to another CBRANCH,
        // OR (b) one of its predecessors is a CBRANCH (cascade tail — reached
        // via fallthrough from the previous CBRANCH in the chain).
        let is_cascade_member = {
            let ft_is_cbranch = if let Some(ft_edge) = b.get_out(0) {
                let ft = ft_edge.point.read().unwrap();
                if ft.size_out() == 2 {
                    let ft_ops = ft.get_ops();
                    ft_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                } else { false }
            } else { false };
            let pred_is_cbranch = if b.size_in() >= 1 {
                (0..b.size_in()).any(|slot| {
                    if let Some(in_edge) = b.get_in(slot) {
                        let pred = in_edge.point.read().unwrap();
                        if pred.size_out() == 2 {
                            let pred_ops = pred.get_ops();
                            pred_ops.last().map_or(false, |o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                        } else { false }
                    } else { false }
                })
            } else { false };
            ft_is_cbranch || pred_is_cbranch
        };
        if is_cascade_member { return false; }

        let cond_idx = b.get_index();
        let true_edge = match b.get_out(0) { Some(e) => e, None => return false };
        let false_edge = match b.get_out(1) { Some(e) => e, None => return false };
        let true_block = true_edge.point.clone();
        let false_block = false_edge.point.clone();
        let true_idx = true_block.read().unwrap().get_index();
        let false_idx = false_block.read().unwrap().get_index();
        drop(b);

        // Protect switch case bodies
        if self.switch_case_indices.contains(&true_idx)
            || self.switch_case_indices.contains(&false_idx) {
            return false;
        }
        // Also check CASE_BODY flag (set by refresh_switch_cases)
        if true_block.read().unwrap().get_flags() & crate::block::block_flags::CASE_BODY != 0
            || false_block.read().unwrap().get_flags() & crate::block::block_flags::CASE_BODY != 0 {
            return false;
        }

        for dir in 0..2 {
            let clause = if dir == 0 { true_block.clone() } else { false_block.clone() };
            let c = clause.read().unwrap();
            let c_idx = c.get_index();
            if c.size_in() != 1 { continue; }
            if c.size_out() != 0 { continue; } // Must have no out-edge (RETURN/exit)
            // Protect: don't extract switch case bodies — they must stay inside
            // their BlockSwitch or the emitted `case` label ends up outside the switch.
            if self.switch_case_indices.contains(&c_idx) { continue; }
            // Also check CASE_BODY flag directly on the clause
            if c.get_flags() & crate::block::block_flags::CASE_BODY != 0 { continue; }
            drop(c);

            let negated = dir == 1;
            let clause_idx = clause.read().unwrap().get_index();
            let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockIf {
                    index: cond_idx,
                    condition: block.clone(),
                    if_body: clause.clone(),
                    else_body: None,
                    negated,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));
            // self_identify captures the clause's boundary edges onto the new BlockIf.
            self.identify_internal(&if_block, &[clause_idx], i);
            self.update_switch_case_reference(cond_idx, &if_block);
            self.change_count += 1;
            return true;
        }
        false
    }

    /// ruleBlockIfElse: detect if-then-else pattern.
    /// A CBRANCH block with 2 out-edges, both clause blocks have 1 in and
    /// 1 out, and both out-edges point to the same merge block.
    fn try_rule_if_else(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return false,
        };
        let b = block.read().unwrap();
        if b.size_out() != 2 { return false; }

        let ops = b.get_ops();
        let has_cbranch = ops.last().map_or(false, |op_ref| {
            op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
        });
        if !has_cbranch { return false; }

        let cond_idx = b.get_index();
        let true_edge = match b.get_out(0) { Some(e) => e, None => return false };
        let false_edge = match b.get_out(1) { Some(e) => e, None => return false };
        let true_block = true_edge.point.clone();
        let false_block = false_edge.point.clone();
        drop(b);

        // Check both clauses: 1 in, 1 out, same merge target
        let tb = true_block.read().unwrap();
        let fb = false_block.read().unwrap();
        if tb.size_in() != 1 || fb.size_in() != 1 { return false; }
        if tb.size_out() != 1 || fb.size_out() != 1 { return false; }

        let t_out = match tb.get_out(0) { Some(e) => e.point.read().unwrap().get_index(), None => return false };
        let f_out = match fb.get_out(0) { Some(e) => e.point.read().unwrap().get_index(), None => return false };
        drop(tb); drop(fb);

        if t_out != f_out { return false; } // both must merge to same block

        let t_idx = true_block.read().unwrap().get_index();
        let f_idx = false_block.read().unwrap().get_index();
        let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockIf {
                index: cond_idx,
                condition: block.clone(),
                if_body: true_block.clone(),
                else_body: Some(false_block.clone()),
                negated: false,
                incoming: Vec::new(),
                outgoing: Vec::new(),
                parent: None,
                flags: 0,
            }));
        // self_identify captures both clauses' boundary edges onto the new BlockIf.
        self.identify_internal(&if_block, &[t_idx, f_idx], i);
        self.update_switch_case_reference(cond_idx, &if_block);
        self.change_count += 1;
        true
    }

    /// ruleBlockIfGoto: when a CBRANCH block has GOTO_EDGE_1 set (taken edge
    /// marked as goto by selectGoto), structure it as if(cond) goto target.
    /// The remaining effective edge (fallthrough) becomes the if-body.
    /// This creates a BlockIf whose condition is negated (if NOT cond, do body).
    fn try_rule_if_goto(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return false,
        };
        let b = block.read().unwrap();
        let flags = b.get_flags();
        // Must have GOTO_EDGE_1 set (taken edge is goto)
        if flags & crate::block::block_flags::GOTO_EDGE_1 == 0 { return false; }
        if b.size_out() != 2 { return false; }

        let ops = b.get_ops();
        let has_cbranch = ops.last().map_or(false, |op_ref| {
            op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
        });
        if !has_cbranch { return false; }

        let cond_idx = b.get_index();
        // The non-goto edge (out[0]) is the fallthrough = the "if body"
        let body_edge = match b.get_out(0) { Some(e) => e, None => return false };
        let body_block = body_edge.point.clone();
        let body_idx = body_block.read().unwrap().get_index();
        drop(b);

        // Don't extract switch case bodies
        if self.switch_case_indices.contains(&body_idx) { return false; }

        // Create BlockIf with negated condition.
        // Note: Ghidra's newBlockIfGoto consumes only [cond] and keeps the body
        // external via forceFalseEdge. Our BlockIf architecture embeds the body,
        // so we consume it (identify_internal) to avoid a dangling visible node
        // and mark DEAD, matching the "clause absorbed into BlockIf" semantics.
        let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockIf {
                index: cond_idx,
                condition: block.clone(),
                if_body: body_block.clone(),
                else_body: None,
                negated: true,
                incoming: Vec::new(),
                outgoing: Vec::new(),
                parent: None,
                flags: 0,
            }));
        // self_identify captures the body's boundary edges onto the new BlockIf.
        self.identify_internal(&if_block, &[body_idx], i);
        self.update_switch_case_reference(cond_idx, &if_block);
        self.change_count += 1;
        true
    }

    /// Ghidra ruleBlockGoto (blockaction.cc:1450), pure-goto branch (size_out==1).
    /// A block whose single out-edge is marked as goto (GOTO_EDGE_0) becomes a
    /// BlockGoto. This lets clip_extra_roots / select_and_mark_goto consumed:
    /// without it, goto-marked single-out blocks never get structured and the
    /// goto-cascade loops forever. Mirrors Ghidra newBlockGoto(bl): wrap bl in a
    /// BlockGoto storing the goto target, consume [bl], forceOutputNum(1).
    /// The BlockGoto behaves as a single node so surrounding cat/if rules can
    /// merge it; at emit time it renders the block's ops followed by a goto.
    fn try_rule_goto(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b, None => return false,
        };
        let (idx, flags, size_out, goto_target) = {
            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic { return false; }
            let flags = b.get_flags();
            // Must have a goto-marked out-edge
            let has_goto = (b.size_out() >= 1 && flags & crate::block::block_flags::GOTO_EDGE_0 != 0)
                        || (b.size_out() >= 2 && flags & crate::block::block_flags::GOTO_EDGE_1 != 0);
            if !has_goto { return false; }
            // Pure-goto case: size_out==1 with GOTO_EDGE_0. (size_out==2 with
            // GOTO_EDGE_1 is handled by try_rule_if_goto as newBlockIfGoto.)
            if b.size_out() != 1 { return false; }
            if flags & crate::block::block_flags::GOTO_EDGE_0 == 0 { return false; }
            let target = b.get_out(0).map(|e| e.point.clone());
            (b.get_index(), flags, b.size_out(), target)
        };
        let goto_target = match goto_target { Some(t) => t, None => return false };

        // Build a BlockGoto wrapping the block. Store the goto target.
        // The BlockGoto is installed at i; the original block (Basic) is consumed.
        // Per Ghidra newBlockGoto: identifyInternal([bl]) + forceOutputNum(1) +
        // removeEdge(ret, ret->getOut(0)). We model forceOutputNum(1)+removeEdge
        // by giving the BlockGoto an empty out-edge list (the goto is "absorbed").
        let goto_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = {
            // BlockGoto.goto_target is Option<Arc<BlockBasic>>; downcast target.
            let target_bb = goto_target.clone();
            let target_basic = target_bb.read().unwrap().as_any()
                .downcast_ref::<crate::block::BlockBasic>().map(|_| {
                    // We can't easily get the Arc<BlockBasic> from dyn; store None
                    // and rely on the original block's ops for emit. The goto
                    // target is implicit via the consumed block's out-edge.
                    None::<Arc<RwLock<crate::block::BlockBasic>>>
                }).flatten();
            let _ = target_basic; // BlockGoto target kept implicit for now
            Arc::new(RwLock::new(crate::block::BlockGoto {
                index: idx,
                flags: 0,
                parent: None,
                goto_target: None, // implicit; emit uses wrapped block's BRANCH op
                incoming: Vec::new(),
                outgoing: Vec::new(),
            }))
        };
        // Consume the original block (at i). self_identify captures its boundary
        // edges onto the BlockGoto so it has correct size_in for further merging.
        self.identify_internal(&goto_block, &[idx], i);
        self.update_switch_case_reference(idx, &goto_block);
        // Faithful to Ghidra newBlockGoto: removeEdge(ret, ret->getOut(0)).
        // After identify_internal, the goto_target has an in-edge from the new
        // BlockGoto. Remove it so the target's sizeIn no longer counts the
        // goto source — this is the "consumption" that lets WhileDo match.
        {
            let goto_idx = goto_block.read().unwrap().get_index();
            goto_target.write().unwrap().remove_in_edge_from(&[goto_idx, idx]);
        }
        self.change_count += 1;
        eprintln!("[COLLAPSE] {} ruleBlockGoto: wrapped block {} (size_out={})", self.name, idx, size_out);
        true
    }

    /// ruleBlockWhileDo: detect while(cond) { body } pattern.
    /// A CBRANCH block with 2 out-edges, where one out-edge (clause) has
    /// size_in==1, size_out==1, and its single out-edge loops back to the
    /// CBRANCH block. Mirrors Ghidra's ruleBlockWhileDo (blockaction.cc:1518).
    fn try_rule_while_do(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b, None => return false,
        };
        let b = block.read().unwrap();
        if b.size_out() != 2 { return false; }
        // Skip switch dispatch blocks
        if b.get_flags() & crate::block::block_flags::CASE_BODY != 0 { return false; }

        let cond_idx = b.get_index();
        for slot in 0..2 {
            let clause = match b.get_out(slot) { Some(e) => e.point.clone(), None => continue };
            let c = clause.read().unwrap();
            // Accept both Basic and structured (BlockList) clauses. Ghidra's
            // ruleBlockWhileDo requires sizeIn()==1, but after cat-chaining the
            // body may be a BlockList that still has a single back-edge to cond.
            // We use count_non_structural_in_edges to ignore DEAD/goto sources.
            let clause_in = self.count_non_structural_in_edges(&c);
            if clause_in != 1 { continue; }
            if c.size_out() != 1 { continue; }
            // Clause must loop back to the condition block
            let clause_out = match c.get_out(0) { Some(e) => e, None => continue };
            if clause_out.point.read().unwrap().get_index() != cond_idx { continue; }
            drop(c);

            // Found while-do: cond block + clause (body) that loops back
            let negated = slot == 1; // If clause is on false edge, negate condition
            let clause_idx = clause.read().unwrap().get_index();
            let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(crate::block::BlockWhileDo {
                    index: cond_idx,
                    condition: block.clone(),
                    body: clause,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));
            // Ghidra newBlockWhileDo: identifyInternal([cond, cl]) + forceOutputNum(1).
            // Consume the body clause; self_identify captures its boundary edges.
            let _ = negated;
            self.identify_internal(&while_block, &[clause_idx], i);
            self.update_switch_case_reference(cond_idx, &while_block);
            self.change_count += 1;
            return true;
        }
        false
    }

    /// ruleBlockDoWhile: detect do { body } while(cond) pattern.
    /// A CBRANCH block where one out-edge loops back to itself.
    /// Mirrors Ghidra's ruleBlockDoWhile (blockaction.cc:1555).
    fn try_rule_do_while(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b, None => return false,
        };
        let b = block.read().unwrap();
        if b.size_out() != 2 { return false; }
        if b.get_flags() & crate::block::block_flags::CASE_BODY != 0 { return false; }

        let cond_idx = b.get_index();
        for slot in 0..2 {
            let target = match b.get_out(slot) { Some(e) => e.point.clone(), None => continue };
            // Must loop back to itself
            if target.read().unwrap().get_index() != cond_idx { continue; }
            drop(b);

            // Found do-while: this block loops back on itself
            let do_while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(crate::block::BlockDoWhile {
                    index: cond_idx,
                    condition: block.clone(),
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));
            // Ghidra newBlockDoWhile(condcl): identifyInternal([condcl]).
            // The condcl block is consumed so its boundary edges (entry from
            // outside the loop, exit to the fallthrough) are captured onto the
            // new BlockDoDoWhile. condcl sits at install_idx=i.
            self.identify_internal(&do_while_block, &[cond_idx], i);
            self.update_switch_case_reference(cond_idx, &do_while_block);
            self.change_count += 1;
            return true;
        }
        drop(b);
        false
    }


    fn dominates(&self, dom: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, node: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        let dom_idx = dom.read().unwrap().get_index();
        let mut curr = node.clone();
        let max_depth = 1000; // Safety limit to prevent infinite traversal
        for _ in 0..max_depth {
            if curr.read().unwrap().get_index() == dom_idx {
                return true;
            }
            let immed_dom = curr.read().unwrap().get_immed_dom();
            match immed_dom {
                Some(weak_parent) => {
                    if let Some(parent) = weak_parent.upgrade() {
                        curr = parent;
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }
        false
    }


    fn collapse_loops(&mut self) {
        self.graph.build_dom_tree();

        let size = self.graph.get_size();
        let mut replacements: Vec<(usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = Vec::new();

        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }

            let mut true_is_backedge = false;
            let mut false_is_backedge = false;
            let mut true_target = None;
            let mut false_target = None;

            if b.size_out() == 2 {
                let ops = b.get_ops();
                let has_cbranch = ops.last().map_or(false, |op_ref| {
                    op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                });
                
                if has_cbranch {
                    if let Some(true_edge) = b.get_out(0) {
                        true_target = Some(true_edge.point.clone());
                        if self.dominates(&true_edge.point, &block) {
                            true_is_backedge = true;
                        }
                    }
                    if let Some(false_edge) = b.get_out(1) {
                        false_target = Some(false_edge.point.clone());
                        if self.dominates(&false_edge.point, &block) {
                            false_is_backedge = true;
                        }
                    }
                }
            }

            let cond_idx = b.get_index();
            drop(b);

            if true_is_backedge && !false_is_backedge {
                if let Some(tb) = true_target {
                    if tb.read().unwrap().get_index() == cond_idx {
                        let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                            Arc::new(RwLock::new(crate::block::BlockDoWhile {
                                index: cond_idx,
                                condition: block.clone(),
                                incoming: Vec::new(),
                                outgoing: Vec::new(),
                                parent: None,
                                flags: 0,
                            }));
                        replacements.push((i, while_block));
                        self.change_count += 1;
                        continue;
                    }
                }
            } else if false_is_backedge && !true_is_backedge {
                if let Some(fb) = false_target {
                    if fb.read().unwrap().get_index() == cond_idx {
                        let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                            Arc::new(RwLock::new(crate::block::BlockDoWhile {
                                index: cond_idx,
                                condition: block.clone(),
                                incoming: Vec::new(),
                                outgoing: Vec::new(),
                                parent: None,
                                flags: 0,
                            }));
                        replacements.push((i, while_block));
                        self.change_count += 1;
                        continue;
                    }
                }
            }

            // Simple While-Do check (A -> B -> A)
            if !true_is_backedge && !false_is_backedge {
                let b = block.read().unwrap();
                if b.size_out() == 2 {
                    if let (Some(te), Some(fe)) = (b.get_out(0), b.get_out(1)) {
                        let tb = te.point.clone();
                        let _fb = fe.point.clone();
                        drop(b);
                        
                        let tbr = tb.read().unwrap();
                        if tbr.size_out() == 1 && tbr.size_in() == 1 {
                            if let Some(out_edge) = tbr.get_out(0) {
                                if out_edge.point.read().unwrap().get_index() == cond_idx {
                                    drop(tbr);
                                    let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                        Arc::new(RwLock::new(BlockWhileDo {
                                            index: cond_idx,
                                            condition: block.clone(),
                                            body: tb.clone(),
                                            incoming: Vec::new(),
                                            outgoing: Vec::new(),
                                            parent: None,
                                            flags: 0,
                                        }));
                                    replacements.push((i, while_block));
                                    self.change_count += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Natural loop detection: find latch blocks with unconditional
        // BRANCH back to a dominating header (header has CBRANCH with 2 out).
        // This handles multi-block loop bodies that the simple A→B→A check misses.
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }
            if b.size_out() != 1 {
                continue;
            }

            let ops = b.get_ops();
            let has_branch = ops.last().map_or(false, |op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_BRANCH
            });
            if !has_branch {
                continue;
            }

            let target_edge = match b.get_out(0) {
                Some(e) => e,
                None => continue,
            };
            let latch_idx = b.get_index();
            drop(b);

            if !self.dominates(&target_edge.point, &block) {
                continue;
            }

            let header = target_edge.point.clone();
            let header_idx = header.read().unwrap().get_index();

            if replacements.iter().any(|(idx, _)| *idx == header_idx as usize) {
                continue;
            }
            if replacements.iter().any(|(idx, _)| *idx == latch_idx as usize) {
                continue;
            }

            let header_has_cbranch = {
                let h = header.read().unwrap();
                if h.size_out() != 2 {
                    continue;
                }
                let ops = h.get_ops();
                ops.last().map_or(false, |op_ref| {
                    op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                })
            };
            if !header_has_cbranch {
                continue;
            }

            let h = header.read().unwrap();
            let out0 = h.get_out(0).unwrap().point.clone();
            let out1 = h.get_out(1).unwrap().point.clone();
            drop(h);

            let out0_idx = out0.read().unwrap().get_index();
            let out1_idx = out1.read().unwrap().get_index();

            let (body_entry, _exit_block) = if out0_idx == header_idx as i32 || out1_idx == latch_idx {
                (out1.clone(), out0.clone())
            } else {
                (out0.clone(), out1.clone())
            };

            let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockWhileDo {
                    index: header_idx,
                    condition: header.clone(),
                    body: body_entry,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));
            replacements.push((header_idx as usize, while_block));
            self.change_count += 1;
        }

        // CBRANCH-latch loop detection: find blocks ending with CBRANCH
        // where one outgoing edge is a back-edge to a dominating header.
        // This handles do-while and while-do patterns where the latch
        // itself contains the loop condition (common in real binaries).
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            if replacements.iter().any(|(idx, _)| *idx == i) {
                continue;
            }

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }
            if b.size_out() != 2 {
                continue;
            }

            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch {
                continue;
            }

            let out0_edge = match b.get_out(0) {
                Some(e) => e,
                None => continue,
            };
            let out1_edge = match b.get_out(1) {
                Some(e) => e,
                None => continue,
            };

            let latch_idx = b.get_index();
            let out0_target = out0_edge.point.clone();
            let out1_target = out1_edge.point.clone();
            drop(b);

            let out0_is_backedge = self.dominates(&out0_target, &block);
            let out1_is_backedge = self.dominates(&out1_target, &block);

            // Exactly one edge should be a back-edge
            if out0_is_backedge == out1_is_backedge {
                continue;
            }

            let (header, _exit) = if out0_is_backedge {
                (out0_target.clone(), out1_target.clone())
            } else {
                (out1_target.clone(), out0_target.clone())
            };

            let header_idx = header.read().unwrap().get_index();

            if replacements.iter().any(|(idx, _)| *idx == header_idx as usize) {
                continue;
            }

            // If latch == header, this is a self-loop do-while
            // (already handled in Phase 1 above, but catch any missed ones)
            if header_idx == latch_idx {
                let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(crate::block::BlockDoWhile {
                        index: latch_idx,
                        condition: block.clone(),
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                        parent: None,
                        flags: 0,
                    }));
                replacements.push((i, while_block));
                self.change_count += 1;
                continue;
            }

            // Header is a different block from latch — this is a multi-block
            // loop where the latch contains the condition.
            // Check if header has a CBRANCH (while-do with condition at top AND bottom).
            // If header is a simple fall-through, it's a do-while with the
            // condition at the latch.
            let header_out_count = header.read().unwrap().size_out();

            if header_out_count <= 1 {
                // Header is a simple block → do-while with condition at latch
                let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(crate::block::BlockDoWhile {
                        index: header_idx,
                        condition: block.clone(),
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                        parent: None,
                        flags: 0,
                    }));
                replacements.push((header_idx as usize, while_block));
                self.change_count += 1;
            } else {
                // Header has CBRANCH too → while-do pattern:
                // header decides entry, latch decides repeat.
                // Use header as condition block, latch's block as body end.
                let h = header.read().unwrap();
                let h_out0 = h.get_out(0).map(|e| e.point.clone());
                let h_out1 = h.get_out(1).map(|e| e.point.clone());
                drop(h);

                // Determine which of header's exits leads into the loop body
                let body_entry = if let Some(ref ho0) = h_out0 {
                    let ho0_idx = ho0.read().unwrap().get_index();
                    if ho0_idx == latch_idx || self.dominates(&block, ho0) {
                        h_out0.clone()
                    } else {
                        h_out1.clone()
                    }
                } else {
                    h_out1.clone()
                };

                if let Some(body) = body_entry {
                    let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                        Arc::new(RwLock::new(BlockWhileDo {
                            index: header_idx,
                            condition: header.clone(),
                            body,
                            incoming: Vec::new(),
                            outgoing: Vec::new(),
                            parent: None,
                            flags: 0,
                        }));
                    replacements.push((header_idx as usize, while_block));
                    self.change_count += 1;
                }
            }
        }

        for (idx, replacement) in replacements {
            if idx < self.graph.blocks.len() {
                self.graph.blocks[idx] = replacement;
            }
        }
    }

    /// Try to structure a WhileDo loop at block index `i`. Faithful to
    /// `CollapseStructure::ruleBlockWhileDo` (blockaction.cc:1518-1549).
    ///
    /// Ghidra's rule: bl has 2 out-edges (binary condition); for each out-edge
    /// i, the clauseblock must (a) have sizeIn()==1, (b) have sizeOut()==1,
    /// (c) not be a switch-out, and (d) its single out-edge must loop back to
    /// bl. Crucially, bl must NOT be `isGotoOut` on either edge — but break
    /// edges that were marked goto by selectGoto/TraceDAG are excluded, which
    /// is exactly how loops WITH breaks get structured (the break edge is the
    /// non-clause out-edge, marked goto so it's skipped here).
    ///
    /// Returns true if a WhileDo was created.
    fn rule_block_while_do(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return false,
        };
        // Collect candidate clause block without holding the read lock across
        // mutations (identify_internal needs write access).
        let candidate: Option<(Arc<RwLock<dyn FlowBlock + Send + Sync>>, i32)> = {
            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy
            { return false; }
            if b.size_out() != 2 { return false; }       // Must be binary condition
            // No switch-out (blockaction.cc:1525): head must not end in a switch.
            if b.get_ops().last().map_or(false, |o| {
                o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_BRANCHIND
            }) { return false; }
            let cond_idx = b.get_index();
            // No loop-at-this-point: out(i) != bl (blockaction.cc:1526-1527)
            for slot in 0..2 {
                if let Some(e) = b.get_out(slot) {
                    if e.point.read().unwrap().get_index() == cond_idx { return false; }
                }
            }
            // Faithful to blockaction.cc:1528-1530: in Ghidra, ruleBlockGoto has
            // already consumed break-edges (wrapped as BlockIfGoto) before
            // ruleBlockWhileDo runs, so neither edge is goto. In Rugra's staged
            // approach, the break-edge may still be marked goto on the loop head.
            // So we do NOT bail on goto edges here; instead we find the NON-goto
            // clause below. (isInteriorGotoTarget omitted — Rugra does not track it.)
            // Find the clause: out-edge slot whose target has sizeIn==1,
            // sizeOut==1, not switch-out, and loops back to bl (cc:1531-1547).
            let mut found: Option<(Arc<RwLock<dyn FlowBlock + Send + Sync>>, i32)> = None;
            for slot in 0..2 {
                // Skip goto-marked edges (break-edges): they should not be
                // structured as the loop body.
                if b.is_goto_out(slot) { continue; }
                let clause_edge = match b.get_out(slot) { Some(e) => e, None => continue };
                let clauseblock = clause_edge.point.clone();
                let loops_back = {
                    let cb = clauseblock.read().unwrap();
                    if cb.size_in() != 1 { continue; }        // Nothing else must hit clause
                    if cb.size_out() != 1 { continue; }        // Only one way out of clause
                    if cb.get_type() == crate::block::BlockType::Switch { continue; } // not switch-out
                    match cb.get_out(0) {
                        Some(e) => e.point.read().unwrap().get_index() == cond_idx,
                        None => false,
                    }
                };
                if loops_back {
                    // Clause must loop back to bl — found a WhileDo.
                    found = Some((clauseblock, cond_idx));
                    break;
                }
            }
            found
        };

        if let Some((clauseblock, cond_idx)) = candidate {
            let body_idx = clauseblock.read().unwrap().get_index();
            let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(crate::block::BlockWhileDo {
                    index: cond_idx,
                    condition: block.clone(),
                    body: clauseblock,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));
            if i < self.graph.blocks.len() {
                self.graph.blocks[i] = while_block.clone();
            }
            self.identify_internal(&while_block, &[body_idx], i);
            self.change_count += 1;
            eprintln!("[COLLAPSE] {} ruleBlockWhileDo head={} body={}", self.name, cond_idx, body_idx);
            return true;
        }
        false
    }
    ///
    /// **Triangle** (if-then, no else):
    /// ```text
    ///     A (CBRANCH, 2-out)
    ///    / \
    ///   B   C
    ///    \ /
    ///     C  (B has 1 out → C)
    /// ```
    ///
    /// **Diamond** (if-then-else):
    /// ```text
    ///     A (CBRANCH, 2-out)
    ///    / \
    ///   B   C
    ///    \ /
    ///     D  (both B and C have 1 out → D)
    /// ```
    fn collapse_conditions(&mut self) {
        // Collect candidate indices first to avoid borrow conflicts
        let size = self.graph.get_size();
        let mut replacements: Vec<(usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = Vec::new();

        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }
            if b.size_out() != 2 {
                continue;
            }

            // Check that this block ends with a CBRANCH
            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |op_ref| {
                let op = op_ref.0.read().unwrap();
                op.opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch {
                continue;
            }

            let true_edge = match b.get_out(0) { Some(e) => e, None => continue };
            let false_edge = match b.get_out(1) { Some(e) => e, None => continue };
            let true_block = true_edge.point.clone();
            let false_block = false_edge.point.clone();
            let true_idx = true_block.read().unwrap().get_index();
            let false_idx = false_block.read().unwrap().get_index();
            let cond_idx = b.get_index();
            drop(b); // release read lock

            // --- Try Triangle: true_block → false_block (if-then, no else) ---
            {
                let tb = true_block.read().unwrap();
                if tb.size_out() == 1 && tb.size_in() == 1 {
                    if let Some(edge) = tb.get_out(0) {
                        let target_idx = edge.point.read().unwrap().get_index();
                        if target_idx == false_idx {
                            drop(tb);
                            // Triangle match: condition=block, if_body=true_block, merge=false_block
                            // CBRANCH out(0)=true edge → if_body is the taken branch → no negation
                            // BlockIf's out-edge points to the merge block (false_block) itself,
                            // so control flow continues to it after the if.
                            let merge_outs: Vec<crate::block::BlockEdge> = vec![
                                crate::block::BlockEdge::new(false_block.clone(), 0),
                            ];
                            let mut bif = BlockIf {
                                index: cond_idx,
                                condition: block.clone(),
                                if_body: true_block.clone(),
                                else_body: None,
                                negated: false,
                                incoming: Vec::new(),
                                outgoing: merge_outs,
                                parent: None,
                                flags: 0,
                            };
                            let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                Arc::new(RwLock::new(bif));
                            replacements.push((i, if_block));
                            self.change_count += 1;
                            continue;
                        }
                    }
                }
            }

            // --- Try Triangle reverse: false_block → true_block ---
            {
                let fb = false_block.read().unwrap();
                if fb.size_out() == 1 && fb.size_in() == 1 {
                    if let Some(edge) = fb.get_out(0) {
                        let target_idx = edge.point.read().unwrap().get_index();
                        if target_idx == true_idx {
                            drop(fb);
                            // Triangle-reverse: if_body is the FALSE edge block (out(1)).
                            // The CBRANCH condition is written for the TRUE edge, so we must
                            // negate it to correctly gate the false-edge body.
                            // BlockIf's out-edge points to the merge block (true_block) itself.
                            let merge_outs: Vec<crate::block::BlockEdge> = vec![
                                crate::block::BlockEdge::new(true_block.clone(), 0),
                            ];
                            let mut bif = BlockIf {
                                index: cond_idx,
                                condition: block.clone(),
                                if_body: false_block.clone(),
                                else_body: None,
                                negated: true,
                                incoming: Vec::new(),
                                outgoing: merge_outs,
                                parent: None,
                                flags: 0,
                            };
                            let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                Arc::new(RwLock::new(bif));
                            replacements.push((i, if_block));
                            self.change_count += 1;
                            continue;
                        }
                    }
                }
            }

            // --- Try Diamond: both true_block and false_block → same merge block D ---
            {
                let tb = true_block.read().unwrap();
                let fb = false_block.read().unwrap();
                if tb.size_out() == 1 && fb.size_out() == 1
                    && tb.size_in() == 1 && fb.size_in() == 1
                {
                    let t_target = tb.get_out(0).map(|e| e.point.read().unwrap().get_index());
                    let f_target = fb.get_out(0).map(|e| e.point.read().unwrap().get_index());
                    if let (Some(tt), Some(ft)) = (t_target, f_target) {
                        if tt == ft {
                            drop(tb);
                            drop(fb);
                            // Diamond match: if_body=true edge, else_body=false edge → no negation
                            // BlockIf's out-edge points to the merge block (D) itself.
                            let merge_blk = self.graph.get_block(tt as usize);
                            let merge_outs: Vec<crate::block::BlockEdge> = if let Some(mb) = merge_blk {
                                vec![crate::block::BlockEdge::new(mb, 0)]
                            } else { Vec::new() };
                            let mut bif = BlockIf {
                                index: cond_idx,
                                condition: block.clone(),
                                if_body: true_block.clone(),
                                else_body: Some(false_block.clone()),
                                negated: false,
                                incoming: Vec::new(),
                                outgoing: merge_outs,
                                parent: None,
                                flags: 0,
                            };
                            let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                Arc::new(RwLock::new(bif));
                            replacements.push((i, if_block));
                            self.change_count += 1;
                            continue;
                        }
                    }
                }
            }
        }

        // Apply replacements
        for (idx, replacement) in replacements {
            if idx < self.graph.blocks.len() {
                self.graph.blocks[idx] = replacement;
            }
        }
    }

    /// Collapse boolean short-circuit patterns into `BlockCondition` (&&/||).
    ///
    /// Implements Ghidra's `ruleBlockOr` from `blockaction.cc`.
    ///
    /// AND: A→true→B, A→false→C, B→false→C  ==>  if(a && b)
    /// OR:  A→false→B, A→true→C, B→true→C   ==>  if(a || b)
    fn collapse_bool_conditions(&mut self) {
        let size = self.graph.get_size();
        let mut replacements: Vec<(usize, usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = Vec::new();

        for i in 0..size {
            let block_a = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let a = block_a.read().unwrap();
            if a.get_type() != crate::block::BlockType::Basic
               && a.get_type() != crate::block::BlockType::Copy { continue; }
            if a.size_out() != 2 {
                continue;
            }

            // A must end with CBRANCH
            let ops_a = a.get_ops();
            let has_cbranch = ops_a.last().map_or(false, |op_ref| {
                let op = op_ref.0.read().unwrap();
                op.opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch {
                continue;
            }

            // out(0) = true edge, out(1) = false edge (Ghidra convention)
            let true_edge_a = match a.get_out(0) { Some(e) => e, None => continue };
            let false_edge_a = match a.get_out(1) { Some(e) => e, None => continue };
            let true_target_a = true_edge_a.point.clone();
            let false_target_a = false_edge_a.point.clone();
            let true_idx_a = true_target_a.read().unwrap().get_index();
            let false_idx_a = false_target_a.read().unwrap().get_index();
            let a_idx = a.get_index();
            drop(a);

            // Try AND pattern: A→true→B (B has CBRANCH, 1 in), A→false→C, B→false→C
            {
                let b_block = true_target_a.clone();
                let b = b_block.read().unwrap();
                if b.size_in() == 1 && b.size_out() == 2 {
                    let b_ops = b.get_ops();
                    let b_has_cbranch = b_ops.last().map_or(false, |op_ref| {
                        let op = op_ref.0.read().unwrap();
                        op.opcode == OpCode::CPUI_CBRANCH
                    });
                    if b_has_cbranch {
                        let false_edge_b = b.get_out(1);
                         if let Some(ref fe_b) = false_edge_b {
                            let false_idx_b = fe_b.point.read().unwrap().get_index();
                            if false_idx_b == false_idx_a {
                                // AND match: both false edges → same target
                                // Outgoing: out(0)=B's true target, out(1)=shared false target
                                let true_edge_b = b.get_out(0);
                                let b_idx = b.get_index();
                                drop(b);
                                let mut out_edges = Vec::new();
                                if let Some(te_b) = true_edge_b {
                                    out_edges.push(te_b);
                                }
                                out_edges.push(fe_b.clone());
                                let cond_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                    Arc::new(RwLock::new(BlockCondition {
                                        index: a_idx,
                                        op_type: BoolOp::And,
                                        first: block_a.clone(),
                                        second: b_block.clone(),
                                        incoming: Vec::new(),
                                        outgoing: out_edges,
                                        parent: None,
                                        flags: 0,
                                    }));
                                replacements.push((i, b_idx as usize, cond_block));
                                self.change_count += 1;
                                continue;
                            }
                        }
                    }
                }
                drop(b);
            }

            // Try OR pattern: A→false→B (B has CBRANCH, 1 in), A→true→C, B→true→C
            {
                let b_block = false_target_a.clone();
                let b = b_block.read().unwrap();
                if b.size_in() == 1 && b.size_out() == 2 {
                    let b_ops = b.get_ops();
                    let b_has_cbranch = b_ops.last().map_or(false, |op_ref| {
                        let op = op_ref.0.read().unwrap();
                        op.opcode == OpCode::CPUI_CBRANCH
                    });
                    if b_has_cbranch {
                        let true_edge_b = b.get_out(0);
                        if let Some(ref te_b) = true_edge_b {
                            let true_idx_b = te_b.point.read().unwrap().get_index();
                            if true_idx_b == true_idx_a {
                                // OR match: both true edges → same target
                                // Outgoing: out(0)=shared true target, out(1)=B's false target
                                let false_edge_b = b.get_out(1);
                                let b_idx = b.get_index();
                                drop(b);
                                let mut out_edges = Vec::new();
                                out_edges.push(te_b.clone());
                                if let Some(fe_b) = false_edge_b {
                                    out_edges.push(fe_b);
                                }
                                let cond_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                    Arc::new(RwLock::new(BlockCondition {
                                        index: a_idx,
                                        op_type: BoolOp::Or,
                                        first: block_a.clone(),
                                        second: b_block.clone(),
                                        incoming: Vec::new(),
                                        outgoing: out_edges,
                                        parent: None,
                                        flags: 0,
                                    }));
                                replacements.push((i, b_idx as usize, cond_block));
                                self.change_count += 1;
                                continue;
                            }
                        }
                    }
                }
                drop(b);
            }
        }

        // Apply replacements: replace A's slot, mark B's slot as absorbed
        for (a_slot, b_idx, replacement) in replacements {
            if a_slot < self.graph.blocks.len() {
                self.graph.blocks[a_slot] = replacement;
            }
            // Mark B as absorbed by replacing with a dummy empty basic block
            if (b_idx as usize) < self.graph.blocks.len() {
                let dummy: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(BlockBasic::new(b_idx as i32, crate::address::Address::new(0))));
                self.graph.blocks[b_idx as usize] = dummy;
            }
        }
    }

    /// Collapse linear sequences: when block A has exactly 1 out → block B,
    /// and B has exactly 1 in (from A), merge them into a `BlockList`.
    fn collapse_sequences(&mut self) {
        let size = self.graph.get_size();
        let mut merged: Vec<bool> = vec![false; size];

        for i in 0..size {
            if merged[i] { continue; }

            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }
            if b.size_out() != 1 {
                continue;
            }

            let succ_edge = match b.get_out(0) { Some(e) => e, None => continue };
            let succ = succ_edge.point.clone();
            let succ_idx = succ.read().unwrap().get_index() as usize;
            drop(b);

            if succ_idx >= size || merged[succ_idx] || succ_idx == i {
                continue;
            }

            let s = succ.read().unwrap();
            if s.size_in() != 1 {
                continue;
            }
            drop(s);

            // Sequence match: merge block[i] and block[succ_idx] into BlockList
            // The BlockList's out-edges come from the LAST child's out-edges
            // (the sequence continues from where the last block ends).
            let succ_outs: Vec<crate::block::BlockEdge> = {
                let s = succ.read().unwrap();
                (0..s.size_out()).filter_map(|slot| s.get_out(slot)).collect()
            };
            let block_idx_val = block.read().unwrap().get_index();
            let mut list_bl = BlockList::new(block_idx_val, vec![block.clone(), succ.clone()]);
            list_bl.outgoing = succ_outs;
            let list_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(list_bl));

            self.graph.blocks[i] = list_block;
            merged[succ_idx] = true;
            self.change_count += 1;
        }
    }

    fn collapse_switches(&mut self) {
        let size = self.graph.get_size();
        let mut replacements: Vec<(usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = Vec::new();

        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            
            // Check if block contains BRANCHIND
            let ops = b.get_ops();
            let has_branchind = ops.iter().any(|op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND
            });
            if !has_branchind {
                continue;
            }

            // If any out-edge is marked as goto (by TraceDAG), skip switch
            // formation — the control flow should be structured as if/goto.
            let flags = b.get_flags();
            if flags & (crate::block::block_flags::GOTO_EDGE_0 | crate::block::block_flags::GOTO_EDGE_1) != 0 {
                continue;
            }

            let size_out = b.size_out();
            if size_out < 1 {
                continue;
            }

            let mut index_varnode = None;
            for op_ref in &ops {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_BRANCHIND && !op.inrefs.is_empty() {
                    index_varnode = Some(op.inrefs[0].clone());
                    break;
                }
            }

            let mut cases = Vec::new();
            let mut case_values = Vec::new();
            for j in 0..size_out {
                if let Some(edge) = b.get_out(j) {
                    cases.push(edge.point.clone());
                    case_values.push(vec![j as u64]);
                }
            }

            let ctrl_idx = b.get_index();
            drop(b);

            let switch_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockSwitch {
                    index: ctrl_idx,
                    control: block.clone(),
                    cases,
                    default_case: None,
                    case_values,
                    index_varnode,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));

            replacements.push((i, switch_block));
            self.change_count += 1;
        }

        for (idx, replacement) in replacements {
            if idx < self.graph.blocks.len() {
                self.graph.blocks[idx] = replacement;
            }
        }
    }

    /// Collapse CBRANCH cascades into `BlockSwitch`.
    ///
    /// Detects chains of blocks where each block ends with CBRANCH comparing
    /// the same variable to a different constant, implementing a switch-case
    /// via comparison cascades (cmp+je chains from GCC -O2).
    ///
    /// Pattern:
    ///   Block A: cmp var, K1 → je case1, fallthrough B
    ///   Block B: cmp var, K2 → je case2, fallthrough C
    ///   Block C: cmp var, K3 → je case3, fallthrough D (default)
    ///   case1, case2, case3 all → merge_point
    ///
    /// Corresponds to Ghidra's `ruleBlockSwitch` for CBRANCH cascades.
    fn collapse_cbranch_cascades(&mut self) {
        use crate::opcodes::OpCode;

        let size = self.graph.get_size();
        let mut consumed: Vec<bool> = vec![false; size];
        let mut replacements: Vec<(usize, Vec<usize>, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = Vec::new();

        for i in 0..size {
            if consumed[i] { continue; }
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
               && b.get_type() != crate::block::BlockType::Copy { continue; }
            if b.size_out() != 2 { continue; }

            // Check if this block ends with CBRANCH
            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch { continue; }

            // If CBRANCH has goto-marked edges (by TraceDAG), skip cascade
            // switch formation — control flow should be structured as if/goto.
            let cflags = b.get_flags();
            if cflags & (crate::block::block_flags::GOTO_EDGE_0 | crate::block::block_flags::GOTO_EDGE_1) != 0 {
                continue;
            }

            // Get the taken target (case body) — edge 1
            let taken_block = match b.get_out(1) {
                Some(e) => e.point.clone(),
                None => continue,
            };
            drop(b);

            // Walk the fallthrough chain collecting consecutive CBRANCH blocks
            let mut chain: Vec<(usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = vec![(i, block.clone())];
            let mut case_bodies: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = vec![taken_block];
            let mut case_values: Vec<u64> = Vec::new();

            // Try to get case value for first block
            let first_ops = self.graph.blocks[i].read().unwrap().get_ops();
            case_values.push(self.get_cbranch_case_info(&first_ops).unwrap_or(0));

            let mut current_idx = i;
            let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
            visited.insert(i);
            loop {
                let current_block = match self.graph.get_block(current_idx) {
                    Some(b) => b,
                    None => break,
                };
                let cb = current_block.read().unwrap();
                if cb.size_out() != 2 { break; }

                // Fallthrough = edge 0
                let fallthrough_edge = match cb.get_out(0) {
                    Some(e) => e,
                    None => break,
                };
                let next_block = fallthrough_edge.point.clone();
                let next_idx = next_block.read().unwrap().get_index() as usize;
                drop(cb);

                if visited.contains(&next_idx) { break; }
                visited.insert(next_idx);

                if next_idx >= size || consumed[next_idx] || next_idx == current_idx {
                    break;
                }

                // Check if next block also has CBRANCH
                let nb = next_block.read().unwrap();
                // Stop cascade at structured blocks (WhileDo/DoWhile/If/etc) —
                // they are not part of a CBRANCH cascade and including them
                // produces duplicate case_values.
                let nb_type = nb.get_type();
                if nb_type != crate::block::BlockType::Basic && nb_type != crate::block::BlockType::Copy {
                    break;
                }
                if nb.size_out() != 2 {
                    // Try following this non-CBRANCH block's single outgoing edge
                    // (skip over case body blocks in the chain)
                    if nb.size_out() == 1 {
                        if let Some(skip_edge) = nb.get_out(0) {
                            let skip_block = skip_edge.point.clone();
                            let skip_idx = skip_block.read().unwrap().get_index() as usize;
                            drop(nb);
                            if skip_idx < size && !consumed[skip_idx] && skip_idx != next_idx {
                                let sb = skip_block.read().unwrap();
                                if sb.size_out() == 2 {
                                    let skip_ops = sb.get_ops();
                                    let skip_has_cb = skip_ops.last().map_or(false, |op_ref| {
                                        op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                                    });
                                    if skip_has_cb {
                                        if let Some(skip_taken) = sb.get_out(1) {
                                            let st = skip_taken.point.clone();
                                            drop(sb);
                                            let skip_block_ops = self.graph.blocks[skip_idx].read().unwrap().get_ops();
                                            let cv = self.get_cbranch_case_info(&skip_block_ops)
                                                .unwrap_or(chain.len() as u64);
                                            chain.push((skip_idx, skip_block.clone()));
                                            case_bodies.push(st);
                                            case_values.push(cv);
                                            current_idx = skip_idx;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                let next_ops = nb.get_ops();
                let next_has_cbranch = next_ops.last().map_or(false, |op_ref| {
                    op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                });
                if !next_has_cbranch { break; }

                // Get case body (taken = edge 1)
                let next_taken = match nb.get_out(1) {
                    Some(e) => e.point.clone(),
                    None => break,
                };
                drop(nb);

                // Get case value
                let next_block_ops = self.graph.blocks[next_idx].read().unwrap().get_ops();
                let case_val = self.get_cbranch_case_info(&next_block_ops)
                    .unwrap_or(chain.len() as u64);

                chain.push((next_idx, next_block.clone()));
                case_bodies.push(next_taken);
                case_values.push(case_val);
                current_idx = next_idx;
            }

            // Need at least 3 comparisons to form a switch
            if chain.len() < 3 { continue; }

            // The last comparison's fallthrough is the default case
            let last_block = &chain.last().unwrap().1;
            let lb = last_block.read().unwrap();
            let default_case = lb.get_out(0).map(|e| e.point.clone());
            drop(lb);

            // Build index_varnode by scanning all chain blocks for a valid
            // comparison. The first block is preferred, but CBRANCH cascades
            // sometimes have a non-standard head (e.g. a range guard) while
            // later blocks use the canonical INT_EQUAL pattern. Walking the
            // whole chain mirrors Ghidra's approach of finding the common
            // compared operand across all case blocks.
            let mut index_varnode: Option<Arc<RwLock<crate::varnode::Varnode>>> = None;
            for (chain_block_idx, _) in &chain {
                let chain_ops = self.graph.blocks[*chain_block_idx].read().unwrap().get_ops();
                if let Some(vn) = self.find_compared_varnode(&chain_ops) {
                    index_varnode = Some(vn);
                    break;
                }
            }
            // Fallback: if no block yielded a clean comparison chain, scan
            // every chain block for ANY comparison op with a non-const
            // operand. In a CBRANCH cascade every case compares the same
            // variable, so any non-const operand of any INT_* comparison in
            // any chain block is a valid switch index.
            if index_varnode.is_none() {
                for (chain_block_idx, _) in &chain {
                    let chain_ops = self.graph.blocks[*chain_block_idx].read().unwrap().get_ops();
                    for op_ref in chain_ops.iter() {
                        let op = op_ref.0.read().unwrap();
                        match op.opcode {
                            crate::opcodes::OpCode::CPUI_INT_EQUAL
                            | crate::opcodes::OpCode::CPUI_INT_NOTEQUAL
                            | crate::opcodes::OpCode::CPUI_INT_LESS
                            | crate::opcodes::OpCode::CPUI_INT_SLESS
                            | crate::opcodes::OpCode::CPUI_INT_LESSEQUAL
                            | crate::opcodes::OpCode::CPUI_INT_SLESSEQUAL => {
                                if op.inrefs.len() >= 2 {
                                    let i0 = op.inrefs[0].read().unwrap();
                                    let i1 = op.inrefs[1].read().unwrap();
                                    if i1.get_space() != crate::space::AddressSpace::Const {
                                        index_varnode = Some(op.inrefs[1].clone());
                                        break;
                                    } else if i0.get_space() != crate::space::AddressSpace::Const {
                                        index_varnode = Some(op.inrefs[0].clone());
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if index_varnode.is_some() { break; }
                }
            }

            // Create BlockSwitch
            let ctrl_idx = chain[0].1.read().unwrap().get_index();
            let case_vals: Vec<Vec<u64>> = case_values.iter().map(|v| vec![*v]).collect();

            let switch_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockSwitch {
                    index: ctrl_idx,
                    control: chain[0].1.clone(),
                    cases: case_bodies.clone(),
                    default_case,
                    case_values: case_vals,
                    index_varnode,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));

            let consumed_indices: Vec<usize> = chain.iter().map(|(idx, _)| *idx).collect();
            for &idx in &consumed_indices {
                consumed[idx] = true;
            }

            // Also consume the case body blocks
            for body in &case_bodies {
                let body_idx = body.read().unwrap().get_index() as usize;
                if body_idx < size {
                    consumed[body_idx] = true;
                }
            }
            if let Some(ref def) = switch_block.read().unwrap()
                .as_any().downcast_ref::<BlockSwitch>()
                .and_then(|s| s.default_case.as_ref())
            {
                let def_idx = def.read().unwrap().get_index() as usize;
                if def_idx < size {
                    consumed[def_idx] = true;
                }
            }

            replacements.push((i, consumed_indices, switch_block));
            self.change_count += 1;
        }

        // Apply replacements
        for (primary_idx, extra_indices, replacement) in replacements {
            if primary_idx < self.graph.blocks.len() {
                self.graph.blocks[primary_idx] = replacement;
                for &idx in &extra_indices[1..] {
                    if idx < self.graph.blocks.len() {
                        // Don't clobber already-structured blocks (WhileDo/DoWhile/If/etc)
                        // created by structure_loops_first — only replace Basic/Copy blocks.
                        let is_structured = {
                            let b = self.graph.blocks[idx].read().unwrap();
                            let t = b.get_type();
                            t != crate::block::BlockType::Basic && t != crate::block::BlockType::Copy
                        };
                        if is_structured { continue; }
                        // Create empty placeholder with valid index (no ops, no edges)
                        let placeholder: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                            Arc::new(RwLock::new(BlockBasic::new(idx as i32, Address::new(0))));
                        self.graph.blocks[idx] = placeholder;
                    }
                }
            }
        }
    }

    /// ruleCaseFallthru: absorb fallthrough successor blocks into switch case
    /// bodies. When a case body block doesn't end with RETURN/BREAK, its
    /// out-edge target is a "fallthrough" successor. If that successor has
    /// a single in-edge (from this case body), merge it into a BlockList.
    /// Mirrors Ghidra's ruleCaseFallthru (blockaction.cc:1707).
    fn collapse_case_fallthru(&mut self) {
        use crate::block::block_flags;
        let size = self.graph.get_size();

        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let bt = {
                let b = block.read().unwrap();
                b.get_type()
            };
            if bt != crate::block::BlockType::Switch { continue; }

            // Read case body indices and check for fallthrough
            let (case_indices, default_idx) = {
                let b = block.read().unwrap();
                let sw = match b.as_any().downcast_ref::<BlockSwitch>() {
                    Some(s) => s, None => continue,
                };
                let ci: Vec<i32> = sw.cases.iter().map(|c| c.read().unwrap().get_index()).collect();
                let di = sw.default_case.as_ref().map(|d| d.read().unwrap().get_index());
                (ci, di)
            };

            // For each case, build fallthrough chain and create BlockList
            let mut new_cases: Vec<Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>> = Vec::new();
            for &case_idx in &case_indices {
                let case_body = match self.graph.get_block(case_idx as usize) {
                    Some(b) => b, None => { new_cases.push(None); continue; }
                };
                let chain = self.build_fallthrough_chain(&case_body, size, i, &case_indices, default_idx);
                if chain.len() > 1 {
                    let lb: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                        Arc::new(RwLock::new(crate::block::BlockList::new(case_idx, chain)));
                    new_cases.push(Some(lb));
                    self.change_count += 1;
                } else {
                    new_cases.push(None);
                }
            }

            // Build default fallthrough chain
            let new_default: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = if let Some(di) = default_idx {
                let def_body = match self.graph.get_block(di as usize) {
                    Some(b) => Some(b), None => None,
                };
                if let Some(db) = def_body {
                    let chain = self.build_fallthrough_chain(&db, size, i, &case_indices, default_idx);
                    if chain.len() > 1 {
                        let lb: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                            Arc::new(RwLock::new(crate::block::BlockList::new(di, chain)));
                        self.change_count += 1;
                        Some(lb)
                    } else { None }
                } else { None }
            } else { None };

            // Apply changes to BlockSwitch by replacing it
            if new_cases.iter().any(|c| c.is_some()) || new_default.is_some() {
                let b = block.read().unwrap();
                let sw = match b.as_any().downcast_ref::<BlockSwitch>() {
                    Some(s) => s, None => continue,
                };
                let mut new_case_list = Vec::new();
                for (idx, nc) in new_cases.iter().enumerate() {
                    if let Some(ref lb) = nc {
                        new_case_list.push(lb.clone());
                    } else {
                        new_case_list.push(sw.cases[idx].clone());
                    }
                }
                let new_def = new_default.or_else(|| sw.default_case.clone());
                let ctrl_idx = sw.index;
                let ctrl = sw.control.clone();
                let cv = sw.case_values.clone();
                let iv = sw.index_varnode.clone();
                drop(b);

                let new_sw: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(BlockSwitch {
                        index: ctrl_idx, control: ctrl, cases: new_case_list,
                        default_case: new_def, case_values: cv, index_varnode: iv,
                        incoming: Vec::new(), outgoing: Vec::new(), parent: None, flags: 0,
                    }));
                self.graph.blocks[i] = new_sw;
            }
        }
    }

    fn build_fallthrough_chain(
        &self, start: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        size: usize, switch_idx: usize,
        case_indices: &[i32], default_idx: Option<i32>,
    ) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        use crate::block::block_flags;
        let mut chain = vec![start.clone()];
        let mut current = start.clone();
        loop {
            let cur = current.read().unwrap();
            if cur.get_flags() & block_flags::RETURN_TERMINAL != 0 { break; }
            if cur.size_out() == 0 { break; }
            let succ_edge = match cur.get_out(0) { Some(e) => e, None => break };
            let succ = succ_edge.point.clone();
            let succ_idx = succ.read().unwrap().get_index();
            drop(cur);
            if succ_idx as usize >= size || succ_idx as usize == switch_idx { break; }
            if case_indices.contains(&succ_idx) { break; }
            if default_idx == Some(succ_idx) { break; }
            let succ_in = succ.read().unwrap().size_in();
            if succ_in != 1 { break; }
            let st = succ.read().unwrap().get_type();
            if st != crate::block::BlockType::Basic && st != crate::block::BlockType::Copy { break; }
            if chain.iter().any(|b| b.read().unwrap().get_index() == succ_idx) { break; }
            chain.push(succ.clone());
            current = succ;
        }
        chain
    }

    ///
    /// Handles two patterns:
    /// 1. Direct: CBRANCH(_, INT_EQUAL(var, const))
    /// 2. x86 flag: CBRANCH(_, ZF) where ZF = INT_EQUAL(INT_SUB(var, const), 0)
    ///
    /// Uses space+offset matching (SSA-safe).
    fn get_cbranch_compared_var(&self, ops: &[crate::op::PcodeOpRef]) -> Option<(crate::space::AddressSpace, u64)> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let cbranch_op = ops.last()?;
        let cb = cbranch_op.0.read().unwrap();
        if cb.opcode != OpCode::CPUI_CBRANCH { return None; }
        if cb.inrefs.len() < 2 { return None; }

        let cond_vn = cb.inrefs[1].read().unwrap();
        let cond_space = cond_vn.get_space();
        let cond_offset = cond_vn.get_offset();
        let cond_size = cond_vn.get_size();
        drop(cond_vn);
        drop(cb);

        // Search backwards for the op that produces the condition (by space+offset+size)
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let out_vn = out.read().unwrap();
                if out_vn.get_space() == cond_space && out_vn.get_offset() == cond_offset && out_vn.get_size() == cond_size {
                    drop(out_vn);
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                            if op.inrefs.len() >= 2 {
                                let in0 = op.inrefs[0].read().unwrap();
                                let in1 = op.inrefs[1].read().unwrap();
                                if in1.get_space() == AddressSpace::Const && in0.get_space() != AddressSpace::Const {
                                    if in1.get_offset() == 0 {
                                        // x86 cmp: INT_EQUAL(INT_SUB(var, const), 0)
                                        let s = in0.get_space(); let o = in0.get_offset(); let sz = in0.get_size();
                                        drop(in0); drop(in1);
                                        return self.find_sub_source(ops, s, o, sz);
                                    }
                                    return Some((in0.get_space(), in0.get_offset()));
                                } else if in0.get_space() == AddressSpace::Const && in1.get_space() != AddressSpace::Const {
                                    if in0.get_offset() == 0 {
                                        let s = in1.get_space(); let o = in1.get_offset(); let sz = in1.get_size();
                                        drop(in0); drop(in1);
                                        return self.find_sub_source(ops, s, o, sz);
                                    }
                                    return Some((in1.get_space(), in1.get_offset()));
                                }
                            }
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
        None
    }

    /// Helper: find INT_SUB(var, const) producing target varnode, return (var_space, var_offset).
    fn find_sub_source(&self, ops: &[crate::op::PcodeOpRef], ts: crate::space::AddressSpace, to: u64, tsz: usize) -> Option<(crate::space::AddressSpace, u64)> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == ts && ov.get_offset() == to && ov.get_size() == tsz {
                    drop(ov);
                    if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                        let i0 = op.inrefs[0].read().unwrap();
                        let i1 = op.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const && i0.get_space() != AddressSpace::Const {
                            return Some((i0.get_space(), i0.get_offset()));
                        } else if i0.get_space() == AddressSpace::Const && i1.get_space() != AddressSpace::Const {
                            return Some((i1.get_space(), i1.get_offset()));
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    /// Extract the constant case value from a CBRANCH comparison.
    fn get_cbranch_case_info(&self, ops: &[crate::op::PcodeOpRef]) -> Option<u64> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let cbranch_op = ops.last()?;
        let cb = cbranch_op.0.read().unwrap();
        if cb.opcode != OpCode::CPUI_CBRANCH { return None; }
        if cb.inrefs.len() < 2 { return None; }
        let cv = cb.inrefs[1].read().unwrap();
        let cs = cv.get_space(); let co = cv.get_offset(); let csz = cv.get_size();
        drop(cv); drop(cb);

        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == cs && ov.get_offset() == co && ov.get_size() == csz {
                    drop(ov);
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                            if op.inrefs.len() >= 2 {
                                let i0 = op.inrefs[0].read().unwrap();
                                let i1 = op.inrefs[1].read().unwrap();
                                if i1.get_space() == AddressSpace::Const && i0.get_space() != AddressSpace::Const {
                                    if i1.get_offset() == 0 {
                                        let s = i0.get_space(); let o = i0.get_offset(); let sz = i0.get_size();
                                        drop(i0); drop(i1);
                                        return self.find_sub_constant(ops, s, o, sz);
                                    }
                                    return Some(i1.get_offset());
                                } else if i0.get_space() == AddressSpace::Const && i1.get_space() != AddressSpace::Const {
                                    if i0.get_offset() == 0 {
                                        let s = i1.get_space(); let o = i1.get_offset(); let sz = i1.get_size();
                                        drop(i0); drop(i1);
                                        return self.find_sub_constant(ops, s, o, sz);
                                    }
                                    return Some(i0.get_offset());
                                }
                            }
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
        None
    }

    /// Helper: extract constant from INT_SUB producing target varnode.
    fn find_sub_constant(&self, ops: &[crate::op::PcodeOpRef], ts: crate::space::AddressSpace, to: u64, tsz: usize) -> Option<u64> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == ts && ov.get_offset() == to && ov.get_size() == tsz {
                    drop(ov);
                    if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                        let i0 = op.inrefs[0].read().unwrap();
                        let i1 = op.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const { return Some(i1.get_offset()); }
                        if i0.get_space() == AddressSpace::Const { return Some(i0.get_offset()); }
                    }
                    break;
                }
            }
        }
        None
    }

    /// Find the actual varnode being compared for switch index display.
    ///
    /// Walks backwards from the CBRANCH's condition varnode. If the
    /// condition is defined directly by a comparison (INT_EQUAL etc.),
    /// returns the non-const operand. If it is defined by BOOL_NEGATE
    /// or COPY, chases through that op to find the underlying comparison.
    /// This handles cascades where the original comparison is negated or
    /// copied before being consumed by CBRANCH.
    fn find_compared_varnode(&self, ops: &[crate::op::PcodeOpRef]) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let cbranch_op = ops.last()?;
        let cb = cbranch_op.0.read().unwrap();
        if cb.opcode != OpCode::CPUI_CBRANCH { return None; }
        if cb.inrefs.len() < 2 { return None; }
        let cv = cb.inrefs[1].read().unwrap();
        let cs = cv.get_space(); let co = cv.get_offset(); let csz = cv.get_size();
        drop(cv); drop(cb);

        // Chase through COPY/BOOL_NEGATE/MULTIEQUAL to find the comparison.
        // Bound the chase depth to avoid pathological loops.
        let mut target = (cs, co, csz);
        for _ in 0..4 {
            let def_op = ops.iter().rev().find_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if let Some(ref out) = op.output {
                    let ov = out.read().unwrap();
                    if ov.get_space() == target.0 && ov.get_offset() == target.1 && ov.get_size() == target.2 {
                        return Some(op_ref.clone());
                    }
                }
                None
            })?;

            let def = def_op.0.read().unwrap();
            match def.opcode {
                OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL => {
                    if def.inrefs.len() >= 2 {
                        let i0 = def.inrefs[0].read().unwrap();
                        let i1 = def.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const && i0.get_space() != AddressSpace::Const {
                            if i1.get_offset() == 0 {
                                let s = i0.get_space(); let o = i0.get_offset(); let sz = i0.get_size();
                                drop(i0); drop(i1);
                                return self.find_sub_var_vn(ops, s, o, sz);
                            }
                            drop(i0); drop(i1);
                            return Some(def.inrefs[0].clone());
                        } else if i0.get_space() == AddressSpace::Const && i1.get_space() != AddressSpace::Const {
                            if i0.get_offset() == 0 {
                                let s = i1.get_space(); let o = i1.get_offset(); let sz = i1.get_size();
                                drop(i0); drop(i1);
                                return self.find_sub_var_vn(ops, s, o, sz);
                            }
                            drop(i0); drop(i1);
                            return Some(def.inrefs[1].clone());
                        }
                    }
                    return None;
                }
                OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL => {
                    if def.inrefs.is_empty() { return None; }
                    let src = def.inrefs[0].read().unwrap();
                    target = (src.get_space(), src.get_offset(), src.get_size());
                    drop(src);
                }
                _ => return None,
            }
        }
        None
    }

    /// Helper: find the non-const varnode input of INT_SUB producing target.
    fn find_sub_var_vn(&self, ops: &[crate::op::PcodeOpRef], ts: crate::space::AddressSpace, to: u64, tsz: usize) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == ts && ov.get_offset() == to && ov.get_size() == tsz {
                    drop(ov);
                    if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                        let i0 = op.inrefs[0].read().unwrap();
                        let i1 = op.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const {
                            drop(i0); drop(i1);
                            return Some(op.inrefs[0].clone());
                        } else if i0.get_space() == AddressSpace::Const {
                            drop(i0); drop(i1);
                            return Some(op.inrefs[1].clone());
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    fn _get_change_count(&self) -> i32 {
        self.change_count
    }
}

/// Action for performing final transformations on the block structure
///
/// Corresponds to Ghidra's `ActionFinalStructure`.
/// Tags remaining unstructured branches as GOTO and removes unreachable
/// ops that follow unconditional BRANCH or RETURN within a basic block.
pub struct ActionFinalStructure;

impl ActionFinalStructure {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionFinalStructure {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        use crate::op::branch_type;

        let mut changed = 0;

        // Tag untagged BRANCH/CBRANCH as GOTO (break/continue already tagged
        // by ActionNormalizeBranches)
        for op_ref in &fd.obank.alivelist {
            let mut op = op_ref.0.write().unwrap();
            if op.branch_type != branch_type::NONE {
                continue;
            }
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    op.branch_type = branch_type::GOTO;
                    changed += 1;
                }
                _ => {}
            }
        }

        // Remove unreachable ops after unconditional BRANCH or RETURN
        let mut dead_indices: Vec<usize> = Vec::new();
        let mut hit_terminator = false;
        let mut prev_addr: Option<u64> = None;

        for (idx, op_ref) in fd.obank.alivelist.iter().enumerate() {
            let op = op_ref.0.read().unwrap();
            let cur_addr = op.get_addr().as_u64();

            // Non-sequential address jump → new basic block
            if let Some(prev) = prev_addr {
                if cur_addr < prev || cur_addr > prev + 32 {
                    hit_terminator = false;
                }
            }
            prev_addr = Some(cur_addr);

            if hit_terminator {
                dead_indices.push(idx);
                continue;
            }

            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_RETURN => {
                    hit_terminator = true;
                }
                _ => {}
            }
        }

        // Reverse removal preserves indices
        for &idx in dead_indices.iter().rev() {
            if idx < fd.obank.alivelist.len() {
                fd.obank.alivelist.remove(idx);
                changed += 1;
            }
        }

        if changed > 0 {
            Ok(1)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "finalstructure"
    }
}

/// Action for normalizing branches (e.g., converting goto to break/continue)
///
/// Corresponds to Ghidra's `ActionNormalizeBranches`
pub struct ActionNormalizeBranches;

impl ActionNormalizeBranches {
    /// Create a new ActionNormalizeBranches instance
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionNormalizeBranches {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;
        let size = fd.sblocks.get_size();

        // Collect loop header/exit pairs from structured blocks
        let mut loop_info: Vec<(crate::address::Address, Option<crate::address::Address>)> = Vec::new();

        for i in 0..size {
            let block = match fd.sblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let block_type = block.read().unwrap().get_type();

            match block_type {
                crate::block::BlockType::WhileDo => {
                    let block_read = block.read().unwrap();
                    if let Some(wd) = block_read.as_any().downcast_ref::<BlockWhileDo>() {
                        let header_addr = wd.condition.read().unwrap().get_start_addr();

                        // The exit block is the false-branch target of the CBRANCH
                        // in the condition block.
                        let exit_addr = {
                            let cond = wd.condition.read().unwrap();
                            if cond.size_out() >= 2 {
                                // false edge (slot 0 for while-do) is typically the exit
                                // but which slot is exit depends on the loop structure.
                                // For while(cond), true edge → exit, false edge → body.
                                // Check both edges to find the one NOT pointing at body.
                                let body_addr = wd.body.read().unwrap().get_start_addr();
                                let out0_addr = cond.get_out(0).map(|e| e.point.read().unwrap().get_start_addr());
                                let out1_addr = cond.get_out(1).map(|e| e.point.read().unwrap().get_start_addr());

                                if out0_addr == Some(body_addr) {
                                    out1_addr
                                } else {
                                    out0_addr
                                }
                            } else {
                                None
                            }
                        };

                        loop_info.push((header_addr, exit_addr));
                    }
                }
                crate::block::BlockType::DoWhile => {
                    let block_read = block.read().unwrap();
                    if let Some(dwd) = block_read.as_any().downcast_ref::<crate::block::BlockDoWhile>() {
                        let header_addr = dwd.condition.read().unwrap().get_start_addr();
                        let exit_addr = {
                            let cond = dwd.condition.read().unwrap();
                            if cond.size_out() >= 2 {
                                cond.get_out(1).map(|e| e.point.read().unwrap().get_start_addr())
                            } else {
                                None
                            }
                        };
                        loop_info.push((header_addr, exit_addr));
                    }
                }
                _ => {}
            }
        }

        if loop_info.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }

        // Walk ALL ops and tag BRANCH/CBRANCH that target loop headers or exits
        for op_ref in &fd.obank.alivelist {
            let mut op = op_ref.0.write().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if op.branch_type != crate::op::branch_type::NONE {
                        continue;
                    }
                    // Input[0] is the branch target address varnode
                    let target_addr = match op.inrefs.get(0) {
                        Some(vn_arc) => vn_arc.read().unwrap().get_offset(),
                        None => continue,
                    };

                    for (header_addr, exit_addr) in &loop_info {
                        if target_addr == header_addr.as_u64() {
                            // Skip the header's own CBRANCH (the loop condition test itself)
                            if op.get_addr().as_u64() == header_addr.as_u64() {
                                continue;
                            }
                            op.branch_type = crate::op::branch_type::CONTINUE;
                            changed += 1;
                            break;
                        }
                        if let Some(ref exit) = exit_addr {
                            if target_addr == exit.as_u64() {
                                if op.get_addr().as_u64() == header_addr.as_u64() {
                                    continue;
                                }
                                op.branch_type = crate::op::branch_type::BREAK;
                                changed += 1;
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "normalizebranches"
    }
}

#[cfg(test)]
mod loopbody_tests {
    use super::*;
    use crate::block::BlockBasic;
    use crate::address::Address;

    /// Build a tiny CFG: 0→1→2→1 (loop), with 2 also →3 (exit).
    /// head=1, tail=2, body={1,2}, exit=3.
    fn build_loop_cfg() -> BlockGraph {
        let mut g = BlockGraph::new();
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(0, Address::new(0x100))));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(1, Address::new(0x110))));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(2, Address::new(0x120))));
        let b3 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(3, Address::new(0x130))));
        for b in [&b0, &b1, &b2, &b3] { g.add_block(b.clone()); }
        g.add_edge(b0.clone(), b1.clone());
        g.add_edge(b1.clone(), b2.clone());
        g.add_edge(b2.clone(), b1.clone()); // back-edge
        g.add_edge(b2.clone(), b3.clone()); // exit edge
        g
    }

    #[test]
    fn test_loopbody_find_base() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        // Body = head(1) + tail(2). Block 0 reaches 2 only via head, so not in body.
        assert!(body.contains(&1));
        assert!(body.contains(&2));
        assert!(!body.contains(&0));
        assert_eq!(lb.unique_count, 2);
        // Clear marks.
        clear_marks(&body, &g);
        assert!(!g.get_block(1).unwrap().read().unwrap().is_mark());
    }

    #[test]
    fn test_loopbody_find_exit() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        lb.find_exit(&body, &g);
        // Exit should be block 3 (the only out-of-body target from tail 2).
        assert_eq!(lb.exit_block, 3);
        clear_marks(&body, &g);
    }

    #[test]
    fn test_loopbody_label_exit_edges() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        lb.find_exit(&body, &g);
        lb.order_tails(&g);
        lb.label_exit_edges(&body, &g);
        // The 2→3 edge should be recorded (as an edge to exit_block).
        assert!(lb.exit_edges.iter().any(|e| e.from_idx == 2 && e.to_idx == 3));
        clear_marks(&body, &g);
    }

    #[test]
    fn test_floating_edge_clone() {
        let e = FloatingEdge { from_idx: 1, to_idx: 3 };
        let e2 = e.clone();
        assert_eq!(e.from_idx, e2.from_idx);
        assert_eq!(e.to_idx, e2.to_idx);
    }

    #[test]
    fn test_merge_identical_heads() {
        let mut order = vec![
            LoopBody::new(1, 2),
            LoopBody::new(1, 4), // same head as first → merge
            LoopBody::new(5, 6),
        ];
        merge_identical_heads(&mut order);
        // After merge: 2 distinct heads (1 with 2 tails, 5).
        assert_eq!(order.len(), 2);
        assert_eq!(order[0].head, 1);
        assert_eq!(order[0].tails.len(), 2);
        assert_eq!(order[1].head, 5);
    }

    /// emit_likely_edges appends exit edges and back-edges in priority order.
    #[test]
    fn test_emit_likely_edges() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        lb.find_exit(&body, &g);
        lb.order_tails(&g);
        lb.label_exit_edges(&body, &g);
        let mut likely: Vec<FloatingEdge> = Vec::new();
        lb.emit_likely_edges(&mut likely, &g);
        // The 2→3 exit edge and the 2→1 back-edge should both appear.
        assert!(likely.iter().any(|e| e.from_idx == 2 && e.to_idx == 3),
            "exit edge 2->3 missing: {:?}", likely);
        assert!(likely.iter().any(|e| e.from_idx == 2 && e.to_idx == 1),
            "back-edge 2->1 missing: {:?}", likely);
        clear_marks(&body, &g);
    }

    /// FlowBlock loop-exit mark primitives work end to end.
    #[test]
    fn test_loop_exit_mark_primitives() {
        let g = build_loop_cfg();
        // Mark block 2's out-edge to 3 as loop-exit.
        let blk2 = g.get_block(2).unwrap();
        let slot = {
            let b = blk2.read().unwrap();
            (0..b.size_out()).find(|&k| {
                b.get_out(k).map(|e| e.point.read().unwrap().get_index() == 3).unwrap_or(false)
            }).unwrap()
        };
        blk2.write().unwrap().set_loop_exit(slot);
        // is_goto_out should now be true (loop_exit is in the goto-class set).
        // Note: is_goto_out checks F_GOTO|F_IRREDUCIBLE, NOT loop_exit;
        // is_loop_dag_out (in tracedag) checks the full set. Here we verify
        // the loop_exit flag persists on the edge.
        let flags = blk2.read().unwrap().get_out(slot).unwrap().flags;
        assert!(flags & crate::block::edge_flags::F_LOOP_EXIT_EDGE != 0);
        // Clear it.
        blk2.write().unwrap().clear_loop_exit(slot);
        let flags2 = blk2.read().unwrap().get_out(slot).unwrap().flags;
        assert!(flags2 & crate::block::edge_flags::F_LOOP_EXIT_EDGE == 0);
    }

    /// Verify is_goto_out reads block-level GOTO_EDGE_0/GOTO_EDGE_1 flags.
    /// This is the fix that connects TraceDAG's goto marking (which sets
    /// block flags) to ruleBlockWhileDo's isGotoOut checks.
    #[test]
    fn test_is_goto_out_reads_block_flags() {
        let mut g = BlockGraph::new();
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(0, Address::new(0x100))));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(1, Address::new(0x110))));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(2, Address::new(0x120))));
        for b in [&b0, &b1, &b2] { g.add_block(b.clone()); }
        g.add_edge(b0.clone(), b1.clone());
        g.add_edge(b0.clone(), b2.clone());

        // Before marking: neither edge is goto.
        assert!(!b0.read().unwrap().is_goto_out(0));
        assert!(!b0.read().unwrap().is_goto_out(1));

        // Mark out-edge 1 as goto (block-level flag, like run_tracedag does).
        b0.write().unwrap().set_flags(crate::block::block_flags::GOTO_EDGE_1);

        // Now is_goto_out(1) must return true; is_goto_out(0) stays false.
        assert!(!b0.read().unwrap().is_goto_out(0), "edge 0 not goto");
        assert!(b0.read().unwrap().is_goto_out(1), "edge 1 is goto via block flag");
    }
}
