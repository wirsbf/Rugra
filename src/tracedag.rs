//! Ghidra TraceDAG port (blockaction.cc:499-1014).
//!
//! Traces the control-flow graph to find "likely unstructured edges" — edges
//! that prevent structured control-flow recovery. Once marked as goto, the
//! remaining flow can be structured as if/while instead of switch.
//!
//! This is the main algorithm behind Ghidra's selectGoto. It builds a DAG of
//! active traces from the function roots, pushes them forward, and when a
//! node can't be opened (not all in-edges traced), selects the worst edge
//! (via BadEdgeScore) to mark as an unstructured goto.

use crate::block::BlockGraph;
use std::sync::Arc;
use std::sync::RwLock;
use std::collections::HashMap;

/// A floating (likely goto) edge: (source_block_idx, dest_block_idx).
#[derive(Clone, Debug)]
pub struct FloatingEdge {
    pub top: i32,
    pub bottom: i32,
}

/// A branch point in the trace DAG. Corresponds to a FlowBlock node that has
/// multiple outgoing edges being traced.
struct BranchPoint {
    /// Parent BranchPoint index (None for root).
    parent: Option<usize>,
    /// Depth from root.
    depth: usize,
    /// Index of the path out of the parent BranchPoint that leads to this.
    pathout: usize,
    /// Mark flag for path-finding (markPath/distance).
    ismark: bool,
    /// The FlowBlock (by graph index) at this branch point.
    top_block_idx: i32,
    /// Indices into BlockTrace vec for paths out of this branch point.
    paths: Vec<usize>,
}

/// A single traced path out of a BranchPoint.
struct BlockTrace {
    /// Index of parent BranchPoint.
    top_bp: usize,
    /// Path index within the BranchPoint.
    pathout: usize,
    /// Current FlowBlock being traced (graph index).
    bottom_block_idx: i32,
    /// Next FlowBlock to push into (graph index).
    dest_block_idx: i32,
    /// Number of edges lumped together.
    edgelump: i32,
    /// Flags: f_active, f_terminal.
    active: bool,
    terminal: bool,
}

/// TraceDAG: the main tracer.
pub struct TraceDAG<'a> {
    graph: &'a BlockGraph,
    branch_points: Vec<BranchPoint>,
    traces: Vec<BlockTrace>,
    /// Indices of active traces.
    active_list: Vec<usize>,
    /// Roots (entry blocks).
    roots: Vec<i32>,
    /// The likely goto edges discovered.
    pub likely_goto: Vec<FloatingEdge>,
    /// Visit-count tracking: block_idx → count of traced in-edges.
    /// Faithful to Ghidra's FlowBlock::visitcount (block.hh:125), only
    /// incremented by remove_trace (matching removeTrace blockaction.cc:661).
    visit_count: HashMap<i32, i32>,
    /// Finish block: if set, only the root trace can open it (Ghidra
    /// finishblock, blockaction.cc:822-823). Used by per-loop TraceDAG.
    finish_block_idx: Option<i32>,
}

impl<'a> TraceDAG<'a> {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new(graph: &'a BlockGraph) -> Self {
        Self {
            graph,
            branch_points: Vec::new(),
            traces: Vec::new(),
            active_list: Vec::new(),
            roots: Vec::new(),
            likely_goto: Vec::new(),
            visit_count: HashMap::new(),
            finish_block_idx: None,
        }
    }

    // RUGRA-GLUE: add_root (no Ghidra counterpart found)
    pub fn add_root(&mut self, root_idx: i32) {
        self.roots.push(root_idx);
    }

    // RUGRA-GLUE: size_out (no Ghidra counterpart found)
    /// Get the size_out of a block by graph index.
    fn size_out(&self, idx: i32) -> usize {
        if let Some(b) = self.graph.get_block(idx as usize) {
            b.read().unwrap().size_out()
        } else {
            0
        }
    }

    // RUGRA-GLUE: get_out (no Ghidra counterpart found)
    /// Get out-edge target block index.
    fn get_out(&self, idx: i32, slot: usize) -> Option<i32> {
        if let Some(b) = self.graph.get_block(idx as usize) {
            let r = b.read().unwrap();
            r.get_out(slot).map(|e| e.point.read().unwrap().get_index())
        } else {
            None
        }
    }

    // RUGRA-GLUE: size_in (no Ghidra counterpart found)
    /// Get size_in of a block.
    fn size_in(&self, idx: i32) -> usize {
        if let Some(b) = self.graph.get_block(idx as usize) {
            b.read().unwrap().size_in()
        } else {
            0
        }
    }

    // RUGRA-GLUE: is_loop_dag_out (no Ghidra counterpart found)
    /// Is the i-th out-edge of `idx` a loop-DAG edge (traceable)?
    /// Faithful to Ghidra `FlowBlock::isLoopDAGOut` (block.hh:342):
    ///   `(outofthis[i].label & (f_irreducible|f_back_edge|f_loop_exit_edge|f_goto_edge))==0`
    /// An edge is traceable only if it is none of: irreducible, back-edge,
    /// loop-exit-edge, or goto-edge. Back/loop-exit exclusion is what prevents
    /// tracing into cycles, so termination follows structurally.
    fn is_loop_dag_out(&self, idx: i32, slot: usize) -> bool {
        if let Some(b) = self.graph.get_block(idx as usize) {
            let r = b.read().unwrap();
            let flags = r.get_out(slot).map(|e| e.flags).unwrap_or(0);
            use crate::block::edge_flags::*;
            (flags & (F_IRREDUCIBLE_EDGE | F_BACK_EDGE | F_LOOP_EXIT_EDGE | F_GOTO_EDGE)) == 0
        } else {
            false
        }
    }

    // Ghidra: block.hh:345 FlowBlock::isLoopDAGIn
    /// Is the i-th in-edge of `idx` a loop-DAG edge?
    /// Faithful to Ghidra `FlowBlock::isLoopDAGIn` (block.hh:345): same
    /// four-flag mask as isLoopDAGOut.
    fn is_loop_dag_in(&self, idx: i32, slot: usize) -> bool {
        if let Some(b) = self.graph.get_block(idx as usize) {
            let r = b.read().unwrap();
            let flags = r.get_in(slot).map(|e| e.flags).unwrap_or(0);
            use crate::block::edge_flags::*;
            (flags & (F_IRREDUCIBLE_EDGE | F_BACK_EDGE | F_LOOP_EXIT_EDGE | F_GOTO_EDGE)) == 0
        } else {
            false
        }
    }

    // Ghidra: blockaction.cc:822 TraceDAG::finishblock
    /// Set the finish block. Faithful to Ghidra TraceDAG::finishblock
    /// (blockaction.cc:822). Only the root trace can open the finish block.
    pub fn set_finish_block(&mut self, idx: i32) {
        self.finish_block_idx = Some(idx);
    }

    // RUGRA-GLUE: initialize (no Ghidra counterpart found)
    /// Initialize: create root BranchPoint and traces for each root.
    pub fn initialize(&mut self) {
        // Root BranchPoint (virtual, no real block)
        self.branch_points.push(BranchPoint {
            parent: None,
            depth: 0,
            pathout: 0,
            ismark: false,
            top_block_idx: -1,
            paths: Vec::new(),
        });
        let root_bp = 0;
        let roots = self.roots.clone();
        for &root_blk in &roots {
            let trace_idx = self.traces.len();
            self.traces.push(BlockTrace {
                top_bp: root_bp,
                pathout: self.branch_points[root_bp].paths.len(),
                bottom_block_idx: -1, // virtual root has no bottom
                dest_block_idx: root_blk,
                edgelump: 1,
                active: false,
                terminal: false,
            });
            self.branch_points[root_bp].paths.push(trace_idx);
            self.insert_active(trace_idx);
        }
    }

    // RUGRA-GLUE: insert_active (no Ghidra counterpart found)
    fn insert_active(&mut self, trace_idx: usize) {
        self.active_list.push(trace_idx);
        self.traces[trace_idx].active = true;
    }

    // RUGRA-GLUE: remove_active (no Ghidra counterpart found)
    fn remove_active(&mut self, trace_idx: usize) {
        self.active_list.retain(|&i| i != trace_idx);
        self.traces[trace_idx].active = false;
    }

    // RUGRA-GLUE: check_open (no Ghidra counterpart found)
    /// Check if a trace can push into its dest node.
    /// Faithful to `TraceDAG::checkOpen` (blockaction.cc:810-833).
    /// A node is openable when the number of traced loop-DAG in-edges
    /// (edgelump + visit_count) >= total loop-DAG in-edges.
    fn check_open(&self, trace_idx: usize) -> bool {
        let trace = &self.traces[trace_idx];
        if trace.terminal {
            return false;
        }
        let bp = &self.branch_points[trace.top_bp];
        let is_root = bp.depth == 0;
        if is_root && trace.bottom_block_idx < 0 {
            return true; // Artificial root (blockaction.cc:817)
        }
        let dest = trace.dest_block_idx;
        if dest < 0 {
            return false;
        }
        // finishblock guard (blockaction.cc:822-823): only root can open it.
        if !is_root && self.finish_block_idx == Some(dest) {
            return false;
        }
        // Count loop-DAG in-edges of dest (blockaction.cc:826-831).
        let vc = self.visit_count.get(&dest).copied().unwrap_or(0);
        let ignore = trace.edgelump + vc;
        let sin = self.size_in(dest);
        let mut count = 0i32;
        for i in 0..sin {
            if self.is_loop_dag_in(dest, i) {
                count += 1;
                if count > ignore {
                    return false;
                }
            }
        }
        true
    }

    // RUGRA-GLUE: check_retirement (no Ghidra counterpart found)
    /// Check if a BranchPoint can be retired (all paths terminal or to same exit).
    fn check_retirement(&self, trace_idx: usize) -> Option<i32> {
        let trace = &self.traces[trace_idx];
        if trace.pathout != 0 {
            return None;
        }
        let bp_idx = trace.top_bp;
        let bp = &self.branch_points[bp_idx];
        if bp.depth == 0 {
            // Root: all paths must be terminal
            for &pidx in &bp.paths {
                if !self.traces[pidx].active || !self.traces[pidx].terminal {
                    return None;
                }
            }
            return Some(-1);
        }
        // Non-root: all paths terminal or to same exit block
        let mut exit_block: i32 = -1;
        for &pidx in &bp.paths {
            let pt = &self.traces[pidx];
            if !pt.active {
                return None;
            }
            if pt.terminal {
                continue;
            }
            if exit_block == pt.dest_block_idx {
                continue;
            }
            if exit_block >= 0 {
                return None;
            }
            exit_block = pt.dest_block_idx;
        }
        Some(exit_block)
    }

    // RUGRA-GLUE: open_branch (no Ghidra counterpart found)
    /// Open a branch: create new BranchPoint at dest node with sub-traces.
    /// Faithful to Ghidra `BranchPoint::createTraces` (blockaction.cc:499-507)
    /// + `openBranch` (blockaction.cc:839-858).
    fn open_branch(&mut self, trace_idx: usize) {
        let dest = self.traces[trace_idx].dest_block_idx;
        let top_bp = self.traces[trace_idx].top_bp;
        let parent_depth = self.branch_points[top_bp].depth;
        let parent_pathout = self.traces[trace_idx].pathout;

        let new_bp_idx = self.branch_points.len();
        self.branch_points.push(BranchPoint {
            parent: Some(top_bp),
            depth: parent_depth + 1,
            pathout: parent_pathout,
            ismark: false,
            top_block_idx: dest,
            paths: Vec::new(),
        });

        // createTraces (blockaction.cc:499-507): create sub-traces for each
        // out-edge that is a loop-DAG edge (isLoopDAGOut). Skip non-DAG edges.
        let size_out = self.size_out(dest);
        for eo in 0..size_out {
            // Ghidra: if (!top->isLoopDAGOut(i)) continue;
            if !self.is_loop_dag_out(dest, eo) { continue; }
            if let Some(target) = self.get_out(dest, eo) {
                let new_trace_idx = self.traces.len();
                self.traces.push(BlockTrace {
                    top_bp: new_bp_idx,
                    pathout: self.branch_points[new_bp_idx].paths.len(),
                    bottom_block_idx: dest,
                    dest_block_idx: target,
                    edgelump: 1,
                    active: false,
                    terminal: false,
                });
                self.branch_points[new_bp_idx].paths.push(new_trace_idx);
            }
        }

        if self.branch_points[new_bp_idx].paths.is_empty() {
            // No sub-traces: mark parent trace as terminal
            self.remove_active(trace_idx);
            self.traces[trace_idx].terminal = true;
            self.traces[trace_idx].bottom_block_idx = -1;
            self.traces[trace_idx].dest_block_idx = -1;
            self.traces[trace_idx].edgelump = 0;
        } else {
            // Deactivate parent, activate children
            self.remove_active(trace_idx);
            for &pidx in &self.branch_points[new_bp_idx].paths.clone() {
                self.insert_active(pidx);
            }
        }
    }

    // RUGRA-GLUE: retire_branch (no Ghidra counterpart found)
    /// Retire a BranchPoint: update parent trace.
    fn retire_branch(&mut self, bp_idx: usize, exit_block: i32) {
        let parent_trace_idx;
        let edgeout_bl;
        let edgelump_sum;

        {
            let bp = &self.branch_points[bp_idx];
            parent_trace_idx = bp.parent.map(|p| {
                self.branch_points[p].paths[bp.pathout]
            });
            let mut sum = 0i32;
            let mut ebl: i32 = -1;
            let paths = bp.paths.clone();
            for &pidx in &paths {
                let pt = &self.traces[pidx];
                if !pt.terminal {
                    sum += pt.edgelump;
                    if ebl < 0 {
                        ebl = pt.bottom_block_idx;
                    }
                }
            }
            edgelump_sum = sum;
            edgeout_bl = ebl;
            // Remove all child traces from active
            for &pidx in &paths {
                self.remove_active(pidx);
            }
        }

        if bp_idx == 0 {
            return; // Root
        }

        if let Some(pti) = parent_trace_idx {
            if edgeout_bl < 0 {
                self.traces[pti].terminal = true;
                self.traces[pti].bottom_block_idx = -1;
                self.traces[pti].dest_block_idx = -1;
                self.traces[pti].edgelump = 0;
            } else {
                self.traces[pti].bottom_block_idx = edgeout_bl;
                self.traces[pti].dest_block_idx = exit_block;
                self.traces[pti].edgelump = edgelump_sum;
            }
            self.insert_active(pti);
        }
    }

    // RUGRA-GLUE: remove_trace (no Ghidra counterpart found)
    /// Remove a trace (mark its edge as goto).
    fn remove_trace(&mut self, trace_idx: usize) {
        let bottom = self.traces[trace_idx].bottom_block_idx;
        let dest = self.traces[trace_idx].dest_block_idx;
        let edgelump = self.traces[trace_idx].edgelump;

        // Record as likely goto
        if bottom >= 0 && dest >= 0 {
            self.likely_goto.push(FloatingEdge { top: bottom, bottom: dest });
        }

        // Update visit count: ignore this edge (mark as goto so the dest
        // node can be opened later without this edge being traced).
        if dest >= 0 {
            *self.visit_count.entry(dest).or_insert(0) += edgelump;
        }

        let top_bp = self.traces[trace_idx].top_bp;
        let bp_top = self.branch_points[top_bp].top_block_idx;

        if bottom != bp_top && bottom >= 0 {
            // Trace has moved past root branch — treat as terminal
            self.traces[trace_idx].terminal = true;
            self.traces[trace_idx].bottom_block_idx = -1;
            self.traces[trace_idx].dest_block_idx = -1;
            self.traces[trace_idx].edgelump = 0;
            return;
        }

        // Remove from active
        self.remove_active(trace_idx);
        self.traces[trace_idx].terminal = true;
    }

    // RUGRA-GLUE: select_bad_edge (no Ghidra counterpart found)
    /// Select the worst edge to mark as goto using BadEdgeScore.
    /// Scores: siblingedge (shared BranchPoint), terminal (dest has no out),
    /// distance (between branch points), depth. The highest score = most likely bad edge.
    fn select_bad_edge(&self) -> usize {
        struct Score {
            trace_idx: usize,
            exit_block: i32,
            distance: i32,    // -1 = not yet computed
            siblingedge: i32,
            terminal: i32,    // 1 if dest has size_out==0
            bp_depth: usize,
        }

        let mut scores: Vec<Score> = Vec::new();
        for &idx in &self.active_list {
            let trace = &self.traces[idx];
            if trace.terminal { continue; }
            let bp = &self.branch_points[trace.top_bp];
            // Skip virtual edges (root, no real bottom)
            if bp.depth == 0 && trace.bottom_block_idx < 0 { continue; }
            let dest = trace.dest_block_idx;
            scores.push(Score {
                trace_idx: idx,
                exit_block: dest,
                distance: -1,
                siblingedge: 0,
                terminal: if dest >= 0 && self.size_out(dest) == 0 { 1 } else { 0 },
                bp_depth: bp.depth,
            });
        }

        if scores.is_empty() {
            return self.active_list[0];
        }

        // Sort by exit_block to find conflicts (same dest)
        scores.sort_by_key(|s| s.exit_block);

        // Process conflicts: traces to the same exit block
        let mut i = 0;
        while i < scores.len() {
            let mut j = i + 1;
            while j < scores.len() && scores[j].exit_block == scores[i].exit_block {
                j += 1;
            }
            if j - i > 1 {
                // Conflict: multiple traces to same exit. Compute distance/sibling.
                for a in i..j {
                    for b in (a+1)..j {
                        let bp_a = self.traces[scores[a].trace_idx].top_bp;
                        let bp_b = self.traces[scores[b].trace_idx].top_bp;
                        if bp_a == bp_b {
                            scores[a].siblingedge += 1;
                            scores[b].siblingedge += 1;
                        }
                        // Simplified distance: depth difference
                        let dist = (self.branch_points[bp_a].depth as i32 -
                                    self.branch_points[bp_b].depth as i32).abs();
                        if scores[a].distance == -1 || scores[a].distance > dist {
                            scores[a].distance = dist;
                        }
                        if scores[b].distance == -1 || scores[b].distance > dist {
                            scores[b].distance = dist;
                        }
                    }
                }
            }
            i = j;
        }

        // Select max: higher siblingedge > higher terminal > higher distance > higher depth
        // (compareFinal: op2 is "less likely bad" if it has smaller siblingedge,
        //  or smaller terminal, or smaller distance, or smaller depth)
        let mut best = 0;
        for k in 1..scores.len() {
            let s = &scores[k];
            let b = &scores[best];
            // s is MORE likely bad than best if:
            let is_more_likely = if s.siblingedge != b.siblingedge {
                s.siblingedge > b.siblingedge
            } else if s.terminal != b.terminal {
                s.terminal > b.terminal
            } else if s.distance != b.distance {
                s.distance > b.distance
            } else {
                s.bp_depth > b.bp_depth
            };
            if is_more_likely {
                best = k;
            }
        }

        scores[best].trace_idx
    }

    // RUGRA-GLUE: push_branches (no Ghidra counterpart found)
    /// Main algorithm: push traces forward, marking bad edges as goto.
    pub fn push_branches(&mut self) {
        let mut missed = 0;
        let mut pos = 0usize;
        // DIAGNOSTIC: hard ceiling to surface any non-termination cleanly.
        // Ghidra's trace is structurally terminating (back/loop-exit edges
        // excluded by isLoopDAGOut/In, plus the missed>=active_count bad-edge
        // fallback removes one trace per pass). If this ceiling ever fires
        // it indicates a flag-computation bug, not a missing guard.
        let mut iter_guard = 0u64;
        let iter_cap = 5000u64;

        while !self.active_list.is_empty() {
            iter_guard += 1;
            if iter_guard > iter_cap {
                eprintln!(
                    "[TRACEDAG] iter cap {} hit for graph size {} — investigate flag calc",
                    iter_cap,
                    self.graph.get_size()
                );
                // Dump active traces for diagnosis
                for &ai in &self.active_list {
                    let t = &self.traces[ai];
                    let dest = t.dest_block_idx;
                    let sin = if dest >= 0 { self.size_in(dest) } else { 0 };
                    let vc = self.visit_count.get(&dest).copied().unwrap_or(0);
                    let mut loopdag_in = 0;
                    for s in 0..sin {
                        if self.is_loop_dag_in(dest, s) { loopdag_in += 1; }
                    }
                    let bp = &self.branch_points[t.top_bp];
                    eprintln!(
                        "[TRACEDAG]   trace#{} dest={} active={} terminal={} edgelump={} vc={} loopDAG_in={} total_in={} bp_depth={}",
                        ai, dest, t.active, t.terminal, t.edgelump, vc, loopdag_in, sin, bp.depth
                    );
                }
                break;
            }
            if pos >= self.active_list.len() {
                pos = 0;
            }
            let active_count = self.active_list.len();
            if missed >= active_count {
                // Can't push any trace — select a bad edge
                let bad = self.select_bad_edge();
                self.remove_trace(bad);
                missed = 0;
                pos = 0;
                continue;
            }

            let trace_idx = self.active_list[pos];

            if let Some(exit_block) = self.check_retirement(trace_idx) {
                let bp_idx = self.traces[trace_idx].top_bp;
                self.retire_branch(bp_idx, exit_block);
                missed = 0;
                pos = 0;
            } else if self.check_open(trace_idx) {
                self.open_branch(trace_idx);
                missed = 0;
                pos = 0;
            } else {
                missed += 1;
                pos += 1;
            }
        }
    }

    // RUGRA-GLUE: run (no Ghidra counterpart found)
    /// Run the full TraceDAG: initialize, push branches, return likely goto edges.
    pub fn run(mut self) -> Vec<FloatingEdge> {
        self.initialize();
        self.push_branches();
        self.likely_goto
    }
}

// RUGRA-GLUE: generate_likely_gotos (no Ghidra counterpart found)
/// Generate likely goto edges for a function's control-flow graph.
/// Returns a list of (source_block_idx, dest_block_idx) edges that should be
/// marked as unstructured goto to allow structured recovery.
pub fn generate_likely_gotos(graph: &BlockGraph) -> Vec<FloatingEdge> {
    // Skip small/simple functions — they don't need goto edge marking.
    if graph.get_size() < 10 { return Vec::new(); }

    // Find root blocks (size_in == 0)
    let roots: Vec<i32> = (0..graph.get_size())
        .filter_map(|i| {
            graph.get_block(i).and_then(|b| {
                let r = b.read().unwrap();
                if r.size_in() == 0 { Some(r.get_index()) } else { None }
            })
        })
        .collect();

    if roots.is_empty() {
        return Vec::new();
    }

    let mut tdag = TraceDAG::new(graph);
    for r in roots {
        tdag.add_root(r);
    }
    tdag.run()
}
