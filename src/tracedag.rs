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
}

impl<'a> TraceDAG<'a> {
    pub fn new(graph: &'a BlockGraph) -> Self {
        Self {
            graph,
            branch_points: Vec::new(),
            traces: Vec::new(),
            active_list: Vec::new(),
            roots: Vec::new(),
            likely_goto: Vec::new(),
        }
    }

    pub fn add_root(&mut self, root_idx: i32) {
        self.roots.push(root_idx);
    }

    /// Get the size_out of a block by graph index.
    fn size_out(&self, idx: i32) -> usize {
        if let Some(b) = self.graph.get_block(idx as usize) {
            b.read().unwrap().size_out()
        } else {
            0
        }
    }

    /// Get out-edge target block index.
    fn get_out(&self, idx: i32, slot: usize) -> Option<i32> {
        if let Some(b) = self.graph.get_block(idx as usize) {
            let r = b.read().unwrap();
            r.get_out(slot).map(|e| e.point.read().unwrap().get_index())
        } else {
            None
        }
    }

    /// Get size_in of a block.
    fn size_in(&self, idx: i32) -> usize {
        if let Some(b) = self.graph.get_block(idx as usize) {
            b.read().unwrap().size_in()
        } else {
            0
        }
    }

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

    fn insert_active(&mut self, trace_idx: usize) {
        self.active_list.push(trace_idx);
        self.traces[trace_idx].active = true;
    }

    fn remove_active(&mut self, trace_idx: usize) {
        self.active_list.retain(|&i| i != trace_idx);
        self.traces[trace_idx].active = false;
    }

    /// Check if a trace can push into its dest node.
    /// A node can only be opened if all incoming edges have been traced.
    fn check_open(&self, trace_idx: usize) -> bool {
        let trace = &self.traces[trace_idx];
        if trace.terminal {
            return false;
        }
        let bp = &self.branch_points[trace.top_bp];
        let is_root = bp.depth == 0;
        if is_root && trace.bottom_block_idx < 0 {
            return true; // Artificial root can always open first level
        }
        let dest = trace.dest_block_idx;
        if dest < 0 {
            return false;
        }
        // Count in-edges and check if all have been traced (via visit count).
        // Simplified: check if dest has size_in <= edgelump (all edges accounted for).
        // In Ghidra, this uses visitCount. We approximate: a node is openable if
        // its size_in matches the number of traced edges reaching it.
        // For now, use a simpler heuristic: openable if size_in == 1 or all
        // predecessors have been traced.
        // TODO: implement visit-count tracking for full fidelity.
        let sin = self.size_in(dest);
        if sin <= trace.edgelump as usize {
            return true;
        }
        // Check if all in-edges are from blocks already consumed/traced
        // (This is the loopDAGIn check in Ghidra)
        false
    }

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

    /// Open a branch: create new BranchPoint at dest node with sub-traces.
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

        // Create sub-traces for each out-edge of dest
        let size_out = self.size_out(dest);
        for eo in 0..size_out {
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

    /// Remove a trace (mark its edge as goto).
    fn remove_trace(&mut self, trace_idx: usize) {
        let bottom = self.traces[trace_idx].bottom_block_idx;
        let dest = self.traces[trace_idx].dest_block_idx;

        // Record as likely goto
        if bottom >= 0 && dest >= 0 {
            self.likely_goto.push(FloatingEdge { top: bottom, bottom: dest });
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

    /// Select the worst edge to mark as goto (simplified BadEdgeScore).
    fn select_bad_edge(&self) -> usize {
        // Simplified: pick the first non-terminal active trace
        // TODO: implement full BadEdgeScore (distance, siblingedge, terminal)
        for &idx in &self.active_list {
            if !self.traces[idx].terminal {
                let bp = &self.branch_points[self.traces[idx].top_bp];
                if bp.depth > 0 || self.traces[idx].bottom_block_idx >= 0 {
                    return idx;
                }
            }
        }
        self.active_list[0]
    }

    /// Main algorithm: push traces forward, marking bad edges as goto.
    pub fn push_branches(&mut self) {
        let mut missed = 0;
        let mut pos = 0usize;

        while !self.active_list.is_empty() {
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

    /// Run the full TraceDAG: initialize, push branches, return likely goto edges.
    pub fn run(mut self) -> Vec<FloatingEdge> {
        self.initialize();
        self.push_branches();
        self.likely_goto
    }
}

/// Generate likely goto edges for a function's control-flow graph.
/// Returns a list of (source_block_idx, dest_block_idx) edges that should be
/// marked as unstructured goto to allow structured recovery.
pub fn generate_likely_gotos(graph: &BlockGraph) -> Vec<FloatingEdge> {
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
