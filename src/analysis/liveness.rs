//! Liveness Analysis for SSA Variables
//!
//! This module computes the live ranges of SSA variables to support
//! variable merging and interference graph construction.

use crate::pcode::Program;
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::ssa::SSAForm;
use std::collections::{HashMap, HashSet, VecDeque};

/// Represents a specific instruction location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstructionIndex {
    pub block: usize,
    pub op_index: usize,
}

/// Liveness information for a single SSA variable
#[derive(Debug, Clone)]
pub struct LiveRange {
    /// Where the variable is defined
    pub def: InstructionIndex,
    /// Where the variable is used (last uses)
    pub uses: Vec<InstructionIndex>,
    /// Blocks where the variable is live-through (live-in and live-out)
    pub live_blocks: HashSet<usize>,
    /// Blocks where the variable is live-in (but maybe not live-out, e.g. usage block)
    pub live_in: HashSet<usize>,
    /// Blocks where the variable is live-out
    pub live_out: HashSet<usize>,
}

impl LiveRange {
    /// Check if this live range intersects with another
    pub fn intersects(&self, other: &LiveRange) -> bool {
        // 1. Check block overlap
        let common_blocks: Vec<&usize> = self.live_in.intersection(&other.live_in).collect();

        for &block in common_blocks {
            // Case 1: Both pass through (live-through) -> Intersection
            if self.live_blocks.contains(&block) && other.live_blocks.contains(&block) {
                return true;
            }

            // Case 2: One is defined/used in this block.
            let range1 = self.get_block_range(block);
            let range2 = other.get_block_range(block);

            if ranges_overlap(range1, range2) {
                return true;
            }
        }

        false
    }

    /// Get instruction index range [start, end] for this variable in a specific block
    fn get_block_range(&self, block: usize) -> (usize, usize) {
        // Start: 0 if live-in, or Def index if defined here
        let start = if self.def.block == block {
            self.def.op_index
        } else {
            0
        };

        // End: MAX if live-out, or max Use index if used here
        let mut end = 0;
        if self.live_out.contains(&block) {
            end = usize::MAX;
        } else {
            for use_idx in &self.uses {
                if use_idx.block == block {
                    end = end.max(use_idx.op_index);
                }
            }
        }

        (start, end)
    }
}

fn ranges_overlap(r1: (usize, usize), r2: (usize, usize)) -> bool {
    r1.0 <= r2.1 && r2.0 <= r1.1
}

/// Analysis result containing live ranges for all SSA variables
#[derive(Debug, Clone)]
pub struct LivenessAnalysis {
    pub ranges: HashMap<String, LiveRange>,
}

impl LivenessAnalysis {
    pub fn new() -> Self {
        LivenessAnalysis {
            ranges: HashMap::new(),
        }
    }

    pub fn get_live_range(&self, var: &str) -> Option<&LiveRange> {
        self.ranges.get(var)
    }

    /// Check if two variables interfere (cannot be merged)
    pub fn interfere(&self, var1: &str, var2: &str) -> bool {
        if let (Some(r1), Some(r2)) = (self.ranges.get(var1), self.ranges.get(var2)) {
            r1.intersects(r2)
        } else {
            false
        }
    }
}

/// Compute liveness for all variables in SSA form
pub fn compute_liveness(
    program: &Program,
    cfg: &ControlFlowGraph,
    ssa: &SSAForm,
) -> LivenessAnalysis {
    let mut analysis = LivenessAnalysis::new();

    for (var_name, &def_block_idx) in &ssa.definitions {
        // Approximate definition instruction index
        // Ideally SSAForm should store this. For now, we search or default to 0.
        let mut def_op_idx = 0;
        let block = &cfg.blocks[def_block_idx];

        // Check Phi nodes
        let mut is_phi = false;
        if let Some(phis) = ssa.phi_nodes.get(&def_block_idx) {
            for phi in phis {
                if &phi.output == var_name {
                    def_op_idx = 0;
                    is_phi = true;
                    break;
                }
            }
        }

        if !is_phi {
            // Heuristic scan for definition in operations
            // This assumes physical varnode name matches base of SSA name
            for (local_idx, &prog_op_idx) in block.operations.iter().enumerate() {
                if prog_op_idx < program.operation_count() {
                    let op = &program.operations()[prog_op_idx];
                    if let Some(output) = op.output() {
                        let vn_name_base = format!("{:?}_{:x}_{}", output.space(), output.offset(), output.size());
                        if var_name.starts_with(&vn_name_base) {
                            def_op_idx = local_idx + 1; // +1 for phi slots
                        }
                    }
                }
            }
        }

        let def_loc = InstructionIndex { block: def_block_idx, op_index: def_op_idx };

        let mut live_range = LiveRange {
            def: def_loc,
            uses: Vec::new(),
            live_blocks: HashSet::new(),
            live_in: HashSet::new(),
            live_out: HashSet::new(),
        };

        // Populate uses from SSA info
        if let Some(use_blocks) = ssa.uses.get(var_name) {
            for &use_block_idx in use_blocks {
                // Approximate use index (end of block for worst case safety)
                let use_op_idx = if use_block_idx < cfg.blocks.len() {
                    cfg.blocks[use_block_idx].operations.len() + 1
                } else {
                    0
                };
                live_range.uses.push(InstructionIndex { block: use_block_idx, op_index: use_op_idx });
                live_range.live_in.insert(use_block_idx);
            }
        }

        // Backward propagation
        let mut worklist = VecDeque::new();
        for &block in &live_range.live_in {
            worklist.push_back(block);
        }

        while let Some(block_idx) = worklist.pop_front() {
            if block_idx == live_range.def.block {
                continue;
            }

            if block_idx < cfg.blocks.len() {
                let block = &cfg.blocks[block_idx];
                for &pred_idx in &block.predecessors {
                    if live_range.live_out.insert(pred_idx) {
                        // If live-out changed, check if we need to propagate to live-in
                        // We propagate if it's not the definition block
                        if pred_idx != live_range.def.block {
                            if live_range.live_in.insert(pred_idx) {
                                live_range.live_blocks.insert(pred_idx);
                                worklist.push_back(pred_idx);
                            }
                        }
                    }
                }
            }
        }

        analysis.ranges.insert(var_name.clone(), live_range);
    }

    analysis
}
