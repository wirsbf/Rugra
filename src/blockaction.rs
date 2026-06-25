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

/// Structure for iteratively collapsing control flow patterns
///
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
        }
    }

    /// Collapse all structured patterns until fixpoint
    ///
    /// Corresponds to Ghidra's `CollapseStructure::collapseAll`
    pub(crate) fn collapse_all(&mut self) {
        // Step 1: Order loop bodies (Ghidra's orderLoopBodies)
        self.order_loop_bodies();

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
            self.collapse_conditions();
            if std::time::Instant::now() > deadline { break; }
            self.collapse_bool_conditions();
            self.collapse_switches();
            self.collapse_cbranch_cascades();
            self.collapse_case_fallthru();
            self.refresh_switch_cases();
            self.collapse_sequences();

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
        if self.try_rule_cat(i) { return; }
        if self.try_rule_proper_if(i) { return; }
        if self.try_rule_if_else(i) { return; }
        if self.try_rule_while_do(i) { return; }
        if self.try_rule_do_while(i) { return; }
        if self.try_rule_if_goto(i) { return; }
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
        loop {
            if std::time::Instant::now() > goto_deadline { break; }
            let goto_marked = self.select_and_mark_goto();
            if !goto_marked { break; }
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
        self.compute_dominators();
        let size = self.graph.get_size();

        // Find all back-edges and create loop bodies
        for i in 0..size {
            let block = match self.graph.get_block(i) { Some(b) => b, None => continue };
            let b = block.read().unwrap();
            let src_idx = b.get_index();
            // Check all out-edges for back-edges (target dominates source)
            for slot in 0..b.size_out() {
                if let Some(edge) = b.get_out(slot) {
                    let tgt_idx = edge.point.read().unwrap().get_index();
                    // Back-edge: target dominates source (target is loop head)
                    if self.dominates_idx(tgt_idx, src_idx) {
                        // Collect loop body: all blocks that can reach src_idx
                        // without going through tgt_idx (the loop head).
                        let body = self.collect_loop_body(tgt_idx, src_idx, size);
                        if !body.is_empty() {
                            self.loop_bodies.push((tgt_idx, body));
                        }
                    }
                }
            }
        }

        // Sort by body size (smallest = innermost first)
        self.loop_bodies.sort_by_key(|(_, body)| body.len());
        eprintln!("[COLLAPSE] {} orderLoopBodies: {} loops found", self.name, self.loop_bodies.len());
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

    /// Compute immediate dominators using iterative dataflow (Cooper et al.
    /// 2001 simplified algorithm). Stores result in self.idom.
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
                        let src_idx = e.point.read().unwrap().get_index();
                        if !consumed_set.contains(&src_idx) {
                            ib.push(e.point.clone());
                        }
                    }
                }
                for slot in 0..c.size_out() {
                    if let Some(e) = c.get_out(slot) {
                        let dst_idx = e.point.read().unwrap().get_index();
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
                        let t = bb.outgoing[eslot].point.read().unwrap().get_index();
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
                        let s = bb.incoming[dslot].point.read().unwrap().get_index();
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
            // BlockIf / BlockList / BlockWhileDo / BlockDoWhile / BlockSwitch
            // all expose incoming/outgoing via as_any_mut. Try the common ones.
            if let Some(bif) = nref.downcast_mut::<crate::block::BlockIf>() {
                bif.incoming = new_in; bif.outgoing = new_out;
            } else if let Some(blist) = nref.downcast_mut::<crate::block::BlockList>() {
                blist.incoming = new_in; blist.outgoing = new_out;
            } else if let Some(bwd) = nref.downcast_mut::<crate::block::BlockWhileDo>() {
                bwd.incoming = new_in; bwd.outgoing = new_out;
            } else if let Some(bdw) = nref.downcast_mut::<crate::block::BlockDoWhile>() {
                bdw.incoming = new_in; bdw.outgoing = new_out;
            }
        }

        // NOW install new_block at install_idx (replaces the cond block).
        // Done AFTER self_identify captured the cond block's boundary edges.
        if install_idx < size {
            self.graph.blocks[install_idx] = new_block.clone();
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
            // Don't merge structured blocks (BlockIf, BlockCondition, etc.)
            if n_type != crate::block::BlockType::Basic && n_type != crate::block::BlockType::Copy {
                break;
            }
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
            if c.size_in() != 1 { continue; }   // Only this block enters clause
            if c.size_out() != 1 { continue; }   // Clause has only one exit
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

    /// Detect and collapse if-then (triangle) and if-then-else (diamond) patterns.
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
                            let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                Arc::new(RwLock::new(BlockIf {
                                    index: cond_idx,
                                    condition: block.clone(),
                                    if_body: true_block.clone(),
                                    else_body: None,
                                    negated: false,
                                    incoming: Vec::new(),
                                    outgoing: Vec::new(),
                                    parent: None,
                                    flags: 0,
                                }));
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
                            let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                Arc::new(RwLock::new(BlockIf {
                                    index: cond_idx,
                                    condition: block.clone(),
                                    if_body: false_block.clone(),
                                    else_body: None,
                                    negated: true,
                                    incoming: Vec::new(),
                                    outgoing: Vec::new(),
                                    parent: None,
                                    flags: 0,
                                }));
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
            let list_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockList::new(
                    block.read().unwrap().get_index(),
                    vec![block.clone(), succ.clone()],
                )));

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
            if b.size_out() != 2 { continue; }

            // Check if this block ends with CBRANCH
            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch { continue; }

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
