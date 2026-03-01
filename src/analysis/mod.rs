//! Analysis module for decompilation
//!
//! This module contains various analysis algorithms used during decompilation:
//! - Control flow analysis (CFG construction, loop detection)
//! - Data flow analysis (use-def chains, reaching definitions)
//! - SSA construction (dominance frontiers, phi placement)
//! - Type inference (constraint-based type recovery)
//! - Variable recovery (stack variables, register allocation)

use crate::{Result, pcode::Program};

// Sub-modules
pub mod variables;
pub mod type_inference;
pub mod ssa;
pub mod optimization;
pub mod rules;
pub mod high_variable;
pub mod liveness;
pub mod type_propagation;
pub mod api;
pub mod calls;

// Sub-modules are defined inline below

/// Results of analyzing a function
#[derive(Debug, Clone)]
pub struct FunctionAnalysis {
    /// Control flow graph
    pub cfg: Option<cfg::ControlFlowGraph>,

    /// Data flow information
    pub dataflow: Option<dataflow::DataFlowInfo>,

    /// SSA form (if constructed)
    pub ssa: Option<ssa::SSAForm>,

    /// Type information
    pub type_info: Option<types::TypeInfo>,

    /// Variable recovery analysis
    pub variables: Option<variables::VariableAnalysis>,

    /// High variables (merged SSA variables)
    pub high_variables: Option<high_variable::HighVariableMap>,

    /// Constraint-based type propagation solver
    pub type_solver: Option<type_propagation::TypeSolver>,

    /// Type inference analysis
    pub type_inference: Option<type_inference::TypeInferenceAnalysis>,

    /// Liveness analysis (for variable merging)
    pub liveness: Option<liveness::LivenessAnalysis>,
}

impl FunctionAnalysis {
    /// Create a new empty analysis
    pub fn new() -> Self {
        FunctionAnalysis {
            cfg: None,
            dataflow: None,
            ssa: None,
            type_info: None,
            variables: None,
            high_variables: None,
            type_solver: None,
            type_inference: None,
            liveness: None,
        }
    }
}

impl Default for FunctionAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyze a P-code program
///
/// This is the main entry point for analysis. It performs:
/// 1. Control flow graph construction
/// 2. Data flow analysis
/// 3. SSA construction (optional)
/// 4. Type inference (optional)
///
/// # Arguments
///
/// * `program` - The P-code program to analyze
/// * `binary` - Optional reference to the binary (for symbol resolution)
///
/// # Returns
///
/// Analysis results
pub fn analyze_function(program: &mut Program, binary: Option<&crate::binary::Binary>) -> Result<FunctionAnalysis> {
    eprintln!("    [Analysis] Start: {} ops", program.operation_count());
    let mut analysis = FunctionAnalysis::new();

    // 1. CFG Construction
    eprintln!("    [Analysis] 1. CFG Construction...");
    let cfg = cfg::ControlFlowGraph::from_program(program)?;
    eprintln!("    [Analysis]    Blocks: {}", cfg.blocks.len());
    analysis.cfg = Some(cfg);

    // 2. Variable Recovery
    eprintln!("    [Analysis] 2. Variable Recovery...");
    let cfg_ref = analysis.cfg.as_ref().unwrap();
    let mut var_analysis = variables::recover_variables(program, cfg_ref)?;
    variables::analyze_variable_lifetimes(program, &mut var_analysis)?;
    analysis.variables = Some(var_analysis);

    // 2.5. Call Semantics Recovery (Arguments & Return Values)
    eprintln!("    [Analysis] 2.5. Call Semantics Recovery...");
    calls::recover_call_semantics(program);

    // 3. Type Inference
    eprintln!("    [Analysis] 3. Type Inference...");
    let type_analysis = type_inference::infer_types(program)?;
    analysis.type_inference = Some(type_analysis);

    // 4. SSA Form Construction (optional)
    eprintln!("    [Analysis] 4. SSA Construction...");
    if let Some(ref cfg) = analysis.cfg {
        match ssa::construct_ssa(cfg, program) {
            Ok(ssa_form) => {
                analysis.ssa = Some(ssa_form);
            }
            Err(e) => {
                // SSA construction is optional, log error but continue
                eprintln!("Warning: SSA construction failed: {}", e);
            }
        }
    }

    // 4.5. Liveness Analysis
    eprintln!("    [Analysis] 4.5. Liveness Analysis...");
    if let (Some(cfg), Some(ssa)) = (&analysis.cfg, &analysis.ssa) {
        let liveness = liveness::compute_liveness(program, cfg, ssa);
        analysis.liveness = Some(liveness);
    }

    // 5. High Variable Construction
    if let (Some(cfg), Some(ssa), Some(var_analysis)) = (&analysis.cfg, &analysis.ssa, &analysis.variables) {
        let liveness = analysis.liveness.as_ref();
        let high_vars = high_variable::construct_high_variables(program, cfg, ssa, var_analysis, liveness);
        analysis.high_variables = Some(high_vars);
    }

    // 6. Type Propagation (Phase 9)
    if let Some(ssa) = &analysis.ssa {
        let mut solver = type_propagation::TypeSolver::new();
        // Use variable analysis hints if available
        let var_analysis = analysis.variables.as_ref();
        solver.solve(program, ssa, var_analysis, binary);

        // Finalize discovered structs
        let mut type_info = types::TypeInfo::new();
        for (struct_name, fields) in &solver.discovered_fields {
            let mut def = crate::types::StructDef::new(struct_name.clone());
            for (&offset, data_type) in fields {
                def.add_field(format!("field_{:x}", offset), data_type.clone(), offset as usize);
            }
            type_info.structs.insert(struct_name.clone(), def);
        }

        analysis.type_info = Some(type_info);
        analysis.type_solver = Some(solver);
    }

    // Phase 8: Optimization
    eprintln!("    [Analysis] 8. Optimization...");
    optimization::optimize_function(program, &analysis);

    eprintln!("    [Analysis] Done.");
    Ok(analysis)
}

/// Control flow graph module
pub mod cfg {
    use crate::{Address, Result, pcode::{Program, PcodeOp}};
    use std::collections::{HashMap, HashSet};

    /// A basic block in the control flow graph
    #[derive(Debug, Clone)]
    pub struct BasicBlock {
        /// Unique index of this block
        pub index: usize,
        /// Indices of operations in the program
        pub operations: Vec<usize>,
        /// Starting address
        pub start_addr: Address,
        /// Ending address
        pub end_addr: Address,
        /// Successor blocks indices
        pub successors: Vec<usize>,
        /// Predecessor blocks indices
        pub predecessors: Vec<usize>,
    }

    /// Control flow graph
    #[derive(Debug, Clone)]
    pub struct ControlFlowGraph {
        /// All basic blocks
        pub blocks: Vec<BasicBlock>,
        /// Entry block index
        pub entry: usize,
        /// Exit block indices
        pub exits: Vec<usize>,
    }

    impl ControlFlowGraph {
        /// Create a new empty CFG
        pub fn new() -> Self {
            ControlFlowGraph {
                blocks: Vec::new(),
                entry: 0,
                exits: Vec::new(),
            }
        }

        /// Compute dominators for the CFG
        pub fn compute_dominators(&self) -> HashMap<usize, usize> {
            eprintln!("    [CFG] Computing dominators for {} blocks...", self.blocks.len());
            let mut dominators = HashMap::new();
            if self.blocks.is_empty() {
                return dominators;
            }

            // Entry block dominates itself
            dominators.insert(self.entry, self.entry);

            // Initialize all other blocks to be dominated by all blocks
            let mut changed = true;
            let mut iterations = 0;
            const MAX_DOM_ITERATIONS: usize = 5000;

            while changed {
                iterations += 1;
                if iterations > MAX_DOM_ITERATIONS {
                    eprintln!("    [CFG] Warning: Dominator computation limit exceeded");
                    break;
                }

                changed = false;
                for i in 0..self.blocks.len() {
                    if i == self.entry {
                        continue;
                    }

                    let block = &self.blocks[i];
                    if block.predecessors.is_empty() {
                        continue;
                    }

                    // Find common dominator of all processed predecessors
                    let mut new_dom = Option::<usize>::None;

                    for &pred in &block.predecessors {
                        if dominators.contains_key(&pred) {
                            if let Some(curr) = new_dom {
                                new_dom = Some(self.common_dominator(curr, pred, &dominators));
                            } else {
                                new_dom = Some(pred);
                            }
                        }
                    }

                    if let Some(new_dom_val) = new_dom {
                        if dominators.get(&i) != Some(&new_dom_val) {
                            dominators.insert(i, new_dom_val);
                            changed = true;
                        }
                    }
                }
            }

            eprintln!("    [CFG] Dominators computed in {} iterations", iterations);
            dominators
        }

        /// Find common dominator of two blocks
        fn common_dominator(&self, a: usize, b: usize, dominators: &HashMap<usize, usize>) -> usize {
            let mut path_a = std::collections::HashSet::new();
            let mut current = a;
            let mut steps = 0;
            const MAX_STEPS: usize = 10000;

            loop {
                path_a.insert(current);
                steps += 1;
                if steps > MAX_STEPS { return self.entry; }

                if let Some(&dom) = dominators.get(&current) {
                    if dom == current { break; }
                    current = dom;
                } else {
                    break;
                }
            }

            current = b;
            steps = 0;
            loop {
                if path_a.contains(&current) {
                    return current;
                }
                steps += 1;
                if steps > MAX_STEPS { return self.entry; }

                if let Some(&dom) = dominators.get(&current) {
                    if dom == current { break; }
                    current = dom;
                } else {
                    break;
                }
            }

            self.entry
        }

        /// Detect natural loops in the CFG
        pub fn detect_loops(&self) -> Vec<Loop> {
            let dominators = self.compute_dominators();
            let mut loops = Vec::new();

            // Find back edges (edges where target dominates source)
            for (i, block) in self.blocks.iter().enumerate() {
                for &succ in &block.successors {
                    if dominators.get(&i) == Some(&succ) || succ == i {
                        // This is a back edge - succ is the loop header
                        let mut loop_info = self.find_loop_body(succ, i, &dominators);

                        // Determine loop type
                        let header_block = &self.blocks[loop_info.header];
                        let latch_block = &self.blocks[loop_info.back_edge_source];

                        if header_block.successors.len() == 2 {
                            loop_info.loop_type = LoopType::While;

                            // Check for for-loop pattern: While loop with a distinct latch block
                            // that acts as an increment step.
                            // Heuristic: Latch block has only 1 successor (header) and isn't the header itself.
                            if loop_info.back_edge_source != loop_info.header && latch_block.successors.len() == 1 {
                                loop_info.loop_type = LoopType::For;
                                loop_info.increment = Some(loop_info.back_edge_source);
                            }
                        } else if latch_block.successors.len() == 2 {
                            loop_info.loop_type = LoopType::DoWhile;
                        } else {
                            loop_info.loop_type = LoopType::Infinite;
                        }

                        loops.push(loop_info);
                    }
                }
            }

            loops
        }

        /// Find all blocks in a loop given a back edge
        fn find_loop_body(&self, header: usize, back_edge_source: usize, _dominators: &HashMap<usize, usize>) -> Loop {
            let mut body = vec![header];
            let mut worklist = vec![back_edge_source];
            let mut visited = std::collections::HashSet::new();
            visited.insert(header);

            while let Some(block) = worklist.pop() {
                if visited.contains(&block) {
                    continue;
                }
                visited.insert(block);
                body.push(block);

                // Add predecessors to worklist
                for &pred in &self.blocks[block].predecessors {
                    if !visited.contains(&pred) {
                        worklist.push(pred);
                    }
                }
            }

            Loop {
                header,
                body,
                back_edge_source,
                increment: None,
                loop_type: LoopType::While, // Default
            }
        }

        /// Identify if/else patterns in the CFG
        pub fn identify_conditionals(&self) -> Vec<Conditional> {
            let mut conditionals = Vec::new();
            let _dominators = self.compute_dominators();

            for (i, block) in self.blocks.iter().enumerate() {
                // Look for blocks with exactly 2 successors (conditional branch)
                if block.successors.len() == 2 {
                    let succ0 = block.successors[0];
                    let succ1 = block.successors[1];

                    // Find post-dominator (where paths merge)
                    let post_dom = self.find_merge_point(succ0, succ1);

                    conditionals.push(Conditional {
                        condition_block: i,
                        true_branch: succ0,
                        false_branch: succ1,
                        merge_point: post_dom,
                    });
                }
            }

            conditionals
        }

        pub fn identify_switches(&self, program: &Program) -> Vec<Switch> {
            let mut switches = Vec::new();
            let mut visited = HashSet::new();

            for (i, block) in self.blocks.iter().enumerate() {
                if visited.contains(&i) {
                    continue;
                }

                // 1. Indirect branch switches (Jump Tables)
                if block.successors.len() > 2 {
                    visited.insert(i);
                    let mut cases = Vec::new();
                    for (idx, &succ) in block.successors.iter().enumerate() {
                        cases.push((idx as u64, succ));
                    }
                    switches.push(Switch {
                        header: i,
                        cases,
                        default: None,
                        merge_point: None,
                    });
                    continue;
                }

                // 2. Cascaded If-Else (Switch) recovery
                // Look for patterns: if (var == C1) ... else if (var == C2) ...
                if let Some((var_key, val)) = self.detect_switch_condition(program, i) {
                    let mut current_block = i;
                    let mut current_cases = Vec::new();
                    let mut chain_blocks = HashSet::new();
                    let mut default_target = None;
                    let switch_var = var_key;

                    // Traverse the chain
                    loop {
                        if visited.contains(&current_block) {
                            break;
                        }

                        if let Some((var, val)) = self.detect_switch_condition(program, current_block) {
                            if var != switch_var {
                                // Different variable, chain breaks
                                default_target = Some(current_block);
                                break;
                            }

                            visited.insert(current_block);
                            chain_blocks.insert(current_block);

                            // In CBranch: successors[0] is TRUE target, successors[1] is FALSE target (fallthrough)
                            if self.blocks[current_block].successors.len() == 2 {
                                let true_target = self.blocks[current_block].successors[0];
                                let false_target = self.blocks[current_block].successors[1];

                                current_cases.push((val, true_target));
                                current_block = false_target;
                            } else {
                                break;
                            }
                        } else {
                            // End of chain (Default case)
                            default_target = Some(current_block);
                            break;
                        }
                    }

                    if current_cases.len() >= 3 {
                        // Find common merge point
                        let merge = self.find_multi_merge_point(&current_cases, default_target);

                        switches.push(Switch {
                            header: i,
                            cases: current_cases,
                            default: default_target,
                            merge_point: merge,
                        });
                    } else {
                        // Not enough cases, remove from visited
                        for b in chain_blocks {
                            visited.remove(&b);
                        }
                    }
                }
            }

            switches
        }

        fn detect_switch_condition(&self, program: &Program, block_idx: usize) -> Option<(String, u64)> {
            if self.blocks[block_idx].successors.len() != 2 {
                return None;
            }

            let block = &self.blocks[block_idx];
            let ops = program.operations();

            // Find CBranch
            for &op_idx in block.operations.iter().rev() {
                if op_idx >= ops.len() { continue; }
                let op = &ops[op_idx];
                if op.opcode == OpCode::CPUI_CBRANCH {
                    // Check condition input
                    if let Some(cond) = op.inputs.as_slice().get(1) {
                        // Find definition of condition in this block
                        // Search backwards
                        if cond.is_unique() || cond.is_register() {
                             for &def_op_idx in block.operations.iter().rev() {
                                if def_op_idx >= ops.len() { continue; }
                                let def_op = &ops[def_op_idx];
                                if let Some(out) = def_op.output.as_ref() {
                                    if out == cond {
                                        // Found definition. Is it INT_EQUAL?
                                        if def_op.opcode == OpCode::CPUI_INT_EQUAL {
                                            let inputs = def_op.inputs.as_slice();
                                            if inputs.len() == 2 {
                                                if let Some(c) = inputs[1].constant_value() {
                                                    let var_key = format!("{:?}_{:x}_{}", inputs[0].space(), inputs[0].offset(), inputs[0].size());
                                                    return Some((var_key, c));
                                                } else if let Some(c) = inputs[0].constant_value() {
                                                    let var_key = format!("{:?}_{:x}_{}", inputs[1].space(), inputs[1].offset(), inputs[1].size());
                                                    return Some((var_key, c));
                                                }
                                            }
                                        }
                                        break;
                                    }
                                }
                             }
                        }
                    }
                }
            }
            None
        }

        fn find_multi_merge_point(&self, cases: &[(u64, usize)], default: Option<usize>) -> Option<usize> {
            let mut targets = Vec::new();
            for (_, t) in cases {
                targets.push(*t);
            }
            if let Some(d) = default {
                targets.push(d);
            }

            if targets.is_empty() { return None; }

            let mut merge = targets[0];
            for &t in &targets[1..] {
                if let Some(m) = self.find_merge_point(merge, t) {
                    merge = m;
                } else {
                    return None;
                }
            }
            Some(merge)
        }

        /// Find where two paths merge (post-dominator)
        fn find_merge_point(&self, a: usize, b: usize) -> Option<usize> {
            // Simple heuristic: find common successor
            let a_successors = self.get_all_successors(a);
            let b_successors = self.get_all_successors(b);

            for &succ_a in &a_successors {
                if b_successors.contains(&succ_a) {
                    return Some(succ_a);
                }
            }

            None
        }

        /// Get all successors reachable from a block
        fn get_all_successors(&self, start: usize) -> Vec<usize> {
            let mut result = Vec::new();
            let mut visited = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(start);

            while let Some(node) = queue.pop_front() {
                if visited.contains(&node) {
                    continue;
                }
                visited.insert(node);
                result.push(node);

                for &succ in &self.blocks[node].successors {
                    if !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }

            result
        }

        /// Build a CFG from a P-code program
        pub fn from_program(program: &Program) -> Result<Self> {
            if program.is_empty() {
                return Ok(Self::new());
            }

            let ops = program.operations();
            let mut leaders = HashSet::new();
            leaders.insert(0); // First op is always a leader

            // 1. Identify leaders
            for (i, op) in ops.iter().enumerate() {
                match op.opcode {
                    OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHInd => {
                        // Target of the branch is a leader
                        if let Some(target_vn) = op.inputs.as_slice().get(0) {
                            if target_vn.space().is_const() {
                                // For P-code branches, the target is often an offset or absolute address
                                // In many P-code implementations, it might be a relative index or an address
                                // For now, we'll assume it's an index if it's in a specific range or handle it as address
                                // TODO: Handle different branch target types properly
                                let target_offset = target_vn.offset();

                                // Find operation with this address or index
                                // For this simplified implementation, we'll look for the address
                                let target_addr = Address::new(target_offset);
                                for (j, target_op) in ops.iter().enumerate() {
                                    if target_op.address() == target_addr && target_op.seqnum().order == 0 {
                                        leaders.insert(j);
                                        break;
                                    }
                                }
                            }
                        }
                        // Instruction after branch is a leader
                        if i + 1 < ops.len() {
                            leaders.insert(i + 1);
                        }
                    }
                    OpCode::CPUI_CALL | OpCode::CPUI_CALLInd | OpCode::CPUI_RETURN => {
                        // Instruction after call/return is a leader
                        if i + 1 < ops.len() {
                            leaders.insert(i + 1);
                        }
                    }
                    _ => {}
                }
            }

            // 2. Create blocks
            let mut sorted_leaders: Vec<usize> = leaders.into_iter().collect();
            sorted_leaders.sort();

            let mut blocks = Vec::new();
            let mut op_to_block = HashMap::new();

            for (i, &start_op_idx) in sorted_leaders.iter().enumerate() {
                let end_op_idx = if i + 1 < sorted_leaders.len() {
                    sorted_leaders[i + 1]
                } else {
                    ops.len()
                };

                let block_ops: Vec<usize> = (start_op_idx..end_op_idx).collect();
                for &op_idx in &block_ops {
                    op_to_block.insert(op_idx, i);
                }

                blocks.push(BasicBlock {
                    index: i,
                    start_addr: ops[start_op_idx].address(),
                    end_addr: ops[end_op_idx - 1].address(),
                    operations: block_ops,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                });
            }

            // 3. Connect blocks
            let mut exits = Vec::new();
            for i in 0..blocks.len() {
                let last_op_idx = *blocks[i].operations.last().unwrap();
                let last_op = &ops[last_op_idx];

                match last_op.opcode {
                    OpCode::CPUI_BRANCH => {
                        if let Some(target_vn) = last_op.inputs.as_slice().get(0) {
                            let target_addr = Address::new(target_vn.offset());
                            if let Some(target_idx) = ops.iter().position(|o| o.address() == target_addr && o.seqnum().order == 0) {
                                if let Some(&target_block_idx) = op_to_block.get(&target_idx) {
                                    blocks[i].successors.push(target_block_idx);
                                }
                            }
                        }
                    }
                    OpCode::CPUI_CBRANCH => {
                        // Conditional branch has two successors: target and next
                        if let Some(target_vn) = last_op.inputs.as_slice().get(0) {
                            let target_addr = Address::new(target_vn.offset());
                            if let Some(target_idx) = ops.iter().position(|o| o.address() == target_addr && o.seqnum().order == 0) {
                                if let Some(&target_block_idx) = op_to_block.get(&target_idx) {
                                    blocks[i].successors.push(target_block_idx);
                                }
                            }
                        }
                        if i + 1 < blocks.len() {
                            blocks[i].successors.push(i + 1);
                        }
                    }
                    OpCode::CPUI_RETURN | OpCode::CPUI_BRANCHInd => {
                        exits.push(i);
                    }
                    _ => {
                        // Fallthrough to next block
                        if i + 1 < blocks.len() {
                            blocks[i].successors.push(i + 1);
                        } else {
                            exits.push(i);
                        }
                    }
                }
            }

            // Fill predecessors
            let mut predecessors = vec![Vec::new(); blocks.len()];
            for (i, block) in blocks.iter().enumerate() {
                for &succ in &block.successors {
                    predecessors[succ].push(i);
                }
            }

            for i in 0..blocks.len() {
                blocks[i].predecessors = predecessors[i].clone();
            }

            Ok(ControlFlowGraph {
                blocks,
                entry: 0,
                exits,
            })
        }

        /// Get the number of blocks
        pub fn block_count(&self) -> usize {
            self.blocks.len()
        }

        /// Get the dominator tree as a string for debugging
        pub fn dominator_tree_string(&self) -> String {
            let dominators = self.compute_dominators();
            let mut result = String::new();
            result.push_str("Dominator Tree:\n");
            for i in 0..self.blocks.len() {
                if let Some(&dom) = dominators.get(&i) {
                    result.push_str(&format!("  Block {} dominated by Block {}\n", i, dom));
                }
            }
            result
        }
    }

    /// Information about a loop
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LoopType {
        While,
        DoWhile,
        For,
        Infinite,
    }

    #[derive(Debug, Clone)]
    pub struct Loop {
        /// Header block (loop entry point)
        pub header: usize,
        /// All blocks in the loop body
        pub body: Vec<usize>,
        /// Block with back edge to header
        pub back_edge_source: usize,
        /// Optional increment block (for for-loops)
        pub increment: Option<usize>,
        /// Type of the loop structure
        pub loop_type: LoopType,
    }

    #[derive(Debug, Clone)]
    pub struct Switch {
        pub header: usize,
        pub cases: Vec<(u64, usize)>,
        pub default: Option<usize>,
        pub merge_point: Option<usize>,
    }

    /// Information about a conditional (if/else)
    #[derive(Debug, Clone)]
    pub struct Conditional {
        /// Block containing the condition
        pub condition_block: usize,
        /// True branch target
        pub true_branch: usize,
        /// False branch target
        pub false_branch: usize,
        /// Where branches merge (if any)
        pub merge_point: Option<usize>,
    }

    impl Default for ControlFlowGraph {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Data flow analysis module
pub mod dataflow {
    use std::collections::HashMap;

    /// Data flow information
    #[derive(Debug, Clone)]
    pub struct DataFlowInfo {
        /// Use-def chains
        pub use_def: HashMap<usize, Vec<usize>>,
        /// Def-use chains
        pub def_use: HashMap<usize, Vec<usize>>,
    }

    impl DataFlowInfo {
        /// Create new data flow info
        pub fn new() -> Self {
            DataFlowInfo {
                use_def: HashMap::new(),
                def_use: HashMap::new(),
            }
        }
    }

    impl Default for DataFlowInfo {
        fn default() -> Self {
            Self::new()
        }
    }
}



/// Type inference module
pub mod types {
    use crate::types::{DataType, StructDef};
    use std::collections::HashMap;

    /// Type information for a program
    #[derive(Debug, Clone)]
    pub struct TypeInfo {
        /// Inferred types for varnodes
        pub varnode_types: HashMap<String, DataType>,
        /// Struct definitions
        pub structs: HashMap<String, StructDef>,
    }

    impl TypeInfo {
        /// Create new type info
        pub fn new() -> Self {
            TypeInfo {
                varnode_types: HashMap::new(),
                structs: HashMap::new(),
            }
        }
    }

    impl Default for TypeInfo {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::PcodeBuilder;
    use crate::Address;

    #[test]
    fn test_function_analysis_creation() {
        let analysis = FunctionAnalysis::new();
        assert!(analysis.cfg.is_none());
        assert!(analysis.dataflow.is_none());
    }

    #[test]
    fn test_cfg_creation() {
        let cfg = cfg::ControlFlowGraph::new();
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_cfg_construction_basic() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Block 0
        builder.add_op(crate::pcode::OpCode::CPUI_COPY, None, vec![]);

        // Block 1 (target of branch)
        builder.at_address(Address::new(0x1010));
        builder.add_op(crate::pcode::OpCode::CPUI_RETURN, None, vec![]);

        let program = builder.build();
        let cfg = cfg::ControlFlowGraph::from_program(&program).unwrap();

        assert_eq!(cfg.block_count(), 2);
        assert_eq!(cfg.blocks[0].successors, vec![1]);
        assert_eq!(cfg.blocks[1].predecessors, vec![0]);
    }

    #[test]
    fn test_cfg_construction_branch() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Block 0: Conditional branch
        let cond = crate::pcode::Varnode::new_register(0, 1);
        let target = crate::pcode::Varnode::new_constant(0x1020, 8);
        builder.add_op(crate::pcode::OpCode::CPUI_CBRANCH, None, vec![target, cond]);

        // Block 1: Fallthrough
        builder.at_address(Address::new(0x1010));
        builder.add_op(crate::pcode::OpCode::CPUI_RETURN, None, vec![]);

        // Block 2: Target
        builder.at_address(Address::new(0x1020));
        builder.add_op(crate::pcode::OpCode::CPUI_RETURN, None, vec![]);

        let program = builder.build();
        let cfg = cfg::ControlFlowGraph::from_program(&program).unwrap();

        assert_eq!(cfg.block_count(), 3);
        assert!(cfg.blocks[0].successors.contains(&1));
        assert!(cfg.blocks[0].successors.contains(&2));
    }

    #[test]
    fn test_dominator_computation() {
        use crate::pcode::PcodeBuilder;
        use crate::Address;

        // Build a simple CFG with 3 blocks
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Block 0
        builder.add_op(crate::pcode::OpCode::CPUI_COPY, None, vec![]);

        // Block 1
        builder.at_address(Address::new(0x1010));
        builder.add_op(crate::pcode::OpCode::CPUI_COPY, None, vec![]);

        // Block 2
        builder.at_address(Address::new(0x1020));
        builder.add_op(crate::pcode::OpCode::CPUI_RETURN, None, vec![]);

        let program = builder.build();
        let cfg = cfg::ControlFlowGraph::from_program(&program).unwrap();

        let dominators = cfg.compute_dominators();
        assert!(dominators.contains_key(&0));
        assert_eq!(dominators.get(&0), Some(&0)); // Entry dominates itself
    }

    #[test]
    fn test_loop_detection() {
        use crate::pcode::{PcodeBuilder, Varnode};
        use crate::Address;

        // Build a CFG with a loop
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Block 0: initialization
        builder.add_op(crate::pcode::OpCode::CPUI_COPY, None, vec![]);

        // Block 1: loop header (0x1010)
        builder.at_address(Address::new(0x1010));
        let cond = Varnode::new_register(0, 1);
        let target = Varnode::new_constant(0x1020, 8);
        builder.add_op(crate::pcode::OpCode::CPUI_CBRANCH, None, vec![target, cond]);

        // Block 2: loop body (0x1020)
        builder.at_address(Address::new(0x1020));
        let loop_target = Varnode::new_constant(0x1010, 8);
        builder.add_op(crate::pcode::OpCode::CPUI_BRANCH, None, vec![loop_target]);

        // Block 3: exit (0x1030)
        builder.at_address(Address::new(0x1030));
        builder.add_op(crate::pcode::OpCode::CPUI_RETURN, None, vec![]);

        let program = builder.build();
        let cfg = cfg::ControlFlowGraph::from_program(&program).unwrap();

        let loops = cfg.detect_loops();
        assert!(!loops.is_empty(), "Should detect at least one loop");
    }

    #[test]
    fn test_conditional_identification() {
        use crate::pcode::{PcodeBuilder, Varnode};
        use crate::Address;

        // Build a CFG with if/else
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Block 0: conditional
        let cond = Varnode::new_register(0, 1);
        let target = Varnode::new_constant(0x1020, 8);
        builder.add_op(crate::pcode::OpCode::CPUI_CBRANCH, None, vec![target, cond]);

        // Block 1: true branch
        builder.at_address(Address::new(0x1010));
        builder.add_op(crate::pcode::OpCode::CPUI_RETURN, None, vec![]);

        // Block 2: false branch
        builder.at_address(Address::new(0x1020));
        builder.add_op(crate::pcode::OpCode::CPUI_RETURN, None, vec![]);

        let program = builder.build();
        let cfg = cfg::ControlFlowGraph::from_program(&program).unwrap();

        let conditionals = cfg.identify_conditionals();
        assert!(!conditionals.is_empty(), "Should detect conditional");
        assert_eq!(conditionals[0].condition_block, 0);
    }
}
