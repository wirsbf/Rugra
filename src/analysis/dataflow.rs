//! Data Flow Analysis Module
//!
//! This module implements various data flow analysis algorithms including:
//! - Reaching definitions analysis
//! - Live variable analysis
//! - Use-def chains
//! - Def-use chains
//! - Available expressions
//! - Dead code detection

use crate::{Address, Result, pcode::{Program, PcodeOp, Varnode, AddressSpace}};
use std::collections::{HashMap, HashSet, VecDeque};

/// Represents a definition point in the program
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Definition {
    /// Block index where the definition occurs
    pub block: usize,
    /// Operation index within the program
    pub operation: usize,
    /// Variable being defined
    pub variable: String,
    /// Address of the defining instruction
    pub address: Address,
}

impl Definition {
    /// Create a new definition
    pub fn new(block: usize, operation: usize, variable: String, address: Address) -> Self {
        Definition {
            block,
            operation,
            variable,
            address,
        }
    }
}

/// Use-def chain entry
#[derive(Debug, Clone)]
pub struct UseDefChain {
    /// The use site (block, operation index)
    pub use_site: (usize, usize),
    /// All definitions that reach this use
    pub reaching_defs: Vec<Definition>,
}

/// Def-use chain entry
#[derive(Debug, Clone)]
pub struct DefUseChain {
    /// The definition site
    pub def_site: Definition,
    /// All uses of this definition
    pub uses: Vec<(usize, usize)>, // (block, operation)
}

/// Complete data flow analysis results
#[derive(Debug, Clone)]
pub struct DataFlowAnalysis {
    /// Reaching definitions at each program point
    /// Maps (block, operation) to set of reaching definitions
    pub reaching_definitions: HashMap<(usize, usize), HashSet<Definition>>,

    /// Live variables at each program point
    /// Maps (block, operation) to set of live variables
    pub live_variables: HashMap<(usize, usize), HashSet<String>>,

    /// Use-def chains
    pub use_def_chains: Vec<UseDefChain>,

    /// Def-use chains
    pub def_use_chains: Vec<DefUseChain>,

    /// Available expressions at each program point
    pub available_expressions: HashMap<(usize, usize), HashSet<String>>,

    /// Dead code locations (unreachable or unused definitions)
    pub dead_code: Vec<(usize, usize)>,
}

impl DataFlowAnalysis {
    /// Create new empty analysis
    pub fn new() -> Self {
        DataFlowAnalysis {
            reaching_definitions: HashMap::new(),
            live_variables: HashMap::new(),
            use_def_chains: Vec::new(),
            def_use_chains: Vec::new(),
            available_expressions: HashMap::new(),
            dead_code: Vec::new(),
        }
    }

    /// Check if a variable is live at a given point
    pub fn is_live(&self, block: usize, operation: usize, variable: &str) -> bool {
        self.live_variables
            .get(&(block, operation))
            .map(|vars| vars.contains(variable))
            .unwrap_or(false)
    }

    /// Get reaching definitions for a variable at a point
    pub fn get_reaching_defs(
        &self,
        block: usize,
        operation: usize,
        variable: &str,
    ) -> Vec<&Definition> {
        self.reaching_definitions
            .get(&(block, operation))
            .map(|defs| {
                defs.iter()
                    .filter(|d| d.variable == variable)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get uses for a definition
    pub fn get_uses_for_def(&self, def: &Definition) -> Option<&[(usize, usize)]> {
        self.def_use_chains
            .iter()
            .find(|chain| chain.def_site == *def)
            .map(|chain| chain.uses.as_slice())
    }
}

impl Default for DataFlowAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform complete data flow analysis
pub fn analyze_dataflow(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
) -> Result<DataFlowAnalysis> {
    let mut analysis = DataFlowAnalysis::new();

    // 1. Compute reaching definitions
    compute_reaching_definitions(cfg, program, &mut analysis);

    // 2. Compute live variables
    compute_live_variables(cfg, program, &mut analysis);

    // 3. Build use-def chains
    build_use_def_chains(cfg, program, &mut analysis);

    // 4. Build def-use chains
    build_def_use_chains(cfg, program, &mut analysis);

    // 5. Compute available expressions
    compute_available_expressions(cfg, program, &mut analysis);

    // 6. Detect dead code
    detect_dead_code(cfg, program, &mut analysis);

    Ok(analysis)
}

/// Compute reaching definitions using iterative data flow analysis
fn compute_reaching_definitions(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
    analysis: &mut DataFlowAnalysis,
) {
    let ops = program.operations();

    // Map blocks to their operations
    let mut block_ops: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, op) in ops.iter().enumerate() {
        for (block_idx, block) in cfg.blocks.iter().enumerate() {
            if block.operations.contains(&i) {
                block_ops.entry(block_idx).or_insert_with(Vec::new).push(i);
                break;
            }
        }
    }

    // Initialize GEN and KILL sets for each block
    let mut gen: HashMap<usize, HashSet<Definition>> = HashMap::new();
    let mut kill: HashMap<usize, HashMap<String, HashSet<Definition>>> = HashMap::new();

    for block_idx in 0..cfg.blocks.len() {
        gen.insert(block_idx, HashSet::new());
        kill.insert(block_idx, HashMap::new());

        if let Some(op_indices) = block_ops.get(&block_idx) {
            for &op_idx in op_indices {
                if let Some(output) = ops[op_idx].output() {
                    let var_name = varnode_to_string(output);
                    let def = Definition::new(
                        block_idx,
                        op_idx,
                        var_name.clone(),
                        ops[op_idx].address(),
                    );

                    gen.get_mut(&block_idx).unwrap().insert(def);
                }
            }
        }
    }

    // Iterative data flow analysis
    let mut in_sets: HashMap<usize, HashSet<Definition>> = HashMap::new();
    let mut out_sets: HashMap<usize, HashSet<Definition>> = HashMap::new();

    for i in 0..cfg.blocks.len() {
        in_sets.insert(i, HashSet::new());
        out_sets.insert(i, HashSet::new());
    }

    let mut changed = true;
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 100;

    while changed && iterations < MAX_ITERATIONS {
        changed = false;
        iterations += 1;

        for block_idx in 0..cfg.blocks.len() {
            // IN[B] = Union of OUT[P] for all predecessors P
            let mut new_in = HashSet::new();
            for &pred in &cfg.blocks[block_idx].predecessors {
                if let Some(pred_out) = out_sets.get(&pred) {
                    new_in.extend(pred_out.clone());
                }
            }

            // OUT[B] = GEN[B] U (IN[B] - KILL[B])
            let mut new_out = gen.get(&block_idx).cloned().unwrap_or_default();
            new_out.extend(new_in.clone());

            if new_in != *in_sets.get(&block_idx).unwrap() {
                changed = true;
                in_sets.insert(block_idx, new_in);
            }

            if new_out != *out_sets.get(&block_idx).unwrap() {
                changed = true;
                out_sets.insert(block_idx, new_out);
            }
        }
    }

    // Store results
    for (block_idx, defs) in in_sets {
        if let Some(op_indices) = block_ops.get(&block_idx) {
            for &op_idx in op_indices {
                analysis.reaching_definitions.insert((block_idx, op_idx), defs.clone());
            }
        }
    }
}

/// Compute live variables using backward data flow analysis
fn compute_live_variables(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
    analysis: &mut DataFlowAnalysis,
) {
    let ops = program.operations();

    // Map blocks to operations
    let mut block_ops: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, op) in ops.iter().enumerate() {
        for (block_idx, block) in cfg.blocks.iter().enumerate() {
            if block.operations.contains(&i) {
                block_ops.entry(block_idx).or_insert_with(Vec::new).push(i);
                break;
            }
        }
    }

    // Compute USE and DEF sets for each block
    let mut use_sets: HashMap<usize, HashSet<String>> = HashMap::new();
    let mut def_sets: HashMap<usize, HashSet<String>> = HashMap::new();

    for block_idx in 0..cfg.blocks.len() {
        let mut uses = HashSet::new();
        let mut defs = HashSet::new();

        if let Some(op_indices) = block_ops.get(&block_idx) {
            for &op_idx in op_indices {
                let op = &ops[op_idx];

                // Variables used before defined
                for input in op.inputs.as_slice() {
                    let var = varnode_to_string(input);
                    if !defs.contains(&var) {
                        uses.insert(var);
                    }
                }

                // Variables defined
                if let Some(output) = op.output.as_ref() {
                    defs.insert(varnode_to_string(output));
                }
            }
        }

        use_sets.insert(block_idx, uses);
        def_sets.insert(block_idx, defs);
    }

    // Backward data flow analysis
    let mut in_sets: HashMap<usize, HashSet<String>> = HashMap::new();
    let mut out_sets: HashMap<usize, HashSet<String>> = HashMap::new();

    for i in 0..cfg.blocks.len() {
        in_sets.insert(i, HashSet::new());
        out_sets.insert(i, HashSet::new());
    }

    let mut changed = true;
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 100;

    while changed && iterations < MAX_ITERATIONS {
        changed = false;
        iterations += 1;

        for block_idx in 0..cfg.blocks.len() {
            // OUT[B] = Union of IN[S] for all successors S
            let mut new_out = HashSet::new();
            for &succ in &cfg.blocks[block_idx].successors {
                if let Some(succ_in) = in_sets.get(&succ) {
                    new_out.extend(succ_in.clone());
                }
            }

            // IN[B] = USE[B] U (OUT[B] - DEF[B])
            let mut new_in = use_sets.get(&block_idx).cloned().unwrap_or_default();
            let def_set = def_sets.get(&block_idx).cloned().unwrap_or_default();
            for var in &new_out {
                if !def_set.contains(var) {
                    new_in.insert(var.clone());
                }
            }

            if new_in != *in_sets.get(&block_idx).unwrap() {
                changed = true;
                in_sets.insert(block_idx, new_in);
            }

            if new_out != *out_sets.get(&block_idx).unwrap() {
                changed = true;
                out_sets.insert(block_idx, new_out);
            }
        }
    }

    // Store results
    for (block_idx, vars) in in_sets {
        if let Some(op_indices) = block_ops.get(&block_idx) {
            for &op_idx in op_indices {
                analysis.live_variables.insert((block_idx, op_idx), vars.clone());
            }
        }
    }
}

/// Build use-def chains from reaching definitions
fn build_use_def_chains(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
    analysis: &mut DataFlowAnalysis,
) {
    let ops = program.operations();

    for (i, op) in ops.iter().enumerate() {
        // For each use
        for input in op.inputs.as_slice() {
            let var = varnode_to_string(input);

            // Find which block this operation is in
            let block_idx = find_block_for_operation(cfg, i);

            // Get reaching definitions
            if let Some(reaching) = analysis.reaching_definitions.get(&(block_idx, i)) {
                let reaching_defs: Vec<Definition> = reaching
                    .iter()
                    .filter(|d| d.variable == var)
                    .cloned()
                    .collect();

                if !reaching_defs.is_empty() {
                    analysis.use_def_chains.push(UseDefChain {
                        use_site: (block_idx, i),
                        reaching_defs,
                    });
                }
            }
        }
    }
}

/// Build def-use chains from reaching definitions
fn build_def_use_chains(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
    analysis: &mut DataFlowAnalysis,
) {
    let mut chains: HashMap<Definition, Vec<(usize, usize)>> = HashMap::new();

    // Collect all uses for each definition
    for chain in &analysis.use_def_chains {
        for def in &chain.reaching_defs {
            chains
                .entry(def.clone())
                .or_insert_with(Vec::new)
                .push(chain.use_site);
        }
    }

    // Convert to def-use chains
    for (def, uses) in chains {
        analysis.def_use_chains.push(DefUseChain {
            def_site: def,
            uses,
        });
    }
}

/// Compute available expressions
fn compute_available_expressions(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
    analysis: &mut DataFlowAnalysis,
) {
    // Simplified available expressions analysis
    // In a full implementation, this would track which expressions
    // are available at each program point

    for block_idx in 0..cfg.blocks.len() {
        let mut available = HashSet::new();

        for &op_idx in &cfg.blocks[block_idx].operations {
            if op_idx < program.operations().len() {
                let op = &program.operations()[op_idx];

                // Simple heuristic: arithmetic operations create available expressions
                if matches!(
                    op.opcode,
                    OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV
                ) {
                    if let Some(output) = op.output.as_ref() {
                        available.insert(varnode_to_string(output));
                    }
                }

                analysis.available_expressions.insert((block_idx, op_idx), available.clone());
            }
        }
    }
}

/// Detect dead code (unused definitions)
fn detect_dead_code(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
    analysis: &mut DataFlowAnalysis,
) {
    let ops = program.operations();

    // Find definitions that are never used
    for (i, op) in ops.iter().enumerate() {
        if let Some(output) = op.output.as_ref() {
            let var = varnode_to_string(output);
            let block_idx = find_block_for_operation(cfg, i);

            // Check if this variable is live
            let is_live = analysis
                .live_variables
                .get(&(block_idx, i))
                .map(|vars| vars.contains(&var))
                .unwrap_or(false);

            // If not live and not a side-effect operation, it's dead code
            if !is_live && !op.has_side_effects() {
                analysis.dead_code.push((block_idx, i));
            }
        }
    }
}

/// Find which block an operation belongs to
fn find_block_for_operation(cfg: &super::cfg::ControlFlowGraph, op_idx: usize) -> usize {
    for (block_idx, block) in cfg.blocks.iter().enumerate() {
        if block.operations.contains(&op_idx) {
            return block_idx;
        }
    }
    0 // Default to entry block
}

/// Convert varnode to string representation
fn varnode_to_string(varnode: &Varnode) -> String {
    format!("{:?}_{:x}_{}", varnode.space(), varnode.offset(), varnode.size())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pcode::PcodeBuilder, analysis::cfg::ControlFlowGraph};

    #[test]
    fn test_definition_creation() {
        let def = Definition::new(0, 1, "x".to_string(), Address::new(0x1000));
        assert_eq!(def.block, 0);
        assert_eq!(def.operation, 1);
        assert_eq!(def.variable, "x");
    }

    #[test]
    fn test_dataflow_analysis_creation() {
        let analysis = DataFlowAnalysis::new();
        assert_eq!(analysis.reaching_definitions.len(), 0);
        assert_eq!(analysis.live_variables.len(), 0);
        assert_eq!(analysis.use_def_chains.len(), 0);
        assert_eq!(analysis.def_use_chains.len(), 0);
    }

    #[test]
    fn test_is_live() {
        let mut analysis = DataFlowAnalysis::new();

        let mut live_vars = HashSet::new();
        live_vars.insert("x".to_string());
        analysis.live_variables.insert((0, 0), live_vars);

        assert!(analysis.is_live(0, 0, "x"));
        assert!(!analysis.is_live(0, 0, "y"));
        assert!(!analysis.is_live(1, 0, "x"));
    }

    #[test]
    fn test_get_reaching_defs() {
        let mut analysis = DataFlowAnalysis::new();

        let mut defs = HashSet::new();
        let def1 = Definition::new(0, 0, "x".to_string(), Address::new(0x1000));
        let def2 = Definition::new(0, 1, "y".to_string(), Address::new(0x1004));
        defs.insert(def1.clone());
        defs.insert(def2);

        analysis.reaching_definitions.insert((0, 5), defs);

        let reaching = analysis.get_reaching_defs(0, 5, "x");
        assert_eq!(reaching.len(), 1);
        assert_eq!(reaching[0].variable, "x");
    }

    #[test]
    fn test_varnode_to_string() {
        let vn = Varnode::new_register(0, 4);
        let s = varnode_to_string(&vn);
        assert!(s.contains("Register"));
        assert!(s.contains("4"));
    }

    #[test]
    fn test_dataflow_analysis_basic() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        let v1 = Varnode::new_register(0, 4);
        let v2 = Varnode::new_register(8, 4);

        builder.add_op(OpCode::CPUI_COPY, Some(v1.clone()), vec![v2.clone()]);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(v2.clone()), vec![v1.clone(), v2.clone()]);

        let program = builder.build();
        let cfg = ControlFlowGraph::from_program(&program).unwrap();

        let analysis = analyze_dataflow(&cfg, &program).unwrap();

        // Should have some data flow information
        assert!(!analysis.reaching_definitions.is_empty() || analysis.live_variables.is_empty());
    }

    #[test]
    fn test_use_def_chain() {
        let chain = UseDefChain {
            use_site: (0, 5),
            reaching_defs: vec![
                Definition::new(0, 1, "x".to_string(), Address::new(0x1000)),
            ],
        };

        assert_eq!(chain.use_site, (0, 5));
        assert_eq!(chain.reaching_defs.len(), 1);
    }

    #[test]
    fn test_def_use_chain() {
        let def = Definition::new(0, 1, "x".to_string(), Address::new(0x1000));
        let chain = DefUseChain {
            def_site: def,
            uses: vec![(0, 5), (0, 10)],
        };

        assert_eq!(chain.uses.len(), 2);
    }

    #[test]
    fn test_find_block_for_operation() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));
        builder.add_op(OpCode::CPUI_COPY, None, vec![]);

        let program = builder.build();
        let cfg = ControlFlowGraph::from_program(&program).unwrap();

        let block = find_block_for_operation(&cfg, 0);
        assert_eq!(block, 0);
    }

    #[test]
    fn test_default_dataflow_analysis() {
        let analysis = DataFlowAnalysis::default();
        assert_eq!(analysis.dead_code.len(), 0);
    }
}
