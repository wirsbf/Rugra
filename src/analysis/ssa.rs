//! SSA (Static Single Assignment) Form Construction
//!
//! This module implements SSA form construction for P-code IR, including:
//! - Dominance frontier computation
//! - Phi node placement
//! - Variable renaming
//! - SSA destruction (converting back from SSA)

use crate::{Result, pcode::{Program, Varnode}};
use std::collections::{HashMap, HashSet, VecDeque};

/// A Phi node in SSA form
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhiNode {
    /// The variable being defined
    pub variable: String,
    /// Incoming values from predecessor blocks
    /// Maps block index to variable name
    pub inputs: HashMap<usize, String>,
    /// Output variable (SSA version)
    pub output: String,
}

impl PhiNode {
    /// Create a new phi node
    pub fn new(variable: String, output: String) -> Self {
        PhiNode {
            variable,
            inputs: HashMap::new(),
            output,
        }
    }

    /// Add an input from a predecessor block
    pub fn add_input(&mut self, block: usize, var: String) {
        self.inputs.insert(block, var);
    }

    /// Get the number of inputs
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

/// SSA variable with version number
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SSAVariable {
    /// Base variable name
    pub base_name: String,
    /// SSA version number
    pub version: usize,
}

impl SSAVariable {
    /// Create a new SSA variable
    pub fn new(base_name: String, version: usize) -> Self {
        SSAVariable { base_name, version }
    }

    /// Get the full SSA name (e.g., "x_1", "y_2")
    pub fn full_name(&self) -> String {
        format!("{}_{}", self.base_name, self.version)
    }
}

impl std::fmt::Display for SSAVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_name())
    }
}

/// SSA form representation
#[derive(Debug, Clone)]
pub struct SSAForm {
    /// Phi nodes at each block
    /// Maps block index to list of phi nodes
    pub phi_nodes: HashMap<usize, Vec<PhiNode>>,

    /// Variable versions
    /// Maps variable name to current version
    pub versions: HashMap<String, usize>,

    /// Definitions - where each SSA variable is defined
    /// Maps SSA variable name to block index
    pub definitions: HashMap<String, usize>,

    /// Uses - where each SSA variable is used
    /// Maps SSA variable name to list of block indices
    pub uses: HashMap<String, Vec<usize>>,
}

impl SSAForm {
    /// Create new empty SSA form
    pub fn new() -> Self {
        SSAForm {
            phi_nodes: HashMap::new(),
            versions: HashMap::new(),
            definitions: HashMap::new(),
            uses: HashMap::new(),
        }
    }

    /// Add a phi node to a block
    pub fn add_phi_node(&mut self, block: usize, phi: PhiNode) {
        self.phi_nodes.entry(block).or_insert_with(Vec::new).push(phi);
    }

    /// Get phi nodes for a block
    pub fn get_phi_nodes(&self, block: usize) -> Option<&Vec<PhiNode>> {
        self.phi_nodes.get(&block)
    }

    /// Get the next version for a variable
    pub fn next_version(&mut self, var: &str) -> usize {
        let version = self.versions.entry(var.to_string()).or_insert(0);
        *version += 1;
        *version
    }

    /// Get the current version for a variable
    pub fn current_version(&self, var: &str) -> Option<usize> {
        self.versions.get(var).copied()
    }

    /// Record a definition
    pub fn add_definition(&mut self, ssa_var: String, block: usize) {
        self.definitions.insert(ssa_var, block);
    }

    /// Record a use
    pub fn add_use(&mut self, ssa_var: String, block: usize) {
        self.uses.entry(ssa_var).or_insert_with(Vec::new).push(block);
    }
}

impl Default for SSAForm {
    fn default() -> Self {
        Self::new()
    }
}

/// Construct SSA form from a CFG
pub fn construct_ssa(
    cfg: &super::cfg::ControlFlowGraph,
    program: &mut Program,
) -> Result<SSAForm> {
    let mut ssa = SSAForm::new();

    // 1. Compute dominance frontiers
    eprintln!("    [SSA] Computing dominance frontiers...");
    let dom_frontiers = compute_dominance_frontiers(cfg);

    // 2. Identify variables
    eprintln!("    [SSA] Identifying variables...");
    let variables = identify_variables(program);
    eprintln!("    [SSA] Found {} variables", variables.len());

    // 3. Place phi nodes
    eprintln!("    [SSA] Placing phi nodes...");
    place_phi_nodes(cfg, program, &variables, &dom_frontiers, &mut ssa);
    eprintln!("    [SSA] Phi nodes placed.");

    // 4. Rename variables
    eprintln!("    [SSA] Renaming variables...");
    rename_variables(cfg, program, &mut ssa);
    eprintln!("    [SSA] Variables renamed.");

    Ok(ssa)
}

/// Compute dominance frontiers for all blocks
fn compute_dominance_frontiers(
    cfg: &super::cfg::ControlFlowGraph,
) -> HashMap<usize, HashSet<usize>> {
    let mut frontiers: HashMap<usize, HashSet<usize>> = HashMap::new();

    // Get dominators
    let dominators = cfg.compute_dominators();

    // For each block
    for b in 0..cfg.blocks.len() {
        frontiers.insert(b, HashSet::new());
    }

    // For each block Y
    for y in 0..cfg.blocks.len() {
        let preds = &cfg.blocks[y].predecessors;

        // If Y has multiple predecessors
        if preds.len() >= 2 {
            for &p in preds {
                let mut runner = p;
                let mut iterations = 0;
                const MAX_ITERATIONS: usize = 10000;

                // Walk up dominator tree
                while runner != *dominators.get(&y).unwrap_or(&y) {
                    iterations += 1;
                    if iterations > MAX_ITERATIONS {
                        eprintln!("    [SSA] Warning: Loop limit exceeded in dominance frontier computation for block {}", y);
                        break;
                    }

                    if let Some(frontier) = frontiers.get_mut(&runner) {
                        frontier.insert(y);
                    }

                    if let Some(&dom) = dominators.get(&runner) {
                        if dom == runner {
                            break;
                        }
                        runner = dom;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    frontiers
}

/// Identify all variables in the program
fn identify_variables(program: &Program) -> HashSet<String> {
    let mut variables = HashSet::new();

    for op in program.operations() {
        // Add output variable
        if let Some(output) = op.output() {
            variables.insert(varnode_to_var_name(output));
        }

        // Add input variables
        for input in op.inputs() {
            variables.insert(varnode_to_var_name(input));
        }
    }

    variables
}

/// Place phi nodes at appropriate blocks using Semi-Pruned SSA logic
fn place_phi_nodes(
    cfg: &super::cfg::ControlFlowGraph,
    program: &Program,
    variables: &HashSet<String>,
    dom_frontiers: &HashMap<usize, HashSet<usize>>,
    ssa: &mut SSAForm,
) {
    let mut globals: HashSet<String> = HashSet::new();
    let mut defs: HashMap<String, HashSet<usize>> = HashMap::new();

    let ops: &Vec<crate::pcode::PcodeOp> = program.operations();
    for (block_idx, block) in cfg.blocks.iter().enumerate() {
        let mut varkill = HashSet::new();
        for &op_idx in &block.operations {
            if op_idx >= ops.len() { continue; }
            let op = &ops[op_idx];

            for input in op.inputs() {
                let var_name = varnode_to_var_name(input);
                if !varkill.contains(&var_name) {
                    globals.insert(var_name);
                }
            }
            if let Some(output) = op.output() {
                let var_name = varnode_to_var_name(output);
                defs.entry(var_name.clone()).or_default().insert(block_idx);
                varkill.insert(var_name);
            }
        }
    }

    for var in variables {
        if !globals.contains(var) { continue; }

        let mut worklist: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
        let mut has_phi = HashSet::new();
        let mut def_blocks = HashSet::new();

        if let Some(blocks) = defs.get(var) {
            for &block in blocks {
                worklist.push_back(block);
                def_blocks.insert(block);
            }
        }

        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100000;

        while let Some(block) = worklist.pop_front() {
            iterations += 1;
            if iterations > MAX_ITERATIONS { break; }

            if let Some(frontier) = dom_frontiers.get(&block) {
                for &df_block in frontier {
                    if !has_phi.contains(&df_block) {
                        let phi = PhiNode::new(var.clone(), format!("{}_phi_{}", var, df_block));
                        ssa.add_phi_node(df_block, phi);
                        has_phi.insert(df_block);

                        if !def_blocks.contains(&df_block) {
                            worklist.push_back(df_block);
                            def_blocks.insert(df_block);
                        }
                    }
                }
            }
        }
    }
}

/// Rename variables to SSA form using Dominator Tree traversal
fn rename_variables(
    cfg: &super::cfg::ControlFlowGraph,
    program: &mut Program,
    ssa: &mut SSAForm,
) {
    if cfg.blocks.is_empty() {
        return;
    }

    // 1. Compute dominator tree children
    let dominators = cfg.compute_dominators();
    let mut dom_children: HashMap<usize, Vec<usize>> = HashMap::new();
    for (&node, &idom) in &dominators {
        if node != idom {
            dom_children.entry(idom).or_default().push(node);
        }
    }

    let mut stacks: HashMap<String, Vec<usize>> = HashMap::new();
    let mut visited = HashSet::new();

    // Start from entry block
    rename_block(cfg.entry, cfg, program, ssa, &mut stacks, &mut visited, &dom_children);
}

/// Rename variables in a block and its dominator tree children
fn rename_block(
    block_idx: usize,
    cfg: &super::cfg::ControlFlowGraph,
    program: &mut Program,
    ssa: &mut SSAForm,
    stacks: &mut HashMap<String, Vec<usize>>,
    visited: &mut HashSet<usize>,
    dom_children: &HashMap<usize, Vec<usize>>,
) {
    if visited.contains(&block_idx) {
        return;
    }
    visited.insert(block_idx);

    let mut pushed_vars = Vec::new();

    // 1. Process phi nodes definitions in this block
    if let Some(phis) = ssa.phi_nodes.get(&block_idx).cloned() {
        for phi in &phis {
            let version = ssa.next_version(&phi.variable);
            let ssa_name = SSAVariable::new(phi.variable.clone(), version).full_name();

            stacks.entry(phi.variable.clone())
                .or_insert_with(Vec::new)
                .push(version);
            pushed_vars.push(phi.variable.clone());

            ssa.add_definition(ssa_name, block_idx);
        }
    }

    // 2. Process instructions in this block
    let block = &cfg.blocks[block_idx];
    for &op_idx in &block.operations {
        let op = &mut program.operations_mut()[op_idx];

        // Update inputs
        for input in op.inputs_mut() {
            let base_name = varnode_to_var_name(input);
            if let Some(versions) = stacks.get(&base_name) {
                if let Some(&version) = versions.last() {
                    *input = input.with_version(version);
                    ssa.add_use(format!("{}_{}", base_name, version), block_idx);
                }
            }
        }

        // Update output
        if let Some(output) = op.output_mut() {
            let base_name = varnode_to_var_name(output);
            let version = ssa.next_version(&base_name);
            *output = output.with_version(version);

            stacks.entry(base_name.clone())
                .or_insert_with(Vec::new)
                .push(version);

            ssa.add_definition(format!("{}_{}", base_name, version), block_idx);
            pushed_vars.push(base_name);
        }
    }

    // 3. Update phi node inputs in successors
    for &succ_idx in &cfg.blocks[block_idx].successors {
        if let Some(phis) = ssa.phi_nodes.get_mut(&succ_idx) {
            for phi in phis {
                if let Some(versions) = stacks.get(&phi.variable) {
                    if let Some(&version) = versions.last() {
                        let ssa_name = SSAVariable::new(phi.variable.clone(), version).full_name();
                        phi.add_input(block_idx, ssa_name);
                    }
                }
            }
        }
    }

    // 4. Process children in dominator tree (parities with Ghidra's algorithm)
    if let Some(children) = dom_children.get(&block_idx) {
        for &child_idx in children {
            rename_block(child_idx, cfg, program, ssa, stacks, visited, dom_children);
        }
    }

    // 5. Pop pushed versions from stacks
    for var in pushed_vars {
        if let Some(versions) = stacks.get_mut(&var) {
            versions.pop();
        }
    }
}

/// Convert varnode to variable name
fn varnode_to_var_name(varnode: &Varnode) -> String {
    format!("{:?}_{:x}_{}", varnode.space(), varnode.offset(), varnode.size())
}

/// Destroy SSA form (convert back to normal form)
pub fn destroy_ssa(_ssa: &SSAForm) -> Result<()> {
    // TODO: Implement SSA destruction
    // This would involve:
    // 1. Replacing phi nodes with copies at predecessor blocks
    // 2. Merging SSA versions back to original variables
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pcode::{PcodeBuilder, PcodeOp}, analysis::cfg::ControlFlowGraph, Address};

    #[test]
    fn test_phi_node_creation() {
        let mut phi = PhiNode::new("x".to_string(), "x_0".to_string());
        assert_eq!(phi.variable, "x");
        assert_eq!(phi.output, "x_0");
        assert_eq!(phi.input_count(), 0);

        phi.add_input(0, "x_1".to_string());
        phi.add_input(1, "x_2".to_string());
        assert_eq!(phi.input_count(), 2);
    }

    #[test]
    fn test_ssa_variable() {
        let var = SSAVariable::new("x".to_string(), 1);
        assert_eq!(var.base_name, "x");
        assert_eq!(var.version, 1);
        assert_eq!(var.full_name(), "x_1");
        assert_eq!(var.to_string(), "x_1");
    }

    #[test]
    fn test_ssa_form_creation() {
        let mut ssa = SSAForm::new();

        let version1 = ssa.next_version("x");
        assert_eq!(version1, 1);

        let version2 = ssa.next_version("x");
        assert_eq!(version2, 2);

        let version_y = ssa.next_version("y");
        assert_eq!(version_y, 1);
    }

    #[test]
    fn test_phi_node_placement() {
        let mut ssa = SSAForm::new();

        let phi = PhiNode::new("x".to_string(), "x_0".to_string());
        ssa.add_phi_node(0, phi);

        assert!(ssa.get_phi_nodes(0).is_some());
        assert_eq!(ssa.get_phi_nodes(0).unwrap().len(), 1);
        assert!(ssa.get_phi_nodes(1).is_none());
    }

    #[test]
    fn test_ssa_definitions_and_uses() {
        let mut ssa = SSAForm::new();

        ssa.add_definition("x_1".to_string(), 0);
        ssa.add_use("x_1".to_string(), 1);
        ssa.add_use("x_1".to_string(), 2);

        assert_eq!(ssa.definitions.get("x_1"), Some(&0));
        assert_eq!(ssa.uses.get("x_1").map(|v| v.len()), Some(2));
    }

    #[test]
    fn test_identify_variables() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        let v1 = Varnode::new_register(0, 4);
        let v2 = Varnode::new_register(8, 4);

        builder.add_op(PcodeOp::Copy, Some(v1.clone()), vec![v2.clone()]);

        let program = builder.build();
        let variables = identify_variables(&program);

        assert!(!variables.is_empty());
    }

    #[test]
    fn test_dominance_frontier_computation() {
        // Create a simple CFG
        let mut builder = PcodeBuilder::new(Address::new(0x1000));
        builder.add_op(PcodeOp::Copy, None, vec![]);

        builder.at_address(Address::new(0x1010));
        builder.add_op(PcodeOp::Copy, None, vec![]);

        let program = builder.build();
        let cfg = ControlFlowGraph::from_program(&program).unwrap();

        let frontiers = compute_dominance_frontiers(&cfg);

        // Should have frontiers for all blocks
        assert_eq!(frontiers.len(), cfg.blocks.len());
    }

    #[test]
    fn test_varnode_to_var_name() {
        let varnode = Varnode::new_register(0, 4);
        let name = varnode_to_var_name(&varnode);

        assert!(name.contains("Register"));
        assert!(name.contains("4"));
    }

    #[test]
    fn test_ssa_form_default() {
        let ssa = SSAForm::default();
        assert_eq!(ssa.phi_nodes.len(), 0);
        assert_eq!(ssa.versions.len(), 0);
    }

    #[test]
    fn test_current_version() {
        let mut ssa = SSAForm::new();

        assert_eq!(ssa.current_version("x"), None);

        ssa.next_version("x");
        assert_eq!(ssa.current_version("x"), Some(1));

        ssa.next_version("x");
        assert_eq!(ssa.current_version("x"), Some(2));
    }
}
