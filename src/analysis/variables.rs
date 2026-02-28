//! Variable Recovery Module
//!
//! This module implements variable recovery algorithms to identify and name
//! variables from P-code IR, including:
//! - Stack variable detection
//! - Register lifetime analysis
//! - Variable naming heuristics
//! - Local variable tracking

use crate::{Address, Result, pcode::{Varnode, AddressSpace, Program}};
use std::collections::{HashMap, HashSet};

/// Represents a recovered variable
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// Unique identifier
    pub id: usize,
    /// Variable name (generated)
    pub name: String,
    /// Storage location (stack offset or register)
    pub storage: VariableStorage,
    /// Size in bytes
    pub size: usize,
    /// Type hint (if known)
    pub type_hint: Option<String>,
    /// First use address
    pub first_use: Option<Address>,
    /// Last use address
    pub last_use: Option<Address>,
}

/// Storage location for a variable
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VariableStorage {
    /// Stack-based variable at given offset from base pointer
    Stack(i64),
    /// Register-based variable
    Register(u64),
    /// Global variable at address
    Global(Address),
    /// Unknown/temporary
    Unknown,
}

/// Variable recovery analysis results
#[derive(Debug, Clone)]
pub struct VariableAnalysis {
    /// All recovered variables
    pub variables: Vec<Variable>,
    /// Mapping from varnode to variable ID
    pub varnode_to_var: HashMap<String, usize>,
    /// Stack frame size
    pub stack_frame_size: Option<usize>,
    /// Function parameters (by variable ID)
    pub parameters: Vec<usize>,
    /// Local variables (by variable ID)
    pub locals: Vec<usize>,
}

impl VariableAnalysis {
    /// Create new empty analysis
    pub fn new() -> Self {
        VariableAnalysis {
            variables: Vec::new(),
            varnode_to_var: HashMap::new(),
            stack_frame_size: None,
            parameters: Vec::new(),
            locals: Vec::new(),
        }
    }

    /// Get variable by ID
    pub fn get_variable(&self, id: usize) -> Option<&Variable> {
        self.variables.get(id)
    }

    /// Find which variable corresponds to a varnode
    pub fn find_variable_for_varnode(&self, varnode: &Varnode) -> Option<usize> {
        for (id, var) in self.variables.iter().enumerate() {
            match &var.storage {
                VariableStorage::Stack(offset) => {
                    if varnode.space() == AddressSpace::Stack
                        && varnode.offset() == *offset as u64 {
                        return Some(id);
                    }
                }
                VariableStorage::Register(reg_offset) => {
                    if varnode.space() == AddressSpace::Register
                        && varnode.offset() == *reg_offset {
                        return Some(id);
                    }
                }
                VariableStorage::Global(addr) => {
                    if varnode.space() == AddressSpace::Ram
                        && varnode.offset() == addr.as_u64() {
                        return Some(id);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Resolve a storage location to a variable
    pub fn resolve_storage(&self, space: AddressSpace, offset: u64) -> Option<&Variable> {
        for var in &self.variables {
            match &var.storage {
                VariableStorage::Stack(stk_off) => {
                    if space == AddressSpace::Stack && offset as i64 == *stk_off {
                        return Some(var);
                    }
                }
                VariableStorage::Register(reg_off) => {
                    if space == AddressSpace::Register && offset == *reg_off {
                        return Some(var);
                    }
                }
                VariableStorage::Global(addr) => {
                    if space == AddressSpace::Ram && offset == addr.as_u64() {
                        return Some(var);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Add a new variable
    pub fn add_variable(&mut self, var: Variable) -> usize {
        let id = self.variables.len();
        self.variables.push(var);
        id
    }
}

impl Default for VariableAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform variable recovery on a P-code program
pub fn recover_variables(program: &Program, cfg: &crate::analysis::cfg::ControlFlowGraph) -> Result<VariableAnalysis> {
    let mut analysis = VariableAnalysis::new();

    // Compute reachable blocks to avoid analyzing dead code
    let mut reachable = HashSet::new();
    if !cfg.blocks.is_empty() {
        let mut worklist = vec![cfg.entry];
        reachable.insert(cfg.entry);

        while let Some(block_idx) = worklist.pop() {
            if block_idx < cfg.blocks.len() {
                for &succ in &cfg.blocks[block_idx].successors {
                    if reachable.insert(succ) {
                        worklist.push(succ);
                    }
                }
            }
        }
    }

    // 1. Detect stack variables
    let stack_vars = detect_stack_variables(program, cfg, &reachable);
    for (offset, size) in stack_vars {
        let var = Variable {
            id: analysis.variables.len(),
            name: generate_stack_var_name(offset),
            storage: VariableStorage::Stack(offset),
            size,
            type_hint: infer_type_from_size(size),
            first_use: None,
            last_use: None,
        };
        let id = analysis.add_variable(var);
        analysis.locals.push(id);

        let key = format!("Stack_{:x}_{}", offset, size);
        analysis.varnode_to_var.insert(key, id);
    }

    // 2. Detect register variables
    let reg_vars = detect_register_variables(program, cfg, &reachable);
    for (reg_offset, size, is_param) in reg_vars {
        let var = Variable {
            id: analysis.variables.len(),
            name: generate_register_var_name(reg_offset, is_param),
            storage: VariableStorage::Register(reg_offset),
            size,
            type_hint: infer_type_from_size(size),
            first_use: None,
            last_use: None,
        };
        let id = analysis.add_variable(var);
        if is_param {
            analysis.parameters.push(id);
        } else {
            analysis.locals.push(id);
        }

        let key = format!("Register_{:x}_{}", reg_offset, size);
        analysis.varnode_to_var.insert(key, id);
    }

    // 3. Estimate stack frame size
    analysis.stack_frame_size = estimate_stack_frame_size(program);

    Ok(analysis)
}

/// Detect stack-based variables from P-code operations
fn detect_stack_variables(program: &Program, cfg: &crate::analysis::cfg::ControlFlowGraph, reachable: &HashSet<usize>) -> Vec<(i64, usize)> {
    let mut stack_accesses: HashMap<i64, HashSet<usize>> = HashMap::new();
    let rsp_offset = 32; // x86-64 RSP is typically register 32

    for block_idx in reachable {
        if *block_idx >= cfg.blocks.len() { continue; }
        let block = &cfg.blocks[*block_idx];
        for &op_idx in &block.operations {
            if op_idx >= program.operation_count() { continue; }
            let op = &program.operations()[op_idx];

            // Look for stack access patterns
            if let Some(output) = op.output() {
            if output.space() == AddressSpace::Stack {
                let offset = output.offset() as i64;
                let size = output.size();
                stack_accesses.entry(offset).or_insert_with(HashSet::new).insert(size);
            }
        }

        for input in op.inputs() {
            if input.space() == AddressSpace::Stack {
                let offset = input.offset() as i64;
                let size = input.size();
                stack_accesses.entry(offset).or_insert_with(HashSet::new).insert(size);
            }
        }

        // Heuristic: Check for RSP-relative address calculations (RSP +/- const)
        let inputs = op.inputs();
        if inputs.len() == 2 {
            let opcode = op.opcode();
            if opcode == crate::pcode::PcodeOp::IntSub {
                // RSP - const
                if inputs[0].space() == AddressSpace::Register && inputs[0].offset() == rsp_offset &&
                   inputs[1].space() == AddressSpace::Const {
                       let offset = -(inputs[1].offset() as i64);
                       stack_accesses.entry(offset).or_insert_with(HashSet::new).insert(8);
                }
            } else if opcode == crate::pcode::PcodeOp::IntAdd {
                // RSP + const (commutative)
                let mut const_val = None;
                let mut has_rsp = false;

                for input in inputs {
                    if input.space() == AddressSpace::Register && input.offset() == rsp_offset {
                        has_rsp = true;
                    } else if input.space() == AddressSpace::Const {
                        const_val = Some(input.offset());
                    }
                }

                if has_rsp {
                    if let Some(val) = const_val {
                        let offset = val as i64;
                        stack_accesses.entry(offset).or_insert_with(HashSet::new).insert(8);
                    }
                }
            }
        }
        }
    }

    // Convert to variable list
    let mut variables = Vec::new();
    for (offset, sizes) in stack_accesses {
        // Use the most common size, or largest if tied
        let size = *sizes.iter().max().unwrap_or(&8);
        variables.push((offset, size));
    }

    variables.sort_by_key(|(offset, _)| *offset);
    variables
}

/// Detect register-based variables and identify parameters
fn detect_register_variables(program: &Program, cfg: &crate::analysis::cfg::ControlFlowGraph, reachable: &HashSet<usize>) -> Vec<(u64, usize, bool)> {
    let mut register_uses: HashMap<u64, (HashSet<usize>, bool)> = HashMap::new();

    // Common parameter registers for x86-64 System V ABI
    let param_registers: HashSet<u64> = [
        56,  // rdi - first parameter
        48,  // rsi - second parameter
        24,  // rdx - third parameter
        16,  // rcx - fourth parameter
        64,  // r8 - fifth parameter
        72,  // r9 - sixth parameter
    ].iter().copied().collect();

    for block_idx in reachable {
        if *block_idx >= cfg.blocks.len() { continue; }
        let block = &cfg.blocks[*block_idx];
        for &op_idx in &block.operations {
            if op_idx >= program.operation_count() { continue; }
            let op = &program.operations()[op_idx];
        if let Some(output) = op.output() {
            if output.space() == AddressSpace::Register {
                let offset = output.offset();
                let size = output.size();
                let is_param = param_registers.contains(&offset);
                let entry = register_uses.entry(offset).or_insert((HashSet::new(), is_param));
                entry.0.insert(size);
            }
        }

        for input in op.inputs() {
            if input.space() == AddressSpace::Register {
                let offset = input.offset();
                let size = input.size();
                let is_param = param_registers.contains(&offset);
                let entry = register_uses.entry(offset).or_insert((HashSet::new(), is_param));
                entry.0.insert(size);
            }
        }
        }
    }

    // Convert to variable list
    let mut variables = Vec::new();
    for (offset, (sizes, is_param)) in register_uses {
        let size = *sizes.iter().max().unwrap_or(&8);
        variables.push((offset, size, is_param));
    }

    variables.sort_by_key(|(offset, _, _)| *offset);
    variables
}

/// Generate a name for a stack variable
fn generate_stack_var_name(offset: i64) -> String {
    if offset < 0 {
        // Negative offsets are typically local variables
        format!("local_{}", (-offset) as u64)
    } else {
        // Positive offsets might be parameters or previous frame
        format!("stack_{}", offset as u64)
    }
}

/// Generate a name for a register variable
fn generate_register_var_name(reg_offset: u64, is_param: bool) -> String {
    // Map common register offsets to names
    let reg_name = match reg_offset {
        0 => "rax",
        8 => "rcx",
        16 => "rdx",
        24 => "rbx",
        32 => "rsp",
        40 => "rbp",
        48 => "rsi",
        56 => "rdi",
        64 => "r8",
        72 => "r9",
        80 => "r10",
        88 => "r11",
        96 => "r12",
        104 => "r13",
        112 => "r14",
        120 => "r15",
        _ => return format!("reg_{}", reg_offset),
    };

    if is_param {
        // Map parameter registers to meaningful names
        match reg_offset {
            56 => "param_1".to_string(),  // rdi
            48 => "param_2".to_string(),  // rsi
            16 => "param_3".to_string(),  // rdx
            8 => "param_4".to_string(),   // rcx
            64 => "param_5".to_string(),  // r8
            72 => "param_6".to_string(),  // r9
            _ => format!("{}_param", reg_name),
        }
    } else {
        reg_name.to_string()
    }
}

/// Infer type hint from variable size
fn infer_type_from_size(size: usize) -> Option<String> {
    match size {
        1 => Some("char".to_string()),
        2 => Some("short".to_string()),
        4 => Some("int".to_string()),
        8 => Some("long".to_string()),
        _ => None,
    }
}

/// Estimate the total stack frame size
fn estimate_stack_frame_size(program: &Program) -> Option<usize> {
    let mut max_stack_offset = 0i64;
    let mut min_stack_offset = 0i64;

    for op in program.operations() {
        if let Some(output) = op.output() {
            if output.space() == AddressSpace::Stack {
                let offset = output.offset() as i64;
                max_stack_offset = max_stack_offset.max(offset);
                min_stack_offset = min_stack_offset.min(offset);
            }
        }

        for input in op.inputs() {
            if input.space() == AddressSpace::Stack {
                let offset = input.offset() as i64;
                max_stack_offset = max_stack_offset.max(offset);
                min_stack_offset = min_stack_offset.min(offset);
            }
        }
    }

    if max_stack_offset == 0 && min_stack_offset == 0 {
        None
    } else {
        Some((max_stack_offset - min_stack_offset).abs() as usize)
    }
}

/// Analyze variable lifetimes (def-use chains)
pub fn analyze_variable_lifetimes(
    program: &Program,
    analysis: &mut VariableAnalysis,
) -> Result<()> {
    // Track first and last use of each variable
    let mut first_use: HashMap<usize, Address> = HashMap::new();
    let mut last_use: HashMap<usize, Address> = HashMap::new();

    for op in program.operations() {
        let addr = op.address();

        // Check output
        if let Some(output) = op.output() {
            if let Some(var_id) = analysis.find_variable_for_varnode(output) {
                first_use.entry(var_id).or_insert(addr);
                last_use.insert(var_id, addr);
            }
        }

        // Check inputs
        for input in op.inputs() {
            if let Some(var_id) = analysis.find_variable_for_varnode(input) {
                first_use.entry(var_id).or_insert(addr);
                last_use.insert(var_id, addr);
            }
        }
    }

    // Update variable lifetimes
    for (var_id, addr) in first_use {
        if let Some(var) = analysis.variables.get_mut(var_id) {
            var.first_use = Some(addr);
        }
    }

    for (var_id, addr) in last_use {
        if let Some(var) = analysis.variables.get_mut(var_id) {
            var.last_use = Some(addr);
        }
    }

    Ok(())
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{PcodeBuilder, PcodeOp};

    #[test]
    fn test_variable_recovery_basic() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Create some stack accesses
        let stack_var = Varnode::new_stack((-8i64) as u64, 8);
        builder.add_op(PcodeOp::Store, None, vec![
            Varnode::new_constant(0, 8),
            stack_var.clone(),
            Varnode::new_constant(42, 8),
        ]);

        let program = builder.build();
        let analysis = recover_variables(&program).unwrap();

        assert!(!analysis.variables.is_empty());
    }

    #[test]
    fn test_stack_variable_detection() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Multiple accesses to same stack location
        let stack_var = Varnode::new_stack((-16i64) as u64, 8);
        builder.add_op(PcodeOp::Copy, Some(stack_var.clone()), vec![
            Varnode::new_constant(10, 8),
        ]);

        let program = builder.build();
        let stack_vars = detect_stack_variables(&program);

        assert!(!stack_vars.is_empty());
        assert_eq!(stack_vars[0].0, -16);
        assert_eq!(stack_vars[0].1, 8);
    }

    #[test]
    fn test_register_variable_detection() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Register operations
        let reg = Varnode::new_register(40, 8); // rdi - first parameter
        builder.add_op(PcodeOp::Copy, Some(Varnode::new_register(0, 8)), vec![reg]);

        let program = builder.build();
        let reg_vars = detect_register_variables(&program);

        assert!(!reg_vars.is_empty());
    }

    #[test]
    fn test_variable_naming() {
        // Test stack variable naming
        assert_eq!(generate_stack_var_name(-8), "local_8");
        assert_eq!(generate_stack_var_name(16), "stack_16");

        // Test register variable naming
        assert_eq!(generate_register_var_name(40, true), "param_1"); // rdi
        assert_eq!(generate_register_var_name(0, false), "rax");
    }

    #[test]
    fn test_type_inference_from_size() {
        assert_eq!(infer_type_from_size(1), Some("char".to_string()));
        assert_eq!(infer_type_from_size(4), Some("int".to_string()));
        assert_eq!(infer_type_from_size(8), Some("long".to_string()));
    }

    #[test]
    fn test_stack_frame_size_estimation() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Create variables at different stack offsets
        builder.add_op(PcodeOp::Copy, Some(Varnode::new_stack((-8i64) as u64, 8)), vec![
            Varnode::new_constant(1, 8),
        ]);
        builder.add_op(PcodeOp::Copy, Some(Varnode::new_stack((-32i64) as u64, 8)), vec![
            Varnode::new_constant(2, 8),
        ]);

        let program = builder.build();
        let frame_size = estimate_stack_frame_size(&program);

        assert!(frame_size.is_some());
        assert_eq!(frame_size.unwrap(), 24); // Distance from -32 to -8
    }

    #[test]
    fn test_variable_analysis_creation() {
        let analysis = VariableAnalysis::new();
        assert_eq!(analysis.variables.len(), 0);
        assert_eq!(analysis.parameters.len(), 0);
        assert_eq!(analysis.locals.len(), 0);
    }
}
