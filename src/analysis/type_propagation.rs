//! Constraint-based Type Propagation
//!
//! This module implements a type propagation algorithm inspired by Ghidra's
//! data type propagation system. It uses a constraint solving approach to
//! infer types for variables in the P-code IR.
//!
//! # Algorithm
//! 1. Assign initial types based on known facts (constants, API calls).
//! 2. Generate constraints for each P-code operation (e.g., ADD inputs must match output).
//! 3. Iteratively propagate types through the constraint graph until convergence.

use crate::pcode::{Program, PcodeOp, Varnode, AddressSpace, PcodeOperation};
use crate::analysis::ssa::SSAForm;
use crate::analysis::variables::VariableAnalysis;
use crate::analysis::api::ApiRegistry;
use crate::types::{DataType, parse_type_string};
use std::collections::{HashMap, HashSet, VecDeque};

/// Type solver state
#[derive(Debug, Clone)]
pub struct TypeSolver {
    types: HashMap<String, DataType>,
    /// Maps variable key to operations that use it as input
    dependents: HashMap<String, Vec<usize>>,
    /// Maps variable key to Phi nodes that use it as input (block_idx, phi_idx)
    phi_dependents: HashMap<String, Vec<(usize, usize)>>,
    worklist: VecDeque<String>,
    api_registry: ApiRegistry,
    /// Discovered fields for structs: StructName -> Map<Offset, DataType>
    pub discovered_fields: HashMap<String, HashMap<u64, DataType>>,
}

impl TypeSolver {
    pub fn new() -> Self {
        TypeSolver {
            types: HashMap::new(),
            dependents: HashMap::new(),
            phi_dependents: HashMap::new(),
            worklist: VecDeque::new(),
            api_registry: ApiRegistry::new(),
            discovered_fields: HashMap::new(),
        }
    }

    /// Run type propagation algorithm
    pub fn solve(
        &mut self,
        program: &Program,
        ssa: &SSAForm,
        var_analysis: Option<&VariableAnalysis>,
        binary: Option<&crate::binary::Binary>
    ) {
        // 1. Initialize types for all variables
        self.initialize_types(program, ssa, var_analysis);

        // 2. Build dependency graph
        self.build_dependencies(program, ssa);

        // 3. Propagate until convergence
        while let Some(var) = self.worklist.pop_front() {
            // A. Propagate through P-code operations
            if let Some(indices) = self.dependents.get(&var).cloned() {
                for op_idx in indices {
                    if op_idx >= program.operation_count() { continue; }
                    let op = &program.operations()[op_idx];
                    self.propagate_op(op, ssa, binary);
                }
            }

            // B. Propagate through Phi nodes
            if let Some(phis) = self.phi_dependents.get(&var).cloned() {
                for (block_idx, phi_idx) in phis {
                    if let Some(block_phis) = ssa.phi_nodes.get(&block_idx) {
                        if let Some(phi) = block_phis.get(phi_idx) {
                            self.propagate_phi(phi);
                        }
                    }
                }
            }
        }
    }

    /// Initialize types from known facts (constants, intrinsics)
    fn initialize_types(
        &mut self,
        _program: &Program,
        ssa: &SSAForm,
        var_analysis: Option<&VariableAnalysis>
    ) {
        // 1. Initialize from SSA definitions (including Phi nodes)
        let mut all_defs: HashSet<String> = ssa.definitions.keys().cloned().collect();

        // Ensure Phi outputs are included
        for phis in ssa.phi_nodes.values() {
            for phi in phis {
                all_defs.insert(phi.output.clone());
            }
        }

        for def in all_defs {
            // Parse properties from name
            let (space, offset, size, _version) = parse_ssa_properties(&def)
                .unwrap_or((AddressSpace::Register, 0, 8, 0));

            let mut initial_type = DataType::Unknown(size);

            // Use VariableAnalysis hints if available
            if let Some(analysis) = var_analysis {
                for var in &analysis.variables {
                    let matches = match &var.storage {
                        crate::analysis::variables::VariableStorage::Stack(stk_off) => {
                            space == AddressSpace::Stack && offset as i64 == *stk_off
                        },
                        crate::analysis::variables::VariableStorage::Register(reg_off) => {
                            space == AddressSpace::Register && offset == *reg_off
                        },
                        _ => false
                    };

                    if matches {
                        if let Some(hint) = &var.type_hint {
                            initial_type = parse_type_string(hint, size);
                        }
                        break;
                    }
                }
            }

            self.types.insert(def.clone(), initial_type);
            self.worklist.push_back(def.clone());
        }
    }

    fn build_dependencies(&mut self, program: &Program, ssa: &SSAForm) {
        // Dependency from Op Inputs to Op Index
        for (i, op) in program.operations().iter().enumerate() {
            for input in op.inputs() {
                let key = varnode_to_key(input);
                self.dependents.entry(key).or_insert_with(Vec::new).push(i);
            }
        }

        // Dependency from Phi Inputs to Phi Index
        for (&block_idx, phis) in &ssa.phi_nodes {
            for (phi_idx, phi) in phis.iter().enumerate() {
                for input_ssa_name in phi.inputs.values() {
                    self.phi_dependents.entry(input_ssa_name.clone())
                        .or_insert_with(Vec::new)
                        .push((block_idx, phi_idx));
                }
            }
        }
    }

    /// Propagate types for a single operation
    fn propagate_op(
        &mut self,
        op: &PcodeOperation,
        _ssa: &SSAForm,
        binary: Option<&crate::binary::Binary>,
    ) {
        // Implementation of transfer functions for each opcode

        let output_vn = match op.output() {
            Some(o) => o,
            None => return, // Store, Branch, etc. handled separately or don't propagate to output
        };
        let output_key = varnode_to_key(output_vn);

        let inputs = op.inputs();
        if inputs.is_empty() { return; }

        match op.opcode() {
            PcodeOp::Copy => {
                let input_key = varnode_to_key(&inputs[0]);
                if let Some(in_type) = self.types.get(&input_key).cloned() {
                    self.update_type(&output_key, in_type);
                } else if let Some(out_type) = self.types.get(&output_key).cloned() {
                    // Back-propagate
                    self.update_type(&input_key, out_type);
                }
            }
            PcodeOp::IntAdd | PcodeOp::IntSub => {
                let type1 = self.types.get(&varnode_to_key(&inputs[0])).cloned();
                let type2 = inputs.get(1).and_then(|vn| self.types.get(&varnode_to_key(vn))).cloned();

                let result_type = match (type1, type2) {
                    (Some(DataType::Pointer(target, sz)), Some(DataType::Pointer(_, _))) => {
                        if op.opcode() == PcodeOp::IntSub {
                            DataType::Int(output_vn.size(), true)
                        } else {
                            DataType::Pointer(target, sz)
                        }
                    }
                    (Some(DataType::Pointer(target, sz)), _) | (_, Some(DataType::Pointer(target, sz))) => {
                        if op.opcode() == PcodeOp::IntAdd {
                            if let DataType::Struct(struct_name) = target.as_ref() {
                                let offset = inputs.iter().find_map(|vn| vn.constant_value());
                                if let Some(off) = offset {
                                    let fields = self.discovered_fields.entry(struct_name.clone()).or_default();
                                    fields.entry(off).or_insert(DataType::Unknown(output_vn.size()));
                                }
                            }
                        }
                        DataType::Pointer(target, sz)
                    }
                    (Some(DataType::Int(s1, signed1)), Some(DataType::Int(s2, signed2))) => {
                        DataType::Int(output_vn.size(), signed1 || signed2)
                    }
                    (Some(DataType::Int(_, signed)), _) | (_, Some(DataType::Int(_, signed))) => {
                        DataType::Int(output_vn.size(), signed)
                    }
                    _ => DataType::Int(output_vn.size(), false),
                };

                self.update_type(&output_key, result_type);
            }
            PcodeOp::IntMult | PcodeOp::IntDiv | PcodeOp::IntSDiv | PcodeOp::IntRem | PcodeOp::IntSRem |
            PcodeOp::IntAnd | PcodeOp::IntOr | PcodeOp::IntXor |
            PcodeOp::IntNot | PcodeOp::IntNeg |
            PcodeOp::IntLeft | PcodeOp::IntRight | PcodeOp::IntSRight => {
                // Standard integer ops -> Int
                // Size usually determined by output size
                let out_type = DataType::Int(output_vn.size(), false); // Default unsigned
                self.update_type(&output_key, out_type);
            }
            PcodeOp::IntEqual | PcodeOp::IntNotEqual |
            PcodeOp::IntLess | PcodeOp::IntLessEqual |
            PcodeOp::IntSLess | PcodeOp::IntSLessEqual |
            PcodeOp::FloatEqual | PcodeOp::FloatNotEqual |
            PcodeOp::FloatLess | PcodeOp::FloatLessEqual |
            PcodeOp::BoolAnd | PcodeOp::BoolOr | PcodeOp::BoolXor | PcodeOp::BoolNot => {
                // Comparison & Boolean -> Bool
                self.update_type(&output_key, DataType::Bool);
            }
            PcodeOp::Load => {
                // out = *ptr
                if let Some(ptr) = inputs.get(1) {
                    let ptr_key = varnode_to_key(ptr);
                    if let Some(DataType::Pointer(target_type, _)) = self.types.get(&ptr_key).cloned() {
                        self.update_type(&output_key, *target_type);
                    } else if let Some(out_type) = self.types.get(&output_key).cloned() {
                        // Back-propagate: if out is T, then ptr is T*
                        if !out_type.is_unknown() {
                            self.update_type(&ptr_key, DataType::Pointer(Box::new(out_type), ptr.size()));
                        }
                    }
                }
            }
            PcodeOp::Store => {
                // *ptr = val
                if let (Some(ptr), Some(val)) = (inputs.get(1), inputs.get(2)) {
                    let ptr_key = varnode_to_key(ptr);
                    let val_key = varnode_to_key(val);

                    if let Some(DataType::Pointer(target_type, _)) = self.types.get(&ptr_key).cloned() {
                        self.update_type(&val_key, *target_type);
                    } else if let Some(val_type) = self.types.get(&val_key).cloned() {
                        if !val_type.is_unknown() {
                            self.update_type(&ptr_key, DataType::Pointer(Box::new(val_type), ptr.size()));
                        }
                    }
                }
            }
            PcodeOp::IntZext | PcodeOp::IntSext => {
                if let Some(in_type) = self.types.get(&varnode_to_key(&inputs[0])) {
                    let new_type = match in_type {
                        DataType::Int(_, signed) => {
                            let is_signed = if op.opcode() == PcodeOp::IntSext { true } else { *signed };
                            DataType::Int(output_vn.size(), is_signed)
                        }
                        DataType::Bool => DataType::Int(output_vn.size(), false),
                        DataType::Pointer(target, _) => DataType::Pointer(target.clone(), output_vn.size()),
                        _ => DataType::Unknown(output_vn.size()),
                    };
                    self.update_type(&output_key, new_type);
                }
            }
            PcodeOp::FloatAdd | PcodeOp::FloatSub | PcodeOp::FloatMult | PcodeOp::FloatDiv |
            PcodeOp::FloatNeg | PcodeOp::FloatAbs | PcodeOp::FloatSqrt |
            PcodeOp::FloatCeil | PcodeOp::FloatFloor | PcodeOp::FloatRound => {
                self.update_type(&output_key, DataType::Float(output_vn.size()));
            }
            PcodeOp::IntToFloat | PcodeOp::FloatToFloat => {
                self.update_type(&output_key, DataType::Float(output_vn.size()));
            }
            PcodeOp::FloatToInt => {
                self.update_type(&output_key, DataType::Int(output_vn.size(), true));
            }
            PcodeOp::Trunc | PcodeOp::SubPiece => {
                // out = trunc(in)
                if let Some(in_vn) = inputs.get(0) {
                    if let Some(in_type) = self.types.get(&varnode_to_key(in_vn)).cloned() {
                         let out_type = match in_type {
                             DataType::Int(_, signed) => DataType::Int(output_vn.size(), signed),
                             _ => DataType::Unknown(output_vn.size()),
                         };
                         self.update_type(&output_key, out_type);
                    }
                }
            }
            PcodeOp::Call => {
                // Call inputs: [0] target_addr, [1..] arguments
                // We need the function name to look up the prototype
                if let Some(target) = inputs.get(0) {
                    if let Some(_addr_val) = target.constant_value() {
                        // In a real decompiler, we'd look up the symbol name at this address
                        // For this prototype, we'll assume the address is mapped to a name elsewhere
                        // and check for known patterns or common symbols.

                        // Placeholder: Get function name from metadata if available
                        // Since we don't have easy access to symbol table here,
                        // we'd typically pass it in.
                        // For now, let's assume we have a way to identify the call target name.
                    }
                }

                // If it's a known API, propagate types to arguments and from return value
                self.propagate_api_call(op, binary);
            }
            _ => {}
        }
    }

    /// Propagate types for an API call based on known prototypes
    /// Propagate types through a Phi node (MULTIEQUAL)
    /// The output type is the 'meet' of all input types.
    fn propagate_phi(&mut self, phi: &crate::analysis::ssa::PhiNode) {
        let mut merged_type: Option<DataType> = None;

        for input_name in phi.inputs.values() {
            if let Some(t) = self.types.get(input_name) {
                match merged_type {
                    None => merged_type = Some(t.clone()),
                    Some(ref current) => {
                        merged_type = Some(current.meet(t));
                    }
                }
            }
        }

        if let Some(t) = merged_type {
            self.update_type(&phi.output, t);
        }
    }

    fn propagate_api_call(&mut self, op: &PcodeOperation, binary: Option<&crate::binary::Binary>) {
        // This requires knowing the function name.
        let func_name = match op.opcode() {
            PcodeOp::Call => {
                // Heuristic: check if there's a symbol name associated with the first input (address)
                if let Some(target) = op.inputs().get(0) {
                    if let Some(addr_val) = target.constant_value() {
                        // Look up symbol in binary
                        if let Some(bin) = binary {
                            if let Some(name) = bin.get_function_name(crate::Address::new(addr_val)) {
                                // Strip PLT suffixes to match canonical API names
                                if let Some(stripped) = name.strip_suffix("@plt") {
                                    stripped
                                } else if let Some(stripped) = name.strip_suffix("_plt") {
                                    stripped
                                } else {
                                    name.as_str()
                                }
                            } else {
                                return;
                            }
                        } else {
                            // Fallback if no binary provided (e.g. tests)
                            // In a real scenario, we might have metadata attached to the program
                            return;
                        }
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            },
            _ => return,
        };

        if let Some(proto) = self.api_registry.get_prototype(func_name).cloned() {
            // 1. Propagate return type to output
            if let Some(output) = op.output() {
                let output_key = varnode_to_key(output);
                self.update_type(&output_key, proto.return_type.clone());
            }

            // 2. Propagate parameter types to inputs
            // Skip input[0] (target address)
            let args = &op.inputs()[1..];
            for (i, arg) in args.iter().enumerate() {
                if i < proto.parameter_types.len() {
                    let arg_key = varnode_to_key(arg);
                    self.update_type(&arg_key, proto.parameter_types[i].clone());
                }
            }
        }
    }

    /// Update the type of a variable, merging with existing type
    fn update_type(&mut self, var_key: &str, new_type: DataType) {
        if let Some(current_type) = self.types.get(var_key) {
            let merged = current_type.meet(&new_type);
            if merged != *current_type {
                self.types.insert(var_key.to_string(), merged);
                self.worklist.push_back(var_key.to_string());

                // Add dependencies to worklist (forward propagation)
                if let Some(_deps) = self.dependents.get(var_key) {
                    // We need a way to map op indices back to input vars or just re-queue operations
                    // But our solver iterates variables.
                    // Actually, we need to find which OUTPUT variables depend on this INPUT variable.
                    // This requires the dependency graph to map InputVar -> List[OutputVar] (or Op).
                    // Current structure `dependents: HashMap<String, Vec<usize>>` maps Var -> OpIndices.
                    // We re-propagate those operations.

                    // In `solve`, we iterate worklist of vars, get dependent ops, and call propagate_op.
                    // propagate_op updates the OUTPUT of that op.
                    // If output changes, update_type(output) is called, which pushes output to worklist.
                    // This chains the propagation.
                }
            }
        } else {
            // First assignment
            self.types.insert(var_key.to_string(), new_type);
            self.worklist.push_back(var_key.to_string());
        }
    }

    pub fn get_type(&self, var: &str) -> Option<&DataType> {
        self.types.get(var)
    }
}

pub fn parse_ssa_properties(name: &str) -> Option<(AddressSpace, u64, usize, usize)> {
    // Expected format: "AddressSpace_Offset_Size_Version"
    // matching ssa.rs: varnode_to_var_name + _version
    let parts: Vec<&str> = name.split('_').collect();
    if parts.len() < 3 { return None; }

    let space = match parts[0] {
        "Register" => AddressSpace::Register,
        "Stack" => AddressSpace::Stack,
        "Ram" => AddressSpace::Ram,
        "Unique" => AddressSpace::Unique,
        "Const" => AddressSpace::Const,
        _ => return None,
    };

    let offset = u64::from_str_radix(parts[1], 16).ok()?;
    let size = parts[2].parse::<usize>().ok()?;
    let version = parts.get(3).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);

    Some((space, offset, size, version))
}

/// Helper to generate a key for a Varnode, including SSA version for global propagation.
pub fn varnode_to_key(vn: &Varnode) -> String {
    // Key format: "Space_Offset_Size_Version" matching SSA variable names
    format!("{:?}_{:x}_{}_{}", vn.space(), vn.offset(), vn.size(), vn.version())
}
