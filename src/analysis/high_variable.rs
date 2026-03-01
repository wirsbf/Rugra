//! High-level variable analysis
//!
//! This module implements the concept of "High Variables" (HighVariable),
//! which groups multiple low-level SSA Varnodes into a single logical variable.
//! This is crucial for producing readable C code, as it reverses the SSA splitting
//! and register allocation artifacts.

use crate::pcode::{AddressSpace, Program, PcodeOp};
use crate::analysis::ssa::SSAForm;
use crate::analysis::variables::{VariableAnalysis, VariableStorage};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::liveness::LivenessAnalysis;
use std::collections::HashMap;

/// A high-level variable representing a single logical entity in the decompiled code.
#[derive(Debug, Clone)]
pub struct HighVariable {
    /// Unique ID
    pub id: usize,
    /// Assigned name (e.g., "iVar1", "local_10")
    pub name: String,
    /// The storage associated with this variable (e.g., stack offset, register)
    pub storage: VariableStorage,
    /// Size in bytes
    pub size: usize,
    /// Associated SSA varnodes (instances of this variable)
    /// Stores the string representation of SSA names
    pub instances: Vec<String>,
}

/// Manages the mapping between Varnodes and HighVariables
#[derive(Debug, Clone)]
pub struct HighVariableMap {
    /// All high variables
    pub variables: Vec<HighVariable>,
    /// Map from SSA variable name (string representation) to HighVariable ID
    pub varnode_to_high: HashMap<String, usize>,
}

impl HighVariableMap {
    pub fn new() -> Self {
        HighVariableMap {
            variables: Vec::new(),
            varnode_to_high: HashMap::new(),
        }
    }

    /// Find the HighVariable for a given SSA variable name
    pub fn get_high_variable(&self, ssa_name: &str) -> Option<&HighVariable> {
        self.varnode_to_high.get(ssa_name).map(|&id| &self.variables[id])
    }
}

/// Construct High Variables from SSA form and Variable Analysis results
pub fn construct_high_variables(
    program: &Program,
    cfg: &ControlFlowGraph,
    ssa: &SSAForm,
    var_analysis: &VariableAnalysis,
    liveness: Option<&LivenessAnalysis>
) -> HighVariableMap {
    let mut map = HighVariableMap::new();

    // We use a Union-Find data structure to group varnodes (SSA versions)
    let mut groups = UnionFind::new();

    // 1. Group by Phi nodes
    for phis in ssa.phi_nodes.values() {
        for phi in phis {
            let def = &phi.variable;
            groups.make_set(def.clone());
            for (_, input) in &phi.inputs {
                groups.make_set(input.clone());
                groups.union(def, input);
            }
        }
    }

    // 2. Group all other variables present in SSA definitions
    for (def, _) in &ssa.definitions {
        groups.make_set(def.clone());
    }

    // 3. Interference-Aware Copy Merging
    for block in &cfg.blocks {
        for &op_idx in &block.operations {
            if op_idx >= program.operation_count() { continue; }
            let op = &program.operations()[op_idx];

            if op.opcode == OpCode::CPUI_COPY {
                if let (Some(out), Some(inp)) = (op.output.as_ref(), op.inputs.as_slice().get(0)) {
                    if inp.is_constant() { continue; }

                    let out_name = format!("{:?}_{:x}_{}_{}", out.space(), out.offset(), out.size(), out.version());
                    let inp_name = format!("{:?}_{:x}_{}_{}", inp.space(), inp.offset(), inp.size(), inp.version());

                    // Check interference before merging
                    let mut can_merge = true;
                    if let Some(live) = liveness {
                        if live.interfere(&out_name, &inp_name) {
                            can_merge = false;
                        }
                    }

                    if can_merge {
                        groups.make_set(out_name.clone());
                        groups.make_set(inp_name.clone());
                        groups.union(&out_name, &inp_name);
                    }
                }
            }
        }
    }

    // 4. Storage-based grouping with interference check
    for var in &var_analysis.variables {
        let mut candidates = Vec::new();
        for (ssa_name, _) in &ssa.definitions {
            if let Some((space, offset, _size)) = parse_ssa_name(ssa_name) {
                let matches = match &var.storage {
                    VariableStorage::Stack(off) => space == AddressSpace::Stack && offset as i64 == *off,
                    VariableStorage::Register(off) => space == AddressSpace::Register && offset == *off,
                    _ => false,
                };
                if matches {
                    candidates.push(ssa_name.clone());
                }
            }
        }

        // Greedy merge: merge each candidate if it doesn't interfere with already merged ones in the group
        for i in 0..candidates.len() {
            for j in i + 1..candidates.len() {
                let v1 = &candidates[i];
                let v2 = &candidates[j];

                let mut can_merge = true;
                if let Some(live) = liveness {
                    if live.interfere(v1, v2) {
                        can_merge = false;
                    }
                }

                if can_merge {
                    groups.union(v1, v2);
                }
            }
        }
    }

    // 4. Create HighVariables for each group
    let grouped_sets = groups.get_sets();

    // Sort keys to ensure deterministic ordering of variable IDs
    let mut root_keys: Vec<String> = grouped_sets.keys().cloned().collect();
    root_keys.sort();

    for root in root_keys {
        let members = &grouped_sets[&root];

        let mut best_name = String::new();
        let mut storage = VariableStorage::Unknown;
        let mut size = 0;
        let mut _is_param = false;

        // Analyze members to determine properties and best storage
        for member in members {
            if let Some((space, offset, sz)) = parse_ssa_name(member) {
                if size == 0 { size = sz; }

                let current_priority = match storage {
                    VariableStorage::Stack(_) => 3,
                    VariableStorage::Register(_) => 2,
                    VariableStorage::Unknown => 0,
                    _ => 1,
                };

                let new_priority = match space {
                    AddressSpace::Stack => 3,
                    AddressSpace::Register => 2,
                    AddressSpace::Unique => 1,
                    _ => 0,
                };

                if new_priority > current_priority {
                    if space == AddressSpace::Stack {
                        let stack_offset = offset as i64;
                        storage = VariableStorage::Stack(stack_offset);
                        best_name = format!("local_{:x}", stack_offset.abs());
                    } else if space == AddressSpace::Register {
                        storage = VariableStorage::Register(offset);
                        // Assign generic register-based name initially
                        if best_name.is_empty() || !best_name.starts_with("param_") {
                             let prefix = match size { 1=>"b", 2=>"s", 4=>"i", 8=>"l", _=>"u" };
                             best_name = format!("{}Var{}", prefix, map.variables.len() + 1);
                        }
                    }
                }

                if space == AddressSpace::Register && member.ends_with("_0") {
                    match offset {
                        56 => { best_name = "param_1".to_string(); _is_param = true; } // rdi
                        48 => { best_name = "param_2".to_string(); _is_param = true; } // rsi
                        24 => { best_name = "param_3".to_string(); _is_param = true; } // rdx
                        16 => { best_name = "param_4".to_string(); _is_param = true; } // rcx
                        64 => { best_name = "param_5".to_string(); _is_param = true; } // r8
                        72 => { best_name = "param_6".to_string(); _is_param = true; } // r9
                        _ => {}
                    }
                }
            }
        }

        // If no specific name found, generate generic name based on type/size
        if best_name.is_empty() {
            let prefix = match size {
                1 => "b", // byte
                2 => "s", // short
                4 => "i", // int
                8 => "l", // long
                _ => "u", // undefined
            };

            // Use ID + 1 for 1-based indexing in names
            best_name = format!("{}Var{}", prefix, map.variables.len() + 1);
        }

        let high_var = HighVariable {
            id: map.variables.len(),
            name: best_name,
            storage,
            size,
            instances: members.clone(),
        };

        let id = map.variables.len();
        map.variables.push(high_var);

        for member in members {
            map.varnode_to_high.insert(member.clone(), id);
        }
    }

    map
}

// Helper to parse SSA name string back to properties
// Format from ssa.rs: format!("{:?}_{:x}_{}_{}", space, offset, size, version)
// e.g., "Register_0_8_0" (rax, size 8, ver 0)
fn parse_ssa_name(name: &str) -> Option<(AddressSpace, u64, usize)> {
    let parts: Vec<&str> = name.split('_').collect();
    // Expected at least 4 parts: Space, Offset, Size, Version
    if parts.len() < 4 { return None; }

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

    Some((space, offset, size))
}

// Simple Union-Find implementation for string keys
struct UnionFind {
    parent: HashMap<String, String>,
}

impl UnionFind {
    fn new() -> Self {
        UnionFind { parent: HashMap::new() }
    }

    fn make_set(&mut self, x: String) {
        self.parent.entry(x.clone()).or_insert(x);
    }

    fn find(&mut self, x: &str) -> String {
        if !self.parent.contains_key(x) {
            // Implicit make_set
            self.parent.insert(x.to_string(), x.to_string());
            return x.to_string();
        }

        let mut p = self.parent[x].clone();
        if p != x {
            p = self.find(&p);
            self.parent.insert(x.to_string(), p.clone());
        }
        p
    }

    fn union(&mut self, x: &str, y: &str) {
        let root_x = self.find(x);
        let root_y = self.find(y);
        if root_x != root_y {
            self.parent.insert(root_x, root_y);
        }
    }

    fn get_sets(&mut self) -> HashMap<String, Vec<String>> {
        let mut sets: HashMap<String, Vec<String>> = HashMap::new();
        let keys: Vec<String> = self.parent.keys().cloned().collect();

        for key in keys {
            let root = self.find(&key);
            sets.entry(root).or_default().push(key);
        }
        sets
    }
}
