# `analysis/type_propagation.rs` API Reference

**源代码路径**: `src/analysis/type_propagation.rs`

## 模块说明 (Module Doc)

Constraint-based Type Propagation

This module implements a type propagation algorithm inspired by Ghidra's
data type propagation system. It uses a constraint solving approach to
infer types for variables in the P-code IR.

# Algorithm
1. Assign initial types based on known facts (constants, API calls).
2. Generate constraints for each P-code operation (e.g., ADD inputs must match output).
3. Iteratively propagate types through the constraint graph until convergence.

## 导出的公共 API (Public API)

### `pub struct TypeSolver`

Type solver state

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn solve(`

Run type propagation algorithm

### `pub fn get_type(&self, var: &str) -> Option<&DataType>`

*暂无代码注释*

### `pub fn parse_ssa_properties(name: &str) -> Option<(AddressSpace, u64, usize, usize)>`

*暂无代码注释*

### `pub fn varnode_to_key(vn: &Varnode) -> String`

Helper to generate a key for a Varnode, including SSA version for global propagation.

