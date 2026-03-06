# `analysis/variables.rs` API Reference

**源代码路径**: `src/analysis/variables.rs`

## 模块说明 (Module Doc)

Variable Recovery Module

This module implements variable recovery algorithms to identify and name
variables from P-code IR, including:
- Stack variable detection
- Register lifetime analysis
- Variable naming heuristics
- Local variable tracking

## 导出的公共 API (Public API)

### `pub struct Variable`

Represents a recovered variable

### `pub enum VariableStorage`

Storage location for a variable

### `pub struct VariableAnalysis`

Variable recovery analysis results

### `pub fn new() -> Self`

Create new empty analysis

### `pub fn get_variable(&self, id: usize) -> Option<&Variable>`

Get variable by ID

### `pub fn find_variable_for_varnode(&self, varnode: &Varnode) -> Option<usize>`

Find which variable corresponds to a varnode

### `pub fn resolve_storage(&self, space: AddressSpace, offset: u64) -> Option<&Variable>`

Resolve a storage location to a variable

### `pub fn add_variable(&mut self, var: Variable) -> usize`

Add a new variable

### `pub fn recover_variables(program: &Program, cfg: &crate::analysis::cfg::ControlFlowGraph) -> Result<VariableAnalysis>`

Perform variable recovery on a P-code program

### `pub fn analyze_variable_lifetimes(`

Analyze variable lifetimes (def-use chains)

