# `analysis/ssa.rs` API Reference

**源代码路径**: `src/analysis/ssa.rs`

## 模块说明 (Module Doc)

SSA (Static Single Assignment) Form Construction

This module implements SSA form construction for P-code IR, including:
- Dominance frontier computation
- Phi node placement
- Variable renaming
- SSA destruction (converting back from SSA)

## 导出的公共 API (Public API)

### `pub struct PhiNode`

A Phi node in SSA form

### `pub fn new(variable: String, output: String) -> Self`

Create a new phi node

### `pub fn add_input(&mut self, block: usize, var: String)`

Add an input from a predecessor block

### `pub fn input_count(&self) -> usize`

Get the number of inputs

### `pub struct SSAVariable`

SSA variable with version number

### `pub fn new(base_name: String, version: usize) -> Self`

Create a new SSA variable

### `pub fn full_name(&self) -> String`

Get the full SSA name (e.g., "x_1", "y_2")

### `pub struct SSAForm`

SSA form representation

### `pub fn new() -> Self`

Create new empty SSA form

### `pub fn add_phi_node(&mut self, block: usize, phi: PhiNode)`

Add a phi node to a block

### `pub fn get_phi_nodes(&self, block: usize) -> Option<&Vec<PhiNode>>`

Get phi nodes for a block

### `pub fn next_version(&mut self, var: &str) -> usize`

Get the next version for a variable

### `pub fn current_version(&self, var: &str) -> Option<usize>`

Get the current version for a variable

### `pub fn add_definition(&mut self, ssa_var: String, block: usize)`

Record a definition

### `pub fn add_use(&mut self, ssa_var: String, block: usize)`

Record a use

### `pub fn construct_ssa(`

Construct SSA form from a CFG

### `pub fn destroy_ssa(_ssa: &SSAForm) -> Result<()>`

Destroy SSA form (convert back to normal form)

