# `analysis/mod.rs` API Reference

**源代码路径**: `src/analysis/mod.rs`

## 模块说明 (Module Doc)

Analysis module for decompilation

This module contains various analysis algorithms used during decompilation:
- Control flow analysis (CFG construction, loop detection)
- Data flow analysis (use-def chains, reaching definitions)
- SSA construction (dominance frontiers, phi placement)
- Type inference (constraint-based type recovery)
- Variable recovery (stack variables, register allocation)

## 导出的公共 API (Public API)

### `pub struct FunctionAnalysis`

Results of analyzing a function

### `pub fn new() -> Self`

Create a new empty analysis

### `pub fn analyze_function(program: &mut Program, binary: Option<&crate::binary::Binary>) -> Result<FunctionAnalysis>`

Analyze a P-code program

This is the main entry point for analysis. It performs:
1. Control flow graph construction
2. Data flow analysis
3. SSA construction (optional)
4. Type inference (optional)

# Arguments

* `program` - The P-code program to analyze
* `binary` - Optional reference to the binary (for symbol resolution)

# Returns

Analysis results

### `pub struct BasicBlock`

A basic block in the control flow graph

### `pub struct ControlFlowGraph`

Control flow graph

### `pub fn new() -> Self`

Create a new empty CFG

### `pub fn compute_dominators(&self) -> HashMap<usize, usize>`

Compute dominators for the CFG

### `pub fn detect_loops(&self) -> Vec<Loop>`

Detect natural loops in the CFG

### `pub fn identify_conditionals(&self) -> Vec<Conditional>`

Identify if/else patterns in the CFG

### `pub fn identify_switches(&self, program: &Program) -> Vec<Switch>`

*暂无代码注释*

### `pub fn from_program(program: &Program) -> Result<Self>`

Build a CFG from a P-code program

### `pub fn block_count(&self) -> usize`

Get the number of blocks

### `pub fn dominator_tree_string(&self) -> String`

Get the dominator tree as a string for debugging

### `pub enum LoopType`

Information about a loop

### `pub struct Loop`

*暂无代码注释*

### `pub struct Switch`

*暂无代码注释*

### `pub struct Conditional`

Information about a conditional (if/else)

### `pub struct DataFlowInfo`

Data flow information

### `pub fn new() -> Self`

Create new data flow info

### `pub struct TypeInfo`

Type information for a program

### `pub fn new() -> Self`

Create new type info

