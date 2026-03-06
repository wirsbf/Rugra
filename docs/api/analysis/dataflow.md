# `analysis/dataflow.rs` API Reference

**源代码路径**: `src/analysis/dataflow.rs`

## 模块说明 (Module Doc)

Data Flow Analysis Module

This module implements various data flow analysis algorithms including:
- Reaching definitions analysis
- Live variable analysis
- Use-def chains
- Def-use chains
- Available expressions
- Dead code detection

## 导出的公共 API (Public API)

### `pub struct Definition`

Represents a definition point in the program

### `pub fn new(block: usize, operation: usize, variable: String, address: Address) -> Self`

Create a new definition

### `pub struct UseDefChain`

Use-def chain entry

### `pub struct DefUseChain`

Def-use chain entry

### `pub struct DataFlowAnalysis`

Complete data flow analysis results

### `pub fn new() -> Self`

Create new empty analysis

### `pub fn is_live(&self, block: usize, operation: usize, variable: &str) -> bool`

Check if a variable is live at a given point

### `pub fn get_reaching_defs(`

Get reaching definitions for a variable at a point

### `pub fn get_uses_for_def(&self, def: &Definition) -> Option<&[(usize, usize)]>`

Get uses for a definition

### `pub fn analyze_dataflow(`

Perform complete data flow analysis

