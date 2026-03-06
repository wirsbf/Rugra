# `analysis/optimization.rs` API Reference

**源代码路径**: `src/analysis/optimization.rs`

## 模块说明 (Module Doc)

Optimization module for Rugra Decompiler (Phase 8)

This module implements various optimization passes to simplify the P-code IR:
- Constant Folding: Evaluates expressions with constant operands at compile time.
- Algebraic Simplification: Simplifies expressions using algebraic identities.
- Dead Code Elimination: Removes operations whose results are not used (replaces with NOP).

## 导出的公共 API (Public API)

### `pub fn optimize_function(program: &mut Program, analysis: &FunctionAnalysis)`

Optimize the function by applying various simplification passes iteratively.

### `pub struct ActionDeadCodeElimination`

Action: Global Dead Code Elimination

Removes operations whose results are not used anywhere in the function.
Leverages global SSA information if available for precision.

