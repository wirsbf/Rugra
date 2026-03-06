# `analysis/rules/dataflow.rs` API Reference

**源代码路径**: `src/analysis/rules/dataflow.rs`

## 模块说明 (Module Doc)

Dataflow optimization rules

Rules for dataflow-based optimizations like copy propagation and dead code elimination.

## 导出的公共 API (Public API)

### `pub struct RuleCopyPropagation`

Rule: Propagate copies to uses

If A = COPY B, replaces uses of A with B (if safe).

### `pub struct RuleDeadCodeElimination`

Rule: Eliminate dead code

Removes operations whose output is unused (and have no side effects).

### `pub struct RuleGlobalPropagation`

Rule: SSA-based Global Copy Propagation

Propagates copies across basic block boundaries using SSA form information.
If A = COPY B, replaces all uses of A with B throughout the program.

### `pub struct RuleTypePropagation`

Rule: Type-based simplification

Uses global type information to:
1. Resolve redundant casts (IntSext, IntZext) when types already match.

### `pub struct RuleIdentityCopy`

Rule: Eliminate identity copies (x = x)

### `pub struct RuleTruncationElimination`

Rule: Eliminate redundant truncations

### `pub struct RuleLoadStorePropagation`

Rule: Resolve memory accesses to direct variable references

If a LOAD or STORE accesses a known local or global variable's storage,
it can sometimes be simplified to a direct access or COPY.

### `pub struct RuleControlFlowSimplification`

Rule: Simplify control flow with constant targets/conditions

