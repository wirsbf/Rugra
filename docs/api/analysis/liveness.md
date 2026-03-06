# `analysis/liveness.rs` API Reference

**源代码路径**: `src/analysis/liveness.rs`

## 模块说明 (Module Doc)

Liveness Analysis for SSA Variables

This module computes the live ranges of SSA variables to support
variable merging and interference graph construction.

## 导出的公共 API (Public API)

### `pub struct InstructionIndex`

Represents a specific instruction location

### `pub struct LiveRange`

Liveness information for a single SSA variable

### `pub fn intersects(&self, other: &LiveRange) -> bool`

Check if this live range intersects with another

### `pub struct LivenessAnalysis`

Analysis result containing live ranges for all SSA variables

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn get_live_range(&self, var: &str) -> Option<&LiveRange>`

*暂无代码注释*

### `pub fn interfere(&self, var1: &str, var2: &str) -> bool`

Check if two variables interfere (cannot be merged)

### `pub fn compute_liveness(`

Compute liveness for all variables in SSA form

