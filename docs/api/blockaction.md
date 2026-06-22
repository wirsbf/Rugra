# `blockaction.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/blockaction.rs`

## 模块说明 (Module Doc)

Control flow structuring actions

Corresponds to Ghidra's `blockaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionBlockStructure`

Action for recovering high-level control flow structures

Corresponds to Ghidra's `ActionBlockStructure`. This action transforms
a flat basic block graph into a hierarchical structure of if, while,
and other high-level blocks.

### `pub fn new() -> Self`

Create a new ActionBlockStructure instance

### `pub struct ActionFinalStructure`

Action for performing final transformations on the block structure

Corresponds to Ghidra's `ActionFinalStructure`

### `pub fn new() -> Self`

Create a new ActionFinalStructure instance

### `pub struct ActionNormalizeBranches`

Action for normalizing branches (e.g., converting goto to break/continue)

Corresponds to Ghidra's `ActionNormalizeBranches`

### `pub fn new() -> Self`

Create a new ActionNormalizeBranches instance

 
### 2026-06-23（续）：interleaved 规则框架

- 新增 Ghidra 风格的 interleaved 规则迭代到 collapse_all 第二阶段。每轮对每块尝试 try_rule_cat → try_rule_proper_if → try_rule_if_else，直到收敛。
- 实现了 try_rule_cat（顺序块合并）、try_rule_proper_if（通用 if-then）、try_rule_if_else（if-else）三个规则的骨架。
- 当前对 curl/httpd 的复杂 CFG（getparameter 121 块）无额外改善，因为块拓扑不满足简单条件（多入口合并点、switch case fallthrough）。需要完整的 Ghidra collapseInternal（含 goto 标记、链式 cat 扩展、循环-条件嵌套）才能处理。
