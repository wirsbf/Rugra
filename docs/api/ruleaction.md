# `ruleaction.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/ruleaction.rs`

## 模块说明 (Module Doc)

Rule-based transformations for P-code operations

Corresponds to Ghidra's `ruleaction.hh`. Rules are small, local
transformations that target specific opcodes to simplify the IR.

## 导出的公共 API (Public API)

### `pub struct RuleCollapseConstants`

Rule for collapsing constants in arithmetic operations

Corresponds to Ghidra's `RuleCollapseConstants`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleTrivialBool`

Rule for simplifying trivial boolean identities (e.g., x && true -> x)

Corresponds to Ghidra's `RuleTrivialBool`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RulePropagateCopy`

Rule for propagating copies

Corresponds to Ghidra's `RulePropagateCopy`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleZextEliminate`

Rule for eliminating redundant zero-extensions

Corresponds to Ghidra's `RuleZextEliminate`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleSextEliminate`

Rule for eliminating redundant sign-extensions

Corresponds to Ghidra's `RuleSextEliminate`.
Collapses `INT_SEXT(x)` to `COPY(x)` when input and output sizes match.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleTrivialArith`

Rule for simplifying trivial arithmetic identities

Corresponds to Ghidra's `RuleTrivialArith`.
Simplifies: `x + 0 → x`, `x - 0 → x`, `x * 1 → x`,
`x ^ 0 → x`, `x | 0 → x`.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleShiftBitops`

Rule for simplifying shift-by-zero operations

Corresponds to Ghidra's shift simplification rules.
Collapses `x << 0 → x`, `x >> 0 → x`, `x >>> 0 → x`.

### `pub fn new() -> Self`

*暂无代码注释*

 