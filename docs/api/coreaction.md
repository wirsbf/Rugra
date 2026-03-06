# `coreaction.rs` API Reference

**源代码路径**: `src/coreaction.rs`

## 模块说明 (Module Doc)

Core analysis actions for the decompiler

Corresponds to Ghidra's `coreaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionHeritage`

Action for performing SSA construction (Heritage)

Corresponds to Ghidra's `ActionHeritage`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionDeadCode`

Action for removing dead P-code operations

Corresponds to Ghidra's `ActionDeadCode`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionConstantPtr`

Action for identifying constant pointers and replacing them

Corresponds to Ghidra's `ActionConstantPtr`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCse`

Action for performing Common Subexpression Elimination (CSE)

Corresponds to Ghidra's `ActionCse`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionStart`

Start of the analysis process

### `pub fn new() -> Self`

*暂无代码注释*

