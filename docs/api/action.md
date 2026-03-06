# `action.rs` API Reference

**源代码路径**: `src/action.rs`

## 模块说明 (Module Doc)

Analysis actions and transformation rules

Corresponds to Ghidra's `action.hh`

## 导出的公共 API (Public API)

### `pub trait Action`

Base trait for all analysis actions

Corresponds to Ghidra's `Action` class. An action represents a high-level
analysis or transformation step performed on a function.

### `pub trait Rule`

Base trait for small-scale transformation rules

Corresponds to Ghidra's `Rule` class. A rule typically targets a specific
P-code opcode and performs a local simplification or optimization.

### `pub struct ActionGroup`

A group of actions executed together

Corresponds to Ghidra's `ActionGroup` class

### `pub fn new(name: &str) -> Self`

*暂无代码注释*

### `pub fn add_action(&mut self, action: Box<dyn Action>)`

*暂无代码注释*

### `pub struct ActionDatabase`

Database for managing all registered actions

Corresponds to Ghidra's `ActionDatabase` class

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn register_action(&mut self, action: Box<dyn Action>)`

*暂无代码注释*

### `pub fn get_action(&self, name: &str) -> Option<&dyn Action>`

*暂无代码注释*

### `pub fn set_default_actions(&mut self)`

Set up default decompiler actions

### `pub const NO_CHANGE: i32 = 0`

*暂无代码注释*

### `pub const CHANGE: i32 = 1`

*暂无代码注释*

### `pub const RESTART: i32 = 2`

*暂无代码注释*

