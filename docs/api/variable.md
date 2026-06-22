# `variable.rs` API Reference

## 文档状态

- **状态**: 部分有效（需对照源码）


**源代码路径**: `src/variable.rs`

## 模块说明 (Module Doc)

High-level variable management

Corresponds to Ghidra's `variable.hh`

## 导出的公共 API (Public API)

### `pub struct HighVariable`

Represents a high-level variable in the decompiler

Corresponds to Ghidra's `HighVariable` class. A HighVariable is a
collection of SSA Varnodes that represent the same logical variable.

### `pub fn new(v_type: Arc<Datatype>) -> Self`

Create a new high-level variable

### `pub fn get_name(&self) -> &str`

Get the name of the high variable

### `pub fn set_name(&mut self, name: String)`

Set the name of the high variable

### `pub fn get_type(&self) -> Arc<Datatype>`

Get the data type of the high variable

### `pub fn set_type(&mut self, v_type: Arc<Datatype>)`

Set the data type of the high variable

### `pub fn add_instance(&mut self, vn: Arc<RwLock<Varnode>>)`

Add a varnode instance to this high variable

### `pub fn num_instances(&self) -> usize`

Get the number of instances

### `pub fn get_instance(&self, i: usize) -> Option<Arc<RwLock<Varnode>>>`

Get a specific instance

### `pub const NAMELOCK: u32 = 1 << 0`

*暂无代码注释*

### `pub const TYPELOCK: u32 = 1 << 1`

*暂无代码注释*

### `pub const PERSIST: u32 = 1 << 2`

*暂无代码注释*

### `pub const ADDRTIED: u32 = 1 << 3`

*暂无代码注释*

### `pub const UNUSED1: u32 = 1 << 4`

*暂无代码注释*

### `pub const CONSTANT: u32 = 1 << 5`

*暂无代码注释*

### `pub const EXTRA_FLAGS: u32 = 1 << 6`

*暂无代码注释*


