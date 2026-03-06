# `funcdata.rs` API Reference

**源代码路径**: `src/funcdata.rs`

## 模块说明 (Module Doc)

High-level function data container

Corresponds to Ghidra's `funcdata.hh`

## 导出的公共 API (Public API)

### `pub struct Funcdata`

Main container for a function being decompiled

Corresponds to Ghidra's `Funcdata` class. This class ties together
the P-code operations, varnodes, control flow graph, and analysis state.

### `pub fn new(name: &str, addr: Address, size: i32) -> Self`

Create a new Funcdata instance

### `pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>)`

Set the self-reference after wrapping in Arc<RwLock>

### `pub fn get_name(&self) -> &str`

*暂无代码注释*

### `pub fn get_address(&self) -> &Address`

*暂无代码注释*

### `pub fn get_size(&self) -> i32`

*暂无代码注释*

### `pub fn clear(&mut self)`

Clear all analysis state

### `pub fn num_heritage_passes(&self) -> i32`

*暂无代码注释*

