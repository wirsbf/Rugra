# `merge.rs` API Reference

**源代码路径**: `src/merge.rs`

## 模块说明 (Module Doc)

High-level variable merging logic

Corresponds to Ghidra's `merge.hh`. This module is responsible for
merging multiple SSA Varnodes into a single HighVariable.

## 导出的公共 API (Public API)

### `pub struct Merge`

Manages the process of merging Varnodes into HighVariables

Corresponds to Ghidra's `Merge` class.

### `pub fn new(fd: Arc<RwLock<Funcdata>>) -> Self`

Create a new Merge instance for a function

### `pub fn clear(&mut self)`

Clear all existing HighVariables and reset merge state

### `pub fn merge_all(&mut self)`

Perform the basic merging process

### `pub fn merge_addr_tied(&mut self)`

Merge varnodes that are tied to the same address

### `pub fn merge_adjacent(&mut self)`

*暂无代码注释*

### `pub fn merge_multi_entry(&mut self)`

*暂无代码注释*

### `pub fn merge_marker(&mut self)`

*暂无代码注释*

### `pub fn merge_by_datatype(&mut self)`

*暂无代码注释*

### `pub fn merge_test(&self, _v1: &Varnode, _v2: &Varnode) -> bool`

*暂无代码注释*

### `pub fn merge_force(&mut self, _vn1: Arc<RwLock<Varnode>>, _vn2: Arc<RwLock<Varnode>>)`

*暂无代码注释*

### `pub struct BlockVarnode`

*暂无代码注释*

