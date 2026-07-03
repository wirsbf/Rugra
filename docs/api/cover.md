# `cover.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/cover.rs`

## 模块说明 (Module Doc)

Liveness cover for varnodes

Corresponds to Ghidra's `cover.hh`

## 导出的公共 API (Public API)

### `pub struct CoverBlock`

Range of P-code ops within a single basic block where a varnode is alive

Corresponds to Ghidra's `CoverBlock` class

### `pub fn new() -> Self`

Create an empty cover block

### `pub fn clear(&mut self)`

Clear the cover block

### `pub fn set_begin(&mut self, s: u32)`

Set the start of liveness

### `pub fn set_end(&mut self, e: u32)`

Set the end of liveness

### `pub fn empty(&self) -> bool`

Check if the cover block is empty

### `pub fn contain(&self, point: u32) -> bool`

Check if the cover block contains a specific point

### `pub fn merge(&mut self, other: &CoverBlock)`

Merge another cover block into this one

### `pub fn intersect(&mut self, other: &CoverBlock)`

Intersect another cover block with this one

### `pub struct Cover`

Full liveness cover of a varnode across multiple blocks

Corresponds to Ghidra's `Cover` class

### `pub fn new() -> Self`

Create a new empty cover

### `pub fn clear(&mut self)`

Clear the cover

### `pub fn add_def_point(&mut self, block_idx: i32, point: u32)`

Add a definition point to the cover

### `pub fn add_ref_point(&mut self, block_idx: i32, point: u32)`

Add a reference point to the cover

### `pub fn contain(&self, block_idx: i32, point: u32) -> bool`

Check if the cover contains a point within a block

### `pub fn merge(&mut self, other: &Cover)`

Merge another cover into this one

### `pub fn intersect(&mut self, other: &Cover)`

Intersect another cover with this one


### 2026-07-04：新增 CoverBlock::boundary + Cover::contain_varnode_def_at
- `CoverBlock::boundary(point)`（对齐 cover.cc:129-142）：返回 0/1/2（非边界/tail/defining point）。
- `Cover::contain_varnode_def_at(is_input, block, order)`（对齐 cover.cc:441-462）：返回 0/1/2/3（未包含/内部/定义边界/tail边界）。供 eliminate_intersect 使用。

### 2026-07-04（续）：新增 intersect_char（非破坏性相交特征）
- `CoverBlock::intersect_char(op2)`（对齐 cover.cc:59）：返回 0/1/2（无/边界/区间相交）。
- `Cover::intersect_char(op2)`（对齐 cover.cc:269）：遍历两个 cover 的 block map，对共同 block 调 CoverBlock::intersect_char。返回 0/1/2。
