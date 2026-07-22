# `variable.rs` API Reference

## 文档状态

- **状态**: ✅ **L3（2026-06-28 完整对齐）**——HighVariable 全部 Ghidra 方法覆盖（含 merge_internal/get_type_representative/strip_type）。4 单元测试。


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

### `pub fn update_internal_cover(&mut self)` (2026-06-29 新增)

Re-derive the internal cover from member Varnodes. Faithful to
`HighVariable::updateInternalCover` (variable.cc:324). Clears `cover`
then merges every instance's cover; skips instances with no cover
(constants/annotations/free). Called by `Merge::update_high_covers`
after merge_by_cover finalizes instance sets, so ActionMarkImplied's
checkImpliedCover/inflateTest can consult `high.cover`.

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



### 2026-07-04：HighVariable 新增 instance-delegated 访问器
- 新增 `is_input`/`is_extra_out`/`is_proto_partial`（对齐 variable.hh:200/205/206）。Ghidra 通过 updateFlags() 聚合 instance Varnode flags；Rugra 遍历 instances 查任一 Varnode flag。
- `is_persist`/`is_addr_tied` 增加 instance fallback（high_flags 位 + 任一 instance Varnode flag）。
<!-- annotation-pass: 2026-07-04 -->
**2026-07-22**: +VariableGroup + VariablePiece structs and methods
