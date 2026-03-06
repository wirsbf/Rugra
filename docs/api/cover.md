# `cover.rs` API Reference (变量生存跨度追踪)

**源代码路径**: `src/cover.rs`

## 模块说明 (Module Doc)

对应 Ghidra `cover.hh`。用于精确追踪一个 `Varnode` 在函数全域内"从定义到最后被使用"之间的活跃时空窗口。
生存跨度 (Liveness / Cover) 是变量合并 (Merge) 和寄存器分配 (Register Allocation) 的核心前提信息——只有当两个变量的 Cover **完全不重叠**时，它们才有可能被安全地合并为同一个 `HighVariable`。

---

## 导出的公共 API (Public API)

### `pub struct CoverBlock` (单块内的生存时间片段)

记录一个变量在**某一个特定 BasicBlock 内部**从哪个微操序号活到哪个微操序号。
*   **`pub start: u32`**: 活跃区间的起始序号（对应 `SeqNum.order`）。
*   **`pub end: u32`**: 活跃区间的终止序号。
*   `pub fn contain(&self, point: u32) -> bool`: 判断指定时间点是否落在此活跃窗口内。
*   `pub fn merge(&mut self, other: &CoverBlock)`: 将另一个片段并入（取更宽的边界），用于合并路径分析结果。
*   `pub fn intersect(&mut self, other: &CoverBlock)`: 取交集（用于冲突检测）。

---

### `pub struct Cover` (跨块全域生存地图)

将上面的 `CoverBlock` 按基本块索引组织成一整张全函数视野的生存地图。
*   **`pub blocks: BTreeMap<i32, CoverBlock>`**: 键为 BasicBlock 的 `index`，值为该块内的活跃时间片段。
*   `pub fn add_def_point(&mut self, block_idx: i32, point: u32)`: 标记定义点（活跃区间起始）。
*   `pub fn add_ref_point(&mut self, block_idx: i32, point: u32)`: 标记引用点（活跃区间延展）。
*   `pub fn contain(&self, block_idx: i32, point: u32) -> bool`: 整体查询某一时空点是否处于该变量的活跃区。
*   `pub fn merge(&mut self, other: &Cover)` / `pub fn intersect(...)`: 全域级别的生存范围合并与交集。
