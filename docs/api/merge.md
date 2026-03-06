# `merge.rs` API Reference (高级变量合并管理器)

**源代码路径**: `src/merge.rs`

## 模块说明 (Module Doc)

对应 Ghidra `merge.hh`。SSA 构造结束后，同一个 C 语言变量会在数据流中分裂为多个跨版本 `Varnode`。`Merge` 模块的职责就是**将这些散碎的 SSA 分身重新收拢聚合到同一个 `HighVariable` 下**，使之在最终反编译输出中呈现为一个统一的人类可读变量。

---

## 导出的公共 API (Public API)

### `pub struct Merge` (合并调度器)

*   `pub fn new(fd: Arc<RwLock<Funcdata>>) -> Self`: 绑定到一个函数级容器上。
*   `pub fn merge_all(&mut self)`: **一键执行全量合并流程**。内部按优先级依次调度五种合并策略：
    1. `merge_addr_tied()` — 地址绑定合并：将同地址同大小的 Varnode 在生存范围不冲突时合并。
    2. `merge_adjacent()` — 相邻合并（桩）。
    3. `merge_multi_entry()` — 多入口合并（桩）。
    4. `merge_marker()` — 标记合并（桩）。
    5. `merge_by_datatype()` — 按数据类型合并（桩）。

*   `pub fn merge_test(&self, v1: &Varnode, v2: &Varnode) -> bool`: 判断两个 Varnode 是否可安全合并（依据 Cover 不重叠等条件）。当前为桩返回 `false`。
*   `pub fn merge_force(&mut self, vn1, vn2)`: 强制合并两个 Varnode 为同一个 HighVariable（桩）。

### `pub struct BlockVarnode`

记录一个 Varnode 及其所在基本块的索引，用于合并算法中的分组排序。
