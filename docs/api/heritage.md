# `heritage.rs` API Reference (SSA 构造与遗产管理引擎)

**源代码路径**: `src/heritage.rs`

## 模块说明 (Module Doc)

对应 Ghidra `heritage.hh`。这是整个反编译器在得到原始 P-code 流之后**最重要也最黑箱的那一步骤**：将杂乱无章的、对同一寄存器反复覆写的指令网络，提纯升级为清洁的 **静态单赋值 (SSA)** 形态。
Heritage 的核心职责是：在控制流交汇点精准投放 `Phi` 节点 (`CPUI_MULTIEQUAL`)，然后用支配树驱动的深度优先遍历将每一个变元引用重命名到其唯一的定义版本上。

---

## 导出的公共 API (Public API)

### `pub struct LocationMap` (地址→分析轮次映射表)

追踪"某个地址在第几轮 SSA 构造中已经被处理过了"，用于跨轮次增量 Heritage 的判重。
*   `pub fn add(&mut self, addr: Address, size: i32, pass: i32)`: 登记。
*   `pub fn find_pass(&self, addr: Address) -> i32`: 查询该地址上次被处理的轮次编号。

---

### `pub struct PriorityQueue` (支配树深度优先调度队列)

Phi 节点插入的工作流引擎。按支配树 depth 分桶优先处理最深处的块，确保做到正确的自底向上推进。
*   `pub fn insert(&mut self, bl: ..., depth: i32)`: 注入待处理控制块。
*   `pub fn extract(&mut self) -> Option<...>`: 弹出当前最深层的待处理块。

---

### `pub struct HeritageInfo` (单空间分析状态记录)

为每种 `AddressSpace` 持有独立的 SSA 延迟策略控制参数：
*   **`delay`**: 某些空间（如栈帧）需要推迟进行 Heritage 直到指针分析完成，此处记录推迟轮数。
*   **`deadcodedelay` / `deadremoved`**: 针对死代码清除的策略延迟参数。

---

### `pub struct LoadGuard` (LOAD/STORE 指针边界卫兵)

在对 `CPUI_LOAD`/`CPUI_STORE` 进行 Heritage 时保持地址范围约束的记录仪器。
*   包含 `pointer_base`, `minimum_offset`, `maximum_offset` 以及分析状态。

---

### `pub struct Heritage` (SSA 构造总引擎)

**本模块的绝对核心**。持有函数的弱引用 (`Weak<RwLock<Funcdata>>`)，在 `heritage()` 主入口被调用时执行 SSA 构造全程。

#### 主入口
*   `pub fn heritage(&mut self)`: **一键启动 SSA 构造**。内部执行：
    1. `place_multiequals()` — Phi 节点投放。
    2. `rename()` — SSA 版本号重命名。
    3. 递增 `pass` 计数器。

#### Phi 节点投放
*   `pub fn place_multiequals(&mut self)`: 标准的基于支配边界的 Phi 投放算法。扫描所有被写入的 Varnode，收集其定义所在的基本块，再利用支配边界 (Dominance Frontier) 传播工作列表来决定在哪些交汇块插入 `CPUI_MULTIEQUAL` 操作。

#### SSA 重命名
*   `pub fn rename(&mut self)`: 经典的基于支配树深度优先遍历的 SSA 重命名算法。维护一个按地址分组的版本栈 `stacks`，自入口块递归地用最新版本替换所有引用输入。

#### 辅助结构
*   `pub struct StackNode`: 重命名栈上的节点记录，用于 Heritage 遍历时的临时追踪。
*   `pub mod heritage_flags`: 追踪节点处理状态的预留标志位 (`BOUNDARY_NODE`, `MARK_NODE`, `MERGED_NODE`)。
