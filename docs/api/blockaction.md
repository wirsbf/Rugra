# `blockaction.rs` API Reference (控制流结构化折叠引擎)

**源代码路径**: `src/blockaction.rs`

## 模块说明 (Module Doc)

对应 Ghidra `blockaction.hh`。在 SSA 构造和数据流优化完成后，本模块负责**将扁平的基本块有向图折叠为等价的高级控制结构**（如 `if-then-else`、`while-do`、`do-while`、`switch` 等），从而生成人类可读的反编译 C 代码。

---

## 导出的公共 API (Public API)

### `pub struct ActionBlockStructure` (控制流结构化行动)

实现 `Action` Trait。被反编译管道在后期阶段调用，执行结构化恢复：
1. 将原始 `bblocks`（基本块图）复制到 `sblocks`（结构化块图）。
2. 创建 `CollapseStructure` 引擎进行迭代折叠。

---

### `pub struct ActionNormalizeBranches` (分支规范化行动)

将非结构化的 `goto` 语句尽可能转化为 `break`/`continue` 等结构化跳转。当前为桩实现。

### `pub struct ActionFinalStructure` (最终结构清理行动)

在结构化完成后进行最后一轮清理和规范化。当前为桩实现。

---

### 内部引擎 (非公开但核心)

*   **`fn build_copy(sblocks, bblocks)`**: 将基本块图深度拷贝到结构化块图中（包括所有节点和边）。
*   **`struct CollapseStructure`**: 迭代式结构折叠引擎。反复扫描图中的模式（如两个出边的条件块 → `if-then-else`、回边 → `while` 循环）并用高级块替换原始基本块子图，直至不能再折叠为止。
    *   `collapse_all()`: 主入口，先处理条件块再迭代处理内部结构。
    *   `collapse_conditions()`: 识别 `size_out() == 2` 的块并尝试折叠为 if 结构。
    *   `collapse_internal(...)`: 迭代折叠内部结构直至达到不动点（所有块均为孤立）。
