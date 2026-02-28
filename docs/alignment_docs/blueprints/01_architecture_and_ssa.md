# Rudra 实现蓝图 01：系统架构与 SSA 变换

本蓝图详细描述了 Rudra 在底层架构、内存管理以及核心 SSA (Heritage) 变换上的实现细节。

## 1. 内存管理与节点池化 (Memory & Pooling)

Ghidra 使用 `VarnodeBank` 和 `PcodeOpBank` 管理成千上万个微型对象。在 Rust 中，我们需要平衡“安全性”与“性能”。

### Rust 实现策略：
- **Arena Allocation**: 使用 `typed-arena` 或 `id-arena` 存储 `Varnode` 和 `PcodeOp`。
- **ID 引用**：内部连接（如 Op 指向其输入 Varnode）不使用裸指针，而是使用 `VarnodeId` (newtype u32)。
- **双向链接同步**：
    - `PcodeOp` 拥有 `inputs: Vec<VarnodeId>`。
    - `Varnode` 拥有 `descendants: Vec<PcodeOpId>`。
    - 必须实现 `Funcdata::link_op_input(op, slot, vn)` 来原子化更新这两个列表。

## 2. Heritage (SSA 变换) 算法细节

这是反编译最核心的“魔法”，将 Raw P-code 转换为语义清晰的数据流图。

### 阶段 A：支配树与边界 (Dominance & Frontiers)
1. **构建 CFG**: 基于 `BRANCH`, `CBRANCH`, `RETURN` 划分基本块。
2. **计算支配器 (IDom)**: 实现 Lengauer-Tarjan 算法。
3. **计算支配边界 (DF)**: 
   ```rust
   // 为每个块 B 计算 DF(B)
   for node in blocks {
       if node.num_in() >= 2 {
           for p in node.predecessors() {
               let mut runner = p;
               while runner != idom[node] {
                   df[runner].insert(node);
                   runner = idom[runner];
               }
           }
       }
   }
   ```

### 阶段 B：Phi 节点插入 (Placement)
- 使用 `LocationMap` (对应 Ghidra 的 `disjoint` map) 维护待处理的地址范围。
- 对于每一个 `MemRange`：
    1. 收集所有写入该范围的块 `W = {b1, b2, ...}`。
    2. 使用工作队列算法在 `DF(W)` 的闭包中插入 `MULTIEQUAL` (Phi) 节点。

### 阶段 C：重命名与堆栈 (Renaming)
- 实现 `rename_recurse(block, stack_map)`：
    1. **处理本块 Phi 节点**：为 Phi 的输出分配新版本号。
    2. **处理普通 Op**：
        - 将输入 Varnode 替换为 `stack_map[addr].top()`。
        - 如果 Op 有输出，分配新版本号并 `stack_map[addr].push(new_vn)`。
    3. **更新后继块的 Phi 输入**：根据当前块在后继块输入中的索引填入对应的版本。
    4. **递归支配树子节点**。
    5. **回溯 (Pop)**：在退出块时，弹出本块产生的所有新定义。

## 3. 对齐校验点 (Sensor Alignment)

- **Input Trace**: 在 `Heritage::heritage()` 入口拦截原始 P-code 序列。
- **Dominance Check**: 拦截 `BlockGraph::calcDominance()` 后输出的 IDom 数组。
- **Phi Check**: 拦截 `Heritage::placeMultiequals()` 插入的每一个 `Varnode` ID 和块 ID。

---
*注：SSA 的版本号分配必须严格遵守 Ghidra 的遍历顺序，通常是按照 Address 升序或 P-code 原始顺序。*