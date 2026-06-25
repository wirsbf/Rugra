# `tracedag.rs` API Reference

**状态**: 骨架（已禁用）
**源代码路径**: `src/tracedag.rs`

## 模块说明

Ghidra TraceDAG (blockaction.cc:499-1014) 的 Rust 移植。追踪控制流图找 likely
unstructured edges（阻止结构化的 goto 边），让剩余控制流结构化为 if/while 而非 switch。

## 导出的公共 API

### `pub fn generate_likely_gotos(graph: &BlockGraph) -> Vec<FloatingEdge>`

为函数的控制流图生成 likely goto 边。返回 (source_block_idx, dest_block_idx) 列表。

### `pub struct FloatingEdge { top: i32, bottom: i32 }`

likely goto 边：top=源块索引，bottom=目标块索引。

## 内部结构

- `TraceDAG`: 主追踪器，包含 BranchPoint/BlockTrace 向量和活跃列表。
- `BranchPoint`: 分支点（对应多出边的 FlowBlock），含 paths（子 trace 索引）。
- `BlockTrace`: 单条追踪路径，含 bottom/dest block 索引、active/terminal 状态。

## 当前限制

check_open 使用简化近似（size_in <= edgelump），select_bad_edge 选第一个活跃 trace
而非完整 BadEdgeScore 评分。需实现 visit-count 追踪和 BadEdgeScore 后才能启用。
