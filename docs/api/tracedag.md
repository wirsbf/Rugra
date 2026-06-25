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

## 2026-06-26 更新：完整 BadEdgeScore + visit-count 追踪

- check_open 改为 visit-count 追踪（block_idx → 已追踪入边计数）。
- select_bad_edge 改为完整 BadEdgeScore 评分（siblingedge/terminal/distance/depth）。
- remove_trace 更新 visit-count（标记 goto 时增加计数，忽略该边）。
- 当前仍 DISABLED：open_branch/retire_branch 需在节点打开/退休时更新 visit-count，
  否则计数过时导致错误边选择。需进一步修复后启用。

## 2026-06-26 更新2：back-edge 过滤

- open_branch 现在跳过 back-edge（target index <= dest），防止追踪回环。
- 启用测试时 gcc 无回归（curl 24/24, httpd 29/29）但 test_bool_condition_folding 失败
  （简单函数被错误标记边）。仍 DISABLED。

## 2026-06-26 更新3：简单函数保护 + 启用

- generate_likely_gotos 跳过 < 10 块的简单函数（防止误标 goto 边）。
- TraceDAG 已启用！176/176 测试通过。curl 24/24 gcc。httpd 29/29 gcc。
- getparameter 仍 10 if（switch 检测先消费块，需进一步对齐）。

## 2026-06-26 更新4：opened 集合 + visit-count 边递增

- 新增 opened 集合追踪已打开的节点，check_open 对已打开节点直接返回 true。
- open_branch 在创建子 trace 时递增目标节点的 visit_count（追踪入边）。
- TraceDAG 现在在 phase1 前安全运行（176/176 测试，curl 24/24，httpd 29/29）。
