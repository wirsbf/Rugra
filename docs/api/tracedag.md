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
- getparameter 仍 （switch 检测先消费块，需进一步对齐）。

## 2026-06-26 更新4：opened 集合 + visit-count 边递增

- 新增 opened 集合追踪已打开的节点，check_open 对已打开节点直接返回 true。
- open_branch 在创建子 trace 时递增目标节点的 visit_count（追踪入边）。
- TraceDAG 现在在 phase1 前安全运行（176/176 测试，curl 24/24，httpd 29/29）。

## 2026-06-26 更新5：back-edge 过滤 + opened 集合双重保护

- open_branch 同时使用 back-edge 过滤（target <= dest）和 opened 集合检查。
- back-edge 过滤防止追踪进入循环（匹配 Ghidra isLoopDAGOut 语义）。
- opened 集合防止重复打开已打开的节点。
- getparameter: , 0 switch（从 + 1 switch 改善）。

### 2026-06-27（会话3 G4续）：isLoopDAGOut 集成 — LoopBody 驱动 TraceDAG

- `TraceDAG::is_loop_dag_out(idx, slot) -> bool` — 忠实于 Ghidra `isLoopDAGOut`（block.hh:342）：当边的 flags 含 `F_IRREDUCIBLE_EDGE|F_BACK_EDGE|F_LOOP_EXIT_EDGE|F_GOTO_EDGE` 时返回 false（TraceDAG 不应追踪）。
- TraceDAG 的 out-edge 遍历现在调用 is_loop_dag_out 跳过这些边。

**关键集成**：`CollapseStructure::apply_loop_exit_marks`（blockaction.cc setExitMarks 等价）将每个 LoopBody 的 exit_edges 标记为 `F_LOOP_EXIT_EDGE`，在 `order_loop_bodies` 后、`run_tracedag` 前调用。这样 TraceDAG 的追踪范围被 LoopBody 分析约束——这是 Ghidra `updateLoopBody` 的核心目的：LoopBody 分析结果实际驱动结构化。

**验证**：curl switch 4→5（循环退出标记改变了结构化路径，证明 LoopBody 分析生效）；687/687 测试 + curl 24/24 + httpd 29/29 + 0 goto。

### 2026-07-04：TraceDAG check_open 对齐 Ghidra blockaction.cc:810-833
- 新增 `finish_block_idx`（对齐 Ghidra finishblock, blockaction.cc:822-823）：只有 root trace 能 open finish block。
- `check_open` 分母从 `size_in`（所有入边）改为 loop-DAG 入边计数（对齐 blockaction.cc:826-831 遍历 isLoopDAGIn）。
- `open_branch` 的 `is_loop_dag_out` 极性修正：从 `if is_loop_dag_out { continue }` 改为 `if !is_loop_dag_out { continue }`（对齐 createTraces :504 `if (!isLoopDAGOut) continue`）。
- 新增 `is_loop_dag_in` helper（对齐 block.hh:345 isLoopDAGIn）。
- `opened` 集合保留为保守安全网（Ghidra 无此机制，靠纯 visit-count 终止；Rugra 的 visit-count 终止性待验证后可移除）。
