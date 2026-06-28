# `callgraph.rs` API Reference

**源代码路径**: `src/callgraph.rs`
**Ghidra 对应**: `callgraph.hh` / `callgraph.cc` (596行)
**状态**: ✅ **L3（2026-06-28 完整对齐）**——全部 Ghidra CallGraph 方法覆盖，含 build_edges/snip_edge/cycle_structure。8 单元测试。

## 模块说明

调用图构建与分析。对应 Ghidra 的 `callgraph.hh`。
构建程序的调用图：哪个函数调用哪个，检测环，按叶子序遍历。

## 导出的公共 API

### `pub struct CallGraphEdge`
有向边（caller→callee）。对应 Ghidra `CallGraphEdge`。

### `pub struct CallGraphNode`
函数节点（含入/出边）。对应 Ghidra `CallGraphNode`。

### `pub struct CallGraph`
调用图容器。对应 Ghidra `CallGraph`。
- `add_node(addr, name)` / `find_node(addr)` / `find_node_mut(addr)`
- `add_edge(from, to, callsite)` — 添加调用边
- `init_leaf_walk()` — 找第一个叶子（无出边）
- `num_nodes()`

测试：callgraph::tests 3 个。

## 2026-06-26（续）：callgraph.rs 完善实现

新增 CallGraph 方法（对应 callgraph.cc 完整 API）：
- `snip_cycles()` — DFS 环检测与标记（callgraph.cc snipCycles）
- `snip_cycles_dfs(addr, visited, in_stack)` — 递归 DFS 环检测
- `find_no_entry()` — 查找无入边节点（callgraph.cc findNoEntry）
- `next_leaf(addr)` — 叶子序遍历下一节点
- `clear_marks()` — 清除所有标记
- `all_addrs()` / `get_out_edges(addr)` / `delete_in_edge(addr, index)`
