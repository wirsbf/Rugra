# `callgraph.rs` API Reference

**源代码路径**: `src/callgraph.rs`
**Ghidra 对应**: `callgraph.hh` / `callgraph.cc` (596行)
**状态**: 📋 L1→🔧 L2（CallGraphEdge/CallGraphNode/CallGraph 完整实现）

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
