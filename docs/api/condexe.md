# `condexe.rs` API Reference

**源代码路径**: `src/condexe.rs`
**Ghidra 对应**: `condexe.hh` / `condexe.cc` (712行)
**状态**: 📋 L1（骨架已创建，ActionConditionalExe 框架已实现，完整分析待块编辑基础设施）

## 模块说明

条件执行简化。对应 Ghidra 的 `condexe.hh`。
当两个 CBRANCH 测试相同（或互补）的布尔条件时，消除冗余的路径合并。

## 导出的公共 API

### `pub struct ActionConditionalExe`
搜索并移除冗余 CBRANCH 的 Action。对应 Ghidra `ActionConditionalExe`。
- `apply(fd)`: 扫描所有基本块，寻找 iblock 候选（2 入边 + CBRANCH），尝试 ConditionalExecution 分析。
- **当前限制**: 完整分析需要块边操作（removeBlockEdge/setOut）、MULTIEQUAL 数据流回拉。骨架框架已就位，待基础设施补齐。

测试：condexe::tests 1 个（get_name）。

## 2026-06-26（续）：condexe.rs 完善实现

新增 ConditionalExecution 完整分析：
- `CondRelation` 枚举：Same/Complement/Unrelated
- `ConditionalExecution::new(iblock_index)` — 构造
- `test_iblock(fd, idx)` — 测试候选块（2入边 + CBRANCH）（condexe.cc trial）
- `find_cbranch(fd, idx)` — 查找块中的 CBRANCH op
- `verify_same_condition(init, iblock)` — 验证两 CBRANCH 是否测试同一/互补条件（condexe.cc verifySameCondition），使用 functional_equality + BOOL_NOT 检测互补
- `trial(fd)` — 完整候选分析：遍历前驱块查找 CBRANCH，验证条件关系
- `ActionConditionalExe::apply(fd)` — 扫描所有块，尝试 trial，报告找到的可简化 iblock

测试：新增 2 个（conditional_execution_creation + cond_relation_equality）。
