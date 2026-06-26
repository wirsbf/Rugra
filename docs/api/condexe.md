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
