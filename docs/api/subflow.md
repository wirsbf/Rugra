# `subflow.rs` API Reference

**源代码路径**: `src/subflow.rs`
**Ghidra 对应**: `subflow.hh` / `subflow.cc` (4589行)
**状态**: 📋 L1→🔧 L2（ReplaceVarnode/ReplaceOp/PatchRecord/SubvariableFlow 骨架已实现）

## 模块说明

子流分析：缩小携带较小逻辑值的大 Varnode。
对应 Ghidra 的 `subflow.hh`。

## 导出的公共 API

### `pub struct ReplaceVarnode`
持有较小逻辑值的 Varnode 占位符。对应 `SubvariableFlow::ReplaceVarnode`。

### `pub struct ReplaceOp`
操作较小逻辑值的 PcodeOp 占位符。对应 `SubvariableFlow::ReplaceOp`。

### `pub enum PatchType`
操作补丁类型（CopyPatch/ComparePatch/ParameterPatch/ExtensionPatch/PushPatch/Int2FloatPatch）。

### `pub struct PatchRecord`
需要修补但无流穿透的操作。对应 `SubvariableFlow::PatchRecord`。

### `pub struct SubvariableFlow`
子流分析引擎。对应 `SubvariableFlow`。
- `new(flow_size, aggressive, sext)` — 构造
- **当前限制**: traceForward/traceBackward/doReplacement 待补。

测试：subflow::tests 2 个。
