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

## 2026-06-26（续）：subflow.rs 完善实现

新增 SubvariableFlow 分析方法：
- `set_replacement(vn, mask)` — 注册子变量覆盖（subflow.cc setReplacement）
- `has_replacement(vn)` / `get_replacement_index(vn)` — 查询
- `create_op(opc, num_params)` / `create_op_down(opc, num_params, op)` — 创建子图 op
- `add_push(op, rvn)` / `add_terminal_patch(op, rvn)` / `add_compare_patch(rvn1, rvn2, op)` — 添加补丁
- `is_worthwhile()` — 是否值得替换（pull_count >= 2）
- `check_mask(mask, flow_bits)` — 验证掩码是有效子变量

测试：新增 4 个（set_replacement + create_op + patches_and_worthwhile + check_mask）。
