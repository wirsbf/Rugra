# `type_system/protomodel.rs` API Reference

**源代码路径**: `src/type_system/protomodel.rs`
**Ghidra 对应**: `fspec.hh` ProtoModel (748-1100) + ParamEntry (84-155) + ParamList (425-588)

## 模块说明

调用约定原型模型。定义参数传递方式（寄存器 vs 栈、顺序、对齐、扩展）。
是参数恢复引擎（checkInputTrialUse/resolveModel/deriveInputMap）的核心依赖。

## 导出的公共 API

### `pub struct ParamEntry`
参数存储位置（寄存器或栈）。
- `contains(addr, sz) -> bool` — 是否包含给定范围
- `intersects(addr, sz) -> bool` — 是否与给定范围相交
- `is_exclusion() -> bool` — 是否独占（alignment==0）

### `pub struct ProtoModel`
调用约定模型。
- `default_x86_64()` — x86-64 System V ABI 默认模型（RDI/RSI/RDX/RCX/R8/R9 + 栈 + RAX 返回）
- `fillin_input_map(active)` — fillinMap 参数推导算法
- `derive_input_map(active)` — 调用 fillin_input_map
- `derive_output_map(active)` — 至多标记 1 个输出试验为 USED
- `possible_input_param(addr, sz, space)` — 是否可能是输入参数
- `characterize_as_input_param(addr, sz, space)` — 参数包含关系分类
- `check_input_split(addr, sz, splitpoint, space)` — 是否可分割

## 2026-06-27 移植状态

5 个单元测试。**剩余**：ParamListRegister/Merged 变体、XML decode、JoinRecord。
