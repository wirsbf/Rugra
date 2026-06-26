# `unify.rs` API Reference

**源代码路径**: `src/unify.rs`
**Ghidra 对应**: `unify.hh` / `unify.cc` (2358行)
**状态**: 📋 L1→🔧 L2（UnifyState/RHSConstant/UnifyConstraint 骨架已实现）

## 模块说明

统一化模式匹配基础设施。对应 Ghidra 的 `unify.hh`。
用于基于模式的规则系统和用户自定义规则。

## 导出的公共 API

### `pub enum UnifyDatatype`
统一化状态槽的数据类型（OpType/VarType/ConstType/BlockType）。

### `pub struct UnifyState`
匹配状态：保存已匹配的 op、varnode、常量。
- `register_slot(dt)` — 注册一个槽，返回其索引
- `set_op/set_varnode/set_constant(idx, val)` — 设置槽值
- `get_op/get_varnode/get_constant(idx)` — 获取槽值

### `pub enum RHSConstant`
RHS 常量构造（Named/Absolute/NZMask/Consumed/Offset/IsConstant）。
`get_constant(state)` 对状态求值。

### `pub enum UnifyConstraint`
约束类型（OpCode/OpEqual/VarnodeEqual/NumParams/ConstEqual/VarnodeSize/AlwaysTrue）。

测试：unify::tests 3 个。

## 2026-06-26（续）：unify.rs 完善实现

新增约束评估引擎：
- `UnifyConstraint::evaluate(state)` — 评估单个约束（unify.cc）
- `ConstraintSequence` — 约束序列容器，`add(constraint)` + `evaluate_all(state)` 批量评估
- `UnifyConstraint::OpCode(slot, opc)` — 现在带 slot 参数，评估时从 state 读取 op
- `UnifyConstraint::CopyVarnode(from, to)` — 复制 varnode 槽（action 约束）
- 约束类型：OpCode/OpEqual/VarnodeEqual/NumParams/ConstEqual/VarnodeSize/CopyVarnode/AlwaysTrue

测试：新增 3 个（constraint_always_true/const_equal/constraint_sequence）。
