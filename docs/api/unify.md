# `unify.rs` API Reference

**源代码路径**: `src/unify.rs`
**Ghidra 对应**: `unify.hh` / `unify.cc` (2358行)
**状态**: ✅ **L3（2026-06-28 完整对齐）**——全部 Ghidra unify 方法覆盖（20 Constraint 类型 + UnifyState + UnifyCPrinter）。111 pub fn，16 单元测试，无 TODO。

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

### 2026-06-27（会话3 L1）：unify.cc 约束系统扩展

移植 8 个新约束类型（忠实于 Ghidra unify.hh/cc）：
- **OpOutput(op_idx, vn_idx)** — ConstraintOpOutput (unify.hh:361)：从 op 获取输出 varnode，存入 state
- **OpInput(op_idx, vn_idx, slot)** — ConstraintOpInput (unify.hh:335)：从 op 获取指定 slot 的输入 varnode
- **OpNotEqual(a, b)** — ConstraintOpCompare 的不等变体
- **VarnodeWritten(idx)** — 检查 varnode 是否有定义 op
- **VarnodeConstant(idx)** / **VarnodeNotConstant(idx)** — 检查 varnode 是否为常量
- **VarnodeFuncEqual(a, b)** — functional_equality 比较
- **OpOutputNoDescend(op_idx)** — 检查 op 输出无后代

新增 evaluate_mut() 方法用于动作约束（OpOutput/OpInput 需修改 state）。
4 个新单元测试：OpOutput、OpInput、VarnodeWritten、VarnodeConstant。
### 2026-06-27：unify.cc L2->L3 完整移植（unify.cc 全文）
- 从 ~460 行骨架扩展到 2415 行完整实现：43 个 struct 含完整约束层级（ConstantAbsolute/Consumed/Expression/NZMask, ConstraintOpcode/OpInput/OpOutput/Group/Or/VarCompare, UnifyState, RuleMatcher, UnifyCPrinter, TraverseGroupState/DescendState/CountState）。106 处 @// unify.cc:@ 源码标注。仅 1 处非关键 unimplemented（CPrinter 常量运算边缘）。对齐 Ghidra P-code 模式匹配框架。
<!-- annotation-pass: 2026-07-04 -->
