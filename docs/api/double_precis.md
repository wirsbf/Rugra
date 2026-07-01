# `double_precis.rs` API Reference

**源代码路径**: `src/double_precis.rs`
**Ghidra 对应**: `double.cc` (双精度合并子系统, ~1000行)
**状态**: ✅ **L2.5（2026-07-01 核心算法 1:1 移植完成）**——SplitVarnode 核心 + 4 Rule 完整移植 + 21 单元测试。已注册进 oppool1(5643-5646)。

## 模块说明

双精度合并（double-precision merge）：检测被拆成两半的 Varnode（成对的 LOAD/STORE/
COPY），在数据流允许时合并为单一宽类型操作。对应 Ghidra `double.cc` 的 `SplitVarnode`
与 `RuleDouble*` 系列。

## 导出的公共 API

### `SplitVarnode` (double.cc)
表示一个被拆成 hi/lo 两半的 Varnode，用于检测可合并的成对操作。
Ghidra `SplitVarnode` 类的 1:1 移植（~50 方法）。
- `from_constant` / `from_pieces` — 从常量/PIECE 构造
- `init_partial_const` / `init_partial_pieces` / `init_all` — 初始化
- `in_hand_*` — 手牌查询（是否有 hi/lo/whole）
- `find_whole_split_to_pieces` / `find_definition_point` / `find_earliest_split_point`
  / `find_whole_built_from_pieces` — 定义点查找
- `is_whole_feasible` / `is_whole_phi_feasible` — 合并可行性
- `find_create_whole` / `find_create_output_whole` / `create_joined_whole` — 合并创建
- `build_lo_from_whole` / `build_hi_from_whole` — 从整体重建半部
- `adjacent_offsets` — 指针相邻判断
- `test_contiguous_pointers` — **核心**：成对 LOAD 指针连续性检测 (double.cc)
- `is_addr_tied_contiguous` / `is_addr_tied_contiguous_result`
- `verify_mult_neg_one` — MULT(-1) 校验
- `whole_list` / `find_copies` / `get_true_false`
- `prepare_*` / `create_*` / `replace_*` op builders
- `apply_rule_in` — opcode 分派骨架（*Form 子类依赖 block 级控制流，标 TODO）

### `SplitDatatype`
结构体/数组拆分辅助类型（与 subflow.rs 共用）。halves 分析。

### oppool1 Rule (coreaction.cc:5643-5646)
- `RuleDoubleLoad` (double.cc:3442) — PIECE，双 LOAD 合并
- `RuleDoubleStore` (double.cc:3513) — STORE，双 STORE 合并
- `RuleDoubleIn` (double.cc:3259) — CALLOTHER (double-in)
- `RuleDoubleOut` (double.cc:3332) — CALLOTHER (double-out)

### 辅助函数
`get_space_from_const` / `is_addr_tied_contiguous` / `parent_block` /
`is_arithmetic_op` / `is_floating_point_op` / `make_space_varnode` / precis-flag helpers。

## 基础设施缺口（已标注 TODO，未绕过）
- `*Form` 类（AddForm/SubForm/…, double.cc:1433-3196）——依赖 block 级控制流（dominance、
  CBRANCH flip），Rugra 缺。`apply_rule_in` 为骨架返回 0；4 Rule + SplitVarnode 核心非 stub。
- 缺失 Rugra 原语：`newVarnodeIop` / `combineInputVarnodes` / `hasUnreachableBlocks`。

## 测试
21 单元测试：`adjacent_offsets`（const-const/const-vs-nonconst/INT_ADD-from-common-base）、
`test_contiguous_pointers`（LE two-loads/mismatched-spaces）、`is_addr_tied_contiguous`（LE/gap/not-addr-tied）、
`init_partial`（implied-zero-hi/two-constants）、`exceeds_const_precision`、`verify_mult_neg_one`、
`SplitDatatype` halves、4 Rule（触发 + 拒绝路径）、rule-registration surface。

### 2026-07-01（续）：TODO 替换 — iop-space 基础设施接入
- replace_indirect_op / reassign_indirects：iop 输入从 `new_constant(8,0)` 占位改为 `fd.new_varnode_iop(&op)`（double.cc:1386/3643）。
- build_lo/hi_from_whole INDIRECT 分支：用 `fd.get_op_from_const(in1)` 解析 affector，op_uninsert→transform→op_insert_after（double.cc:602-648）。
- no_write_conflict / test_indirect_use：iop varnode 精确配对（affector==op1/op2），替代保守 return None（double.cc:3406/3598）。
- *Form 类族（依赖 block 级控制流）保留 TODO。

### 2026-07-01（续 2）：*Form 类完整移植（double.cc:1104-3196）
13 个 Form 类全部 1:1 移植：AddForm/SubForm/LogicalForm/Equal1-3Form/LessThreeWay(13方法)/LessConstForm/ShiftForm/MultForm(9方法)/PhiForm/IndirectForm/CopyForceForm。SplitVarnode::apply_rule_in 调度器按 opcode 映射到 Form（double.cc:1090-1232）。各 Form 的 verify/apply_rule 完整实现，非 stub。
