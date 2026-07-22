# `rangeutil.rs` API Reference

**源代码路径**: `src/rangeutil.rs`
**Ghidra 对应**: `rangeutil.hh` / `rangeutil.cc` (3015行)
**状态**: ✅ **L3（2026-06-28 完整对齐）**——全部 CircleRange 方法覆盖（含 normalize/contains_range/widen/push_forward_trinary/get_max_info/set_stride）。26 单元测试。

## 模块说明

整数值范围分析工具。对应 Ghidra 的 `rangeutil.hh`。
`CircleRange` 表示模 2^n 上的半开区间 [left, right)，带可选步长。

## 导出的公共 API

### `pub struct CircleRange`
模运算整数范围。对应 Ghidra `CircleRange`（rangeutil.hh:50）。
- `empty()` / `full(size)` / `single(val, size)` / `new(left, right, size, step)` / `boolean(val)` — 构造方法
- `is_empty()` / `is_full()` / `is_single()` — 状态查询
- `contains_val(val)` — 包含检查
- `intersect(op2)` / `union(op2)` — 集合操作
- `next(val)` — 范围内迭代
- `get_size()` — 范围大小

测试：rangeutil::tests 6 个。

## 2026-06-26（续）：rangeutil.rs CircleRange 完善

新增 CircleRange 方法（对应 rangeutil.cc 完整 API）：
- `invert()` — 转互补范围（rangeutil.hh:89）
- `set_full(size)` — 设置全范围
- `push_forward_unary(opc, in1, in_size, out_size)` — 通过一元操作前推（rangeutil.hh:94）
- `push_forward_binary(opc, in1, in2, in_size, out_size, max_step)` — 通过二元操作前推（rangeutil.hh:95）
- `translate_to_op()` — 范围→比较操作转换（rangeutil.hh:99）

测试：新增 4 个（invert/push_forward_add/push_forward_copy/translate_to_op）。

## 2026-06-27：CircleRange 守卫扩展（pullBack）基础设施

新增 `CircleRange::pullBack` 所需全套方法，解锁 JumpBasic::analyzeGuards 的守卫范围扩展：

**CircleRange 方法**：
- `complement()`（rangeutil.cc:38）：取补集（仅 step==1）。
- `convert_to_boolean() -> bool`（rangeutil.cc:63）：转为布尔范围 [0,2)/[0,1)/[1,2)/空，返回是否含 0 和 1。
- `set_nz_mask(nzmask, size) -> Option<CircleRange>`（rangeutil.cc:672）：从 NZ 掩码构建范围，bit_transitions>2 返回 None。
- `pull_back_unary(opc, in_size, out_size) -> bool`（rangeutil.cc:728）：通过一元操作（COPY/INT_NEG/INT_NOT/INT_ZEXT/INT_SEXT/BOOL_NOT）反向。
- `pull_back_binary(opc, val, slot, in_size, out_size) -> bool`（rangeutil.cc:807）：通过二元操作（INT_EQUAL/NOTEQUAL/LESS/LESSEQUAL/ADD/SUB/RIGHT）反向。

**自由函数**：
- `bit_transitions(val, size) -> i32`（address.cc:818）：计算位转换次数。
- `sign_extend_size(in_val, size_in, size_out) -> u64`（address.cc:666）：字节间符号扩展。

测试：新增 11 个（complement/convert_to_boolean/set_nz_mask/pull_back_unary/pull_back_binary_add/pull_back_binary_less/bit_transitions/sign_extend_size）。

## 2026-07-16：expand_mask + pullBack SUBPIECE usenzmask 完整化

- `expand_mask(size)`（rangeutil.cc:1060 内联）：设置 mask = calc_mask(size)，供 pullBack SUBPIECE 特殊情况使用。
- `pull_back_through_op`（jumptable.rs）的 SUBPIECE usenzmask 特殊情况（rangeutil.cc:1053-1064）已补齐：当 pullBackBinary 对 SUBPIECE val==0 失败时，检查 NZMask 确认截断的字节是否为零，是则保留范围并扩展 mask。此前保守返回 None。

## 2026-06-27（续）：union 返回码修复

- **CircleRange::union** 返回码对齐 Ghidra circleUnion 语义：0=single range（在 self 中），1=two pieces（无法表示），2=full（覆盖全部）。
- 新增相邻范围合并逻辑：`op2.left == self.right` 或 `self.left == op2.right` 时合并为单一范围。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
<!-- annotation-pass: 2026-07-04 -->
**2026-07-22**: +5 CircleRange methods (newStride/newDomain/setRange)
