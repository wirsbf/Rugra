# `rangeutil.rs` API Reference

**源代码路径**: `src/rangeutil.rs`
**Ghidra 对应**: `rangeutil.hh` / `rangeutil.cc` (3015行)
**状态**: 📋 L1→🔧 L2（CircleRange 核心实现：构造/包含/交集/并集/迭代）

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
