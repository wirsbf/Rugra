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
