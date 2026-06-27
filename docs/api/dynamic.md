# `dynamic.rs` API Reference

**源代码路径**: `src/dynamic.rs`
**Ghidra 对应**: `dynamic.hh` / `dynamic.cc` (773行)

## 模块说明

动态哈希：为 Varnode 和 PcodeOp 生成内容寻址哈希，跨编译保持稳定。
用于 equate/重命名标注、跨编译变量识别、调试标注。

## 导出的公共 API

### `fn translate_opcode(opc) -> u32`
opcode 翻译表：将变体（ADD/SUB）映射到同一哈希值。零=跳过。

### `struct ToOpEdge`
从 Varnode 到读取它的 PcodeOp 的边。
- `compare(other)` — 排序（按地址→order→slot）
- `hash_into(reg)` — CRC 哈希折叠

### `struct DynamicHash`
哈希引擎。核心方法：
- `calc_hash_vn(root, method)` — 计算基于 Varnode 的哈希
- `calc_hash_op(op, slot, method)` — 计算基于 PcodeOp+slot 的哈希
- 静态方法：`get_slot/method/opcode/position/total_from_hash`、`clear_total_position`

## 2026-06-27 移植状态

5 个单元测试。数据结构 + transtable + calcHash 核心逻辑 + CRC 哈希 + 边排序已移植。
完整 BFS 子图扩展（gatherUnmarkedVn/gatherUnmarkedOp 多层）待后续。
