# `type_system/datatype.rs` API Reference

**源代码路径**: `src/type_system/datatype.rs`
**Ghidra 对应**: `type.hh` / `type.cc` (`Datatype` 类层次)
**状态**: ✅ **L3（2026-06-28 完整对齐）**——全部 Datatype 方法覆盖（含 compare/compare_dependency/get_stripped/is_primitive_whole/print_raw）。9 单元测试。

## 模块说明

Rugra 的数据类型系统，对应 Ghidra 的 `Datatype` 类层次
（`TypeBase`/`TypePointer`/`TypeArray`/`TypeStruct`/`TypeUnion`/`TypeEnum`/`TypeCode`/`TypeSpacebase`）。
采用 `enum Datatype` + 携带各自 `TypeBase` 的变体表示。

## 2026-06-26 新增原语（解锁 varmap.cc 移植）

以下方法对应 Ghidra `type.cc` 中的算法，是 `varmap.cc` 的
`RangeHint::reconcile` / `attemptJoin` / `preferred` 所必需的：
此前缺失，导致 varmap 骨架被迫简化。

### `pub fn get_alignment(&self) -> usize`
对应 `Datatype::getAlignment` (type.hh:241)。基类型对齐由 size 经
Ghidra 默认 `size_alignment_map` (type.cc:4649) 派生：
`{0:1, 1:1, 2:2, 3:2, 4:4, 5:4, 6:4, 7:4, 8+:8}`。

### `pub fn get_align_size(&self) -> usize`
对应 `Datatype::getAlignSize` (type.hh:240) +
`TypeFactory::getPrimitiveAlignSize` (type.cc:3312)。
即 `calc_align_size(size, alignment)`。

### `pub fn get_sub_type(&self, off: i64) -> (Option<&Datatype>, i64)`
对应 `Datatype::getSubType` (type.hh:247, type.cc:174)。
返回包含 `off` 的一级组件类型及组件内偏移。
- Struct: `TypeStruct::getSubType` (type.cc:1640) 经 `getFieldIter`
- Union: 字段均从 offset 0 起
- Array: `TypeArray::getSubType` (type.cc:1234)，`newoff = off % elem.alignSize`
- 其他: 返回 `(None, off)`

### `pub fn get_hole_size(&self, off: i64) -> i64`
对应 `Datatype::getHoleSize`。
Struct: 距下一字段或结构末尾的距离 (type.cc:1652)。

### `pub fn type_order(&self, other: &Datatype) -> i32`
对应 `Datatype::typeOrder` (type.hh:283) = `compare(other, 10)`。
先比 submeta(metatype)，再比 size（小者优先，返回 `(op.size - size)`）。
varmap `RangeHint::preferred` 用其选择更具体的类型。

### `pub fn type_order_bool(&self, other: &Datatype) -> i32`
对应 `Datatype::typeOrderBool` (type.hh:916)：bool 永不被优先。

### `pub fn calc_align_size(sz, align) -> usize`
对应 `Datatype::calcAlignSize` (type.cc:536)。

### `pub fn primitive_alignment(size) -> usize`
对应 `TypeFactory::setDefaultAlignmentMap` (type.cc:4649)。

## 测试

`type_system::datatype::tests` — 9 个测试覆盖上述原语：
alignment map、calc_align_size、struct/array subtype、type_order（size & metatype）。

### 2026-07-01：is_char_print / is_piece_structured（解锁 RulePtrsubCharConstant/RulePieceStructure/Rule2Comp2Sub）
- `is_char_print()`（type.hh:218）— 检查 CHARTYPE|UTF16|UTF32|OPAQUE_STRUCT flag。
- `is_piece_structured()`（type.hh:929-935）— Struct|Union|Array 语义判断（Ghidra 用 metatype<=TYPE_ARRAY，Rugra 枚举值不同故用 matches!）。

### 2026-07-01（续）：needs_resolution/find_resolve/is_enum_type/get_stripped/equate + type_flags 对齐
- needs_resolution()（type.hh:231）、find_resolve()（type.cc:586）、is_enum_type()（type.hh:219）、has_stripped()（type.hh:229）。
- mark_equate/mark_un_equate/is_equated（Rugra 私有 EQUATED 位，Ghidra 对应 EquateSymbol）。
- type_flags 补齐 CHARTYPE/ENUMTYPE/UTF16/UTF32/HAS_STRIPPED/IS_PTRREL/TYPE_INCOMPLETE/NEEDS_RESOLUTION。
