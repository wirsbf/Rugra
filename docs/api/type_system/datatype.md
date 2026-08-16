# `type_system/datatype.rs` API Reference

**源代码路径**: `src/type_system/datatype.rs`
**Ghidra 对应**: `type.hh` / `type.cc` (`Datatype` 类层次)
**状态**: 🔧 **L2（2026-08-11 锁定审计）**——submeta、派生 compare/compareDependency、alignment、Pointer spaceid/PointerRel/Spacebase/FuncProto 完整状态与 codec 尚未对齐；方法名覆盖与 Rust 单测不能支撑 L3。

## 模块说明

Rugra 的数据类型系统，对应 Ghidra 的 `Datatype` 类层次
（`TypeBase`/`TypePointer`/`TypeArray`/`TypeStruct`/`TypeUnion`/`TypeEnum`/`TypeCode`/`TypeSpacebase`）。
采用 `enum Datatype` + 携带各自 `TypeBase` 的变体表示。

## 2026-08-11 ANN-J annotation bootstrap

This pass classified eighteen previously unanchored helpers without changing
behavior:

- The `elem::{element,attribute,type_,typeref,field,void_,val,def,off,
  prototype}` helpers and `TypeXmlIdMap::{new,id_for_element,
  id_for_attribute}` are `RUGRA-GLUE`. Ghidra declares fixed global
  `AttributeId`/`ElementId` objects and registers them during static
  initialization; it has no per-thread sequential allocator. Numeric ids are
  observable in the packed protocol, so the glue is not codec `MATCH`.
- `address_to_byte_int` and `byte_to_address_int` are anchored to
  `space.hh:532/541`; they are source mappings only and still depend on
  Rugra's incomplete address-space metadata.
- `covering_mask` is anchored to `address.cc:800 coveringmask`; a locked
  runtime boundary fixture, including the high-bit case, is still absent.
- `cmp_u64` is Rust glue extracted from repeated inline id comparisons in the
  concrete Ghidra `compare` methods; there is no standalone C++ function.
- `TypeSpacebase::is_invalid` is Rust glue extracted from direct
  `localframe.isInvalid()` calls. Rugra currently treats numeric address zero
  as invalid, whereas Ghidra invalidity is a null address-space identity.

These annotations provide provenance only. They do not raise the module above
L2 or change its formal `NO_ORACLE` status.

## 2026-08-15 TYPEFACTORY-UNDEFNAME-0001（命名下游影响）

`Datatype::print_name_base`（`type.hh:273` 基类 `printNameBase`、`:424`
TypePointer、`:457` TypeArray 的枚举派发移植）本身与具体类型名无关——它取
名字首字符，因此**无行为改动**。本 TODO 改的是其输入：TypeFactory 核心未知
类型由 `xunknown1/2/4/8` 更名为数据组织命名 `undefined1/2/4/8`
（ghidra_arch.cc:349-352），于是 `print_name_base` 对未知类型输出 `'u'`，
`Scope::build_variable_name`（database.cc:2434）产出的本地变量前缀家族从
`xVar`/`axVar`/`pxVar` 变为 golden 的 `uVar`/`auVar`/`puVar`。Ghidra 侧同理：
standalone SLEIGH 架构（sleigh_arch.cc:229 的 `xunknown*`）产出 `xVar` 家族，
headless/数据组织路径产出 `uVar` 家族；Rugra 选择对齐后者（E2E 差分门禁目标）。
见 `typefactory.md` 2026-08-15 节。

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

## 2026-07-22 新增 P0：TypePartialStruct / TypePartialEnum / TypePartialUnion + TypeSpacebase 结构补齐（非完整对齐）

部分填补 `docs/alignment_audit/type_audit.md` 指出的 P0 缺口：三个 partial 子类此前完全缺失
（被 `varmap.cc`/`printc.cc`/`ruleaction.cc` 大量使用），且 `TypeSpacebase::getMap/getSubType/getAddress`
（栈帧/全局变量类型传播）未实现。本次按 `type.cc` 行号逐一忠实移植。

### 新增 TypeMetatype 变体
- `PartialStruct = 13`、`PartialEnum = 14`、`PartialUnion = 15`
（对应 Ghidra `TYPE_PARTIALSTRUCT/TYPE_PARTIALENUM/TYPE_PARTIALUNION`，type.hh:79-98）。

### `struct TypePartialStruct`（type.hh:571-585, type.cc:2330-2420）
表示从一个 struct/array 容器中按字节区间 `[offset, offset+size)` 切出的部分。
- `new(container, offset, size, stripped)`（type.cc:2330）— 断言容器为 Struct|Array，置 `HAS_STRIPPED`。
- `get_component_for_ptr(off, sz)`（type.cc:2382）— 在容器内查找容纳 `[off, off+sz)` 的字段。
- `compare` / `compare_dependency`（type.cc:2405/2415）— 先比 container 指针、再比 offset、再比 size。
- 通过 `partial_struct_get_sub_type` / `partial_struct_get_hole_size`（free 函数）接入
  `Datatype::get_sub_type` / `get_hole_size` 的 match 分派。

### `struct TypePartialEnum`（type.hh:587-595, type.cc:2247-2330）
表示枚举值的高/低字节切片：解析前将值左移 `8*offset` 位再委托给父枚举。
- `new(container, offset, size, stripped)`（type.cc:2254）— 断言容器为 Enum。
- `resolve_in_flow(val)`（type.cc:2280）— `val << (8*offset)` 后构造 `EnumRepresentation`。
- `find_resolve(val)` / `find_compatible_resolve(val)`（type.cc:2300/2315）。
- `resolve_truncation(val, skip)`（type.cc:2322）— 截断到 `size` 字节后解析。
- `has_named_value` / `get_matches` 经 `enum_has_named_value`（type.cc:1354）、
  `enum_get_matches`（type.cc:1365）实现，后者为 Ghidra 的命名恢复算法：
  贪心匹配最大命名值，并以 `val` 的按位补码作第二轮回退（`covering_mask`）。

### `struct TypePartialUnion`（type.hh:597-617, type.cc:2425-2546）
union 切片，解析延迟到流分析阶段（`needs_resolution` 恒真）。
- `new(container, offset, size, stripped)`（type.cc:2433）。
- `resolve_in_flow(val)`（type.cc:2478）— 遍历容器 union 的同偏移字段，返回首个匹配 size 的字段类型。
- `find_resolve(val)` / `find_compatible_resolve(val)`（type.cc:2500/2515）。
- `find_truncation(val, shortsize)`（type.cc:2525）— 在 union 字段中找截断匹配。
- `num_depend` / `get_depend` 经 `union_num_depend` / `union_get_depend`（type.cc:2540）
  返回容器 union 的字段列表。

### `TypeSpacebase` 完整方法（type.hh:721-746, type.cc:2935-3098）
将一个 `AddrSpace` 视作按指针偏移索引的"结构体"，用于栈帧/全局变量类型传播。
- 结构体新增字段 `spaceid: Option<AddressSpace>`、`localframe: Address`、`scope: Option<Arc<Scope>>`。
- `get_map(off)`（type.cc:2996）— 委托 `Scope::map_addr(localframe, off, ...)`；
  无 scope 时返回空（对应 Ghidra "no map ⇒ TYPE_UNKNOWN" 回退）。
- `get_sub_type(off)`（type.cc:3040）— 经 `get_map` 取组件。
- `get_address(off, sz)`（type.cc:3060）— 构造目标 `Address`。
- `compare` / `compare_dependency`（type.cc:3085/3092）— 比 spaceid/localframe。
- `new_global(address)` 便捷构造全局 spacebase；`is_invalid()` 判定 localframe 是否 INVALID。

### 依赖范围与工厂（见 `typefactory.md` / `typefactory.rs`）
- `TypeFactory::depends_of` 已覆盖三 partial 变体：PartialStruct 返回 container；
  PartialEnum 返回 parent；PartialUnion 返回 union 字段。
- `TypeFactory::typedef` 已覆盖三 partial 变体的克隆（带新 base）。
- 新增工厂 getter：`get_type_partial_struct` / `get_type_partial_enum` /
  `get_type_partial_union`（type.cc:3929/3980/3955），以 `__part{struct,enum,union}_{ptr}_{off}_{sz}`
  合成名做去重键（Rugra 平坦 map 无法像 Ghidra 树那样按结构键查找）。
- `get_type_spacebase`（type.cc:3992）。

### 测试
新增 10 个单元测试覆盖：partial struct 的 offset 切片与 compare、partial enum 的位移解析与
`get_matches`、partial union 的 `resolve_in_flow`、spacebase 的 `get_map`/`is_invalid` 行为。
<!-- partial-port: 2026-07-22 -->
<!-- annotation-pass: 2026-07-04 -->
<!-- printnamebase-port: 1783140112.9236958 -->

### 2026-08-16：`get_inheritable` 修正为锁定 oracle 语义（TYPE-WIRING 收尾）

复核 varnode_init fixture 揭出：Rust 旧实现返回
`flags & (chartype|utf16|utf32|opaque_string|enumtype)`（引 type.hh:208 的
过时行号），而锁定 12.0.4 `type.hh:233` 是 `flags & coretype`——只有
core-type 位向指针传播。已改为 `flags & CORETYPE`；工厂核心类型
（undefinedN/xunknownN）现正确传播 1。
