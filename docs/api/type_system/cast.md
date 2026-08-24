# `type_system/cast.rs` API Reference

## 文档状态

**2026-08-23 修复（GETSTR-ZERODIFF-D）**: `base_type_for` 补 `(Bool,1) => "bool"` 映射——Ghidra 比较类 op 的输出 token 是 TypeFactory 的 interned `bool` 基型（TypeOpFunc::getOutputLocal typeop.cc:365-380），旧 fall-through 把 1 字节 bool 标成 "long"。


- **状态**: ✅ **L3（2026-07-02 完整对齐）**——全部 CastStrategyC 方法覆盖（含 is_subpiece_cast/is_sext_cast/is_zext_cast + cast_standard_full 忠实移植 cast.cc:300-392）。5 单元测试。
- **2026-08-17（PRINTC-SUBPIECE-FIELDEXTRACT-0001 缺口 c）**：`is_subpiece_cast` 输入白名单补齐 PartialStruct/PartialUnion 臂（cast.cc:416-418 逐字 `inmeta!=TYPE_PARTIALSTRUCT && inmeta!=TYPE_PARTIALUNION`），输出白名单与 PTR→int 特例补 enum 映射——Ghidra `TypeEnum` 构造器（type.hh:489-494）把存储 metatype 归一为 TYPE_INT/TYPE_UINT，故 Ghidra 的 enum 输入/输出以 UINT/INT 通过白名单；Rugra `TypeMetatype::Enum` 显式列入（与本文件 check_int_promotion_for_extension/compare 的既有约定一致）。真 oracle fixture（tests/oracle/printc_subpiece_fieldextract_1204）8 条 cast 记录逐字节 MATCH，新增 2 个单元测试（partial 臂 + enum 映射）。
- **2026-08-17 审计返工（REWORK #2）**：三白名单再补 `TypeMetatype::PartialEnum`——`TypePartialEnum` 构造器（type.cc:2255-2262）委托同一 TypeEnum 构造器归一化为 TYPE_UINT，Ghidra 的 partial-enum 与 plain enum 同样全过白名单（真 oracle 实测 `cast.int_partialenum_0=1`/`cast.partialenum_out_0=1`，fixture cast sweep 8→10 条）。


**源代码路径**: `src/type_system/cast.rs`

## 模块说明 (Module Doc)

Type casting and promotion strategies

Corresponds to Ghidra's `cast.hh`. This module defines the rules
for when explicit casts are required in the output C code and how
types are promoted during arithmetic operations.

## 导出的公共 API (Public API)

### `pub trait CastStrategy`

Interface for determining when a cast is necessary

Corresponds to Ghidra's `CastStrategy` class.

### `pub struct CastStrategyC`

Standard C-language casting strategy

Corresponds to Ghidra's `CastStrategyC` class.

### `pub fn new(promote_size: usize) -> Self`

*暂无代码注释*

### `pub fn get_promote_size(&self) -> usize`

Size of the `int` data-type (size that integers get promoted to). Ghidra
`CastStrategy::promoteSize`（cast.hh:57）为保护字段，在
`CastStrategy::setTypeFactory` 中一次性赋值（`promoteSize = tlst->getSizeOfInt()`，
cast.cc:27）；Ghidra 侧消费者（cast.cc:86/182/284）均为 strategy 成员函数直接读字段，
故无访问器。Rugra 的 cast.cc:284 消费者 `is_extension_cast_implied` 落在
printc.rs（`PrintC` impl），字段私有故跨模块读取需要本访问器——纯 Rust 可见性胶水，
无自身行为（PRINTC-PTRCONST-DAT-SYMBOL-0001 M4，2026-08-25）。
钉住测试：`test_get_promote_size_matches_constructor`。

### `pub fn base_type_for(size: usize, meta: TypeMetatype) -> Arc<Datatype>`

Build a base integer/unsigned type for a given size and metatype.
Faithful to Ghidra `TypeFactory::getBase(size, metatype)` (type.cc) for
the integer cases: size 1→char/byte, 2→short, 4→int, 8→long (signed) /
ulong (unsigned). Used by input-type-local to derive the type an op
expects for its input slot (`TypeOpBinary::getInputLocal`, typeop.cc:329-333).

### `pub fn cast_standard_full(&self, reqtype: &Datatype, curtype: &Datatype, care_uint_int: bool, care_ptr_uint: bool) -> Option<Arc<Datatype>>`

Faithful 1:1 port of Ghidra `CastStrategyC::castStandard` (cast.cc:300-392).
Determines whether an explicit cast is required when a varnode of
`curtype` feeds an op expecting `reqtype`.

- Returns `Some(reqtype)` if a cast IS needed (caller inserts CPUI_CAST),
  or `None` if no cast is needed.
- `care_uint_int` — if true, distinguish signed/unsigned (under pointers);
  if false, treat int/uint interchangeably (most arithmetic ops).
- `care_ptr_uint` — if true, casting a pointer to an integer needs a cast
  (e.g. STORE value slot); if false, it's implied.

Handles: pointer-layer peeling (cast.cc:310-324), void conversion,
size-change casts (cast.cc:333-337), and the TYPE_UINT/TYPE_INT
metatype-specific same-size rules (cast.cc:339-389). Rugra's Datatype
lacks typedef chains, variable-length arrays, and per-pointer AddrSpace;
those branches are faithful no-ops.


<!-- annotation-pass: 2026-07-04 -->
