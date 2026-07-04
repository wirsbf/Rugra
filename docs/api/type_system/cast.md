# `type_system/cast.rs` API Reference

## 文档状态

- **状态**: ✅ **L3（2026-07-02 完整对齐）**——全部 CastStrategyC 方法覆盖（含 is_subpiece_cast/is_sext_cast/is_zext_cast + cast_standard_full 忠实移植 cast.cc:300-392）。5 单元测试。


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
