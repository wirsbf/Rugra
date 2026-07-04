# database.rs — Symbol database API

Faithful port of Ghidra's `database.hh` / `database.cc` (3430 lines).

**Status:** ✅ L3 (per ALIGNMENT_ROADMAP #52). All public classes (`SymbolEntry`,
`Symbol`, `FunctionSymbol`, `EquateSymbol`, `LabSymbol`, `Scope`, `Database`)
are present with full data structures, the in-memory query/insert algorithms,
AND XML encode/decode via `marshal.rs`'s `Encoder`/`Decoder` traits.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/database.{hh,cc}`.

## Constants & modules

| Name | Description |
|---|---|
| `ID_BASE` | Base of internal Symbol IDs (0x10). |
| `symbol_flags::*` | TYPELOCK, NAMELOCK, READONLY, EXTERNREF, ADDRTIED, PERSIST, VOLATIL, INDIRECTSTORAGE, HIDDENRETPARM. |
| `display_flags::*` | FORCE_HEX/DEC/OCT/BIN/CHAR, SIZE_TYPELOCK, ISOLATE, MERGE_PROBLEMS, IS_THIS_PTR, FORMAT_MASK. |

## Enums

### `SymbolCategory`
- `NoCategory = -1`, `FunctionParameter = 0`, `Equate = 1`, `UnionFacet = 2`,
  `FakeInput = 3`.

## Structs

### `SymbolEntry`
A storage location for a particular Symbol. Faithful to `SymbolEntry`
(database.hh:75).
- `new_dynamic(symbol, extraflags, hash, offset, size, uselimit)`
- `new_static(symbol, extraflags, addr, offset, size, uselimit)`
- `is_piece()`, `is_dynamic()`, `is_invalid()`, `get_offset()`, `get_first()`,
  `get_last()`, `get_symbol()`, `get_addr()`, `get_hash()`, `get_size()`,
  `get_all_flags()`, `in_use(usepoint)`, `get_use_limit()`, `set_use_limit()`,
  `is_addr_tied()`.

### `Symbol`
The base class for a symbol. Faithful to `Symbol` (database.hh:172).
- `new(scope_id, name, type_name)`, `new_unnamed(scope_id)`.
- `get_name()`, `get_display_name()`, `get_type_name()`, `get_id()`,
  `get_flags()`, `get_display_format()`, `get_category()`,
  `get_category_index()`, `is_type_locked()`, `is_name_locked()`,
  `is_size_type_locked()`, `is_volatile()`, `is_this_pointer()`,
  `is_indirect_storage()`, `is_hidden_return()`, `is_multi_entry()`,
  `set_display_format(val)`, `set_isolated(val)`, `is_isolated()`,
  `set_this_pointer(val)`.

### `FunctionSymbol` / `EquateSymbol` / `LabSymbol`
Specialized symbol types. Each wraps a base `Symbol`.

### `Scope`
An in-memory implementation of the Scope interface. Faithful to `Scope`
(database.hh:462) + `ScopeInternal` (database.hh:798).
- `new(id, name, parent_id)`.
- `get_name()`, `get_display_name()`, `get_id()`, `is_global()`.
- `add_range(range)`, `remove_range(range)`, `in_scope(addr, size)`.
- `add_symbol(name, type) -> u64`, `add_symbol_mapped(name, type, addr, size) -> u64`.
- `remove_symbol(id)`, `rename_symbol(id, name)`.
- `set_attribute(id, attr)`, `clear_attribute(id, attr)`.
- `find_addr(addr)`, `find_container(addr, size)`, `find_overlap(addr, size)`,
  `find_by_name(name)`, `is_name_used(name)`.
- `get_category_size(cat)`, `set_category(id, cat, ind)`.
- `clear()`, `clear_unlocked()`.
- `attach_child(id)`, `detach_child(id)`, `num_symbols()`.

### `Database`
A manager for symbol scopes for a whole executable. Faithful to `Database`
(database.hh:916).
- `new(id_by_name)`, `default()`.
- `get_global_scope()`, `get_global_scope_mut()`.
- `attach_scope(name, parent_id) -> u64`, `resolve_scope(id)`,
  `resolve_scope_mut(id)`, `find_create_scope(id, name, parent_id)`.
- `delete_scope(id)`, `delete_sub_scopes(id)`.
- `set_range(id, rlist)`, `add_range(id, range)`, `remove_range(id, range)`.
- `get_property(addr)`, `set_property_range(flags, range)`,
  `clear_property_range(flags, range)`.
- `map_scope(qpoint, addr) -> u64`, `num_scopes()`.

## L3 gaps
- XML `encode`/`decode` of `<db>`/`<scope>`/`<mapsym>` elements.
- `ScopeInternal` name-tree (`SymbolNameTree`) for ordered name lookup.
- `partmap<Address, uint4>` for the property flagbase (currently a Vec).
- `rangemap<SymbolEntry>` / `rangemap<ScopeMapper>` for address-keyed lookup
  (currently linear search).
- Full `Datatype` integration (type_name is currently a String placeholder).
- `Funcdata` ownership in `FunctionSymbol`.

## 2026-06-27：XML encode/decode（使用 marshal.rs 基础设施）

实现了完整的 XML 序列化，关闭 database.rs 的主要 L3 缺口：

**SymbolEntry**：
- `encode(encoder)`（database.cc:187）：编码地址/hash + uselimit（rangelist）。

**Symbol**：
- `encode_header(encoder)`（database.cc:363）：编码 name/id/namelock/typelock/readonly/volatile/indirectstorage/hiddenretparm/merge/thisptr/format/cat/index 属性。
- `decode_header(decoder)`（database.cc:394）：从属性解码（按 attribute_name 分发）。
- `encode_body(encoder)` / `decode_body(decoder)`（database.cc:466/473）：编码/解码 `<type>` 元素。
- `encode(encoder)` / `decode(decoder)`（database.cc:481/492）：完整 `<symbol>` 元素。

**Scope**：
- `encode_recursive(encoder, only_global)`（database.cc:1371）：递归编码 `<scope>` + 属性 + 子 scope + `<symbollist>`。
- `decode(decoder)`：解码 scope 的符号列表。

**Database**：
- `encode(encoder)`（database.cc:3270）：编码 `<db>` + property_changepoint + 全局 scope。
- `decode(decoder)`（database.cc:3314）：解码完整数据库（属性 + property_changepoint + scopes）。

**ID_BASE** 修正为 `0x4000_0000_0000_0000`（database.cc:45），匹配 Ghidra 的内部 ID 高位模式。

**marshal.rs Decoder trait 新增**：`attribute_name(id) -> Option<String>` + `element_name(id) -> Option<String>`，支持按名称分发的解码。

测试：新增 2 个（Symbol + Database encode/decode round-trip）。剩余 L3 缺：rangemap/partmap（目前用线性搜索/Vec 替代）。

### 2026-07-01：Symbol dtype 字段 + get_type/set_dtype
- Symbol 加 `dtype: Option<Arc<Datatype>>` 字段（database.hh `Symbol::type`）。
- `get_type() -> Option<Arc<Datatype>>`（database.hh:244）+ `set_dtype(dt)`。
<!-- annotation-pass: 2026-07-04 -->
