# database.rs — Symbol database API

Rust symbol database corresponding to Ghidra's `database.hh` / `database.cc`.

**Status:** L2. The 2026-08-11 locked audit rejects the prior L3 claim:
Symbol flags use an incompatible bit namespace; `Scope::addMap`, rangemap/
usepoint selection, specialized Symbol identity, and ScopeLocal-to-Funcdata
property propagation are not equivalent. All public classes (`SymbolEntry`,
`Symbol`, `FunctionSymbol`, `EquateSymbol`, `LabSymbol`, `ExternRefSymbol`,
`UnionFacetSymbol`, `Scope`, `Database`)
are present, but API presence and Rust-only round trips are not parity evidence.

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
- `encode(encoder)` (database.cc:187): emits `<addr>` (static) or `<hash>`
  (dynamic) + a `<rangelist>` uselimit. Pieces are skipped.
- `decode(decoder)` (database.cc:206): parses `<hash>` (dynamic) or `<addr>`
  (static), then the `<rangelist>` uselimit via `decode_use_limit`.

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

### `FunctionSymbol` / `EquateSymbol` / `LabSymbol` / `ExternRefSymbol` / `UnionFacetSymbol`
Specialized symbol types. Each wraps a base `Symbol` and now implements its own
XML encode/decode, faithful to the per-subclass methods in database.cc:
- `FunctionSymbol`: `encode`/`decode` (database.cc:566/580) — `<functionshell>`
  with header, entry `<addr>`, and consume-size.
- `EquateSymbol`: `encode`/`decode` (database.cc:659/670) — `<equatesymbol>`
  with header and a `<value>` child carrying the constant.
- `LabSymbol`: `encode`/`decode` (database.cc:751/759) — `<labelsym>` with
  header and the labelled `<addr>`.
- `ExternRefSymbol`: `encode`/`decode` (database.cc:796/805) —
  `<externrefsymbol>` with header and the reference `<addr>`.
- `UnionFacetSymbol`: `encode`/`decode` (database.cc:698/708) — `<facetsymbol>`
  with header and the `field` attribute giving the union field index.

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
- `get_category_size(cat)`, `get_category_symbol(cat, ind)`,
  `set_category(id, cat, ind)`.
- `clear()`, `clear_unlocked()`.
- `attach_child(id)`, `detach_child(id)`, `num_symbols()`.
- XML encode/decode (database.cc:2616/2744):
  - `encode(encoder)` — `<scope>` with name/id/label, optional `<parent>`,
    `<rangelist>`, and a `<symbollist>` of `<mapsym>` children (each carrying a
    symbol + its `<addr>`/`<hash>` mappings).
  - `encode_recursive(encoder, only_global)` (database.cc:1371) — encodes this
    scope; the Database drives the recursive descent over its child ids.
  - `decode(decoder)` (database.cc:2744) — reads `<parent>` (skipped, applied
    by Database), `<rangelist>` / `<rangeequalssymbols>`, and a `<symbollist>`
    of `<mapsym>`/`<hole>`/`<collision>` children.
  - `add_map_sym(decoder)` (database.cc:1564) — parses one `<mapsym>`
    (symbol header + `<addr>`/`<hash>` mappings) and inserts the symbol +
    entries.
  - `decode_hole(decoder)` (database.cc:2667) — parses a `<hole>` element
    into a (Range, flags) pair.
  - `decode_collision_name(decoder)` (database.cc:2695) — parses a
    `<collision>` element's name.
  - `assign_default_names(base)` (database.cc:2850) — assigns default
    variable names to unnamed symbols via `build_default_name`.

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
- XML encode/decode (database.cc:3270/3314):
  - `encode(encoder)` — `<db>` with optional `scopeidbyname` attribute,
    `<property_changepoint>` children, then the global scope and all its
    descendants via `encode_scope_recursive`.
  - `encode_scope_recursive(encoder, scope_id)` (database.cc:1371) —
    Database-driven recursive walk over the scope map.
  - `decode(decoder)` — reads `scopeidbyname`, property change-points, and
    one or more `<scope>` elements (parent resolved via `parse_parent_tag`,
    scope created via `find_create_scope`, contents filled by `Scope::decode`).
  - `parse_parent_tag(decoder)` (database.cc:3300) — parses a `<parent>`
    element, returning the parent scope id.
  - `decode_scope(decoder, new_scope_id)` (database.cc:3375) — registers and
    fills out a single Scope from a `<scope>` (or wrapping) element.
  - `attach_scope_by_id(scope_id, parent_id)` — RUGRA-GLUE helper mirroring
    `attachScope` (database.cc:3381) for `decode_scope`.
  - `decode_scope_path(decoder)` (database.cc:3398) — decodes a namespace
    path (`<val>` children) and ensures each namespace exists.

## L3 gaps
- `ScopeInternal` name-tree (`SymbolNameTree`) for ordered name lookup.
- `partmap<Address, uint4>` for the property flagbase (currently a Vec).
- `rangemap<SymbolEntry>` / `rangemap<ScopeMapper>` for address-keyed lookup
  (currently linear search).
- Full `Datatype` integration (type_name is currently a String placeholder).
- `Funcdata` ownership in `FunctionSymbol`.

## 2026-08-13: locked category table semantics (`SCOPE-CAT0-0001`)

`Scope` now represents Ghidra's `vector<vector<Symbol *>> category` with a
`CategoryList` that keeps indexed `NULL` holes and non-owning `Weak` symbol
references. The owning `symbols` name tree remains the only category-related
owner of each `Symbol`, matching `ScopeInternal`'s destructor and
`removeSymbol` behavior.

- `get_category_size(cat)` (`database.cc:2806`) returns zero for negative or
  absent categories and otherwise returns the physical vector length,
  including interior null holes.
- `get_category_symbol(cat, ind)` (`database.cc:2814`) returns no symbol for a
  negative/out-of-range category or index and for an interior null slot; a
  populated slot returns the same `Arc` allocation, preserving pointer
  identity.
- `set_category(id, cat, ind)` (`database.cc:2824`) clears only the symbol's
  former indexed slot and removes trailing nulls without compacting interior
  holes. Category 0 converts `ind: i32` to Ghidra's `uint2` index and places the
  symbol at that exact slot, padding with nulls. Categories greater than zero
  ignore `ind` and append. Negative categories update the symbol fields but do
  not create a category table.
- The outer table grows through all intermediate categories and never shrinks
  merely because an inner list becomes empty. Removing a symbol clears and
  trims its exact category list before releasing entries and the name-tree
  owner.

The locked direct oracle fixture is
`tests/oracle/scope_category_1204.{cc,rs,metadata.json}`, run by
`tools/run_scope_category_oracle.sh`. It records oracle tag/commit,
architecture/compiler/options, canonical input fingerprint, slot-by-slot
state, symbol `(category,index)`, exact identity, ownership, destruction count,
and pinned comparand hashes. Its proof is deliberately limited to these three
category functions plus the directly observed removal/ownership closure; it
does not promote the overall database module beyond L2.

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

## 2026-07-22：Full Symbol/Scope/Database XML port (L3 completion)

Ported the remaining Symbol/Scope/Database/SymbolEntry XML serialization from
database.cc, closing the last XML gap:

**SymbolEntry** (database.cc:187/206):
- `encode` fixed to emit the `offset` attribute on `<addr>` (was `space`).
- `decode` + private `decode_use_limit` — parse `<hash>`/`<addr>` + the
  `<rangelist>` uselimit.

**Symbol subclasses** — full encode/decode per subclass:
- `FunctionSymbol::encode`/`decode` (database.cc:566/580) — `<functionshell>`.
- `EquateSymbol::encode`/`decode` (database.cc:659/670) — `<equatesymbol>` +
  `<value>`.
- `LabSymbol::encode`/`decode` (database.cc:751/759) — `<labelsym>`.
- `ExternRefSymbol` (new struct) `encode`/`decode` (database.cc:796/805) —
  `<externrefsymbol>`.
- `UnionFacetSymbol` (new struct) `encode`/`decode` (database.cc:698/708) —
  `<facetsymbol>` + `field` attribute.

**Scope** (database.cc:2616/2744/1564/2850):
- `encode` — `<scope>` + `<parent>` + `<rangelist>` + `<symbollist>` of
  `<mapsym>` children (with `rangetree_encode` helper).
- `decode` — reads `<parent>`/`<rangelist>`/`<rangeequalssymbols>`/`<symbollist>`
  (dispatching `<mapsym>`/`<hole>`/`<collision>`), via `decode_rangelist`,
  `add_map_sym`, `decode_hole`, `decode_collision_name`.
- `add_map_sym` (database.cc:1564) — parse one `<mapsym>` (symbol + mappings).
- `assign_default_names` (database.cc:2850) + `build_default_name` — default
  variable naming.

**Database** (database.cc:3270/3314/3300/3375/3398):
- `encode` enhanced: emits `scopeidbyname` attribute + drives
  `encode_scope_recursive` over the scope map.
- `decode` enhanced: reads `scopeidbyname`, property change-points with
  `offset`/`val`, and resolves each `<scope>`'s parent via `parse_parent_tag`.
- `parse_parent_tag` (database.cc:3300), `decode_scope` (database.cc:3375),
  `attach_scope_by_id` (RUGRA-GLUE for `attachScope`, database.cc:3381),
  `decode_scope_path` (database.cc:3398).
- `id_by_name` field added to the struct + wired through `new`.

Each ported function carries a `// Ghidra: database.cc:<line> <func>` comment
(84 alignment comments total). The one RUGRA-GLUE method
(`attach_scope_by_id`) is marked accordingly.

Tests: 26 database tests pass (`cargo test --lib database::`), including the
Symbol and Database encode/decode round-trips. `cargo check --lib` is clean
(0 database.rs warnings/errors).
