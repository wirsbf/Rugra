# database.rs — Symbol database API

Rust symbol database corresponding to Ghidra's `database.hh` / `database.cc`.

## 2026-08-26：`set_symbol_flag` 驱动侧符号标志通道（MAINDIFF-STRCONST-0001）

`Scope::set_symbol_flag` / `Database::set_symbol_flag`（Ghidra 侧对应
`Symbol::decodeHeader` 的 XML 标志属性读取，database.cc:394-462）：设置/清除
Symbol 的单个 flag 位。平台分析器通过符号 XML 表达标志——ASCII 字符串分析器
的 defined Data 带锁定 char 数组类型（`ATTRIB_TYPELOCK` cc:439-442），只读
内存块中的全局量带 `Varnode::readonly`（`ATTRIB_READONLY` cc:435-438）。下游
消费：`Funcdata::spacebaseConstant` 读 `sym->isTypeLocked()`（funcdata.cc:416）
决定 PTRSUB 输出的 char 指针类型能否在后续类型传播中存活，
`Scope::queryProperties` 的 entry-hit 臂（database.cc:1273
`flags = res->getAllFlags()`）把符号位折进 readonly 答案，供
`RulePtrsubCharConstant`（ruleaction.cc:7372）与 `PrintC::pushPtrCharConstant`
（printc.cc:1709）消费。驱动侧（examples/curl_decompile.rs）对字符串地址
符号置 TYPELOCK、对 `.rodata` 全局量置 READONLY。

**Status:** L2. The 2026-08-11 locked audit rejects the prior L3 claim:
rangemap/usepoint selection, specialized Symbol identity, and
ScopeLocal-to-Funcdata property propagation are not equivalent.
2026-08-23 (DB-LOCALSCOPE-MAP-0001): the flagbase is now a faithful
`partmap<Address,uint4>` (`PartMap`), `Scope::addMap`'s flag rules
(persist / global-discovery uselimit clear / addrtied + flagbase property
fold, database.cc:1126-1155) run through `AddMapContext`, and
`symbol_flags` alias the Varnode bit values (database.hh:183 stores the
Varnode namespace on `Symbol::flags`); the threefold
`db_localscope_map_1204` oracle fixture pins the projections. All public
classes (`SymbolEntry`, `Symbol`, `FunctionSymbol`, `EquateSymbol`,
`LabSymbol`, `ExternRefSymbol`, `UnionFacetSymbol`, `Scope`, `Database`)
are present, but API presence and Rust-only round trips are not parity
evidence.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/database.{hh,cc}`.

## Constants & modules

| Name | Description |
|---|---|
| `ID_BASE` | Base of internal Symbol IDs (0x10). |
| `symbol_flags::*` | TYPELOCK, NAMELOCK, READONLY, EXTERNREF, ADDRTIED, PERSIST, VOLATIL, INDIRECTSTORAGE, HIDDENRETPARM — aliasing the Varnode bit values (varnode.hh:82-115) so `Symbol::flags` mixes with `extraflags` in one space, like `getAllFlags` (database.hh:271). |
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
- `get_sized_type(type_factory, inaddr, sz)` (database.cc:151): offset =
  dynamic ? entry offset : `(inaddr - addr) + offset`，然后调用方传入的
  Architecture-owned TypeFactory 的 canonical `get_exact_piece`
  （database.cc:161 经 `symbol->getScope()->getArch()->types` 到达同一工厂；
  Rugra 的 Symbol 不持有 Scope owner，故工厂作为显式参数传入，不建局部/全局替身）。
  2026-08-24（TYPEFACTORY-EXACTPIECE-CALLERS-0001）移除旧的
  `Datatype::get_sub_type` 本地替代路径。
- `update_type(type_factory, vn_addr, vn_size)` (database.cc:135):
  TYPELOCK 门 + `get_sized_type` 投影（C++ 原型接收 `Varnode*` 并调
  `vn->updateType(dt,true,true)`；Rust 返回解析出的 Datatype 由调用方应用）。

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
  with header and a `<value>` child carrying the constant. `new` sets
  `category = equate` (database.cc:628) and `dispflags |= format`
  (cc:630) on the wrapped base Symbol, like the C++ constructor.
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
- `add_dynamic_symbol(name, type_name, size, caddr, hash) -> u64`
- `add_map_point(symbol_id, addr, usepoint, size, ctx)` (database.cc:1548) —
  the whole-map static entry via `Scope::addMap`: persist for a global
  scope, global-discovery persist + uselimit CLEAR, then addrtied + the
  flagbase property fold at `addr` when the uselimit is empty
  (`apply_add_map_rules`, database.cc:1126-1155). `ctx: Option<&AddMapContext>`
  carries the Database lookups (`None` = standalone scope, no fold).
  (database.cc:1690) — dynamic hashed SymbolEntry.
- `add_equate_symbol(name, format, value, addr, hash) -> (EquateSymbol, u64)`
  (database.cc:1712) — builds the symbol with `category = equate`
  (database.cc:628), registers `value` on the symbol identity via
  `varnode::equate_symbol_registry::register_value` (the Rust stand-in for the
  C++ EquateSymbol subtype payload that `dynamic_cast<EquateSymbol*>`
  (varnode.cc:516) would read), runs the addSymbolInternal category-table
  registration (cc:1827-1836 via private
  `add_symbol_internal_category`, `catindex = list.size()` append), then
  pushes the 1-byte dynamic entry (database.cc:1722). Main-pipeline equates
  therefore reach `Varnode::copy_symbol_if_valid` with their value, and
  `get_category_size(equate)`/`get_category_symbol(equate, ind)` observe the
  same table state as the C++ scope.
- `clear()`, `clear_unlocked()`.
- `attach_child(id)`, `detach_child(id)`, `num_symbols()`.
- XML encode/decode (database.cc:2616/2744):
  - `encode(encoder)` — `<scope>` with name/id/label, optional `<parent>`,
    `<rangelist>`, and a `<symbollist>` of `<mapsym>` children (each carrying a
    symbol + its `<addr>`/`<hash>` mappings).
  - `encode_recursive(encoder, only_global)` (database.cc:1371) — encodes this
    scope; the Database drives the recursive descent over its child ids.
  - `decode(decoder)` (database.cc:2744) — standalone form: reads
    `<parent>` (skipped, applied by Database), `<rangelist>` /
    `<rangeequalssymbols>`, and a `<symbollist>` of
    `<mapsym>`/`<hole>`/`<collision>` children; `<hole>` properties are
    dropped and mappings install without the addMap flag rules (no
    Database side-channel).
  - `decode_with_ctx(decoder, flagbase, global_ranges)` (database.cc:2744,
    Database-integrated) — `<mapsym>` children install through the addMap
    rules with the LIVE flagbase property lookup + global discovery-range
    snapshot; `<hole>` children apply `setPropertyRange` IMMEDIATELY
    (database.cc:2778-2779 → 2683-2685) in document order — a `<hole>`
    BEFORE a `<mapsym>` feeds that mapsym's fold, one AFTER does not.
  - `add_map_sym(decoder, ctx)` (database.cc:1564) — parses one `<mapsym>`
    (symbol header + `<addr>`/`<hash>` mappings) and installs each mapping
    through `addMap(entry)` (database.cc:1602): the persist /
    global-discovery / addrtied + flagbase fold rules
    (`apply_add_map_rules`, database.cc:1126-1155) run per mapping with the
    flagbase state as of that document position; the installed entry
    carries `Varnode::mapped` extraflags (database.cc:1155/1147). For
    `<equatesymbol>` children the decode follows
    `EquateSymbol::decode` (database.cc:670-683): the `<value>` child is read
    (Rust `val`-attribute convention; an attribute-less `<value>` yields the
    database.hh:306 default 0) and the symbol identity is registered in
    `equate_symbol_registry` — mirroring the C++ `new EquateSymbol(owner)`
    (database.cc:1572-1573) whose object identity survives into
    `dynamic_cast<EquateSymbol*>`.
  - `decode_hole(decoder)` (database.cc:2667) — parses a `<hole>` element
    into a (Range, flags) pair (readonly/volatile bool attrs → the Varnode
    bits); the decode_with_ctx form forwards non-zero pairs to
    `PartMap::set_property_range` (database.cc:2683-2685).
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
- `get_property(addr)` — `flagbase.getValue(addr)` (database.hh:946).
- `set_property_range(flags, range)` — database.cc:3220-3239: split at
  `getFirstAddr`/`getLastAddrOpen`, OR `flags` into every partition
  `[addr1, addr2)` — overlapping property ranges ACCUMULATE on the shared
  partitions.
- `clear_property_range(flags, range)` — database.cc:3245-3265: same walk,
  AND `!flags` into the partitions of the sub-range only.
- `flagbase: PartMap` — the `partmap<Address,uint4>` mirror (partmap.hh:50):
  `BTreeMap<Address, u32>` split points + a default value (0,
  database.cc:2929); `get_value` (partmap.hh:83), `split` (partmap.hh:119),
  `set_property_range`/`clear_property_range` (the database.cc walks).
- `AddMapContext` — RUGRA-GLUE carrier for the two `glb->symboltab` lookups
  `Scope::addMap` needs: the flagbase property at an address
  (`getProperty`, database.cc:1153) and the global-scope discovery-range
  test (`glbScope->inScope`, database.cc:1138).
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

## 2026-08-23：equate 值注册表接线（DATABASE-EQUATE-VALUE-REGISTRY-0001）

- `EquateSymbol::new`（database.cc:624-631）补齐 cc:628
  `category = equate`：此前包装的 base `Symbol` 一直停留在 `NoCategory`，
  与 C++ 构造器状态不一致（varnodeeq 交付发现的残差）。
- `Scope::add_equate_symbol`（database.cc:1712-1724）：注册侧 base
  `Symbol` 现在设 `category = Equate`（cc:628），并在注册 `Arc` 身份上调用
  `varnode::equate_symbol_registry::register_value(&sym_arc, value)` ——
  C++ 中被注册对象本身就是携带 `uintb value` 的 EquateSymbol，
  `dynamic_cast<EquateSymbol*>`（varnode.cc:516）从同一对象身份读出
  payload；Rust 无子类型化，注册表条目即该 subtype payload 的替身，因此
  主管线（database::Scope 侧创建/解码的 equate）从此携带 value 到达
  `Varnode::copy_symbol_if_valid`。
- `Scope::add_map_sym`（database.cc:1564-1606）`<equatesymbol>` 腿：此前
  `<value>` 子元素被 `close_element_skipping` 整体跳过，解码出的 equate 既
  无值也无 equate 身份。现按 `EquateSymbol::decode`（database.cc:670-683）
  读取 `<value>`（Rust 编码侧 `val` 属性约定；无属性时取 database.hh:306
  解码构造器默认 0），并对该 `Arc` 注册 equate 身份，镜像 cc:1572-1573
  `new EquateSymbol(owner)` 的对象身份语义。真实 Ghidra XML 以元素文本
  （ATTRIB_CONTENT，`<value>66</value>`）携带值，Decoder trait 目前不暴露
  文本内容——属性化形式已覆盖 Rust 编码回环，文本形式登记为残差
  （需 marshal.rs ATTRIB_CONTENT 访问器，不在本租约 write-set）。
- 残差（如实登记）：`Funcdata::build_dynamic_symbol` 常量 equate 腿
  （funcdata.rs / funcdata_varnode.cc:1301）走 varmap ScopeLocal 模型，
  不经 `database::Scope::add_equate_symbol`，也不构造 varnode 级
  mapentry——funcdata.rs/varmap.rs 不在本租约 write-set，未接线。
- 验证：`cargo test --lib database` 59 绿（新增同值重复/跨 scope 隔离/
  XML 解码注册/copy_symbol_if_valid 通路 4 项）；oracle 行为门禁
  `tests/oracle/database_equatereg_1204`（pin-base schema2，
  `tools/run_database_equatereg_oracle.sh`）。

## 2026-08-23（补充）：addSymbolInternal 类别表注册接入 add_equate_symbol

- `Scope::add_symbol_internal_category`（私有，database.cc:1810
  `ScopeInternal::addSymbolInternal` 的类别块 cc:1827-1836）：`category >= 0`
  时按 cc:1828-1829 将外层类别向量扩张到该类别；`category > 0` 时
  `catindex = list.size()`（cc:1831-1832），类别 0 沿用符号现有 catindex 槽；
  cc:1833-1835 以 NULL 槽填充后放置 Weak 引用。
- `add_equate_symbol` 在 cc:1718 对应位置调用之：同值重复的第二个 equate
  `catindex=1`、`get_category_size(equate)=2` 与 C++ 可观察状态一致（此前
  Rust 完全不入类别表）。`add_union_facet_symbol` 存在同样缺口（本租约
  equate 限定，登记为后续 TODO）。

## 测试签名适配（2026-08-23，root）

equate-pipeline 测试随 VARNODE-COPYSYMBOL-HIGHBRANCH-0001 的关联函数签名（copy_symbol_if_valid(&Arc, &Varnode)）适配调用点，修复 opswitch 复核发现的 master lib-test 编译失败（生产代码零改动）。

## 2026-08-25：Database 级 query 通道入口 + resolvemap 分裂语义（B3-COREACTION-CONSTANTPTR-0001 a1）

- `Database::ancestor_stack(scope_id)`（database.cc:1251 的 `getParent()` 链
  物化）：从 `scope_id` 沿 `parent_id` 上溯到 global 的有序 `Vec<&Scope>`
  （`[0]` 最内层），带 parent 环护栏。这是静态 `Scope::query_*` 家族
  （`stack_container` 等）所需的「祖先栈」约定构造器——此前无生产调用方。
- `QueryContainerHit`：`queryContainer`/`queryProperties` 命中的可观察投影
  （scope_id/name、entry_addr/size/offset、symbol_id/name、`getAllFlags`、
  `type_metatype`、`base_is_char_print`、`symbol_type`）。携带
  ActionConstantPtr::isPointer（coreaction.cc:1151-1163）消费的全部字段：
  needexacthit 判据 `entry->getAddr() != rampoint`（经 `entry_addr`）与
  char-array 中部例外 `TYPE_ARRAY + base->isCharPrint()`（经
  `type_metatype`+`base_is_char_print`）。段(b) 新增 `symbol_type:
  Option<Arc<Datatype>>`（`entry->getSymbol()->getType()` 的共享句柄，
  spacebaseConstant 的 getTypePointerStripArray/typelock 折叠消费，
  funcdata.cc:413-419）；`PartialEq` derive 因 Datatype 无等价实现而移除
  （无既有相等比较调用方）。
- `Database::query_container(qpoint,addr,size,usepoint)`（database.cc:1246
  Database 级入口）：`map_scope(qpoint,addr)` 定位 base scope →
  `ancestor_stack` → 静态 `Scope::query_container` → 命中投影。
- `Database::query_properties(qpoint,...)`（database.cc:1263）：同一栈上的
  静态 `Scope::query_properties`，`flag_lookup` 直接接本库 `get_property`
  （flagbase）；三分支（entry getAllFlags / scope-only mapped|addrtied|persist|prop
  / property-only）不变。
- `Database::is_read_only(qpoint,...)`（database.cc:1796 `Scope::isReadOnly`）：
  `query_properties` 后测 `readonly` 位——ruleaction.cc:7372 /
  printc.cc:1709 的消费形态。
- `Database::query_by_name(qpoint,nm) -> Vec<QueryNameHit>`（database.cc:1198）。
- `Database::add_symbol_mapped(scope_id,nm,dtype,addr,size)`
  （database.hh:742 `Scope::addSymbol(nm,ct,addr,usepoint)` 的库级入口）：
  `AddMapContext` 接 LIVE flagbase + global 发现范围（与 `Database::decode`
  同一接线），走既有 `add_map_point`/`apply_add_map_rules` 完整 addMap 折叠
  （persist/addrtied/属性折入 symbol flags）。
- `add_map_point` 修正：整映射 entry 的 extraflags 从 0 改为
  `Varnode::mapped`（database.cc:1148-1149 `addMapInternal(symbol,
  Varnode::mapped,...)`），`getAllFlags` 现在包含 mapped 位。
- `add_range`/`remove_range` 重写为 `clearResolve`+`fillResolve` 语义
  （database.cc:3050-3077/:2871/:2897）：global scope 不入 resolvemap
  （cc:2873/:2901 早退；Rugra scope 无 fd 绑定，functional-scope 守卫为空，
  已注释）；namespace range 以 `resolve_insert_split`（ScopeResolve
  rangemap insert 的重叠分裂语义，database.hh:900）写入，新 range 接管与
  现有 owner 的重叠区，旧 owner 保留不相交余量。
- `map_scope` 修正回退语义：空 resolvemap 与未命中均回退 **qpoint**
  （database.cc:3188/:3195），不再是 global_scope_id。
- 验证：双侧 fixture `tests/oracle/cptr_query_channel_1204`（runner
  `tools/run_cptr_query_channel_oracle.sh`，oracle 12.0.4 真实执行）；
  `cargo test` 因 master 既有的 typeop.rs 测试目标编译错误在本分支同样
  不可用（本租约外），`cargo check --lib` 绿。

### 2026-08-26：findContainer 移植 + maptable 惰性索引（MAINDIFF-GLOBAL-0001）
- `Scope::find_container` 重写为 `ScopeInternal::findContainer`
  （database.cc:2250-2276）的忠实移植：签名加 `usepoint`（`inUse` 过滤在
  cc:2272 内部，stackContainer cc:952 依赖），返回值从 `Option<&SymbolEntry>`
  改为 `Option<usize>`（entries 下标，免除 stackContainer 的线性
  position 查找）。选择语义逐条对齐：窗口逆序走（cc:2267-2268
  `--res.second`）、`getLast() >= end` 包含判定（cc:2270）、严格更小
  `size < oldsize || oldsize == -1`（cc:2271）、`inUse(usepoint)`
  （cc:2272）、精确尺寸 break（cc:2274）。
- 新增 `addr_index: Mutex<AddrIndex>`：按 `(addr, 插入 seq)` 排序的
  maptable 等价物（database.hh:877-878 的 per-space rangemap）+ 前缀最大
  end 剪枝数组；所有 entries 变更点（add_map_internal/remove_symbol/
  decode/add_function_name 等）`invalidate_addr_index()` 置脏，查询时惰性
  重建——纯函数于 entries 的查询答案与 C++ 增量维护一致。`Scope` 的
  `Clone` 改手写（拷贝后脏索引，等价 C++ 拷贝构造逐条 addMap）。
- `Database::query_container_entry`（queryContainer 活入口形态）与
  `query_properties`/`discover_scope`（database.cc:1246/1263/1353）是
  `Funcdata::mapGlobals`（funcdata_varnode.cc:1701/1703）与
  `linkSymbol`（cc:1169）的查询通道。

## 2026-08-29（FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001）：inUse 三腿 + addMap 折叠接线 + same_storage_identity

- `SymbolEntry::in_use(usepoint)` 修正为 database.cc:114-120 全三腿：
  `isAddrTied()`（symbol 的 addrtied 位）恒 true；Ghidra-invalid usepoint
  （legacy spaceless Address 即 is_invalid）恒 false；否则
  `uselimit.in_range(usepoint)`。旧"空 uselimit = 全程有效"读法与 cc:118-119
  矛盾——空 uselimit 的 entry 只因 addMap 的 addrtied 折叠才有效。
- `SymbolEntry::same_storage_identity(other)`（RUGRA-GLUE）：C++
  `SymbolEntry*` 指针比较的稳定恒等代理（symbol Arc ptr_eq + addr + offset +
  size + hash），供 varnode.cc:415 `mapentry != entry` 使用。
- `Scope::add_symbol_mapped`（database.cc:1530 addSymbol 形态）与
  `Scope::add_code_label`（cc:1677 `addMapPoint(sym,addr,Address())`）都改经
  `apply_add_map_rules`（database.cc:1126-1155 addMap 折叠：persist /
  global-discovery uselimit 清空 / 空 uselimit → symbol ADDRTIED + flagbase
  property 折叠；label entry 的 extraflags 随 addMapInternal 取
  `Varnode::mapped`）。findCodeLabel 的 `inUse(addr)` 由 addrtied 腿放行。
