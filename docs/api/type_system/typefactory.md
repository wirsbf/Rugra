# `type_system/typefactory.rs` API Reference

## 文档状态

- **状态**: L2（2026-08-11 锁定审计）。当前单名称 map 不等价于 Ghidra 结构主树 + `(name,id)` 树；canonical findAdd、递归 stub 身份、exact-piece、hashSize 和严格 codec 未闭合。


**源代码路径**: `src/type_system/typefactory.rs`

## 模块说明 (Module Doc)

Type management and deduplication

Corresponds to Ghidra's `TypeFactory` class in `type.hh`. This class is responsible
for the lifecycle of all `Datatype` objects, ensuring that identical types are
deduplicated and providing a central point for type lookup.

## 导出的公共 API (Public API)

### `pub struct TypeFactory`

Managed container for all Datatype objects

### `pub fn new(ptr_size: usize) -> Self`

Create a new TypeFactory and initialize core types

# Arguments
* `ptr_size` - Default pointer size for the target architecture (e.g., 4 or 8)

### `pub fn find_by_name(&self, name: &str) -> Option<Arc<Datatype>>`

Find a type by name

### `pub fn get_ptr(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype>`

Get or create a pointer type to the given base type. Applies the
`TypePointer::calcSubmeta` needs_resolution inheritance arm
(type.cc:1051-1052): a pointer to a resolution-needing non-pointer pointee
inherits `needs_resolution` (see 2026-08-18 section below).

### `pub fn get_array(&mut self, array_of: Arc<Datatype>, num_elements: usize) -> Arc<Datatype>`

Get or create an array type. Applies the inline `TypeArray` ctor arm
(type.hh:937-944): `num_elements == 1` sets `needs_resolution` ("A varnode
which is an array of size 1, should generally always be treated as the
element data-type").

### `pub fn create_struct(&mut self, name: &str) -> Arc<Datatype>`

Create a new structure type

### `pub fn set_fields(&mut self, name: &str, fields: Vec<TypeField>) -> Option<Arc<Datatype>>`

Set fields for an existing structure and update its size (size derived from
the fields — the grammar.cc:2798 derived-newSize form). Applies the
`TypeStruct::setFields` single-field arm (type.cc:1569-1571) against
Ghidra's caller-supplied `newSize` semantics: for the grammar path (this
function's only production caller) the arm recomputes
`calc_align_size(field.get_align_size(), field.get_alignment().max(1))`
(`TypeStruct::assignFieldOffsets`, type.cc:1971-1993) and ORs
`needs_resolution` in when the single field's full `get_size()` equals it.
Comparing against the derived `max(offset + get_size())` instead would
over-fire for a field type whose `alignSize > size` (an XML-decoded
unrounded struct: Ghidra newSize 8 vs field size 5 keeps the flag clear) —
pinned by the `grammar.overfire` fixture record.

### `pub fn set_fields_sized(&mut self, name: &str, fields: Vec<TypeField>, new_size: usize, new_align: usize) -> Option<Arc<Datatype>>`

Explicit-newSize twin of `TypeFactory::setFields` (type.cc:3479-3490 /
`TypeStruct::setFields` type.cc:1563-1574): sets `size = new_size`
unconditionally and evaluates the single-field needs_resolution arm against
that EXPLICIT size. This is the only form under which the "single field
does not fill" and "offset not examined" matrix cells are reachable.
`new_align` is accepted for signature parity (Rugra `TypeBase` has no
alignment field yet).

### `pub fn num_types(&self) -> usize`

Get the number of types currently managed

### `pub fn clear_non_core(&mut self)`

Clear all non-core types

### Internal `insert`

Annotation anchor: `type.cc:3390 TypeFactory::insert`.

This is a known `MISMATCH`, not completed coverage. Ghidra inserts into the
structural `DatatypeSet tree`, rejects a duplicate comparator key with a
`LowlevelError`, and adds non-zero-id types to the separate `nametree`
cross-reference. Rugra currently overwrites one
`BTreeMap<String, Arc<Datatype>>` entry by name. It therefore loses structural
canonicalization, the `(name,id)` index, duplicate failure behavior, and
multiple distinct unnamed/eponymous types.



### 2026-07-01：get_base(size, metatype)（type.cc:3631-3660）
- 按 (size, metatype) 查 core_types（int→int/int2/int8, uint→uint/uint2/uint8, float→float/double），未命中则现场创建 Base type。

### 2026-07-01（续）：补全 14 个 TypeFactory 工厂方法
get_type_void/char/unicode、get_type_union+set_union_fields、get_type_enum+set_enum_values、get_type_code、get_type_pointer_rel、get_typedef、resize_pointer、find_by_id/find_by_id_local、concretize/deconcretize、hash_size。+rel_pointers/typedefs 侧表字段。18 新测试。
<!-- annotation-pass: 2026-07-04 -->

**2026-07-22 (printc batch 2)**: +3 TypeFactory methods to support
`PrintC::docTypeDefinitions` (printc.cc:2401) dependency-ordered type emission:

- `dependent_order(&mut Vec<Arc<Datatype>>)` — type.cc:3563
  `TypeFactory::dependentOrder`. Iterates the type tree (BTreeMap, sorted by
  name = matches Ghidra's `tree` ordered set) and recursively orders each via
  `order_recurse`. Output excludes nothing — callers filter core types.
- `order_recurse(deporder, mark, ct)` — type.cc:3545
  `TypeFactory::orderRecurse`. Visits typedef target first, then each
  `getDepend(i)` for `i in 0..numDepend()`, then pushes `ct`. Cycle-break via
  insert-second-check on a `HashSet<usize>` (Arc pointer identity, mirroring
  Ghidra's DatatypeSet pointer-identity semantics).
- `depends_of(ct)` — RUGRA-GLUE aggregator of Ghidra's per-variant
  `Datatype::numDepend` + `Datatype::getDepend` virtual dispatch table
  (type.hh:261 base; overrides 422 Pointer, 455 Array, 526 Struct, 555 Union,
  629 Code). C++ uses virtual dispatch; Rust matches on the Datatype enum.

## 2026-08-11 ANN-J annotation bootstrap

`TypeFactory::insert` received its real locked-source start line only. No
behavior changed, no runtime oracle was added, and the method/module remains
L2 with formal status `NO_ORACLE`; the annotation must not be interpreted as
`MATCH`.

## 2026-08-13 TYPE-UNKNOWN-0001

`TypeFactory::get_base(size, TypeMetatype::Unknown)` now preserves the
targeted canonical object semantics of locked Ghidra 12.0.4
`TypeFactory::getBase(int4,type_metatype)` (`type.cc:3631`):

- sizes 1, 2, 4, and 8 resolve to the SLEIGH core types `xunknown1`,
  `xunknown2`, `xunknown4`, and `xunknown8`, with the exact Ghidra name hash,
  core flag, size, and metatype;
- other in-range sizes resolve to one unnamed, id-zero, non-core `TypeBase`
  per `(size, metatype)`, enter the factory's atomic structural registry, and
  repeated requests return the same `Arc`;
- `get_base_named` mirrors the named overload at `type.cc:3667`: it hashes the
  name, canonicalizes repeated equivalent requests, and rejects a conflicting
  same-name definition with Ghidra's error text.

The direct runtime fixture is `tests/oracle/type_unknown_1204.{cc,rs}` and the
gate is `tools/run_type_unknown_oracle.sh`. It compares fixed-order JSON
byte-for-byte for type properties, repeated pointer identity, cross-size
non-identity, named identity, the collision error, anonymous structural order,
and `clearNoncore` removal plus post-clear repeated-recreation identity. The
fixture intentionally does not compare a Ghidra pointer retained across
`clearNoncore`: Ghidra deletes that object, whereas a cloned Rust `Arc` would
keep it alive, so external-old-handle lifetime/identity remains `UNTESTED`.
The Rust closure is a verified
archive of commit `6e373f08f42fd5d3b0a02d282d4245c046387558` with only the owned
`src/type_system/typefactory.rs` snapshot overlaid, so unrelated live source
churn cannot change the comparand. The runner also materializes curl and every
SLEIGH/spec input from verified blobs at provenance commit
`34a3febff160031c265cfbd841a94022c68c2c19`; it never reads the live
`examples/curl` or spec worktree and does not require runtime HEAD equality.

This closes only the observed unknown atomic-base slice. The module remains
L2: sizes above `Architecture::max_basetype_size` (array-of-unknown-byte
conversion), decode/cache rebuilding, Address/Varnode consumers, and the
general pointer/array/aggregate structural registry remain unproved. The
latter is the existing `TYPE-0001` mismatch; atomic ordering evidence must not
be read as proof that the whole TypeFactory tree is aligned.

## 2026-08-15 TYPEFACTORY-UNDEFNAME-0001

`TypeFactory::init_core_types` now names the four core TYPE_UNKNOWN base types
`undefined1/undefined2/undefined4/undefined8` (was `xunknown1/2/4/8`),
following the Ghidra data-organization registration
`ArchitectureGhidra::buildCoreTypes` (`ghidra_arch.cc:349-352`:
`setCoreType("undefined",1,TYPE_UNKNOWN,false)` … `"undefined8"`). The id
remains `Datatype::hash_name(name)` per the named `getBase` overload
(`type.cc:3667-3673`), so ids change with the name exactly as in Ghidra. The
canonical headless oracle output uses this family (`undefined8`, `undefined2`
casts, and via `Datatype::printNameBase` (`type.hh:273`, first character of
the name) the `uVar`/`auVar`/`puVar` prefixes; cf.
`tests/golden/ghidra_curl.c` `undefined1 auVar21 [24];`).

Ghidra itself has two legitimate registration flavors and this rename chooses
the headless/data-organization one deliberately:

- `ArchitectureGhidra::buildCoreTypes` (ghidra_arch.cc:349-352) —
  `undefined*`, the flavor the E2E diff gate targets;
- `SleighArchitecture::buildCoreTypes` standalone else-branch
  (sleigh_arch.cc:229-232) — `xunknown*`, the flavor the standalone console /
  direct-runner goldens (`tests/golden/ghidra_{curl,httpd}_1204.direct-runner.c`)
  and the `type_unknown_1204` oracle harness (BfdArchitecture) observe.

Consequences, registered under `TYPEFACTORY-UNDEFNAME-0001`:

- the 2026-08-13 `type_unknown_1204` recorded MATCH is superseded: its Ghidra
  side runs the SLEIGH standalone fallback, so re-running the gate against the
  renamed factory now yields a name/id MISMATCH on the four core unknowns
  (structural identity, anonymous ordering, and clear/recreate behavior are
  unaffected). This is a registered inter-flavor divergence — Rugra has one
  factory default rather than per-architecture core-type registration — not a
  port defect of `getBase` itself;
- the `xVar` prefix family disappears for every name sourced from the factory;
  `VarnodeBank`'s bank-local default adapter (`src/varnode.rs`
  `unknown_datatype`, `TYPE-UNKNOWN-0001`) still produces `xunknown{size}`
  names and is out of this change's write-set.

## 2026-08-17 CSPEC-TYPEORG-STATE-0001

`TypeFactory` now persists the `<data_organization>` state Ghidra keeps in
its private members (`type.hh:763-771`), replacing the previous
return-only snapshots:

- New private fields `size_of_int/long/char/wchar/pointer/alt_pointer`,
  `enum_size`, `enum_type`, `align_map` — zeroed at construction exactly as
  `TypeFactory::TypeFactory` (type.cc:3106-3119). Public snapshot getters
  `get_size_of_int/long/char/wchar/pointer/alt_pointer` mirror the inline
  accessors at type.hh:813-818.
- `decode_data_organization` (type.cc:4583-4615) stores the five consumed
  size children into the fields; every other child
  (`machine_alignment`, `short_size`, `float_size`, ...) is
  closed-and-skipped. No defaulting happens at decode: an absent
  `<char_size>` leaves `size_of_char == 0` until `setup_sizes`. The
  `<size_alignment_map>` branch falls through to the unified
  `close_element(sub_id)` exactly as the oracle's sam branch falls to
  `closeElement` (type.cc:4604-4612), so children *after* the map are
  still consumed (review-rework fix: a stray `continue` used to leave the
  TreeDecoder stack on the map element and silently drop trailing
  children).
- `decode_alignment_map` (type.cc:4619-4641) fixed three divergences:
  index 0 now keeps the `-1` fill sentinel (unless an explicit
  `<entry size="0">` exists), an empty `<size_alignment_map>` leaves the
  map empty (the default install belongs to `setup_sizes`, and no invented
  exception), and duplicates let the later entry win as in the oracle.
- `set_default_alignment_map` (type.cc:4644-4656) now applies
  `resize(9, 0)` semantics, so the default map is
  `[0,1,2,2,4,4,4,4,8]` — index 0 is 0, not 1.
- `setup_sizes(arch: &SizeArchInputs)` (type.cc:3137-3170) applies the
  full default derivation 1:1 (int from the stack spacebase clamped to 4,
  long via `(int==4) ? 8 : int`, char 1, wchar 2, pointer from the default
  data space, far-pointer `alt_pointer`, default map, enum defaults).
  Because Rugra's factory has no `glb` Architecture handle yet, the
  `glb->getStackSpace()/getDefaultDataSpace()/getSegmentOp()/getDefaultSize()`
  lookups are passed in as `SizeArchInputs` (RUGRA-GLUE).
- New readers `get_alignment(u32) -> Result<i32, String>` (type.cc:3296;
  verbatim `LowlevelError("TypeFactory alignment map not initialized")`
  text, last-entry fallback for sizes at/beyond the map end) and
  `get_primitive_align_size(u32)` (type.cc:3312; unsigned 32-bit modulo
  semantics, so a `-1` alignment behaves as `0xFFFFFFFF`).
- `parse_enum_config` (type.cc:4662-4672) is now an instance method that
  stores `enum_size`/`enum_type` instead of returning a tuple.

Oracle evidence: `tests/oracle/cspec_typeorg_state_1204.{cc,rs,metadata.json}`
+ `tools/run_cspec_typeorg_state_oracle.sh` — the locked 12.0.4 oracle
(production `BfdArchitecture::init` chain plus seven synthetic
`<data_organization>` documents) and the Rust comparand emit
byte-identical state projections (`DECLARED_OBSERVATIONS_MATCH`,
expected_stdout_sha256 locked in metadata). Residuals (UNTESTED/MISMATCH)
are registered in the metadata `coverage` block: enum state is private in
the oracle (no getters), live Architecture input derivation is unwired on
Rust, ill-formed non-entry map children diverge (unreachable via
well-formed specs), zero-alignment primitive queries abort on both sides.

## 2026-08-16 TYPE-WIRING-0001

The dual-track unknown typing is closed: `VarnodeBank`'s bank-local
`xunknown{size}` adapter no longer exists, so every production Varnode /
RangeHint / symbol unknown type now resolves through a `TypeFactory`.

- `TypeFactory::shared_default()` (`typefactory.rs`) models the locked
  headless oracle's single Architecture: Ghidra builds exactly one
  `TypeFactory` per `Architecture` (`TypeFactory::TypeFactory(Architecture*)`,
  `type.cc:3106-3119`) and the headless oracle runs one Architecture per
  process. Production Rugra `Funcdata` does not yet carry an attached
  Architecture (`FUNCPROTO-MODEL-BIND-0001` chain), so factory-less callers
  resolve this process-wide DataOrg-flavor canonical instance. An explicitly
  injected handle (`VarnodeBank::set_type_factory`, `fd.arch.types` in
  `ScopeLocal::restructure_varnode`) always wins, reproducing Ghidra's
  per-Architecture channel.
- `TypeFactory::concretize` now routes its TYPE_CODE→unknown substitution
  through `get_base(1, TYPE_UNKNOWN)` (`type.cc:4147`) instead of minting a
  fresh `undefined1` object; repeated calls return the same factory `Arc`,
  and the RUGRA-GLUE `deconcretize` inverse still recognizes the core
  `undefined1` spelling.
- Residual: Ghidra's `ScopeLocal::createEntry` wraps multi-element symbols
  via `glb->types->getTypeArray` (`varmap.cc:625`); Rust has no
  `TypeFactory::getTypeArray` yet, so the array shell is still built locally
  around the factory-owned element type (factory array dedup identity
  remains unproved).

## 2026-08-18 TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001

The complete `needs_resolution` setting matrix is now mirrored on every
TypeFactory creation path, closing the audit gap where Rugra never produced
a single-field `needsResolution` struct (the SUBPIECE findResolve write-side
producer):

- `set_fields` — `TypeStruct::setFields` single-field arm
  (type.cc:1569-1571): ORs the flag in (never cleared) when exactly one
  field's full `get_size()` equals the caller-supplied `newSize`. Rugra's
  arm recomputes the grammar-path newSize
  (`calc_align_size(field.get_align_size(), field.get_alignment().max(1))`,
  `assignFieldOffsets` type.cc:1971-1993) instead of comparing against the
  derived `max(offset + get_size())`, which would over-fire for a field type
  with `alignSize > size` (XML-decoded unrounded struct) — pinned by the
  `grammar.overfire` record.
- `set_fields_sized` (new) — explicit `newSize`/`newAlign` twin of
  `TypeFactory::setFields` (type.cc:3479-3490): `size = new_size`
  unconditionally, single-field arm against the EXPLICIT size. Proves the
  "not fills" (explicit size > field size → 0) and "offset not examined"
  (single field @4 whose type size == newSize → 1) cells.
- `decode_struct` — the full `TypeStruct::decodeFields` acceptance loop
  (type.cc:1839-1870) plus tail (1871-1877): per-field void-metatype throw,
  strictly-lower-offset order throw, overlap throw-out (the dropped field is
  observable via the surviving field count and feeds the single-field arm),
  does-not-fit throw — all four LowlevelError texts verbatim; tail leaves
  the factory type `type_incomplete` iff it ended with zero fields (the
  decodeStruct→`TypeFactory::setFields` transfer, type.cc:4350-4356 +
  3487-3488) and sets the single-field arm against the decoded `size`
  attribute.
- `get_ptr` / `get_type_pointer` / `get_type_pointer_rel` /
  `resize_pointer` / decode pointer branch — `TypePointer::calcSubmeta`
  inheritance arm (type.cc:1051-1052, run by every Ghidra `TypePointer`
  ctor): pointer to a resolution-needing pointee inherits the flag, never
  through a second pointer level. Consumers waive `TYPE_PTR` at every
  needsResolution rejection (printc.cc:1962), so the flag on pointers
  changes no resolved type — it makes the waiver load-bearing, as in Ghidra.
- `get_array` — inline `TypeArray` ctor size-1 arm (type.hh:937-944).
- decode array branch — `TypeArray::decode` `arraysize == 1` arm
  (type.cc:1341-1342) plus the `arraysize<=0 || arraysize*alignSize != size`
  validation (type.cc:1338-1339, "Bad size for array of type"), plus a real
  bug fix: the branch now `rewind_attributes()` after `decode_basic` before
  reading `arraysize` (type.cc:1331) — previously the attribute loop had
  consumed the element and every decoded array errored "Bad size for array
  of type".

Scope notes: calcSubmeta's SUB_PTR/SUB_PTR_STRUCT reclassification and the
ctors' `flags = ptrto->getInheritable()` (coretype inheritance, type.hh:413)
are not yet modelled (no sub_metatype field on `TypePointer`); only the
needs_resolution arm is mirrored. `set_fields`'s stored `st.base.size` stays
the derived `max(offset + get_size())` (can differ from Ghidra's
align-rounded grammar newSize for trailing padding; plumbing the explicit
size from the grammar caller is a registered follow-up in grammar.rs's
domain).

Oracle evidence: `tests/oracle/typefactory_needsres_1204.{cc,rs,metadata.json}`
+ `tools/run_typefactory_needsres_oracle.sh` — 27 records
(set/grammar/dec/arr.factory/ptr/union.setfields + grammar.regressions
[overfire + nested], ptr.ordering [stub-time pointer never inherits; cached
pointer stays clear; differently-sized new pointer inherits],
dec.acceptance [overlap throw-out ×2, empty size-8 and size-0 incomplete
residue], dec.err [order/fit/void/name-empty/name+void-precedence verbatim
error texts]), real locked-12.0.4 oracle vs Rugra byte-identical
(`records=27 … MATCH`), expected stdout sha256 locked in metadata. E2E curl
output byte-identical to the pre-change baseline (diff 0 lines;
differential gates defects=0/numbering=0 on both
`tests/golden/ghidra_curl.c` and `result/ghidra_curl_12.0.4.c`), confirming
the activated flag paths have no observable E2E effect on the current corpus
(all pointer consumers waive TYPE_PTR; no curl-parsed single-field struct
reaches the SUBPIECE walk). The printc_subpiece fixture's Rust-side manual
flag on `fixture_inner` is now reclaimable (root noted: not urgent).


