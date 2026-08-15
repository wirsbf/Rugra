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

Get or create a pointer type to the given base type

### `pub fn get_array(&mut self, array_of: Arc<Datatype>, num_elements: usize) -> Arc<Datatype>`

Get or create an array type

### `pub fn create_struct(&mut self, name: &str) -> Arc<Datatype>`

Create a new structure type

### `pub fn set_fields(&mut self, name: &str, fields: Vec<TypeField>) -> Option<Arc<Datatype>>`

Set fields for an existing structure and update its size

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


