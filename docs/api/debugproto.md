# `debugproto.rs` API Reference

`src/debugproto.rs` implements Rugra's native equivalent of Ghidra's
pre-decompiler debug-import boundary. Ghidra's DWARF analyzer writes declared
function prototypes into the Program database; the C++ decompiler subsequently
receives a locked `FuncProto`. Rugra now parses concrete ELF DWARF subprograms,
follows `DW_AT_abstract_origin` / `DW_AT_specification`, preserves formal
parameter order, names, resolved scalar/pointer types and varargs, assigns
register storage from the locked `x86-64-gcc.cspec` default prototype, and
locks input/output/model state before Actions run.

It also imports DWARF global variables (`DWARF-TYPE-IMPORT-0001`):
`DebugGlobalDatabase::parse_elf` walks `DW_TAG_variable` DIEs whose
`DW_AT_location` is exactly `DW_OP_addr <addr>` and records each global's
storage address, name, and resolved data type. `address_pointer_map` projects
those globals into the `Funcdata::global_struct_ptrs` seeding form: the type
of an address constant that references the global, i.e. a pointer to the
declared variable type with C array decay (0x17660 `glob_expand` →
`URLGlob **`, 0x17520 `config` → `Configurable *`, 0x17680 `glob_buffer`
→ `char *`).

## Locked libc ABI signatures (`CALLSPEC-DRIVER-0001`)

`LibcSignatureTable` is Rugra's native front-end adapter for the platform-side
signature data Ghidra ships as generic_clib: the decompile/cpp code never
parses these declarations — the Program database holds the locked `FuncProto`
for each EXTERNAL symbol, `FlowInfo::queryCall` (flow.cc:656-672) associates
the call site with it, and `ActionDefaultParams` (coreaction.cc:2322-2330)
copies the prototype onto the call site. The table encodes the same 24 public
glibc ABI declarations verbatim (glibc reserved `__`-prefixed parameter names
included) that back the external-stub rendering
(`EXTERNAL-STUB-SUPPORT-0001`).

- `LibcSignatureTable::lookup(name)` — the signature record for an imported
  symbol, `None` for anything else (unknown imports stay unlocked).
- `LibcSignatureTable::locked_proto(name, storage)` — materializes the locked
  call-site `FuncProto`: parameter storage assigned through
  `X86_64GccStorage::assign` (the locked `x86-64-gcc.cspec` resource order),
  input and output locked (`FuncProto::setPieces`, fspec.cc:3830), model left
  unlocked so `ActionDefaultParams` attaches the default model — the golden's
  "Unknown calling convention -- yet parameter storage is locked" warning is
  exactly this combination. Returns `Ok(None)` for unknown imports and `Err`
  when a listed signature cannot be represented (stack/aggregate spill).

Supporting parsers: `split_parameter_list` / `split_declaration` split the
comma-separated `TYPE NAME` declarations (the trailing identifier run is the
name, pointer stars belong to the type: `void *__ptr`), and `parse_c_type`
maps the C spellings (`void`, `char`, `int`, `long`, `size_t`, `time_t`,
`ushort`, opaque base names, pointer layers) onto `Datatype` metatype/size
pairs. Unit tests cover the 24-entry table, SYSV storage assignment
(`free`→RDI void*, `strtol`→RDI/RSI/RDX, `__ctype_b_loc`→locked void input,
`ushort **` return), and the unknown-import unlock path.

## Type resolution

`resolve_type` materializes the DWARF type graph into `Datatype` objects:

- base types map `DW_AT_encoding` onto the Rugra metatype (float/unsigned/
  boolean/int);
- pointers/references build `Datatype::Pointer` with the pointee's spelling
  (`URLGlob *`, and `URLGlob **` for pointer-to-pointer);
- `DW_TAG_structure_type`/`DW_TAG_union_type` build fielded
  `Datatype::Struct`/`Datatype::Union` from `DW_TAG_member` children (name,
  `DW_AT_data_member_location` constant or `DW_OP_plus_uconst`, resolved
  member type) — named by `DW_AT_name` without a `struct `/`union ` prefix,
  which is the spelling Ghidra's type manager prints (`Configurable *`,
  matching the 12.0.4 golden);
- `DW_TAG_enumeration_type` builds `TypeEnum` with its `DW_TAG_enumerator`
  value table;
- `DW_TAG_array_type` builds `Datatype::Array` from the first subrange's
  `DW_AT_count`/`DW_AT_upper_bound`+1 (`char *[10]`, `URLPattern[9]`);
- typedefs over composites/enums are materialized as the renamed underlying
  type (Rugra has no `TypeTypedef` variant yet — fields and enumerator names
  are carried on the renamed type);
- recursive type graphs (`FILE` → `struct _IO_FILE` → `_chain FILE *`) break
  at the back edge with a shallow named projection (name/size/metatype, no
  fields), mirroring how Ghidra's two-phase type manager exposes an
  already-created type before its members are filled.

This is the first `DWARF-PROTO-0001` closure, not a claim of complete DWARF or
prototype recovery. Cross-compilation-unit references, location-list state,
aggregate rules, stack parameters, split DWARF and non-x86 compiler specs remain
explicitly unsupported. Such a prototype is rejected instead of being assigned
approximate storage. Stripped-binary inference remains
`PARAM-RECOVERY-0001`. The module and signature pipeline therefore remain L2.

The current curl regression input has SHA-256
`4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a`.
Rust-side import tests cover `GetStr` (2 fixed parameters), `myprogress` (5),
`helpf` (1 plus varargs), the optimized `getparameter` definition (4 via
`DW_AT_abstract_origin`), locked zero-input `hugehelp`, and the five DWARF
globals of the curl fixture (`config`, `save`, `beenhere`, `glob_buffer`,
`glob_expand`) including the `URLGlob` 304-byte layout (literal char*[10] @0,
pattern URLPattern[9] @80, size int @296) and the `&global` pointer map.
This is useful regression evidence, but it is not a Ghidra DWARF-analyzer
oracle fixture; the importer remains `NO_ORACLE` under mechanism B2.

#### 会话状态（2026-08-16）
本 session 在此文件对应的 `src/debugproto.rs` 上落地了
`CALLSPEC-DRIVER-0001`（`LibcSignatureTable` 24 条 glibc ABI 签名 + 按入口地址
解析调用目标）与 DWARF 全局变量类型图（`address_pointer_map` 投影，见上文
`DWARF-TYPE-IMPORT-0001` 段落）。两者均为 front-end 适配层：Ghidra 对应行为
发生在 Program 数据库与 analyzer 侧，decompile/cpp 内无逐行对应物，因此标注为
`RUGRA-GLUE` 类桥接，不参与机制 C 核心白名单。端到端效果由
`result/curl_cur.c` 对 `tests/golden/ghidra_curl_1204.c` 的差分门禁回归
（`FUN_0` → `free`/`strdup` 调用解析与全局类型指针化在本 session 达到
byte-stable）。
