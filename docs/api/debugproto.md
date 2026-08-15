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
