# `debugproto.rs` API Reference

`src/debugproto.rs` implements Rugra's native equivalent of Ghidra's
pre-decompiler debug-import boundary. Ghidra's DWARF analyzer writes declared
function prototypes into the Program database; the C++ decompiler subsequently
receives a locked `FuncProto`. Rugra now parses concrete ELF DWARF subprograms,
follows `DW_AT_abstract_origin` / `DW_AT_specification`, preserves formal
parameter order, names, resolved scalar/pointer types and varargs, assigns
register storage from the locked `x86-64-gcc.cspec` default prototype, and
locks input/output/model state before Actions run.

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
`DW_AT_abstract_origin`), and locked zero-input `hugehelp`.  This is useful
regression evidence, but it is not a Ghidra DWARF-analyzer oracle fixture;
the importer remains `NO_ORACLE` under mechanism B2.
