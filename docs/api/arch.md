# arch.rs — Architecture manager API

Faithful port of Ghidra's `architecture.hh` / `architecture.cc` (1570 lines).

**Status:** L1 → L2. The configuration container with all fields and defaults
is complete. The virtual factory hooks (`buildTranslator`/`buildLoader`/…) and
XML decode/parse methods are L3 gaps pending Translate/LoadImage/
DocumentStorage infrastructure.

This is the Ghidra `Architecture` class — distinct from `types::Architecture`
(which is the target CPU enum). It holds all configuration parameters and owns
the sub-component references.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.{hh,cc}`.

## Constants

| Name | Value | Description |
|---|---|---|
| `MAJOR_VERSION` | 6 | Decompiler major version. |
| `MINOR_VERSION` | 1 | Decompiler minor version. |
| `FLOWOPT_ERROR_TOOMANY` | 1 | FlowInfo error-on-too-many bit. |

## Module `split_datatype`
- `OPTION_STRUCT = 1`, `OPTION_ARRAY = 2`, `OPTION_POINTER = 4`.

## Traits

### `ArchitectureCapability`
Abstract extension point for building Architecture objects. Faithful to
`ArchitectureCapability` (architecture.hh:117).
- `name() -> &str`
- `build_architecture(filename, target) -> Result<Box<dyn ArchitectureBuilder>, String>`
- `is_file_match(filename) -> bool`
- `is_xml_match(doc) -> bool`

### `ArchitectureBuilder`
Provides the virtual factory hooks for sub-components. Faithful to the
protected virtual methods of `Architecture` (architecture.hh:264-348).
- `build_database()`, `build_translator()`, `build_loader()`,
  `build_pcode_inject_library()`, `build_typegrp()`, `build_core_types()`,
  `build_comment_db()`, `build_string_manager()`,
  `build_constant_pool()`, `build_context()`, `build_symbols()`,
  `build_spec_file()`, `modify_spaces()`, `resolve_architecture()`.

## Structs

### `CapabilityRegistry`
Registry of `ArchitectureCapability` extensions. Faithful to the static
`thelist` and static methods (architecture.hh:120-156).
- `new()`, `register(cap)`, `find_capability_for_file(filename)`,
  `find_capability_for_xml(doc)`, `get_capability(name)`,
  `sort_capabilities()`, `major_version()`, `minor_version()`.

### `ProtoModelEntry`
Lightweight prototype-model entry.
- Fields: `name`, `is_default`, `print_in_decl`.

### `Architecture`
Manager for all the major decompiler subsystems. Faithful to `Architecture`
(architecture.hh:165).

| Field | Type | Description |
|---|---|---|
| `archid` | `String` | Unique architecture id. |
| `trim_recurse_max` | `i32` | Parameter trim recursion limit. |
| `max_implied_ref` | `i32` | Max implied-var references. |
| `max_term_duplication` | `i32` | Max duplicated terms. |
| `max_basetype_size` | `i32` | Max integer size before array. |
| `min_funcsymbol_size` | `i32` | Min function symbol size. |
| `max_jumptable_size` | `u32` | Max jumptable entries. |
| `aggressive_ext_trim` | `bool` | Aggressive sign-ext trim. |
| `readonlypropagate` | `bool` | Treat readonly as constants. |
| `infer_pointers` | `bool` | Infer pointers from constants. |
| `analyze_for_loops` | `bool` | Convert while-do to for loops. |
| `nan_ignore_all` / `nan_ignore_compare` | `bool` | NaN handling. |
| `funcptr_align` | `i32` | Function ptr alignment bits. |
| `flowoptions` | `u32` | Flow engine options. |
| `max_instructions` | `u32` | Max instructions per function. |
| `alias_block_level` | `i32` | Alias blocking (0-3). |
| `split_datatype_config` | `u32` | Datatype split config bits. |
| `proto_models` | `ProtoModelMap` | Prototype models. |
| `defaultfp_name` | `Option<String>` | Default model name. |
| `evalfp_current_name` / `evalfp_called_name` | `Option<String>` | Eval models. |
| `nohighptr` | `RangeList` | No-high-pointer ranges. |
| `overrides` | `Override` | Override commands. |
| `loadersymbols_parsed` | `bool` | Loader symbols read. |

**Methods:** `new()`, `reset_defaults_internal()` (architecture.cc:1416),
`reset_defaults()` (architecture.cc:1438), `get_model(name)`, `has_model(name)`,
`set_default_model(name)` (architecture.cc:323), `high_ptr_possible(addr, size)`
(architecture.hh:408), `add_no_high_ptr(range)` (architecture.cc:576),
`globalify()` (architecture.cc:437), `create_model_alias(alias, parent)`,
`decode_flow_override()`, `get_description()`, `print_message(msg)`.

## L3 gaps
- Virtual factory hooks (`buildTranslator`, `buildLoader`, `buildTypegrp`, …)
  require Translate/LoadImage/TypeFactory integration.
- XML decode of processor/compiler spec (`parseProcessorConfig`,
  `parseCompilerConfig`, …).
- `AddrSpaceManager` integration (`getSpaceBySpacebase`, `getSegmentOp`).
- `DocumentStorage` for `init`/`restoreXml`.
