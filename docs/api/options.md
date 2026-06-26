# options.rs — Architecture configuration options API

Faithful port of Ghidra's `options.hh` / `options.cc` (1063 lines).

**Status:** L1 → L2. Complete ArchOption trait + OptionDatabase dispatcher +
37 registered options. Options that modify Architecture fields (inferconstptr,
analyzeforloops, readonly, jumptablemax, maxinstruction, aliasblock, nanignore,
splitdatatype, defaultprototype) are fully functional. Print-language options
(nullprinting, conventionprinting, etc.) are stubs pending PrintLanguage
integration.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/options.{hh,cc}`.

## Free functions
- `on_or_off(p) -> bool` — parse "on"/"off"/empty string (options.cc:69).
- `get_split_datatype_bit(val) -> u32` — translate struct/array/pointer.

## Module `split_datatype_option`
- `OPTION_STRUCT = 1`, `OPTION_ARRAY = 2`, `OPTION_POINTER = 4`.

## Trait `ArchOption`
Base trait for options (options.hh:75).
- `name() -> &str`
- `apply(arch, p1, p2, p3) -> String` — modify Architecture, return message.

## `OptionDatabase`
Dispatcher for ArchOption commands (options.hh:106).
- `new()` — register all 37 built-in options.
- `set(arch, name, p1, p2, p3) -> String` — execute an option command
  (options.cc:150).
- `has_option(name) -> bool`, `num_options() -> usize`,
  `option_names() -> Vec<&str>`.

## Fully functional options (modify Architecture fields)
| Option | Field | Effect |
|---|---|---|
| `inferconstptr` | `infer_pointers` | Toggle pointer inference |
| `analyzeforloops` | `analyze_for_loops` | Toggle for-loop recovery |
| `readonly` | `readonlypropagate` | Toggle readonly propagation |
| `jumptablemax` | `max_jumptable_size` | Set max jumptable entries |
| `maxinstruction` | `max_instructions` | Set max instructions/function |
| `aliasblock` | `alias_block_level` | Set alias blocking (none/struct/array/all) |
| `nanignore` | `nan_ignore_all`/`nan_ignore_compare` | Set NaN ignore mode |
| `splitdatatype` | `split_datatype_config` | Set datatype split config |
| `defaultprototype` | `defaultfp_name` | Set default proto model |

## Stub options (pending PrintLanguage/ActionDatabase/ContextDatabase integration)
extrapop, inline, noreturn, protoeval, warning, nullprinting, inplaceops,
conventionprinting, nocastprinting, hideextensions, maxlinewidth,
indentincrement, commentindent, commentstyle, commentheader,
commentinstruction, integerformat, braceformat, setaction, currentaction,
allowcontextset, ignoreunimplemented, errorunimplemented, errorreinterpreted,
errortoomanyinstructions, setlanguage, jumpload, togglerule,
namespacestrategy.

## L3 gaps
- PrintLanguage options (nullprinting, conventionprinting, etc.) require
  PrintLanguage field access.
- ActionDatabase options (setaction, currentaction, togglerule) require
  ActionDatabase integration.
- ContextDatabase options (allowcontextset) require context integration.
- XML decode of `<optionslist>` (decodeOne/decode).

## 2026-06-27（续）：XML decode — options.rs 达到 L3

- **OptionDatabase::decode_one**（options.cc:163）：解析单个选项元素，读取最多 3 个 `<param1>/<param2>/<param3>` 子元素或元素内容作为参数，调用 `set()` 执行选项。
- **OptionDatabase::decode**（options.cc:192）：解析 `<optionslist>` 元素，对每个子元素调用 `decode_one`。
- options.rs L3 缺口（XML decode）已关闭。
