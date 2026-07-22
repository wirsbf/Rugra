# options.rs — Architecture configuration options API

Faithful port of Ghidra's `options.hh` / `options.cc` (1063 lines).

**Status:** L3. Complete `ArchOption` trait + `OptionDatabase` dispatcher +
38 registered options (one per `OptionXxx` subclass in `options.cc`).
Every option carries a `// Ghidra: options.cc:<line>` alignment comment.
Options that target subsystems present in rugra (flow flags, prototype
models, alias blocks, etc.) mutate real `Architecture` state. Options that
target subsystems not yet ported (PrintLanguage emitter, ActionDatabase
group manipulation, ContextCache) return the faithful Ghidra confirmation
message and are tagged `// RUGRA-GLUE:`.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/options.{hh,cc}`.

## Free functions
- `on_or_off(p) -> bool` — parse "on"/"off"/empty string. Faithful to
  `ArchOption::onOrOff` (options.cc:69). Empty defaults to true.
- `parse_int_any_base(s) -> Option<i64>` — replicate `std::istringstream`
  basefield-reset semantics: `0x..`→hex, leading `0`→octal, else decimal.
  Sign aware. `// RUGRA-GLUE` (no Ghidra counterpart; C++ uses streams).
- `parse_uint_any_base(s) -> Option<u64>` — unsigned variant.
- `alias_block_flag(name) -> Option<i32>` — symbolic token → alias-block bit
  (struct=1, array=2, global=4, param1..param12, all, none). Mirrors the
  inline bit mapping in `OptionAliasBlock::apply` (options.cc:982-995).
- `get_split_datatype_bit(name) -> u32` — float/pointer → split-datatype bit.

## Module `split_datatype_option`
- `OPTION_FLOAT: u32 = 1`, `OPTION_POINTER: u32 = 2`. `// RUGRA-GLUE` bit
  constants used by `OptionSplitDatatypes::apply` (options.cc:999).

## Module `elem_ids`
`<optionslist>` XML element ids. `// RUGRA-GLUE` — Ghidra registers these
via the runtime ElementId registry (options.cc:23-63); rugra holds them as
plain `u32` constants because the `Decoder` trait keys off integer ids.
- `ELEM_OPTIONSBODY = 174`, `ELEM_OPTIONSHEAD = 175`, `ELEM_OPTIONSLIST = 176`,
  `ELEM_PARAM1 = 177`, `ELEM_PARAM2 = 178`, `ELEM_PARAM3 = 179`.

## Trait `ArchOption`
Base trait for options (options.hh:75).
- `name() -> &str`
- `apply(arch, p1, p2, p3) -> String` — modify Architecture, return message.

## `OptionDatabase`
Dispatcher for ArchOption commands (options.hh:106). The C++ class keys its
map by element id (`uint4`); rugra keys by name string because the `Decoder`
trait resolves element ids to names.
- `new()` / `default()` — register all 38 built-in options in the order
  Ghidra's constructor uses (options.cc:96-133).
- `register<O: ArchOption>(opt)` — insert one option. Mirrors
  `registerOption` (options.cc:84).
- `set(arch, name, p1, p2, p3) -> Option<String>` — execute an option
  command. Faithful to `OptionDatabase::set` (options.cc:150). Returns
  `None` for unknown options (Ghidra throws `ParseError`).
- `try_set(...) -> Result<String, String>` — non-panicking variant
  (`// RUGRA-GLUE`).
- `has_option(name) -> bool`, `num_options() -> usize`,
  `option_names() -> Vec<String>` (`// RUGRA-GLUE`).
- `decode_one(arch, decoder) -> Result<(), String>` — decode one
  `<optionslist>` entry. Faithful to `OptionDatabase::decodeOne`
  (options.cc:163). Linearly scans `ELEM_PARAM1`/`ELEM_PARAM2`/`ELEM_PARAM3`
  children as Ghidra does.
- `decode(arch, decoder) -> Result<(), String>` — decode the
  `<optionslist>` block. Faithful to `OptionDatabase::decode`
  (options.cc:192).

## Fully functional options (mutate real Architecture state)
| Option | Field | Effect |
|---|---|---|
| `inferconstptr` | `infer_pointers` | Toggle pointer inference |
| `analyzeforloops` | `analyze_for_loops` | Toggle for-loop recovery |
| `readonly` | `readonlypropagate` | Toggle readonly propagation |
| `jumptablemax` | `max_jumptable_size` | Set max jumptable entries |
| `maxinstruction` | `max_instructions` | Set max instructions/function |
| `aliasblock` | `alias_block_level` | Set alias blocking (none/struct/array/.../all) |
| `nanignore` | `nan_ignore_all`/`nan_ignore_compare` | Set NaN ignore mode (all/none/compare/input) |
| `splitdatatypes` | `split_datatype_config` | Set datatype split config (none/float/pointer/both) |
| `defaultprototype` | `defaultfp_name` | Set default proto model via `set_default_model` |
| `protoeval` | `evalfp_current_name` | Set prototype eval model ("default" resets) |
| `ignoreunimplemented` | `flowoptions & IGNORE_UNIMPLEMENTED` | Toggle flow flag |
| `errorunimplemented` | `flowoptions & ERROR_UNIMPLEMENTED` | Toggle flow flag |
| `errorreinterpreted` | `flowoptions & ERROR_REINTERPRETED` | Toggle flow flag |
| `errortoomanyinstructions` | `flowoptions & ERROR_TOOMANYINSTRUCTIONS` | Toggle flow flag |
| `jumpload` | `flowoptions & RECORD_JUMPLOADS` | Toggle flow flag |
| `extrapop` | (deferred) | Parses int / "unknown"; ProtoModelEntry lacks extrapop field |

## Faithful-message options (target subsystems not yet ported)
These return the exact Ghidra confirmation string and are tagged
`// RUGRA-GLUE` with the missing integration. They will become functional
when the corresponding subsystem lands.

- **PrintLanguage options** (require emitter integration):
  `nullprinting`, `inplaceops`, `conventionprinting`, `nocastprinting`,
  `hideextensions`, `maxlinewidth`, `indentincrement`, `commentindent`,
  `commentstyle`, `commentheader`, `commentinstruction`, `integerformat`,
  `braceformat`, `setlanguage`, `namespacestrategy`.
- **ActionDatabase options** (require `setCurrent`/`enableSubRule`):
  `setaction`, `currentaction`, `togglerule`, `warning`.
- **ContextDatabase option** (require `ContextCache::allowSet`):
  `allowcontextset`.
- **Function-property options** (require `queryFunction`): `inline`,
  `noreturn`.

## Tests
26 unit tests under `options::tests` covering: default registry contents,
every flow-flag toggle, alias-block combination, split-datatype config,
NaN-ignore modes, integer-format/brace-format messages, set/current/toggle
action messages, allowcontextset, protoeval unknown/default, unknown-option
rejection, and `parse_int_any_base`/`parse_uint_any_base` hex/octal/decimal
parsing. Run with `cargo test --lib options::`.

## L3 coverage
- All 38 `OptionXxx` subclasses from `options.cc` are ported (OptionExtraCleanup
  does not exist in this Ghidra version).
- `registerOption` (options.cc:84), `OptionDatabase` ctor (options.cc:93),
  `set` (options.cc:150), `decodeOne` (options.cc:163), `decode`
  (options.cc:192) are all ported.
- XML decode of `<optionslist>` works against the `Decoder` trait.

## Remaining gaps
- `OptionExtraPop` parses its parameter but cannot store it —
  `ProtoModelEntry` has no `extrapop` field.
- PrintLanguage / ActionDatabase / ContextCache / function-lookup hooks.
<!-- annotation-pass: 2026-07-22 -->
