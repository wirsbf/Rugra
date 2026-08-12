# Function signature / parameter recovery diagnosis (2026-08-12)

## Scope and evidence status

This audit diagnoses why the current curl output contains inflated function
parameter lists.  The source oracle is the locked Ghidra 12.0.4 tree at
`e40ed13014025f82488b1f8f7bca566894ac376b`.  No mapped Rust behavior was
changed in this audit, and no new 12.0.4 runtime fixture was produced, so the
affected functions remain `NO_ORACLE` under the B2 gate.  The checked-in
11.3.2 curl golden is used below only as a regression signal, not as final
alignment evidence.

The input ELF (`examples/curl`) is an x86-64 PIE with `.debug_info` and is not
stripped.  `readelf --debug-dump=info` confirms that the binary already carries
formal parameter DIEs, including:

- `myprogress`: `clientp`, `dltotal`, `dlnow`, `ultotal`, `ulnow`;
- `GetStr`: `string`, `value`;
- `helpf`: `fmt` followed by `DW_TAG_unspecified_parameters`;
- `getparameter`: `flag`, `nextarg`, `usedarg`, `config`.

The Rugra curl driver does not decode these function-prototype DIEs.  It only
installs a small hand-written set of struct layouts/global types in
`examples/curl_decompile.rs`, so parameter names, exact types, varargs and
locked storage never reach `FuncProto`.

## Reproduced symptom

The current `result/curl_cur.c` and the diagnostic 11.3.2 golden show:

| Function | Rugra params | diagnostic Ghidra params |
|---|---:|---:|
| `my_fwrite` | 7 | 4 |
| `myprogress` | 13 | 5 |
| `GetStr` | 5 | 2 |
| `my_get_token` | 4 | 1 |
| `helpf` | 14 | 1 fixed + varargs |
| `getparameter.constprop.0` | 35 | 4 |
| `progressbarinit` | 7 | 1 |
| `hugehelp` | 2 | 0 |
| `glob_url` | 8 | 3 |
| `next_url` | 6 | 1 |

The curl prepass is an important stage-local witness.  It runs heritage plus
only Rugra's `ActionInferParams` and reports `myprogress=5`, `GetStr=2`,
`helpf=1`, and `getparameter=5`.  The full action pipeline later prints
13/5/14/35 respectively.  Thus the gross inflation is introduced after the
initial heuristic recovery, not by the final comma-separated renderer.

## Root cause chain

### 1. `Funcdata` has no architecture-owned function prototype model

`Funcdata::new` creates a flat `FuncProto` with calling convention `unknown`
and stores `arch=None`.  The curl driver never calls `set_arch`.  Even if it
did, `set_arch` only stores the `Arc`; it does not attach the architecture's
default prototype model to the function prototype.  `Architecture` currently
stores lightweight model names, while the hard-coded
`type_system::protomodel::ProtoModel::default_x86_64` is only installed on some
call-site `FuncCallSpecs` paths.

Ghidra's own-function recovery depends on a real `FuncProto::model` and its
space-aware `ParamList`: `possibleInputParam` filters trials, then
`resolveModel` / `deriveInputMap` applies `ParamListStandard::fillinMap`.
Rugra's flat own-function `FuncProto` cannot perform this chain.

### 2. Rugra's invented `ActionInferParams` seeds an approximate prototype

`src/coreaction.rs:1312-1615` has no single Ghidra Action counterpart.  It
scans register inputs, uses a hand-written SysV register list, consults
binary-specific `known_param_count` / `known_param_types` tables, and creates
unlocked `ProtoParameter`s.

The tables are internally and externally inconsistent.  Examples include
`hugehelp=1` instead of zero, `helpf=2` instead of one fixed vararg parameter,
`glob_url=2` instead of three, and `next_url=3` instead of one.  The normal
SysV list uses R8/R9 offsets `0x80/0x88`, while the supplementation path uses
`0x40/0x48`.  Types are reduced to `ptr`/`int`/size fallbacks, so `size_t`,
`bool *`, `FILE *`, structures and varargs cannot survive.

### 3. `ActionUnjustifiedParams` is the immediate parameter-count amplifier

Locked Ghidra `coreaction.cc:4784 ActionUnjustifiedParams::apply` never appends
formal parameters.  It asks `FuncProto::unjustifiedInputParam` whether a
partial input is incorrectly justified inside a legal parameter container,
expands overlaps, and calls `Funcdata::adjustInputVarnodes` to construct the
full input plus `SUBPIECE` relationship.

Rugra `src/coreaction.rs:5327-5385` instead scans every used input varnode and,
if its numeric offset is absent from the current flat parameter list, appends
a new `long param_N`.  It does not call `unjustifiedInputParam`, does not build
or adjust a container varnode, ignores address-space identity and compares
only `u64` offsets.  Once `ActionInferParams` has seeded one or more unlocked
parameters, this pass converts flag registers, unrelated live-in registers
and other input state into formal parameters.  This directly explains the
prepass-to-final inflation.

The existing `FuncProto::is_input_locked` also uses `Iterator::all`; an empty
parameter vector is therefore incorrectly locked.  This makes recovery
behavior depend on whether the invented seed pass happened to create at least
one parameter.

### 4. `ActionInputPrototype` is a latent second over-collector

Locked Ghidra `coreaction.cc:4707 ActionInputPrototype::apply`:

1. clears unlocked inputs and fake-input symbols;
2. iterates input varnodes in `VarnodeDefSet` order;
3. registers only locations accepted by `FuncProto::possibleInputParam`;
4. marks active trials, resolves the model, and derives the input map;
5. creates only model-required unreferenced inputs after intersection checks;
6. updates types from trials and clears dead varnodes.

Rugra `src/coreaction.rs:4887-4954` builds a `ParamActive` but never marks its
trials, never calls model resolution or map derivation, never performs the
intersection/unreferenced logic, and never consumes the `ParamActive`.  If the
prototype is empty, it installs every used input varnode as a `long` formal
parameter.  In today's curl pipeline the earlier unjustified-parameter pass
usually makes the list non-empty, so this defect is mostly shadowed, but it is
not a valid fallback.

### 5. `PrintC::doc_function` bypasses its canonical declaration emitter

Locked Ghidra `printc.cc:2641 PrintC::docFunction` calls
`emitFunctionDeclaration(fd)` exactly once.  That method prints the return and
inputs from the finalized `FuncProto`.

Rugra has an approximately mapped `emit_function_declaration`, but production
`doc_function` does not call it.  Instead `src/printc.rs:5787-5927`:

- hard-codes `main(int argc, char **argv)`;
- infers the return type from any RAX write;
- when the prototype is empty, scans register reads again and emits another
  hand-written six-register fallback (the computed `written_regs` set is not
  consulted);
- otherwise prints the already-corrupted flat parameter vector.

This is not the source of the 13/35 counts when `FuncProto.parameters` is
non-empty, but it independently corrupts return types and makes empty-prototype
behavior diverge from the action result.

## Four decisive semantics

- **References/output mutation:** Ghidra mutates both the formal prototype and
  input-varnode graph (`adjustInputVarnodes`, unreferenced inputs, marks and
  dead nodes).  Rugra appends detached flat parameters and leaves the expected
  IR mutation absent.
- **Traversal/order:** Ghidra iterates the space-aware `VarnodeDefSet`, then
  lets `ParamListStandard` sort/classify trials.  Rugra iterates its bank and
  hand-written ABI arrays, then appends in observed input order.
- **Counters:** Ghidra trial slots, active/used flags and parameter count are
  distinct state.  Rugra uses `parameters.len()+1` as the name/counter while
  appending every unmatched live-in; its constructed `ParamActive` is unused.
- **Comparison keys:** Ghidra compares `(AddrSpace identity, offset, size,
  endian justification, ParamEntry group/alignment)`.  Rugra's amplifier
  compares only numeric offsets, and the current `Address` cannot represent
  space identity.

## Required repair DAG

1. Complete `SPACE-0001` / `ADDRESS-0001`, then `FSPEC-0001` lock/model state.
2. Complete `FSPEC-0002`: exact `ParamEntry` / `ParamActive` ordering, slots,
   groups, justification and `fillinMap` behavior.
3. Attach the cspec/default `ProtoModel` to each production `Funcdata`; remove
   the architecture-less own-function path.
4. Port `ActionUnjustifiedParams` and `ActionInputPrototype` exactly, with one
   locked 12.0.4 fixture observing the full prototype and all input-varnode/IR
   mutations.  Remove `ActionInferParams` after its callers are covered.
5. Add DWARF function-prototype import for debug-bearing corpora and lock the
   resulting `FuncProto` before analysis.  This is required for the exact
   source names/types present in `examples/curl`; it must not replace recovery
   for stripped binaries.
6. Make production `doc_function` call `emit_function_declaration`; delete the
   hard-coded main/return/empty-prototype signature paths after the prototype
   oracle is green.
7. Replace `ActionCallParams` count/type tables with real callee `FuncProto` /
   `FuncCallSpecs` recovery so call expressions use the same prototypes.

Do not treat “truncate to six parameters” or disabling
`ActionUnjustifiedParams` as a fix.  Those shortcuts would hide this curl
symptom while breaking stack parameters, variadic calls, subregister
containers and non-x86 conventions.
