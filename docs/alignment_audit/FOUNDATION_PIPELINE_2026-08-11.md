# Foundation and pipeline audit — 2026-08-11

This report records independent, read-only audits against the locked oracle:

- Ghidra tag: `Ghidra_12.0.4_build`
- commit: `e40ed13014025f82488b1f8f7bca566894ac376b`
- source denominator: 114 decompiler `.cc` files

Unless a section explicitly names a runtime fixture, its status is
`MISMATCH / NO_ORACLE`: the source is sufficient to prove that the current
implementations differ, but it is not sufficient to claim runtime parity for a
future fix.

## Executive findings

| TODO | Area | Deterministic finding | Current status |
|---|---|---|---|
| `PIPE-0000` | Action executor | Rugra calls child `apply()` directly for non-repeat groups and the CLI calls the root `apply()`; Ghidra executes `reset -> perform`, and group children always go through `perform()` | MISMATCH / NO_ORACLE |
| `PIPE-0001` | Default Action tree | Rugra expands 90 leaves, versus 76 in `universal` and 71 in the oracle's filtered default `decompile` tree | MISMATCH / NO_ORACLE |
| `CALLSPEC-0001` | CALL/CALLIND | normal Rugra flow explicitly defers callspec creation, while Ghidra creates one stable `FuncCallSpecs` per call during flow discovery | MISMATCH / NO_ORACLE |
| `PCODE-0002` | TypeOp/opcode mutation | `TypeOp::get_flags` conflates two flag domains and `Funcdata::op_set_opcode` leaves or drops derived flags and opcode-bank membership | MISMATCH / NO_ORACLE |
| `OPCODE-0001` | Opcode wire protocol | ten protocol names differ, reverse lookup is missing, and packed decode rejects reserved values accepted by Ghidra | MISMATCH / NO_ORACLE |
| `SLEIGH-0001` | Linux source build | the build probe swallows a failing C++ compilation, producing a false-green library check and later undefined FFI symbols | MISMATCH; temporary build probe reproduced |
| `SLEIGH-0002` | SLEIGH context | `lift_from_func` omits pspec context; an x86-64 instruction decodes as length 1 instead of length 3 | MISMATCH; temporary runtime probe reproduced |
| `COMP-0001` | `Decompress` | the initial implementation differed in return value, stream lifetime, input aliasing, completion, and errors | PARTIAL MATCH; durable direct stdout diff covers normal/replacement/alias/data-error paths, fault injection remains untested |
| `MULTI-0001` | Multiprecision | the complete 16-function limb engine is absent; mainline RuleDiv code uses native `u128` and diverges above 64 bits | MISMATCH; locked runtime counterexample reproduced |
| `LEDGER-0001` | Function denominator | the historical 2,055 estimate covers only 26 `.cc` files; locked source has 5,691 `.cc` definitions before header-inline accounting | inventory complete; ledger not implemented |
| `GATE-0001` | Enforcement | hooks are not installed/executable, paths are wrong, evidence validation is weak, and 19 strict refs plus 247 annotations currently fail | FAIL |

## 1. Action executor and default pipeline

### Executor first

The first dependency is not tree ordering. Ghidra's `Action::perform` owns the
status/count/repeat lifecycle, and `ActionGroup::apply` invokes every child via
`perform()`. Current Rugra instead calls a non-repeat child's `apply()` directly
at `src/action.rs:250`; the CLI calls the root `apply()` directly at
`src/bin/rugra.rs:282`. Consequently, a tree-only reorder cannot reproduce
once/repeat/count semantics.

The repair order is therefore:

1. restore `reset -> perform` as the only production execution entry;
2. make group execution pass every child through `perform()`;
3. verify status/count/restart behavior with a locked runtime fixture;
4. only then replace the Action tree.

### Tree shape

Ghidra `coreaction.cc:5462` builds a 76-leaf `universal` tree. Filtering its
base groups produces a 71-leaf default `decompile` tree. Current Rugra builds a
90-leaf tree because `src/action.rs:843` flattens the 28 entries returned by
`build_full_pipeline_actions()` into the root and then registers many of the
same actions again in their nested stages.

Observed consequences include:

- 21 duplicated Action classes/names; `DirectWrite` occurs three times;
- missing `ForceGoto`, `DynamicMapping`, `LaneDivide`, the first
  `Unreachable("base")`, and the first `DynamicSymbols` occurrence;
- `StartTypes` runs before the first main loop instead of after its first pass;
- `AssignHigh`, `DominantCopy`, and `CopyMarker` run before Heritage/merge;
- `stackstall` contains only its rule pool, with its fixed successors moved out;
- `ConstantPtr` precedes `BlockStructure` and `ConditionalExe` precedes
  `NodeJoin`;
- `FinalStructure` and `PrototypeWarnings` are reversed;
- the six oracle presets (`decompile`, `jumptable`, `normalize`, `paramid`,
  `register`, `firstpass`) and their base-group filtering are absent.

Node identity for the oracle fixture must include path, ordinal, class/name,
base group, flags, and constructor arguments. Sorting by class name would hide
both intentional duplicates and ordering defects.

## 2. CALL/CALLIND and callspec identity

Ghidra's normal closure is:

```text
ActionStart -> startProcessing -> followFlow -> generateOps
            -> xrefControlFlow -> setupCallSpecs/setupCallindSpecs
```

Each encountered CALL or CALLIND immediately gets a unique, stable
`FuncCallSpecs`; direct calls have input 0 rewritten to an Fspec annotation.
The ordering is block index then `SeqNum::order`, and lookup uses Fspec identity
or the exact `PcodeOp*`, not the machine address.

Current Rugra diverges at several earlier points:

- `src/flow.rs:2088` explicitly skips normal CALL/CALLIND setup;
- `ActionStart::apply` is a no-op and the CLI manually invokes flow;
- the x86 lifter emits every call as CALL and represents indirect calls as
  `CALL ram:0`, destroying CALLIND identity;
- examples bypass `FlowInfo` entirely;
- the later `ActionFuncLink` shim scans only direct CALLs and deduplicates by
  machine address, which merges distinct P-code calls at the same address.

A correct bottom-up repair needs an Fspec address space and stable callspec/op
identity before flow rewiring. It must then distinguish x86 direct and indirect
calls, create specs in normal/injection/inline/truncation paths, and make all
entry points consume the same flow closure. Real indirect-call samples are
available at curl `0x5449` (`41 ff 14 df`) and httpd `0x2daa5`
(`41 ff d4`) / `0x2f22c` (`ff 13`).

## 3. TypeOp flags, PcodeOp mutation, and opcode protocol

### Flag ownership and mutation

Ghidra stores two independent TypeOp flag domains: `opflags` returned by
`getFlags()`, and `addlflags` queried by semantic predicates. Current
`src/typeop.rs` mixes them; all 72 registered opcodes violate the oracle
`getFlags()` contract.

`src/op.rs::opcode_flags` happens to contain the correct 72 `opflags`, but the
main mutation path bypasses it. `Funcdata::op_set_opcode`:

- clears only `0x2008084e` instead of the oracle-derived `0x200fc8de` mask;
- loses or retains `COMMUTATIVE`, `NOCOLLAPSE`, `BOOLOUTPUT`, `UNARY`,
  `BINARY`, `TERNARY`, and `SPECIAL` incorrectly;
- omits `CODEREF` for CBRANCH and adds it to BRANCHIND;
- does not remove/append the op in the STORE, LOAD, RETURN, or CALLOTHER bank
  lists.

Starting from Rugra's current `new_op(COPY)` and changing to each target opcode,
only COPY itself has the expected derived flags: 1 of 72. This path has 406
call sites in 15 source files, plus 15 direct opcode writes that bypass any
setter.

The repair DAG is: exact behavior/error foundation, TypeOp dual flags and owned
behavior, one PcodeOp setter plus bank lifecycle, Funcdata integration, then
migration of direct writes. A 72x72 mutation matrix and list-order fixture are
required before touching mainline Rules/Actions.

### Wire names and reserved values

All 72 formal numeric opcode discriminants match, but ten protocol names do
not:

| Value | Ghidra protocol | Current Rugra name |
|---:|---|---|
| 54 | `INT2FLOAT` | `FLOAT_INT2FLOAT` |
| 55 | `FLOAT2FLOAT` | `FLOAT_FLOAT2FLOAT` |
| 56 | `TRUNC` | `FLOAT_TRUNC` |
| 57 | `CEIL` | `FLOAT_CEIL` |
| 58 | `FLOOR` | `FLOAT_FLOOR` |
| 59 | `ROUND` | `FLOAT_ROUND` |
| 60 | `BUILD` | `MULTIEQUAL` |
| 61 | `DELAY_SLOT` | `INDIRECT` |
| 65 | `LABEL` | `PTRADD` |
| 66 | `CROSSBUILD` | `PTRSUB` |

Ghidra reverse lookup accepts only the protocol column; Rugra has no
`get_opcode` equivalent. Ghidra packed decoding also admits raw values 0
(`BLANK`) and 45 (`UNUSED1`), whereas the Rust enum mapping rejects them. These
raw protocol values need a representation that does not pretend they are valid
runtime P-code operations. `src/ffi.rs:228` also contains an unreachable second
SUBPIECE arm mapping to 56; the live mapping remains 63.

## 4. SLEIGH build and context

The Linux source-build failure chain is reproducible:

1. the shim include directory shadows system `<unistd.h>` with a Windows-only
   file that includes missing `<io.h>`;
2. `/EHa` is passed unconditionally to GNU C++;
3. `build.rs` swallows `try_compile` failure, so `cargo build --lib` looks green;
4. a real binary link then reports undefined `rugra_sleigh_*` symbols;
5. after fixing those, zlib symbols remain unresolved;
6. `examples/sleigh_test.rs` still imports the removed `jingle_sleigh` crate.

A temporary probe compiled all 22 translation units after using target-specific
flags/includes and linked after adding zlib. The locked oracle builds its
vendored zlib 1.3.1 sources with `LOCAL_ZLIB`/`NO_GZIP`; that is preferable to a
host-version dependency.

Once linked, another independent mismatch appears:
`SleighLifter::lift_from_func` does not load pspec context although normal flow
uses this method. Bytes `48 89 f8 c3` decode as a one-byte first instruction
without x86-64 `addrsize/opsize/rexprefix/longMode/DF`; with the oracle context,
the first instruction is length 3 and emits one COPY.

## 5. Compression and multiprecision

### `Decompress`

The initial locked probes established five differences: no-input completion,
remaining-capacity return polarity, persistence across output-limited calls,
`Z_DATA_ERROR`, and caller-owned input aliasing. `COMP-0001` now uses one
stable-address system `z_stream`, performs one `inflate(..., Z_NO_FLUSH)` per
call, returns `avail_out`, and preserves the caller-owned `next_in` pointer.

`tools/run_decompress_oracle.sh` builds both the locked C++ source and a Rust
mirror. It verifies that both binaries resolve the same `libz.so.1` and runtime
version, then directly diffs their common stdout schema. The durable fixture
now matches for:

- no-input and output-limited calls;
- continuation on the same input;
- clean and mid-stream input replacement;
- mutation of the caller-owned input between calls;
- identical input/output pointers with in-place decompression;
- stream completion and `Z_DATA_ERROR`.

This is deliberately a partial closure, not a module promotion. Runtime fault
injection for constructor failure, `Z_NEED_DICT`, `Z_MEM_ERROR`,
`Z_STREAM_ERROR`, and destructor cleanup remains untested. `COMP-0001`
therefore stays `IN_PROGRESS`, and the whole compression module remains L2:
`Compress` still differs and `CompressBuffer` is missing.

### Multiprecision

The absent module is a 16-definition limb engine (seven public operations,
including inline `set_u128`, plus nine internal helpers), not merely six APIs.
Three mainline RuleDiv families replace it with native `u128` arithmetic.

One locked counterexample is `calcDivisor(65, y=[1,1], xsize=64)`: Ghidra
returns 2 and mutates `y` to `[0,1]`; Rust debug arithmetic panics, while release
returns 0 and leaves `y` unchanged. The repair must port the full limb engine
and correct extended-constant PIECE layout before integrating the three Rules.

## 6. Ledger and enforcement health

Universal Ctags 6.2 gives this locked-source inventory:

- 114 `.cc` files, 5,691 definitions (including 111 file-scope/static), and
  101 `.cc` prototypes;
- 113 `.hh` files, 3,803 inline definitions and 6,216 prototypes;
- 15,811 raw tag occurrences.

The historical 2,055 denominator is the sum of estimates for only 26 `.cc`
files. Those same 26 files actually contain 2,327 `.cc` definitions, before
1,774 relevant header-inline definitions. Existing `func_gap_audit.py` compares
two decompiled C outputs and cannot generate a source-function ledger.

Current annotation diagnostics further show why a definition-aware ledger is
needed: of 5,771 parseable markers, 4,010 land on an exact definition/prototype
start, 841 land inside a body, 911 are outside any function span, and 9 are out
of range. Fuzzy name or body-span matches may propose candidates, but must not
change authoritative state.

Enforcement is currently non-operative:

- `core.hooksPath` is unset;
- `.githooks/pre-commit` is non-executable and there is no `commit-msg` hook;
- hook scripts use the wrong repository path and `python` executable;
- `.zcode/config.json` contains a Windows path and an invalid process-command
  shape;
- the evidence checker accepts only a fuzzy three-of-four match, and unchecked
  boxes can pass;
- 247 non-test functions lack annotations and 19 strict refs are broken;
- the ref checker validates only file/line range, not definition starts.

Eight broken `printc.rs` refs additionally hide a real wire-value mismatch:
Rugra assigns `CHAR=3, OCT=4, BIN=5`, while Ghidra assigns
`OCT=3, BIN=4, CHAR=5`. This requires its own source, oracle, and output-diff
change rather than a mechanical annotation edit.

## Required next order

1. Keep `PARSER-0002` closed: it has a locked runtime fixture and independent
   approval in commit `c1e799a`.
2. Repair enforcement without declaring it green until the 247 annotation and
   19 strict-ref baselines are resolved honestly.
3. Fix a low-coupling runtime-proven foundation closure (`COMP-0001`) while the
   larger Action/callspec/Pcode DAGs receive their own fixtures.
4. Do `PIPE-0000` before `PIPE-0001`; do stable Fspec identity before normal
   callspec flow; do TypeOp/PcodeOp ownership before migrating Rules/Actions.
5. Treat every legacy L3 claim contradicted above as unverified until its exact
   function ledger entries have locked-oracle evidence.
