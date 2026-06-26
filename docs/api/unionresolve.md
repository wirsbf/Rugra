# unionresolve.rs — Union resolution API

Faithful port of Ghidra's `unionresolve.hh` / `unionresolve.cc` (1110 lines).

**Status:** L1 → L2. Complete ResolvedUnion + ResolveEdge + ScoreUnionFields
data structures and scoring framework. L3 gap: full scoring algorithm
requiring TypeFactory + PcodeOp integration.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/unionresolve.{hh,cc}`.

## Structs

### `ResolvedUnion`
A data-type resolved from a TypeUnion/TypeStruct (unionresolve.hh:39).
- `new_self(parent_name)`, `new_field(parent_name, field_name, fld_num)`.
- `get_datatype_name()`, `get_base_name()`, `get_field_num()`,
  `is_locked()`, `set_lock(val)`.

### `ResolveEdge`
A data-flow edge for resolved types (unionresolve.hh:60).
- `new(type_id, op_time, slot, is_pointer)`.
- Derives `Ord` for set keying.

### `DirType`
- `FitDown`, `FitUp`.

### `Trial`
Trial data-type fitted to a data-flow position (unionresolve.hh:84).
- `new_down(slot, type_name, index, is_array)`, `new_up(type_name, index, is_array)`.

### `VisitMark`
Visit tracking for Varnode+field (unionresolve.hh:120).
- `new(vn_id, index)`. Derives `Ord`.

### `ScoreUnionFields`
Scores union fields for a specific access (unionresolve.hh:82).
- `new(parent_name, field_names)`.
- `get_result() -> &ResolvedUnion`, `num_fields()`, `add_score(index, score)`.
- `compute_best_index()` — pick highest-scoring field (unionresolve.cc).
- `run()` — L3 gap: full scoring framework.

## Constants
- `MAX_PASSES = 5`, `THRESHOLD = 10`, `MAX_TRIALS = 50`.

## L3 gaps
- Full `scoreTrialDown`/`scoreTrialUp` with TypeFactory + PcodeOp data-flow.
- `testArrayArithmetic`, `testSimpleCases`, `scoreLockedType`,
  `scoreParameter`, `scoreReturnType`, `derefPointer`.
- `scoreTruncation`, `scoreConstantFit`.
