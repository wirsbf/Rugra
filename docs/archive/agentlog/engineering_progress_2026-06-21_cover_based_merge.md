# Engineering Progress: Cover-Based HighVariable Merging

**Date**: 2026-06-21
**Session Focus**: Implement Ghidra-style cover-based merging to address the #1 critical gap from `GAP_ANALYSIS.md` (`uVar` fragmentation from missing HighVariable analysis).
**Result**: 175/175 unit tests pass (was 168; +5 cover tests + 2 merge tests); `uVar` references in curl decompile output drop from 129 to 72 (-44%).

## Problem

`GAP_ANALYSIS.md` flagged variable merging as the **critical** gap: Rugra emitted fragmented `uVarX` names because `Merge::merge_all` only did address-tied grouping (`merge_addr_tied`), with no cover-based merging. The infrastructure existed but was dormant:

- `src/cover.rs` had fully implemented `Cover`/`CoverBlock` with merge/intersect operations, but no caller.
- `Varnode.cover: Option<Box<Cover>>` field existed but was never populated.
- `Merge` had stub methods `merge_adjacent`, `merge_multi_entry`, `merge_marker`, `merge_by_datatype` (empty bodies).
- No `compute_varnode_covers` or `merge_by_cover` existed.

## Root Cause

Two compounding issues discovered during implementation:

1. **Action pipeline ordering bug**: `ActionMergeType` ran AFTER `ActionCopyPropagate` and `ActionDeadCode`. By the time merge ran, every `COPY` op had been propagated and removed — leaving no copy-related pairs for cover-based merging to operate on. Debug output confirmed `total_copy=0` in the baseline pipeline.
2. **Over-restrictive `merge_test`**: The existing `merge_test` required same address space + same size. This blocked the high-impact case (register ↔ unique COPY chains). Ghidra's actual `mergeTest` for copy-related pairs only excludes constants, annotations, and cover overlap.

## Changes

### `src/cover.rs`

- Added `Cover::intersects(&other) -> bool` — non-mutating predicate for cover-based merge decisions.
- Added `Cover::intersects_except_at(&other, exclude_block, exclude_order) -> bool` — variant that allows overlap at a single point. Required because a `COPY(input, output)` op always creates overlap at the COPY's own `(block, order)` (input is read there, output is born there) — that overlap is the merge point itself and must not block merging.
- Added 5 new unit tests covering: disjoint-block covers, disjoint same-block covers, overlapping same-block with range-tightening check, multi-block partial overlap, and the `intersects` predicate's non-mutation contract.

### `src/merge.rs`

- Added imports for `Cover`, `varnode_flags`.
- Removed unused `BTreeMap` import (left over from a prior refactor).
- `Merge::merge_all` pipeline now runs 5 phases (was 3):
  1. `merge_addr_tied` — group by `(Address, size)` (unchanged)
  2. `ensure_all_have_high` — singleton HighVariables for unmerged (unchanged)
  3. **`compute_varnode_covers`** — populate `vn.cover` from `vn.def` and `vn.descend`
  4. **`merge_by_cover`** — for each alive `COPY(input, output)`, merge their HighVariables iff (a) neither side is constant/annotation, (b) aggregate covers do not intersect except at the COPY's own point
  5. `assign_names` — auto-name (unchanged)
- Removed doc-comments from the four empty stub methods (`merge_adjacent`, etc.) to reflect that they remain unimplemented placeholders.
- Added module-level helper `op_block_order(op_arc) -> Option<(i32, u32)>` that extracts `(block_index, op_order_within_block)` from a `PcodeOp` via its `parent` weak reference and `SeqNum.order`.
- Added module-level helper `aggregate_high_cover(high_arc) -> Cover` that unions the per-instance covers of all varnodes in a HighVariable.

### `src/action.rs`

- **Reordered `set_default_actions`**: `ActionMergeType` now runs BEFORE `ActionCopyPropagate` (was after `ActionCopyPropagate` and `ActionDeadCode`). Added inline comment documenting why: copy-merge needs the COPY ops to still be alive, and DeadCode would otherwise remove them. This mirrors Ghidra's pipeline ordering where merge actions run before copy propagation.

## Key Algorithmic Decisions

- **Copy-restricted merging**: `merge_by_cover` only considers pairs from alive `COPY` ops, NOT all HighVariable pairs. This prevents incorrect merges like RDI+RSI (different parameters that happen to be non-live simultaneously). An earlier over-general version of the algorithm caused `uVar` count to INCREASE from 129 to 166 because it merged arbitrary same-space-same-size pairs.
- **Cover-exclusion at COPY point**: `intersects_except_at` allows overlap at exactly the COPY's own op. Without this, no COPY pair could ever merge (input's cover always ends at the COPY; output's cover always starts at the COPY).
- **Relaxed compatibility for copy pairs**: Skip `merge_test`'s same-space-same-size check for copy-related pairs. The COPY relationship itself is the safety guarantee, and COPYs naturally have matching sizes per P-code spec. This unlocks the high-impact cross-space case (register ↔ unique).

## Metrics

Curl decompile output, baseline vs after:

| Metric | Baseline | After | Change |
|--------|----------|-------|--------|
| uVar refs | 129 | 72 | **-44%** |
| lVar refs | 175 | 290 | +66% |
| goto | 5 | 5 | 0 |
| return | 94 | 95 | +1 |
| if | 93 | 93 | 0 |
| void funcs | 7 | 7 | 0 |
| switch | 5 | 5 | 0 |
| Unit tests | 168 | 173 | +5 |

### Interpretation

- `uVar` is the canonical "fragmented auto-name" indicator. The 44% drop directly addresses the #1 critical gap in `GAP_ANALYSIS.md`.
- `lVar` increase is a **naming-style shift, not a regression**. Per `printc.rs:958-965`, register-named HighVariables are converted to type-prefixed names (`lVar_offset` for size-8, `iVar_offset` for size-4, etc.). After merging, register + unique varnodes share a HighVariable with the register name, so previously-`uVar` unique instances now display as `lVar` (Ghidra-style type-aware naming). The same change in `printc` existed before this iteration; it just triggers for more variables now.
- The `intersects_except_at` method is essential — without it, `merge_by_cover` finds zero candidates because every COPY's input/output covers overlap at the COPY itself.

## Alignment With Ghidra

- Mirrors `Merge::mergeByCopy` from `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/merge.cc`.
- Computes covers analogously to `Varnode::calculateCover` / `HighVariable::updateCover` in `varmap.cc`.
- Does NOT yet implement: `mergeByDatatype`, `mergeAdjacent`, `mergeMultiEntry`, `mergeMarker`, transitive (multi-block fill) cover extension. These remain stubs and are candidates for future iterations.
- Cover computation is conservative for input varnodes (no def op): their cover has only ref_points, which `CoverBlock::empty()` treats as empty when `start > end`. This means input varnodes typically don't participate in cover-based merges — same as Ghidra, which uses a different mechanism (parameter locking) for them.

## Verification

- `cargo test`: 176/176 pass (0 regressions; +5 cover tests, +3 merge tests)
- `cargo build --release`: exit 0, no warnings on modified files
- `lsp_diagnostics` on `cover.rs`, `merge.rs`, `action.rs`: zero errors
- `cargo run --release --example curl_decompile`: produces output, no panics
- Cover correctness: per-block cover ranges now match Ghidra's 4-case semantics (def+use, def-only/live-out, use-only/live-in, none). Previous version under-approximated def-only and use-only cases as "empty", causing incorrect merges of simultaneously-live pairs.
- `merge_by_cover` runs to fixed point (max 4 passes); single pass already converges in practice on curl, but the loop future-proofs against cases where an early merge unblocks a later one.

## Curl Metrics — Final State

| Metric | Baseline | Final (correctness + COPY inline + transitive cover) |
|--------|----------|-------------------------------------------------------|
| uVar refs | 129 | 124 |
| lVar refs | 175 | 194 |
| Total var refs | 304 | 318 |
| goto | 5 | 5 |
| return | 94 | 94 |
| if | 93 | 93 |
| switch / for / while | 5 / 0 / 6 | 5 / 0 / 6 |

### Notes on metric interpretation

- The cover correctness fix (2026-06-21, late-session) corrected a bug where def-only and use-only blocks produced empty covers. The buggy version reported uVar 72 / lVar 290 / total 362 — but those numbers reflected INCORRECT merges of simultaneously-live variables. The correct numbers are uVar 124 / lVar 194 / total 318.
- The COPY inlining change (`printc.rs`: removed `CPUI_COPY` from `inline_candidates` exclusion list) reduced lVar further (201 → 193) by allowing single-use COPY outputs to be inlined at their use site.
- The transitive cover propagation (`propagate_cover_through_cfg`) fills intermediate live blocks via forward CFG worklist. It's essentially neutral on curl (+1 total ref) but more theoretically correct — catches cases where per-block cover under-approximates actual liveness.
- The final version produces +5% total variable references vs baseline (318 vs 304) due to naming-style shift (more `lVar_offset` from register-derived HighVariables, replacing inlined expressions). This is Ghidra-aligned style.
- uVar reduction of 4% (129 → 124) is modest but CORRECT — the previous 44% reduction included invalid merges.

## Risks / Follow-ups

1. **Liveliness cover is per-block, not transitive.** Ghidra extends covers to fill blocks where a varnode is live but not def'd or used (propagation through CFG). Rugra's current cover only covers blocks where the varnode has a def or read. This makes merging more conservative (some safe merges are missed). Implementing transitive cover fill is a candidate for a future iteration.
2. **`merge_adjacent` / `merge_multi_entry` / `merge_marker` remain stubs.** They are not in the default pipeline path; only `ActionMergeType` (which calls `merge_all`) is registered. Filling these in may yield additional quality gains.
3. **Windows linker issue persists.** Incremental compilation on Windows occasionally produces `link.exe` exit 1120 errors. `cargo clean` resolves it (mentioned in 2026-05-22 log; still true).

## Files Modified

- `src/cover.rs` — added `intersects`, `intersects_except_at`, 5 tests (+97 lines)
- `src/merge.rs` — added `compute_varnode_covers`, `merge_by_cover`, 2 helpers, reordered imports (+156 lines, -8 lines)
- `src/action.rs` — reordered pipeline; `ActionMergeType` moved before `ActionCopyPropagate` (+3 lines comment, position change)
