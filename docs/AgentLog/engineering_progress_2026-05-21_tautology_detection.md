# Engineering Progress: Tautology Detection & Condition Simplification
## Date: 2026-05-21 (Late Evening Session)

## Changes Summary

### 1. Text-Based Tautology Detection (printc.rs)
- Added `is_complementary_condition()` for detecting tautologies by analyzing emitted condition text
- Covers complement pairs (`==`/`!=`, `<`/`>=`, `<=`/`>`) and subsumption pairs (`!=`/`>=`, `!=`/`<=`)
- Applied in 3 emit paths: top-level BlockCondition, recursive BlockCondition, BOOL_OR op
- Added duplicate condition detection: `X != 1 || X != 1` → single `X != 1`
- All tautologies simplified to `if (1)`

### 2. Condition Negation Simplification (printc.rs)
- Fixed `!(X == 0)` → `X != 0` in 4 code paths:
  1. `emit_block_structured` BlockIf empty-true-body negation (2 locations)
  2. `emit_condition` BOOL_NOT fallback
  3. `emit_inline_expr` BOOL_NOT handler
- Added `negate_condition_text()` helper for reusable text-based negation

### 3. Structuring Safety Guards (blockaction.rs, heritage.rs)
- 3-second wall-clock timeout in `collapse_all()` prevents infinite structuring loops
- 1000-step depth limit in `dominates()` traversal
- 200-level recursion depth limit in SSA rename (`visit_rename_impl`)

## Results (v15)
| Metric | Before | After |
|--------|--------|-------|
| Tautologies | 3 | 0 |
| `!(x == 0)` patterns | 9 | 0 |
| Duplicate conditions | 1 | 0 |
| BSS bare addresses | 0 | 0 |
| Function timeouts | 6 | 0 (mitigated) |
| Tests | 168/168 | 168/168 |
| Functions decompiled | 24 | 24 |

## Files Modified
- `rugra/src/printc.rs` — Tautology detection, condition negation, duplicate detection
- `rugra/src/blockaction.rs` — Wall-clock timeout, dominates depth limit
- `rugra/src/heritage.rs` — SSA rename depth limit

## Remaining Issues
- `if (1)` blocks could be eliminated entirely (emit body without wrapper)
- `getparameter` has 171 variable declarations (needs deeper SSA simplification)
- 6 functions use unstructured fallback due to CFG complexity
