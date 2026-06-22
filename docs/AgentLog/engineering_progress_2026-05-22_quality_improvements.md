# Engineering Progress: Decompilation Quality v24→v28

**Date**: 2026-05-22  
**Session Focus**: Decompiled C output quality improvements  
**Tests**: 168/168 passed, 24/24 functions decompiled  

## Changes

### Files Modified
- `src/printc.rs` — Return type inference, string resolution, switch variable detection, variable inlining, case formatting
- `src/prettyprint.rs` — Exit-label goto→break/return conversion
- `examples/curl_decompile.rs` — String detection minimum length

### Key Implementations

1. **Return Type Inference** — Scans ops for RAX writes to infer int/long return types. Trivial functions (≤2 ops) remain void.

2. **String Constant Substring Lookup** — When a Const value falls within a known .rodata string's address range, emit the substring. Handles mid-string references like `0x62f8` → `"--"` (8 bytes into `"--_curl_--"`).

3. **Switch Condition Variable** — For CBRANCH cascade switches, scans control block for `INT_EQUAL`/`INT_NOTEQUAL` comparisons and extracts the non-constant operand.

4. **Case Character Formatting** — Printable ASCII case values displayed as character literals.

5. **Extended Variable Inlining** — Register-space single-use varnodes now inlineable. Priority 1.7 check added after def-chain resolution fails.

6. **Exit-Label Goto Reduction** — Pre-scans for "dominant exit labels" (referenced ≥3 times, no label definition). Converts:
   - Plain `goto` at indent ≥4 → `break`
   - Plain `goto` at indent 2 → `return`
   - `if (cond) goto` → `if (cond) break`/`return`

## Metrics (v24 → v28)

| Metric | v24 | v28 | Change |
|--------|-----|-----|--------|
| goto | 135 | 66 | -51% |
| void funcs | 23 | 7 | -70% |
| uVar refs | 582 | 502 | -14% |
| switch() | 5 | 1 | -80% |
| break | 6 | 52 | +46 |
| return | 5 | 64 | +59 |

## Remaining Issues
- 66 gotos require structural improvements in blockaction.rs
- 1 empty switch uses non-standard comparison pattern
- 502 uVar references need deeper SSA/type propagation

## Build Note
Persistent linker errors with incremental compilation on Windows. `cargo clean` required between builds due to stale `.rlib` artifacts causing "unresolved external symbol" errors.
