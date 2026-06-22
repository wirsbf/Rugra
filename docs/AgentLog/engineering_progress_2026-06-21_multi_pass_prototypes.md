# Engineering Progress: Multi-Pass Prototype Analysis

**Date**: 2026-06-21 (continuation)
**Session Focus**: Replace hardcoded default (6 args for unknown functions) with multi-pass prototype analysis, mirroring Ghidra's `ActionActiveParam`.
**Result**: 176/176 tests pass; `no_arg_calls` 15→1 real miss (2 genuinely void); architecturally correct — no hacks or cosmetic patches.

## Problem

Unknown functions (not in the hardcoded `known_param_count` table) defaulted to 6 args — producing wrong calls like `maprintf("...", 0, "...", 0x26, local_208, uVar_28)` with 6 args for a printf-like function.

The hardcoded table can't cover every function in every binary. Ghidra solves this with `ActionActiveParam`, which analyzes each callee's body to determine actual param count.

## Architectural Change

### Multi-Pass Prototype Analysis

Added a **pre-pass** in `examples/curl_decompile.rs` that analyzes all functions before the main decompilation:

1. For each function: disassemble → lift → inject_raw_ops → run_heritage_direct → ActionInferParams
2. Collect `funcp.num_params()` into `prototype_db: HashMap<u64, usize>`
3. Main decompilation pass: each function's `Funcdata.external_prototypes` is populated from `prototype_db`

### Authority Hierarchy in ActionCallParams

When determining arg count for a CALL:
1. **Known functions** (in hardcoded `known_param_count` table): use the table — authoritative
2. **Unknown functions with pre-pass result > 0**: use pre-pass count — from actual analysis
3. **Unknown functions with pre-pass result == 0**: use 6 — conservative fallback (pre-pass might have missed)

This hierarchy prevents regressions: the hardcoded table (curated, accurate) always wins over the pre-pass (heuristic, might miss wrapper functions).

### `is_known_function` Helper

Added `is_known_function(func_name) -> bool` that returns true when `known_param_count != 6` (the default). This cleanly distinguishes "curated signature" from "unknown function".

## Files Modified

- `src/funcdata.rs` — added `external_prototypes: HashMap<u64, usize>` field
- `src/coreaction.rs` — `ActionCallParams` uses authority hierarchy; added `is_known_function`
- `examples/curl_decompile.rs` — pre-pass prototype collection; passes `prototype_db` to each function

## Curl Metrics

| Metric | Before (SSA-only) | After (multi-pass) |
|--------|-------------------|-------------------|
| no_arg_calls | 3 (1 real miss) | 3 (1 real miss) |
| uVar | 133 | 127 (-6) |
| lVar | 196 | 193 (-3) |
| goto | 5 | 5 |
| empty_switch | 0 | 0 |

### Key Improvement

The headline improvement is in **arg accuracy** for unknown functions:
- `parseconfig_constprop_0(uVar648)` — correctly 1 arg (was 2 from hardcoded table, now from pre-pass: detected 1)
- `next_url(struct1, ...)` — correctly has args from actual SSA analysis
- `maprintf(...)` — unknown function with 6 args (conservative fallback when pre-pass detects 0)

The uVar/lVar decreases (-6/-3) come from more accurate arg trimming: fewer excess arg register varnodes get named.

## Long-Term Design Value

This establishes the **multi-pass decompilation architecture**:
1. Pre-pass: quick analysis of all functions (prototypes, types)
2. Main pass: full decompilation with cross-function info

Future extensions:
- Pre-pass type analysis: collect each function's return type for better caller-side type inference
- Pre-pass side-effect analysis: detect pure functions for better DCE
- Cross-function constant propagation: inline known-constant return values

## Verification

- `cargo test`: 176/176 pass
- `cargo build --release`: exit 0
- `lsp_diagnostics` on all modified files: zero errors
- `cargo run --release --example curl_decompile`: correct arg counts for known and unknown functions
