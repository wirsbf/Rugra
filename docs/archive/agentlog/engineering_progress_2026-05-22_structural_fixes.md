# Engineering Progress: Structural Bug Fixes v32→v35

**Date**: 2026-05-22  
**Session Focus**: Fix three core structural issues in decompilation output  
**Result**: All three issues significantly improved, 168/168 tests pass, 24/24 functions decompile

## Changes Summary

### 1. if-without-body Fix (`printc.rs`)

**Problem**: `BlockType::Condition` at top level emitted `if (compound_cond)` without any body block `{}`, producing syntactically invalid output.

**Root Cause**: The `emit_block_structured` handler for `BlockType::Condition` was generating `if(...)` wrapping but never opening a block body. This happened because `BlockCondition` is a compound condition (AND/OR of two sub-conditions) that should only produce `if()` when used as part of a `BlockIf`, not standalone.

**Fix**: Changed the top-level `BlockCondition` handler to recursively emit its sub-blocks flat (via `emit_block_structured`), letting the individual CBRANCH ops within each sub-block emit proper `if (cond) goto` statements.

**Result**: 4→0 if-without-body instances.

### 2. Missing Function Arguments Fix (`coreaction.rs`)

**Problem**: ~15 function calls emitted with zero arguments when they should have had arguments.

**Changes**:
- **Restored CBRANCH stop**: Re-added CBRANCH/BRANCH as backward search stop conditions. An earlier attempt to remove these caused regression (e.g., `fclose("out of memory\n")` from wrong execution path).
- **First-call entry fallback**: For the first CALL in a function, search ALL ops before it for register writes. This handles `free(param_1)` patterns where the arg register is set at function entry.
- **Expanded signature database**: Added `fputc`, `fgetc`, `curl_slist_free_all`, `_init`, `_fini`, `__libc_csu_init`, `__libc_csu_fini`, `SetHTTPrequest_part_0`, `parseconfig_constprop_0`, `curl_slist_append`.

**Result**: 15→9 no-arg calls (remaining are blocked by CBRANCH between register write and call site, requiring block-level SSA to fix).

### 3. Dead Code After Return Fix (`prettyprint.rs`)

**Problem**: getparameter had 41 flat returns with 11 lines of dead code after `return;` statements.

**Fix**: Added "Tenth pass" in prettyprint's post-processing that:
1. Tracks dead zones after `return;`/`break;`/`continue;` at a given indent level
2. Removes subsequent lines at the same indent unless they are goto-referenced labels, closing braces, case labels, or empty lines
3. Cross-references all labels against `goto` references to preserve reachable code

**Result**: Dead code after return: 11→0, getparameter lines: 295→251, returns: 41→33.

## Regression Testing

- **fclose**: No wrong arguments (previously regressed to `fclose("out of memory\n")`)
- **fputc**: Correctly `fputc(0x23, *stderr)` (was `fputc(..., ..., uVar124)` with 3 args)
- **maprintf**: Correctly 2 args
- **168/168 tests pass**

## Overall Metrics v24→v35

| Metric | v24 | v35 | Change |
|--------|-----|-----|--------|
| Lines | 1167 | 928 | -20% |
| goto | 135 | 66 | -51% |
| uVar declarations | 225 | 76 | -66% |

## Remaining Issues

- **9 no-arg calls**: `fclose()` ×4, `free()` ×2, `my_get_token()`, `SetHTTPrequest_part_0()`, `_init()` — blocked by CBRANCH between register write and call site
- **66 goto**: Some are genuine unstructured control flow that can't be reduced without more aggressive loop/switch detection
- **76 uVar declarations**: Further reduction needs better SSA-based variable merging
