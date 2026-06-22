# Engineering Progress: Variable Declarations Overhaul & Puts Parsing Fixes

**Date**: 2026-05-23  
**Session Focus**: Resolve missing uVar/lVar declarations and puts string resolution failures  
**Result**: 168/168 tests pass, curl stdout compiles with all used variables properly declared at headers, puts 0x hex resolved

## Changes Summary

### 1. Robust Variable Declarations Overhaul (`printc.rs`)
- **Problem**: Variables renamed from Registers (`lVar_XX`, `uVar_XX`) and Unique temporaries (`uVar_a0`) were used in code but never declared at the function header, causing invalid C syntax.
- **Root Cause**: The previous declaration strategy relied on backward scanning of existing AST ops to build declarations, which missed variables from dead/inlined COPY op-chains. Furthermore, all Register-space variables were excluded, and output-only Register/Unique patterns were filtered.
- **Fix**: 
  - Substituted the buggy AST op-scanning declaration builder with a unified collection-based declaration model.
  - Added `used_varnode_types` map to record the exact name, AddressSpace, offset, and type of every variable printed during the Discovery Pass (Pass 1).
  - Modified `mark_variable_used` and `mark_varnode_used` to feed this map.
  - Rewrote `doc_variable_decls_from_funcdata` to iterate directly over `used_varnode_types`, applying target filters.
  - Allowed declarations of variables in the `Register` space if they have been variable-ized (names starting with `lVar_`, `uVar_`, etc.).
  - Added expression name filtering in `mark_variable_used` to drop structure member access names (like `struct2->field_8`) so that only the structure base is declared.

### 2. Lossy UTF-8 String Parsing (`examples/curl_decompile.rs`)
- **Problem**: Three major puts calls with hex addresses (e.g. `puts(0x7180)`) remained unresolved because they contained aligned NULL padding or non-ASCII printable bytes, causing string parser decoding failures.
- **Fix**: Replaced strict `std::str::from_utf8` decoding with lossy `String::from_utf8_lossy` decoding to successfully recover all help text strings.
- **Result**: Hex puts remaining: 0.

### 3. Extra Paren Prettyprint Pass (`prettyprint.rs`)
- **Problem**: `puts` calls emitted an extra closing parenthesis `puts());`.
- **Fix**: Added "Fifteenth pass" in prettyprint to clean up double parenthesis artifacts (e.g., `func());` -> `func();`).

## Regression Testing
- Verified all 168 unit tests pass successfully.
- Re-decompiled curl and confirmed that:
  - All variables (Unique/Register/Stack) used in `main` (like `lVar_a8`, `uVar_a0`, etc.) are now correctly declared at the beginning of the function.
  - Illegal declarations like `struct2->field_8` are successfully filtered out.

## Overall Metrics (v40 → v45)

| Metric | v40 | v45 | Change |
|--------|-----|-----|--------|
| Hex puts calls | 3 | **0** | -100% |
| uVar declarations (with underscore) | 0 | **98** | +98 (All used registers/uniques declared) |
| Undefined variables | Yes | **No** | Fixed ✅ |
| illegal decls (e.g. `struct->field`) | 2 | **0** | Fixed ✅ |
