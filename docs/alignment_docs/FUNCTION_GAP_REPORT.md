# Per-function STRICT output gap audit

**Rugra**: `result/curl_cur.c`  |  **Ghidra golden**: `tests/golden/ghidra_curl.c`

**Criterion**: token-level EXACT match after comment/whitespace normalization (NOT semantic equivalence).


## Summary

| metric | value |
|---|---|
| Rugra functions | 24 |
| Ghidra functions | 80 |
| Paired (in both) | 24 |
| **EXACT match** | **0** |
| DIFF | 24 |
| Rugra unpaired (pseudo/extra) | 0 |
| In Ghidra, missing from Rugra | 57 |

## EXACT matches (0)

_(none)_

## DIFF (24) — needs alignment

| Rugra fn | Ghidra fn | rugra/ghidra size | diff reasons |
|---|---|---|---|
| `main` | `main` | 5540/17462 | StackX_ placeholder (varmap), goto count 0 vs 19 |
| `my_fwrite` | `my_fwrite` | 272/367 | param_N placeholder (var naming), StackX_ placeholder (varmap) |
| `myprogress` | `myprogress` | 1070/1582 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 1 |
| `GetStr` | `GetStr` | 247/270 | param_N placeholder (var naming), StackX_ placeholder (varmap) |
| `my_get_token` | `my_get_token` | 244/1363 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 1 |
| `my_get_line` | `my_get_line` | 769/1943 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 2 |
| `helpf` | `helpf` | 863/1577 | param_N placeholder (var naming), StackX_ placeholder (varmap) |
| `file2string_part_0` | `file2string` | 329/4264 | param_N placeholder (var naming), StackX_ placeholder (varmap) |
| `SetHTTPrequest_part_0` | `SetHTTPrequest` | 90/211 | param_N placeholder (var naming), StackX_ placeholder (varmap) |
| `parseconfig_constprop_0` | `parseconfig` | 1594/2706 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 8 |
| `getparameter_constprop_0` | `getparameter` | 2404/15763 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 17, switch count 0 vs 1 |
| `main_init` | `main_init` | 58/48 | token-order/naming/expression diff (needs -v) |
| `main_free` | `main_free` | 31/35 | token-order/naming/expression diff (needs -v) |
| `SetHTTPrequest` | `SetHTTPrequest` | 183/211 | param_N placeholder (var naming) |
| `progressbarinit` | `progressbarinit` | 231/399 | param_N placeholder (var naming), StackX_ placeholder (varmap) |
| `hugehelp` | `hugehelp` | 415/6644 | param_N placeholder (var naming), StackX_ placeholder (varmap) |
| `glob_word` | `glob_word` | 606/3874 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 6, switch count 0 vs 8 |
| `glob_set` | `glob_set` | 811/2331 | param_N placeholder (var naming), goto count 0 vs 6, switch count 0 vs 8 |
| `glob_range` | `glob_range` | 1059/2712 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 1 |
| `glob_url` | `glob_url` | 341/342 | param_N placeholder (var naming) |
| `next_url` | `next_url` | 868/3136 | param_N placeholder (var naming), goto count 0 vs 5 |
| `match_url` | `match_url` | 760/2355 | param_N placeholder (var naming), StackX_ placeholder (varmap), goto count 0 vs 1 |
| `__libc_csu_init` | `__libc_csu_init` | 183/305 | StackX_ placeholder (varmap) |
| `__libc_csu_fini` | `__libc_csu_fini` | 37/41 | token-order/naming/expression diff (needs -v) |

## Ghidra functions absent from Rugra output (57)

_(includes library stubs; USER fns = the real gap)_

- `FUN_00102020`
- `FUN_001022e0`
- `_ITM_deregisterTMCloneTable`
- `_ITM_registerTMCloneTable`
- `__ctype_b_loc`
- `__cxa_finalize`
- `__do_global_dtors_aux`
- `__fprintf_chk`
- `__gmon_start__`
- `__isoc99_sscanf`
- `__libc_start_main`
- `__printf_chk`
- `__sprintf_chk`
- `__stack_chk_fail`
- `__vfprintf_chk`
- `__xstat`
- `_fini`
- `_init`
- `_start`
- `curl_easy_cleanup`
- `curl_easy_init`
- `curl_easy_perform`
- `curl_easy_setopt`
- `curl_formparse`
- `curl_getdate`
- `curl_getenv`
- `curl_slist_append`
- `curl_slist_free_all`
- `curl_version`
- `deregister_tm_clones`
- `exit`
- `fclose`
- `fgets`
- `fileno`
- `fopen`
- `fputc`
- `frame_dummy`
- `free`
- `fwrite`
- `isatty`
- `malloc`
- `maprintf`
- `memcpy`
- `puts`
- `realloc`
- `register_tm_clones`
- `strcat`
- `strchr`
- `strcpy`
- `strdup`
- `strequal`
- `strlen`
- `strnequal`
- `strrchr`
- `strstr`
- `strtol`
- `time`
---

## Cross-function systemic root-cause analysis (2026-07-02 19:50)

Per-USER-function normalized comparison (Ghidra's own 21 user fns vs Rugra's 21
counterparts, same binary). **Defects where Ghidra = 0 are pure Rugra bugs —
uncontaminated by library stubs.**

| defect | Ghidra(21fn) | Rugra(21fn) | gap | verdict |
|---|---|---|---|---|
| `self-xor V^V` | **0** | 16 | +16 | **pure Rugra bug** |
| `return V^V` (as return value) | **0** | 5 | +5 | **pure Rugra bug** |
| `param_N` placeholder | **0** | 72 | +72 | **pure Rugra bug** (naming) |
| `StackX_` placeholder | **0** | 87 | +87 | **pure Rugra bug** (varmap) |
| `->` struct field access | **97** | **1** | −96 | **pure Rugra gap** (lost struct typing) |
| reg-leak (`EAX_22` etc) | 36 | 137 | +101 | Rugra worse, partial overlap (lib stubs) |
| `*(T*)` raw cast | 46 | 109 | +63 | Rugra worse, partial overlap |

### Root-cause → defect mapping (with Ghidra source line evidence)

| defect | root cause | Ghidra source | Rugra status |
|---|---|---|---|
| `return V^V` (5 fns) | `ActionReturnRecovery::buildReturnOutput` missing → RETURN op never gets in(1) → printc heuristic emits raw RAX def (incl. un-folded `V^V`) | coreaction.cc:**1836-1906** (buildReturnOutput) | ❌ MISSING (BATCH1:76). printc.rs:4217-4241 heuristic is the workaround, diverges from Ghidra opReturn (printc.cc:754-766 which ONLY prints `getIn(1)`). |
| `param_N` (72) | `ActionInputPrototype` builds throwaway ParamActive + hardcoded `param_{N}`; `ActionNameVars` is empty stub | coreaction.cc:4924 (InputPrototype), coreaction.cc:**2779-3006** (NameVars) | R77 + R5 (SUMMARY). |
| `StackX_` (87) | `varmap create_entry` does not write back Symbol/HighVariable/ScopeInternal | varmap.cc:**617-628** (addSymbol) | R1 (SUMMARY). varmap.rs:1435. |
| missing `->` (−96) | struct/pointer type recovery + field offset→name resolution incomplete | type.cc / unionresolve.cc | R60/R61 (Partial subclasses + assignFieldOffsets). Rugra emits `*(T*)(ptr+off)` raw. |
| self-xor `V^V` (16) | `x^x→0` fold not reaching this op (iteration limit) OR printc emitting before fold | ruleaction.cc:2382-2433 (RuleTrivialArith) | R9/R73. Fold exists (ruleaction.rs:405) but doesn't fire here; compounded by the return heuristic above. |

### Highest-ROI alignment targets (Phase 2 order)

1. **`return V^V` (5 fns, clear correctness bug)** — port `ActionReturnRecovery::buildReturnOutput`
   (coreaction.cc:1836-1906), then **delete** the printc heuristic (printc.rs:4211-4241) to match
   Ghidra opReturn. This alone fixes main_init/myprogress/SetHTTPrequest/glob_url/parseconfig.
2. **`StackX_` (87, pure naming)** — port varmap.cc:617-628 addSymbol writeback (R1).
3. **`param_N` (72, pure naming)** — port ActionNameVars (R5) + fix InputPrototype (R77).
4. **`->` access (−96)** — struct type recovery (R60/R61). Largest gap, harder.
