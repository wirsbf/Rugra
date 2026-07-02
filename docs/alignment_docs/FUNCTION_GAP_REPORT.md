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

---

## Phase 2 progress (2026-07-02 20:10)

### Done
- **R73** (commit `03734ee`): removed `perform`/`ActionGroup` iteration caps
  (`iterations>1`/`>2` breaks) in action.rs, restored Ghidra's unbounded
  `do-while` (action.cc:298-362). **Output-neutral** (0/24 EXACT unchanged) but
  removes a convergence blocker; zero regressions, zero loops, glob_range
  completes without stack overflow across 3 runs. Alignment Evidence block
  verified 4/4 decisive-semantics classes.

### Investigated, NOT the assumed root cause
- **`return iVar1 ^ iVar1`** (main_init etc.): via `RUGRA_DBG_XOR` diagnostic,
  confirmed ALL 48 XORs reaching the rule pool are `var ^ constant` (legit,
  correctly NOT folded) — **none** are `xor eax,eax`. The `V^V` is synthesized
  by the printc return-value heuristic (printc.rs:4211-4241) from an
  **uninitialized** varnode. A single-instruction `xor eax,eax` lift test
  (`test_xor_eax_eax_input_identity`) proves the lifter's varnode-identity
  dedup is CORRECT (ptreq=true). So the real root cause is the missing
  `ActionReturnRecovery::buildReturnOutput` (coreaction.cc:1836-1906) — RETURN
  ops never get their return value attached as in(1), so the printc heuristic
  fires on garbage. Faithful fix = port ActionReturnRecovery (heavy, needs
  ParamActive/AncestorRealistic/deriveOutputMap infra).

### Next highest-ROI (correct root cause, scope-bounded)
- **StackX_ (87) + param_N (72)**: confirmed via Ghidra golden inspection that
  Ghidra emits `iVar1`/`lVar2`/`cVar1`/`pCVar6` (typed-prefix names from
  `Datatype::printNameBase` + shared `int4 base` counter), NOT `StackX_`. The
  `StackX_` is Rugra's correct *fallback* default name (buildVariableName,
  varmap.cc:548) — what's MISSING is `ActionNameVars` (coreaction.cc:2978-3000)
  + `assignDefaultNames` (database.cc, the shared-`base` scheme that drove the
  181538f bug). This is R5 — a 400+ line multi-file port (coreaction.rs +
  database.rs + type printNameBase), gated by 铁律 10 Red Flags.
- **`->` access (−96)**: struct/pointer type recovery (R60/R61). Largest gap.

### Untouched pre-existing work
- `src/ffi.rs` (CPUI_CAST round-trip) + `src/funcdata.rs` `op_set_opcode`
  flag-sync were in the working tree before this session (not authored here).
  Verified **output-neutral** (gap audit identical with/without). Left in place
  per 铁律 §8; their owner should verify/commit.

---

## Phase 2 progress (2026-07-02 21:30) — naming fixes

### Done (commits 084e9aa, 81d7b9e)
- **compact_name_for 共享 base** (`084e9aa`): per-prefix `HashMap<&str,u32>` → 单一
  `compact_base: u32` (初值1, 跨所有前缀单调递增)。faithful to Ghidra
  `assignDefaultNames(int4 &base)` (database.cc:2850) + `ActionNameVars::apply`
  `int4 base=1` (coreaction.cc:2988)。修正 181538f bug。Alignment Evidence 4/4。
- **StackX_ 符号接入共享 base 重命名** (`81d7b9e`): 新增 `rename_scope_symbol`,
  两处接入 (get_stack_variable_name 使用路径 + doc_variable_decls 声明路径)。
  faithful to Ghidra `assignDefaultNames` 对 stack-local fallback 名 (varmap.cc:548)
  的重命名。**StackX_ 102→0** (21 distinct 全转 iVar/lVar/bVar)。Alignment Evidence 4/4。

### Measured impact (curl_cur.c, 2026-07-02 21:30)
| metric | before phase 2 | after naming fixes | delta |
|---|---|---|---|
| StackX_ | 98 (102 with decls) | **0** | **−102** ✅ |
| param_N | 74 | 74 | 0 (独立路径, 未处理) |
| selfxor V^V | 17 | 17 | 0 (ActionReturnRecovery 缺) |
| reg-leak | 195 | 195 | 0 (varmap/HighVariable 缺) |
| func_gap_audit EXACT | 0 | **0** | 0 |

### 为什么 EXACT 仍 0 (诚实)
命名对齐消除了**一整类占位缺陷** (StackX_ 全清), 但每个函数仍有多类
剩余差异使整体 token 序列无法 EXACT:
- **param_N** (74): 走 printc 的 param_names 路径 (独立于 compact_name_for),
  未接入共享 base。需单独处理 (ActionInputPrototype/param naming)。
- **reg-leak** (195, 53 distinct): EAX_/RAX_ 等未提升为 HighVariable 的寄存器名
  直接输出。根因在 varmap/HighVariable 合并未覆盖这些寄存器 varnode。
- **selfxor V^V** (17): ActionReturnRecovery::buildReturnOutput 缺 (见上方阶段2①)。
- **struct 访问** (-> 1 vs Ghidra 87): struct/pointer 类型恢复缺 (R60/R61)。
- **丢失的语句/调用** (如 GetStr 丢 strdup 调用): 控制流结构化 + ActionMarkExplicit
  把 CALL 输出标 implied 导致 printc 跳过。

### GetStr 逐函数示例 (剩余差距的典型)
```
GHIDRA: void GetStr(char **string,char *value){ char *pcVar1; if(*string!=0) free(*string);
        if(value!=0 && *value!='\0'){ pcVar1=strdup(value); *string=pcVar1; return; } *string=0; return; }
RUGRA:  long GetStr(long param_1,long param_2){ long bVar2; long lVar1; int * piVar3;
        if(param_1!=0) free(param_2); if(lVar1==0){ *(int *)piVar3=0; return; } else { if(!(bVar2)) return; } }
```
差异: param_N 命名 / 类型 (char** vs long) / reg-leak (bVar2,lVar1,piVar3 未初始化) /
丢失 strdup 调用 / 条件结构错位。非单一命名问题。

### 剩余对齐优先级 (按 ROI)
1. **param_N (74)** — 接入共享 base 重命名 (类似 StackX_ 修复, 中等工作量)
2. **reg-leak (195)** — varmap/HighVariable 提升寄存器 varnode (大工程, SSA 层)
3. **selfxor V^V (17)** — ActionReturnRecovery 移植 (大工程, ParamActive 基础设施)
4. **struct -> 访问 (−96)** — struct/pointer 类型恢复 (R60/R61, 大工程)
