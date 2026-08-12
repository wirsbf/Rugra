# PRINT-RESIDUAL-0001: Curl/GetStr printing residual attribution

Date: 2026-08-13

Status: read-only audit; no production change and no alignment claim

Verdict: the current `2/23` GCC result is dominated by state that is already wrong before `PrintC`, with several independently provable printer mismatches layered on top. The dependency order is therefore storage/callspec and Varnode lifecycle, SSA/Action, type/prototype/scope, and structure before any full-C printer repair. Text-level cleanup is not an admissible substitute for those layers.

## Scope and provenance

| Item | Pinned observation |
|---|---|
| Locked oracle | Ghidra `Ghidra_12.0.4_build`, commit `e40ed13014025f82488b1f8f7bca566894ac376b` |
| Rugra revision inspected | `fcf1345ff04a6cc11b2dda9fa42b750ba9c4d3a3`; the four print/varmap sources had no diff against this revision when inspected |
| Current full-C artifact | `result/curl_cur.c`, SHA-256 `018041a8eb273635ed47a19e46ba03946fd619c0ae1256fde4045e860a488ac9` |
| Full-C input | `examples/curl`, SHA-256 `4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a` |
| GetStr fixture | `PIPE-SNAPSHOT-0001`, `x86:LE:64:default`, compiler spec `gcc`, ELF/BFD symbols only, entry `0x36d0`, 74 bytes, input fingerprint `e4fe0d6fe28d4347f12cdf1062f2954b6a64ba499cd3d9fb225c5888dc65b162` |
| GetStr fixture state | overall `MISMATCH`; Rugra's six stored layers are stable across two isolated release runs |
| Audit command | `python3 tools/audit_syntax.py result/curl_cur.c` |

The stored GetStr layer snapshot and the current full-C artifact are separate observations. The current `GetStr` signature has improved since the C text stored in the snapshot, so the old Rugra `05_c` text is not treated as a current-output golden. The snapshot remains decisive evidence about the earliest observed object-state divergence because its oracle, input, options, normalization, comparands, and every layer are pinned in `tests/oracle/getstr_pipeline_1204.metadata.json`.

The following locked function bodies were re-read, not inferred from comments or a newer branch:

- `printlanguage.cc:129-582`: `pushOp`, `pushAtom`, `pushVn`, `pushVnExplicit`, `pushSymbolDetail`, `parentheses`, `emitOp`, `emitAtom`, `recurse`, `opBinary`, and `opUnary`.
- `printc.cc:424-810,1850-3218`: opcode printing including direct/indirect calls and return; symbol/partial-symbol emission; prototype and local declarations; `emitExpression`; `docFunction`; basic/graph/condition/if/loop emitters.
- `prettyprint.cc:349-1244`: `TokenSplit::print` and the complete `EmitPrettyPrint` queue, width, grouping, indentation, and flush path.
- `varmap.cc:1-340,548-581,630-895,1000-1430` plus the relevant `varmap.hh` declarations: `RangeHint`, variable naming, alias offset gathering, MapState collection/ordering, scope restructuring, and fake inputs.
- Naming dependency only: `database.cc:1756-1793,2434-2517,2850-2865` and `database.hh:358-379` for authoritative default naming and `SymbolNameTree` ordering.

The corresponding Rugra production paths were read in full around `src/printlanguage.rs`, `src/printc.rs`, `src/prettyprint.rs`, and `src/varmap.rs`; tests were not used as substitutes for production behavior.

## Baseline: what `2/23` does and does not mean

The stock audit currently reports:

```text
23 functions parsed
2 C-syntax OK
21 failed
error kinds: other=1195, undeclared=201
```

The two passing parsed functions are `main_free` and `__libc_csu_fini`. This is a useful regression signal, but it is not a semantic defect count:

1. `result/curl_cur.c` says 24 functions were emitted, while `split_functions` recognizes only 23. It misses `main_init` because the return type `CURLcode` is outside its signature regex.
2. The harness compiles each function separately. File-level typedefs are consumed for the first parsed function only, so later `unknown type name 'byte'` first-errors are harness slicing artifacts; `byte` exists at file line 7.
3. The harness supplies some declarations but not `FILE`, `HttpReq`, `URLGlob`, `CURLcode`, or complete `ProgressData`/`Configurable` definitions. Such first-errors cannot by themselves identify a printer defect.
4. GCC is invoked with `-w`. In particular, non-void `return;` diagnostics are hidden.
5. The `other=1195` counter includes source excerpts, carets, notes, and all unmatched stderr lines. It is not 1,195 independent semantic errors.

A diagnostic-only whole-translation-unit pass was also run without `-w`, after removing the report header/footer and supplying placeholder definitions for the named external types. Those placeholders are not oracle data and this pass is not a completion gate; it only removes obvious harness noise. Normalized GCC occurrences were:

| Diagnostic family | Occurrences | Interpretation limit |
|---|---:|---|
| Used but undeclared identifier | 259 | GCC occurrence count, not unique storage objects |
| Scalar `local_*` called as a function | 127 | Static text contains 133 such call sites; later parse damage prevents all sites being diagnosed |
| `return;` in a non-void function | 32 warnings | Suppressed by the stock audit |
| Conflicting/redeclared local name | 5 | Concentrated in `glob_word` and `glob_range` |
| Tokens parsed at file scope after a premature brace | 9 | Concentrated in `match_url` |
| Whole-struct assignment from integer | 1 | `progressbarinit`: `*bar = 0` |
| Pointer/integer comparison or conversion | 7 warnings | Type-state symptom, not proof of a cast-token bug |
| Implicit function declaration | 13 warnings | Mixes absent program declarations with lost call identity |

Additional artifact-level signals, counted directly from the current file:

| Signal | Count / affected scope |
|---|---|
| `local_[0-9a-f]+(...)` call syntax | 133 sites in 18 functions |
| Standalone `(identifier);` expression | 70 lines in 12 functions |
| `(bool)(long)` or `(long)(long)` cast-chain lines | 11 lines in 9 functions |
| Bare `return;` | 46 total; 32 are in 14 functions declared non-void |
| Duplicate/conflicting generated declarations | `glob_word` (`uVar6`, `uVar64`) and `glob_range` (`uVar5`) |
| Code after an unmatched closing brace | `match_url`, current file lines 2017-2058 |

The 18 functions with a scalar `local_*` call are `my_fwrite`, `myprogress`, `GetStr`, `my_get_token`, `my_get_line`, `helpf`, `file2string.part.0`, `SetHTTPrequest.part.0`, `parseconfig.constprop.0`, `SetHTTPrequest`, `progressbarinit`, `glob_word`, `glob_set`, `glob_range`, `glob_url`, `next_url`, `match_url`, and `__libc_csu_init`.

## Earliest decisive evidence: GetStr diverges before printing

The stored GetStr snapshot has an equal numeric lifting skeleton but unequal state at the same layer, followed by a large SSA/Action divergence:

| Layer | Locked Ghidra | Rugra | Decisive observation |
|---|---:|---:|---|
| `00_raw_pcode` | 103 ops / 272 Varnodes | 103 / 272 | Numeric `(address, opcode, input_count, has_output)` sequence is `MATCH`, but direct CALL storage at op 31 is Fspec space index 5 versus synthetic Iop index 7. Varnode 0 is `xunknown8`, flags `0x1000030`, versus no type, flags `0x30`. |
| `01_cfg` | 6 blocks | 6 | First block flags are `0x200` versus `0`; equal block count is not equal parent/flag state. |
| `02_heritage_ssa` | 156 ops / 273 Varnodes / 6 blocks | 105 / 287 / 6 | This boundary is diagnostic (`NO_ORACLE` on the Rugra pause mechanism), but the object cardinality and state are already far apart. |
| `03_action_ir` | 14 ops / 23 Varnodes / 6 blocks | 131 / 439 / 6 | Dead/implied/merged expression state and high-variable ownership are not remotely emitter-equivalent inputs. |
| `04_structure` | 1 root child | 3 | The printer is handed a different structured graph. |
| `05_c` | 272 bytes | 721 bytes | Consequence, not the first divergence. |

The first CALL difference is especially diagnostic. Locked `PrintC::opCall` (`printc.cc:593`) requires input 0 to be `IPTR_FSPEC`, recovers the `FuncCallSpecs`, and otherwise clears the expression state and throws. Locked `PrintC::opCallind` (`printc.cc:637`) obtains the callspec from `op->getParent()->getFuncdata()->getCallSpecs(op)`. A printer cannot reconstruct those identities from a numeric machine address after they were lost.

The current full-C `GetStr` still contains undeclared `plVar*` aliases, hidden `param_35`/`param_33`, and an `int local_0` used as a call target. Its improved two-parameter signature therefore does not close the raw-state, SSA, callspec, symbol, or declaration gaps demonstrated above.

## Locked printer contract versus Rugra's current boundary

| Contract | Locked 12.0.4 behavior | Current Rugra behavior relevant to this audit |
|---|---|---|
| Expression ownership | `pushVn` retains the real Varnode and consuming PcodeOp; `recurse` expands an implied Varnode through its defining `TypeOp`, otherwise resolves its HighVariable/Symbol. | The active RPN path is enabled by default (`printc.rs:585`), but `dispatch_op_rpn` is explicitly partial (`:883-1367`), directly emits some operator text, and silently drops its default opcode arm. CBRANCH pushes a leaf rather than the complete implied definition (`:1161-1169`). |
| Direct/indirect call | Direct calls consume Fspec; indirect calls consume the parent Funcdata callspec; target and arguments retain their object associations and exact order. | The active RPN arm merges CALL and CALLIND, looks up input-0's numeric offset in a flat symbol table, and falls back to `FUN_<offset>` (`printc.rs:1112-1147`). |
| Local declaration | `emitScopeVarDecls` walks authoritative Scope maps/categories and emits Symbols, including their Datatype and identity (`printc.cc:2497-2565`). | `doc_variable_decls_from_funcdata` builds declarations from a discovery/name cache and safety nets (`printc.rs:2925-3113`). Its register declaration prefix list omits names such as `plVar` and `pbVar` that the name producer accepts. |
| Default naming | Scope naming consumes address, use point, Datatype, flags, Symbol category, and one shared `int4 &base`; undefined Symbols are traversed in `SymbolNameTree` order. | `compact_name_for`, `rename_scope_symbol`, and preallocation run in PrintC and approximate creation order using first touch or definition address (`printc.rs:2798-2920`). |
| Function document | `docFunction` reads a completed Funcdata/prototype/scope/structure, emits declarations, and calls `emitBlockGraph` once (`printc.cc:2641-2675`). | `doc_function` builds or clones scope, infers pointer use, writes pointer Datatypes back into final Varnodes, constructs semantic copy/use maps, runs a silent discovery traversal including unreachable subgraphs, emits process-global typedefs/guessed externs, then emits the graph (`printc.rs:4975-5844`). |
| Basic/structured blocks | The basic block walks PcodeOps in list order and filters `notPrinted`, branch, and implied-output state; structured nodes obtain their condition from the terminal branch and recursively emit their exact children. | Narrow tests establish only terminal selection and one top-level graph traversal. Current condition rendering also captures/reparses text and has literal-`1` fallback paths (`printc.rs:1458` and `:4196` region). Complete block-object parity remains unproved. |
| Pretty printing | `EmitPrettyPrint` queues TokenSplit objects, commits groups, calculates spaces/line breaks/indentation, preserves markup payload, and flushes. It does not infer variables, repair types, delete statements, or rebuild control flow. | `EmitNoMarkup::get_output` always invokes `post_process`; `post_process_output` calls the legacy semantic text pipeline (`prettyprint.rs:288-326`). That pipeline backfills locals, changes dereference declarations/pointer arithmetic, and deletes orphan breaks, duplicate labels, illegal lvalues, and orphan cases (`:1737-1763`, `:1917-2490`). |
| Stack symbols | MapState gathers actual stack-space Varnodes in location order, incorporates LOAD/STORE guards, adds a terminal range, `stable_sort`s by `RangeHint`, reconciles Datatypes, and restructures in that order. | Rugra synthesizes stack hints from RSP expressions, omits LOAD/STORE guards, uses a fixed full-stack range, omits `reconcileDatatypes` in `initialize`, and approximates fake inputs (`varmap.rs:1216-1316,1444-1478,1653+`). `gather_offset` also tests byte size against 64 before shifting by `size * 8`, leaving the registered 8-byte boundary defect (`:903-968`). |

## Four decisive semantic dimensions

These dimensions explain why text equality or a syntax-only pass cannot establish the boundary:

1. **References and output mutation.** Locked PrintC borrows the finalized `Funcdata`, `PcodeOp`, `Varnode`, `HighVariable`, `Symbol`, Datatype, and `FuncCallSpecs`; semantic object identity is part of the input. Its mutable state is printer/RPN/token state. Rugra currently mutates Varnode type state during `doc_function` and creates semantic discovery/copy/name maps. A fixture must preserve both alias identity and all object mutations, not just rendered names.
2. **Loop bounds and traversal order.** Locked code uses Scope map/category order, PcodeOp list order, `BlockGraph::getList()` order, reverse input pushes for RPN, and FIFO token-queue order. Rugra additionally uses first-touch discovery, `BTreeMap` declaration order, hash/set membership, definition-address preallocation, and pointer-identity visited sets. Each ordering must be observed separately.
3. **Counters and reset scope.** Locked RPN maintains `pending` and per-entry `visited`; token/group IDs are emitter state; default symbol naming receives one shared mutable base and increments only through authoritative naming. Rugra resets a printer-side compact base, uses a process-global typedef flag, and performs discovery plus final passes. Per-function reset, per-process state, and increment timing are visible semantics.
4. **Sort/comparison keys.** Locked `RangeHint` order is signed start, size, range type, flags, then high index; Datatype is deliberately not a comparison key. Symbol name order is lexical name then `nameDedup`. RPN parentheses use token type, precedence, associativity, and current stage. Replacing these with definition address, first touch, rendered text, or an unordered identity changes output and sometimes state.

## Diagnostic attribution matrix

`UPSTREAM-FIRST` means the earliest demonstrated difference precedes PrintC. `MIXED` means a separate printer contract mismatch is also visible in source. `UNRESOLVED-L4/L5` means the current evidence cannot distinguish a malformed structured input from wrong emission of an equal input.

| Diagnostic class | Current evidence | Earliest upstream cause | Independently real emitter residual | Attribution / required gate |
|---|---|---|---|---|
| Undeclared variables and hidden parameters | 259 normalized GCC occurrences; recurrent body names `plVar*`, `pbVar*`, and `param_N` do not match declarations/prototype. GetStr has this after its signature improved. | Varnode def/use and HighVariable membership; prototype input storage; Scope/SymbolEntry ownership; authoritative naming. GetStr's first Varnode type/flags differ at raw and the Action object graph is 14/23 versus 131/439. | Declaration generation is use/name discovery rather than Scope iteration. The declaration whitelist omits pointer-name forms produced by `compact_name_for`; prettyprint's backfill is another incomplete text-name scan. | **MIXED, UPSTREAM-FIRST.** Require L0-L3 object parity plus an authoritative Scope snapshot before judging remaining declaration text. |
| “Called object is not a function” | 133 textual `local_*` call sites in 18 functions; GCC reaches 127 of them. GetStr declares `local_0` as `int` and calls it. | Stable Fspec/callspec identity, PcodeOp parent Funcdata, function Symbol/Datatype, and ActionFuncLink/call cleanup. GetStr's first substantive storage difference is Fspec index 5 versus Iop index 7. | CALL and CALLIND are collapsed into numeric-offset lookup; the locked mandatory callspec paths are not consumed. Name discovery can then declare the rendered call target as an integer local. | **MIXED, UPSTREAM-FIRST.** `SPACE-0001` → `ADDRESS-0001` → `CALLSPEC-0001` and parent/opbank identity must match before the complete direct/indirect call printer fixture is meaningful. |
| Conditional type / malformed condition | Pointer/integer warnings; cast chains; empty conditions; 70 standalone expressions; code after returns. | CBRANCH input def/use, implied/explicit flags, boolean Datatype, dead/notPrinted state, Action simplification, and structured-block terminal/parent identity. GetStr already has huge Action and root-shape differences. | Active CBRANCH emits the input as a leaf, incomplete opcode arms bypass OpToken precedence, and condition helpers capture/reparse rendered text with a literal-`1` fallback. These differ from locked RPN/structured emission even on a sound IR. | **MIXED, UPSTREAM-FIRST.** Compare the exact terminal CBRANCH and complete implied-def tree at L3, then the exact BlockCondition/BlockIf input at L4, before an L5 RPN trace. |
| Void/return/type/field errors | 32 suppressed non-void bare-return warnings; pointer/integer conversions; `progressbarinit` assigns integer zero to an entire `ProgressData` object; named type first-errors depend on harness context. | Final FuncProto output/input, callspec, Datatype identity and facing type, field/offset recovery, Symbol map, and type Actions. The raw GetStr Varnode lacks even the oracle's initial unknown type. | PrintC writes guessed pointer types into Varnodes, supplies fallback scalar types/guessed externs, and emits incomplete global type context. Incomplete RPN STORE/partial-symbol resolution can lose a field selection. | **MIXED.** Treat missing `FILE`/`HttpReq`/`URLGlob` as harness/environment noise until the translation-unit type contract is pinned. Gate expression/type blame on L0-L3 type/prototype/Symbol parity. |
| Duplicate names | `glob_word` has conflicting/repeated `uVar6`/`uVar64`; `glob_range` has conflicting/repeated `uVar5`. Existing naming work also records cross-run instability. | Duplicate or split HighVariables/Symbols, incomplete scope restructuring, and absent authoritative Symbol tree identity. | Printer-time compact renaming/preallocation is not `SymbolNameTree` traversal and declaration collection is split across multiple safety-net sources. | **MIXED.** Close `VARMAP-GATHEROFFSET-0001` and run `VARMAP-NAMING-0001` with full Symbol/Scope state before measuring L5 declaration order. |
| Repeated/strange expressions and unreachable text | 70 no-op expressions; empty loops/conditions; repeated regions after unconditional returns; `match_url` closes a brace early and leaves lines 2017-2058 at file scope. | Dead/implied/notPrinted flags, parent ownership, Action convergence/cleanup, and structured root/child identity. The GetStr L3/L4 evidence proves these inputs can differ dramatically. | Partial RPN silently drops opcodes; custom structured emission is only narrowly tested; semantic post-processing can delete or rewrite statements/labels/types/control-flow after emission. | **UNRESOLVED-L4/L5 for the brace failure; otherwise MIXED, UPSTREAM-FIRST.** Capture pre-postprocess tokens/text and the complete structured object graph. Never infer a brace or dead-code repair from final text alone. |

### What is already narrowed by existing printer fixtures

- `PRINT-RPN-0001A` matches visible group text for selected unary/binary cases, but exact TokenSplit group identity remains untested. It does not validate the opcode dispatcher or symbols.
- `PRINT-RPN-0001B` matches six terminal/no-branch statement-selection scenarios, while raw text remains `MISMATCH`. It rules out one selection rule as the sole cause of all standalone expressions; it does not establish equal CBRANCH expression inputs.
- `PRINT-RPN-0001C` matches one `docFunction` → `emitBlockGraph` list-order/single-dispatch contract, while the complete object graph remains `MISMATCH`. It does not prove every structured node's recursion, braces, parent ownership, or condition emission.
- The current full Curl artifact has 70 standalone expressions. Historical counts attached to those fixtures describe their pinned artifacts and must not be substituted for this current count.

## Required observability ladder

Each layer must preserve array/list order and object identity. Only JSON key order/whitespace and already documented host-pointer-to-space-index normalization are admissible.

| Layer | Required observable state | Question it answers |
|---|---|---|
| L0: raw P-code/storage | Complete AddrSpace name/index/type, Fspec/Iop distinction, SeqNum, op order/address/opcode, all input/output Varnode identities and storage, Varnode type/flags/def/descendant order | Did lifting/storage/lifecycle already change the object the printer will eventually see? |
| L1: CFG/parent | Block order/ranges/flags, exact PcodeOp parent and Funcdata identity, input/output edge slot and reverse index, terminal op | Are calls, branches, and block ownership attached to the correct function and block? |
| L2: Heritage/SSA | Full ordered op/Varnode sets, MULTIEQUAL/INDIRECT creation, def-use links, HighVariable membership, cover/input/marker flags | Are aliases such as `plVar` and redundant expressions products of wrong SSA state? |
| L3: Action/type/symbol/callspec | Live/dead/notPrinted/implied flags, op parents, FuncCallSpecs per call, FuncProto storage/type/locks, facing Datatypes, Scope/Symbol/SymbolEntry maps/categories/names and mutation order | Are the callable, declaration, condition, return, and field identities final and oracle-equal? |
| L4: structure | Root/list order, exact node subtype/flags/parent, child order, terminal CBRANCH, iterate/initializer/goto targets, one ownership/emission path per block | Is repeated text or brace damage already represented in the structure? |
| L5: PrintC/RPN | Selected declaration Symbols and statement PcodeOps; call target class; ordered `pushOp`/`pushVn`/`pushAtom` trace with actual object IDs; pending/visited/paren/modifier state; text before post-processing | Which residual is a true PrintC mismatch on equal semantic input? |
| L6: pretty printer | TokenSplit class, semantic payload IDs, group/open-close IDs, widths, spaces, bump, indent stack, queue/scan order, low-level text | Is the residual only token grouping, markup, spacing, or line breaking? |
| L7: complete translation unit | Real type/prelude environment, all emitted functions and declarations, GCC without `-w`, structured diagnostic JSON | Is the final artifact valid C after the causal layers are known? This is a sink gate, not root-cause localization. |

For `match_url`, the decisive missing observation is the boundary between L4 and L5: the exact same structured graph must first be shown to have identical parent/child/order/terminal state, then pre-postprocess output must be captured. For undeclared variables and scalar calls, L0-L3 are already known to be unequal on GetStr, so L5 text edits would only hide the first divergence.

## Dependency-ordered repair gates

This is an implementation dependency order, not a proposal to change the printer in this audit.

1. **Make the measurement honest.** Pin one complete Curl translation-unit type environment, include every emitted function (including `CURLcode` return types), remove `-w`, retain per-function and whole-unit diagnostics, and record artifact/toolchain hashes. Keep the current `2/23` as the named historical baseline rather than silently changing its denominator.
2. **Close storage, identity, and parent foundations.** `SPACE-0001` → `ADDRESS-0001`/`SEQNUM-0001` → `VARNODE-0001`/`OPBANK-0001` and the in-flight Varnode/block/insert fixtures; then `CALLSPEC-0001`. Acceptance is full L0/L1 equality, not just 103 numeric opcode signatures.
3. **Close SSA and Action state.** `VARIABLE-0001`, `COVER-0001`, `HERITAGE-0001`, canonical Action lifecycle/tree, cleanup and type Actions. Acceptance is equal ordered L2/L3 objects, including HighVariable membership and live/dead/notPrinted/implied mutations.
4. **Close type, prototype, database, and local-scope state.** `TYPE-0001`, `FSPEC-0001/0002`, parameter recovery/binding, `DATABASE-0001`, `VARMAP-GATHEROFFSET-0001`, then `VARMAP-NAMING-0001`. Acceptance is equal FuncProto, callspec, Datatype facing, Scope/SymbolEntry tree, names, and declaration order before PrintC.
5. **Close structured ownership.** `BLOCK-0001` and the relevant control-flow/structure Actions must yield equal L4 roots, parents, child order, terminal branches, and unique ownership. The `match_url` L4/L5 boundary fixture belongs here.
6. **Only then classify remaining PrintC residuals.** Extend `PRINT-RPN-0001` from its narrow fixtures to full direct/indirect call, implied expression, STORE/partial symbol, declaration, prototype, and each structured node using equal L3/L4 inputs. A remaining ordered token/text difference at this point is a genuine emitter mismatch.
7. **Pretty printing is last.** `PRETTY-0001` should compare TokenSplit payload/group/queue/line-break behavior only after L5 semantic text matches. Semantic text post-processing cannot be credited as pretty-printer alignment and must not be used to declare upstream state fixed.

`PRINT-DETERMINISM-0001` spans gates 4-6: full Curl output must be byte-identical across isolated processes, but forcing a stable hash by sorting rendered text would not satisfy authoritative Symbol/RPN ordering.

## Stop conditions and non-conclusions

- Do not open a printer patch from the `2/23` number alone. A category becomes printer-owned only when the corresponding L0-L4 input is equal or when a narrow same-object fixture independently demonstrates the PrintC contract difference.
- Do not declare undeclared `plVar*` fixed by adding a prefix to a text backfill list; declaration and body identity must originate from the same HighVariable/Symbol/Scope object.
- Do not declare scalar calls fixed by formatting `local_*` as `FUN_*`; direct and indirect call specs, parent Funcdata, argument order, prototype, and error behavior must match.
- Do not replace malformed conditions with `1`, delete illegal lvalues, or remove post-return regions as a correctness repair. Those transformations erase the state needed to diagnose Action/structure defects.
- Do not treat missing named external types in the current per-function harness as proof of a PrintC expression defect; first pin the translation-unit type environment.
- The current evidence supports `MISMATCH`, not L3, for full PrintC/prettyprint/varmap behavior.

## Reproduction commands used

```bash
git rev-parse HEAD
git -C ghidra rev-parse HEAD
sha256sum result/curl_cur.c examples/curl \
  result/pipeline_snapshots/getstr/comparison.json \
  tests/oracle/getstr_pipeline_1204.metadata.json
python3 tools/audit_syntax.py result/curl_cur.c
rg -o '\blocal_[0-9a-f]+\s*\(' result/curl_cur.c | wc -l
rg -n '^[[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\);[[:space:]]*$' result/curl_cur.c | wc -l
rg -n '\((bool|long)\)\(long\)' result/curl_cur.c | wc -l
```

The diagnostic-only whole-unit compile used GCC `-std=gnu11 -fsyntax-only` without `-w`, stripped only the report header/footer, and prepended placeholder named types in the command stream. Its counts are intentionally reported as diagnostic observations rather than oracle evidence.
