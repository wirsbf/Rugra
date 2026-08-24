# R10 — ACTION-EXECUTOR-BREAKPOOL-0001 post-varmap rebase adjudication

- Date: 2026-08-25 (session R10, adjudication + re-verification agent)
- Worktree: `/home/wirs/.cache/rugra-wt-breakpool-rebase`, branch `agent/action-break-pool-rebase`
- Locked oracle: Ghidra 12.0.4, commit `e40ed13014025f82488b1f8f7bca566894ac376b` (cpp tree `b02e230a…`, Makefile blob `ca0719fa…`) — verified by both runners' identity gates
- Discipline: every build/run under `flock /tmp/rugra-cargo-build.lock`, `CARGO_TARGET_DIR=/home/wirs/.cache/r10-adj-target`, `TMPDIR=/home/wirs/.cache/r10-adj-tmp`, `timeout` wrappers; no `git add -A`; no push; main repo untouched (read-only)
- Inputs: master post-varmap baseline `result/curl_cur.c` sha256 `b9f34811cbce602ba10387650fcb7b0311d123adabd98a800434c365dbfb9b2e` (skeleton 2405 / defects 2 / numbering 1, reproduced this session), golden `tests/golden/ghidra_curl_1204.c`

## 1. Rebase result

`git rebase master` (master = `0f6b284`, includes varmap `c042d9a` + `4fcfc1b`): **clean, zero conflicts** — confirmed by file-set intersection (master's 81665b8..0f6b284 touches `src/{varmap,flow,fspec,stringmanage,arch}.rs` etc.; the branch's write-set is `src/{action,subflow,double_precis,ruleaction,condexe,constseq}.rs` + tests/tools — **no overlap**).

| old (base 81665b8) | new (base 0f6b284) | subject |
|---|---|---|
| 3e62f15 | 7d7a6ba | core: implement breakpoint-aware Action pool executor |
| 39c8812 | d39ef31 | rework: close ACTION-EXECUTOR-BREAKPOOL-0001 review rejections |
| c3b3366 | e7da910 | test: re-pin ACTIONPOOL/BREAKPOOL oracle runners to rebased tree |
| — | **da55e15** | test: re-pin BREAKPOOL runner base to post-varmap master (R10) |

Blob identity across the rebase: all six overlay blobs byte-identical (`src/action.rs` blob `5e8de9b…` unchanged; subflow/double_precis/ruleaction/condexe/constseq SAME). Runner pin deltas: only `rugra_base_commit/tree/src_tree` moved (→ `d39ef31f` / `80fa0648` / `dfa35ed2`); `sleigh_shim` tree and Cargo.toml/lock/build.rs blobs unchanged (master never touched them since 81665b8). Metadata `rugra_source` + `comparand.runner_sha256` updated in the same commit (da55e15, hooks green, 4-line diff).

## 2. Re-verification (all real executions)

| gate | result |
|---|---|
| `cargo check --lib` (r10 target, flock, timeout 1200) | PASS, exit 0 (pre-existing warnings only) |
| `tools/run_action_break_pool_oracle.sh` (re-pinned to d39ef31, full bilateral: C++ oracle rebuilt from locked commit + Rust snapshot rebuilt) | **exit 0, covered_projection=MATCH**, overall=MISMATCH (conservative: PIPE-BREAK/PIPE-POOL/PIPE-RESTART/OPBANK), stdout sha `4a095fe46cd96aef…c1bbf` (796 lines), stderr sha `e9bc4d9f…fc33b` — **byte-identical to the R7-approved projection** |
| `tools/run_action_pool_clone_filter_oracle.sh` (no re-pin needed: base `1b859f2` is an ancestor of master, overlays unchanged) | **exit 0, B2 covered projection MATCH (27 records) SHA `600441907a37bf…7f7fe`** — identical to R7 |
| `cargo build --release --example curl_decompile` + single E2E run | exit 0; **124/124 processed: 75 decompiled, 0 empty, 1 timeout, 0 panic** (= master profile); output `/tmp/r10-curl-merged.c` sha256 `165f3e72d6c713c3fa527d9793f23b3dffefde29bc6c8f7b69041a6a52e16858` |
| `compare_ghidra.py` merged vs golden | **skeleton 2412 / defects 2 / numbering 1** (master baseline: 2405/2/1 → **+7 skeleton, defects & numbering unchanged in count AND location**) |

Defect/numbering location identity: defects stay in `helpf` + `file2string.part.0`, numbering stays in `match_url` — the same functions as the post-varmap master baseline (VARMAP-LOCALWINDOW-0001 Differential). The executor swap introduces **no new compare-tool defect**.

## 3. Label adjudication (post-varmap)

### 3.1 Landscape change vs R7

R7's drift set (GetStr / my_get_token, `uVar_10000044` vs `uVar_100000a1`) is **obsolete**:
- **GetStr is now byte-identical on both sides and clean vs golden** — the varmap local-window fix resolved it; R7's original blocker function no longer drifts.
- The drift **migrated**: 10 functions now differ in label sets between merged and master (211 diff lines total, all inside these 10 + decl-block index shifts).

### 3.2 Per-function adjudication table

golden truth = what `tests/golden/ghidra_curl_1204.c` has at the same source position.

| function | merged side | master side | golden truth | text verdict |
|---|---|---|---|---|
| myprogress | `uVar_10000044` | `uVar_100000a1` | counter-named `uVar2/uVar4/uVar6…` (no `_`-fallback) | **equidistant** (same fallback defect class, both wrong form) |
| helpf (defect fn) | `uVar_100000fc` | `uVar_10000090` | clean canary-free body, `__stack_chk_fail()` | **equidistant** (identical defect expression both sides) |
| file2string.part.0 (defect fn) | `uVar_100000bc` | `uVar_10000060` | same | **equidistant** |
| match_url (numbering fn) | `uVar_10000175` | `uVar_10000181` | `while (cVar4 == '#')` | **equidistant** |
| my_get_line | `uVar_100001e4`/`uVar_100002d3` | `uVar_100000d8`/`uVar_100002eb` | typed `lVar1/pbVar2/pcVar3/__dest…` | **equidistant** |
| next_url | `uVar_1000003c`/`_dc`/`_1df` | `uVar_100000d3`/`_f7`/`_ff` | typed `cVar1/sVar2/UVar3…` | **equidistant** |
| my_get_token | + unused `undefined8 uVar2;` decl, indices +1 (pbVar3→4 …) | no extra decl | `cVar1/ppuVar2/pcVar3/__n/__dest` | **master closer** (merged adds 1 unused decl) |
| glob_set | + unused `undefined4 uStack_68;` | none extra | no stack locals at all (8 clean typed vars) | **master closer** |
| glob_range | + unused `int iStack_40;` | none extra | no stack locals | **master closer** |
| glob_word | + unused `undefined4 uStack_90;` + extra used local `pbVar10` (real IR split) | different fallback set | 7 clean typed vars | **master closer** (+2 lines) |
| progressbarinit | + unused `undefined4 uVar1;`, `lVar1→lVar2` shift | `lVar1` | `__nptr` + **`lVar1`** | **master closer** (+1 unused decl; index moves away from golden's literal `lVar1`) |
| getparameter.constprop.0 | 2 fallback decls, **drops 2 `piVar6 = uVara8 + 1;` copies**, `uVarb8`→`uVar_100000ac` | 1 fallback decl, keeps copies | **no golden counterpart** (golden inlines `getparameter` callers only) | neutral (unadjudicable vs golden) |

The +7 skeleton decomposition: glob_set +1, glob_range +1, glob_word +2, my_get_token +1, progressbarinit +1, getparameter.constprop.0 +1 — exactly the 5 unused declarations + glob_word's extra used local + getparameter's second fallback decl line.

**All 5 extra declarations are single-occurrence (declaration only, zero uses)** — verified by occurrence counts.

### 3.3 Unique-offset arithmetic cannot arbitrate

`uVar_<hex>` is `format!("uVar_{:x}", vn.get_offset())` (printc.rs:4220/5164/8152) over the unique space; Ghidra allocates unique offsets monotonically (`varnode.cc:1265-1271 VarnodeBank::createUnique`: `Address addr(uniq_space,uniqid); uniqid += s;`). The final offset therefore encodes **creation order/count of intermediate varnodes**. Observed deltas are mixed (myprogress merged 0x44 < master 0xa1; helpf merged 0xfc > master 0x90; my_get_line mixed) — neither executor uniformly allocates fewer intermediates, and golden's own offsets are invisible in C text (golden has **zero** `uVar_` forms; master output has 226 — all Rugra-side unsymbolized-varnode artifacts of the PRINTC-UNLINKED-REF family). Numeric adjudication: **inconclusive by design**.

### 3.4 Structural tie-break (Ghidra citations) — the equidistant swaps

Both sides' swapped labels are the same defect class; the deciding question is which executor's semantics Ghidra actually has. Read this session against the locked oracle:

1. **`action.cc:877-888 ActionPool::apply`**: `op_state = data.beginOpAll()` is a **live iterator into the PcodeOpTree** (SeqNum-ordered map); `for(;op_state!=data.endOpAll();) if (0!=processOp((*op_state).second,data)) return -1;`. Ops created mid-pass with SeqNum after the cursor ARE visited in the same pass (std::map iteration picks up later insertions). Master's `ActionPool::apply` instead iterates a **snapshot** `fd.obank.alivelist.clone()` — same-pass insertions are invisible until the next repeatapply pass. The branch's `next_op_after` strict-successor range query (src/action.rs:1380-1398) reproduces the live iterator. → **candidate faithful, master deviates.**
2. **`action.cc:829-834`** dead-op entry of `processOp`: `if (op->isDead()) { op_state++; data.opDeadAndGone(op); rule_index = 0; return 0; }` — the op is destroyed from the bank. Candidate mirrors this (`fd.obank.destroy(op_ref)`, src/action.rs:1406-1411); master merely `continue`s. → **candidate faithful.**
3. **`action.cc:836-869`** per-op rule loop: `rl->isDisabled()` skip (:838), `count_tests += 1` (:842), `res = rl->applyOp(op,data)` (:843), on `res>0`: `count_apply += 1; count += res; rl->issueWarning(...); if (rl->checkActionBreak()) return -1;` (:847-852), opcode-change `rule_index = 0` (:860-869). Candidate implements all of it (src/action.rs:1414-1462); master omits disabled-check/tests/warning/break (env-gated histogram instead). In default E2E these are latent, but they are Ghidra semantics the candidate carries. → **candidate faithful.**
4. **`action.cc:880-883` + `:298-362 Action::perform`**: `status != status_mid` re-anchors the cursor; `status_mid` resumes `op_state/rule_index` after a breakpoint return (perform's "continue from the break point", :295). Candidate implements `apply_from_status` resume; master is stateless. → **candidate faithful.**
5. **`action.cc:506-527 ActionGroup::apply`** retained `state` cursor with `++state` before the action-break return (:518), and **`:553-582 ActionRestartGroup::apply`** restart loop (`curstart`, `clearAnalysis`, reset-all-but-self at :574-580): candidate ports the cursor/status forwarding (rework point 4 of d39ef31); master has no cursor. → **candidate faithful.**

**Ruling on the R7 blocker question (uVar label ownership): neither side's label is "the right one" — golden contains none of them.** The drift is a *visibility artifact* of the PRINTC-UNLINKED-REF/varmap symbolization residual fired under different IR shapes; it is **not owned by the executor**. On every semantic axis Ghidra actually specifies (live traversal, dead-op destroy, rule-index/state machine, restart/cursor), the candidate matches the oracle and master's histogram/snapshot form does not.

### 3.5 The 5 unused declarations: latent downstream gap, not executor logic

Ghidra emits "a formal variable declaration … for every symbol in the given function scope" (`printc.cc:2260-2279 PrintC::emitLocalVarDecls`) — Ghidra can afford this because a scope symbol only ever exists for a range that had a live read: symbols come out of the rename pass over live varnodes (`varmap.cc:1044-1059 MapState::gatherSymbols` seeds from existing entries; `varmap.cc:1088-1118 MapState::isReadActive` filters copy-markers; naming happens on live HighVariable instances). A window range whose varnode's uses are later eliminated never produces a surviving symbol in Ghidra. Rugra's port keeps the window symbol alive after use-elimination and still declares it → the 5 unused declarations. Under master's (unfaithful) executor that IR shape never arises, so the gap is latent there. **Firing a latent downstream gap is not evidence against the faithful executor** (铁律 1.5: default assumption is a porting defect elsewhere, fix bottom-up), but it IS a real +5-line regression vs golden text that must be bound to a TODO before/with integration.

Fix direction for the new gap: suppress declaration emission (or scope-entry removal) for local-window symbols with zero surviving uses — the invariant being Ghidra's symbol⇔live-range coupling above. Files: `src/prettyprint.rs` decl emission / `src/varmap.rs` window entry lifecycle.

## 4. Final recommendation

**先修（登记+修复 orphan-decl），随后集成；不再继续 block 在 uVar 标签归属上。**

1. **Do not block on the label swap itself** — adjudicated equidistant-vs-golden on both sides and structurally owned by the symbolization residual (PRINTC-UNLINKED-REF family), not by the executor. The candidate executor is the faithful substrate (§3.4, five citations).
2. **Register before integration** (root, TODO board — outside R10 write-set):
   - `VARMAP-ORPHAN-DECL-0001` (new): 5 unused local-window declarations (glob_set `uStack_68`, glob_range `iStack_40`, glob_word `uStack_90`, my_get_token `uVar2`, progressbarinit `uVar1`) — declaration-only, zero uses, golden has none; fix = symbol⇔live-use coupling per printc.cc:2260-2279 + varmap.cc:1044-1118.
   - bind the residual fallback-label drift (7 swap functions) to the existing PRINTC-UNLINKED-REF-0001 family rows.
   - glob_word's extra used local (`pbVar10`) and getparameter.constprop.0's `uVarb8→uVar_100000ac` fallback degradation + dropped `piVar6 = uVara8 + 1;` copies: bind to the same family (naming-class residuals; no golden counterpart for getparameter.constprop.0).
3. **Integration gate** (mechanism B/C): integration commit needs a `## Differential` block binding the +7 skeleton (per-function list in §3.2) to the TODO IDs above, and a fresh `## Cross-Review: APPROVE` for the d39ef31 content — R10's independent read of action.cc:298-362/506-527/553-582/822-934/899-924 and varnode.cc:1250-1285 found no MISMATCH in the candidate's covered semantics and supports approval, but the block must come from the designated reviewer per process.
4. Evidence anchors for root: bilateral runner outputs (both PASS, shas above == R7-approved projections), merged E2E output kept at `/tmp/r10-curl-merged.c` (sha `165f3e72…`, 2412/2/1, 75/0/1 profile), re-pin commit `da55e15` on the branch.

R10 verdict on R7's specific question — "candidate `uVar_10000044` vs master `uVar_100000a1`, which is right?": **neither; both are the same known unsymbolized-varnode defect class (golden: zero `uVar_` forms). Where Ghidra does define an answer (executor semantics), the candidate is correct and master's snapshot executor is the deviation.**
