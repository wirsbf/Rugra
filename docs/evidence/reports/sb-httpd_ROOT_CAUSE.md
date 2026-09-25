# ROOT_CAUSE.md — httpd skeleton 2344→3576 regression from 79bb0f6 (FINAL, M1)

Lane N, wt/sb-httpd. Oracle = Ghidra 12.0.4 e40ed130 (worktree ghidra/ symlink).

## Verdict (one line)

79bb0f6 ported ONLY the three anchoring steps of `FlowInfo::setupCallSpecs`
(flow.cc:683-686) onto the inject path and deliberately skipped the flow-time tail
(flow.cc:688-694 `applyPrototype`/`queryCall`/cycle-check/`checkForFlowModification`);
on the httpd driver nothing else completes the tail (curl has TWO completions:
FlowInfo::query_call at flow.rs:1389 + driver-side link_call_specs at
curl_decompile.rs:827), so every anchored spec enters the universal Action pipeline
modelless+nameless, `ActionDefaultParams` (coreaction.rs:9310-9348) then installs the
internal default model (+ RUGRA-GLUE default_x86_64 proto_model seeding) and
`ActionFuncLink` (coreaction.rs:9871-9888 → fspec.rs init_active_input/output) turns on
active trial recovery for EVERY call — the trial slice fabricates per-call param/return
COPY statements (379 `x=x` self-copies + ~559 floating assignments in the bad output)
that the base (spec-less) state never produced → +1232 skeleton lines.

## Evidence chain (Ghidra ↔ Rugra line mapping)

1. Ghidra flow.cc:680-695 `FlowInfo::setupCallSpecs`:
   - 683-684 `new FuncCallSpecs(op)` (ctor fspec.cc:4924-4947: CALL → entryaddress =
     in(0)->getAddr(); if IPTR_FSPEC dereference prior spec; CALLIND → invalid entry)
   - 685 `data.opSetInput(op, data.newVarnodeCallSpecs(res), 0)`
   - 686 `qlst.push_back(res)`
   - 688 `data.getOverride().applyPrototype` (no overrides on this path)
   - 689 `queryCall(*res)` → flow.cc:656-672: entry valid → scope->queryFunction(entry)
     → `setFuncdata` (name+entry) → `copyFlowEffects` (is_inline|no_return)
   - 690-693 injection cycle check (fc==0 here)
   - 694 `checkForFlowModification(*res)` → flow.cc:636-651: isInline→injectlist;
     isNoReturn→`artificialHalt` insert AFTER op (block boundary!)
2. Rugra 79bb0f6 block, src/funcdata.rs:6834-6870 (post-diff): implements exactly
   (1a)+(1b)+(1c) over ALL CPUI_CALL in op_refs (linear-scan dump, includes ops Ghidra's
   flow walk would never xref — H1 scope widening), with NO counterpart of 688-694.
   Rugra HAS the tail ported for the FlowInfo path: flow.rs:1367-1407 setup_call_specs
   calls self.query_call (flow.rs:1308-1351, faithful to 656-672 using fd.symbol_table +
   driver-fed callee_func_protos) and check_for_flow_modification.
3. Driver topology asymmetry:
   - curl FINAL decompile = `follow_flow_with_callee_protos` (curl_decompile.rs:2667) →
     specs anchored WITH query_call; then driver `link_call_specs` (curl_decompile.rs:
     827-930) installs locked libc/DWARF protos + noreturn marks → ActionDefaultParams
     sees hasModel() → skips internal-default → FuncLink takes the locked path
     (direct attachment, no trials) → no garbage; curl 3718→3711 (improvement via the
     pre-pass channel: prototype-worker fds now anchor specs, ActionInferParams count
     results shift slightly).
   - httpd FINAL decompile = `inject_raw_ops` (httpd_decompile.rs:394) → specs anchored
     WITHOUT any tail; NO driver-side completion exists; `fd.external_prototypes`
     (param counts, httpd_decompile.rs:357) is consumed by NOTHING in the default
     action set for direct CALLs (only ActionCallParams:2075 — NOT registered in
     universal_action — and ActionDeindirect:9979 — CALLIND only).
4. Output forensics (/dev/shm/rugra-tests/sb-httpd/*.c):
   - base main = 137 lines (collapsed straight-line call soup, calls named via the Iop
     compatibility offset → symbol_table printc bridge, funcdata.rs:9848-9858)
   - bad main = 669 lines: 212 `uVarN = uVarN` self-copies + floating copies
     (`uVar8 = uVar1` after apr_app_initialize etc.) — trial-slice fabrication
   - golden main = 534 lines: full oracle param recovery
     (`iVar3 = apr_app_initialize(auStack_9c,&local_a8,0);`) — Ghidra's specs all carry
     queryCall-resolved Funcdata (analyzeHeadless discovered every callee), so trials
     converge on real models.

## Four-category semantics check of 79bb0f6's port (per AGENTS.md 机制 A)

- 引用/输出参数: anchoring 3 steps faithful (owner Arc shared across
  new_varnode_call_specs/op_set_input/add_call_specs_owner) — OK
- 循环边界/遍历顺序: op_refs linear order, CPUI_CALL only — OK for reached ops,
  WIDER than Ghidra (all dumped ops vs flow-reached only) — noted, secondary
- 计数器/累加器: none — OK
- 排序/比较键: Vec append order — OK
- MISSING (root cause): the flow-time tail data flow (queryCall name/noreturn/model +
  halt insertion). A spec anchored without its resolution data is a state Ghidra never
  produces at Action time.

## Why curl is unaffected

curl's specs never reach ActionDefaultParams modelless: FlowInfo::query_call +
driver link_call_specs complete the tail (locked protos). httpd's do.

## Fix direction (M2)

Complete the tail at the same inject boundary (src/funcdata.rs phase-1.5 block),
using the data the httpd driver already provides (symbol_table names,
external_prototypes counts), mirroring the exact flow.rs query_call slice + the
curl driver's lock/noreturn install semantics — so anchored specs enter the pipeline
with names/models and the trial slice either converges or is bypassed as in curl.
Experiments (env-gated single build) to pick the minimal variant meeting gates:
httpd ≤2350 defects=0 numbering=0; curl ≤3715 defects=0 numbering=0.

## M2 fix (SHIPPED) — CALLSPEC-DRIVER-0002 registration gate

Empirical probe matrix (single build, env-gated, /dev/shm/rugra-tests/sb-httpd/probe_*.c):
- off        httpd 2344  (parent reproduced; curl 3711 — curl's -7 is inject-independent)
- none       httpd 3576  (79bb0f6 reproduced; curl 3711)
- name       httpd 3576  (set_funcdata alone: zero effect — names already print via the
                          Iop compatibility-offset -> symbol_table printc bridge)
- namevoid   httpd 3576  (input/output locks: byte-identical to none — FuncLink locked
                          vs trial path produces no observable difference on this path)
- namecount  httpd 3576  (httpd arch has NO defaultfp -> carrier.has_model()==false ->
                          install skipped entirely)
- spec_only  httpd 3576  (register WITHOUT in(0) swap: full regression -> the driver is
                          the qlst REGISTRATION, not the swap)
- swap_only  httpd 2343  (swap WITHOUT registration: better than parent)

Mechanism (corrected): registering modelless specs into fd.callspecs flips
Heritage::callOpIndirectEffect (heritage.cc:362-364 / heritage.rs:4339) from the
conservative no-spec polarity into per-call effect guarding; with no defaultfp model
and no trial registration on the inject path, ActionFuncLink/ActionActiveParam attach
nothing, so every call site gains indirect-effect barriers whose reload copies
(379 x=x chains + ~560 floating assignments) survive as statements — Rugra's universal
tree has no ActionCopyPropagation (coreaction.cc:5510-5511) to collapse them.

Fix: keep anchoring + annotation swap unconditional (CALLSPEC-DRIVER-0001 intent);
gate add_call_specs_owner on fd.funcp.has_model() — the data precondition of the
setupCallSpecs tail (flow.cc:688-694) that Ghidra never separates from qlst
registration. Curl prototype workers bind cspec models -> unchanged.

Final gates: httpd 2343 / defects=0 / numbering=0 (<=2350 ✓); curl 3711 / 0 / 0
(<=3715 ✓). Binaries: /dev/shm/rugra-tests/sb-httpd/final_{httpd,curl}.c.
