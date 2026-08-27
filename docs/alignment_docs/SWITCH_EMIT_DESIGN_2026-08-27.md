# Switch emission design — Ghidra 12.0.4

**Task:** PRINTC-SWITCH-EMIT-0001 (stage A)  
**Oracle:** Ghidra commit `e40ed13014025f82488b1f8f7bca566894ac376b`, tag `Ghidra_12.0.4_build`.  
**Target:** x86-64 curl specimen, compiler/spec and analysis options are those recorded by the checked-in curl golden generator; input is the repository curl ELF used by `examples/curl_decompile.rs`.

## 1. Rendering chain

### `PrintC::emitBlockSwitch` (`printc.cc:3313-3353`)

The function first saves modifiers, clears `no_branch|only_branch`, then emits the root switch component twice: once with `no_branch` (the index calculation/statements) and once with `only_branch|comma_separate` (the `BRANCHIND` expression). It opens the switch brace with `option_brace_switch`. For each case in the already-finalized order it calls `emitSwitchCase`, starts a per-case indent, and either emits an explicit `emitGotoStatement(root, case, gototype)` for an unstructured edge or calls the case block's virtual `emit`. A case marked `isExit` receives an explicit break unless it is the final case. Indent is stopped and the closing brace is emitted at `3313-3353`.

`PrintC::emitSwitchCase` (`printc.cc:3129-3158`) gets the switch datatype and the case first op. A default emits exactly one `default:` (`3140-3145`). Otherwise it walks `i=0; i<num; ++i`, gets labels in jump-table order, tags a line, prints `case`, one space, and calls `pushConstant(val, ct, casetoken, null, op)`, then `recurse` and `:` (`3146-3157`). Thus case formatting is type-sensitive and labels are not reconstructed from CFG conditions.

The `BRANCHIND` operation is handled by `opBranchind` (`printc.cc:582-591`): it emits the operation's input expression between parentheses. Consequently the switch selector is the input to the indirect branch, not a synthetic cast or a newly inferred expression.

### `BlockSwitch` data and lifecycle (`block.hh:745-800`, `block.cc:3485-3649`)

`BlockSwitch` owns `JumpTable *jump` (`block.hh:753`), and its first graph component is the switch root; remaining components are cases (`block.hh:747-751`). `addCase` (`block.cc:3495-3516`) stores the structured case block, its first basic leaf, the reverse outgoing index, `gototype`, `isexit`, and `isdefault`. `grabCaseBasic` (`3524-3554`) maps switch outgoing slots to case positions, then recognizes plain `BlockGoto` fall-throughs whose target is another switch case (`3535-3545`); a `BlockMultiGoto` root contributes unstructured cases (`3548-3553`).

`finalizePrinting` (`3556-3592`) is essential before emission. It walks each chain to mark non-roots with negative depth, assigns the root label and copies it through the fall-through chain, then performs `stable_sort` on `CaseOrder::compare`. The comparator (`block.hh:899-909`) sorts by `label`, then `depth`; equal labels therefore retain stable input order while chain depth orders fall-through labels. `getSwitchType` (`block.cc:3596-3601`) follows the jump table's indirect op and returns `getHighTypeReadFacing` of input 0. The public accessors (`block.hh:772-792`) expose root, case count/case block, per-case labels, default, goto type, exit bit, and switch type.

### `CollapseStructure::ruleBlockSwitch` (`blockaction.cc:1649-1723`)

The rule requires `bl->isSwitchOut()` (`1652`). It determines an obvious exit by scanning outgoing edges: self-loop first, then a target with `sizeOut>1` or `sizeIn>1` (`1656-1671`). If none is obvious, it rejects goto-in, nested switch, and goto-out cases and chooses a common single output as exit (`1672-1690`). For a determined exit it rejects incoming/outgoing gotos on the exit and requires every case to have at most one non-goto output, to target that exit, and not be a nested switch (`1692-1708`). It then calls `checkSwitchSkips` (`1711-1712`), builds `cases = [switch root, every outgoing target except exit]` in outgoing-edge order (`1714-1720`), and calls `graph.newBlockSwitch(cases, exit != null)` (`1721`).

`checkSwitchSkips` (`blockaction.cc:1607-1644`) is the guard for jump-table default/skip ambiguity. It detects a non-default edge directly to exit and a default edge not directly to exit (`1617-1628`); a multigoto default counts as `defaultnottoexit` (`1630-1634`). When both exist, all non-default skip edges are converted to goto edges (`1637-1641`) and the rule returns false, preventing an unsafe structured switch.

### Pretty-print dispatch

`PrintC::docFunction` (`printc.cc:2641-2676`) chooses flat basic blocks or the structured graph. Structured emission starts at `emitBlockGraph` (`2746-2757`), which wraps every component in `beginBlock`, invokes the virtual `FlowBlock::emit`, and closes the block. `BlockSwitch::emit` is the virtual dispatch declared at `block.hh:797`; it invokes `PrintLanguage::emitBlockSwitch`, implemented by `PrintC::emitBlockSwitch` at `3313`. `EmitPrettyPrint` is the token/layout backend: its `beginBlock`/`endBlock` (`prettyprint.cc:900-915`) enqueue block boundaries and call `scan`; `tagLine` (`917-935`) flushes pending tokens and queues a line break. It does not choose block type; block virtual dispatch does.

## 2. Four decisive semantic checks

| Semantic | Oracle fact | Required Rust check |
|---|---|---|
| References/output | `emitBlockSwitch(const BlockSwitch *bl)` reads shared `jump`, case metadata and mutates only emitter/token state; `getSwitchType` reads the BRANCHIND input type (`printc.cc:3313`, `block.cc:3596-3601`). | Selector and case metadata must be borrowed from the same structured block; do not synthesize or copy a selector type. |
| Loop bounds/order | Cases loop `i=0; i<getNumCaseBlocks(); ++i` (`331-335`); labels loop `i=0; i<num` (`3147-3149`); final order is stable sort label then depth (`3590-3592`, `block.hh:903-909`). | Preserve finalized case order, all labels, and strict `<` bounds; do not deduplicate labels as a CFG convenience. |
| Counters/accumulators | `depthcount=1` is reset per chain root (`3577-3584`); `separator=false` is per basic block (`2692-2721`). | Fallthrough depth is per root chain; emitter separator state is per block/case, never global. |
| Comparison key | `CaseOrder::compare`: label first, depth tie-break (`block.hh:903-909`); `outindex` is reverse-index-derived (`3506-3509`). | Sort by unsigned label then signed depth, with stable-sort preservation for equal keys; retain edge-index mapping. |

## 3. Rust implementation plan (printc.rs lease held by strconst2; no edits in stage A)

Current Rust switch entry is `emit_structured_switch` at `src/printc.rs:4153-4407` (Ghidra counterpart `printc.cc:3313`). Case body dispatch helper is `emit_switch_case_body` at `src/printc.rs:4424-4443`; case label/value emission is inline at `4295-4338` (Ghidra `emitSwitchCase`, `3129-3158`). Structured graph routing is `emit_block_structured` at `src/printc.rs:3464-4149` (Ghidra virtual dispatch chain `block.hh:797`, `printc.cc:2746-2757`).

Expected post-lease diff:

1. `emit_structured_switch`: replace selector fallback heuristics (currently `4212-4252`) with the BlockSwitch's BRANCHIND input accessor, preserving `no_branch` root emission and `only_branch|comma_separate` selector emission. Match `tagLine/openBrace/startIndent/stopIndent` sequencing from `3318-3351`.
2. Case labels (`4295-4338`): consume finalized labels in `caseblocks` order, call the canonical constant renderer using `getSwitchType`, emit one default label only, and retain multiple labels per case. Remove any value-based deduplication unless proven equivalent to `JumpTable`'s per-case label list.
3. Case metadata/break (`4340-4378`): add `gototype`, `isexit`, and final-case metadata to `BlockSwitch`; dispatch nonzero goto type through `emit_goto_statement` and emit break only for `isExit && i != last`.
4. `emit_switch_case_body` (`4424-4443`): keep virtual type dispatch but ensure it does not apply top-level DEAD/consumed suppression to owned case blocks, matching `bl2->emit(this)` at `3339-3341`.
5. `emit_block_structured` switch arm (`4071-4149`/switch callsite): ensure a structured switch is emitted once, while its owned case blocks are not replayed by the unreachable sweep.

### Input data structure gaps

* `BlockSwitch` currently exposes a selector varnode/control arc but not a faithful `JumpTable` label accessor/type path for all cases.
* Per-case `gototype` and `isexit` are not fully represented in the Rust case vector; current code infers return termination and last-label status.
* Fall-through `chain` and `depth` are not exposed, so stable label/depth ordering cannot be independently verified.
* Default is represented as an Arc pointer rather than `isdefault` in each case entry.
* Root outgoing reverse-index/default-edge metadata and `checkSwitchSkips` result are not available to the emitter.
* Virtual case emission lacks a no-DEAD guard equivalent to C++ ownership semantics unless the emitted set is coordinated explicitly.

## 4. Structure-vs-rendering boundary (root baseline update)

The later irreducible-agent baseline supersedes the earlier local measurement: on its tree (five WIP rounds), E2E is defects **0**, numbering **0**, skeleton **2598**, but `getparameter.constprop.0` is **0 switch / 0 case** and is the sole remaining `selectGoto exhausted` site. Its graph is 138 blocks / 51 non-isolated / 86 DEAD, with live root `blk0 -> blk29/blk127`, a large live fan-in goto `blk131`, and an isolated List root `blk133`. This is a structural recovery failure before printing, not evidence that `emitBlockSwitch` rendered incorrectly.

Rugra does have a named `CollapseStructure::try_rule_switch` at `src/blockaction.rs:4191-4453`, corresponding to Ghidra `ruleBlockSwitch` (`blockaction.cc:1649-1723`), and it is registered in the collapse loop at `src/blockaction.rs:1730-1731`. Therefore the gap is not an absent function. The entry gate is `is_switch_out` (`src/blockaction.rs:4196-4199`), and the current implementation additionally leaves `checkSwitchSkips` as a TODO/no-op (`src/blockaction.rs:4370-4371`). The rule constructs and installs a `BlockSwitch` (`src/blockaction.rs:4414-4449`), but the current baseline reaches no successful candidate for getparameter; `selectGoto` exhaustion (`blockaction.cc:1260-1277`, especially the one-edge `clipExtraRoots` failure at 1275) is upstream of emission. `blockaction.cc` has no splitDag/duplicate method; its real TraceDAG is `blockaction.cc:499-1014`, with `pushBranches` `983-1014` and `selectGoto` `1260-1277`. This section is read-only diagnosis: blockaction.rs remains irreducible-agent's lease and is not modified here.

### Jump-table data channel audit

The Rust `BlockSwitch` shape is present at `src/block.rs:5352-5363`. It carries `control`, `cases`, `case_values`, `default_case`, and `index_varnode`; accessors `get_num_labels/get_label/is_default_case/is_exit/get_switch_varnode` are at `src/block.rs:5454-5566`. However, the production `try_rule_switch` currently fills `case_values` with synthetic outgoing-slot ordinals (`src/blockaction.rs:4391-4405`, `case_values.push(vec![j as u64])`) rather than querying the owning `JumpTable`. A second legacy CBRANCH-cascade path similarly fabricates ordinal values (`src/blockaction.rs:5320-5331`) and is explicitly marked non-oracle/disabled. Thus the 48 labels are available in the recovered `JumpTable`, but there is no faithful `BlockBasic -> JumpTable -> BlockSwitch.case_values` channel yet. `BlockSwitch` also lacks C++ `gototype`, `isexit`, `chain`, `depth`, `outindex`, and per-case `isdefault` fields; Rust currently infers/approximates these in printc. This is a **structure-side input/data-model gap**, distinct from the printc rendering lease.

Ownership boundary: irreducible agent/root must first make `is_switch_out` and `ruleBlockSwitch` succeed for getparameter and thread real JumpTable labels/metadata. After that, the printc agent can validate selector and case rendering against the now-live BlockSwitch. The printer cannot recover a missing BlockSwitch or reconstruct labels from CFG slot ordinals without violating the oracle.

## 5. Stage-A measurements (this worktree)

On this worktree's three WIP commits, optimized example build succeeded. E2E (`timeout 500`, stdout/stderr separated) exited 0: 124/124 functions matched, defects **0/124**, numbering **0**, total skeleton diff 3214. Its local artifact happened to show one switch/48 labels; that result is superseded for the coordinated irreducible baseline, which shows 0/0. `glob_set` remains goto-shaped (switch=0, skeleton diff 101, defects 0). Both observations are retained to prevent mixing trees: the coordinated conclusion is that getparameter's remaining exhausted path is structural, while printc remains responsible only for rendering once a real BlockSwitch exists.

## 6. Fixture status

`tests/oracle/switch_emit_1204.cc` and `tools/run_switch_emit_oracle.sh` provide a minimal, compileable text contract harness. The C++ harness records the exact `emitSwitchCase`/`emitBlockSwitch` sequencing and expected 48-label shape; the Rust side is deliberately a TODO placeholder until the printc lease is released. It is a design-stage fixture (`NO_ORACLE` for production Rust output) and must not be promoted to MATCH without a real Ghidra build and pinned metadata.
