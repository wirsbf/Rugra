# HERITAGE-DRIVER-0001: Heritage driver and GetStr SSA audit

Date: 2026-08-13

## Scope and evidence state

This is a read-only source audit. No implementation, TODO-board, or roadmap
state was changed as part of the audit.

- Locked source oracle: Ghidra 12.0.4 tag `Ghidra_12.0.4_build`, commit
  `e40ed13014025f82488b1f8f7bca566894ac376b` (verified in the local
  `ghidra/` tree).
- Ghidra source read in full for this boundary: `heritage.hh`,
  `Heritage::heritage`, `buildADT`, `processJoins`, the complete refinement
  chain including `splitByRefinement`, `placeMultiequals`, `calcMultiequals`,
  `visitIncr`, `rename`, `renameRecurse`, `reprocessFreeStores`,
  `analyzeNewLoadGuards`, `guard`, `guardCalls`, `guardStores`, `guardLoads`,
  `guardReturns`, `guardInput`, and `clearStackPlaceholders`; also
  `ActionHeritage`, `Funcdata::opHeritage`, the surrounding default Action
  construction, `VarnodeCompareLocDef`, `Address`/`SeqNum` ordering, and the
  indirect-op construction/insertion primitives.
- Rugra source read for the same boundary: `src/heritage.rs`, the
  `ActionHeritage` and relevant upstream Actions in `src/coreaction.rs`, and
  the Heritage, op mutation, input, IOP, and indirect constructors in
  `src/funcdata.rs`. The address, space, Varnode ordering, CFG, and call-spec
  dependencies were followed where the Heritage code directly relies on
  them.
- Immutable quantitative witness: `result/pipeline_snapshots/getstr`, made
  from Rugra commit `7e0ebcb874a0417262670725665b8e997fd5ba7b` and the locked
  oracle. The binary SHA-256 is
  `4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a`;
  function is `GetStr@0x36d0+74`, architecture `x86:LE:64:default`, compiler
  spec `gcc`, symbols are ELF/BFD only, and the full language/cspec hashes are
  recorded in `tests/oracle/getstr_pipeline_1204.metadata.json`.
- The Rugra working tree was changing concurrently during this audit. Source
  findings below name functions instead of treating transient line numbers as
  immutable. In particular, op insertion and `op_set_input` had in-flight
  changes after the snapshot. Those changes require a new snapshot and a new
  independent review; they do not retroactively alter the checked-in GetStr
  counts.
- Last live-source fingerprint observed during review: repository HEAD
  `fcf1345ff04a6cc11b2dda9fa42b750ba9c4d3a3`; SHA-256
  `heritage.rs=0ebda7db0326d6797efad3e709cc5a4c8a30b0784e2320854a5fa63cf4ff6b9c`,
  `coreaction.rs=16227e65dcebd78d2895ed061ae819b0b10b3c78a5160e1a459eee9fc7675be3`,
  and
  `funcdata.rs=b8944edc31304f42a5680244710ecc0f909b395d0bcbbb95fa8052aec58f73c8`.
  These content hashes, rather than HEAD alone, identify the dirty concurrent
  source actually reviewed.

Formal result: **MISMATCH at source level**. The checked-in GetStr
`02_heritage_ssa` comparison is explicitly **NO_ORACLE**, not `MATCH`, because
Ghidra pauses the real Action tree immediately before `paramdouble`, whereas
Rugra invokes `ActionHeritage` directly on a different pre-state. The counts
below are strong diagnostic evidence, but not a B2 behavior proof.

## Decisive conclusion

The first Heritage-local repair is the execution/ownership boundary:

`ActionHeritage::apply -> Funcdata::opHeritage -> one Heritage::heritage pass`

Ghidra's wrapper contains exactly `data.opHeritage(); return 0;`
(`coreaction.hh:281-290`), and `Funcdata::opHeritage` contains exactly one call
to `heritage.heritage()` (`funcdata.hh:462`). `Heritage::heritage` performs one
pass and increments `pass` once, at its last line (`heritage.cc:2663-2758`).

Rugra's production wrapper does not call its `Heritage::heritage`. It runs the
alternative `place_multiequals_direct`/`rename_direct` path twice, inserts
`ActionDeadCode` between the two internal passes, discovers stack stores
between them, increments `pass` twice, and permanently returns early after
`pass >= 2` (`src/coreaction.rs`, `ActionHeritage::apply`).
`Funcdata::run_heritage_direct` is another production-facing entry to the same
alternative path. Consequently, fixes made only inside Rugra's nominal
`Heritage::heritage` do not affect the main path.

This is the earliest causal fork inside Heritage, not merely a phi-placement
defect. It bypasses `processJoins`, the persistent/per-pass LocationMaps,
`collect`, exact refinement, `guardInput`, call/return/load/store guards, the
augmented dominator tree, canonical rename, free-store reprocessing, value-set
guard analysis, and the shared `PreferSplitManager` lifetime.

It is **not safe simply to redirect the call today**. The nominal Rugra
`Heritage::heritage` holds the `Funcdata` write lock obtained through a `Weak`,
then attempts to acquire that write lock again in nested helpers; it also has
stubbed or non-equivalent stages. The ownership bridge and the dependencies in
the next section must land before the production switch.

For the two observed headline symptoms specifically:

- First immediate cause of `MULTIEQUAL=0`: the direct Cytron-style placement
  consumes stored dominance-frontier data, but the direct snapshot path has
  not built the oracle-equivalent dominator/ADT state; all frontier worklists
  therefore terminate without a merge. Even with a populated frontier, exact
  `(space,address)` grouping is not equivalent to Ghidra's overlapping
  `LocationMap -> collect -> refinement -> guard` pipeline.
- First immediate cause of the missing 20 call `INDIRECT`s: canonical
  `guardCalls` is not on the production path. Its partial Rugra counterpart
  also cannot reproduce the result because call effects currently collapse to
  `unknown_effect`, output characterization calls the input characterization,
  stack translation and two effect branches are missing, and the indirect
  constructors lose the requested space/IOP identity.

## Exact dependency DAG

An arrow means the target cannot be behaviorally correct until the source
contract is correct. This is a semantic DAG, not just a Rust module-import
graph.

```text
SPACE-IDENTITY (dynamic space index/type/wrap/word-size)
  -> ADDRESS (space + offset identity and order)
     -> VARNODE-LOC-ORDER
        -> LocationMap/globaldisjoint/TaskList
           -> collect/refinement/guardInput
              -> placeMultiequals
     -> RANGE/OVERLAP
        -> processJoins/refinement/load-store guards

SEQNUM (PC address + uniq/time order)
  -> OPBANK/XREF (nullable inputs, def/use, create/destroy, opcode lists)
     -> OP-INSERT (parent + exact block position)
        -> IOP-ALIAS (INDIRECT input[1] aliases the exact causing op)
           -> guardCalls/guardStores/reprocessFreeStores
           -> rename same-time INDIRECT rule

CFG-EDGE-IDENTITY (slot + reverse slot + edge flags)
  -> DFS BLOCK ORDER + immediate dominators + ordered dom children
     -> buildADT (depth, boundary flags, augment order)
        -> PriorityQueue/visitIncr/calcMultiequals
           -> placeMultiequals
              -> rename

PROTO-MODEL effect list + parameter lists + stack translation
  -> stable FuncCallSpecs objects in call order
     -> ActionExtraPopSetup/ActionPrototypeTypes/ActionFuncLink
        -> call placeholders + active input/output trials
           -> guardCalls

ACTION lifecycle (startProcessing + filtered/repeating Action tree)
  -> exact pre-Heritage state and same observer boundary
     -> ActionHeritage wrapper
        -> Funcdata::opHeritage ownership bridge
           -> canonical Heritage::heritage single pass

processJoins ------------------------------------+
PreferSplitManager(pass-0 shared instance) ------+
per-space delay/placeholder/discovery -----------+
LocationMap -> collect -> refinement -> guards --+-> place -> rename
freeStores shared vector ------------------------+-> reprocessFreeStores
load/store guard suffixes -----------------------+-> analyzeNewLoadGuards
loadCopyOps -------------------------------------+-> handleNewLoadCopies
                                                   -> splitAdditional(pass 0)
                                                   -> pass += 1 exactly once

one-pass Heritage result
  -> later ParamDouble/.../DeadCode Actions in mainloop
     -> Action repeat/convergence decides whether another Heritage pass occurs
```

The critical foundation gates are therefore:

1. Space-aware `Address` and dynamic space-index order. Rugra's `Address` is a
   scalar `u64`, while Ghidra's identity and order are `(AddrSpace*, offset)`.
2. Stable PcodeOp/Varnode identity, complete bidirectional def-use updates,
   nullable input-slot semantics, block parent/order insertion, and IOP
   references that alias the actual causing op.
3. Oracle DFS block order, edge/reverse-slot identity, immediate dominators,
   ordered dominator children, and ADT construction.
4. Stable callspecs, prototype-model effect lookup, parameter
   characterization, stack offset translation, and active-trial mutation.
5. `startProcessing`/Action execution and a same-boundary observer, so both
   sides enter Heritage after the same preceding Actions.

An op-insertion fix is necessary but not sufficient: it unlocks parented
`INDIRECT`/`MULTIEQUAL` operations, but does not create the missing disjoint
ranges, call effects, ADT, or canonical pass ownership.

## Locked Ghidra pass, in exact mutation order

`Heritage::heritage` is a single pass with this sequence
(`heritage.cc:2663-2758`):

1. If `maxdepth == -1`, call `buildADT`.
2. Call `processJoins`.
3. Construct one local `PreferSplitManager`. On pass 0, initialize it from the
   architecture's real `splitrecords` and call `split`.
4. Iterate `infolist` by ascending architecture space index. For each active
   space whose `delay <= pass`:
   1. clear call placeholders once when its flag says they exist;
   2. perform indexed-stack-pointer discovery once when `loadGuardSearch` is
      false, sharing one `freeStores` vector across the pass; if discovery
      succeeds, increment `reprocessStackCount` and remember `stackSpace`;
   3. iterate that space's `VarnodeLocSet` interval in location order;
   4. advance the iterator before any mutation (`vn = *iter++`);
   5. skip dead unused frees and write-mask Varnodes;
   6. update persistent `globaldisjoint`, and add a correctly flagged range to
      the current-pass `disjoint` cover according to `prev` = 0, 1, or 2;
   7. preserve warning/restart state if new or overlapping ranges appear after
      dead removal.
5. `placeMultiequals` walks the current `disjoint` cover in order. For each
   range it clears and reuses the four vectors, calls `collect`, optionally
   refines a range larger than four bytes when no write spans it, removes
   revisited markers, fills/concatenates partial inputs, normalizes all reads
   and writes, adds indirect guards once for a new range, calculates merge
   blocks, and inserts each phi at the beginning of its block.
6. `rename` starts only at block 0 and clears current `disjoint` after the
   recursive dominator walk.
7. If discovery requested it, reprocess the same `freeStores` vector in its
   original order.
8. Analyze only newly appended LOAD/STORE guard suffixes, then handle newly
   generated load-copy ops.
9. On pass 0, invoke `splitAdditional` on the **same** `PreferSplitManager`
   instance used by step 3.
10. Increment `pass` once.

There is no `pass >= 2` early return in `Heritage::heritage`, and it does not
run `ActionDeadCode`. `ActionDeadCode` is a later sibling in the repeating
`mainloop` (`coreaction.cc:5487-5504`); the Action executor, not Heritage,
decides convergence and another invocation.

## Reference, alias, and lock semantics

### Oracle contracts

- `Heritage::fd` is one authoritative `Funcdata*`. Every helper mutates the
  same VarnodeBank, PcodeOpBank, block lists, callspec objects, warning state,
  and architecture objects.
- `globaldisjoint` persists across passes. `disjoint` is the current-pass cover
  and is cleared only by `rename`. They are different state with different
  lifetimes.
- The `read`, `write`, `input`, and `remove` vectors contain the actual
  Varnode pointers. `guardCalls`, `guardReturns`, `guardStores`, and
  `guardLoads` append into the same `write` vector later consumed by
  `calcMultiequals`; this is an output/reference parameter, not a returned
  copy.
- `freeStores` is one pass-local vector shared by discovery and
  `reprocessFreeStores`. Its order is observable because reprocessing walks it
  by index and walks each block backward through the contiguous INDIRECT group.
- `FuncCallSpecs*` and its `ParamActive` objects are stable shared objects.
  `guardCalls` registers trials and appends call inputs in place while it also
  creates guards.
- An IOP Varnode's address identifies the exact causing `PcodeOp*`.
  `PcodeOp::getOpFromConst` must round-trip that alias. Address equality alone
  is insufficient because multiple p-code ops can share an instruction
  address.
- All op rewrites go through `Funcdata::opSetInput`, `opSetOutput`, insertion,
  unlink, and destroy APIs. These atomically preserve both sides of the
  def-use graph and exact block membership/order.

### Rugra mismatches and lock hazard

- `Heritage` stores `Weak<RwLock<Funcdata>>`. The nominal `heritage()` upgrades
  and takes a write lock, then nested code takes that same write lock again.
  This cannot model Ghidra's non-owning raw pointer; it can deadlock before
  completing a pass.
- The production workaround detaches/takes banks and invokes direct helpers.
  Those helpers consequently bypass many `Funcdata` mutation contracts and
  form a second algorithm rather than a Rust ownership translation of the
  oracle algorithm.
- The nominal per-space loop iterates a clone of `infolist`; per-space state
  changes cannot naturally persist through that cloned record. It also loops
  over every `globaldisjoint` entry for every space (its filter is literally
  true), then gives `guardCalls` a fresh `empty_write`, discarding the output
  vector that should drive phi placement.
- The nominal pass creates a new `PreferSplitManager` for
  `splitAdditional`; this loses the state of the instance used by `split`.
- `Address` omits address-space identity. Rugra compensates with parallel
  `AddressSpace` parameters and `(AddressSpace, Address)` keys in some paths,
  but `LocationMap` and several helpers still receive only `Address`. Ranges in
  different spaces can alias or be cross-processed.
- Current `guard_calls_range_with_space` finds a call op by instruction address
  rather than stable callspec/op identity, drops the computed output-effect
  override, omits stack translation, and handles only `unknown_effect`. It
  omits `return_address` and `killedbycall` constructor branches.
- `FuncCallSpecs::has_effect` currently returns `unknown_effect` for every
  range; `characterize_as_output` delegates to input characterization.
- `new_indirect_op` hard-codes Stack space and `INDIRECT_STORE`, and builds
  input 1 as a Const/annotation rather than the IOP-space Varnode already
  supported by `new_varnode_iop`. `new_indirect_creation` hard-codes Unique
  output space. Both lose the caller-supplied `Address` space semantics.
- In the audited direct rename, input replacement writes `op.inrefs` and
  pushes a new descendant directly instead of using `Funcdata::op_set_input`.
  Thus the old descendant is not removed before `has_no_descend` is tested.
  The same defect exists on successor-phi inputs. It also copies `v_type` from
  the free read to its replacement, a Rugra-only mutation.
- The checked-in snapshot exposes the consequence: both Rugra INDIRECTs have
  no parent block and their IOP-like operand is in Const space. Concurrent
  op-insertion/xref work may change this live source symptom, but must be
  re-snapshotted before it can count as evidence.

The Rust-safe ownership translation should keep one persistent `Heritage`
object but pass an exclusive `&mut Funcdata` explicitly through the pass. The
top-level `Funcdata` bridge can temporarily move out `self.heritage`, execute
one pass against `self`, and restore the same Heritage state. That prevents
re-entrant locking without cloning banks, ranges, callspecs, output vectors, or
the pass state.

## Loop order, pass counters, and sorting keys

These details are load-bearing; equivalent sets in a different iteration order
are not proven equivalent.

| Contract | Locked Ghidra behavior | Audited Rugra issue |
|---|---|---|
| Constructor | `pass = 0`, `maxdepth = -1` | `Heritage::new` sets `maxdepth = 0`, so the driver's `-1` rebuild condition cannot fire initially |
| Heritage pass | one call, one final `pass += 1` | wrapper performs two internal increments and hard-stops at 2 |
| Per-space order | `infolist[0..numSpaces)` in architecture index order | fixed enum list `Ram, Register, Unique, Const, Stack, Join, Iop`, not the architecture's dynamic order |
| Space delay | skip while `pass < delay` | direct path checks delays only while gathering exact-location definitions; it bypasses the rest of the per-space state machine |
| Join write | only when `pass == piecespace.delay` | `process_joins` is incomplete; equality is critical because a join write must split once |
| Varnode scan | `beginLoc(space)..endLoc(space)`, iterator advanced before mutation | direct grouping and cloned vectors do not reproduce the ordered, mutation-safe scan |
| Current ranges | ordered `TaskList`, merged only with the previous range because producer order is sorted | direct `BTreeMap<(space,address)>` groups exact starts; overlap cover/refinement is absent |
| Phi seed order | normalized `write` vector order, then block 0 if unmarked | direct worklist seeds exact definitions and any input-like entry blocks |
| Rename root | block 0 only | direct rename visits every block with zero predecessors |
| Op/input order | block execution order; input slots ascending; write pushed after reads | direct traversal separates leading phis, marks every storage active, and pre-seeds all inputs |
| Phi successor order | outgoing edges ascending; exact reverse slot; leading MULTIEQUALs only | depends on Rugra edge/order state and directly edits inputs |
| Dom traversal | `domchild[block]` order | uses block-stored children; correctness depends on the not-yet-proven CFG/dom producer order |
| Stack pop | writes in their encounter order after all dom children | iterative form can be equivalent only if child scheduling and per-block write order are identical |
| Free-store postpass | `freeStores[0..n)`, then `previousOp()` through a contiguous matching IOP group | incomplete/disconnected from the production pass |
| Guard analysis | newest unanalyzed LOAD suffix backward, then STORE suffix backward; update suffixes forward | conservative stub; no `ValueSetSolver` result |

Exact comparison keys are:

1. `Address`: null/sentinel handling, then address-space `getIndex()`, then
   offset (`address.hh:368-392`). A scalar offset is not the same key.
2. `SeqNum`: p-code PC `Address`, then `uniq/time` (`address.hh:153-158`).
3. `VarnodeCompareLocDef` (`varnode.cc:34-52`): Address; size ascending;
   `(input|written)-1` class, which orders input, then written, then free;
   written values by defining SeqNum; free values by `createIndex`; inputs at
   the same storage compare equal. Rugra's live comparator comments mention
   `(f-1)` but compare raw flag values, which puts free first, and it orders
   `AddressSpace` by Rust enum declaration rather than architecture index.
4. `PriorityQueue`: maximum dominator depth first and LIFO within equal depth
   (`heritage.cc:141-175`).
5. `buildADT`: blocks by DFS index; child and predecessor slots ascending;
   bottom-up loop `size-1` down through 0; top-down loop 1 through `size-1`;
   augment edges appended in discovery order.
6. `visitIncr` scans each augment vector in producer order and has an early
   `break` when the strict-ancestor condition stops holding
   (`heritage.cc:2394-2428`). Augment order is therefore semantic, not cosmetic.
7. `calcMultiequals` consumes writes in vector order, requires every write's
   defining op to have a valid parent block, always seeds block 0, and clears
   mark/merged flags only after queue exhaustion (`heritage.cc:2439-2466`).

`analyzeNewLoadGuards` has two solver iteration budgets, not Heritage passes:
first `solve(10000, WidenerNone)`, then, only if partial results remain,
`solve(10000, WidenerFull)`. It collects only the newest contiguous
`analysisState == 0` suffix of each guard list by walking backward; it appends
LOADs before STOREs to the solver arrays, then writes results forward over the
same suffixes (`heritage.cc:834-900`).

## Why GetStr is 23 MULTIEQUAL / 20 INDIRECT versus 0 / 2

### Aggregate delta

Both raw snapshots have 103 ops and 272 Varnodes, and their numeric
`(address.offset, opcode, input_count, has_output)` op signature sequence
matches. At the diagnostic Heritage layer:

| Side | ops | Varnodes | MULTIEQUAL | INDIRECT |
|---|---:|---:|---:|---:|
| Ghidra 12.0.4 | 156 | 273 | 23 | 20 |
| Rugra snapshot | 105 | 287 | 0 | 2 |

The exact Ghidra raw-to-layer delta is 53 ops:

| Added opcode | Count | Producer at this layer |
|---|---:|---|
| COPY | 1 | `ActionConstbase` tracked-context initialization |
| INT_ADD | 4 | two call extra-pop repairs plus two call stack-placeholder address calculations |
| LOAD | 2 | one stack placeholder per call from `ActionFuncLink` |
| INDIRECT | 20 | Heritage `guardCalls` |
| MULTIEQUAL | 23 | Heritage ADT placement |
| PIECE | 1 | Heritage normalization/refinement |
| SUBPIECE | 2 | Heritage normalization/refinement |

Thus the preceding Actions contribute 7 ops, and Heritage contributes 46.
Rugra adds only two stack-store INDIRECTs. This also proves that comparing
“immediately call Rugra ActionHeritage” with Ghidra's real Action breakpoint
mixes different input states; a same-boundary fixture is required.

### The 20 call guards

Ghidra creates exactly ten guards immediately before each of the two calls:

- Call at decimal 14052 (`0x36e4`), block 1: 10 INDIRECTs, each IOP operand
  aliases normalized call-op ID 32.
- Call at decimal 14091 (`0x370b`), block 4: 10 INDIRECTs, each IOP operand
  aliases normalized call-op ID 120.

The affected register ranges are identical at both calls, in this order:

```text
(offset,size) =
(0,8), (48,8), (56,8),
(512,1), (514,1), (518,1), (519,1), (522,1), (523,1),
(648,8)
```

For offset 0 the first input is constant zero, showing the
`newIndirectCreation`/killed-by-call form. For the remaining nine ranges the
first input is the prior register value, showing the normal `newIndirectOp`
form. Every op is parented in the call's block and inserted in the contiguous
INDIRECT group immediately before the exact call.

The count is therefore `2 calls * 10 ABI-affected ranges = 20`. It is not a
generic “one guard per call” heuristic. It depends on the compiler model's
effect records, callspec order, output activity/trials, exact range/space
identity, write-vector append order, and two different indirect constructors.

The two Rugra INDIRECTs are instead at instruction addresses 14032 and 14036,
use Stack-space sentinel/wrapped storage, have no parent in the checked-in
snapshot, and use Const-space input 1. They are stack STORE discovery guards,
not the 20 call guards. Canonical `guardCalls` never ran on the production
path.

### The 23 phi nodes

Ghidra places 11 phis at block 2, the merge of the entry bypass and the first
call path:

```text
register (offset,size) =
(0,8), (32,8), (48,8), (56,8),
(512,1), (514,1), (518,1), (519,1), (522,1), (523,1),
(648,8)
```

Ten ranges carry the first call's guarded effects. Register `(32,8)` is the
stack pointer: it merges the entry path's raw/pre-action stack update with the
extra-pop repair after the call.

Ghidra places 12 phis at block 5, the merge of the block-2 bypass and the
block-3 conditional path:

```text
unique   (146176,1), (151296,1), (361216,8), (361472,1),
         (361728,1), (508416,1), (508928,1)
register (512,1), (514,1), (518,1), (519,1), (523,1)
```

These are branch-local definitions plus normalized/refined pieces. The second
call is in exit block 4, so its ten guards do not flow to another join in this
function. Therefore `11 + 12 = 23`; the number is explained by concrete merge
blocks and storage ranges, not by raw CFG join count alone.

Rugra places zero because the active direct algorithm never constructs the
oracle ADT/disjoint/collect/guard state, and its dominance-frontier input is
empty at this boundary. Its exact-start grouping would additionally miss
overlapping/refined ranges even after a dominator fix.

### Varnode lifecycle signal

| Snapshot | total | `def == null` | `uses` empty | both |
|---|---:|---:|---:|---:|
| Ghidra raw | 272 | 182 | 92 | 2 |
| Ghidra Heritage layer | 273 | 130 | 58 | 4 |
| Rugra raw | 272 | 182 | 92 | 2 |
| Rugra Heritage layer | 287 | 195 | 83 | 6 |

Ghidra adds 53 ops but only one net Varnode because canonical rename replaces
and deletes frees while maintaining both def-use directions. Rugra adds only
two ops yet grows by 15 Varnodes. That is independent evidence of a replacement
and destruction lifecycle defect, not merely missing phi placement. The
direct manual input assignment explains the checked-in symptom; the ongoing
`op_set_input` fix will help only after rename actually calls it.

## Function-by-function source mismatches

| Oracle function | Required behavior | Rugra state at audit |
|---|---|---|
| `ActionHeritage::apply` | one `data.opHeritage()` call, return 0 | alternate two-pass algorithm, embedded DeadCode, hard pass limit |
| `Funcdata::opHeritage` | thin authoritative bridge | no production-equivalent bridge; `run_heritage_direct` is a different algorithm |
| `Heritage::Heritage` | `pass=0`, `maxdepth=-1` | `maxdepth=0` |
| `buildInfoList` | one record per architecture space, keyed by dynamic index | fixed enum list/order |
| `buildADT` | consume already-built oracle dominators/DFS order and construct Bilardi-Pingali augmentation | partial implementation behind re-entrant lock; production direct path uses Cytron frontiers instead |
| `processJoins` | split free reads; split writes exactly on `pass == delay`; preserve float-extension path and mutation-safe iteration | partial/stub behavior |
| `heritage` per-space driver | placeholders, one-time discovery, persistent/global and per-pass covers, warnings/restarts | TODOs and cross-space `globaldisjoint` scan; not production path |
| `collect` | one ordered range scan; clear four output vectors; return maximum write size; identify revisited markers | direct path groups exact definitions and bypasses this contract |
| refinement / `splitByRefinement` | `size+1` fencepost, convert boundaries to piece sizes, remove 1-3 patterns, split/refit reads/writes/inputs and both covers | refinement array is `size`, boundary bits are used as piece sizes, and cover updates are not canonical |
| `guardInput` | fill holes, mark pieces write-mask, concatenate a final full-range active value | incomplete final-state/mask behavior |
| `guard` | normalize exact range; mark active; add calls/returns/stores/loads only for new ranges | production direct rename marks nearly every non-constant/annotation Varnode active |
| `guardCalls` | call order, translated stack address, exact effects/trials, three effect branches, append shared writes | disconnected and partial as detailed above |
| `placeMultiequals` | ordered disjoint ranges, exact collect/refine/guard, ADT queue, parented insertion at block start | alternative exact-location dominance-frontier algorithm |
| `rename` / `renameRecurse` | block 0 only, op order, slot order, exact `opSetInput`, stable IOP same-time rule, ordered dom recursion and pop | all entry-like blocks, pre-seeded inputs, direct graph edits, broad active marking, extra type mutation |
| `reprocessFreeStores` | rediscover same vector and remove only contiguous matching store INDIRECTs | helper exists but driver does not call it with canonical discovery state |
| `analyzeNewLoadGuards` | suffix-only ValueSetSolver with None then Full widener | conservative “mark analyzed/full range” stub |

## Smallest safe atomic implementation after foundations

The smallest production-safe unit is **one complete canonical Heritage pass and
its ownership bridge**, not an isolated phi heuristic:

1. Give the Rust Heritage pass an explicit exclusive `Funcdata` reference;
   retain one Heritage object and all of its persistent state, but do not take
   a nested `RwLock<Funcdata>` and do not detach/copy the banks.
2. Add the thin `Funcdata::op_heritage` ownership bridge that temporarily moves
   out that one Heritage object, calls the pass once against the same
   `Funcdata`, and restores it.
3. Make `ActionHeritage::apply` do only that one call and return zero. Remove
   production use of the direct placement/rename route, its embedded DeadCode,
   its hard two-pass limit, and internal pass increments.
4. Within that same behavior unit, execute the exact
   `processJoins -> pass-0 split -> per-space discovery/cover ->
   placeMultiequals -> rename -> postpasses -> splitAdditional -> pass++`
   sequence. The same vectors/objects must flow across its stages.
5. Leave repeat scheduling and DeadCode to the Action executor, as in the
   oracle.

Landing only items 2-3 while calling the current nominal method would expose a
deadlock/incomplete algorithm. Landing only exact ADT placement while the
production wrapper still bypasses it would be dead code. They must switch as
one atomic behavior unit after the five foundation gates in the DAG are met.

The smallest useful proving fixture for that unit is a **call-free diamond**
with one exact storage range. It must prove one complete pass:
LocationMap/collect, ADT placement, parented phi
insertion, exact rename, deletion of consumed frees, and one pass increment.
This is a narrow fixture, not a claim that calls, joins, delayed stack heritage,
or load guards are aligned. The GetStr fixture and the focused fixtures below
must all pass before `HERITAGE-DRIVER-0001` can be marked `MATCH`.

## Real Ghidra fixture schema and acceptance matrix

### Provenance envelope

Every fixture result must record, and the runner must reject omissions or
differences in:

- fixture ID and schema version;
- oracle tag and commit;
- Rugra commit and source-tree hash;
- architecture/language ID and hashes of SLA, pspec, cspec, ldefs;
- compiler spec and prototype model;
- complete Action name, enabled group list, breakpoint/observer position, and
  analysis options;
- binary or serialized-input SHA-256, function entry/name/size, loader and
  symbol source;
- context/tracked-register inputs, overrides, random seed, and error-injection
  policy;
- producer/generator hashes and build profile.

### Same-input pre-state

Capture an ordered `before` object graph immediately before the real
`ActionHeritage` on both sides. The preferred mechanism is an Action observer
inside each normal filtered `decompile` tree. Replaying a leaf directly is not
the same boundary.

The graph must include:

- Heritage `pass`, `maxdepth`, persistent `globaldisjoint`, current
  `disjoint`, queue/merge state, per-space info including space index/type,
  `delay`, `deadcodedelay`, `deadremoved`, `loadGuardSearch`, warning and
  placeholder flags, plus load/store guards and load-copy ops;
- architecture spaces in index order with type, highest offset, wrapping,
  address/word size, delays, contain/overlay/base relationships, and split
  records;
- callspecs in call order: exact op identity, selected model/effect records,
  stack offset, locks, input/output active trials and their order;
- blocks in index order: parent/type/flags, entry address, immediate dominator,
  depth, ordered dominator children, ordered input/output edges with slot,
  reverse slot, and flags, and exact op membership/order;
- ops: stable fixture ID, complete SeqNum (space/index/offset, uniq/time/order),
  opcode and all flags, parent block and list position, ordered nullable inputs,
  output, and callspec/guard relationships;
- Varnodes: stable fixture ID/createIndex, space index/name/type and offset,
  size, all flags, Datatype/symbol/cover state, defining op, and ordered
  descendant occurrences including operand slot;
- warnings, restart state, dead-list/alive-list/opcode-list membership, and
  pending placeholders.

### Complete observed result

Capture the same graph as `after`, plus an ordered mutation journal sufficient
to distinguish create/delete/relink/reorder operations. Record return value or
exception class/message and every output/reference mutation, including:

- ranges added/merged/refined and exact flags/pass numbers;
- callspec trial registration and inserted call operands;
- each created/destroyed/moved PcodeOp and Varnode;
- old/new operands and both descend-list changes;
- IOP target aliases as references to stable op IDs;
- block insertion position and parent changes;
- final per-space/pass/guard/warning/restart state.

Only process pointers and serialization map keys may be normalized to stable
fixture IDs. Array order, object aliasing, edge/reverse slots, SeqNum order,
block membership, state changes, and repeated references must not be erased by
normalization.

### Required fixture set

| Fixture | Required witness | Main branches covered |
|---|---|---|
| `heritage_empty_pass_1204` | one empty entry block, no IR change, one pass increment, exact wrapper return | ownership bridge, constructor/rebuild, Action boundary |
| `heritage_diamond_phi_1204` | exactly one parented phi and full before/after def-use graph | ADT, queue, placement, rename, free deletion |
| `heritage_overlap_refinement_1204` | exact PIECE/SUBPIECE/write-mask graph and refined covers | fencepost, split read/write/input, guardInput |
| `heritage_call_guard_sysv_1204` | one call, exact effect list, expected per-range INDIRECTs and IOP aliases | effect branches, trials, call order, insertion order |
| `heritage_stack_delay_store_1204` | pass 0 skips delayed stack; later pass discovers, guards, and selectively reprocesses stores | delays, placeholders, freeStores alias/order, DeadCode separation |
| `heritage_join_1204` | free read splitting and write splitting exactly at `pass == delay` | processJoins mutation and equality boundary |
| `heritage_load_guard_1204` | old guard prefix untouched; new suffix None-widener then Full-widener result | suffix order, solver budgets, load/store lists |
| `getstr_heritage_1204` | same Action boundary and exact 23 phi / 20 call guard graph at the listed blocks/ranges | integrated processor/unique/call/refinement path and all upstream pre-state |

Each row remains `NO_ORACLE` until the locked C++ fixture has actually run and
its complete result is stored. It is `MISMATCH` when a real result exists with
a registered difference, `UNTESTED` when required branches/state are absent,
and only `MATCH` when the complete ordered observation is zero-diff on the same
input. A hand-written expected count or Rust-only test is a regression test,
not a behavior gate.

## Acceptance order

1. Pass the space/address/SeqNum, op/xref/IOP, and CFG/dominator foundation
   fixtures.
2. Pass the callspec/effect and exact Action-boundary fixtures.
3. Land and cross-review the single-pass ownership/driver atomic unit.
4. Pass empty, diamond, overlap, call, stack-delay/store, join, and load-guard
   fixtures with complete object-graph comparison.
5. Regenerate GetStr at the same boundary. Require exact 23/20 identities,
   ranges, parents, input slots, IOP aliases, def-use lists, and final pass
   state—not counts alone.
6. Run the affected call closure and end-to-end curl/httpd differential gates.

Until these gates pass, Heritage remains L2/MISMATCH-or-NO_ORACLE regardless of
whether a C sample becomes prettier.

## Primary locked source anchors

- `heritage.cc:218-224` — constructor.
- `heritage.cc:307-347` — `collect` output vectors and ordered range scan.
- `heritage.cc:834-900` — new guard suffix analysis and two solver budgets.
- `heritage.cc:1111-1141` — free-store reprocessing and backward INDIRECT walk.
- `heritage.cc:1156-1199` — normalization and guard fan-out.
- `heritage.cc:1443-1527` — call order, translated address, active trials,
  effect branches, and write-vector append.
- `heritage.cc:1694-1940` — fencepost refinement, splitting, and cover rewrite.
- `heritage.cc:1952-2010` — input-hole filling, write masks, final concat.
- `heritage.cc:2281-2313` — mutation-safe join scan and exact delay equality.
- `heritage.cc:2316-2385` — augmented dominator tree.
- `heritage.cc:2394-2466` — ordered augmentation walk and priority queue phi
  calculation.
- `heritage.cc:2479-2593` — exact recursive rename and disjoint clearing.
- `heritage.cc:2599-2645` — ordered placement pipeline.
- `heritage.cc:2650-2758` — space list and entire single-pass driver.
- `heritage.hh:95-170,172-275` — queue, per-space/guard state, shared object
  layout, and single-pass contract.
- `coreaction.hh:281-290`, `funcdata.hh:462`,
  `coreaction.cc:5477-5504` — wrapper and Action ownership/order.
- `varnode.cc:34-52`, `address.hh:153-158,368-392` — decisive ordering keys.
