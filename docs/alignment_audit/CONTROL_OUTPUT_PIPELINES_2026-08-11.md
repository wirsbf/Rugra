# Control, recovery, and output pipelines audit — 2026-08-11

This report records independent read-only audits against the locked oracle:

- tag: `Ghidra_12.0.4_build`
- commit: `e40ed13014025f82488b1f8f7bca566894ac376b`
- Rugra baseline: `cb46f31` plus this documentation-only audit
- source denominator: 114 decompiler `.cc` files

The source audits establish deterministic non-equivalence and reject the
affected L3/L2.5 claims. The repository does not yet contain locked 12.0.4
same-input fixtures for these behaviors, so the formal behavior-gate state is
`NO_ORACLE`, not `MATCH` and not a fixture-backed `MISMATCH`. Existing Rust
unit tests and the 11.3.2 curl golden remain regression diagnostics only.

## Executive result

The failures form one production pipeline:

```text
Architecture init / ownership
  -> UserOp + PcodeInject registries
  -> Flow lift, CALLOTHER xref, entry/call injection
  -> ActionStart: CFG order + dominators + Heritage info
  -> one canonical Heritage pass
  -> stable PcodeOp/Varnode/Block state
  -> CondExe and PathMeld rewrites
  -> JumpTable model recovery and SwitchNorm
  -> PrintLanguage RPN + PrintC structured walk
  -> PrettyPrint token queue and semantic markup
```

Every arrow currently has at least one broken invariant or missing production
call. Adding a high-level Action before the lower state model is repaired would
make the latent failure reachable rather than close the pipeline.

| Area | Locked-source result | Formal gate |
|---|---|---|
| Heritage / SSA | live Action bypasses canonical driver; canonical driver deadlocks; pass/order/def-use/guards differ | REJECT / NO_ORACLE |
| CondExe / PathMeld | block/op lifecycle, edge slots, ordered path merge, exceptions, and Action state differ | REJECT / NO_ORACLE |
| JumpTable | Override/Basic/Basic2/Assisted model recovery and emulation closure are incomplete or bypassed | REJECT / NO_ORACLE |
| Print / PrettyPrint | RPN groups, token recursion, structured traversal, semantic payload, and Oppen queue differ | REJECT / NO_ORACLE |
| Architecture / UserOp / PcodeInject | component ownership and initialization are absent; Flow never invokes the injection closure | REJECT / NO_ORACLE |

## 1. Heritage is not the production SSA algorithm

The locked pipeline calls `ActionStart -> Funcdata::startProcessing`, then one
`ActionHeritage -> Funcdata::opHeritage -> Heritage::heritage` pass. The pass
increments its counter once after completing space-delay selection, collect,
normalization, refinement, guards, ADT Phi placement, and rename.

Rugra's production sequence is materially different:

```text
ActionStart                                      no-op
ActionHeritage
  direct dominance-frontier Phi + direct rename  pass += 1
  DeadCode
  custom stack STORE BFS
  direct dominance-frontier Phi + direct rename  pass += 1
... later ActionBlockStructure builds dominators
```

The CLI performs another direct Heritage pass before the Action tree. Thus CLI
and example paths enter later Actions at different pass counts, while neither
matches the oracle state machine.

### P0: first live pass has no dominance state

- `src/coreaction.rs:596-600` leaves ActionStart empty.
- the existing `Funcdata::start_processing` at `src/funcdata.rs:5529` has no
  production caller;
- direct Phi placement reads dominance frontiers at
  `src/heritage.rs:3226-3234`, and rename follows dominator children at
  `:3662`, before the pipeline builds either structure;
- tests explicitly call `build_dom_tree` first, masking the production order;
- the later `ActionBlockStructure` cannot repair the first pass because the
  global `pass >= 2` guard has already disabled Heritage.

### P0: canonical entry is both unreachable and unsafe to connect

`Heritage::heritage` at `src/heritage.rs:2937` has no production caller. It
takes `fd_arc.write()` at `:2946` and tries to take the same non-reentrant write
lock again at `:3020`, before the outer guard is released. The first eligible
range would deadlock.

Even after that lock is corrected, the current body is not the locked state
machine: it discards the TaskList predecessor returned by range insertion,
uses an always-true range filter, skips collect/refinement/guard and join
branches, and initializes `maxdepth` to 0 instead of -1. It must not be wired
into the Action tree as-is.

### P0: live rename corrupts def-use and IOP identity

The locked rename goes through `Funcdata::opSetInput`, which removes the old
read occurrence, installs the new one, and deletes a now-unused free Varnode.
Rugra directly overwrites input Arcs at `src/heritage.rs:3568-3577` and
`:3645-3654`, adds the new descendant, and never removes the old descendant.
The correct integrated helper already exists at `src/funcdata.rs:886-933` but
is bypassed.

The same-time INDIRECT branch requires an IOP reference to the causing op.
`new_indirect_op` instead stores a Const-space SeqNum annotation, while the
existing IOP helper is unused. New guards are also placed only in the flat op
bank, not in `BlockBasic.ops` with a parent/order, so block rename cannot see
them.

### P0: direct Phi and refinement are different algorithms

The locked algorithm uses an augmented dominator tree, a maximum-depth LIFO
priority queue, `visitIncr`, and range-aware `calcMultiequals`. The live Rust
path is a FIFO dominance-frontier worklist keyed only by `(space,address)`:

- size is absent from the key;
- frontier iteration comes from a `HashSet`;
- Phi size is guessed from an often-empty map or defaults to four;
- placeholder inputs are pushed without descendant records;
- traversal starts from every zero-input block and silently stops after a
  hard work-item cap.

The dormant refinement path has a separate termination bug. It records
boundary bits but never converts boundary positions to segment lengths;
`split_by_refinement` then consumes a zero `cutsz` without changing remaining
size, address, or offset. Connecting this branch can produce an infinite loop.

### P1: guards, joins, delays, and restart are stubs or substitutes

`guard_calls` is empty; `guard_returns` creates detached COPY ops;
`guard_loads_range` records a hit without creating the required COPY;
ValueSet results are forced to a full range/state 1; `process_joins` only logs.
The live stack search is a custom BFS supporting a small COPY/constant ADD/SUB
subset rather than the locked descendant-order DFS with
INDIRECT/SEGMENTOP/MULTIEQUAL and load/store/free-store records.

`clear`, dead-code delay overrides, restart state, and per-architecture space
iteration also differ. These are not leaf TODOs: downstream alias, merge, and
`RuleIndirectCollapse` consume the missing state.

## 2. CondExe and PathMeld cannot preserve CFG state

ConditionalExecution depends on exact PcodeOp lifecycle and atomic two-sided
CFG edges. Both foundations are currently invalid, and the module adds its own
deterministic differences.

### P0: graph rewrites fail at the primitive level

- `Funcdata::op_destroy` removes an op from global state but not from
  `BlockBasic.ops`; a supposedly emptied conditional block remains non-empty.
- `remove_from_flow_split` implements `flip=false` as the locked crossed case;
  its `flip=true` branch accesses outgoing slot 1 after deleting the first
  edge and can index out of range.
- half-delete and swap operations fail to repair peer reverse indices.
- new pullback/Phi/RETURN COPY ops can be alive globally without block parent,
  block order, or specialized opcode-list membership.

### P0: branch truth is translated twice

The locked CFG has outgoing slot 0=false/fallthrough and slot 1=true/target.
BooleanExpressionMatch accounts for the CBRANCH flip exactly once. Current
Flow builds target before fallthrough, helper methods already inspect
`BOOLEAN_FLIP`, and CondExe verification applies another flip. The four
combinations of two matching CBRANCH flip bits cannot all map to the locked
paths. `FALLTHRU_TRUE` is also absent from the model.

### P0: execution state, pullback, and errors differ

- heritage eligibility is a fixed four-space all-true array instead of
  architecture `numSpaces`, per-space heritage flag, pass, and delay;
- pullback replaces the original output storage with a new unique and inserts
  at block begin instead of preserving storage and inserting at predecessor
  end;
- verification scans forward and ignores every branch; the locked algorithm
  scans backward, skips only the final CBRANCH, and checks earlier ops;
- unsupported reads and illegal COPY continuations become `None` after partial
  mutation instead of the locked exception;
- ActionConditionalExe omits the unreachable-block guard, rebuilds its object
  for each block, walks a snapshot rather than a growing live vector, discards
  hit count, returns the wrong Action status, and is registered before its
  structural prerequisites;
- RuleOrPredicate is registered as `or_predicate`, while the locked name is
  `orpredicate`.

### PathMeld is not an ordered meld

Locked `PathMeld::meldOps` compares parent blocks and `SeqNum.getOrder`, finds
the next common point, computes a cutoff for incomparable paths, and truncates
both paths. The Rust implementation uses pointer identity and conservative
append, with no order comparison, cutoff, or truncation. It writes a bit into
`addlflags` rather than the PcodeOp `MARK` flag and invents a LOAD exception
that accepts a one-byte range of 256 values where the locked code rejects it.
`set_path`/`set_single` clear the object although the oracle APIs append.

## 3. JumpTable recovery has no complete model path

The public type surface gives a false impression of closure. The decisive
recovery paths remain missing or bypassed:

- `JumpBasicOverride::findStartOp` is absent and `trialNorm` returns -1, so an
  override cannot recover the locked normalized path;
- recovery clears state that the oracle retains across the override/model
  handoff;
- the shared PathMeld cannot order or truncate paths;
- local EmulateFunction cannot read loader-backed inputs, execute LOAD or
  MULTIEQUAL correctly, or preserve address-space identity; unknown values
  become zero;
- JumpBasic starts from an unrestricted boolean range, discards a computed
  guard intersection, has an invented LOAD exception, and lacks complete
  readonly/guard recovery;
- Basic2 loses its RangeDefault subtype and JumpAssisted has stubbed decoding
  and consumers;
- model selection tries Basic then an invented trivial fallback, skipping the
  locked Override/Assisted/Basic2 order and configured size/sanity rules;
- switch normalization and truncated-flow repair are disconnected or convert
  errors into address zero/catch-unwind continuation;
- several mutations write op inputs directly instead of using integrated
  Funcdata operations.

These failures explain why individual helpers can pass local tests while a
real switch never reaches a valid model. The repair must start with Address,
PcodeOp, Block, Range, PathMeld, emulation, and injection—not with another
high-level fallback in `recover_model`.

## 4. Print has three incompatible output paths

The locked printer has one chain:

```text
PrintLanguage RPN atoms/tokens
  -> PrintC op and structured-block dispatch
  -> EmitPrettyPrint / EmitMarkup TokenSplit stream
  -> Oppen scan queue and final bytes
```

Rugra mixes an incomplete RPN path, direct text emission, and 27+ legacy text
rewrite passes. Local syntax success therefore does not prove token or semantic
output parity.

### P0: root invisible group becomes a literal unmatched parenthesis

The locked root uses an invisible group to delimit precedence state; opening
and closing it emits no character. Rugra maps that group to a visible `(` and
does not close it at root completion. The default path has RPN enabled, so a
single binary expression is enough to expose the discrepancy.

### P0: normal ops bypass RPN and one recursion path drops nodes

The locked static token table covers all arithmetic, comparison, boolean,
comma, subscript, call, member, and surround operators. The selected Rust table
contains only a small subset. Binary, unary, CALL, STORE, and subscript paths
often emit input/text/input directly, bypassing precedence, token identity,
pending modifiers, and semantic atoms.

The free `printlanguage::rpn_recurse` pops a pending node and discards it. Some
push helpers call this function even though PrintC has a separate working
recurse method. Which entry is selected can therefore change whether an
implied expression is printed at all.

### P0: structured blocks are emitted more than once

The RPN block walker ignores its terminal-suppression argument, so a condition
block can print the terminating CBRANCH as a statement and then print it again
as the structured condition. After the normal root/unconnected-block walk,
`doc_function` creates a fresh emitted set and walks every WhileDo/DoWhile
again. A top-level loop can be duplicated even when each individual block
emitter appears correct.

### P1: semantic markup and Oppen formatting are absent

Locked RPN atoms retain real OpToken, PcodeOp, Varnode, Funcdata, Datatype,
highlight, field offset, and case value identities. EmitMarkup forwards them.
Current trait signatures cannot carry the same payload and several tag calls
use fixed zero IDs. Namespace resolution has an enum but no current-scope,
scope stack, resolution-depth walk, or CALL/declaration consumer.

PrettyPrint lacks the locked `TokenSplit` queue, left/right totals, remaining
space, oldest-break selection, max line width, group/indent stack, and
`spaces(num,bump)` semantics. The legacy postprocessor is still called despite
nearby comments claiming it is dead. Output bytes can therefore look plausible
while token order, breaks, indentation, and references differ.

## 5. Architecture, UserOp, and PcodeInject are detached containers

`Funcdata.arch` is initialized to `None`; repository-wide production callers
do not install it. A bare Architecture also initializes loader, type factory,
userops, constant pool, and related components to `None`. PrintC therefore
cannot read userop/cpool metadata, and Flow/Actions cannot consume injection
state. Adding only `set_arch` would still install an empty container.

### UserOp differences

The locked manager owns derived UserPcodeOp objects with stable selector slots,
name/index conflict checks, type-specific flags, and builtin registration.
Current storage flattens important derived state, permits selector holes or
overwrites, and does not reproduce the complete builtin contract.

SegmentOp is not universally `(base << 4) + inner`: locked processors include
HCS12 XOR, Z80 shift-by-12, and x86 protected-mode shift-by-16 semantics.
Rugra hardcodes shift-by-4. ActionSegmentize is registered but only counts and
does not rewrite. JumpAssist decoding and jump-table consumption are absent.

### PcodeInject differences and reachability

The injection library lacks complete payload decoding, per-parameter indices,
script and ID vectors, tempbase allocation, executable/dynamic payloads, and
duplicate-registration errors. A direct Flow helper picks the first HashMap
entry when multiple callother fixups exist, making selection process-dependent,
and clears state with different lifetime semantics.

More importantly, the production closure is absent:

- Architecture has no pcodeinject-library field or locked build/decode step;
- Flow does not queue CALLOTHER for cross-reference injection;
- Flow does not call `injectPcode` for call, callother, entry, or return paths;
- ActionConstbase and Segmentize cannot see initialized registries;
- JumpTable does not attempt JumpAssisted recovery.

The existing userop selector fixture proves one PcodeCompile detail only; it
does not establish userop runtime or injection parity.

## Four decisive semantic classes

| Class | Locked contract | Current failure |
|---|---|---|
| References / outputs | canonical Funcdata/PcodeOp/Varnode/Block pointers, IOP identity, payload objects, RPN semantic objects, and Action counts survive every mutation | direct Arc replacement, detached ops, Const annotations, flattened payloads, zero tag IDs, and discarded counts lose shared state |
| Traversal / boundaries | ActionStart precedes one Heritage pass; CFG slots are false then true; rename and path meld use stable block/op order; structured print walks once; pretty scan chooses the oldest break | pass runs before dominance and twice; edge interpretation flips twice; HashSet/pointer/snapshot order substitutes for SeqNum/live order; loops and terminals are re-emitted |
| Counters / accumulators | Heritage pass increments once after completion; per-space delays gate work; PathMeld cutoff and Action hits accumulate; RPN pending/visited and pretty totals update at precise points; temp selectors are global and ordered | global pass cap and driver prepass replace delays; hit/cutoff state is dropped; group IDs are fixed; pretty counters do not exist; registry order/HashMap replaces stable selectors |
| Sort / comparison keys | Address/space and SeqNum order define IR; edge slot/reverse slot defines truth; path meld compares parent+order; RPN compares precedence+token identity; injection selects registered payload ID | lossy Address, stale reverse slots, pointer identity, incomplete token tables, and first HashMap item replace the semantic keys |

## Bottom-up repair DAG

```text
F0 SPACE/ADDRESS/SEQNUM + VARNODE/OPBANK + BLOCK/COVER
 |
 +-- F1 ARCH-0001
 |     stable component ownership, initialization, decode, production install
 |       |
 |       +-- USEROP-0001 exact registry/derived types/segment/jumpassist
 |       +-- INJECT-0001 payload decode/temp allocation/Flow consumers
 |
 +-- F2 HERITAGE-0001
 |     remove lock re-entry -> exact collect/refinement/guards/ADT/rename
 |     -> ActionStart -> one canonical ActionHeritage -> remove driver prepass
 |       |
 |       +-- CONDEXE-0001 exact CFG rewrite and Action stage
 |       +-- PATHMELD-0001 ordered meld/cutoff/truncate/MARK
 |              |
 |              +-- JUMPTABLE-0001 exact model selection and SwitchNorm
 |
 +-- F3 PRINT-RPN-0001
       invisible groups -> complete tokens -> one structured CFG walk
         |
         +-- PRETTY-0001 TokenSplit/Oppen/markup/namespace
```

Within each branch, a durable locked fixture should be written before the
behavior-changing implementation. Heritage, CondExe, JumpTable, and PrintC are
core or visible-output modules and require independent source re-review;
PrintC/CondExe/JumpTable changes also require the repository differential gate.

## Required durable fixtures

### Heritage

Use the same serialized pre-state for one locked `opHeritage` call and one
Rust entry. Record architecture spaces/delays, ordered CFG and dominators,
alive/dead/opcode lists, every op slot/parent/order/flag, every Varnode storage,
definition and ordered `(op,slot)` descendants, Phi placement/input mapping,
guard lists, pass/restart state, mutations, and exceptions. Cases must cover a
diamond, loop-header Phi, cross-space equal offsets, overlap/refinement,
same-time INDIRECT, dynamic stack LOAD/STORE, calls/returns, join records,
multipass/restart, and error paths.

### CondExe and PathMeld

Record ordered edge halves with both slots/reverse indices/flags, block op
order, complete def-use, heritage delay, Action count/status, and exceptions.
Cover all four CBRANCH flip combinations, both flow-split directions,
Phi/RETURN/pullback ops, unreachable guard, illegal reads, same-block orders
10/20/30, incomparable parent blocks, MARK versus addlflags, and the one-byte
range-256 LOAD case.

### JumpTable

Record requested/selected model, normalized and unnormalized Varnodes,
PathMeld, ranges/guards, emulator reads and loader bytes, load points/counts,
address-space/word-size conversion, target/label arrays, CFG mutations,
warnings, and errors. Include Override, Basic, Basic2 RangeDefault, Assisted,
readonly values, dynamic LOAD, MULTIEQUAL paths, maximum-size/sanity rejection,
and failed model fallback.

### Print and PrettyPrint

In addition to raw output bytes, emit ordered token NDJSON containing token
type/text, group/paren ID, spaces/bump, highlight, stable op/vn/type/function
references, field offset, and case value. Run fixed max-line widths and all
namespace strategies. Minimum cases: one invisible-root binary expression,
precedence/associativity identities, a long call at width 20, scoped markup,
and one WhileDo whose condition block ends in CBRANCH.

### Architecture/UserOp/PcodeInject

Record pspec/cspec/sla hashes, complete space/component tables, userop
name/index/type/flags, payload type/ID/name/parameter indices/temp allocation,
decoded p-code order, call/entry/return/CALLOTHER injection points, duplicate
and missing-payload errors, SegmentOp per architecture, JumpAssist metadata,
and resulting op/varnode identities. Multiple payloads must prove registered-ID
selection rather than map iteration order.

All fixtures must verify the exact oracle commit and fixture hashes and must
directly diff the two observation streams. Pointer values may be normalized to
stable object IDs, but pointer equality, aliasing, order, slots, storage,
exceptions, and mutation sequences must remain observable.
