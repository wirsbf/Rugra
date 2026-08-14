# Runtime services and mutation engines audit — 2026-08-11

## Scope and evidence status

Independent agents read the complete relevant locked functions for Flow/SLEIGH,
LoadImage/Context, OpBehavior/Emulate/MemState, Transform/Subflow, and
Override/Comment/StringManager against:

- tag: `Ghidra_12.0.4_build`
- commit: `e40ed13014025f82488b1f8f7bca566894ac376b`
- source denominator: 114 decompiler `.cc` files

The source review yields deterministic counterexamples and rejects the current
L3/L2.5 claims. These subsystems still lack tracked 12.0.4 same-input fixtures,
so their formal behavior-gate state is `NO_ORACLE`, not `MATCH` and not a
durable fixture-backed `MISMATCH`.

## Executive result

```text
LoadImage + Context + Translate
  -> Flow instruction/xref/error state
  -> OpBehavior registry + MemState
  -> Emulate / EmulateUtil / JumpTable

Varnode/PcodeOp mutation primitives
  -> TransformManager
  -> Subvariable / SplitDatatype / Subfloat / LaneDivide

Marshal + Address + Type/Fspec
  -> Override / Comment / StringManager
  -> Flow / Actions / Print consumers
```

| Area | Locked-source result | Formal gate |
|---|---|---|
| Flow / SLEIGH | two translators determine length and IR; xref/calls/injection/errors/CFG closure differ | REJECT / NO_ORACLE |
| LoadImage / Context | open/VMA/in-out semantics, partmap ranges, tracked storage, cache, codec, and persistent context differ | REJECT / NO_ORACLE |
| OpBehavior / Emulate / MemState | production bypasses complete registry; dispatch, error classes, spaces, byte aliasing, loader and callbacks differ | REJECT / NO_ORACLE |
| Transform / Subflow | mutation transaction, storage/IOP/property identity, call flows, split/subfloat/lane/piece algorithms differ | REJECT / NO_ORACLE |
| Override / Comment / String | fixed IDs/address codec/ownership and all major production consumers are missing or disconnected | REJECT / NO_ORACLE |

## 1. Flow uses different decoders for instruction size and p-code

`FlowInfo::process_instruction` decodes with iced-x86 to choose instruction
length, discards that decoded Instruction, then creates a new SLEIGH context to
generate p-code. The `X86Lifter` supplied to FlowInfo is unused. Locked
`Translate::oneInstruction` produces length, p-code, context commits, and
exceptions as one transaction. Prefixes, invalid encodings, or context-dependent
length can therefore give Rugra one visited/fall-through boundary and another
instruction's IR.

The production SLEIGH entry compounds this split: every instruction creates a
new `SleighCtx`, does not load the processor spec, and cannot retain context
commits. x86-64 `longMode`, `opsize`, `addrsize`, and tracked DF defaults are
lost. FFI collapses all exceptions to an empty op vector and silently caps each
instruction at 64 ops and each op at 16 inputs. Flow treats the result as a
valid instruction with no p-code and continues.

### xref and CFG are not the locked state machine

Locked `xrefControlFlow` carries `startbasic` and `isfallthru` by reference,
tracks relative `SeqNum.time`, mutates a growing dead-op interval, truncates
after terminal/noreturn ops, schedules new addresses with source identity,
builds CALL/CALLIND specs, records CALLOTHER injection, and handles errors by
configured flags. Current `xref_control_flow` returns one bool over an alive
snapshot and omits those shared outputs.

Production CBRANCH edges are also reversed: locked edge 0 is
fall-through/false and edge 1 target/true; `build_blocks_from_alive` inserts
target first. The separate `collect_edges` happens to use the locked order, but
its result is not the production builder.

BRANCHIND recovery mode values are decoded incorrectly, and recovery failure
does not perform the locked return/thunk/callother/default truncation. Errors
or unsupported switch paths remain as a live BRANCHIND. `fallthruOp` skips all
p-code with the same instruction address instead of preferring the next op in
the same instruction, and constant-space internal relative branches are
rewritten to RAM before Flow can recognize them.

### three incompatible production entries

- the CLI calls a free `flow::follow_flow`, then bypasses Flow's block builder;
- `Funcdata::follow_flow` is an empty flag setter;
- curl uses whole-function SLEIGH injection, while other examples use a manual
  x86 lifter.

None applies the complete locked `flowoptions`, instruction limit, size,
generateBlocks, jump-table switch-over, or unimplemented/bad-data flags. A
single instruction records size zero because only the starting address is
accumulated.

## 2. LoadImage and Context lose live range state

### LoadImage

Locked RawLoadImage rejects every second `open`, including a retry after the
first open failed, and retains a live file stream. Rugra permits repeat opens
and appends bytes to the old buffer; a successful second open doubles data and
size. It snapshots the whole file, so post-open file changes are invisible.

`adjustVma` must use the attached space's `addressToByte(adjust,wordsize)`.
Rugra has no attach-to-space state and adds the raw integer. With wordsize 2,
adjust 3 maps the first byte to 6 in the oracle and 3 in Rugra.

`getReadonly` is a `RangeList&` in-out API. A base no-op preserves caller
ranges and derived loaders append to that same object. Rust returns a fresh
empty RangeList, losing caller state and aliasing. Architecture does not walk
loader symbols or install readonly ranges; it only flips a parsed flag.

### Context partition and tracked storage

Locked `setVariable` paints a bit range forward across every unrelated split
until the next explicit change-point for the same mask. Rugra updates one split
and never sets or consults `ContextBlob.mask`:

```text
set y@0x200 = 1
set x@0x100 = 1
locked: x@0x200 = 1
Rugra:  x@0x200 = 0
```

The result incorrectly depends on insertion order. Registration after
partition initialization and ranges crossing a storage word must throw;
Rugra permits both and can later index old short blobs out of bounds. Unknown
variables become no-op/zero instead of exceptions.

TrackedContext storage is full `VarnodeData(space,offset,size)`. Queries match
contained subranges and crop according to the space's endianness. Rugra stores
only offset/size and requires exact equality. It also ignores `createSet`'s
right boundary, letting values flow to the end of the address space rather than
restoring the old value at `[start,end)`.

Context serialization uses fixed element IDs, full space+offset addresses,
and `<set>` children. Rugra uses element ID 0, writes offset into the space
attribute, omits offset, and emits `<tracked_set>`. `decodeFromSpec`, ParserContext,
ParserWalker, commit snapshots/order, and ContextCache range invalidation are
missing; the Rust cache setter is empty. Production SLEIGH uses a separate
per-instruction context anyway, so Architecture.context_db has no effect.

## 3. OpBehavior, Emulate, and MemState are three incompatible models

### the complete-looking registry is not the production API

Rust has an object/factory layer with FLOAT implementations, but production
callers in op, emulate, jumptable, and unify use free match functions. Those
free functions have no FLOAT branches and uniformly mask almost every result,
although locked behavior is per opcode. Examples from the direct contracts:

```text
COPY(sizeout=1,input=0x1234)  locked 0x1234, Rust 0x34
INT2FLOAT(sizein=1,0xff)      locked -1.0,   Rust 255.0
LZCOUNT(sizein=16,value=0)    locked 128,    Rust 64
```

The free API also invents binary PTRADD with implicit scale 1. Locked emulator
registration uses a base behavior that throws; the concrete ternary PTRADD is
a separate TypeOp behavior. `LowlevelError` and `EvaluationError` are both
collapsed to `None` or panic, changing callers that catch only the recoverable
class. FLOAT behavior must borrow the caller's Translate and select its first
matching format; Rust uses global 4/8-byte caches.

### emulator dispatch and control state differ

- two-input SUBPIECE is sent to unary evaluation;
- POPCOUNT/LZCOUNT and FLOAT unary ops are absent from the unary list;
- three-input PTRADD is evaluated with two inputs;
- CALLOTHER/SEGMENTOP/CPOOLREF/NEW/CAST lack exact special dispatch;
- evaluator failure silently leaves output unchanged;
- RETURN permanently terminates instead of calling branch-indirect logic;
- constant BRANCH is treated as an absolute address instead of a p-code-cache
  relative branch;
- halt, current instruction, external loop control, and a self-invented
  instruction limit are conflated.

LOAD/STORE ignore input0 space, hardcode `ram`, omit wordsize conversion, and
turn missing banks into zero/no-op. A second value map stores whole u64 values
by `(space_id,offset)` rather than bytes, so overlapping accesses do not alias:

```text
write 4 bytes at offset 0, read 1 byte at offset 1
locked: the selected overlapping byte
Rugra:  0 from a different hash key
```

MemState indexes banks by string names, collapsing distinct custom spaces, and
uses placeholder register hashes instead of Translate register storage. The
claimed L3 cannot stand independently of Emulate.

BreakTable/BreakCallBack, PcodeEmitCache, EmulatePcodeCache, relative
fall-through, userop hooks, architecture-backed EmulatePcodeOp,
MULTIEQUAL predecessor selection, and EmulateSnippet validation/reset are
missing. JumpTable's local emulator first routes LOAD to unsupported binary
evaluation, making its later loader branch unreachable; failure is then
converted into target address zero.

## 4. Transform and Subflow mutate different objects

The five TransformManager phases have the same names and top-level order, but
the mutations inside them differ:

- output pieces lose original space, big-endian offset, renormalization,
  datatype/symbol/flags, and property transfer; `new_varnode_out` hardcodes
  Register space;
- IOP pieces become ordinary constants although working IOP helpers already
  exist;
- MULTIEQUAL replacements are inserted before the old op instead of at block
  begin;
- INDIRECT creation marking and special handling are no-ops;
- existing inputs are unset without truly clearing slots, then pointer-equal
  reinstallation skips descendant repair;
- removing one repeated input can erase every occurrence or leave stale reads;
- expanded slots allocate fake zero-byte constant Varnodes instead of null
  slots, polluting the bank;
- invalid lane specs or conflicting `getPiece` calls log and continue instead
  of throwing.

Many comments justify these differences by claiming missing infrastructure,
but the repository already has IOP, integrated input/delete/property/indirect
helpers, PartialStruct, architecture options, and callspec access. These are
stale premises, not blockers.

### Subvariable and split flows

- call pull and return push are hard-disabled although callspec lookup exists;
- artificial halt RETURN is not filtered;
- repeated use of one Varnode in two CALL slots finds the first slot twice;
- one-bit flow tests `flowsize*8 >= 8` instead of `bitsize >= 8`, incorrectly
  reusing original storage, and hardcodes Register/little-endian;
- constant replacements are cached and shared across patches while the oracle
  creates distinct constants;
- push patches retain discovery order rather than the locked reverse order,
  and one RETURN path resets `push_front_count`, causing existing push patches
  to be skipped;
- RuleSubvarSext never consumes `aggressive_ext_trim`.

SplitDatatype hardcodes struct/array splitting on, compares mostly size rather
than offset/type/hole compatibility, and can construct a three-piece chain in
which a PIECE output is also its own input0. It rebuilds unused outputs that the
oracle skips and can split a non-pointer LOAD. TypePartialStruct support and
configuration already exist but are ignored.

SubfloatFlow is missing. The substitute rule can rewrite a constant even with
zero terminators and can assign a 4-byte type to an unchanged 8-byte Varnode.
LaneDivide is missing; ActionLaneDivide is a no-op excluded from the pipeline.
PieceNode lacks earliest-reader `compareOrder` traversal, Merge grouping is a
no-op, and LogicalForm ignores a valid high operand in slot 1.

## 5. Override, Comment, and StringManager have no complete consumer path

All three codecs use element ID 0, but 0 is the packed no-element sentinel.
Addresses write the numeric offset into the space attribute and omit the
offset and space identity. Locked IDs are fixed (`comment=86..88`, string
`83..85`, override `218..224`) and share common address attributes.

### Override

Prototype overrides own a FuncProto and apply it by copying into FuncCallSpecs.
Rust stores a bool and can only answer that a marker exists. Negative delay,
unknown flow, and invalid address errors are ignored; cross-space equal offsets
overwrite. Encoding and printRaw differ, and a vector containing only negative
delay values is incorrectly considered empty.

No production consumer closes the gap: Flow's override-present flag is always
false, call/callind setup has explicit TODOs, ActionForceGoto is a no-op,
startProcessing does not apply dead-code delay, and multistage queries are only
tested directly.

### Comment

Unknown or combined comment types must throw; Rust writes empty type. The
locked sorter stores the database's same Comment pointers and mutates `emitted`.
Rust clones values, so state never flows back. Header Subsort index is signed
-1; Rust uses `u32::MAX`, reversing order. Position search lacks block end
containment, setupHeader is empty, and repeated setupOpList returns old prefix
comments rather than advancing a cursor.

PrintC never sets up the sorter, the default line-comment emitter is empty,
and draining a group with no op returns early. Comments therefore do not reach
the normal C output path.

### StringManager

UTF-8 branches return before common surrogate and maximum-codepoint checks,
accepting `ED A0 80` and `F4 90 80 80`; invalid writeUtf8 becomes empty output
instead of an exception. Unicode loading reads `maximumChars * charsize` in one
request, while the locked algorithm reads at most maximumChars bytes in
32-byte chunks. Load failure is not cached, so a later retry can change the
result.

Cache keys lose space, results are cloned instead of stable references with an
`isTrunc&` output, and internal-string hashing requires a terminator and ignores
contents rather than using CRC data identity. The hex decoder expects
whitespace-separated byte tokens and drops the locked continuous hex form.
GhidraStringManager/client fetch is completely missing, Architecture cannot
install a dynamic manager, and PrintC's string path does not consume one.

## Four decisive semantic classes

| Class | Locked contract | Current failure |
|---|---|---|
| References / outputs | shared translator/context/loader/memory/callspec/comment/string objects and in-out ranges retain identity; mutation APIs repair both def-use directions | per-instruction contexts, owned returns/clones, bool markers, fake inputs, cached constants, and direct slot edits lose alias/output state |
| Traversal / boundaries | one decode transaction; live xref/injection worklists; false-first edges; partmap `[start,end)`; behavior-driven dispatch; transform phase and patch order; sorter cursors | snapshot/dual decoder and reversed edges; unbounded context; arity dispatch; wrong Phi/push/order; prefix comment replay and one-shot string reads |
| Counters / accumulators | SeqNum maxtime, flow size, context masks, cache bounds, op emit uniq, pull/push/terminator/lane counters, comment uniq/position, string count/trunc update at fixed points | counters are absent, reset early, clamped, or replaced by global/hardcoded state; failures often continue with zero |
| Sort / comparison keys | full Address/space, op identity+SeqNum, behavior opcode slot, piece offset/type/hole, Comment Subsort signed index, string content hash | u64/string/pointer/size-only keys, slot-first lookup, element ID 0, and address-only hash collapse distinct state |

## Bottom-up repair DAG

```text
SPACE/ADDRESS/SEQNUM + MARSHAL fixed IDs/error state
  +-> LOADIMAGE -> CONTEXT partmap/tracked/cache -> persistent Translate/SLEIGH
  |     -> FLOW xref/calls/injection/errors -> CFG/JT
  +-> OPBEHAVIOR typed registry -> MEMSTATE -> EMULATE/EMULATEUTIL -> JT
  +-> VARNODE/OPBANK transaction primitives -> TRANSFORM
  |     -> SUBVARIABLE/SPLIT/SUBFLOAT/LANE -> PieceNode/Merge/Double
  +-> TYPE/FSPEC -> OVERRIDE -> Flow/Actions
  +-> BLOCK/OPBANK -> COMMENT -> Print
  +-> LOADIMAGE/ARCH client -> STRING -> Rules/UserOp/Print
```

Each branch requires a tracked C++/Rust fixture that verifies the locked
commit, compiler/spec/options/input hashes, and directly diffs an ordered
observation stream. Required observations include complete addresses, alias
identity, mutation order, edge/slot state, error class/message, loader/context
request traces, memory bytes, type/storage pairs, and final consumer output.

Minimum fixture families:

- `flow_sleigh_1204`: CBRANCH order, entry loop, offcut, bounds/errors,
  relative p-code, calls/injection growth, four JT recovery modes, pspec and
  cross-instruction context commit;
- `loadimage_context_1204`: repeat/failed open, live file changes, wordsize VMA,
  RangeList in-out, interleaved variables, tracked containment/endian/range,
  fixed codec, cache mutation, persistent SLEIGH;
- `opbehavior_emulate_1204`: raw registry versus TypeOp, width/high-bit/error
  matrix, FLOAT formats, byte-overlap memory, relative branches, callbacks,
  loader LOAD, MULTIEQUAL/INDIRECT, and explicit assertion that failures never
  become target zero;
- `transform_subflow_1204`: big-endian pieces, Phi/IOP/INDIRECT and repeated
  slots, one-bit storage, calls/halts, push order, aggressive options,
  three-field composites, Subfloat terminators, lanes, PieceNode earliest
  reader, and LogicalForm slot 1;
- `override_comment_string_1204`: fixed wire events, cross-space addresses,
  real prototype application, comment cursor/shared emitted/final C, Unicode
  invalid/truncated inputs, scripted loader caching, internal CRC, and client
  string fetch.
