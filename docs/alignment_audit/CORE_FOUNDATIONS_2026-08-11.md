# Core identity and state foundations audit — 2026-08-11

This report records independent read-only audits against the locked oracle:

- tag: `Ghidra_12.0.4_build`
- commit: `e40ed13014025f82488b1f8f7bca566894ac376b`
- source denominator: 114 decompiler `.cc` files

The auditors compiled several temporary C++ probes from the locked source and
compared them with Rust probes. Those probes were deliberately not promoted to
tracked fixtures, so the formal behavior-gate status remains `NO_ORACLE`.
They are diagnostic evidence of the mismatches below, not reusable `MATCH`
evidence for a future repair.

## Executive result

The current Address, Space, Varnode, Variable, Cover, Block, Fspec, Database,
and Datatype/TypeFactory L3 claims are rejected. The failures form one
dependency graph rather than a set of independent leaf bugs:

```text
AddrSpace registry
  -> Address(space identity, byte offset)
     -> SeqNum immutable identity / mutable order
     -> Range and RangeList space-aware ordering
        -> FlowBlock identity and bidirectional edges
        -> VarnodeBank indices and canonicalization
           -> PcodeOp slots / descendants / destroy / IOP retention
           -> HighVariable ownership and Cover rebuilding
        -> SymbolEntry rangemap and Fspec storage trials
```

Fixing a higher layer while its key or identity is still lossy would only
create another locally green but structurally invalid implementation.

| Area | Deterministic mismatch | Formal gate |
|---|---|---|
| Space / Address / SeqNum / Range | space identity, wrapping, word size, stable op identity, and range boundaries are lost | MISMATCH / NO_ORACLE |
| Block graph | flag values collide; edge halves, parent, RPO, dominators, and marshal IDs violate the oracle contracts | MISMATCH / NO_ORACLE |
| Varnode / PcodeOp bank | tree keys mutate in place; canonicalization, nullable slots, occurrence reads, destroy, and IOP retention are broken | MISMATCH / NO_ORACLE |
| Variable / Cover | ownership cycles, endpoint sentinels, wrapping covers, CFG recursion, and dirty rebuild are missing or inverted | MISMATCH / NO_ORACLE |
| Database / Scope | flag namespace, addMap, rangemap selection, polymorphic symbol identity, and Funcdata propagation are disconnected | MISMATCH / NO_ORACLE |
| Fspec | lock state, trial numbering/selection, comparator, and storage assignment differ | MISMATCH / NO_ORACLE |
| Marshal / Translate IDs | fixed process-global wire IDs are replaced with instance-order IDs; packed state and shared IDs differ | MISMATCH / NO_ORACLE |
| Datatype / TypeFactory | subtype ordering, canonical identity, dual indices, recursive completion, exact-piece, and codec contracts differ | MISMATCH / NO_ORACLE |

## 1. Space, Address, SeqNum, and Range

Ghidra `Address` is `(AddrSpace *, byte offset)`. The space pointer is part of
validity, equality, ordering, wrapping, and serialization. Current
`src/address.rs` stores only a `u64`, while `src/space.rs` substitutes a fixed
enum for architecture-owned spaces and their dynamic index, type, name,
address size, word size, endianness, and flags.

Temporary locked-source observations included:

```text
ram:0 is valid; Rugra Address(0) is treated as null
ram:0x10 != register:0x10; Rugra cannot represent the distinction
16-bit ram 0xffff + 1 = 0; Rugra produces 0x10000
wordsize-2 byte offset 3 encodes as address 1 + remainder; Rugra assumes wordsize 1
```

`SeqNum` is a separate identity failure. Ghidra equality/order use address plus
immutable `uniq/time`; `order` is mutable block-local topology. `setOrder()`
does not change identity. Rugra folds these roles into one key, then mutates it
after insertion into ordered PcodeOpBank sets. A probe with equal uniq/time and
different display order is equal in Ghidra but unequal and ordered in Rugra.

Range behavior also depends on the missing space identity. Ghidra preserves
adjacent ranges `[0,3]` and `[4,7]` as two records, keeps equal numeric ranges
in different spaces distinct, and requires the full queried interval to fit.
Rugra merges adjacency, cannot distinguish spaces, and its point-based
`in_range` accepts an interval whose end escapes the stored range.

## 2. FlowBlock and bidirectional graph state

The graph invariant in `block.cc:73-256` is:

```text
A.out[i] = (B, reverse=j, label=f)
B.in[j]  = (A, reverse=i, label=f)
```

Both halves are one logical edge. Current half-delete, replace, swap, and flag
methods update only one side or update the wrong remaining record. Concrete
downcasts also make structured blocks and graphs bypass the shared state.

Locked temporary observations:

- the nine oracle edge bits are `1,2,4,8,16,32,64,128,256`; Rugra uses a
  different layout and gives `DEFAULTSWITCH` and `TREE` the same `0x80` bit;
- deleting the first incoming edge changes the remaining peer reverse index
  from 1 to 0 in Ghidra, while Rugra leaves 1;
- `addLoopEdge` labels one existing slot on both halves; Rugra appends an
  unlabeled duplicate edge;
- swapping two outgoing edges repairs both targets in Ghidra and leaves stale
  target reverse slots in Rugra;
- `addBlock` sets every child's parent in Ghidra and none in Rugra;
- two independent roots retain `[A,B]` order in Ghidra but become `[B,A]` in
  Rugra;
- after disconnecting `A -> B`, recomputation clears `B.idom` in Ghidra but
  Rugra retains stale `A`;
- block marshal IDs and most edge attributes differ from the locked protocol.

The CFG producer adds a CBRANCH fallthrough/false edge first and target/true
edge second in Ghidra. Current flow construction inserts target first. Dozens
of consumers then disagree about what slots 0 and 1 mean.

## 3. VarnodeBank, PcodeOp lifecycle, and IOP identity

The VarnodeBank mismatch begins at construction:

```text
oracle first createUnique(4) = unique:0x10000000
Rugra  first create_unique(4) = unique:0x0

oracle loc class order = input,written,free
Rugra  loc class order = free,input,written

oracle cross-space def records = ram,register (count 2)
Rugra  def comparator says Equal (count 1)
```

Ghidra's location tree key is space-index/offset, size, class, then defining
SeqNum or free create-index. Its definition tree starts with class and SeqNum,
then uses the complete Address. Rugra inserts nodes with one space/class and
later mutates those key fields inside `BTreeSet`; it also has `Eq`/`Ord` pairs
that can disagree.

The `xref`, `setInput`, and `setDef` family must return a canonical pointer. On
a duplicate, Ghidra migrates every read to the existing object and deletes the
candidate. Rugra ignores failed set insertion and returns an orphan Arc marked
`INSERT` even though it is not in the bank. `makeFree` and destroy similarly
mutate keys without erase/reinsert and omit the integrated-node guard.

The directly dependent op lifecycle has additional P0 gaps:

- PcodeOp input arity is a fixed vector of nullable slots in Ghidra; Rugra
  shrinks the vector or creates fake sentinel Varnodes;
- descendants are `(op, slot)` occurrences, not a set of op identities; reading
  the same Varnode twice must retain two occurrences;
- set/unset input/output is one transaction across slots, descendants,
  definition, tree keys, and code lists;
- destroy clears every relation without changing arity, while Rugra can leave
  output/bank references and shrink to zero inputs;
- Ghidra moves destroyed ops to `deadandgone` so raw IOP annotations remain
  readable until bank clear; Rugra frees the last Arc and reconstructs it with
  `Arc::from_raw`, creating a use-after-free/ownership hazard;
- HighVariable attachment is not atomic, annotation nodes are attached when
  they should not be, later nodes lack a High, and strong Arc ownership forms
  permanent cycles.

## 4. Cover endpoints and CFG recursion

Ghidra encodes four endpoint categories by pointer identity: Null/begin, End,
Input, and a real PcodeOp. A range with `start > stop` is a valid wrapping
two-segment cover; only two Null endpoints mean empty. Current Cover reduces
endpoints to numeric order and treats `start > stop` as empty.

Consequences include:

- a loop Phi read at order 0 of a value defined at order 10 has the valid
  cover `[10,0]` in Ghidra and an empty cover in Rugra;
- INDIRECT ordering must use its effect op's order, not the INDIRECT op order;
- `addDefPoint/addRefPoint` must clear/set both endpoints and recursively fill
  predecessor blocks. In `B0(def) -> B1 -> B2(use)`, Ghidra sets B1 to all;
  Rugra omits B1, an unsafe under-approximation that permits illegal merges;
- Ghidra rebuild uses a FIFO growing vector and the root Varnode. Rugra either
  clears `COVERDIRTY` without rebuilding or uses a LIFO/different implied node;
- `contain(op,2)` means interior only. Rugra loses the level and accepts a
  boundary point;
- the `Cover` versus `PcodeOpSet`, `StackAffectingOps`, and
  `HighIntersectTest` closure is absent, so address-tied stack variables can be
  merged across CALL/STORE effects.

## 5. Database, Scope, and symbol propagation

Database defines a second incompatible set of compact symbol flag bits, then
ORs them with canonical Varnode flags. A symbol containing only
NAMELOCK|READONLY should propagate `0x2200`; Rugra produces `0x6`, interpreted
as CONSTANT|ANNOTATION rather than either requested property.

`Scope::addMap` is bypassed. Direct entry insertion omits `MAPPED`, global
`PERSIST`, empty-use `ADDRTIED`, address properties, consumed byte size, join
piece expansion/endianness, overflow checks, and whole-map accounting. A locked
probe for one ordinary global static mapping produced `0x20c000` in Ghidra and
zero in Rugra.

The flat Vec query model cannot reproduce rangemap/usepoint semantics:

- invalid usepoint with an empty non-address-tied limit is false in Ghidra and
  true in Rugra;
- after one candidate fails its usepoint, Ghidra continues to the next valid
  mapping; Rugra selects first and returns none;
- Ghidra MapIterator orders intervals by end boundary then EntrySubsort
  `(use-space index,use-offset)`; Rugra orders by start/size;
- symbol IDs include scope bits. Per-scope counters in Rugra collide, and a
  query for an integer `foo` can return an unrelated outer function `bar` with
  the same numeric ID;
- Function, Equate, ExternRef, and UnionFacet are detached views while Scope
  stores a generic Symbol, losing their payload and polymorphic encode/decode.

The entire subsystem is also disconnected from production. Ghidra's
`newVarnode/newVarnodeOut` query ScopeLocal and immediately propagate the
SymbolEntry. Rugra's ScopeLocal is a separate type, Funcdata factories do not
query Database, Architecture's symbol table has no read path, and both dynamic
symbol Actions are no-ops. An attached readonly+typelock mapping therefore
still creates a Varnode with flags 0 and no map entry.

Three independent leaf corrections are real but must not disguise the DAG:
`isPiece` tests PRECISLO/PRECISHI, undefined names are exactly 15 characters
with `$$undef` prefix, and an empty `mapScope` resolution preserves the caller's
qpoint.

## 6. Fspec trial and lock state

The Fspec L3 claim is also false:

- an empty parameter list is not automatically input-locked in Ghidra; Rust's
  use of `all()` makes it locked;
- input/output/model lock coupling and void-input state are missing;
- ParamActive slot numbering starts at 1, while Rugra starts at 0; the maximum
  pass starts at 0, not 4;
- `whichTrial` selects overlap according to the ordered trial set, not exact
  address equality; `getNumUsed` is a used prefix, not all used flags;
- split slot/flag updates and the trial comparator lose space and ordering
  fields;
- parameter assignment must use ParamEntry alignment/group APIs and preserve
  type pieces; the current path clears or substitutes data.

Storage identity repairs depend on Address/Space, but lock-state and initial
trial counter corrections can be isolated first.

## 7. Marshal and Translate wire identity

Ghidra registers AttributeId and ElementId in process-global static tables with
explicit IDs. Zero is an end-of-iteration sentinel, not UNKNOWN. In locked
12.0.4, `ATTRIB_UNKNOWN=159` and `ELEM_UNKNOWN=289`; the complete common tables
contain 146 attributes and 274 elements before the unknown entries.

Rugra assigns IDs dynamically per registry and maps unknown to zero. Translate
then invents `space=47,size=48` instead of reusing common
`ATTRIB_SPACE=20,ATTRIB_SIZE=19`. Empty element names also prevent reverse
lookup. Packed decode is not just unfinished: its open/close/skip state,
unknown handling, error channel, and raw-byte behavior differ. Every module
that serializes a block, type, symbol, override, or architecture inherits this
wire mismatch.

## 8. Datatype comparison and TypeFactory identity

Locked 12.0.4 has no separate `typefactory.cc`; Datatype and TypeFactory are a
single 4,674-line `type.cc` closure. The former roadmap denominator and L3
claim were therefore wrong before behavior was considered.

Datatype comparison starts with an independent 24-value `submeta`, then uses
the derived virtual comparator. Base size comparison returns
`other.size - this.size` and does not compare the display name. Rugra has no
stored submeta, reverses the size subtraction, includes name, and omits virtual
dispatch for Partial, Spacebase, and PointerRel. It also lacks fields such as
pointer space ID, stored alignment, field identity/signed offset, and complete
FuncProto flags. Types that are distinct ordering classes in Ghidra can compare
equal, while renamed equivalent types can compare different.

TypeFactory requires two independent indices:

- a structural tree ordered by `compareDependency`, then unsigned ID;
- a name tree ordered by `(name, id)`, excluding anonymous ID zero.

Current Rust has one `BTreeMap<String, Arc<Datatype>>` and `insert` silently
overwrites. Same-name/different-ID types cannot coexist, same-ID structural
collisions do not throw, and anonymous types become name-visible. The
variable-size ID transform is also wrong: Ghidra XORs
`size * 0x98251033aecbabaf`, while the selected Rust helper shifts the ID and
appends one byte before falling back to name/size.

Canonical object identity is equally important. `findAdd`, recursive struct or
prototype stub completion, rename, and field installation mutate the same
factory-owned pointer after erase/reinsert. `Arc::make_mut` and map replacement
clone or detach the object as soon as any recursive/caller alias exists. Old
aliases therefore remain incomplete. The factory also lacks Ghidra's complete
`getExactPiece`: union pieces must immediately create canonical partial unions,
and descent failure can create partial struct/array/enum types while updating
the caller's offset out-parameter.

Finally, aggregate encode currently calls a base-only path, decode can replace
rather than complete recursive stubs, and the core type cache is a no-op. A
Rust round-trip can lose fields, pointees, enum signedness, prototype state,
space identity, and alignment while still passing local tests.

## Four decisive semantic classes

| Class | Locked Ghidra contract | Current failure |
|---|---|---|
| References / outputs | space pointers, canonical Varnode/Symbol pointers, mirrored edge halves, endpoint kinds, and out-parameters retain shared identity | numeric offsets/IDs and detached Arcs copy or lose identity; one-sided mutations leave stale peers |
| Traversal / boundaries | edge slots and reverse slots are paired; Varnode trees use lower/upper bounds; Cover recursion is FIFO and predecessor ordered; rangemap iterates end/subsort order | Vec/filter or pointer order replaces the oracle order; wrapping and inclusive boundaries are inverted |
| Counters / accumulators | dynamic space indices, unique base `0x10000000`, create-index postincrement, ParamActive slot base 1, scope-scoped symbol IDs, and fixed marshal IDs each have distinct scopes | counters start at different values, reset at the wrong scope, collide, or are assigned by registration order |
| Sort / comparison keys | Address=`space index,offset`; SeqNum identity excludes mutable order; block equality is object identity; Varnode loc/def, TypeFactory structural/name trees, and MapIterator use complete composite keys | mutable/incomplete keys are inserted into BTree sets; Eq and Ord can disagree; name, endpoint, or insertion order substitutes for semantic keys |

## Bottom-up repair DAG

1. `MARSHAL-ID-0001`: install exact locked common ID/name tables and reverse
   lookup; then repair Translate's shared IDs.
2. `SPACE-0001`: architecture-owned stable space handles with exact index,
   type, size, word size, endianness, flags, and invalid semantics.
3. `ADDRESS-0001`: `(SpaceId, byte offset)` Address, wrapping arithmetic, and
   complete comparison. Then split immutable SeqNum identity from mutable
   topology order and repair Range/RangeList.
4. `BLOCK-0001`: one FlowBlockCore/arena identity for every basic and
   structured block. Restore exact flags, atomic bidirectional edge primitives,
   parent/copy state, false-first CFG, RPO/loop, and dominator APIs.
5. `VARNODE-0001`: immutable complete tree keys and exact constructors, then
   canonical xref/setInput/setDef/makeFree/query. Follow with nullable op slots,
   occurrence descendants, lifecycle transactions, deadandgone IOP retention,
   and High attach/detach.
6. `COVER-0001`: endpoint enum carrying op identity, exact block recursion and
   dirty rebuild, then PcodeOpSet/HighIntersectTest and Merge consumers.
7. `DBSYM-FLAGS`: unify the canonical flag namespace. After Address exists,
   implement SymbolKind identity, addMap, per-space rangemap/query, TypeFactory
   exact-piece updates, and finally Funcdata/Action integration.
8. `FSPEC-0001`: correct independent lock/counter state first; migrate storage
   trial/assignment only after Address and ParamEntry ordering are available.
9. `TYPE-0001`: add the exact data model and stable arena identity before
   virtual compare, dual indices, canonical find/add, recursive completion,
   exact-piece, and codec consumers.
10. Only after these foundations have durable locked fixtures should Heritage,
   CondExe, Merge, JumpTable, and printing consumers be promoted.

## Required durable fixtures

At minimum, add tracked C++ source, metadata, Rust mirror, and a runner that
directly diffs both observation streams for:

- `space_address_seq_range_1204`;
- `block_graph_1204`;
- `varnode_bank_lifecycle_1204`;
- `cover_cfg_merge_1204`;
- `database_entry_scope_1204`;
- `fspec_trial_lock_1204`;
- `marshal_ids_packed_1204`;
- `type_factory_1204`.

Metadata must record the locked commit, architecture/space layout, compiler
spec or explicit N/A, options, fixture hashes, compiler flags, and every
normalized field. Pointer values may be normalized to stable object IDs, but
pointer equality, aliasing, ordering, edge slots, storage spaces, and mutations
must remain observable.
