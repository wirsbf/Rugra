# jumptable.rs — Jump-table recovery API

Faithful port of Ghidra's `jumptable.hh` / `jumptable.cc` (2883 lines).

**Status:** L1 → L2. All public classes present with full data structures; the
data-flow / CFG-rewriting algorithms that depend on `Varnode::def`,
`EmulateFunction`, and branch-editing primitives are documented as L3 gaps.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.{hh,cc}`.

## Constants

| Name | Type | Description |
|---|---|---|
| `NO_LABEL` | `u64` | Sentinel (`0xBAD1_ABE1_BAD1_ABE1`) for an unlabelled jump-table entry. |
| `MARK_FLAG` | `u32` | `addlflags` bit mirroring `PcodeOp::setMark`. |

## Enums

### `RecoveryMode`
Recovery status of a `JumpTable` — faithful to `JumpTable::RecoveryMode`
(jumptable.hh:544).
- `Success = 0`, `FailNormal = 1`, `FailThunk = 2`, `FailReturn = 3`,
  `FailCallother = 4`.

## Structs

### `LoadTable`
A description of where and how data was loaded from memory
(jumptable.hh:50).

| Field | Type | Description |
|---|---|---|
| `addr` | `Address` | Starting address of the table. |
| `size` | `i32` | Size of each table entry. |
| `num` | `i32` | Number of entries. |

**Methods:**
- `single(addr, size) -> Self` — single-entry table.
- `new(addr, size, num) -> Self` — full table.
- `collapse_table(&mut Vec<LoadTable>)` — sort and merge contiguous entries
  (jumptable.cc:60).

### `PcodeOpNode`
A data-flow path edge (op + input slot).

### `PathMeld`
All paths from a putative switch variable to the BRANCHIND (jumptable.hh:72).

| Method | Description |
|---|---|
| `num_common_varnode()` / `num_ops()` / `empty()` | Container sizes. |
| `get_varnode(i)` / `get_op(i)` / `get_op_parent(i)` | Element accessors. |
| `get_earliest_op(pos)` | Earliest op using the i-th common varnode. |
| `is_load_in_path(i)` | True if a LOAD precedes position `i`. |
| `set_from(&PathMeld)` | Copy paths. |
| `set_path(&[PcodeOpNode])` | Initialise to a single path. |
| `set_single(op, vn)` | Initialise to a single-node path. |
| `append(&PathMeld)` | Append a new set of paths. |
| `meld(&mut Vec<PcodeOpNode>)` | Meld a new path in (jumptable.cc:970). |
| `mark_paths(val, start_varnode)` | Mark/unmark ops from a start varnode. |
| `clear()` | Empty the container. |

### `GuardRecord`
A switch-variable Varnode and a constraint imposed by a CBRANCH
(jumptable.hh:138).

| Field | Type | Description |
|---|---|---|
| `cbranch` | `Option<Arc<RwLock<PcodeOp>>>` | CBRANCH guarding the switch. |
| `read_op` | `Option<Arc<RwLock<PcodeOp>>>` | Op causing the restriction. |
| `vn` | `Option<Arc<RwLock<Varnode>>>` | The restricted varnode. |
| `base_vn` | `Option<Arc<RwLock<Varnode>>>` | Quasi-copy source. |
| `indpath` | `i32` | CBRANCH path to the switch. |
| `bits_preserved` | `i32` | Bits copied (others zero). |
| `range` | `CircleRange` | Range taking the switch path. |
| `unrolled` | `bool` | Duplicated across blocks. |

**Methods:** `new`, `is_unrolled`, `get_branch`, `get_read_op`, `get_path`,
`get_range`, `clear`, `value_match`.

### Free functions
- `quasi_copy(vn) -> (Option<Arc<RwLock<Varnode>>>, i32)` — quasi-COPY chain
  source (jumptable.cc:721).
- `one_off_match(op1, op2) -> i32` — 1 if two ops produce the same value
  (jumptable.cc:686).

## Traits

### `JumpValues`
Iterator over values a switch variable can take (jumptable.hh:166).
- `truncate(nm)`, `get_size()`, `contains(val)`, `initialize_for_reading()`,
  `next()`, `get_value()`, `get_start_varnode()`, `get_start_op()`,
  `is_reversible()`, `clone_boxed()`.

### `JumpModel`
A jump-table execution model (jumptable.hh:243).
- `is_override()`, `get_table_size()`,
- `recover_model(fd, indop, matchsize, maxtablesize) -> bool`,
- `build_addresses(fd, indop, addresstable, loadpoints, loadcounts)`,
- `find_unnormalized(maxaddsub, maxleftright, maxext)`,
- `build_labels(fd, addresstable, label, orig)`,
- `fold_in_normalization(fd, indop) -> Option<Varnode>`,
- `fold_in_guards(fd, jump) -> bool`,
- `sanity_check(fd, indop, addresstable, loadpoints, loadcounts) -> bool`,
- `clone_model(jt) -> Box<dyn JumpModel>`, `clear()`.

## `JumpValuesRange` / `JumpValuesRangeDefault`
Implementations of `JumpValues` for a single-entry range / a range plus an
extra default value (jumptable.hh:188 / 214).

## Model implementations

### `JumpModelTrivial`
The BRANCHIND input is the switch variable (jumptable.hh:350).
Constructor: `new(jt)`.

### `JumpBasic`
The basic switch model (jumptable.hh:374). Notable methods:
- `new(jt)`, `get_path_meld()`, `get_value_range()`.
- `is_prune(Varnode)`, `is_point(Varnode)`, `get_stride(Varnode)`,
  `get_max_value(Varnode)`, `duplicate_varnodes(&[Varnode])`.
- `find_determining_varnodes(op, slot)` (jumptable.cc:556).
- `calc_range(vn, &mut CircleRange)` (jumptable.cc:1137).
- `find_smallest_normal(matchsize)` (jumptable.cc:1182).
- `mark_foldable_guards()` (jumptable.cc:1258).
- `mark_model(val)` (jumptable.cc:1273).
- `analyze_guards(bl, pathout)` (jumptable.cc:1063).

## `JumpTable`
A map from values to control-flow targets within a function
(jumptable.hh:541).

| Field | Type | Description |
|---|---|---|
| `jmodel` | `Option<Box<dyn JumpModel>>` | Current model. |
| `origmodel` | `Option<Box<dyn JumpModel>>` | Saved model. |
| `addresstable` | `Vec<Address>` | Raw addresses. |
| `block2addr` | `Vec<IndexPair>` | Block→address-index map. |
| `label` | `Vec<u64>` | Case labels. |
| `loadpoints` | `Vec<LoadTable>` | In-memory model data. |
| `opaddress` | `Address` | BRANCHIND address. |
| `indirect` | `Option<Arc<RwLock<PcodeOp>>>` | BRANCHIND op. |
| `switch_var_consume` | `u64` | Switch-var bits consumed. |
| `default_block` | `i32` | Default out-edge (-1 = undef). |
| `last_block` | `i32` | Out-edge of last table entry. |
| `norm_max` | `NormMax` | Normalisation restrictions. |
| `partial_table` / `collect_loads` / `default_is_folded` | `bool` | Flags. |

**Methods (selected):** `new(opaddress)`, `is_recovered`, `is_labelled`,
`is_override`, `is_partial`, `mark_complete`, `num_entries`,
`get_switch_var_consume`, `get_default_block`, `get_op_address`,
`get_indirect_op`, `set_indirect_op`, `set_norm_max`, `get_address_by_index`,
`set_last_as_default`, `set_default_block`, `set_load_collect`,
`set_folded_default`, `has_folded_default`, `get_label_by_index`,
`add_block_to_switch`, `save_model`, `restore_saved_model`,
`clear_saved_model`, `clear`.

### `IndexPair`
Block-position / address-index pair (jumptable.hh:553).
`new(pos, index)`, `less_than(&Self)`, `compare_by_position(&Self, &Self)`.

### `NormMax`
Normalisation restrictions `{ addsub, leftright, ext }`.

### `EmulateFunction`
Light-weight emulator for switch targets (jumptable.hh:110).
- `new()`, `set_load_collect(Option<Vec<LoadTable>>)`,
  `get_varnode_value(vn)`, `set_varnode_value(vn, val)`.

## L3 gaps (documented in source)
- `Varnode::def` traversal — blocks: `find_determining_varnodes` deep walk,
  `quasi_copy` chain, `findUnnormalized` chain walk, `getMaxValue` INT_AND /
  MULTIEQUAL inspection, `isLoadInPath` LOAD detection.
- `EmulateFunction::emulate_path` per-value address computation.
- `CircleRange::pullBack` integration for guard expansion.
- CFG-rewriting (`foldInOneGuard`, `switchOver`, branch editing via
  `Funcdata::pushBranch`).
- `backup2Switch` reverse emulation for case-label recovery.
