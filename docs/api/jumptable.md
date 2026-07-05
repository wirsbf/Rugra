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
**2026-07-05 修正**：`curval`/`lastvalue` 改为 `AtomicU64`/`AtomicBool`（对应
Ghidra `mutable curval`/`mutable bool lastvalue`），使 `&self` 的
`initialize_for_reading` 能像 Ghidra `const` 方法一样产生设置 curval 的副作用
（jumptable.cc:289 / 341-353）。Default 变体之前两分支都返回 true 且不设
`curval`/`lastvalue`，现已按 Ghidra cc:344-352 正确分支。手动 `Clone` impl
（Atomic 类型非 Clone）。

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
- ~~`Varnode::def` traversal~~ — **DONE**: `find_determining_varnodes` now does
  full def-chain DFS; `quasi_copy` walks COPY/INT_AND/INT_OR/SEXT/ZEXT/PIECE/
  SUBPIECE chains; `get_max_value` inspects INT_AND/MULTIEQUAL; `isLoadInPath`
  detects LOAD via `get_def()`.
- `EmulateFunction::emulate_path` per-value address computation.
- `CircleRange::pullBack` integration for guard expansion.
- CFG-rewriting (`foldInOneGuard`, `switchOver`, branch editing via
  `Funcdata::pushBranch`).
- `backup2Switch` reverse emulation for case-label recovery.

## 2026-06-27（续）：pullBack 守卫扩展 + backup2Switch + findUnnormalized

**新增自由函数**：
- `pull_back_through_op(rng, op, usenzmask) -> Option<Varnode>`（rangeutil.cc:1022）：通过 PcodeOp 反向范围，返回未知输入 varnode。处理一元/二元操作 + NZ 掩码交集。

**JumpBasic 新增/升级方法**：
- `analyze_guards`：现执行完整 pullBack 扩展循环（jumptable.cc:1119），从布尔 varnode 反向最多 2 步，每步创建新 GuardRecord。
- `backup2_switch(output, outvn, invn) -> Option<u64>`（jumptable.cc:474）：从规范化值反向模拟到未规范化值，使用 opbehavior::recover_input_unary/binary。
- `find_unnormalized`：现执行完整 ADD/SUB/ZEXT/SEXT 链遍历（jumptable.cc:1484），计数 addsub/ext 限制。
- `flows_only_to_model(vn, trail_op) -> bool`（jumptable.cc:1293）：检查 varnode 是否仅流向模型。
- `build_labels`：现使用 backup2_switch 恢复 case 标签（jumptable.cc:1528），不再全部发 NO_LABEL。

剩余 L3 缺：emulate_path 地址计算、CFG 重写（foldInGuards/switchOver）。

## 2026-06-27（续 3）：emulate_path 地址计算完成

**EmulateFunction 新增方法**：
- `execute_op(op) -> bool`：执行单个 pcode op，使用 opbehavior::evaluate_unary/binary/ternary 计算结果并存储。LOAD 时收集 loadpoint。
- `emulate_path(val, path_meld, startop, startvn) -> Option<u64>`（jumptable.cc:218）：从起始值流过 pathMeld 的所有路径到 BRANCHIND，返回计算的目标地址。处理 MULTIEQUAL 起始特殊情况。

**JumpBasic::build_addresses**：现使用 emulate_path 计算每个 switch 值的目标地址（jumptable.cc:1453），不再放置占位符。
**2026-07-05 修正**：jumptable.cc:1465-1469 的 `funcptr_align` 掩码之前被硬编码为 `u64::MAX`（无对齐），与 Ghidra 在任何 `funcptr_align != 0` 的架构上分歧；并补上 jumptable.cc:1475 的 `AddrSpace::addressToByte(addr, spc->getWordSize())`（Rugra 单空间模型下 `wordSize==1`，no-op，已显式标注）。同时把 `loadcounts` 改为 Ghidra 的累计语义（`loadpoints->size()` 而非 per-iter 局部计数）。`curval` 重置（jumptable.cc:289 `mutable curval`）改为在 `build_addresses` 内重置克隆的迭代器，对齐 Ghidra 的 `initializeForReading` 副作用。

测试：新增 2 个（emulate_path INT_ADD + COPY）。

剩余 L3 缺：CFG 重写（foldInGuards/switchOver via Funcdata::pushBranch）。

## 2026-06-27（续 4）：CFG 重写完成 — jumptable.rs 达到 L3

**Funcdata 新增方法**（funcdata_block.cc）：
- `push_branch(bb, slot, bbnew)`（funcdata_block.cc:404）：将 CBRANCH 转为 BRANCH，重定向 out-edge 到 BRANCHIND 块。
- `force_goto(pcop, pcdest) -> bool`（funcdata_block.cc:752）：标记指定分支为非结构化 goto。
- `set_goto_branch(bl, j)`：标记 out-edge j 为 goto（使用 GOTO_EDGE_0/1 标志）。
- `move_out_edge(bb, slot, bbnew)`：重定向 out-edge（BlockGraph::moveOutEdge）。

**JumpBasic 新增方法**：
- `fold_in_one_guard(fd, guard, jump) -> bool`（jumptable.cc:1392）：消除单个守卫——或将 CBRANCH 条件设为常量，或通过 push_branch 将分支推入 switch。
- `fold_in_guards`：现使用 fold_in_one_guard 处理每个守卫（jumptable.cc:1577）。

**Override 新增方法**：
- `apply_force_gotos(fd) -> usize`（override.cc:204）：将所有 force-goto 覆写推入函数。

测试：新增 2 个（set_goto_branch 标志 + apply_force_gotos）。jumptable.rs 所有算法 L3 缺口已关闭。

### 2026-07-01：JumpTable 接入 Funcdata
recover_model/recover_addresses/try_recover/recover_jump_tables。ActionSwitchNorm 调用 recover_jump_tables。jump_tables 现可被填充，find_jump_table 返回非 None。
<!-- annotation-pass: 2026-07-04 -->
<!-- ref-fix2: 1783141346.3299575 -->
