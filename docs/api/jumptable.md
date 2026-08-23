# jumptable.rs — Jump-table recovery API

对应 Ghidra `jumptable.hh` / `jumptable.cc`。**当前状态：🔧 L2
（2026-08-11 锁定 12.0.4 审计）**。Override 的 start-op/trial normalization、
PathMeld 的 SeqNum 归并截断、EmulateFunction loader/LOAD、Basic/Basic2/Assisted
model selection 与 SwitchNorm 调用闭包均未闭合；正式行为门禁为 `NO_ORACLE`。

## 2026-08-23：JUMPTABLE-GUARDS-0001 — analyzeGuards 完整移植 + valueMatch 补全 + checkUnrolledGuard 接线

- `analyze_guards(bl, pathout)`（jumptable.cc:1046-1112）：完整重写。
  ① `pathout>=0 && sizeOut==2` 首轮步进语义：prevbl=当前块、bl=out(pathout)、
  indpath=pathout、pathout 消耗为 -1，第一轮即分析步进块自身的 CBRANCH
  （JumpBasic2 传入 pathout 时守卫不再为空）；② 步进/回走任一分支后
  `bl = prevbl` 逐轮上移；③ 回走循环遇 `sizeIn != 1`：`sizeIn > 1` 时调
  `check_unrolled_guard`（cc:1069-1070），随后无条件 return；④ `i != 0` 的
  other-switch 保护（cc:1083-1091）：第二条 CBRANCH 的旁路出边终点若为
  BRANCHIND 且不是本表 `get_indirect_op()` 则 break；⑤ `indpathstore =
  prevbl.getFlipPath() ? 1-indpath : indpath`（cc:1100-1101）；⑥ pullBack
  循环（j=0..1）按 cc:1103-1111 顺序 break/push。
- `value_match(vn2, base_vn2, bits_preserved2)`（jumptable.cc:637-680）：补全
  `oneOffMatch == 1 → 1` 分支与 LOAD 等价 `→ 2` 分支（in(0) 空间偏移相等 +
  指针相同 或 双方 INT_ADD 同基址同常量偏移）。
- `check_unrolled_guard`（jumptable.cc:1338-1370）：GuardRecord 改经
  `GuardRecord::new`（构造器内 quasiCopy 填 base_vn/bits_preserved），并保持
  oracle 内层 `PcodeOp *readOp = vn->getDef();` 对外层 readOp 的遮蔽 —— 所有
  push 的 readOp 恒为 cbranch。
- `find_multiequal`（block.cc:2753-2772）：补上缺失的 `parent == bl` 检查
  （cc:2761）。
- `quasi_copy` / `pull_back_through_op`：改读原始 `nzm` 字段
  （`Varnode::get_nzm`，对应 varnode.hh:231 的 inline `getNZMask` 字段读），
  不再用按 size 截断的近似。
- 门禁：`tools/run_jt_guards_oracle.sh` + `tests/oracle/jt_guards_1204.*`
  （FX-GUARD，oracle 12.0.4 e40ed130 双侧）：sc2_unrolled/sc4_other_switch/
  sc5_pathout MATCH；sc1/sc3 MISMATCH = `JUMPTABLE-GUARDS-RESIDUAL-0001`
  （rangeutil.rs `pull_back_binary` 缺 INT_SLESS/INT_SLESSEQUAL，oracle
  rangeutil.cc:882-917，不在本租约 write-set）；sc6 MISMATCH =
  `JUMPTABLE-GUARDS-RESIDUAL-0002`（funcdata.rs `calc_nz_mask` 简化，未做
  unwritten 输入 nzm 初始化，oracle funcdata_varnode.cc:889-893）。

## 2026-07-16：checkUnrolledGuard + checkCommonCbranch + findMultiequal

- `check_unrolled_guard(bl, max_pullback, use_nzmask)`（jumptable.cc:1338-1370）：检测跨多块展开的守卫。使用 checkCommonCbranch + CircleRange pullBack + liftVerifyUnroll + duplicateVarnodes + findMultiequal 创建 GuardRecord。所有依赖（getFlipPath b661e5e、liftVerifyUnroll b661e5e、pullBack a962f29）已完成。2026-08-23 起由 analyzeGuards 的 sizeIn>1 回走分支真正接线（此前为死代码）。
- `check_common_cbranch(var_array, bl)`（jumptable.cc:1305-1327）：验证所有 in-edge 来自相同 boolean-flip/out-slot 的 CBRANCH 块，收集 boolean 输入 varnode。
- `find_multiequal(bl, var_array)`（block.cc:2753-2772）：查找输入匹配 varArray 的 MULTIEQUAL op（须位于 bl 内）。

**Status:** L2. Public class coverage does not establish behavior parity; the
data-flow and CFG-rewriting algorithms still depend on broken Address,
Varnode/PcodeOp, Block, Range, injection, and emulation foundations.

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
  source (jumptable.cc:719); bits derive from the raw `nzm` field.
- `one_off_match(op1, op2) -> i32` — 1 if two ops produce the same value
  (jumptable.cc:684).

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
- `calc_range(vn, &mut CircleRange)` (jumptable.cc:1120). **2026-08-23 修正
  (JUMPTABLE-CALCRANGE-0001)**：初始 range 按 oracle 三分支派发——constant 取
  single(offset,size) 且**不再提前 return**（继续走守卫交集与 positive 截断）；
  `is_written() && def.is_bool_output()`（op.hh:184，经 `set_opcode_flags` 缓存的
  BOOLOUTPUT 位）取 `CircleRange(0,2,1,1)`；否则 getMaxValue/getStride 初始
  range（stride 仅此分支更新，constant/布尔分支保持 1）。守卫循环
  `rng.intersect(guard.range)` **就地写回**（cc:1144），`valueMatch!=0` 即应用；
  size>0x10000 时尝试 positive 半区截断（cc:1150-1155）。
- `find_smallest_normal(matchsize)` (jumptable.cc:1165).
- `mark_foldable_guards()` (jumptable.cc:1239).
- `mark_model(val)` (jumptable.cc:1254). **2026-08-23 修正
  (JUMPTABLE-CALCRANGE-0001 / JUMPTABLE-MARKMODEL-0001)**：先取
  `guard.get_branch()`，为 None（被 `mark_foldable_guards` 清除的守卫）则
  continue **跳过 readOp 标记**（cc:1259-1260），不再以 `get_read_op()` 判空。
- `analyze_guards(bl, pathout)` (jumptable.cc:1046).

### JT-CALCRANGE-1204 fixture
`tests/oracle/jt_calcrange_1204.{cc,rs,metadata.json}` +
`tools/run_jt_calcrange_oracle.sh`：锁定 12.0.4 双侧差分（base f6fd4ea +
jumptable.rs overlay，pin-base schema2）。三个场景（无符号守卫链 /
constant 输入 / markModel skip）投影全 MATCH，residuals 为空；sc2 的
constant-空交集判别力受 rangeutil `intersect` 保守实现限制（RANGE-0001）。

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
- `pull_back_through_op(rng, op, usenzmask) -> Option<Varnode>`（rangeutil.cc:1022）：通过 PcodeOp 反向范围，返回未知输入 varnode。处理一元/二元操作 + NZ 掩码交集 + SUBPIECE usenzmask 特殊情况（2026-07-16 补齐 rangeutil.cc:1053-1064）。

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

## 2026-06-27 历史实现记录（“达到 L3”结论已于 2026-08-11 撤回）

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
 

### 2026-07-05: JumpValues trait 多态 + JumpBasic2 修复 + find_normalized
- `JumpBasic.jrange` 改 `Option<Box<dyn JumpValues>>`(Ghidra `JumpValues*` 多态)。
- `JumpValues::clone_boxed_any_range` trait 辅助。
- `JumpValuesRangeDefault::new/Default`。
- `JumpBasic::find_normalized`(cc:1223)提取为独立方法。
- `JumpBasic2` 修复 check_normal_dominance/find_unnormalized/recover_model 类型错误,recover_model 对齐 cc:1698-1734。

## 注释行号勘误（2026-08-23，root）

复核发现的 annotation 漂移已修正：`JumpTable::clear` 引用 jumptable.cc:2739（原误 2761，那行是 encode 的 doc）；`clearSavedModel` 引用 jumptable.cc:2243（原误 2265）。行为零改动。

## calcRange/markModel 集成与注释行号勘误（2026-08-23，root）

dbcc9cb 集成：守卫交集就地写回、isBoolOutput 分支、常量无 early-return、markModel branch 判空跳过。复核域外 4 处既有注释行号漂移已修正（recoverModel 1437→1418、1453→1434、1484→1462、1293→1274）。
