# `merge.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/merge.rs`

## 模块说明 (Module Doc)

High-level variable merging logic

Corresponds to Ghidra's `merge.hh`. This module is responsible for
merging multiple SSA Varnodes into a single HighVariable.

## 导出的公共 API (Public API)

### `pub struct Merge`

Manages the process of merging Varnodes into HighVariables

Corresponds to Ghidra's `Merge` class. Groups SSA varnodes that
represent the same logical variable into `HighVariable` instances,
then assigns human-readable names to each group.

### `pub fn new() -> Self`

Create a new Merge instance

### `pub fn clear(&mut self, fd: &mut Funcdata)`

Clear all existing HighVariables and reset merge state

### `fn live_varnode_set(fd: &Funcdata) -> HashSet<usize>` (private)

Liveness for merge. Builds the set of varnode Arc pointers that are still
referenced (as input or output) by any **alive** op — drawn from
`fd.obank.alivelist` plus block-level ops not marked DEAD. The result is
cached in `Merge::live_set` once per `merge_all` run and consulted by every
`loc_tree` traversal.

Why membership-in-alive-op-set, not `vn.def`/`vn.descend`: after
copy-propagation redirects `user.inrefs[slot]` to a new source, the old
varnode's `vn.def` still points at the now-marked-dead COPY op, and
`vn.descend` becomes empty — even though the varnode is still live (the
new consumer references it). So def/descend are unreliable post-optimization
signals; the only authoritative liveness source is "is this varnode in some
alive op's inrefs/output?". Input varnodes (function parameters) are always
live.

This is what makes `high.instances` authoritative when merge runs after
dead-code in the pipeline.

**Note (2026-07-02)**: `live_set` is now consulted only for cover computation.
`ensure_all_have_high` and `assign_names` no longer filter by it — they
iterate the full `loc_tree`, faithful to Ghidra's `Funcdata::setHighLevel`
(funcdata_varnode.cc:595) and `ActionNameVars::linkSymbols`
(coreaction.cc:2940-2976). The prior live_set filter left implied/CAST-output
and free Varnodes without a HighVariable name, forcing printc into the
`uVar_{offset}` fallback (341 placeholders in curl).

### `pub fn merge_all(&mut self, fd: &mut Funcdata)`

Perform the full merging + naming pipeline. Phase order:
1. `live_varnode_set` → cache authoritative live varnodes
2. `merge_addr_tied` → group same-loc varnodes
3. `ensure_all_have_high` → singleton HighVariables for EVERY Varnode in
   `loc_tree` lacking one (faithful to `Funcdata::setHighLevel`,
   funcdata_varnode.cc:595 — no live_set filter)
4. `compute_varnode_covers` → per-Varnode liveness covers (precise def→use
   range, NOT propagated through CFG successors — that over-approximation
   broke ActionMarkImplied's inflateTest; `propagate_cover_through_cfg` is
   now `#[allow(dead_code)]` disabled)
5. `merge_by_cover` → merge copy-related disjoint-cover pairs
6. `update_high_covers` → sync each HighVariable.cover from members
7. `assign_names` → Ghidra-style auto-naming

### `fn update_high_covers(&mut self, fd: &mut Funcdata)` (private, 2026-06-29)

Re-derive every HighVariable's internal cover by calling
`high.update_internal_cover()`. Collects distinct HighVariables reachable
from loc_tree varnodes (deduped by Arc pointer). Must run after
merge_by_cover finalizes instance sets so high.cover reflects all members.
ActionMarkImplied (later in pipeline) consults high.cover.

### `pub fn mark_implied(vn: &Arc<RwLock<Varnode>>)` (2026-06-29)

Faithful to Merge::markImplied (merge.cc:1595). Sets the IMPLIED flag on a
varnode. Ghidra also marks coverdirty on the def op's inputs; Rugra
recomputes covers wholesale per merge_all so only the flag is set. Called
by ActionMarkImplied when checkImpliedCover passes.

### `pub fn inflate_test(a: &Arc<RwLock<Varnode>>, high: &HighVariable) -> bool` (2026-06-29)

Faithful to Merge::inflateTest (merge.cc:1616). Tests if inflating varnode
`a`'s cover to cover `high` causes an intersection with a sibling instance
of a's own HighVariable (excluding `a` itself / its copy-shadow). Returns
true if there IS an intersection (varnode CANNOT be implied). The
authoritative check in ActionMarkImplied::checkImpliedCover.

### `pub fn merge_addr_tied(&mut self, fd: &mut Funcdata)`

Merge varnodes that are tied to the same address+size.

This is the primary merge pass: varnodes at the same location
and with the same size are different SSA versions of the same
logical variable and should share a HighVariable.

### `pub fn merge_test(&self, v1: &Varnode, v2: &Varnode) -> bool`

Test whether two varnodes can be merged into the same HighVariable.

Returns true if they share the same address space and size, and
neither is a constant or annotation (which should never be merged).

### `pub fn merge_force(&mut self, vn1: Arc<RwLock<Varnode>>, vn2: Arc<RwLock<Varnode>>)`

Force-merge two varnodes into the same HighVariable.

If vn1 already has a HighVariable, add vn2 to it (or vice versa).
If neither has one, create a new HighVariable for both.

### `pub fn assign_names(&mut self, fd: &mut Funcdata)`

Assign human-readable names to all HighVariables in the function.

Iterates every Varnode in `loc_tree` except constants and annotations
(faithful to `ActionNameVars::linkSymbols`, coreaction.cc:2940-2976).
Free Varnodes are named too — see the TODO in source: Ghidra skips `isFree()`
because its printc routes free Varnodes to `pushUnnamedLocation` (raw address),
but Rugra's printc still emits them (SSA-completeness gap), so they need a
name to avoid the `uVar_{offset}` fallback.

Naming follows Ghidra conventions:
- Stack negative offset → `local_Xh`
- Stack positive offset → `param_stack_Xh`
- Register → `uVarN`
- Unique temp → `uVarN`
- RAM global → `DAT_XXXXXXXX`

### `pub fn merge_adjacent(&mut self, _fd: &mut Funcdata)`

Merge adjacent varnodes (placeholder for future enhancement)

### `pub fn merge_multi_entry(&mut self, _fd: &mut Funcdata)`

Merge multi-entry varnodes (placeholder for future enhancement)

### `pub fn merge_marker(&mut self, _fd: &mut Funcdata)`

Merge marker varnodes (placeholder for future enhancement)

### `pub fn merge_by_datatype(&mut self, _fd: &mut Funcdata)`

Merge by datatype compatibility (placeholder for future enhancement)

### `pub struct BlockVarnode`

Represents a varnode within a specific block for merging purposes

 
### 2026-07-01：补全 Merge 9 步序列
merge_required(mergeAddrTied+groupPartials+mergeMarker)、merge_marker(MULTIEQUAL/INDIRECT IO 合并)、merge_copy(COPY 链 cover-guarded 合并)、merge_adjacent(同 op IO 推测合并)、merge_by_datatype(类型分组+线性合并)、hide_shadows(copy-shadow 分析)、copy_marker(internal COPY NONPRINTING 标记)。+merge_speculative 原语。merge_all 重排为完整 9 步。2 新测试。multi_entry/group_partials/dominant_copy 仍 stub（需 ScopeLocal 符号机器）。

### 2026-07-01（续 2）：merge_multi_entry + dominant_copy
merge_multi_entry（merge.cc:908-963）：按 SymbolEntry Symbol 分组，多入口符号合并。dominant_copy（merge.cc:1415-1436）：COPY 链 cover-guarded 合并选主导。3 新测试。9 步 merge 全部实装（仅 group_partials/allocateCopyTrim 是忠实 no-op）。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- `merge_linear_speculative` → `merge_linear`（对齐 `Merge::mergeLinear` merge.hh:110。原 Rust 名多出 `_speculative` 后缀，Ghidra 方法名无此后缀）。

### 2026-07-03（续）：命名对齐 Ghidra（camelCase→snake_case）
- `copy_marker` → `mark_internal_copies`（对齐 `Merge::markInternalCopies` merge.hh:1444）。

### 2026-07-03（续 2）：修正 Ghidra 引用行号
- `mark_internal_copies` 的 `// Ghidra:` 注释行号从 merge.hh:1444（实为 merge.cc 行号）修正为 merge.hh:134（声明所在）。

### 2026-07-04：merge_opcode/process_copy_trims 对齐 Ghidra（消除 3 个自创方法）
- `merge_copy` → `merge_opcode(fd, opc)`（对齐 `Merge::mergeOpcode` merge.cc:326）。签名改为通用 OpCode 参数；用 `merge_test_required`（新增，对齐 merge.cc:102-166）+ `merge_speculative`（cover 相交静默跳过，对齐 merge.cc:1565-1575）。删除原来的 `intersects_except_at` 豁免（Ghidra 无此豁免）。
- `dominant_copy` → `process_copy_trims`（对齐 `Merge::processCopyTrims` merge.cc:1415）。删除原自创的 cover-extent dominant 合并，改为忠实 no-op（copyTrims 列表为空）。剩余缺口：snip 子系统未移植。
- 删除 `merge_by_cover` + `merge_by_cover_single_pass`（无 Ghidra 对应的自创迭代补偿 pass）。
- 删除死代码 `merge_speculative_by_vn_except` + `merge_speculative_except`（原被 merge_copy/dominant_copy/merge_by_cover 调用，现已无调用者）。
- 删除 4 个基于自创行为的测试（test_merge_by_cover_*, test_dominant_copy_*, test_copy_marker_*）——它们的断言依赖 cover-except 豁免合并，与 Ghidra 的 cover-skip 语义冲突。
- merge_all 顺序对齐 Ghidra coreaction.cc:5717-5729（删 merge_by_cover，merge_copy→merge_opcode，dominant_copy→process_copy_trims）。

### 2026-07-04（续）：移植 snip/trim 子系统（copyTrims 填充链路）
移植 Ghidra merge.cc 的 forced-merge + snip 数据流改写子系统：
- `allocate_copy_trim`（merge.cc:411）：创建 COPY op + unique 输出，push 进 copy_trims。union 解析路径省略（无 union 基础设施）。
- `snip_reads`（merge.cc:443）：截断一组读取到临时变量。
- `eliminate_intersect`（merge.cc:489）：检测单读 cover 相交并标记 snip（含 copy_shadow/partial_copy_shadow 检查）。
- `unify_address`（merge.cc:581）：对同地址组消除相交。
- `merge_addr_tied` 接入 unify_address（forced merge 前 snip，对齐 merge.cc:631-632）。
- `process_copy_trims` 改为遍历 copy_trims + 按 high 计数 + 清空（对齐 merge.cc:1420-1434）。dominant-copy 替换（processHighDominantCopy）待移植。
- 新增 Merge.copy_trims 字段（对齐 merge.hh:87）。
- 基础设施：BlockVarnode 完善（Ord/set/find_front）、varnode_def_loc/op_loc helpers。

### 2026-07-04（续 3）：完整移植 dominant-copy 替换子系统
- 移植 `process_high_dominant_copy`（merge.cc:1316）：对收到 ≥2 trim COPY 的 high，按同源 Varnode 分组，对每组调 build_dominant_copy。
- 移植 `find_all_into_copies`（merge.cc:1295）+ `compare_copy_by_in_varnode`（merge.cc:1045）：收集 high 的所有外来 COPY，按输入 Varnode + block index + order 排序。
- 移植 `build_dominant_copy`（merge.cc:1151）：支配树 LCA 选 dominant block（find_common_block_n），cover 检查可替换性（intersect_char>1），totalReplace+opDestroy 替换冗余 COPY。
- `process_copy_trims` 接入 process_high_dominant_copy（之前只计数，现在真正替换）。
- 移植 `merge_test_must`（merge.cc:241）+ 接入 merge_addr_tied（对齐 mergeRangeMust 的 mergeTestMust 门控）。
- 新增 `Cover::intersect_char`/`CoverBlock::intersect_char`（cover.cc:269/59）返回 0/1/2。
- 新增 `BlockGraph::find_common_block_n`（block.cc:796）N-way 支配树 LCA。
- 新增 `BlockBasic::get_stop_addr`（近似 block.cc:2328 getStop）。
- 新增 `Funcdata::op_insert_end`（funcdata.hh:461）+ `op_mark_non_printing`（funcdata.hh:519）。
- 新增 `Varnode::has_cover`（varnode.hh:284）。

### 2026-07-04（续 4）：hide_shadows 重写 + ActionHideShadow 委托
- `hide_shadows` 拆分为 `hide_shadows_of(fd, high) -> bool`（对齐 `Merge::hideShadows(high)` merge.cc:1070）+ `hide_shadows(fd)`（遍历所有 high）。
- `hide_shadows_of` 现在真正应用 opSetInput 重写（之前只分析不重写）。用 copy_shadow + cover.contain_varnode_def_at + op_set_input。
- `ActionHideShadow::apply` 从内联地址匹配逻辑改为委托 `Merge::hide_shadows_of(high)`（对齐 coreaction.cc:4831-4845 遍历 high + 调 hideShadows）。

### 2026-07-04（续 5）：移植 mergeOp per-op forced-merge 路径
移植 Ghidra mergeMarker 的 per-op forced-merge 子系统（merge.cc:656-902）：
- `trim_op_input`（merge.cc:692）：在 op 前插入 COPY trim（经 allocateCopyTrim → 填 copy_trims），替换 slot 输入。MULTIEQUAL 时 pc 取入边块的 getStop，插入到入边块末尾。
- `trim_op_output`（merge.cc:656）：把 op 输出移到 stubby unique，COPY 还原原输出。用原始 newOp（不填 copyTrims）。
- `merge_op`（merge.cc:719）：三阶段 forced merge — 非cover限制 trim → cover 限制迭代 trim（trimOpInput/trimOpOutput）→ 真正 merge。
- `collect_inputs`（merge.cc:783）+ `snip_output_interference`（merge.cc:811）：INDIRECT 输出干扰检测 + snip。
- `merge_indirect`（merge.cc:846）：snipOutputInterference + mergeOp。
- `merge_test_with_list`（merge.cc:1657）：HighIntersectTest 替代（用 aggregate_high_cover + intersect_char）。
- `merge_marker` 从 merge_force 改为委托 merge_op/merge_indirect（对齐 merge.cc:889-902）。
