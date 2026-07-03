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
