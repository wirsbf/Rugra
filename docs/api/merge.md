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

### `pub fn merge_all(&mut self, fd: &mut Funcdata)`

Perform the full merging + naming pipeline. Phase order:
1. `live_varnode_set` → cache authoritative live varnodes
2. `merge_addr_tied` → group same-loc varnodes
3. `ensure_all_have_high` → singleton HighVariables
4. `compute_varnode_covers` → per-Varnode liveness covers
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

 