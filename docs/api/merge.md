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

### `fn is_live_varnode(vn: &Varnode) -> bool` (private)

Liveness guard for merge participation. Faithful to Ghidra's contract
that merge operates on the post-optimization varnode set: only varnodes
still live after dead-code elimination are grouped into HighVariables.

- Input varnodes (function parameters / entry values) always pass.
- Written varnodes pass iff their def op is not marked DEAD.
- Free varnodes (neither input nor written) are skipped — they are
  copy-prop/dead-code leftovers with no meaningful def.

Applied to all four `loc_tree` traversals (merge_addr_tied /
ensure_all_have_high / compute_varnode_covers / assign_names). This is
what makes `high.instances` authoritative when merge runs after
dead-code in the pipeline.

### `pub fn merge_all(&mut self, fd: &mut Funcdata)`

Perform the full merging + naming pipeline

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

 