# prefersplit.rs — Prefer-split records API

Faithful port of Ghidra's `prefersplit.hh` / `prefersplit.cc` (631 lines).

**Status:** L1 → L2. Complete PreferSplitRecord + PreferSplitManager +
SplitInstance with record lookup and split-offset computation. L3 gap: full
split algorithm (testX/splitX methods requiring Funcdata op-editing).

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/prefersplit.{hh,cc}`.

## Structs

### `PreferSplitRecord`
A record indicating a storage location should be split (prefersplit.hh:27).
- `new(offset, space, size, splitoffset)`.
- `less_than(&other) -> bool` — ordering by space, size (desc), offset
  (prefersplit.cc).
- Fields: `storage_offset`, `storage_space`, `storage_size`, `splitoffset`.

### `SplitInstance`
An instance of a split varnode being processed (prefersplit.hh:34).
- `new(vn_offset, vn_size, splitoffset)`.
- `fillin(bigendian, sethi, setlo)` — compute hi/lo piece offsets
  (prefersplit.cc `fillinInstance`).
- `lo_size(bigendian)`, `hi_size(bigendian)`.

## Free function
- `initialize(records)` — sort records (prefersplit.cc `PreferSplitManager::initialize`).

## `PreferSplitManager`
Manages splitting based on records (prefersplit.hh:33).
- `new()`, `init(records)`.
- `num_records()`, `records()`.
- `find_record(space, size, offset) -> Option<&PreferSplitRecord>` — binary
  search lookup (prefersplit.cc `findRecord`).
- `split()` / `split_additional()` — L3 gap (Funcdata op-editing).

## L3 gaps
- Full split algorithm: `splitRecord` → `splitVarnode` → `testDefiningCopy`/
  `splitLoad`/`splitStore`/`testZext`/`testPiece`/`testSubpiece` etc.
  (prefersplit.cc:46-72). Requires deep Funcdata op-editing.
- `splitAdditional` for temporary splitting.

## 2026-06-27（续）：PreferSplitManager::split Funcdata 集成

- **split(fd)**：现接受 Funcdata 参数——遍历 VarnodeBank 查找匹配 split record 的 Varnodes，标记后清除。完整 SUBPIECE/PIECE 创建待更深层 op-editing。
- **split_additional(fd)**：现接受 Funcdata——扫描 SUBPIECE ops 检测需要进一步分裂的临时变量。
