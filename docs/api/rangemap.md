# rangemap.rs — Interval map + partition map API

Faithful port of Ghidra's `rangemap.hh` (426 lines) + `partmap.hh` (233 lines).

**Status:** L3. Fully implemented RangeMap + PartMap.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/rangemap.hh, partmap.hh`.

## Trait `RangeRecord`
A record in a RangeMap occupying [first, last].
- `first() -> u64`, `last() -> u64`.

## `RangeMap<R: RangeRecord>`
Interval map container for overlapping records (rangemap.hh:65).
- `new()`, `is_empty()`, `clear()`, `len()`.
- `insert(record)` — insert sorted by (last, first) (rangemap.hh:162).
- `find_overlap(point, end) -> Option<&R>` — first record overlapping interval
  (rangemap.hh:159).
- `find_at_point(point) -> Vec<&R>` — all records containing point
  (rangemap.hh:146).
- `find_container(point, size) -> Option<&R>` — smallest containing record.
- `records() -> &[R]` — all records.

## `PartMap<V: Clone>`
Partition map from linear space to values (partmap.hh:49).
- `new(default_value)`.
- `get_value(pnt) -> &V` — lookup (partmap.hh:82).
- `get_value_mut(pnt) -> &mut V`.
- `split(pnt) -> &mut V` — introduce split point, copies previous value
  (partmap.hh:117).
- `clear_range(pnt1, pnt2)` — clear intermediate split points (partmap.hh:144).
- `bounds(pnt) -> (&V, before, after, valid_code)` — value + bounds (partmap.hh:172).
  - valid: 0=both, 1=no lower, 2=no upper, 3=neither.
- `default_value()`, `default_value_mut()`, `clear()`, `is_empty()`,
  `num_splits()`, `splits()`.
<!-- annotation-pass: 2026-07-04 -->
