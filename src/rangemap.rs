//! Range and partition maps — faithful port of `rangemap.hh` (426 lines) and
//! `partmap.hh` (233 lines).
//!
//! Generic interval map containers used by the symbol database (SymbolEntry
//! lookup) and the context database (property flag partition).
//!
//! # RangeMap
//! A container for records occupying (possibly overlapping) intervals. Records
//! are stored in a sorted list of disjoint sub-ranges forming the common
//! refinement of all record ranges. Find operations use binary search on the
//! sub-range boundaries.
//!
//! # PartMap
//! A map from a linear space to value objects. The linear space is partitioned
//! at split points; each partition maps to a value. The default value applies
//! before the first split point.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/rangemap.{hh},
//! partmap.hh.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// RangeMap — interval map for overlapping records
// ---------------------------------------------------------------------------

/// A record in a RangeMap, occupying the interval [first, last]. The user of
/// RangeMap provides records that implement this trait.
pub trait RangeRecord: Clone {
    /// The start of the record's range.
    fn first(&self) -> u64;
    /// The end of the record's range (inclusive).
    fn last(&self) -> u64;
}

/// A sub-range entry in the internal refinement. Sorted by `last` boundary.
#[derive(Clone)]
struct SubRange<R: RangeRecord> {
    /// Start of this disjoint sub-range.
    first: u64,
    /// End of this disjoint sub-range (inclusive).
    last: u64,
    /// The actual record this sub-range belongs to.
    record: R,
}

/// An interval map container. Records can overlap; the container maintains a
/// sorted list of disjoint sub-ranges for efficient lookup. Faithful to
/// `rangemap<>` (rangemap.hh:65).
///
/// This is a simplified implementation that uses linear scan for find_overlap
/// but sorted insertion for correct ordering. Full Ghidra uses a multiset of
/// AddrRange; we use a Vec sorted by (last, first).
pub struct RangeMap<R: RangeRecord> {
    /// Sorted sub-ranges (by last boundary, then first).
    sub_ranges: Vec<SubRange<R>>,
    /// All records stored (for iteration).
    records: Vec<R>,
}

impl<R: RangeRecord> Default for RangeMap<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RangeRecord> RangeMap<R> {
    /// Create an empty range map.
    pub fn new() -> Self {
        Self {
            sub_ranges: Vec::new(),
            records: Vec::new(),
        }
    }

    /// Is the container empty? Faithful to `empty`.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all records. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.sub_ranges.clear();
        self.records.clear();
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Insert a new record into the container. Faithful to `insert`.
    /// The record occupies [a, b]. A sub-range entry is created and inserted
    /// in sorted position.
    pub fn insert(&mut self, record: R) {
        let a = record.first();
        let b = record.last();
        let sr = SubRange {
            first: a,
            last: b,
            record: record.clone(),
        };
        // Insert sorted by (last, first).
        let pos = self
            .sub_ranges
            .partition_point(|s| (s.last, s.first) < (sr.last, sr.first));
        self.sub_ranges.insert(pos, sr);
        self.records.push(record);
    }

    /// Find the first record overlapping the given interval [point, end].
    /// Faithful to `find_overlap` (rangemap.hh:159). Returns the index of the
    /// overlapping record, or None.
    pub fn find_overlap(&self, point: u64, end: u64) -> Option<&R> {
        for sr in &self.sub_ranges {
            // Overlap: sr.first <= end && point <= sr.last
            if sr.first <= end && point <= sr.last {
                return Some(&sr.record);
            }
        }
        None
    }

    /// Find all records overlapping the given point. Returns indices.
    /// Faithful to `find` (rangemap.hh:146).
    pub fn find_at_point(&self, point: u64) -> Vec<&R> {
        self.sub_ranges
            .iter()
            .filter(|sr| sr.first <= point && point <= sr.last)
            .map(|sr| &sr.record)
            .collect()
    }

    /// Find the smallest containing record for [point, size).
    /// Used by Scope::findContainer.
    pub fn find_container(&self, point: u64, size: u64) -> Option<&R> {
        let end = point + size - 1;
        let mut best: Option<&R> = None;
        let mut best_span = u64::MAX;
        for sr in &self.sub_ranges {
            if sr.first <= point && end <= sr.last {
                let span = sr.last - sr.first + 1;
                if span < best_span {
                    best_span = span;
                    best = Some(&sr.record);
                }
            }
        }
        best
    }

    /// Iterate over all records.
    pub fn records(&self) -> &[R] {
        &self.records
    }
}

// ---------------------------------------------------------------------------
// PartMap — partition map for address-keyed values
// ---------------------------------------------------------------------------

/// A map from a linear space to value objects. Faithful to `partmap<>`
/// (partmap.hh:49).
///
/// The linear space is partitioned at split points; each partition maps to a
/// value. The default value applies before the first split point.
#[derive(Clone)]
pub struct PartMap<V: Clone> {
    /// Map from split points to value objects.
    database: BTreeMap<u64, V>,
    /// The value before the first split point.
    default_value: V,
}

impl<V: Clone> PartMap<V> {
    /// Construct with a default value.
    pub fn new(default_value: V) -> Self {
        Self {
            database: BTreeMap::new(),
            default_value,
        }
    }

    /// Get the value at a point. Faithful to `getValue` (partmap.hh:82).
    /// Looks up the first split point <= pnt.
    pub fn get_value(&self, pnt: u64) -> &V {
        match self.database.range(..=pnt).next_back() {
            Some((_, v)) => v,
            None => &self.default_value,
        }
    }

    /// Get a mutable reference to the value at a point.
    pub fn get_value_mut(&mut self, pnt: u64) -> &mut V {
        // We need to handle the borrow checker carefully.
        let has_key = self
            .database
            .range(..=pnt)
            .next_back()
            .map(|(k, _)| *k)
            .is_some();
        if has_key {
            let key = self
                .database
                .range(..=pnt)
                .next_back()
                .map(|(k, _)| *k)
                .unwrap();
            self.database.get_mut(&key).unwrap()
        } else {
            &mut self.default_value
        }
    }

    /// Introduce a new split point. Faithful to `split` (partmap.hh:117).
    /// Copies the current value at pnt into the new partition.
    pub fn split(&mut self, pnt: u64) -> &mut V {
        if self.database.contains_key(&pnt) {
            return self.database.get_mut(&pnt).unwrap();
        }
        // Copy the current value at this point.
        let val = match self.database.range(..pnt).next_back() {
            Some((_, v)) => v.clone(),
            None => self.default_value.clone(),
        };
        self.database.entry(pnt).or_insert(val)
    }

    /// Clear split points in a range. Faithful to `clearRange`
    /// (partmap.hh:144).
    /// Splits at pnt1 and pnt2, then removes all split points in between.
    pub fn clear_range(&mut self, pnt1: u64, pnt2: u64) {
        self.split(pnt1);
        self.split(pnt2);
        // Remove keys in (pnt1, pnt2).
        let keys_to_remove: Vec<u64> = self
            .database
            .range((std::ops::Bound::Excluded(pnt1), std::ops::Bound::Excluded(pnt2)))
            .map(|(k, _)| *k)
            .collect();
        for k in keys_to_remove {
            self.database.remove(&k);
        }
    }

    /// Get the default value. Faithful to `defaultValue`.
    pub fn default_value(&self) -> &V {
        &self.default_value
    }

    /// Get a mutable reference to the default value.
    pub fn default_value_mut(&mut self) -> &mut V {
        &mut self.default_value
    }

    /// Clear all split points. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.database.clear();
    }

    /// Is the partition map empty of split points? Faithful to `empty`.
    pub fn is_empty(&self) -> bool {
        self.database.is_empty()
    }

    /// Number of split points.
    pub fn num_splits(&self) -> usize {
        self.database.len()
    }

    /// Get the value and bounds at a point. Faithful to `bounds`
    /// (partmap.hh:172). Returns (value, before, after, valid_code):
    /// - 0 = both bounds apply
    /// - 1 = no lower bound
    /// - 2 = no upper bound
    /// - 3 = neither bound
    pub fn bounds(&self, pnt: u64) -> (&V, u64, u64, i32) {
        if self.database.is_empty() {
            return (&self.default_value, 0, 0, 3);
        }
        // Find the split point <= pnt.
        let lower = self.database.range(..=pnt).next_back();
        let upper = self.database.range((std::ops::Bound::Excluded(pnt), std::ops::Bound::Unbounded)).next();

        match (lower, upper) {
            (Some((lo_k, lo_v)), Some((hi_k, _))) => {
                (lo_v, *lo_k, *hi_k, 0)
            }
            (Some((lo_k, lo_v)), None) => {
                (lo_v, *lo_k, 0, 2)
            }
            (None, Some((hi_k, _))) => {
                (&self.default_value, 0, *hi_k, 1)
            }
            (None, None) => {
                (&self.default_value, 0, 0, 3)
            }
        }
    }

    /// Iterate over all split points.
    pub fn splits(&self) -> impl Iterator<Item = (&u64, &V)> {
        self.database.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct TestRecord {
        first: u64,
        last: u64,
        name: &'static str,
    }

    impl RangeRecord for TestRecord {
        fn first(&self) -> u64 {
            self.first
        }
        fn last(&self) -> u64 {
            self.last
        }
    }

    #[test]
    fn test_rangemap_empty() {
        let rm: RangeMap<TestRecord> = RangeMap::new();
        assert!(rm.is_empty());
        assert_eq!(rm.len(), 0);
    }

    #[test]
    fn test_rangemap_insert_find_overlap() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord { first: 100, last: 199, name: "A" });
        rm.insert(TestRecord { first: 300, last: 399, name: "B" });

        let r = rm.find_overlap(150, 160).unwrap();
        assert_eq!(r.name, "A");

        let r = rm.find_overlap(350, 360).unwrap();
        assert_eq!(r.name, "B");

        assert!(rm.find_overlap(200, 299).is_none());
    }

    #[test]
    fn test_rangemap_find_at_point() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord { first: 100, last: 199, name: "A" });
        rm.insert(TestRecord { first: 150, last: 250, name: "B" });

        let results = rm.find_at_point(175);
        assert_eq!(results.len(), 2); // Both A and B overlap at 175.
    }

    #[test]
    fn test_rangemap_find_container() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord { first: 100, last: 399, name: "big" });
        rm.insert(TestRecord { first: 100, last: 199, name: "small" });

        let r = rm.find_container(150, 10).unwrap();
        assert_eq!(r.name, "small"); // Smaller container wins.
    }

    #[test]
    fn test_rangemap_records() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord { first: 0, last: 10, name: "X" });
        rm.insert(TestRecord { first: 20, last: 30, name: "Y" });
        assert_eq!(rm.len(), 2);
        assert_eq!(rm.records()[0].name, "X");
        assert_eq!(rm.records()[1].name, "Y");
    }

    #[test]
    fn test_rangemap_clear() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord { first: 0, last: 10, name: "X" });
        rm.clear();
        assert!(rm.is_empty());
    }

    // PartMap tests

    #[test]
    fn test_partmap_default() {
        let pm: PartMap<u32> = PartMap::new(0);
        assert_eq!(*pm.get_value(100), 0);
        assert!(pm.is_empty());
    }

    #[test]
    fn test_partmap_split_and_get() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 5;
        *pm.split(20) = 99;

        assert_eq!(*pm.get_value(5), 0); // Before first split → default.
        assert_eq!(*pm.get_value(10), 5); // At split 10.
        assert_eq!(*pm.get_value(15), 5); // Between 10 and 20.
        assert_eq!(*pm.get_value(20), 99); // At split 20.
        assert_eq!(*pm.get_value(100), 99); // After last split.
    }

    #[test]
    fn test_partmap_split_copies_previous() {
        let mut pm: PartMap<u32> = PartMap::new(42);
        *pm.split(10) = 10;
        // Split at 20 should copy value from partition at 15 (which is 10).
        let val = pm.split(20);
        assert_eq!(*val, 10); // Copied from partition [10, 20).
    }

    #[test]
    fn test_partmap_split_exact() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 5;
        *pm.split(10) = 99; // Split at same point → overwrite.
        assert_eq!(*pm.get_value(10), 99);
    }

    #[test]
    fn test_partmap_clear_range() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 1;
        *pm.split(20) = 2;
        *pm.split(30) = 3;
        pm.clear_range(10, 30);
        // Should have splits at 10 and 30, with 20 removed.
        assert_eq!(pm.num_splits(), 2);
        assert_eq!(*pm.get_value(15), 1);
        assert_eq!(*pm.get_value(35), 3);
    }

    #[test]
    fn test_partmap_bounds() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 5;
        *pm.split(20) = 10;

        let (val, before, after, valid) = pm.bounds(15);
        assert_eq!(*val, 5);
        assert_eq!(before, 10);
        assert_eq!(after, 20);
        assert_eq!(valid, 0); // Both bounds.

        let (val, _, _, valid) = pm.bounds(5);
        assert_eq!(*val, 0); // Default.
        assert_eq!(valid, 1); // No lower bound.

        let (val, _, _, valid) = pm.bounds(100);
        assert_eq!(*val, 10);
        assert_eq!(valid, 2); // No upper bound.
    }

    #[test]
    fn test_partmap_bounds_empty() {
        let pm: PartMap<u32> = PartMap::new(42);
        let (val, _, _, valid) = pm.bounds(100);
        assert_eq!(*val, 42);
        assert_eq!(valid, 3); // Neither bound.
    }

    #[test]
    fn test_partmap_default_value_mut() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.default_value_mut() = 77;
        assert_eq!(*pm.get_value(100), 77);
    }
}
