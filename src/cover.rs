//! Liveness cover for varnodes
//!
//! Corresponds to Ghidra's `cover.hh`

use std::collections::BTreeMap;
use std::fmt;

/// Range of P-code ops within a single basic block where a varnode is alive
///
/// Corresponds to Ghidra's `CoverBlock` class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverBlock {
    /// Start of liveness (order in SeqNum)
    pub start: u32,
    /// End of liveness (order in SeqNum)
    pub end: u32,
}

impl CoverBlock {
    /// Create an empty cover block
    pub fn new() -> Self {
        Self {
            start: u32::MAX,
            end: 0,
        }
    }

    /// Clear the cover block
    pub fn clear(&mut self) {
        self.start = u32::MAX;
        self.end = 0;
    }

    /// Set the start of liveness
    pub fn set_begin(&mut self, s: u32) {
        self.start = s;
    }

    /// Set the end of liveness
    pub fn set_end(&mut self, e: u32) {
        self.end = e;
    }

    /// Check if the cover block is empty
    pub fn empty(&self) -> bool {
        self.start > self.end
    }

    /// Check if the cover block contains a specific point
    pub fn contain(&self, point: u32) -> bool {
        point >= self.start && point <= self.end
    }

    /// Merge another cover block into this one
    pub fn merge(&mut self, other: &CoverBlock) {
        if other.empty() { return; }
        if self.start > other.start { self.start = other.start; }
        if self.end < other.end { self.end = other.end; }
    }

    /// Intersect another cover block with this one
    pub fn intersect(&mut self, other: &CoverBlock) {
        if self.start < other.start { self.start = other.start; }
        if self.end > other.end { self.end = other.end; }
        if self.start > self.end { self.clear(); }
    }
}

/// Full liveness cover of a varnode across multiple blocks
///
/// Corresponds to Ghidra's `Cover` class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cover {
    /// Mapping from basic block index to the cover block for that block
    pub blocks: BTreeMap<i32, CoverBlock>,
}

impl Cover {
    /// Create a new empty cover
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
        }
    }

    /// Clear the cover
    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    /// Add a definition point to the cover
    pub fn add_def_point(&mut self, block_idx: i32, point: u32) {
        let cb = self.blocks.entry(block_idx).or_insert_with(CoverBlock::new);
        cb.set_begin(point);
    }

    /// Add a reference point to the cover
    pub fn add_ref_point(&mut self, block_idx: i32, point: u32) {
        let cb = self.blocks.entry(block_idx).or_insert_with(CoverBlock::new);
        if cb.empty() || point > cb.end {
            cb.set_end(point);
        }
    }

    /// Check if the cover contains a point within a block
    pub fn contain(&self, block_idx: i32, point: u32) -> bool {
        if let Some(cb) = self.blocks.get(&block_idx) {
            cb.contain(point)
        } else {
            false
        }
    }

    /// Merge another cover into this one
    pub fn merge(&mut self, other: &Cover) {
        for (idx, other_cb) in &other.blocks {
            let cb = self.blocks.entry(*idx).or_insert_with(CoverBlock::new);
            cb.merge(other_cb);
        }
    }

    /// Intersect another cover with this one
    pub fn intersect(&mut self, other: &Cover) {
        let mut keys_to_remove = Vec::new();
        for (idx, cb) in &mut self.blocks {
            if let Some(other_cb) = other.blocks.get(idx) {
                cb.intersect(other_cb);
                if cb.empty() {
                    keys_to_remove.push(*idx);
                }
            } else {
                keys_to_remove.push(*idx);
            }
        }
        for idx in keys_to_remove {
            self.blocks.remove(&idx);
        }
    }

    /// Non-mutating predicate: true iff this cover and `other` share at least
    /// one live point. Used by cover-based merging to decide whether two
    /// HighVariables are simultaneously live (and thus cannot share a name).
    pub fn intersects(&self, other: &Cover) -> bool {
        for (idx, cb) in &self.blocks {
            if let Some(other_cb) = other.blocks.get(idx) {
                let lo = std::cmp::max(cb.start, other_cb.start);
                let hi = std::cmp::min(cb.end, other_cb.end);
                if lo <= hi {
                    return true;
                }
            }
        }
        false
    }

    /// Like `intersects`, but ignores overlap at one specific point. Used by
    /// copy-merge: the COPY op itself reads the input and writes the output,
    /// so their covers always overlap at that single op — that overlap is the
    /// merge point itself and must not block merging. Any OTHER overlap means
    /// the two HighVariables are simultaneously live elsewhere and must not
    /// merge.
    pub fn intersects_except_at(
        &self,
        other: &Cover,
        exclude_block: i32,
        exclude_order: u32,
    ) -> bool {
        for (idx, cb) in &self.blocks {
            let Some(other_cb) = other.blocks.get(idx) else {
                continue;
            };
            let lo = std::cmp::max(cb.start, other_cb.start);
            let hi = std::cmp::min(cb.end, other_cb.end);
            if lo > hi {
                continue;
            }
            if *idx == exclude_block && lo <= exclude_order && exclude_order <= hi {
                // The overlap range includes the excluded point. If the range
                // contains any OTHER point, that's a real overlap.
                if hi > lo {
                    return true;
                }
                // Range is exactly {exclude_order} — no real overlap, continue.
            } else {
                return true;
            }
        }
        false
    }
}

impl fmt::Display for CoverBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.empty() {
            write!(f, "[]")
        } else {
            write!(f, "[{:x}, {:x}]", self.start, self.end)
        }
    }
}

impl fmt::Display for Cover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        for (i, (idx, cb)) in self.blocks.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{}: {}", idx, cb)?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_block_basic() {
        let mut cb = CoverBlock::new();
        assert!(cb.empty());

        cb.set_begin(10);
        cb.set_end(20);
        assert!(!cb.empty());
        assert!(cb.contain(15));
        assert!(!cb.contain(5));
        assert!(!cb.contain(25));
    }

    #[test]
    fn test_cover_merge() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 10);
        c1.add_ref_point(1, 20);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 15);
        c2.add_ref_point(1, 25);
        c2.add_def_point(2, 5);
        c2.add_ref_point(2, 10);

        c1.merge(&c2);
        assert_eq!(c1.blocks.get(&1).unwrap().start, 10);
        assert_eq!(c1.blocks.get(&1).unwrap().end, 25);
        assert_eq!(c1.blocks.get(&2).unwrap().start, 5);
        assert_eq!(c1.blocks.get(&2).unwrap().end, 10);
    }

    /// Disjoint-block covers must not intersect: the canonical safe-merge case.
    #[test]
    fn test_intersect_disjoint_blocks() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 5);
        c1.add_ref_point(1, 10);

        let mut c2 = Cover::new();
        c2.add_def_point(2, 5);
        c2.add_ref_point(2, 10);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        assert!(tmp.blocks.is_empty(), "disjoint-block covers must not intersect");
    }

    /// Same-block non-overlapping ranges must yield empty intersection.
    #[test]
    fn test_intersect_disjoint_same_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 5);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        match tmp.blocks.get(&1) {
            None => {}
            Some(cb) => {
                assert!(cb.empty(), "disjoint same-block covers must yield empty CoverBlock, got {:?}", cb);
            }
        }
    }

    /// Overlapping same-block ranges must produce the tightened [max_start, min_end].
    #[test]
    fn test_intersect_overlapping_same_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 15);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        let cb = tmp.blocks.get(&1).expect("overlapping same-block covers must keep the block");
        assert!(!cb.empty(), "expected non-empty intersection, got {:?}", cb);
        assert_eq!(cb.start, 10);
        assert_eq!(cb.end, 15);
    }

    /// Multi-block intersect keeps overlapping blocks (narrowed) and drops disjoint ones.
    #[test]
    fn test_intersect_partial_multi_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 20);
        c1.add_def_point(2, 1);
        c1.add_ref_point(2, 20);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 30);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        assert!(tmp.blocks.contains_key(&1), "overlapping block must survive intersect");
        assert!(!tmp.blocks.contains_key(&2), "non-overlapping block must be dropped");
        let cb = tmp.blocks.get(&1).unwrap();
        assert_eq!(cb.start, 10);
        assert_eq!(cb.end, 20);
    }

    /// `intersects` is a non-mutating predicate; it must not alter either cover.
    #[test]
    fn test_intersects_predicate() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 10);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 20);
        c2.add_ref_point(1, 30);

        let mut c3 = Cover::new();
        c3.add_def_point(1, 5);
        c3.add_ref_point(1, 15);

        assert!(!c1.intersects(&c2), "disjoint covers must not intersect");
        assert!(c1.intersects(&c3), "overlapping covers must intersect");

        assert_eq!(c1.blocks.get(&1).unwrap().start, 1);
        assert_eq!(c1.blocks.get(&1).unwrap().end, 10);
    }
}
