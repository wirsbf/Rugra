//! Prefer-split records — faithful port of `prefersplit.hh` / `prefersplit.cc`
//! (631 lines).
//!
//! Infrastructure for designating registers that should be split into separate
//! pieces during decompilation. The `PreferSplitManager` applies splits based
//! on a list of `PreferSplitRecord` entries.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/prefersplit.{hh,cc}.

use crate::address::Address;
use crate::space::AddressSpace;
use std::sync::{Arc, RwLock};

/// A record indicating that a specific storage location should be split into
/// two pieces. Faithful to `PreferSplitRecord` (prefersplit.hh:27).
#[derive(Debug, Clone)]
pub struct PreferSplitRecord {
    /// The storage location (space + offset + size) to split.
    pub storage_offset: u64,
    /// The address space of the storage.
    pub storage_space: AddressSpace,
    /// The size of the storage in bytes.
    pub storage_size: u32,
    /// Number of initial bytes (in address order) to split into the first
    /// piece.
    pub splitoffset: i32,
}

impl PreferSplitRecord {
    /// Construct given storage details and split offset.
    pub fn new(offset: u64, space: AddressSpace, size: u32, splitoffset: i32) -> Self {
        Self {
            storage_offset: offset,
            storage_space: space,
            storage_size: size,
            splitoffset,
        }
    }

    /// Compare two records for sorting. Faithful to `operator<`
    /// (prefersplit.cc). Orders by space index, then size (descending), then
    /// offset.
    pub fn less_than(&self, op2: &PreferSplitRecord) -> bool {
        let s1 = self.storage_space.space_id();
        let s2 = op2.storage_space.space_id();
        if s1 != s2 {
            return s1 < s2;
        }
        if self.storage_size != op2.storage_size {
            return self.storage_size > op2.storage_size; // Bigger sizes come first.
        }
        self.storage_offset < op2.storage_offset
    }
}

/// Sort a vector of PreferSplitRecords. Faithful to `PreferSplitManager::initialize`
/// (prefersplit.cc).
pub fn initialize(records: &mut Vec<PreferSplitRecord>) {
    records.sort_by(|a, b| {
        if a.less_than(b) {
            std::cmp::Ordering::Less
        } else if b.less_than(a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
}

/// An instance of a split varnode being processed. Faithful to
/// `PreferSplitManager::SplitInstance` (prefersplit.hh:34).
#[derive(Debug)]
pub struct SplitInstance {
    /// Number of initial bytes in the first piece.
    pub splitoffset: i32,
    /// The original varnode offset being split.
    pub vn_offset: u64,
    /// The size of the original varnode.
    pub vn_size: u32,
    /// The most-significant piece offset.
    pub hi_offset: Option<u64>,
    /// The least-significant piece offset.
    pub lo_offset: Option<u64>,
}

impl SplitInstance {
    /// Construct given the varnode details and split offset. Faithful to the
    /// constructor (prefersplit.hh:41).
    pub fn new(vn_offset: u64, vn_size: u32, off: i32) -> Self {
        Self {
            splitoffset: off,
            vn_offset,
            vn_size,
            hi_offset: None,
            lo_offset: None,
        }
    }

    /// Define the varnode pieces. Faithful to `fillinInstance`
    /// (prefersplit.cc). Computes the hi/lo piece sizes based on endianness.
    /// `sethi`/`setlo` control which pieces to compute.
    pub fn fillin(&mut self, bigendian: bool, sethi: bool, setlo: bool) {
        let losize = if bigendian {
            self.vn_size as i32 - self.splitoffset
        } else {
            self.splitoffset
        };
        let hisize = self.vn_size as i32 - losize;
        if setlo {
            // The low piece is at the base offset, size losize.
            self.lo_offset = Some(self.vn_offset);
        }
        if sethi {
            // The high piece is at base + losize, size hisize.
            self.hi_offset = Some(self.vn_offset + losize as u64);
        }
        let _ = hisize;
    }

    /// Get the low piece size in bytes.
    pub fn lo_size(&self, bigendian: bool) -> u32 {
        if bigendian {
            (self.vn_size as i32 - self.splitoffset) as u32
        } else {
            self.splitoffset as u32
        }
    }

    /// Get the high piece size in bytes.
    pub fn hi_size(&self, bigendian: bool) -> u32 {
        self.vn_size - self.lo_size(bigendian)
    }
}

/// Manages the splitting of varnodes based on a list of PreferSplitRecords.
/// Faithful to `PreferSplitManager` (prefersplit.hh:33).
pub struct PreferSplitManager {
    /// The records describing which storage locations to split.
    records: Vec<PreferSplitRecord>,
}

impl Default for PreferSplitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PreferSplitManager {
    /// Construct an empty manager.
    pub fn new() -> Self {
        Self { records: Vec::new() }
    }

    /// Initialize with records and sort them. Faithful to `init` +
    /// `initialize`.
    pub fn init(&mut self, mut records: Vec<PreferSplitRecord>) {
        initialize(&mut records);
        self.records = records;
    }

    /// Number of split records.
    pub fn num_records(&self) -> usize {
        self.records.len()
    }

    /// Get all records.
    pub fn records(&self) -> &[PreferSplitRecord] {
        &self.records
    }

    /// Find the split record that applies to a varnode with the given storage
    /// details. Faithful to `findRecord` (prefersplit.cc). Returns None if no
    /// matching record.
    pub fn find_record(&self, space: AddressSpace, size: u32, offset: u64) -> Option<&PreferSplitRecord> {
        // Binary search for the matching record.
        let mut lo = 0usize;
        let mut hi = self.records.len();
        let search_space = space.space_id();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let rec = &self.records[mid];
            let rec_space = rec.storage_space.space_id();
            if rec_space < search_space
                || (rec_space == search_space && rec.storage_size > size)
                || (rec_space == search_space && rec.storage_size == size && rec.storage_offset < offset)
            {
                lo = mid + 1;
            } else if rec_space > search_space
                || (rec_space == search_space && rec.storage_size < size)
                || (rec_space == search_space && rec.storage_size == size && rec.storage_offset > offset)
            {
                hi = mid;
            } else {
                // Exact match.
                return Some(rec);
            }
        }
        None
    }

    /// The main split entry point. Faithful to `split` (prefersplit.cc). In
    /// the full Ghidra implementation, this iterates over all records and
    /// performs the actual varnode splitting via Funcdata op-editing. This is
    /// an L3 gap pending Funcdata integration.
    pub fn split(&mut self) {
        // L3 gap: requires Funcdata op-editing (splitRecord → splitVarnode →
        // testDefiningCopy/splitLoad/splitStore/etc.)
    }

    /// Split additional temporaries. Faithful to `splitAdditional`. L3 gap.
    pub fn split_additional(&mut self) {
        // L3 gap: requires Funcdata op-editing.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(offset: u64, space: AddressSpace, size: u32, split: i32) -> PreferSplitRecord {
        PreferSplitRecord::new(offset, space, size, split)
    }

    #[test]
    fn test_prefer_split_record_construction() {
        let r = make_record(0x100, AddressSpace::Register, 4, 2);
        assert_eq!(r.storage_offset, 0x100);
        assert_eq!(r.storage_space, AddressSpace::Register);
        assert_eq!(r.storage_size, 4);
        assert_eq!(r.splitoffset, 2);
    }

    #[test]
    fn test_prefer_split_record_ordering() {
        let r1 = make_record(0x100, AddressSpace::Register, 8, 4);
        let r2 = make_record(0x200, AddressSpace::Register, 4, 2);
        // Bigger sizes come first.
        assert!(r1.less_than(&r2));
        assert!(!r2.less_than(&r1));
    }

    #[test]
    fn test_prefer_split_record_ordering_offset() {
        let r1 = make_record(0x100, AddressSpace::Register, 4, 2);
        let r2 = make_record(0x200, AddressSpace::Register, 4, 2);
        assert!(r1.less_than(&r2));
    }

    #[test]
    fn test_initialize_sorts() {
        let mut records = vec![
            make_record(0x300, AddressSpace::Register, 4, 2),
            make_record(0x100, AddressSpace::Register, 8, 4),
            make_record(0x200, AddressSpace::Register, 4, 2),
        ];
        initialize(&mut records);
        // After sort: 8-byte at 0x100 first (bigger size), then 4-byte at 0x200,
        // then 4-byte at 0x300.
        assert_eq!(records[0].storage_offset, 0x100);
        assert_eq!(records[0].storage_size, 8);
        assert_eq!(records[1].storage_offset, 0x200);
        assert_eq!(records[2].storage_offset, 0x300);
    }

    #[test]
    fn test_split_instance_fillin_little_endian() {
        // 4-byte varnode at 0x100, split at 2 bytes → lo=0x100 (2 bytes),
        // hi=0x102 (2 bytes).
        let mut inst = SplitInstance::new(0x100, 4, 2);
        inst.fillin(false, true, true);
        assert_eq!(inst.lo_offset, Some(0x100));
        assert_eq!(inst.hi_offset, Some(0x102));
        assert_eq!(inst.lo_size(false), 2);
        assert_eq!(inst.hi_size(false), 2);
    }

    #[test]
    fn test_split_instance_fillin_big_endian() {
        // 4-byte varnode at 0x100, split at 2 bytes → lo is the last 2 bytes.
        let mut inst = SplitInstance::new(0x100, 4, 2);
        inst.fillin(true, true, true);
        assert_eq!(inst.lo_size(true), 2); // 4 - 2 = 2
        assert_eq!(inst.hi_size(true), 2);
    }

    #[test]
    fn test_split_instance_fillin_uneven() {
        // 8-byte varnode at 0x200, split at 3 bytes → lo=3 bytes, hi=5 bytes.
        let mut inst = SplitInstance::new(0x200, 8, 3);
        inst.fillin(false, true, true);
        assert_eq!(inst.lo_size(false), 3);
        assert_eq!(inst.hi_size(false), 5);
        assert_eq!(inst.lo_offset, Some(0x200));
        assert_eq!(inst.hi_offset, Some(0x203));
    }

    #[test]
    fn test_manager_init_and_find() {
        let mut mgr = PreferSplitManager::new();
        let records = vec![
            make_record(0x100, AddressSpace::Register, 8, 4),
            make_record(0x200, AddressSpace::Register, 4, 2),
            make_record(0x300, AddressSpace::Register, 4, 1),
        ];
        mgr.init(records);
        assert_eq!(mgr.num_records(), 3);
        // Find the 8-byte at 0x100.
        let rec = mgr.find_record(AddressSpace::Register, 8, 0x100);
        assert!(rec.is_some());
        assert_eq!(rec.unwrap().splitoffset, 4);
    }

    #[test]
    fn test_manager_find_not_found() {
        let mut mgr = PreferSplitManager::new();
        mgr.init(vec![make_record(0x100, AddressSpace::Register, 4, 2)]);
        assert!(mgr.find_record(AddressSpace::Register, 4, 0x999).is_none());
        assert!(mgr.find_record(AddressSpace::Register, 8, 0x100).is_none()); // wrong size
        assert!(mgr.find_record(AddressSpace::Ram, 4, 0x100).is_none()); // wrong space
    }

    #[test]
    fn test_manager_empty() {
        let mgr = PreferSplitManager::new();
        assert_eq!(mgr.num_records(), 0);
        assert!(mgr.find_record(AddressSpace::Register, 4, 0x100).is_none());
    }
}
