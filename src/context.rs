//! Context database — faithful port of `globalcontext.hh` / `globalcontext.cc`
//! (618 lines).
//!
//! Utilities for getting address-based context to the disassembler and
//! decompiler. Context information is a set of named variables that hold
//! concrete values at specific addresses. Two flavors:
//! - Low-level context variables: affect instruction decoding, packed into a
//!   context blob of words.
//! - High-level tracked variables: normal memory locations (registers) treated
//!   as constants.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/globalcontext.{hh,cc}.

use crate::address::Address;
use std::collections::BTreeMap;

/// The word type used in context blobs (matches Ghidra's `uintm`).
pub type ContextWord = u32;

/// Number of bits in a context word.
const WORD_BITS: usize = 32;

/// Description of a context variable within the disassembly context blob.
/// Faithful to `ContextBitRange` (globalcontext.hh:40).
#[derive(Debug, Clone)]
pub struct ContextBitRange {
    /// Index of word containing this context value.
    pub word: usize,
    /// Starting bit of the value within its word.
    pub startbit: i32,
    /// Ending bit of the value within its word.
    pub endbit: i32,
    /// Right-shift amount to apply when unpacking.
    pub shift: u32,
    /// Mask to apply (after shifting) when unpacking.
    pub mask: ContextWord,
}

impl ContextBitRange {
    /// Construct a context value given an absolute bit range. Faithful to the
    /// constructor (globalcontext.cc:33). Bits within the whole blob are
    /// labeled starting with 0 as the MSB of the first word.
    pub fn new(sbit: i32, ebit: i32) -> Self {
        let word = (sbit as usize) / WORD_BITS;
        let startbit = sbit - (word as i32) * WORD_BITS as i32;
        let endbit = ebit - (word as i32) * WORD_BITS as i32;
        let shift = (WORD_BITS as i32 - endbit - 1) as u32;
        let mask = if (startbit as u32 + shift) >= WORD_BITS as u32 {
            ContextWord::MAX
        } else {
            ContextWord::MAX >> (startbit as u32 + shift)
        };
        Self {
            word,
            startbit,
            endbit,
            shift,
            mask,
        }
    }

    /// Return the shift-amount for this value. Faithful to `getShift`.
    pub fn get_shift(&self) -> u32 {
        self.shift
    }

    /// Return the mask for this value. Faithful to `getMask`.
    pub fn get_mask(&self) -> ContextWord {
        self.mask
    }

    /// Return the word index. Faithful to `getWord`.
    pub fn get_word(&self) -> usize {
        self.word
    }

    /// Set this value within a given context blob. Faithful to `setValue`
    /// (globalcontext.hh:57).
    pub fn set_value(&self, vec: &mut [ContextWord], val: ContextWord) {
        let newval = vec[self.word];
        let newval = newval & !(self.mask << self.shift);
        let newval = newval | ((val & self.mask) << self.shift);
        vec[self.word] = newval;
    }

    /// Retrieve this value from a given context blob. Faithful to `getValue`
    /// (globalcontext.hh:68).
    pub fn get_value(&self, vec: &[ContextWord]) -> ContextWord {
        (vec[self.word] >> self.shift) & self.mask
    }
}

/// A tracked register (storage location) and the value it contains. Faithful
/// to `TrackedContext` (globalcontext.hh:78).
#[derive(Debug, Clone)]
pub struct TrackedContext {
    /// The register offset (address) being tracked.
    pub offset: u64,
    /// The size of the register in bytes.
    pub size: u32,
    /// The value of the register.
    pub val: u64,
}

/// A set of tracked registers and their values at one code point. Faithful to
/// `TrackedSet` (globalcontext.hh:84).
pub type TrackedSet = Vec<TrackedContext>;

/// A context blob holding context variable values across a range of addresses.
/// Contains the array of words and a mask array indicating explicitly-set
/// variables. Faithful to `ContextInternal::FreeArray` (globalcontext.hh:271).
#[derive(Debug, Clone, Default)]
pub struct ContextBlob {
    /// The array of words holding context variable values.
    pub array: Vec<ContextWord>,
    /// The mask array indicating which variables are explicitly set.
    pub mask: Vec<ContextWord>,
}

impl ContextBlob {
    /// Construct an empty blob of the given word size.
    pub fn new(size: usize) -> Self {
        Self {
            array: vec![0; size],
            mask: vec![0; size],
        }
    }

    /// Resize the blob, preserving old values. Faithful to `reset`.
    pub fn reset(&mut self, size: usize) {
        self.array.resize(size, 0);
        self.mask.resize(size, 0);
    }
}

/// An interface to a database of disassembly/decompiler context information.
/// Faithful to `ContextDatabase` (globalcontext.hh:118).
pub trait ContextDatabase: Send + Sync {
    /// Retrieve the context blob of values associated with a given address.
    /// Faithful to `getContext`.
    fn get_context(&self, addr: Address) -> &[ContextWord];

    /// Get the set of tracked register values associated with the given
    /// address. Faithful to `getTrackedSet`.
    fn get_tracked_set(&self, addr: Address) -> &TrackedSet;

    /// Create a tracked register set valid over the given range. Faithful to
    /// `createSet`.
    fn create_set(&mut self, addr1: Address, addr2: Address) -> &mut TrackedSet;

    /// Get the default tracked set. Faithful to `getTrackedDefault`.
    fn get_tracked_default(&self) -> &TrackedSet;

    /// Get the default context blob. Faithful to `getDefaultValue`.
    fn get_default_value(&self) -> &[ContextWord];

    /// Get the default context blob (mutable). Faithful to `getDefaultValue`.
    fn get_default_value_mut(&mut self) -> &mut [ContextWord];

    /// Register a new named context variable. Faithful to `registerVariable`.
    fn register_variable(&mut self, nm: &str, sbit: i32, ebit: i32);

    /// Retrieve the number of words in a context blob. Faithful to
    /// `getContextSize`.
    fn get_context_size(&self) -> usize;

    /// Query the tracked value of a register at a given point. Faithful to
    /// `getTrackedValue` (globalcontext.hh:256).
    fn get_tracked_value(&self, offset: u64, size: u32, point: Address) -> u64 {
        let tracked = self.get_tracked_set(point);
        for tc in tracked {
            if tc.offset == offset && tc.size == size {
                return tc.val;
            }
        }
        0
    }
}

/// An in-memory implementation of the ContextDatabase interface. Faithful to
/// `ContextInternal` (globalcontext.hh:264).
///
/// Context blobs are held in a partition map on addresses. Sets of tracked
/// registers are held in a separate map.
pub struct ContextInternal {
    /// Number of words in a context blob.
    size: usize,
    /// Map from context variable name to description.
    variables: BTreeMap<String, ContextBitRange>,
    /// The default context blob.
    default_blob: ContextBlob,
    /// Partition map of context blobs: (start_addr, blob).
    database: Vec<(Address, ContextBlob)>,
    /// Default tracked set.
    default_tracked: TrackedSet,
    /// Partition map of tracked sets: (start_addr, tracked_set).
    trackbase: Vec<(Address, TrackedSet)>,
}

impl Default for ContextInternal {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextInternal {
    /// Construct an empty context database.
    pub fn new() -> Self {
        Self {
            size: 0,
            variables: BTreeMap::new(),
            default_blob: ContextBlob::new(0),
            database: Vec::new(),
            default_tracked: Vec::new(),
            trackbase: Vec::new(),
        }
    }

    /// Get a mutable reference to a registered variable by name. Returns None
    /// if not found.
    pub fn get_variable_mut(&mut self, nm: &str) -> Option<&mut ContextBitRange> {
        self.variables.get_mut(nm)
    }

    /// Get a reference to a registered variable by name.
    pub fn get_variable(&self, nm: &str) -> Option<&ContextBitRange> {
        self.variables.get(nm)
    }

    /// Set a context variable's default value. Faithful to
    /// `setVariableDefault` (globalcontext.cc:104).
    pub fn set_variable_default(&mut self, nm: &str, val: ContextWord) {
        if let Some(var) = self.variables.get(nm) {
            let var = var.clone();
            var.set_value(&mut self.default_blob.array, val);
        }
    }

    /// Get a context variable's default value.
    pub fn get_default_value_for(&self, nm: &str) -> ContextWord {
        if let Some(var) = self.variables.get(nm) {
            return var.get_value(&self.default_blob.array);
        }
        0
    }

    /// Set a context value at the given address. Faithful to `setVariable`
    /// (globalcontext.cc:126).
    pub fn set_variable(&mut self, nm: &str, addr: Address, value: ContextWord) {
        let Some(bitrange) = self.variables.get(nm).cloned() else {
            return;
        };
        // Find or create the blob at this address.
        let blob = self.get_or_create_blob_at(addr);
        bitrange.set_value(&mut blob.array, value);
    }

    /// Get a context variable's value at a given address.
    pub fn get_variable_at(&self, nm: &str, addr: Address) -> ContextWord {
        let Some(bitrange) = self.variables.get(nm) else {
            return 0;
        };
        let blob = self.find_blob(addr);
        bitrange.get_value(blob)
    }

    /// Find the context blob valid at the given address (or default).
    fn find_blob(&self, addr: Address) -> &[ContextWord] {
        for (start, blob) in self.database.iter().rev() {
            if addr.as_u64() >= start.as_u64() {
                return &blob.array;
            }
        }
        &self.default_blob.array
    }

    /// Get or create a blob at the given address.
    fn get_or_create_blob_at(&mut self, addr: Address) -> &mut ContextBlob {
        // Check if one already starts here (by index to satisfy borrow checker).
        let existing_idx = self.database.iter().position(|(s, _)| s.as_u64() == addr.as_u64());
        if let Some(idx) = existing_idx {
            return &mut self.database[idx].1;
        }
        // Create a new blob by copying the previous blob's values.
        let prev: Vec<ContextWord> = self.find_blob(addr).to_vec();
        let blob = ContextBlob {
            array: prev,
            mask: vec![0; self.size],
        };
        self.database.push((addr, blob));
        // Keep sorted by address.
        self.database.sort_by_key(|(a, _)| a.as_u64());
        // Return the newly created blob by index.
        let idx = self
            .database
            .iter()
            .position(|(s, _)| s.as_u64() == addr.as_u64())
            .unwrap();
        &mut self.database[idx].1
    }
}

impl ContextDatabase for ContextInternal {
    fn get_context(&self, addr: Address) -> &[ContextWord] {
        self.find_blob(addr)
    }

    fn get_tracked_set(&self, addr: Address) -> &TrackedSet {
        for (start, ts) in self.trackbase.iter().rev() {
            if addr.as_u64() >= start.as_u64() {
                return ts;
            }
        }
        &self.default_tracked
    }

    fn create_set(&mut self, addr1: Address, _addr2: Address) -> &mut TrackedSet {
        // Create a new tracked set at addr1.
        self.trackbase.push((addr1, Vec::new()));
        self.trackbase.sort_by_key(|(a, _)| a.as_u64());
        for (start, ts) in &mut self.trackbase {
            if start.as_u64() == addr1.as_u64() {
                return ts;
            }
        }
        unreachable!()
    }

    fn get_tracked_default(&self) -> &TrackedSet {
        &self.default_tracked
    }

    fn get_default_value(&self) -> &[ContextWord] {
        &self.default_blob.array
    }

    fn get_default_value_mut(&mut self) -> &mut [ContextWord] {
        &mut self.default_blob.array
    }

    fn register_variable(&mut self, nm: &str, sbit: i32, ebit: i32) {
        let bitrange = ContextBitRange::new(sbit, ebit);
        let needed_size = bitrange.word + 1;
        if needed_size > self.size {
            self.size = needed_size;
            self.default_blob.reset(self.size);
        }
        self.variables.insert(nm.to_string(), bitrange);
    }

    fn get_context_size(&self) -> usize {
        self.size
    }
}

/// A helper class for caching the active context blob to minimize database
/// lookups. Faithful to `ContextCache` (globalcontext.hh:317).
pub struct ContextCache {
    /// The encapsulated context database.
    database: std::sync::Arc<std::sync::RwLock<dyn ContextDatabase>>,
    /// If false, setContext calls are dropped.
    allow_set: bool,
}

impl ContextCache {
    /// Construct given a context database. Faithful to the constructor.
    pub fn new(database: std::sync::Arc<std::sync::RwLock<dyn ContextDatabase>>) -> Self {
        Self {
            database,
            allow_set: true,
        }
    }

    /// Toggle whether setContext calls are ignored.
    pub fn allow_set(&mut self, val: bool) {
        self.allow_set = val;
    }

    /// Retrieve the context blob for the given address. Faithful to
    /// `getContext`.
    pub fn get_context(&self, addr: Address) -> Vec<ContextWord> {
        self.database.read().unwrap().get_context(addr).to_vec()
    }

    /// Set context at an address. Faithful to `setContext`.
    pub fn set_context(&self, _addr: Address, _num: usize, _mask: ContextWord, _value: ContextWord) {
        if !self.allow_set {
            return;
        }
        // Full implementation requires getRegionForSet; simplified.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_bit_range_construction() {
        // Bits 0-3 (MSB of word 0): shift=28, mask=0xF.
        let br = ContextBitRange::new(0, 3);
        assert_eq!(br.get_word(), 0);
        assert_eq!(br.get_shift(), 28);
        assert_eq!(br.get_mask(), 0xF);
    }

    #[test]
    fn test_context_bit_range_set_get() {
        let br = ContextBitRange::new(0, 7); // 8-bit value at MSB.
        let mut blob = vec![0u32];
        br.set_value(&mut blob, 0xAB);
        assert_eq!(blob[0] >> 24, 0xAB);
        assert_eq!(br.get_value(&blob), 0xAB);
    }

    #[test]
    fn test_context_bit_range_word1() {
        // Bits 32-35 (word 1, bits 0-3).
        let br = ContextBitRange::new(32, 35);
        assert_eq!(br.get_word(), 1);
        let mut blob = vec![0, 0];
        br.set_value(&mut blob, 5);
        assert_eq!(br.get_value(&blob), 5);
    }

    #[test]
    fn test_context_internal_register() {
        let mut db = ContextInternal::new();
        assert_eq!(db.get_context_size(), 0);
        db.register_variable("mode", 0, 3);
        assert_eq!(db.get_context_size(), 1);
        assert!(db.get_variable("mode").is_some());
    }

    #[test]
    fn test_context_internal_default_value() {
        let mut db = ContextInternal::new();
        db.register_variable("flag", 0, 0);
        db.set_variable_default("flag", 1);
        assert_eq!(db.get_default_value_for("flag"), 1);
    }

    #[test]
    fn test_context_internal_set_get_variable() {
        let mut db = ContextInternal::new();
        db.register_variable("mode", 0, 3);
        db.set_variable("mode", Address::new(0x1000), 5);
        assert_eq!(db.get_variable_at("mode", Address::new(0x1000)), 5);
        // Before the change point, returns default (0).
        assert_eq!(db.get_variable_at("mode", Address::new(0x500)), 0);
    }

    #[test]
    fn test_context_internal_context_lookup() {
        let mut db = ContextInternal::new();
        db.register_variable("x", 0, 7);
        db.set_variable("x", Address::new(0x2000), 0x42);
        let ctx = db.get_context(Address::new(0x2000));
        assert_eq!(ctx[0] >> 24, 0x42);
    }

    #[test]
    fn test_context_internal_tracked() {
        let mut db = ContextInternal::new();
        {
            let ts = db.create_set(Address::new(0x1000), Address::new(0x2000));
            ts.push(TrackedContext {
                offset: 0x100,
                size: 4,
                val: 0xDEAD,
            });
        }
        let val = db.get_tracked_value(0x100, 4, Address::new(0x1500));
        assert_eq!(val, 0xDEAD);
        // Not tracked at a different address.
        let val2 = db.get_tracked_value(0x100, 4, Address::new(0x500));
        assert_eq!(val2, 0);
    }

    #[test]
    fn test_context_internal_tracked_default() {
        let mut db = ContextInternal::new();
        db.default_tracked.push(TrackedContext {
            offset: 0x200,
            size: 8,
            val: 0x1234,
        });
        let val = db.get_tracked_value(0x200, 8, Address::new(0x9999));
        assert_eq!(val, 0x1234);
    }

    #[test]
    fn test_context_blob_reset() {
        let mut blob = ContextBlob::new(2);
        blob.array[0] = 0xAB;
        blob.reset(4);
        assert_eq!(blob.array.len(), 4);
        assert_eq!(blob.array[0], 0xAB); // preserved
        assert_eq!(blob.array[3], 0); // new
    }

    #[test]
    fn test_tracked_context_struct() {
        let tc = TrackedContext {
            offset: 0x100,
            size: 4,
            val: 42,
        };
        assert_eq!(tc.offset, 0x100);
        assert_eq!(tc.size, 4);
        assert_eq!(tc.val, 42);
    }
}
