//! Memory state: MemoryBank for emulation and LOAD/STORE analysis.
//!
//! Corresponds to Ghidra's `memstate.hh` / `memstate.cc` (946 lines).
//!
//! MemoryBank provides byte-level read/write access to an address space,
//! with word and page abstractions. Used by the emulator for constant
//! propagation and jump-table analysis.
//!
//! Key classes:
//! - `MemoryBank`: base class for memory storage in a single address space
//! - `MemoryImage`: read-only bank backed by a LoadImage
//! - `MemoryPageOverlay`: copy-on-write overlay bank
//! - `MemoryHashOverlay`: hash-table-based overlay
//! - `MemState`: manages all memory banks across address spaces
//!
//! # Status
//! Core MemoryBank with value get/set and constructValue/deconstructValue.
//! LoadImage-backed and overlay banks are deferred.

use std::collections::BTreeMap;
use crate::space::AddressSpace;

/// Memory storage/state for a single AddressSpace.
/// Corresponds to Ghidra's `MemoryBank` (memstate.hh:38).
pub struct MemoryBank {
    /// Number of bytes in an aligned word access
    pub word_size: usize,
    /// Number of bytes in an aligned page access
    pub page_size: usize,
    /// The address space associated with this memory
    pub space: AddressSpace,
    /// Word-aligned storage: offset → value
    words: BTreeMap<u64, u64>,
    /// Byte-level storage for non-word-aligned data
    bytes: BTreeMap<u64, u8>,
}

impl MemoryBank {
    pub fn new(space: AddressSpace, word_size: usize, page_size: usize) -> Self {
        Self {
            word_size,
            page_size,
            space,
            words: BTreeMap::new(),
            bytes: BTreeMap::new(),
        }
    }

    pub fn get_word_size(&self) -> usize { self.word_size }
    pub fn get_page_size(&self) -> usize { self.page_size }

    /// Set the value of a (small) range of bytes.
    pub fn set_value(&mut self, offset: u64, size: usize, val: u64) {
        let bytes = Self::deconstruct_value(val, size);
        for (i, &b) in bytes.iter().enumerate() {
            self.bytes.insert(offset + i as u64, b);
        }
    }

    /// Retrieve the value encoded in a (small) range of bytes.
    pub fn get_value(&self, offset: u64, size: usize) -> u64 {
        let mut buf = vec![0u8; size];
        for i in 0..size {
            if let Some(&b) = self.bytes.get(&(offset + i as u64)) {
                buf[i] = b;
            }
        }
        Self::construct_value(&buf)
    }

    /// Set values of an arbitrary sequence of bytes.
    pub fn set_chunk(&mut self, offset: u64, val: &[u8]) {
        for (i, &b) in val.iter().enumerate() {
            self.bytes.insert(offset + i as u64, b);
        }
    }

    /// Retrieve an arbitrary sequence of bytes.
    pub fn get_chunk(&self, offset: u64, size: usize) -> Vec<u8> {
        let mut result = vec![0u8; size];
        for i in 0..size {
            if let Some(&b) = self.bytes.get(&(offset + i as u64)) {
                result[i] = b;
            }
        }
        result
    }

    /// Decode bytes to a value (little-endian).
    pub fn construct_value(ptr: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for (i, &b) in ptr.iter().enumerate() {
            val |= (b as u64) << (i * 8);
        }
        val
    }

    /// Encode a value to bytes (little-endian).
    pub fn deconstruct_value(val: u64, size: usize) -> Vec<u8> {
        let mut result = vec![0u8; size];
        for i in 0..size {
            result[i] = ((val >> (i * 8)) & 0xff) as u8;
        }
        result
    }
}

/// Manages memory banks across address spaces.
/// Corresponds to Ghidra's `MemState`.
pub struct MemState {
    /// Memory banks by address space name
    pub banks: BTreeMap<String, MemoryBank>,
}

impl MemState {
    pub fn new() -> Self {
        Self { banks: BTreeMap::new() }
    }

    /// Register a memory bank for an address space.
    pub fn set_bank(&mut self, space_name: String, bank: MemoryBank) {
        self.banks.insert(space_name, bank);
    }

    /// Get a memory bank by space name.
    pub fn get_bank(&self, space_name: &str) -> Option<&MemoryBank> {
        self.banks.get(space_name)
    }

    /// Get a mutable memory bank by space name.
    pub fn get_bank_mut(&mut self, space_name: &str) -> Option<&mut MemoryBank> {
        self.banks.get_mut(space_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_deconstruct() {
        let val = 0x12345678u64;
        let bytes = MemoryBank::deconstruct_value(val, 4);
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
        let val2 = MemoryBank::construct_value(&bytes);
        assert_eq!(val2, val);
    }

    #[test]
    fn test_set_get_value() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        bank.set_value(100, 4, 0xdeadbeef);
        assert_eq!(bank.get_value(100, 4), 0xdeadbeef);
    }

    #[test]
    fn test_set_get_chunk() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 1, 4096);
        bank.set_chunk(200, &[1, 2, 3, 4, 5]);
        let chunk = bank.get_chunk(200, 5);
        assert_eq!(chunk, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_mem_state() {
        let mut state = MemState::new();
        let bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        state.set_bank("ram".into(), bank);
        assert!(state.get_bank("ram").is_some());
        assert!(state.get_bank("nonexistent").is_none());
    }
}
