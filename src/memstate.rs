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
    // Ghidra: memstate.cc:75 MemoryBank::new
    pub fn new(space: AddressSpace, word_size: usize, page_size: usize) -> Self {
        Self {
            word_size,
            page_size,
            space,
            words: BTreeMap::new(),
            bytes: BTreeMap::new(),
        }
    }

    // Ghidra: memstate.cc:75 MemoryBank::getWordSize
    pub fn get_word_size(&self) -> usize { self.word_size }
    // Ghidra: memstate.cc:75 MemoryBank::getPageSize
    pub fn get_page_size(&self) -> usize { self.page_size }

    // Ghidra: memstate.cc:182 MemoryBank::setValue
    /// Set the value of a (small) range of bytes.
    pub fn set_value(&mut self, offset: u64, size: usize, val: u64) {
        let bytes = Self::deconstruct_value(val, size);
        for (i, &b) in bytes.iter().enumerate() {
            self.bytes.insert(offset + i as u64, b);
        }
    }

    // Ghidra: memstate.cc:252 MemoryBank::getValue
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

    // Ghidra: memstate.cc:302 MemoryBank::setChunk
    /// Set values of an arbitrary sequence of bytes.
    pub fn set_chunk(&mut self, offset: u64, val: &[u8]) {
        for (i, &b) in val.iter().enumerate() {
            self.bytes.insert(offset + i as u64, b);
        }
    }

    // Ghidra: memstate.cc:335 MemoryBank::getChunk
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

    // Ghidra: memstate.cc:27 MemoryBank::constructValue
    /// Decode bytes to a value (little-endian).
    pub fn construct_value(ptr: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for (i, &b) in ptr.iter().enumerate() {
            val |= (b as u64) << (i * 8);
        }
        val
    }

    // Ghidra: memstate.cc:53 MemoryBank::deconstructValue
    /// Encode a value to bytes (little-endian).
    pub fn deconstruct_value(val: u64, size: usize) -> Vec<u8> {
        let mut result = vec![0u8; size];
        for i in 0..size {
            result[i] = ((val >> (i * 8)) & 0xff) as u8;
        }
        result
    }

    // Ghidra: memstate.cc:75 MemoryBank::insertWord
    /// Insert a word at an aligned location.
    pub fn insert_word(&mut self, addr: u64, val: u64) {
        self.words.insert(addr, val);
    }

    // Ghidra: memstate.cc:75 MemoryBank::findWord
    /// Find a word at an aligned location.
    pub fn find_word(&self, addr: u64) -> Option<u64> {
        self.words.get(&addr).copied()
    }

    // Ghidra: memstate.cc:75 MemoryBank::clear
    /// Clear all stored values.
    pub fn clear(&mut self) {
        self.words.clear();
        self.bytes.clear();
    }
}

/// A read-only MemoryBank backed by a byte buffer (simulates LoadImage).
/// Corresponds to Ghidra's `MemoryImage` (memstate.hh:90).
pub struct MemoryImage {
    /// The backing byte array
    pub data: Vec<u8>,
    /// Base address of the image
    pub base_addr: u64,
}

impl MemoryImage {
    // Ghidra: memstate.cc:407 MemoryImage::new
    pub fn new(base_addr: u64, data: Vec<u8>) -> Self {
        Self { data, base_addr }
    }

    // Ghidra: memstate.cc:407 MemoryImage::read
    /// Read bytes from the image at the given offset.
    pub fn read(&self, offset: u64, size: usize) -> Vec<u8> {
        let start = (offset.saturating_sub(self.base_addr)) as usize;
        if start >= self.data.len() {
            return vec![0u8; size];
        }
        let end = (start + size).min(self.data.len());
        let mut result = self.data[start..end].to_vec();
        result.resize(size, 0);
        result
    }

    // Ghidra: memstate.cc:407 MemoryImage::getValue
    /// Read a value from the image.
    pub fn get_value(&self, offset: u64, size: usize) -> u64 {
        let bytes = self.read(offset, size);
        MemoryBank::construct_value(&bytes)
    }

    // Ghidra: memstate.cc:407 MemoryImage::len
    /// Get the size of the image.
    pub fn len(&self) -> usize { self.data.len() }

    // Ghidra: memstate.cc:407 MemoryImage::isEmpty
    /// Check if the image is empty.
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
}

/// A copy-on-write overlay memory bank.
/// Corresponds to Ghidra's `MemoryPageOverlay` (memstate.hh:106).
pub struct MemoryPageOverlay {
    /// The underlying bank (or None for zero-initialized)
    pub underlie: Option<Box<MemoryBank>>,
    /// Overlayed pages: page_number → page data
    pub pages: BTreeMap<u64, Vec<u8>>,
    /// Page size
    pub page_size: usize,
}

impl MemoryPageOverlay {
    // Ghidra: memstate.cc:533 MemoryPageOverlay::new
    pub fn new(page_size: usize, underlie: Option<Box<MemoryBank>>) -> Self {
        Self { underlie, pages: BTreeMap::new(), page_size }
    }

    // Ghidra: memstate.cc:533 MemoryPageOverlay::write
    /// Write bytes to the overlay.
    pub fn write(&mut self, offset: u64, data: &[u8]) {
        let page_num = offset / self.page_size as u64;
        let page_off = (offset % self.page_size as u64) as usize;
        let page = self.pages.entry(page_num).or_insert_with(|| vec![0u8; self.page_size]);
        for (i, &b) in data.iter().enumerate() {
            if page_off + i < page.len() {
                page[page_off + i] = b;
            }
        }
    }

    // Ghidra: memstate.cc:533 MemoryPageOverlay::read
    /// Read bytes from the overlay.
    pub fn read(&self, offset: u64, size: usize) -> Vec<u8> {
        let page_num = offset / self.page_size as u64;
        let page_off = (offset % self.page_size as u64) as usize;
        let mut result = vec![0u8; size];
        if let Some(page) = self.pages.get(&page_num) {
            for i in 0..size {
                if page_off + i < page.len() {
                    result[i] = page[page_off + i];
                }
            }
        } else if let Some(ref under) = self.underlie {
            // Fall through to underlying bank.
            for i in 0..size {
                result[i] = under.get_chunk(offset + i as u64, 1)[0];
            }
        }
        result
    }

    // Ghidra: memstate.cc:533 MemoryPageOverlay::getValue
    /// Read a value from the overlay.
    pub fn get_value(&self, offset: u64, size: usize) -> u64 {
        let bytes = self.read(offset, size);
        MemoryBank::construct_value(&bytes)
    }

    // Ghidra: memstate.cc:533 MemoryPageOverlay::isPageOverlayed
    /// Check if a page is overlayed.
    pub fn is_page_overlayed(&self, page_num: u64) -> bool {
        self.pages.contains_key(&page_num)
    }

    // Ghidra: memstate.cc:533 MemoryPageOverlay::numPages
    /// Get the number of overlayed pages.
    pub fn num_pages(&self) -> usize { self.pages.len() }
}

/// Manages memory banks across address spaces.
/// Corresponds to Ghidra's `MemState`.
pub struct MemState {
    /// Memory banks by address space name
    pub banks: BTreeMap<String, MemoryBank>,
}

impl MemState {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new() -> Self {
        Self { banks: BTreeMap::new() }
    }

    // RUGRA-GLUE: set_bank (no Ghidra counterpart found)
    /// Register a memory bank for an address space.
    pub fn set_bank(&mut self, space_name: String, bank: MemoryBank) {
        self.banks.insert(space_name, bank);
    }

    // RUGRA-GLUE: get_bank (no Ghidra counterpart found)
    /// Get a memory bank by space name.
    pub fn get_bank(&self, space_name: &str) -> Option<&MemoryBank> {
        self.banks.get(space_name)
    }

    // RUGRA-GLUE: get_bank_mut (no Ghidra counterpart found)
    /// Get a mutable memory bank by space name.
    pub fn get_bank_mut(&mut self, space_name: &str) -> Option<&mut MemoryBank> {
        self.banks.get_mut(space_name)
    }

    // RUGRA-GLUE: set_value (no Ghidra counterpart found)
    /// Set a value in a specific address space.
    /// Faithful to Ghidra MemState::setValue (memstate.cc:652).
    pub fn set_value(&mut self, space_name: &str, offset: u64, size: usize, val: u64) {
        if let Some(bank) = self.banks.get_mut(space_name) {
            bank.set_value(offset, size, val);
        }
    }

    // RUGRA-GLUE: get_value (no Ghidra counterpart found)
    /// Get a value from a specific address space.
    /// Faithful to Ghidra MemState::getValue (memstate.cc:668).
    pub fn get_value(&self, space_name: &str, offset: u64, size: usize) -> Option<u64> {
        self.banks.get(space_name).map(|bank| bank.get_value(offset, size))
    }

    // RUGRA-GLUE: set_chunk (no Ghidra counterpart found)
    /// Write a chunk of bytes to a specific address space.
    /// Faithful to Ghidra MemState::setChunk (memstate.cc:729).
    pub fn set_chunk(&mut self, space_name: &str, offset: u64, val: &[u8]) {
        if let Some(bank) = self.banks.get_mut(space_name) {
            bank.set_chunk(offset, val);
        }
    }

    // RUGRA-GLUE: get_chunk (no Ghidra counterpart found)
    /// Read a chunk of bytes from a specific address space.
    /// Faithful to Ghidra MemState::getChunk (memstate.cc:712).
    pub fn get_chunk(&self, space_name: &str, offset: u64, size: usize) -> Vec<u8> {
        self.banks.get(space_name)
            .map(|bank| bank.get_chunk(offset, size))
            .unwrap_or_default()
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

    #[test]
    fn test_memory_image() {
        let img = MemoryImage::new(0x1000, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(img.get_value(0x1000, 4), 0x04030201);
        assert_eq!(img.get_value(0x1004, 1), 0x05);
        // Out of bounds returns zero
        assert_eq!(img.get_value(0x2000, 2), 0);
    }

    #[test]
    fn test_page_overlay_write_read() {
        let mut overlay = MemoryPageOverlay::new(16, None);
        overlay.write(0, &[0xaa, 0xbb]);
        assert_eq!(overlay.read(0, 2), vec![0xaa, 0xbb]);
        assert!(overlay.is_page_overlayed(0));
        // Unwritten page returns zero.
        assert_eq!(overlay.read(100, 2), vec![0x00, 0x00]);
    }

    #[test]
    fn test_page_overlay_with_underlie() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 1, 16);
        bank.set_value(0, 4, 0xdeadbeef);
        let mut overlay = MemoryPageOverlay::new(16, Some(Box::new(bank)));
        // Read from underlie when not overlayed.
        assert_eq!(overlay.get_value(0, 4), 0xdeadbeef);
        // Overlay a write.
        overlay.write(0, &[0x11]);
        assert_eq!(overlay.read(0, 1), vec![0x11]);
    }

    #[test]
    fn test_mem_state_value_ops() {
        let mut state = MemState::new();
        let bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        state.set_bank("ram".into(), bank);
        state.set_value("ram", 0x100, 4, 0x12345678);
        assert_eq!(state.get_value("ram", 0x100, 4), Some(0x12345678));
        assert_eq!(state.get_value("ram", 0x100, 2), Some(0x5678));
    }

    #[test]
    fn test_mem_state_chunk_ops() {
        let mut state = MemState::new();
        let bank = MemoryBank::new(AddressSpace::Ram, 1, 4096);
        state.set_bank("ram".into(), bank);
        state.set_chunk("ram", 0x200, &[0xaa, 0xbb, 0xcc, 0xdd]);
        let chunk = state.get_chunk("ram", 0x200, 4);
        assert_eq!(chunk, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }
}
