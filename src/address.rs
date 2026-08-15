//! Address representation and manipulation
//!
//! This module corresponds to Ghidra's `address.hh` and provides core address
//! types used throughout the decompiler.
//!
//! # Core Types
//!
//! - [`Address`] - A memory address in a specific address space
//! - [`SeqNum`] - Sequence number (address + order for P-code ops)
//! - [`Range`] - An address range (first, last)
//! - [`RangeList`] - A collection of non-overlapping address ranges

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Memory address type
///
/// Represents a virtual memory address in the target binary.
/// Internally stored as u64 to support 64-bit architectures.
///
/// Corresponds to Ghidra's `Address` class in `address.hh`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address(u64);

impl Address {
    /// Create a new address
    // RUGRA-GLUE: Scalar-address constructor; Ghidra also requires an AddrSpace, which this representation omits.
    pub const fn new(addr: u64) -> Self {
        Address(addr)
    }

    /// Get the raw address value
    // Ghidra: address.hh:329 Address::getOffset
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    // Ghidra: address.cc:91 Address::offset
    /// Add an offset to the address
    pub fn offset(&self, offset: i64) -> Self {
        Address((self.0 as i64 + offset) as u64)
    }

    // Ghidra: address.cc:153 Address::overlap
    /// If `self + skip` falls in the range `[op, op+size)`, return the
    /// offset of `self+skip` relative to `op`. Otherwise return -1.
    /// Faithful to `Address::overlap` (address.cc:153-165).
    /// Rugra's single-space model skips the `base != op.base` check.
    pub fn overlap(&self, skip: i64, op: Address, size: i32) -> i32 {
        let dist = self.0.wrapping_add(skip as u64).wrapping_sub(op.0);
        if dist >= size as u64 {
            return -1;
        }
        dist as i32
    }

    // Ghidra: address.cc:91 Address::isNull
    /// Check if address is null (0x0)
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    // Ghidra: address.cc:91 Address::isAligned
    /// Check if address is aligned to the given boundary
    pub fn is_aligned(&self, alignment: u64) -> bool {
        self.0 % alignment == 0
    }

    // Ghidra: address.cc:91 Address::next
    /// Get the next address
    pub fn next(&self) -> Self {
        Address(self.0.wrapping_add(1))
    }

    // Ghidra: address.cc:91 Address::prev
    /// Get the previous address
    pub fn prev(&self) -> Self {
        Address(self.0.wrapping_sub(1))
    }
}

impl fmt::Display for Address {
    // Ghidra: address.cc:91 Address::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl fmt::LowerHex for Address {
    // Ghidra: address.cc:91 Address::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl fmt::UpperHex for Address {
    // Ghidra: address.cc:91 Address::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl From<u64> for Address {
    // Ghidra: address.cc:91 Address::from
    fn from(addr: u64) -> Self {
        Address(addr)
    }
}

impl From<Address> for u64 {
    // Ghidra: address.cc:91 Address::from
    fn from(addr: Address) -> Self {
        addr.0
    }
}

/// Sequence number for P-code operations within a single instruction
///
/// When a machine instruction translates to multiple P-code ops,
/// they are numbered sequentially using SeqNum.
///
/// Corresponds to Ghidra's `SeqNum` class in `address.hh`
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SeqNum {
    /// Address of the original machine instruction
    pub addr: Address,
    /// Immutable creation identity (`uniq` / `time` in Ghidra).
    pub time: u32,
    /// Mutable execution order within the containing basic block.
    pub order: u32,
}

impl SeqNum {
    // Ghidra: address.hh:130 SeqNum::SeqNum(const Address&,uintm)
    /// Create a sequence number with immutable `time` identity.
    ///
    /// Ghidra leaves `order` unset until block insertion. Rust initializes it
    /// to `time`, preserving deterministic pre-insertion behavior without
    /// conflating the fields after `set_order` is called.
    pub fn new(addr: Address, time: u32) -> Self {
        SeqNum {
            addr,
            time,
            order: time,
        }
    }

    // RUGRA-GLUE: convenience constructor for the next immutable creation id;
    // Ghidra increments PcodeOpBank::uniqid inline in op.cc:944.
    /// Get the next creation identity at the same address.
    pub fn next(&self) -> Self {
        SeqNum::new(self.addr, self.time + 1)
    }

    // Ghidra: address.hh:136 SeqNum::getAddr
    /// Get the address
    pub fn get_addr(&self) -> Address {
        self.addr
    }

    // Ghidra: address.hh:148 SeqNum::operator==
    /// Test Ghidra's time-only sequence identity.
    pub fn same_identity(&self, other: &Self) -> bool {
        self.time == other.time
    }

    // Ghidra: address.hh:139 SeqNum::getTime
    /// Get the immutable creation identity.
    pub fn get_time(&self) -> u32 {
        self.time
    }

    // Ghidra: address.hh:142 SeqNum::getOrder
    /// Get the mutable execution order within a basic block.
    pub fn get_order(&self) -> u32 {
        self.order
    }

    // Ghidra: address.hh:145 SeqNum::setOrder
    /// Set the execution order without changing this sequence's identity.
    pub fn set_order(&mut self, order: u32) {
        self.order = order;
    }

    // Ghidra: address.cc:69 SeqNum::decode
    /// Decode from string format "addr:order"
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let addr = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).ok()?;
        let time = parts[1].parse().ok()?;
        Some(SeqNum::new(Address::new(addr), time))
    }

    // Ghidra: address.cc:60 SeqNum::encode
    /// Encode to string format "addr:order"
    pub fn encode(&self) -> String {
        format!("{}:{}", self.addr, self.time)
    }
}

impl PartialEq for SeqNum {
    // RUGRA-GLUE: Rust Eq must agree with Ord for BTree/Hash keys. Ghidra's
    // operator== is time-only; callers needing that semantic use
    // `same_identity`, while ordered keys use `(Address,time)` as operator<.
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.time == other.time
    }
}

impl Eq for SeqNum {}

impl PartialOrd for SeqNum {
    // Ghidra: address.hh:154 SeqNum::operator<
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeqNum {
    // Ghidra: address.hh:154 SeqNum::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.addr
            .cmp(&other.addr)
            .then_with(|| self.time.cmp(&other.time))
    }
}

impl Hash for SeqNum {
    // RUGRA-GLUE: Rust Hash must use the same immutable identity as Eq/Ord;
    // Ghidra's SeqNum keys are ordered by address.hh:154 operator<.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.time.hash(state);
    }
}

impl fmt::Display for SeqNum {
    // Ghidra: address.cc:32 operator<<(ostream&,const SeqNum&)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.time)
    }
}

/// Address range (inclusive first and last addresses)
///
/// Corresponds to Ghidra's `Range` class in `address.hh`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// First address in the range (inclusive)
    first: Address,
    /// Last address in the range (inclusive)
    last: Address,
}

impl Range {
    // Ghidra: address.cc:236 Range::new
    /// Create a new range
    ///
    /// Returns `None` if first > last
    pub fn new(first: Address, last: Address) -> Option<Self> {
        if first.as_u64() <= last.as_u64() {
            Some(Range { first, last })
        } else {
            None
        }
    }

    // Ghidra: address.cc:236 Range::getFirst
    /// Get the first address
    pub fn get_first(&self) -> Address {
        self.first
    }

    // Ghidra: address.cc:236 Range::getLast
    /// Get the last address
    pub fn get_last(&self) -> Address {
        self.last
    }

    // Ghidra: address.cc:236 Range::getFirstAddr
    /// Get the first address (Ghidra naming)
    pub fn get_first_addr(&self) -> Address {
        self.first
    }

    // Ghidra: address.cc:236 Range::getLastAddr
    /// Get the last address (Ghidra naming)
    pub fn get_last_addr(&self) -> Address {
        self.last
    }

    // Ghidra: address.cc:265 Range::getLastAddrOpen
    /// Get the last address + 1 (open end)
    pub fn get_last_addr_open(&self) -> Address {
        self.last.next()
    }

    // Ghidra: address.cc:236 Range::contains
    /// Check if an address is contained in this range
    pub fn contains(&self, addr: Address) -> bool {
        addr.as_u64() >= self.first.as_u64() && addr.as_u64() <= self.last.as_u64()
    }

    // Ghidra: address.cc:236 Range::size
    /// Get the size of the range in bytes
    pub fn size(&self) -> u64 {
        self.last.as_u64().saturating_sub(self.first.as_u64()).saturating_add(1)
    }

    // Ghidra: address.cc:236 Range::overlaps
    /// Check if this range overlaps with another
    pub fn overlaps(&self, other: &Range) -> bool {
        self.first.as_u64() <= other.last.as_u64()
            && other.first.as_u64() <= self.last.as_u64()
    }

    // Ghidra: address.cc:236 Range::isAdjacent
    /// Check if this range is adjacent to another
    pub fn is_adjacent(&self, other: &Range) -> bool {
        self.last.as_u64().saturating_add(1) == other.first.as_u64()
            || other.last.as_u64().saturating_add(1) == self.first.as_u64()
    }

    // Ghidra: address.cc:283 Range::printBounds
    /// Print bounds (for debugging)
    pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.first, self.last)
    }

    // Ghidra: address.cc:304 Range::decode
    /// Decode from string format "first-last"
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return None;
        }
        let first = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).ok()?;
        let last = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok()?;
        Range::new(Address::new(first), Address::new(last))
    }

    // Ghidra: address.cc:316 Range::decodeFromAttributes
    /// Decode from attributes (XML-style)
    pub fn decode_from_attributes(first: &str, last: &str) -> Option<Self> {
        let first_addr = u64::from_str_radix(first.trim_start_matches("0x"), 16).ok()?;
        let last_addr = u64::from_str_radix(last.trim_start_matches("0x"), 16).ok()?;
        Range::new(Address::new(first_addr), Address::new(last_addr))
    }

    // Ghidra: address.cc:292 Range::encode
    /// Encode to string format "first-last"
    pub fn encode(&self) -> String {
        format!("{:x}-{:x}", self.first.as_u64(), self.last.as_u64())
    }
}

impl fmt::Display for Range {
    // Ghidra: address.cc:236 Range::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.print_bounds(f)
    }
}

/// Properties associated with a range
///
/// Corresponds to Ghidra's `RangeProperties` in address.hh
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProperties {
    /// Name of the address space containing the range. For a register form,
    /// this temporarily holds the register name until an `AddrSpaceManager`
    /// is available.
    pub space_name: String,
    /// Offset of the first byte in the range.
    pub first: u64,
    /// Offset of the last byte in the range.
    pub last: u64,
    /// Whether a `name` attribute specified a register.
    pub is_register: bool,
    /// Whether the end of the range was explicitly specified.
    pub seen_last: bool,
}

impl RangeProperties {
    // Ghidra: address.hh:223 RangeProperties::RangeProperties(void)
    /// Construct empty, partially parsed range properties.
    pub fn new() -> Self {
        RangeProperties {
            space_name: String::new(),
            first: 0,
            last: 0,
            is_register: false,
            seen_last: false,
        }
    }

    // Ghidra: address.cc:354 RangeProperties::decode
    /// Decode a `<range>` or `<register>` element into this partial state.
    ///
    /// Fields are deliberately not reset before decoding. Recognized
    /// attributes mutate the object in source order, and an error does not
    /// roll back earlier mutations, matching Ghidra's in-place decode.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> anyhow::Result<()> {
        let elem_id = decoder.open_element();
        if elem_id != 12 && elem_id != 14 {
            anyhow::bail!("Expecting <range> or <register> element");
        }
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            if attrib_id == 20 {
                self.space_name = decoder.read_string();
            } else if attrib_id == 27 {
                self.first = decoder.read_unsigned_integer();
            } else if attrib_id == 28 {
                self.last = decoder.read_unsigned_integer();
                self.seen_last = true;
            } else if attrib_id == 14 {
                self.space_name = decoder.read_string();
                self.is_register = true;
            }
        }
        decoder.close_element(elem_id);
        Ok(())
    }
}

impl Default for RangeProperties {
    // Ghidra: address.hh:223 RangeProperties::RangeProperties(void)
    fn default() -> Self {
        RangeProperties::new()
    }
}

/// List of non-overlapping address ranges
///
/// Corresponds to Ghidra's `RangeList` class in `address.hh`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeList {
    /// Sorted list of non-overlapping ranges
    ranges: Vec<Range>,
}

impl RangeList {
    // Ghidra: address.hh:174 RangeList::new
    /// Create a new empty range list
    pub fn new() -> Self {
        RangeList { ranges: Vec::new() }
    }

    // Ghidra: address.cc:383 RangeList::insertRange
    /// Insert a range into the list, merging overlapping ranges
    pub fn insert_range(&mut self, new_range: Range) {
        if self.ranges.is_empty() {
            self.ranges.push(new_range);
            return;
        }

        let mut merged = new_range;
        let mut to_remove = Vec::new();

        for (i, existing) in self.ranges.iter().enumerate() {
            if merged.overlaps(existing) || merged.is_adjacent(existing) {
                // Merge the ranges
                let first = std::cmp::min(merged.first.as_u64(), existing.first.as_u64());
                let last = std::cmp::max(merged.last.as_u64(), existing.last.as_u64());
                merged = Range {
                    first: Address::new(first),
                    last: Address::new(last),
                };
                to_remove.push(i);
            }
        }

        // Remove merged ranges (in reverse order to maintain indices)
        for &i in to_remove.iter().rev() {
            self.ranges.remove(i);
        }

        // Insert merged range in sorted position
        let insert_pos = self.ranges
            .binary_search_by_key(&merged.first.as_u64(), |r| r.first.as_u64())
            .unwrap_or_else(|pos| pos);
        self.ranges.insert(insert_pos, merged);
    }

    // Ghidra: address.cc:417 RangeList::removeRange
    /// Remove a range from the list
    pub fn remove_range(&mut self, to_remove: Range) {
        let mut new_ranges = Vec::new();

        for existing in &self.ranges {
            if !existing.overlaps(&to_remove) {
                // No overlap, keep the range
                new_ranges.push(*existing);
            } else {
                // Handle partial overlap
                if existing.first.as_u64() < to_remove.first.as_u64() {
                    // Keep the part before the removed range
                    if let Some(range) = Range::new(
                        existing.first,
                        Address::new(to_remove.first.as_u64().saturating_sub(1))
                    ) {
                        new_ranges.push(range);
                    }
                }
                if existing.last.as_u64() > to_remove.last.as_u64() {
                    // Keep the part after the removed range
                    if let Some(range) = Range::new(
                        Address::new(to_remove.last.as_u64().saturating_add(1)),
                        existing.last
                    ) {
                        new_ranges.push(range);
                    }
                }
            }
        }

        self.ranges = new_ranges;
    }

    // Ghidra: address.cc:468 RangeList::inRange
    /// Check if an address is in any range in the list
    pub fn in_range(&self, addr: Address) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }

    // Ghidra: address.hh:174 RangeList::numRanges
    /// Get the number of ranges in the list
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    // Ghidra: address.hh:174 RangeList::empty
    /// Check if the list is empty
    pub fn empty(&self) -> bool {
        self.ranges.is_empty()
    }

    // Ghidra: address.hh:174 RangeList::ranges
    /// Get all ranges
    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }

    // Ghidra: address.hh:174 RangeList::begin
    /// Get iterator to beginning
    pub fn begin(&self) -> std::slice::Iter<'_, Range> {
        self.ranges.iter()
    }

    // Ghidra: address.hh:174 RangeList::end
    /// Get iterator to end
    pub fn end(&self) -> std::slice::Iter<'_, Range> {
        self.ranges.iter()
    }

    // Ghidra: address.cc:451 RangeList::merge
    /// Merge another RangeList into this one
    pub fn merge(&mut self, other: &RangeList) {
        for range in &other.ranges {
            self.insert_range(*range);
        }
    }

    // Ghidra: address.hh:174 RangeList::clear
    /// Clear all ranges
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    // Ghidra: address.cc:512 RangeList::longestFit
    /// Find the longest fit for an address
    pub fn longest_fit(&self, addr: Address) -> Option<&Range> {
        self.ranges.iter()
            .filter(|r| r.contains(addr))
            .max_by_key(|r| r.size())
    }

    // Ghidra: address.cc:588 RangeList::printBounds
    /// Print bounds of all ranges
    pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, range) in self.ranges.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            range.print_bounds(f)?;
        }
        write!(f, "]")
    }

    // Ghidra: address.cc:618 RangeList::decode
    /// Decode from string format (comma-separated ranges)
    pub fn decode(s: &str) -> Option<Self> {
        let mut list = RangeList::new();
        if s.is_empty() {
            return Some(list);
        }
        for range_str in s.split(',') {
            let range = Range::decode(range_str.trim())?;
            list.insert_range(range);
        }
        Some(list)
    }

    // Ghidra: address.cc:604 RangeList::encode
    /// Encode to string format (comma-separated ranges)
    pub fn encode(&self) -> String {
        self.ranges
            .iter()
            .map(|r| r.encode())
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Default for RangeList {
    // Ghidra: address.hh:174 RangeList::default
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RangeList {
    // Ghidra: address.hh:174 RangeList::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.print_bounds(f)
    }
}

// --- Bit-level helpers (faithful to address.cc/address.hh:576-590) ---

// Ghidra: address.hh:174 RangeList::signbitNegative
/// Return true if the sign-bit of the sized value is set (negative).
/// Faithful to `signbit_negative` (address.cc:641-647).
pub fn signbit_negative(val: u64, size: usize) -> bool {
    if size == 0 {
        return false;
    }
    let mask: u64 = 0x80u64 << (8 * (size - 1));
    (val & mask) != 0
}

// Ghidra: address.hh:174 RangeList::calcMask
/// Calculate an all-ones mask for the given byte size.
/// Faithful to `calc_mask` (address.hh:577). Equivalent to the `calc_mask`
/// already present in ruleaction.rs; centralised here for reuse.
pub fn calc_mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

// Ghidra: address.hh:174 RangeList::countLeadingZeros
/// Count leading zero bits in a 64-bit value. Faithful to
/// `count_leading_zeros` (address.cc:773).
pub fn count_leading_zeros(val: u64) -> i32 {
    if val == 0 {
        return 64;
    }
    val.leading_zeros() as i32
}

// Ghidra: address.hh:174 RangeList::leastsigbitSet
/// Return the index of the least-significant set bit, or -1 if val==0.
/// Faithful to `leastsigbit_set` (address.cc:714). Uses trailing_zeros for
/// an exact equivalent.
pub fn leastsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        val.trailing_zeros() as i32
    }
}

// Ghidra: address.hh:174 RangeList::mostsigbitSet
/// Return the index of the most-significant set bit, or -1 if val==0.
/// Faithful to `mostsigbit_set` (address.cc:735).
pub fn mostsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        63 - val.leading_zeros() as i32
    }
}

// Ghidra: address.hh:174 RangeList::coveringmask
/// Return the mask covering all set bits of `val`. Faithful to
/// `coveringmask` (address.cc:760). For val==0 returns 0; otherwise returns
/// `(1 << (msb+1)) - 1`, i.e. all bits from the least significant up to and
/// including the most-significant set bit.
pub fn coveringmask(val: u64) -> u64 {
    if val == 0 {
        return 0;
    }
    let msb = mostsigbit_set(val);
    if msb >= 63 {
        u64::MAX
    } else {
        (1u64 << (msb + 1)) - 1
    }
}

// Ghidra: address.hh:174 RangeList::minimalmask
/// Return the minimal mask covering the set bits of `val` (alias for
/// `coveringmask`, matching Ghidra's `minimalmask` in jumptable.cc).
pub fn minimalmask(val: u64) -> u64 {
    coveringmask(val)
}

// Ghidra: address.hh:174 RangeList::functionalEquality
/// Determine if two Varnodes hold the same value (immediate level).
/// Faithful to Ghidra's `functionalEquality` (expression.cc:520-526), using
/// only the level-0 test (expression.cc:404-417): identical varnode pointer,
/// or identical constants. The deeper structural comparison
/// (functionalEqualityLevel) is deferred. Returns true if provably equal.
pub fn functional_equality(
    vn1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    vn2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> bool {
    // level-0: same pointer → 0
    if std::sync::Arc::ptr_eq(vn1, vn2) {
        return true;
    }
    let v1 = vn1.read().unwrap();
    let v2 = vn2.read().unwrap();
    if v1.get_size() != v2.get_size() {
        return false;
    }
    // both constants → equal?
    if v1.is_constant() && v2.is_constant() {
        return v1.get_offset() == v2.get_offset();
    }
    // otherwise cannot immediately prove equality
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coveringmask() {
        assert_eq!(coveringmask(0), 0);
        assert_eq!(coveringmask(1), 1);
        assert_eq!(coveringmask(0xFF), 0xFF);
        assert_eq!(coveringmask(0x100), 0x1FF);
        assert_eq!(coveringmask(0x80), 0xFF);
        assert_eq!(coveringmask(0x8000_0000_0000_0000), u64::MAX);
    }

    #[test]
    fn test_minimalmask() {
        assert_eq!(minimalmask(0), 0);
        assert_eq!(minimalmask(0xF), 0xF);
        assert_eq!(minimalmask(0x10), 0x1F);
    }

    #[test]
    fn test_address_creation() {
        let addr = Address::new(0x1000);
        assert_eq!(addr.as_u64(), 0x1000);
        assert!(!addr.is_null());
    }

    #[test]
    fn test_address_alignment() {
        let addr = Address::new(0x1000);
        assert!(addr.is_aligned(0x10));
        assert!(!addr.is_aligned(0x2000));
    }

    #[test]
    fn test_seqnum() {
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let next = seq.next();
        assert_eq!(next.addr, Address::new(0x1000));
        assert_eq!(next.time, 1);
        assert_eq!(next.order, 1);
    }

    #[test]
    fn test_seqnum_identity_ignores_mutable_order() {
        use std::collections::{BTreeSet, HashSet};

        let original = SeqNum::new(Address::new(0x1000), 7);
        let mut reordered = original;
        reordered.set_order(0xf000_0000);
        assert_eq!(original, reordered);
        assert_eq!(original.cmp(&reordered), std::cmp::Ordering::Equal);
        assert_eq!(BTreeSet::from([original]).get(&reordered), Some(&original));
        assert!(HashSet::from([original]).contains(&reordered));
    }

    #[test]
    fn test_range_creation() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();
        assert_eq!(range.get_first().as_u64(), 0x1000);
        assert_eq!(range.get_last().as_u64(), 0x2000);

        // Invalid range (first > last)
        assert!(Range::new(Address::new(0x2000), Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_range_contains() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();

        assert!(range.contains(Address::new(0x1000))); // First
        assert!(range.contains(Address::new(0x1500))); // Middle
        assert!(range.contains(Address::new(0x2000))); // Last
        assert!(!range.contains(Address::new(0x0FFF))); // Before
        assert!(!range.contains(Address::new(0x2001))); // After
    }

    #[test]
    fn test_range_list_insert() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        assert_eq!(list.num_ranges(), 1);

        // Non-overlapping range
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());
        assert_eq!(list.num_ranges(), 2);
    }

    #[test]
    fn test_range_list_merge() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x1500), Address::new(0x2500)).unwrap());

        // Should merge into one range
        assert_eq!(list.num_ranges(), 1);
        assert_eq!(list.ranges()[0].get_first().as_u64(), 0x1000);
        assert_eq!(list.ranges()[0].get_last().as_u64(), 0x2500);
    }

    #[test]
    fn test_seqnum_decode_encode() {
        let seq = SeqNum::new(Address::new(0x1000), 5);
        let encoded = seq.encode();
        let decoded = SeqNum::decode(&encoded).unwrap();
        assert_eq!(seq, decoded);
    }

    #[test]
    fn test_range_decode_encode() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();
        let encoded = range.encode();
        let decoded = Range::decode(&encoded).unwrap();
        assert_eq!(range.get_first(), decoded.get_first());
        assert_eq!(range.get_last(), decoded.get_last());
    }

    #[test]
    fn test_range_decode_from_attributes() {
        let range = Range::decode_from_attributes("0x1000", "0x2000").unwrap();
        assert_eq!(range.get_first().as_u64(), 0x1000);
        assert_eq!(range.get_last().as_u64(), 0x2000);
    }

    #[test]
    fn test_range_properties() {
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        use std::sync::{Arc, RwLock};

        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        {
            let mut ids = registry.write().unwrap();
            ids.register_element_with_id("range", 12);
            ids.register_attribute_with_id("name", 14);
            ids.register_attribute_with_id("space", 20);
            ids.register_attribute_with_id("first", 27);
            ids.register_attribute_with_id("last", 28);
            ids.register_attribute_with_id("unknown", 159);
        }
        let mut element = Element::new();
        element.set_name("range");
        element.add_attribute("name", "RAX");
        element.add_attribute("unknown", "ignored");
        element.add_attribute("space", "ram");
        element.add_attribute("first", "16");
        element.add_attribute("last", "32");
        let root = Arc::new(RwLock::new(element));
        let mut decoder = TreeDecoder::new(root, registry);
        let mut props = RangeProperties::new();

        props.decode(&mut decoder).unwrap();

        assert_eq!(props.space_name, "ram");
        assert_eq!(props.first, 16);
        assert_eq!(props.last, 32);
        assert!(props.is_register);
        assert!(props.seen_last);
    }

    #[test]
    fn test_range_properties_invalid_element_preserves_state() {
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        use std::sync::{Arc, RwLock};

        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        registry
            .write()
            .unwrap()
            .register_element_with_id("bogus", 77);
        let mut element = Element::new();
        element.set_name("bogus");
        let root = Arc::new(RwLock::new(element));
        let mut decoder = TreeDecoder::new(root, registry);
        let mut props = RangeProperties {
            space_name: "stack".to_string(),
            first: 4,
            last: 9,
            is_register: true,
            seen_last: true,
        };

        let error = props.decode(&mut decoder).unwrap_err();

        assert_eq!(error.to_string(), "Expecting <range> or <register> element");
        assert_eq!(props.space_name, "stack");
        assert_eq!(props.first, 4);
        assert_eq!(props.last, 9);
        assert!(props.is_register);
        assert!(props.seen_last);
    }

    #[test]
    fn test_range_list_decode_encode() {
        let mut list = RangeList::new();
        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());

        let encoded = list.encode();
        let decoded = RangeList::decode(&encoded).unwrap();
        assert_eq!(list.num_ranges(), decoded.num_ranges());
    }

    #[test]
    fn test_range_list_in_range() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());

        assert!(list.in_range(Address::new(0x1500)));
        assert!(list.in_range(Address::new(0x3500)));
        assert!(!list.in_range(Address::new(0x2500)));
    }

    #[test]
    fn test_signbit_negative() {
        // size 1: sign bit is bit 7 (0x80).
        assert!(signbit_negative(0x80, 1));
        assert!(signbit_negative(0xff, 1));
        assert!(!signbit_negative(0x7f, 1));
        assert!(!signbit_negative(0x00, 1));
        // size 4: sign bit is bit 31 (0x80000000).
        assert!(signbit_negative(0x80000000, 4));
        assert!(!signbit_negative(0x7fffffff, 4));
    }

    #[test]
    fn test_calc_mask() {
        assert_eq!(calc_mask(0), 0);
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(2), 0xffff);
        assert_eq!(calc_mask(4), 0xffffffff);
        assert_eq!(calc_mask(8), u64::MAX);
    }

    #[test]
    fn test_leastsigbit_set() {
        assert_eq!(leastsigbit_set(0), -1);
        assert_eq!(leastsigbit_set(1), 0);
        assert_eq!(leastsigbit_set(0x100), 8);
        assert_eq!(leastsigbit_set(0x18), 3); // 0b11000 → bit 3
    }

    #[test]
    fn test_mostsigbit_set() {
        assert_eq!(mostsigbit_set(0), -1);
        assert_eq!(mostsigbit_set(1), 0);
        assert_eq!(mostsigbit_set(0x100), 8);
        assert_eq!(mostsigbit_set(0x18), 4); // 0b11000 → bit 4
    }

    #[test]
    fn test_count_leading_zeros() {
        // Faithful to count_leading_zeros (address.cc:773).
        assert_eq!(count_leading_zeros(0), 64);
        assert_eq!(count_leading_zeros(1), 63);
        assert_eq!(count_leading_zeros(0x100), 55);
        assert_eq!(count_leading_zeros(1u64 << 63), 0);
        assert_eq!(count_leading_zeros(u64::MAX), 0);
    }
}
