# `address.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/address.rs`

## 模块说明 (Module Doc)

Address representation and manipulation

This module corresponds to Ghidra's `address.hh` and provides core address
types used throughout the decompiler.

# Core Types

- [`Address`] - A memory address in a specific address space
- [`SeqNum`] - Sequence number (address + order for P-code ops)
- [`Range`] - An address range (first, last)
- [`RangeList`] - A collection of non-overlapping address ranges

## 导出的公共 API (Public API)

### `pub struct Address(u64)`

Memory address type

Represents a virtual memory address in the target binary.
Internally stored as u64 to support 64-bit architectures.

Corresponds to Ghidra's `Address` class in `address.hh`

### `pub const fn new(addr: u64) -> Self`

Create a new address

### `pub const fn as_u64(&self) -> u64`

Get the raw address value

### `pub fn offset(&self, offset: i64) -> Self`

Add an offset to the address

### `pub fn is_null(&self) -> bool`

Check if address is null (0x0)

### `pub fn is_aligned(&self, alignment: u64) -> bool`

Check if address is aligned to the given boundary

### `pub fn next(&self) -> Self`

Get the next address

### `pub fn prev(&self) -> Self`

Get the previous address

### `pub struct SeqNum`

Sequence number for P-code operations within a single instruction

When a machine instruction translates to multiple P-code ops,
they are numbered sequentially using SeqNum.

Corresponds to Ghidra's `SeqNum` class in `address.hh`

### `pub fn new(addr: Address, order: u32) -> Self`

Create a new sequence number

### `pub fn next(&self) -> Self`

Get the next sequence number at the same address

### `pub fn get_addr(&self) -> Address`

Get the address

### `pub fn get_order(&self) -> u32`

Get the order/time

### `pub fn set_order(&mut self, order: u32)`

Set the order/time

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format "addr:order"

### `pub fn encode(&self) -> String`

Encode to string format "addr:order"

### `pub struct Range`

Address range (inclusive first and last addresses)

Corresponds to Ghidra's `Range` class in `address.hh`

### `pub fn new(first: Address, last: Address) -> Option<Self>`

Create a new range

Returns `None` if first > last

### `pub fn get_first(&self) -> Address`

Get the first address

### `pub fn get_last(&self) -> Address`

Get the last address

### `pub fn get_first_addr(&self) -> Address`

Get the first address (Ghidra naming)

### `pub fn get_last_addr(&self) -> Address`

Get the last address (Ghidra naming)

### `pub fn get_last_addr_open(&self) -> Address`

Get the last address + 1 (open end)

### `pub fn contains(&self, addr: Address) -> bool`

Check if an address is contained in this range

### `pub fn size(&self) -> u64`

Get the size of the range in bytes

### `pub fn overlaps(&self, other: &Range) -> bool`

Check if this range overlaps with another

### `pub fn is_adjacent(&self, other: &Range) -> bool`

Check if this range is adjacent to another

### `pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result`

Print bounds (for debugging)

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format "first-last"

### `pub fn decode_from_attributes(first: &str, last: &str) -> Option<Self>`

Decode from attributes (XML-style)

### `pub fn encode(&self) -> String`

Encode to string format "first-last"

### `pub struct RangeProperties`

Properties associated with a range

Corresponds to Ghidra's `RangeProperties` in address.hh

### `pub fn new(flags: u32) -> Self`

Create new range properties

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string

### `pub struct RangeList`

List of non-overlapping address ranges

Corresponds to Ghidra's `RangeList` class in `address.hh`

### `pub fn new() -> Self`

Create a new empty range list

### `pub fn insert_range(&mut self, new_range: Range)`

Insert a range into the list, merging overlapping ranges

### `pub fn remove_range(&mut self, to_remove: Range)`

Remove a range from the list

### `pub fn in_range(&self, addr: Address) -> bool`

Check if an address is in any range in the list

### `pub fn num_ranges(&self) -> usize`

Get the number of ranges in the list

### `pub fn empty(&self) -> bool`

Check if the list is empty

### `pub fn ranges(&self) -> &[Range]`

Get all ranges

### `pub fn begin(&self) -> std::slice::Iter<'_, Range>`

Get iterator to beginning

### `pub fn end(&self) -> std::slice::Iter<'_, Range>`

Get iterator to end

### `pub fn merge(&mut self, other: &RangeList)`

Merge another RangeList into this one

### `pub fn clear(&mut self)`

Clear all ranges

### `pub fn longest_fit(&self, addr: Address) -> Option<&Range>`

Find the longest fit for an address

### `pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result`

Print bounds of all ranges

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format (comma-separated ranges)

### `pub fn encode(&self) -> String`

Encode to string format (comma-separated ranges)

