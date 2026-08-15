# `address.rs` API Reference

**状态**: 接口描述可用；Ghidra 12.0.4 对齐级别 L2
**源代码路径**: `src/address.rs`

> 2026-08-11 锁定审计：当前仅保存数值 offset，无法表达
> AddrSpace 身份、架构宽度/字宽环绕仍未表达。SeqNum 的不可变
> `(Address,time)` 身份与可变 block `order` 已于 2026-08-13 分离，并由
> 锁定 12.0.4 fixture 验证 block 重排不会破坏集合身份。
> 详见 `docs/alignment_audit/CORE_FOUNDATIONS_2026-08-11.md`。
>
> 2026-08-12 ANN-N 仅补 provenance：标量 `new` 是缺少 AddrSpace 参数的
> Rust 兼容层胶水；`as_u64` 对应锁定 oracle 的 inline `Address::getOffset`。
> 本次未改变行为或模块状态。

## 模块说明 (Module Doc)

Address representation and manipulation

This module corresponds to Ghidra's `address.hh` and provides core address
types used throughout the decompiler.

# Core Types

- [`Address`] - A memory address in a specific address space
- [`SeqNum`] - P-code operation key with immutable `(Address, time)` identity and
  a separately mutable basic-block execution order
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

### `pub fn new(addr: Address, time: u32) -> Self`

Create a sequence number with immutable creation time. `order` is
deterministically initialized to `time` until block insertion assigns it.

### `pub fn next(&self) -> Self`

Get the next sequence number at the same address

### `pub fn get_addr(&self) -> Address`

Get the address

### `pub fn get_time(&self) -> u32`

Get the immutable operation creation identity used by Eq/Ord/Hash and bank lookup.

### `pub fn same_identity(&self, other: &Self) -> bool`

Exact Ghidra `SeqNum::operator==` semantic: compare only globally unique
`time`, even when addresses differ. Rust `Eq` instead follows `(Address,time)`
so it remains consistent with `Ord`/`Hash`; ordered bank keys match Ghidra's
`operator<`.

### `pub fn get_order(&self) -> u32`

Get the mutable execution order inside a basic block.

### `pub fn set_order(&mut self, order: u32)`

Set block execution order without changing identity.

### `pub fn decode(s: &str) -> Option<Self>`

Decode identity from string format "addr:time".

### `pub fn encode(&self) -> String`

Encode identity as "addr:time"; mutable block order is omitted.

Ghidra's copy constructor copies only Address/time and leaves `order`
uninitialized; Rust `Copy` necessarily copies all fields. The mapped
`PcodeOpBank::create_seq` path constructs a fresh op from the copied SeqNum,
so copied-order observability remains explicitly `MISMATCH` outside that path.

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

Partially parsed `<range>` / `<register>` state used before dynamic address
spaces and register storage are available. The public projection contains
`space_name`, `first`, `last`, `is_register`, and `seen_last`.

Corresponds to Ghidra's `RangeProperties` in `address.hh:215-225`.

### `pub fn new() -> Self`

Create empty properties with an empty space name, zero endpoints, and both
booleans clear.

### `pub fn decode(&mut self, decoder: &mut dyn Decoder) -> anyhow::Result<()>`

Open the next element, require locked element ID 12 (`range`) or 14
(`register`), then traverse attributes in source order. Locked attribute IDs
20/27/28/14 update `space_name`/`first`/`last`/register name respectively;
unknown attributes are ignored without stopping traversal. `seen_last` is set
only after `last` is read and `is_register` only after `name` is read.

The method intentionally preserves pre-existing fields, applies mutations in
place, does not roll them back on error, and closes the element without
traversing its children. This mirrors `RangeProperties::decode` rather than
performing dynamic `AddrSpace` or register resolution; that application step
remains dependent on the address-space foundation.

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


## 2026-06-26：bit 助手（address.cc:641-745）

新增与 Ghidra 一致的位级自由函数（解锁 RuleSlessToLess/RuleDoubleShift 等）：
- `signbit_negative(val, size)` — address.cc:641，符号位是否置位（负）
- `calc_mask(size)` — address.hh:577，给定字节数的全1掩码
- `leastsigbit_set(val)` — address.cc:714，最低有效位置位索引（-1 若 0）
- `mostsigbit_set(val)` — address.cc:735，最高有效位置位索引

测试：address::tests +4。

## 2026-06-26（续）：functional_equality

- `functional_equality(vn1, vn2) -> bool`（expression.cc:520, level-0:404）：判断两 varnode 是否持相同值（同指针或同常量）。深层 functionalEqualityLevel 待补。解锁 RuleEquality。

## 2026-06-27：coveringmask / minimalmask

- `coveringmask(val: u64) -> u64`（address.cc:760）：返回覆盖 val 所有置位位的掩码 = `(1 << (msb+1)) - 1`。val==0 返回 0。解锁 JumpBasic::get_max_value（INT_AND 掩码分析）。
- `minimalmask(val: u64) -> u64`：coveringmask 别名，匹配 jumptable.cc 的 minimalmask 用法。

### 2026-06-27（会话2 续）：count_leading_zeros

- `count_leading_zeros(val) -> i32` — `count_leading_zeros`（address.cc:773）：64 位前导零计数，val==0 返回 64。用 Rust `leading_zeros` 精确等价。被 RuleDivOpt::findForm 用于计算 numerand 的有效位数（xsize = 64 - clz(nz_mask)）。
<!-- annotation-pass: 2026-07-04 -->
 
