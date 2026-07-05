# `space.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/space.rs`

## 模块说明 (Module Doc)

Address space definitions

This module corresponds to Ghidra's `space.hh` and defines the various
address spaces used in the decompiler.

# Address Spaces

Ghidra uses multiple address spaces to represent different types of storage:
- **RAM**: Normal memory
- **Register**: CPU registers
- **Unique**: Temporary/intermediate values (SSA temporaries)
- **Const**: Constant values
- **Stack**: Stack space
- **Other**: Custom/architecture-specific spaces

## 导出的公共 API (Public API)

### `pub type SpaceId = u8`

Address space identifier

### `pub const SPACEID_RAM: SpaceId = 0`

*暂无代码注释*

### `pub const SPACEID_REGISTER: SpaceId = 1`

*暂无代码注释*

### `pub const SPACEID_UNIQUE: SpaceId = 2`

*暂无代码注释*

### `pub const SPACEID_CONST: SpaceId = 3`

*暂无代码注释*

### `pub const SPACEID_STACK: SpaceId = 4`

*暂无代码注释*

### `pub const SPACEID_JOIN: SpaceId = 5`

*暂无代码注释*

### `pub const SPACEID_OVERLAY: SpaceId = 6`

*暂无代码注释*

### `pub enum AddressSpace`

Address space in which a varnode resides

Corresponds to Ghidra's AddrSpace hierarchy in `space.hh`

Ghidra uses multiple address spaces to represent different types of storage:
- RAM: Normal memory
- Register: CPU registers
- Unique: Temporary/intermediate values
- Const: Constant values
- Stack: Stack space
- Other: Custom address spaces

### `pub fn space_id(&self) -> SpaceId`

Get the space ID

### `pub fn from_id(id: SpaceId) -> Self`

Create from space ID

### `pub fn is_register(&self) -> bool`

Check if this is a register space

### `pub fn is_unique(&self) -> bool`

Check if this is a temporary/unique space

### `pub fn is_const(&self) -> bool`

Check if this is a constant space

### `pub fn is_ram(&self) -> bool`

Check if this is RAM space

### `pub fn is_stack(&self) -> bool`

Check if this is stack space

### `pub fn is_big_endian(&self) -> bool`

Check if this is a big-endian space

### `pub fn word_size(&self) -> usize`

Get the word size for this space (in bytes)

### `pub fn addr_size(&self) -> usize`

Get the address size for this space (in bytes)

### `pub fn name(&self) -> &'static str`

Get the name of this space

### `pub struct ConstantSpace`

Constant space (for constant values)

Corresponds to Ghidra's `ConstantSpace` in space.hh

### `pub fn new() -> Self`

Create a new constant space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string

### `pub fn overlap_join(&self, _offset: u64, _size: usize) -> bool`

Check if this overlaps with a join space

### `pub fn print_raw(&self) -> String`

Print raw representation

### `pub struct UniqueSpace`

Unique space (for SSA temporaries)

Corresponds to Ghidra's `UniqueSpace` in space.hh

### `pub fn new() -> Self`

Create a new unique space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn allocate(&mut self, size: usize) -> u64`

Allocate a new unique offset

### `pub fn reset(&mut self)`

Reset the allocator

### `pub struct OtherSpace`

Other/custom address space

Corresponds to Ghidra's `OtherSpace` in space.hh

### `pub fn new(id: SpaceId, name: String) -> Self`

Create a new other space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn print_raw(&self) -> String`

Print raw representation

### `pub struct JoinSpace`

Join space (for combining multiple spaces)

Corresponds to Ghidra's `JoinSpace` in space.hh

### `pub struct JoinPiece`

A piece of a join

### `pub fn new(pieces: Vec<JoinPiece>) -> Self`

Create a new join space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn size(&self) -> usize`

Get the total size of the join

### `pub fn num_pieces(&self) -> usize`

Get the number of pieces

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format

### `pub fn decode_attributes(attrs: &[(&str, &str)]) -> Option<Self>`

Decode from attributes (XML-style)

### `pub fn encode_attributes(&self) -> Vec<(String, String)>`

Encode to attributes (XML-style)

### `pub fn overlap_join(&self, offset: u64, size: usize) -> bool`

Check if this overlaps with another join

### `pub fn print_raw(&self) -> String`

Print raw representation

### `pub fn read(&self, _offset: u64, _size: usize) -> Vec<u8>`

Read value from the joined pieces

### `pub struct OverlaySpace`

Overlay space (for overlaying another space)

Corresponds to Ghidra's `OverlaySpace` in space.hh

### `pub fn new(id: SpaceId, base_space: AddressSpace, name: String) -> Self`

Create a new overlay space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn base(&self) -> AddressSpace`

Get the base space

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format "id:base_space_id:name"


### 2026-07-01：Iop 地址空间（Ghidra IPTR_IOP）
- 新增 `AddressSpace::Iop` 变体 + `SPACEID_IOP=7` + `is_iop()`。Ghidra `IPTR_IOP`（space.hh:35）用于让 varnode 引用另一个 PcodeOp（INDIRECT creation 的 iop 输入）。是 `new_varnode_iop` + `get_op_from_const` 的前置。
<!-- annotation-pass: 2026-07-04 -->

<!-- sleigh-fix: 1783218732.6904683 -->
