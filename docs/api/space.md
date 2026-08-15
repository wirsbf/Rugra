# `space.rs` API Reference

**状态**: 接口描述可用；Ghidra 12.0.4 对齐级别 L2
**源代码路径**: `src/space.rs`

> 固定枚举尚不能保存 Ghidra 架构动态 space index/type/name/
> address-size/wordsize/endianness/flags；跨空间 Address/Varnode 键因此不完整。

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
 

### 2026-07-05: AddressSpace delay/deadcodedelay/is_heritaged
- `get_delay`(space.hh): Stack=1,其他=0(Ghidra .sla spec 默认)。
- `get_deadcode_delay`: = get_delay。
- `is_heritaged`: Const/Iop/Join 不 heritaged。
 
 


### 2026-08-15：SPACE-0001 architecture-owned AddrSpace registry（Ghidra space.cc/translate.cc AddrSpaceManager）

固定枚举 `AddressSpace` 保留为过渡 adapter（消费方未迁移），新增 1:1 移植的架构动态注册表：

- `SpaceType`（space.hh:30 `spacetype`）：Constant/Processor/SpaceBase/Internal/Fspec/Iop/Join。
- `space_flags`（space.hh:85-98）：big_endian/heritaged/does_deadcode/…/has_nearpointers 共 12 位。
- `AddrSpace`（space.hh:82）：`Rc<RefCell<AddrSpaceInner>>` 共享句柄（Ghidra 裸指针 + refcount 语义），
  携带 type/name/index/addressSize/wordsize/flags/highest/pointerBounds/shortcut/delay/deadcodedelay/refcount
  与 SpacebaseState（contain/hasbaseregister/isNegativeStack/baseloc/baseOrig，translate.hh:173-178）。
  `None`（`Option<AddrSpace>`）对应 Ghidra null `AddrSpace*`（Address::Address() 的 invalid 态）。
- 派生空间构造器：`new_space`（space.cc:58 全参 ctor）、`new_constant_space`（space.cc:356）、
  `new_other_space`（space.cc:396，硬编码 index 1）、`new_unique_space`（space.cc:427）、
  `new_join_space`（space.cc:446）、`new_iop_space`（op.cc:33）、`new_fspec_space`（fspec.cc:2116）、
  `new_spacebase_space`（translate.cc:57）、`new_overlay_space`（space.cc:654/661 decode 体语义）。
- 访问器/算法：`calc_scale_mask`（space.cc:34）、`wrap_offset`（space.hh:383）、`truncate_space`（space.cc:105）、
  `set_flags`/`clear_flags`（space.hh:264/270）、谓词族（is_heritaged/does_deadcode/has_physical/…）、
  静态换算 `address_to_byte` 族（space.hh:514-543）、`compare_by_index`（space.hh:549）、
  `calc_mask`（address.hh:499/address.cc:633 表）。
- `SpaceRegistry`（translate.hh:220 AddrSpaceManager，resolver/join 半部仍留在 translate.rs 旧 manager）：
  `insert_space`（translate.cc:352，含逐类型校验/重复拒绝/baselist 部分增长/refcount）、
  `assign_shortcut`（translate.cc:517，碰撞推进 + >26 后 'z' 复用不更新表）、
  `get_space_by_name`/`get_space_by_shortcut`/`get_space`/`num_spaces`/`get_next_space_in_order`
  （空槽跳过 + 端哨兵）、`set_default_code_space`/`set_default_data_space`、`add_spacebase_pointer`
  （translate.cc:460 → setBaseRegister translate.cc:86，BE 截断偏移上移）、`copy_spaces`（translate.cc:443，
  共享句柄 refcount+1）、`set_deadcode_delay`/`truncate_space`/`mark_near_pointers`/`set_reverse_justified`/
  `set_infer_ptr_bounds`、缓存槽访问器族（get_constant_space 等，translate.hh:448-530）。
- 错误通道：`Result<_, String>` 携带 Ghidra LowlevelError 逐字消息（如
  "const space must be assigned index 0"、"Space X was assigned as id duplicating: Y"）。

Oracle 证据：`tests/oracle/space_registry_1204.{cc,rs}` + `tools/run_space_registry_oracle.sh`
（锁定 12.0.4 oracle，8 case 逐字节 MATCH）。未移植残留：per-space `read/printRaw/encode/decode`
属性编解码（MARSHAL/TRANSLATE 原子）、`resolveConstant` 与 join-record 半部（留在旧 enum manager，
待 ADDRESS-0001 统一切换）。
