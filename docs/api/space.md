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

### 2026-08-15：ADDRESS-0001 配合新增（Ghidra space.cc printRaw/overlapJoin）

`AddrSpace` 句柄新增两方法（供 `SpaceAddress::print_raw`/`overlap_join` 派发）：

- `print_raw(offset)`（space.cc:206 `AddrSpace::printRaw`）：>4 字节空间对小 offset 收缩打印
  宽度（>>32==0 → 4 字节、>>48==0 → 6 字节），offset 经 `byteToAddress` 缩放到可编址单位后
  以 `setw(2*sz)` 补零 hex 打印，wordsize>1 且 off-cut 时追加 `+cut`（十进制）。
  `ConstantSpace::printRaw`（space.cc:372）与 `OtherSpace::printRaw`（space.cc:410）覆盖为
  无填充 hex —— 派发按 type==Constant / is_other_space 标志（仅生产 OTHER 置位）。
- `overlap_join(offset, size, point_space, point_off, point_skip)`（space.cc:126）：空间指针不等
  恒 -1；距离经 `wrapOffset` 环绕；`>= size` → -1。`ConstantSpace::overlapJoin`（space.cc:364）
  恒 -1；JoinSpace 覆盖需要 join-record 数据库（残差）。
- `identity_ptr()`（RUGRA-GLUE）：共享记录地址，供 Address/Range 的 Ord 身份 tiebreak，
  对应 Ghidra 裸指针比较。

Oracle 证据：`tests/oracle/address_space_handle_1204.{cc,rs}`（锁定 12.0.4，7 case 逐字节 MATCH，
printRaw 覆盖 const/ram/register 路径与 wordsize 换算）。SPACE-0001 残差中
`resolveConstant`/join-record 统一**未**在本 wave 完成（JoinDB 仍在 translate.rs 旧 manager），
登记为 ADDRESS 后继原子。

### 2026-08-15：EXTERNAL-STUB-SUPPORT-0001 构造期 decode 注册（Ghidra translate.cc:254/281 + space.cc:87/304/339）

`AddrSpace` 句柄新增 decode 期构造与属性解码面，`SpaceRegistry` 新增（impl 于
`src/translate.rs`，因 marshal 常量在那侧）构造期注册入口：

- `new_for_decode(space_type)`（space.cc:87 部分构造器）：type + `heritaged|does_deadcode`
  起始 flags、wordsize 1、shortcut `' '`；name/size/index/delay 留空待
  `decode_basic_attributes` 填（C++ 未初始化成员的 Rust 零值对应）。
- `new_other_space_for_decode`（space.cc:403）/`new_unique_space_for_decode`（space.cc:433）/
  `new_spacebase_space_for_decode`（translate.cc:73，置 `programspecific`，contain 悬空至
  `set_contain`）/`new_overlay_space_for_decode`（space.cc:654，置 `overlay`）。
- `decode_basic_attributes(decoder)`（space.cc:304-337）：先重置 deadcodedelay=-1，遍历
  name/index/size/wordsize/bigendian/delay/deadcodedelay/physical 属性，缺省
  deadcodedelay=delay，末尾 `calcScaleMask`。
- `decode(decoder)`（space.cc:339 基类）：open → decodeBasicAttributes → close，服务于
  `<space>`/`<space_unique>`/`<space_other>`（三者无 decode 覆盖）。
- `set_contain(base)`（RUGRA-GLUE setter）：对应 C++ decode 体直接写
  `SpacebaseSpace::contain`/`OverlaySpace::baseSpace` 私有成员。
- `EXTERNAL_SPACE_NAME`（"EXTERNAL"）与 `new_external_space(ind, endian)`（RUGRA-GLUE）：
  12.0.4 decompiler `spacetype` **无** IPTR_EXTERNAL（space.hh:30-38 止于 IPTR_JOIN）、
  packed 协议拒编组 Java TYPE_EXTERNAL（PackedEncode.java:186）。EXTERNAL 工件在 Ghidra
  平台侧：Java `GenericAddressSpace("EXTERNAL", 32, TYPE_EXTERNAL, 0)`（AddressSpace.java:80）
  + ELF importer 在默认空间造人工 EXTERNAL 内存块（ElfProgramBuilder.java:1532-1556，
  0x1000 对齐 linkage 块、每 UND import 8 字节）。Rugra 按该 Java 定义构造（Processor 型、
  addrsize 4），供 registry 命名注册。

`src/translate.rs` 侧：

- `SpaceRegistry::decode_space(decoder)`（translate.cc:254-275）：element id 分派 → 部分构造器
  → decode；`<space_base>`/`<space_overlay>` 的 contain/base 引用按 `Decoder::readSpace`
  （marshal.cc:400-409）语义经 manager 名字解析，未知名 `Err("Unknown address space name: X")`。
- `SpaceRegistry::decode_spaces(decoder)`（translate.cc:281-303）：先插 ConstantSpace；读
  `<spaces defaultspace=...>`；逐子元素 decode+insert；按**名字**查默认空间（缺失
  `Err("Bad 'defaultspace' attribute: X")`）并 `set_default_code_space`。
- 新增 ATTRIB_NAME(14)/ATTRIB_INDEX(10)/ATTRIB_BASE(89) 常量（marshal.cc:1241/1237、
  space.cc:21）；decode 路径用运行时具名 `AttributeId`（const 版无法保留 name，见
  `named_attrib_id` RUGRA-GLUE）。

Oracle 证据：`tests/oracle/external_stub_1204.{cc,rs}` + `tools/run_external_stub_oracle.sh`
（锁定 12.0.4，7 case 逐字节 MATCH：canonical decodeSpaces 注册+defaultspace、overlay 标记
overlaybase、spacebase contain 解析、readSpace 未知名错误、bad defaultspace 错误、EXTERNAL
命名空间注册+重名拒绝、deadcodedelay 缺省=delay）。driver 侧 stub 投影（48 个
EXTERNAL-block import 的 `void free(void *__ptr)` halt_baddata 声明段）在
`examples/curl_decompile.rs`，由 124 语料端到端差分验证（EXTERNAL-stub 计数变化），不属本
fixture 范围。
