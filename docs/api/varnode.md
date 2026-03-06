# `varnode.rs` API Reference

**源代码路径**: `src/varnode.rs`

## 模块说明 (Module Doc)

Varnode definitions for P-code IR

Corresponds to Ghidra's `varnode.hh`

## 导出的公共 API (Public API)

### `pub const MARK: u32 = 1 << 0`

*暂无代码注释*

### `pub const CONSTANT: u32 = 1 << 1`

*暂无代码注释*

### `pub const ANNOTATION: u32 = 1 << 2`

*暂无代码注释*

### `pub const INPUT: u32 = 1 << 3`

*暂无代码注释*

### `pub const WRITTEN: u32 = 1 << 4`

*暂无代码注释*

### `pub const INSERT: u32 = 1 << 5`

*暂无代码注释*

### `pub const IMPLIED: u32 = 1 << 6`

*暂无代码注释*

### `pub const EXPLICIT: u32 = 1 << 7`

*暂无代码注释*

### `pub const TYPELOCK: u32 = 1 << 8`

*暂无代码注释*

### `pub const NAMELOCK: u32 = 1 << 9`

*暂无代码注释*

### `pub const NOLOCALALIAS: u32 = 1 << 10`

*暂无代码注释*

### `pub const VOLATIL: u32 = 1 << 11`

*暂无代码注释*

### `pub const EXTERNREF: u32 = 1 << 12`

*暂无代码注释*

### `pub const READONLY: u32 = 1 << 13`

*暂无代码注释*

### `pub const PERSIST: u32 = 1 << 14`

*暂无代码注释*

### `pub const ADDRTIED: u32 = 1 << 15`

*暂无代码注释*

### `pub const UNAFFECTED: u32 = 1 << 16`

*暂无代码注释*

### `pub const SPACEBASE: u32 = 1 << 17`

*暂无代码注释*

### `pub const INDIRECTONLY: u32 = 1 << 18`

*暂无代码注释*

### `pub const DIRECTWRITE: u32 = 1 << 19`

*暂无代码注释*

### `pub const ADDRFORCE: u32 = 1 << 20`

*暂无代码注释*

### `pub const MAPPED: u32 = 1 << 21`

*暂无代码注释*

### `pub const INDIRECT_CREATION: u32 = 1 << 22`

*暂无代码注释*

### `pub const RETURN_ADDRESS: u32 = 1 << 23`

*暂无代码注释*

### `pub const COVERDIRTY: u32 = 1 << 24`

*暂无代码注释*

### `pub const PRECISLO: u32 = 1 << 25`

*暂无代码注释*

### `pub const PRECISHI: u32 = 1 << 26`

*暂无代码注释*

### `pub const INDIRECTSTORAGE: u32 = 1 << 27`

*暂无代码注释*

### `pub const HIDDENRETPARM: u32 = 1 << 28`

*暂无代码注释*

### `pub const INCIDENTAL_COPY: u32 = 1 << 29`

*暂无代码注释*

### `pub const AUTOLIVE_HOLD: u32 = 1 << 30`

*暂无代码注释*

### `pub const PROTO_PARTIAL: u32 = 1 << 31`

*暂无代码注释*

### `pub struct Varnode`

A Varnode represents a storage location and size in P-code IR

Corresponds to Ghidra's `Varnode` class in `varnode.hh`

### `pub fn new(size: usize, loc: Address) -> Self`

*暂无代码注释*

### `pub fn get_addr(&self) -> &Address`

*暂无代码注释*

### `pub fn get_space(&self) -> AddressSpace`

*暂无代码注释*

### `pub fn get_offset(&self) -> u64`

*暂无代码注释*

### `pub fn get_val(&self) -> u64`

*暂无代码注释*

### `pub fn is_unique(&self) -> bool`

*暂无代码注释*

### `pub fn is_register(&self) -> bool`

*暂无代码注释*

### `pub fn constant_value(&self) -> Option<u64>`

*暂无代码注释*

### `pub fn size(&self) -> usize`

*暂无代码注释*

### `pub fn offset(&self) -> u64`

*暂无代码注释*

### `pub fn space(&self) -> AddressSpace`

*暂无代码注释*

### `pub fn version(&self) -> usize`

*暂无代码注释*

### `pub fn with_version(mut self, _version: usize) -> Self`

*暂无代码注释*

### `pub fn new_constant(val: u64, size: usize) -> Self`

*暂无代码注释*

### `pub fn new_register(offset: u64, size: usize) -> Self`

*暂无代码注释*

### `pub fn new_ram(offset: u64, size: usize) -> Self`

*暂无代码注释*

### `pub fn new_stack(offset: u64, size: usize) -> Self`

*暂无代码注释*

### `pub fn new_unique(offset: u64, size: usize) -> Self`

*暂无代码注释*

### `pub fn get_size(&self) -> usize`

*暂无代码注释*

### `pub fn get_create_index(&self) -> u32`

*暂无代码注释*

### `pub fn is_constant(&self) -> bool`

*暂无代码注释*

### `pub fn is_input(&self) -> bool`

*暂无代码注释*

### `pub fn is_written(&self) -> bool`

*暂无代码注释*

### `pub fn is_free(&self) -> bool`

*暂无代码注释*

### `pub fn set_flags(&mut self, f: u32)`

*暂无代码注释*

### `pub fn clear_flags(&mut self, f: u32)`

*暂无代码注释*

### `pub struct VarnodeLocRef(pub Arc<RwLock<Varnode>>)`

A wrapper for Rc<RefCell<Varnode>> for location-based sorting

### `pub struct VarnodeDefRef(pub Arc<RwLock<Varnode>>)`

A wrapper for Rc<RefCell<Varnode>> for definition-based sorting

### `pub struct VarnodeData`

Simplified varnode data (for serialization/deserialization)

### `pub fn new(space: AddressSpace, offset: u64, size: usize) -> Self`

*暂无代码注释*

### `pub struct VarnodeBank`

Container for managing Varnodes

Corresponds to Ghidra's `VarnodeBank` class in `varnode.hh`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn create(&mut self, size: usize, loc: Address) -> Arc<RwLock<Varnode>>`

Create a new free varnode

### `pub fn create_unique(&mut self, size: usize) -> Arc<RwLock<Varnode>>`

Create a new unique varnode

### `pub fn create_constant(&mut self, size: usize, val: u64) -> Arc<RwLock<Varnode>>`

Create a new constant varnode

### `pub fn set_input(&mut self, vn: Arc<RwLock<Varnode>>)`

Mark a varnode as an input

### `pub fn set_def(&mut self, vn: Arc<RwLock<Varnode>>, op: Weak<RwLock<PcodeOp>>)`

Mark a varnode as defined by an operation

### `pub fn clear(&mut self)`

*暂无代码注释*

### `pub fn make_free(&mut self, vn: &mut Varnode)`

*暂无代码注释*

### `pub fn replace(&mut self, vn1: &mut Varnode, vn2: &mut Varnode)`

*暂无代码注释*

### `pub fn begin_def(&self) -> std::collections::btree_set::Iter<'_, VarnodeDefRef>`

*暂无代码注释*

### `pub fn begin_loc(&self) -> std::collections::btree_set::Iter<'_, VarnodeLocRef>`

*暂无代码注释*

### `pub fn has_input_intersection(&self) -> bool`

*暂无代码注释*

### `pub fn num_varnodes(&self) -> usize`

*暂无代码注释*

### `pub fn get_create_index(&self) -> u32`

*暂无代码注释*

### `pub fn find_free(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>>`

Find a free varnode at a specific location and size

