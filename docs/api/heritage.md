# `heritage.rs` API Reference

**源代码路径**: `src/heritage.rs`

## 模块说明 (Module Doc)

SSA construction and Heritage management

Corresponds to Ghidra's `heritage.hh`

## 导出的公共 API (Public API)

### `pub struct LocationMap`

Mapping from Address to size and pass information
Corresponds to Ghidra's `LocationMap`

### `pub struct SizePass`

*暂无代码注释*

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn add(&mut self, addr: Address, size: i32, pass: i32)`

*暂无代码注释*

### `pub fn find_pass(&self, addr: Address) -> i32`

*暂无代码注释*

### `pub fn clear(&mut self)`

*暂无代码注释*

### `pub struct PriorityQueue`

Priority queue for flow blocks during heritage
Corresponds to Ghidra's `PriorityQueue`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn reset(&mut self, maxdepth: usize)`

*暂无代码注释*

### `pub fn insert(&mut self, bl: Arc<RwLock<BlockBasic>>, depth: i32)`

*暂无代码注释*

### `pub fn extract(&mut self) -> Option<Arc<RwLock<BlockBasic>>>`

*暂无代码注释*

### `pub fn empty(&self) -> bool`

*暂无代码注释*

### `pub struct HeritageInfo`

Information about heritage status for a specific address space
Corresponds to Ghidra's `HeritageInfo`

### `pub fn new(space: AddressSpace) -> Self`

*暂无代码注释*

### `pub struct LoadGuard`

Guard record for LOAD/STORE operations
Corresponds to Ghidra's `LoadGuard`

### `pub struct Heritage`

Main Heritage class responsible for SSA construction
Corresponds to Ghidra's `Heritage` class

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn heritage(&mut self)`

Main entry point for heritage (SSA construction)

### `pub fn place_multiequals(&mut self)`

Insert Phi nodes (MULTIEQUAL)

### `pub fn rename(&mut self)`

Perform SSA renaming

### `pub fn get_pass(&self) -> i32`

*暂无代码注释*

### `pub fn clear(&mut self)`

*暂无代码注释*

### `pub const BOUNDARY_NODE: u32 = 1 << 0`

*暂无代码注释*

### `pub const MARK_NODE: u32 = 1 << 1`

*暂无代码注释*

### `pub const MERGED_NODE: u32 = 1 << 2`

*暂无代码注释*

### `pub struct StackNode`

Node in the SSA renaming stack
Corresponds to Ghidra's `Heritage::StackNode`

