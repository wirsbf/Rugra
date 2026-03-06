# `op.rs` API Reference

**源代码路径**: `src/op.rs`

## 模块说明 (Module Doc)

P-code operation structures

Corresponds to Ghidra's `op.hh`

## 导出的公共 API (Public API)

### `pub struct TypeOp`

*暂无代码注释*

### `pub const STARTBASIC: u32 = 1 << 0`

*暂无代码注释*

### `pub const BRANCH: u32 = 1 << 1`

*暂无代码注释*

### `pub const CALL: u32 = 1 << 2`

*暂无代码注释*

### `pub const RETURNS: u32 = 1 << 3`

*暂无代码注释*

### `pub const NOCOLLAPSE: u32 = 1 << 4`

*暂无代码注释*

### `pub const DEAD: u32 = 1 << 5`

*暂无代码注释*

### `pub const MARKER: u32 = 1 << 6`

*暂无代码注释*

### `pub const BOOLOUTPUT: u32 = 1 << 7`

*暂无代码注释*

### `pub const BOOLEAN_FLIP: u32 = 1 << 8`

*暂无代码注释*

### `pub const FALLTHRU_TRUE: u32 = 1 << 9`

*暂无代码注释*

### `pub const INDIRECT_SOURCE: u32 = 1 << 10`

*暂无代码注释*

### `pub const CODEREF: u32 = 1 << 11`

*暂无代码注释*

### `pub const STARTMARK: u32 = 1 << 12`

*暂无代码注释*

### `pub const MARK: u32 = 1 << 13`

*暂无代码注释*

### `pub const COMMUTATIVE: u32 = 1 << 14`

*暂无代码注释*

### `pub const UNARY: u32 = 1 << 15`

*暂无代码注释*

### `pub const BINARY: u32 = 1 << 16`

*暂无代码注释*

### `pub const SPECIAL: u32 = 1 << 17`

*暂无代码注释*

### `pub const TERNARY: u32 = 1 << 18`

*暂无代码注释*

### `pub const RETURN_COPY: u32 = 1 << 19`

*暂无代码注释*

### `pub const NONPRINTING: u32 = 1 << 20`

*暂无代码注释*

### `pub const HALT: u32 = 1 << 21`

*暂无代码注释*

### `pub const BADINSTRUCTION: u32 = 1 << 22`

*暂无代码注释*

### `pub const UNIMPLEMENTED: u32 = 1 << 23`

*暂无代码注释*

### `pub const NORETURN: u32 = 1 << 24`

*暂无代码注释*

### `pub const MISSING: u32 = 1 << 25`

*暂无代码注释*

### `pub const SPACEBASE_PTR: u32 = 1 << 26`

*暂无代码注释*

### `pub const INDIRECT_CREATION: u32 = 1 << 27`

*暂无代码注释*

### `pub const CALCULATED_BOOL: u32 = 1 << 28`

*暂无代码注释*

### `pub const HAS_CALLSPEC: u32 = 1 << 29`

*暂无代码注释*

### `pub const PTRFLOW: u32 = 1 << 30`

*暂无代码注释*

### `pub const INDIRECT_STORE: u32 = 1 << 31`

*暂无代码注释*

### `pub struct IopSpace`

Corresponds to Ghidra's `IopSpace` class in `op.hh`

### `pub const NAME: &'static str = "iop"`

*暂无代码注释*

### `pub struct PcodeOp`

Represents a single P-code operation in the data flow graph

Corresponds to Ghidra's `PcodeOp` class in `op.hh`

### `pub fn new(start: SeqNum, opcode: OpCode) -> Self`

*暂无代码注释*

### `pub fn get_opcode(&self) -> OpCode`

*暂无代码注释*

### `pub fn get_addr(&self) -> Address`

*暂无代码注释*

### `pub fn get_seq_num(&self) -> &SeqNum`

*暂无代码注释*

### `pub fn num_input(&self) -> usize`

*暂无代码注释*

### `pub fn get_in(&self, slot: usize) -> Option<&Arc<RwLock<Varnode>>>`

*暂无代码注释*

### `pub fn get_out(&self) -> Option<&Arc<RwLock<Varnode>>>`

*暂无代码注释*

### `pub fn is_dead(&self) -> bool`

*暂无代码注释*

### `pub fn is_call(&self) -> bool`

*暂无代码注释*

### `pub fn is_branch(&self) -> bool`

*暂无代码注释*

### `pub struct PcodeOpRef(pub Arc<RwLock<PcodeOp>>)`

Wrapper for Arc<RwLock<PcodeOp>> for use in collections

### `pub struct PieceNode`

Corresponds to Ghidra's `PieceNode` class in `op.hh`

### `pub fn new(op: Weak<RwLock<PcodeOp>>, slot: i32, offset: i32) -> Self`

*暂无代码注释*

### `pub fn is_leaf(&self) -> bool`

*暂无代码注释*

### `pub fn get_type_offset(&self) -> i32`

*暂无代码注释*

### `pub fn get_slot(&self) -> i32`

*暂无代码注释*

### `pub struct PcodeOpBank`

Container for managing P-code operations

Corresponds to Ghidra's `PcodeOpBank` class in `op.hh`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn create(&mut self, opcode: OpCode, num_inputs: usize, addr: Address) -> PcodeOpRef`

Create a new P-code operation and add it to the bank

### `pub fn mark_alive(&mut self, op: PcodeOpRef)`

*暂无代码注释*

### `pub fn mark_dead(&mut self, op: PcodeOpRef)`

*暂无代码注释*

### `pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode)`

*暂无代码注释*

### `pub fn destroy_dead(&mut self)`

*暂无代码注释*

### `pub fn destroy(&mut self, op: PcodeOpRef)`

*暂无代码注释*

### `pub fn find_op(&self, seq: &SeqNum) -> Option<PcodeOpRef>`

*暂无代码注释*

### `pub fn clear(&mut self)`

*暂无代码注释*

### `pub fn is_empty(&self) -> bool`

*暂无代码注释*

### `pub fn get_uniqid(&self) -> u32`

*暂无代码注释*

### `pub fn set_uniqid(&mut self, val: u32)`

*暂无代码注释*

