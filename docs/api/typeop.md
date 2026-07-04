# `typeop.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/typeop.rs`

## 模块说明 (Module Doc)

Type operations for P-code

Corresponds to Ghidra's `typeop.hh`

## 导出的公共 API (Public API)

### `pub struct OpBehavior`

*暂无代码注释*

### `pub struct Encoder`

*暂无代码注释*

### `pub const INHERITS_SIGN: u32 = 1 << 0`

*暂无代码注释*

### `pub const INHERITS_SIGN_ZERO: u32 = 1 << 1`

*暂无代码注释*

### `pub const SHIFT_OP: u32 = 1 << 2`

*暂无代码注释*

### `pub const ARITHMETIC_OP: u32 = 1 << 3`

*暂无代码注释*

### `pub const LOGICAL_OP: u32 = 1 << 4`

*暂无代码注释*

### `pub const FLOATINGPOINT_OP: u32 = 1 << 5`

*暂无代码注释*

### `pub trait TypeOp`

Core trait representing a P-code operation type

Corresponds to Ghidra's `TypeOp` class

### `pub struct TypeOpBinary`

Base behavior for binary operations

### `pub struct TypeOpUnary`

Base behavior for unary operations

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct TypeOpCopy`

CPUI_COPY implementation

### `pub struct TypeOpLoad`

CPUI_LOAD implementation

### `pub struct TypeOpStore`

CPUI_STORE implementation

### `pub struct TypeOpBranch`

*暂无代码注释*

### `pub struct TypeOpCbranch`

*暂无代码注释*

### `pub struct TypeOpBranchind`

*暂无代码注释*

### `pub struct TypeOpCall`

*暂无代码注释*

### `pub struct TypeOpCallind`

*暂无代码注释*

### `pub struct TypeOpReturn`

*暂无代码注释*

### `pub struct TypeOpPtradd`

*暂无代码注释*

### `pub struct TypeOpPtrsub`

*暂无代码注释*

### `pub struct TypeOpMulti`

*暂无代码注释*

### `pub struct TypeOpIndirect`

*暂无代码注释*

### `pub struct TypeOpSegment`

*暂无代码注释*

### `pub struct TypeOpCpoolref`

*暂无代码注释*

### `pub struct TypeOpNew`

*暂无代码注释*

### `pub struct TypeOpCallother`

*暂无代码注释*

### `pub struct TypeOpManager`

Manager for TypeOps

This handles the mapping between OpCodes and their TypeOp implementations.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn get_op(&self, opcode: OpCode) -> Option<&dyn TypeOp>`

*暂无代码注释*

### `pub fn push(&self, lng: &mut dyn PrintLanguage)`

Push this operation to a language printer

 2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-07-01：getInputCast/getOutputToken/propagateType 补全
TypeOp trait +get_output_token/get_input_cast/propagate_type/get_output_metatype（默认 None）。
关键 op 实现：COPY（透明传播）、LOAD/STORE（指针↔值）、MULTIEQUAL/INDIRECT（透明）、INT_ADD（指针传播）、6 个比较 op（bool 输出+跨 input 传播）。+propagate_to_pointer/from_pointer 辅助。8 新测试。
<!-- annotation-pass: 2026-07-04 -->
<!-- opcode-correct: 1783180039.060287 -->
