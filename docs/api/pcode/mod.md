# `pcode/mod.rs` API Reference

**源代码路径**: `src/pcode/mod.rs`

## 模块说明 (Module Doc)

P-code Intermediate Representation

This module implements Ghidra-inspired P-code, a register transfer language (RTL)
used as the intermediate representation for decompilation.

P-code represents low-level operations in a generic, architecture-independent way,
making it easier to analyze and transform machine code from different architectures.

# Architecture

```text
Machine Code → P-code Operations → SSA Form → High-level IR → C Code
```

# P-code Operations

P-code consists of a small set of operations that can represent any machine instruction:

- **Data Movement**: COPY, LOAD, STORE
- **Arithmetic**: INT_ADD, INT_SUB, INT_MULT, INT_DIV, etc.
- **Logical**: INT_AND, INT_OR, INT_XOR, INT_NOT
- **Comparison**: INT_EQUAL, INT_LESS, INT_SLESS, etc.
- **Control Flow**: BRANCH, CBRANCH, CALL, RETURN
- **Type Conversion**: INT_ZEXT, INT_SEXT, TRUNC, etc.

# Example

x86: `add eax, ebx` might translate to:
```text
$U10:4 = INT_ADD eax:4, ebx:4
eax:4 = COPY $U10:4
ZF:1 = INT_EQUAL $U10:4, 0:4
SF:1 = INT_SLESS $U10:4, 0:4
```

## 导出的公共 API (Public API)

### `pub struct PcodeId(u64)`

Unique identifier for a P-code operation

### `pub const fn new(id: u64) -> Self`

Create a new P-code ID

### `pub const fn as_u64(&self) -> u64`

Get the raw ID value

### `pub fn next(&self) -> Self`

Get the next ID

