# `opcodes.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/opcodes.rs`

## 模块说明 (Module Doc)

P-code operation codes

Corresponds to Ghidra's `opcodes.hh`

## 导出的公共 API (Public API)

### `pub enum OpCode`

P-code operation type (OpCode in Ghidra)

This enum represents all possible P-code operations. Each operation
has specific semantics for how it operates on its input and output varnodes.
Prefixes match Ghidra's `CPUI_` naming convention.

### `pub fn name(&self) -> &'static str`

*暂无代码注释*

### `pub fn from_i32(raw: i32) -> Option<OpCode>`

Convert from raw integer opcode to OpCode enum

Used by the P-code injection bridge to convert `PcodeOpRaw.opcode`
integer values into typed `OpCode` variants.

### `pub fn is_block_terminator(&self) -> bool`

Check if this opcode is a control flow terminator (ends a basic block)

### `pub fn is_commutative(&self) -> bool`

Check if this opcode is commutative (operand order doesn't matter)

### `pub fn is_commutative_or_pure(&self) -> bool`

Check if this opcode is a deterministic, side-effect-free operation
suitable for CSE (Common Subexpression Elimination).

Excludes LOAD/STORE (memory side-effects), branches, calls, and
SSA-internal ops (MULTIEQUAL, INDIRECT).

 
## 2026-06-26：get_booleanflip（opcodes.cc:94-135）

### `pub fn get_booleanflip(opc: OpCode, reorder: &mut bool) -> OpCode`
比较 op 的互补翻转表（Ghidra opcodes.cc:94-135）：
- `INT_EQUAL ↔ INT_NOTEQUAL`（reorder=false）
- `INT_LESS ↔ INT_LESSEQUAL`、`INT_SLESS ↔ INT_SLESSEQUAL`（reorder=true，需换序）
- `BOOL_NOT → COPY`（reorder=false）。注：Rugra `CPUI_BOOL_NOT` == Ghidra `BOOL_NEGATE`。
- `FLOAT_EQUAL ↔ FLOAT_NOTEQUAL`、`FLOAT_LESS ↔ FLOAT_LESSEQUAL`
非可翻 op 返回 `CPUI_MAX`。用于 RuleBoolNegate。
