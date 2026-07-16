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

**2026-06-27 新增 `CPUI_CAST` (=73)**：对齐 Ghidra `opcodes.hh:119`。P-code
annotation op — 保持 bit pattern，仅标注 metatype/size 变更。ActionSetCasts
在 P-code 层插入，print 层渲染 cast 语法。`CPUI_MAX` 相应 73→74。

**待对齐的命名缺口**（Rugra 改名 vs Ghidra 规范名，205 处引用待重命名）：
- `CPUI_BOOL_NOT` ← Ghidra `CPUI_BOOL_NEGATE` (opcodes.hh:81)
- `CPUI_INT_NEG` ← Ghidra `CPUI_INT_2COMP` (opcodes.hh:67)
- `CPUI_INT_NOT` ← Ghidra `CPUI_INT_NEGATE` (opcodes.hh:68)
- `CPUI_TRUNC`：Ghidra opcodes.hh 无此 op（Rugra 多出）

### `pub fn name(&self) -> &'static str`

*暂无代码注释*

### `pub fn from_i32(raw: i32) -> Option<OpCode>`

Convert from raw integer opcode to OpCode enum

Used by the P-code injection bridge to convert `PcodeOpRaw.opcode`
integer values into typed `OpCode` variants.

### `pub fn is_block_terminator(&self) -> bool`

Check if this opcode is a control flow terminator (ends a basic block)

### `pub fn is_commutative(&self) -> bool`

Check if this opcode is commutative (operand order doesn't matter). 镜像
Ghidra typeop.cc ctor bodies 中 \`opflags = ... | PcodeOp::commutative\` 的集合
（与 op.rs::opcode_flags 的 COMMUTATIVE 位一致）。

完整集合：INT_ADD, INT_MULT, INT_AND, INT_OR, INT_XOR, INT_EQUAL, INT_NOTEQUAL,
**INT_CARRY, INT_SCARRY**, BOOL_AND, BOOL_OR, BOOL_XOR, FLOAT_ADD, FLOAT_MULT,
FLOAT_EQUAL, FLOAT_NOTEQUAL。

注意 INT_LEFT（左移）和 INT_DIV（无符号除）在 Ghidra 中**不**可交换
（typeop.cc:1505/1645 opflags 仅 binary），尽管常被误判。

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
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
<!-- annotation-pass: 2026-07-04 -->
<!-- opcode-correct: 1783180039.0464888 -->
