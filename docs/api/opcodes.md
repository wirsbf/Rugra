# `opcodes.rs` API Reference

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

