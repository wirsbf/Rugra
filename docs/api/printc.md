# `printc.rs` API Reference

**源代码路径**: `src/printc.rs`

## 模块说明 (Module Doc)

C language printing implementation

Corresponds to Ghidra's `printc.hh` and `printc.cc`

## 导出的公共 API (Public API)

### `pub struct PrintC`

Printer for the C programming language

Corresponds to Ghidra's `PrintC` class. This handles the conversion
of high-level IR (P-code and Control Flow) into valid C source code.

### `pub fn new(emit: Box<dyn Emit>) -> Self`

Create a new PrintC instance

