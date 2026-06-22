# `disasm/x86_lift.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/disasm/x86_lift.rs`

## 模块说明 (Module Doc)

x86-64 to P-code lifter

Translates disassembled x86-64 instructions into raw P-code operations.

## 导出的公共 API (Public API)

### `pub struct X86Lifter`

Lifter for translating x86-64 instructions to P-code

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn lift(&mut self, inst: &Instruction) -> Vec<PcodeOpRaw>`

Lift a single instruction to P-code

