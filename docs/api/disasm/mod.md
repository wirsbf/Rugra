# `disasm/mod.rs` API Reference

**源代码路径**: `src/disasm/mod.rs`

## 模块说明 (Module Doc)

Disassembly module for Rugra

This module provides architecture-specific disassemblers for converting
machine code into instructions that can be translated to P-code.

Currently supported architectures:
- x86-64 (via iced-x86)

# Example

```rust,no_run
use rugra::disasm::{Disassembler, X86_64Disassembler};
use rugra::Address;

# fn example() -> rugra::Result<()> {
let code = vec![0x48, 0x89, 0xc3]; // mov rbx, rax
let mut disasm = X86_64Disassembler::new();
let instructions = disasm.disassemble(&code, Address::new(0x1000))?;
# Ok(())
# }
```

## 导出的公共 API (Public API)

### `pub struct Instruction`

A disassembled instruction

### `pub fn new(address: Address) -> Self`

Create a new instruction

### `pub fn is_branch(&self) -> bool`

Check if this is a branch instruction

### `pub fn is_call(&self) -> bool`

Check if this is a call instruction

### `pub fn is_return(&self) -> bool`

Check if this is a return instruction

### `pub fn next_address(&self) -> Address`

Get the next instruction address (if not a branch)

### `pub fn branch_target(&self) -> Option<Address>`

Get the branch target (if this is a branch/call)

### `pub enum Operand`

Instruction operand

### `pub struct InstructionMetadata`

Metadata about an instruction

### `pub trait Disassembler`

Trait for architecture-specific disassemblers

### `pub fn create_disassembler(arch: Architecture) -> Result<Box<dyn Disassembler>>`

Create a disassembler for the given architecture

