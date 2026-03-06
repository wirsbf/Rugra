# `translator/mod.rs` API Reference

**源代码路径**: `src/translator/mod.rs`

## 模块说明 (Module Doc)

Instruction to P-code translation module

This module handles the translation of architecture-specific instructions
into P-code intermediate representation. It bridges the gap between
disassembled machine code and our architecture-independent IR.

# Architecture

```text
Disassembled Instruction → Translator → P-code Operations
↓
Register Map
Flag Handling
Operand Conversion
```

# Example

```rust,no_run
use rugra::translator::{Translator, X86_64Translator};
use rugra::disasm::Instruction;
use rugra::Address;

# fn example() -> rugra::Result<()> {
let translator = X86_64Translator::new();
// instruction: mov rax, rbx
// let inst = ...;
// let pcode_ops = translator.translate(&inst)?;
# Ok(())
# }
```

## 导出的公共 API (Public API)

### `pub trait Translator`

Trait for instruction translators

Implementers of this trait convert architecture-specific instructions
into sequences of P-code operations.

### `pub fn create_translator(arch: Architecture) -> Result<Box<dyn Translator>>`

Create a translator for the given architecture

# Arguments

* `arch` - Target architecture

# Returns

A boxed translator instance

### `pub struct PcodeBuilder`

Helper struct for building P-code operations during translation

### `pub fn new() -> Self`

Create a new P-code builder

### `pub fn new_unique(&mut self, size: usize) -> Varnode`

Create a new unique varnode

### `pub fn add_op(`

Add a P-code operation

### `pub fn build(self) -> Vec<PcodeOperation>`

Build and return all operations

### `pub fn op_count(&self) -> usize`

Get the current operation count

