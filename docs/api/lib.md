# `lib.rs` API Reference

**源代码路径**: `src/lib.rs`

## 模块说明 (Module Doc)

# Rugra - Rust Ghidra-inspired Decompiler

A high-performance, memory-safe decompiler for C/C++ binaries written in Rust.
Rugra aims to provide production-quality decompilation with a focus on correctness,
performance, and extensibility.

## Architecture

```text
Binary → Loader → Disassembler → P-code IR → Analysis → AST → C Code
↓                   ↓             ↓          ↓        ↓       ↓
ELF              x86/ARM        SSA Form    CFG      Types   Output
PE               MIPS           Optimizer   DFA
Mach-O
```

## Modules

- [`binary`] - Binary parsing and loading (ELF, PE, Mach-O)
- [`pcode`] - P-code intermediate representation
- [`analysis`] - Control flow, data flow, and type analysis
- [`codegen`] - C code generation

## Quick Start

```rust,no_run
use rugra::{Decompiler, Architecture};

# fn main() -> anyhow::Result<()> {
// Load a binary
let binary_data = std::fs::read("program.exe")?;

// Create decompiler
let mut decompiler = Decompiler::new(Architecture::X86_64)?;
decompiler.load_binary(&binary_data)?;

// Decompile a function
let c_code = decompiler.decompile_function(0x401000)?;
println!("{}", c_code);
# Ok(())
# }
```

## 导出的公共 API (Public API)

### `pub struct Decompiler`

Main decompiler interface

This is the primary entry point for using Rugra. It orchestrates the entire
decompilation pipeline from binary loading to C code generation.

# Example

```rust,no_run
use rugra::{Decompiler, Architecture};

# fn main() -> anyhow::Result<()> {
let mut dec = Decompiler::new(Architecture::X86_64)?;
dec.load_binary(&std::fs::read("binary")?)?;
let code = dec.decompile_function(0x1000)?;
# Ok(())
# }
```

### `pub fn new(arch: Architecture) -> Result<Self>`

Create a new decompiler for the specified architecture

# Arguments

* `arch` - Target architecture (X86_64, ARM64, etc.)

# Returns

A new decompiler instance

### `pub fn load_binary(&mut self, data: &[u8]) -> Result<()>`

Load a binary file for analysis

# Arguments

* `data` - Raw binary data

# Returns

Result indicating success or failure

### `pub fn decompile_function(&mut self, address: u64) -> Result<String>`

Decompile a function at the given address

# Arguments

* `address` - Virtual address of the function entry point

# Returns

Decompiled C code as a string

### `pub fn get_functions(&self) -> Result<Vec<Address>>`

Get list of all functions in the binary

# Returns

Vector of function entry point addresses

### `pub fn get_function_name(&self, addr: Address) -> Option<String>`

Get the name of a function at the given address

### `pub fn architecture(&self) -> Architecture`

Get the target architecture

### `pub fn clear_cache(&mut self)`

Clear all caches

### `pub const VERSION: &str = env!("CARGO_PKG_VERSION")`

Version information

### `pub fn version() -> &'static str`

Get the version string

### `pub extern "C" fn rugra_evaluate_constant(`

*暂无代码注释*

### `pub extern "C" fn rugra_observe_jumptable(op_addr: u64, table_addr: u64, size: usize)`

*暂无代码注释*

