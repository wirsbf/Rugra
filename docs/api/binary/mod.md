# `binary/mod.rs` API Reference

**源代码路径**: `src/binary/mod.rs`

## 模块说明 (Module Doc)

Binary parsing and loading module

This module handles parsing and loading of various binary formats including:
- ELF (Executable and Linkable Format) - Linux
- PE (Portable Executable) - Windows
- Mach-O - macOS

# Example

```rust,no_run
use rugra::binary::Binary;

# fn main() -> anyhow::Result<()> {
let data = std::fs::read("program.exe")?;
let binary = Binary::parse(&data)?;
println!("Entry point: {}", binary.entry_point());
# Ok(())
# }
```

## 导出的公共 API (Public API)

### `pub enum BinaryFormat`

Binary format type

### `pub struct Binary`

Parsed binary file

### `pub fn parse(data: &[u8]) -> Result<Self>`

Parse a binary file from raw bytes

# Arguments

* `data` - Raw binary data

# Returns

Parsed binary or error

### `pub fn entry_point(&self) -> Address`

Get the entry point address

### `pub fn format(&self) -> BinaryFormat`

Get the binary format

### `pub fn architecture(&self) -> Architecture`

Get the target architecture

### `pub fn get_functions(&self) -> Vec<Address>`

Get list of function addresses

# Returns

Vector of function entry point addresses

### `pub fn get_function_name(&self, addr: Address) -> Option<&String>`

Get function name by address

### `pub fn read_string_at(&self, addr: Address) -> Option<String>`

Read a null-terminated string from the binary at the given address

### `pub fn disassemble_function(`

Disassemble a function at the given address

# Arguments

* `addr` - Function entry point address
* `arch` - Target architecture

# Returns

Vector of disassembled instructions

