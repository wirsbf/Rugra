# `ffi.rs` API Reference

**源代码路径**: `src/ffi.rs`

## 模块说明 (Module Doc)

FFI interface for Rugra

This module provides C-compatible interfaces to Rugra's core logic,
allowing it to be integrated into Ghidra's C++ decompiler or used for
comparison testing ("对拍").

## 导出的公共 API (Public API)

### `pub struct VarnodeFFI`

C-compatible representation of a Varnode for FFI comparison

### `pub extern "C" fn rugra_evaluate_constant(`

FFI interface for constant folding evaluation

This matches Ghidra's OpBehavior::evaluateBinary/Unary logic.

# Arguments
* `opcode` - The Ghidra OpCode integer
* `size_out` - Expected output size in bytes
* `val1` - First input constant value
* `size1` - First input size in bytes
* `val2` - Second input constant value
* `size2` - Second input size in bytes
* `has_val2` - Boolean indicating if the second input is used (binary op)

# Returns
The resulting constant value, or 0 if evaluation failed or opcode is unsupported.

### `pub extern "C" fn rugra_version() -> *const c_char`

Get the version of Rugra as a C string

### `pub fn set_current_program(program: Program)`

Set the current program for comparison
This is called by Rugra before starting the comparison with Ghidra

### `pub extern "C" fn rugra_init_test_program()`

Initialize a blank program for FFI testing

### `pub extern "C" fn rugra_add_test_op(`

Add an operation to the current test program
This allows Python/C++ to simulate Rugra's analysis state for comparison tests

### `pub extern "C" fn rugra_set_binary_data(_ptr: *const u8, len: usize)`

Set the binary data context for FFI analysis
Allows Rugra to perform memory-backed verification

### `pub extern "C" fn rugra_observe_jumptable(op_addr: u64, table_addr: u64, size: usize)`

Observe and validate a jumptable recovery in Ghidra

This is used for comparison testing to ensure Rugra's jumptable
recovery matches Ghidra's and is logically sound.

### `pub unsafe extern "C" fn rugra_compare_pcode(`

Compare a P-code operation from Ghidra with Rugra's internal state

This is the "ultimate comparison" function that verifies if Rugra's
entire analysis pipeline produces the same P-code structure as Ghidra.

