# `pcode/program.rs` API Reference

**源代码路径**: `src/pcode/program.rs`

## 模块说明 (Module Doc)

P-code program representation

This module defines the structure for P-code programs, which consist of
sequences of P-code operations that represent machine code functions.

## 导出的公共 API (Public API)

### `pub struct PcodeOperation`

A P-code operation with inputs and output

This represents a single P-code instruction with:
- An opcode (the operation to perform)
- Zero or one output varnode
- Zero or more input varnodes
- Metadata (ID, sequence number)

### `pub fn new(`

Create a new P-code operation

# Arguments

* `id` - Unique identifier
* `seqnum` - Sequence number
* `opcode` - Operation type
* `output` - Output varnode (optional)
* `inputs` - Input varnodes

### `pub fn id(&self) -> PcodeId`

Get the operation ID

### `pub fn seqnum(&self) -> SeqNum`

Get the sequence number

### `pub fn opcode(&self) -> PcodeOp`

Get the opcode

### `pub fn output(&self) -> Option<&Varnode>`

Get the output varnode

### `pub fn inputs(&self) -> &[Varnode]`

Get the input varnodes

### `pub fn output_mut(&mut self) -> Option<&mut Varnode>`

Get a mutable reference to the output

### `pub fn set_output(&mut self, output: Option<Varnode>)`

Set the output varnode

### `pub fn inputs_mut(&mut self) -> &mut Vec<Varnode>`

Get a mutable reference to the inputs

### `pub fn has_side_effects(&self) -> bool`

Check if this operation has side effects

### `pub fn is_terminator(&self) -> bool`

Check if this operation is a terminator (ends a basic block)

### `pub fn input_count(&self) -> usize`

Get the number of inputs

### `pub fn address(&self) -> Address`

Get the address this operation came from

### `pub struct Program`

A P-code program representing a function

This contains all P-code operations for a function, along with metadata
about varnodes, basic blocks, and control flow.

### `pub fn new() -> Self`

Create a new empty P-code program

### `pub fn with_entry_point(entry: Address) -> Self`

Create a program with a known entry point

### `pub fn add_operation(&mut self, op: PcodeOperation)`

Add a P-code operation to the program

### `pub fn operations(&self) -> &[PcodeOperation]`

Get all operations

### `pub fn operations_mut(&mut self) -> &mut Vec<PcodeOperation>`

Get mutable access to all operations

### `pub fn entry_point(&self) -> Option<Address>`

Get the entry point address

### `pub fn set_entry_point(&mut self, addr: Address)`

Set the entry point address

### `pub fn new_unique_varnode(&mut self, size: usize) -> Varnode`

Generate a new unique varnode

### `pub fn new_operation_id(&mut self) -> PcodeId`

Generate a new operation ID

### `pub fn operation_count(&self) -> usize`

Get the number of operations

### `pub fn metadata(&self) -> &ProgramMetadata`

Get metadata

### `pub fn metadata_mut(&mut self) -> &mut ProgramMetadata`

Get mutable metadata

### `pub fn operations_at_address(&self, addr: Address) -> Vec<&PcodeOperation>`

Find all operations at a specific address

### `pub fn find_operation(&self, id: PcodeId) -> Option<&PcodeOperation>`

Find an operation by ID

### `pub fn clear(&mut self)`

Clear all operations

### `pub fn is_empty(&self) -> bool`

Check if the program is empty

### `pub struct ProgramMetadata`

Metadata about a P-code program

### `pub fn new() -> Self`

Create new metadata

### `pub fn with_name(mut self, name: String) -> Self`

Set the function name

### `pub fn set_property(&mut self, key: String, value: String)`

Set a property

### `pub fn get_property(&self, key: &str) -> Option<&String>`

Get a property

### `pub struct PcodeBuilder`

Builder for creating P-code operations

### `pub fn new(entry_point: Address) -> Self`

Create a new builder for a program

### `pub fn at_address(&mut self, addr: Address) -> &mut Self`

Move to a new address

### `pub fn add_op(`

Add an operation

### `pub fn new_unique(&mut self, size: usize) -> Varnode`

Create a new unique varnode

### `pub fn build(self) -> Program`

Build and return the program

### `pub fn program_mut(&mut self) -> &mut Program`

Get a mutable reference to the program

