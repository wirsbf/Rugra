# `pcoderaw.rs` API Reference

**源代码路径**: `src/pcoderaw.rs`

## 模块说明 (Module Doc)

Raw P-code operations

This module corresponds to Ghidra's `pcoderaw.hh` and provides raw
P-code operation structures used during initial translation before
full P-code generation.

# Overview

PcodeOpRaw represents a P-code operation in its initial, unprocessed form.
It's used by the SLEIGH translator before operations are fully constructed
and added to the function's P-code representation.

## 导出的公共 API (Public API)

### `pub struct VarnodeRaw`

Raw varnode data (before full Varnode construction)

Simplified representation used during P-code translation

### `pub fn new(space: AddressSpace, offset: u64, size: usize) -> Self`

Create a new raw varnode

### `pub fn to_varnode_data(&self) -> VarnodeData`

Convert to VarnodeData

### `pub struct PcodeOpRaw`

Raw P-code operation

Corresponds to Ghidra's `PcodeOpRaw` class in pcoderaw.hh

This represents a P-code operation during the translation phase,
before it's fully constructed and added to the function.

### `pub fn new(opcode: i32) -> Self`

Create a new raw P-code operation

### `pub fn add_input(&mut self, varnode: VarnodeRaw)`

Add an input varnode

Corresponds to `addInput` in Ghidra

### `pub fn clear_inputs(&mut self)`

Clear all inputs

Corresponds to `clearInputs` in Ghidra

### `pub fn get_opcode(&self) -> i32`

Get the opcode

Corresponds to `getOpcode` in Ghidra

### `pub fn num_input(&self) -> usize`

Get the number of inputs

Corresponds to `numInput` in Ghidra

### `pub fn inputs(&self) -> &[VarnodeRaw]`

Get the inputs

### `pub fn set_output(&mut self, varnode: VarnodeRaw)`

Set the output varnode

Corresponds to `setOutput` in Ghidra

### `pub fn output(&self) -> Option<&VarnodeRaw>`

Get the output varnode

### `pub fn set_seq_num(&mut self, seqnum: SeqNum)`

Set the sequence number

Corresponds to `setSeqNum` in Ghidra

### `pub fn seq_num(&self) -> Option<SeqNum>`

Get the sequence number

### `pub fn set_behavior(&mut self, behavior: u32)`

Set the behavior flags

Corresponds to `setBehavior` in Ghidra

### `pub fn behavior(&self) -> u32`

Get the behavior flags

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format

Corresponds to `decode` in Ghidra

Format: "opcode output input1 input2 ..."

### `pub fn encode(&self) -> String`

Encode to string format

### `pub struct PcodeOpRawBuilder`

Builder for PcodeOpRaw

### `pub fn new(opcode: i32) -> Self`

Create a new builder

### `pub fn output(mut self, space: AddressSpace, offset: u64, size: usize) -> Self`

Set output

### `pub fn input(mut self, space: AddressSpace, offset: u64, size: usize) -> Self`

Add input

### `pub fn seq_num(mut self, addr: Address, order: u32) -> Self`

Set sequence number

### `pub fn behavior(mut self, behavior: u32) -> Self`

Set behavior

### `pub fn build(self) -> PcodeOpRaw`

Build the PcodeOpRaw

