# P-code IR Reference

This document provides a detailed reference for the `src/pcode` module, which defines the Intermediate Representation (IR) used by Rugra.

---

## 1. Program (`program.rs`)

The `Program` struct is the container for the entire P-code representation of a function. It stores the linear sequence of operations and manages unique identifiers.

### `Program::new` / `Program::with_entry_point`
**Signature**: `pub fn new() -> Self` / `pub fn with_entry_point(addr: Address) -> Self`

Creates a new, empty P-code program.
*   **Entry Point**: Stores the virtual address where execution begins.
*   **ID Counters**: Initializes counters for generating unique Operation IDs and Varnode IDs.

### `Program::add_operation`
**Signature**: `pub fn add_operation(&mut self, op: PcodeOperation)`

Appends a new P-code operation to the end of the program's instruction stream. This is typically used by the `Translator` as it processes machine instructions.

### `Program::operations` / `Program::operations_mut`
**Signature**: `pub fn operations(&self) -> &[PcodeOperation]`

Returns a slice (or mutable slice) of all operations. This is the primary way Analysis passes iterate over the code.
*   *Note*: The returned list is linear. Control flow structure (blocks) is managed separately by the CFG.

### `Program::new_unique_varnode`
**Signature**: `pub fn new_unique_varnode(&mut self, size: usize) -> Varnode`

Generates a new temporary variable in the `Unique` address space.
*   **Mechanism**: Increments an internal counter (`next_unique_id`) to ensure the varnode offset is unique within the program.
*   **Usage**: Used by the Translator to store intermediate calculation results (e.g., effective address calculation).

---

## 2. PcodeOperation (`program.rs`)

Represents a single P-code instruction.

### `PcodeOperation::new`
**Signature**: `pub fn new(id: PcodeId, seqnum: SeqNum, opcode: PcodeOp, output: Option<Varnode>, inputs: Vec<Varnode>) -> Self`

Constructs an operation.
*   **id**: Unique identifier for tracking the op (stable across reordering).
*   **seqnum**: Links the op back to the original machine instruction address.
*   **opcode**: The action to perform (`INT_ADD`, `COPY`, etc.).
*   **output**: Destination variable (optional, e.g., `STORE` has no output).
*   **inputs**: Source variables.

### `PcodeOperation::inputs` / `PcodeOperation::inputs_mut`
**Signature**: `pub fn inputs(&self) -> &[Varnode]`

Access the input operands. Mutable access allows Analysis passes (like SSA renaming or Call Argument Recovery) to modify arguments.

### `PcodeOperation::set_output`
**Signature**: `pub fn set_output(&mut self, output: Option<Varnode>)`

Updates the output destination. Used by optimization passes or when refining semantics (e.g., adding a return value to a `Call` op).

### `PcodeOperation::has_side_effects`
**Signature**: `pub fn has_side_effects(&self) -> bool`

Determines if the operation modifies system state beyond its explicit output variable.
*   **True for**: `STORE`, `CALL`, `RETURN`, `BRANCH`.
*   **Usage**: Critical for Dead Code Elimination. Ops with side effects are never removed, even if their output is unused.

---

## 3. Varnode (`varnode.rs`)

A `Varnode` (Variable Node) represents a value in the program. It is the atomic unit of data flow.

### `Varnode::new`
**Signature**: `pub fn new(address: Address, size: usize) -> Self`

Creates a generic varnode.

### `Varnode::new_register` / `Varnode::new_unique` / `Varnode::new_constant`
Helper constructors for specific address spaces.
*   `new_register(offset, size)`: CPU register.
*   `new_unique(id, size)`: Temporary variable.
*   `new_constant(val, size)`: Immediate value.

### Properties
*   **`space()`**: Returns the `AddressSpace` (`Ram`, `Register`, `Unique`, `Const`, `Stack`).
*   **`offset()`**: The location within the space.
*   **`size()`**: The size in bytes.
*   **`version()`**: The SSA version number (0 if not in SSA form).

### `Varnode::with_version`
**Signature**: `pub fn with_version(&self, version: usize) -> Self`

Creates a copy of the varnode with a specific SSA version. Used during the Renaming phase of SSA construction.

---

## 4. Opcodes (`ops.rs`)

The `PcodeOp` enum defines the set of all valid operations.

| Opcode | Inputs | Output | Description |
| :--- | :--- | :--- | :--- |
| `COPY` | 1 | Yes | `out = in1` |
| `LOAD` | 2 | Yes | `out = *in1` (in2 is space ID) |
| `STORE` | 3 | No | `*in1 = in2` (in0 is space ID) |
| `INT_ADD` | 2 | Yes | `out = in1 + in2` |
| `INT_SUB` | 2 | Yes | `out = in1 - in2` |
| `INT_MULT` | 2 | Yes | `out = in1 * in2` |
| `INT_ZEXT` | 1 | Yes | `out = zero_extend(in1)` |
| `BRANCH` | 1 | No | `goto in1` |
| `CBRANCH` | 2 | No | `if (in1) goto in2` |
| `BRANCHIND`| 1 | No | `goto *in1` |
| `CALL` | 1+ | Opt | `call in1(in2...)` |
| `RETURN` | 0+ | No | `return (in1...)` |
| `PHI` | N | Yes | `out = phi(in1, in2...)` |

---

## 5. PcodeBuilder (`program.rs`)

A helper struct to simplify the generation of P-code sequences, primarily used by the `Translator`.

### `PcodeBuilder::add_op`
**Signature**: `pub fn add_op(&mut self, opcode: PcodeOp, output: Option<Varnode>, inputs: Vec<Varnode>)`

Adds an operation to the program being built. It automatically assigns a new `PcodeId` and increments the sequence number for the current instruction.