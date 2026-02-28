# Translator Module Reference

This document provides a rigorous function-level reference for the `src/translator` module, specifically focusing on the x86-64 implementation.

---

## 1. Main Entry Point (`x86_64.rs`)

### `X86_64Translator::translate`

**Signature**:
```rust
fn translate(&self, instruction: &Instruction) -> Result<Vec<PcodeOperation>>
```

**Inputs**:
*   `instruction`: The disassembled machine instruction (from `iced-x86`).

**Outputs**:
*   `Result<Vec<PcodeOperation>>`: A sequence of P-code operations implementing the instruction's semantics.

**Algorithm**:
1.  Initialize a `PcodeBuilder` with the instruction's address.
2.  Inspect `instruction.mnemonic`.
3.  Dispatch to specific handler functions (e.g., `translate_mov`, `translate_add`) based on the mnemonic.
4.  Collect and return the built operations from the builder.

---

## 2. Data Movement

### `translate_mov`

**Signature**:
```rust
fn translate_mov(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Source**: Call `operand_to_varnode(inst.operands[1])` to get the source value.
2.  **Destination**: Call `store_operand(inst.operands[0], source)`.
    *   *Note*: `store_operand` handles the implicit zero-extension for 32-bit register writes.

### `translate_lea` (Load Effective Address)

**Signature**:
```rust
fn translate_lea(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Check**: Ensure destination is a register and source is a memory operand.
2.  **Calculate**: Call `translate_address` on the source memory operand `[Base + Index*Scale + Disp]`.
    *   This generates `INT_ADD` / `INT_MULT` ops to compute the address.
    *   It returns a `Varnode` holding the *address* (not the value at the address).
3.  **Store**: Emit `PcodeOp::Copy` to move this calculated address into the destination register.

### `translate_push`

**Signature**:
```rust
fn translate_push(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Source**: Resolve operand 0 (value to push).
2.  **Stack Pointer**: Get `RSP` varnode.
3.  **Decrement**: Emit `new_rsp = INT_SUB(RSP, 8)`.
4.  **Update RSP**: Emit `COPY RSP = new_rsp`.
5.  **Store**: Emit `STORE(space=ram, ptr=RSP, value=source)`.

### `translate_pop`

**Signature**:
```rust
fn translate_pop(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Stack Pointer**: Get `RSP` varnode.
2.  **Load**: Emit `val = LOAD(space=ram, ptr=RSP)`.
3.  **Increment**: Emit `new_rsp = INT_ADD(RSP, 8)`.
4.  **Update RSP**: Emit `COPY RSP = new_rsp`.
5.  **Destination**: Call `store_operand(inst.operands[0], val)` to save the popped value.

---

## 3. Arithmetic and Logic

### `translate_add` / `translate_sub`

**Signature**:
```rust
fn translate_add(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Operands**: Resolve op0 (dest/src1) and op1 (src2).
2.  **Compute**: Emit `res = INT_ADD(op0, op1)` (or `INT_SUB`).
3.  **Flags**: Call `update_flags_arithmetic` to update `ZF`, `SF`, `CF`, `OF`.
4.  **Store**: Call `store_operand(inst.operands[0], res)` to update the destination.

---

## 4. Control Flow

### `translate_call`

**Signature**:
```rust
fn translate_call(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Direct Call**: If `inst.branch_target()` is known:
    *   Create `Const` varnode with target address.
    *   Emit `CALL(target)`.
2.  **Indirect Call**: Else (target is register/memory):
    *   Resolve operand 0 via `operand_to_varnode`.
    *   Emit `CALLIND(target_var)`.
    *   *Note*: Argument/Return semantics are injected later by Analysis.

### `translate_jmp`

**Signature**:
```rust
fn translate_jmp(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Direct Jump**: If `inst.branch_target()` is known:
    *   Create `Const` varnode.
    *   Emit `BRANCH(target)`.
2.  **Indirect Jump**: Else:
    *   Resolve operand 0.
    *   Emit `BRANCHIND(target_var)`.
    *   *Significance*: This distinguishes dynamic jumps (switch tables, PLT stubs) from static control flow, ensuring correct CFG termination.

### `translate_ret`

**Signature**:
```rust
fn translate_ret(&self, inst: &Instruction, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Liveness Helper**:
    *   Create input list.
    *   Add `RAX` (and `EAX`) to input list if they exist.
    *   Add `XMM0` if it exists.
2.  **Emit**: Emit `RETURN(inputs...)`.
    *   *Significance*: Explicitly marking `RAX` as an input prevents Dead Code Elimination from removing the function's return value calculation logic.

---

## 5. Helpers

### `operand_to_varnode`

**Signature**:
```rust
fn operand_to_varnode(&self, operand: &Operand, builder: &mut PcodeBuilder, ...) -> Result<Varnode>
```

**Algorithm**:
1.  **Register**: Look up name in `register_map`. Return Register Varnode.
2.  **Immediate**: Return Const Varnode.
3.  **Memory**:
    *   Call `translate_address` to generate calculation ops.
    *   Emit `LOAD(space=ram, ptr=address)` into a new temporary `val`.
    *   Return `val`.

### `store_operand`

**Signature**:
```rust
fn store_operand(&self, dest: &Operand, src: Varnode, builder: &mut PcodeBuilder, ...) -> Result<()>
```

**Algorithm**:
1.  **Register**:
    *   Get destination Register Varnode (`dst`).
    *   Emit `COPY dst = src`.
    *   **Zero Extension Rule**: If `dst` size is 4 bytes (32-bit):
        *   Find corresponding 64-bit register (e.g., `EAX` -> `RAX`).
        *   Emit `INT_ZEXT` from `src` to the 64-bit register.
2.  **Memory**:
    *   Call `translate_address` to compute pointer.
    *   Emit `STORE(space=ram, ptr=address, value=src)`.

### `translate_address`

**Signature**:
```rust
fn translate_address(&self, base, index, scale, disp, ...) -> Result<Varnode>
```

**Algorithm**:
1.  **Base**: Start with `base` register value (or 0).
2.  **Index**: If present:
    *   Calculate `idx_val = index * scale` (via `INT_MULT`).
    *   Update `current = current + idx_val` (via `INT_ADD`).
3.  **Displacement**: If non-zero:
    *   Update `current = current + disp` (via `INT_ADD`).
4.  Return `current` (the effective address).