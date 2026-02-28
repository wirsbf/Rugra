# 08 Output and Printing Checklist

This checklist tracks the implementation of the "Output and Printing" phase in Rugra, corresponding to Ghidra's `PrintLanguage`, `PrintC`, and related classes. This phase is responsible for converting the high-level P-code and Control Flow Graph into human-readable source code (C language).

## Core Infrastructure
- [x] **Define `PrintLanguage` Trait** (`src/printlanguage.rs`)
    - [x] `get_emit` / `set_emit`
    - [x] `doc_function`
    - [x] `doc_all_proto`
    - [x] `doc_variable_decl`
    - [x] `doc_statement`
    - [x] `op_copy`, `op_load`, `op_store`
    - [x] `op_binary`, `op_unary`
    - [x] `op_multiequal`, `op_indirect`
    - [x] `op_call`, `op_return`
    - [x] `push_type`, `push_varnode`
- [x] **Implement `PrintC` Struct** (`src/printc.rs`)
    - [x] Constructor with `Emit` implementation.
    - [x] Implementation of `PrintLanguage` trait methods.

## Statement Generation (C Language)
- [x] **Basic Operations**
    - [x] `COPY`: Implemented as assignment (`=`).
    - [x] `LOAD`: Implemented as pointer dereference (`*`).
    - [x] `STORE`: Implemented as pointer assignment (`*ptr = val`).
- [ ] **Expression Operations**
    - [ ] `BINARY`: Replace placeholder `" op "` with actual C operators (`+`, `-`, `&`, `|`, etc.) based on opcode.
    - [ ] `UNARY`: Replace placeholder `"op"` with actual C operators (`~`, `-`, `!`) based on opcode.
    - [ ] **Operator Precedence**: Implement logic to add parentheses when necessary.
- [ ] **Control Flow Operations**
    - [x] `CALL`: Basic implementation (func name + args).
    - [x] `RETURN`: Basic implementation.
    - [ ] `BRANCH`/`CBRANCH`: Implement goto or structured control flow printing.
    - [x] `MULTIEQUAL` (Phi): Basic printing as `phi(...)`.

## Control Flow Structuring (Printing Side)
- [ ] **Structured Block Printing**
    - [ ] `doc_function`: Currently iterates basic blocks linearly. Needs to walk the `BlockGraph` structure (once `ActionBlockStructure` is complete).
    - [ ] Implement `emit_block_if`, `emit_block_while`, `emit_block_do_while`, `emit_block_switch`.
    - [ ] Handle indentation nesting in `Emit`.

## Type and Variable Formatting
- [ ] **Variable Naming**
    - [ ] `push_varnode`: Currently prints `v_{size}_{offset}`. Needs to look up `HighVariable` names or `Symbol` names.
    - [ ] Handle variable scope/shadowing.
- [ ] **Type Syntax**
    - [ ] `push_type`: Enhance to handle pointer syntax (`*`), arrays (`[]`), and structs (`.`).
    - [ ] Handle cast insertion (`(type)val`) where necessary.

## Integration
- [ ] **Connect to `ActionBlockStructure`**: Ensure the printer can traverse the structured `BlockGraph`.
- [ ] **Connect to `HighFunction`**: Ensure the printer uses high-level variable information.