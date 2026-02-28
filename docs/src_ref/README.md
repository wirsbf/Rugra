# Rugra Source Code Reference

This directory contains detailed technical documentation for the internal modules of the Rugra decompiler. It is intended for contributors and developers who want to understand the implementation details of the decompilation pipeline.

## 📚 Module Reference

### 1. [Analysis Engine](analysis.md) (`src/analysis/`)
The core intelligence of the decompiler.
- **Control Flow Graph (CFG)**: Basic block construction and edge detection.
- **SSA Form**: Static Single Assignment construction, dominance frontiers, and Phi placement.
- **Variable Recovery**: Stack and register variable identification.
- **Call Semantics**: Function argument and return value recovery (x86-64 ABI).
- **Optimization**: Dead code elimination, copy propagation, and rule-based simplification.

### 2. [Code Generation](codegen.md) (`src/codegen/`)
Converts analyzed P-code into high-level C code.
- **Structured Blocks**: Algorithms for recovering `if`, `while`, `for`, and `switch` structures.
- **AST**: Abstract Syntax Tree definitions for C.
- **Formatting**: Textual output generation.

### 3. [Translator](translator.md) (`src/translator/`)
Bridges the gap between machine code and P-code.
- **x86-64 Translator**: Mapping x86 instructions to P-code operations.
- **Semantics**: Handling of flags, stack operations, and indirect jumps.

### 4. [P-code IR](pcode.md) (`src/pcode/`)
The intermediate representation used throughout Rugra.
- **Operations**: Definition of all P-code opcodes (`COPY`, `INT_ADD`, `CALL`, etc.).
- **Varnodes**: Representation of variables (Register, Stack, RAM, Unique).

## 🏗️ Architecture Overview

Rugra follows a linear pipeline architecture:

1.  **Loader (`src/binary`)**: Parses the input binary (ELF/PE) and identifies functions.
2.  **Disassembler (`src/disasm`)**: Uses `iced-x86` to decode raw bytes into instructions.
3.  **Translator (`src/translator`)**: Lifts instructions into P-code operations.
4.  **Analysis (`src/analysis`)**:
    *   Builds CFG.
    *   Recovers Variables.
    *   Analyzes Call Semantics.
    *   Constructs SSA form.
    *   Optimizes and simplifies IR.
5.  **Code Generation (`src/codegen`)**:
    *   Recovers high-level control structures.
    *   Generates C AST.
    *   Formats final output.