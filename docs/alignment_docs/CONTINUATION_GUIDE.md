# Rugra-Ghidra Alignment Master Guide

**Version**: 3.0 (Consolidated)
**Last Updated**: 2024
**Target Audience**: AI Agents & Developers

---

## 📚 Table of Contents

1.  [Project Status Overview](#-project-status-overview)
2.  [Agent & Documentation Standards](#-agent--documentation-standards)
3.  [Quick Start & Workflow](#-quick-start--workflow)
4.  [Roadmap & Implementation Plans](#-roadmap--implementation-plans)
5.  [Recent Progress & Technical Notes](#-recent-progress--technical-notes)
6.  [Technical Implementation Guides](#-technical-implementation-guides)
7.  [Appendix A: Architecture Mappings](#-appendix-a-architecture-mappings)
8.  [Appendix B: API Reference Index](#-appendix-b-api-reference-index)

---

## 📋 Project Status Overview

We are rewriting the Rugra (Rust decompiler) codebase to **align 1:1** with Ghidra's C++ decompiler structure. The core analysis pipeline is established, and we are currently synchronizing implementation tracking with high-level design milestones.

| Phase | Checklist File | Corresponding Ghidra Modules | Status | Progress |
|-------|---------------|------------------------------|--------|----------|
| 01 | `01_core_infrastructure.md` | `address.hh`, `space.hh`, `pcoderaw.hh` | 🟡 Partial | ~70% (Translator pending) |
| 02 | `02_syntax_tree.md` | `varnode.hh`, `op.hh`, `typeop.hh`, `fspec.hh` | 🟡 In Progress | ~60% |
| 03 | `03_ssa_and_heritage.md` | `heritage.hh`, `variable.hh`, `merge.hh` | 🟡 In Progress | ~90% |
| 04 | `04_control_flow.md` | `block.hh`, `flow.hh`, `graph.hh` | 🟡 In Progress | ~85% |

| 05 | `05_actions_and_rules.md` | `action.hh`, `ruleaction.hh` | 🟡 In Progress | ~55% |
| 06 | `06_type_system.md` | `type.hh`, `cast.hh`, `cpool.hh` | 🟡 In Progress | ~75% |
| 07 | `07_decompilation_process.md` | `funcdata.hh`, `architecture.hh` | 🟡 In Progress | ~15% |
| 08 | `08_output_and_printing.md` | `printlanguage.hh`, `printc.hh` | 🟡 In Progress | ~30% |
| 09 | `09_emulation_and_util.md` | `emulate.hh`, `marshal.hh`, `xml.hh` | ⚪ Pending | 0% |
| 10 | `10_other_modules.md` | `callgraph.hh`, `comment.hh`, `sleigh.hh` | ⚪ Pending | 0% |

---

## 🚨 Agent & Documentation Standards

To ensure project integrity and alignment, all AI Agents and Developers **MUST** adhere to the following standards.

### 🤖 Agent Development Norms

1.  **Atomic Updates**: Never update code without updating the corresponding documentation (checklists, guides). Code and docs must remain in sync.
2.  **Strict Synchronization**:
    *   Every session **MUST** end with an update to `CONTINUATION_GUIDE.md`.
    *   Progress percentages in this Guide must match the actual density of `[x] ... ✅` markers in the checklists (`docs/alignment_docs/checklists/`).
3.  **Path Resolution**: Always use **absolute paths** when referencing project files to avoid ambiguity across environments (e.g., `D:\ghidra\rugra\src\...`).
4.  **Proactive Verification**: Before finishing a task, run `cargo build` and `cargo test` to ensure no regressions were introduced.
5.  **No Hallucinations**: Do not mark items as "Done" unless they are fully implemented and compiling. If a feature is stubbed, mark it as "Partial".
6.  **Interior Mutability Pattern**:
    *   Use `Arc<RwLock<T>>` for graph nodes (`Varnode`, `PcodeOp`, `BlockBasic`).
    *   Use `Arc<Datatype>` (Immutable) for types to allow safe sharing.
    *   Use `Weak<RwLock<T>>` for back-references to avoid reference cycles.

### 📝 Documentation Norms

1.  **Single Source of Truth**: This file (`CONTINUATION_GUIDE.md`) is the master document. All other guides should be merged here or deleted to prevent fragmentation.
2.  **Checklist Usage**:
    *   Use the checklists in `docs/alignment_docs/checklists/` for granular task tracking.
    *   Do not modify the checklist structure (filenames/headers) unless the architecture changes.
3.  **Format**: All documentation must be in standard Markdown.
4.  **Content Consolidation**: When creating new insights (e.g., "Investigation Summary"), append them to the "Recent Progress & Technical Notes" section of this guide instead of creating a new file.

---

## 🚀 Quick Start & Workflow

### 1. Verify Build Status
```bash
cd D:\ghidra\rugra
cargo build --lib        # Should succeed with warnings only
cargo test --lib         # Should pass all 66+ tests
```

### 2. Workflow Guide
1.  **Read the Checklist**: Open the relevant file in `docs/alignment_docs/checklists/`.
2.  **Verify Progress**: Ensure all implemented methods are marked with `[x] ... ✅`.
3.  **Update BOTH**: Never update the Guide without updating the corresponding Checklist, and vice-versa.
4.  **Prioritize Algorithm**: Focus on `ActionBlockStructure` as the next major logical hurdle.

### 3. Current Priorities (P0)

#### 1. Control Flow Structuring Algorithm (Phase 04)
*   **Goal**: Implement the core logic in `ActionBlockStructure`.
*   **Task**: Recover nested `if`, `while`, and `do-while` constructs from the flat CFG using dominator and cycle analysis.
*   **Status**: `calc_loop` and `structure_loops` are currently stubs. `BlockList` and `BlockCondition` are missing.

#### 2. Variable Merging Completeness (Phase 03)
*   **Goal**: Implement `mergeByDatatype` and `mergeMarker` in `src/merge.rs`.
*   **Task**: Complete the variable recovery pipeline to group remaining non-conflicting SSA instances.
*   **Status**: `mergeByDatatype` and `mergeMarker` are implemented. `mergeMultiEntry` is a stub.

#### 3. Advanced Rule Expansion (Phase 05)
*   **Goal**: Implement pointer-specific simplifications in `src/ruleaction.rs`.
*   **Task**: Implement `RulePtrArith`, `RulePushPtr`, and `RuleStructOffset0` to simplify memory access logic.
*   **Status**: Pending implementation.

---

## 🗺️ Roadmap & Implementation Plans

### 1. Overall Goal
Achieve 1:1 behavioral consistency between Rudra (Rust) and Ghidra (C++). Verify via FFI injection into Ghidra to compare P-code execution, constant folding, and control flow analysis.

### 2. Implementation Phases

#### Phase 1: Foundation & Environment (Partial)
*   **Modules**: `address.hh`, `space.hh`, `opcodes.hh`
*   **Goal**: Build address spaces, constant modeling, and Sleigh translation.
*   **Verification**: `rugra_evaluate_constant` matches Ghidra.
*   **Status**: Core types & OpCodes done. Sleigh translation pending.

#### Phase 2: Dataflow & SSA (Current Focus)
*   **Modules**: `varnode.hh`, `op.hh`, `heritage.cc`
*   **Goal**: Implement `VarnodeBank`, `PcodeOpBank`, and the `Heritage` SSA algorithm (Renaming & Phi placement).
*   **Verification**: `rugra_compare_pcode` matches `MULTIEQUAL` sequences.

#### Phase 3: Control Flow Structuring (Next Up)
*   **Modules**: `block.hh`, `blockaction.cc`, `jumptable.cc`
*   **Goal**: Convert basic block graphs into high-level control flow trees (If/Else, Loops). Recover Jump Tables.
*   **Verification**: `rugra_check_block_structure` matches block IDs and connections.

#### Phase 4: Optimization Engine
*   **Modules**: `action.hh`, `coreaction.cc`, `ruleaction.hh`
*   **Goal**: Replicate hundreds of P-code simplification rules.
*   **Verification**: `rugra_check_action_apply` matches op counts after optimization.

#### Phase 5: Type System & Symbol Recovery
*   **Modules**: `typeop.cc`, `variable.hh`, `fspec.hh`
*   **Goal**: Recover C types, merge variables, and resolve function prototypes.
*   **Verification**: Output types match Ghidra XML export.

#### Phase 6: Code Generation
*   **Modules**: `printlanguage.cc`, `printc.cc`
*   **Goal**: Generate readable C code.
*   **Verification**: Semantic logic matches Ghidra output.

---

## 📈 Recent Progress & Technical Notes

### Key Milestones (Latest Session)
1.  **Phase 04 Progress**: Expanded `FlowBlock` trait and implemented structured block variants (`BlockCopy`, `BlockGoto`, `BlockList`, `BlockCondition`).
2.  **Loop Recovery Foundation**: Added `BlockGraph::add_loop_edge`, `calc_loop`, and `structure_loops` stubs.
3.  **ActionBlockStructure Implementation**: Enhanced `CollapseStructure` with initial `collapse_conditions` logic.
4.  **Interior Mutability Alignment**: Updated `FlowBlock` to include `Send + Sync` for better thread-safe graph manipulation.
5.  **SSA Construction & Heritage**: Completed `Heritage` main loop and SSA renaming algorithm using dominator trees. Phi placement correctly handles `INPUT` varnodes.

2.  **High-Level Variable Recovery**: Implemented `Cover` and `CoverBlock` for liveness analysis. `merge_addr_tied` and `merge_adjacent` are functional.
3.  **Analysis Actions**: Built `ActionDatabase` and `ActionGroup`. Implemented core actions like `ActionDeadCode` and `ActionCse`.
4.  **Control Flow**: Implemented `BlockIf`, `BlockWhileDo`, `BlockDoWhile` structures.

### Technical Note: TypeOp `push()` vs `propagate_type()`
During the investigation of `TypeOp`, a critical distinction was clarified:
*   **`propagate_type()`**: Used during the **analysis phase** to determine the data types of Varnodes based on the operation (e.g., `INT_ADD` implies integer types).
*   **`push()`**: Used during the **code generation phase** (Output). It pushes the operation onto the `PrintLanguage`'s RPN stack to be rendered as C code.
    *   *Lesson*: Do not mix analysis logic with generation logic. `push()` delegates to `PrintLanguage`, while `propagate_type()` interacts with the `TypeFactory`.

---

## 🛠️ Technical Implementation Guides

### TypeOp Implementation Guide

#### Overview
`TypeOp` is the base class for all P-code operations in the high-level analysis. It provides type propagation rules and code generation logic.

#### Architecture
*   **Trait**: `TypeOp` trait defines the interface (`get_output_local`, `push`, etc.).
*   **Structs**: Each opcode (e.g., `CPUI_INT_ADD`) has a corresponding struct (`TypeOpIntAdd`) implementing the trait.
*   **Manager**: `TypeOpManager` registers and retrieves these instances.

#### The `push()` Method
*   **Purpose**: Code generation.
*   **Signature**: `fn push(&self, printer: &mut dyn PrintLanguage, op: &PcodeOp)`
*   **Implementation**:
    ```rust
    fn push(&self, printer: &mut dyn PrintLanguage, op: &PcodeOp) {
        printer.op_int_add(op); // Delegate to printer
    }
    ```

#### Type Propagation (Future)
*   **`get_output_local`**: Returns the expected output data type given input types.
*   **`get_input_local`**: Returns expected input data types given the output type.

---

## 📎 Appendix A: Architecture Mappings

This table maps core Ghidra C++ functions to their Rudra Rust equivalents.

### 1. Decompilation Loop
| Logic | Ghidra (C++) | Rudra (Rust) | Status |
| :--- | :--- | :--- | :--- |
| Init | `startDecompilerLibrary` | `rudra::core::init` | ✅ Aligned |
| Run | `Action::apply` | `rudra::decompiler::Action::apply` | 🟡 In Progress |
| Flow | `Funcdata::followFlow` | `rudra::funcdata::Funcdata::follow_flow` | 🟡 In Progress |

### 2. P-code & Translation
| Logic | Ghidra (C++) | Rudra (Rust) | Status |
| :--- | :--- | :--- | :--- |
| Decode | `Sleigh::printAssembly` | `rudra::sleigh::Sleigh::decode` | ✅ Aligned |
| Create Op | `Funcdata::newOp` | `rudra::funcdata::Bank::new_op` | ✅ Aligned |
| Evaluate | `OpBehavior::evaluateBinary` | `rudra::pcode::eval::evaluate_binary` | ✅ Aligned |

### 3. SSA & Heritage
| Logic | Ghidra (C++) | Rudra (Rust) | Status |
| :--- | :--- | :--- | :--- |
| SSA | `Heritage::heritage` | `rudra::heritage::Heritage::execute` | 🟡 In Progress |
| Dominance | `BlockGraph::calcDominance` | `rudra::graph::dominance::calc` | ✅ Aligned |
| Phi | `Heritage::placeMultiequals` | `rudra::heritage::place_phi` | ✅ Aligned |

### 4. Actions & Rules
| Logic | Ghidra (C++) | Rudra (Rust) | Status |
| :--- | :--- | :--- | :--- |
| Apply | `ActionGroup::apply` | `rudra::actions::Pool::apply` | ✅ Aligned |
| Dead Code | `ActionDeadCode::apply` | `rudra::actions::DeadCode::apply` | ✅ Aligned |

---

## 📎 Appendix B: API Reference Index

*(Condensed Index of Key Classes to Implement)*

### Core
*   **`Action`**: Base class for optimization passes.
*   **`Address`**: Represents a memory location (Space + Offset).
*   **`Architecture`**: Global decompiler environment.
*   **`BlockGraph`**: Control flow graph of basic blocks.
*   **`Funcdata`**: Container for all function analysis data (CFG, P-code, Vars).

### Analysis
*   **`Heritage`**: SSA construction engine.
*   **`Merge`**: Variable merging engine.
*   **`Rule`**: Individual optimization rule (e.g., `RuleCollapseConstants`).
*   **`Varnode`**: A variable, register, or constant.
*   **`PcodeOp`**: An operation (instruction).

### Type System
*   **`Datatype`**: Base class for types (Int, Float, Ptr, Struct).
*   **`TypeFactory`**: Manages type creation and unique-ing.
*   **`Symbol`**: Named symbol in a scope.

### Output
*   **`PrintLanguage`**: Abstract base for code emitters.
*   **`PrintC`**: C language emitter.
*   **`Emit`**: Low-level token stream interface.