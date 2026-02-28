# Analysis Module Reference

This document provides a rigorous function-level reference for the `src/analysis` module. It details the inputs, outputs, and algorithmic steps for the core components of the Rugra decompilation pipeline.

---

## 1. Analysis Orchestrator (`mod.rs`)

### `analyze_function`

**Signature**:
```rust
pub fn analyze_function(program: &mut Program, binary: Option<&Binary>) -> Result<FunctionAnalysis>
```

**Inputs**:
*   `program`: Mutable reference to the P-code `Program`. The program will be modified in-place (e.g., by SSA construction and Optimization).
*   `binary`: Optional reference to the loaded `Binary` (used for symbol lookups during type propagation).

**Outputs**:
*   `Result<FunctionAnalysis>`: A struct containing all analysis artifacts (CFG, SSA form, Variable definitions, Types).

**Algorithm**:
1.  **CFG Construction**: Call `ControlFlowGraph::from_program` to build basic blocks.
2.  **Variable Recovery**:
    *   Calculate reachable blocks via BFS on CFG.
    *   Call `recover_variables` with the reachable set to identify stack/register vars.
3.  **Call Semantics**: Call `calls::recover_call_semantics` to inject ABI-specific arguments and return values into `CALL` operations.
4.  **Type Inference**: Call `type_inference::infer_types` (initial pass).
5.  **SSA Construction**: Call `ssa::construct_ssa` to transform the program into Static Single Assignment form.
6.  **High Variable Construction**: Merge SSA versions into logical variables.
7.  **Optimization**: Call `optimization::optimize_function` to simplify the P-code iteratively.
8.  **Return**: Assemble the `FunctionAnalysis` struct.

---

## 2. Control Flow Graph (`mod.rs` :: `cfg`)

### `ControlFlowGraph::from_program`

**Signature**:
```rust
pub fn from_program(program: &Program) -> Result<Self>
```

**Inputs**:
*   `program`: The linear P-code program.

**Outputs**:
*   `ControlFlowGraph`: A struct containing a list of `BasicBlock`s and edge information.

**Algorithm**:
1.  **Identify Leaders**: Scan all operations to find block boundaries. An instruction is a leader if:
    *   It is the first instruction (Index 0).
    *   It is the target of a `BRANCH` or `CBRANCH`.
    *   It immediately follows a terminator (`BRANCH`, `RETURN`, `BRANCHIND`).
2.  **Create Blocks**:
    *   Sort leader indices.
    *   Slice the program operations between leader `i` and leader `i+1`.
    *   Create a `BasicBlock` for each slice.
3.  **Connect Blocks (Edge Generation)**:
    *   Iterate over blocks. Check the last operation:
    *   `BRANCH`: Add edge to the block containing the target address.
    *   `CBRANCH`: Add edge to the target block (True path) AND the next linear block (False/Fallthrough path).
    *   `BRANCHIND` (Indirect Jump): No successors added (treat as terminator to avoid falling through into unrelated code, e.g., PLT stubs).
    *   `RETURN`: No successors.
    *   Other: Add edge to the next linear block.

### `ControlFlowGraph::detect_loops`

**Signature**:
```rust
pub fn detect_loops(&self) -> Vec<Loop>
```

**Inputs**:
*   `self`: The initialized CFG.

**Outputs**:
*   `Vec<Loop>`: A list of detected loops with metadata.

**Algorithm**:
1.  **Dominator Tree**: Call `compute_dominators`.
2.  **Back Edge Detection**: Iterate all edges `A -> B`. If `B` dominates `A` (i.e., `B` is an ancestor of `A` in the dominator tree), this is a Back Edge. `B` is the **Header**. `A` is the **Latch**.
3.  **Body Discovery**: For each back edge `A -> B`:
    *   Initialize `body = {B}`.
    *   Perform a reverse BFS/DFS starting from `A` (predecessors), stopping if we hit `B`. Add visited blocks to `body`.
4.  **Classification**:
    *   **While**: Header has 2 successors.
    *   **Do-While**: Latch has 2 successors.
    *   **For**: Latch is distinct from Header, has 1 successor (the Header), and is not the only block in the body. The Latch is marked as the `increment` block.

### `ControlFlowGraph::identify_switches`

**Signature**:
```rust
pub fn identify_switches(&self, program: &Program) -> Vec<Switch>
```

**Inputs**:
*   `self`: The CFG.
*   `program`: The P-code program (needed to inspect instruction logic).

**Outputs**:
*   `Vec<Switch>`: Identified switch structures.

**Algorithm**:
1.  **Jump Table Detection**: Iterate blocks. If `successors.len() > 2`, assume resolved jump table. Create cases based on successor indices.
2.  **Cascaded If-Else Detection**:
    *   Iterate blocks. If a block ends in `CBRANCH`:
    *   Inspect the condition. Is it `INT_EQUAL(var, const)`?
    *   If yes, traverse the "False" edge. Check if the next block checks the **same variable**.
    *   Repeat chain traversal.
    *   If chain length >= 3, merge these blocks into a `Switch` struct.
    *   Calculate **Merge Point** (common post-dominator of all case targets).

---

## 3. Variable Recovery (`variables.rs`)

### `recover_variables`

**Signature**:
```rust
pub fn recover_variables(program: &Program, cfg: &ControlFlowGraph) -> Result<VariableAnalysis>
```

**Inputs**:
*   `program`: P-code instructions.
*   `cfg`: Control flow graph.

**Outputs**:
*   `VariableAnalysis`: Map of stack/register locations to logical variable IDs.

**Algorithm**:
1.  **Reachability Analysis**: Perform BFS on CFG starting from `entry`. Build a `HashSet` of reachable blocks. (Crucial for filtering out dead code after PLT stubs).
2.  **Stack Detection**: Call `detect_stack_variables(program, cfg, &reachable)`.
3.  **Register Detection**: Call `detect_register_variables(program, cfg, &reachable)`.
4.  **Storage Resolution**: Populate the lookup map `varnode_to_var`.

### `detect_stack_variables`

**Algorithm**:
1.  Iterate operations in **reachable** blocks only.
2.  **Pattern Match**:
    *   `Varnode` in `Stack` space: Record offset and size.
    *   `INT_ADD/SUB(RSP, Const)`: Record the effective stack offset.
3.  **Aggregation**: Collect all unique `(offset, size)` pairs.
4.  **Creation**: Create a `Variable` struct for each unique slot (e.g., `local_8`, `stack_10`).

---

## 4. Call Semantics (`calls.rs`)

### `recover_call_semantics`

**Signature**:
```rust
pub fn recover_call_semantics(program: &mut Program)
```

**Inputs**:
*   `program`: Mutable program.

**Outputs**:
*   None (Modifies `program` in-place).

**Algorithm**:
1.  Iterate all operations `i` from `0` to `end`.
2.  Check if `op.opcode` is `CALL` or `CALLIND`.
3.  **Return Value Injection**:
    *   If `op.output` is `None`: Set `op.output = Some(RAX)`. (RAX = Register 0, Size 8).
    *   *Reason*: Prevents DCE from killing the function call if the return value is used later.
4.  **Argument Injection**:
    *   List standard x86-64 argument registers: `RDI, RSI, RDX, RCX, R8, R9`.
    *   For each register: Check if it is already in `op.inputs`.
    *   If not, append it to `op.inputs`.
    *   *Reason*: Forces SSA/Liveness to see these registers as "consumed" by the call, preserving the instructions that set them up.

---

## 5. SSA Construction (`ssa.rs`)

### `construct_ssa`

**Signature**:
```rust
pub fn construct_ssa(cfg: &ControlFlowGraph, program: &mut Program) -> Result<SSAForm>
```

**Inputs**:
*   `cfg`: Control Flow Graph.
*   `program`: Mutable program (instructions will be modified to include version numbers).

**Outputs**:
*   `SSAForm`: Struct containing Phi nodes, definitions, and use-def chains.

**Algorithm**:
1.  **Dominance Frontiers**: Call `compute_dominance_frontiers`.
2.  **Variable Identification**: Scan all ops to find all unique storage locations (Variables).
3.  **Phi Placement**: Call `place_phi_nodes`.
4.  **Renaming**: Call `rename_variables`.

### `place_phi_nodes`

**Algorithm**:
1.  For each variable `v`:
    *   Find set `Defs(v)`: List of blocks where `v` is assigned.
    *   Initialize `Worklist = Defs(v)`.
    *   While `Worklist` not empty:
        *   Pop block `d`.
        *   For each block `f` in `DominanceFrontier(d)`:
            *   If `f` has no Phi for `v`:
                *   Insert `Phi(v)` at start of `f`.
                *   Add `f` to `Worklist` (Phi is a new definition).

### `rename_variables`

**Algorithm**:
1.  Initialize `Stacks`: Map from variable name to `Vec<version>`. Push `0` for all vars.
2.  Call recursive `rename_block(entry)`.

**`rename_block(b)`**:
1.  **Phi Defs**: For each Phi in `b`, generate new version `i`, push to stack. Record `Def(v_i) = b`.
2.  **Instructions**: Iterate ops in `b`.
    *   **Uses (Inputs)**: For each input `v`, read `current_version` from stack top. Update op input to `v_current`. Record `Use(v_current)`.
    *   **Defs (Outputs)**: For output `v`, generate new version `j`, push to stack. Update op output to `v_j`. Record `Def(v_j) = b`.
3.  **Successors**: For each successor `s` of `b`:
    *   Update Phi inputs in `s`. Find Phi for `v`, add parameter corresponding to version at stack top.
4.  **Recurse**: Call `rename_block` on children in Dominator Tree.
5.  **Cleanup**: Pop all versions pushed in step 1 and 2 from stacks.

---

## 6. Optimization (`optimization.rs`)

### `optimize_function`

**Signature**:
```rust
pub fn optimize_function(program: &mut Program, analysis: &FunctionAnalysis)
```

**Algorithm**:
1.  Initialize pipeline: `[ActionSimplify, ActionDeadCodeElimination]`.
2.  **Loop**:
    *   Run `ActionSimplify`. Returns `true` if changes made.
    *   Run `ActionDeadCodeElimination`. Returns `true` if changes made.
    *   If no changes in this iteration, **Break**.
    *   If iteration count > Limit, **Break**.

### `ActionDeadCodeElimination`

**Algorithm**:
1.  **Liveness Collection**:
    *   Iterate `analysis.ssa.uses`. Collect set `UsedVars`.
    *   (Note: Relies on `Call Semantics` to ensure function outputs are marked used if consumed by Return/Call).
2.  **Sweep**:
    *   Iterate all operations in `program`.
    *   If `op.has_side_effects()` (STORE, CALL, RET), **Keep**.
    *   If `op.output` is in `UsedVars`, **Keep**.
    *   Else, **Remove** (Replace with `NOP`).