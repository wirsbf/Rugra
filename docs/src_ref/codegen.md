# Code Generation Module Reference

This document provides a rigorous function-level reference for `src/codegen/mod.rs`. This module translates the analyzed P-code IR and Control Flow Graph (CFG) into high-level C source code.

---

## 1. Main Entry Point

### `generate_c_code`

**Signature**:
```rust
pub fn generate_c_code(
    analysis: &FunctionAnalysis,
    program: &Program,
    binary: Option<&Binary>
) -> Result<String>
```

**Inputs**:
*   `analysis`: The results of the analysis phase (CFG, SSA, Variables, Types).
*   `program`: The optimized P-code program.
*   `binary`: The loaded binary (for symbol resolution).

**Outputs**:
*   `Result<String>`: The complete decompiled C function code.

**Algorithm**:
1.  **Structure Analysis**:
    *   Call `cfg.detect_loops()` to find natural loops.
    *   Call `cfg.identify_conditionals()` to find if-else blocks.
    *   Call `cfg.identify_switches(program)` to find switch-case structures.
2.  **Metadata Generation**:
    *   Resolve function name using `binary.get_function_name` or fall back to `func_ADDRESS`.
    *   Sanitize name (replace `.` with `_`).
    *   Infer return type (check if any `RETURN` op has inputs).
    *   Call `generate_function_signature`.
3.  **Body Generation**:
    *   Initialize `structured_blocks` set (tracks blocks already emitted).
    *   Mark all loop body blocks as "structured" initially to prevent duplicate emission during sequential traversal (loops handle their own bodies).
    *   Call `generate_structured_blocks` starting at Entry Block (0).
4.  **Assembly**:
    *   Combine Signature + Variable Declarations + Body + `}`.

---

## 2. Structure Recovery

### `generate_structured_blocks`

**Signature**:
```rust
fn generate_structured_blocks(
    cfg: &ControlFlowGraph,
    program: &Program,
    analysis: &FunctionAnalysis,
    ...,
    start_block: usize,
    loops: &[Loop],
    conditionals: &[Conditional],
    switches: &[Switch],
    structured_blocks: &mut HashSet<usize>,
    ...
) -> String
```

**Inputs**:
*   `start_block`: The current block index to generate code for.
*   `structured_blocks`: Mutable set of visited blocks to prevent infinite recursion/duplication.

**Outputs**:
*   `String`: The C code for the control flow structure rooted at `start_block`.

**Algorithm**:
1.  **Loop Check**: Is `start_block` a loop header?
    *   **While**: Emit `while (cond) {`. Recurse for body. Emit `}`.
    *   **Do-While**: Emit `do {`. Recurse for body. Emit `} while (cond);`.
    *   **For**: Extract increment expression from latch block. Emit `for (; cond; inc) {`. Recurse for body. Emit `}`.
    *   *Recursion*: Call `generate_structured_blocks` for successors **inside** the loop body.
    *   *Next*: Call `generate_structured_blocks` for successors **outside** the loop (loop exit).
2.  **Conditional Check**: Is `start_block` an if-header?
    *   Emit `if (cond) {`.
    *   Recurse for `true_branch`.
    *   Emit `}`.
    *   If `false_branch` exists (and isn't the merge point), emit `else {`, recurse, emit `}`.
    *   *Next*: Jump to `merge_point` and continue generation.
3.  **Switch Check**: Is `start_block` a switch header?
    *   Emit `switch (expr) {`.
    *   For each case: Emit `case val:`. Recurse for case target block. Emit `break;`.
    *   Emit `}`.
    *   *Next*: Jump to `merge_point`.
4.  **Basic Block**: If no structure matches:
    *   Call `generate_block_content(start_block)`.
    *   Mark `start_block` as visited.
    *   Follow CFG edges:
        *   If 1 successor (fallthrough): Recurse.
        *   If 0 successors (Return): Stop.
        *   If jump to visited block (Back edge/Goto): Emit `goto label_X;`.

---

## 3. Statement Generation

### `generate_block_content` / `get_block_statements`

**Signature**:
```rust
fn get_block_statements(..., block_idx: usize, ...) -> Vec<ast::Statement>
```

**Inputs**:
*   `block_idx`: Index of the basic block.

**Outputs**:
*   `Vec<ast::Statement>`: List of C statements.

**Algorithm**:
1.  Iterate over all P-code operations in the block.
2.  **Filter Noise**:
    *   Skip `NOP` and `CBRANCH` (handled by structure recovery).
    *   **Stack Adjustment Filter**: Skip `INT_SUB` / `INT_ADD` on `RSP` (stack frame allocation).
    *   **Prologue Filter**: If Block 0, skip `STORE` operations where:
        *   The value is a callee-saved register (`RBX`, `RBP`, `R12`-`R15`).
        *   The pointer is `RSP` or a Stack Temporary.
        *   *Reason*: Hides `push rbp`, `push r15` etc.
3.  **Translation**: Call `pcode_to_statement` for the op.
4.  **Simplification**: Call `simplify_ast` to remove redundant assignments (e.g., `tmp = x; y = tmp` -> `y = x`).

### `pcode_to_statement`

**Signature**:
```rust
fn pcode_to_statement(op: &PcodeOperation, ...) -> Option<ast::Statement>
```

**Algorithm**:
*   **`COPY`**: `lhs = rhs;` (Assignment).
*   **`LOAD`**: `lhs = *ptr;` (Dereference).
*   **`STORE`**: `*ptr = val;` (Assignment).
*   **`INT_ADD`, etc**: `lhs = op1 + op2;`.
    *   Detects `lhs = lhs + op2` pattern -> `lhs += op2`.
*   **`CALL`**: `lhs = func(args...);` or `func(args...);`.
    *   **Name**: Sanitizes function name (replace `.` with `_`).
    *   **Arguments**: Iterates inputs[1..]. Calls `fold_expression` on each to inline temporary calculations.
*   **`RETURN`**: `return val;` or `return;`.
    *   Checks inputs[0]. If present, generates return value expression.

---

## 4. Expression Generation

### `varnode_to_expression`

**Signature**:
```rust
fn varnode_to_expression(vn: &Varnode, ...) -> ast::Expression
```

**Algorithm**:
1.  **High Variables**: Check `analysis.high_variables`. If mapped, return the high-level variable name (e.g., `iVar1`).
2.  **Recovered Variables**: Check `analysis.variables`. If mapped (Stack/Reg), return the recovered name (e.g., `local_8`, `param_1`).
3.  **Constants**:
    *   If valid address in binary -> Check if string literal exists -> Return string (`"hello"`).
    *   If function address -> Return function name.
    *   Else -> Return integer literal.
4.  **Registers**: If unmapped, return register name (`rax`).
5.  **Temporaries**: Return `uVarX`.

### `fold_expression`

**Signature**:
```rust
fn fold_expression(vn: &Varnode, ...) -> ast::Expression
```

**Inputs**:
*   `vn`: The variable to potentially expand.

**Outputs**:
*   `Expression`: The AST expression representing the variable's value.

**Algorithm**:
1.  Get base expression via `varnode_to_expression(vn)`.
2.  **Check Foldability**: Is `vn` a temporary (`Unique`) or SSA-versioned variable?
3.  **Lookup Definition**: Find the P-code operation that defined `vn` (using `SSAForm` definitions).
4.  **Expand**:
    *   If defined by `INT_ADD(a, b)`: Return `BinaryExpr(fold(a) + fold(b))`.
    *   If defined by `LOAD(ptr)`: Return `UnaryExpr(*fold(ptr))`.
    *   If defined by `PTR_ADD(base, offset)`: Return field access `base->field` (if type info exists) or array index `base[idx]`.
5.  *Recursion Limit*: Implicitly bounded by the depth of the SSA graph slice.

---

## 5. Metadata

### `generate_function_signature`

**Algorithm**:
1.  Start with `ret_type func_name(`.
2.  Collect parameters from `VariableAnalysis` or `HighVariableMap`.
3.  Sort by storage/index.
4.  Append `type name` for each param, separated by commas.
5.  End with `) {`.

### `generate_variable_declarations`

**Algorithm**:
1.  Iterate all recovered variables.
2.  Check if variable name is in `used_names` set (populated during body generation).
3.  If used, emit declaration `type name;\n`.