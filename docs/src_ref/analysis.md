# 分析模块技术参考 (Analysis Module)

本文档提供了 `src/analysis` 模块核心函数的结构级别技术说明。该模块主要负责构建控制流图、解析变量、生成和优化 P-code 程序的 SSA（静态单赋值）形式。

---

## 1. 分析调度器 (`mod.rs`)

### `analyze_function`

**签名**:
```rust
pub fn analyze_function(program: &mut Program, binary: Option<&Binary>) -> Result<FunctionAnalysis>
```

**输入**:
*   `program`: 指向 P-code `Program` 的可变引用，用于原地构造 SSA 或优化。
*   `binary`: 可选的 `Binary` 引用，用于在类型推导阶段查询符号。

**输出**:
*   `Result<FunctionAnalysis>`: 返回包含了 CFG、SSA 形式、变量定义及类型的分析特征集合构造体。

**算法步骤**:
1.  **CFG 构建**: 调用 `ControlFlowGraph::from_program` 构建基本块。
2.  **变量恢复**:
    *   通过对 CFG 的 BFS 遍历计算可达图块。
    *   调用 `recover_variables` 识别寄存器和栈上的变量。
3.  **调用语义解析**: 调用 `calls::recover_call_semantics` 将 ABI 相关的参数或者返回值写入被分析的 `CALL` 操作指令中。
4.  **类型推导**: 执行 `type_inference::infer_types`。
5.  **SSA 构建**: 执行 `ssa::construct_ssa` 生成 P-code 程序的 SSA（静态单赋值）形式表示。
6.  **高级变量组装**: 将多版本 SSA 合并推导为逻辑变量。
7.  **迭代优化**: 利用 `optimization::optimize_function` 对 P-code 进行进一步简化和消除。
8.  返回拼装好的 `FunctionAnalysis` 结构体。

---

## 2. 控制流图 / CFG (`mod.rs` :: `cfg`)

### `ControlFlowGraph::from_program`

**算法要点**:
1.  **定位头指令 (Leaders)**: 首指令、`BRANCH`或`CBRANCH`目标、跳跃或返回等终止符后的首指令。
2.  **划分基本块**: 对序列指令按照头指令所在位置进行切片切割。
3.  **连接边 (Edges)**: 
    * `BRANCH` 连接到目标地址所在块。
    * `CBRANCH` 连接目标块（真分支）与下一条线性块（假分支）。

### `ControlFlowGraph::detect_loops`

根据计算出的支配树 (Dominator Tree)，搜索图中所有的**回边 (Back Edge)** 来探测各类循环（如 While、Do-While、For等），并在分析其闭环分支（Latch/Header）后注入相关的元数据。

### `ControlFlowGraph::identify_switches`

通过分析是否有超过2条出边来探测基于“跳转表”(Jump Table) 的 Switch。
对于多层嵌套验证判定（如 `INT_EQUAL(var, const)`）的 if-else 链，如果同一个变量检测超过三次以上，则将其合并转换为一个更高级的 `Switch` 逻辑块。

---

## 3. 变量恢复 (`variables.rs`)

### `recover_variables`

结合 CFG 的图连通性与 P-code 的指令形式，遍历**可达图块 (Reachable Blocks)** ：
1.  `Stack Detection`：识别指向 Stack 空间的 Varnode，或解析形如 `INT_ADD/SUB(RSP, Const)` 形式的等效指针操作。
2.  组合并去重所有发现的局部栈槽和寄存器碎片记录，构建为后续 SSA 用到的基础 `Variable` 对象（例如：`local_8`, `stack_10`）。

---

## 4. 分析优化 (`optimization.rs`)

### `optimize_function`

结合 Liveness 分析图和依赖关系执行以下迭代清洗（死代码消除 / 简单恒等代数化简）：
1. 循环执行 `ActionSimplify` 与 `ActionDeadCodeElimination`。
2. 对于 `ActionDeadCodeElimination` (死代码消除)：
   * 保留具有**副作用**的指令 (STORE, CALL, RET)。
   * 若非副作用指令的输出在 `UsedVars` (有效消耗列表) 内，保留。
   * 其他的标记并剔除 (替换成 `NOP`)。