# `analysis/` API Reference (分析管道总览)

**源代码路径**: `src/analysis/`

## 模块说明 (Module Doc)

本子目录收录了反编译管道中**所有高级分析算法**的旧版实现（基于 `pcode::Program` API）。
包括控制流图构建、数据流分析、SSA 构造、类型推断、变量恢复、生存分析等。

---

## 子模块导航

### `mod.rs` (入口与主分析管道)

*   **`pub struct FunctionAnalysis`**: 分析结果总容器，聚合 CFG、DataFlow、SSA、TypeInfo、Variables、HighVariables、TypeSolver、TypeInference、Liveness 等可选分析产物。
*   `pub fn analyze_function(program, binary) -> Result<FunctionAnalysis>`: **主入口**。按序执行 CFG 构建 → 数据流分析 → SSA 构造 → 优化 → 类型推断 → 变量恢复。
*   内联定义了 `mod cfg` (控制流图构建)、`mod dataflow` (数据流分析)、`mod types` (类型分析) 等子模块。

### `ssa.rs` (SSA 构造)

旧版基于 `Program` 的 SSA 构造实现（`SSAForm`, `SSAVarnode`），已被 Ghidra 对齐层的 `heritage.rs` 策略性替代。

### `variables.rs` (变量恢复)

栈变量识别、寄存器变量追踪、变量命名策略。

### `type_inference.rs` (约束式类型推断)

基于类型格子的约束收集与求解。

### `type_propagation.rs` (类型传播求解器)

`TypeSolver`：约束驱动的全局类型传播引擎。

### `high_variable.rs` (高级变量映射)

`HighVariableMap`：将 SSA 版本合并为逻辑变量的映射管理。

### `liveness.rs` (生存分析)

变量活跃区间计算，服务于变量合并决策。

### `optimization.rs` (IR 优化)

常量折叠、死代码消除、复制传播等旧版优化 Pass。

### `calls.rs` (调用分析)

函数调用点的参数/返回值恢复。

### `rules/` (分析规则子目录)

*   `algebra.rs`: 代数化简规则。
*   `constants.rs`: 常量折叠/评估引擎（含 `evaluate_constant_op`）。
*   `dataflow.rs`: 数据流相关规则。

### `api/mod.rs`

公开 API 层，用于外部调用分析功能。
