# `typeop.rs` API Reference (操作码语义类型模型)

**源代码路径**: `src/typeop.rs`

## 模块说明 (Module Doc)

对应 Ghidra `typeop.hh`。本文件为每一种 P-code 操作码赋予**类型级语义行为**——它不关心操作码"怎么算"，而是回答三件事：
1. 该操作的输出应推导出什么类型？（`get_output_local`）
2. 该操作的第 N 个输入应该是什么类型？（`get_input_local`）
3. 该操作在打印时应该走哪条路径？（`push` → 委派到 `PrintLanguage` 的具体 `op_xxx` 方法）

这是类型传播引擎和代码生成器之间的**桥梁层**。

---

## 导出的公共 API (Public API)

### `pub trait TypeOp` (操作类型行为契约)

所有操作码类型行为的统一接口：
*   `fn get_opcode(&self) -> OpCode`: 返回对应操作码。
*   `fn get_name(&self) -> &str`: 人类可读名称（如 `"INT_ADD"`）。
*   `fn get_flags(&self) -> u32`: 属性标志（算术/逻辑/浮点/移位等）。
*   `fn print_raw(&self, op: &PcodeOp) -> String`: 原始文本格式输出（调试用）。
*   `fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp)`: 将自身委派给打印语言发射器。
*   `fn get_output_local(...)` / `fn get_input_local(...)`: 类型推导挂钩。

### `pub mod typeop_flags` (操作属性标志)

*   `INHERITS_SIGN` / `INHERITS_SIGN_ZERO`: 该操作会继承输入的有符号/无符号性。
*   `SHIFT_OP` / `ARITHMETIC_OP` / `LOGICAL_OP` / `FLOATINGPOINT_OP`: 操作分类标志。

---

### 基类结构体

*   **`TypeOpBinary`**: 通用二元操作基类，格式 `out = in0 OP in1`。
*   **`TypeOpUnary`**: 通用一元操作基类，格式 `out = OP in0`。

### 宏生成的具体实现（约 50+ 个结构体）

通过 `binary_op!`、`unary_op!`、`functional_unary_op!`、`functional_binary_op!` 四套宏批量展开：

| 分类 | 代表结构体 | 操作码 |
|------|-----------|--------|
| 算术 | `TypeOpIntAdd`, `TypeOpIntSub`, `TypeOpIntMult`, `TypeOpIntDiv` 等 | `+`, `-`, `*`, `/` |
| 位运算 | `TypeOpIntAnd`, `TypeOpIntOr`, `TypeOpIntXor`, `TypeOpIntNot` | `&`, `|`, `^`, `~` |
| 移位 | `TypeOpIntLeft`, `TypeOpIntRight`, `TypeOpIntSright` | `<<`, `>>`, `s>>` |
| 比较 | `TypeOpIntEqual`, `TypeOpIntLess`, `TypeOpIntSless` 等 | `==`, `<`, `s<` |
| 扩展 | `TypeOpIntZext`, `TypeOpIntSext`, `TypeOpTrunc` | `zext()`, `sext()` |
| 浮点 | `TypeOpFloatAdd` ~ `TypeOpFloatRound` 全系列 | `f+`, `f-`, `fsqrt()` 等 |
| 布尔 | `TypeOpBoolAnd`, `TypeOpBoolOr`, `TypeOpBoolNot` | `&&`, `||`, `!` |
| 特殊 | `TypeOpPiece`, `TypeOpSubpiece`, `TypeOpPopcount`, `TypeOpLzcount` | 拼接/截取/位计数 |
| 控制流 | `TypeOpBranch`, `TypeOpCbranch`, `TypeOpCall` 等 | goto/if/call/return |

### 手写的特殊操作

*   **`TypeOpCopy`**: 直接赋值，类型从输入继承到输出。
*   **`TypeOpLoad`**: 内存读取，输出类型尝试从指针输入的 pointee 推导。
*   **`TypeOpStore`**: 内存写入，被写入值的类型从指针的 pointee 推导。
*   **`TypeOpMultiequal`** / **`TypeOpIndirect`** / **`TypeOpCall`** / **`TypeOpReturn`**: 控制流和副作用操作。
