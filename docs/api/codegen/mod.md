# `codegen/` API Reference (C 代码生成器)

**源代码路径**: `src/codegen/`

## 模块说明 (Module Doc)

反编译管道的**最终输出阶段**（旧版 API）。接收分析完成的 `FunctionAnalysis` 和 `Program`，生成结构化的 C 语言源代码字符串。

---

## 导出的公共 API (Public API)

### `pub fn generate_c_code(analysis, program, binary) -> Result<String>`

**主入口函数**。按以下步骤生成 C 代码：
1. 生成函数签名（类型+名称+参数列表）。
2. 生成局部变量声明。
3. 利用 CFG 的循环检测 (`detect_loops`)、条件识别 (`identify_conditionals`)、switch 识别 (`identify_switches`) 结果生成结构化的函数体。

### 内部模块

*   `mod formatter`: C 代码格式化器，处理缩进、运算符优先级、表达式折叠等。
*   循环结构 (`while/do-while/for/goto`) 和条件结构 (`if/else`) 的模板化生成。
*   表达式树的递归发射（含运算符符号映射、常量格式化、字符串字面量恢复等）。
