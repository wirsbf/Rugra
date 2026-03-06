# `printc.rs` API Reference (C 语言代码生成器)

**源代码路径**: `src/printc.rs`

## 模块说明 (Module Doc)

对应 Ghidra `printc.hh` / `printc.cc`。这是反编译最终产物的核心制造车间——将经过 SSA 优化和结构化恢复后的高级 IR **转化为人类可读的 C 语言源代码**。

---

## 导出的公共 API (Public API)

### `pub struct PrintC` (C 语言打印器)

实现了 `PrintLanguage` Trait，通过内嵌的 `Emit` 后端发射 C 代码 Token，是整个反编译管道的最终输出阶段。

#### 核心方法

*   `doc_function(&mut self, fd: &Funcdata)`: **入口方法**。接收一个完整的函数分析容器并输出完整的 C 函数定义：
    1. 发射函数签名 (`void func_name()`)。
    2. 打开花括号域。
    3. 遍历所有基本块中的所有操作，逐条调用 `doc_statement()`。
    4. 关闭花括号域。

*   `doc_statement(&mut self, op: &PcodeOp)`: 将单条 P-code 操作转化为一条 C 语句（含末尾分号），内部委派到各 `op_xxx` 方法。

#### 各操作码的 C 语义发射

*   `op_copy`: `out = in0;`
*   `op_load`: `out = *ptr;`
*   `op_store`: `*ptr = val;`
*   `op_binary`: `out = in0 OP in1;` — 支持 `+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`, `<<`, `>>`, `==`, `!=`, `<`, `<=`, `&&`, `||` 等全量二元运算符映射。
*   `op_unary`: `out = OP in0;` — 支持 `~`, `-`, `!` 等一元运算符。
*   `op_multiequal`: `out = phi(in0, in1, ...);` — SSA Phi 节点的调试级输出。
*   `op_call`: `[out =] callee(arg1, arg2, ...);`
*   `op_return`: `return [val];`

#### 辅助方法

*   `push_type(&mut self, dt: &Datatype)`: 发射类型名 Token。
*   `push_varnode(&mut self, vn: &Varnode, op)`: 将 Varnode 转化为变量名 Token（当前格式为 `v_SIZE_OFFSET`，后续将接入 HighVariable 符号查询）。
