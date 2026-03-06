# 代码生成模块技术参考 (Code Generation)

本文档提供了 `src/codegen/mod.rs` 的结构级别技术规范。该模块负责将分析完毕的 P-code 中间表示与控制流图（CFG）最终翻译回高级的 C 源语言代码。

---

## 1. 顶层入口调度

### `generate_c_code`

**签名**:
```rust
pub fn generate_c_code(
    analysis: &FunctionAnalysis,
    program: &Program,
    binary: Option<&Binary>
) -> Result<String>
```

**输入**:
*   `analysis`: 分析阶段成果（包括 CFG、SSA、变量定义与类型推断）。
*   `program`: 原始或经优化的 P-code 线性切片程序。
*   `binary`: 可选二进制句柄（用于符号解析）。

**完整流程**:
1.  **控制流结构解析 (Structure Analysis)**:
    *   通过 `cfg.detect_loops()` 寻找自然循环。
    *   通过 `cfg.identify_conditionals()` 探查 if-else 块组。
    *   通过 `cfg.identify_switches(program)` 鉴别 switch-case 代码结构。
2.  **函数元数据生成 (Metadata Generation)**:
    *   解析函数名（依赖符号表，否则 fallback 为 `func_地址`），过滤非法符号如小数点。
    *   推断返回类型，利用 `generate_function_signature` 拼凑出 C 签名。
3.  **块体代码生成 (Body Generation)**:
    *   初始化 `structured_blocks` 哈希集以跟踪已经完成生成的结构块。
    *   从 Entry (块 0) 开始调用 `generate_structured_blocks` 递归组装。为了防止多次生成，内层循环块自身在最初即标记为“已被结构化安排”。
4.  **组装 (Assembly)**: 连接签名、推导出的本地变量声明、块体内容并包上 `}`。

---

## 2. 结构重组与还原 (Structure Recovery)

### `generate_structured_blocks`

该递归函数用于吐出特定控制流结构所嵌套的 C 代码。

**核心分发逻辑**:
1.  **循环探测 (Loop Check)**: 若起始块 `start_block` 是某个循环结构的头部 (Header)：
    *   **While / For**: 生成 `while (cond) {` -> 遍历体块 -> `}` (目前源码对侦测出的 For 循环结构统一降级使用 while 输出)。
    *   **Do-While**: 生成 `do {` -> 遍历体块 -> `} while (cond);`。
    *   最后跳到循环外的汇聚块并继续递归处理。
2.  **条件重组 (Conditional Check)**: 
    *   遇到普通条件判定：生成 `if (cond) {` 进真分支，接着判断是否有 `else {` 进入假分支（如果假分支不是共同合流点 Merge Point 的话），最后跳往合并块继续。
3.  **普通基本块转义 (Basic Block)**:
    *   所有结构都不命中的线性块，执行 `generate_block_content` 产生单块的具体计算表达式序列，顺着单出边（Fallthrough）往下递归生成。
    *   *(注：当前分支暂未在转译核心落实基于分析层已标识 `Switch` 结构的对应 C 代码 `switch (expr)` 语句的精确还原输出)*。

---

## 3. 语句和表达式翻译 (Statement & Expression)

### `pcode_to_statement`

将粗粒度的 P-code 直译为带分号的 C `ast::Statement`:
*   **`COPY`**: 转换赋值 `lhs = rhs;` 
*   **`LOAD` / `STORE`**: 解析带有解引用特征的 `*ptr` 行为。
*   **计算类 / `INT_ADD`等**: 若探测到左右侧寄存器重叠，会自动折叠为缩写式，例如 `lhs += op2`。
*   **`CALL`**: 通过函数符号与提取得到的入参，调用 `fold_expression`，将其全部翻译拼接。

### `fold_expression` (内联折叠)

利用推导图和依赖关系：将一些为了底层存取方便而引入的独有变量（`Unique/Temporaries`）和中间版号多引入的废料语句缩短折叠：
如 `INT_ADD(a, b)` 被内联后作为 `fold(a) + fold(b)`，或将 `PTR_ADD(base, offset)` 强翻译回对结构体成员/数组下标的 `base->field` 或 `base[idx]` 的操作。

---

## 4. 元数据声明生成 (Metadata Generation)

**`generate_variable_declarations` 逻辑**:
在函数代码实体之前，检索之前确立的恢复变量组，如果检查它们在函数内被实际以各种形式使用过（在 `used_names` 集合中），才最终向代码开头吐出形如 `type name;\n` 的 C 层级前置声明语句。