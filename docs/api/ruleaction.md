# `ruleaction.rs` API Reference (局部优化规则集)

**源代码路径**: `src/ruleaction.rs`

## 模块说明 (Module Doc)

对应 Ghidra `ruleaction.hh`。本文件收录了所有**小粒度、单操作码级别**的 IR 简化/优化规则。每个规则实现 `Rule` Trait，只在匹配的操作码上被触发，执行局部模式匹配+就地改写。

---

## 导出的公共 API (Public API)

### `pub struct RuleCollapseConstants` (常量折叠规则)

**触发操作码**: `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_AND`, `INT_OR`, `INT_XOR`

**逻辑**: 若一条二元运算的**两个输入全部为常量** Varnode，则直接在编译期计算出结果，将该操作替换为 `CPUI_COPY` 加一个常量 Varnode。

---

### `pub struct RuleTrivialBool` (布尔恒等消除规则)

**触发操作码**: `BOOL_AND`, `BOOL_OR`, `BOOL_XOR`

**逻辑**: 识别布尔恒等式并简化：
*   `x && true` → `x` (COPY)
*   `x || false` → `x` (COPY)
*   `x ^^ false` → `x` (COPY)

---

### `pub struct RulePropagateCopy` (COPY 传播规则)

**触发操作码**: `CPUI_COPY`

**逻辑**: 如果一条 COPY 操作 `out = in`，则将所有使用 `out` 的下游操作的对应输入直接替换为 `in`，消除冗余的中间赋值。同时更新 `descend` 引用列表。

---

### `pub struct RuleZextEliminate` (零扩展消除规则)

**触发操作码**: `CPUI_INT_ZEXT`

**逻辑**: 如果 `ZEXT` 的输入大小与输出大小完全相同（即扩展为 0 位），则将其降级为 `CPUI_COPY`。
