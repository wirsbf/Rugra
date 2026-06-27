# `expression.rs` API Reference

**源代码路径**: `src/expression.rs`
**Ghidra 对应**: `expression.hh` / `expression.cc`
**状态**: 🔧 L2（TermOrder/AdditiveEdge/AddExpression 已实现，解锁 RuleCollectTerms 等）

## 模块说明

表达式分析基础设施，用于加法表达式树的项收集、排序和等价匹配。
对应 Ghidra 的 `expression.hh`。

## 导出的公共 API

### `pub struct AdditiveEdge`
加法表达式中的一个项。对应 Ghidra `AdditiveEdge`。
- `op: Arc<RwLock<PcodeOp>>` — 读取该 term 的 op
- `slot: usize` — 输入槽位
- `vn: Arc<RwLock<Varnode>>` — 该 term 的 varnode
- `mult: Option<Arc<RwLock<PcodeOp>>>` — 可选的乘法 op

### `pub struct TermOrder`
加法表达式项排序器。对应 Ghidra `TermOrder`。
- `new(root)` — 以 INT_ADD root op 构造
- `collect()` — 遍历 ADD/MULT 链收集所有项（expression.cc:236-283）
- `sort_terms()` — 按项排序（expression.cc:285-293）
- `get_sort()` / `get_term(idx)` — 访问排序结果

### `pub struct AddExpression`
轻量级加法表达式匹配（最多 2 项 + 常量）。对应 Ghidra `AddExpression`。
- `gather_two_terms_subtract(a, b)` — 从两个相减根收集（expression.cc:368）
- `gather_two_terms_add(a, b)` — 从两个相加根收集（expression.cc:379）
- `gather_two_terms_root(root)` — 从单个根收集（expression.cc:389）
- `is_equivalent(other)` — 判断两表达式是否等价（expression.cc:309）

测试：expression::tests 2 个（常量折叠、等价匹配）。

## 2026-06-27（续）：functional_equality_level — expression.cc:404-512

完整移植 Ghidra 的 `functionalEqualityLevel`（值相等性分析）。

### `pub fn functional_equality_level(vn1, vn2) -> FunctionalEqualityResult`
尝试判断两个 Varnode 是否持有相同值。忠实移植 expression.cc:432-512。
- 返回 `code == -1`：不相等 / 无法立即验证
- 返回 `code == 0`：确定相等
- 返回 `code > 0`： contingent（取决于 `pairs` 中的 varnode 对是否相等）

### `pub struct FunctionalEqualityResult`
- `code: i32` — 相等性代码
- `pairs: Vec<(vn1, vn2)>` — 需要匹配的 varnode 对

### 算法细节
- **Level 0**（`functional_equality_level0`）：相同指针→0；不同大小→-1；都是常量→比较 offset；free→-1；其他→1。
- **深层比较**：两者都必须 written，定义 op 必须相同 opcode、相同输入数、非 marker、非 call。LOAD 需要相同指令地址。PTRADD 检查 slot 2（元素大小）。
- **交换律**：对可交换运算符（INT_ADD/INT_MULT/INT_XOR/INT_AND/INT_OR），尝试翻转输入对匹配。
- 用于 `ActionMultiCse::findMatch`（coreaction.cc:807）和 `ActionBlockStructure` 的 CSE 检测（blockaction.cc:1936）。

测试：expression::tests 新增 5 个（same_pointer/constants_equal/constants_unequal/different_sizes/free_varnodes）。

## 2026-06-27（续 2）：BooleanMatch — expression.cc:57-216

完整移植 Ghidra 的 `BooleanMatch`（布尔值相关性分析）。

### `pub fn boolean_match_evaluate(vn1, vn2, depth) -> i32`
判断两个布尔 Varnode 是否持有相关值。忠实移植 expression.cc:111-216。
返回 `boolean_match::SAME`(1) / `COMPLEMENTARY`(2) / `UNCORRELATED`(3)。

### `pub mod boolean_match`
常量：`SAME = 1`, `COMPLEMENTARY = 2`, `UNCORRELATED = 3`。

### 算法细节
- **BOOL_NEGATE 递归**：如果任一 vn 由 BOOL_NOT 定义，递归评估并翻转结果（same↔complementary）。
- **BOOL_AND/OR/XOR 递归**：对深度 > 0，递归评估输入对，应用德摩根律。
- **直接比较**：相同 opcode → varnodeSame 检查所有输入 → same；sameOpComplement 检查 x<n, n-1<x 模式 → complementary。
- **翻转比较**：get_booleanflip 检查互补运算符对（INT_EQUAL/INT_NOTEQUAL, INT_LESS/INT_LESSEQUAL 等）。

### 辅助函数
- `varnode_same(a, b)` — expression.cc:93-100：相同指针或相同常量值。
- `same_op_complement(bin1op, bin2op)` — expression.cc:57-86：检查 INT_LESS/INT_SLESS 的 x<n, n-1<x 互补模式。

测试：expression::tests 新增 3 个（same_pointer/uncorrelated_constants/complement_via_flip）。
解锁 RuleBooleanUndistribute/RuleBooleanDedup 的完整 De Morgan 定律实现。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
