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
