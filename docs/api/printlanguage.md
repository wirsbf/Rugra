# `printlanguage.rs` API Reference

## 文档状态

- **状态**: 🔧 **L2（2026-08-12）**——`PRINT-RPN-0001A` 已用锁定
  12.0.4 `PrintLanguage::pushOp/pushAtom` 运行时 fixture 证明 root unary/binary、
  无括号嵌套和必须括号嵌套的**可见纯文本**为 `MATCH`。token 表、完整递归、
  exact group ID/queue、真实 op/vn/type/highlight/field/case payload、namespace
  策略及多个虚方法仍为 `UNTESTED/MISMATCH`，模块保持 L2。

**源代码路径**: `src/printlanguage.rs`

## 模块说明 (Module Doc)

Base language printing interface — Reverse Polish Notation (RPN) engine.

对应 Ghidra 的 `printlanguage.hh` / `printlanguage.cc`。本模块移植了共享基类 `PrintLanguage` 的基础设施：RPN token 栈、运算符优先级/括号化算法、Atom/OpToken 数据类型，以及格式化工具。

Rugra 的 `PrintC` 目前为了输出质量直接通过 `Emit` 发射；本模块只提供了部分 Ghidra 基类算法接口：
1. 括号化算法（`parentheses()`）可作为 1:1 参考使用。
2. RPN 数据类型（`OpToken`/`ReversePolish`/`Atom`/`NodePending`）作为 Ghidra 对齐的规范定义存在。
3. 纯格式化工具可以针对 Ghidra 行为进行单元测试。

## Ghidra 对应关系

| Ghidra (printlanguage.cc/hh) | Rugra (printlanguage.rs) | 行号 |
|---|---|---|
| `PrintLanguage::modifiers` enum | `modifiers` mod (FORCE_HEX..PENDING_BRACE) | hh:144 |
| `PrintLanguage::tagtype` enum | `TagType` enum | hh:163 |
| `PrintLanguage::namespace_strategy` enum | `NamespaceStrategy` enum | hh:175 |
| `OpToken::tokentype` enum | `TokenType` enum | hh:87 |
| `EmitMarkup::syntax_highlight` enum | `SyntaxHighlight` enum | prettyprint.hh |
| `OpToken` class | `OpToken` struct + constructors | hh:84 |
| `PrintLanguage::ReversePolish` struct | `ReversePolish` struct | hh:182 |
| `PrintLanguage::NodePending` struct | `NodePending` struct | hh:195 |
| `PrintLanguage::Atom` struct | `Atom` struct + `AtomPayload` enum | hh:210 |
| `PrintLanguageCapability` class | `PrintLanguageCapability` struct | hh:42 |
| `PrintLanguage::parentheses` | `parentheses()` fn | cc:269 |
| `PrintLanguage::unicodeNeedsEscape` | `unicode_needs_escape()` fn | cc:411 |
| `PrintLanguage::mostNaturalBase` | `most_natural_base()` fn | cc:731 |
| `PrintLanguage::formatBinary` | `format_binary()` fn | cc:793 |
| `PrintLanguage::unnamedField` | `unnamed_field()` fn | cc:719 |
| `PrintLanguage::setIntegerFormat` | `apply_integer_format()` fn | cc:698 |
| `PrintLanguage::pushAtom` | `rpn_push_atom()` fn | cc:162 |
| `PrintLanguage::pushOp` | `rpn_push_op()` fn | cc:129 |
| `PrintLanguage::emitOp` | `rpn_emit_op()` fn | cc:328 |
| `PrintLanguage::emitAtom` | `rpn_emit_atom()` fn | cc:375 |
| `PrintLanguage::recurse` | `rpn_recurse()` fn | cc:514 |
| `PrintLanguage::pushVn` | `rpn_push_vn()` fn | cc:197 |
| `PrintLanguage::opBinary` | `rpn_op_binary()` fn | cc:546 |
| `PrintLanguage::opUnary` | `rpn_op_unary()` fn | cc:566 |
| `PrintLanguage::resetDefaultsInternal` | `reset_defaults_internal_state()` fn | cc:575 |
| `OPEN_PAREN`/`CLOSE_PAREN` consts | `OPEN_PAREN`/`CLOSE_PAREN` consts | cc:22 |

## 导出的公共 API (Public API)

### 枚举与常量

- `pub mod modifiers` — 打印修改标志位掩码（FORCE_HEX=1..PENDING_BRACE=0x8000）
- `pub enum TagType` — Atom 类型（Syntax/VarToken/FunToken/OpToken/TypeToken/FieldToken/CaseToken/BlankToken）
- `pub enum NamespaceStrategy` — 命名空间显示策略（Minimal/NoNamespaces/AllNamespaces）
- `pub enum TokenType` — 运算符 token 类型（Binary/UnaryPrefix/Postsurround/Presurround/Space/HiddenFunction）
- `pub enum SyntaxHighlight` — 语法高亮颜色标签
- `pub const OPEN_PAREN: &str = "("`
- `pub const CLOSE_PAREN: &str = ")"`

### 数据结构

- `pub struct OpToken` — 运算符 token（print1/print2/stage/precedence/associative/type_/spacing/bump/negate）+ 6 个构造器（`binary`/`unary_prefix`/`postsurround`/`presurround`/`space`/`hidden_function`）
- `pub struct ReversePolish` — RPN 栈条目（tok_index/visited/paren/op_index/id/id2）
- `pub struct NodePending` — 待处理数据流节点 + `NodePending::new()`
- `pub struct Atom` + `pub enum AtomPayload` — 非运算符 token + 7 个构造器（`new`/`with_type`/`with_field`/`with_op`/`with_op_vn`/`with_op_fd`/`with_op_vn_int`）
- `pub struct PrintLanguageCapability` — 语言能力注册对象 + `new()`/`get_name()`

### RPN 引擎函数

- `pub fn parentheses(top: &OpToken, stage: i32, op2: &OpToken, prev: Option<&OpToken>) -> bool` — 括号化判定（cc:269-323）。`prev` = `revpol[size-2].tok` 的 token（None 编码 `revpol.size()<=1`），仅 hiddenfunction 分支读取（cc:309-319，2026-08-17 审计修复：原硬编码 `true` 改为按祖父 token 类型/优先级精确判定）
- `pub fn rpn_push_op(...)` — 运算符入栈（cc:129）
- `pub fn rpn_push_atom(...)` — Atom 入栈（cc:162）
- `pub fn rpn_push_vn(...)` — 隐含 Varnode 入待处理列表（cc:197）
- `pub fn rpn_emit_op(...)` — 运算符发射（cc:328）
- `pub fn rpn_emit_atom(...)` — Atom 发射（cc:375）
- `pub fn rpn_recurse(...)` — RPN 递归发射（cc:514）
- `pub fn rpn_op_binary(...)` — 二元运算符推送（cc:546）
- `pub fn rpn_op_unary(...)` — 一元运算符推送（cc:566）

`rpn_push_op` 现在严格区分可见括号与不可见打印组：root 表达式及不需要
括号的子表达式调用 `Emit::open_group/close_group`，不会再把 Ghidra 的
`openGroup()` 错发成字符 `(`。需要保持求值顺序的子表达式仍调用
`open_paren/close_paren`。

### 12.0.4 oracle：`PRINT-RPN-0001A`

运行 `tools/run_printlanguage_group_oracle.sh` 会分别执行锁定 Ghidra 与 Rugra，
并对 stdout 做无规范化 direct diff。四个已覆盖结果为：

```text
root_unary=!x
root_binary=a + b
nested_invisible=a + b * c
nested_parenthesized=a * (b + c)
```

这些 case 的 visible-text 状态为 `MATCH`；fixture overall 仍是 `UNTESTED`，
因为 `EmitPrettyPrint` 的 TokenSplit 队列、exact group ID、换行和 markup payload
尚未观察。完整 provenance 位于
`tests/oracle/printlanguage_group_1204.metadata.json`。

### 格式化工具

- `pub fn unicode_needs_escape(codepoint: i32) -> bool` — Unicode 是否需要转义（cc:411）
- `pub fn most_natural_base(val: u64) -> i32` — 最自然进制选择（cc:731）
- `pub fn format_binary(val: u64) -> String` — 二进制格式化（cc:793）
- `pub fn unnamed_field(off: i32, size: i32) -> String` — 人工字段名生成（cc:719）
- `pub fn apply_integer_format(mods: &mut u32, nm: &str) -> Result<(), String>` — 整数格式修改器应用（cc:698）
- `pub fn reset_defaults_internal_state(...)` — 默认值重置（cc:575）
- `pub fn escape_character_data(buf: &[u8], charsize: usize) -> String` — 字符串转义（遗留兼容）

### 遗留 Trait

- `pub trait PrintLanguage` — 遗留 trait shim，保持 `printc.rs` 的 `impl PrintLanguage for PrintC` 编译。新代码应使用上述自由函数与数据类型。

<!-- annotation-pass: 2026-07-22 -->
