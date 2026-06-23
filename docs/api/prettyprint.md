# `prettyprint.rs` API Reference

## 文档状态

- **状态**: 已核对（当前有效）
- **对应源码**: 当前 `rugra/src/prettyprint.rs`

**源代码路径**: `src/prettyprint.rs`

## 模块说明 (Module Doc)

Pretty printing and token emission

Corresponds to Ghidra's `prettyprint.hh`

## 导出的公共 API (Public API)

### `pub trait Emit`

Trait for emitting decompilation tokens

This provides a generic interface for "printing" decompiled code,
allowing for different output formats (plain text, XML, HTML with markup, etc.)

### `pub struct EmitNoMarkup`

Simple emitter that produces plain text with no markup

### `pub fn new() -> Self`

创建并初始化一个不带任何标记的 `EmitNoMarkup` 纯文本发射器。

### `pub fn get_output(self) -> String`

获取发射器缓存的最终格式化 C 代码字符串，同时消费该发射器实例。
在该方法内部，发射器会对收集到的原始行序列进行**多达 15 趟的后处理 Pass** 以极大改善输出质量。包括：
- **死代码消除**：如删除 `return;`/`break;` 后的不可达代码。
- **孤立控制流清理**：如合并连续重复的 `goto`、移除空 `else` 代码块的空行、重写 `return void()` 表达式等。
- **双括号规范化 (Pass 15)**：在最后一趟后处理中，将函数调用多余的括号（如 `puts());`）规范化为 C 语言的标准形式 `puts();`。

### `pub struct NullEmit`

Emitter that discards all output (used for discovery pass)

### `pub fn new() -> Self`

创建一个静默发射器，所有的打印输入均会被丢弃。常用于 Discovery Pass (探测阶段) 以静默跑通反编译打印管线以搜集已使用的变量。

---

## 更新日志

### 2026-06-23：输出合法化与控制流规范化

- `get_output()` 现自动调用 `post_process()`，确保所有调用方（含 example）都得到规范化输出（此前 example 直接取原始 output，跳过了后处理）。
- 新增 `rewrite_struct_deref()`：将所有 `IDENT->field_N` 重写为 `*(long *)(IDENT + 0xN)`。原因：printc 多处 emit `ptr->field_N`，但我们不追踪具体 struct 布局，无法保证 `ptr` 指向匹配的 struct 类型。cast 形式无论 base 声明类型如何都合法。
- `try_convert_ptr_add()` 与 second pass 的 `*var + N` 模式同样改为 emit cast 形式。
- while-break 折叠 pass：`while(cond){stmt;break;}` → `if(cond) stmt`。
- 空 switch case 移除 pass：删除 `case N: { break; }` fallthrough 组。

### 2026-06-23（续）：一元解引用声明合法化

- 新增 `fix_unary_deref_declarations()`：扫描所有 `*IDENT` 一元解引用模式，把这些 IDENT 的声明从 scalar（long/int/byte）改成 `char *`。原因：printc 对 STORE/LOAD 发射 `*param_N = val`，若 param_N 被推断为 long/int 则非法。`char *` 既能解引用又能赋标量值。
- 参数签名同步重写：签名行里的 `long param_N` 若属于 derefed 集合，改为 `char * param_N`。

### 2026-06-23（续）：栈/局部变量声明兜底

- 新增 `backfill_missing_locals()` post-process pass：扫描每个函数 body 里使用但未声明的 `local_XX`/`lVar_XX`/`uVar_XX`/`iVar_XX` 等匈牙利前缀变量，按前缀推断类型（lVar/uVar→long, iVar/bVar/local_→int, piVar/pcVar→char*），在声明块末尾补声明。兜底覆盖 mark_variable_used 路径不完整导致的遗漏。



### 2026-06-23（续）：DCE 改进

- 空行不再重置 dead zone（它们不让后续死代码可达）。
- 同 indent 或更深的 `}` 保持 dead（它关闭 dead zone 内的块）。

### 2026-06-23（续）：orphan break/continue 移除

- 新增 `remove_orphan_breaks()` post-process pass：跟踪 brace 深度与 loop/switch 上下文栈，删除不在任何 loop/switch 内的 break/continue 语句。支持裸 `break;` 和内联 `if (cond) break;` 两种形式。内联形式移除 break 后若行变空则整行删除。

### 2026-06-23（续）：DAT_ 全局 backfill 恢复

- `backfill_missing_locals()` 重新加入 `DAT_` 前缀扫描。之前移除是因为可能把 extern 放函数中间，但现在的声明块检测逻辑能正确把 extern 放在声明块末尾。DAT_ 名声明为 `extern long DAT_xxxxx;`。

### 2026-06-23（续）：orphan break context 继承改进

- `remove_orphan_breaks()` 的 context 栈改进：嵌套块（if/else/匿名）继承父块的 loop/switch context；函数签名行重置为 false；`} else {` 继承 parent。修复了 switch case 内嵌套 if 里的 break 被误删的问题。

### 2026-06-23（续）：orphan break 的 switch 范围追踪 + brace 双计修复

- 重写 `remove_orphan_breaks()`：用 brace 深度 + loop/switch 深度栈预扫描，标记每行是否在 loop/switch 体内。比行级 context 栈更可靠。
- 修复 `} else {` 的 brace 双计 bug：这类行既匹配 `endswith("{")` 又匹配 `starts_with("} else")`，导致 brace_depth 多 +1。现在 `endswith("{")` 排除以 `}` 开头的行。
- 函数签名行重置 brace_depth=1，防止跨函数累积。

### 2026-06-23（续）：backfill 扩展无下划线前缀 + struct

- `backfill_missing_locals()` 现在同时匹配带下划线（`bVar_592`）和无下划线（`bVar592`）两种匈牙利命名，以及 `struct3` 栈结构体名。类型推断：structN → int（占位），其余按原规则。

### 2026-06-23（续）：指针算术合法化

- 新增 `fix_pointer_arithmetic()` post-process pass：检测 `ptrA + ptrB` / `ptrA * ptrB`（两者都声明为指针类型），把右操作数 cast 成 `(long)`，使运算变为 pointer + integer。跳过赋值语句的 LHS。

### 2026-06-23（续）：非法 lvalue 赋值移除

- 新增 `remove_illegal_lvalue_assignments()` post-process pass：检测 LHS 含顶层二元运算符（`RSP + expr = val`）的非法赋值行并移除。这些来自 printc op_store 对复杂地址的错误渲染。

### 2026-06-23（续）：CaseDetectEmit + case_body_indices + dry-run 检测

- 新增 `CaseDetectEmit`（Emit 适配器），记录 emit 是否产生 `case`/`default:`/`tag_case_label`。
- `PrintC` 新增 `case_body_indices` 字段，在 doc_function 开始时从 BlockSwitch.cases/default + CASE_BODY flag 收集。
- 实现了 dry-run case-label 检测（临时替换 emit 为 CaseDetectEmit，emit if_body 检查）。
- 但 dry-run 只覆盖 emit_block_ops（不覆盖 emit_block_structured 的嵌套路径），漏掉部分 case label。
- if_no_exit 仍禁用。printc 的 CASE_BODY emit 保护已移除（破坏正常 BlockIf）。

### 2026-06-23（续）：orphan case label 移除（精确 switch depth 追踪）

- post-process 新增 `remove_orphan_case_labels()`：用 brace depth + switch body depth 栈精确追踪 switch 上下文，移除不在任何 switch 内的 case/default label。
- httpd main case label 问题解决！gcc 53/53。
- 但 test_bool_condition 又失败（goto 级联对非 switch 函数的影响）。
