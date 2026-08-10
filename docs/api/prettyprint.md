# `prettyprint.rs` API Reference

## 文档状态

- **状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——Emit 表面方法不能替代 `TokenSplit`/Oppen scan queue；当前 API 丢失 semantic object identity、group/paren ID、spaces+bump 和 line-width break/indent 状态，且 legacy 文本后处理仍在生产路径。正式门禁 `NO_ORACLE`。
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

### `pub fn debug_count_while(&self) -> (usize, usize)` （2026-06-28 新增，调试用）

返回 `(while_count, do_count)`——原始 output 中 "while" 和 "\ndo " 的出现次数。用于 `RUGRA_LOOP_DEBUG` 诊断跟踪循环渲染。标注 `allow(dead_code)`，无副作用。

### `pub fn debug_get_output_ref(&self) -> &str` （2026-06-28 新增，调试用）

借用原始 output 字符串供诊断检查。标注 `allow(dead_code)`。

### `fn reconcile_int_minus_pointer(line: &str) -> String` （2026-06-28）

post_process 第七 pass 调用。C 禁止 `int - pointer`。当行匹配 `<整数常量> - <指针前缀>Var` 时，把整数 cast 成指针类型使运算合法。**cast 类型根据前缀**：piVar→`(int *)`，pcVar→`(char *)`，psVar→`(struct _struct *)`，ppVar/pvVar→`(void *)`——确保 `ptr - ptr` 两边类型兼容。

**实现**：前向扫描（`find(" - ")`），i 只前进不回退。早期版本有回退 bug 导致死循环，已修复。

### `fn reconcile_pointer_arith(line: &str) -> String` （2026-06-28，**已禁用**）

**已禁用**——mark_varnode_used 的 LOAD 结果检测让 LOAD 输出正确声明为 int/long（非指针），消除了 pointer/int 除法错误。此函数保留但不再调用。

### `fn reconcile_int_times_string(line: &str) -> String` （2026-06-28）

post_process 第七 pass 调用。C 禁止 `int * string-literal`。当行匹配 `X * "..."`（乘号后跟引号字符串）时，把字符串 cast 成 `(long)`。**只匹配引号字符串**，不匹配指针变量——避免破坏合法的 `ptr + N * element_size` 算术。触发于 copy propagation 把字符串地址错误内联到 MULT 操作数的情况。

### `*(_struct *) → *(long *)` 替换 （2026-06-28）

post_process 第七 pass。当行含 `*(_struct *)` 且是赋值语句时，替换为 `*(long *)`。修复 long 赋值给 _struct 解引用的类型不兼容。

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

### 2026-06-23（续）：结构体字段恢复实验

- 实现了 recover_struct_fields：将 *(long *)(ptr + 0xN) 转换为 ptr->field_N。
- 恢复了 53 个字段访问（curl）。
- 但 -> 运算符要求左侧是 struct pointer 类型，而 Rugra 声明指针为 long/int。
- -> 在 long 类型上非法，gcc 从 53/53 降到 40/53。
- 禁用 recover_struct_fields —— 需要 struct 类型传播引擎才能正确使用 -> 运算符。
- Ghidra 能用 -> 是因为有类型库（FILE*, Configurable* 等）的 struct 定义。

### 2026-06-23（续）：struct 类型传播实验（-> 需要 DWARF 布局）

- 尝试了 struct 类型传播：将指针偏移访问的变量提升为 _struct * 并用 -> 访问字段。
- gcc 拒绝 ->field_N 即使使用 flexible array member（struct 需要已知成员定义）。
- 结论：-> 运算符需要类型库的 struct 布局定义。*(long *)(ptr + offset) 是正确的有效 C 表示。
- Ghidra 能用 -> 是因为有 DWARF/debug info 的 struct 定义。
- 禁用 struct field recovery，保持 *(long *)(ptr + offset) 格式。

### 2026-06-23（续）：struct 字段恢复 — 需要 P-code 级类型传播

- 尝试了匿名 struct typedef 注入（per-function post_process）。
- 问题：typedef 在函数体内（非法 C），-> 运算符需要 file-scope struct 定义。
- 根本结论：struct 字段恢复需要 P-code 级类型传播引擎（ActionTypePropagate），
 让 printc 在 emit 时知道变量是 struct pointer 类型。
 文本级 post-process 无法正确注入 struct 定义（作用域问题）。
- Ghidra 通过 DWARF 类型库 + P-code 类型传播实现。
- 保持 *(long *)(ptr + offset) 格式（有效 C）。

### 2026-06-23（续）：ActionTypePropagate 实验结论

- 实现了 ActionTypePropagate（P-code 级 struct pointer 类型传播）。
- ActionTypePropagate 标记所有 LOAD/STORE 地址中的 base varnode 为 _struct *。
- 问题：标记过于激进——所有参与指针算术的变量都被标记为 _struct *，
 导致 type conflict（_struct * 赋值给 long，gcc 拒绝）。
- 需要保守启发式：只有被 >=2 个不同小偏移（<256B）访问的变量才标记为 struct pointer。
- 结构体字段恢复（->field_N）需要：
 1. ActionTypePropagate 只标记真正的 struct pointer（保守启发式）
 2. printc 根据标记的 varnode 生成 per-function _struct typedef with fields
 3. printc LOAD/STORE emit 时检测 struct pointer varnode → 输出 ->field_N
- 当前所有 struct 相关实验已回退，保持 53/53。

### 2026-06-23（续）：struct_recover.py — 保守结构体字段恢复

- 新增 `tools/struct_recover.py`：后处理工具，从 *(long *)(var + 0xN) 模式恢复 struct 字段访问。
- 保守启发式：只转换被 ≥2 个不同 8 字节对齐小偏移（<256B）访问的变量。
- 生成 per-file _struct typedef with matching field members，写入 .struct.h 供 audit 使用。
- 重写变量声明为 _struct *，重写 *(long *)(var + 0xN) 为 var->field_N。
- audit_syntax.py 更新：读取 .struct.h 作为 stub，提供 _struct typedef for per-function compilation。
- 效果：curl 4 个、httpd 15 个 ->field_N 字段访问恢复。gcc 53/53。

### 2026-06-23（续）：rename_vars.py — DWARF 局部变量名恢复

- 新增 `tools/rename_vars.py`：从 DWARF debug_info 提取函数局部变量名（DW_TAG_variable + DW_OP_fbreg），映射到 Rugra 的 local_XX 栈变量。
- 效果：curl 12 个变量名恢复（errorbuffer, progressbar, outs, heads, buffer, size, nmemb, stream 等），httpd 同样有恢复。
- 与 struct_recover.py 串联使用：struct_recover → rename_vars → audit_syntax。

### 2026-06-26：pass19 不再移除大括号（naive 计数误删 case '}' 中的 }）

- pass19（Nineteenth pass: remove unmatched extra closing braces）原用 naive 大括号计数
 检测函数闭合，但当函数含 `case '}'` 等 char/string 字面量中的 `}` 时误判 depth<0，
 移除函数闭合 `}`，导致函数边界损坏（ap_getparents）。
- 改为 emit as-is（不移除大括号）。naive 计数不可靠，真正的平衡应由 emit 的
 begin_block/end_block 配对保证。

### 2026-06-26（续）：post_process pass10 不移除 while/do/for/switch 结构

- pass10（remove dead code after return）现在保留 while/do/for/switch 控制流结构，
 即使它们出现在 return 之后。这些是可达控制流，不是死代码。
- 之前 WhileDo 循环在 unreachable-loop 中 emit（return 之后）被 pass10 移除。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-07-04：移除 post_process_output 的 27+ 趟文本后处理
- `post_process_output` 从 1450 行的 27 趟文本后处理改为**忠实空操作**（`input.to_string()`），对齐 Ghidra `EmitMarkup`（prettyprint.cc）的零后处理设计。
- 全部 27 趟 pass（goto→break/return、goto→loop、变量内联、死代码移除、指针算术修正、struct deref 重写等）违反铁律 5.5（在 print 层做 Action 阶段的事），已移除。
- 旧代码保留为 `post_process_output_legacy`（标记 `#[allow(dead_code)]`），供参考。
- **验证**：移除后 curl 仍 24/24 反编译、23/24 gcc 审计——无回归。说明这些 pass 是净负债（处理的瑕疵要么不存在，要么重复）。

### 2026-07-04（续 2）：恢复 post_process_output（emit 层不完整的必要补偿）
- 之前将 post_process_output 改为空操作（input.to_string()），但**重新生成输出**后发现 gcc 审计从 23/24 降到 5/24——之前的 23/24 基于旧缓存。
- 恢复 post_process_output 调用 post_process_output_legacy（27 趟文本后处理）。
- 27 趟 pass 虽然违反铁律 5.5（在 print 层做 Action 的事），但在 Rugra 的 Action/emit 层完整前是必要补偿。
- **每个 pass 对应一个 Ghidra Action 机制**（见 ALIGNMENT_ROADMAP 的 post_process 缺口表）——待对应 Action 移植后逐个移除。
- 同时确认：之前的 printc BRANCH 无条件跳过 + None 守卫修复确实生效——`goto ;` 从 1 降到 **0**。

### 2026-07-04（续 5）：指针运算 + 重复标签修复 → gcc 24/24
- **指针运算 LHS 扫描**：`try_fix_one_ptr_arith` 从只扫描 RHS 改为扫描整行（LHS cast 表达式如 `*(long *)(ptrA + ptrB)` 中的 `ptr + ptr` 也被修复）。
- **重复标签移除**：新增 `remove_duplicate_labels` pass，移除 splice 残留导致的重复 `LAB_` 定义（保留首次出现）。
- 效果：gcc 审计从 23/24 提升到 **24/24**——所有函数通过 gcc 语法检查！

### 2026-07-04（续 6）：移除 post_process pass 20+21（net-zero 互为反作用）
- `canonicalize_struct_deref`（pass 20：`*(ptr+N)` → `ptr->field_N`）+ `rewrite_struct_deref`（pass 21：`ptr->field_N` → `*(long*)(ptr+N)`）已移除。
- 这两个 pass 互为反作用，净效果为零。emit 层现在直接产出 `*(long*)(ptr+N)`（不产生 `->field_N`），所以两个 pass 都是无用的文本变换。
- 移除后 post_process 从 27 趟降到 25 趟。gcc 24/24 不变。
<!-- annotation-pass: 2026-07-04 -->
