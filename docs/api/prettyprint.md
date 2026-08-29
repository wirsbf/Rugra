# `prettyprint.rs` API Reference

## 2026-08-28：RPN variable metadata bridge

`Emit::tag_variable_with_metadata` 为 Ghidra
`tagVariable(name,highlight,vn,op)` 增加无损 Rust 边界：字符常量 Atom 的 highlight、
Varnode create-index 和 PcodeOp time 不再在 RPN→emitter 调用处被写死为 0。旧 emitter
可回退到文本/id API。`PRINTLANGUAGE-ATOM-METADATA-0001` 的 8 records / 678 bytes
双侧 stdout 已逐字节 `MATCH`（SHA-256
`d84d1ae86bad70fc570630ebbc8a65f172f97655d129a6b49b2faded09c9acbd`），覆盖两次
相同 vn/op identity 的 stage-1 hidden group 和 syntax control。该 fixture 在
metadata-aware Emit 边界结束；当前 `TokenSplit/EmitPrettyPrint` 仍会丢
highlight/vn/op，绑定 `PRETTY-0001`，完整 markup encoder 也未获全函数门禁。

## 2026-08-27：移除 `0x4f` 字符后处理 workaround（TRI2-CALLOUT-RESID-0002）

删除 `post_process_output_legacy` 第七趟中 `0x4f → 'O'` 的赋值替换。
该映射没有合法消费者：它对所有 `= 0x4f;` 赋值生效，而 Ghidra 的字符形由
`PrintC::pushConstant` 的 propagated read-facing 类型分派决定，不应由文本后处理
猜测。现在由 `src/printc.rs` 的 `TYPE_INT/TYPE_UINT + isCharPrint` 通道负责该决定。

验证记录：移除前 curl 输出有 3 个 `= '..';` 赋值（`config='&'`、
`myprogress='#'`、`progressbarinit='O'`），移除后为 2 个；仅
`progressbarinit` 受影响并收敛到 golden 的 `bar->width = 0x4f;`，其余两处与
golden 保持一致。

## 2026-08-26：`EmitPrettyPrint` Oppen 折行引擎 1:1 移植（PRINTC-LINEWRAP-0001）

Ghidra 反编译器的主输出走 `EmitPrettyPrint`（`printlanguage.cc:69`
`emit = new EmitPrettyPrint()`），即 Derek C. Oppen 令牌队列折行算法。
Rugra 此前只有 `EmitNoMarkup` 直写路径，长表达式永不折行（hugehelp
长字面量为单行，golden 为 `puts(\n      "..."\n      );` 三行）。

本提交补齐 emit 层行宽机制（prettyprint.cc:541-1243 / prettyprint.hh:609-1115）：

- `pub struct TokenSplit`（hh:609）——令牌/命令对象：`tagtype`（28 值
  `TagType`）+ `delimtype`（9 值 `PrintClass`）+ `tok`/`indentbump`/
  `numspaces`/`size`/`count`。每个 emitter 方法对应一个构造器
  （`begin_document`..`tag_line_indent`），`size` 为内容字符数或未提交
  组的负扫描偏移。
- `struct CircularQueue<T>`（hh:944）——环形缓冲，栈用法 `push/pop`、
  队列用法 `push/popbottom`，整型引用在 push/pop 后仍有效；
  `expand(amount)` 重分配并紧凑到引用 0（hh:1003-1027），
  `EmitPrettyPrint::expand`（cc:564-579）按
  `(ref + max - left) % max` 同步调整 scanqueue 引用。
- `pub struct EmitPrettyPrint`——scan/advanceleft/print/overflow 四函数
  心脏（cc:614-802）+ `checkstart/checkstring/checkend/checkbreak`（cc:806-856）
  + 全部 emitter 方法（cc:858-1192）。`open_paren` 自动开组（cc:1094-1103:
  `id = openGroup(); …; needbreak = true`），`close_paren` 关组；
  `flush`（cc:1194-1211）排空队列（未闭合组在 oracle 抛 LowlevelError，
  Rugra 记日志跳过——emit 层无错误通道的保守降级）；
  `set_max_line_size`（cc:1225-1235，20..=10000，`3*val` 队列容量）；
  `clear`（cc:1153-1166）。低层为 `EmitNoMarkup` 字节汇。
- `Emit` trait 变更：`open_paren(paren) -> i32` / `close_paren(paren, id)`
  （默认实现即打印括号、返回 0，cc:587-591）；`spaces(num, bump)`
  （cc:46-59 spacearray 折叠，默认实现打印 `num` 个空格；pretty printer
  里是 \e tokenbreak）；`start_comment/stop_comment/flush/set_comment_fill`
  空默认。
- 调用方（printc/printlanguage 的 RPN 路径）改用带 id 的
  open/close_paren 与 `spaces(spacing, bump)`（printlanguage.cc:146-179/
  338-369）；docFunction 尾部补 `tagLine→endFunction→flush`
  （printc.cc:2663-2665）；typedef 前言包进 `beginDocument..endDocument`
  （docAllGlobals 形态，printc.cc:2621-2629）；`PrintC::new` 设置
  comment fill `"   "`（setCommentDelimeter "/* " 宽度，printlanguage.cc:96-110）。
- 驱动（examples/curl_decompile.rs）换用 `EmitPrettyPrint`。

**验证**：hugehelp 函数体与 `tests/golden/ghidra_curl_1204.c` 逐字节一致
（`--func hugehelp` Skeleton identical）；全量差分 defects=0 /
numbering=0；总 skeleton 2824→2776（main -24、getparameter -26、
hugehelp -12；5 个函数 +14 行均为内容本已分叉的长表达式折行位置差）。
逐函数 oracle 行为差分状态仍按机制 B2 记 `UNTESTED`（分支/边界未全
覆盖），不得据此把模块升 L3；emit 层折行行为以 curl golden 为证据。

## 2026-08-27：死会话遗留两处收尾（PRINTC-LINEWRAP-0001 续）

- `EmitPrettyPrint::next_count`：C 的 `countbase++`（prettyprint.hh:685
  等 TokenSplit 构造器）是后置自增，表达式值为自增**前**的旧值；
  `AtomicI32::fetch_add(1)` 同样返回旧值——原实现 `fetch_add(1) + 1`
  把 id 整体偏移了 1。count 只用于 begin/end 配对（非 PRETTY_DEBUG
  构建不参与输出字节），修正为语义 1:1。
- `post_process` 移除 `RUGRA_DBG_NO_P3` 临时旁路（机制 D：`[DBG]`
  临时通道提交前必须删除）。
- 驱动（examples/curl_decompile.rs）STRCONST-SPANNONOVERLAP：字符串
  Data 严格非重叠注入（run+NUL 跨度内跳过 per-byte DAT、8 字节槽
  entry 裁剪到下一字符串起点），恢复 oracle Program DB 的
  findContainer 最小包含选择，使 ActionConstantPtr 字符串臂在字符串
  起点命中——回归 A（字面量退化为指针算术）的本 worktree 侧修复，
  供 hugehelp 折行形态 E2E 验证。

## 2026-08-26：`EmitNoMarkup` 空白折叠不进入字符串字面量（MAINDIFF-STRCONST-0001）

`get_output` 后处理的取消-清理段（cancel_patterns 之后的双空格折叠与
` )` 修剪）此前对整行盲做。反编译器的字符串常量合法包含多空格 run
（hugehelp 别名的 `\n   or specify` / 八空格缩进），盲折叠会改写字面量内容。
现折叠循环带引号状态机：`"`/`'` 开启的字面量区域逐字复制（反斜杠逃逸不翻转
引号态），折叠与修剪仅发生在字面量外。golden 中 hugehelp 三个
`puts("...")` 字面量（含连续空格与 `\n`）逐字节保持。

## 文档状态

- **状态**: 🔧 **L2（2026-08-12）**——`Emit::open_group/close_group` 已补齐，
  `PRINT-RPN-0001A` 对已覆盖 RPN case 的纯文本为 `MATCH`；但默认实现只保留
  plain-text 的不可见语义，尚未实现/观察 `TokenSplit`/Oppen scan queue、exact
  group ID、semantic object identity、spaces+bump 和 line-width break/indent，
  模块整体仍为 `UNTESTED/MISMATCH`。
- **对应源码**: 当前 `rugra/src/prettyprint.rs`

**源代码路径**: `src/prettyprint.rs`

## 模块说明 (Module Doc)

Pretty printing and token emission

Corresponds to Ghidra's `prettyprint.hh`

## 导出的公共 API (Public API)

### `pub enum BraceStyle` （2026-08-15 新增，PRINTC-FORMAT-0001）

对应 Ghidra `Emit::brace_style`（prettyprint.hh:124-129）：`SameLine = 0`
（`if/do/while/for/switch` 的 `{` 同行）、`NextLine = 1`（下一行）、
`SkipLine = 2`（空一行后，函数体默认样式）。

### `pub trait Emit`

Trait for emitting decompilation tokens

This provides a generic interface for "printing" decompiled code,
allowing for different output formats (plain text, XML, HTML with markup, etc.)

- `open_group() -> i32` / `close_group(id)` 对应 Ghidra
  `Emit::openGroup/closeGroup`。纯文本 emitter 的 group 不产生字符，默认 ID 为 0；
  它与会实际输出 `(`/`)` 的 `open_paren/close_paren` 是两套不同操作。
- `open_brace_indent(brace, style)` / `close_brace_indent(brace)` 对应
  `Emit::openBraceIndent`（prettyprint.cc:61-76）与
  `Emit::closeBraceIndent`（prettyprint.hh:481-483）。`EmitNoMarkup` 的
  覆写按 oracle 的无条件 `tagLine`（`\n` + indent，prettyprint.hh:557）
  语义发射：`SkipLine` 产生恰好两个换行（`)\n\n{`），`SameLine` 产生
  ` {`；close 为 stopIndent + 换行 + `}`。Rugra 的 `tag_line` 会吞掉重复
  换行，因此两个换行在覆写里直接写入以保证 oracle 字节格式。
  `bump_indent`/`drop_indent` 是 startIndent/stopIndent 的 indent 半边
  （indentincrement=2 空格/层）。
- 锁定 12.0.4 visible-text fixture：
  `tools/run_printlanguage_group_oracle.sh`。已覆盖 case 为 `MATCH`，exact
  PrettyPrint group queue/ID 仍归 `PRETTY-0001`，不得据此升级 L3。
- 锁定 12.0.4 纯格式 fixture（PRINTC-FORMAT-0001）：
  `tools/run_printc_format_oracle.sh`，六 case（函数头花括号 skip_line 布局、
  参数 `char *pattern`/`char **argv`/`int argc`/`...` join 间距、逗号无空格、
  2 空格缩进策略）双侧逐字节 `MATCH`。

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

- `backfill_missing_locals()` 重新加入 `DAT_` 前缀扫描。之前移除是因为可能把 extern 放函数中间，但现在的声明块检测逻辑能正确把 extern 放在声明块末尾。DAT_ 名声明为 `extern long DAT_xxxxx;`。**2026-08-25 改为跳过（MAIN-DATPOOL-0001）**：oracle printc.cc 零 `extern` 关键字、golden 零 extern 行，DAT_ 名不再注入任何声明，仅保留 use-site 裸引用。

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

### 2026-08-15：PRINTC-FORMAT-0001 — 纯格式层对齐 oracle（skip_line 花括号 / 指针 join / 逗号间距）

- 新增 `BraceStyle` 枚举与 `Emit::open_brace_indent`/`close_brace_indent`
  （prettyprint.cc:61-76、prettyprint.hh:481-483 的 1:1 移植）；
  `EmitNoMarkup` 覆写按 oracle 的无条件 tagLine 语义发射。
- post_process 第八趟格式修正：不再凭空在声明块后插入空行——保留发射器
  已产出的**缩进保留分隔行**（emitLocalVarDecls 尾 tagLine 的忠实渲染，
  printc.cc:2277-2278），无声明则无分隔行；旧版把每个无声明函数体 `{` 后
  插一个空行是纯格式 bug。
- post_process 各函数签名检测（pass 11/17/18/19、remove_orphan_breaks、
  backfill_missing_locals）统一经 `signature_opens_function_body` 识别
  oracle 的两行式函数头（`sig` + 独立 `{` 行，printc.cc:1590/2655），
  skip_line 布局下 `{` 行不重复计入 brace depth；backfill 的声明收集跳过
  独立 `{` 行（否则 declared 集为空导致全部变量重复声明——numbering
  126→6 的根因）。
- `fix_unary_deref_declarations`/`recover_struct_fields_anon`/backfill 的
  指针声明模板从 `char * name` 改为 oracle join `char *name`
  （printc.cc:73-77 ptr_expr spacing=0）。
- 锁定 fixture `tests/oracle/printc_format_1204`（cover_rebuild 模式，
  pinned base=a51e0c5）：六 case 双侧逐字节 MATCH。

### 2026-08-16：声明识别白名单扩展（TYPE-WIRING 配套）

`flush_func_remove_unused` 的声明匹配从 `type uVarN;` 扩展到指针形
（`char *uVarN;` / `void *uVarN;` / `undefinedN *uVarN;` 三 token 形），
变量名取尾部 token 去前导 `*`——与 printc 的 ptr_expr join
（printc.cc:73-77）两种拼写一致。避免符号驱动声明落地后指针形被误判
missing 而合成重复 `int uVarN;`（numbering 残差机制见
PRINTC-LEGACY-DECL-DUP-0001）。

### 2026-08-16：PRINTC-LEGACY-DECL-DUP-0001 — 符号驱动函数旁路合成声明 pass，消 20 处重复

前次的"三 token 指针形"白名单扩展**未生效**：printc 的 ptr_expr join
（printc.cc:73-77 spacing=0）产出的是 2-token 形 `char *uVarN;`
（`split_whitespace` → `["char","*uVarN"]`），三 token 分支
（`["char","*","uVarN"]`）从不命中，`char *uVar20;` 仍被判 missing →
`int uVar20;` 注入 → `fix_unary_deref_declarations` 重写为
`char *uVar20;` → 与符号声明重复（8 函数 20 处 `declared twice`）；无任何
uVar 声明被收集时 `last_decl_idx=0` 使注入落在签名与 `{` 之间（K&R
old-style，gcc 11 错）。

**修法（oracle 判断）**：Ghidra 打印期零声明合成/删除——
printc.cc:2656 `docFunction` 的全部函数局部声明来自
`emitLocalVarDecls`（printc.cc:2260，Action 期 Symbol），`EmitNoMarkup`
（prettyprint.hh:547）无任何 post-process。故符号驱动函数不再接受任何
**合成/改写声明**的文本 pass，而非继续扩白名单（per-name 过滤 hack
掩盖缺符号函数仍需 backfill 的事实，被 root 指令禁止）。实验数据决定了
保留边界：三 pass 全旁路时 gcc FAIL 24→25（未链接符号引用如实暴露为
undeclared，SetHTTPrequest 新增 FAIL）；旁路两个合成 pass、保留 backfill
（其 declared 收集本就正确处理两种指针拼写，只补真缺名）时 FAIL 24→19
且 numbering 同为 0——后者使缺符号函数（符号块外的 uVar_<offset> 引用，
PRINTC-UNLINKED-REF-0001 域）保持可编译，是任务要求的 backfill 保留语义。

- 新增 `has_symbol_driven_decls()`（RUGRA-GLUE）：保守判据 = 函数声明块
  非空且至少一行声明呈现 ①类型 token 以 `undefined` 开头
  （undefined1/2/4/8 核心类型拼写，legacy pass 只合成
  int/long/`char *`/float/double）或 ②名字 token 以 `in_` 开头
  （in_RAX/in_ram_*/in_register_* 寄存器/内存符号名）。两种拼写只能由
  `emit_local_var_decls` 产出。
- 新增 `symbol_driven_function_line_mask()`（RUGRA-GLUE）：整文本按
  `signature_opens_function_body` 分段（前缀集含 `undefinedN` 返回型），
  为 `fix_unary_deref_declarations` 的行级重写提供函数归属掩码。
  分段边界修正（MAIN-ARGC-PROTO）：skip_line 布局下签名行自身无花括号
  （depth=0），且 `open_brace_indent` SkipLine 在签名与体 `{` 之间产生一个
  **空行**——原深度循环在空行上立即 `depth<=0` break，"函数块"退化为
  [签名,空行] 两行，`has_symbol_driven_decls` 看不到任何声明，main 等
  DWARF 锁参函数不被掩码，`fix_unary_deref_declarations` 遂把签名中锁定的
  `int argc` 重写为 `char *argc`（body 中存在 `*argc` 解引用）。修正：深度
  走查前先向前推进到 `signature_opens_function_body` 前瞻已定位的 `{`
  （途中只允许空行；其他非空行 = 前瞻契约破坏，回退旧行为），随后从
  depth=1 起算跨越真实函数体。A/B（124 函数全量）字节级 delta 共 8 处且
  全部向 oracle 收敛：`int main(char *argc` → `int main(int argc`
  （=golden）、`glob_set(char *pattern,char *pos` → `(char *pattern,int pos`
  （=golden）、match_url `char *param_1`→`long param_1`、5 处
  `char *unique0x…`→`long unique0x…`（回退到未命名位置 fallback 的
  long 默认）；defects 0→0、numbering 1→1（match_url per-prefix，基线
  同值预存）。
- 两处旁路：`flush_func_remove_unused` 对符号驱动函数整块直通（不删
  unused、不注入 missing——Ghidra 无条件发射所有符号声明，
  printc.cc:2260；该 pass 的 type_ok 表识别不了 2-token join 形
  `char *uVarN;`，正是重复注入与 K&R 位置的源头）；
  `fix_unary_deref_declarations` 跳过符号驱动函数的行（不在符号标量
  声明上重写 `char *`，oracle 按符号 Datatype 逐字打印，
  printc.cc:2503-2506）。
- `backfill_missing_locals` **保留对所有函数运行**：其 declared 收集
  正确处理两种指针拼写，在两个重复源被旁路后只会注入符号块中**真缺**
  的名字（未链接符号 body 引用，PRINTC-UNLINKED-REF-0001 域），使这些
  函数保持可编译。验收（12.0.4 golden）：numbering **20→0**、
  defects 0→0、gcc 审计 FAIL **24→19**（old-style 7 错→0、redeclaration
  →0；FUN_00102020/SetHTTPrequest_part_0/_init/deregister_tm_clones/
  register_tm_clones 恢复 OK，零新增 FAIL）；skeleton 4368→4403（+35：
  backfill 注入组保留所致，重复声明行已消——对照实验：三 pass 全旁路
  时 skeleton 4052 但 gcc FAIL 25，未链接引用如实暴露为 undeclared）。

### 2026-08-17：WARN-EMIT2 R2 — backfill 签名启发式误匹配控制流行（重复声明根因）

`backfill_missing_locals` 的函数签名判定 `sig_shape` 含
`trimmed.contains(" *")` 臂（本意覆盖 `char *foo(...)` 这类前缀表外签名）。
该臂同时命中**带 `/* N */` 十六进制注解的控制流开行**：例如
`if ((bool)(piVar1 <= 0x1000 /* 4096 */)) {` ——含 `(`、含 `" *"`
（` /* 4096 */` 里的 ` */`）、以 `{` 结尾，三条件全真。pass 随即把 if 体
当作嵌套函数：declared 收集只看块内（函数顶声明不可见）→ 块内全部
匈牙利前缀名被判 missing → 五条声明**整组注入 if 体内**，与函数顶那组
逐字重复（glob_url 的 `piVar1`/`uVar0`/`uVar20`/`uVar_1000004a`/
`uVar_9100`，numbering 0→3 的直接来源；隔离复现：删干净双批后单次
`post_process_output` 即再生两批）。

修复：`sig_shape` 前置 `control_flow_opener` 排除
（`if (/while (/for (/switch (/do {/else/case /default:` 各带无空格变体），
只有真函数签名（首 token 为类型）能进入注入路径。验收：glob_url 单批注入
（保留 PRINTC-UNLINKED-REF-0001 兜底语义）；锁定 12.0.4 golden 差分
numbering 3→**0**、defects 0 不变、Matched 123 不降；11.3.2 回归 golden
同 0/0。诊断期临时插桩（RUGRA_DUMP_PRE_POSTPROCESS 等五处）已全部移除。

### 2026-08-25：PRINTC-SWITCH-EMIT-0001 配套 — switch 语句前缀谓词

`is_switch_stmt_prefix`（RUGRA-GLUE）：oracle 的 opBranchind
（printc.cc:586-587）发射无空格的 `switch(`（golden `switch((int)x…)`
佐证），而 legacy 文本后处理的 5 处前缀检查只认 `switch `/`switch (`
形态——printc 对齐该字节后，`remove_orphan_case_labels` 会把
`switch(...)` 的全部 case 标签当孤儿剥掉。谓词统一接受两种前缀；
`switch` 是 C 关键字，`switch(` 不可能是标识符调用，词法安全。改动点：
remove_orphan_case_labels（2052）、tenth-pass 死区豁免（1050）、
pass17 循环上下文（1447）、brace_depth 循环头判定（2357）、
scan_up_for_loop_header（3131）；2491 原本就双形态。

### 2026-08-25（续）：A69 配套 — backfill 前缀表识别 oracle 未命名位置兜底 token

A69（`a9351d26`，PRINTC-UNLINKED-REF-FAMILY slice A）把 print 侧三条兜底
命名阶梯合并为唯一 oracle 形式 `<spacename><printRaw>`
（printc.cc:1938-1945 `PrintC::pushUnnamedLocation` + space.cc:206-222
`AddrSpace::printRaw`：`"0x"` + 小写 hex，`setw(2*sz)` 零填充最小宽度）。
`uVar_`/`local_`/`param_stack_`/`vn_` 全族消灭后，body 里换出的
`unique0x…`/`register0x…`/`stack0x…`/`ram0x…` token 不再被
`backfill_missing_locals` 的前缀表（原 2582-2586）与类型推断识别：
未链接引用不注入声明（match_url 的 `unique0x00023b00` 等保持 undeclared），
且 hex 尾部若走十进制续读臂会在首个 a-f 数字处截断 token。

同步改动（src/prettyprint.rs）：

- 前缀表加入 `unique0x`/`register0x`/`stack0x`/`ram0x` 四前缀
  （const/join/iop/overlay 空间的 token 形态按 A69 记录不可达——const 走
  pushConstant，join/iop 在 print 前被 split/unify/注解吸收）。
- 续读扫描新增第三臂：前缀以 `0x` 结尾的走 `is_ascii_hexdigit`
  （printRaw 的 `hex` 流操纵符，space.cc:216），不再落入十进制臂。
- 类型推断为四形式加显式 `long` 臂（与被替换的 uVar 族缺省一致；此前
  落入兜底 else 同为 long，显式化便于 grep 与防未来缺省漂移）。
- 新增 `#[cfg(test)] mod tests`（4 例：四空间形式注入、hex 尾不截断、
  已声明不重注、legacy 前缀不回归），`cargo test --lib prettyprint::`
  4 passed。

已知边界（同 legacy uVar 拼写，非本片回归）：`*unique0x…`/`*register0x…`
一元解引用出现在 symbol-driven 函数时，注入的 `long` 声明不解引用
（`fix_unary_deref_declarations` 在 pass 22 先于 backfill 运行且对
symbol-driven 函数旁路，pre-A69 `*uVara0 = 0` 同类）；`ram0x` 名的
printc extern 路径（printc.rs used_varnode_types Ram/Const 臂）已于
2026-08-25 随 MAIN-DATPOOL-0001 移除，backfill 的局部 `long` 遮蔽
注入行为保持不变（C 合法，curl 语料 ram0x 出现为 0 行）。
symbol-driven 函数旁路，pre-A69 `*uVara0 = 0` 同类）；`ram0x` 名若已被
printc extern 路径（printc.rs used_varnode_types Ram/Const 臂）声明为
file-scope `extern long`，backfill 仍会注入局部 `long` 遮蔽（C 合法，
curl 语料 ram0x 出现为 0 行）。

### 2026-08-25（续2）：FLAT-CBRANCH 配套 — Pattern 5 尾调用重写排除 code_ 标签

`post_process_output_legacy` 的 Pattern 5（"goto func;" → "return func();"
尾调用重写）此前只检查"标识符形 + 小写首字母"。FLAT-CBRANCH 补全后
printc 发射 flat 尾部 `goto code_r0x...;`（printc.rs 对 printc.cc:2723-2741
的移植），`code_r0x000026A5` 恰好全 alphanumeric 且小写开头——16 处
flat goto 被误重写为 `return code_r0x000026A5();`，gcc 报"将标签隐式
声明为函数"。

修复：Pattern 5 谓词排除 `code_` / `joined_` / `dup_` 前缀——三者是
`PrintC::emitLabel`（printc.cc:3164-3193）的标签构造前缀
（code_ 常规 / joined_ 拼接块 / dup_ 复制块），goto 到它们是控制流
转移，不是尾调用。行为对 libc 尾调用路径（`puts` 等）无影响。

验收：curl E2E `return code_r0x` 假象 16 → 0；audit_syntax 53 → 55 OK
（71 → 69 FAIL，清零 2 处"标号使用前未定义"；其余失败为预存——
progressbarinit/hugehelp 等函数的提取体在两次输出中逐字节相同）。

### 2026-08-25（续3）：NUMDECL-DOUBLE-V — backfill 扫描器左词边界

`backfill_missing_locals()` 的标识符扫描器此前无左词边界检查：前缀表
不含 `plVar`/`pbVar` 等指针前缀，`plVar64` 在内部 `l` 位置匹配 `lVar`
前缀，制造幻影 "used local" `lVar64`，随后注入 `long lVar64;` 与符号
驱动声明 `long *plVar64;` 并存——同名异类型双声明（NUMDECL-DOUBLE-V
的 SUB-B 形态，curl 语料 18 处幻影/8 函数）。

修复：前缀匹配要求 p==0 或前一字节不是 `[A-Za-z0-9_]`（C 标识符字符
集）。C 标识符为 `[A-Za-z_][A-Za-z0-9_]*`，长 token 内部的前缀命中
不是短名的使用。同时修正函数注解：`Ghidra: prettyprint.hh:547
EmitNoMarkup::backfillMissingLocals` 为误引（锁定 oracle 的
prettyprint.hh:547 是 EmitNoMarkup 类声明，oracle 无任何 backfill
文本 pass），改为 `RUGRA-GLUE` 并记录保留理由（PRINTC-UNLINKED-REF-0001
未链接引用域的可编译性兜底，该域关闭时退役）。

验收：curl E2E 幻影声明 18→0；真未链接引用（glob_set piVar1、
register0x/unique0x token）注入保持；defects=0/numbering=0 保持。

### 2026-08-26：GOTO-LABEL — `code_r0x...:` 标号的死区保留

`post_process` 死代码消除中"被引用标号行"的判定从 `LAB_` 前缀扩展到
`code_` 前缀（PrintC::emitLabel 产出的 `code_r0x...:` 与 LAB_ 同为 goto
目标；跳入死区是合法 C，被引用的 code_ 标号必须存活，否则所有指向它的
goto 成为未定义标号 gcc 错误——httpd ap_update_vhost_given_ip /
ap_strchr 观察）。判据不变：整行 `标识符:` 且无空格，且全文存在
`goto <标识符>;` 引用。

## 2026-08-29：WARN-EMIT2 R3 + DUPDECL-uVar 边界 — glob_range 双重声明修复

两处 legacy GLUE 文本 pass 缺陷（oracle prettyprint 无对应物，见各 pass
头部注释的退役计划）：

1. **`backfill_missing_locals` 签名误判（WARN-EMIT2 R3）**：多行 if 条件的
   续行（如 `&& \n (SEXT14(...) < 0x1a)) {`）以 `(` 开头却经
   `contains(" *")`（解引用 `*(char *)` 文本）命中 `sig_shape`，被当成函数
   签名后其"声明块"walk 只覆盖片段本体，块内 auto 前缀名全判 missing，
   在 if 块内部重复注入 `int iVar1; int iVar3;`（glob_range
   numbering=1 的直接来源）。C 函数签名永不以 `(` 开头，新增
   `cond_continuation` 门禁。
2. **uVar 扫描缺左词界（DUPDECL-uVar）**：`ppuVar4` 内部子串 `uVar4` 被判
   为未声明并在签名与 `{` 之间注入游离 `int uVar4;`。补齐与
   NUMDECL-DOUBLE-V6 左边界一致的 identifier 字节检查。

验收：curl E2E numbering 1→0，glob_range diff 93→89，全量 skeleton
2134→2118 零回归。varmap 侧共享计数器不变式另由双侧 fixture
`varmap_dupdecl_1204`（MATCH）钉住。
