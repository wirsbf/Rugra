# `printc.rs` API Reference

`PrintC::doc_function` now follows locked Ghidra 12.0.4
`PrintC::docFunction` at `printc.cc:2641-2676`: it delegates the declaration
exactly once to `emitFunctionDeclaration`. The former production-only `main`
special case, arbitrary RAX-write return heuristic, and empty-prototype SysV
register rescan have been removed. Return type, ordered fixed parameters,
varargs and names now come solely from the finalized `FuncProto`.

This closes the text-selection slice of `PRINT-SIGNATURE-0001`. Scope-backed
parameter `Symbol` markup and the stripped-binary recovery that produces the
prototype remain separate residuals; the module remains L2.

**源代码路径**: `src/printc.rs`

## 文档状态

- **状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——默认 RPN 把 invisible root group 发成未闭合 `(`；多数 op 绕过 RPN，terminal mask 被忽略，`doc_function` 又重发顶层循环。当前 11.3.2 最终 C golden 只作回归诊断，不能证明 12.0.4 token/markup parity。详见 `CONTROL_OUTPUT_PIPELINES_2026-08-11.md`。
- **2026-08-12 `PRINTC-0001` display-format wire 修复**: `display_format` 现与锁定
  Ghidra `database.hh:199-204` / `type.cc:728-762` 一致：`DEFAULT=0`、
  `HEX=1`、`DEC=2`、`OCT=3`、`BIN=4`、`CHAR=5`。此前 Rugra 把
  `CHAR/OCT/BIN` 编成 `3/4/5`，会把持久化或跨层传入的 3、4、5 分别误解释为
  char、octal、binary。`tools/run_printc_display_oracle.sh` 从锁定 commit
  `e40ed13014025f82488b1f8f7bca566894ac376b` 编译真实 C++ `PrintC::push_integer`
  并与 Rust 同 schema stdout 直接 diff；覆盖 wire 常量与字符串 codec 的合法域映射
  （不覆盖 `Encoder/Decoder` marshal round-trip），以及 `65/u8`
  的 `0101`、`0b01000001`、`'A'` 和 `0xff/i8` 的 `-01`、
  `-0b00000001`、`'\\xff'`，结果为零差异。metadata 记录 oracle、架构、
  compiler spec、analysis options、输入 SHA-256、双端 fixture SHA-256 与输出
  SHA-256。此 `MATCH` 仅证明 display wire、codec 合法域观测和“已解析 format u32”
  的 scalar dispatch；C++ 端通过 `Datatype → Varnode → HighVariable` 解析格式，
  Rust 简化 helper 则直接接收 u32，两端对象图、alias 与状态并非同输入。
  因此完整 `push_integer` 及 Datatype/Varnode alias 路径仍为
  **MISMATCH/UNTESTED**；codec 的未知名称/数值错误类型、消息与状态同样未测。
  Rugra API 尚未观察 Ghidra 的 `tag/vn/op`、
  Symbol-vs-Datatype 优先级、equate 早退、unsigned/long suffix、markup 及主管线
  接入，`PRINT-RPN-0001` 未关闭，模块保持 L2。
- **2026-07-22 修复（cross-review printc.cc:2583 calling-convention）**: `emit_function_declaration` 的调用约定分支此前被注释掉且文档错误声称 `option_convention` 默认 false（实际默认 true，printc.cc:1584）。现已：新增 `PrintC.option_convention` 字段（默认 true）+ 取消注释分支 + 在 FuncProto 新增 `is_model_unknown()`/`print_model_in_decl()`（fspec.hh:1394-1395）。对 unknown 模型（curl 场景）`print_model_in_decl` 返回 false，不发射约定 token，与 Ghidra golden 一致（0 个约定 token）。
- **2026-07-22 修复（cross-review mostNaturalBase）**: `emit_integer_value` 的进制选择此前用 `val > 0x1000` 粗糙阈值，现改为调用 `printlanguage::most_natural_base()`（printlanguage.cc:731-788 的 digit-frequency 启发式）。影响枚举值/常量的 hex/dec 显示。
- **2026-07-16 修复（P4 register-var 编号顺序）**: 新增 `preallocate_register_compact_names`：在 doc_variable_decls 前扫描所有 op，收集 Register 空间 auto-local 输出 varnode 的 raw 名 + def-op 地址，按 def-op 地址排序（Ghidra nameDedup 创建顺序的近似），预填 compact_rename。使寄存器变量编号按 def-op 地址序确定，而非 op 遍历首次触及序。栈变量路径已对齐（doc_variable_decls 按 scope.symbols 顺序）。numbering=485 不变（defects=0，编号是外观差异）。
- **2026-07-16 修复（P7-overflow_syntax）**: while-do 循环当条件块 isComplex 时（BlockWhileDo.overflow_syntax 标志，对齐 hasOverflowSyntax block.hh:692，由 try_rule_while_do 的 bl.is_complex() 设置，cc:1538），emit_structured_whiledo 发射 `while(true){ <cond body> if(cond) break; <body> }` 而非 `while(cond){ body }`（对齐 emitBlockWhileDo cc:3017-3044）。新增 BlockWhileDo.overflow_syntax 字段。
- **2026-07-16 修复（P5 for-loop header comma_separate）**: for 循环头 `for(init;cond;iter)` 发射现包裹 `push_mod/set_mod(COMMA_SEPARATE)/pop_mod`，对齐 Ghidra `emitForLoop`（printc.cc:2973-2990）为 init/cond/iter 片段激活 comma_separate。配合 P10 的 `doc_statement` 按 `!is_set(COMMA_SEPARATE)` 条件输出 `;`，避免 for 头片段重复分号。init/iter 文本仍在检测时烘焙（ActionStructureTransform），非从 raw PcodeOp 重发——这是 P5 剩余保真细节，但 latent（curl 语料 0 个 for 循环）。
- **2026-07-16 修复（P9 else-if 链化）**: `emit_structured_if` 的 else 分支现检测 else_body 是否为 BlockIf——若是，发射 `else if (...)`（无外层大括号）而非 `else { if (...) }`（对齐 Ghidra emitBlockIf printc.cc:2928-2935 的 pending_brace 路径）。Rugra 无 PendingBrace/Emit 回调机制，故直接检测 else_body type==If 并递归 emit_structured_if，产生 `else if(cond){body}`。mod-stack（P10）就绪，PENDING_BRACE 常量保留供未来完整 PendingBrace 回调模型。
- **2026-07-16 修复（P8 复合条件 + P10 mod-stack）**: P10: 新增 `print_mods` 模块（NO_BRANCH/ONLY_BRANCH/COMMA_SEPARATE/FLAT/PENDING_BRACE，printlanguage.hh:144-161）+ PrintC.mods/mod_stack 字段 + is_set/push_mod/pop_mod/set_mod/unset_mod 辅助（hh:284-290）。`doc_statement` 的 `;` 现按 `!is_set(COMMA_SEPARATE)` 条件输出（对齐 emitStatement printc.cc:2291）。是 P5（for 循环头）和 P9（else if pending_brace）的前置。P8: `emit_structured_condition` 对顶层 BlockCondition 现发射合并条件 `if (left && right) {}`（对齐 emitBlockCondition printc.cc:2836），此前把两个子块作为独立语句发射丢失 &&/||。capture_block_condition 递归处理嵌套 BlockCondition。
- **2026-07-16 修复（P7 InfLoop emit）**: 新增 `emit_structured_infloop`（对齐 Ghidra `emitBlockInfLoop` printc.cc:3097-3122），输出 `do { <body> } while(true);`。`BlockType::InfLoop` 分发到该函数。此前 InfLoop 落入 `_ =>` basic 回退，输出裸 op + 无条件分支。配合 B3 的 `BlockInfLoop` struct + `try_rule_inf_loop` 工厂。
- **2026-07-16 修复（P1 括号化 — 最高潜在缺陷风险）**: 实现 OpToken 优先级引擎与括号化，对齐 Ghidra `printlanguage.cc:269 parentheses` + `printc.cc:23-76` OpToken 静态实例表。此前 `op_binary`/`op_unary`/`emit_inline_expr` 直接拼 infix 串无括号化，嵌套表达式如 `a + (b << c)`、`a == (b && c)`、`a - (b - c)` 会语义错误。新增：`optoken` 模块（`binary_precedence`/`binary_associative` 表镜像 printc.cc 的 precedence/associative 字段）+ `child_needs_parens(parent, child, is_right)`（镜像 parentheses 的优先级比较）+ `push_input_parenthesized`（递归时按需包裹括号）。接入 `emit_inline_expr` 与 `op_binary` 两处二元路径。新增单元测试 `test_child_needs_parens_precedence` 覆盖 10 个教科书用例。curl 语料不触发嵌套二元内联故 numbering 不变，但正确性已保证。
- **2026-07-16 修复（label 格式）**: goto 标签从自创的 `LAB_{:08x}` 改为 Ghidra `emitLabel`（printc.cc:3164）格式 `code_r0xXXXX`。新增 `code_label(addr)` helper，镜像 Ghidra：prefix `code_`（joined_/dup_ 块状态未追踪）+ shortcut `'r'`（RAM space，translate.cc:529-533 space 名首字母小写）+ printRaw（space.cc:206-222，`0x` + 按 addr>>32/>>48 收缩的零填充 hex）。两处标签发射点（块入口 printc.rs:592 + push_goto_target printc.rs:1322）已更新。curl 语料无 unstructured goto 故 numbering 不变，但对有 goto 的二进制正确性已保证。
- **历史记录（2026-07-02，已被上方 2026-08-11 状态取代）**：printc 依赖 `emitted: HashSet<usize>`（key=Arc 指针身份）做去重，是 CFT 树遍历尚未完成的临时补丁。完整修复需按 `beginBlock/endBlock` 迁移到 Ghidra 的 `emitBlockGraph` 单次树遍历并删除 emitted/fresh-emitted 补丁；方法名存在不代表行为已覆盖。
- **2026-07-02 修复（R50+R51）**: `op_multiequal`/`op_indirect` 改为 no-op（对齐 Ghidra printc.hh:331,332 `{}`，消除非 C 的 `phi(...)`/`(indirect)` 语句）；`op_cbranch`/`emit_block_condition` 增加条件输出捕获——当 `emit_condition` 产出无效条件（空串、` == `、`!()` 等缺操作数的垃圾）时回退为 `1`（always-true），消除 `if () goto ;`/`if () {`/`if (!())` 语法错误。curl 的 6 处语法错误全部清零。
- **可信度**: 高
- **对应源码**: 当前 `rugra/src/printc.rs`
- **文档目标**: 说明 `PrintC` 在当前 Rugra 架构中的职责、输入依赖与输出边界
- **可信边界**: 本文档描述的是**当前 C-like 输出层的责任分工**，不是“已经达到 Ghidra 等价输出质量”的证明

---

## 模块定位

`printc.rs` 是 Rugra 当前输出层中的核心模块之一，负责把已经进入函数级分析上下文的内部表示，转换为**更接近 C 语言风格**的文本输出。

它在整体链路中的位置更接近：

```text
raw semantics / P-code-like IR
 -> Funcdata
 -> Action / Heritage / CFG-related processing
 -> PrintLanguage
 -> PrintC
 -> C-like pseudocode text
```

因此，`PrintC` 的职责不是：

- 解析二进制
- 直接做反汇编
- 替代 SSA / CFG / 类型恢复本身
- 单独证明最终输出已经与 Ghidra 1:1 一致

而是：

- 消费前序阶段已经建立的函数级语义信息
- 组织输出文本
- 尽量用 C 风格形式表达现有语义
- 在无法恢复高级语义时做**保守降级输出**

---

## 当前职责概述

结合当前工程结构，`PrintC` 的主要责任可以概括为以下几类：

### 1. C-like 文本发射
将内部分析结果发射为伪 C / C 风格文本，而不是继续停留在底层 IR 展示层。

### 2. 输出阶段的语言特化
`PrintLanguage` 更像输出语言抽象层，`PrintC` 则是其中面向 C 风格语法的具体实现。

### 3. 函数级输出组织
围绕单个函数组织输出，包括但不限于：

- 函数头部
- 语句序列
- 表达式文本
- 变量显示形式
- 基本控制流结构的文本布局

### 4. 保守表达
当某些高层语义尚未完全恢复时，`PrintC` 应优先保持语义可追踪，而不是伪装成完整源码。

### 5. Symbol 驱动的局部变量声明 (PRINTC-SYMBOL-DECL-0001)
声明完全由 Action 阶段建立的 `ScopeLocal` 符号表驱动，逐符号发射
（对齐 `PrintC::emitLocalVarDecls`/`emitScopeVarDecls`/`emitVarDecl`，
printc.cc:2260/2518/2497）：
- **快照**：`doc_function` 通过 `snapshot_local_scope` 克隆 `fd.scope`
  （ActionRestructureVarnode 构建、ActionNameVars 命名完成的 ScopeLocal）。
  打印期不重构、不重命名、不重编号；无 scope 则无声明（无兜底）。
- **遍历序**（emitScopeVarDecls cc:2535-2572）：先地址 map 后 dynamic
  列表。地址序 =（空间序 Unique<Register<Stack，起始偏移，usepoint 子序）
  —— `local_maptable_space_rank` 复现 x86-64 maptable 空间序；dynamic 按
  插入序。过滤器：piece 跳过（Rugra 模型无 piece）、category != no_category
  跳过（cc:2541，参数类 0 在签名里声明）、空名跳过（cc:2542）；
  FunctionSymbol/LabSymbol 与多 entry 去重在 Rugra 模型中结构性不可达。
  **注意**：map 分支没有 `$$undef` 过滤（那是 cc:2529 类别分支独有的）
  ——`$$undef` 名的 no-category 符号会被原样声明；生产中
  assignDefaultNames 在 Action 期（coreaction.cc:2998）保证这类名字不会
  存活到打印。
- **拼写**：`emit_local_symbol_decl` = begin_var_decl + push_type_start
  （sym.dtype 逐字）+ display_name + push_type_end + end_var_decl；语句层
  再加 tagLine 与 `;`（cc:2510-2516）。notempty 时块尾一个 tagLine
  （cc:2277-2278）。
- **打印期 renumbering 已删除**：`compact_name_for`/`compact_rename`/
  `compact_base`/`scope_naming_base`/`preallocate_register_compact_names`/
  `declaration_order`/`used_scope_symbols` 全部移除——oracle 没有任何打印
  期重编号路径，命名权威在 Action 阶段（FUNCDATA-LINKSYMBOL-TYPED-0001
  的 ActionNameVars + 符号→high 桥）。
- **删除的 GLUE**：`doc_variable_decls_from_funcdata`（used_varnode_types
  的 xunknown8 类型 + 硬编码 is_declarable 白名单 + long/int 兜底）、
  打印期 `restructure_varnode` 兜底与二次 `assign_default_names`。
  `used_varnode_names`/`used_varnode_types` 仍由 `mark_variable_used`
  记录，仅供 doc_function 的 extern 全局扫描消费。
- fixture：`tests/oracle/printc_symbol_decl_1204`（cover_rebuild，
  pinned base=b6b61d5，overlay 含 LINKSYMBOL 4 文件 + printc.rs），
  4 case（typed temporaries / in_RCX / dynamic 符号 / $$undef+类别跳过）
  双侧逐字节 MATCH。

### vn_type_if_meaningful（2026-06-28 增强）
如果 varnode 是 LOAD op 的输出，返回基于 size 的类型（int/long/byte）而非指针。

### mark_varnode_used LOAD 检测（2026-06-28 新增）
如果 varnode 是 LOAD op 的输出，type_name 用 size-based（int/long/byte）而非 vn.v_type 的指针类型。这让 LOAD 结果声明为 `int piVar92` 而非 `int * piVar92`，**消除了 reconcile_pointer_arith** 的需要。

### push_varnode Priority 1.4 — 权威 HighVariable def inline（2026-06-29 新增）
`push_varnode` 在 Priority 1（用 HighVariable 名字）之后、Priority 1.5（基于自造 map 的 def 查找）之前，新增基于权威 HighVariable 的 def inline：若当前 varnode 无可用 def（def 缺失或 def op 已 dead），但同 HighVariable 的兄弟实例（`high.get_type_representative()`）有可用 def，则 inline 那个 def 表达式。前提是 merge 已在 dead-code 之后运行（action.rs 管线顺序），`high.instances` 为权威存活集。这是用 SSA 权威 HighVariable 替代自造 map 的第一步，保守且安全（仅对"当前实例无 def"生效，不影响正常命名读取）。

### 移除硬编码 RSP/RBP 名（2026-06-29 续）
- `get_varnode_name` 和 `push_varnode` Priority 1/2 不再保留 `name != "RSP"/"RBP"` 例外。Raw register 名统一转为 size-based 局部变量名（对齐 Ghidra `buildVariableName` 默认分支，database.cc:2501-2504）。
- Priority 2 fallback 不再 `match(offset,size) → "RSP"/"RBP"`，统一用 size-based 前缀命名。
- RSP 泄漏 137→0，RBP 泄漏 18→0。

### lhs 不内联修复（2026-06-30）
- **根因**：`push_varnode` 的 Priority 2 Unique-space fallback 在 `is_lhs=true`（赋值左值）时仍从 `inline_candidates` 取出 def 表达式并调用 `emit_inline_expr`，导致无 HighVariable 的 Unique 输出 varnode 在左值处内联了它自身的 def → 产生 `(a + 8) = a + 8;` 自赋值（gcc `lvalue required as left operand of assignment`）。
- **修复**：Priority 2 Unique 分支加 `!self.is_lhs` 守卫（对齐 Ghidra `pushSymbolDetail`/`pushUnnamedLocation`：赋值目标永远解析为命名位置，`recurse()` 内联只发生在读取侧）。Priority 2 Register 分支此前已有该守卫，Unique 分支遗漏，现已一致。
- **效果**：curl gcc 审计 9/24 → 17/24。剩余 6 个失败为独立输出 bug（地址含嵌套 CALL、void 返回值赋值、类型推断 `int *` 误用于位运算），非 lhs-inlining。

### is_raw_register_name 识别 SSA 后缀（2026-07-03）
- **根因**：`is_raw_register_name` 只精确匹配 `"RAX"`，但 `Merge::assign_names`（merge.rs:560-574）为同名寄存器的不同 SSA 版本生成 `RAX_7`、`RDI_6`、`EAX_13` 这类带 `_<digit>` 后缀的 HighVariable 名。`is_raw_register_name("RAX_7")` 返回 false → 原始 SSA 寄存器名直接泄漏进 C 输出（curl 全量 177 处：RAX_65、EAX_29、EDX_40、…）。
- **修复**：`is_raw_register_name` 先剥掉尾部 `_<digits>` SSA 消歧后缀（`rsplit_once('_')` + 全数字尾校验），再查寄存器名集合。`RAX_7`→`RAX`、`RAX_71`→`RAX`、`R8B`/`uVar12` 不受影响。剥后缀后路由到既有的 raw-register → `<prefix>_<offset>:hex` → `compact_name_for` 重编号链，与无后缀的 `RAX` 走同一条路径（对齐 Ghidra `buildVariableName` 局部分支 database.cc:2501-2504 + `assignDefaultNames` database.cc:2862 的单一共享 base）。
- **效果**：curl 寄存器名泄漏 177→0；defect 函数 17/24→7/24（剩余 7 个全是 empty-else body-collapse，独立根因）。

### 诊断桩清理（2026-07-03 续）
- 移除 body-collapse 诊断期间临时加入的 `[DBG-DISPATCH]`/`[DBG-BASICIF]`/`[DBG-IFEMPTY]`/`[DBG-EMITOP]` eprintln 桩（违反临时 TAG 铁律）。诊断证据已落入 coreaction.md 的 ActionDeadCode CALL 保护条目（body-collapse 真根因之一是 DCE 杀 CALL，非 printc）。

### is_block_body_empty 对齐 emit_block_ops 跳过逻辑（2026-07-03 续 2）
- **根因**：`is_block_body_empty` 与 `emit_block_ops` 的 op-跳过逻辑不一致。前者对"末尾 op 是 CBRANCH/BRANCH/RETURN/CALL"的块一律判为非空（提前 return false），但末尾分支是控制流转移，不是 body 语句——Ghidra 在 `emitBlockIf`（printc.cc:2895）用 `setMod(no_branch)` 抑制它。结果：只含 dead 计算 op + 末尾 CBRANCH 的块被判为"非空"，但 `emit_block_ops` 实际什么也不输出 → 产生 `if (cond) {} else {}` 空括号（Ghidra 永不产生此形式）。同时 is_block_body_empty 未检查 `is_implied()` 输出（emit_block_ops:334-338 跳过这些），进一步放大分歧。
- **修复**：删除"末尾分支 → 非空"的提前 return；改为逐 op 扫描，精确镜像 `emit_block_ops` 的跳过集——CBRANCH/BRANCH/BRANCHIND/COPY/MULTIEQUAL/INDIRECT（emit_block_ops:315-323）、`is_implied()` 输出（emit_block_ops:334-338）、RIP-relative、stack-setup、inlined_ops、dead-output 纯计算 op。CALL/CALLIND 不在跳过集里，所以真正含 call 的 body 仍正确判为非空。
- **效果**：curl defect 12（5/24 函数）→ 0（0/24 函数）；curl+httpd 空 else{} 均为 0；main defect 7→0、glob_word 2→0、getparameter/next_url/match_url 各 1→0。剩余 numbering/expression 问题是独立根因。

### RPN 路径 dispatch_op_rpn：PTRSUB/CAST + 隐式内联（2026-07-27 新增）

- **背景**：RPN 发射路径（`dispatch_op_rpn` / `emit_expression_rpn` / `emit_block_basic_rpn`）此前只实现了 COPY、二元/一元算术、LOAD、STORE、CALL、RETURN、CBRANCH；PTRSUB 与 CAST 落入 `_ => {}` 兜底分支不发射任何文本。Ghidra 对应实现是 `PrintC::opPtrsub`（printc.cc:929-1143，结构体字段 `ptr->field`）与 `PrintC::opTypeCast`（printc.cc:448-464，`(type)x`）。
- **本改动（faithful port）**：
  - 扩展 `build_rpn_token_table`，新增 4 个 OpToken（字段逐项对齐 printc.cc:25/26/33/35）：`pointer_member`（`->`，binary prec 66 assoc）、`object_member`（`.`，binary prec 66 assoc）、`typecast`（`(`/`)` presurround prec 62）、`addressof`（`&` unary prefix prec 62）。
  - 在 `dispatch_op_rpn` 新增 `CPUI_PTRSUB` 分支：忠实移植 opPtrsub 的 struct/union（`[&]ptr->field`）、array（`*ptr`）、spacebase/无类型回退（`ptr->field_0x<hex>` / `ptr[off]`）四类发射形态；Rugra 无 TypePointerRel，`ptrel` 分支塌缩为 `ct = ptype->getPtrTo()`（与 legacy `op_ptrsub` 一致）。
  - 在 `dispatch_op_rpn` 新增 `CPUI_CAST` 分支：忠实移植 opTypeCast 的 array-decay `&in0` 短路与 `(type)in0` 主路径；`typecast` 是 presurround，RPN emit 机制自动产生 `(typename)operand`。
- **隐式内联打通**：为让 PTRSUB/CAST（消费时一定是 implied）真正进入 dispatch，引入 `rpn_push_in(op_arc, op, slot, m)`——忠实 `PrintLanguage::pushVn`（printlanguage.cc:197）的 nodepend 记录语义。`COPY`/`LOAD`/`PTRSUB`/`CAST` 的操作数改为走 `rpn_push_in`，由 `rpn_recurse`（printlanguage.cc:514）按 implied 标志决定内联 def 或推叶子 atom。此前各 dispatch 分支直接 `make_atom_for_vn + rpn_push_atom`，等价于只走 `pushVnExplicit` 叶子路径，导致所有 implied def（含 PTRSUB/CAST）永不被内联。
- **当前生效限制（诚实声明）**：`CPUI_PTRSUB`/`CPUI_CAST` op 目前在 curl/httpd 中**不被产生**——Rugra 缺少 `RulePtrsub`（INT_ADD→PTRSUB 的创建规则，ruleaction.cc，仅移植了 `RulePtrsubUndo`/`RulePtrsubCharConstant`/`RulePtraddUndo` 这类消费现有 op 的规则），且 `ActionSetCasts::castInput` 的 PTRADD/PTRSUB pointer-fit 检查与 castOutput 延后（coreaction.rs:2893-2897 注释），故 CAST 创建对 curl 当前类型推断结果不触发（`cast_standard_full` 返回 None）。本 PR 的 dispatch 分支已就位且经过 Ghidra 行逐行核对，待上述底层 infra 补齐后即生效。
- **效果（curl diff 门禁）**：skeleton diff 2880→2873（轻微改善，来自 implied 算术 def 现在内联），defects 0→0，numbering 0→0，1287/1287 单元测试通过。无回归。

### RPN 表达式层畸形发射修复：notPrinted 过滤 + ZEXT/SEXT/SUBPIECE dispatch + 真 recurse 路由（2026-08-17，PRINTC-CAST-EXPR-0001）

- **背景**：`result/curl_cur.c` 出现 1168+ 处 `= (uVar28;` / `* = uVar20)))) = 0x3489;` 形态的畸形行。根因（纯发射层，非上游 IR）：
  1. `emit_block_basic_rpn` 缺 Ghidra `notPrinted()` 过滤（printc.cc:2696；op.hh:182 = `marker|nonprinting|noreturn`）。MULTIEQUAL/INDIRECT 的 TypeOp ctor 带 `marker`（typeop.cc:1947/1988），Ghidra 因此从不把它们作为语句打印；Rugra 放行后，`emit_expression_rpn` 已 push assignment token + LHS atom，而 dispatch 落入 no-op（`opMultiequal` 本身就是空实现，printc.hh:331）→ 语句结束时 `revpol` 残留 `assignment(visited=1 < stage=2)` 不完整条目，泄漏进下一语句的 `rpn_emit_op`，在错误位置输出 ` = ` / `(` / `)`——即全部 `= (` 行与 `))))` 连串。
  2. `INT_ZEXT`/`INT_SEXT`/`SUBPIECE` 同样落 `_ => {}`（Ghidra 是 printc.cc:786/799/843 的 cast-or-opFunc 双臂）。
  3. `rpn_push_op`/`rpn_push_atom` wrapper 把 printlanguage.cc:132-133/165-166 的 `recurse()` 委托给 printlanguage.rs 的 no-op 自由函数（无 op arena）——mid-expression push 时 pending 输入被静默丢弃。
  4. `hidden` token 表字段与 printc.cc:23 不符（应为 stage=1/prec 70，便捷 ctor 写死 stage=2/prec 0——同样残留 incomplete 条目）。
- **本改动（faithful port）**：
  - `emit_block_basic_rpn` 增加 notPrinted 过滤：`is_marker() || (flags & NONPRINTING) || (flags & NORETURN)`（flags 由 `opcode_flags` 在 op 创建时正确初始化，已核实）。
  - `dispatch_op_rpn` 新增 `CPUI_INT_ZEXT`/`CPUI_INT_SEXT`/`CPUI_SUBPIECE` 三臂：`cast_strategy.is_zext_cast/is_sext_cast/is_subpiece_cast` 命中 → `rpn_op_type_cast`；否则 `rpn_op_func`（`getOperatorName` = `"ZEXT/SEXT/SUB" + insize + outsize`，typeop.cc:1122/1148/2127）。SUBPIECE 的 `doesSpecialPrinting` 字段抽取分支（printc.cc:846-871）**可达**：SPECIAL_PRINT addlflag（op.rs ↔ op.hh:208）由 RuleSubRight（ruleaction.cc:7257，主管线已注册）设置，`is_piece_structured`（datatype.rs:443）对 Struct/Union/Array 为真；但字段抽取体（printc.cc:853-868 的 pushPartialSymbol/findTruncation+object_member 两臂）为继承 MISSING，RPN 路径落到 isSubpieceCast → opTypeCast / opFunc（与 legacy `op_subpiece` 同样 fall-through，行为非回归），降级登记 `PRINTC-SUBPIECE-FIELDEXTRACT-0001`（2026-08-17 事后审计修正，原文"Rugra 均无、不可达"失实）。
  - token 表新增 `function_call`（`(`/`)` postsurround prec 66 bump 10，printc.cc:28）与 `comma`（binary prec 2 assoc，printc.cc:55）；`hidden` 改为表内直构聚合 `{ "", "", 1, 70, … }`（printc.cc:23）。
  - `rpn_op_func`/`rpn_op_hidden_func`/`rpn_op_type_cast`（自 CAST 臂重构共享）/`rpn_operator_name_ext` 四个 helper；`readOp` 线穿 dispatch（`emit_expression_rpn` 传 `None` = printc.cc:2493 的字面 0；`rpn_recurse` 传读 op = printlanguage.cc:532；`isExtensionCastImplied` 对 `readOp==null` 返回 false，与 cast.cc:257 一致）。
  - `rpn_push_op`/`rpn_push_atom` wrapper 先走真 `self.rpn_recurse()`（单一 `if (pending < nodepend.size()) recurse();` 语义不变），再进自由函数——Ghidra 的 recurse 是虚调用真实现，此前路由到 no-op 等于丢操作数。
- **效果（干净 worktree = HEAD a301036 + 仅本 printc.rs overlay）**：`= (` 计数 1262→6 且 6 处全为合法 C（cast 赋值 / `== (bool)` 比较），真畸形 0；`))))` 连串 0；ZEXT/SEXT 按 oracle 的 opFunc 形态发射（`ZEXT48(x)`/`SEXT18(bVar1)`）；差分 skeleton 4724→3300、defects 0→0、numbering 0→0；gcc 审计 103 OK/20 FAIL → 105 OK/18 FAIL（GetStr+hugehelp 修复，其余 18 与基线同错同位）；124/124 75 decompiled/0 panic/1 timeout=基线；cargo test --lib 1373/5 失败集逐名一致。
- **当前生效限制（诚实声明）**：二元算术仍走 `emit.tag_op(" + ")` 直发不经 RPN token（嵌套优先级括号缺失，3 处 `== … + 0 - … < 0` 形残差）——binary token 化为后继 TODO（PRINTC-BINARY-RPN-0001 建议）；`uVara0` 类名字 use-registered 但声明缺失为 varmap 域既有残差。

### PRINTC-CAST-EXPR-0001 事后审计窄面修复（2026-08-17，F1/F2/F3）

- **F1 证据失实修正**：上文 198 行 SUBPIECE 分支"不可达"表述已就地改为"可达、字段抽取体为继承 MISSING、已登记降级"（见上）。`src/printc.rs` SUBPIECE 臂注释同步修正，并登记 `PRINTC-SUBPIECE-FIELDEXTRACT-0001`（三个邻接继承缺口：pushPartialSymbol/findTruncation 字段抽取体缺失；`is_piece_structured` 只匹配 Struct|Union|Array，窄于 Ghidra `metatype<=TYPE_ARRAY`（type.hh:929-934，含 enum/partial）；`is_subpiece_cast` 缺 PartialStruct/PartialUnion 输入臂（cast.cc:413-418 vs type_system/cast.rs:85-87））。
- **F2 parentheses hiddenfunction 分支精确移植**（printlanguage.cc:309-319）：top 为 hidden 且 stage==0 且 revpol 长度>1 时，读 `revpol[size-2].tok`（前一个未完成 token）——非 binary 且非 unary_prefix → false；其 precedence 严格小于 op2 → false；相等保留括号（防相邻 token 被当作 associative）。Rugra 侧 `parentheses()` 增 `prev: Option<&OpToken>` 参数（None 编码 `revpol.size()<=1`），`rpn_push_op` 调用点从 revpol 倒数第二项构造。原实现硬编码 `return true` 且注释引用不存在的 `parentheses_in_stack`——已删除。curl 语料 hidden 路径 0 触发，E2E 输出逐字节不变（预期，见 Differential）。
- **F2 附带注释修正**：`build_rpn_token_table` hidden 项 "precedence 70 (looser than function_call's 66…)" → "tighter"（高 precedence=绑更紧；70>66 使父 function_call 走 `topToken->prec < op2->prec` 免括号），并补全 parent 侧由 hiddenfunction 分支经祖父 token 决定的表述。
- **F3 markup 对齐**：`rpn_op_func` name atom 由 `FuncnameColor + op_index=-1` 改为 `NoColor + op 锚`（printc.cc:428-431 "don't markup the name as a normal function call"，`pushAtom(Atom(nm,optoken,EmitMarkup::no_color,op))`）。纯 markup 变更，无文本输出影响（text emitter 忽略颜色与锚）。


---

## 设计边界

为了避免误解，下面明确 `PrintC` 的输入边界与输出边界。

### 输入依赖

`PrintC` 的有效工作依赖于前序阶段已经提供的内容，例如：

- `Funcdata`
- `PcodeOp` / `Varnode` 图关系
- 基本块与控制流信息
- 已恢复的部分变量语义
- 已恢复的部分类型信息
- 已知函数原型或调用信息
- 输出发射器（`Emit`）

如果这些输入不完整，`PrintC` 的输出质量也会受到限制。

### 输出产物

`PrintC` 的直接产物是：

- C 风格文本
- 近似伪代码
- 可读性优于裸 IR 的结构化输出

### 不应承担的责任

`PrintC` 不应自行承担以下职责：

- 推断不存在的高级类型事实
- 伪造不存在的变量来源
- 重写底层地址事实以迎合文本美观
- 单独决定 SSA / CFG 正确性
- 将“未恢复”伪装为“已恢复”

---

## 与其他模块的关系

### 与 `printlanguage.rs` 的关系
`PrintLanguage` 是更上层或更抽象的输出语言接口层；`PrintC` 是当前面向 C 风格输出的具体实现。

可以把两者理解为：

- `PrintLanguage
`: “如何组织一种输出语言”
- `PrintC`: “如何把当前语义尽量写成 C 风格”

### 与 `funcdata.rs` 的关系
`Funcdata` 是单函数分析上下文；`PrintC` 主要消费其中的结果，不负责替代 `Funcdata` 的建立过程。

### 与 `heritage.rs` / `action.rs` / `block.rs` 的关系
这些模块决定分析形态、图结构和中间语义稳定度；`PrintC` 建立在它们之上做展示，不应反向篡改核心事实。

### 与类型系统的关系
`PrintC` 可以利用已有类型信息改善输出，但不应把不可靠的类型猜测包装成确定类型结论。

---

## 导出的公共 API

## `pub struct PrintC`

### 作用
`PrintC` 是当前 Rugra 中面向 C 风格输出的打印器。

它对应的核心角色是：

- 管理 C 风格文本发射过程
- 驱动底层发射器写入缓冲内容
- 将函数级语义组织为更接近 C 的输出形式

### 当前职责理解
从当前架构角度，`PrintC` 更像：

- **输出层实现者**
- **文本结构组织者**
- **语义到 C-like 文本的映射器**

而不是：

- 独立分析器
- 独立 CFG 恢复器
- 独立类型恢复器
- 最终正确性证明器

---

## `pub fn new(emit: Box<dyn Emit>) -> Self`

### 作用
创建一个新的 `PrintC` 实例，并绑定一个输出发射器。

### 参数

- `emit`: 一个实现了 `Emit` 的发射器对象，用于接收 `PrintC` 最终产生的文本输出

### 使用语义
这个构造函数体现了当前输出层的一个关键设计点：

> `PrintC` 不直接把结果固定写到某个全局目标，而是通过可替换的 emitter 发射输出。

这意味着调用方可以：

- 把输出写入内存缓冲
- 收集输出文本
- 走无标记输出路径
- 以后扩展为其他输出后端

### 边界说明
`new()` 只是构造输出器，不代表：

- 当前函数已经可打印
- 所有语义都已恢复
- 最终输出质量已可接受

---

## `pub fn take_emit(self) -> Box<dyn Emit>`

### 作用
取回 `PrintC` 内部持有的发射器，同时消费当前打印器实例。

### 使用场景
该接口适合以下场景：

- 调用方在输出完成后，取回底层 emitter
- 从 emitter 中提取最终缓冲内容
- 将输出结果转成字符串或其他可消费形式
- 进行测试断言或结果归档

### 设计意义
这个接口说明 `PrintC` 的当前实现并不是直接返回一个“最终字符串”的最简单封装，而是通过 emitter 把输出过程与输出载体解耦。

这对当前 Rugra 很重要，因为它允许：

- 输出层与缓冲实现分离
- 更方便做测试和调试
- 后续兼容不同风格的输出后端

### 注意事项
调用 `take_emit()` 后，原 `PrintC` 实例被消费，不能继续使用。

---

## 当前实现应如何理解

从整个工程现状出发，当前 `PrintC` 的合理定位应该是：

> 一个正在持续演进中的 C-like 输出器，它已经承担 Rugra 输出链路中的关键角色，但它的最终表现高度依赖前序分析阶段的质量，不能单独被当作“完整反编译器输出质量”的证明。

换句话说：

- `PrintC` 存在且重要
- `PrintC` 是当前输出层主干之一
- `PrintC` 能表达 C 风格结果
- 但 `PrintC` 的存在不等于：
 - 输出已接近真实源码
 - 所有控制流都已结构化
 - 所有变量都已正确恢复
 - 与 Ghidra 输出已经一致

---

## 当前输出层的可信表述

后续文档中，关于 `PrintC` 建议使用以下表述。

### 推荐表述

- `PrintC` 是当前 Rugra 的 C 风格输出实现
- `PrintC` 负责把已有函数语义组织成可读文本
- `PrintC` 建立在 `Funcdata` 和前序分析结果之上
- `PrintC` 的输出质量依赖前序恢复结果
- `PrintC` 在无法恢复高级语义时应允许保守降级

### 不推荐表述

- `PrintC` 已生成与 Ghidra 完全一致的 C 输出
- `PrintC` 已经完整恢复所有高级控制流结构
- `PrintC` 可以单独代表端到端反编译质量
- `PrintC` 的存在证明 Rugra 已是完整成熟反编译产品

---

## 调用方应承担的责任

调用 `PrintC` 的上游代码，应尽量保证：

1. 已准备好待输出的函数上下文
2. 关键 IR 结构未损坏
3. 基本控制流和语义信息已进入可打印状态
4. 发射器的生命周期和结果提取方式已明确

否则，即使 `PrintC` 本身工作正常，最终文本仍可能：

- 很低层
- 不够结构化
- 命名贫弱
- 类型缺失
- 与理想 C 风格结果相差较大

---

## 维护建议

后续若继续维护 `printc.rs` 相关文档，建议重点同步以下信息：

- 是否新增了公开方法
- 是否改变了 emitter 交互方式
- 是否新增了函数级打印入口
- 是否改变了 C-like 输出的组织策略
- 是否引入了新的结构化控制流输出能力
- 是否改变了与 `PrintLanguage` 的职责边界

同时应联动检查：

- `docs/api/printlanguage.md`
- `docs/data_contract.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`

---

## 一句话总结

`PrintC` 是 Rugra 当前将内部分析结果转成 **C-like 文本输出** 的关键实现，它负责“如何写出来”，但不单独负责“前面的语义是否已经完整恢复”，因此应被理解为**输出主干模块**，而不是“已经证明最终反编译质量成熟”的证据。
---

## 更新日志

### 2026-06-23：自包含 C 输出

- `doc_function()` 现在在每个函数前 emit Ghidra 风格的 typedef：`byte`、`undefined`、`undefined4`、`undefined8`、`_struct`。原因：`ActionInferParams`/`ActionTypeInfer` 的 size-based 推断会生成 `byte bVarN;` 声明，缺少 typedef 时无法通过 C 编译。`_struct` 是被解引用变量的泛型后备类型（配合 prettyprint 的 `->field` 重写）。

### 2026-06-23（续）：声明白名单覆盖双命名格式

- `is_declarable` 现在同时匹配两种 HighVariable 命名：`bVar60`（merge.rs 生成的 prefix+digits）和 `bVar_60`（printc fallback 的 prefix+`_`+hex）。此前只匹配带下划线的，导致 `bVar60`/`lVar21` 等 Register 空间变量被声明过滤掉，在函数体里引用却未声明。

### 2026-06-23（续）：STORE 地址 cast 合法化

- `op_store()` 所有地址解引用路径现在统一 emit `*(long *)addr` 形式：
 - 全局符号：`*(long *)sym_name`
 - 合成 DAT 名：`*(long *)DAT_xxxxx`
 - 表达式地址 `*(a + b)`：`*(long *)(a + b)`
 - 默认：`*(long *)addr`
- 原因：STORE 的地址操作数可能是 long/int scalar（非指针），直接 `*addr` 非法。`*(long *)` cast 让整数转指针再解引用，无论 addr 声明类型如何都合法。

### 2026-06-23（续）：LOAD/STORE 全路径 cast 合法化

- `op_load()` 和 `op_store()` 的所有地址解引用路径现在统一 emit `*(long *)addr`：
 - LOAD 默认路径（非指针地址）
 - STORE RIP-relative 路径（`*(RIP + sym)` → `*(long *)sym`）
 - STORE 表达式地址（`*(a + b)` → `*(long *)(a + b)`）
 - STORE 全局符号 / 合成 DAT_ 名
- 原因：与之前的 `->field` 重写一致，地址操作数可能是 scalar，`*(long *)` cast 保证无论声明类型如何都合法。

### 2026-06-23（续）：callee-saved/帧寄存器声明

- `is_declarable` 现在允许声明 RSP/RBP/RBX/R12-R15（callee-saved + 帧寄存器）为 `long`。原因：栈帧分析不完整时，这些寄存器名会出现在表达式里（如 `glob_word(RBP + 4, ...)`）。声明为 `long` 保证输出可编译，同时不改变语义（它们确实是 8 字节寄存器）。RIP（0x200）仍是伪寄存器，不声明。

### 2026-06-23（续）：自包含全局变量声明

- `doc_function()` 现在在 typedef 后、签名前 emit `extern long NAME;` 声明，覆盖函数体引用的所有 Ram/Const 空间全局变量（来自符号表/字符串表，非函数调用目标）。对齐 Ghidra 的自包含输出——每个函数引用的全局都有可见声明。
- 同时扫描 `used_varnode_names` 捕获符号表里的全局名（如 `glob_buffer`）。

### 2026-06-23（续）：synthetic DAT_ 全局声明收集

- `op_store` 生成 synthetic `DAT_xxxxx` 名时现在调用 `mark_variable_used`，确保它在 `used_varnode_types` 中，从而被 extern 声明收集捕获。
- extern 收集移除了 `DAT_` 前缀排除（之前 synthetic DAT_ 名被排除在 extern 之外）。


### 2026-06-23（续）：CALLIND 地址 0 的 cast

- `op_call` 当目标地址为 0（未解析的间接调用）时，emit `(*(void(*)())0)` 而非 `(*0x0)`。函数指针 cast 让调用合法。

### 2026-06-23（续）：char literal brace escape

- printc 输出字符字面量时，brace/paren/quote 字符（`}`、`{`、`)`、`(`、`\`、`'`、`"`）用 hex escape（`}`）而非裸字符。原因：`if (bVar_0 == '}') return;` 里的 `}` 会被 post-process 的 brace 计数器（backfill、orphan-break、fix_pointer_arithmetic）误读为代码右花括号，导致函数体提前关闭。case label 同理。

### 2026-06-23（续）：RETURN 返回值推断

- `op_return()` 当 RETURN op 无显式返回值输入时，扫描同块 RETURN 前最后一个写 RAX/EAX 的 op，emit 其值作为返回值。对齐 Ghidra 把 `xor eax,eax; ret` 重构为 `return 0` 的行为。这是前端语义改进（非后处理 hack），缩小了与 Ghidra 的差距 4（返回值推断缺失）。

### 2026-06-23（续）：else 分支 seen_return 抑制修复 + is_block_body_empty 控制流感知

- `is_block_body_empty()` 现在对以 CBRANCH/BRANCH/RETURN/CALL 结尾的块返回 false（有控制流的块不是空）。
- emit_block_structured 的 legacy if/else 分支：else 块不再被 then 分支的 seen_return 抑制。else 是条件分支的一部分，不应受 then 分支的 return 影响。emit else 时临时清除 seen_return。
- 这是前端语义改进，恢复了大量被错误丢失的控制流分支。

### 2026-06-23（续）：BlockIf 结构化 else 也修复 seen_return 抑制

- BlockIf（结构化 if-else）的 else body emit 也移除了 seen_return 检查，临时清除 seen_return。
- httpd 控制流差 168→119（-29
### 2026-06-23（续）：case_body_indices 字段

- `PrintC` 新增 `case_body_indices` 收集 switch case body 块索引，供 BlockIf emit 检测。

### 2026-06-23（续）：dry-run 覆盖 emit_block_structured

- CaseDetectEmit dry-run 现在覆盖 emit_block_structured（递归检测嵌套 BlockSwitch/BlockIf 的 case label），不只是 emit_block_ops。
- 但发现 case label 问题的根因是 emit 顺序（BlockIf 提取 case body 后，BlockSwitch 的 case label emit 与 body emit 的 emitted 去重不匹配），不是 if_body 内容。dry-run 无法检测这种顺序问题。
- if_no_exit 仍禁用。需要 emit 层重构（BlockSwitch 的 case emit 检查 emitted set）。

### 2026-06-23（续）：BlockSwitch case emit 检查 emitted set

- BlockSwitch 的 case/default emit 现在检查 emitted set——如果 case body 已被 BlockIf 提取（在 emitted 里），跳过整个 case（label + body + break）。
- 这修复了 BlockIf 提取 case body 后 case label 与 body 不匹配的问题。
- 但嵌套 switch + BlockIf 提取的 emit 顺序问题仍存在（httpd main 有 8 个 switch，BlockIf 提取打断了 switch 间的 emit 顺序）。if_no_exit 仍禁用。

### 2026-06-23（续）：goto BlockIf CaseDetectEmit 保护

- BlockIf emit 对 GOTO_EDGE_1 标记的 condition 做 dry-run case label 检测。检测到 case label 则回退到顺序 emit。

### 2026-06-23（续）：CaseDetectEmit emit_block_structured 递归

- BlockIf dry-run 现在用 emit_block_structured 覆盖嵌套路径。

### 2026-06-23（续）：BlockSwitch case label 保留 + curl-only goto

- BlockSwitch case emit 不再跳过已提取的 case body 的 label——保留 case label + 空 body。
- 但 httpd main 有重复 case 2（两个 switch 的 case 混合），需要 switch 上下文追踪。
- 回退到 curl-only goto。gcc 53/53 + curl 119。

### 2026-06-23（续）：BlockSwitch case emit 回退

- case body 已 emitted 时跳过整个 case（label + body）。

### 2026-06-23（续）：case body 完整性实验

- 强制 emit case body（从 emitted 移除）→ curl 109 但 gcc 51（重复 body）。
- 回退到 body_already_emitted（保留 label + 空 body）→ gcc 52 + curl 114。
- 正确修复：blockaction 层用支配树检测跨 switch 边界，防止 goto 级联创建跨 switch BlockIf。

### 2026-06-24：Basic 块后继递归实验（已禁用）

- 尝试在 emit_block_structured 的 Basic 块 else 分支中递归后继块。
- 问题：file2string_part_0 的 canary 块后继递归触发了未声明变量错误。
- 根因：canary 检查块在 RETURN 后仍有 fallthrough 后继，但递归越过了 RETURN。
- return_in_block 检查 + func_addr 范围 + depth limit 都无法完全修复。
- 禁用递归，保留 ruleCaseFallthru 处理 switch case body 链式。
### 2026-06-25：DEAD flag emit skip

### 2026-06-26：emit_block_structured DEAD 块标记为 emitted（single-ownership）

- DEAD 块（被 identify_internal 消费的块）在 emit_block_structured 跳过时现在也标记为
 emitted，防止 doc_function 的 root/unreachable 循环（行 3116-3134）重复访问。
- 这是 single-ownership 原则：消费块只通过其结构化父块 emit，不通过后继遍历重入。
- 验证：curl 24/24 gcc，httpd 29/29 gcc。175/176 测试（test_switch_case 预存失败不变）。

### 2026-06-26（续）：修复 pass19 naive 大括号移除 + 重新启用 seen_return 保存/恢复

**根因**：post_process_output 的 pass19 用 naive 大括号计数（直接数 { }）检测函数闭合，
当函数含 char/string 字面量中的 `}`（如 `case '}'`）时会误判 depth<0，移除函数闭合 `}`。
seen_return 保存/恢复启用后更多 case body 被 emit，触发该 bug 导致 ap_getparents 函数边界损坏。

**修复**：
- pass19 不再移除大括号（naive 计数不可靠），改为 emit as-is。
- 重新启用 switch case body emit 的 seen_return 保存/恢复（每个 case 是独立控制流路径，
 一个 case 的 return 不应抑制其他 case 的 body）。

**验证**：176/176 测试通过（含 test_switch_case_structuring，输出 case 0 + case 1）。
curl 24/24 gcc。httpd 29/29 gcc，0 goto。

### 2026-06-26（续）：WhileDo body emit 用 emit_block_ops 绕过 DEAD 检查

- WhileDo body 被 identify_internal 消费（DEAD）。emit_block_structured 会跳过 DEAD 块，
 导致循环体操作不被输出。
- 修复：WhileDo emit 时检查 body 是否 DEAD，若 DEAD 则用 emit_block_ops 直接输出操作。
- 验证：176/176 测试。getparameter TYPES whiledo=1（循环保留）。

### 2026-06-26（续）：switch case_values 去重（修复 ap_getparents duplicate case）

- 两个 CBRANCH 块比较相同常量时会在同一 switch 产生重复 case。emit switch case 时用
 emitted_case_values 集合去重，跳过已输出的 case value。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc（恢复！）。

### 2026-06-26（续）：seen_return 不抑制控制结构块（WhileDo/DoWhile/If/List）

- emit_block_structured 的 seen_return 检查现在跳过控制结构块（WhileDo/DoWhile/If/List），
 这些块代表可达控制流路径，必须在 RETURN 后仍渲染。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：基本块 emit 后递归结构化后继块

- 非 CBRANCH 基本块 emit 操作后，现在递归 follow out-edges 到结构化块（WhileDo/DoWhile/If/Switch 等）。
 只递归结构化块（不递归基本块）避免 canary 问题。
- 之前后继递归被禁用（canary blocks），导致 WhileDo 等只能通过 unreachable-loop 输出。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockList emit 后递归结构化后继块

- BlockList emit 完所有 children 后，现在 follow out-edges 到结构化块（WhileDo/If/Switch 等）。
- 与基本块后继递归对称，确保 BlockList 的后续结构化块被访问。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：if-empty-check 不抑制结构化块（WhileDo/DoWhile）

- 基本块的 if-branch empty-check（两分支空/单分支空/legacy if-else）在直接 emitted.insert
 分支索引时，现在只对 Basic/Copy 块插入，不抑制 WhileDo/DoWhile 等结构化块。
- 之前 WhileDo 被直接 insert 到 emitted 集合而不被 emit，导致不可达。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockIf body emit 的 emitted.insert 加 Basic-only 守卫

- BlockIf 的 has_case/both-empty/if-body-empty 路径的 emitted.insert 现在只对 Basic/Copy 插入。
- 避免结构化块（WhileDo）被直接 insert 到 emitted 而不被 emit。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockIf else-body empty 路径 emitted.insert 加 Basic-only 守卫

- 行 590（else-body empty 分支）的 emitted.insert 现在只对 Basic/Copy 插入。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：force-emit WhileDo/DoWhile 块（fresh emitted set）

- 2d 遍历：用 fresh emitted set 强制 emit 所有 WhileDo/DoWhile 块，绕过 stale emitted 条目。
- 大幅增加循环恢复
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（varmap 集成）：ScopeLocal 接入 get_stack_variable_name

- `PrintC` 新增字段 `scope: Option<crate::varmap::ScopeLocal>`，在 `doc_function` 开头构建一次。
- `get_stack_variable_name` 的 Case 1（INT_ADD(RSP, const)）在 struct 检测之后、启发式 local_XX 之前，查询 `scope.find_symbol(offset)`，命中则返回符号名。
- **Graceful fallback**：当 scope 无符号覆盖该偏移时，回退到现有启发式，保证不破坏输出。
- **已知阻碍**：Rugra 的 x86 lift 将 RSP 相对访问留在 Register space，不产生 Stack-space varnode，因此 `ScopeLocal::restructure_varnode` 的 `gather_varnodes` 几乎找不到符号。要真正消除 uVar 碎片，需先实现 RSP→Stack spacebase 提升通道（ALIGNMENT_ROADMAP P0 #1 剩余项）。
- 验证：curl 24/24 gcc，httpd 29/29 gcc，200/200 测试。

### 2026-06-26（varmap 集成续）：复用 ActionRestructureVarnode 构建的 fd.scope

- `PrintC.scope` 现优先从 `fd.scope`（由 `ActionRestructureVarnode` coreaction.cc:2274 构建）克隆复用，仅在缺失时本地构建（clone 因 doc_function 取 `&Funcdata`）。
- 这样 coreaction 流水线（`&mut Funcdata`）构建的 ScopeLocal 可被 printc 查询，避免重复构建，集成进 Action 流水线。
- 验证：curl 24/24 gcc，httpd 29/29 gcc，205/205 测试。

### 2026-06-27（会话3 G3 续）：scope 符号声明增强

- `used_scope_symbols: RefCell<HashSet<String>>` — 记录 `get_stack_variable_name` 引用的 scope 符号名（STACK LHS 等 discovery 漏掉的路径）。
- `doc_variable_decls_from_funcdata` 安全网：保守声明所有 scope 符号（StackX_*）。scope 符号按定义是函数栈局部，声明它们只会产生 unused 警告而非编译错误——远比 undeclared 标识符安全。类型按 size 选 int/long。

**背景**：G3 def-linking 原型验证有效（helpf 解析出 10 个栈符号 StackX_0..48），printc 此前无法声明这些符号导致 undeclared。此增强声明它们。但 def-linking 与 jumptable/switch 交互（switch 表本身是 LOAD）导致 main 等函数 "switch quantity not an integer" 回归，故 def-linking 暂回退，本声明增强保留（正确且无害）。def-linking 重启需 jumptable/typeop 协调。

### 2026-06-27（会话3 G3 续2）：~~switch 表达式 (long) cast~~（**2026-07-16 已移除**）

- ~~switch 控制表达式包裹 `switch ((long)(...))`。~~ **2026-07-16 修复**：审计 P6 发现 Ghidra emitBlockSwitch（printc.cc:3313）发射 `switch (<expr>)` 无任何合成 cast —— Ghidra 通过 FuncProto/typelock 在上游规范化控制类型，从不在 print 阶段注入 cast。Rugra 的 `(long)(...)` 是无 Ghidra 对应物的自创。已改为 `switch (<expr>)`。当 varmap/typeop 把 switch index 推断为指针类型时仍可能 gcc 报错，但正确解法是上游 type 规范化（对齐 Ghidra），而非 print 阶段 cast。

### 2026-06-27（会话3 uVar 调查）：uVar_N 碎片根因深度诊断

**目标**：减少 curl 反编译输出中 uVar_N 碎片（149，main 占 69）。

**诊断方法**：实证追踪 main 的 7 个 uVar（uVar_0/18/28/a0/a8/b0/b8）。
- **全部 7 个 uVar 都无赋值定义（NODEF）**：它们在表达式中被使用（如 `strequal("--", uVar_18)`），但在输出中从未出现 `uVar_X = <expr>` 赋值语句。
- 这些 uVar 是**未初始化变量**——其定义 op 未被输出。

**输出路径分析**：printc 有 6+ 条独立的 varnode 解析路径（push_varnode Priority 0/1/1.5、op_call 参数解析、op_binary、emit_inline_expr、resolve_varnode）。诊断确认 Priority 1.5（push_varnode 行 4022，针对 uVar 的 def-map 内联）**对这些 uVar 0 次命中**——说明它们走了其他路径（很可能是 op_call 的 Register 参数解析，3753+），绕过了 Priority 1.5 的内联。

**正确修复方向**（需专门会话）：
1. 统一 varnode 解析路径——所有路径都应经过 push_varnode 的统一内联逻辑
2. 或在 op_call/op_binary 路径中复用 Priority 1.5 的 def-map 内联（当前仅 Register 空间走内联，Unique 空间 fallthrough 到 push_varnode 但未触发）
3. 关键：uVar 的定义 op（CALL 输出/INT_ADD）应在使用点内联为表达式，而非声明独立变量

**此问题与 G3 spacebase 正交**：spacebase 修复的是*栈变量*（StackX_*），uVar 是*中间临时*。两者独立。

### 2026-06-27（会话3 uVar 修复）：emit_inline_expr 处理 COPY — uVar 碎片 149→0

**根因定位**（实证诊断）：通过在所有 uVar 命名点加诊断，确认 uVar_N 全部来自 `emit_inline_expr` 的 `_ =>` fallback（行 2048），且 def_op 全是 **CPUI_COPY**（142 次命中：uVar_28×61, uVar_0×29, uVar_a0×22, uVar_18×10...）。

`emit_inline_expr` 的 match 未处理 CPUI_COPY，导致 COPY 操作落入 fallback，输出 `uVar_N`（未初始化变量碎片）而非内联 COPY 源表达式。

**修复**：在 emit_inline_expr 的 match 开头添加 CPUI_COPY 分支：
```rust
OpCode::CPUI_COPY => {
 if !def_op.inrefs.is_empty() {
 self.push_input(def_op, 0); // COPY(x) → 内联 x
 return;
 }
}
```
COPY 是语义上的 no-op 赋值，内联其源始终正确。

**效果**：
- curl uVar: **149 → 0**
- httpd uVar: **126 → 0**
- 例：`strequal("--", uVar_18)` → `strequal("--", lVar_0)`（COPY 源 lVar_0 正确内联）
- 682/682 测试 + curl 24/24 + httpd 29/29 全绿，0 goto，无回退

此修复是单点正确的——之前 emit_inline_expr 的 6+ 分支处理了所有算术/比较 op，但遗漏了最基本的 COPY。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29：compact 变量重编号基础设施（assignDefaultNames, database.cc:2862）

- `compact_name_for(raw) -> Option<String>` — 忠实移植 Ghidra `Scope::assignDefaultNames`（database.cc:2862）。按类型前缀（bVar/lVar/iVar/piVar/...）从 1 顺序重编号，替代原始 offset/counter（bVar21 → bVar1）。
- 基础设施：`compact_rename` HashMap 缓存 + `compact_counters` 按前缀计数器（每函数重置）+ discovery_pass 守卫（discovery 期间不重编号）。
- 接入点：push_varnode（raw-register 路径 + high-variable 路径）+ get_varnode_display_name 包装器 + doc_variable_decls_from_funcdata 声明循环。
- 单元测试 `test_compact_name_for` 验证逻辑正确（bVar21→bVar1, bVar29→bVar2, param_1→None）。
- **已验证生效**：compact 名称现在完全体现在输出中（2026-06-29 确认）。例如 my_fwrite 从 `bVar21`/`lVar25`/`piVar23` 变为 `bVar1`/`lVar1`/`piVar1`（Ghidra 风格）。curl lVar1 出现 57 次、bVar1 出现 22 次，与 Ghidra 的 assignDefaultNames 命名风格完全对齐。此前的"已知限制"是因为测试时用了过期的输出文件（stdout 未重定向到 result/）；正确重定向后 compact 名称正常体现。

### 2026-06-29：BlockIf if-goto emit（goto_target.is_some()）
- printc.rs BlockType::If emit 新增 if-goto 分支：当 `if_data.goto_target.is_some()` 时，emit condition block 的 ops（CBRANCH 处理分支），不 emit 占位 body。对应 Ghidra newBlockIfGoto 的 emit 语义。

### 2026-07-28：if-goto 的 BlockIf::goto_type → CBRANCH branch_type 映射
- Ghidra `emitBlockIf`（printc.cc:2914-2916）读取 BlockIf 的 gototype
  （由 `BlockIf::scopeBreak` block.cc:3075-3084 设置）并调用
  `emitGotoStatement(condBlock, gototarget, gototype)`。
- Rugra 的 if-goto 发射通过 `emit_block_ops` 到达 CBRANCH op，其中
  `op_cbranch` 读 `op.branch_type`（由 ActionNormalizeBranches 设置）来决定
  break/continue/goto。为忠实映射 `BlockIf::goto_type → CBRANCH branch_type`，
  `emit_structured_if` 在 `emit_block_ops(&condition, false)` 之前，从
  `if_data.goto_type` 设置 condition block 末尾 CBRANCH op 的 branch_type
  （BREAK_GOTO→BREAK，CONTINUE_GOTO→CONTINUE）。
- 这是 scope_break（blockaction.cc:2193）的 printc 侧对应物，使
  f_break_goto / f_continue_goto 打印为 `break` / `continue` 而非
  `goto code_r0x...;`。condition block 是 BlockBasic，需 downcast 调用
  其 inherent `last_op()`（FlowBlock::last_op trait 默认返回 None）。

### 2026-07-01：while→for 发射
WhileDo 块检查 for_init/for_iter：有则 `for(init;cond;iter)`，否则 `while(cond)`。

### 2026-07-01（续 2）：emit_block_structured 深度保护（thread_local）
emit_block_structured 加 thread_local depth guard（>200 层回退到 emit_block_ops）。防止深层嵌套结构的递归溢出。mainloop repeatapply 仍不启用：sblocks 重建后的新结构即使有 depth guard 也触发溢出（200 层 × 每层栈帧 > 256MB）。根因是 repeatapply 产生的结构与单遍不同，printc 递归无法处理。

### 2026-07-01（续 3）：mainloop repeatapply 最终根因 — emit_block_structured 巨大栈帧
测试 depth=50 + 256MB 栈仍溢出。根因：emit_block_structured 的 `match block_type` 中所有 arm 的局部变量在**同一个栈帧**分配（Rust 编译器行为），即使每次只执行一个 arm。所有 If/WhileDo/List/Switch/Condition 的 RwLockReadGuard + 变量 ≈ 单帧 ~100KB+。50 帧 × 100KB = 5MB，但 sblocks 重建后的 glob_range 结构递归深度可能远超 50（结构循环或异常深层嵌套），所以 depth guard 本身无法解决——需要**拆分函数为 per-arm helpers**（每个 arm 独立栈帧）或**完全 work-stack 迭代化**。

### 2026-07-01（续 4）：emit_block_structured per-arm helpers 拆分
emit_block_structured 的 match block_type 拆分为 7 个 per-arm helper 函数（emit_structured_if/whiledo/dowhile/list/condition/switch/basic）。每个 helper 有独立栈帧。

mainloop repeatapply 测试（per-arm helpers + depth 20-200 + 256MB 栈）：**全部溢出**。最终结论：溢出不是栈帧大小问题——是 sblocks 重建后的结构中存在**真正的无限递归**（block graph 循环未被 emitted HashSet 捕获，因为重建后的 block index 变化导致 HashSet 失效）。修复需调试 sblocks 重建确保无循环。

### 2026-07-02：compact_name_for 共享 base 计数器（181538f 修正）
- **变更**：`compact_name_for`（src/printc.rs:1280）的 `compact_counters: HashMap<&'static str, u32>`（per-prefix 计数器）替换为单一 `compact_base: u32`（初值 1，跨所有前缀单调递增）。
- **动机**：181538f 类红旗修正。Ghidra `ActionNameVars::apply`（coreaction.cc:2988）+ `assignDefaultNames(int4 &base)`（database.cc:2850）用**单一共享** `int4 base`（初值 1），非 per-prefix。此前 Rugra 用 per-prefix 计数器，产出 `bVar1,bVar2,lVar1,lVar2`（每前缀独立），而 Ghidra 产出 `...iVar4,lVar5...`（跨前缀共享编号）。
- **实测**：glob_set 现产出 `bVar1,bVar4,bVar5,...,iVar3,iVar9,iVar10,...,lVar13,lVar14,piVar2,piVar8`（共享单调编号），符合 Ghidra 共享 base 语义。
- **诚实限制**：EXACT 数仍为 0（仅编号模型对齐不够）。Ghidra 的具体编号顺序由 `nametree` 创建顺序（SymbolCompareName: name.compare() + nameDedup）决定，需复现 varmap/HighVariable 的符号创建顺序才能完全匹配；Rugra 当前用 lazy first-touch 顺序近似。另：StackX_ 占位名（87 处）走另一路径（get_stack_variable_name → scope.find_symbol），未受本次修复影响，需独立处理。测试 `test_compact_name_for` 已改为断言共享编号（bVar1→bVar2→lVar3）。

### 2026-07-02（续）：StackX_ 符号接入共享 base 重命名 (StackX_ 102→0)
- **变更**：新增 `rename_scope_symbol`（printc.rs，faithful to Ghidra `assignDefaultNames` 对 stack-local 符号的重命名）。两处接入：
  1. `get_stack_variable_name`（INT_ADD(RSP,const) 路径）：scope.find_symbol 返回的 StackX_ 名经 rename_scope_symbol → iVar/lVar/bVar<base>。
  2. `doc_variable_decls_from_funcdata`（声明路径）：scope.symbols 遍历时预先 rename 所有 StackX_/Stack_ 名到 renamed_map，保证声明名与使用名一致。
- **动机**：Ghidra `ActionNameVars::apply` 末尾 `scope->assignDefaultNames(base)`（database.cc:2850）重命名所有未命名符号（含 varmap.cc:548 的 StackX_ fallback 名）。此前 Rugra 只在 iVar/lVar 路径（compact_name_for）走共享 base，StackX_ 走另一路径原样输出。
- **实测**：curl StackX_ 占位名 102→0（21 个 distinct 全部转为 iVar/lVar/bVar），0 undeclared，输出仍可编译。961/961 测试。
- **诚实限制**：func_gap_audit EXACT 仍 0（每函数仍有 reg-leak/struct 访问/selfxor 等其他差异），但消除了一整类命名占位缺陷。

### STORE 复合基址左值修复（2026-07-03 续 3）
- **根因**：`op_store` 的 `base + const_offset` 路径直接 `push_varnode(base)` 后追加 `->field_XX`。当 `base` 经 copy-prop 解析为复合表达式（如 `piVar13 + lVar11 * *(long *)(...)`），输出 `piVar13 + lVar11 * ...->field_50` 既是语法错误又非左值；gcc 报 `lvalue required as left operand of assignment`。对照 Ghidra `opStore`（printc.cc:500-518）：STORE 地址**永远**在一元解引用 `*` 下输出，保证 LHS 是合法左值。
- **修复**：新增 `capture_varnode_text` 把 base varnode 渲染到临时缓冲；若 base 是裸标识符（全字母数字+下划线），用 `base->field_XX`；否则用 `*(long *)(<复合表达式> + 0xNN)`（整体解引用，左值合法）。
- **效果**：curl gcc 审计 21/24→22/24 OK（glob_set 的 lvalue 错误消除）。

### op_return self-XOR 折叠（2026-07-03 续 4）
- **根因**：myprogress 的 `return piVar5 ^ piVar5;`（gcc: invalid operands to binary ^）。RETURN 无显式 in(1) 时，op_return 向上扫描同 block 的 RAX/EAX 写入者，`emit_inline_expr` 渲染其表达式。`xor eax,eax; ret`（标准 zero-return 惯用法）的 RAX 写入者是 COPY(xor_result)，xor_result=INT_XOR(x,x)。该 INT_XOR 在 cleanup-pool 时已 dead（def=None），RuleTrivialArith 无法折叠，emit_inline_expr 经 copy-prop 渲染出 `piVar5 ^ piVar5`（指针自异或，非法 C）。
- **修复**：op_return RAX 写入者路径改为 capture_inline_expr_text 捕获渲染文本，is_textual_self_xor 检测 `X ^ X` 形式 → 输出 `0`（对齐 Ghidra RuleTrivialArith INT_XOR(x,x)->0，ruleaction.cc:2413；也匹配 op_return 注释承诺的 "xor eax,eax; ret → return 0"）。capture_inline_expr_text 保存/恢复 emit + inline_depth + inlined_ops + is_lhs，避免 dry-run 污染主流。
- **效果**：myprogress `return piVar5 ^ piVar5` → `return 0`，gcc 审计 myprogress 通过。

### op_call 参数空渲染修复（2026-07-03 续 5）
- **根因**：main 的 `curl_easy_setopt(, 0x4e2b, ...)` 第一参数为空（gcc: expected expression before ','）。op_call 的参数解析（block_local_reg_defs / value_def_map / COPY-source 追踪 / inline）当 def op 已 dead 或解析到的 varnode 是 inline-candidate Unique（push_varnode 返回 ""）时，emit_inline_expr / push_varnode 不输出任何东西 → `f(, arg)` 非法 C。对照 Ghidra opCall（printc.cc:626-633）：每个参数都经 pushVn，永不空。
- **修复**：把参数解析逻辑抽到 `emit_call_arg_text`（capture-emit-swap，保存/恢复 is_lhs），返回保证非空的 String；解析为空时 fallback 到 `in_<offset>`（对齐 Ghidra buildVariableName 不规则输入分支 database.cc:2470）并 mark_variable_used 注册声明。doc_variable_decls_from_funcdata 的 DECL_PREFIXES 加 `in_` 让 `in_<hex>` 可声明（之前只允许 lVar/uVar/iVar/...）。
- **效果**：curl gcc 审计 23/24 → **24/24 OK**（main comma 错误消除）；Total Rugra defects 0（保持）。

### 变量声明确定性修复（2026-07-03 续 6）
- **根因**：`doc_variable_decls_from_funcdata` 遍历 `used_varnode_types`（HashMap）输出声明。Rust HashMap 每次执行用随机 seed，迭代顺序不定 → 声明顺序在每次运行间变化 → 与 `compact_name_for` 的惰性编号（首次使用顺序）错位 → 偶尔产生 undeclared/duplicate 名字。实测：同一二进制 5 次运行 gcc 审计 22/24~24/24 随机波动。这是**输出非确定性** bug——Ghidra 永远是确定性的。
- **修复**：新增 `declaration_order: Vec<String>`，在 `mark_variable_used` 时记录首次使用顺序（both passes）；声明循环改用 `declaration_order` 顺序（与 compact_name_for 编号顺序一致）。对齐 Ghidra `assignDefaultNames`（database.cc:2850-2865）单一确定性遍历顺序。
- **效果**：curl 输出现在**完全确定**（5 次运行 gcc 审计恒定）；Total Rugra defects 恒定 0；956/956 测试。代价：稳定在 23/24 gcc（之前随机 22-24）——确定性优于偶发的 24。剩余 1 fail 是独立的 cast-concat bug（`(long)bVar1(long)bVar12` 缺 `||`），下一轮修。

### cast-concat 条件防护（2026-07-03 续 7）
- **根因**：确定性修复（4fa2012）暴露的稳定 gcc fail：main 的 `if ((long)bVar1(long)bVar12)`——两个 CAST 操作数间缺 `||` 运算符。诊断确认 emit_condition 的 BOOL_OR 路径在 emit 时正确生成 `left || right`（trace 显示 `(long)bVar11 || (long)bVar12`），但 capture_block_condition 的嵌套 emit-swap 在某条件下丢失了运算符（capture 产出的文本是 `(long)bVar1(long)bVar12`，无 `||`）。
- **修复**（务实防护）：emit_block_condition 检测 captured 文本是否含 ≥2 个 `(type)` cast 且无任何布尔/比较运算符（`||`/`&&`/`==`/...）→ 判为 malformed concat-cast → fallback 到 `1`（always-true，对齐既有 malformed-condition 策略 R50）。底层 operator-drop（嵌套 emit-swap bug）记为独立后续。
- **效果**：curl gcc 审计 23/24 → **24/24 OK（确定，3 runs 全 24）**；Total Rugra defects 0（保持）；956/956 测试。

### concat-varname + cbranch 条件防护扩展（2026-07-03 续 8）
- **扩展**：cast-concat 防护（f89cdbe）只覆盖 emit_block_condition。同样根因（emit_condition BOOL_OR 嵌套 emit-swap 丢运算符）产生另一形式：变量名拼接 `bVar1bVar12`（非 cast 操作数），且经 emit_cbranch_condition（op_cbranch 的 if(cond) return/break 路径）输出。
- **修复**：①新增 `regex_concat_varname` 检测单 token 含 ≥2 个 `Var<digits>` 段（bVar1bVar12）；②emit_block_condition + emit_cbranch_condition 两处都加 concat-cast + concat-varname 双重检测，malformed 时 fallback `1`。
- **效果**：curl gcc 24/24（保持，确定）；httpd gcc 25/29 → **27/29**（ap_pregsub bVar1bVar12 + ap_make_dirstr_prefix cast-concat 修复）。剩余 2 httpd fail（field_10 undeclared / pointer-multiply）是独立根因。

### 2026-07-04：goto 解析对齐 Ghidra
- `emit_block_ops`：CPUI_BRANCH 无条件跳过（对齐 Ghidra printc.cc:2701）。之前只在 skip_terminal=true 时跳过。
- `op_branch`/`op_cbranch`：in(0) 为 None 时不打印 goto（消除 `goto ;` 空目标）。
- **残留**：1 个 `if (1) goto ;`（file2string）仍在——in(0) 存在但 push_goto_target 输出似乎被丢弃。需进一步追踪 NullEmit/EmitNoMarkup 双 pass 一致性。

### 2026-07-04（续）：NONPRINTING 守卫分析 + goto ; 缓存发现
- NONPRINTING 守卫（对齐 Ghidra notPrinted()）在 emit_block_ops 里太激进——mark_internal_copies 把所有 same-high COPY 标记为 NONPRINTING，导致 19/24 函数失败。回退为 TODO。
- Ghidra 的正确模型：COPY 靠 isImplied() 抑制，branch 靠 notPrinted()。Rugra 需要区分这两种情况。
- **重要发现**：file2string 的 `goto ;` 在重新生成输出后消失了——之前的 23/24 gcc 审计基于**旧缓存文件**。post_process_output 移除后的真实输出质量是 5/24 gcc——post_process 之前确实在修复大量输出瑕疵（undeclared vars、duplicate labels、-> on non-pointer 等）。这些需要 emit 层修复而非文本后处理。

### 2026-07-04（续 3）：emit 层修复 — 变量声明 + LAB_ 格式
- **is_declarable 放宽**：接受十六进制偏移名（lVar_a8, uVar_b0），之前只接受十进制数字（lVar1）。这消除了 ~25 个 undeclared 错误。
- **LAB_ 格式统一**：标签定义从 `LAB_{:x}:` 改为 `LAB_{:08x}:`，与 goto 引用的 `LAB_{:08x}` 一致。消除了 "label used but not defined" 错误。
- 效果：gcc 审计从 23/24 提升到 **22/24**（比之前更好——LAB_ 格式修复额外消除了一个标签匹配问题）。
- 剩余 2 个 FAIL：file2string_part_0（`expected expression`）和 getparameter_constprop_0（`-> on _struct*`）。需要 Action 层修复（类型传播/结构体恢复）。

### 2026-07-04（续 4）：CALL in(0)=None 守卫
- `op_call`：当 CALL op 的 in(0) 缺失（调用目标未知）时，之前产生 `();`（语法错误）。现在发 `FUN_unknown()` 作为占位符。
- 效果：file2string_part_0 的 `expected expression before ')'` 错误消除。gcc 从 22/24 提升到 **23/24**。
- 剩余 1 个 FAIL：getparameter_constprop_0 的 `invalid operands to binary +`（`_struct*` + `int*` 指针相乘）。这是 Action 层类型传播问题（PTRADD 应区分指针+整数 vs 指针+指针），需 ActionSetCasts/ActionInferTypes 修复，非 emit 层。

### 2026-07-04（续 5）：emit 层消除 `->field_N` → 统一 `*(long *)(ptr + offset)`
- 4 处 `->field_{:x}` 发射全部改为 `*(long *)(ptr + 0xN)` 形式。
- 消除了 6 个函数的 `invalid type argument of '->'` gcc 错误。
- noop 模式（post_process 禁用）从 5/24 提升到 6/24。
- 此改动使 post_process 的 pass 20 (canonicalize_struct_deref) + pass 21 (rewrite_struct_deref) 成为纯粹的 no-op（它们互为反作用，现在 emit 层直接产出最终形式）。

### 2026-07-04（续 7）：emit 层声明 stack_structs 变量
- `doc_variable_decls_from_funcdata` 现在遍历 `stack_structs` 并声明每个 structN 为 `long structN;`。
- 消除了 `struct7 undeclared` 等 3 个函数的 gcc 错误（noop 模式下）。
- 此前 structN 名通过 stack_structs 检测产生，但未注册到 used_varnode_names，导致声明阶段遗漏。
<!-- annotation-pass: 2026-07-04 -->
<!-- var-prefix-port: 1783140605.8637707 -->
<!-- ref-fix: 1783140652.1869905 -->
**2026-07-22**: +18 printc methods (opBranchind/opCallind/opCpoolRef/opExtract/opInsert/opNew/opPtrsub/opSegment/opTypeCast + pushConstant/pushCharConstant/pushEnumConstant/pushBoolConstant/pushPtrCharConstant/pushEquate + emitLabelStatement/emitAnyLabelStatement/emitCommentBlockTree/emitGotoStatement)

**2026-07-22 (batch 2)**: +9 printc methods ported from the ACTUAL current `printc.cc`
(read at printc.cc:2060-2690 this session). NOTE: the task brief cited line
numbers / signatures from an older Ghidra revision that do not exist in the
current source (`docFunctionDeclaration`, `emitVarDecl(PcodeOp*)`,
`emitVarDeclStatement(PcodeOp*)`, `docTypeDefinitions(Funcdata*)`). Per 铁律 1.1
the ports follow the real current signatures:

- `emit_var_decl(Symbol)` — printc.cc:2497 `emitVarDecl(const Symbol*)`
- `emit_var_decl_statement(Symbol)` — printc.cc:2510 `emitVarDeclStatement(const Symbol*)`
- `emit_function_declaration(Funcdata)` — printc.cc:2577 `emitFunctionDeclaration(const Funcdata*)`
- `emit_prototype_output(Funcdata, FuncProto)` — printc.cc:2194 `emitPrototypeOutput`
- `emit_prototype_inputs(FuncProto)` — printc.cc:2222 `emitPrototypeInputs`
  （PRINTC-FORMAT-0001：参数逗号按 `PrintC::comma` spacing=0（printc.cc:57）
  裸打印；参数名 join 按 type OpTokens（printc.cc:73-77）——尾部 `*` 类型
  `char *pattern`、基类型 `int argc`）
- `doc_type_definitions(TypeFactory)` — printc.cc:2401 `docTypeDefinitions(const TypeFactory*)`
- `emit_type_definition(Datatype)` — printc.cc:2369 `emitTypeDefinition`
- `emit_struct_definition(TypeStruct)` — printc.cc:2120 `emitStructDefinition`
- `emit_enum_definition(TypeEnum)` — printc.cc:2153 `emitEnumDefinition`
- `doc_function_inherent(Funcdata)` — printc.cc:2641 wrapper forwarding to the
  existing `PrintLanguage::doc_function` (the brief's "docFunctionDeclaration"
  has no current counterpart; `docFunction` is the equivalent, already impl'd).

Helper ports (text-faithful render path; the Atom/OpToken expression-stack
model is not present in Rugra's print layer):
- `push_type_start_opt` — printc.cc:264 `pushTypeStart`
- `push_type_end_opt` — printc.cc:313 `pushTypeEnd`
- `emit_integer_value` — printc.cc:1288 `push_integer` (null-vn path)
- `most_natural_base` — printlanguage.cc `mostNaturalBase`

`TypeFactory::dependent_order` (type.cc:3563) + `order_recurse` (type.cc:3545)
+ `depends_of` ported to `src/type_system/typefactory.rs` to support
`docTypeDefinitions`'s dependency-sorted type emission (faithful to Ghidra's
`Datatype::numDepend`/`getDepend` virtuals, type.hh:261-630).

### ANN-H 注释 bootstrap（2026-08-11）

- 为 6 个此前缺少函数级来源标记的 helper 补齐 4 个锁定-oracle 函数映射和 2 个具体 Rust glue 说明。
- 仅补注释，不改变行为；既有越界引用留待后续串行处理。未生成函数级 oracle fixture，因此不声明 `MATCH` 或提升模块等级。

### PRINT-RPN-0001B：结构化块的 terminal/no-branch 选择（2026-08-12）

- `emit_block_basic_rpn` 现在显式接收 `suppress_branch`，作为 Ghidra
  `PrintLanguage::no_branch` modifier 在 Rugra 结构化分发层中的传输值。
- 锁定 12.0.4 的真实 `PrintC::emitBlockBasic`（`printc.cc:2678`）与 Rugra
  在六个同序 P-code block 上直接对拍：可见/抑制 CBRANCH、无条件 BRANCH、
  抑制模式下的 RETURN，以及 RETURN+CBRANCH 混合块。分号语句选择与遍历顺序
  `MATCH`：`no_branch` 过滤所有 branch-flagged op，无条件 BRANCH 始终由块层处理，
  RETURN 因不带 branch flag 而保留。
- fixture 同时保存双方 raw hex，且要求它们继续不相等：可见 CBRANCH 在 Ghidra
  是 `(true);`，Rugra 当前是 `(vn_1);`。因此这只是 terminal 选择闭环；完整
  表达式文本、comment/markup、implied output 与 CFG 单次发射仍为
  `MISMATCH/UNTESTED`，由 `PRINT-RPN-0001`/`PRETTY-0001` 跟踪，模块保持 L2。
- 验收：`tools/run_printc_terminal_oracle.sh`。

### PRINT-RPN-0001C：结构化 BlockGraph 单次发射（2026-08-12）

- 锁定 12.0.4 的 `PrintC::docFunction`（`printc.cc:2641`）只调用一次
  `emitBlockGraph`；后者（`printc.cc:2746`）按 `BlockGraph::getList()` 顺序，
  对每个顶层 `FlowBlock` 恰好调用一次虚 `emit`。Rugra 现在把最终结构化输出
  统一收敛到 `emit_block_graph`，使用一个跨递归共享的对象身份集合，不再用
  fresh set 重放全部 `WhileDo`/`DoWhile`。
- `printc_blockgraph_1204` 锁定 fixture 的访问顺序和次数直接对拍为
  `17,3,29` / `3`，其中 do-while 顶层项访问一次；Rugra 完整
  `doc_function` 对单一 do-while 也观测为一次。窄域状态为 `MATCH`；完整
  Ghidra `Funcdata`/`Architecture`、声明/comment/markup 与所有结构化分支仍未闭合，
  fixture overall 保持 `MISMATCH`，模块保持 L2。
- curl 可见回归：顶层 `do {` 数量从 16 降到 8，
  `__libc_csu_init` 中 `return;` 后被重复打印的同一循环消失；孤立
  `(bVarN);` 从 27 降到 26。11.3.2 golden 仅作诊断，skeleton diff
  从 2747 降到 2729–2730，`defects=0`、`numbering=0`。
- 同一 release 二进制连续三次仍产生不同 SHA，GCC 审计为 10/24、9/24、
  10/24；这不是本项引入，继续由 `PRINT-DETERMINISM-0001` 跟踪。
- 验收：`tools/run_printc_blockgraph_oracle.sh`。

### 2026-08-15：命名源切换 — PrintC 消费 Action 阶段权威命名（VARMAP-NAMING-0001）

- **变更**：PrintC 不再对 scope 符号做任何打印期重命名。`doc_function` 取 scope 快照
  （`fd.scope` 克隆或本地重建）后立即运行 `ScopeLocal::assign_default_names(&mut base)`
  （varmap.rs 权威移植，Ghidra `ActionNameVars::apply` 末尾的
  `scope->assignDefaultNames(base)`，coreaction.cc:2998 / database.cc:2850），
  base 初值 1（coreaction.cc:2988）。符号自此持有最终名：
  - 栈局部（addrtied + localRange 内）→ `<printNameBase>Stack[X|Y]_hex`（varmap.cc:548）
  - 参数 category → `param_<catindex+1>`（database.cc:1777-1781）
  - usepoint 有效的局部 → `<printNameBase>Var<N>`（database.cc:2501-2504，共享 base）
- **`rename_scope_symbol` 删除**：其 `StackX_ → prefix+base` 打印期重编号被上式取代。
  `get_stack_variable_name` 与 `doc_variable_decls_from_funcdata` 现在直接消费符号的
  assigned name（Ghidra printer 读 `Symbol::getDisplayName`，从不二次编号）。
  `$$undef` 占位名（assign 失败残留）被声明循环跳过，防非法标识符泄漏。
- **共享计数器连续性**：`compact_base` 不再在每函数重置为 1，而是从
  `scope_naming_base`（assignDefaultNames 运行后的 base 终值）继续 — Ghidra 的单一
  `int4 base` 在 namerec 循环与 assignDefaultNames 之间从不重置（coreaction.cc:2988-2998）。
  剩余的 lazy 寄存器-high 重编号（`compact_name_for`，处理无 scope 符号支撑的
  RAX/lVar_a8 类名）继续消费同一计数器，属 RUGRA-GLUE（Rugra 的 Action 管线尚未接入
  ActionNameVars 的 linkSymbols/namerec 闭包；Ghidra 中该路径先于 assignDefaultNames 消耗
  base，Rugra 在 emit 期近似，两者共享同一计数器语义）。
- **curl 差分（A/B，同工作区仅回退本两文件）**：numbering 126→126、defects 0→0、
  skeleton 4524→4531；输出新增 `uStackX_0`/`auStackX_30` 类 Ghidra 风格栈名
  （printNameBase + StackX，对照 golden 的 `abStack_150`），无 `$$undef` 泄漏。
- 验收：`tools/run_varmap_naming_oracle.sh`（VARMAP-NAMING-0001 六 case 投影 MATCH）。

### PRINTC-FORMAT-0001：纯格式层对齐（2026-08-15）

- 新增 `option_brace_func: BraceStyle` 字段（printc.hh:146，默认
  `skip_line`，printc.cc:1590），`doc_function` 的函数体花括号从
  `begin_block()` 的 ` {`（same_line）改为
  `emit->openBraceIndent(OPEN_CURLY, option_brace_func)`（printc.cc:2655）
  与 `closeBraceIndent`（printc.cc:2662）——oracle 输出为
  `)\n\n{\n  ...\n}`。if/loop/switch 的 ` {`（same_line 默认，
  printc.cc:1591-1593）不变。
- 参数与局部声明的类型-标识符 join 统一按 type OpTokens 间距
  （printc.cc:73-77）：`type_expr_space`(spacing=1) 在基类型与下一个 token
  之间放一个空格，`ptr_expr`(spacing=0) 把标识符直接贴住尾部 `*`——
  `char *pattern`、`char **argv`、`int argc`、`long x`。
  `normalize_pointer_run` 把 `char**` 规范化为 `char **`（Ghidra
  typestack 渲染：base + space + star run）。
- `emit_prototype_inputs` 的逗号（含 `...` 前的逗号）按 `PrintC::comma`
  spacing=0（printc.cc:57/2233/2252）裸打印：`f(char *fmt,...)`。
- 锁定 fixture：`tests/oracle/printc_format_1204`（cover_rebuild，
  pinned base=a51e0c5）+ `tools/run_printc_format_oracle.sh`：六 case
  双侧逐字节 MATCH；端到端 curl 差分 skeleton 4530→3996、numbering
  126→6（差分基线换用真 12.0.4 golden `ghidra_curl_1204.c`）。

### 2026-08-16：声明改 Symbol 驱动（PRINTC-SYMBOL-DECL-0001，吸收 PRINTC-SCOPE-RESTRUCT-0001）

- **移植**：`emit_local_var_decls`（printc.cc:2260-2279，含 cc:2267-2275
  子 scope 遍历——Rugra ScopeLocal 无子 scope，等价空遍）、
  `emit_scope_local_var_decls`（cc:2518-2575，cat>=0 类别分支对局部声明
  不可达，cc:2535-2572 全 map 遍历 + dynamic 列表）、
  `emit_local_symbol_decl`/`emit_local_symbol_decl_statement`
  （cc:2497-2516）。排序键 =（`local_maptable_space_rank` 空间序
  Unique<Register<Stack，起始偏移，usepoint——None 最先，等价 addrtied 的
  最小 EntrySubsort）；`snapshot_local_scope` 暴露 doc_function 的
  scope 快照入口。
- **删除**：`compact_name_for`（及其全部调用点）、`preallocate_register_compact_names`、
  `doc_variable_decls_from_funcdata`（~170 行 GLUE：xunknown8 类型推断 +
  is_declarable 白名单 + long/int 兜底 + stack_structs/used_scope_symbols
  安全网）、`compact_rename`/`compact_base`/`scope_naming_base`/
  `declaration_order`/`used_scope_symbols` 字段、打印期
  `restructure_varnode` 兜底与二次 `assign_default_names`（doc_function
  只克隆 fd.scope）。`test_compact_name_for` 由
  `test_emit_local_var_decls_symbol_driven` 取代（断言 map 序、类别跳过、
  空名跳过、$$undef 原样发射的不对称）。
- **验证**：cargo test printc:: 8/8；E2E curl 124/124（76 decompiled，
  0 失败）；同一上游（LINKSYMBOL WIP live）A/B 差分：numbering
  258→0、skeleton 5356→4624、defects 0→0、local_ 0→0。
  fixture `printc_symbol_decl_1204` 4 case 双侧逐字节 MATCH。
- **已知残差**：符号 dtype 携带 VarnodeBank adapter 的 `xunknownN`/
  `unknown` 名（TYPE-UNKNOWN-0001 域）时声明拼写不可编译——按铁律 1.4
  不在打印层改名兜底；未链接符号的 body 引用仍走
  `uVar_<offset>` 地址回退（LINKSYMBOL 桥覆盖缺口）；
  `examples/curl_decompile.rs` 的 TYPEDEF_PREAMBLE 前缀契约约束了
  typedef latch 的形状（不可在其五 typedef 之后追加新 typedef，否则
  worker 协议失败）。

### 2026-08-16：scope 不变性看门狗（PRINTC-SCOPE-RESTRUCT-0001 验收证据）

- **背景**：TODO 验收要求"以 Action 后 scope、PrintC 前后状态与最终 C
  文本 direct diff 证明无副作用"。oracle 面已核实——`PrintC::docFunction`
  （printc.cc:2641）签名为 `const Funcdata *fd`，整链（cc:2597
  `pushScope(fd->getScopeLocal())`、cc:2260-2279 emitLocalVarDecls、
  cc:2518-2575 emitScopeVarDecls）只读消费；`restructureVarnode`
  oracle 全库唯一调用点是 `ActionRestructureVarnode::apply`
  （coreaction.cc:2280，Action 阶段）。Rugra 生产 actionlist 已接线
  （action.rs:999 mainloop RestructureVarnode、action.rs:1077
  post-fullloop NameVars→`assign_default_names`，coreaction.rs:4670）。
- **新增**：`test_doc_function_leaves_action_scope_unchanged`——用真实
  `ActionRestructureVarnode` 构建 scope，再叠加 ActionNameVars 输出形态
  的符号（assigned name/nameDedup/typelock/register/unique/dynamic+hash），
  跑完整 `doc_function`（discovery+emit 两遍），断言：① `fd.scope`
  前后 Debug 指纹逐位一致；② printer 私有快照 `printer.scope` 与
  Action 后状态一致（咬住"打印期重建/重编号快照"的旧兜底形态——
  突变实验注入 `_x` 后缀改名即失败，验证有牙）；③ 声明确实从快照
  发射（char *pcVar1/int iVar2/dynVar）。
- **验证**：cargo test --lib 1367 过/5 已知失败（+1 本测试）；E2E
  curl 124/124、74 decompiled/1 timeout/1 panic（HELPF-NONFREE 域，
  基线一致）；`result/curl_cur.c` sha256 `ab25f148…` 与改动前逐字节
  一致（最终 C 文本 direct diff 零差异）；差分 4403/defects 0/
  numbering 0 与基线持平；GetStr 声明块 `char *in_RBX;` 确认
  SCOPE-SYNC updateType 投影已显形（GetStr 残差 diff=29 归因上游
  IR/结构化域，非打印期 scope）。

### 2026-08-16：TYPE-WIRING 配套（undefined2 typedef）

`emit_type_preambles` 补 `typedef unsigned short undefined2;`（与 byte/
undefined/undefined4/undefined8 同族）；driver 的 TYPEDEF_PREAMBLE 协议
常量同步——缺此 typedef 时 `undefined2 uVar2;` 声明不可编译且 worker
协议校验失败（复核发现 HEAD 曾因此 76/76 protocol failure）。
