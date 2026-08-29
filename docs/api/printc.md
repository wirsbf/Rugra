# `printc.rs` API Reference

## 2026-08-29：INT_NEGATE 一元 token 序（GLOBWORD-C4-INTNOT-TOKEN-0001）

`dispatch_op_rpn` 一元臂（INT_NEGATE/BOOL_NEGATE/INT_2COMP/FLOAT_NEG 等）此前
`emit.tag_op("~")` **dispatch 时刻直发**，违反 Ghidra `PrintLanguage::opUnary`
（printlanguage.cc:566-573：`pushOp(tok,op)` + `pushVn(in(0),op,mods)`，零直接
输出）。unary_prefix token 必须进 revpol 栈，由下一次 pushOp/pushAtom 入口的
`emitOp(revpol.back())`（printlanguage.cc:143/171）在 `visited==0`（cc:338-342）
打印——即操作数首个 atom 之前。nodepend 是 LIFO drain：二元 op 的右操作数
`AND(ADD(load,0xfefefeff), NEGATE(load))` 中 NEGATE 在左子树排空后才 dispatch，
直发的 `~` 落在左操作数常量之后、父 op 的 stage-1 ` & ` 之前——产出非法 C 形态
`0xfefefeff~ & *puVar10`（oracle/golden 为 `... & ~*puVar10`，ghidra_curl_1204.c:1309）。

- `build_rpn_token_table` 追加 `bitwise_not`（`~`，printc.cc:29）与 `unary_minus`
  （`-`，printc.cc:31），unary_prefix/stage=1/prec 62，追加在 binary 块之后
  （索引 31/32，`RPN_TOK_BINARY_BASE=11` 与 negate-id 算术保持稳定）；
  新增字段 `rpn_tok_bitwise_not`/`rpn_tok_unary_minus`。
- 一元臂改为 `rpn_push_op(tok)`：INT_NEGATE→bitwise_not（printc.hh:297）、
  INT_2COMP/FLOAT_NEG→unary_minus（printc.hh:296/322）、BOOL_NEGATE→boolean_not
  （printc.cc:814-825 else 臂；negatetoken/checkPrintNegation 短路尚未移植，
  现为该函数最终 else 的恒打 token 行为）。FLOAT_ABS/SQRT/CEIL/FLOOR/ROUND 在
  Ghidra 为 opFunc（printc.hh:323-327），Rugra 无函数调用形，不推 token 只排
  操作数——与旧行为逐字节一致。
- 括号决策：unary(62) 嵌于 binary(如 `&`34) 下走 `34<62 → false` 免括号，
  `~*p` 与 golden `& ~*puVar4` 形态逐字一致。
- **验收**：curl E2E `[0-9a-f]~` 非法形态 2→**0**；getparameter.constprop.0 的
  两条语句变为 `*puVar10 + 0xfefefeff & ~*puVar10`（=golden token 序）；
  全量 skeleton 2911→**2905**、defects 1（预存 empty-else，与本改无关）、
  numbering 0；cargo test --lib 1627/17/5 与基线逐项相同。
- **双侧 fixture（PRINTC-INTNOT-TOKEN-0001，`tests/oracle/printc_intnot_token_1204.*`）**：
  C++ 侧驱动真 PrintC::emitExpression（printc.cc:2468）于无输出顶层 op（跳过赋值臂，
  纯 token 序），Rust 侧驱动其移植 `emit_expression_rpn`（本 commit 起为 pub，同
  `op_subpiece_rpn` 的 fixture 再暴露惯例）。5 case：AND(ADD(LOAD,c),NEGATE(LOAD))/
  NEGATE(c)/INT_2COMP(c)/OR(NEG,ADD)/ADD(c,NEG)，常量叶 uint4 定型、子表达式输出
  implied。Runner `tools/run_printc_intnot_token_oracle.sh` 输出 **MATCH**（6/6 记录
  逐字节一致，expected_stdout_sha256 锁定）。注意：Rust 侧 `Varnode.def` 为 Weak，
  fixture 的 def op Arc 必须 `_op*` 绑定保活，否则递归 implied 升级失败静默丢弃。

## 2026-08-28：字符常量 read-facing 类型与条件极性

RPN 常量叶现在用 consuming op 的精确 input slot 查询 High read-facing type，并以
`vartoken + ConstColor + op/vn` 构造 Atom；GetStr 的零常量因此沿通用 char 路径打印为
`'\0'`。`emitBlockIf` 不再读取 Rust-only `BlockIf.negated` 或设置文本层
`NEGATETOKEN`；极性已由结构化阶段真实修改条件对象。完整 PrintC 常量族、legacy
direct emit 和 markup 仍保持 `MISMATCH/UNTESTED`。

## 2026-08-28：BlockCopy 入口地址解析

PrintC 的 label discovery、pending-label backpatch、graph code start、
`emit_any_label` 与 BlockIf goto-target 路径现通过 `flow_entry_address` 取得入口：
先沿 `front_leaf` 到 `BlockCopy`，再经 `subBlock(0)` 读取原始 Basic 的地址。
这恢复了真实 `BlockCopy` 上线后的入口地址语义，不再依赖过去的 Basic stand-in。

完整 `FlowBlock::getEntryAddr`、真实 parent/next-flow、BlockGoto/MultiGoto 和
异常路径仍未等价，当前状态为 `MISMATCH/UNTESTED`；该 helper 不是完整 PrintC
函数行为 `MATCH` 证明。当入口解析失败时，部分现有路径仍以
`unwrap_or(0)` 生成零地址 sentinel；残差继续绑定
`GOTO-LABEL-UNPRINTED-0001` / `PRINTC-GOTOPRINTS-0001`。

## 2026-08-28：结构化条件按 FlowBlock 类型分派（GETSTR-PRINTC-STRUCTCOND-0001）

`emitBlockIf` 的 condition 不再抽取/拼接条件文本，而是像 Ghidra
`PrintC::emitBlockIf`（`printc.cc:2878-2949`）一样，对同一个 condition
对象先在 `no_branch` 下虚分派一次，再在 `only_branch` 下分派一次；body
同样按其真实结构类型递归发射。配套实现了当前 Rust trait-object 需要的
dispatcher，并按 `emitBlockBasic`（`:2678-2744`）、`emitBlockLs`
（`:2781-2834`）和 `emitBlockCondition`（`:2836-2870`）恢复 non-flat
路径的 modifier、语句分隔、遍历顺序和条件括号协议。旧的打印期
`capture_block_condition`/De Morgan 文本重写不再承担这条路径。

锁定 12.0.4 bilateral fixture
`PRINTC-STRUCTURED-IF-CONDITION-0001` 覆盖 Basic condition、condition
本身为 BlockIf、BlockCondition 和 GetStr 形 BlockList 四种 non-flat、
zero-edge、`EmitNoMarkup` 图。双方输出均为 5 records / 9284 bytes，SHA-256
`1440f27ef73ffc13d2dfcf319576f8d4dd17102c6fcc9a25911cf4657f129758`，raw
diff 为空；重复发射、CALL/STORE/comment 顺序、modifier 恢复和树快照在该
投影内 `MATCH`。完整结构发射状态为 `MISMATCH`：独立复核已确认
Graph/MultiGoto 分派、带 condition prelude 的 pending-brace else-if，以及
FLAT+NOFALLTHRU tail 三类确定残差；有出边的 `nextInFlow`、markup、普通
else/if-goto、异常和其余结构子类型还未由该夹具覆盖。PrintC 继续保持 L2。

fresh GetStr 六阶段 runner 已恢复真实 `BlockCondition`：Ghidra 与 Rugra 的
`04_structure` 都只有一个 root child，Rugra 的目标行逐字为
`if ((param_1 != (char *)0x0) && (*param_1 != '\0')) {`，锁定 Ghidra 对应行为
`param_2`。runner 只把 `03_action_ir` 已证明同为 `register:48:8` 的 producer-local
标识投影成 `value_pointer`；双方原始行、op/Varnode ID 与空白全部保留，没有做
文本合并、正则替换或字面量归一化。短路结构与字符 token 因而是聚焦 `MATCH`。
完整 GetStr 仍为 overall `MISMATCH`：五个 stage 非零差异，Heritage 边界为
`NO_ORACLE`，参数恢复、签名、未知类型 identity、FSPEC/地址空间及完整
PrintC/markup 闭包继续绑定 metadata 中的 residual IDs。

## 2026-08-27：CALLIND 函数指针形渲染（PRINTC-CALLIND-PTR-0001）

`CPUI_CALLIND` 已与 `CPUI_CALL` 分离：按 Ghidra `PrintC::opCallind`
（`printc.cc:637-672`）输出 `(*(code *)<target>)(args)`，target 通过正常
Varnode 表达式发射，保留 GOT 槽的 `PTR_<name>_<addr>` 符号；直接 CALL 仍按
`opCall` 的 callspec 名称路径输出。RPN 与 legacy inline 两条路径均保持该分派。

验证：oracle `e40ed13014025f82488b1f8f7bca566894ac376b`，x86-64 BFD curl；
全量 defects=0、numbering=0、skeleton=2637。CALLIND 形态已变为函数指针调用，
但当前整体 audit 仍受既有 `_IO_FILE` 声明与其他上游残差影响，详见 Differential。

## 2026-08-27：CALLIND 实测结果

重建后 PLT 样例已输出 `(*(code *)PTR_00116e80)()`（带 GOT 名称时为
`PTR_<name>_<addr>`）。`audit_syntax.py` 维持 28 OK/95 FAIL；全量差分仍为
 defects=0、numbering=0、124/124，skeleton=2678。嵌套 CALLIND 的错误 `= PTR_...`
已消失，剩余 audit 失败主要是返回值调用形（如 `lVar1(*(code *)PTR_...)`）及上游
`_IO_FILE`/声明问题，已在 TODO 保留为后续审查项。

## 2026-08-27：隐含表达式与类型化常量发射（TRI2-UNNAMED-VN-IMPLIED / TRI2-CALLOUT-RESID-0002）

- RPN 的 `rpn_recurse`、`rpn_op_func`、`CPUI_PTRADD` 与 `CPUI_PIECE` 臂已按
  `printlanguage.cc:197-211, 514-540` 和 `printc.cc:880-893, 424-442`
  保持 implied 输入的逆序入栈与递归内联；当前 master 已包含该链，本次复核未重复实现。
- `push_varnode` 的 Const 分支不再依据可打印 ASCII 猜测字符形。对传播类型为
  `TYPE_INT/TYPE_UINT` 且非 `isCharPrint()` 的常量，直接走
  `integer_text`，对应 `pushVnExplicit` 提供 read-facing 类型后由
  `pushConstant` 在 `printc.cc:1744-1764` 的整数分派；因此
  `progressbarinit` 的 `0x4f` 不会误发为 `'O'`。真正的 char-print 类型仍保留字符转义路径。

**验证**：oracle `e40ed13014025f82488b1f8f7bca566894ac376b`，x86-64 BFD / locked curl
fixture；全量 `defects=0`、`numbering=0`，`progressbarinit` 目标常量 `0x4f`。

## 2026-08-26：RPN opCall 接通 + pretty-printer 挂接（PRINTC-LINEWRAP-0001）

- `rpn_op_call`（Ghidra: printc.cc:596 PrintC::opCall）：RPN 路径的
  CALL/CALLIND 渲染替换直写拼串——`pushOp(&function_call)`、fspec 名
  atom（functoken/funcname_color）、`count-1` 个 comma token、参数
  varnode 逆序 `pushVnImplied`（LIFO 排空正序出），count==0 推空
  blank atom（cc:635-636）。postsurround token 的
  `spaces(0,bump) openParen spaces(0,bump) … closeParen` 布局是
  pretty printer 在参数组周围折行缩进的来源。
- `PrintC::new` 尾部 `emit.set_comment_fill("   ")`：resetDefaultsPrintC
  → setCStyleComments → setCommentDelimeter("/* "," */")（printc.cc:1594/
  printlanguage.cc:96-110）的空格填充宽度，武装注释块内强制折行的填充。
- `doc_function` 尾部改为 oracle 时序 `closeBraceIndent → tagLine →
  endFunction → flush`（printc.cc:2662-2665）；typedef 前言包进
  `beginDocument…endDocument…flush`（docAllGlobals 形态，printc.cc:2621-2629）。
- 所有 `open_paren()/close_paren()` 调用点升级为带括号串与组 id 的
  trait 新签名（`open_paren("(")` / `close_paren(")", id)`），为
  `EmitPrettyPrint` 的 openGroup/closeGroup 配对提供 id。

**验证**：hugehelp 与 golden 逐字节一致（含三个 `puts(\n      "..."\n
      );` 折行），全量差分 defects=0/numbering=0。

## 2026-08-26：RPN 常量臂接通完整 pushConstant 分派（MAINDIFF-STRCONST-0001）

RPN 叶片 `make_atom_for_vn` 的常量路径此前走自创 `format_constant_value`
（小值十进制 / 大值 `0x..  /* dec */` 注释 / `-1` 特判），既不查类型也不查
StringManager。本次替换为 `constant_leaf_text`（`&mut self`，持 vn/op），完整
移植 `PrintC::pushConstant` 的 metatype 分派（printc.cc:1749-1815）：

- `TYPE_UINT`/`TYPE_INT`：`isCharPrint()` → `char_constant_text`
  （pushCharConstant cc:1606-1654），`isEnumType()` → `enum_constant_text`
  （pushEnumConstant cc:1666-1687 的 exact-member 切片），否则
  `integer_text`（cc:1288-1368，signed 求补、hex/dec 自然底判定）。
- `TYPE_UNKNOWN` → `integer_text`；`TYPE_BOOL` → `true/false`
  （pushBoolConstant cc:1488-1495）。
- `TYPE_PTR`/`TYPE_PTRREL`（cc:1775-1790）：`option_NULL && val==0` →
  `NULL` token；ptr-to charPrint → `ptr_char_constant_text`
  （`pushPtrCharConstant` cc:1698-1719 文本核：非零值、默认数据空间
  resolveConstant、全局 scope readonly、`print_character_constant` 引号串）；
  ptr-to CODE → `ptr_code_constant_text`（cc:1730-1742，默认代码空间 +
  `queryFunction` 符号名）；未命中落入 default cast
  （`default_cast_constant_text` cc:1806-1815，可选 `(type)` cast + force_hex
  整数）。
- `TYPE_VOID`（cc:1772-1774）：oracle 是 `clear(); throw LowlevelError`；
  Rugra 双路径统一降级为 `/* void constant */` 标记（发射路径不 panic，与
  直接发射臂同形）。`TYPE_FLOAT`（cc:1791-1793 → `push_float`
  cc:1380-1424）：Rugra 无 FloatFormat，统一发 `FLOAT_UNKNOWN`——
  cc:1386 无格式 sentinel 本身，与直接发射臂同形。
- 其余 metatype → default cast。

直接发射 helper（`push_integer`/`push_char_constant_fmt`/
`emit_default_cast_constant`/`push_ptr_char_constant`）改为文本核的薄包装，
两条路径（RPN 叶片与直接发射）输出同一形态；`format_constant_value` 连同
`/* dec */` 自创注释删除。`print_unicode` 的逃逸判定由
`!(0x20..=0x7e).contains` 纠正为 `printlanguage::unicode_needs_escape`
（printlanguage.cc:411-487：C0 控制 + 可打印 ASCII 内的 `\\` `"` `'`），修复
字符串字面量内引号不逃逸。E2E（curl 124 函数）：hugehelp 三个字符串字面量
与 golden 逐字节一致（2132/2105/2139 字节含截断标记），progressbarinit
`curl_getenv("COLUMNS")`、my_fwrite `fopen(..., "wb")` 折叠，
`/* dec */` 清零，defects=0 / numbering=0。

**源代码路径**: `src/printc.rs`

## 2026-08-25：`find_partial_field` 半开区间边界修复（type.cc:1580-1638）

`find_partial_field` 的字段包含判定由闭区间 `off + sz <= f.offset + f_size`
改为 Ghidra `TypeStruct::findTruncation`（经 `getFieldIter`，
type.cc:1580-1602）的语义：包含区间是半开的 `[offset, offset+size)`
（`curfield.offset <= off && curfield.offset + size > off`），外加跨度检查
`noff + sz <= size`。旧闭上界使 offset 恰落在字段起点且 `sz == 0` 时命中
**前一个**字段（PTRSUB(bar,0x10) 渲染成 `bar->prev` 而非 `bar->point`）。
这是 STOP/PTRSUB 接线（VARNODE-STOPUP-FLAGS-0001）在 E2E 验收中暴露的
移植缺陷：`( )bar` 空 cast（coreaction getInputCast 旧启发式，另修）消除
后字段名仍偏早一格。

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
- **2026-08-23 修复（`PIPE-ORDER-EMPTYELSE-0001` 空 else defect——legacy
  发射路径补 `is_dead` guard）**:
  `emit_block_ops` 与 `is_block_body_empty` 此前不跳过已销毁（`DEAD` flag）的
  PcodeOp——只有 RPN 路径 `emit_block_basic_rpn` 有该 guard。Ghidra 的不变式
  是 `Funcdata::opDestroy`（funcdata_op.cc:203-222）立即把 op 从所属
  BlockBasic 的 op 列表摘除，且结构图 `BlockGraph::buildCopy`
  （block.cc:1925-1936）用 `BlockCopy` 包**原始**块而非克隆，所以 oracle
  从不会迭代到已销毁 op。Rugra 的 `build_copy`（blockaction.rs:98）把 op
  列表快照进克隆块，快照之后销毁的 op（flags 含 `DEAD`）滞留在结构节点里；
  fullloop 尾部 `ActionDeadCode`（coreaction.cc:5682 槽位）销毁的 op 即属
  此类。后果：else 臂块（仅含 dead INT_ADD + implied LOAD/COPY）被
  `is_block_body_empty` 判为非空 → 打印 `} else { }`（E2E 唯一 defect，
  getparameter.constprop.0）。修复：两个函数的 per-op 循环头部加
  `if op.is_dead() { continue; }`，与 `emit_block_basic_rpn` 的既有 guard
  一致——在可观测边界恢复 oracle 的块列表不变式。E2E（curl_1204 golden）：
  defects 1→0、numbering=0、skeleton 2452→2083（28 个函数全部只降不升，
  `__libc_csu_fini`/`main_free` 达 identical）。
- **2026-08-17 修复（`PRINTC-BINARY-RPN-0001` 二元 op 接入 RPN token 流）**:
  `dispatch_op_rpn` 的二元算术/比较/逻辑臂此前 `emit.tag_op(" + ")` 直发，
  括号决策全靠 legacy 侧 `child_needs_parens` 的**倒置教科书启发式**（左操作数
  等优先级永不加括号），与 Ghidra `PrintLanguage::parentheses`
  （printlanguage.cc:269-323，binary 分支 277-286：等优先级且非 associative 即
  `return true`）相悖——输出残留 3 处 `(bool)x == y + 0 - z < 0` 形态
  （ADD 嵌 SUB 左槽 / SUB 嵌 ADD 右槽等优先级无括号；`+ 0 -` 裸形态）。修复：
  - `optoken` 模块重写为**逐字段 OpToken 注册表** `BINARY_TOKENS`（20 项，
    printc.cc:36-55 逐字：multiply `*`54assoc / divide `/`54 / modulo `%`54 /
    binary_plus `+`50assoc / binary_minus `-`50 / shift_left `<<`46 /
    shift_right|shift_sright `>>`46×2 / less_than `<`42 / less_equal `<=`42 /
    greater_than `>`42 / greater_equal `>=`42 / equal `==`38 / not_equal `!=`38 /
    bitwise_and `&`34assoc / bitwise_xor `^`30assoc / bitwise_or `|`26assoc /
    boolean_and `&&`22 / boolean_xor `^^`20 / boolean_or `||`18；全部
    spacing=1 bump=0，negate 按 printc.cc:129-134 翻转对），`binary_token(opc)`
    按 printc.hh:283-318 虚拟 dispatch 表解析 opcode→token（INT_LESS/SLESS/
    FLOAT_LESS 同 less_than 实例、INT_ADD/FLOAT_ADD 同 binary_plus 实例等，
    以 token id 表达 Ghidra 的 OpToken 指针同一性）。**修正既有失配**：
    BOOL_XOR 原映射 `^`@30 → Ghidra 为 boolean_xor `^^`@20（printc.cc:54）。
  - `build_rpn_token_table` 追加这 20 个 token（索引 9..=28，negate 存翻转
    token 的表索引）；新增 `rpn_tok_binary(opc)`（printlanguage.cc:539-545
    negatetoken 翻转前奏 + printc.hh dispatch 映射）。
  - `dispatch_op_rpn` 二元臂：`rpn_push_op(tok)` 接管操作符发射（emitOp 在
    printlanguage.cc:332-337 以 spacing=1 打印 ` op `，与旧直发文本逐字节一致）；
    INT_ADD 结构体字段短路改走 pointer_member token 流
    （`pushOp(->66)+pushVn(base)+field atom`，opPtrsub printc.cc:476-484 形态）。
  - **2026-08-23 操作数全面接通 pushVn/nodepend**（`PRINTC-UNLINKED-REF-0001`
    printc 域残差修复）：二元臂操作数由 `make_atom_for_vn` 叶子原子改为
    `rpn_push_in`（in1-先-in0 后的 nodepend 记录，printlanguage.cc:551-552）；
    一元臂、STORE 的 addr/value、CALL 参数、RETURN 值、CBRANCH 条件、PTRSUB
    变址回退与 INT_ADD 字段短路 base 同步改造（直发文本的臂用
    `rpn_push_in`+`rpn_recurse` 队列化排出，保持文本位置不变）。`rpn_recurse`
    的 implied 分支由此对全部操作数位生效——implied 高变量在表达式位内联
    def 表达式（printlanguage.cc:526-536），替代 GLUE 兜底独立命名
    （`get_varnode_display_name_inner` 的 `uVar_<hex>`/`uVar20` fallback），
    使 prettyprint `backfill_missing_locals` 不再为这些名字注入声明。
    新增 `rpn_def_inline_reachable` 守卫（RUGRA-GLUE）：Ghidra 的
    `TypeOp::push` 虚 dispatch 覆盖全部 opcode，Rugra `dispatch_op_rpn`
    partial（PRINT-RPN-0001），对无发射臂/缺输入/已 dead 的 def op 回退
    叶子原子，防止操作数文本被静默丢弃（MULTIEQUAL/INDIRECT 在 Ghidra
    同样空发射，printc.hh:331-332，保守取叶子直到 dispatch 表补全）。
    前序"队列化实测 numbering 0→16 已回退"的失败不复现：E2E
    defects=0/numbering=0/Matched 116 全保持，Unique-GLUE 声明行 117→45，
    含 GLUE 名函数 12→8（消除 GetStr/_start/glob_url/progressbarinit）。
  - `child_needs_parens` 重写为 parentheses() binary 分支的忠实移植
    （277/278/281/286 逐行；等优先级非 assoc 双侧都加括号=Ghidra 保守风格
    `(a - b) - c`；同 token 且 assoc 才免括号=`a + (b + c)`）；
    `emit_inline_expr` 与 `op_binary` 的操作符文本改由注册表生成（print1+
    spacing，含 BOOL_XOR `^^` 修正）；`emit_condition` Case-1/Case-2 操作数经
    `push_input_parenthesized`（父上下文参与括号决策——3 处残差的实际发射
    路径，emit_structured_condition→capture_block_condition→emit_condition 链，
    实证 [DBG2] 捕获）；BOOL_AND/OR 递归两侧经 `condition_side_needs_parens`
    （&&/|| 非 assoc，等优先级组合子互相嵌套加括号）。删除死代码
    `c_binary_op_str`。
  - 单元测试 `test_child_needs_parens_precedence` 重写为 277/278/281/286 语义
    （含 `(x==y)<0` 案例判别、`(a+b)-c`、`a&&(b&&c)`、XOR@20 共 20 断言）。
  - **验收**：`+ 0 -` 裸形态 grep 3→**0**；`(==|!=) … (<|<=…)` 无括号邻接
    0；3 处原残差站点现形 `(bool)uVar_20b == (bool)uVar_10 + (0 - …) < 0`
    （`0 - X` 已括号化=278/286 决策；外层 EQUAL(38)⊃SLESS(42) 嵌套按
    printlanguage.cc:278 `38<42 → false` 正确免括号——IR 树 EQUAL 为外层，
    [DBG3]/[DBG4] def 链实证）；Matched 123 不降、defects 0、numbering 0、
    gcc 106 OK/17 FAIL（=门禁上限）；cargo test --lib 1412/5（5 失败=
    comment/dynamic/funcdata×2/ruleaction 预存集）。
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
- **2026-08-23 修复（GETSTR-ZERODIFF-D 域，类型感知常量 + (bool) 抑制）**: ① `make_atom_for_vn`/push_varnode Const 臂加 `typed_constant_literal`（PrintC::pushConstant printc.cc:1744-1810 移植）：指针类型 0 值 → `({type})0x0`（默认臂 cc:1805-1809，C 无 null token）；char 打印类型 → 字符字面量（cc:1750-1752 pushCharConstant），转义表忠实 printUnicode（printc.cc:1426-1466：\\0 \\a \\b \\t \\n \\v \\f \\r \\" \\' \\\\ + 通用 hex）。② ActionSetCasts castOutput 的 token==high 短路由 Arc::ptr_eq 改为 Datatype::type_equal 结构比较（Ghidra 用 TypeFactory interned 指针比较，cc:2544-2551；Rugra 无 intern，Base 型按 name+size+metatype 等价），base_type_for 补 Bool→"bool" 映射（原落 "long"）——消除 CBRANCH 条件上的伪 `(bool)` cast。
- **历史记录（2026-08-23，已由 2026-08-28 结构化极性实现取代）**: 当时曾以
  `demorgan_negate_text` 和 Rust-only `BlockIf.negated` 在打印期补偿复合条件。
  这不是当前实现，也不是可接受的 Ghidra 等价机制；两者现已删除。当前极性由
  `BlockList/BlockCondition/BlockCopy::negateCondition` 虚派发及完整 reciprocal
  edge-slot 交换在结构化阶段原地完成，`BLOCK-STRUCTURED-NEGATE-0001` 的 13-case
  scoped stdout 已与锁定 oracle 逐字节一致；完整 CollapseStructure 仍保持
  `MISMATCH/UNTESTED`。
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
  记录（doc_function 的 extern 全局扫描消费端已于 2026-08-25 移除，
  MAIN-DATPOOL-0001）。
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
  - 在 `dispatch_op_rpn` 新增 `CPUI_PTRSUB` 分支：忠实移植 opPtrsub 的 struct/union（`[&]ptr->field`）、array（`*ptr`）与无类型回退（`ptr->field_0x<hex>` / `ptr[off]`）发射形态；Rugra 无 TypePointerRel，`ptrel` 分支塌缩为 `ct = ptype->getPtrTo()`（与 legacy `op_ptrsub` 一致）。
- 2026-08-25（B3-COREACTION-CONSTANTPTR-0001 段(b)）：RPN 路径补齐 TYPE_SPACEBASE 臂（printc.cc:1057-1097，此前 RPN 恒落 `field_0x` 回退）。symbol 经 in(1) high 的 linkSymbolReference 附件（namerec 残留未接，打印侧替代为同一 queryContainer 通道：global scope + 空 usepoint）；ARRAY symbol 按 cc:1062-1070 弃 `&`；`!valueon` 发 `&name`；无 symbol 走 `0x<hex>` 无名位置；arrayvalue 后置 `[0]`。hugehelp 六别名经此臂渲染 `&DAT_00107180/…99a8/…c1d8`（与 golden 逐字节一致）。
  - **R-RAWQUAR F3 登记（2026-08-25）**：该臂两分支缺口登记 TODO 并入 ALIGNMENT_ROADMAP printc 行——①`PRINTC-SPACEBASE-TYPECODE-0001`（printc.cc:1068-1069 `TYPE_CODE → valueon=true`：函数符号不打 `&`；program-DB hit 只带 type_metatype、driver DAT 层无 CODE 条目，现管线不可达）；②`PRINTC-SPACEBASE-PARTIALSYM-0001`（printc.cc:1084-1093 `symbolOffset≠0 → pushPartialSymbol`：mid-symbol 命中打子字段；容器查询 stand-in 无 symbol-offset 通道且 ConstantPtr 路径 off 恒 0，现管线不可达；解锁依赖 FUNCDATA-LINKSYMBOL 的 high→symbol 附着通道）。
  - 在 `dispatch_op_rpn` 新增 `CPUI_CAST` 分支：忠实移植 opTypeCast 的 array-decay `&in0` 短路与 `(type)in0` 主路径；`typecast` 是 presurround，RPN emit 机制自动产生 `(typename)operand`。
- **隐式内联打通**：为让 PTRSUB/CAST（消费时一定是 implied）真正进入 dispatch，引入 `rpn_push_in(op_arc, op, slot, m)`——忠实 `PrintLanguage::pushVn`（printlanguage.cc:197）的 nodepend 记录语义。`COPY`/`LOAD`/`PTRSUB`/`CAST` 的操作数改为走 `rpn_push_in`，由 `rpn_recurse`（printlanguage.cc:514）按 implied 标志决定内联 def 或推叶子 atom。此前各 dispatch 分支直接 `make_atom_for_vn + rpn_push_atom`，等价于只走 `pushVnExplicit` 叶子路径，导致所有 implied def（含 PTRSUB/CAST）永不被内联。**2026-08-23 扩展**：二元/一元算术、STORE、CALL、RETURN、CBRANCH、PTRSUB 变址回退与 INT_ADD 字段短路的全部操作数位同步接通（见上文 PRINTC-UNLINKED-REF-0001 节），implied 内联覆盖所有表达式位。
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

### PRINTC-SUBPIECE-FIELDEXTRACT-0001 三缺口实现收口（2026-08-17）

- **缺口 (a) RPN `opSubpiece` 字段抽取体（printc.cc:846-871）**：`dispatch_op_rpn` 的 `CPUI_SUBPIECE` 臂补齐 oracle 两臂——
  - 臂 (a)（printc.cc:853-861）：`vn.is_explicit()` 且 high 带 Symbol 时走 `rpn_push_partial_symbol`（`PrintC::pushPartialSymbol` printc.cc:1947-2065 的 RPN 全量移植）：从 **symbol 的类型**（非 facing 类型）出发的 bottom-up walk（STRUCT→`find_truncation` 字段下降 + object_member 条目；ARRAY→`array_get_sub_entry` 元素下降 + subscript 条目；UNION→无缓存解析时 break；其他 metatype→allowCast 的 `is_subpiece_cast_endian` 截断 cast；全部失败→`unnamedField(off,sz)`=`_off_sz_` 合成条目，printlanguage.cc:719-727），发射顺序 = finalcast 前缀 + 条目 token 逆序 + 基符号 atom + 条目 atom 正序（printc.cc:2044-2064）。`suboff>0` 时 `byteOff += suboff`；`slot = needs_resolution ? 1 : 0`（人工 slot）。
  - 臂 (b)（printc.cc:862-868）：无符号/非 explicit vn 时 `find_truncation(byteOff, outSize)`（slot=1）返回 `offset==0` 的形式字段 → `pushOp(object_member) + pushVn + Atom(field.name, fieldtoken)`。
  - `byteOff` 来自 `compute_byte_offset_for_composite`（typeop.cc:2195-2207 的忠实移植，含 big-endian 臂 `vn.size - outsize - lsb`）。
  - token 表新增 `subscript`（`[`/`]` postsurround prec 66，printc.cc:27，index 9；binary 块基址 9→10）。
  - 新公开入口 `op_subpiece_rpn`（镜像 Ghidra public virtual `PrintC::opSubpiece` printc.hh:334）供 oracle fixture 做 op 级观测；`cast_strategy` 字段转 pub（镜像 `PrintLanguage::getCastStrategy` printlanguage.hh:449）。legacy 直发 `op_subpiece` 同步补两臂（经 `push_partial_symbol`/`find_truncation`），并修正其合成字段名 `.field_X_Y`→`._X_Y_`（unnamedField 格式）。
- **缺口 (b) `is_piece_structured` 宽度（type.hh:929）**：见 docs/api/type_system/datatype.md——匹配集扩为 {Struct, Union, Array, PartialStruct, PartialUnion}；oracle 实测证实 enum/partialenum 因 TypeEnum 构造器 metatype 归一化（type.hh:489-494）报告 TYPE_UINT/TYPE_INT，**不属于** piece-structured（"含 enum" 的直觉表述被真 oracle 输出纠正）。
- **缺口 (c) `is_subpiece_cast` PartialStruct/PartialUnion 输入臂（cast.cc:413-418）**：见 docs/api/type_system/cast.md；附带 enum 输入/输出映射（Ghidra TypeEnum 归一化后以 UINT/INT 通过白名单，cast.rs 既有先例 186/197 行同约定）。
- **fixture**：`tests/oracle/printc_subpiece_fieldextract_1204.{cc,rs,metadata.json}` + `tools/run_printc_subpiece_fieldextract_oracle.sh`——22 条记录（10 piece sweep + 8 cast sweep + armA.field=`S.hi`/armA.array=`A.arr[0]`/armA.synthetic=`Y._2_4_`/armB.field=`B.lo`）与锁定 12.0.4 oracle **逐字节一致**（runner 输出 `records=22 MATCH`）。C++ 侧为真 Funcdata 图（type-locked ScopeLocal 符号 + `opMarkSpecialPrint`）；Rust 侧经 `op_subpiece_rpn` 同图构造。
- **Differential（curl 语料）**：输出与改前逐字节不变（`diff result/curl_cur.c` 前后 0 行）——语料中无 RuleSubRight 置位且输入为 piece-structured 的 SUBPIECE，亦无 offset-0 的 enum/partial SUBPIECE cast；门禁 defects=0/numbering=0 维持。

### PRINTC-SUBPIECE-FIELDEXTRACT-0001 审计返工（2026-08-17，三处 MISMATCH 修正）

- **REWORK #1 STRUCT 臂 findResolve**：原实现 `needs_resolution && size==sz` 时无条件 break——错误。oracle 的 `TypeStruct::findResolve` 有 override（type.cc:1944-1951）：**无缓存**返回 `field[0].type`（≠ct → 不 break，继续 findTruncation 下降），**有缓存**返回 `ResolvedUnion::getDatatype()`，仅 `==ct` 才 break（printc.cc:1969-1971）。修正：`rpn_push_partial_symbol` 查 `union_resolutions` 快照（PrintC 新字段，doc_function 时从 `fd.union_map` 克隆——Rugra 的 PcodeOp/block 无 Funcdata 反向指针，快照等价于 Ghidra 经 `op->getParent()->getFuncdata()` 的查询），无缓存回退 `field[0].type`，`Arc::ptr_eq` 判等。真 oracle 验证：`armA.nested=N.in.x`（fixture_inner 单字段填满 → 真 TypeFactory::setFields 置 needs_resolution，type.cc:1569-1871）。
- **REWORK #2 PartialEnum 白名单**：`TypePartialEnum` 构造器（type.cc:2255-2262）委托 TypeEnum 归一化为 TYPE_UINT → Ghidra 三白名单全过；Rugra 侧 `is_subpiece_cast` 三处白名单（in/out/PTR→int 特例）补 `TypeMetatype::PartialEnum`。真 oracle 验证：`cast.int_partialenum_0=1` / `cast.partialenum_out_0=1`。
- **REWORK #3 allowCast 臂实参**：Ghidra printc.cc:859 传 `op->getOut()`（**输出** varnode）——2019 行 `outtype = vn->getHigh()->getType()` 读输出 high 类型，2020-2022 的 space 回退同源；原实现传输入 vn → outtype 落输入类型 → 白名单恒拒 → finalcast 死代码。修正：dispatch 臂 (a) 传输出 varnode；符号 atom 的 vn 锚点同步取输出。真 oracle 验证：`armA.allowcast=(uint2)C.lo`（输出 typed uint2 → `(uint2)` 前缀可达）。
- **同批**：legacy `push_partial_symbol` 补 loop-top TYPE_PTR 豁免（printc.cc:1962 `(!needsResolution || metatype==TYPE_PTR)`）；C++ fixture 的 COPY/SUBPIECE 插入真实基本块（`const_cast<BlockGraph&>(fd.getBasicBlocks()).newBlockBasic` + `opInsertEnd`）使 `findResolve` 的 `op->getParent()->getFuncdata()` 可达。
- **衍生登记**：`TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001`（Rugra `TypeFactory::set_fields` 不置单字段 needs_resolution，type.cc:1569-1871——铁律 1.5 基础设施缺口；fixture Rust 侧手动置 flag 规避并注释指向 TODO）。
- **fixture 重钉**：runner 22→**26 records**（+`armA.nested=N.in.x`、+`cast.int_partialenum_0=1`、+`cast.partialenum_out_0=1`、+`armA.allowcast=(uint2)C.lo`，cast sweep 8→10），双侧逐字节 MATCH；E2E 复跑零回归（diff 0 行），门禁 defects=0/numbering=0；metadata 登记修正（`needs_resolution_struct_break` UNTESTED→MATCH，`union_resolution_cache` → 读侧已接线/写侧 UNTESTED，`pipeline_needs_resolution_production` → MISSING 指向 TYPEFACTORY TODO）。

### TYPEUNION-CACHE-READSIDE-0001——UNION 臂 findTruncation 缓存读侧接线（2026-08-18）

- **UNION 臂补上缺失的 findTruncation 调用**（printc.cc:2001-2016）：原 `rpn_push_partial_symbol` 的 Union 臂直接做 `size==sz` break（把"无缓存 miss"当成了唯一行为）。oracle 的 union 臂先 `ct->findTruncation(off,sz,op,slot,newoff)`（printc.cc:2003）——`TypeUnion::findTruncation`（type.cc:2185-2199）是 (parent,op,slot) 解析缓存的**只读**消费方（"No new scoring is done"）：命中且 `fieldNum>=0` → `newoff = off - field.offset`、跨字段拒绝（严格 `>`）后下降字段（object_member 条目，2004-2014）；miss/null → `size==sz` break（2015-2016）→ 否则合成条目。修正后 Union 臂与 Ghidra 同序。
- **find_truncation (op,slot) 参数化**（docs/api/type_system/datatype.md 详述）：union/partial-union 的 ct 现在能通过 `union_resolutions` 快照命中缓存；RPN `opSubpiece` 两臂（dispatch 的 findTruncation 字段 atom 臂 slot=1 与 `rpn_push_partial_symbol`）与 legacy `op_subpiece` 均传入 `(Some(op), slot, Some(&self.union_resolutions))`。
- **新公开方法 `snapshot_union_resolutions(&mut self, fd)`**（RUGRA-GLUE）：从 doc_function 提取的快照入口（doc_function 仍是主管线唯一安装点），供 op 级 fixture（不经完整 doc_function 直接 `op_subpiece_rpn` 渲染单 op）安装同一 (parent,op,slot) 键控通道。Ghidra 无对应物：其类型层经 `op->getParent()->getFuncdata()` 直达活 Funcdata（type.cc:2189）。
- **fixture 26→31 records**：新增 5 条 union 读侧记录（`armB.unionhit=U.b`/`armA.unionhit=V.b`/`armA.unionmiss=W`/`armA.unionspan=X`/`armA.unionsynth=Z._0_2_`），C++ 侧经真 `Funcdata::setUnionField`（funcdata.cc:937）+ `ResolvedUnion(altUnion,1,types)`（unionresolve.cc:40）注入缓存（artificial slot 1），Rust 侧镜像经 `Funcdata::set_union_field` 写端口 + `snapshot_union_resolutions` 读通道。双侧逐字节 MATCH（runner `records=31 MATCH`）。
- **Differential（curl 语料）**：隔离归因验证零影响——同一工作树上仅回退本改动的两文件（datatype.rs/printc.rs）重跑 curl，输出 diff 0 行；主管线 `fd.union_map` 当前无可被 SUBPIECE (op,slot=1) 边命中的条目（unionresolve 生产方未接入主管线），miss 路径与改前行为逐字节一致。门禁 defects=0/numbering=0 维持。

### PRINTC-PTRCONST-DAT-SYMBOL-0001——pushPtrCharConstant/printCharacterConstant 去桩 + TYPE_SPACEBASE `&DAT_*` 臂 + M4/M5 卫生（2026-08-24）

- **`push_ptr_char_constant` 全量移植**（printc.cc:1698-1719，替换 `"<str>"` 桩）：`val==0` 拒绝（1701）→ 默认数据空间的 `resolveConstant`（1702-1707；消费 op 地址作 point，无 `AddrSpaceManager` 时走 translate.cc:637-641 默认路径）→ 全局 scope `isReadOnly`（1709-1710，经 `Scope::query_properties` 的 database.cc:1796-1801 等价：symbol-entry flags 优先、否则 flagbase 属性）→ `print_character_constant`（1713-1715）→ 常量色 atom 直发（1717）。printc.cc:1708 的 `isInvalid` 臂在 Rust 侧为空转（transitional spaceless `Address::new` 即解析后的数据空间形态，与 rule 侧消费方同键形；失配 resolver 无 Rust 表示，SPACE-0001 残余）。
- **`print_character_constant` 移植**（printc.cc:1534-1553）：共享 manager（`fd.arch.string_manager` 的 doc_function 快照，与 cpool/userops 同款 B4 共享模型）`get_string_data` 取 UTF8；空 → false（1542-1543）；`L` 前缀（1543-1545，charsize>1 非 opaque，`doEmitWideCharPrefix()==true`）；`escape_character_data`（printlanguage.cc:498-511 的 1:1 移植，charsize 固定 1、`getCodepoint` 前进、NUL/-1 停）逐 codepoint 走 `print_unicode`；`isTrunc` → `...\" /* TRUNCATED STRING LITERAL */`（1548-1549）。同批移植 `push_ptr_code_constant`（printc.cc:1730-1742：默认代码空间 + `addressToByte` + 全局 scope `queryFunction` + 显示名 atom）。
- **`push_constant_typed` Pointer 臂接通分派**（printc.cc:1775-1790）：签名扩为 `(val, ct, vn: Option<&Varnode>, op: Option<&PcodeOp>)`（对齐 `pushConstant` 的 vn/op 形态，point 语义必需）；`option_NULL && val==0` → `NULL`；ptr-to-`isCharPrint()` → `push_ptr_char_constant`；ptr-to-CODE → `push_ptr_code_constant`；否则 default cast。生产调用点接线（make_atom_for_vn/legacy 路径改道 + driver string_table 退役）属 D3，本片后 E2E curl 输出不变。
- **`op_ptrsub` TYPE_SPACEBASE 臂移植**（printc.cc:1057-1097，替换 `field_0x` 回退）：in(1) HighVariable symbol（`updateSymbol` 的 mapentry 回退等价，variable.cc:419-432）；array/code symbol 类型改写 valueon/arrayvalue（1062-1069）；`!valueon` 发 `&`（1071-1072）；symbol 引用 offset==0 → `push_symbol`（`&DAT_xxx`），否则 `push_partial_symbol`（allowCast=false，1092）；无 symbol → `TypeSpacebase::getAddress` + `push_unnamed_location`（1078-1082）；arrayvalue → 后置 `[0]`（1095-1096）。
- **`push_unnamed_location` 格式修正**（printc.cc:1938-1945 + space.cc:206-218）：`{space name}` + `0x` + `byteToAddress(offset,wordsize)` 的 `2*sz` 位零填充十六进制（8 字节空间高位为零时收窄到 4/6 字节宽度）——`ram0x00002100` 形态（原 `ram2100` 非 Ghidra 形态）。
- **M5**：legacy `push_partial_symbol` 补 allowCast/finalcast 臂（printc.cc:2018-2029：outtype=消费 vn 的 HighVariable 类型 + `cast_strategy.is_subpiece_cast_endian`，命中则 `(outtype)` 前缀于整条 entry 链前，2044-2047），签名增 `outtype/out_space_bigend/allow_cast` 三参；`op_subpiece` 调用点传 `allow_cast=true`（printc.cc:859）。陈旧注释（"Rugra has no isSubpieceCastEndian"/"SUBPIECE-style cast is a TODO hook"）随重写消除。**M4**（cast.cc:27 promoteSize 路由）**已收尾（2026-08-25，agent/cast-promotesize）**：`CastStrategyC` 补 `get_promote_size()` 访问器（cast.hh:57 保护字段 `promoteSize` 的 Rust 可见性胶水——Ghidra 侧消费者都是 strategy 成员函数直接读字段，Rugra 的 `is_extension_cast_implied` 落在 printc.rs 故需跨模块读取），`is_extension_cast_implied` 的 cast.cc:284 比较改经 `self.cast_strategy.get_promote_size()`，字面量 4 残余消除；访问器由 `type_system::cast::tests::test_get_promote_size_matches_constructor` 钉住，行为与所有锁定语料等价（x86/x64 int==4）。
- **快照字段**：`string_manager`/`symboltab`（doc_function 从 `fd.arch` 克隆，cpool/userops 同款）；`spaceman`（`glb->resolveConstant` 的 AddrSpaceManager，Architecture 尚无所有者 SPACE-0001——生产 None 走默认路径，fixture/driver 经 `set_space_manager` 注入）。
- **双侧 fixture**（`tests/oracle/printc_ptrconst_1204.*` + `tools/run_printc_ptrconst_oracle.sh`）：14 渲染记录 + 5 read 计数——合法 ASCII×2（正缓存零重读）、0xAD 非法×2（负缓存零重读，hugehelp 0x7180/0x99a8/0xc1d8 的 print 侧规则）、>2048 截断（2048 字符 + TRUNCATED 标记的 2098 字符记录逐字节一致）、非只读（manager 零查询）、null、子串、上下文分辨（0x40@0x5000/0x5008 经真 AddressResolver）、`&DAT_00002100` 与 `&ram0x00002100`。manager 为声明式 GhidraStringManager/Java 契约（与 stringmanager_core_1204 同款子类）；输出 sha256 `315a0901…3585` 双侧一致。

### PRINTC-UNLINKED-REF-FAMILY B1——未符号化 varnode 兜底地址源统一到 high 的 name representative（2026-08-25）

- **Ghidra 语义**（printlanguage.cc:238-262 `PrintLanguage::pushSymbolDetail`）：sym==null 唯一臂调 `pushUnnamedLocation(high->getNameRepresentative()->getAddr(), vn, op)`（:244）——兜底标签的地址是 **high 名字代表的地址**（`HighVariable::getNameRepresentative`，variable.cc:492-511，compareName 评分 variable.cc:456-488：namelock > unaffected > persist > input > addrtied > protoPartial > 非 internal 空间 > written > 更早 def），不是当前实例的 offset。`PrintC::pushUnnamedLocation`（printc.cc:1938-1945）打印该地址的空間名 + printRaw。推论：**一个 HighVariable 无论持有多少实例、在多少站点被打印，都只产生一个标签**。`emitExpression` 的两侧输出臂（printc.cc:2475/2482）与 `pushVnExplicit`（printlanguage.cc:229）都汇入该单一路径。
- **Rugra 缺陷**（A35 审计类 (a)②）：三条空间阶梯（`get_varnode_display_name_inner` 尾部、`make_atom_for_vn` RPN 原子 fallback、`push_varnode` Priority 2 阶梯）+ `emit_inline_expr` 的 `_ =>` 臂 + raw-register 名转换臂，全部以 `vn.get_offset()`（当前实例）为地址源——同一 high 的 N 个实例碎片化为 N 个 `uVar_<offset>` 标签（A35 §1 的 my_get_line/next_url/glob_word 交换标签即其 E2E 放大面）。
- **B1 修复**：新增 `PrintC::unnamed_location_offset(vn)`（单一地址源 helper，`// Ghidra: printlanguage.cc:238`）：有 high 且有实例 → `get_name_representative().get_offset()`；否则保守退回实例自身 offset（Ghidra 打印期不会遇到无 high 的显式 varnode，纯 Rugra 形态）。上述全部兜底标签臂改经该 helper 取地址；标签形式（`uVar_`/`uVar` + hex、`local_`/`param_stack_`、`vn_`、`DAT_`）**不变**（形式统一属切片 A）。Stack/Ram addrtied 臂经 helper 后观测等价（HighVariable 从不合并不同地址的两个 addrtied 实例，且 compareName 偏好 addrtied 成员 → 代表地址 == 实例地址），走 helper 仅为与 Ghidra 单一路径同构。
- **不改变 inline 判定键**：`inline_candidates`/`value_def_map`/`def_map` 仍按当前实例 `(space, offset)` 键控（内联决策是逐实例的），只有发射标签的地址源移到代表。
- **验收**（`tests/oracle/printc_unnamed_1204` + `tools/run_printc_unnamed_oracle.sh`，基线重钉到 9bdd5e3 + `src/printc.rs` overlay）：`multi_instance_unnamed` site=b 行从 `uVar_10000008`（第二实例自身 offset）塌缩为 `uVar_10000000`（代表地址，与 site=a 同标签）——registered 表第 31 行重钉，碎片化轴闭合；行 7/23/30/31 的 `uVar_` 形式差异与行 2/3 的 typechar 差异保留（分别属切片 A 与类型系统域）。Rust 侧回归 `test_unnamed_fallback_collapses_to_name_representative`（合并双实例 high → 双站点同标签；无 high 孤儿 → 退回实例 offset）。

### PRINTC-UNLINKED-REF-FAMILY A——兜底 token 形式统一到 `PrintC::pushUnnamedLocation`（2026-08-25）

- **Ghidra 语义**（printc.cc:1938-1945 `PrintC::pushUnnamedLocation`）：`s << addr.getSpace()->getName(); addr.printRaw(s);` 后推 var 色 atom——**空間名 + printRaw**，打印点无任何空间分支。`printRaw` 是虚分派：base `AddrSpace::printRaw`（space.cc:206-222）= `"0x"` + `byteToAddress(offset,wordsize)`（**除法**，space.hh:523-525：byte 单位→可寻址单位）的 `2*sz` 位零填充十六进制（`setw` 最小宽度不截断），`sz=getAddrSize()` 仅当 >4 时按 `offset>>32==0→4`、`else if offset>>48==0→6` 收窄，wordsize>1 且 `offset%wordsize!=0` 时后缀 `+cut`（十进制）；`ConstantSpace::printRaw`（space.cc:372-376）与 `OtherSpace::printRaw`（space.cc:410-414）覆盖为无填充 plain hex；`JoinSpace::printRaw`（space.cc:590-609）/`IopSpace::printRaw`（op.cc:41-54）按记录表解码（打印期显式 varnode 不可达，Rugra 平面枚举无对应 registry → 保守走 base 形式，注释已记降级与修复路径）。unique 空间 addrsize=4（UniqueSpace::SIZE，space.cc:418）→ `unique0x10000000`；ram addrsize=8 高位零收窄 → `ram0x00023e00`。
- **Rugra 缺陷**（A35 审计类 (a)①③）：三条阶梯形式互不一致且全非 oracle 形式——`get_varnode_display_name_inner` 尾部（Register→`uVar<hex>`/Stack→`local_`|`param_stack_`/Unique→`uVar_<hex>`）、`make_atom_for_vn` RPN fallback（Register→`uVar<hex>`/else→`vn_<hex>`）、`push_varnode` Priority 2（Register→`<prefix>_<hex>` var_prefix 名/Stack/Ram→`DAT_<08hex>`/else→`v_<size>_<hex>`）+ `emit_inline_expr` 的 `_` 臂（`uVar_<hex>`）。Register 阶梯 `uVar{:x}` 直接吞 raw 负 offset（E2E `uVarffffffffffffff70`×3，result/curl_cur.c:1233/1323/1396）。
- **A 修复**：新增 `PrintC::addr_space_print_raw(space, offset)`（`// Ghidra: space.cc:206`，虚分派等价：Const/Other→plain hex，其余 base 形式含收窄/除法 byteToAddress/`+cut`）与 `PrintC::unnamed_location_token(space, offset)`（`// Ghidra: printc.cc:1938`，token 构造半部 = 空間名+printRaw）；三条阶梯 + `_` 臂的全部标签形式改走该单一 helper（param_names 前置检查与 inline-candidacy 守卫保留，inline 键仍按当前实例——B1 约定不变）；`push_varnode` Priority 2 Register 臂的 `var_prefix` 形式退役（Ghidra 打印期无 buildVariableName 路径——那是 symbol 命名域）。既有 `pub fn push_unnamed_location`（printc_symbol_decl 期移植）改为委托 token builder，并修正其 `byteToAddress` 方向 bug（原 `offset * wordsize` 是 `addressToByte`；x86-64 全 wordsize=1 故不可见，潜在 wordsize>1 分歧消除）。
- **验收**（同 fixture，runner 重钉 slice C+B1+A）：行 7/23/30/31 翻为双侧逐字节一致（`unique0x10000000 = 5/7/5/6;`）——registered 表 6→2 行（仅 typechar 行 2/3，类型系统域）；`multi_instance` site=a/b 同标签（B1 地址源 + A 形式）；Rust 单测断言更新 `uVar_10000000`→`unique0x10000000`。E2E 方向（root 全量收口）：残余 `uVar_*` 兜底族整体变形为 `unique0x…`（golden 0 兜底，仍为差异但已是 oracle 兜底形式；真值闭合属 B2 符号化到达）；`local_`/`param_stack_`→`stack0x…`、`DAT_<08hex>`→`ram0x…`、Register 阶梯负 offset 产物→`register0xffffffffffffff…` 形。

### PRINTC-IFGOTO-EMIT——emitBlockIf 的 goto 分支移植（emit_structured_if goto_target 臂 + goto-cascade 顺序回退臂）（2026-08-25）

- **Ghidra 语义**（printc.cc:2878-2949 `PrintC::emitBlockIf`，goto 分支 cc:2894-2916）：`pushMod(); setMod(no_branch); condBlock->emit(); popMod()`（cc:2894-2898）先发射条件块的**非分支语句**；`emitCommentBlockTree(condBlock)`；然后 cc:2905 `tagLine()`（else-if 的 pendingBrace 合并 cc:2900-2903 属父链职责）；cc:2907-2913 `tagOp(KEYWORD_IF)` + `spaces(1)` + `pushMod(); setMod(only_branch); condBlock->emit()`（走 `emitBlockBasic` 的 only_branch 臂 → `opCbranch` 打印条件表达式）；cc:2914-2916 `spaces(1) + emitGotoStatement(condBlock, bl->getGotoTarget(), bl->getGotoType())`。`emitGotoStatement`（printc.cc:2303-2322）= `beginStatement(bl->lastOp())` → keyword（f_break_goto→`break` / f_continue_goto→`continue` / f_goto_goto→`goto` + `emitLabel(exp_bl)`）→ `SEMICOLON` → `endStatement`——**函数体自身无 tagLine**，唯一行断点在调用点（emitBlockGoto cc:2775 的 tagLine；emitBlockIf 的 goto 臂是行中 `if (cond) ` 之后）。
- **Rugra 缺陷**（F1 47 处 discarded conditions 的 emit 侧形态之一）：`emit_structured_if` 的 `goto_target.is_some()` 臂以 `emit_block_ops(&condition, false)`（no_branch **未激活**）发射条件块——终端 CBRANCH 走到 `doc_statement` 被捕获成一条裸 `(cond);` 语句（多数被 produced-empty 过滤吞掉，即"条件被丢弃"），从不打印 `if`/`goto`，直接 return——结构化期 `try_rule_if_goto`（blockaction.rs，newBlockIfGoto cc:1799-1816）建出的每个 if-goto 包装在发射侧全部作废。goto-cascade 顺序回退臂（GOTO_EDGE_1 干跑检测命中后的顺序发射）同样以 `emit_block_ops(&condition, false)` 泄漏 CBRANCH。
- **修复**：goto_target 臂改为 ①`emit_block_ops(&condition, true)`（= cc:2894-2898 setMod(no_branch)；Rugra 的 skip_terminal 布尔是 no_branch 的传输载体）→ ②`tag_line(0)`（cc:2905）→ ③`if (` + `emit_block_condition(&condition)` + `)`（cc:2907-2913 的 only_branch 条件发射，`emit_block_condition_rpn` 已是 opCbranch pushVn(in(1))+recurse 的移植）→ ④`print(" ")` + `emit_goto_statement(target_addr, bt)`（cc:2914-2916）。goto_type 映射（block.hh:89-91 f_goto_goto/f_break_goto/f_continue_goto → op::branch_type）与 `emit_block_goto` 一致；Ghidra 直接把 `bl->getGotoType()` 透传给 emitGotoStatement，**从不改写 CBRANCH op**（旧实现的 branch_type 改写 hack 已删）。target_addr = `goto_target` 块的 `get_start_addr()`（结构块递归到首个 Basic 的 initial_range/start_addr，与 emitLabel 的 `getFrontLeaf→getEntryAddr`、UNSTRUCTURED_TARG 标记、`emit_any_label_statement` 同源）。顺序回退臂同型改造（目标/类型取自条件块自身 CBRANCH 的 in(0) offset + branch_type，flat-mode opCbranch 尾 printc.cc:574-579 的投影，经新增 helper `cbranch_goto_info`），随后仍发射 if_body。`emit_goto_statement` 移除函数内 `tag_line(0)`（cc:2303-2322 无 tagLine；调用点语义：emit_block_goto 自带 tag_line，if-goto 臂是行中——两处均忠实）。
- **验收**：curl E2E（HEAD `e17b4295` 干净树对照同构 fast-release 构建）：HEAD 输出 **0 个 goto**（16 处裸 `(cond);`/条件丢弃形态）→ 修复后 **22 个 `if (cond) goto <label>;`**（golden 61；缺口=flat opCbranch 完整移植（stash `flatcbr-prev-agent-diff` 中的 FLAT mod + op_cbranch_rpn 全臂，未含本轮）与结构化覆盖域）；skeleton 2927→2923、defects 0→0、numbering 1→1（唯一 match_url numbering 为既有存量，与本改动无关）；多次重跑输出字节一致（一次 main TIMEOUT 为 10s 上限的负载抖动，复跑恢复）。逐行 diff 确认全部变化均为裸条件语句 → if-goto 形态（含 2 处复合条件 `(A) || (B)` 合并恢复：match_url 与 my_get_token 的两条独立条件语句合并回单条复合 if-goto）。样本：`(piVar37 != 0);` → `if (piVar37 != 0) goto code_r0x00002728;`（result/curl_cur.c main）。
- **表示层残差**（如实登记）：①`if (` 文本直接 print（无 tagOp markup——Rugra EmitNoMarkup 无 markup 通道，文本等价）；②空体/畸形条件仍走 R50 `1` 回退；③goto 目标 label 与 golden 的 `LAB_` 符号名差异属 varmap 符号化域（golden 经 ScopeLocal queryCodeLabel，Rugra 的 `code_label` 已是 emitLabel 兜底形式 cc:3183-3192 的移植）；④golden 的 `file2string`/`parseconfig` 全体 goto 形态还依赖 flat 模式与结构化覆盖的后续 wave。

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

- `doc_function()` 曾在 typedef 后、签名前 emit `extern long NAME;` 声明。**2026-08-25 移除（MAIN-DATPOOL-0001）**：oracle printc.cc 全文无 `extern` 关键字（0 命中），docFunction（printc.cc:2641-2670）无全局声明步骤；锁定 golden 含零 extern 行。移除后 main 段 extern 行 83→0、全文件 `extern long DAT_` 69→0，use-site 裸引用（`DAT_*`、`::config`、`stderr`）不变。
- 同时扫描 `used_varnode_names` 捕获全局名的逻辑一并移除；`used_varnode_names`/`used_varnode_types` 集合仍由 `mark_variable_used` 记录（保留字段，doc_function 内不再消费）。

### 2026-06-23（续）：synthetic DAT_ 全局声明收集

- `op_store` 生成 synthetic `DAT_xxxxx` 名时调用 `mark_variable_used`（仍在）；其 extern 收集消费端已于 2026-08-25 随 doc_function extern 块一并移除（MAIN-DATPOOL-0001）。


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

### 2026-07-28：if-goto 的 BlockIf::goto_type → CBRANCH branch_type 映射（已被 2026-08-25 PRINTC-IFGOTO-EMIT 取代）
- ~~Ghidra `emitBlockIf`（printc.cc:2914-2916）读取 BlockIf 的 gototype 并调用 `emitGotoStatement`；Rugra 在 `emit_block_ops(&condition, false)` 之前改写 condition block 末尾 CBRANCH 的 branch_type。~~
- **2026-08-25 失效说明**：该方案（发射前改写 op.branch_type + `emit_block_ops(&condition, false)` 泄漏 CBRANCH 为裸 `(cond);`）已整体删除——Ghidra 从不改写 CBRANCH op，`bl->getGotoType()` 直通 `emitGotoStatement`（printc.cc:2914-2916）；条件以 only_branch 语义单独发射（`if (` + `emit_block_condition` + `)`）。现行实现见上文 PRINTC-IFGOTO-EMIT 节。

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
- `build_type_stack` — printc.cc:143 `buildTypeStack`（匿名 PTR/ARRAY/CODE
  下钻至命名 base；无 proto 的 CODE 层以合成 `void` 替代
  `glb->types->getTypeVoid()`，见函数内 DIVERGENCE 注记）
- `type_stack_for` — RUGRA-GLUE 借用适配器（Arc 入栈/出栈配对）
- `push_type_start_opt` — printc.cc:264 `pushTypeStart`（签名
  `Option<&Arc<Datatype>>`，buildTypeStack 型栈渲染；匿名 base 走
  `generic_type_name`；单层栈按 cc:275-278 仅由 `noident` 决定
  type_expr_space/nospace — 命名单层指针 `char *` 因此渲染 `char * x`，
  oracle named_ptr_contrast 锁定；原 `emit_type_prefix` 组合名捷径与
  `datatype_name_ends_with_star` 连接启发式已移除）
- `decl_prefix_ends_with_star` — RUGRA-GLUE 连接判定（多层栈 = 空白已由
  type_expr_space 发射；单层栈 = 需补一个空白）
- `push_type_end_opt` — printc.cc:313 `pushTypeEnd`（含 PTR-under-ARRAY/CODE
  的括号闭合 + `[N]`/`(params)` 后缀走；无 proto 匿名 CODE 的
  上游死循环见函数内 DIVERGENCE 注记）
- `push_prototype_inputs` — printc.cc:169 `pushPrototypeInputs`（类型表达式
  内的参数表；与顶层 `emit_prototype_inputs` printc.cc:2222 相对）
- `debug_render_type_decl` / `debug_render_type_start_only` —
  RUGRA-GLUE fixture 观察面（对应 oracle fixture 的 FixturePrintC 子类）
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

### 2026-08-17：UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ②③ — docFunction 注释链接线 + mask 对调

**③（mask 对调，printlanguage.cc:579/582）**：构造器里
`instr_comment_type`/`head_comment_type` 两个掩码此前互相装反——Rugra 写成
`instr = header|warningheader`、`head = user2|warning`，而 oracle
`PrintLanguage::resetDefaultsInternal`（printlanguage.cc:575-583）为

```cpp
head_comment_type = Comment::header | Comment::warningheader;   // cc:579
instr_comment_type = Comment::user2 | Comment::warning;         // cc:582
```

已对调并同步字段 doc 注释。装反的直接后果：`emitCommentFuncHeader`
（printc.cc:3280 `(head_comment_type & comm->getType())==0 → continue`）把
`warningheader`(32) 注释全部滤掉（旧 head 掩码 18 与 32 按位与为 0）——
即使接线也不会发射。

**②（docFunction 注释链接线，printc.cc:2650-2653 逐字调用序）**：
`doc_function` 在 `emit_function_declaration` 前补齐 oracle 的注释调用序：

```cpp
commsorter.setupFunctionList(instr_comment_type|head_comment_type,
    fd,*fd->getArch()->commentdb,option_unplaced);   // cc:2650
int4 id1 = emit->beginFunction(fd);                  // cc:2651（文本无字节）
emitCommentFuncHeader(fd);                           // cc:2652
emit->tagLine();                                     // cc:2653
```

- `setup_function_list` 从 `fd.arch.commentdb`（每 worker 的
  `CommentDatabaseInternal`，examples 在 `Architecture::new` 后分配）按
  函数地址收集；无 Architecture/commentdb 的 legacy 调用方 sorter 保持空，
  与 Ghidra 空库行为一致。
- `emit_comment_func_header`（printc.cc:3272-3311 移植体，原零调用方）由此
  获得 doc_function 调用方；`option_unplaced`/`option_nocasts` 默认 false，
  header_basic 排水循环按 `head_comment_type` 掩码过滤。
- **`emit_line_comment` 实装**（printlanguage.cc:589-648 全量移植，作为
  `PrintLanguage` trait 在 `impl PrintLanguage for PrintC` 的覆盖；原 trait
  默认体是 no-op，`emit_comment_func_header`/`emit_comment_group` 全部经它
  发射）。语义：`indent<0` 取 `line_commentindent`（新字段，默认 20，
  printlanguage.cc:580）；`tag_line(indent)` 后发 `"/* "`（PrintC 经
  `setCStyleComments()`=printc.hh:242 `setCommentDelimeter("/* "," */",false)`
  的不变量）；逐字节 token 循环（空格/tab run→等长空格、`\n`→换行、
  `\r` 丢弃、`{@…@}` 注解单 token、词边界=isspace）后发 `" */"`。
- cc:2653 的 `tagLine()`：oracle 的 `EmitPrettyPrint::tagLine` 无条件写
  endl，注释与签名间隔一空行；Rugra `EmitNoMarkup::tag_line` 在输出已以
  `\n` 结尾时抑制重复换行，故警告与签名间只保留单个换行（差分门禁对空行
  归一化，注释位置=签名前最后一行不变；与 `open_brace_indent` 处登记的
  同源发射器差异）。

**验收（锁定 curl E2E 新鲜 stdout 捕获）**：`/* WARNING: Unknown calling
convention` **24 → 51**，与锁定 12.0.4 golden
（`tests/golden/ghidra_curl_1204.c`）**51/51 逐位置零失配**（24 PLT stub
+ 24 EXTERNAL stub + main_init/main_free/hugehelp 3 个真实函数；地址按
0x100000 运行基址归一后按（地址,函数名,字节数,警告文本）四元组逐处对照）。
差分门禁（双 golden）：defects=0 / numbering=0 / Matched 123 不降。R3 复核
结论：锁定 12.0.4 golden 的 main_init(:2128)/main_free(:2139)/hugehelp(:2191)
全部带完整 ` -- yet parameter storage is locked` 后缀——旧 11.3.2 golden
（`tests/golden/ghidra_curl.c`）的"裸 main_init"是过版误引，R3 残差在锁定
oracle 下不存在，无需也不应在 DWARF apply 侧改锁属性。

### 2026-08-23：COMMENT-SORTER-PRINTC-0001 — 注释消费端迁到直接协议

printc.rs 的三个注释消费端从 `CommentSorter` 的 Vec 胶水快照
（`setup_block_list`/`setup_op_list`/`header_comments`，已随本迁移从
comment.rs 删除）迁移到 oracle 的迭代器状态机直接驱动：

- **`emit_comment_group(inst: Option<&PcodeOpRef>)`**（printc.cc:3231-3241）：
  `setup_op_stop(inst)` + `while has_next() { get_next(); isEmitted→skip;
  instr 掩码→skip; emit_line_comment(-1) }`。签名从 `Option<&PcodeOp>` 改为
  `Option<&PcodeOpRef>`（`setup_op_stop` 的原生参数；原先在消费端手工推导
  block_index/op_order 的胶水删除）。**`None` 分支补上
  `setupOpList(NULL)` 语义**（comment.cc:365-367）：`opstop = stop`，排空当前
  块剩余注释——旧实现 `None => return` 是缺语义（cc:3241/3266 的
  `emitCommentGroup((const PcodeOp *)0)` 尾排空）；调用约定同 oracle：需先
  `setup_block_bounds` 建立块窗口（emitBasicBlock cc:2684 首行 /
  emitCommentBlockTree cc:3265）。
- **`emit_comment_func_header`**（printc.cc:3272-3311）：两轮
  `setup_header(HEADER_BASIC)` / `setup_header(HEADER_UNPLACED)` 窗口行走
  取代一次性 `header_comments()` 快照——unplaced 横幅轮现在只走
  (-1, header_unplaced, *) 键（旧快照轮重复迭代 basic 键，在
  `option_unplaced=true` 时会把 header 注释在横幅下二次发射；该偏差
  随直接协议关闭。oracle 的 unplaced 轮无 head 掩码——逐字保留）。
- **`emit_comment_block_tree` 叶子**（printc.cc:3265-3266）：
  `setup_block_bounds(index)` + `emit_comment_group(None)`，与 oracle
  `commsorter.setupBlockList(bl); emitCommentGroup(0)` 一一对应。
- **`setEmitted(true)` 落地**（printlanguage.cc:648）：`Comment.emitted` 改
  `AtomicBool`（`mutable bool emitted` 的 1:1，comment.hh:50；不用
  `Cell<bool>` 因 `ffi.rs` 的 `Mutex<Option<Funcdata>>` 全局要求 `Sync`），
  三个消费端在发射处调用 `comm.set_emitted(true)`。Rust 投影：先复制
  text、标记、再 `emit_line_comment(&mut self)`（不可变借用先结束）；
  mark 与 emit 字节之间无人读 `is_emitted`，观测顺序等价。
- **`doc_function` 的 `setup_function_list` Result 处理**（原 :6743 unused
  Result 警告）：死 op LowlevelError（comment.cc:289/303）经
  `eprintln!("[DECOMP] ...")` 记录后继续——print 层既定 log-and-continue
  投影（同 `emit_type_definition` 的 LowlevelError 处理）。

**迁移纯度**：E2E 可观测行为不变（块级注释仍只经 `emit_comment_block_tree`
发射；Rugra 的语句行走本就不跑 per-op `emitCommentGroup` 链——该已知缺口
不变，见 `doc_statement` 处注释）。回归：printc:: 9 过 / comment:: 16 过；
oracle fixture `comment_sorter_iterators_1204` Rust 侧 38 行 stdout sha256
`072c03b2…` 与 pin 逐字节一致（注册 runner 的 `comment_rs_sha256` 门随
comment.rs 编辑失效，需主仓重登记）。

### 2026-08-25：PRINTC-WARNING-COMMENT-0001 — 语句级 WARNING 注释发射接线

上一节登记的已知缺口（"Rugra 的语句行走不跑 per-op `emitCommentGroup`
链"）由本变更关闭：golden 16 条 `/* WARNING: Subroutine does not return */`
（flow.cc:646 → funcdata.cc:119 入库 commentdb）此前忠实存储但从不打印。

**①（emitBlockBasic 注释协议接线，printc.cc:2684/2712/2717/2742）**：
`emit_block_basic_rpn`（rpn_enabled 默认 true，E2E 实际路径）与
`emit_block_ops`（legacy 路径）都补上 oracle 的四步协议：

- 块首 `commsorter.setupBlockList(bb)`（cc:2684）→ `setup_block_bounds`
  （`ops_block_index` RUGRA-GLUE helper 从 ops 的 `parent` 推导 BlockBasic
  index——与 `findPosition`/`setupOpList`（comment.cc:295/370）的
  `op->getParent()->getIndex()` 同键）；
- 每条打印语句前 `emitCommentGroup(inst)`（cc:2712/2717，instr 掩码
  user2|warning 在此放行 noreturn 警告）——RETURN 语句同样接入
  （`emit_block_ops` 的 RETURN 特例分支）；
- 块尾 `emitCommentGroup(NULL)`（cc:2742，opstop=stop 排空剩余）。
  二次发射由 `Comment::emitted` 标记防护（`emit_comment_block_tree` 与
  本路径互斥安全）。

**②（emit_line_comment 绝对缩进字节，printlanguage.cc:597 +
prettyprint.hh:557）**：oracle `EmitNoMarkup::tagLine(int4)` 写 **无条件
endl + 恰好 `indent` 个空格**（列覆盖，非当前层级）；Rugra
`EmitNoMarkup::tag_line` 忽略覆盖参数且在行首抑制换行。`emit_line_comment`
内经 `as_any_mut().downcast_mut::<EmitNoMarkup>` 直接复刻 oracle 字节
（`\n` + `indent` 空格），其他 emitter 走 trait 调用。文本内 `\n` 分支
（cc:616-617 `tagLine()` 无参，当前层级）字节等价保持不变。

**③（fixture 可见性 glue）**：`setup_function_comments(fd)`（cc:2650 步骤
从 doc_function 内联块重构为方法，doc_function 调用它——生产行为不变）
与 `setup_block_comment_list(index)`（cc:2684 步骤）提供 pub 可见性
（Ghidra 经 protected `docFunction`/`emitBlockBasic` 内部执行；Rust 无
protected，oracle fixture `printc_warning_1204` 经它们驱动生产代码）。

**双侧 oracle fixture `tests/oracle/printc_warning_1204.{cc,rs}`**（runner
`tools/run_printc_warning_oracle.sh`，重钉三件套齐备）：三 case 覆盖
clean（零注释零字节）/ noreturn（`Funcdata::warning` 生产通道，62 字节
endl+20 空格+注释）/ multi（`warningHeader` 头注释 + 两块两调用点警告，
202 字节含头注释后的空行）。C++ 侧 FixturePrintC 换装裸 EmitNoMarkup
隔离未移植的 EmitPrettyPrint fill 状态。双侧 stdout sha256 相同
`0d639688…`，9 行逐字节 MATCH。Rust 侧块用 start_addr=首 op 地址构造
（`initial_range` 仅生产 followFlow 设置），fixture 注释全部落在块首 op
地址——与 C++ `setBasicBlockRange` 同界。

**E2E 预期（root 合流批验证）**：golden 16 条 noreturn 警告分布于
main(1)/myprogress(1)/my_get_line(1)/helpf(1)/file2string(1)/parseconfig(1)/
getparameter(1)/glob_word(2)/glob_set(2)/glob_range(1)/next_url(1)/
match_url(3)——全部为 `__stack_chk_fail`/`exit` 类 noreturn 调用点，
语句级发射接通后应逐条出现（这是正向变化；差分门禁全量判定留给 root）。
附注（已解决）：`comment_sorter_iterators_1204` 的失配根因是 fixture 构造了
非法状态（未安装 cover）——Ghidra 的 C++ fixture 经 `setBasicBlockRange`
显式装 cover（`block.hh:462` setInitialRange private+friend）。已按合法状态
构造修复（`8d59b77`，`set_initial_range` pub 化一行 + fixture 同构装 cover，
38/38 逐字节，BLOCK-STOPADDR-FIXTURE-REGRESSION-0001 关闭）。

### 2026-08-25（续）：PRINTC-SWITCH-EMIT-0001 — emitBlockSwitch case 发射对齐

A10 集成（try_rule_switch 经 identify_internal 安装 BlockSwitch，
finalize_structure 把被吸收的 case 块标 DEAD）后暴露的发射层缺陷：
`emit_structured_switch` 把 case 体路由进 `emit_block_structured` 的
DEAD 守卫——case 块恰好带着 DEAD+CASE_BODY 标志，体被整块吞掉，随后
legacy 空移除后处理把整个 switch 剥成 `switch(...) {}` 空壳（funcdata
测试 `case 0:`/`case 1:` 断言因此绑定本 TODO）。

**①（case 体直接 dispatch，printc.cc:3339-3341）**：新增
`emit_switch_case_body`（RUGRA-GLUE，对应 `FlowBlock::emit` block.hh:221
的虚分派）——按块类型分派到各 `emit_structured_*`，跳过 DEAD 守卫并
把 case 块标记进 `emitted` 防 doc_function 不可达清扫重放。这正是
oracle 的语义：`bl2->emit(this)` 从不带 consumed/dead 检查，BlockSwitch
组件是其 case 块的唯一发射者。

**②（oracle 布局字节，printc.cc:3329/3333/3348/3350-3351 +
prettyprint.hh:555-556）**：`openBrace(OPEN_CURLY, same_line)`（printc.cc:1593
option_brace_switch 默认 same_line）= 空格 + `{` 无换行；每 case
`startIndent`/`stopIndent`（Rugra `bump_indent`/`drop_indent`），
`beginBlock`/`endBlock` 在 EmitNoMarkup 是 no-op——**不再**给 case 体包
大括号；标签落在 switch 体缩进层、语句 +1 层；收尾 `tagLine` + `}`。

**③（`switch(` 无空格，printc.cc:586-587）**：opBranchind 是
`tagOp(KEYWORD_SWITCH)` 紧跟 `openParen`——无分隔空格，golden 的
`switch((int)pCVar10 - 0x23U & 0xff)` 佐证。Rugra 原先打印 `switch (`
（带空格）——修正为 `switch` + `(` 两段。配套：prettyprint 后处理 5 处
`switch `/`switch (` 前缀启发式统一走 `is_switch_stmt_prefix`（两种形态，
`switch` 是 C 关键字不可能是标识符调用，词法安全）——否则
`remove_orphan_case_labels` 会把无空格形态的全部 case 标签当孤儿剥掉。

**④（case 值格式，printc.cc:1744 pushConstant + 1288 push_integer）**：
标签值改走 `push_integer`（char-print 类型走 CHAR 格式；int 按符号翻转
+ `val<=10` 十进制 / mostNaturalBase 十六进制）；RPN 常量 helper
`format_constant_value` 的十进制边界同步 9→10（cc:1332）。**⑤（break
语义，printc.cc:3342-3345）**：`isExit(i) && i != numCaseBlocks-1` →
RETURN 终止的 case（可证不流向出口块）不打 break，其余 case 打 break，
最后一个标签（含尾随 default）从不打。

**双侧 oracle fixture `tests/oracle/printc_switch_emit_1204.{cc,rs}`**
（runner `tools/run_printc_switch_emit_oracle.sh`，三件套重钉齐备）：C++
侧手工搭生产形态 BlockSwitch（BlockBasic 原件 + 边、newBlockCopy/
copymap/replaceUsingMap 复刻 buildCopy block.cc:1925-1938、JumpTable
label/block2addr 表、grabCaseBasic+identifyInternal+addBlock 复刻
newBlockSwitch block.cc:1904-1919），驱动真 `emitBlockSwitch`；Rust 侧
手工搭同形 BlockSwitch 走 `emit_block_graph`。四 case：two_case_return /
single_case_default（default 边带表项——default 臂无条件 getLabel）/
multi_label_first（首 case 双标签连续行，时序缺陷检测器）/ break_exit_form
（空体 isexit case 的显式 break）。**双层 MATCH**：statement 层（switch(E)
归一 + 标签逐字 + 体归类）与 raw hex 层逐字节一致（双侧 raw sha256 同为
`6e46461c…`）。范围外缺口登记于 metadata `out_of_scope_gaps`：生产
try_rule_switch 的 case 标签是出边索引（非 jumptable 恢复标签）且
default 恒 None；doc_function 全管线中 `uVar0 = 10; return uVar0;` 未折叠
为 `return 10;`（ActionReturnRecovery + implied 层）。funcdata
`test_switch_case_structuring` 断言恢复（case 标签 ×2 + 体 return 计数）。
附注：`comment_sorter_iterators_1204` fixture 在 0d2252d（`get_stop_addr`
回退从"末 op 地址"改为 `initial_range`）后 Rust 侧回归失配（内部地址
注释落入 header_unplaced）——预存在问题，非本租约，建议 root 重登记
（fixture 手工块无 initial_range，需 pub 化 `set_initial_range` 或恢复
无 range 时的末 op 回退）。

### 2026-08-25：flattened emitBlockBasic 逐块注释窗口协议（main 打印 panic 修复）
- `op_parent_block_index`（新 helper）— 从单个 op 的 live parent 取块索引。
- `emit_block_basic_rpn` / `emit_block_ops` — Ghidra 逐基本块调 emitBlockBasic（每块
  setupBlockList → emit → 尾部 emitCommentGroup(NULL)，printc.cc:2684/2742）。Rugra 的
  flattened ops 切片原先只按首 op 的 parent 开窗：首 op parent 失效时 setup 被跳过，
  per-op emitCommentGroup(Some) 使用陈旧窗口，start 可超过后续 opstop，
  get_next 索引越过 commmap 末尾（main 打印阶段 index-out-of-bounds panic）。现于每个
  parent 块边界：先 drain 离开块的尾部注释，再以 live parent 索引开新窗口，
  复现 oracle 的逐块协议。

### 2026-08-25（续2）：PRINTC-COMMENT-WINDOW-PANIC-0001 — ops_block_index 死 op 前缀跳过 setupBlockList 的 OOB panic

E2E 中 parseconfig.constprop.0 / glob_set / next_url 三个 worker PANICKED
（`comment.rs get_next` 越界：`commmap.len()==1` 但 `start==1`、`opstop==0`）。

**根因（instrumented 复现）**：`emit_block_basic_rpn`/`emit_block_ops` 的块窗口
键经 `ops_block_index(ops)` 从 `ops.first()` 的 `parent` 推导。Rugra 的死 op
transport 让块 op 列表快照保留已销毁 op（`parent=None`，is_dead=true），首 op
为死 COPY 时推导得 `None`，cc:2684 的 `setup_block_bounds`（setupBlockList）
被整段跳过；但循环内 per-op `emit_comment_group(Some(op))`（cc:2712/2717 语义）
仍对活 op 触发——`setup_op_stop` 以该 op 真实父块（如 blk=14）算
`upper_bound`，落在上一块（blk=27）遗留窗口 `start=1` 之前（opstop=0），
`hasNext`（`start != opstop`，comment.hh:250）返回 true，`getNext` 在 `end()`
取值——C++ 侧同序列是 end() 解引用 UB；Ghidra 不会走到，因为
`BlockBasic::removeOp`（block.cc:2292-2297）setParent(NULL) 与从列表 erase
同一步发生，`bb->beginOp()..endOp()`（printc.cc:2694）里每个 op 的 parent
都是 bb，且 setupBlockList(bb) 无条件先于一切 op landmark。

**修复**：`ops_block_index` 从 `ops.first()` 改为 `ops.iter().find_map(...)`——
返回**首个有 parent 的 op** 的块 index（即 Ghidra 循环实际看到的首 op）。
窗口键与 `findPosition`/`setupOpList` 的 `op->getParent()->getIndex()`
（comment.cc:292/370）保持同键不变式恢复：同块窗口内
`lower_bound((bl,0,0)) <= upper_bound((bl,order,0xffffffff))` 恒成立，
opstop 不会落到 start 之前。全死 op 前缀的块本就无 per-op landmark
（is_dead 先 continue），None 分支行为不变。

**验收**：`--rugra-selected-function parseconfig.constprop.0 glob_set next_url`
→ 3/3 decompiled（633/402/547 字节），0 panic 0 timeout；main 维持 TIMEOUT
（既有状态，非本缺陷范畴）。

### 2026-08-25（续3）：PRINTC-EMPTYELSE-0001 — is_block_body_empty 自创 dead-output 过滤移除（空 if 臂内容恢复）

**根因**：`is_block_body_empty`（决定 emit_structured_if 是否打印 then/else 臂）内嵌一个
Ghidra 无对应物的"死输出过滤"——`global_used_outputs` 查询 + 纯计算 opcode 白名单
（INT_EQUAL/INT_ADD/LOAD 等 27 op），输出无人读的比较/算术 op 被当作"不可发射"，
整臂被判空后抑制。oracle 的 emitBlockBasic（printc.cc:2678-2742）只有三道门：
notPrinted()（cc:2696，op.hh:182 = marker|nonprinting|noreturn）、branch 抑制
（cc:2697-2702，臂上下文 no_branch 已 set → 全部 branch skip）、implied-output
（cc:2704-2705）——从不因"输出没人读"丢语句；真死计算在 oracle 里已被 ActionDeadCode
从 PcodeOpBank 移除。emitBlockIf（printc.cc:2919-2924）对形成的 BlockIf 无条件开臂括号。

**修复**：谓词改为精确镜像默认发射路径 `emit_block_basic_rpn` 的四道门
（is_dead → notPrinted 三 flag → is_branch → implied output），逐门与
printc.cc:2695-2705 一致；删除 dead-output 过滤与 legacy 路径专属的
COPY/RIP/stack-frame/inlined skip（RPN 发射路径无这些 skip，谓词与发射门禁
错配会判空但实际有输出，或反向）。

**验收（E2E curl 12.0.4 golden）**：空 if 体 7→6（main 的 glob_url 臂
`if (piVar38 != 0) { iStack_22c = 0; … }` 与 myprogress 的 `else { dlnow = 0; }`
两处真实语句恢复，方向朝 golden `if (iVar4 == 0) { bVar3 = false; … }`）；
defects 0→0、numbering 1→1、skeleton 2884→2891（+7 = 恢复的 9 行语句归一化后净增）。
剩余 6 处空 if 体与 file2string 主体缺失为 IR 层残差（op 已被上游 Action 移除，
非 printc 判空），归 FILE2STRING-EMPTYELSE 后续分层修复。
### 2026-08-25（续3）：FLAT-CBRANCH — flat opCbranch 全臂 + emitBlockBasic 尾部 goto/label 补全（F1 discarded conditions）

Ghidra `emitBlockBasic`（printc.cc:2678-2744）的 flat 语义链此前只落了
op 循环（cc:2694-2722），三个决定性缺口导致 F1（丢条件）与 label-less
goto：

**1. `opCbranch` 全臂（printc.cc:536-580，前任草案 + 本轮补全）**
- `print_mods::FLAT`（0x400）镜像：`emit_block_ops` 在 `!skip_terminal`
  （flat 上下文 transport）时 set FLAT，离开时恢复——Ghidra 只有
  docFunction 的 `isSet(flat)` 分支（cc:2657-2658）会走到 emitStatement →
  opCbranch 的 `yesif` 臂。
- `op_cbranch_rpn`（新）：cc:540-578 的逐行移植——`yesif`（isSet flat）、
  `booleanflip`（isBooleanFlip，op.hh:191）、`is_fallthru_true` 取反
  （cc:548-551，op.hh:193；fallthru 为真边时打印否定条件并置
  `print_mods::FALSEBRANCH` 0x800——oracle 只置无读者，faithful transport）、
  `check_print_negation` 折叠（cc:558-563 → NEGATETOKEN，== → !=）、
  `boolean_not` RPN token（cc:564-565，printc.cc:30 `"!"` unary prec 62，
  token 表 index 10）、`pushVn(in(1), m)` + recurse（cc:566/568）、尾随
  `goto <label>`（cc:575-578）。
- legacy `op_cbranch`（printlanguage trait）：同结构直发 twin，`!(...)`
  显式括号形式。
- 效果（curl E2E）：50 处裸表达式语句 `(cond);`（丢条件）恢复为
  `if (cond) goto code_r0x...;`。

**2. label 发射（printc.cc:2685 `emitLabelStatement(bb)` + cc:3198-3214）**
- flat 模式下每个 isJumpTarget 块要打 `code_r0x...:` 标签。Rugra 的
  dispatcher 不逐 CFG 块跑 emitBlockBasic，所以标签在 `emit_block_ops` /
  `emit_block_basic_rpn` 尾部补齐：块内 CBRANCH/BRANCH 的 code 地址目标
  ∈ `goto_targets` 时逆序发射标签（逆序保持多目标时序稳定）。
- `emit_label_statement` 重写为 cc:3198-3214 的 faithful 形式
  （tagLine + emitLabel + COLON）；isJumpTarget 判定在调用方 membership。
- 效果：39/39 label-less goto → 41/41 goto 全部有 label（含 ifgoto Agent
  集成后的 goto 增量）。

**3. 尾部 nofallthru goto（printc.cc:2723-2741）**
- `print_mods::NOFALLTHRU`（0x1000，printlanguage.hh:157）新增。
- 尾部 trailing BRANCH（cc:2701 跳过的直连分支）在目标是 live goto
  target 时发射独立 `goto <label>;` 语句（cc:2727-2740 的
  tagLine/beginStatement/goto/SEMICOLON/endStatement 序列；单出边场景
  cc:2738 emitLabel(getOut(0))）。

**配套修复（prettyprint.rs）**：`post_process_output_legacy` Pattern 5
（goto→尾调用重写）排除 `code_`/`joined_`/`dup_` 前缀标签——flat 尾部
goto 的目标是 emitLabel 标签（printc.cc:3164-3193），不是 libc 函数；
不排除时每条 flat goto 被误重写为 `return code_r0x...();`（gcc 报
label 的 implicit-function-declaration）。

**验收（curl E2E, worktree agent/flat-cbranch）**：
- goto/label 一致性：41 goto 目标 / 45 标签，0 goto-without-label，
  4 orphan（无引用标签，无害）；0 `return code_r0x` 假象。
- `compare_ghidra --summary-only`：skeleton 2927 → 2908（−19），
  defects 0/0，numbering 1/1（match_url 预存 per-prefix 计数问题）。
- `audit_syntax`：53 OK/71 FAIL → 55 OK/69 FAIL（+2：清零 2 处
  "标号使用前未定义"）。
- `cargo test --lib printc` 10/10；funcdata 18 失败为预存（stash 验证）。

## DEAD 守卫上移 + 结构化体空判定域（PRINTC-DEADGUARD-TOPLEVEL-0001，2026-08-25）

1. **DEAD 跳过只属于顶层游走**：Ghidra 的发射树没有 dead-block 概念——
   emitBlockIf 无条件 `getBlock(1)->emit(this)`（printc.cc:2921-2922），
   emitBlockList 对每个 child 同理。结构化父块是其子块唯一发射者（无论
   consumed 标志），父定向递归不得消费 DEAD 标志。`emit_block_structured`
   内的 DEAD 早退移除，改由入口游走（`emit_block_graph` 顶层循环与
   doc_function 的 root/unreachable 循环）在调用前自行跳过 DEAD 块。
2. **is_block_body_empty 只对叶体有意义**：Ghidra 的 emitBlockIf
   （printc.cc:2878-2943）没有空体跳过；Rugra 的空体扫描只对叶体
   （Basic/Copy，get_ops() 列真实 op）有意义——结构化体（BlockIf/
   BlockList/...）自身无直接 op，扫描必须报非空并交给递归发射决定；之前
   扫描把每个结构化体都误判为空，吞掉整个 then 分支（my_fwrite 的嵌套
   fopen/return-if 丢失只剩 `if (cond) {}` 的根因之一）。

### 2026-08-25：NUMDECL-DOUBLE-V — 符号背书变量名 print 期逐字输出

SUB-A 形态双声明根因：`get_varnode_display_name_inner` 与 `push_varnode`
Priority 1 两处的 `maybe_apply_type_prefix`（RUGRA-GLUE）按 print 期
实例类型把符号背书的匈牙利前缀重写（`iVarN` → `piVarN`），而
`emitLocalVarDecls` 声明侧仍打印符号原名 `int iVarN;`——body/decl 名分
裂后 prettyprint backfill 为 `piVarN` 注入第二个异类型声明（curl 语料
9 对/7 函数，如 main `int iVar37;` + 注入 `char *piVar37;`）。

修复：两处调用点镜像 oracle 分支结构——`printlanguage.cc:238-262
pushSymbolDetail`：`sym != null` → `PrintC::pushSymbol`（printc.cc:1905-
1936）打印 `sym->getDisplayName()` 逐字（唯一修饰是 unmerged `$N` 后
缀，无类型前缀重写）；`sym == null` → unnamed-location。Rugra 侧
`high.symbol.is_some()` → `high.get_name()` 逐字返回（ActionNameVars 的
RUGRA-GLUE write-back 保证 high.name == symbol.display_name）；
symbol-less high 保留原前缀重写（未链接引用域的 GLUE 兜底不变）。

符号声明类型的陈旧性（符号类型 int、实例类型 int* 的 file2string_part_0
audit 一处错误形态变化）为 varmap 域既登记残差（命名期类型前缀，
PRINTC-UNLINKED-REF-0001 诊断⑤），不属 print 租约。

验收：curl E2E 9 对 SUB-A 双声明全消（body 全部改用符号名 iVarN/lVarN）；
语句结构零丢失（前缀归一化后逐语句 multiset 相同）；defects=0/
numbering=0 保持；audit 错误总数 15→15（1 处形态变化见上）。

### 2026-08-26：genericTypeName + 平面 cast 类型拼写（printc.cc:3373）
- 新增 `generic_type_name`（`PrintC::genericTypeName`，printc.cc:3373-3399
  逐分支）：INT→`unkint<size>`、UINT→`unkuint<size>`、UNKNOWN→
  `unkbyte<size>`、FLOAT→`unkfloat<size>`、SPACEBASE→`BADSPACEBASE`（无
  尺寸后缀）、其余→`BADTYPE`（无尺寸）。
- 新增 `cast_type_string`：cast 位点的平面类型拼写（pushType 的
  buildTypeStack 折叠，printc.cc:264/313/1472-1476）——根类型 displayName
  （匿名根走 genericTypeName）+ 每指针层一个 `*` + 每数组层 `[n]`；
  `(*)[n]` 运算符形态不发射（Rugra cast 位点只拼平面类型）。PTR_ 槽位
  符号因此能拼出 golden 的 `(undefined *)0x0` 形态。
## RPN 常量字符串解析 + comma 分隔符（MYFWRITE-TEMPVAR-0001，2026-08-26）

1. RPN 常量臂接入地址键符号/字符串表解析（对应 push_varnode Priority 0；
   位运算操作数掩码门控与主路径一致）——call 实参位置的字符串字面量
   （`fopen(...,"wb")`）经此打印。
2. call 实参分隔符由 `", "` 改 `","`（printc.cc:623-631 pushOp(&comma)，
   comma 记号 spacing 0，printc.cc:57）——`fwrite(buffer,size,nmemb,__s)`。
3. push_varnode Priority 0.5 寄存器参数名门控收紧为"本函数实际输入"
   （printlanguage.cc:218-262 pushSymbolDetail 语义）。

## cast_type_string / rpn_op_type_cast：嵌套指针粘着拼写（2026-08-27）

- `cast_type_string`（对齐 printc.cc:279-286 pushTypeStart + cc:292-302）
  修饰链在**一个** type_expr_space（printc.cc:73 spacing=1）后发射——基名
  与首个修饰符间单一空格——随后每层 ptr_expr `*`（printc.cc:75
  unary_prefix spacing=0）或 array_expr `[n]`（printc.cc:78 postsurround
  spacing=1）。连续指针层粘着：Pointer(Pointer(char)) 打 `char **`，
  Pointer³ 打 `ushort ***`；旧逐层 `" *"` 产出非 oracle 的 `char * *`。
  buildTypeStack 的 named-layer 早断（printc.cc:150）不镜像：Rugra 解析的
  嵌套指针携带显示名而 oracle 语料类型为匿名工厂指针，named 层截断会
  重新引入 `char * *`。
- `rpn_op_type_cast` 的 pushType（printc.cc:2013）同样走结构化折叠：旧
  `dt.get_name()` 直读外层原始名（make_ptr 造的 pointer-to-pointer 外层名
  就是 `char * *`），在 `*(char * *)stream` 泄漏处 oracle 打
  `*(char **)stream`；现改走 cast_type_string 同一折叠。

### 2026-08-26：GOTO-LABEL-UNPRINTED-0001 — goto 标号四症状族

**症状族**（httpd 首暴露）：① goto 目标 `code_r0x...:` 标号未打印
（undefined-label gcc 错误）；② `goto code_r0x0` 零地址；③
`if (( = ...)` 畸形 CBRANCH 链；④ goto 超发（goto_prints 恒 true）。

- `emit_any_label_statement` 重写为 cc:3219-3226 faithful 形式：
  only_branch 早退（cc:3201）→ 前叶下降（cc:3223，block.rs
  front_leaf）→ f_unstructured_targ + Basic|Copy 门（cc:3207-3208
  isUnstructuredTarget/t_copy）→ tagLine(0)+emitLabel+COLON（cc:3211-
  3213）。Rugra 侧传输层差异（均注释记录）：printed_labels 地址键
  once-guard 是 f_label_bumpup（block.hh:99）的传输——Rugra 结构树共享
  Basic 叶（Ghidra 复制 BlockCopy 子树），带标叶可从多个构造入口到达，
  必须恰好打印一次；discovery_pass / main_emit_id 门排除 NullEmit 发现
  pass 与捕获缓冲（标号打印进丢弃缓冲会既消失又占用 once-guard）。
  addr==0 防御跳过（GOTO-ZERO-TARGET-UPSTREAM-0001）。
- `emit_block_ops` 顶部调用 emit_any_label_statement：Ghidra 在每个
  构造入口（emitBlockCopy cc:2762、emitBlockList/If/WhileDo/DoWhile
  cc:2965/3014/3076/3104）对其子树调用；Rugra 构造发射器直接经
  emit_block_ops 发射 Basic 体/条件，前叶检查在同一入口执行。
- `emit_goto_statement`（cc:2303-2323）：零地址与非 block-start 目标
  防御跳过（GOTO-ZERO/UNIQSPACE/NEVEREMITTED-TARGET-UPSTREAM-0001，
  oracle 的 emitGotoStatement 总是收到活 FlowBlock，此形态无 oracle 对
  应物；上游登记在 TODO_BOARD）；GOTO 臂后接 pending_goto_labels 账本
  ——目标块稍后发射时 backpatch 标号（oracle 位置：带标叶自身），
  discovery_block_starts 不含的目标（结构器丢块，上游域）在 goto 点
  锚定（落入 fall-through，合法 C）。
- 平面 goto 尾（op_branch / op_cbranch / op_cbranch_rpn 的
  cc:575-578 折叠）：`flat_goto_target_valid` 白名单门——in(0) offset
  必须非零且属于 code_block_starts（doc_function 2a.5 收集
  fd.bblocks+结构图全部块 start；unique-space 改写 0x10000008/
  0x1000011F 等与 0x0 退化链永不是块 start，而真代码 offset 一定是）；
  拒绝则整段 goto 文本不打印，语句级 `;` 收尾 `if (cond);`（合法 C）。
  空间不过滤：结构器可把 in(0) 改写进 unique space 而保留真代码 offset
  （httpd ap_fini_vhost_config 观察 0x2D53A）。
- `cbranch_goto_info` 移除 Const/Ram 空间过滤（同上：offset-vs-
  block-start 是精确判据）。
- PTRADD/PIECE RPN push 臂补齐（printc.cc:880-893 opPtradd：
  printval→subscript 否则 binary_plus，in(1) 先 in(0) 后；printc.hh:333
  opPiece→opFunc，CONCAT<sz0><sz1> 函数式）——此前缺失使 stage-2 token
  悬空不平衡（`if (( = ...)` 畸形链的一环）。

**发现 pass 预种子（续）**：目标块在 goto 语句**之前**发射时 backpatch
已错过——`pending_goto_labels` 必须**先于** pass 2 预填。

- 2a.5 账本（code_block_starts/goto_targets/三个 clear）**上移到 pass 1
  之前**：白名单是结构图静态属性，发现 pass 的 goto 决策
  （flat_goto_target_valid / emit_goto_statement）同样要查；空表会使
  pass 1 抑制所有 op 级 goto、无法预填 pending_goto_labels（观察：
  code_r0x0002E679 ap_getparents、code_r0x0002DB30 ap_update_vhost_
  given_ip——goto 从平面尾打印时目标块的唯一发射已过，标号悬空）。
  pending_goto_labels 在此处 clear 后**不在 pass 2 前重清**（种子存活）。
- `discovery_emit_id`：发现 pass 主发射器（NullEmit）的身份。pass 1 的
  `record_goto_label_pending` 只认 main_emit_id / discovery_emit_id 两个
  身份——丢弃上下文（CaseDetectEmit 干跑、捕获缓冲）在**任一** pass 都
  不记录，保持两 pass 的 goto 集合相等；discovery_block_starts 的插入
  同样仅限 NullEmit 主发射器（只进丢弃缓冲的块不算主输出发射，误计会
  错误抑制 never-emitted 锚）。
- `emit_any_label_statement` 新增 Basic|Copy 挂起臂：叶未带
  f_unstructured_targ（Rugra 结构器留下未包裹的 goto 边，oracle 中
  ruleBlockGoto blockaction.cc:1450 总会包裹）但 pending_goto_labels
  含其地址（pass 2 中**稍后**才打印的 goto 亦可——两 pass 决策相同）。
  这是 oracle 顺序无关性的地址键传输：标号在本块发射点打印，与 goto
  文本在前在后无关。addr==0 防御保持。
- 平面尾标号扫描（emit_block_ops 两处）新增 `needs_anchor`：目标在
  pending_goto_labels 且不在 discovery_block_starts——无块会携带其标号，
  在本块语句后锚定（与 emit_goto_statement 的 never-emitted 锚同位，
  合法 C：跳转落到 fall-through 语句）。已发射目标仍排除（其标号归
  目标块自身）。

## 2026-08-29:组合名指针的声明 join 恢复 golden 形态(DECL-SPACING-NAMEFLOW-0001)

集成 w-anondecl3 匿名声明渲染后 E2E 出现 `char * pcVar4` 形(golden 为 glued `char *pcVar1`)。
根因分层:Ghidra `TypePointer(s,pt,ws)` 构造名为空(type.hh:412),生产指针皆匿名 →
buildTypeStack 钻取为多层栈 → ptr_expr(spacing=0)与标识符 glue;Rugra 的 debugproto 导入器
两处本地 helper(src/debugproto.rs:696 深度循环/:1337 pointer_type)组合名 "char *" 绕过工厂
直建命名指针 → 单层栈走了 type_expr_space。修复(printc.rs):`decl_prefix_ends_with_star`
与 push_type_start_opt 单层分支对"尾随 `*` 的组合名"按 drilled 语义 glue 标识符。
效果:skeleton 2198→2114(优于集成前 2118),六函数 typeless 装声明保持 0。
残差:fixture `printc_anonymous_pointer_decl_1204` 的 named_ptr_contrast 记录(真实 oracle
直驱动命名单层指针输出 `char * x`)与本修复的组合名 glue 可能分歧——待 full runner 复核;
根治方向=让 debugproto 指针构造改走工厂匿名路径(需核对 Ghidra DWARF 类型名的 XML 流转),
登记 DECL-SPACING-NAMEFLOW-0001。

### 2026-08-29：WhileDo body 门固定为 legacy flatten 路径（BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 residual）

- 背景：`identify_internal`/序列合并不再对被消费组件置 `DEAD`（oracle
  `BlockGraph::identifyInternal` block.cc:940-963 不设任何 flag；Ghidra 全仓
  `setDead()` 仅 funcdata_block.cc:333/370 的死基本块删除），printc 的 whiledo
  body 门（emit_structured_whiledo 及 overflow 臂的 `body_is_dead`）失去判定来源。
- 语义事实：BlockWhileDo 的 body 恒为被消费组件——旧 `DEAD` 测试在打印期恒为
  true，structured 分支从未在验证基线中执行过；拍平路径（`emit_block_ops`）
  才是 2134/0/1 基线的实际行为。
- 修改：两处 `body_is_dead` 固定为 `true`（保留 structured 分支供后续切换），
  附 BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 residual 注释。
- A/B 证据（2026-08-29 w-identify3）：no-f_dead WIP + 本固定 → curl E2E 输出与
  merge-base（9dbaf51d）**逐字节相同**（2134/0/1，main 696）；若改走
  printc.cc:2994-2995 规定的结构化发射，main 残留未结构化组件以 raw goto 形态
  暴露（+404 skeleton、numbering 1→2，main 1100）——该区域与
  NONCONVERGE-GETPARAM-MATCHURL-0001 同族，属结构化既有缺口，修复后可切换回
  oracle 规定的结构化发射。
parent of 7c3df2ce (fix: composed-name pointer declarations glue identifiers to the star run)

## 2026-08-29:组合名 glue 兜底撤销(DECL-SPACING-NAMEFLOW-0001 闭环)

根治修复 e331a5c5(w-anondecl3,六处构造点匿名化:coreaction make_pointer_type/make_ptr/COPY-spacebase、
typeop propagate_to_pointer、debugproto parse_c_type/pointer_type/DWARF 数组,全部改走 3 参
getTypePointer 空名形态)落地后,渲染层 glue 兜底(7c3df2ce)不再必要——生产指针已匿名,
buildTypeStack 钻取多层栈走 ptr_expr 原生 glue;命名单层指针(仅显式具名构造)恢复 oracle 的
type_expr_space 形态(`char * x`),与 fixture named_ptr_contrast 记录重新一致。

测试 `printc::tests::test_doc_function_leaves_action_scope_unchanged` 的 pcVar1 构造改为工厂匿名
`TypePointer::new(8, char, 1)`(生产形态,匹配 e331a5c5 匿名化),断言的 glued 输出不变。

### 2026-08-30：MAIN-RC3-STRUCTURED-EMIT-0001 — WhileDo/For body 门翻转为 oracle 结构化发射

- **翻转**:2026-08-29 固定的两处 `body_is_dead = true`(emit_structured_whiledo
  的 body 门,含 overflow 臂;emit_for_loop 的 body 门)按 oracle 条件评估——
  printc.cc:3061-3062 / 2994-2995 规定 `setMod(no_branch); beginBlock(getBlock(1));
  getBlock(1)->emit(this)`,**无条件结构化虚派发,oracle 没有 flatten 旁臂**。
  两处改为无条件 `emit_block_structured`(seen_return 域作用域保持)。
- **触发时机**:RC2(BlockGoto wrapped,MAIN-RC2-BLOCKGOTO-WRAPPED-0001)+
  guard-lattice 落地后,2026-08-29 记录的暴露面(+404 skeleton、numbering 1→2、
  main 1100)缩小为 **+58 skeleton、numbering 0→1、main 838→926**。
- **emit_comment_block_tree 的 BlockGoto 子表修正**:Ghidra `BlockGoto :
  BlockGraph`(block.hh:547),cc:3257-3263 的非 basic 递归走 `subBlock(i)` =
  BlockGraph 列表 = identifyInternal(ret,[bl])(block.cc:1706-1708)移入的
  **wrapped 组件**;旧代码取 `goto_target`(legacy 投影,实践恒 None)——改为
  `wrapped`。goto TARGET 不参与子块遍历。
- **E2E 差分(curl 12.0.4 golden)**:defects=0 保持;numbering 0→1(main 的
  `iVar4 declared twice`,见下残差);skeleton 3104→3162。逐函数:
  main +88、file2string.part.0 −16、parseconfig.constprop.0 −14、my_get_token −2、
  next_url +2。main 的 URL-glob 区现在与 golden 1:1 结构形态(含 golden 自身的
  `goto LAB_0010282a` 反向边、`LAB_00102873:` 标签、if/else 嵌套链、for 循环);
  next_url +2 = golden 的 `if (glob->size <= (int)uVar8) goto LAB_001050e7;`
  循环守卫首次发射(Rugra 以 `==0 || <` 规范两行形态)。httpd:baseline 与翻转
  **逐字节相同**(2178/4/0,4 defects 均为 master 既有)。
- **残差登记**(不回退,新 TODO):
  - `PRINTC-STRUCTEMIT-MAIN-IVAR4-DUP-0001`:main 结构化暴露区内 mid-block
    `int iVar4;` 二次声明(numbering +1),伴随 `fopen(...); if (...)` 同行
    (缺 tagLine 断行)——声明发射/行断点在结构化路径的缺口。
  - main 的 for 头部畸形(`for (var_8; iVar11 != 0; ...)`,golden 为
    `for (lVar13 = 0x26; lVar13 != 0; lVar13 + -1)`)——varmap for-init/iterate
    数据侧残差,先前被 flatten 汤掩盖。

### 2026-08-30:GLOBWORD-C3 — carry 族 opFunc 打印(printc.rs)

- **根因**(w-x86carry 双侧证明,docs/alignment_docs/CARRY-PRINT-ROOTCAUSE-2026-08-30.md):
  SLEIGH 提升的 INT_CARRY 完整存活到最终 IR(输出 implied),但 printc 无
  CARRY/SCARRY/SBORROW 分支——RPN 侧 `rpn_def_inline_reachable` 无臂(不可内联,
  叶 atom 走未命名位置)、`dispatch_op_rpn` 无臂、legacy 侧 `emit_inline_expr`
  落 `_ =>` fallback,CF(:register:200)打成 `register0x00000200`(curl 5 处)。
- **修复**(5 处,全在 printc.rs):
  1. `dispatch_op_rpn` 新臂 → `rpn_op_func`(opFunc printc.cc:424-442 的既有
     RPN 端口);
  2. `rpn_def_inline_reachable` 同族 → `has(0)&&has(1)`;
  3. 新 `rpn_operator_name_carry`:`CARRY/SCARRY/SBORROW + dec(in0 size)`
     (typeop.cc:1340/1356/1372 getOperatorName 移植,产出 CARRY1/SCARRY4/SBORROW2,
     大写非 pcode 名);
  4. `emit_inline_expr` legacy 臂:函数式语法,逗号 token spacing=0
     (printc.cc:54,`,` 无空格);
  5. 语句级 `op_func`:carry 族名 + 逗号改 `,`(原 `", "` 偏离 spacing=0)。
- **E2E 判据**:泄漏 `register0x00000200` 5→0;`CARRY1(` ×3;skeleton
  3162→3164(+2 = file2string.part.0/my_get_line 各 +1);defects=0;numbering
  不变。+2 行为规格 §3.3 预告的 cast 链残差现形(原泄漏行位置):
  参数 `(int *)uVar6` vs oracle `(byte)uVar7`(heritage piece-split 域)、
  外包 `(0 - (int *)(bool)(long)CARRY1(...))` vs `-(ulong)CARRY1(...)`
  (cast 链域)。typeop.rs functional_binary_op push 路由 opFunc(规格 §3.2)
  与上述两域均在 printc 租约外,登记残差待相应 owner。
