# 批4 函数级对齐审计报告（2026-07-02）— 代码生成/打印层

> 纯只读并发审计。9 个 Agent。判档：✅ALIGN / ⚠️DIFF / ❌MISSING / ➕EXTRA。
> **本批驱动 curl 输出质量——大多 L3 声明不实，printc/prettyprint/printlanguage 尤甚。**

## 批4 跨文件头号根因（续编 R50+）

| # | 根因 | 文件:行 | 直接症状 | Ghidra 对照 |
|---|---|---|---|---|
| R50 | **printc `op_cbranch` 吞 None in1 → `if () goto ;`** | printc.rs:4192/4200/4207/4218 | 6 个语法错（2× if()goto + 4× if()） | printc.cc:536-580 从不静默丢 |
| R51 | **printc `op_multiequal`/`op_indirect` 发 `phi(...)`/`(indirect)`** | printc.rs:4016,4036 | 非 C 输出（Ghidra 是 no-op{}） | printc.hh:331,332 |
| R52 | **printc 无 opPtrsub/opPtradd/opSubpiece/opCast 独立 handler，全塌 op_binary** | printc.rs/typeop.rs:1817 | 无结构体字段访问、cast gap 114 vs 339 | printc.cc:929,880,843,448 |
| R53 | **printc 无 OpToken/RPN 栈，是语句式 emitter** | printc.rs 全 | 嵌套表达式无优先级括号 | printc.cc:23-77 (51 OpToken) |
| R54 | **prettyprint 无 EmitPrettyPrint/Oppen/TokenSplit** | prettyprint.rs | 无 line-breaking/最大行宽/group commit | prettyprint.cc:541-1243 |
| R55 | **prettyprint 无 parenlevel/indentstack/spaces()** | prettyprint.rs | paren 深度不可见，`open_paren` 丢 (paren,id) 契约 | prettyprint.hh:100,371 |
| R56 | **printlanguage 仅 ~20% 表面，无 pushOp/pushVn/recurse/OpToken** | printlanguage.rs | 抽象 emit API 无 RPN 引擎 | printlanguage.cc:129-540 |
| R57 | **typeop opflags/addlflags 混淆**（get_flags 返 addlflags 非 opflags）| typeop.rs | op_set_opcode 拿不到正确 flag → CSE 静默失效 | typeop.hh:72 |
| R58 | **TypeOpCast 缺 + 无 op_set_opcode 用 TypeOpManager** | typeop.rs/funcdata.rs:515 | opcode 切换后 flag 位陈旧 | op.cc:276-285 |
| R59 | **types 无 sub_metatype，compare 用 12 metatype 非 24 submeta** | type_system/datatype.rs | type_order 对 char/enum/ptrrel/partial 错 | type.cc:23-27,212 |
| R60 | **types 3 Partial 子类全缺（PartialStruct/Union/Enum）** | type_system/datatype.rs | union 解析无处落 resolveInFlow 结果 | type.hh:569-640 |
| R61 | **types alignment/alignSize 从 size 派生非 TypeFactory 存储** | type_system/datatype.rs | struct alignment 错（field 全 1B→1 非 8 如有 double field）| type.cc:1971 |
| R62 | **grammar 整 CParse/解析器核缺，parse_type 只 lex 2 token** | grammar.rs:569 | 不能 parse 用户类型串 | grammar.cc:2585-3098 |
| R63 | **grammar `parse_to_separator` 字符类错** | grammar.rs:593 | 漏 ( [ * + : 续积 | grammar.cc:3197 |
| R64 | **expression boolean_match 在 condexe.rs 是坏副本（dead re-pairing），expression.rs 是好副本** | condexe.rs:767 dup expression.rs:338 | De Morgan 漏检；condexe 用坏的那份 | expression.cc:111-216 |
| R65 | **TermOrder::sort_terms 用 Arc::ptr 而非 Varnode::termOrder（地址+INT_MULT 剥）** | expression.rs:110 | RuleCollectTerms 项序不稳 | varnode.cc:1153-1173 |
| R66 | **comment CommentSorter 零调用，Funcdata 无 cmtsort 字段** | comment.rs/funcdata.rs | warning 进 DB 但永不 emit 出 | funcdata.hh cmtsort |
| R67 | **comment find_position 多块函数块定位错** | comment.rs:420 | 总放 block 0 | comment.cc:270 |
| R68 | **stringmanage encode/decode `<addr>` 错（space=u64 无 offset）** | stringmanage.rs | 不能 Ghidra XML 往返 | stringmanage.cc:203 |
| R69 | **stringmanage 缺 registerInternalStringData/calcInternalHash** | stringmanage.rs | 内部字符串注册无声缺 | stringmanage.cc:95,185 |

---

## 报告 1: printc.rs

**Summary**: 4828 行/~68 fn vs printc.cc ~102 方法 + 51 OpToken | 多数 ⚠️/❌

**Headline（根因从 printc 侧看）**:
1. **`if () goto ;` 空条件 bug 确认，位置锁定**。op_cbranch（rs:4187-4226）在三臂都吞 None from get_in(1)（BREAK rs:4192, CONTINUE rs:4200/4207, default rs:4218）。每臂 `if let Some(in1)=op.get_in(1){...}` 然后无条件发 `") goto"`/`") break"`。Ghidra opCbranch（cc:536-580）调 pushVn(op->getIn(1)) 然后 recurse——**从不静默丢**。**同吞 None 模式在 op_branch（rs:4240/4247）goto 目标**。这是 2× `if () goto ;` + 4× `if ()` 语法错的 printc 直接单因。
2. **`uVar_{:x}` 回退确认，但 AGENTS.md:1483 过时**。实际回退在 rs:1529（Unique）和 rs:1514（Register→`uVar{:x}` 无下划线）。触发当 varnode 无 HighVariable 名/无 param_names/无 symbol_table 命中。根因上游（varmap 从不建 HighVariable），但 printc 加剧：**三**个分离 uVar 生成器（rs:1498,1514,1529,4361,4463,2346）无单 chokepoint。
3. **`uVar_uVar_` 嵌套畸形名 bug 在 printc**。mark_variable_used/compact_name_for 组名，第二遍重加前缀（maybe_apply_type_prefix on rs:1504/4365 加到已 uVar 前缀的名）。
4. **cast gap（114 vs 339）printc 侧也有**。Rugra PcodeOp::push（typeop.rs:1796）把 ~40 p-code op 塌成 11 handler——PTRSUB/PTRADD/CAST/SUBPIECE/SEGMENTOP/PIECE/CPOOLREF/NEW/INSERT/EXTRACT/POPCOUNT/LZCOUNT/CALLOTHER 全落 `_=>op_binary`。op_binary（rs:3903-3966）**完全无 cast 逻辑**——只发 `out=in0 op_sym in1`。Ghidra 有专用 opCast/opPtrsub（cc:929 结构体字段）/opPtradd（cc:880）/opSubpiece（cc:843）/opIntZext/Sext（cc:786/799 cast-or-omit）——各自发精确 cast。
5. **架构模型分歧**（承重）。Ghidra 是 **RPN 栈/推表达式基**：op 推 atom+token 到栈，recurse()/emitExpression 按 precedence 驱动括号排空（51 OpToken 静态 init cc:23-77）。**Rugra 无 OpToken 表、无 RPN 栈、无 recurse()**——是**语句式 emitter**，每 op_xxx 直接写 `out=rhs` 字串到 emit。后果：无算子优先级括号（嵌套表达式错分组风险）、无栈式隐式表达式内联（Rugra 用 is_implied()+emit_inline_expr+临时 map 假冒）。

**Pipeline 接线**: printc LIVE。doc_function（rs:2774）是唯一输出阶段。两遍模型（discovery NullEmit rs:3320 + 真 emit）是 Rugra-local，是状态泄漏源（uVar_uVar_ 组合、def_map 在 discovery 期被改 rs:2461/2959）。

**关键修复**（见 R50-R53 +）:
1. P0 **op_cbranch（rs:4192/4200/4207/4218）+ op_branch（rs:4240/4247）None 处理**——发 `1`（永真）或跳语句或占位 label。永不空 `()`/`goto ;`。单修修 6 语法错
2. P1 **杀总是错的 phi/indirect 语句 emit**——op_multiequal rs:4016 + op_indirect rs:4036 改 no-op{}
3. P1 **加缺 op handler**——opPtrsub（cc:929 结构体字段）/opPtradd（cc:880）/opSubpiece（cc:843）/opCast 独立语句（cc:448）/opFunc（cc:424 carry/floatabs/sqrt）。加 typeop.rs:1796 dispatch 非 _=>op_binary
4. P2 三 uVar 回退并一 chokepoint；修 uVar_uVar_ 双前缀（maybe_apply_type_prefix 守 uVar 前缀）
5. P2 移植 opCbranch booleanFlip/negatetoken（cc:548-565）替文字 negate_condition_text（rs:1866）
6. P3 把 ~600 行分析预计算移出 doc_function（rs:2807-3299）——属上游 Action
7. P3 考虑 OpToken/RPN 栈基底——最深 gap，长期保真阻塞

---

## 报告 2: prettyprint.rs

**Summary**: **非 L3；L0-L1**。~114 fn 中 **0 映射 Ghidra pretty-print 算法**，~20 是退化 Emit API 桩，**~90 是 Rugra 自创后处理无 Ghidra 对应**。Ghidra ~79 cpp/hh 方法 ~95% 未移植。

**Headline**: prettyprint.rs **不移植** Ghidra EmitPrettyPrint。Oppen line-break 算法、TokenSplit token 流、circularqueue、indentstack、paren 跟踪层**全缺**。文件所称"prettyprint"实为 ~2200 行**文本后处理器**（EmitNoMarkup::post_process_output）螺栓在 drastically 简化 Emit trait 上（单 EmitNoMarkup 字串缓冲 impl）。

**Ghidra 三协作层**: (1) Emit 抽象基——token/markup API + indent/paren 账 + pending-print + brace-style helper；(2) EmitMarkup/EmitNoMarkup 两具体叶 emitter；(3) EmitPrettyPrint——Derek Oppen pretty-printer 包叶 emitter，缓冲 TokenSplit 在 circularqueue，分 size，advanceleft() 提交，overflow()/scan() 强断行。**Rust 只有退化叶 emitter**（EmitNoMarkup）+ 两抛 impl（NullEmit/CaseDetectEmit）。层 2（markup）+ 3（pretty-print）缺。line break 缩成 tag_line() 推字面 `\n`+indent 空格；无最大行宽强制、无 group commit、无空格/断行区分。

**证据**: grep 全 src/ 0 命中 EmitPrettyPrint/TokenSplit/circularqueue/scanqueue/advanceleft/maxlinesize/indentstack/EmitMarkup/PendPrint/parenlevel。

**Pipeline 接线错配后果**: 因 token 从不入队，Rugra 不能做 Ghidra line-break 决策（group 装下则提交否则最佳空格断）。缩进/包行因此对超隐式宽度的表达式/声明分歧。文本后处理器部分补偿（删/重写行）但不能复现 Ghidra 包-缩进行为。

**关键修复**（见 R54-R55 +）:
1. 🔴 移植 EmitPrettyPrint + Oppen 算法（或显式接受分歧降级 L3→L1）
2. 🔴 恢复 paren 跟踪 + indent 栈——加 parenlevel + indentstack/startIndent-stopIndent，修 open_paren/close_paren 匹配 (paren,id)->id 契约
3. 🔴 加 spaces(num,bump) + 真 tagLine()/tagLine(indent) 到 Emit trait
4. 🟠 移植 EmitMarkup（或承诺 no-markup）
5. 🟠 移植 brace-style helper
6. 🟡 分离：重命名/迁移后处理器出 prettyprint.rs（→output_normalize.rs）

---

## 报告 3: printlanguage.rs

**Summary**: **接口素描非 L3**。~25 trait 项 vs Ghidra ~120+ 方法/虚/3 enum/4 嵌套结构/OpToken-RPN 引擎。**表面覆盖 ~20%**。

**Headline**: 每个 doc 注释行引用**准确**（cc:671/678/653/662/113/589/498 全验）。9 个在的 opcode handler（op_copy/load/store/multiequal/indirect/call/return/cbranch/branch）+ doc_function/push_type 名+签名兼容。**坏**：(1) 核引擎缺——pushOp/pushAtom/pushVn/recurse/pushMod/popMod/setMod/resetDefaultsInternal/unicodeNeedsEscape 全无；整个 RPN 栈机制（revpol/nodepend/modstack/scopestack）走；(2) OpToken/Atom/ReversePolish/NodePending 类型系统**全缺**，及 modifiers/tagtype/namespace_strategy enum；(3) ~70/~80 opcode dispatch 虚缺；(4) op_binary/op_unary 误类——Ghidra 是受保护 generic helper 取 OpToken*（cc:546/566），非 opcode 分派条目，Rugra 当对等 opcode 且丢 OpToken 参；(5) 多个"Faithful to"doc 假——reset_defaults/clear/set_packed_output/set_flat/pop_scope/emit_line_comment 都是空{}默认体不复制所引 cc 逻辑；(6) doc_all_proto/proto: &FuncProto 和 doc_variable_decl(vn: &Varnode) 无 Ghidra 对应——Ghidra 是 docAllGlobals()(无参)/emitFunctionDeclaration(fd)/emitVarDecl(sym)/emitVarDeclStatement(sym)，名+参类型错；(7) escape_character_data 是语义重写非忠实移植——丢 count/bigend，返 String 非 (ostream,bool)，字节级 C-escape 非 Ghidra codepoint-decode+printUnicode+终止符检测；(8) PrintLanguageCapability 是空壳——缺 isdefault/thelist 静态注册/initialize/buildLanguage/getDefault/findCapability。

**关键修复**（见 R56 +）:
1. 停止叫 L3——L1（接口骨架）最多
2. 移植 OpToken/Atom/ReversePolish/NodePending 类型 + modifiers/tagtype/namespace_strategy enum
3. 移植受保护 RPN 引擎（pushOp/pushAtom/pushVn/pushVnExplicit/pushSymbolDetail/parentheses/emitOp/emitAtom/recurse）
4. 修 op_binary/op_unary 还原 OpToken* 参 + 移出 opcode 分派组
5. 删/重映射 phantom 方法（doc_all_proto/doc_variable_decl）
6. 填桩体或删"Faithful to"声明
7. 重做 escape_character_data 匹配 cc:498-511
8. 完成 PrintLanguageCapability
9. 加 12 block emitter + 公共配置 API + 9 缺受保护 push/emit 虚

---

## 报告 4: typeop.rs

**Summary**: ~67/~70 子类在（96%），**仅 TypeOpCast 缺**。但**根缺陷是 flag 混淆**。

**Headline**: **op.rs 审计问的"per-opcode flags 表"在 typeop.rs 不存在**。op.rs 声明（"Rugra 无 opcode→flags 映射表"）**部分过时但方向对**：partial、硬编码 flags 映射现活在 funcdata.rs::op_set_opcode（rs:515-549），但只覆盖 ~10 控制流 opcode，漏 ~50 算术/逻辑/比较/浮点 flag 位。关键：**这映射与 typeop.rs::TypeOpManager 完全脱节**——两者从未互通。

**根缺陷: flag 混淆**。Ghidra TypeOp 带**两分离** uint4 字段：
- opflags（getFlags 返）——**PcodeOp** flag（unary/binary/commutative/nocollapse/branch/call/booloutput/special/ternary/coderef/has_callspec/returns/marker/return_copy）。这是 PcodeOp::setOpcode 经 flags|=t_op->getFlags() 应用的（op.cc:284）。
- addlflags——**TypeOp 内部** enum（inherits_sign=1/.../floatingpoint_op=0x20；typeop.hh:41-48）。

Rugra typeop.rs **只建模 addlflags enum**（typeop_flags 值正确）但经方法**名 get_flags()** 返 addlflags 风格值。**opflags——整个 PcodeOp-flags 侧——typeop.rs 未建模**。故 TypeOp::get_flags() 对 op_set_opcode 目的返错，typeop.rs 无物供 setOpcode 所需 flag。

**后果**: (1) funcdata.rs::op_set_opcode 不得不自创硬编码 flags 表（因 typeop.rs 无用）——且**不全**；(2) Rust OPC_FLAGS_MASK 清掩码漏 14 flag 中 7（COMMUTATIVE/NOCOLLAPSE/BOOLOUTPUT/UNARY/BINARY/TERNARY/SPECIAL）——改 opcode 留陈旧位；(3) OpBehavior* 链接全桩。

**关键修复**（见 R57-R58 +）:
1. P0 **修 opflags/addlflags 混淆**——加 opflags 字段到 TypeOp 模型，每子类 get_flags() 现返 addlflags 风格。加第二字段/返 PcodeOp-flags Ghidra 构造赋（INT_ADD→BINARY|COMMUTATIVE 等，全在 typeop.cc 构造）。重命名 get_flags()→get_addlflags() + 加真 get_opflags()
2. P0 **使 op_set_opcode 咨询 TypeOpManager 非 funcdata.rs 硬编码表**——删/替 funcdata.rs:530-547 不全 match，用 manager.get_op(opc).get_opflags()。需把 TypeOpManager 接 architecture/Funcdata（现无导入）
3. P1 缺 TypeOpCast——CPUI_CAST 无类型元数据
4. P1 完成 per-opcode propagateType 覆盖（PTRADD/PTRSUB/SEGMENT/NEW/PIECE/SUBPIECE/INT_XOR/AND/OR）+ 移植 propagateAddIn2Out/propagateAddPointer
5. P2 建模 metain/metaout
6. P2 OpBehavior 桩——evaluateUnary/Binary/Ternary/recoverInputBinary/Unary 全缺

---

## 报告 5: types.rs（type_system/datatype.rs）

**Summary**: **主目标 src/type_system/datatype.rs（852 行）非旧 src/types.rs（580 行过时）**。**结构忠实但语义浅**。

**Headline**: 6 关键命名方法（get_align_size/get_sub_type/get_hole_size/type_order/getAlignment）**都在**+正确签名+琐碎输入单测过。但三结构决策使**非 Ghidra 语义 drop-in**:
1. **sub_metatype 全缺**。Ghidra Datatype::compare 按 submeta（24 变体，base2sub[] 表 type.cc:23-27）序，区分 int/int-char/uint-plain/uint-enum/uint-partialenum/ptr/ptrrel/ptr-struct。Rugra 塌成 12 值 metatype enum 比之。**故 type_order 对每个 char/enum/ptrrel 案序错**——对 RangeHint::preferred + 类型格点传播静默错。
2. **getAlignment/getAlignSize 从 size 算非存储**。Ghidra 存 alignment/alignSize 作 TypeFactory 填字段（assignFieldOffsets→struct max field alignment；getPrimitiveAlignSize base；arrayof->getAlignment() 数组）。Rugra 两都纯从 primitive_alignment(get_size()) 派生，故 field 全 1B struct 得 alignment 1 非 8 如有 8B double field。struct set_fields 路径甚至不算 alignment。
3. **resolveInFlow/union 解析入口缺**。Datatype::find_resolve 是 no-op return self（datatype.rs:412-414），无 resolveInFlow。union resolveInFlow（type.cc:2128-2135）+ findResolve（type.cc:2137-2145）是 ScoreUnionFields 调用点；unionresolve.rs 在（ScoreUnionFields 结构 445 行）但**从不被 Datatype enum 调**——run_on_func 自文档 gap。故 union 字段传播期从不解析。

**metatype enum 核查**: 值全不同（Ghidra 降序高值；Rugra 升序 0..12）。**6 变体缺**: TYPE_PTRREL/TYPE_ENUM_INT/TYPE_ENUM_UINT/TYPE_PARTIALSTRUCT/TYPE_PARTIALUNION/TYPE_PARTIALENUM（确认 unionresolve 审计）。24 值 sub_metatype 无 Rust 表征。type_class enum 未建模。

**关键修复**（见 R59-R61 +）:
1. 🔴 引入 sub_metatype（或至少 submeta:u8 字段）+ 切 compare/type_order/compare_dependency 按它序。复用 Ghidra base2sub[18] 表。**最高杠杆**——同时修 metatype + typeOrder 关键检查
2. 🔴 加 3 Partial 类型变体（PartialStruct/Union/Enum）——union 解析返回类型，无则 resolveInFlow 无处落。是子类对等 + resolve 集成关键检查的根因
3. 🔴 接 resolveInFlow+find_resolve 在 Union/Struct/Array 臂调 ScoreUnionFields。需 Funcdata::get_union_field/set_union_field 缓存
4. 🔴 存 alignment+alignSize 作 TypeFactory 填字段非从 size 派生。移植 TypeStruct::assignFieldOffsets
5. 🟠 修 TypeFactory::get_base interning 成结构（functional）非名键——加 BTreeSet<Arc<Datatype>> 按 compare_dependency 序。是 varmap 审计标的
6. 🟠 加 displayName 字段 + 缺 trivial 访问器（isASCII/isUTF16/...）
7. 🟡 对齐 TypeStruct::getHoleSize 算法到 getLowerBoundField

---

## 报告 6: grammar.rs

**Summary**: **表层/桩级**端口。只映射叶数据结构（GrammarToken/GrammerLexer token 化/TypeModifier/TypeDeclarator 容器）+ 重实 lexer 作独立状态机而非忠实 1:1 移植 Ghidra moveState/establishToken/getNextToken 三件。**整解析器核缺**: 无 CParse、无 lex()、无 runParse、无 Bison LALR action handler、无 TypeFactory/Architecture 集成。入口 parse_type/parse_to_separator **非忠实重实**（parse_type 根本不用解析器只 lex 2 token；parse_to_separator 用错字符类）。

**⚠️ 前提纠正**: Ghidra grammar.cc/.hh 是 **C 类型声明 grammar**（Bison 生 LALR 解析器 grammarparse，经 CParse 解析 C 类型串/原型/typedef）。非"规则 DSL 解析器"。Rugra 试图（松散）镜像的是 C 声明解析器。

**Pipeline 接线**: **未接任何管线**。lib.rs:69 声明但**零外部调用者**。types.rs::parse_type_string（line 556）手摇串匹配解析 C 类型串**非经 grammar 模块**。

**关键修复**（见 R62-R63 +）:
1. 🔴 parse_type（rs:569）不 parse——重写或删"faithful"声明。现 2-token lexer peek 返 Option<(String,String)>，Ghidra 返完整 Datatype*。要么移植 CParse+Bison action（巨），要么降级 doc/api/grammar.md 的 L3 声明
2. 🔴 parse_to_separator（rs:590）停条件错——Ghidra 积 isalnum||'_'；Rust 断空白/逗号/分号。修字符类成 [A-Za-z0-9_]+ 加前导空白跳
3. 🔴 lexer moveState 分歧——恢复 identifier 接 `:`、number 接 `_/A-F 外 hex`、`=`/`-` 处理、SingleQuote 反斜杠转义、set() 字符常量转义解码
4. 🔴 缺 CParse 整类（~35 方法 cc:2585-3098）
5. 🔴 缺 extern 解析器: parse_machaddr/parse_varnode/parse_op/parse_C/parse_protopieces
6. 🟡 TypeDeclarator/TypeModifier 是数据壳——加 buildType/getPrototype/getModel/isValid + 3 modType 虚
7. 🟡 GrammarLexer 模型错配（istream+buffer+filestack vs Vec<char>）
8. 🟡 纠正 roadmap/doc 矛盾（L3 vs L2.5）

---

## 报告 7: expression.rs

**Summary**: **忠实干净端口——但被 condexe.rs 的坏副本遮蔽，condexe 用坏的那份**。"De Morgan 死码"condexe 审计标的是真，但修位置错：不在 expression.rs，且正确非死版本**已在此**。

**关键结构发现**: BooleanMatch::evaluate/sameOpComplement/varnodeSame/verifyCondition **跨两文件逐字重复**（除一关键 bug）。expression.rs（lines 264-516）持**正确**副本。condexe.rs（lines 720-930）持**有 bug**副本——condexe 实际调用的那份。两副本不一致，坏的是 condexe 内用。

**condexe.rs:831-838 死码**（确认，比报告更糟）：`if p1==UNCORRELATED { match (a,d,c,b){_=>{}} return UNCORRELATED; }`——match 臂 `_=>{}` 死 + 立即 return，故 BOOL_AND/OR/XOR 输入交换重配**全跳**。`x&&y` vs `y&&x` 形树首输入配对 uncorrelated 时错返 UNCORRELATED，De Morgan complementary 分支不可达。**正确版本已存在 expression.rs:437-448**。

**TermOrder::sort_terms 用 Arc::ptr 非 Varnode::termOrder**（F2 类，RuleCollectTerms 用）——Ghidra termOrder 剥一级 INT_MULT-by-const 然后按地址比，Rust 按 Arc 指针同一性（跨跑不稳）。

**关键修复**（见 R64-R65 +）:
1. 🔴 F1 **删 condexe.rs:716-907**（varnode_same/same_op_complement/boolean_match_evaluate/boolean_match_verify_condition）+ 重导出 expression.rs 版本。常量也不同（condexe SAME=0/COMP=1/UNCORR=2 vs expression.rs SAME=1/COMP=2/UNCORR=3 匹配 Ghidra）——两副本值不兼容，必须重指 condexe 内调用到 expression::boolean_match 模块常量
2. 🟠 F2 实 varnode_term_order helper 镜像 varnode.cc:1153-1173，sort_terms 调之
3. 🟠 F3 functional_equality（address.rs）仅 level-0；ExprTerm::is_equivalent 因此弱于 Ghidra。加 functional_equality_full 包装（==0）或 address::functional_equality 调 expression::functional_equality_level
4. 🟡 F4 verifyCondition 误置 + 部分移植——若 expression.rs 选作整合家，移 verifyCondition+flip 逻辑来此作单函数
5. 🟢 F5 functionalDifference 未移植（低严重，无规则调）

---

## 报告 8: comment.rs

**Summary**: **Comment 类 + CommentDatabaseInternal L3+；CommentSorter L2；Pipeline 接线 L0**。

**Headline**: comment.rs 是 Comment 类 + CommentDatabaseInternal 忠实干净移植。**但 CommentSorter——实际 emit/排序集成（绑注释到打印输出）——是"CommentSorter Lite"**：findPosition 用手摇 op 地址搜而非 Ghidra PcodeOpTree（fd->beginOp），更重要 **CommentSorter 全代码库零调用**。Funcdata **不拥有 cmtsort 字段**。故 warning 进 DB 但无物读出 emit。roadmap "L3" 对数据结构对；emit 管线 L0（未接）。

**funcdata.rs warning_header 确认 funcdata 审计发现**: arch.commentdb 在则 add_comment_no_duplicate+早返；不在则 eprintln。**该回退是唯一让 warning 对用户可见的路径**。

**关键修复**（见 R66-R67 +）:
1. 🔴 Funcdata 须拥有 cmtsort: CommentSorter + print/emit 路径须调 setup_function_list 然后走 setup_block_list/setup_op_list/setup_header。现 CommentSorter 是死码——warning 入 DB 永不出。**未接前 eprintln 回退是承重的，勿删**
2. 🔴 CommentSorter::find_position 多块函数块定位错——回退（comm_addr>=block.start→放 order=u32::MAX）在首 start≤addr 块触发——实总 block 0。替成 Ghidra 真算法：op 树查 op、block.contains、回退前 op、backupOp、空函数→block-0、header_unplaced/false。需 Funcdata::begin_op(addr)
3. 🟠 CommentDatabaseInternal::deleteComment 缺
4. 🟠 CommentSorter 迭代模型（start/stop/opstop, hasNext/getNext, setupHeader(headerType) 作用域）走——未来 emit 端口会期望该契约
5. 🟡 Comment::encode/decode 用临时属性名 + ElementId 0 vs Ghidra ATTRIB_*+id 86/87/88——与真 Ghidra XML 不能往返
6. 🟡 encode/decode_comment_type 返 0/"" 非 throw——掩盖损坏 DB
7. 🟢 O(n) 扫描（Ghidra O(log n) 经排序 set+lower_bound）

---

## 报告 9: stringmanage.rs

**Summary**: **L2 非 L3**。纯字符解码原语（writeUtf8/readUtf16/getCodepoint/checkCharacters/hasCharTerminator/writeUnicode/assignStringData）忠实——UTF-8/16/32 解码逻辑/代理数学/截断规则逐行匹配 Ghidra。**但公共 API 表面 + 序列化分歧**:
- **2 函数全缺**: registerInternalStringData + calcInternalHash（crc32.rs 引用但 stringmanage.rs 不实现）
- **StringManager::encode/decode 产/期不同 `<addr>` 序列化**（Ghidra Address::encode 发 space+offset；Rugra 手摇 space=<u64> only）——与真 Ghidra XML 往返断
- **StringManagerUnicode::getStringData 算法简化**: Ghidra 32 字节 chunk 增量 loadFill 循环至终止符/max；Rugra 一次性 loadFill(max_chars*charsize)——不同 I/O 行为
- **StringManager::isString 仅缓存查**，Ghidra 触发解码
- **Datatype/opaque-string/endianness 管道丢**: 无 charType/isOpaqueString()/addr.isBigEndian() 集成
- **writeUtf8 静默吞无效 codepoint** 而非 throw LowlevelError

**关键修复**（见 R68-R69 +）:
1. 加 register_internal_string_data + calc_internal_hash
2. 修 encode/decode 地址处理——发/解真 Address::encode（`<addr space=... offset=.../>`）非手摇 space=<u64>
3. 重做 StringManagerUnicode::get_string_data 用 chunked 32-byte loadFill 循环 + hasCharTerminator 检查；恢复 isTrunc 出参
4. 使 is_string 触发解码；恢复 charType/isOpaqueString 管道
5. write_utf8 至少 panic/sentinel 镜像 LowlevelError

---

## 批4 总结

- 9/9 报告完成
- **代码生成层是 curl 输出质量差的直接现场**: printc 的 R50（if()goto）/R52（无 opPtrsub）/R53（无 RPN 栈）+ prettyprint 的 R54-R55（无 Oppen/paren）+ printlanguage 的 R56（~20% 表面）
- 头号根因 20 个（R50-R69）入修复清单
- **R50（op_cbranch 吞 None）+ R51（phi/indirect 发垃圾）是单点最高 ROI**——printc 一函数修
- **R53（无 OpToken/RPN 栈）+ R54（无 Oppen）是长期保真阻塞**——非阻塞当前 curl 修复但锁长期
- expression.rs 是唯一"忠实但被遮蔽"——R64 修法是删 condexe 副本非补
- comment/stringmanage 揭示**emit 路径死代码 + 序列化与 Ghidra 不兼容**两系统性问题

下一步: 批5-6 待发起（剩 ~31 文件）。
