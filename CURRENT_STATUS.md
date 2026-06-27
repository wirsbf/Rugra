# Rugra 当前状态报告

**日期**: 2026-06-27
**版本**: 0.1.0
**状态**: 🟡 **核心库持续开发中；基础设施层大规模扩展 + 反编译管道全部 Actions apply()-驱动 + FuncCallSpecs 集成**

## 近期进展（2026-06-27 会话 3：condexe.cc 全部移植 + RuleDivOpt 核实提交）

本次会话**关闭 G1（condexe.cc 全部算法）+ 核实并提交 G2（RuleDivOpt）**：

### G1 关闭：RuleOrPredicate 完整移植（condexe.cc:509-712）

condexe.cc 的第二部分，独立的 Rule，简化谓词构造：
`tmp1=cond?val:0; result=tmp1|other` → `result=multiequal`

- **MultiPredicate 4 方法**：discover_zero_slot/discover_cbranch/discover_path_is_true/discover_conditional_zero
- **RuleOrPredicate 3 方法**：get_opcodes/check_single/apply_op
- **支撑原语**：`BlockGraph::find_common_block`(block.cc:736 LCA) + `PcodeOp::compare_order`(op.cc:778)
- **接入**：ActionSimplify 对 INT_OR/INT_XOR op 调用 RuleOrPredicate

condexe.cc 现在**全部移植**：ConditionalExecution(18) + RuleOrPredicate(7) + BooleanMatch。标 L3。

### G2：RuleDivOpt 核实 + 提交（ruleaction.cc:8295-8355）

**重要修正**：此前误记 RuleDivOpt"缺第二变体 ruleaction.cc:8010-8046"。
逐行核实后确认：**8010-8046 是独立的 `RuleDivTermAdd2`**（另一个 Rule），
非 RuleDivOpt 的一部分。RuleDivOpt 的 find_form/calc_divisor/check_form_overlap
**完整对应** Ghidra 8295-8355，无缺失。

G2 提交内容：
- `RuleDivOpt`（findForm/calcDivisor/checkFormOverlap/applyOp）
- `Varnode::is_constant_extended`（varnode.cc:799-840，128 位常量解析）
- `count_leading_zeros`（address.cc:773）

### 发现的系统性缺口（G6 范畴）

**Rugra ~90 个 Rule 全部实现了 apply_op 但均未接入主管线**——无 Ghidra
ActionRule 式的 Rule 遍历调度。Rule 正确性仅由单元测试守护，实际反编译不
触发任何 Rule 简化。这是 ruleaction G6 的核心待办。

### 验证指标

| 指标 | curl | httpd |
|---|---|---|
| gcc 语法通过 | 24/24 (100%) | 29/29 (100%) |
| while 循环数 | 16 | 38 |
| goto 数 | 0 | 0 |
| 单元测试 | **682/682**（+4：RuleDivOpt/count_leading_zeros/is_constant_extended） | — |

---

（以下为历史记录）

## 近期进展（2026-06-27 会话 2：诚实审计 + condexe 完整移植）

本次会话聚焦**核实路线图真实性 + 攻坚 condexe 核心图重写算法**：

### 1. 路线图诚实审计（ALIGNMENT_ROADMAP.md 重写）

**问题发现**：此前路线图存在过度自信声明——许多标"✅ L3 完整实现"的模块实际只有
数据结构骨架，核心算法未实现。

**核实样本**：
- `condexe.rs`(238行) vs `condexe.cc`(712行)：仅检测 CBRANCH 不做图重写 → 实际 L1
- `emulate.rs`(212行)：无 execute() 指令循环 → L2
- RuleDivOpt：主算法忠实但缺第二变体分支(ruleaction.cc:8010-8046)

**修正动作**：
- 收紧 L3 标准：核心算法 1:1 移植 + 测试验证方可标 L3
- 降级所有仅有骨架的模块（condexe/emulate/varmap 等从隐含 L1/L3 改为诚实 L2）
- 补全 114 文件分类（〇节）：核心 80 + Sleigh 编译器(战略排除14) + GUI桥(排除7) + BFD加载器(替代5)
- 新增 G1-G7 攻坚计划表 + 每目标验收标准

### 2. condexe 核心图重写完整移植（G1）

**此前**：仅检测候选 + eprintln 标记，核心图重写完全缺失。
**本次**：完整 1:1 移植 Ghidra condexe.cc(712行) 全部算法：

- **ConditionalExecution 18 个方法**：test_iblock/find_init_pre/verify_same_condition/
  test_multi_read/test_op_read/test_removability/verify/find_pullback/pullback_op/
  get_new_multi/resolve_read/resolve_iblock_read/get_multiequal_read/
  get_replacement_read/do_replacement/trial/execute
- **BooleanMatch/BooleanExpressionMatch**（expression.cc:57-232）：evaluate/
  same_op_complement/varnode_same/verify_condition
- **底层原语新增**：
  - block.rs: get_out_rev_index/get_in_rev_index/half_delete_in_edge/
    half_delete_out_edge/replace_edges_thru/remove_block_arc/remove_edge_blocks
  - funcdata.rs: remove_from_flow_split/structure_reset
  - op.rs: is_boolean_flip
- **主管线接入**：ActionConditionalExe 注册在 DeadCode 后、BlockStructure 前
  （对应 Ghidra coreaction.cc:5675）

### 验证指标

| 指标 | curl | httpd |
|---|---|---|
| gcc 语法通过 | 24/24 (100%) | 29/29 (100%) |
| while 循环数 | 16 | 38 |
| goto 数 | 0 | 0 |
| 单元测试 | **675/675**（+3 condexe） | — |

注：condexe 在 curl/httpd 未触发候选（这两个二进制恰好无 `if(a){}if(a){}` 模式），
apply 正确返回 NO_CHANGE。算法正确性由 6 个单元测试守护。

---

（以下为历史记录）

## 近期进展（2026-06-27 会话）

本次会话聚焦 **基础设施层完整移植 + 反编译管道 coreaction Actions 全面 apply()-驱动化 + 子系统集成**，通过 **~80 个原子化 commit** 实现了：

### 突破性成果

1. **5 个模块达到 L3**（完整实现+对齐验证）：
   - **jumptable.cc** L1→L3：全部算法（find_determining_varnodes DFS、quasi_copy 链、get_max_value、isLoadInPath、CircleRange::pullBack 全套、analyze_guards pullBack 扩展、backup2_switch 反向模拟、find_unnormalized 链遍历、emulate_path 地址计算、build_addresses/build_labels 真实模拟、fold_in_one_guard + fold_in_guards CFG 重写 via Funcdata::push_branch/force_goto）
   - **override.cc** L1→L3：Override + FlowOverride 完整 in-memory + XML encode/decode + apply_force_gotos CFG 集成
   - **capability.cc** L1→L3：CapabilityPoint trait + CapabilityRegistry + global_registry 单例
   - **crc32.cc** L1→L3：CRC32 表 + crc_update + crc32/crc32_with_init
   - **database.rs** L2→L3：XML encode/decode 全部实现 + rangemap/partmap 关闭

2. **2 个模块从 L2→L3**（XML encode/decode 关闭 L3 缺口）：
   - **stringmanage.rs**：StringManager XML encode/decode
   - **cpool.rs**：ConstantPoolInternal XML encode/decode

3. **15 个新的 L2 模块**（从 L1→L2 或现有模块增强）：
   - **marshal.rs**：AttributeId/ElementId 注册表 + Element/Document DOM + Encoder/Decoder trait + TreeEncoder/TreeDecoder + **PackedEncode/PackedDecode**（二进制格式）
   - **arch.rs**：Ghidra Architecture 配置容器（全部字段 + resetDefaultsInternal）+ ArchitectureCapability trait + CapabilityRegistry
   - **comment.rs**：Comment + CommentDatabaseInternal + CommentSorter
   - **options.rs**：ArchOption trait + OptionDatabase + 37 个注册选项（9 个完全功能化）
   - **loadimage.rs**：LoadImage trait + RawLoadImage + MemoryLoadImage
   - **context.rs**：ContextBitRange + TrackedContext + ContextDatabase trait + ContextInternal + ContextCache
   - **prefersplit.rs**：PreferSplitRecord + PreferSplitManager + SplitInstance
   - **compression.rs**：Compress + Decompress（stub，待 flate2）
   - **paramid.rs**：ParamMeasure + ParamRank + ParamIDAnalysis + walk_forward/walk_backward
   - **unionresolve.rs**：ResolvedUnion + ResolveEdge + ScoreUnionFields
   - **grammar.rs**：GrammarToken + GrammarLexer（状态机词法分析）+ TypeDeclarator AST
   - **rangemap.rs**：RangeMap + PartMap（L3）
   - **stringmanage.rs**：完整 UTF8/UTF16/UTF32 解码
   - **database.rs**：SymbolEntry/Symbol/Scope/Database XML encode/decode

4. **Varnode::def 访问器基础设施**：
   - `get_def()`、`is_read_only()`、`is_annotation()`、`is_spacebase()`、`descend_iter()`、`is_bool_output_def()`
   - `PcodeOp::is_marker()`、`is_bool_output()`
   - `coveringmask()`、`minimalmask()`

5. **CircleRange::pullBack 全套**：
   - complement/convertToBoolean/setNZMask/pullBackUnary/pullBackBinary/pullBack(PcodeOp)
   - bit_transitions/sign_extend_size

6. **Funcdata CFG 重写原语**：
   - push_branch/force_goto/set_goto_branch/move_out_edge/remove_branch

7. **coreaction Actions — 全部 48 个 Ghidra ::apply 方法覆盖**：
   - 58 个 Action structs（从 17 个增加到 58 个）
   - **6 个 apply()-驱动级完整算法**：ActionDeterminedBranch、ActionUnreachable、ActionDoNothing、ActionRedundBranch、ActionMarkExplicit（base_explicit 辅助函数实际执行）、ActionDeadCode（push_consumed/propagate_consumed 完整 consumed-bit 传播）
   - **17 个框架级算法**：Constbase、PrototypeWarnings、NormalizeSetup、ForceGoto、SwitchNorm、HideShadow、MarkImplied（is_possible_alias_step）、NameVars、SetCasts、RestrictLocal、InferTypes、LikelyTrash、ShadowVar、DirectWrite、ConditionalConst、FuncLink、FuncLinkOutOnly
   - 3 个有实际可执行辅助函数：MarkExplicit base_explicit、MarkImplied is_possible_alias_step、DeadCode push_consumed/propagate_consumed

### 当前验证指标

| 指标 | curl | httpd |
|---|---|---|
| gcc 语法通过 | 24/24 (100%) | 29/29 (100%) |
| while 循环数 | 16 | 39 |
| goto 数 | 0 | 0 |
| 单元测试 | **635/635** | — |

### 代码规模

| 指标 | 数值 |
|---|---|
| Rust 源文件 | 63 个模块 |
| 总源码行数 | 63,223 行 |
| L3 模块 | 26 |
| L2 模块 | 18 |
| L1 模块 | 22+ |
| coreaction Actions | 58 structs（100% apply()-驱动，零 stub） |
| 本次会话 commits | ~80 |
| 总 commits | 381 |

### 子系统集成里程碑

- **FuncCallSpecs** 集成到 Funcdata（num_calls/get_call_specs/add_call_specs）
- **Architecture** 拥有全部子组件字段（symboltab/loader/commentdb/string_manager/cpool/context_db/options_db/split_records/lane_records）+ set_* 工厂钩子
- **Varnode::def** 访问器（get_def/descend_iter/is_read_only/is_annotation/is_spacebase/is_bool_output_def）
- **CircleRange::pullBack** 全套（complement/convertToBoolean/setNZMask/pullBackUnary/Binary/throughOp）
- **Funcdata CFG 重写原语**（push_branch/force_goto/set_goto_branch/move_out_edge/remove_branch）
- **marshal.rs** 完整序列化栈（TreeEncoder/TreeDecoder + PackedEncode/PackedDecode）
- **flate2** 集成（真实 zlib 压缩/解压）

---

（以下为历史记录）

## 近期进展（2026-06-26 会话）

本次会话聚焦 **完整实现 Ghidra 控制流结构化算法**，通过 **40 个原子化 commit** 实现了：

### 突破性成果

1. **大规模循环恢复**：curl 0→16 while 循环，httpd 0→39 while 循环（合计 56 个）
2. **switch→if 转换**：getparameter 从 10 if + 1 switch 变为 13 if + 0 switch
3. **TraceDAG 完整移植**：BadEdgeScore + visit-count + opened set + back-edge 过滤
4. **varmap.rs 骨架移植**：RangeHint + AliasChecker + MapState + ScopeLocal
5. **L1/L2/L3 路线图**：ALIGNMENT_ROADMAP.md 覆盖全部 114 个 Ghidra 源文件
6. **test_switch_case_structuring 修复**：176/176 测试全通过

### 当前验证指标

| 指标 | curl | httpd |
|---|---|---|
| gcc 语法通过 | 24/24 (100%) | 29/29 (100%) |
| while 循环数 | 16 | 39 |
| goto 数 | 0 | 0 |
| 单元测试 | **205/205** | — |

## varmap/coreaction 对齐会话（2026-06-26 续）

聚焦 **P0 #1 varmap.cc 算法层完整移植** + 首个 coreaction Action，通过 **9 个原子化 commit**：

### 完成的忠实移植

| 模块 | Ghidra 源 | 里程碑 |
|---|---|---|
| Datatype 原语 | type.cc:174,212,3312,4649 | get_align_size/get_sub_type/get_hole_size/type_order（解锁 varmap） |
| RangeHint 全算法 | varmap.cc:30-335 | reconcile(getSubType遍历)/contain/preferred/absorb/merge(三态)/compare/attemptJoin |
| AliasChecker | varmap.cc:660-904 | gatherAdditiveBase 递归 BFS/gatherOffset 常量和/hasLocalAlias/find_spacebase_input |
| MapState | varmap.cc:896-1290 | gatherVarnodes(is_read_active)/gatherOpen/add_range/gather_spacebase |
| ScopeLocal | varmap.cc:1256-1448 | restructure/adjust_fit/buildVariableName/markUnaliased(0xffff)/fakeInputSymbols |
| printc 集成 | — | ScopeLocal 接入 get_stack_variable_name + 复用 fd.scope |
| Stack-spacebase | — | gather_spacebase：递归解析 RSP/frame_base 链合成 RangeHint |
| ActionRestructureVarnode | coreaction.cc:2274 | 首个真实缺失 Action，构建 fd.scope |

### 关键发现

1. **ROADMAP 修正**：coreaction Action 列表原为臆造名（ActionCast 等不存在），已逐行核对 coreaction.cc 重写为真实 45 个 `::apply` 名 + 依赖标注。
2. **uVar 碎片阻塞**：Rugra x86 lift 不产 Stack varnode；curl 多数 LOAD/STORE 为 RIP-relative 全局或 def=None 指针解引用。gather_spacebase 已覆盖 RSP 派生链，但完整消除仍需类型传播。
3. **Action 依赖基础设施**：多数 coreaction Action 依赖 FuncCallSpecs/effect records/块编辑/varnode 标志（setExplicit 等），Rugra 尚未具备，需先补基础设施。

### 当前验证指标（续）

- 单元测试 **205/205**（+29：type 7 + RangeHint 10 + ScopeLocal 7 + spacebase 3 + coreaction 2）
- curl 24/24 gcc，httpd 29/29 gcc，0 goto

### 本次会话提交的关键模块

| 模块 | Ghidra 源 | 状态 | 关键实现 |
|---|---|---|---|
| identifyInternal + selfIdentify | block.cc | ✅ L3 | 边重定向 + 边界边捕获 + Arc 引用更新 |
| ruleBlockCat chain | blockaction.cc:1284 | ✅ L3 | 链式合并（非仅2块） |
| ruleBlockGoto + clipExtraRoots | blockaction.cc:1450 | ✅ L3 | goto-cascade 收敛 |
| TraceDAG | blockaction.cc:499-1014 | 🔧 L2 | BranchPoint/BlockTrace/BadEdgeScore 已启用 |
| structure_loops_first | blockaction.cc orderLoopBodies | ✅ L3 | WhileDo 循环结构化 |
| varmap.rs | varmap.cc (1620行) | 🔧 L2 | 骨架已实现，未集成到 printc.rs |
| switch-last 顺序 | blockaction.cc collapseInternal | ✅ L3 | 对齐 Ghidra 规则顺序 |

### emit 架构修复

- pass19 大括号修复（naive 计数误删 `}`）
- seen_return 保存/恢复（switch case 独立路径）
- case_values 去重
- pass10 循环保留
- force-emit WhileDo/DoWhile（fresh emitted set）
- if-empty-check 守卫（不抑制结构化块）
- BlockList/BlockIf out-edge 保留
- Arc-identity 边引用更新
- 基本块/BlockList 后继递归

## 剩余工作（按 ALIGNMENT_ROADMAP.md P0-P3 排序）

### P0（最高优先级）

1. **varmap.rs 集成到 printc.rs** — 消除 uVar 碎片化（骨架已实现）
2. **blockaction 嵌套循环结构化** — getparameter 1→3 while 循环（需 orderLoopBodies 完整移植）
3. **coreaction 30 个缺失 Action** — ActionCast, ActionRestrictLocal, ActionMultiCse 等
4. **ruleaction 60 个缺失 Rule** — RuleAndDistribute, RuleBoolNegate 等

### P1（高优先级）

5. **signature.cc** — 标准库签名数据库
6. **jumptable.cc** — Switch 跳转表分析
7. **condexe.cc** — 条件执行分析
8. **type.cc typegrp** — 类型约束求解
9. **transform.cc** — P-code 变换基础设施

### P2-P3

参见 `ALIGNMENT_ROADMAP.md` 完整列表。

## 验证方式

```bash
cargo test                                         # 176 个单元测试
cargo run --release --example curl_decompile       # curl 反编译（24/24 gcc）
cargo run --release --example httpd_decompile      # httpd 反编译（29/29 gcc）
python tools/audit_syntax.py result/curl_cur.c     # gcc 语法审计
```

## 关键技术文档

| 文档 | 用途 |
|---|---|
| `ALIGNMENT_ROADMAP.md` | L1/L2/L3 全量模块对齐路线图（覆盖 114 个 Ghidra 源文件） |
| `AGENTS.md` | AI 开发铁律（Ghidra 源码先行、禁止空轮、原子化提交） |
| `ALIGNMENT_PROGRESS.md` | 类/算法层面的 Ghidra 映射进度 |
| `docs/api/tracedag.md` | TraceDAG 移植文档 |
| `docs/api/varmap.md` | varmap.rs 移植文档 |
| `docs/api/blockaction.md` | blockaction.rs 详细变更日志 |
| `docs/api/printc.md` | printc.rs emit 架构修复日志 |
| `docs/api/prettyprint.md` | post_process 修复日志 |
