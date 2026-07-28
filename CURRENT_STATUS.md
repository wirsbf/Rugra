# Rugra 当前状态报告

**日期**: 2026-06-28（核实更新）
**版本**: 0.1.0
**状态**: 🟡 **核心库持续开发中；大规模算法移植 + 接入生效**

## 关键指标（2026-07-02 重新核实）

| 指标 | 当前 | 核实方式 |
|---|---|---|
| 单元测试 (`cargo test --lib`) | **736/736 通过** | 2026-06-28 实跑 |
| curl gcc 审计 | **24/24 OK 0 FAIL** | `python tools/audit_syntax.py result/curl_cur.c` |
| httpd gcc 审计 | **29/29 OK 0 FAIL** | 同上 |
| curl 结构缺陷 | **17/24 函数有缺陷**（空 else / 寄存器泄漏 / 调用丢失） | `python tools/compare_ghidra.py --summary-only` |
| curl 变量编号问题 | **0 个**（checker 修复后；详见下方 2026-07-27 备注） | 同上 |
| goto | **0**（curl + httpd） | 实测 |
| uVar 碎片 | **0** | 实测 |

> ⚠️ **旧 while/if 计数 KPI 已废弃**（2026-07-02）。计数相同 ≠ 结构对齐（for↔while 等价变换），且检测不到真实缺陷。详见 `tools/compare_ghidra.py`（重写为结构骨架 diff + 编号连续性检查）和 AGENTS.md 铁律 11。

### 2026-07-27 numbering checker 修复（numbering 749 → 0）

`tools/compare_ghidra.py` 的 `check_numbering_continuity` 旧实现用 `VARDECL_RE` 扫整个函数体，把每一次变量**使用**当成**声明**计数（`return pcVar1;` / `if (bVar5)` / `bVar3 = ...` 全被计入）。这导致 fc6fd1f 引入类型前缀命名后，numbering 从 3 暴涨到 749——而其中**全部都是误报**：连 Ghidra 自己的正确黄金输出（`tests/golden/ghidra_curl.c`）也被同一 checker 报 995 个问题。

修复：改为只统计**声明行**（`^[ \t]+<C 类型>...<Var 名>(;|=)`，要求 Var 名前是真正的 C 类型关键字而非 `return`/语句关键字），并用**共享计数器不变量**替换被声明字母序干扰的 per-prefix 文本序单调性检查——直接抓 181538f 类 per-prefix 计数器 bug（max(num) << 声明总数）。修复后 Rugra 与 Ghidra 黄金输出 numbering 均为 0。详见 `tools/compare_ghidra.py` 注释。


### 2026-06-28 双重突破（历史记录，数值已被后续覆盖）

**突破 1：CFG 基本块划分修复**（commit 2bcfcde）
- 根因：`build_blocks_from_ops` 不在跳转目标地址处分裂块，导致回边丢失
- 修复：忠实移植 Ghidra 块划分（terminator + 跳转目标分裂点）
- 效果：循环回边检测恢复（旧计数显示 curl 循环数大幅提升，但该计数已不作为 KPI）

**突破 2：identify_internal RwLock 死锁修复**（commit e581dbc）
- 根因：identify_internal 持有 write guard 时对自环边的 point 调 read，write+read 同一 RwLock 死锁
- 修复：4 处 `e.point.read().unwrap()` → `try_read()`，失败跳过
- 影响：httpd 从"卡在第 8 个函数"变成"完成全部 29 函数"

**类型修复链**（commits 7a9b359/89bf0d4/1e67ae6/73f2581/3aa2fe7）：reconcile int-pointer 减法/除法 + 死循环修复 + 指针类型匹配 cast + discovery pass 不可达块遍历 → curl 审计 24/24。

## 已接入且实际生效的模块（curl/httpd 验证）

| 模块 | 效果 |
|---|---|
| **ActionConditionalExe** | 接入主管线，curl 无匹配模式正确返回 NO_CHANGE |
| **ActionPool (44 Rule)** | 接入 ActionSimplify 之后，Rule 真实触发（main 28 pass_changes） |
| **ActionRestructureVarnode** | 接入 DeadCode 后，构建 scope + sync_varnodes_with_symbols |
| **RuleOrPredicate** | 接入 ActionSimplify，扫描 INT_OR/INT_XOR |
| **LoopBody pipeline** | parseconfig 检测嵌套循环 (depths=1,0)；orderLoopBodies 全 pipeline 运行 |
| **TraceDAG + goto cascade** | 176 条 goto 候选边处理；selectGoto + emitLikelyEdges 集成 |
| **uVar 内联 (printc)** | emit_inline_expr COPY 内联，uVar 149→0 |
| **spacebase 解析** | resolve_rsp_offset_via_bank，helpf 栈符号 5→9 |
| **switch cast (long)** | switch 表达式 (long) cast 保证整数性 |

## 已实现但需 example 层接线才能触发的模块

| 模块 | 状态 | 未触发原因 |
|---|---|---|
| **ActionFuncLink** | ✅ apply 完整+接入管线 | curl_decompile.rs 不创建 FuncCallSpecs |
| **ActionActiveParam** | ✅ ProtoModel.fillinMap 驱动 | 同上 |
| **ActionActiveReturn** | ✅ output trial recovery | 同上 |
| **ActionDeindirect** | ✅ 常量目标解析 | 同上 |
| **ActionReturnRecovery** | ✅ RETURN 扫描 | 需 FuncProto active_output |

**修复方法**：在 curl_decompile.rs 的 lift 阶段为每个 CALL/CALLIND 创建 FuncCallSpecs。

## 已实现但未接入主管线的模块

| 模块 | 状态 | 未接入原因 |
|---|---|---|
| **ActionUnreachable** | ✅ apply 完整 + remove_unreachable_blocks | 接入导致回归 (curl 24→11) |
| **ActionDoNothing** | ✅ apply 完整 + splice_block_basic | 同上（staged structurer 依赖被删块） |
| **ActionRedundBranch** | ✅ apply 完整 (case1 splice + case2 remove_branch) | 同上 |
| **ActionDeterminedBranch** | ✅ apply 完整 | 同上 |

**修复方法**：需 staged→collapseInternal 架构迁移（G4 可选优化）。

## 本会话移植的核心 Ghidra 算法（按源文件）

### ✅ condexe.cc — 全部移植（L3）
- ConditionalExecution 18 方法（testIBlock/findInitPre/verifySameCondition/doReplacement/pullbackOp/execute 全部）
- RuleOrPredicate 7 方法（MultiPredicate 4 + getOpList/checkSingle/applyOp）
- BooleanMatch/BooleanExpressionMatch（expression.cc:57-232）
- 底层原语：replace_edges_thru / remove_from_flow_split / find_common_block / compare_order

### ✅ blockaction.cc — LoopBody + selectGoto（L2 核心完成）
- LoopBody 完整类（find_base/extend/find_exit/order_tails/label_exit_edges/label_containments/merge_identical_heads/emit_likely_edges）
- orderLoopBodies pipeline
- apply_loop_exit_marks（setExitMarks）
- TraceDAG isLoopDAGOut 集成
- FlowBlock 标记原语（mark/visit_count/loop_exit/goto_in/out）
- edge_flags 新增 F_LOOP_EXIT_EDGE/F_BACK_EDGE/F_IRREDUCIBLE_EDGE

### ✅ emulate.cc — execute() 主循环（L2 核心完成）
- execute_current_op（executeCurrentOp, emulate.cc:143-216 全 opcode dispatch）
- execute() 主循环
- get_value/set_value（值解析，非仅常量）
- execute_unary/binary/load/store

### 🔧 coreaction.cc — 8+ Action apply()（L2 进展）
- ActionDeindirect（常量目标解析 + COPY 链追踪）
- ActionFuncLink/FuncLinkOutOnly（funcLinkInput/funcLinkOutput）
- ActionActiveParam（ProtoModel.fillinMap 驱动）
- ActionActiveReturn（output trial recovery）
- ActionReturnRecovery（RETURN 扫描）
- ActionRestructureVarnode（sync_varnodes_with_symbols）
- ActionUnreachable/DoNothing/RedundBranch/DeterminedBranch（apply 完整，未接入）
- ActionPool Rule 调度器（44 Rule 接入主管线）

### 🔧 fspec.cc — 参数恢复完整闭环（L2 进展）
- ParamTrial（30+ 方法，fspec.hh:210-273）
- ParamActive（15+ 方法，fspec.hh:285-380）
- ProtoModel/ParamEntry（type_system/protomodel.rs）
- checkInputTrialUse（ProtoModel.possible_input_param 驱动）
- deriveInputMap（ProtoModel.fillin_input_map）
- buildInputFromTrials（参数恢复最终输出）
- FuncCallSpecs: active_input/active_output/proto_model 字段

### 🔧 subflow.cc — SubvariableFlow 完整三段式（L2 进展）
- doesOrSet/doesAndClear（mask 分析原语）
- doTrace（worklist 驱动入口）
- traceForward（~286行，全 opcode 模式匹配）
- traceBackward（~196行，定义 op 反向追踪）
- doReplacement（替换执行引擎）

### 🔧 constseq.cc — 核心算法（L2 进展）
- interfereBetween（干扰检测）
- checkInterference（序列收集）
- RuleStringCopy applyOp（字符串序列检测）

### 🔧 userop.cc — 专用子类（L2 进展）
- DatatypeUserOp/VolatileReadOp/VolatileWriteOp
- SegmentOp/JumpAssistOp/InternalStringOp

### 🔧 unify.cc — 约束系统（L2 进展）
- 16 个约束类型（OpCode/OpEqual/VarnodeEqual/OpOutput/OpInput 等）
- evaluate/evaluate_mut（只读/动作约束评估）

### 📋 dynamic.cc — DynamicHash（L1 从零创建）
- ToOpEdge + translate_opcode + DynamicHash
- calc_hash_vn/calc_hash_op（CRC 哈希计算）
- 5 个单元测试

### 🔧 printc.cc — uVar 消除 + scope声明（L2 进展）
- emit_inline_expr COPY 内联（uVar 149→0）
- switch (long) cast
- scope 符号保守声明
- used_scope_symbols RefCell

### 🔧 varmap.cc — spacebase 解析（L2 进展）
- resolve_rsp_offset_via_bank（只读 def 桥接）
- ActionRestructureVarnode 接入

### 🔧 funcdata.rs — 新增原语
- remove_unreachable_blocks / splice_block_basic
- sync_varnodes_with_symbols
- structure_reset

### 🔧 block.rs — 新增原语
- replace_edges_thru / half_delete_in/out_edge
- remove_block_arc / remove_edge_blocks / find_common_block
- FlowBlock: set_mark/clear_mark/visit_count/set_loop_exit/is_goto_in/out

## 剩余工作

### P0（影响输出质量/接入）
- curl_decompile.rs 为 CALL/CALLIND 创建 FuncCallSpecs → 解锁 FuncLink/ActiveParam/ActiveReturn/Deindirect
- staged→collapseInternal 迁移 → 解锁 Unreachable/DoNothing/RedundBranch 接入

### P1（L1 模块核心算法）
- dynamic.cc 完整 BFS 多层扩展
- constseq.cc transform（CALLOTHER 替换）
- subflow.cc RuleSubvarAnd/RuleSubvarSubpiece applyOp

### P2（简化版→完整版）
- ActionFuncLink opStackLoad pcode 注入
- ActionActiveParam AncestorRealistic/ancestorOpUse
- ActionReturnRecovery 完整 RETURN 分析

### P3（L1 模块从零）
- G7 BreakTable/EmulateFunction
- 其他 L1 模块

---

## 当前反编译质量(2026-07-02 19:29 实测 `result/curl_cur.c` + `result/httpd_cur.c`)

> 本节从 AGENTS.md 迁移而来(2026-07-05),避免数据在 AGENTS.md 里过期。AGENTS.md 是规则文档,不放易过期的数据。

### curl(`curl_cur.c`,1281 行)
- `while`=39 / `for`=0 / `if`=149 / `switch`=0 ✅(`0fc0806` 把过度 switch 化从 18 降到 0)
- `goto`=2 ❌(仍是 `if (1) goto ;` 空目标**语法错误**)
- `uVar_<hex>`=0 ✅(07-02 差距报告里的 215 已修)
- `StackX_*`=98 次(19 个去重,仍残留)
- `param_N`=74 次(5 个去重)
- `memcpy`=0 ❌
- 结构骨架 diff 详见 `docs/QUALITY_GAP_2026-07-02.md`

### httpd(`httpd_cur.c`,Jun 30,1459 行)
- `while`=58 / `for`=0 / `switch`=15 / `goto`=0
- `uVar_<hex>`=**262 次(56 个去重)❌**(质量明显比 curl 差,此前文档「0 uVar」对 httpd 错误)
- `StackX_*`=49 / `param_N`=73

### 测试
**952/952 通过**(`cargo test --lib`,2026-07-05 核实)。`cargo test` 默认含 examples,需先 `cargo build --examples`。

### 已完成的核心移植(历史日志,2026-07-02)
identifyInternal/selfIdentify, ruleBlockCat chain, ruleBlockGoto+clipExtraRoots, TraceDAG(BadEdgeScore+visit-count), structure_loops_first, Datatype get_align_size/get_sub_type/get_hole_size/type_order, varmap RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐 + printc 集成 + Stack-spacebase, Varnode flag 访问器 + get_nz_mask + lone_descend/has_no_descend + get_consume/set_consume/get_nzm/set_nzm + is_boolean_value, PcodeOp::is_calculated_bool, Funcdata op-edit API, get_booleanflip, bit helpers signbit_negative/calc_mask/leastsigbit_set/mostsigbit_set + functional_equality, expression.rs: TermOrder/AdditiveEdge/AddExpression, ActionRestructureVarnode, ~100 个 Rule struct, L1 模块骨架(14): condexe/transform/subflow/unify/constseq/opbehavior/rangeutil/userop/mem-state/float_emulate/pcodeinject/emulate/callgraph/signature, jumptable.rs L1→L2, override_rs.rs L1→L2, arch.rs L1→L2, database.rs L1→L2, findSpanningTree DFS 边分类 + F_BACK_EDGE 循环回边检测 + 回边保护, CFG 基本块划分修复(curl while 4→26).

### 2026-07-05 对齐审计(6 个并行 agent)
`docs/alignment_audit/INDEX.md` 汇总 8 个核心算法模块的 cross-review:73 MISMATCH / 68 PARTIAL / 36+ MISSING / 14 GLUE-UNJUSTIFIED / ~91 CITED-LINE-DRIFT。已修复 5 个 P0(参见 git log `10679d0`/`0c7ad89`/`8e11b3b`/`86c8e04`/`7eea43c`)。

> 注:旧 while/if 计数 KPI 已废弃(见 AGENTS.md 机制 B)。模块级算法对齐状态以 `ALIGNMENT_ROADMAP.md` 为准(其「最后核实」标注时效)。
