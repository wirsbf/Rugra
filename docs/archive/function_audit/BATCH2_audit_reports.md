# 批2 函数级对齐审计报告（2026-07-02）

> 纯只读并发审计。8 个 Agent。判档：✅ALIGN / ⚠️DIFF / ❌MISSING / ➕EXTRA。
> 修复不在本轮。本表是修复阶段输入清单。

## 批2 跨文件头号根因（按 ROI 排序，续编 R15+）

| # | 根因 | 文件:行 | 直接症状 | Ghidra 对照 |
|---|---|---|---|---|
| R15 | **`collapse_cbranch_cascades` 凭空把 CBRANCH if/else-if 链转 BlockSwitch** | blockaction.rs:4014 | switch 18 vs 2（9×过 switch 的单一根因）| blockaction.cc:1649 ruleBlockSwitch 只在 isSwitchOut(BRANCHIND) 触发 |
| R16 | **block.rs edge-flag 位值全错**（F_BACK_EDGE=0x20 vs 0x80, F_LOOP_EDGE=0x400 vs 0x02...）| block.rs:60-87 | loop/goto 结构化解码错位 | block.hh:88-118 |
| R17 | **`setOutEdgeFlag`/`set_loop_exit` 不镜像到目标入边** | block.rs:142,591 | is*In 查询读陈旧 flag | block.cc:240-256 |
| R18 | **`halfDeleteInEdge/OutEdge` 修复自身 reverse_index 而非 peer 的** | block.rs:640,653 | 每次 edge 删除留悬挂 reverse index | block.cc:100-127 |
| R19 | **EmulateFunction 不读 LoadImage → 内存加载跳转表全得 0 目标** | jumptable.rs:2835 | switch 恢复在真二进制上失效 | jumptable.cc:115 executeLoad |
| R20 | **JumpBasic2/JumpBasicOverride/JumpAssisted 三个模型类全缺** | jumptable.rs | 默认守卫 switch（最常见形式）失败 | jumptable.cc:1656-2245 |
| R21 | **ActionSwitchNorm 后恢复管线全注释掉**（matchModel/recoverLabels/foldInNormalization/foldInGuards）| coreaction.rs:2282-2289 | 恢复的表从不变成 switch | coreaction.cc:4548 |
| R22 | **`calcRange` `let _ = gr.intersect(rng)` 丢弃不相交返回值** | jumptable.rs:1607 | range 永远 intersect，从不 skip | jumptable.cc:1137 |
| R23 | **SubfloatFlow 整类缺**（9 方法）| subflow.rs | 浮点精度降级失效 | subflow.cc:3079-3481 |
| R24 | **LaneDivide 整类缺 + ActionLaneDivide 空桩** | subflow.rs/coreaction.rs:5584 | SIMD lane 分裂永不跑 | subflow.cc:3518-4128 |
| R25 | **transform.rs `create_op_replacement` 丢 MULTIEQUAL→opInsertBegin 分支** | transform.rs:944 | RuleSplitFlow 经 MULTIEQUAL 插错位置 | transform.cc:243-248 |
| R26 | **transform.rs constant_iop 做成普通常量而非 new_varnode_iop** | transform.rs:423 | INDIRECT placeholder 丢 causing-op | transform.cc:213 |
| R27 | **unionresolve.rs `run_on_func` 是捏造启发式**（Ghidra 没有）| unionresolve.rs | union 字段解析给错结果 | unionresolve.cc:963 run() |
| R28 | **unionresolve.rs 三常量全错**（MAX_PASSES 5 vs 6, THRESHOLD 10 vs 256, MAX_TRIALS 50 vs 1024）| unionresolve.rs | 评分过早中止 | unionresolve.cc:79-81 |
| R29 | **unionresolve.rs ResolveEdge Ord 字段顺序错 + 编码常量错**（0x10000 vs 0x1000）| unionresolve.rs | map 排序变 → 非确定性解析 | unionresolve.cc:72 |
| R30 | **condexe `boolean_match_evaluate` 交换操作数重配是死代码** | condexe.rs:832 | De Morgan 互补式漏检 | expression.cc:156-160 |
| R31 | **override 所有权错**（在 Architecture 非 Funcdata）+ proto-override 存 bool | override_rs.rs/arch.rs:341 | 丧失每函数隔离 + proto 数据丢 | funcdata.hh:98 |
| R32 | **ActionNormalizeBranches/ActionFinalStructure 职责对调** | blockaction.rs:4776,4692 | goto/break 处理错乱 | blockaction.cc:2117,2186 |

---

## 报告 1: blockaction.rs（重跑成功）

**Summary**: 78 Rust fn / ~45 Ghidra（TraceDAG 另审）+ ~30 ➕EXTRA（Rugra-local 结构化）| ✅19 ⚠️9 ❌6 ➕~30

**Headline（两个根因已对 Ghidra 精确源核实）**:
1. **9× 过 switch ← `collapse_cbranch_cascades`（rs:4014）把长度≥3 的 CBRANCH if/else 链转 BlockSwitch**。Ghidra `ruleBlockSwitch`（cc:1649）只在 `isSwitchOut()` 触发，而 `f_switch_out` 由 BRANCHIND 独占设置（block.cc:2286-2287）。**Ghidra 从不把 CBRANCH 级联形成 switch**。Rugra 这么做 → 数千次比较的 if/else 链。~16/18 假 switch 出于此。
2. **`if () goto ;` 空条件 ← printc.rs:4191-4224 `op_cbranch`**：发 `if (` 然后 `if let Some(in1)=op.get_in(1){...}` 然后 `) goto`。当 CBRANCH 的 in(1) 为 None 时 `if let` 静默不发 → `if () goto ;`。blockaction 贡献是 goto 插入路径可留无 in(1) 的 CBRANCH，但**即时 bug 在 printc 吞 None**。
3. **switch 注释错归因**：blockaction.rs:4013 声称 `collapse_cbranch_cascades` "对应 Ghidra ruleBlockSwitch for CBRANCH cascades"——**假**。Ghidra 无此路径。

**Pipeline 接线**: 已接。ActionBlockStructure（rs:33）→ build_copy → CollapseStructure::new → collapse_all（rs:630）。Ghidra ActionBlockStructure::apply（cc:2169）installSwitchDefaults→buildCopy→collapseAll。**Rugra 漏 installSwitchDefaults()**。

**关键修复**:
1. 🔴 **删 `collapse_cbranch_cascades`（rs:4014-4283）及支撑代码**。这是 switch 18→2 单一根因。同时删 refresh_switch_cases 的 CBRANCH-cascade 分支（rs:2072-2114）、select_and_mark_goto 的级联守卫（rs:1456-1597）、try_rule_if_no_exit 的级联成员跳过（rs:2690-2711）。让 if/else-if 链经 try_rule_proper_if/try_rule_if_else 结构化为嵌套 BlockIf（Ghidra collapseInternal 的做法）
2. 🔴 修 `if () goto ;`：printc.rs:4191-4224 in(1)=None 时发占位或报错；blockaction try_rule_if_goto（rs:2832）保 CBRANCH 留 in(1)
3. 🟠 移植 checkSwitchSkips（cc:1607）+ installSwitchDefaults 进 collapse_switches（rs:3922）——现 default_case 永远 None
4. 🟠 修 ActionNormalizeBranches/ActionFinalStructure 职责对调（R32）：NormalizeBranches 应做 opFlipInPlace（cc:2130）非 goto→break/continue；FinalStructure 应做 orderBlocks/finalizePrinting/scopeBreak/markUnstructured（cc:2191-2195）
5. 🟡 加 ruleBlockInfLoop（cc:1579）；合并重复的 proper_if/if_else/while_do 实现
6. 🟡 删 5 秒 deadline + eprintln! 垃圾（rs:651,703,904）——掩盖非收敛 bug

**重要 Rugra-local ➕EXTRA**: LoopBody 系列（find_base/extend/find_exit/order_tails/label_exit_edges/label_containments/emit_likely_edges/merge_identical_heads）全部 ✅ALIGN Ghidra；find_spanning_tree（rs:1786）✅；compute_dominators（rs:1947）✅ 等价。**唯一结构性问题是 collapse_cbranch_cascades 这条凭空路径**。

---

## 报告 2: block.rs

**Summary**: 254 Rust（~38 distinct trait 方法 + impl + ~30 struct 方法）| Ghidra ~110（block.hh ~110 declared + block.cc ~80 out-of-line）| ✅~24 ⚠️~14 ❌~62 ➕~7

**Headline**: **L3"完全对齐"声明不实**。三大缺陷:
1. **edge-flag 位值全乱** vs Ghidra（每个常量位都不同）。命名集也错（Rugra 捏造 F_BREAK_EDGE/F_CONTINUE_EDGE/F_SWITCH_DISPATCH；缺 Ghidra 的 f_loop_edge=bit1，用 F_BREAK_EDGE=0x01 替）。因 isLoopDAGOut/structurer/LoopBody 全 AND 这些 mask，**loop/goto 结构化解码错位**。
2. **dominator 算法错**。Rust build_dom_tree/compute_dominators 用 RPO 序 Cooper-Harvey-Kennedy 变体 + 自制 intersect；Ghidra 用 post-order CHK + canonical finger1/finger2 按 `numnodes-index` 键合。Rust 按块位置 index 键合——对非假定序图已知不健全。
3. **~62/110 FlowBlock/BlockGraph 方法 MISSING**，含整个 findSpanningTree/findIrreducible/structureLoops/calcLoop/calcForwardDominator 算法套件（被搬到 blockaction.rs/tracedag.rs 改了形）+ ~45 edge-flag 访问器。

**Pipeline 接线**: blockaction 直接构造子类（非 Ghidra 的 BlockGraph::newBlockX 工厂）：BlockBasic/BlockIf/BlockWhileDo/BlockDoWhile/BlockSwitch/BlockCondition/BlockGoto/BlockGraph 已构。**BlockCopy/BlockMultiGoto/BlockInfLoop/BlockList 声明但从不构造**。structure_loops（block.rs:1237）**返回 false 桩**。

**关键修复**（见 R16-R18 +）:
1. 🔴 **edge_flags/block_flags 位值重编**（block.rs:28-93）匹配 Ghidra（block.hh:88-118）。注释甚至写对了 hex（rs:79 "f_tree_edge=0x10" 但代码 1<<7=0x80）。删 F_BREAK_EDGE/F_CONTINUE_EDGE/F_SWITCH_DISPATCH/GOTO_EDGE_0/1 捏造，用 Ghidra 的 f_break_goto/f_continue_goto block-flag + per-edge f_goto_edge 模型
2. 🔴 **tracedag.rs:280 `is_loop_dag_out` 调用逻辑反转**：helper 返回 true=可追踪边，但 open_branch 做 `if is_loop_dag_out { continue }`——跳过该追踪的边、追踪该排除的 goto/back/exit 边。改 `if !is_loop_dag_out { continue }`
3. 🔴 **setOutEdgeFlag/set_loop_exit/clear_loop_exit 镜像到目标入边**（cc:240-256）
4. 🔴 **halfDeleteInEdge/OutEdge 修 peer 的 reverse_index 非 self**（cc:100-127）
5. 🟠 **dominator 算法**：统一一个 CHK-in-post-order + virtual-root；删重复；build_dom_depth root=0→1（off-by-one）
6. 🟠 **findSpanningTree 计算 numdesc + copymap=self**（cc:1009-1136）；移植 findIrreducible（cc:1147）+ structureLoops 重建循环（cc:2194，现 false 桩）
7. 🟠 **BlockGraph impl FlowBlock**（Ghidra BlockGraph : FlowBlock）——现 standalone struct，结构化块不能统一作 FlowBlock 子，14 个 BlockGraph 虚函数全缺
8. 🟡 补 BlockMultiGoto + BlockInfLoop 子类
9. 🟡 ~45 edge/block-flag 访问器缺失（isLoopIn/Out, isDecisionIn/Out, isLoopDAGIn, isBackEdgeIn, isTreeEdgeIn, isIrreducibleIn/Out, isDefaultBranch, isLabelBumpUp, isUnstructuredTarget, isInteriorGotoTarget, hasInteriorGoto, isSwitchOut, isDonothingLoop, isJoined, isDuplicated, hasSpecialLabel, getFlipPath, isJumpTarget, hasLoopIn/Out, setGotoBranch, setDefaultSwitch, getInIndex, getOutIndex, getFrontLeaf, calcDepth, getCopyMap, setBackEdge, setDonothingLoop, setDead, negateCondition, restrictedByConditional, getExitLeaf, nextFlowAfter, subBlock, markUnstructured, markLabelBumpUp, scopeBreak, printHeader/Tree/Raw, emit, encode*/decode*, finalTransform, finalizePrinting, isComplex, preferComplement, getSplitPoint, flipInPlaceTest/Execute）

**判定**: block.rs **非 L3，实为 L1-L2**。FlowBlock/BlockBasic/BlockGraph 数据结构 + 基础 edge/dominator 脚手架在，子类类型声明了，但 flag 编码全错、核心算法桩/搬/改、62/110 方法缺、BlockGraph 非 FlowBlock、2 个关键 edge-mutation helper 损坏 reverse-index、TraceDAG edge filter 逻辑反转。L3 声明应降级。

---

## 报告 3: condexe.rs

**Summary**: ~40 Rust / 28 Ghidra | ✅25 ⚠️6 ❌0 ➕3

**Headline**: **任务前提错**。Ghidra condexe.cc/.hh **没有** CondVarData/examineQuad/examineVarnode/testStackVn/testSwitch/checkExteriorDoor/findExteriorTest/doTan/doFold/OpFollow/PathMeld。全 decompile/cpp 树 grep：这些名**无处**（PathMeld 属 jumptable.cc，OpFollow 属 userop.cc）。实际 condexe.cc 算法是 ConditionalExecution（iblock folding）+ RuleOrPredicate（predicated INT_OR/XOR）。**Rust 端口正对这两个类，忠实 1:1**。无 condexe-特定守卫缺失（那些名是虚构的）。

**Pipeline 接线**: ✅ ActionConditionalExe 接 mainloop（action.rs:850）；RuleOrPredicate 接 op-pool（action.rs:634）。**非死 L2.5**。

**关键修复**:
1. 🟠 **`boolean_match_evaluate` 交换操作数重配是死代码**（condexe.rs:832-837）：`match (a,d,c,b){_=>{}}` 后 return UNCORRELATED。漏检互补 BOOL_AND/BOOL_OR（De Morgan，操作数交换时）。移植真逻辑：`pair1=evaluate(a,d); 若仍 uncorrelated return; pair2=evaluate(c,b)`
2. 🟠 **`test_removability` 无后代 heritage 守卫结构性死**（condexe.rs:375-383）：两臂都 return true。Ghidra 无后代且 space 无 heritage 时返回 false（cc:392-393）。现被假 heritageyes(all-true) 掩盖
3. 🟠 **ActionConditionalExe::apply 漏 hasUnreachableBlocks() 守卫**（rs:1289）；迭代序分歧（每折后从块 0 重启 vs Ghidra 一遍/轮）
4. 🟡 pullbackOp 输出地址未保留（用 new_unique_out 而非 new_varnode_out 保原 addr）
5. 🟡 resolveIblockRead 吞 LowlevelError（cc:261 throw，rs:556 返回 None 静默欠折）

---

## 报告 4: subflow.rs

**Summary**: 155 Rust（含测试）| Ghidra ~108 方法（5 类 + 11 Rule）| ✅~76 ⚠~16 ❌~33 ➕~8

**⚠️ 前提纠正**：subflow = SubvariableFlow/SplitFlow/SplitDatatype/SubfloatFlow/LaneDivide（缩小/拆分携带小逻辑值的 Varnode），**非** ValueSet/LoopBody/OpCodeMotion（那些在 rangeutil.cc/loop.cc）。Rugra 注释自证。

**Headline**: **subflow.rs 不是"死 L2.5 缺 Rule 包装器"——AGENTS.md 记忆过时**。所有 11 Rule 已实现且已接管线（action.rs oppool1:624-636 + cleanup:679-688）。真差距：**SubfloatFlow 整类缺（9 方法）**、**LaneDivide 整类缺（16 方法）+ ActionLaneDivide NO_CHANGE 桩**、SplitDatatype/tryCallPull/tryCallReturnPush/tryReturnPull 保守降级禁用大部分变换。**部分活，非死**。

**Pipeline 接线核查（AGENTS.md 声明证伪）**: oppool1 注册 RuleSubvarAnd/Subpiece/RuleSplitFlow/SubvarCompZero/Shift/Zext/Sext/SubfloatConvert；cleanup 注册 RuleDumptyHumpLate/SplitCopy/SplitLoad/SplitStore。**11/11 接入**。

**关键修复**:
1. ❌ **移植 SubfloatFlow**（9 方法，subflow.cc:3079-3481）。现 RuleSubfloatConvert 只折常量+标类型，无真精度追踪。需 maxPrecisionMap/exceedsPrecision/setReplacement/precision-aware traceForward/Back/doTrace + 可用 TransformManager::apply
2. ❌ **移植 LaneDivide**（16 方法，subflow.cc:3518-4128）+ 解桩 ActionLaneDivide（coreaction.rs:5584）。coreaction.rs:7364 的 assert 甚至主动排除它。需 LaneDescription::restriction/extension/getBoundary/getPosition + 10 个 build* helper
3. ⚠️ **接 FuncCallSpecs 查找**（`fd->getCallSpecs(op)`）。tryCallPull/tryCallReturnPush 现无条件 false，禁用：call 参数修剪 + CALL/CALLIND 间接创建 push（SEXT/ZEXT push-back）。每次调用还 eprintln! 噪声
4. ⚠️ **修 get_replacement_address 大端**（subflow.rs:2192）——只算了小端
5. ⚠️ 移植 SplitDatatype 缺失机制：getValueDatatype/RootPointer::find/backUpPointer/duplicateToTemp/freePointerChain/categorizeDatatype/testCopyConstraints/isArithmeticInput/Output。RuleSplitLoad/Store 缺 getValueDatatype 预检
6. ⚠️ RuleSubvarSext::reset 孤立——非 Rule-trait hook，aggressive_ext_trim 硬 false
7. 📝 **纠正 AGENTS.md 记忆**（line 128）："subflow 缺 Rule 包装器/L2.5 未接入"为假——11 Rule 全写全接。真实状态：L2.5→部分活；差距是两缺引擎类 + FuncCallSpecs 依赖的降级，非 Rule 包装器

**SubvariableFlow 核心引擎 ~76 方法 ✅ALIGN**：doesOrSet/doesAndClear/setReplacement/createOp/createOpDown/trySwitchPull/tryInt2FloatPull/traceForward(22 op-case)/traceBackward/traceForwardSext/BackwardSext/createLink/addConstant/addNewConstant/createNewOut/addPush/addTerminalPatch*/addBooleanPatch/addExtensionPatch/addComparePatch/useSameAddress/processNextWork/doTrace/doReplacement 全 1:1。

---

## 报告 5: jumptable.rs

**Summary**: ~90 distinct Rust 方法（159 fn 含 trait 重复）/ Ghidra ~131 out-of-line + ~40 inline ≈ 171 | ✅~62 ⚠~18 ❌~48 ➕~6

**Headline**: **EmulateFunction 不忠实回放**。对直接算术 switch（switchvar→ADD/MULT/shift→BRANCHIND，test_emulate_path_int_add/copy 证明）正确，但**对主流真二进制形式——内存加载跳转表（`goto *(base+idx*size)`）——损坏**。execute_op 记 LoadTable 但从不从 LoadImage 读加载值（默认 0），get_varnode_value 对未写 varnode 返回 0 而非查 loader。**结果 switch 恢复在大多真二进制上静默产错/零目标或失败**。加剧：JumpBasic2/JumpBasicOverride/JumpAssisted **全缺**，带默认守卫路径/手动覆盖/jumpassist 伪 op 的 switch 无法恢复。ActionSwitchNorm 只跑地址恢复，**标注/规范化/守卫折叠全注释掉**（coreaction.rs:2282-2289），故即便成功恢复的表也从不变成 switch。

**Pipeline 接线**: recover_jump_tables 已接（ActionSwitchNorm::apply, coreaction.rs:2274，注册 coreaction.rs:7050）。**缺**（vs Ghidra ActionSwitchNorm cc:4548）：恢复后循环体是空桩——只数未标表。注释掉的：matchModel/recoverLabels/foldInNormalization/foldInGuards。故恢复的表无 case 标签，BRANCHIND 输入从不重写为 switch var，守卫从不折。try_recover 包 `std::panic::catch_unwind`（rs:2962）——**把模拟/守卫 bug 伪装成良性"恢复失败"**。

**关键修复**（见 R19-R22 +）:
1. **EmulateFunction 加载模拟（阻塞器）**：execute_op/get_varnode_value 必须查 LoadImage 解析 LOAD 结果和未写 varnode。接线 Funcdata/Arch/loader + 真 executeLoad（+addressToByte/wordSize）。加 executeCall/Callind/Callother(fallthru)/executeBranch/Branchind(fail)
2. **移植缺模型类 JumpBasic2/JumpAssisted/JumpBasicOverride**。JumpBasic2 最高价值——覆盖极常见默认守卫模式（`if(x>N) default; goto *table[x]`），JumpBasic 显式失败（cc:441）。加进 JumpTable::recover_model 级联（override→JumpAssisted→JumpBasic→JumpBasic2），删错置的 JumpModelTrivial
3. **修 analyzeGuards + 加 checkUnrolledGuard/checkCommonCbranch**：(a) impl FlowBlock::getFlipPath()——现 indpath_store 错；(b) checkUnrolledGuard 需 BlockBasic::findMultiequal+liftVerifyUnroll；(c) 修 pathout>=0 分支（JumpBasic2 用）；(d) 恢复 i!=0 "保护其它 switch" 检查
4. **修 calcRange intersect 语义 + 加 isBoolOutput 分支**：`let _ = gr.intersect(rng);` 丢弃不相交指示——Ghidra intersect 返非零时 skip。用返回值。恢复 isBoolOutput→CircleRange(0,2,1,1)
5. **接全 ActionSwitchNorm 管线**：现只调 recover_jump_tables 然后空。每表须 matchModel→recoverLabels→foldInNormalization→foldInGuards（折时 clear structure）。需移植 MISSING JumpTable::{switchOver,recoverLabels,matchModel,foldInNormalization,foldInGuards} + 修 addBlockToSwitch 的 lastBlock 语义（须 switch-block 出边 index 非 地址表 index）。修 foldInOneGuard 的 val 极性 `(indpath==0)!=isBooleanFlip` + 加 noInterveningStatement/单 folded-target 守卫
6. **修 sanityCheck 过截断 + 加顶层 thunk 检测**：JumpBasic::sanity_check 无条件 diff>0xffff 截断；Ghidra 只在 loader 无数据时截。查 LoadImage 或删 0xffff。另 impl JumpTable::sanityCheck（cc:2317）让单入口疑似 thunk 抛 JumptableThunkError（产 RecoveryMode::FailThunk）
7. 次要：恢复 findNormalized 只读单分支回退（cc:1231）；恢复 valueMatch 的 oneOffMatch+LOAD aliasing 分支（helper 已存在，只是没调用）；修 JumpValuesRange::initialize_for_reading/JumpValuesRangeDefault 真初始化 curval/lastvalue；修 PathMeld::meldOps 用 SeqNum/block 排序 + 恢复 truncatePaths；把恢复移出 catch_unwind（或窄化）让缺陷暴露

**结论**: 骨架（PathMeld/GuardRecord/quasiCopy/JumpValuesRange/JumpModel trait/JumpBasic 算术路径/EmulateFunction 纯算术）结构忠实，简单例测试过。但模拟器不能处理加载（常见情况）、五模型类缺三、守卫分析多处语义缺陷、ActionSwitchNorm 恢复后管线空桩。**净效果：switch/case 恢复在真二进制上实际失效**——会恢复少量直接算术 switch 成原始地址表但从不标注/规范化/结构折入 switch 输出。L1→L2 记忆过誉。

---

## 报告 6: transform.rs

**Summary**: ~31 Rust / ~38 Ghidra | ✅25 ⚠️8 ❌5 ➕3

**Headline**: 暂存层（TransformVar/TransformOp/TransformManager）结构忠实——字段对齐、arena 重映射、5 步 apply 管线（createOps→createVarnodes→removeOld→transformInputVarnodes→placeInputs）全在且序对。**但 commit 路径有 4 个真正确性缺陷**：(1) createOpReplacement 丢 CPUI_MULTIEQUAL→opInsertBegin 分支；(2) ConstantIop createReplacement 不调已有的 new_varnode_iop/get_op_from_const 而做普通常量——静默破坏 INDIRECT iop 解析；(3) transformInputVarnodes 跳过 deleteVarnode（旧输入不移）且用 set_flags(INPUT) 替 setInputVarnode（无去重/注册）；(4) Piece varnode 的 transferVarnodeProperties 是空操作。两暂存 helper 也半桩：specialHandling/markIndirectCreation 空操作，inheritIndirect 不能区分 indirect_creation vs indirect_creation_possible_out（无 is_indirect_zero）。唯一接线的调用者 RuleSplitFlow（subflow.rs）调 mgr.apply(fd)，故这些缺陷是活的。RuleSubfloatConvert 明确不用 transform（务实类型标签回退）。

**Pipeline 接线**: arch.rs:281,613 用 LanedRegister（数据）；subflow.rs:91 import TransformManager+LaneDescription；subflow.rs:2898 SplitFlow.mgr 拥 TransformManager 转发 apply；RuleSplitFlow 端到端接线。RuleSubfloatConvert 明确不用（缺口非 transform.rs bug）。

**关键修复**（见 R25-R26 +）:
1. **[CRITICAL] create_op_replacement + attempt_insertion 丢 CPUI_MULTIEQUAL→opInsertBegin 分支**（rs:944-947, 495-499）。经 MULTIEQUAL 的 lane-split（RuleSplitFlow 常见）插错位置。op_insert_begin 已存在（funcdata.rs:1624）但需 follow op 的 parent block
2. **[CRITICAL] TransformVar::create_replacement constant_iop 做普通常量非 iop varnode**（rs:423-428）。new_varnode_iop（funcdata.rs:1437）+ get_op_from_const（~1455）都存在且正是 Ghidra cc:213-214 调的——就是不调。一行修：经 get_op_from_const 再 new_varnode_iop
3. **[HIGH] transform_input_varnodes 半桩**（rs:1080-1092）：deleteVarnode 全跳，setInputVarnode 替成裸 set_flags(INPUT)。移植 Funcdata::delete_varnode + set_input_varnode
4. **[HIGH] special_handling/markIndirectCreation 空操作**（rs:892-896），Funcdata::mark_indirect_creation 不存在。加 Varnode::is_indirect_zero + Funcdata::mark_indirect_creation
5. **[MEDIUM] create_varnodes 独立变量用过滤启发**（rs:1043-1057）而非 Ghidra 专用 newVarnodes list。重构保持独立 list
6. **[MEDIUM] Piece varnode 跳 transferVarnodeProperties**（rs:417-421）
7. **[LOW] 错误策略分歧**：get_piece/parse_sizes/create_replacement 错位 eprintln!+continue（Ghidra throw LowlevelError）

**判定**: transform.rs ~75% 移植——暂存结构+apply 骨架忠实，但 commit 路径 4 个真正确性缺口使 apply() 对非平凡变换产微妙错。**分类 L2.5 声称但 apply 路径实 L2**——暂存 L3，commit L2。

---

## 报告 7: unionresolve.rs

**Summary**: ❌ 整体：**伪装成端口的桩**。只有数据结构壳 + computeBestIndex 是真的。整个 union 字段评分算法——文件心脏（~900 行 C++：scoreTrialDown/scoreTrialUp/scoreLockedType/scoreTruncation 等）——**MISSING**。更糟，run_on_func 是**捏造启发式**（扫 SUBPIECE/INT_AND）Ghidra 无处存在，会产错字段解析。常量错，ResolveEdge 编码常量错，ResolveEdge 排序错，**无管线接线**（无 Funcdata::getUnionField/setUnionField）。AGENTS.md "L1→?" 宽宏；实际 **L1 only + 假算法**。

**Pipeline 接线**: Rust: lib.rs:102 声明但零非测试调用者。无 Funcdata::get_union_field/set_union_field。**未接**。Ghidra: 重度接线——ScoreUnionFields 在 type.cc:1182-1934 Datatype::resolve 族内构；Funcdata::getUnionField/setUnionField 维护 per-edge 解析 map；从 coreaction.cc:2500-2516/merge.cc:424,1172/printc.cc:983,2094/funcdata_varnode.cc:1646 调。

**关键修复**（见 R27-R29 +）:
1. **删/替 run_on_func**——捏造启发式会发错字段解析。替成真 run() pass-loop（cc:963-980）+ runOneLevel
2. **移植评分核心**：scoreTrialDown（cc:305,~335 行）+ scoreTrialUp（cc:642,~190 行）+ 4 评分原语 scoreLockedType/scoreParameter/scoreReturnType/derefPointer/scoreTruncation/scoreConstantFit + trial 构造器 newTrialsDown/newTrials/testSimpleCases/testArrayArithmetic
3. **修三常量**：MAX_PASSES 5→6, THRESHOLD 10→256, MAX_TRIALS 50→1024
4. **修 ResolveEdge 指针编码**：0x10000→0x1000（cc:72）；**修 derive-Ord 字段序**成 (type_id,encoding,op_time)——现 op_time 和 encoding 调换，破 map 排序
5. **Trial 带 vn/op 句柄**；ResolvedUnion 持 Datatype*（Arc）——名-only 表示使真算法不可能
6. **接线**：加 Funcdata::get_union_field/set_union_field（funcdata.cc:917-999）+ 从 Rust 类型解析路径调 ScoreUnionFields

---

## 报告 8: override_rs.rs

**Summary**: ⚠️ 整体：内存容器大体忠实（FlowOverride 枚举全，map 全，insert/query/encode/decode 形对）——AGENTS.md "L1→L2" 对*容器*大致对。但三严重问题：(1) **所有权错**——Override 在 Rust 的 Architecture，Ghidra 在 Funcdata（localoverride），丧失每函数隔离；(2) **proto-override 存 bool 占位**而非 FuncProto*，apply 和 encode/decode 全丢原型数据；(3) **apply 方法桩/未接**——ActionForceGoto.apply() 返回 NO_CHANGE 不应用，decode_flow_override 空体，无 applyDeadCodeDelay。XML `<addr>` 编码只写 offset 到 space 属性（Ghidra 经 writeSpace 写全 space+offset），跨工具往返畸形。

**Pipeline 接线**: Rust 调用者：arch.rs:341 overrides 在 Architecture（错主）；arch.rs:470 decode_flow_override 桩空体；coreaction.rs:5677 ActionForceGoto.apply 桩 NO_CHANGE；jumptable.rs:3409 测试；apply_indirect/apply_prototype/get_flow_override/query_multistage/has_deadcode_delay 无非测试调用者。Ghidra 活跃接线：flow.cc:416,688,711,714/funcdata.cc:167,759,812/coreaction.cc:674,4890/heritage.cc:2579/fspec.cc:5454,5495/jumptable.cc:2724,2876/architecture.cc:465。**Rust 侧缺几乎所有集成点**。

**关键修复**（见 R31 +）:
7. **修所有权**：Override 从 Architecture 移到 Funcdata（localoverride, funcdata.hh:98）。每函数隔离必需
8. **修 proto-override**：存真 FuncProto（fspec.rs 落地后）；apply_prototype/apply_indirect 取 (Funcdata,&mut FuncCallSpecs) 做 copy/setAddress 变异
9. **加 apply_dead_code_delay**（cc:217）+ 从 Funcdata::init 调；填 ActionForceGoto.apply 真调 apply_force_gotos；impl decode_flow_override
10. **修 `<addr>` XML 编解码**发/解 space 名+offset（匹配 Address::encode/writeSpace），或文档 marshal 层为 Rust-internal-only。恢复 deadcodedelay/flow 错标签的 LowlevelError throw

---

## 批2 总结

- 8/8 报告完成
- 头号根因 18 个（R15-R32）已记入修复输入清单
- **blockaction 的 collapse_cbranch_cascades（R15）是单点最高 ROI**——删一个函数 switch 18→2
- **block.rs 的 flag 位错（R16）+ edge-mutation 损坏（R17,R18）是结构化层系统性 bug 的根源**
- **jumptable 的 EmulateFunction 不读加载（R19）+ 三模型类缺（R20）+ 后恢复桩（R21）= switch 恢复实际失效**——这解释了为何 Rugra 把 if/else 当 switch（blockaction 的 cascade 函数可能是对 jumptable 失效的补偿性误补偿）
- unionresolve.rs 是**唯一"伪装端口"**——其余文件都是真移植带不同程度缺陷

下一步: 批3-6 待发起（剩 ~50 文件）。
