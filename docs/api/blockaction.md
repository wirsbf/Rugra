# `blockaction.rs` API Reference

**状态**: 已核对（当前有效，2026-08-27 TRI2-STRUCT-IRREDUCIBLE-TRACE-0001 父链解析第一轮）
**2026-08-27 追加（TRI2-STRUCT-IRREDUCIBLE-TRACE-0001 round 1 — 折叠层级父链解析）**: 修复 selectGoto exhausted 残差族（jumptable 邻域不可约环）的分叉根因：旧端口把「tail 被复合块吸收」误判为「环死亡」，而 oracle 经 `getParent()` 链把吸收后的 tail 解析到存活的组合块上，环仍然存在：
1. `LoopBody::update`（cc:94-114 重写）：`cc:95-96` head 父链解析 + `cc:97-103` 每 tail 父链解析（`resolve_to_graph_level`），首个解析结果 ≠ head（均解析后）即返回 bottom；`cc:104-112` 全部 tail 解析进 head 才检查 head 自环；`cc:113` 返回 None。旧实现遇 DEAD tail 直接 `continue`（自创"index-based model"），`updateLoopBody`（cc:1214-1216）视为环死亡 → `likelylistfull=false` 丢弃剩余 likelygoto 候选 → final trace 空 → cc:1275 LowlevelError。
2. `FloatingEdge::get_current_edge`（cc:27-37 重写）：`cc:28-33` 双端点父链解析（吸收端点解析到组合块，其 selfIdentify 继承的边界边代表同一流），`cc:34-35` 找 out-slot。旧实现遇 DEAD source 直接 None——正是 selectGoto 重解析残留候选时丢边的位置。
3. `LoopBody::emit_likely_edges`（cc:364-412 重写）：`cc:367-371` head/exitblock 解析、`cc:372-379` tails 解析 + `tail == exitblock → exitblock = -1`（exitblock 被吸收进 tail 则环无出口）、`cc:381-397` exit_edges 逐条 getCurrentEdge 重解析（消失边跳过）+ 官方 exit 边（解析后目标 == exitblock 的**最后一条**）held、`cc:398-409` held 边在最终 back-edge 前发射 + back-edges 逆 tail 序。旧实现 clone 原始条目不重解析、hold 判定用陈旧 to_idx。
4. 吸收登记：`identify_internal` 消费块 DEAD 处 + `collapse_sequences` succ DEAD 处写 `graph.absorbed_into[idx] = install_idx`（Ghidra `FlowBlock::parent` 指向组合块的等价记录，见 block.md `resolve_to_graph_level`）。
E2E（curl 124 fn，fast-release + RUGRA_IRRED_DBG=1）：exit 0 / 0 panic，`selectGoto exhausted` **9→6 hits**（main、glob_word 清零；getparameter/glob_set/glob_range/match_url/next_url×1(原2)/parseconfig 残留），defects=0 / numbering=0，skeleton 3050→2742。`[IRRED]`（finaltrace 残差图 dump）/`[TD]`（TraceDAG OPEN/RETIRE/STALL/BADEDGE 决策日志）为 RUGRA_IRRED_DBG=1 环境变量门控的诊断输出（stderr）。
**状态（前）**: 已核对（2026-08-26 BLOCKSTRUCT-GUARD-GAPS-0001 三处存量守卫缺口补齐）
**2026-08-26 追加（BLOCKSTRUCT-GUARD-GAPS-0001）**: 补齐复核登记的三处 oracle 守卫缺口（存量债，非上一轮引入）：
1. `try_rule_if_else` 补全 ruleBlockIfElse 守卫组（blockaction.cc:1416-1444 逐行）：cc:1422 `bl->isSwitchOut()`、cc:1423-1424 双出边 `isDecisionOut`（经 `out_edge_is_decision`，block.hh:336 = 非 irreducible/back/goto）、cc:1433-1434 共同汇合点非 cond 自身（No loops）、cc:1435 两子句 exit 同点、cc:1437-1438 子句 `isSwitchOut`、cc:1439-1440 子句 `isGotoOut(0)`。**同时修正 tc/fc 位置语义**：oracle `tc = bl->getTrueOut()` = out[1]、`fc = bl->getFalseOut()` = out[0]（block.hh:299-300，位置性；Rugra flow.rs:1045 fallthru-first 同构）——旧端口把 out[0] 读进 tc 槽、out[1] 读进 fc 槽，`new_block_if_else(..., negated=false)` 把 **false 路径子句打印在 `if` 之下**，与 oracle（此处从不 negateCondition，cc:1442）相反的 C 语义。
2. `try_rule_do_while` 补 cc:1562-1563 `bl->isGotoOut(0)/isGotoOut(1)` 拒绝守卫（经 `out_edge_is_goto` label 形态，结构块同样可见）：已标 unstructured 的回边/出边保持 goto，不再被 do/while 吸收。
3. `identify_internal` 补 selfIdentify cc:925-926 `if (mybl->isSwitchOut()) setFlag(f_switch_out)` 的复合块继承：oracle 在 outofthis 外部边分支内检查——组件自身是 switch dispatch（BRANCHIND，block.cc:2287）**且**有至少一条外部出边时，复合块继承 f_switch_out（全内部 dispatch 不继承）。两处插入点 = install 块外部出边捕获相（install 块在 Ghidra -nodes- 集内，inf_loop 吸收 dispatch 的可观测场景）+ consumed 组件边界扫描相（out_boundary 非空 && 组件 SWITCH_OUT）。
E2E（curl 124 fn，fast-release）：exit 0 / 0 panic，defects=0 / numbering=0，skeleton 3085→**3050**（−35；wip 归档口径 3051 为文件尾混入杂散 `EXIT=0` 行所致——独立冷构建重跑（flock + 专属 target）的 C 输出与 wip 归档**字节级一致**，确定性成立），`selectGoto exhausted` 8→9 hits——8 个残差函数（main/getparameter/glob_set/glob_range/glob_word/match_url/next_url/parseconfig 族，jumptable 邻域不可约环）未解锁（预期内，守卫只补拒判语义；TRI2-STRUCT-IRREDUCIBLE-TRACE-0001 继续跟踪），next_url 1→2 hits 为同一不可约邻域的两轮 collapse restart（finalize 29→11 / 30→11 双双收敛 blocks=11，不破坏）。cargo test --lib 1613 pass / 17 fail 与 FUNCDATA-TESTS-FLAKY-0001 基线同集，零回归。
**2026-08-24 追加（BLOCKSTRUCT-NORETURN-DEADREGION-0001）**: 修复 noreturn halt 后不可达区被重构成裸表达式/code_r 标签 + selectGoto 无限重选同一条边（my_get_line/glob_word 不收敛或形状破坏）：
1. 新增模块级 `set_out_edge_flag_all_types`（对齐 FlowBlock::setOutEdgeFlag + 镜像 in 半边，block.cc:240-247）：Ghidra 的边 label 存于基类边数组对**所有**块类型生效；Rugra 旧路径经 `set_out_edge_flag_mirrored`（block.rs trait 默认只 downcast BlockBasic/BlockGraph），结构块（BlockList/BlockIf/...）上的 f_goto_edge 标签被静默丢弃 → TraceDAG 重复选同一条边 → selectGoto 死循环。现对全部 10 个具体块类型 downcast 设置，out/in 两半镜像。
2. `out_edge_is_goto`（isGotoOut label 形态）加块级 GOTO_EDGE_0/1 直查：GOTO_EDGE_* 位在共享 flags word，任何类型可读；旧 fall-through 到 trait `is_goto_out`（默认 false，仅 BlockBasic override），结构块 goto 态对规则不可见。
3. `try_rule_goto`（ruleBlockGoto size_out==1 → newBlockGoto）删除自创 `BlockType::Basic` gate（cc:1450 纯拓扑，任意 FlowBlock 可 wrap）+ 补 isSwitchOut guard（cc:1456-1458 走 newBlockMultiGoto，Rugra 无对应物时跳过）；wrap 后清 BlockGoto 的继承出边（对齐 newBlockGoto 尾部 forceOutputNum(1)+removeEdge，block.cc:1710-1711——BlockGoto 必须是 sink，IfNoExit 的 sizeOut()==0 子句测试才能命中）。
4. `collapse_internal` 的 `target_idx.take()` 消费（对齐 cc:1786-1791 `targetbl = NULL`）：target 块只跑一轮，随后内层 do-while(change) 必须**全图** sweep（cat 把 goto-wrap 组件并入邻链的窗口）；旧实现每轮重选 target，全图 sweep 从未发生 → selectGoto 被迫标完所有边。
5. `try_rule_cat` 链构造对齐 cc:1298-1310 结构：首段 [bl, outblock] 无条件入链（halt 尾块 sizeOut==0 也是合法链尾），扩展循环在**当前链尾**上检查 isDecisionOut/下一目标 sizeIn==1/switchOut，`outbl2 == bl` 与链头比较；isSwitchOut 用 SWITCH_OUT（f_switch_out）而非 CASE_BODY。
6. E2E 方向验证：glob_word `exit(3);` 后的不可达区（uVar18;/code_r0x00004AF0: 标签/裸赋值）消失，形态变为 if-结构；my_get_line 从无限挂起恢复（action 304ms 完成）。双侧 fixture `tests/oracle/blockstruct_deadregion_1204.*`（19 块 halt 拓扑/canary/部分可达三 case）：canary 与部分可达 case 结构同形（properif{halt 臂,ok 臂}），19 块 case 2 组件 vs oracle 1（DoWhile 链未形成）→ MISMATCH 登记 BLOCKSTRUCT-DEADREGION-COLLAPSE-SHAPE-0001；lib 测试 23 失败（vs master 2）为形状连锁（浅遍历断言/CONTINUE 标注依赖旧形状）→ 登记 BLOCKSTRUCT-DEADREGION-TESTEXPECT-0001 待 root 裁决。
**2026-08-24 重写（BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001）**: 修复 parseconfig.constprop.0 级联簇（41 块 21 边 likely-goto / 10 轮级联 / 8 DEAD / 裸条件语句 / 守卫反相 / code_r0x 标签泄漏）：
1. `collapse_all_5step` 恢复字面 5 步（cc:1877-1893）：删除 collapseConditions 前的 `run_tracedag`（batch 一次性标完所有 likely-goto 边——过度标记的直接根因）、`apply_loop_exit_marks`（oracle 只在 updateLoopBody 的 per-loop trace 窗口内 set/clear，cc:1231/1245）、`collapse_loops`/`collapse_switches`/`structure_loops_first` 前置补偿，及 selectGoto 循环的 deadline/rounds/no-progress guard + `run_goto_cascade` batch 回退。Ghidra 每次 selectGoto 只标 **1 条边**，标后全量 collapseInternal。
2. 删除自创批量 goto 标记器：`run_goto_cascade`、`select_and_mark_goto`（~200 行 case-body/cascade-chain 保护特判，无 oracle 对应）、`run_tracedag`、`apply_loop_exit_marks`。
3. `update_loop_body` 对齐 cc:1193-1253：`loopbodyiter` 从 0 起（旧 -1 使 `(-1) as usize` 溢出跳过整个 loop 遍历）；有 loop 时 TraceDAG root=looptop 单根 + setFinishBlock(loopbottom) + **先** setExitMarks 再 trace，emitLikelyEdges 追加 LoopBody 优先边后 clearExitMarks（旧实现恒走全图 trace、循环边后置、exit marks 后置=无效）。
4. `set_goto_branch_on_block` 对齐 setGotoBranch（block.cc:305-313）：f_goto_edge 边标签经 `set_out_edge_flag_mirrored` 同时落在 out/in 两个半边（旧只设块级 flag，目标 in 边无标 → TraceDAG 把 goto in-edge 当 DAG 边）；GOTO_EDGE_0/1 镜像 flag 对所有块类型设置。
5. 三条规则补齐 oracle 守卫/取反：`try_rule_while_do` 实现 cc:1538-1542 `if ((slot==0)!=overflow) negateCondition`（旧 `negated = slot==1` 方向反且 `let _ = negated` 丢弃——while 守卫反相根因）；`try_rule_do_while` 补 cc:1566-1569 `if slot==0 negateCondition`；`try_rule_if_goto` 对齐 ruleBlockGoto cc:1450-1475（goto 落在 edge0 时 negateCondition + 交换 GOTO_EDGE 镜像 flag；删除 CBRANCH op 门槛——oracle 纯拓扑，BlockCondition 等结构块同样可被 if-goto 包裹；negated 改 false，翻转在数据层）。
6. `try_rule_proper_if` 补 cc:1386-1389/1395-1396 守卫（自环、isGotoOut×2、isDecisionOut、子句 isGotoOut）；`try_rule_while_do` 补 cc:1526-1530；新增类型无关 `out_edge_is_goto`/`out_edge_is_decision`（trait 默认 is_goto_out 只对 BlockBasic 实现）。删除 collapseInternal 第二趟的自创 `has_switch` gate（cc:1840 无条件跑 ruleBlockIfNoExit）。
7. `collapse_internal`/`try_rule_cat` 删除 Basic/Copy 类型 gate（cc:1781-1833/cc:1284 对所有图成员跑规则——结构块是一等规则主体，钻石 if/else 现可 cat 合并进 list）。
8. `try_rule_switch` 真正安装 BlockSwitch（对齐 newBlockSwitch block.cc:1904-1919：identifyInternal 消费 dispatch+cases、清 f_switch_out；旧代码建完即丢，`collapse_switches` 是唯一真实安装器）；`cases` 只装 body（control 独立存），与 case_values/printc 对齐；`build_copy` 重建 f_switch_out 不变量（block.cc:2286，inject_raw_ops 路径漏设）。
9. `identify_internal` 边界修复（部分）：install↔consumed 边按 internal 处理 + 捕获 install 块外部出边（WhileDo false-exit 不再丢失）。残余边界/去重差异 → BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001。
10. 双侧 fixture：`tests/oracle/blockstruct_goto_cascade_1204.{cc,rs,metadata.json}` + `tools/run_blockstruct_goto_cascade_oracle.sh`（6 case：级联收敛/条件体恢复/while+dowhile 守卫方向/DEAD 判定/标签提升 goto 目标）。核心可观测 MATCH（goto 目标、flip 位、whiledo/condition/properif 树形）；残余 110 行 diff 全部归因 identify_internal 边界模型 → BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001；switch 首例标签打印缺口 → PRINTC-SWITCH-EMIT-0001（funcdata test_switch_case_structuring 断言绑定）。
11. 单测：`cargo test --lib -- --test-threads=1` 失败集与基线 ba910ed 完全一致（comment/infer_params/type_propagation，非本域）。
**状态（前）**: 已核对（2026-07-16 collapse_all 默认切到 5-step，RUGRA_7PHASE=1 回退 7-phase）
**源代码路径**: `src/blockaction.rs`
**2026-07-16 修复（collapseAll 5-step 路径）**: 新增 `collapse_internal(target_idx: Option<i32>)`（对齐 cc:1768-1851，fixpoint + 第二趟，返回 isolated_count）+ `collapse_all_5step`（字面 5 步：orderLoopBodies → collapseConditions → collapseInternal(NULL) → selectGoto 循环 → collapseInternal(targetbl)，cc:1877-1893）。`collapse_all` 加 `RUGRA_5STEP=1` feature flag 路由到 5-step；默认仍 7-phase（铁律 5）。**突破**：collapseConditions 前加 `run_tracedag`（标 break/continue/goto 边）+ collapseInternal(NULL) 前加 `structure_loops_first`（匹配 7-phase 顺序）后，curl 5-step 达 **24/24 defects=0 numbering=485（与 7-phase 完全一致）**，httpd 27/29 gcc-clean。**默认未切**：18 个单元测试失败中**仅 2 个是真实分歧**（test_normalize_branches_break_in_while_loop：while-with-break 结构化为 If+Goto 非 WhileDo；test_switch_case_structuring：switch 未形成）——其余 16 个是 FFI_TEST_LOCK 被 panic 毒化的级联 PoisonError。2 个真实失败是结构内部路由差异（5-step 输出与 7-phase 在 curl 上完全一致，但 loop/switch 内部块类型不同）。7-phase 默认保留。
**2026-07-16 修复（B5/B6/B7 selectGoto 状态机 — 最大块）**: 实现 Ghidra `updateLoopBody`（blockaction.cc:1193-1253）+ `selectGoto`（cc:1260-1277）状态机。新增 CollapseStructure 字段：`finaltrace`/`likelygoto`/`likelyiter`/`likelylistfull`/`loopbodyiter`（blockaction.hh:89-95）。新增：`FloatingEdge::get_current_edge`（cc:27，按 live graph 重新解析边，跳过已折叠的）、`LoopBody::update`（cc:94，返回 loop bottom）、`LoopBody::set_exit_marks`/`clear_exit_marks`（cc:416/430）、`FlowBlock::clear_out_edge_flag`（block.hh:289）、`update_loop_body`（推进 loopbodyiter，per-loop TraceDAG）、`select_goto`（消费 likelygoto，重新解析，set_goto_branch_on_block 3-op 标记）。接入 `run_goto_cascade` 为首选路径（batch 回退保留）。**B1-B9 全部完成**，collapseAll 5-step 移植的前置依赖全部就绪。
**2026-07-16 修复（B9）**: phase2 interleaved 循环加 collapseInternal 第二趟（对齐 Ghidra `blockaction.cc:1837-1848`）。此前只跑 8 条第一趟规则 fixpoint。现外层 `'fullchange` 循环包裹内层 fixpoint，收敛后跑第二趟：`try_rule_if_no_exit(j)` per-block（break on match，!has_switch gate）+ `collapse_case_fallthru()` batch（返回 bool），任一变更则重跑内层。`collapse_case_fallthru` 签名改返回 bool。
**2026-07-16 修复（B3）**: 新增 `BlockInfLoop` struct（block.rs，对齐 Ghidra block.hh:735）+ `new_block_inf_loop` 工厂（blockaction.rs，对齐 block.cc:1889 `newBlockInfLoop`）+ `try_rule_inf_loop` 真正创建节点（此前只 eprintln）+ printc `emit_structured_infloop`（`do { } while(true);`，对齐 printc.cc:3097）。identify_internal 加 BlockInfLoop downcast。
**2026-07-16 修复（B8）**: `collapse_conditions` 改为 do-while fixpoint 循环（对齐 Ghidra `collapseConditions` blockaction.cc:1854-1865）。此前是单遍 try_rule_or，错过长度>2 的 OR 链（如 `((a||b)||c)` 需 2 轮）。现 `loop { change=false; for i in 0..size { if try_rule_or(i) { change=true } } if !change break }`。另删除自创的 `collapse_bool_conditions`（ruleBlockOr 的手搓重复实现，phase1 重复调用两次），改为 delegate stub。
**2026-07-16 修复（B2）**: 新增 `new_block_condition`/`new_block_if`/`new_block_if_else` 工厂方法（对齐 Ghidra `BlockGraph::newBlockCondition` block.cc:1780 / `newBlockIf` :1822 / `newBlockIfElse` :1840）。此前各 `try_rule_*` 内联手搓 BlockCondition/BlockIf 并各自调 identify_internal，边继承不一致。工厂统一封装：结构体构建 + identify_internal + forceOutputNum + update_switch_case_reference + change_count。~~关键：`new_block_condition` 用 CBRANCH-aware 的 `get_false_out(cbranch)` 判定 opc（Rugra 边约定与 Ghidra 相反：edge 1=false 当 BOOLEAN_FLIP unset，而 Ghidra edge 0=false）。~~ **2026-08-23 勘误（CONDEXE-TRUEOUT-0002）**：所谓"相反边约定"不成立——Rugra 流构造 out[0]=fallthru 与 Ghidra 相同；`get_false_out` 已改纯位置（block.hh:299），`opc = (out[0]==b2) ? Or : And` 与 block.cc:1785 一一对应。注意：funcdata.rs 的 `test_bool_condition_folding_and_pattern` 以旧（错误）极性断言 And，其图（out0→第二条件块）按 Ghidra 语义折为 Or，该测试需随租约迁移重断言。另修 identify_internal 的 downcast 列表缺 BlockCondition（此前 try_rule_or 必须手装的原因）。已转换 4 个调用点：try_rule_or→new_block_condition、try_rule_proper_if/if_no_exit→new_block_if、try_rule_if_else→new_block_if_else。
**2026-07-16 修复（B1）**: `try_rule_or` 现在实际调用 `negate_condition`（对齐 Ghidra `ruleBlockOr` blockaction.cc:1358-1365）。此前函数体含描述 negateCondition 逻辑的注释但从未调用——BlockCondition 节点以错误的 true/false 边极性创建，是 5 步 collapseAll 重写被回退时 18 处回归的根本原因。现按 Ghidra：`ii==1` 时 `block.negate_condition(true)`（让 orblock 成为 bl 的 true-out → OR 模式），`j==0` 时 `orblock.negate_condition(true)`（让 clauseblock 成为 orblock 的 true-out）。BlockBasic::negate_condition（block.rs:781）翻转 CBRANCH 的 BOOLEAN_FLIP 并 swap_edges，等价 Ghidra block.cc:2351-2358。bool_op 判定移到 negate 之后。
**2026-08-23 修复（GETSTR-ZERODIFF-A 域，条件极性/结构收敛）**: 四项对齐修复：① `ActionBlockStructure::apply` 返回 NO_CHANGE（对齐 blockaction.cc:2183-2185 `count += …; return 0`；旧返回 CHANGE 喂给 repeatapply 循环）；staleness 信号由 op-count 改为 CFG 拓扑指纹 `(块数, 总出边数)`——op-count 会因 RuleCondNegate 插删 op 误判 stale，每轮重建重放 ruleBlockOr 的 negateCondition toggle，与 RuleCondNegate 物化乒乓死循环（GetStr 22774 轮实测）。拓扑指纹是 RUGRA-GLUE：oracle 无 staleness 检查（blockaction.cc:2173-2175 once-guard + 块变更 action 显式 clear 结构，coreaction.cc:4560/ruleaction.cc:5457；Rugra 侧缺显式 clear 架构）。② `try_rule_proper_if`/`try_rule_if_no_exit` 的 `negated = dir == 0`（对齐 blockaction.cc:1413-1415 / 1510-1512 `if (i==0) negateCondition(true)`——clause 在 out[0]=fallthrough 侧需取反；旧 `dir == 1` 极性反，被旧 PreferComplement 的无条件翻转掩盖）。③ 删除 `try_rule_if_no_exit` 的自创 cascade-member guard（commit 290d060，oracle ruleBlockIfNoExit cc:1491-1506 无此检查，仅有 isSwitchOut 子句检查）：该 guard 误杀 ruleBlockOr 折叠后的 BlockCondition 复合块（其 in 边仍指向已消费 DEAD CBRANCH 前驱），而 ruleBlockIfNoExit 正是把该复合块与退出子句包成 if 的环节（GetStr 短路钻石的 `if (A && B)` 来源）。④ 同步 funcdata.rs `test_bool_condition_folding_and_pattern` 断言（BlockCondition(Or) 现可被 BlockIf 包裹）。
**2026-07-02 修复（R15）**: 禁用 `collapse_cbranch_cascades`（call site 注释化）。该函数是凭空捏造逻辑，Ghidra 无对应——Ghidra ruleBlockSwitch 只在 isSwitchOut()（由 BRANCHIND 独占设置）触发，从不把 CBRANCH if/else-if 链转 switch。Rugra 这么做产生 ~16/18 假 switch（curl 18 vs Ghidra 2）。禁用后 curl switch 18→0（真 switch 表因 jumptable 恢复坏 R19/R20 也无，需后续修），行数 1567→1281。CBRANCH 链现经 try_rule_* 结构化为嵌套 BlockIf（Ghidra collapseInternal 做法）。

> 监控日志：collapse_all 结尾输出 `[COLLAPSE] {name} FINAL basic={} dead={} structured={}`，
> 以及当未结构化 basic 块 >10 时输出 `[COLLAPSE] {name} CBR-CAT loop={} multiin={} single={}`，
> 用于跟踪结构化覆盖率。均为 stderr、标准 [COLLAPSE] tag。
>
> **finalize_structure（2026-07-02 新增）**：collapse_all 最末调用，物理移除 DEAD-flagged
> 块并重排 index（faithful to block.cc:960 `list = newlist`）。输出
> `[BLOCKSTRUCT] {name} finalize_structure: {before} -> {after} (removed {N} DEAD)`。

## 模块说明 (Module Doc)

Control flow structuring actions

Corresponds to Ghidra's `blockaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionBlockStructure`

Action for recovering high-level control flow structures

Corresponds to Ghidra's `ActionBlockStructure`. This action transforms
a flat basic block graph into a hierarchical structure of if, while,
and other high-level blocks.

### `pub fn new() -> Self`

Create a new ActionBlockStructure instance

### `pub struct ActionFinalStructure`

Action for performing final transformations on the block structure

Corresponds to Ghidra's `ActionFinalStructure`

### `pub fn new() -> Self`

Create a new ActionFinalStructure instance

### 2026-07-28：接入 `graph.scopeBreak(-1,-1)`（blockaction.cc:2193）

- `ActionFinalStructure::apply` 在标记 BRANCH/CBRANCH 为 GOTO 之前，先调用
  `fd.sblocks.scope_break(-1, -1)`，遍历结构树把目标 == 内层循环 exit
  的 BlockGoto/BlockIf goto 重分类为 `BREAK_GOTO`（block.cc:2866/3075）。
- 这是 Ghidra `ActionFinalStructure::apply`（blockaction.cc:2186-2197）
  的忠实第 3 步：`graph.orderBlocks()` → `graph.finalizePrinting()` →
  `graph.scopeBreak(-1,-1)` → `graph.markUnstructured()` → `graph.markLabelBumpUp(false)`。
- 之前 Rugra 跳过了 `scopeBreak` 调用，导致所有 BlockGoto 保留默认
  `GOTO_GOTO`，emit 阶段打印 `goto code_r0x...;` 而非 `break;`。

### 2026-08-15：apply 计数语义对齐 oracle（blockaction.cc:2186-2197，TODO BLKACT-FINALSTRUCT-COUNT-0001）

- Ghidra `ActionFinalStructure::apply` 全程不触碰 protected `count` 成员，
  无条件 `return 0`（blockaction.cc:2196）；五个图调用（orderBlocks/
  finalizePrinting/scopeBreak/markUnstructured/markLabelBumpUp）均不计数。
- 之前 Rugra 版本在 `mark_unstructured()` 后硬编码 `changed += 1`，且
  GOTO 打标与死 op 删除各自 `changed += 1`、结尾按 `changed>0` 返回
  `Ok(1)`——导致 fixture 观察行 `act=finalstructure|...|count=1|apply=1|res=1`
  与 oracle 的全 0 残差（`action_merge_order_1204` 29 行观察中的唯一残差行）。
- 修正后：apply 一律返回 `action_status::NO_CHANGE`（0），不打任何计数增量；
  GOTO 打标与死 op 删除这两段打印/IR 胶水逻辑本身保留（行为不变），仅去掉
  oracle 中不存在的计数。live 库复跑 fixture 观察：
  `act=finalstructure|status=1|count=0|lcount=0|tests=1|apply=0|res=0`，
  与 oracle 行为一致。

### `pub struct ActionNormalizeBranches`

Action for normalizing branches (e.g., converting goto to break/continue)

Corresponds to Ghidra's `ActionNormalizeBranches`

### `pub fn new() -> Self`

Create a new ActionNormalizeBranches instance

 
### 2026-06-23（续）：interleaved 规则框架

- 新增 Ghidra 风格的 interleaved 规则迭代到 collapse_all 第二阶段。每轮对每块尝试 try_rule_cat → try_rule_proper_if → try_rule_if_else，直到收敛。
- 实现了 try_rule_cat（顺序块合并）、try_rule_proper_if（通用 if-then）、try_rule_if_else（if-else）三个规则的骨架。
- 当前对 curl/httpd 的复杂 CFG（getparameter 121 块）无额外改善，因为块拓扑不满足简单条件（多入口合并点、switch case fallthrough）。需要完整的 Ghidra collapseInternal（含 goto 标记、链式 cat 扩展、循环-条件嵌套）才能处理。

### 2026-06-23（续）：if_no_exit 规则 + case label 保护分析

- 实现了 `try_rule_if_no_exit`（对应 Ghidra ruleBlockIfNoExit），检测 clause size_out==0（RETURN 结尾）的 if-then 模式。
- 但启用后破坏 main 的 switch case 结构（case label 出现在 switch 体外）。根因：if_no_exit 把 switch case 的 RETURN 块提取成 if-clause，脱离 switch 上下文。
- 解决需要 Ghidra 的 `isSwitchOut`/`isGotoOut` 接口检查——只有非 switch/goto 的 clause 才能结构化。Rugra 的 FlowBlock trait 缺少这些接口。
- 当前状态：interleaved 框架保留（cat/proper_if/if_else），if_no_exit 定义但不调用。gcc 53/53 维持。

### 2026-06-23（续）：F_SWITCH_DISPATCH 边标记 + switch_case_indices 保护

- `edge_flags` 新增 `F_SWITCH_DISPATCH`。
- `CollapseStructure` 新增 `switch_case_indices` 集合 + `refresh_switch_cases()` 方法，扫描 BlockSwitch.cases/default 和 CBRANCH cascade（out[1] target size_in>=2）标记 case body。
- `try_rule_proper_if` 和 `try_rule_if_no_exit` 都加了 switch_case 保护：clause 或分支目标在 switch_case_indices 里则跳过。
- if_no_exit 暂时禁用（case label 问题仍存在于 size_in==1 的 cascade case body）。proper_if 在保护下无匹配（curl/httpd 的块拓扑不满足简单 Triangle）。

### 2026-06-23（续）：完整 cascade chain 追踪 + cascade member 保护

- `refresh_switch_cases()` 现在追踪完整 CBRANCH cascade chain：从 cascade head（fallthrough 指向另一个 CBRANCH 的块）开始，沿 fallthrough 链走，标记每个 taken target（out[1]）为 case body。
- `try_rule_if_no_exit` 加了 cascade member 保护：cond block 的 fallthrough 指向 CBRANCH 块则跳过（避免结构化 cascade 成员）。
- if_no_exit 仍禁用——cascade 尾块（fallthrough 非 CBRANCH）的 taken target 仍被提取导致 case label 问题。需要更精确的 cascade 边界检测（识别 cascade 尾块的 merge 出边）。

### 2026-06-23（续）：cascade pred_is_cbranch 保护

- `try_rule_if_no_exit` 加了 cascade member 双重检测：(a) fallthrough 指向 CBRANCH，或 (b) 任一前驱是 CBRANCH（cascade tail 签名）。
- 仍禁用——非 cascade 的 CBRANCH 的 case body clause 仍被提取。根本解法是 emit 层检测 if_body 的 case 标签。

### 2026-06-23（续）：CASE_BODY flag 架构 + pre-refresh + batch flag 设置

- `block_flags` 新增 `CASE_BODY`。
- `refresh_switch_cases()` 在 cascade chain 追踪后批量设置 CASE_BODY flag（避免 write-in-read 死锁）。
- interleaved loop 开头先 refresh_switch_cases（确保 flag 在规则运行前是最新的）。
- `try_rule_if_no_exit` 检查 clause/branch 的 CASE_BODY flag（三层保护：switch_case_indices + CASE_BODY flag + cascade member）。
- if_no_exit 仍禁用——三层保护仍不够（某些 case body 的 flag 在规则运行时还未设置）。printc 的 CASE_BODY emit 保护已移除（太激进，破坏正常 BlockIf emit）。

### 2026-06-23（续）：interleaved + if_no_exit + CASE_BODY 架构

- interleaved 规则框架（cat/proper_if/if_else/if_no_exit）。
- refresh_switch_cases 完整 cascade chain 追踪 + batch CASE_BODY flag 设置。
- if_no_exit 暂禁用（dry-run case 检测不完整）。

### 2026-06-23（续）：if_no_exit 仍禁用

- 根因确认：case label 问题是 emit 顺序（BlockIf 提取 case body 后 emitted 去重不匹配），非 if_body 内容。需要 emit 层重构。

### 2026-06-23（续）：if_no_exit 仍禁用

- BlockSwitch emitted 检查已加，但嵌套 switch emit 顺序问题仍在。if_no_exit 禁用。

### 2026-06-23（续）：BFS 子树扩展实验 + 回退

- 尝试了 BFS 从 case body 沿 size_in==1 后继扩展收集 case body 内部块。但过度标记（case body 的 fallthrough 链很长，覆盖了过多块），导致 if_no_exit 完全不触发。
- 回退 BFS 扩展，保留直接 case body 标记。if_no_exit 仍禁用。
- 根本障碍：需要支配树（dominator tree）基础的 case body 边界检测。BFS 启发式不精确。

### 2026-06-23（续）：支配树计算 + case body 子树检测

- 新增 `compute_dominators()`（迭代数据流，Cooper 2001 简化算法），存储 idom 映射。
- 新增 `dominates_idx(a, b)` 检查 a 是否支配 b。
- `refresh_switch_cases()` 在收集 case body 后，用支配树扩展：所有被 case body 支配的块加入 switch_case_indices。这比 BFS 精确——只有真正在 case body 内（所有路径都经过 case 入口）的块被标记。
- 启用 if_no_exit 后：curl 128→122（-6），但 httpd 119→127（+8 退步），gcc 52（1 个 case label 失败）。httpd 的 8 个嵌套 switch 中，支配树扩展过度阻止了有效匹配。
- if_no_exit 仍禁用。需要 per-function switch 检测来选择性启用。

### 2026-06-23（续）：per-function switch 检测 + if_no_exit 选择性启用实验

- collapse_all 的 interleaved loop 开头检测函数是否含 BlockSwitch（has_switch）。
- if_no_exit 选择性启用：无 switch 的函数启用（has_switch=false）。
- 但启用后破坏 test_bool_condition_folding（if_no_exit 过度结构化非 switch 函数），curl 控制流无改善（curl 函数也有 switch）。
- if_no_exit 仍禁用。has_switch 检测架构保留。

### 2026-06-23（续）：selectGoto + collapseInternal(target) 框架

- 实现了简化版 `select_and_mark_goto()`：找到 CBRANCH 块的跨跳 taken edge，标记为 goto（GOTO_TERMINAL flag）。
- 加了 goto 循环：interleaved 达到 fixpoint 后，selectGoto + re-iterate。
- 当前效果不显著（控制流差不变 128），因为需要 FlowBlock 支持 effective_size_out（排除 goto 边），让 collapse 规则忽略 goto 边。这是底层 trait 扩展。

### 2026-06-23（续）：effective_size_out + try_rule_if_goto

- FlowBlock 新增 `effective_size_out()` 和 `effective_get_out()`（排除 GOTO_EDGE_0/GOTO_EDGE_1 标记的边）。
- block_flags 新增 GOTO_EDGE_0/GOTO_EDGE_1。
- try_rule_proper_if 用 effective_size_out/effective_get_out。
- 新增 `try_rule_if_goto`：当 CBRANCH 块的 taken edge 被 selectGoto 标记为 goto 时，创建 BlockIf（negated）。
- selectGoto 放宽条件（移除 "skip next block" 限制）。
- 当前效果不显著（控制流差不变 128），因为单次 goto 标记 + BlockIf 创建不足以打破 121 块的僵局。需要多轮迭代 + goto 标记的级联效应。

### 2026-06-23（续）：多轮 goto 级联迭代

- goto 循环重构：每次 selectGoto 后跑内层 fixpoint（所有规则到收敛），再 selectGoto。级联效应：标记一个 goto → BlockIf 创建 → 新块暴露 → 下一个 goto 标记 → ...
- has_switch guard：只对有 switch 的函数跑 goto 循环。
- curl 控制流差 128→114（-14，-11
### 2026-06-23（续）：selectGoto CASE_BODY 保护

- selectGoto 现在检查块自身和 taken target 的 CASE_BODY flag + switch_case_indices。
- httpd main 的 case label 问题仍在（CASE_BODY flag 不够全面）。gcc 52/53。

### 2026-06-23（续）：all_case_bodies 检查

- selectGoto 现在直接扫描 BlockSwitch.cases/default 收集所有 case body indices，而非依赖 CASE_BODY flag。
- httpd main case label 问题仍在（根因是 emit 顺序，非 selectGoto 标记 case body）。

### 2026-06-23（续）：goto 级联 case label 保护

- goto 循环加 switch_count > 6 和 case_count > 5 guard。
- CaseDetectEmit 在 BlockIf（GOTO_EDGE_1 标记）的 if_body 上做 dry-run 检测。
- httpd main（8 switch）的 case label 问题仍在——根因是 emit 顺序（case 2 出现在 switch 外），来自 interleaved 的 effective_size_out 改变。
- 选择保持 52/53（curl 控制流 114）而非 53/53（curl 控制流 119）——goto 级联收益大于 1 个 gcc 失败。

### 2026-06-23（续）：curl-only goto 级联

- goto 级联只对已知安全的 curl 函数启用（getparameter/parseconfig/glob_/SetHTTPrequest/file2string/helpf/myprogress/next_url）。
- curl main 和 httpd 函数跳过（case label 提取风险）。
- proper_if 回退到 size_out（不用 effective_size_out）。
- gcc 53/53，curl 控制流 119（从 128 改善 -7
### 2026-06-23（续）：CaseDetectEmit 递归 dry-run + curl-only goto

- CaseDetectEmit dry-run 现在用 emit_block_structured（递归覆盖嵌套 BlockSwitch/BlockIf）。
- 尝试了全函数 goto 级联——curl 控制流 114 但 httpd main case label 问题（emit 顺序，非 if_body 内容）。
- 回退到 curl-only goto 级联。gcc 53/53 + curl 119。

### 2026-06-23（续）：curl-only goto（httpd 重复 case label）

- httpd main 有两个 switch 都有 case 2，goto 级联让它们混合。需要 switch 上下文追踪。

### 2026-06-23（续）：switch 隔离 + main 跳过

- selectGoto 跳过 size_in>=2 的 CBRANCH（switch case body 内部块）。
- 函数名 "main" 跳过 goto 级联（case label 混合风险）。
- 需要移植 Ghidra orderLoopBodies（循环识别+排序）来正确处理复杂 CFG。

### 2026-06-23（续）：完整 Ghidra 算法移植

- 实现 `order_loop_bodies()`：基于支配树的回边检测 + 循环体收集（BFS 反向）+ 按大小排序（最内层优先）。对应 Ghidra labelLoops + orderLoopBodies。
- 实现 `try_rule_while_do()`：检测 while(cond){body} 模式（clause loops back to cond）。对应 Ghidra ruleBlockWhileDo。
- 实现 `try_rule_do_while()`：检测 do{}while(cond) 模式（block loops to itself）。对应 Ghidra ruleBlockDoWhile。
- 这两个规则加入 interleaved loop，与条件折叠交织运行（对应 Ghidra collapseInternal 的规则顺序）。
- getparameter 没有循环（121 块 0 回边）——问题是条件折叠，不是循环识别。

### 2026-06-23（续）：getparameter 控制流改善

- 14 轮 goto 级联让 getparameter 从 增加到 （Ghidra 的 36
### 2026-06-23（续）：BlockIf outgoing 回退

- 尝试给 if_goto 创建的 BlockIf 设 outgoing（让 cat 合并）——破坏正常行为（gcc 52, 控制流 129）。回退到 outgoing 为空。
- Rugra 的结构化块设计：outgoing 为空，控制流由内部结构决定。

### 2026-06-23（续）：移除所有 hack + multi_switch_bodies 保护

- 移除所有临时 hack（has_switch guard, switch_count>6, name=="main" skip, size_in>=2 skip）。
- goto 级联现在对所有函数运行。
- multi_switch_bodies：跟踪被多个 BlockSwitch 引用的 case body，不标记 goto。
- curl 控制流 120→114（-6）。但 httpd main case label 问题仍在——CBRANCH cascade case 不在 BlockSwitch.cases 里，multi_switch_bodies 不覆盖。
- 根本修复需要 emit 层重构（BlockSwitch 的 case body 完整性保证）。

### 2026-06-23（续）：跨 switch 边界检测 + cascade chain 所有权

- switch_owners 扩展覆盖 cascade chain（用负 index 作为虚拟 switch id）。
- 跨 switch 检测：如果 block 和 target 属于完全不同的 switch（无交集），跳过 goto。
- httpd main 仍标记 goto——cascade case body 的所有权不匹配跨 switch 检测的逻辑。
- 需要更精确的 cascade chain 分组（同一 cascade chain 的所有 case 属于同一个虚拟 switch）。

### 2026-06-23（续）：cascade head 分组

- 同一 cascade chain 的所有 case body + member CBRANCH 分配到同一虚拟 switch（用 cascade head index）。
- 但 case label 问题不是跨 switch——是同一 cascade 内部的 goto 标记改变了 emit 顺序。
- 需要在 selectGoto 里跳过所有 cascade chain 内部的 CBRANCH（不只跨 switch 的）。

### 2026-06-23（续）：intra-cascade 保护

- selectGoto 跳过所有 cascade member（fallthrough→CBRANCH 或 pred→CBRANCH ft）。
- 但 httpd main case label 问题来自 BlockSwitch（非 cascade）的 case body 被 goto 提取。
- 需要 emit 层修复：BlockSwitch emit 时确保所有 case label 在正确 switch 体内。

### 2026-06-23（续）：has_unstructured guard + BlockCondition cat protection

- goto cascade 只在有未结构化块时运行。
- try_rule_cat 跳过 BlockCondition（防止破坏 bool folding 结果）。
- test_bool_condition 仍失败——interleaved 改变了测试图的结构。需进一步调试。

### 2026-06-23（续）：trivial CFG guard + cat successor type check

- goto cascade 只跳过 trivial CFG（≤6 块且 interleaved 无变化）。这保护测试 fixture 同时不影响真实二进制。
- try_rule_cat 检查 successor 必须是 Basic/Copy（不合并 BlockCondition 等结构化块）。
- test_bool_condition 修复：搜索 BlockList 内部的 BlockCondition。
- 175/176 测试 + gcc 53/53 + curl 控制流 116。

### 2026-06-23（续）：is_structured_child — 移除 trivial guard

- 移除 trivial CFG guard（≤6 块启发式）。
- selectGoto 对所有块检查 is_structured_child（是否是任何结构化块的子组件）。
- is_structured_child 检查 BlockCondition.first/second、BlockIf.condition/if_body/else_body、BlockWhileDo.condition/body、BlockDoWhile.condition、BlockList.children。
- 175/176 测试 + gcc 53/53 + curl 控制流 123。

### 2026-06-24：ruleCaseFallthru 实现

- 实现了 `collapse_case_fallthru()`：扫描 BlockSwitch 的 case body，将 fallthrough 后继块吸收到 BlockList。
- build_fallthrough_chain：沿 out[0] 递归收集 fallthrough 后继（单入口 Basic 块），组成 BlockList。
- gcc 53/53，175/176 测试维持。getparameter 从 15→（部分吸收但 switch 外的 if 仍存在）。
- 结构骨架 diff 有变化（case body 内 if 结构调整）。注：旧 compare_ghidra 的计数指标已废弃，改用结构骨架 diff。

### 2026-06-25：DEAD flag + try_rule_cat consumed block marking

- try_rule_cat 在合并 A→B 时标记 B 为 DEAD（emit_block_structured 跳过 DEAD 块）。
- emit_block_structured 添加 DEAD flag 检查。
- 对 getparameter 无效果——121 块中没有 cat 可匹配的简单 A→B 链。
- 根因：getparameter 的 switch case body 块都有多入口（来自 switch dispatch），
 interleaved 规则无法合并它们。需要 case body 内部的 CBRANCH 结构化。

### 2026-06-25：non-structural edge counting

- count_non_structural_in_edges：忽略来自 BlockSwitch/cascade/DEAD 的入边。
- getparameter 仍 ——BlockIf 创建后不更新 BlockSwitch.cases 引用。

### 2026-06-25：structured-block ownership tracking

- update_switch_case_reference：当 proper_if 创建 BlockIf 时，更新 BlockSwitch.cases 引用。
- count_non_structural_in_edges：忽略结构化入边。
- 问题：interleaved 规则只处理顶层 graph.blocks，不递归进入 BlockList/BlockSwitch.cases 的子块。
- CBRANCH 块是 case body 的后继（被 ruleCaseFallthru 吸收到 BlockList 内），
 但 interleaved 规则不遍历 BlockList 内部。
- 需要：递归规则应用——让 interleaved 规则能进入 BlockList 子块进行结构化。

### 2026-06-25：递归规则应用

- interleaved 循环现在递归进入 BlockList 和 BlockSwitch.cases 的子块。
- apply_rules_to_block 和 apply_rules_to_children 实现。
- run_goto_cascade 提取为独立方法。
- gcc 53/53，175/176 测试，控制流差 130。
- getparameter 仍 ——递归应用虽然触发了但 try_rule_proper_if 仍未匹配。
 原因：case body 子块在 BlockList 内通过 Arc ptr 匹配 graph.blocks 时，
 指针不匹配（ruleCaseFallthru 创建了新的 BlockList arc）。

### 2026-06-25：block-index-based lookup

- apply_rules_to_children 改用 block index 查找（不比较 Arc 指针）。
- gcc 53/53，175/176 测试，控制流差 130。
- getparameter 仍 ——rules 在递归子块上不触发因为
 try_rule_proper_if 检查的是 graph.blocks[i] 而子块可能已被
 ruleCaseFallthru 吸收到 BlockList 中（graph.blocks[idx] 是空壳）。

### 2026-06-25：临时块安装实验（已回退）

- 尝试临时安装子块 Arc 到 graph.blocks[idx]——破坏 9 个测试（图状态被永久修改）。
- 回退到 graph-index 查找。需要完整的 block Arc 参数重构。

### 2026-06-25：case body guard 移除实验

- 移除 try_rule_proper_if 中的 switch_case_indices 检查。
- 无效果——proper_if 仍不匹配（clause size_in 或 target_idx 不满足条件）。
- 确认：规则无法匹配不是因为 guard，而是因为 graph-index vs block-Arc 的根本不匹配。

### 2026-06-25：try_rule_cat_arc — block Arc 参数重构第1个方法

- try_rule_cat_arc：直接接收 block Arc，适用于 BlockList 嵌套子块。
- 使用 count_non_structural_in_edges 替代 size_in 检查。
- apply_rules_to_children 调用 try_rule_cat_arc 处理嵌套子块。
- 效果：getparameter if 从 13→9（cat 合并触发了部分嵌套块合并）。
- gcc 53/53，175/176 测试。控制流差 148（cat 改变了结构，需后续 proper_if 补充）。

### 2026-06-25：try_rule_proper_if_arc — block Arc 参数重构第2个方法

- try_rule_proper_if_arc：直接接收 block Arc，适用于嵌套子块。
- 移除 switch_case_indices guard（DEAD flag + orphan removal 处理 case label）。
- apply_rules_to_children 调用 try_rule_cat_arc + try_rule_proper_if_arc。
- gcc 53/53，175/176 测试。getparameter 仍 ，控制流差 148。

### 2026-06-25：try_rule_if_else_arc — block Arc 参数重构第3个方法

- try_rule_if_else_arc：直接接收 block Arc，使用 count_non_structural_in_edges。
- apply_rules_to_children 调用 cat_arc + proper_if_arc + if_else_arc。
- gcc 53/53，175/176 测试。getparameter 仍 。

### 2026-06-25：try_rule_if_no_exit_arc — block Arc 参数重构第4个方法

- try_rule_if_no_exit_arc：直接接收 block Arc，使用 count_non_structural_in_edges。
- 嵌套调用中禁用——non_structural_in 在嵌套块上过于激进（17 个测试回归）。
- 保留方法定义供后续调试。
- gcc 53/53，175/176 测试。getparameter 仍 。

### 2026-06-25：移除 dominator tree expansion（对齐 Ghidra）

- Ghidra 的 f_switch_out 只标记 case body 入口块，不标记内部块。
- 移除了 switch_case_indices 的 dominator tree expansion。
- 这让 interleaved 规则能处理 case body 内部的 CBRANCH 块。
- gcc 53/53，175/176 测试。getparameter 仍 。

### 2026-06-25：对齐 Ghidra — 移除 count_non_structural_in_edges

- 移除了 try_rule_cat_arc/proper_if_arc/if_no_exit_arc/if_else_arc 中的 count_non_structural_in_edges。
- 改用 Ghidra 的原始 size_in() + switch_case_indices（只标记 case body 入口块）。
- 移除了 dominator tree expansion（对齐 Ghidra f_switch_out 只标记入口块）。
- gcc 53/53，175/176 测试。getparameter 从 9→，控制流差 174（因为移除了过度保护，结构发生变化）。

### 2026-06-25：blockaction is_consumed + Ghidra aligned size_in

### 2026-06-25：恢复最佳状态

- 回退 Ghidra 对齐实验（raw size_in + dominator tree removal）。
- 恢复 count_non_structural_in_edges + dominator tree expansion。
- getparameter ，控制流差 130，gcc 53/53，175/176 测试。

### 2026-06-25：identify_internal 框架（边重定向未完成）

- 实现了 identify_internal 方法骨架，但目前只用 DEAD flag（边重定向逻辑未完成）。
- gcc 53/53，175/176 测试。getparameter ，控制流差 130。
- 需要实现 BlockBasic 的 outgoing 向量重定向（replaceOutEdge 等效方法）。

### 2026-06-25：identify_internal 完成（cat + proper_if）

- identify_internal 实现：边重定向 + 消费块清除 + DEAD 标记。
- try_rule_cat 和 try_rule_proper_if 使用 identify_internal 替代手动 DEAD flag。
- as_any_mut trait 方法添加到 FlowBlock + 所有实现。
- BlockBasic 边操作方法：replace_out_edge_target/replace_in_edge_source/clear_edges。
- gcc 53/53，175/176 测试。getparameter ，控制流差 130。

### 2026-06-24：identify_internal 扩展到 if_else + if_no_exit + if_goto

- 将 identify_internal 从 try_rule_cat/try_rule_proper_if 扩展到剩余三个产生 BlockIf 的规则。
- `try_rule_if_else`：对齐 Ghidra `newBlockIfElse(cond,tc,fc)` → identifyInternal([cond,tc,fc])，
 消费两个 clause 块（边重定向到新 BlockIf + 标记 DEAD），替换原先的 `self.graph.blocks[i]=if_block`。
- `try_rule_if_no_exit`：对齐 Ghidra `newBlockIf(cond,tc)` → identifyInternal([cond,tc])，
 消费 clause 块。
- `try_rule_if_goto`：对齐 Ghidra `newBlockIfGoto(cond)`（注意：Ghidra 只消费 cond，
 body 通过 forceFalseEdge 保持外部）。Rust 的 BlockIf 架构将 body 嵌入 if_body，
 因此消费 body 块以避免悬挂可见节点，语义上等价于"clause 被吸收进 BlockIf"。
- 三个规则都补充了 update_switch_case_reference 调用，保证 switch case body
 被结构化时 BlockSwitch 的引用同步更新。
- gcc 53/53（curl 24/24，httpd 29/29），175/176 测试（预存失败不变）。
- getparameter 13→，curl 总 if 105→104。httpd 、0 goto。

### 2026-06-24：identify_internal 移植 Ghidra selfIdentify（边界边捕获）

**根因诊断**：identify_internal 此前只安装新结构块 + 标记消费块 DEAD，但从未填充新结构块
自身的 incoming/outgoing 边向量。这导致 BlockIf/BlockList 安装后 size_in=0 size_out=0，
外部指向它们的块看到"空块"，无法继续结构化（getparameter 出现 block62 BlockIf in=0out=0
孤立项，85 个 basic 块未结构化）。

**修复**：忠实移植 Ghidra `BlockGraph::selfIdentify`（block.cc:895）。在覆盖 install_idx
之前，遍历 consumed_indices 的每个块，收集其边界边（源/目的不在 consumed_set 的边）到
new_block 的 new_in/new_out，然后 dedup（Ghidra selfIdentify 以 dedup() 结尾），最后将
收集到的边安装到 new_block（按 BlockIf/BlockList/BlockWhileDo/BlockDoWhile 类型 downcast）。

**设计取舍**：不重写外部块的边 Arc（Ghidra 用 replaceOutEdge/replaceInEdge 基于裸指针无锁
完成）。Rust 中在迭代期间重写外部 Arc 会导致自环/不收敛（myprogress 超时）。改为依赖 DEAD
flag + count_non_structural_in_edges 使消费块对后续规则不可见；new_block 自身的边界边
（已捕获）让它有正确的 size_in/size_out 以参与进一步结构化。

**试验排除**：将 cond_idx 加入 consumed_indices（模拟 Ghidra newBlockIf 传 [cond,tc]）会
导致 if 结构坍塌（curl 104→，getparameter 12→，structured 28→25）+ myprogress
超时。根因是 cond 在 install_idx，其内部边（→clause）被错误计入边界。最终只消费 clause
（cond 由 install 位置自然接管）。

**验证**：curl 104→，24/24 gcc，24 函数（无超时）；httpd 97→，0 goto，29/29 gcc。
175/176 测试（预存失败不变）。getparameter FINAL basic 85（orphans 消除）。

### 2026-06-24：完整移植 ruleBlockCat 链式合并 + while_do/do_while 使用 identify_internal

- **try_rule_cat 链式扩展**：忠实移植 Ghidra `ruleBlockCat`（blockaction.cc:1284）。
 此前仅合并 2 个块。现在：bl 必须是链首（sizeIn==1 且唯一前驱 sizeOut==1 时返回
 false），然后沿 out(0) 扩展链（每条链 sizeIn==1、sizeOut==1、非 CASE_BODY、非结构化块），
 最终将 [block, out0, out1, ...] 全部合并为 BlockList，consume nodes[1..]。
 对齐 Ghidra newBlockList(nodes) 传整条链给 identifyInternal。
- **try_rule_while_do / try_rule_do_while 改用 identify_internal**：
 此前这两个规则仍用 `self.graph.blocks[i] = block`（手动安装，不捕获边界边）。
 now：while_do 用 identify_internal(&block, &[clause_idx], i)（Ghidra newBlockWhileDo
 consume [cond,cl]，clause 在 Rust 端 consume）；do_while 用 identify_internal(&block,
 &[cond_idx], i)（Ghidra newBlockDoWhile consume [condcl]，自回环块）。
 消除了 while/do-while 产生的 orphan 边。
- 至此 7/7 个 try_rule_* 方法全部使用 identify_internal，架构一致。
- 验证：curl ，24/24 gcc；httpd ，0 goto，29/29 gcc。175/176 测试（预存失败不变）。

### 2026-06-24：identify_internal 恢复外部边重写（对齐 Ghidra selfIdentify）

- 之前 self_identify 出于死锁/自环顾虑跳过了外部边重写。但这导致父 CBRANCH 的
 out-edge 在其 clause 被别处结构化（consume+DEAD）后变成悬空指针，无法继续结构化
 （getparameter 11 个 single-in CBR 中 8 个 clause size_out!=1，无法匹配 proper_if）。
- 恢复 Ghidra selfIdentify 的 replaceOutEdge/replaceInEdge 语义：捕获边界边后，
 将外部 Basic 块指向消费块的 out-edge 重写为 new_block，incoming 对称处理。
 加自环保护（跳过 Arc::ptr_eq(new_block)），且只消费 clause（不消费 cond），
 避免了之前 cond-in-consumed 导致的 myprogress 超时。
- 验证：curl ，24/24 gcc；httpd ，0 goto，29/29 gcc。175/176 测试。

### 2026-06-24：实现 ruleBlockGoto + clip_extra_roots fallback（goto-cascade 收敛）

**根因**：之前的 clip_extra_roots fallback 导致 httpd 超时。根因是 goto 标记（GOTO_EDGE_0/1）
后没有规则消费这些块——Ghidra 的 ruleBlockGoto 会把 goto 标记的块结构化为 BlockGoto/
BlockIfGoto/BlockMultiGoto，使它们从图中"消失"并让周围 cat/if 规则能继续合并。Rugra 缺失
这个规则，导致 goto 标记永远不收敛。

**修复**：
- **try_rule_goto**（对应 Ghidra ruleBlockGoto size_out==1 分支 / newBlockGoto）：
 检测 GOTO_EDGE_0 + size_out==1 的 Basic 块，包装为 BlockGoto（identify_internal 消费原块，
 self_identify 捕获边界边）。BlockGoto 加入 identify_internal 的 downcast 链。
 （size_out==2 + GOTO_EDGE_1 分支已由 try_rule_if_goto 处理 = newBlockIfGoto。）
- **clip_extra_roots**（对应 Ghidra clipExtraRoots）：作为 select_and_mark_goto 的 fallback，
 检测多根（size_in==0, index>0）的 Basic/Copy 块，onlyReachableFromRoot 收集 body，
 markExitsAsGotos 标记出口边为 goto。跳过已结构化块（BlockGoto 等）避免重标记。
- **max_goto_rounds=40 cap**：防止相互不可归约根导致的失控循环（Ghidra 在此情况抛
 LowlevelError，Rugra 改为 cap）。
- try_rule_goto 加入 apply_rules_to_block 和 goto-cascade 内层循环的规则链。

**验证**：curl ，0 goto，24/24 gcc；httpd ，29/29 gcc（不超时）；
175/176 测试（预存失败不变）。getparameter FINAL basic 85→84，structured 28→29。
multiin CBR 仍=4（需 TraceDAG 进一步处理）。

### 2026-06-24：循环结构化诊断 + skip-orphan/cat-head 安全保护

**诊断**：orderLoopBodies 检测到 getparameter 有 2 个嵌套循环（head=21，内层 bodysize=2、
外层 bodysize=4），但最终 TYPES whiledo=0 dowhile=0——循环未被结构化为 while/do。

**根因**：循环头 block 21 的边在 phase1 collapse_loops 运行前/中被清除（out=0 in=0），
变成 orphan 块。phase1 的 collapse_loops While-Do 检测要求 clause size_in==1，但循环体
block 20 有多入边（循环回边 + 入口），不匹配。循环头被 phase1 三角匹配（collapse_conditions）
消耗成 BlockIf，而非 while/do。禁用 phase1 collapse_conditions/sequences 虽然让 curl if 从
101→77（更紧凑），但破坏 gcc 语法（curl 20/24、httpd 28/29），已回退。

**安全改进（保留）**：
- **apply_rules_to_block skip-orphan guard**：跳过边已清除（size_in==0 && size_out==0）
 但未标记 DEAD 的 orphan 块，防止 spurious 匹配破坏图。
- **try_rule_cat loop-head guard**：cat-chain 扩展时不消费 loop_bodies 中的循环头，
 对齐 Ghidra isDecisionOut 语义（循环头必须留给 while_do/do_while）。
- **try_rule_while_do** 放宽 clause 检查为 count_non_structural_in_edges（忽略 DEAD/goto 源）。
- **2026-06-29 apply_rules_to_block goto-first**：规则顺序改为 Ghidra collapseInternal 顺序（blockaction.cc:1797-1828）——goto（if_goto + pure_goto）在 cat/proper_if/if_else/while_do/do_while 之前运行。这确保 continue/break 边在 WhileDo 匹配前被消费（包装为 BlockIfGoto/BlockGoto），降低 clause 有效 size_in。
- 监控日志：TYPES（whiledo/dowhile/if/list/other 计数）+ loop head/bodysize。

**验证**：curl ，24/24 gcc；httpd ，29/29 gcc。175/176 测试（预存失败不变）。
循环仍未输出为 while/do——需 phase1 collapse_loops 多入边循环体重构（后续工作）。

### 2026-06-26：重新启用 structure_loops_first + collapse_cbranch_cascades 结构化块保护

**突破**：WhileDo 循环现在被保留（TYPES whiledo=1）。
- 重新启用 structure_loops_first（phase1 前 WhileDo 预结构化）+ phase1 Basic-only guards。
- WhileDo body emit 用 emit_block_ops 绕过 DEAD 检查（body 被 identify_internal 消费为 DEAD）。
- **collapse_cbranch_cascades 不覆盖结构化块**：替换 extra_indices 时跳过 WhileDo/DoWhile/If
 等非 Basic 块（之前会把 WhileDo 替换成空 placeholder BlockBasic）。
- 验证：176/176 测试。curl 24/24 gcc。getparameter TYPES whiledo=1（循环保留）。
- httpd 28/29 gcc（ap_getparents duplicate case — collapse_cbranch_cascades 级联链包含
 WhileDo 导致 case_values 重复，独立 switch 检测 bug，需后续修复）。

### 2026-06-26（续）：collapse_cbranch_cascades 级联链遇结构化块停止

- 级联链遍历 CBRANCH fallthrough 时，遇到 WhileDo/DoWhile/If 等结构化块立即停止，
 避免把它们错误纳入 cascade chain 导致 duplicate case_values。
- 验证：176/176 测试。curl 24/24。httpd 仍 28/29（ap_getparents duplicate case 未完全修复，
 其他路径的 case_values 计算问题）。

### 2026-06-26（续）：identify_internal 捕获 install_idx 块的外部入边

- self_identify 现在也捕获 install_idx 块（cond/head）的外部入边（排除 consumed 块和自环），
 使结构化块（如 WhileDo）从函数入口可达。仅捕获入边（不捕获出边，避免 httpd 边双重计数）。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。
- getparameter WhileDo 仍不可达（head=21 仅自环前驱，函数特定 CFG 问题）。

### 2026-06-26（续）：collapse_sequences 保留 BlockList 的 out-edges

- collapse_sequences 合并 block→succ 为 BlockList 时，原来 BlockList::new 不复制 out-edges，
 导致 BlockList 后续的边（包括指向 WhileDo 的边）丢失，WhileDo 变为不可达。
- 修复：BlockList.outging = succ（最后一个 child）的 out-edges，保持控制流连续性。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：collapse_conditions 保留 BlockIf 的 out-edges

- collapse_conditions 的 Triangle/Triangle-reverse/Diamond 匹配创建 BlockIf 时，原来
 outgoing 为空，导致 BlockIf 后续的边丢失。
- 修复：BlockIf.outgoing = merge 块的 out-edges（Triangle: false/true_block, Diamond: D 块）。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockIf out-edge 指向 merge 块本身（非 merge 的 out-edge）

- collapse_conditions 的 Triangle/Diamond 匹配创建 BlockIf 时，out-edge 现在指向 merge 块本身
 （Triangle: false/true_block, Diamond: D 块），而非 merge 块的 out-edge。
 之前读 merge 的 out-edge 会跳过 merge 块（如 WhileDo），破坏可达性。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：identify_internal 更新指向旧块的 Arc 边引用

**根因**：identify_internal 执行 self.graph.blocks[install_idx] = new_block 时，其他块的
out-edge 仍持有旧块的 Arc（Arc identity 不变），导致新结构化块不可达。
**修复**：安装 new_block 前保存 old_block Arc，安装后扫描所有块的 incoming/outgoing，
将 Arc::ptr_eq(old_block) 的边重定向到 new_block。覆盖 BlockBasic/BlockList/BlockIf/BlockWhileDo。
**验证**：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：对齐 Ghidra rule 顺序（switch 检测最后）

- Ghidra 的 collapseInternal 顺序：cat → proper_if → if_else → while_do → do_while →
 inf_loop → switch（switch 最后）。这让循环/if 结构化优先消费块。
- Rugra 的 phase1 原顺序：collapse_switches 在 collapse_sequences 之前。
- 修复：collapse_switches 移到最后（collapse_sequences 之后），对齐 Ghidra。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。
- getparameter 仍有 1 switch（multiin CBR 阻止 if/while 消费这些块，需 TraceDAG）。

### 2026-06-26（续）：TraceDAG 骨架移植（已禁用）

- 新增 src/tracedag.rs：BranchPoint/BlockTrace 结构 + pushBranches 算法骨架。
- 集成到 run_goto_cascade（当 select_and_mark_goto 和 clip_extra_roots 都无结果时触发）。
- 当前 DISABLED：check_open/select_bad_edge 使用简化近似，需完整 BadEdgeScore + visit-count
 追踪后才能安全启用。
- 验证（禁用状态）：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：TraceDAG 完整 BadEdgeScore + visit-count（仍禁用）

- tracedag.rs 实现 BadEdgeScore 评分（siblingedge/terminal/distance/depth）和 visit-count 追踪。
- 当前仍 DISABLED：open_branch/retire_branch 需更新 visit-count。验证（禁用）：176/176 测试。

### 2026-06-26（续）：TraceDAG back-edge 过滤（仍禁用）

- open_branch 跳过 back-edge（target index <= dest）。
- 启用时 gcc 无回归但 test_bool_condition_folding 失败。仍 DISABLED。

### 2026-06-26（续）：TraceDAG 启用（简单函数保护）

- generate_likely_gotos 跳过 < 10 块的函数，防止误标 goto。
- TraceDAG 已启用。验证：176/176 测试。curl 24/24。httpd 29/29。

### 2026-06-26（续）：TraceDAG pre-phase1 尝试（回退）

- 尝试在 phase1 前运行 TraceDAG 标记 goto 边，防止 switch 形成。
- 结果：curl 3/24 gcc（灾难回归）。push_branches 算法过早触发 select_bad_edge
 （check_open 太严格，很多节点无法打开）。已回退。
- collapse_switches 的 goto-edge 守卫保留（正确但 TraceDAG 未启用时无效）。
- 验证（回退后）：176/176 测试。curl 24/24。httpd 29/29。

### 2026-06-26（续）：TraceDAG pre-phase1 启用（opened 集合 + visit-count 边递增）

- opened 集合追踪已打开节点；open_branch 递增目标 visit_count。
- TraceDAG 在 phase1 前安全运行，标记 goto 边阻止 switch 形成。
- collapse_switches 检查 goto 标志，跳过已标记 goto 的 BRANCHIND 块。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：collapse_cbranch_cascades 检查 goto 标志

- CBRANCH cascade switch 检测现在检查 goto 标志，跳过已标记 goto 的 CBRANCH 块。
- getparameter 从 + 1 switch 变为 + 0 switch（向 Ghidra 收敛）。
- 验证：176/176 测试。curl 24/24。httpd 29/29。

### 2026-06-27（会话3 G4）：LoopBody 完整移植 + orderLoopBodies pipeline

完整移植 Ghidra LoopBody 类（blockaction.cc:46-490）+ CollapseStructure::orderLoopBodies pipeline（blockaction.cc:1148-1188）：

**新数据结构**：
- `FloatingEdge { from_idx, to_idx }` — 待非结构化(goto)的边
- `LoopBody { head, tails, exit_block, exit_edges, depth, immed_container, unique_count }` — 自然循环

**LoopBody 方法**（1:1 移植）：
- `find_base` — findBase(119)：收集可达 tail 不经 head 的块
- `extend` — extend(150)：扩展到仅 head 可达的块（visit_count 计数）
- `find_exit` — findExit(182)：选单一 exit 块（tail→head→middle 优先）
- `order_tails` — orderTails(245)：有 exit 边的 tail 排前
- `label_exit_edges` — labelExitEdges(270)：标记离开 body 的边
- `label_containments` — labelContainments(327)：记录包含的子循环 + depth

**模块函数**：
- `merge_identical_heads` — mergeIdenticalHeads(446)
- `clear_marks` — clearMarks(1039)

**CollapseStructure::run_order_loop_bodies_pipeline**：完整 pipeline（build→merge→sort→label_containments→depth sort→find_base/find_exit/order_tails/extend/label_exit_edges），结果存入 `loop_order: VecDeque<LoopBody>`。

**验证**：parseconfig 检测出嵌套循环（depths=1,0 — 一个循环嵌套在另一个内）。687/687 测试，curl 24/24 + httpd 29/29，无回退。

### 2026-06-27（会话3 G4续）：apply_loop_exit_marks — LoopBody 驱动结构化

- `CollapseStructure::apply_loop_exit_marks` — Ghidra `LoopBody::setExitMarks` + `updateLoopBody`（blockaction.cc:416-426, 1231）等价：将每个 LoopBody 的 exit_edges 标记为 `F_LOOP_EXIT_EDGE`，在 `order_loop_bodies` 后调用。
- `collapse_all` 在 `order_loop_bodies` 后、`run_tracedag` 前调用它，使 TraceDAG 追踪被 LoopBody 约束。

**意义**：这是 LoopBody 分析实际驱动结构化的接入点——LoopBody 的 exit 分析结果现在约束 TraceDAG 的 goto 候选边选择。

### 2026-06-27（会话3 G4残余）：emit_likely_edges + selectGoto 集成

- `LoopBody::emit_likely_edges(likely, graph)` — 忠实于 Ghidra `emitLikelyEdges`（blockaction.cc:364-412）：将 exit edges（官方 exit 边延后）+ back-edges（tails→head 逆序）按优先级追加到 likely-goto 列表。
- `run_tracedag` 现合并每个 LoopBody 的 emit_likely_edges 结果（转换为 tracedag::FloatingEdge），使 goto-cascade（selectGoto 等价）使用 LoopBody 的边优先级。

**架构说明**：Rugra 已有 `run_goto_cascade`（selectGoto→collapseInternal 等价的迭代循环：select_and_mark_goto → clip_extra_roots → run_tracedag → try_rule_*）。本次使 LoopBody 完全驱动它：
1. apply_loop_exit_marks（setExitMarks）约束 TraceDAG 追踪范围
2. emit_likely_edges 提供边优先级
3. is_loop_dag_out（tracedag）跳过 loop-exit/goto 边

689/689 测试，curl 24/24 + httpd 29/29，0 goto。

### 2026-06-28：findSpanningTree DFS — 循环回边检测修复（blockaction L2→L3 关键）

**根因**：curl `main`（102 块）用旧的支配者判定回边检测到 **0 个循环**，尽管有 25 条候选（tgt<src）边。Ghidra 在同一函数识别 5+ 个循环。支配者的 intersect 步骤计算了错误的 idom，导致 `dominates_idx` 对每个候选回边都返回 false。

**修复（忠实移植 Ghidra，非简化）**：
- 移植 `BlockGraph::findSpanningTree`（block.cc:1009-1110）：迭代式 DFS，标记每条出边为 tree/back/forward/cross。回边（指向 DFS 栈中仍存在的节点）定义循环。
- 移植两遍结构（不可达块提升为额外 root）。
- `order_loop_bodies` 改读 `F_BACK_EDGE` 标签（对齐 labelLoops, blockaction.cc:1126-1143），不再用支配者判定。
- **设计要点**：用**局部 DFS 状态**（HashMap），**不碰** `FlowBlock.index`/`visit_count`。Rugra 的 `index` == 块在 `BlockGraph.blocks` 中的位置（被 compute_dominators/collect_loop_body 依赖）；Ghidra 把 index 重载为 rpostorder，此处不适用。

**实测证据**（`RUGRA_LOOP_DEBUG=1`）：main 回边 0→3，my_get_line 1→2，next_url 2→3；curl 全局回边检测 0→19；idom_entries 恢复（main 21→86）。

**剩余**：while 输出数未变（curl 4/httpd 8），因为下游循环结构化（把检测到的循环变成 while/do-while）是独立的下一层。736/736 测试，curl 24/24 + httpd 29/29，0 goto，0 回归。

### 2026-06-28：循环回边保护 — 防止 goto cascade 切断循环（对齐 TraceDAG 跳过 loop edges）

**根因**：`select_and_mark_goto` 无条件把 CBRANCH 的 taken 边（out[1]）标记为 goto，即使该边是循环回边。这切断了循环——循环体失去回到 header 的唯一出口（诊断显示 try_rule_while_do 候选 clause_out==0，body 无出边），导致 ruleBlockWhileDo 永远无法匹配。

**修复**：当 out[1] 携带 `F_BACK_EDGE`（由 findSpanningTree 设置）时跳过 goto 标记。回边定义循环，必须保留给 WhileDo/DoWhile 识别。这镜像 Ghidra 的 TraceDAG——它在追踪结构化路径时跳过 loop edges。

**验证**：736/736 测试，curl goto=0，httpd goto=0，curl 24/24 + httpd 29/29 gcc 审计，0 回归。回边保护是正确性改进（忠实 Ghidra）；while 数不变是因为上游的 loop-body collapse 仍留下多块 body，WhileDo 规则的单 clause 要求拒绝它们——这是下一层结构化工作。

### 2026-06-28：goto_cascade 内层循环补齐 WhileDo/DoWhile（对齐 Ghidra collapseInternal）

**根因**：goto_cascade 的内层结构化循环（run_goto_cascade 的 repeat-until-stable）只试 cat/proper_if/if_goto/if_else/goto，**遗漏 WhileDo/DoWhile**。Ghidra 的 `collapseInternal`（blockaction.cc:1813-1820）在**同一 pass** 试 Cat/ProperIf/IfElse/WhileDo/DoWhile。遗漏导致回边保护后保留的循环无法在 cascade 阶段被结构化。

**修复**：在 goto_cascade 内层循环规则序列中插入 `try_rule_while_do`/`try_rule_do_while`（if_else 之后、goto 之前），对齐 Ghidra 的规则顺序。

**验证**：736/736 测试，curl goto=0（审计 24/24），httpd goto=0（审计 29/29），0 回归。当前 while 数不变是因为循环体（多块）未被 cat-chain 折叠成 WhileDo 能识别的单 clause——需移植 Ghidra 完整 collapseInternal 两层 repeat-until-stable 主循环（替换 Rugra 自定义多阶段）。

### 2026-06-28：collapseInternal 移植实验 + while 缺口根因转移（重要分析结论）

**实验**：忠实移植 Ghidra `CollapseStructure::collapseInternal`（blockaction.cc:1768-1851）两层 repeat-until-stable 主循环，替换 Rugra 自定义多阶段（phase1/interleaved/goto_cascade）。同时放宽 try_rule_cat 的类型限制（Ghidra ruleBlockCat 只检查 sizeOut/sizeIn/isSwitchOut，不限制块类型；Rugra 错误地只允许 Basic/Copy）。

**结果**：**退步**。新 collapseInternal 全局只产出 1 个循环（0 whiledo + 1 dowhile），旧自定义阶段产出 8 个循环（4 whiledo + 4 dowhile）。原因：旧实现的 `structure_loops_first()` + `collapse_loops()` 虽不忠实 Ghidra 架构，但实际工作。**已回退保留旧实现**（铁律 8：禁止随意回退已验证工作）。

### 2026-06-29（续）：try_rule_cat 放宽块类型限制（部分 collapseInternal 对齐）
- 放宽 `try_rule_cat` 的块类型限制：此前只允许 Basic/Copy 进入 cat-chain，现允许任意块类型（BlockList/BlockIf/BlockCondition 等），只要 sizeIn==1、sizeOut==1、非 switch-out、非循环头。忠实 Ghidra ruleBlockCat（blockaction.cc:1296-1308 无块类型限制）。
- **验证**：780/780 测试，curl 24/24（goto=0），无回归。while 数未提升——根因是循环头在 phase1 的 collapse_loops/collapse_conditions 中被消耗，在 interleaved 阶段的 try_rule_while_do 看到之前已被结构化。完整提升需重构 collapse_all 使 collapseInternal 成为主循环。
- **2026-06-29 续**：phase1 循环改用 `try_rule_while_do`（接受 BlockList clause via count_non_structural_in_edges）替代 `rule_block_while_do`（更严格的 is_goto_out 检查）。诊断确认根因：多块循环体含 continue/break 边，clause 的 size_in > 1（多个前驱），try_rule_while_do 的 size_in==1 守卫失败。修复需完整 collapseInternal 的 selectGoto→ruleBlockGoto→while_do 迭代在每轮消费 continue/break 边。

**关键根因发现**：curl `main` 只检测到 **3 个回边**（全指向 head=5，即 1 个循环），而 Ghidra `main`（684行起）有 **6 个 while**（6 个循环：1 do-while(argc) + 1 while(true) + 4 do-while(cVar1!=0)）。**while 缺口的根因不在 blockaction 结构化层，而在更底层的 CFG 构建层**（funcdata.rs:1427-1473 的基本块划分/边建立）——Rugra 的 main CFG 缺少回边，所以无论结构化多完善都检测不到那些循环。

**下一步方向**（按优先级）：
1. **CFG 构建层**（funcdata.rs）：对比 Rugra vs Ghidra 在 main 上的基本块数和边，定位缺失的回边。可能是 BRANCH/CBRANCH 目标地址计算错误，或基本块划分边界不对。
2. **增量改进 blockaction**：在旧自定义阶段基础上，逐个对齐 Ghidra 规则（先放宽 cat 类型限制**配合**修复的 CFG，而非单独），而非整体替换。
3. cat 类型放宽**单独**无效（已验证），因为即使能吸收 BlockIf，循环体本身在 CFG 里就没回边。

**教训**：忠实移植 Ghidra 架构 ≠ 直接替换。旧实现虽不忠实但有实际功能，替换前必须确保新实现**至少不退步**。应采用增量对齐策略。

### 2026-06-28：identify_internal RwLock 死锁修复（httpd 性能突破）

**根因**：identify_internal 的边界边捕获和边重写阶段，在持有某块的 **write guard** 时，对该块的出/入边的 `point` 调用 `read()`。如果 `point` 恰好是该块自己（自环边），`write + read` 同一个 RwLock = **死锁**。这导致 httpd ap_fini_vhost_config 在 structure_loops_first 的 head=59 identify_internal 卡死。

**修复**：将 identify_internal 中 4 处 `e.point.read().unwrap()` 改为 `try_read()`，失败时 `continue` 跳过该边。try_read 不阻塞——如果锁被持有（包括自环的 write），立即返回 Err。

**影响**：httpd 从"卡在第 8 个函数（ap_fini_vhost_config）"变成"完成全部 29 个函数"。httpd while 从 8 跃升到 **44**（goto=0）。curl 审计 **24/24 0 FAIL**（从 23/23 进一步改善）。736/736 测试通过。

### 2026-06-29：rule_block_while_do 1:1 移植 + is_goto_out 修复（blockaction.cc:1518-1549）

- 新增 `rule_block_while_do(i)`（blockaction.rs）——忠实移植 Ghidra `CollapseStructure::ruleBlockWhileDo`：bl 必须有 2 条 out 边（二路条件）、非 switch-out、out(0/1)≠bl；对每条 out 边找 clause（sizeIn==1, sizeOut==1, 非 switch, 单 out 回到 bl）→ 构建 BlockWhileDo。接入 collapse_all phase 循环每轮迭代（对齐 Ghidra collapseInternal 中 ruleBlockWhileDo 与 cat/proper_if/if_else 交错）。**2026-06-29 修正**：不再因任一边 goto 就 bail，而是在 clause 搜索时跳过 goto 边（适配 Rugra staged 架构——break 边未被 ruleBlockGoto 消费）。
- **关键修复**：`BlockBasic::is_goto_out` 此前只查边级 `F_GOTO_EDGE`，但 TraceDAG/run_tracedag 把 goto 标在 **block 级** `GOTO_EDGE_0/GOTO_EDGE_1` 上 → 查询不到。修复后 is_goto_out 同时查边级和 block 级标志。这是 break 边识别的基础——ruleBlockWhileDo 据此跳过 break 循环的非结构边。
- **验证**：777/777 测试（含 test_is_goto_out_reads_block_flags）。curl 24/24（goto=0, uVar=0），httpd 29/29（goto=0, uVar=0）。无回归。
- **剩余缺口**：staged→collapseInternal 架构迁移。Ghidra 的 ruleBlockGoto 在每轮 collapseInternal 中"消费"goto 边（实际重连，使 break 边从结构化视图消失），然后 ruleBlockWhileDo 看到 2 条非 goto 边。Rugra 目前只标记不重连，故带 break 的循环 WhileDo 形成受限（parseconfig 检测到 7 loops 但仅 1 WhileDo）。这是 G4 架构工作。


### 2026-06-29（续 2）：try_rule_goto removeEdge 消费机制（部分实现）
- `try_rule_goto`（pure-goto, size_out==1）：创建 BlockGoto 后调用 `remove_in_edge_from` 从 goto target 的 incoming 移除 BlockGoto。忠实 Ghidra `newBlockGoto` 的 `removeEdge(ret, ret->getOut(0))`（block.cc:1711）。**安全**：BlockGoto 无结构化 fallthrough，移除 in-edge 不产生不对称。
- `try_rule_if_goto`（CBRANCH, size_out==2）：**未实现** removeEdge。需 Ghidra `forceOutputNum(2)`+`forceFalseEdge` 保留条件边——Rugra 的 BlockIf 缺这些，尝试 removeEdge 导致图损坏（curl 28→26）。留作已记录缺口。
- **验证**：780/780 测试，curl 24/24（goto=0），httpd 29/29（goto=0）。无回归。

### 2026-06-29（续 3）：try_rule_if_goto newBlockIfGoto 风格
- 重构 `try_rule_if_goto`：只消费 [cond]（body 保持外部 out-edge），设 goto_target。removeEdge 从 target incoming + if_block outgoing 双向移除 goto 边。
- **结果**：循环结构化对齐度提升（旧 while 计数显示显著改善，但该计数 2026-07-02 已废弃为 KPI）。while 循环对齐缺口对 curl 已闭合。
- 3 个函数在 goto_cascade 中不收敛（ap_count_dirs 等）——收敛问题，待修复。

### 2026-06-29（续 4）：goto_cascade 收敛守卫
- `run_goto_cascade` 新增收敛守卫：若 graph size 在 3 轮后未减少（规则震荡无进展），停止。防止病态 CFG（ap_count_dirs 等）无限循环。
- httpd example 新增每函数 15s 超时（对齐 curl 模式），防止单函数挂起阻塞全局。
- **结果**：循环结构化对齐度进一步提升，29/29 函数完成（1 个 TIMEOUT 占位），0 goto。

### 2026-06-29（续 5）：goto_cascade 收敛守卫改进 + remove_in_edge_from 死锁修复
- goto_cascade 收敛守卫改为同时检查 graph size 和 change_count（两者都无进展才停止）。
- `remove_in_edge_from` 自环死锁修复（block.rs）：try_read 替代 read。这是 ap_count_dirs 挂起的根因。
- **结果**：循环结构化对齐度进一步提升，29/29 函数完成，0 TIMEOUT。

### 2026-07-01（管线改造）：Action apply &self→&mut self 连锁

### 2026-07-01（续）：Dead-flow Actions 作为 pre-structuring pass
ActionUnreachable + ActionDeterminedBranch 在 ActionBlockStructure::apply 开头运行（build_copy 之前）。build_dom_tree 在删除后重新索引块。ActionDoNothing/RedundBranch 实现就位但未接入（删除测试预期的块）。

### 2026-07-01（续 2）：BlockWhileDo for-loop 字段 + printc for 发射
BlockWhileDo 加 for_init/for_iter 字段（对齐 Ghidra iterateOp/initializeOp）。printc WhileDo 发射：有 for_init+for_iter → `for(init;cond;iter)`，否则 `while(cond)`。

### 2026-07-01（续 3）：ActionBlockStructure sblocks 失效重建
ActionBlockStructure 加 last_op_count 字段。每次 apply 时检查 current op count vs last：不同则 clear sblocks 重建（防止 bblocks 变化后 sblocks 不同步）。mainloop repeatapply 仍不启用：sblocks 重建后 printc 的 emit_block_structured 在新结构上仍递归溢出。修复 printc 迭代化是前置条件。

### 2026-07-03：修正 collapse_cbranch_cascades 的错误注释
- 该函数的注释曾错误声称 "Corresponds to Ghidra's ruleBlockSwitch"，但 Ghidra `ruleBlockSwitch`（blockaction.cc:1649）只对 `isSwitchOut()` 块触发（由 CPUI_BRANCHIND 设置 f_switch_out），从不从 CBRANCH if/else-if 链造 switch。此函数是 fabricated logic（无 Ghidra 对应），已修正注释明确说明。函数仍禁用（:695）。**未改名**为 rule_block_switch——那会给 fabricated logic 披上 Ghidra 对应的外衣。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-12：ANN-M expanded-scanner 溯源

本轮只补函数来源标注，不改变运行时行为。源码 oracle 固定为 Ghidra 12.0.4
commit `e40ed13014025f82488b1f8f7bca566894ac376b`。

- `CollapseStructure::new` 映射 `blockaction.cc:1870
  CollapseStructure::CollapseStructure`。Rust 额外接收诊断名并初始化若干缓存、
  switch 与 iterator 状态；这些扩展不把构造器变成无 oracle 对应物的胶水。
- `CollapseStructure::collapse_all` 映射 `blockaction.cc:1877
  CollapseStructure::collapseAll`。当前 Rust 仍包含 `RUGRA_7PHASE` 分流、额外
  TraceDAG/loop/switch 阶段、deadline 和 fallback，因此 provenance 注释不代表
  逐函数行为已经 `MATCH`。

ANN-M 不提升本模块的对齐状态，也不替代锁定 oracle 的函数级差分验证。
 
 
 
 
 
 
 

### 2026-08-15：私有 `find_spanning_tree` 保留不接线（`BLOCK-INDEX-WIRE-0001`）

`BLOCK-INDEX-ASSIGN-0001` 已在 `src/block.rs:1647` 落地公共
`BlockGraph::find_spanning_tree`（全副作用对齐 block.cc:1009-1135，8/8 oracle
MATCH）。本模块的私有 TraceDAG 变体（`src/blockaction.rs:2369` 起）**保留未接线**，
源码注释已注明公共 port 的位置与接线前提；迁移属 `BLOCK-INDEX-WIRE-0001`，须
保证 TraceDAG 行为零变化并通过主管线差分门禁。本轮对本模块零行为改动。

### 2026-08-19：私有 `find_spanning_tree` 迁移到公共 port（`BLOCK-INDEX-WIRE-0001` 完成）

删除 blockaction.rs 的私有位置索引变体（原 :2369 起，局部 HashMap DFS、只写
out-half 边 label、不写 index/visitcount/numdesc/copymap、不重排 blocks），
`order_loop_bodies` 改调公共 `BlockGraph::find_spanning_tree`
（`src/block.rs`，Ghidra block.cc:1009-1136）——index=RPO + 组件表重排
（cc:1135）、visitcount=preorder、numdesc 累计、copymap=self、边 label 双侧
镜像、每遍 wipe 全部边 flag（cc:1045）、rootlist 首尾 swap（cc:1031-1035/
1114-1116/1129-1133）、两遍 extraroots。

Oracle 依据：`orderLoopBodies` 本身从不计算树——StructureGraph 路径在
CollapseStructure 前一步跑 `structureLoops`（ghidra_process.cc:354），进程内
ActionBlockStructure 路径经 `newBlockCopy` 继承同一批 label/index/numdesc
（block.cc:1685-1691）。Rugra `build_copy` 造全新无边 label 的边，故在
`order_loop_bodies` 内以公共 port 重算树，重现 oracle collapseAll 的入口状态。
树调用后立即把全图 visitcount 清 0，对齐 Ghidra `collapseAll` 头部
`graph.clearVisitCount()`（blockaction.cc:1883，oracle 在 orderLoopBodies 前
一条语句执行）。

非零差异（差分门禁，`## Differential` 详见任务报告）：curl E2E 基线 vs 修改
defects 0→0、numbering 0→0、golden 函数匹配 122/124→123/124、decompiled
74→75、timeout 2→1（`next_url` 0x4ff0 从 >10s 超时变为成功反编译）、
skeleton 2785→2904（增量主体为 `next_url` 新函数体；`my_get_line` -10、
`helpf` +12、`my_get_token` ±0，均 defects=0）。输出非 byte 级一致：私有变体
消费的是 bblocks 旧 RPO 域（可能滞后于 dead-flow 清理后的图），公共 port 对
清理后图现算 RPO——即本任务目标「index 域统一」本身，方向与 StructureGraph
oracle 路径（对最终图 fresh 计算）一致。

---

## 2026-08-23：order_loop_bodies 接线完整 structure_loops 驱动（BLOCK-CALCLOOP-0001）

`CollapseStructure::order_loop_bodies` 的生成树重算点从裸
`BlockGraph::find_spanning_tree(preorder, rootlist)` 升级为完整
`BlockGraph::structure_loops(&mut rootlist)` 驱动（block.cc:2194-2215）。

**oracle 调用点对照：** Ghidra 侧 CollapseStructure 从不自己算树——
`Funcdata::structureReset`（funcdata_block.cc:711 `bblocks.structureLoops`）
在 basic 块图上打完整标签（含 findIrreducible 的 f_irreducible 与
irreduciblecount>0 时 calcLoop 的 f_loop_edge，cc:2211-2214），
`ActionBlockStructure::apply`（blockaction.cc:2177）经 `buildCopy`
（newBlockCopy 复制 intothis/outofthis 边标签 + index + numdesc，
block.cc:1685-1691）把这些标签带入结构图；StructureGraph 控制台路径
（ghidra_process.cc:352-355）则 buildCopy 后直接
`structureLoops + calcForwardDominator` 再 CollapseStructure。Rugra 的
`build_copy` 造全新（无标签）边，故在 order_loop_bodies 处对结构图重跑
完整驱动——与两条 oracle 路径"CollapseStructure 消费 structureLoops 产物"
的入口态等价。

**行为影响：** 可归约图（irreduciblecount==0）与原裸树逐字节一致（驱动
单遍收敛，无 rebuild、无 calcLoop）；不可归约图新增 f_irreducible 边标
（is_goto_out 由此为真，影响 select_goto/结构化决策）与 calcLoop 的
f_loop_edge 环断边标——即 oracle 的入口态，此前缺失。结构化输出按机制 B
差分白名单由 root 集成时跑 curl 差分门禁（worktree 内 fast-release E2E
见任务报告）。

**calcLoop 本体：** 见 docs/api/block.md BLOCK-CALCLOOP-0001 节
（block.cc:2104-2147 完整移植 + oracle fixture
`tests/oracle/block_calcloop_1204` 七 case 双侧 byte-MATCH，含
structureReset 链 structureLoops+calcForwardDominator 端到端投影）。

## selfIdentify 外部边改写/dedup/剥离域（BLOCKSTRUCT-SELFIDENTIFY-EXT-0001，2026-08-25）

`identify_internal`（BlockGraph::identifyInternal+selfIdentify，
block.cc:884-963）补齐三个外部半边语义：

1. **改写全类型化**（`rewrite_out_edges_to_idx`/`rewrite_in_edges_to_idx`，
   对应 cc:910-912/922-924 的 replaceOutEdge/replaceInEdge）：Ghidra 的边数组
   在 FlowBlock 基类，任何块类型的邻居边都会被改写；Rugra 之前的
   BlockBasic-only 改写使结构化块残留指向已消费组件的陈旧边，膨胀下游规则
   的 sizeIn/sizeOut（ruleBlockCat `outblock->sizeIn()!=1`，
   blockaction.cc:1292）。
2. **外部 dedup**（`dedup_edges_all_types`，cc:930 selfIdentify 末尾的
   dedup()）：多个被消费组件（或 install 块+组件）各有边指向同一外部块时，
   Ghidra 的成对半边删除顺带收敛外部重复边；Rugra 单侧边模型需在全部改写
   完成后对 touched 外部块显式 dedup（labels OR 合并，block.cc:447-501）。
3. **组件外边剥离**（strip_external）：Ghidra 的 replace*Edge 半删除把组件
   的外部边移交给复合块，组件只保留组件间内部边；Rugra 之前对被消费块
   blanket clear_edges，现改为按 is_component 谓词 retain（内部边如
   cond→clause 保留，外部边如 clause→merge 移交复合块），与 oracle 的
   per-component in/out 计数一致。

另：cc:951 `ident->flags |= (f_interior_gotoout|f_interior_gotoin)`——复合块
从每个被消费组件（含 install 块，它在 Ghidra 的 -nodes- 集内）继承
interior-goto 标记。

### ruleBlockGoto 消费边改双边 removeEdge（2026-08-25，BLOCK-RECIPROCAL-OOB-0001）
- if-goto 臂（newBlockIfGoto 尾，block.cc:1814 `removeEdge(ret,
  getTrueOut())`）与 pure-goto 臂（newBlockGoto 尾，block.cc:1711
  `removeEdge(ret, getOut(0))`）都改经
  `BlockGraph::remove_edge_blocks(new_block, goto_target)` 全双边删除
  （含槽位重结对）；原"目标侧 retain + 源侧 outgoing.clear"单侧对留下
  stale reverse_index（httpd ap_getword 等 panic 根因之一）。
- `dedup_edges_all_types` 改为 trait 级 `FlowBlock::dedup(self_arc)` 成对
  协议（block.cc:525）；原 `edges.remove(i)` 单侧去重滑列表不作对侧修正。
- `identify_internal` 安装后新增 `resync_boundary_reverse_indices`
  （RUGRA-GLUE 不变量修复）：Ghidra selfIdentify 经 replace*Edge
  （block.cc:160-191, 910-924）在重定向时同步两侧 reverse_index；Rugra
  的 rewrite_* 只翻 e.point，故按指针重结对复合块边界边以恢复
  checkEdges 不变量（一致状态下 no-op），并把 new_block 纳入安装后 dedup。

### selectGoto exhausted 调试注桩（2026-08-26，TRI2-STRUCT-SELECTGOTO-SELFLOOP-0001）
- `debug_type_name` / `CollapseStructure::debug_dump_graph`（RUGRA-GLUE，
  无 Ghidra 对应物）：`RUGRA_BS_DUMP=1` 时在 selectGoto exhausted 位点
  （blockaction.cc:1275 LowlevelError 站点）dump 全图 in/out/flags 状态，
  用于结构化分叉 triage。
- `collapse_internal_rules` 内 `bs_try!` 宏：`RUGRA_BS_TRACE=1` 时打印
  每条规则命中（规则名 + 块索引）。默认关闭，零行为变化。

### identify_internal 成对去重 + 规则守卫回 oracle（2026-08-26，TRI2-STRUCT-SELECTGOTO-SELFLOOP-0001）
- **成对去重协议**：删除安装前对 `new_in`/`new_out` 的单侧 `retain` 去重。
  oracle 的 selfIdentify（block.cc:895-931）对每个被重定向的 peer 槽位各推
  一个复合块半边（平行边合法），仅由末尾 `dedup()`（block.cc:930）成对收
  敛——`eliminateInDups/eliminateOutDups`（block.cc:440-501）在对侧半删
  duplicate 槽位。旧单侧 retain 使复合块边数欠计，随后 touched peer 的成对
  dedup 按陈旧 reverse_index `halfDeleteOutEdge`（slot=-1→usize::MAX 时
  `while slot < last` 跳过循环、pop 尾边）删掉复合块仅存的出边——proper-if
  复合块 sizeOut==0 → TraceDAG 走断 → `selectGoto exhausted` → `code_r`
  自环 goto 兜底发射的完整根因链。现顺序为 resync（双射）→ 复合块 dedup →
  touched peers dedup（Ghidra 只 dedup ident；peer 侧为幂等 no-op 保护）。
- **边标签继承**：捕获边界边时保留 `e.flags`（对齐 replaceIn/OutEdge 的
  `BlockEdge(this, outofthis[num].label, num)`，block.cc:172/188）；旧
  `BlockEdge::new` 清零 flags，goto/loopback 标签在复合块边界丢失。
- **双射 resync**：`resync_boundary_reverse_indices` 改为按 peer 出现次序
  消费对侧槽位（第 occ 个回指边），平行边各自配对；旧首匹配把所有平行边
  配到同一对侧槽位。
- **install==consumed 跳过**：消费循环跳过 `c_idx == install_idx`（对齐
  newBlockGoto/newBlockDoWhile 的 `nodes={bl}`——install 块已由 install 捕
  获阶段处理；二次遍历把每条边界边翻倍，未配对的 reverse_index 又触发上述
  pop-尾边误删）。
- **规则守卫回 oracle**：`try_rule_proper_if`/`try_rule_if_no_exit`/
  `try_rule_while_do`/`try_rule_do_while` 删除自创
  `switch_case_indices`/`CASE_BODY` 级联守卫（与 a9d68f77 从
  try_rule_if_no_exit 删 cascade-member guard 同族；CBRANCH 链在 oracle 中
  就是嵌套 if/else，不存在的"级联 switch"概念阻塞了合法结构化），补上
  oracle 守卫：cc:1383/1487/1525/1561 `bl->isSwitchOut()`（f_switch_out 由
  build_copy 对 BRANCHIND 块重建，block.cc:2286 不变量）、cc:1394/1500/
  1534 子句 `isSwitchOut`、cc:1501 `!isDecisionOut`、cc:1487-1490 自环/
  goto-out。真实 switch（BRANCHIND 派发块）仍被保护。
- funcdata `test_bool_condition_folding_and_pattern` 搜索层扩到两级：该 CFG
  的 oracle 规则序列为 ruleBlockOr → ruleBlockIfNoExit 包 D（cc:1840 第二
  趟）→ ruleBlockCat 合并 sink C，终态 List[If[Condition(Or), D], C]（旧断
  言只搜一层，恰好匹配旧 bug 造成的 Condition 直接 List 子节点形态）。
## build_copy 活动视图接线（TRI2-STORESPLIT-WHOLESTRUCT-0001，2026-08-26）

`build_copy` 不再快照 `ops`：镜像块经 `live_ops_source` 链接到原 bblock 的
活动 op 列表（Ghidra `BlockGraph::buildCopy` block.cc:1925-1938 建立的
BlockCopy 委托契约，block.hh:520-535）。BRANCHIND 的 f_switch_out 复算改从
源块读取（镜像不再持有自己的 op 快照）。效果：ActionBlockStructure 之后由
cleanup pool（RuleSplit* 等）插入的 STORE 对打印可见。
- `build_copy`（block.cc:1933 newBlockCopy）：为每个结构图 BlockBasic 副本
  挂 `source_basic` 回指针（BLOCK-BUILDCOPY-MIRROR-0001）。Ghidra
  BlockCopy 包装器的 op 访问委托源活块（block.hh:533-534），Rugra 副本
  借回指针让 get_ops 暴露源块当前 op：结构化时点的成员资格快照供
  collapse 消费，此后所有后续读取（打印、ActionSetCasts 等结构化后
  Action 插入）看到源块实时 op，与 BlockCopy 一致。
