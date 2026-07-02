# 批1 P0 函数级对齐审计报告（2026-07-02）

> 纯只读并发审计。每个子 Agent 负责一个 .rs 文件，逐函数对照 Ghidra .cc/.hh。
> 判定档：✅ALIGN / ⚠️DIFF / ❌MISSING / ➕EXTRA。
> 本文件汇总 7 个 Agent 的报告原文（blockaction 重跑中）。修复不在本轮——本表是修复阶段的输入清单。

## 跨文件头号根因（按 ROI 排序）

| # | 根因 | 文件:行 | 直接症状 | Ghidra 对照 |
|---|---|---|---|---|
| R1 | **`create_entry` 不回写 Symbol/HighVariable/ScopeInternal**，只 push 到游离 `Vec<LocalSymbol>` | varmap.rs:1435 | StackX_ 名占位 | varmap.cc:617-628 `addSymbol` |
| R2 | **`fake_input_symbols` 用 `param_{:x}` 字面名** | varmap.rs:1561 | 48 个 `param_` 占位 | varmap.cc:1440 空名+makeNameUnique |
| R3 | **`direction` 符号反转**（x86 应 +1，Rugra -1） | varmap.rs:1278,1345,558 | 边界判断颠倒 → 名字错 | varmap.cc:700 |
| R4 | **mainloop/fullloop 丢 `rule_repeatapply`**（每 Action 只跑一次） | action.rs:797,816 | Action 不收敛 | coreaction.cc:5487,5489 |
| R5 | **`ActionNameVars` 是空桩** | coreaction.rs:3613-3643 | 无语义名 → 全部占位 | coreaction.cc:2779-3006 |
| R6 | **`ActionSetCasts` 被注释掉 + 只移植 castInput** | action.rs:868 + coreaction.rs:2704 | cast 114 vs 339 | coreaction.cc:2349-2774 |
| R7 | **StackSolver/StackEqn/analyzeExtraPop 完全缺失** | coreaction.rs:5204 | RSP 泄漏 | coreaction.cc:25-318 |
| R8 | **func_link_input 注册 0 个 ParamActive trial** | coreaction.rs:4906 | CALL 参数丢失 | coreaction.cc:1490-1491 |
| R9 | **RuleTrivialArith 实现错误**（做了 RuleIdentityEl 的活，没做 `x^x→0`） | ruleaction.rs:321-386 | `switch((iVar1^iVar1))` | ruleaction.cc:2382-2433 |
| R10 | **系统性 dispatch 缺口**：3 个"适用于所有 opcode"的 Rule 注册不全 | action.rs:174,400 | DCE/常量折叠大面积失效 | ruleaction.hh:93/710/730 |
| R11 | **op-edit API 语义损坏**：set_input/destroy/unset_input 不维护 descend 链 | funcdata.rs:554,612,577,713 | DCE 静默失败、僵尸节点 | funcdata_op.cc:104,203,291,92 |
| R12 | **merge 缺 HighIntersectTest + 强制合并 snip 机制** | merge.rs:350,645 | 过度阻止合并 → uVar 爆炸 | merge.cc:1616,489-810 |
| R13 | **tracedag `select_bad_edge` siblingedge 极性反转 + distance 公式错** | tracedag.rs:475,453 | 错标 goto/结构化失败 | blockaction.cc:620,524 |
| R14 | **tracedag `check_open` 用总入度而非 loop-DAG 入度** | tracedag.rs:181 | 节点打不开 | blockaction.cc:810 |

---

## 报告 1: varmap.rs ↔ varmap.cc/.hh（Agent 完成）

**Summary**: Rust fns ~52 | Ghidra ~63 | ✅18 ⚠️13 ❌21 ➕5

**Headline**: QUALITY_GAP 的指控**经核实且被低估**。`grep -c HighVariable src/varmap.rs == 0` 确认。`LocalSymbol` 是游离结构，无 Varnode↔Symbol 链接，无 HighVariable 合并。

**Pipeline 接线核查**: 部分接入但消费端是死的。coreaction.rs:439-441 ActionRestructureVarnode 建 ScopeLocal → restructure_varnode → sync_varnodes_with_symbols；但 sync 只匹配 **Stack-space** varnode（printc.rs:2775 承认 Rugra lift 不产 Stack-space），且只设 DIRECT_WRITE 代理，不挂 Symbol。

**关键 MISSING（21 个）**: reconcileDatatypes, addGuard(LoadGuard/StoreGuard), gatherSymbols, collectNameRecs, annotateRawStackPtr, checkUnaliasedReturn, resetLocalWindow, isUnmappedUnaliased, remapSymbol, remapSymbolDynamic, recoverNameRecommendationsForSymbols, applyTypeRecommendations, addTypeRecommendation, addRecommendName, getSpaceId, isUnaffectedStorage, deriveBoundaries(桩), gather(公开入口), AliasChecker::gather 等。

**关键 DIFF**:
- `adjust_fit` 只查 symbol 重叠，无 `getRangeTree().longestFit`（cc:593）→ 超大 range 保留
- `build_variable_name` 缺 `sign_extend`/`printNameBase`/`'Y'` 分支
- `mark_not_mapped` 无 wrap/clamp、无 symbol-table removeRange、无 category
- `mark_unaliased` 无 RangeList walk、无 `alias_block_level`
- `fake_input_symbols` 无 `getParamRange().inRange` gate（cc:1407）

**全文**: 见会话内 Agent 报告（已逐条核对）。

---

## 报告 2: blockaction.rs ↔ blockaction.cc/.hh — ❌ Agent 失败，重跑中

---

## 报告 3: coreaction.rs PART1（StackPtrFlow+prototype Actions）

**Summary**: In-scope 22 Rust / 28 Ghidra | ✅5 ⚠️11 ❌10 ➕2

**Headline**: `ActionStackPtrFlow` 是真移植但**只一半**——clog-repair 半（isStackRelative/adjustLoad）忠实，整个 **StackEqn/StackSolver/analyzeExtraPop 完全缺失**（src/ 全无代码）。`ActionLaneDivide` 纯桩且未注册（死代码）。**CALL 参数恢复结构性损坏**：func_link_input 从不注册 ParamActive trial → ActionActiveParam 迭代 0 trial → 48 个 param_N 占位。`ActionNonzeroMask` 缺最高影响 opcode（INT_ADD carry、MULTIEQUAL、INT_SRIGHT、INT_DIV/REM）。

**Pipeline 注册核查（关键）**: Action 注册分两处，且**两套 builder 不一致**：
- 真管线 `set_default_actions`（action.rs:771-873）
- 补充 `build_full_pipeline_actions`（coreaction.rs:7011-7068）
- **mainloop/fullloop 用 `ActionGroup::new` 而非 `rule_repeatapply`**（action.rs:797,816）→ 每 Action 只跑一次，Ghidra 跑到收敛。`stackstall` 是唯一保留 repeatapply 的。

**逐函数表（节选关键 DIFF/MISSING）**:
| Ghidra | Rust | 判定 |
|---|---|---|
| StackSolver::propagate/solve/build/duplicate (cc:67-252) | — | ❌MISSING（全部） |
| ActionStackPtrFlow::analyzeExtraPop (cc:261-318) | — | ❌MISSING |
| ActionStackPtrFlow::repair (cc:378-422) | rs:5277-5325 | ⚠️ 前向扫整 alivelist，非 Ghidra 的后向块前驱走 |
| ActionStackPtrFlow::checkClog (cc:432-479) | rs:5351-5398 | ⚠️ 缺 INT_MULT×(-1) 解包 |
| ActionLaneDivide::apply (cc:585-622) | rs:5588-5593 | ⚠️ 纯桩，且未注册 |
| ActionFuncLink::funcLinkInput (cc:1474-1513) | rs:4906-4936 | ⚠️ 不注册 trial、无 IPTR_SPACEBASE、无 spacebase placeholder、无 varargs |
| ActionFuncLink::funcLinkOutput (cc:1521-1572) | rs:4955-4989 | ⚠️ 无 stack-output-lock、无 assumedOutputExtension |
| ActionActiveParam::apply (cc:1725-1771) | rs:4357-4398 | ⚠️ 无 AliasChecker::gather、无 finalInputCheck |
| ActionActiveReturn::apply (cc:1773-1792) | rs:4407-4465 | ⚠️ 从不调 buildOutputFromTrials（方法不存在） |
| ActionReturnRecovery::buildReturnOutput (cc:1836-1906) | — | ❌MISSING |
| ActionPrototypeTypes::extendInput (cc:4590-4607) | — | ❌MISSING |
| ActionNonzeroMask/calcNZMask INT_ADD carry 臂 (cc:732-738) | rs:1742-1800 | ⚠️ 缺 INT_ADD/MULTIEQUAL/SRIGHT/DIV/REM/POPCOUNT/LZCOUNT 臂 |

---

## 报告 4: coreaction.rs PART2（其余 Action）

**Summary**: In-scope ~38 Action | ✅10 ⚠️28 ❌9 ➕6

**Headline**: **(1) `ActionSetCasts` 被注释出管线**（action.rs:868）且只移植 castInput——castOutput/resolveUnion/testStructOffset0/tryResolutionAdjustment/checkPointerIssues/PTRADD-PTRSUB-fit/insertPtrsubZero/markExplicitUnsigned/LongSize 全缺 → cast 114 vs 339。**(2) `ActionNameVars` 纯桩** → 全部占位名。**(3) mainloop/fullloop 不跑 repeatapply**。

**注册核查（关键发现）**:
- `ActionSetCasts` — **注释掉**（action.rs:868）
- `ActionNameVars`/`ActionMapGlobals`/`ActionMarkIndirectOnly` — 桩 + 未注册
- 5 个 merge Action 折叠进一个 `ActionMergeType::merge_all`，各自 struct 是死代码
- 4 个 standalone Action（HideShadow/DominantCopy/CopyMarker/AssignHigh）与 merge_all 内部**重复执行**

**逐函数表（节选）**:
| Ghidra | Rust | 判定 |
|---|---|---|
| ActionSetCasts::castOutput/resolveUnion/testStructOffset0/tryResolutionAdjustment/checkPointerIssues/insertPtrsubZero (cc:2349-2774) | rs:2704-2834 | ⚠️CRITICAL 只 castInput，且未注册 |
| ActionNameVars::linkSymbols/lookForFuncParamNames/makeRec/lookForBadJumpTables/linkSpacebaseSymbol/apply (cc:2779-3006) | rs:3613-3643 | ❌CRITICAL 纯桩 |
| ActionRestructureVarnode::protectSwitchPaths/protectSwitchPathIndirects (cc:2174-2295) | rs:425-451 | ⚠️ 全缺 |
| ActionDeadCode (cc:3925) gatherConsumedReturn/markConsumedParameters/lastChanceLoad/neverConsumed/autoLive | rs:171-274 | ⚠️ 缺多项 consume 路径 |
| ActionConstantPtr (cc:957-1217) | rs:279-324 | ⚠️ 严重简化，无 isPointer/space-attribute/infer-space |
| ActionConditionalConst (cc:4069-4546) + 9 helpers | rs:5521-5541 | ❌MISSING（全桩） |
| ActionSegmentize/ForceGoto/MapGlobals/DynamicMapping/DynamicSymbols/LikelyTrash | rs 各处 | ❌/⚠️ 多为桩 |
| ActionInferTypes propagateSpacebaseRef/propagateRef/propagateTypeEdge/applyTypeRecommendations (cc:5008-5416) | rs:2850-3603 | ⚠️ 缺空间基引用传播 |

➕EXTRA: ActionCopyPropagate/ActionCse/ActionSimplify/ActionInferParams/ActionTypeInfer/ActionTypePropagate — Rugra 本地替代，注释自承 "TODO replace with Ghidra mechanisms"。

---

## 报告 5: ruleaction.rs PART1（arithmetic+bool Rules）

**Summary**: 审计 105 个 Rule 类（算术+布尔/位运算）| Ghidra 共 142 个 Rule，其中 6 个 Ghidra 自己也注释掉了 → **0 真正 MISSING** | ✅~88 ⚠️8 ❌3(子情形) ➕1

**Headline**:
- **P0 `switch((iVar1^iVar1))` 文档诊断错**。不是 RuleXorCollapse 的锅（它只处理比较内的 `(V^W)==0`）。`x^x→0` 自消除是 **RuleTrivialArith**（ruleaction.cc:2382-2433, line 2413 INT_XOR 案）的活。**Rugra RuleTrivialArith 根本实现错了**——它做了 RuleIdentityEl 的活（`x+0→x`），从未做 `x^x→0`。get_opcodes 也错（Rust 5 个 vs Ghidra 16 个）。
- **phase-separation 修复完整正确**。oppool1 注册 Rule2Comp2Mult/RuleSub2Add；独立 cleanup 池注册 RuleMultNegOne/Rule2Comp2Sub——精确镜像 coreaction.cc:5552/5553 vs 5696/5698。无 ping-pong。

**逐 Rule 表（节选关键）**:
| Rule | 判定 | 说明 |
|---|---|---|
| **RuleTrivialArith** | ❌SEVERE | 做了 RuleIdentityEl 的活；get_opcodes 5 个 vs Ghidra 16 个；从不 `x^x→0`。**switch((x^x)) 的直接根因** |
| RuleIdentityEl | ⚠️ | get_opcodes 多 INT_SUB/INT_AND（Ghidra 无）；INT_AND 的 `V&0→COPY(V)` 是正确性 bug（应为 0）|
| RuleXorCollapse | ✅ | 忠实（原被怀疑，洗清）|
| Rule2Comp2Sub | ⚠️ | 算法完全不同：Ghidra 把 2COMP 并入 loneDescend 的 INT_ADD→SUB 再销毁；Rugra 把 2COMP 改成 `0-W`。池正确所以不循环 |
| RuleDivChain | ⚠️ | 不设 in(0)=baseVn；缺 isFree/resval==0/signbit 溢出守卫 |
| RuleSLess2Zero | ❌ | case1 缺 INT_AND feedOp + INT_LEFT feedOp 子情形 |
| RuleEqual2Zero | ⚠️ | 缺 isHeritageKnown 守卫 |
| RuleSubNormal | ⚠️ | "shrink the cut" 未应用 → c_new 错 |
| RuleEarlyRemoval | ⚠️ | 6 守卫齐全✓，但 dispatch 只覆盖 9 opcode（Ghidra 全 opcode）|

---

## 报告 6: ruleaction.rs PART2（shift/concat/ptr/struct/misc Rules）

**Summary**: 审计 ~70 个 Rule | ✅~55 ⚠️9 ❌0 ➕1 | 6 个 Ghidra 也注释掉的 Rule 正确省略

**Headline**: **P0 指针/结构规则移植质量高**——RulePtrsubUndo（5 helpers 全移植）、RulePtrFlow（完整，`has_truncations=false` 对 x86-64 是正确的）、RulePieceStructure（6 helpers）。**RuleEarlyRemoval 6 守卫齐全**。StackX_ 问题**不在此层**（varmap/ActionStackPtrFlow 层）。

**关键发现**:
| Rule | 判定 | 说明 |
|---|---|---|
| **系统性 dispatch 缺口** | ❌ | RuleEarlyRemoval/RulePropagateCopy/CollapseConstants 是"全 opcode"Rule，但 Rust `get_opcodes()` 无法表达。Rule::applies_to_all() 应为默认 true，ActionPool 应把全适用 Rule 加入每 opcode 列表 |
| **RuleShiftBitops** | ❌ | 完全错实现：做 trivial-shift-by-0（重复 RuleTrivialShift），Ghidra 是 NZM-based 位运算操作数消除（pcode_left/right+calc_mask），全缺 |
| **RulePropagateCopy** | ❌ | 算法+范围都错：Ghidra 迭代任意 op 的输入、若输入是 COPY 输出则替换；Rugra 只在 COPY 上触发、向后代推。缺 isReturnCopy/isMarker 守卫 |
| **RuleIdentityEl** | ⚠️ | get_opcodes 多 INT_AND（`V&0→COPY(V)` 错，应为 0）；缺 BOOL_XOR/BOOL_OR |
| RuleLeftRight | ⚠️ | 硬编码 `Address::new(0x1000)` 而非 `shiftin->getAddr()+renormalize` |
| RulePtrsubUndo/PtrFlow/PieceStructure/PtrArith/StructOffset0/PtraddUndo | ✅ | 忠实 |

---

## 报告 7: tracedag.rs + merge.rs

**Summary A (tracedag)**: 18 Rust / ~26 Ghidra | ✅~7 ⚠️8 ❌7 ➕2
**Summary B (merge)**: ~36+5 / ~44 | ✅~6 ⚠️16 ❌~16 ➕4

**tracedag Headline**: 骨架忠实且已接线，但 3 个结构化关键机制偏离：(1) `check_open` 用**总入度**而非 Ghidra 的**loop-DAG 入度**（visit-count 机制）；(2) `open_branch` 加了 2 个 Ghidra 没有的启发（`target<=dest` 错——block 索引非拓扑序；`opened.contains`）；(3) `select_bad_edge` **siblingedge 极性反转**，且用 depth-diff 替代 Ghidra 的 `BranchPoint::distance`（common-ancestor 走）。

**merge Headline**: `merge_all` **确实被调用**（action.rs:864 → ActionMergeType → merge_all），非死代码。但合并**结构性浅**：整个**强制合并+snip 机制**（mergeOp/mergeIndirect/trimOpInput/trimOpOutput/allocateCopyTrim/snipReads/eliminateIntersect/unifyAddress/mergeRangeMust）和 **HighIntersectTest 缓存**（含 StackAffectingOps 二级测试 + VariablePiece）全缺。强制合并要么静默跳过要么无 snip 强合（产生同时活跃实例）；投机合并用原始 cover 交集（过度阻止 Ghidra 会允许的合并）。**直接导致 uVar_ 占位爆炸**。

**tracedag 关键修复**:
1. P0 `check_open` (rs:181-205): 换成 Ghidra 的 per-edge 只数 `is_loop_dag_in` 边（block.hh:345）；加 finishblock+set_finish_block
2. P0 `open_branch` (rs:273,275): 删 `target<=dest`（索引非拓扑序，错跳前向边）和 `opened.contains`（Ghidra 无）；删 opened 集合
3. P0 `select_bad_edge` (rs:475,453): siblingedge 极性反转（取小不取大）；移植真 `BranchPoint::distance` via markPath；加 3-key 排序
4. P1 `remove_trace` (rs:364): 移植 parentbp->paths 槽压缩 + derivedbp->pathout 修复；BlockTrace 加 derivedbp 字段

**merge 关键修复**:
5. P0 移植 HighIntersectTest+StackAffectingOps（merge.hh:52, merge.cc:1616-1647）→ uVar 爆炸最大单因
6. P0 移植强制合并 snip 机制（merge.cc:411-810）
7. P0 移植 mergeTestRequired/mergeTestAdjacent 谓词（merge.cc:102-220）——merge_test 现只查 space/size
8. P1 merge_addr_tied 换 overlapLoc+unifyAddress/mergeRangeMust（cc:609-648）
9. P1 merge_linear_speculative 加 compareHighByBlock 排序（merge.hh:152）
10. P1 hide_shadows 是空操作（rs:1217）——实现 opSetInput 改写（cc:1086-1096）
11. P1 去重管线：删 4 个死 ActionMerge* struct；协调 hide_shadows/dominant_copy/copy_marker 双执行

---

## 报告 8: funcdata.rs ↔ 4 个 funcdata_*.cc + .hh

**Summary**: Rust ~86 方法 | Ghidra ~127（4 文件）+ ~70 inline(.hh) | ✅~24 ⚠️~18 ❌~70+ ➕~6

**Headline**: **op-edit API 语义损坏**。Ghidra 在 opSetInput/opSetOutput/opDestroy 维护的 3 个核心不变量部分或完全未实现。注释（rs:561-562）承认 op_set_input 不清理被替换 Varnode 的 descend（"对 rule 可接受"——并不）。opSetInput 缺常量去重守卫；opSetOutput 不解绑已写 Varnode 的旧 def；opDestroy 不调 destroyVarnode（只清 def 链）。**全代码库 ~856 个 op-edit 调用点都在一个微妙的损坏图上操作**。

**引用准确度抽查**: 12/12 抽样精确（funcdata_op.cc:203-222 opDestroy 等）。

**逐函数表（节选 P0）**:
| Ghidra | Rust | 判定 | 说明 |
|---|---|---|---|
| opSetInput (cc:104-125) | op_set_input (rs:554-564) | ⚠️P0 | 替换 slot 不清旧 descend→DCE 静默失败；缺常量去重；fill-while-extend 双推 descend |
| opSetOutput (cc:70-87) | op_set_output (rs:597-606) | ⚠️P0 | 若 vn 已有 def，未先 opUnsetOutput 旧 def→两 op 同写一 Varnode |
| opDestroy (cc:203-222) | op_destroy (rs:612-628) | ⚠️P0 | 不调 destroyVarnode→输出成僵尸带陈旧读者 |
| destroyVarnode (varnode.cc:272-292) | — | ❌P0 | 缺失（op_destroy 依赖它）|
| opRemoveInput (cc:291-300) | op_remove_input (rs:577-582) | ⚠️P0 | 不先 opUnsetInput→残留 descend 反向引用 |
| opUnsetInput (cc:92-99) | op_unset_input (rs:713-720) | ⚠️P0 | 不 clearInput，只 retain descend——注释错 |
| pushMultiequals/branchRemoveInternal/blockRemoveInternal/opZeroMulti | — | ❌P1 | 整块块移除数据流补丁全缺→SSA 在分支/块移除后不一致 |
| spliceBlockBasic (cc:919-956) | splice_block_basic (rs:1218-1269) | ⚠️P1 | 不移动后继 ops→P-code 丢失 |
| calcNZMask (varnode.cc:856-926) | calc_nz_mask (rs:1712-1806) | ⚠️P1 | 单遍线性近似，非 DFS+worklist 不动点；多数 opcode 落 full_mask |
| flag enum (hh:57-73) | funcdata_flags (rs:15-25) | ⚠️P2 | 位值错（TYPE_RECOVERY_ON=1 vs 0x20）→无法 Ghidra 互通 |
| structureReset FFI (cc:705-742) | structure_reset (rs:1012-1022) | ⚠️P2 | 不发 rugra_check_block_structure FFI 调用 |

**额外发现**: combineInputVarnodes 在 totalReplace 前销毁输入（rs:260-261）→ 顺序 bug。opUndoPtradd 硬编码 8 字节而非 offVn->getSize()。

---

## 下一步

- **blockaction.rs** Agent 失败，单独重跑（见下一轮）
- 批2-6 待发起
- 修复阶段：从本表 14 个头号根因（R1-R14）按 ROI 攻。R9（RuleTrivialArith 重写）是单点最高 ROI——一行修正就能消掉 `switch((x^x))`。
