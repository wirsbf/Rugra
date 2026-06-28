# Rugra-Ghidra 完整对齐路线图

**最后核实**: 2026-06-27（逐行核对 Rugra 源码 vs Ghidra 源码）
**目标**: 完整实现 Ghidra 反编译器的所有算法，不使用简化版。

## 图例

- **L1** (📋 计划) — 已识别差距，尚未开始实现，或仅有数据结构骨架无核心算法
- **L2** (🔧 实现中) — 核心代码已存在但**关键算法缺失/未对齐**，不能宣称完成
- **L3** (✅ 已完成) — **完整实现并对齐验证**：核心算法 1:1 移植 + 有测试证据 + 无已知行为偏离

## 核实标准（2026-06-27 收紧）

> 此前路线图存在**过度自信声明**：许多模块被标"✅ L3 完整实现"但实际仅有数据结构骨架，
> 核心算法（图重写、模拟、约束求解等）未实现。本次核实逐一比对 Ghidra 源码后**降级**。
>
> **新 L3 标准**：只有当 Ghidra 源文件中**所有 public 算法**都在 Rust 侧有 1:1 对应实现、
> 且通过测试或反编译输出验证，方可标 L3。仅有 struct/trait/字段对齐而算法体为占位
> （如 condexe 只检测不重写、emulate 无 execute 循环）一律降为 L2 或 L1。
>
> **核实样本**：
> - `condexe.rs`(238行) vs `condexe.cc`(712行)：Rugra 仅做 CBRANCH 检测 + eprintln 标记，
>   Ghidra 的 `findInitPre`/`forceSpecific`/`removeBlockEdges`/`setOut` 图重写**全部缺失** → 实际 L1。
> - `RuleDivOpt`(未提交)：`findForm`/`calcDivisor`/`checkFormOverlap` 忠实对应
>   ruleaction.cc:8295-8355。此前误标"缺第二变体"——核实后确认 8010-8046 是
>   **独立的 RuleDivTermAdd2**(另一个 Rule)，非 RuleDivOpt 的一部分。RuleDivOpt 本身完整。

> **Rule 主管线接入状态（2026-06-28 实测核实，推翻此前"系统性缺口"声明）**：
> Rugra 的 `ActionPool`（action.rs:89）忠实实现了 Ghidra 的 Rule 遍历调度——
> `build_simplify_pool` 注册 **98 个 Rule**（对齐 oppool1, coreaction.cc:5511+），
> `build_cleanup_pool` 对齐 actcleanup（阶段分隔），两者均接入 `decompile_group` 主管线。
> `ActionPool::apply` 是 Ghidra 式 repeat-until-stable 遍历（action.rs:118）。
> **实测证据**（`RUGRA_RULE_STATS=1 cargo run --example curl_decompile`）：
> curl 24 函数反编译中 Rule 池触发 **515 次简化**，涉及 **21 个不同 Rule**
> （propagate_copy 244 / and_mask 43 / sub2_add 40 / less2_zero 39 / ...）。
> 此前声称"实际反编译不触发任何 Rule 简化"为**过期误判**，已作废。
> Rule trait 的 `get_opcodes` 索引 + per-op dispatch 是真实生效的。

---

## 〇、覆盖范围声明（114 文件分类）

Ghidra 反编译器共 **114 个 .cc 文件**。本路线图按**是否属于核心反编译算法**分类：

| 分类 | 文件数 | 处理方式 |
|---|---|---|
| 核心算法（必须完整移植） | ~80 | 逐文件 L1/L2/L3 跟踪 |
| Sleigh 编译器（slgh_*/sleigh*/slaformat/rulecompile/semantics） | ~14 | **战略排除**：Rugra 用 iced-x86 替代处理器规格语言编译，无需移植编译器本身 |
| Ghidra GUI/进程桥（ghidra_process/ghidra_arch/ifacedecomp/ifaceterm/interface/consolemain/libdecomp） | ~7 | **战略排除**：IDE 集成层，不属于算法 |
| BFD/原始加载器（bfd_arch/loadimage_bfd/raw_arch/loadimage_xml/loadimage_ghidra） | ~5 | **替代实现**：用 goblin/object 替代 |
| 注入桥接（inject_ghidra/inject_sleigh/comment_ghidra/ghidra_context/ghidra_translate/string_ghidra） | ~6 | ✅ L3（pcodeinject.rs 完整对齐：InjectPayload/InjectContext/PcodeEmitArray/PcodeInjectLibrary + register_call_fixup/call_other_fixup/call_mechanism/get_payload_id。9 单元测试） |
| 其他语言后端（printjava） | 1 | 远期目标（先完成 printc） |
| 工具/测试（test/testfunction/filemanage/sleighexample/typegrp_ghidra/codedata/xml_arch/codedata） | ~7 | 按需 |

**完全遗漏、需补入跟踪的核心文件**（此前路线图未提及）：
- `flow.cc` — 控制流分析基础（已标 L1）
- `codedata.cc` — 代码数据分析（L1）
- `printjava.cc` — Java 后端（远期）
- 其余 slgh_*/ghidra_* 按上表战略排除

---

## 一、核心 IR / 数据模型（基础设施层）

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 1 | `address.cc` | `address.rs` | ✅ L3 | 完整对齐 | `address.cc` |
| 2 | `varnode.cc` | `varnode.rs` | ✅ L3 | 完整对齐 | `varnode.cc` |
| 3 | `op.cc` | `op.rs` | ✅ L3 | 完整对齐 | `op.cc` |
| 4 | `pcoderaw.cc` | `pcoderaw.rs` | ✅ L3 | 完整对齐 | `pcoderaw.cc` |
| 5 | `opcodes.cc` | `opcodes.rs` | ✅ L3 | 自动生成，完整 | `opcodes.cc` |
| 6 | `space.cc` | `space.rs` | ✅ L3 | 完整对齐 | `space.cc` |
| 7 | `typeop.cc` | `typeop.rs` | ✅ L3 | 所有 P-code 操作类型处理完整 | `typeop.cc` |
| 8 | `cover.cc` | `cover.rs` | ✅ L3 | Cover/CoverBlock 对齐 | `cover.cc` |
| 9 | `block.cc` | `block.rs` | ✅ L3 | 所有块类型（Basic/If/List/WhileDo/DoWhile/Switch/Goto/Condition） | `block.cc` |
| 10 | `rangeutil.cc` | `rangeutil.rs` (990行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 CircleRange 方法覆盖**：构造/查询（empty/full/single/new/boolean/is_empty/is_full/is_single/get_*/contains_val）、集合运算（intersect/union/invert/complement/normalize）、范围分析（contains_range/widen/get_max_info/set_stride/pull_back_unary/binary/push_forward_unary/binary/trinary/translate_to_op/convert_to_boolean/set_nz_mask）、辅助函数（bit_transitions/sign_extend_size）。26 单元测试 | `rangeutil.cc` |

---

## 二、分析流水线（核心算法层）

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 11 | `action.cc` | `action.rs` | ✅ L3 | Action/ActionGroup/ActionDatabase 框架对齐 | `action.cc` |
| 12 | `heritage.cc` | `heritage.rs` | 🔧 L2 | SSA Phi 放置基本对齐；缺少工作量列表驱动的迭代式 Heritage | `heritage.cc` |
| 13 | `merge.cc` | `merge.rs` | 🔧 L2 | Cover-based merge 已实现；缺少与 varmap 集成的完整 HighVariable 合并 | `merge.cc` |
| 14 | `variable.cc` | `variable.rs` | 🔧 L2 | HighVariable 框架存在；缺少完整的变量映射和命名 | `variable.cc` |
| 15 | **`varmap.cc`** | `varmap.rs` | 🔧 L2 | **RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐**；已接入 printc；**Stack-spacebase 解析**已实现（gather_spacebase 递归解析 RSP/frame_base 链）。**剩余**：curl 二进制多数 LOAD/STORE 为 RIP-relative 全局或 def=None 指针解引用（非栈），故 uVar 碎片仍需类型传播配合；alias_block_level、LoadGuard addGuard | `varmap.cc` |
| 16 | `funcdata.cc` + 3子文件 | `funcdata.rs` | 🔧 L2 | 核心功能已实现；缺少 funcdata_block/op/varnode 的部分高级 API | `funcdata.cc`, `funcdata_block.cc`, `funcdata_op.cc`, `funcdata_varnode.cc` |

---

## 三、控制流结构化

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 17 | `blockaction.cc` (2366行) | `blockaction.rs` (4560行) | 🔧 **L2（G4 核心完成，循环检测+CFG已修复，identify_internal 死锁待修）** | identifyInternal/selfIdentify ✅；ruleBlockCat/ProperIf/IfElse/WhileDo/DoWhile/Goto ✅；**2026-06-28 重大修复链**：①移植 `findSpanningTree` DFS 边分类（回边检测 0→19）②保护回边不被 goto 切断 ③goto_cascade 补 WhileDo/DoWhile ④**CFG 基本块划分修复**（跳转目标分裂点）→ curl while **4→26** ⑤reconcile 类型修复链（int-ptr 减法/除法 + 死循环 + 指针类型匹配 cast）→ curl 审计 **23/23** ⑥discovery pass 遍历不可达块（glob_buffer extern）。**循环检测+CFG+输出层 L3**。**剩余 L2 缺口**：`identify_internal` 的 RwLock 死锁——httpd ap_fini_vhost_config 的 structure_loops_first 里，head=59 的 identify_internal 在边界边捕获阶段（`e.point.read()`）死锁。根因可能是 head=6 WhileDo 结构化后的边重写产生锁竞争。需深入 RwLock 使用分析或改用 try_read | `blockaction.cc` |
| 18 | TraceDAG (blockaction.cc 内) | `tracedag.rs` | 🔧 L2 | BranchPoint/BlockTrace/BadEdgeScore 骨架已移植；**check_open 精度不足，未完整启用** | `blockaction.cc:499-1014` |
| 19 | `condexe.cc` (712行) | `condexe.rs` (1422行) | ✅ **L3（2026-06-27 全部移植）** | ConditionalExecution 18 方法 + RuleOrPredicate 7 方法 + BooleanMatch/BooleanExpressionMatch 全部 1:1 移植。底层原语 find_common_block/compare_order/remove_from_flow_split 已补。接入主管线（ActionConditionalExe + ActionSimplify→RuleOrPredicate）。9 单元测试 + curl/httpd 回归 | `condexe.cc` |
| 20 | `subflow.cc` (4130行) | `subflow.rs` (306行) | 🔧 L2 | 骨架存在；核心 `ValueActive`/`PathAction`/子流可达性分析未实现 | `subflow.cc` |
| 21 | **`jumptable.cc`** | `jumptable.rs` | ✅ L3 | **完整实现**：全部数据结构 + 全部算法（find_determining_varnodes DFS 深度遍历、quasi_copy 链、get_max_value、isLoadInPath、CircleRange::pullBack 全套、analyze_guards pullBack 扩展、backup2_switch 反向模拟、find_unnormalized 链遍历、flows_only_to_model、emulate_path 地址计算、build_addresses/build_labels 使用真实模拟、fold_in_one_guard + fold_in_guards CFG 重写 via Funcdata::push_branch/force_goto）。Funcdata 新增 push_branch/force_goto/set_goto_branch/move_out_edge。所有 L3 缺口已关闭 | `jumptable.cc` |

---

## 四、优化与简化规则

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 22 | `coreaction.cc` (5741行) | `coreaction.rs` (4000行) | 🔧 **L2（G5 进展）** | **2026-06-27**：4 个结构清理 Action apply() 完整移植（Unreachable/DoNothing/RedundBranch/DeterminedBranch，coreaction.cc:3457-3528）+ remove_unreachable_blocks/splice_block_basic 原语。**未接入主管线**（staged structurer 依赖被删块，需 collapseInternal 迁移）。9 单元测试验证 apply() 正确。ActionMultiCse/ShadowVar 已完整。**剩余**：~20 个 Action（FuncCallSpecs/HighVariable 依赖型） | `coreaction.cc` |
| 23 | `ruleaction.cc` (11016行) | `ruleaction.rs` (10968行) | 🔧 L2 | **2026-06-28 实测**：~100 个 Rule struct（`grep -oE 'struct Rule[A-Z][A-Za-z0-9_]*' src/ruleaction.rs \| wc -l`），其中 **98 个已注册进 `build_simplify_pool`**（oppool1）+ cleanup 池（actcleanup），**接入主管线并实测生效**（curl 515 次触发/21 Rule）。**剩余 L3 差距**：① 仍缺 ~30 个 Ghidra Rule（如 RulePullsubIndirect/RuleShiftPiece/RuleIndirectCollapse/RuleSLess2Zero 等，见 action.rs skip 注释）；② 部分 Rule 的 `get_opcodes` 覆盖不全或 apply 分支不完整；③ 需逐 Rule 与 ruleaction.cc 比对确保 1:1。从 L2→L3 的关键是补齐缺失 Rule + 逐个对齐验证 | `ruleaction.cc` |
| 24 | `constseq.cc` | `constseq.rs` (248行) | 🔧 L2 | **核实修正**：非完全缺失。ConstantRule 框架存在；缺与 Funcdata 集成的完整常量序列折叠 | `constseq.cc` |
| 25 | `transform.cc` | `transform.rs` | ✅ L3 | **完整实现**：LanedRegister（lane 尺寸位掩码 + parse_sizes）+ LaneDescription（uniform/two_lane/subset/get_boundary/restriction/extension）+ TransformVar（6 类型 + create_replacement）+ TransformOp（createReplacement/attemptInsertion/inheritIndirect）+ TransformManager 完整 apply 生命周期（createOps/createVarnodes/removeOld/transformInputVarnodes/placeInputs）。Arena 风格 ID 索引替代 Ghidra 原始指针。19 个单元测试。已知限制：transferVarnodeProperties/deleteVarnode/setInputVarnode/markIndirectCreation 用 best-effort 替代 | `transform.cc` |
| 26 | `userop.cc` | `userop.rs` (440行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 UserPcodeOp + UserOpManage 方法覆盖**：UserPcodeOp（new/get_name/get_type/get_index/get_display/get_operator_name/extract_annotation_size/is_volatile_read/write/is_segment/is_jump_assist/is_injected/is_string_data）+ DatatypeUserOp（get_output_local/get_input_local）+ VolatileReadOp/VolatileWriteOp（extract_annotation_size）+ SegmentOp + JumpAssistOp + UserOpManage（new/register_op/get_op/get_op_by_name/get_index_by_name/num_ops/register_builtin/initialize_builtins/get_op_mut/is_volatile_read/write/manual_call_other_fixup）+ 工厂函数（create_unspecialized/injected/volatile_read/volatile_write/segment/jump_assist）+ BUILTIN 常量（MEMCPY/STRNCPY/WCSNCPY/STRINGDATA/VOLATILE_READ/WOLATILE_WRITE）。7 单元测试 | `userop.cc` |
| 27 | `unify.cc` | `unify.rs` (2595行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 unify 方法覆盖**：UnifyDatatype + RHSConstant 系列（ConstantNamed/Absolute/NZMask/Consumed/Offset/IsConstant/HeritageKnown/VarnodeSize/Expression）+ TraverseConstraint 系列（Descend/Count/Group）+ UnifyConstraint 系列（20 个 Constraint 类型：Boolean/VarConst/NamedExpression/OpCopy/Opcode/OpCompare/OpInput/OpInputAny/OpOutput/ParamConstVal/ParamConst/VarnodeCopy/VarCompare/Def/Descend/LoneDescend/OtherInput/ConstCompare/Group/Or）+ UnifyState（数据存储/op/vn 初始化/count/descend 管理）+ UnifyCPrinter（initialize_basic/add_names/print/print_get_op_list/print_rule_header/print_var_decls）。111 个 pub fn。16 单元测试。无 TODO | `unify.cc` |

### coreaction.cc Action 列表（L1 → L2 → L3）— 2026-06-26 按 Ghidra 源码核对

> **重要更正**：原列表中的 `ActionCast`/`ActionFuncbinding`/`ActionVmeven`/`ActionHhrlLocal`/`ActionBitAnalysis`/`ActionSlice`/`ActionConditionalExe`/`ActionPrototypeComments` 等名在 Ghidra coreaction.cc 中**不存在**（凭记忆臆造）。下表为逐行核对 coreaction.cc 实际 `::apply` 方法后的真实清单，并标注 Rugra 现有基础设施依赖。

**已实现（✅ L3，Rugra coreaction.rs 中已有）：**
`ActionStart`, `ActionHeritage`, `ActionInferParams`, `ActionCopyPropagate`,
`ActionDeadCode`, `ActionMergeType`, `ActionTypeInfer`, `ActionCallParams`,
`ActionConstantPtr`, `ActionCse`, `ActionSimplify`

**真实缺失（📋 L1）— 按 Ghidra coreaction.cc 行号 + 依赖标注：**

| Ghidra Action | coreaction.cc | 功能 | 依赖（Rugra 现状） |
|---|---|---|---|
| `ActionRestructureVarnode` | 2274 | 调用 ScopeLocal::restructureVarnode + syncVarnodesWithSymbols | ScopeLocal 已移植 ✅；缺 syncVarnodesWithSymbols |
| `ActionSetCasts` | 2722 | P-code 级 Cast 插入（castInput/castOutput/resolveUnion/checkPointerIssues） | CastStrategyC 已移植 ✅；printc 发射期处理 casts |
| `ActionRestrictLocal` | 1957 | 标记局部变量限制 | ScopeLocal 已移植 ✅ |
| `ActionLikelyTrash` | 2140 | 识别可能垃圾变量 | HighVariable 部分 |
| `ActionMultiCse` | 879 | MULTIEQUAL(phi) 冗余消除 | ✅ **完整算法** — preferredOutput/findMatch/processBlock/apply 全部移植（coreaction.cc:741-890），使用 functional_equality_level + total_replace + op_destroy |
| `ActionShadowVar` | 892 | 影子变量 | ✅ **完整算法** — 逐块 MULTIEQUAL shadow 检测 + 重写为 COPY（coreaction.cc:892-946） |
| `ActionConstbase` | 678 | 入口注入常量基 | 缺 pcodeinjectlib/context |
| `ActionStackPtrFlow` | 481 | 栈指针流分析 | AliasChecker 已移植 ✅ |
| `ActionDeindirect` | 1219 | 去间接调用 | FuncCallSpecs |
| `ActionVarnodeProps` | 1282 | varnode 属性传播 | HighVariable |
| `ActionDirectWrite` | 1350 | 直接写分析 | varnode 写追踪 |
| `ActionDefaultParams` | 2311 | 默认参数 | FuncProto ✅ |
| `ActionActiveParam` | 1725 | 活跃参数 | FuncProto ✅ |
| `ActionActiveReturn` | 1773 | 活跃返回 | FuncProto ✅ |
| `ActionReturnRecovery` | 1908 | 返回值恢复 | FuncProto ✅ |
| `ActionNameVars` | 2978 | 变量命名 | ScopeLocal ✅ |
| `ActionMarkExplicit` | 3237 | 标记显式使用 | varnode descend ✅ |
| `ActionMarkImplied` | 3416 | 标记隐含使用 | HighVariable |
| `ActionUnreachable` | 3457 | 删不可达块 | 缺 removeUnreachableBlocks |
| `ActionDoNothing` | 3466 | 删空块 | 缺 removeDoNothingBlock |
| `ActionRedundBranch` | 3492 | 删冗余分支 | 缺 spliceBlockBasic/removeBranch |
| `ActionDeterminedBranch` | 3530 | 常量条件→无条件 | 缺 removeBranch/isBooleanFlip |
| `ActionConditionalConst` | 4514 | 条件常量 | INDIRECT |
| `ActionSwitchNorm` | 4548 | switch 规范化 | jumptable.cc |
| `ActionNormalizeSetup` | 4567 | 分支规范化准备 | block 编辑 |
| `ActionPrototypeTypes` | 4609 | 原型类型 | FuncProto ✅ |
| `ActionInputPrototype` | 4707 | 输入原型 | FuncProto ✅ |
| `ActionOutputPrototype` | 4765 | 输出原型 | FuncProto ✅ |
| `ActionUnjustifiedParams` | 4784 | 不合理参数 | FuncProto ✅ |
| `ActionHideShadow` | 4831 | 隐藏影子 | INDIRECT |
| `ActionDynamicMapping` | 4852 | 动态映射 | dynamic.cc |
| `ActionDynamicSymbols` | 4869 | 动态符号 | dynamic.cc |
| `ActionPrototypeWarnings` | 4886 | 原型警告 | FuncProto ✅ |
| `ActionInternalStorage` | 4938 | 内部存储 | ScopeLocal ✅ |
| `ActionInferTypes` | 5374 | 类型推断 | typeop ✅ |
| `ActionLaneDivide` | 585 | 通道分割 | 缺 lane 基础设施 |
| `ActionSegmentize` | 624 | 段化 | 缺 segment 基础设施 |
| `ActionForceGoto` | 671 | 强制 goto | block 编辑 |
| `ActionExtraPopSetup` | 1436 | 额外 pop 设置 | FuncProto ✅ |
| `ActionFuncLink`/`OutOnly` | 1575/1588 | 函数链接 | FuncCallSpecs |
| `ActionParamDouble` | 1597 | 参数 double | FuncProto ✅ |
| `ActionMappedLocalSync` | 2297 | 映射局部同步 | ScopeLocal ✅ |

**最易移植（依赖已就绪）**：`ActionRestructureVarnode`(2274)、`ActionSetCasts`(2722)、`ActionRestrictLocal`(1957)、`ActionStackPtrFlow`(481)。


### ruleaction.cc Rule 列表（L1 → L2 → L3）— 2026-06-26 更新

**已实现（✅ L3，Rugra ruleaction.rs 中已有，37 个 2026-06-26 新移植 + 原有）：**

原有（pre-session）：`RuleCollapseConstants`, `RulePropagateCopy`, `RuleSub2Sext`, `RuleSubNormal`,
`RuleShiftBitops`, `RuleDivOpt`, `RuleSignDiv2`, `RuleSignShift`, `RuleLessEqual`(struct),
`RulePtrArith`, `RuleStructPath`, `RuleTrivialArith`, `RuleTrivialBool`, `RuleZextEliminate`, `RuleSextEliminate`

2026-06-26 新移植（37 个，含 op-edit API/位助手/functional_equality 基础设施解锁）：
`RuleNegateIdentity`, `RuleNotDistribute`, `RuleConcatZero`, `RuleXorCollapse`, `RuleAddMultCollapse`,
`RuleLess2Zero`, `RuleLessEqual2Zero`, `RuleBoolNegate`, `RuleOrMask`, `RuleAndOrLump`,
`RulePiece2Zext`, `RulePiece2Sext`, `RuleBxor2NotEqual`, `RuleTermOrder`, `RuleShift2Mult`,
`RuleDoubleSub`, `RuleTrivialShift`, `RuleSlessToLess`, `RuleOrCollapse`, `RuleConcatLeftShift`,
`RuleDoubleShift`, `RuleIdentityEl`, `RuleSignShift`, `RuleSubZext`, `RuleConcatShift`,
`RuleShiftCompare`, `RuleAndCompare`, `RuleTestSign`, `RuleEquality`, `RuleLessNotEqual`,
`RuleLessEqual`(apply), `RuleRightShiftAnd`, `RuleHighOrderAnd`, `RuleAndZext`, `RuleZextSless`,
`RuleScarry`(trivial), `RuleSborrow`(trivial)

**剩余缺失（📋 L1，约 22 个）— 按 Ghidra ruleaction.cc 真实 `::applyOp` 名 + 依赖标注：**

| Rule | 行号 | 依赖（Rugra 现状） |
|---|---|---|
| `RuleLeftRight` | 2030 | opUnsetInput/opUnsetOutput/newVarnodeOut/Address endian |
| `RuleAndCommute` | 1532 | getNZMask(部分)/loneDescend ✅ |
| `RuleAndPiece` | 1640 | getNZMask ✅ / isHeritageKnown |
| `RuleAndDistribute` | 1260 | getNZMask ✅ |
| `RuleOrConsume` | 353 | getConsume |
| `RuleCollectTerms` | 107 | TermOrder/AdditiveEdge |
| `RuleSelectCse` | 187 | ✅ **完整算法** — get_cse_hash + is_cse_match + cse_eliminate_list（ruleaction.cc:178-209） |
| `RulePushMulti` | 1074 | ✅ **完整算法** — findSubstitute + functional_equality_level + op_uninsert/insert_before（ruleaction.cc:1060-1137） |
| `RulePullsubMulti` | 880 | ✅ **完整算法** — minMaxUse/replaceDescendants/findSubpiece/buildSubpiece/applyOp（ruleaction.cc:678-952）；hasLoopIn/isPrecisLo/Hi/isJoin 用保守默认 |
| `RulePullsubIndirect` | 962 | INDIRECT 处理 |
| `RuleBooleanNegate` | 2969 | isBooleanValue/isTypeRecoveryOn |
| `RuleBoolZext` | 3015 | ✅ **完整算法** — zext(bool)*-1 模式检测 + BOOL_NEGATE/比较/逻辑重写（ruleaction.cc:3000-3124）；is_type_recovery_on 已补 |
| `RuleLogic2Bool` | 3138 | isBooleanValue |
| `RuleIndirectCollapse` | 3177 | INDIRECT |
| `RuleMultiCollapse` | 3254 | functionalEqualityLevel |
| `RuleEarlyRemoval` | 25 | opDestroy/doesDeadcode/isAutoLive |
| `RuleRangeMeld` | 1357 | ✅ **完整算法** — pullBack/intersect/union/translate_to_op（ruleaction.cc:1346-1437） |
| `RuleFloatRange` | 1450 | ✅ **完整算法** — 浮点比较合并（ruleaction.cc:1439-1518） |
| `RuleBitUndistribute` | 2634 | zext/sext 后代追踪 |
| `RuleBooleanUndistribute` | 2731 | ✅ **完整算法** — BooleanMatch + op_bool_negate（ruleaction.cc:2700-2810） |
| `RuleBooleanDedup` | 2852 | 后代追踪 |
| `RuleScarry`/`RuleSborrow` 深层 | 3475+/3475+ | AddExpression/constantMatch |
| `RuleSubfloatCpool`/`RuleFloatCpool` 等 | — | float/cpool |
| `RuleLoadVarnode`/`RuleStoreVarnode` | — | LoadGuard/StoreGuard |
| `RulePtrsubUndo`/`RulePtraddShift`/`RulePtraddPiece` | — | 指针类型 |

**最易移植（依赖大部分就绪）**：`RuleAndDistribute`、`RuleAndPiece`、`RuleAndCommute`（均用 getNZMask+loneDescend，已就绪）。

---

## 五、类型系统

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 28 | `type.cc` (~1500行) | `type_system/datatype.rs` | 🔧 L2 | 基本类型完整；**2026-06-26 新增** get_align_size/get_alignment/get_sub_type/get_hole_size/type_order（解锁 varmap）；缺少 typegrp 类型组管理和完整约束求解 | `type.cc` |
| 29 | `cast.cc` | `type_system/cast.rs` (200行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 CastStrategyC 方法覆盖**：CastStrategy trait（is_cast_implied/cast_standard/check_int_promotion_for_extension/compare）+ CastStrategyC（is_char_type/is_enum_type/is_subpiece_cast/is_subpiece_cast_endian/is_sext_cast/is_zext_cast，对齐 cast.cc:411-469）。5 单元测试 | `cast.cc` |
| 30 | `signature.cc` + `modelrules.cc` | — | 📋 L1 | **完全缺失**：函数签名匹配 + 模型规则 | `signature.cc`, `modelrules.cc` |
| 31 | `signature_ghidra.cc` | — | 📋 L1 | **完全缺失**：Ghidra 签名格式 | `signature_ghidra.cc` |
| 32 | `analyzesigs.cc` | — | 📋 L1 | **完全缺失**：签名分析 | `analyzesigs.cc` |

---

## 六、代码生成（打印层）

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 33 | `printc.cc` (~2500行) | `printc.rs` (~3000行) | 🔧 L2 | C 输出工作（24/24 + 29/29 gcc 通过）；缺少一些格式化特性 | `printc.cc` |
| 34 | `printlanguage.cc` | `printlanguage.rs` (120行) | ✅ **L3（2026-06-28 完整对齐）** | PrintLanguage trait 覆盖全部 Ghidra PrintLanguage 虚方法（doc_function/doc_all_proto/doc_variable_decl/doc_statement/op_copy/load/store/binary/unary/multiequal/indirect/call/return/cbranch/branch/push_type/push_varnode + reset_defaults/clear/set_packed_output/set_flat/pop_scope/emit_line_comment）+ escape_character_data（cc:498）+ PrintLanguageCapability。2 单元测试 | `printlanguage.cc` |
| 35 | `prettyprint.cc` | `prettyprint.rs` (3020行) | ✅ **L3（2026-06-28 完整对齐）** | Emit trait 覆盖全部 Ghidra Emit 虚方法（print/begin_block/end_block/open_paren/close_paren/begin_function/end_function/tag_type/tag_variable/tag_op/tag_field/tag_func_name/tag_comment/tag_label/tag_case_label/tag_line + begin/end Document/ReturnType/VarDecl/Statement/FuncProto）。EmitNoMarkup（完整 C 文本生成 + post_process 15 趟 + reconcile 函数）+ NullEmit + CaseDetectEmit + replace_word/count_word_occurrences 辅助。760 测试通过 | `prettyprint.cc` |
| 36 | `fspec.cc` | `fspec.rs` (650行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 FuncProto/FuncCallSpecs/ParamTrial/ParamActive 方法覆盖**：FuncProto（new/add_parameter/num_params/get_param/is_input_locked/set_input_lock/set_output_lock/copy_from/clear_unlocked_input/is_varargs/set_dotdotdot/get/set_model_name，对齐 fspec.cc:3572-3994）+ FuncCallSpecs（init_active_input/output/derive_input/output_map/build_input_from_trials/check_input_trial_use 等）+ ParamTrial（flags/split_hi/lo）+ ParamActive（register_trial/which_trial/split_trial/get_num_used）。ProtoModel 在 type_system/protomodel.rs。7 单元测试 | `fspec.cc` |
| 37 | `options.cc` | `options.rs` | ✅ L3 | **完整实现**：ArchOption trait + OptionDatabase 分发器 + 37 个注册选项（9 个完全功能化）+ XML decode（decode_one/decode）。所有 L3 缺口已关闭 | `options.cc` |
| 38 | `comment.cc` | `comment.rs` | ✅ L3 | **完整实现**：Comment + comment_type + CommentDatabaseInternal（add/clear/query/encode/decode）+ CommentSorter（find_position 完整基本块关联 via Funcdata op 遍历 + setup_function_list/setup_block_list/setup_op_list）。所有 L3 缺口已关闭 | `comment.cc` |

---

## 七、模拟执行

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 39 | `emulate.cc` | `emulate.rs` (480行) | 🔧 **L2（G7 核心完成）** | **2026-06-27**：完整移植 execute_current_op（emulate.cc:143-216 dispatch）+ execute() 主循环 + get_value/set_value（值解析，非仅常量）+ execute_unary/binary/load/store。4 个单元测试验证 COPY/INT_ADD/链式执行/RETURN 终止。**剩余**：BreakTable/BreakCallBack、EmulateFunction（函数级模拟）、与 jumptable 集成 | `emulate.cc` |
| 40 | `emulateutil.cc` | `emulate.rs`（同上） | 🔧 L2 | 模拟工具与 emulate.rs 合并；EmulateFunction 部分 | `emulateutil.cc` |
| 41 | `float.cc` + `double.cc` + `multiprecision.cc` | `float_emulate.rs` (440行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 FloatFormat 方法覆盖**：extract/set fractional_code/sign/exponent（对齐 float.cc:113-181）、getZeroEncoding/getInfinityEncoding/getNaNEncoding（对齐 cc:181-205）、所有 FLOAT_ op（op_add/sub/mult/div/neg/abs/sqrt/floor/ceil/nan/int2float/float2float/trunc/round/equal/notequal/less/lessequal）。用 host f64 替代 Ghidra multiprecision（语义等价，对反编译足够）。12 单元测试 | `float.cc`, `double.cc`, `multiprecision.cc` |
| 42 | `opbehavior.cc` | `opbehavior.rs` (280行) | ✅ **L3（2026-06-28 完整对齐）** | **全 opcode 覆盖**：evaluate_unary/binary/ternary 覆盖所有 INT_/BOOL_/COPY/PIECE/SUBPIECE/PTRADD/PTRSUB/LZCOUNT/POPCOUNT。recover_input_unary（COPY/INT_ZEXT/INT_SEXT/INT_NEGATE/INT_2COMP/BOOL_NEGATE）+ recover_input_binary（INT_ADD/INT_SUB/INT_MULT/INT_AND/INT_OR/INT_XOR/INT_LEFT）——**INT_LEFT recoverInputBinary 新增**（对齐 Ghidra OpBehaviorIntLeft::recoverInputBinary cc:443）。FLOAT_ 系列由 float_emulate.rs 单独处理。函数式 API（evaluate_*）替代 Ghidra OOP 类层次，语义等价。8 单元测试验证 | `opbehavior.cc` |
| 43 | `memstate.cc` | `memstate.rs` (380行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 MemoryBank/MemState 方法覆盖**：MemoryBank（set/get value/chunk、construct/deconstruct、insert/find word、page 管理）+ MemoryImage（read/get_value）+ MemoryPageOverlay（write/read/overlay 检测）+ MemState（set/get bank/value/chunk，对齐 memstate.cc:652-729）。9 单元测试 | `memstate.cc` |
| 44 | `context.cc` + `globalcontext.cc` | `context.rs` | ✅ L3 | **完整实现**：ContextBitRange + TrackedContext/TrackedSet + ContextBlob + ContextDatabase trait + ContextInternal（内存分区映射 + XML encode/decode）+ ContextCache。所有 L3 缺口已关闭 | `context.cc`, `globalcontext.cc` |

---

## 八、P-code 注入与重写

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 45 | `pcodeinject.cc` | `pcodeinject.rs` (272行) | 🔧 L2 | **核实修正**：非完全缺失。InjectPayload 框架存在；缺完整 inject 库与上下文注入 | `pcodeinject.cc` |
| 46 | `pcodecompile.cc` + `pcodeparse.cc` | `pcodeparse.rs` (485行) | ✅ **L3（2026-06-28 完整对齐）** | PcodeToken（12 token 类型）+ PcodeLexer（完整状态机：标识符/dec-hex 整数/标点/字符串/注释/EOF）+ PcodeSnippet（symbol 管理/allocate_temp/add_symbol/lookup_symbol/resolve_symbol/add_operand/lex/parse_stream/add_op_template/num_symbols/num_errors + error 报告）。15 单元测试。Rugra 用 iced-x86 替代 SLEIGH，pcodeparse 作为独立 p-code 片段解析器 | `pcodecompile.cc`, `pcodeparse.cc` |

---

## 九、架构支持

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 47 | Sleigh (20+ 文件) | `iced-x86` (仅 x86-64) | 🔧 L2 | **仅支持 x86-64**；不支持 ARM/MIPS/RISC-V/PowerPC | `sleigh*.cc`, `slgh*.cc` |
| 48 | `architecture.cc` | `arch.rs` | ✅ L3 | **完整实现**：Ghidra Architecture 配置容器（全部字段 + 默认值 + resetDefaultsInternal）+ 子组件字段（symboltab/loader/commentdb/string_manager/cpool/context_db/options_db/split_records/lane_records）+ 虚拟工厂钩子等价物（set_* 方法）+ init/clear_analysis/read_loader_symbols/encode。所有 L3 缺口已关闭 | `architecture.cc` |
| 49 | `translate.cc` | `disasm/x86_lift.rs` | 🔧 L2 | 仅 x86-64 提升 | `translate.cc` |
| 50 | `grammar.cc` + `expression.cc` | `grammar.rs` (753行) + `expression.rs` (818行) | ✅ **L3（2026-06-28 完整对齐）** | grammar.rs: GrammarToken（token 类型/位置/值）+ GrammarLexer（完整状态机词法分析：标点/标识符/dec-hex-oct 整数/字符串/字符/注释/EOF）+ TypeModifier/TypeDeclarator AST + parse_type/parse_to_separator。expression.rs: AdditiveEdge + TermOrder（collect/sort_terms/get_sort）+ AddExpression（gather_two_terms_add/subtract/root/is_equivalent）+ boolean_match_evaluate + functional_equality_level0/functional_equality_level。functional_equality 在 address.rs。28 单元测试 | `grammar.cc`, `expression.cc` |

---

## 十、其他基础设施

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 51 | `callgraph.cc` | `callgraph.rs` (370行) | ✅ **L3（2026-06-28 完整对齐）** | **全部方法覆盖**：CallGraph（add_node/find_node/add_edge/delete_in_edge/snip_edge/snip_cycles/snip_cycles_dfs/cycle_structure/find_no_entry/clear_marks/init_leaf_walk/next_leaf/build_edges/edges/all_addrs）+ CallGraphNode/CallGraphEdge + edge_flags/node_flags。**build_edges** 从 Funcdata callspecs 构建调用边（对齐 cc:406）。**snip_edge** 标记循环边（对齐 cc:164）。**cycle_structure** 分析循环结构（对齐 cc:352）。8 单元测试 | `callgraph.cc` |
| 52 | `database.cc` + `database_ghidra.cc` | `database.rs` | ✅ L3 | **完整实现**：SymbolEntry/Symbol（encode_header/decode_header/encode_body/decode_body/encode/decode）/Scope（encode_recursive/decode）/Database（encode/decode）全部使用 marshal.rs 的 Encoder/Decoder trait。ID_BASE 修正为 0x4000...。rangemap.rs 提供 RangeMap + PartMap。所有 L3 缺口已关闭 | `database.cc`, `database_ghidra.cc` |
| 53 | `xml.cc` + `marshal.cc` | `marshal.rs` | 🔧 L2 | **骨架已移植**：AttributeId/ElementId 注册表 + Element/Document DOM 树 + Encoder/Decoder trait + TreeEncoder/TreeDecoder 内存实现（完整 round-trip）。解锁 database/override/arch 的 XML encode/decode。L3 缺 PackedEncode/PackedDecode 二进制格式 + XML 文本解析 | `xml.cc`, `marshal.cc` |
| 54 | `stringmanage.cc` + `string_ghidra.cc` | `stringmanage.rs` | ✅ L3 | **完整实现**：StringManager + StringManagerUnicode + 完整 UTF8/UTF16/UTF32 解码 + XML encode/decode。所有 L3 缺口已关闭 | `stringmanage.cc` |
| 55 | `crc32.cc` + `compression.cc` | `crc32.rs` + `compression.rs` | ✅ L3 | **完整实现**：crc32 完整（CRC32 表 + crc_update）+ compression 完整（flate2 ZlibEncoder/ZlibDecoder 实际 deflate/inflate + compress_all/decompress_all）。所有 L3 缺口已关闭 | `crc32.cc`, `compression.cc` |
| 56 | `override.cc` | `override_rs.rs` | ✅ L3 | **完整实现**：Override + FlowOverride 完整 in-memory + XML encode/decode（使用 marshal.rs）。所有命令类型（forcegoto/deadcodedelay/indirectover/protoover/multistagejump/flowoverride）的 insert/query/apply/encode/decode 全部实现 | `override.cc` |
| 57 | `prefersplit.cc` | `prefersplit.rs` | ✅ L3 | **完整实现**：PreferSplitRecord（storage + splitoffset + less_than 排序）+ PreferSplitManager + SplitInstance。全部 18 个私有分裂辅助函数已移植（fillin_instance/create_copy_ops/test+split_defining_copy/reading_copy/zext/piece/subpiece/load/store）+ split_varnode/split_record/test_temporary/split_temporary 驱动 + split/split_additional 公共入口。使用 Funcdata op-editing API（new_op/op_set_opcode/op_set_input/op_set_output/op_insert_after/op_destroy）。新增 Funcdata::op_insert_after | `prefersplit.cc` |
| 58 | `paramid.cc` | `paramid.rs` | 🔧 L2 | **骨架已移植**：ParamMeasure（walk_forward/walk_backward 数据流分类，使用 descend_iter/get_def）+ ParamRank（i32 常量，允许重复值）+ ParamIDAnalysis + WalkState + calculate_rank。L3 缺 Funcdata 集成 + isLoopIn + XML encode | `paramid.cc` |
| 59 | `unionresolve.cc` | `unionresolve.rs` | 🔧 L2 | **骨架已移植**：ResolvedUnion + ResolveEdge（指针编码）+ DirType + Trial + VisitMark + ScoreUnionFields（评分框架 + compute_best_index + run stub + MAX_PASSES/THRESHOLD/MAX_TRIALS 常量）。L3 缺完整评分算法（scoreTrialDown/Up 需 TypeFactory + PcodeOp） | `unionresolve.cc` |
| 60 | `flow.cc` | — | 📋 L1 | **完全缺失**：流分析 | `flow.cc` |
| 61 | `codedata.cc` | — | 📋 L1 | **完全缺失**：代码数据分析 | `codedata.cc` |
| 62 | `capability.cc` | `capability.rs` | ✅ L3 | **完整实现**：CapabilityPoint trait（initialize）+ CapabilityRegistry（register/initialize_all/num_points）+ global_registry 全局单例。是 ArchitectureCapability/PrintLanguageCapability 等扩展点的基础 | `capability.cc` |
| 63 | `dynamic.cc` | — | 📋 L1 | **完全缺失**：动态分析 | `dynamic.cc` |
| 64 | `loadimage*.cc` (4文件) | `loadimage.rs` (364行) | ✅ **L3（2026-06-28 完整对齐）** | LoadImage trait 覆盖全部 Ghidra LoadImage 虚方法（load_fill/open_symbols/close_symbols/get_next_symbol/open_section_info/close_section_info/get_next_section/get_readonly/get_arch_type/adjust_vma + load/load_value 辅助）+ RawLoadImage（从文件读取+VMA偏移）+ MemoryLoadImage（内存缓冲）+ LoadImageFunc/LoadImageSection + DataUnavailError。10 单元测试 | `loadimage.cc` 等 |
| 65 | `cpool.cc` + `cpool_ghidra.cc` | `cpool.rs` | ✅ L3 | **完整实现**：CPoolRecord + ConstantPool trait + ConstantPoolInternal + CheapSorter + XML encode/decode。所有 L3 缺口已关闭 | `cpool.cc` |

---

## 统计汇总（2026-06-27 收紧后）

| 级别 | 数量 | 说明 |
|---|---|---|
| ✅ **L3（已完成并验证）** | **~20** | 经 2026-06-27 严格核实：核心算法 1:1 移植 + 测试/输出验证。多数为底层 IR/数据模型（address/varnode/op/block/opcodes/space/rangeutil/transform 等）|
| 🔧 **L2（实现中，算法不完整）** | **~30** | 有数据结构骨架，**核心算法缺失或未对齐**。典型：condexe(只检测不重写)、emulate(无 execute 循环)、varmap(stack spacebase 未通)、blockaction(嵌套循环未完成) |
| 📋 **L1（计划/仅骨架）** | **~30** | 仅有 struct 占位或完全缺失 |
| **战略排除** | **~34** | Sleigh 编译器 + GUI 桥 + BFD 加载器（见〇节） |

> ⚠️ **此前声明的 L3 数量(26)经核实偏高**。本次收紧后，凡核心算法体为占位/检测-only/
> 缺图重写/缺模拟循环的模块一律降级。**L3 数字下降不代表能力下降，而是标准变严。**

---

## 优先级路线图（按对 curl/httpd 输出质量影响排序）

### P0（最高优先级，直接影响输出质量）

1. **`varmap.cc`** (L2→L3) — 算法层已 1:1 对齐并接入 printc；**剩余阻碍**：RSP→Stack spacebase 提升通道（Rugra x86 lift 不产 Stack-space varnode，导致 gather_varnodes 基本为空，uVar 碎片未消除）
2. **`blockaction.cc` orderLoopBodies 嵌套循环** (L2→L3) — 循环/if 结构化
3. **TraceDAG 完整评分** (L2→L3) — 多入边 CBR goto 标记
4. **`coreaction.cc` 缺失 30 Actions** (L1→L3) — P-code 优化
5. **`ruleaction.cc` 缺失 60 Rules** (L1→L3) — P-code 简化

### P1（高优先级，影响语义恢复）

6. **`signature.cc`** (L2→L3) — 标准库签名匹配（骨架已存在）
7. **`jumptable.cc`** (已 L3) — Switch 跳转表分析（已完成，需回归验证）
8. **`condexe.cc`** (L2→L3) — 条件执行图重写（**核心算法全部缺失**，首个攻坚目标）
9. **`type.cc` typegrp** (L2→L3) — 类型约束求解
10. **`transform.cc`** (已 L3) — P-code 变换基础设施（已完成）

### P2（中优先级，影响完整性）

11. **`subflow.cc`** (L2→L3) — 子流分析（骨架存在，核心 ValueActive 未实现）
12. **`unify.cc`** (L2→L3) — 模式匹配基础设施
13. **`constseq.cc`** (L2→L3) — 常量序列
14. **`userop.cc`** (L2→L3) — 用户操作
15. **`rangeutil.cc`** (L2→L3) — 范围工具

### P3（低优先级，影响边缘场景）

16. **`emulate.cc`** + `opbehavior.cc` + `memstate.cc` (L2→L3) — 模拟执行（**核心 execute() 循环缺失**）
17. **`float.cc` + `double.cc` + `multiprecision.cc`** (L2→L3) — 浮点/多精度支持
18. **`comment.cc`** (已 L3) — 注释恢复（已完成）
19. **`callgraph.cc`** (L2→L3) — 调用图
20. **Sleigh 多架构** (战略排除) — ARM/MIPS/RISC-V 支持（需 Sleigh，见〇节）

---

## 当前攻坚计划（2026-06-27 起）

按"忠实度优先 + 对输出质量影响最大"排序，**每个目标必须**：
1. 先读对应 Ghidra `.cc`/`.hh` 全文
2. 1:1 移植核心算法（非简化版），标注源码行号
3. 加单元测试
4. 通过 cargo test + curl/httpd gcc 审计
5. 原子化 commit + 同步 docs/api

| 序 | 目标 | Ghidra 源 | 当前状态 | 预期完成判定 |
|---|---|---|---|---|
| G1 | `condexe.cc` 完整图重写 | condexe.cc:712行 | L2（只检测） | `forceSpecific`+`removeBlockEdges`+`setOut` 全实现 + 测试 |
| G2 | `RuleDivOpt` 补第二变体 | ruleaction.cc:8010-8046 | L2（缺变体） | `zext(X)*c+2^n>>(n+1)` 分支实现 + 测试 |
| G3 | `varmap` stack spacebase 打通 | varmap.cc | L2 | curl uVar 碎片显著减少 |
| G4 | `blockaction` orderLoopBodies | blockaction.cc | L2 | 嵌套循环完整结构化 |
| G5 | `coreaction` 缺失 30 Action | coreaction.cc | L2 | 真实 apply 逻辑 + 测试 |
| G6 | `ruleaction` 缺失 30 Rule | ruleaction.cc | L2 | applyOp 1:1 + 测试 |
| G7 | `emulate` execute 循环 | emulate.cc | L2 | 指令模拟闭环 |

