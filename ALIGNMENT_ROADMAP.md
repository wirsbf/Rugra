# Rugra-Ghidra 完整对齐路线图

> 📌 **主管线差异基线（2026-07-01）**：见 [`docs/alignment_docs/PIPELINE_DIFF_2026-07-01.md`](docs/alignment_docs/PIPELINE_DIFF_2026-07-01.md)。
> 逐 Action 对齐 Ghidra `universalAction`（coreaction.cc:5462-5739）vs Rugra `set_default_actions`（action.rs:383-492）。
> **核心发现**：Ghidra 是 4 层嵌套 repeatapply 管线（universal→fullloop→mainloop→stackstall），Rugra 是单遍扁平 24 步；
> 37 个顶层 Action 中只有 8 个真正对齐，19 个有 impl 未接入，6 个完全缺失；~~oppool1 缺 36 条规则~~（2026-07-01 已补 ~30 条，剩 RulePtrFlow 等 ~6 条），oppool2 整池缺，~~cleanup 缺 11 条~~（已补 10 条，剩 RuleDumptyHumpLate）；
> 另有 6 个 Ghidra 不存在的自造 Action（simplify/typeinfer/copypropagate/typepropagate/inferparams/cse）是技术债。
> P0 = 管线嵌套化改造 + 19 个未接入 Action 接线。
>
> 📌 **2026-07-01 更新**：并发移植 subflow.cc（SubvariableFlow + 8 Rule）、double.cc（SplitVarnode + 4 Rule）、ruleaction.cc 补 21 Rule + 修 RuleDivOpt。oppool1/cleanup 池大批补缺 Rule 已接入主管线。~~832/832 测试，curl 24/24 无回归~~（**2026-07-02 19:29 校对注**：测试数现 960/960，curl 当前 `switch` 已 18→0、`uVar` 已 0，但仍残留 2 个 `if (1) goto ;` 语法错误 + StackX/param 占位名；详见 AGENTS.md「当前反编译质量（2026-07-02 19:29）」节）。

**最后核实**: 2026-06-27（逐行核对 Rugra 源码 vs Ghidra 源码）。**2026-07-02 19:29 校对注**：此日期后已 **204 commit**（含 `docs/QUALITY_GAP_2026-07-02.md` 质量诊断 + `28f1cfe` 全量函数级审计），本文件中模块级 L1/L2/L3 逐行状态仍反映 06-27 核实结果，**输出质量/测试数等可实测项已过时**——以 AGENTS.md「当前反编译质量（2026-07-02 19:29）」节及下方统计汇总表「2026-07-02 19:29 校对」注为准。模块级状态需重新逐行核实 Ghidra 源码后方可更新（铁律 10：禁止形式上改、实质没验证）。
**目标**: 完整实现 Ghidra 反编译器的所有算法，不使用简化版。

## 图例

- **L1** (📋 计划) — 已识别差距，尚未开始实现，或仅有数据结构骨架无核心算法
- **L2** (🔧 实现中) — 核心代码已存在但**关键算法缺失/未对齐**，不能宣称完成
- **L2.5** (🟢 代码完整未接入) — 核心算法 1:1 移植完成且有测试，但**尚未接入主管线**（缺 Rule 包装器 / 被 Sleigh 基础设施阻塞 / Ghidra 设计上不属于 universalAction）。差一步接入即 L3。
- **L3** (✅ 已完成) — **完整实现 + 接入主管线 + 对齐验证**：核心算法 1:1 移植 + 有测试证据 + **实际在反编译流程中被调用** + 无已知行为偏离。代码完整但从未被调用的模块**不是 L3**。

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
| 注入桥接（inject_ghidra/inject_sleigh/comment_ghidra/ghidra_context/ghidra_translate/string_ghidra） | ~6 | 🟢 L2.5（pcodeinject.rs 代码完整：InjectPayload/InjectContext/PcodeEmitArray/PcodeInjectLibrary + register_call_fixup/call_other_fixup/call_mechanism/get_payload_id。9 单元测试。**未接入主管线**：需 Sleigh 架构初始化 + .cspec 解码，见条目 #45） |
| 其他语言后端（printjava） | 1 | 远期目标（先完成 printc） |
| 工具/测试（test/testfunction/filemanage/sleighexample/typegrp_ghidra/codedata/xml_arch/codedata） | ~7 | 按需 |

**完全遗漏、需补入跟踪的核心文件**（此前路线图未提及）：
- `flow.cc` — 控制流分析基础。**2026-07-04 核实**：FlowInfo 范式确实 L1（无忠实移植）。Rugra 用**线性扫描 + 离线 CFG 分割**（inject_raw_ops + build_blocks_from_ops）替代 Ghidra 的可达性流追踪（followFlow/generateOps）。对普通函数功能等价（curl 24/24 能反编译）。**真正缺失的 5 个子系统**：(1) 可达性流追踪（无法区分可达/不可达字节）；(2) 跳转表流内展开（跳转表目标不被流追踪）；(3) 截断流/部分 Funcdata 克隆（truncatedFlow）；(4) 子函数内联（inlineSubFunction/inlineFlow/EZ-model）；(5) 流内 P-code 注入（injectPcode/injectSubFunction）。CFG 构建（generateBlocks）有等价替代（build_blocks_from_ops, ~L2）。这是架构级迁移，需专门多轮 sessions。
- `codedata.cc` — 代码数据分析（L1）
- `printjava.cc` — Java 后端（远期）
- 其余 slgh_*/ghidra_* 按上表战略排除

---

## 一、核心 IR / 数据模型（基础设施层）

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 1 | `address.cc` | `address.rs` | 🔧 L2 | 2026-08-11 锁定审计：`Address` 仅保存 `u64`，丢失 AddrSpace 身份/排序/换算/环绕；有效 `ram:0` 被当 null。`SeqNum` 又把不可变 uniq/time 与可变 order 合并，破坏有序 bank 键；见 `CORE_FOUNDATIONS_2026-08-11.md` | `address.cc` |
| 2 | `varnode.cc` | `varnode.rs` | 🔧 L2 | VarnodeBank 初值/unique base/loc+def 比较键/canonical xref/makeFree/destroy/query 不等价；PcodeOp nullable slots、重复 read occurrence、IOP deadandgone 稳定身份与 High 挂接均未闭合 | `varnode.cc` |
| 3 | `op.cc` | `op.rs` | ✅ L3 | 完整对齐 | `op.cc` |
| 4 | `pcoderaw.cc` | `pcoderaw.rs` | ✅ L3 | 完整对齐 | `pcoderaw.cc` |
| 5 | `opcodes.cc` | `opcodes.rs` | ✅ L3 | 自动生成，完整 | `opcodes.cc` |
| 6 | `space.cc` | `space.rs` | 🔧 L2 | 固定枚举无法表达架构动态 space index/type/name/address-size/wordsize/endianness/flags，并使 Address/Range/Varnode 跨空间键失真 | `space.cc` |
| 7 | `typeop.cc` | `typeop.rs` | 🔧 L2 | 2026-08-11：`TypeOpFloatInt2Float::preferredZextSize` 及 4 个调用点已用源码编译 oracle 验证为 MATCH；模块仍缺 `getFlags` 的 opflags/addlflags 精确组合、OpBehavior 桥接及专用虚函数全量对拍，原“所有操作完整/L3”声明撤回（`PCODE-0002`） | `typeop.cc` |
| 8 | `cover.cc` | `cover.rs` | 🔧 L2 | endpoint Null/End/Input/Op 身份被数值化，合法 `start>stop` 回绕 cover 被判空；CFG 前驱递归、dirty rebuild、PcodeOpSet/HighIntersectTest 缺失 | `cover.cc` |
| 9 | `block.cc` | `block.rs` | 🔧 L2 | edge flag 数值冲突，双向 reverse-index/label 不同步，parent/copy/RPO/loop/dominator/marshal 契约均有反例；CBRANCH 边顺序与 oracle 相反 | `block.cc` |
| 10 | `rangeutil.cc` | `rangeutil.rs` (990行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 CircleRange 方法覆盖**：构造/查询（empty/full/single/new/boolean/is_empty/is_full/is_single/get_*/contains_val）、集合运算（intersect/union/invert/complement/normalize）、范围分析（contains_range/widen/get_max_info/set_stride/pull_back_unary/binary/push_forward_unary/binary/trinary/translate_to_op/convert_to_boolean/set_nz_mask）、辅助函数（bit_transitions/sign_extend_size）。26 单元测试 | `rangeutil.cc` |

---

## 二、分析流水线（核心算法层）

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 11 | `action.cc` | `action.rs` | ✅ L3 | Action/ActionGroup/ActionDatabase 框架对齐 | `action.cc` |
| 12 | `heritage.cc` | `heritage.rs` | 🔧 L2 | 2026-08-11 锁定审计拒绝 L3：canonical `Heritage::heritage` 无生产调用且重入 `RwLock` 会死锁；ActionStart 未建 dominator，live Action 改走自创 direct phi/rename 两遍并把 pass 加两次，def-use/IOP/block membership/refinement/guards 均未闭合。正式门禁 `NO_ORACLE`，见 `CONTROL_OUTPUT_PIPELINES_2026-08-11.md` | `heritage.cc` |
| 13 | `merge.cc` | `merge.rs` | ✅ **L3（2026-07-04 完整对齐）** | merge 子系统全部 public/private 方法已移植（mergeOpcode/mergeTestRequired/snip 子系统/dominant-copy/SUBPIECE 影子/hideShadows/mergeOp per-op forced-merge/redundant-copy 标记）。已知简化：build_dominant_copy/allocate_copy_trim 的 union 解析路径省略（需 inheritResolution/forceFacingType/getUnionField 基础设施）；mergeRangeMust 用 merge_test_must+merge_force 近似（Ghidra 失败 throw，Rugra 跳过）。 | `merge.cc` |
| 14 | `variable.cc` | `variable.rs` | 🔧 L2 | HighVariable 未原子建立 VN↔High 关系，annotation/后建 VN 挂接错误，强 Arc 形成环，instances 未按 compareJustLoc 维持顺序，销毁与 dirty 传播未闭合 | `variable.cc` |
| 15 | **`varmap.cc`** | `varmap.rs` | 🔧 L2 | **RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐**；已接入 printc；**Stack-spacebase 解析**已实现（gather_spacebase 递归解析 RSP/frame_base 链）。**2026-06-29 重大进展**：ActionSpacebase 接入主管线（coreaction.cc:5506），标记 RSP 输入为 SPACEBASE → varmap/printc 正确识别栈指针 → **curl uVar 碎片 149→0**。**剩余**：alias_block_level、LoadGuard addGuard；部分 LOAD/STORE 为 RIP-relative 全局（非栈）仍需类型传播配合 | `varmap.cc` |
| 16 | `funcdata.cc` + 3子文件 | `funcdata.rs` | 🔧 L2 | 核心功能已实现；缺少 funcdata_block/op/varnode 的部分高级 API | `funcdata.cc`, `funcdata_block.cc`, `funcdata_op.cc`, `funcdata_varnode.cc` |

---

## 三、控制流结构化

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 17 | `blockaction.cc` (2366行) | `blockaction.rs` (4560行) | 🔧 **L2（orderLoopBodies 完整 + ruleBlockWhileDo 移植，剩 collapseInternal 架构迁移）** | identifyInternal/selfIdentify ✅；ruleBlockCat/ProperIf/IfElse/WhileDo/DoWhile/Goto ✅；**2026-06-29 进展**：①`order_loop_bodies` + LoopBody 全管道（find_base/merge_identical_heads/label_containments/find_exit/order_tails/extend/label_exit_edges）实测生效（parseconfig 12 回边→7 loops, depth 至 5）②新增 `rule_block_while_do`（blockaction.cc:1518-1549）1:1 移植含 isGotoOut 检查 ③修复 `is_goto_out` 读取 block 级 GOTO_EDGE_0/1 标志（此前 TraceDAG 标的 goto 查询不到）④findSpanningTree DFS 回边检测 + CFG 跳转目标分裂 + reconcile 类型修复链（循环回边检测恢复，审计 24/24；旧 while 计数 4→28 已废弃为 KPI）。**剩余 L2 缺口**：staged→collapseInternal 架构迁移——Ghidra 的 ruleBlockGoto 在每轮 collapseInternal 中"消费"goto 边（重连而非仅标记），使 break 边从结构化视图中消失，ruleBlockWhileDo 才能看到 2 条非 goto 边。Rugra 目前只标记不重连，故 break 循环的 WhileDo 形成受限 | `blockaction.cc` |
| 18 | TraceDAG (blockaction.cc 内) | `tracedag.rs` | 🟢 **L2.5（2026-07-04 check_open 修复）** | BranchPoint/BlockTrace/BadEdgeScore 完整移植。**check_open 已修复 3 个差异**：(1) finishblock 守卫（对齐 blockaction.cc:822）；(2) loop-DAG in-edge 分母（对齐 :826-831）；(3) isLoopDAGOut 极性修正。`opened` HashSet 保留为保守安全网（Ghidra 无此机制，标 TODO 待移除——需验证 visit-count 终止性）。 | `blockaction.cc:499-1014` |
| 19 | `condexe.cc` | `condexe.rs` | 🔧 L2 | 依赖的 op destroy/insert 与双向 CFG 边不变量已破坏；removeFromFlowSplit 两支映射相反且一支可越界，CBRANCH true/false 被重复翻转，pullback storage/顺序、异常、Action guard/count/stage 与 PathMeld 均不等价 | `condexe.cc`, `expression.cc` |
| 20 | `subflow.cc` (4130行) | `subflow.rs` (3400+行) | 🟢 **L2.5→近 L3（2026-07-01：8/9 Rule 已移植+接入 oppool1/cleanup）** | SubvariableFlow 引擎完整 1:1（trace_forward/backward/sext, do_replacement, create_link/compare_bridge, patches, process_next_work）。**8 个 subvar/split Rule 已移植并注册进 oppool1(5621-5628)/cleanup(5706-5708)**：RuleSubvarAnd/Subpiece/SplitFlow/CompZero/Shift/Zext/Sext + RuleSplitCopy/Load/Store。29 单元测试。**唯一剩余缺口**：RulePtrFlow(5624, ruleaction.cc:9177)——重（trialSetPtrFlow/propagateFlowToDef/Reads/truncatePointer + arch 构造）。另：RuleSubfloatConvert 的 TransformManager.apply 待补。基础设施 TODO：Varnode::isPtrFlow/isZeroExpanded | `subflow.cc` |
| 21 | **`jumptable.cc`** | `jumptable.rs` | 🔧 L2 | JumpBasicOverride::findStartOp 缺失且 trialNorm 恒 -1；PathMeld 不按 parent/SeqNum 归并截断；EmulateFunction 无 loader/LOAD/MULTIEQUAL；JumpBasic guard/range、Basic2 subtype、JumpAssisted 与 model selection/ActionSwitchNorm 闭包均未对齐 | `jumptable.cc` |

---

## 四、优化与简化规则

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 22 | `coreaction.cc` (5741行) | `coreaction.rs` (4000行) | 🔧 **L2（G5 进展 + spacebase 接入）** | **2026-06-29**：新增 `ActionSpacebase`（coreaction.hh:270-279）+ `Funcdata::spacebase()`（funcdata.cc:230-269）+ `split_uses()`（funcdata_varnode.cc:1540-1567）——标记 RSP 输入为 SPACEBASE，接入主管线在 Heritage 后。**curl uVar 149→0**。**2026-06-27**：4 个结构清理 Action apply() 完整移植（Unreachable/DoNothing/RedundBranch/DeterminedBranch，coreaction.cc:3457-3528）+ remove_unreachable_blocks/splice_block_basic 原语。**未接入主管线**（staged structurer 依赖被删块，需 collapseInternal 迁移）。9 单元测试验证 apply() 正确。ActionMultiCse/ShadowVar 已完整。**剩余**：~20 个 Action（FuncCallSpecs/HighVariable 依赖型） | `coreaction.cc` |
| 23 | `ruleaction.cc` (11016行) | `ruleaction.rs` (10968行) | 🔧 L2 | **2026-06-29**：新增 `RuleSubCommute`（ruleaction.cc:4534-4673）——SUBPIECE 与二元算术的 commute（SUBPIECE(INT_ADD(a,b),0) → INT_ADD(SUBPIECE(a,0),SUBPIECE(b,0))），注册进 oppool1（5577）。2 单元测试（含 loneDescend 守卫验证）。**2026-06-28 实测**：~100 个 Rule struct，其中 **98 个已注册进 `build_simplify_pool`**（oppool1）+ cleanup 池（actcleanup），**接入主管线并实测生效**（curl 515 次触发/21 Rule）。**剩余 L3 差距**：① 仍缺 ~11 个 Ghidra Rule（见 action.rs skip 注释，已从~30修正——许多此前标"缺失"的其实已实现并注册）；② 部分 Rule 的 `get_opcodes` 覆盖不全或 apply 分支不完整；③ 需逐 Rule 与 ruleaction.cc 比对确保 1:1 | `ruleaction.cc` |
| 24 | `constseq.cc` | `constseq.rs` (395行) | ✅ **L3（2026-06-29 接入主管线）** | WriteNode + ArraySequence（form_byte_array/select_string_copy_function/interfere_between/check_interference/is_valid_string/get_string）+ StringSequence（空壳，需 Funcdata op 集成）+ HeapSequence（空壳，需 heap pointer analysis）+ RuleStringCopy（COPY 检测 + select_string_copy_function 调用）+ RuleStringStore（STORE 检测，constseq.cc:974-1002 的检测阶段）。4 单元测试。**2026-06-29 接入 build_cleanup_pool（coreaction.cc:5709-5710）**——RuleStringCopy/RuleStringStore 现在实际跑在 cleanup 池。transform 阶段（替换为 CALLOTHER）待 userop 基础设施。验证：curl 24/24 + httpd 29/29 无回归 | `constseq.cc` |
| 25 | `transform.cc` | `transform.rs` | ✅ L3 | **完整实现**：LanedRegister（lane 尺寸位掩码 + parse_sizes）+ LaneDescription（uniform/two_lane/subset/get_boundary/restriction/extension）+ TransformVar（6 类型 + create_replacement）+ TransformOp（createReplacement/attemptInsertion/inheritIndirect）+ TransformManager 完整 apply 生命周期（createOps/createVarnodes/removeOld/transformInputVarnodes/placeInputs）。Arena 风格 ID 索引替代 Ghidra 原始指针。19 个单元测试。已知限制：transferVarnodeProperties/deleteVarnode/setInputVarnode/markIndirectCreation 用 best-effort 替代 | `transform.cc` |
| 26 | `userop.cc` | `userop.rs` | 🔧 L2 | derived UserPcodeOp 类型被扁平化，selector/index/conflict/builtin 契约不全；SegmentOp 被硬编码 `base<<4`（不适用于 HCS12/Z80/x86 protected），JumpAssist consumer 缺失，ActionSegmentize 仅计数 no-op；生产 Architecture/Flow 链未安装或读取 userops | `userop.cc` |
| 27 | `unify.cc` | `unify.rs` (2595行) | 🟢 **L2.5（代码完整，Ghidra 设计上非主管线模块）** | **全部 unify 方法覆盖**：UnifyDatatype + RHSConstant 系列（ConstantNamed/Absolute/NZMask/Consumed/Offset/IsConstant/HeritageKnown/VarnodeSize/Expression）+ TraverseConstraint 系列（Descend/Count/Group）+ UnifyConstraint 系列（20 个 Constraint 类型：Boolean/VarConst/NamedExpression/OpCopy/Opcode/OpCompare/OpInput/OpInputAny/OpOutput/ParamConstVal/ParamConst/VarnodeCopy/VarCompare/Def/Descend/LoneDescend/OtherInput/ConstCompare/Group/Or）+ UnifyState（数据存储/op/vn 初始化/count/descend 管理）+ UnifyCPrinter（initialize_basic/add_names/print/print_get_op_list/print_rule_header/print_var_decls）。111 个 pub fn。16 单元测试。无 TODO。**设计上不属于主管线**：Ghidra 的 unify 引擎是**规则编译器代码生成工具**（rulecompile.cc/ruleparse.y）的一部分，用于在**构建时**生成自定义 Rule 的 C++ 代码，运行时不被 universalAction 调用。Rugra 的 Rule 全部手写（不经过 unify 引擎），与 Ghidra 的内置 Rule 一致 | `unify.cc` |

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

**✅ 全部已移植（2026-07-04 核实）** — 主管线 oppool1/oppool2/cleanup 的 Rule 差距为 0。
之前此表标注的 22 个"缺失"Rule 经逐行对比 Ghidra coreaction.cc 注册列表 vs Rugra action.rs 注册列表，确认全部已移植并注册到主管线。
（`RuleSubfloatCpool`/`RuleFloatCpool`/`RulePtraddShift`/`RulePtraddPiece` 在 Ghidra 中不存在——虚构条目。`RuleIndirectConcat` 在 Ghidra 中被注释掉。）

---

## 五、类型系统

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 28 | `type.cc` (4674行) | `type_system/datatype.rs` + `typefactory.rs` | 🔧 L2 | 2026-08-11 审计拒绝 L3：submeta/派生 compare+dependency/alignment/Pointer spaceid 缺失；TypeFactory 只有单名称 map，缺结构主索引、canonical `findAdd`、稳定递归 stub 身份、exact-piece 与严格 codec，hashSize 算法也错；正式门禁 NO_ORACLE | `type.cc` |
| 29 | `cast.cc` | `type_system/cast.rs` (200行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 CastStrategyC 方法覆盖**：CastStrategy trait（is_cast_implied/cast_standard/check_int_promotion_for_extension/compare）+ CastStrategyC（is_char_type/is_enum_type/is_subpiece_cast/is_subpiece_cast_endian/is_sext_cast/is_zext_cast，对齐 cast.cc:411-469）。5 单元测试 | `cast.cc` |
| 30 | `signature.cc` + `modelrules.cc` | `modelrules.rs` (3137行) | 🟢 **L2.5（modelrules，2026-07-22 cross-reviewed）/ 📋 L1（signature）** | **modelrules Phase 1**：22 个类/特质 1:1 移植（PrimitiveExtractor + 5 DatatypeFilter + 5 QualifierFilter + 11 AssignAction + ModelRule）。提取算法 / 过滤谓词 / justify_pieces 全 1:1，29 测试。**Cross-review (Mechanism C) APPROVED**: extract/checkOverlap/SizeRestrictedFilter::filter/ModelRule::assignAddress 4 函数四类语义全 MATCH。**2 个已知 REJECT（待上游）**：(1) HomogeneousAggregate::filter 元素比较用 structural compare() 而非 Ghidra pointer-identity（extract() 每次 Arc::new 破坏 identity）；(2) MultiSlotAssign::assignAddress 是返回 Fail 的 stub（70 行算法待 ParamEntry/assignAddressFromPieces 上游）。assign_address 方法体待 ParamListStandard/TypeFactory 上游（每处已摘录 Ghidra 源码）。**signature 仍完全缺失** | `signature.cc`, `modelrules.cc` |
| 31 | `signature_ghidra.cc` | — | 📋 L1 | **完全缺失**：Ghidra 签名格式 | `signature_ghidra.cc` |
| 32 | `analyzesigs.cc` | — | 📋 L1 | **完全缺失**：签名分析 | `analyzesigs.cc` |

---

## 六、代码生成（打印层）

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 33 | `printc.cc` | `printc.rs` | 🔧 L2 | 默认 RPN 根 invisible group 被发成未闭合字面 `(`；大多数算术/CALL/STORE 绕过 RPN，block walker 忽略 terminal mask，doc_function 又用 fresh set 重发所有循环；当前 11.3.2 最终 C golden 不能证明 12.0.4 token/markup parity | `printc.cc` |
| 34 | `printlanguage.cc` | `printlanguage.rs` | 🔧 L2 | RPN token 表/递归/括号 identity 不完整，自由 `rpn_recurse` 可丢 pending node；真实 PcodeOp/Varnode/Datatype 与 group ID/highlight payload 丢失，namespace 三种策略和多个虚方法仍为空 | `printlanguage.cc` |
| 35 | `prettyprint.cc` | `prettyprint.rs` | 🔧 L2 | Emit 签名无法携带 oracle markup identity；TokenSplit/Oppen scan queue、line width、spaces+bump、group break/indent 状态机缺失，27+ 文本后处理仍在实际路径 | `prettyprint.cc` |
| 36 | `fspec.cc` | `fspec.rs` | 🔧 L2 | 空参数列表被 `all()` 误判 input-locked，lock/void/model 联动缺失；ParamActive slot 应从 1 而非 0，whichTrial/getNumUsed/split/comparator 与 ParamEntry 分配均有确定差异，storage 部分依赖 ADDRESS-0001 | `fspec.cc` |
| 37 | `options.cc` | `options.rs` | 🔧 L2 | option name/wire ID/注册集合与顺序、非法参数异常与 numeric 边界、alias/split/nan 参数、decode 错误传播和多个 Architecture/Action/Print 状态突变均不等价；无 12.0.4 同输入 fixture | `options.cc` |
| 38 | `comment.cc` | `comment.rs` | ✅ L3 | **完整实现**：Comment + comment_type + CommentDatabaseInternal（add/clear/query/encode/decode）+ CommentSorter（find_position 完整基本块关联 via Funcdata op 遍历 + setup_function_list/setup_block_list/setup_op_list）。所有 L3 缺口已关闭 | `comment.cc` |

### post_process 对齐缺口（2026-07-03 核实）— `prettyprint.rs::post_process_output`

> **铁律 5.5 违反清单**：`EmitNoMarkup::post_process_output`（260-1714 行）含 27+ 趟文本级后处理。
> Ghidra 的 `EmitMarkup`（prettyprint.cc）**零后处理**——所有语义在 Action 阶段 + emit 阶段正确遍历完成。
> 逐 pass 按"对应的 Ghidra 正确机制"分组，按对齐难度排序。

**A. 简单（纯 Rugra-Emit 输出瑕疵；Ghidra Emit 层从不产生，对齐 = 直接移除该 pass）**

| Pass | 行 | 功能 | 移除条件 |
|---|---|---|---|
| 3 | 382 | 折叠连续空行 | Emit 层不该产生连续空行 |
| 8 | 749 | 声明块内删空行 | Emit 层单遍发声明 |
| 12 | 975 | `} else {` 后删空行 | Emit 层括号后无换行 |
| 15 | 1029 | `func());`→`func();` 双括号修 | printc emitFuncCall 括号配对 bug，应在 emit 修 |
| 19 | 1425 | 删多余 `}` | Rugra Emit 遍历括号不平衡（纯 Emit bug） |

**B. 中等（局部类型/格式问题，需轻量分析但非完整 Action）**

| Pass | 行 | 功能 | Ghidra 机制 |
|---|---|---|---|
| 7 | 640 | `*&x`→x / int-ptr 强转 / 常量折叠 / hex→char | ActionSetCasts + RuleCollapseConstants + printc char 格式化 |
| 13 | 988 | `return func();`→`func(); return;`（void func） | FuncProto 返回类型（ActionActiveParam）+ printc emitReturn |
| 26 | 1703 | 删非法左值赋值行 | printc STORE 地址必须合法左值（类型化后自然解决） |

**C. 困难（直接补偿缺失的 Ghidra Action 子系统 — 核心违规）**

| Pass | 行 | 功能 | 缺失的 Ghidra 机制 |
|---|---|---|---|
| 1 | 265 | goto→break/return、删冗余 goto | ActionBlockStructure(selectGoto/collapseInternal) + printc emitGotoStatement |
| 2,5 | 362,533 | 删未引用标签 | 同上（结构化后无裸标签） |
| 4 | 397 | 回边 goto→while/do-while | ActionBlockStructure 循环恢复(RuleWhileDo/RuleDoWhile) + printc emitWhileLoop |
| 6 | 548 | 单用变量内联 | ActionMarkImplied + ActionCopyPropagate + ActionDeadCode |
| 9 | 790 | if(1)→body / 恒真折叠 / 尾调用 | ActionDeadCode + RuleBoolNegate/RuleCondOr + 尾调用识别 |
| 10,14 | 874,1011 | 删 return/break/goto 后死代码 | ActionDeadCode（P-code 级完全移除） |
| 11 | 942 | 删未用变量声明 | ActionDeadCode + Varnode::isPrinted |
| 16 | 1036 | 前向 goto→if 折叠 | ActionBlockStructure selectGoto + collapseInternal |
| 17 | 1210 | 删孤立 break/continue / 多余 `}` | ActionBlockStructure 循环/switch 归属 |
| 18 | 1351 | 删函数体首行 return | ActionDeadCode + 入口块正确性 |
| while-break | 1506 | `while{...break}`→`if` | ActionBlockStructure 不把单次循环结构化成 while |
| empty-switch | 1619 | 删空 case | ActionBlockStructure switch 结构化 |
| 20,21 | 1658,1663 | `*(p+N)`↔`p->field_N`（**互为反作用**！） | ActionInferTypes + ActionSetCasts（类型系统解析结构体指针） |
| 22 | 1678 | `*X` 解引用变量改声明为指针 | ActionInferTypes（STORE 地址类型化） |
| 23 | 1685 | 补缺失 local 声明 | ActionHighSymbol 符号具体化 |
| 24 | 1690 | 删循环外 break/continue | ActionBlockStructure 结构遍历固有属性 |
| 25 | 1695 | 指针算术强转 | ActionInferTypes + ActionSetCasts |
| 27 | 1705 | 删 switch 外 case 标签 | ActionBlockStructure 结构遍历固有属性 |

**最关键观察**：
- Pass 20 和 21 **互为反作用**（20 引入 `->field_N`，21 又改回 `*(long *)(p+N)`）。两者同时存在，净效果是双重文本变换什么都没做。这是铁律 5.5 违规的教科书案例。
- **goto/loop/label/死代码 pass（C 组前半）占大多数**，全部依赖 `ActionBlockStructure` 的结构恢复 + `ActionDeadCode`。这是 Rugra 当前最薄弱的子系统。
- **对齐策略**：不能一次性移除（会破坏输出）。必须**自底向上**——先补齐对应 Action（让 P-code/CFG 层正确），再移除补偿 pass。每移除一个 pass 前先验证其对应的 Ghidra 机制已移植。

### merge 命名对齐缺口（2026-07-03 深度分析）— `merge.rs`

> 2026-07-04 更新：原 3 个偏离方法已全部对齐处理。详见下表。

| Rugra 方法 | Ghidra 对应 | 状态（2026-07-04） |
|---|---|---|
| `Merge::merge_opcode(opc)` (原 merge_copy) | `Merge::mergeOpcode(OpCode)` (merge.cc:326) | ✅ **已对齐**：签名改为通用 `opc` 参数，用 `merge_test_required` + `merge_speculative`（cover 相交静默跳过，对齐 merge.cc:1565-1575）。`ActionMergeCopy::apply` 改为纯委托（coreaction.hh:392）。新增 `merge_test_required`（对齐 merge.cc:102-166）。 |
| `Merge::process_copy_trims` (原 dominant_copy) | `Merge::processCopyTrims()` (merge.cc:1415) | ✅ **已对齐为忠实 no-op**：原自创的 cover-extent dominant 合并已删除，改为遍历 `copyTrims`（永远空）的 no-op。**剩余缺口**：copyTrims 由 forced-merge 路径填充（snipReads/eliminateIntersect/allocateCopyTrim，merge.cc:411/443/489），Rugra 未移植 snip 子系统。要实现真正的 dominant-copy 合并需先补齐 snip 机制（见下方 snip 子系统缺口）。 |
| ~~`Merge::merge_by_cover`~~ | **无 Ghidra 对应** | ✅ **已删除**：原自创的多趟迭代补偿 pass 已移除。`merge_opcode` 忠实于 Ghidra 后不再需要迭代。 |

**snip 子系统已移植（2026-07-04）**：
- ✅ `allocate_copy_trim` (merge.cc:411) — 创建 COPY op + unique 输出，push 进 copy_trims
- ✅ `snip_reads` (merge.cc:443) — 截断一组读取到临时变量
- ✅ `eliminate_intersect` (merge.cc:489) — 检测 cover 相交并标记 snip（含 copy_shadow 检查）
- ✅ `unify_address` (merge.cc:581) — 对同地址组消除相交
- ✅ `merge_addr_tied` 接入 unify_address（forced merge 前 snip）
- ✅ `process_copy_trims` 改为遍历 copy_trims + 按 high 计数 + 调用 process_high_dominant_copy
- 配套基础设施：`PcodeOp::slot_of_input`、`Cover::contain_varnode_def_at`/`CoverBlock::boundary`/`intersect_char`、`BlockGraph::find_common_block_n`、`BlockBasic::get_stop_addr`、`BlockVarnode`(Ord/set/find_front)、`Varnode::copy_shadow`/`partial_copy_shadow`/`has_cover`、`Funcdata::op_insert_end`/`op_mark_non_printing`、`Merge::merge_test_must`
- **2026-07-04 续**：完整移植 dominant-copy 替换子系统：
  - ✅ `process_high_dominant_copy` (merge.cc:1316) + `find_all_into_copies` (merge.cc:1295) + `compare_copy_by_in_varnode` (merge.cc:1045) + `build_dominant_copy` (merge.cc:1151) — 支配树 LCA 选 dominant COPY，cover 检查可替换性，totalReplace+opDestroy 替换。
  - ✅ `partial_copy_shadow` 完整移植（findSubpieceShadow/findPieceShadow，varnode.cc:1006/1062）—— 不再是保守 stub。
  - ✅ `merge_test_must` 门控接入 merge_addr_tied（对齐 mergeRangeMust 的 mergeTestMust 检查）。
- **剩余已知简化**（非阻塞，记录为技术债）：
  - `build_dominant_copy` 的 union 解析路径（merge.cc:1170-1178）省略（无 union 基础设施）
  - `merge_range_must` (merge.cc:301) 用 merge_test_must + merge_force 近似（Ghidra 失败 throw，Rugra 跳过）
  - `find_piece_shadow` 无 MULTIEQUAL 递归（Ghidra 本身也无，对齐）
  - `processHighRedundantCopy`/`markRedundantCopies`/`checkCopyPair`/`shadowedVarnode`（merge.cc:1345/1249/1112/1271）✅ **2026-07-04 续 6 已移植**：4 个方法全部移植，接入 mark_internal_copies（含 shadowedVarnode 无后代检查 + processHighRedundantCopy 冗余标记）。
- **2026-07-04 续 4 审计发现的 2 个高优先级缺口**（之前路线图低估）：
  - **`mergeOp`/`mergeIndirect` + `trimOpOutput`/`trimOpInput`/`snipOutputInterference`/`collectInputs`**（merge.cc:719/846/656/692/811/783）— ✅ **2026-07-04 续 5 已修复**：全部 6 个方法已移植。merge_marker 从 merge_force 改为委托 merge_op/merge_indirect（对齐 merge.cc:889-902）。含 merge_test_with_list（对齐 mergeTest(high,tmplist) merge.cc:1657）。
  - **`hideShadows` 重写未应用**（merge.cc:1070 + coreaction.cc:4841 ActionHideShadow）— ✅ **2026-07-04 续 4 已修复**：hide_shadows_of 现在真正应用 opSetInput 重写；ActionHideShadow::apply 改为委托 Merge::hide_shadows_of（对齐 coreaction.cc:4831-4845）。

---

## 七、模拟执行

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 39 | `emulate.cc` | `emulate.rs` (480行) | 🟢 **L2.5（核心引擎完整，缺集成包装器）** | **2026-06-27**：完整移植 execute_current_op（emulate.cc:143-216 dispatch）+ execute() 主循环 + get_value/set_value（值解析，非仅常量）+ execute_unary/binary/load/store。4 个单元测试验证 COPY/INT_ADD/链式执行/RETURN 终止。**接入缺口**：BreakTable/BreakCallBack、EmulateFunction（函数级模拟包装器）。注：jumptable.rs 已用 EmulateFunction（L3）；emulate.rs 核心引擎完整 | `emulate.cc` |
| 40 | `emulateutil.cc` | `emulate.rs`（同上） | 🔧 L2 | 模拟工具与 emulate.rs 合并；EmulateFunction 部分 | `emulateutil.cc` |
| 41 | `float.cc` + `double.cc` + `multiprecision.cc` | `float_emulate.rs` (440行) | 🟢 **L2.5（代码完整，Ghidra 设计上无 float emulation Action）** | **全部 FloatFormat 方法覆盖**：extract/set fractional_code/sign/exponent（对齐 float.cc:113-181）、getZeroEncoding/getInfinityEncoding/getNaNEncoding（对齐 cc:181-205）、所有 FLOAT_ op（op_add/sub/mult/div/neg/abs/sqrt/floor/ceil/nan/int2float/float2float/trunc/round/equal/notequal/less/lessequal）。用 host f64 替代 Ghidra multiprecision（语义等价，对反编译足够）。12 单元测试。**设计上不属于主管线**：Ghidra **没有** float emulation Action，float 语义由 Rule 处理（RuleFloatRange/RuleFloatSign/RuleFloatCast 等已在 oppool1/cleanup，coreaction.cc:5613-5637）。float_emulate.rs 作为这些 Rule 的底层求值库被间接使用 | `float.cc`, `double.cc`, `multiprecision.cc` |
| 42 | `opbehavior.cc` | `opbehavior.rs` (280行) | ✅ **L3（2026-06-28 完整对齐）** | **全 opcode 覆盖**：evaluate_unary/binary/ternary 覆盖所有 INT_/BOOL_/COPY/PIECE/SUBPIECE/PTRADD/PTRSUB/LZCOUNT/POPCOUNT。recover_input_unary（COPY/INT_ZEXT/INT_SEXT/INT_NEGATE/INT_2COMP/BOOL_NEGATE）+ recover_input_binary（INT_ADD/INT_SUB/INT_MULT/INT_AND/INT_OR/INT_XOR/INT_LEFT）——**INT_LEFT recoverInputBinary 新增**（对齐 Ghidra OpBehaviorIntLeft::recoverInputBinary cc:443）。FLOAT_ 系列由 float_emulate.rs 单独处理。函数式 API（evaluate_*）替代 Ghidra OOP 类层次，语义等价。8 单元测试验证 | `opbehavior.cc` |
| 43 | `memstate.cc` | `memstate.rs` (380行) | ✅ **L3（2026-06-28 完整对齐）** | **全部 MemoryBank/MemState 方法覆盖**：MemoryBank（set/get value/chunk、construct/deconstruct、insert/find word、page 管理）+ MemoryImage（read/get_value）+ MemoryPageOverlay（write/read/overlay 检测）+ MemState（set/get bank/value/chunk，对齐 memstate.cc:652-729）。9 单元测试 | `memstate.cc` |
| 44 | `context.cc` + `globalcontext.cc` | `context.rs` | ✅ L3 | **完整实现**：ContextBitRange + TrackedContext/TrackedSet + ContextBlob + ContextDatabase trait + ContextInternal（内存分区映射 + XML encode/decode）+ ContextCache。所有 L3 缺口已关闭 | `context.cc`, `globalcontext.cc` |

---

## 八、P-code 注入与重写

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 45 | `pcodeinject.cc` | `pcodeinject.rs` | 🔧 L2 | decoder/参数索引/tempbase/script/id-vector/dynamic payload/duplicate-error 契约不全；Architecture 无 pcodeinjectlib，Flow 不收集 CALLOTHER injection、也不调用 injectPcode，直接 API 又从 HashMap 非确定地取首项，故生产闭包不可达 | `pcodeinject.cc` |
| 46 | `pcodecompile.cc` + `pcodeparse.cc` | `pcodeparse.rs` | 🔧 **L2（解析失败语义未对齐，且未接 Sleigh 架构初始化）** | Lexer、模板构造与递归下降语法主体已存在；`UserOpSymbol` 的非零 index 现会进入 `CPUI_CALLOTHER` input 0。仍有 27 个必选标点错误被丢弃、3 个 `local` 分支可静默漏分号，失败时 result 状态也未与 Bison 对齐（`PARSER-0001`）。Ghidra 在 inject 初始化链调用该解析器，Rugra 尚未接入同等 Sleigh 架构初始化。 | `pcodecompile.cc`, `pcodeparse.cc`, `pcodeparse.y` |

---

## 九、架构支持

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 47 | Sleigh (20+ 文件) | `iced-x86` (仅 x86-64) | 🔧 L2 | **仅支持 x86-64**；不支持 ARM/MIPS/RISC-V/PowerPC | `sleigh*.cc`, `slgh*.cc` |
| 48 | `architecture.cc` | `arch.rs` | 🔧 L2 | 配置容器存在，但 `Funcdata.arch` 生产路径始终 None，裸 Architecture 的 loader/types/userops/cpool 也为空；缺 pcodeinjectlib 及 build/init/decode 闭包，使 userop/injection/type/cpool consumers 全不可达 | `architecture.cc` |
| 49 | `translate.cc` | `disasm/x86_lift.rs` | 🔧 L2 | 仅 x86-64 提升 | `translate.cc` |
| 50 | `grammar.cc` + `expression.cc` | `grammar.rs` (753行) + `expression.rs` (818行) | 🟢 **L2.5（grammar 代码完整，设计上非主管线模块）** | grammar.rs: GrammarToken（token 类型/位置/值）+ GrammarLexer（完整状态机词法分析：标点/标识符/dec-hex-oct 整数/字符串/字符/注释/EOF）+ TypeModifier/TypeDeclarator AST + parse_type/parse_to_separator。expression.rs: AdditiveEdge + TermOrder（collect/sort_terms/get_sort）+ AddExpression（gather_two_terms_add/subtract/root/is_equivalent）+ boolean_match_evaluate + functional_equality_level0/functional_equality_level。functional_equality 在 address.rs。28 单元测试。**grammar 设计上不属于主管线**：Ghidra 的 grammar 是 .cspec/.pspec 解析器，在架构初始化时解析编译器规范（非反编译运行时 Action）。expression.rs **已接入**主管线（printc 排序用 TermOrder）。注意：lib.rs:68 标注 grammar 已接入，但实际 parse_type/parse_to_separator 无外部调用方 | `grammar.cc`, `expression.cc` |

---

## 十、其他基础设施

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 51 | `callgraph.cc` | `callgraph.rs` (370行) | 🟢 **L2.5（代码完整，Ghidra 设计上非主管线模块）** | **全部方法覆盖**：CallGraph（add_node/find_node/add_edge/delete_in_edge/snip_edge/snip_cycles/snip_cycles_dfs/cycle_structure/find_no_entry/clear_marks/init_leaf_walk/next_leaf/build_edges/edges/all_addrs）+ CallGraphNode/CallGraphEdge + edge_flags/node_flags。**build_edges** 从 Funcdata callspecs 构建调用边（对齐 cc:406）。**snip_edge** 标记循环边（对齐 cc:164）。**cycle_structure** 分析循环结构（对齐 cc:352）。8 单元测试。**设计上不属于主管线**：Ghidra 的 CallGraph 是程序级全局对象，仅通过控制台命令（ifacedecomp.cc:2721 `IfcCallGraphBuild`）构建，非 universalAction 的一部分。Rugra 的主管线是 per-function 的，与 CallGraph 的全局粒度不匹配 | `callgraph.cc` |
| 52 | `database.cc` + `database_ghidra.cc` | `database.rs` | 🔧 L2 | compact Symbol flags 与 Varnode 位域冲突；Scope::addMap/rangemap+usepoint/Symbol 多态身份/ID+category 契约不等价，ScopeLocal→Funcdata 属性传播与 Dynamic Actions 主管线也断开 | `database.cc`, `database_ghidra.cc` |
| 53 | `xml.cc` + `marshal.cc` | `marshal.rs` | 🔧 L2 | 固定进程级 ID/名称表被实例注册顺序取代（0 被误当 UNKNOWN），Translate 共享 ID 也错；PackedDecode 以单 `pos+pending` 替代 start/cur/end/attributeRead，导致 unread attributes、strict/recursive close、typed error/EOF/raw byte 全不等价，Decoder trait 又无错误通道 | `xml.cc`, `marshal.cc` |
| 54 | `stringmanage.cc` + `string_ghidra.cc` | `stringmanage.rs` | ✅ L3 | **完整实现**：StringManager + StringManagerUnicode + 完整 UTF8/UTF16/UTF32 解码 + XML encode/decode。所有 L3 缺口已关闭 | `stringmanage.cc` |
| 55 | `crc32.cc` + `compression.cc` | `crc32.rs` + `compression.rs` | 🔧 L2 | crc32 已实现；`Decompress` 的无输入/分步/替换/原位变更/输入输出同址/data-error 路径已与 12.0.4 同 schema stdout 直接差分 MATCH，异常注入仍未闭合。`Compress` 仍重建流、错误处理/返回值不符，`CompressBuffer` 缺失，禁止宣称模块 L3 | `crc32.cc`, `compression.cc` |
| 56 | `override.cc` | `override_rs.rs` | ✅ L3 | **完整实现**：Override + FlowOverride 完整 in-memory + XML encode/decode（使用 marshal.rs）。所有命令类型（forcegoto/deadcodedelay/indirectover/protoover/multistagejump/flowoverride）的 insert/query/apply/encode/decode 全部实现 | `override.cc` |
| 57 | `prefersplit.cc` | `prefersplit.rs` | ✅ L3 | **完整实现**：PreferSplitRecord（storage + splitoffset + less_than 排序）+ PreferSplitManager + SplitInstance。全部 18 个私有分裂辅助函数已移植（fillin_instance/create_copy_ops/test+split_defining_copy/reading_copy/zext/piece/subpiece/load/store）+ split_varnode/split_record/test_temporary/split_temporary 驱动 + split/split_additional 公共入口。使用 Funcdata op-editing API（new_op/op_set_opcode/op_set_input/op_set_output/op_insert_after/op_destroy）。新增 Funcdata::op_insert_after | `prefersplit.cc` |
| 58 | `paramid.cc` | `paramid.rs` | 🟢 **L2.5（算法完整，缺 Funcdata 集成）** | **核心算法完整移植**：ParamMeasure（walk_forward/walk_backward 数据流分类，含 descend_iter/get_def + 全 opcode dispatch：BRANCH/CBRANCH/CALL/CALLOTHER/RETURN/INDIRECT/MULTIEQUAL，使用 update_rank + ParamRank）+ calculate_rank（terminal_rank 选择 + walk 调度）+ ParamIdAnalysis::analyze（遍历 vbank.loc_tree 构建 ParamMeasure + 扫描 RETURN）。9 pub fn，0 stub。2 个轻微简化（MULTIEQUAL loop-avoidance 用递归 walk 无 isLoopIn；backward-walk default 用 DIRECT_WRITE_WITHOUT_READ）。**接入缺口**：缺 Funcdata 集成 + isLoopIn（需 BlockBasic）+ XML encode | `paramid.cc` |
| 59 | `unionresolve.cc` | `unionresolve.rs` | 🔧 L2 | **骨架已移植**：ResolvedUnion + ResolveEdge（指针编码）+ DirType + Trial + VisitMark + ScoreUnionFields（评分框架 + compute_best_index + run stub + MAX_PASSES/THRESHOLD/MAX_TRIALS 常量）。L3 缺完整评分算法（scoreTrialDown/Up 需 TypeFactory + PcodeOp） | `unionresolve.cc` |
| 60 | `flow.cc` | — | 📋 L1 | **完全缺失**：流分析 | `flow.cc` |
| 61 | `codedata.cc` | — | 📋 L1 | **完全缺失**：代码数据分析 | `codedata.cc` |
| 62 | `capability.cc` | `capability.rs` | ✅ L3 | **完整实现**：CapabilityPoint trait（initialize）+ CapabilityRegistry（register/initialize_all/num_points）+ global_registry 全局单例。是 ArchitectureCapability/PrintLanguageCapability 等扩展点的基础 | `capability.cc` |
| 63 | `dynamic.cc` | — | 📋 L1 | **完全缺失**：动态分析 | `dynamic.cc` |
| 64 | `loadimage*.cc` (4文件) | `loadimage.rs` (364行) | ✅ **L3（2026-06-28 完整对齐）** | LoadImage trait 覆盖全部 Ghidra LoadImage 虚方法（load_fill/open_symbols/close_symbols/get_next_symbol/open_section_info/close_section_info/get_next_section/get_readonly/get_arch_type/adjust_vma + load/load_value 辅助）+ RawLoadImage（从文件读取+VMA偏移）+ MemoryLoadImage（内存缓冲）+ LoadImageFunc/LoadImageSection + DataUnavailError。10 单元测试 | `loadimage.cc` 等 |
| 65 | `cpool.cc` + `cpool_ghidra.cc` | `cpool.rs` | ✅ L3 | **完整实现**：CPoolRecord + ConstantPool trait + ConstantPoolInternal + CheapSorter + XML encode/decode。所有 L3 缺口已关闭 | `cpool.cc` |

---

## 统计汇总

> **2026-08-11：旧汇总已撤销。** 2026-06/07 的计数把结构存在、Rust
> 单测通过或局部接线误当成了 Ghidra 1:1 运行验证，并且在模块状态修改后没有
> 重新计数。当前唯一有效状态是上方逐模块行及
> `docs/alignment_audit/*_2026-08-11.md` 的锁定审计结论。在完成全量函数账本、
> 主管线可达性证明和 12.0.4 同输入直接差分前，不再发布 L1/L2/L2.5/L3
> 聚合数量。

---

## L2.5 模块接入阻塞分析（2026-06-29 新增）

> 这 9 个模块的**核心算法已 1:1 移植完成并通过测试**，但卡在"接入主管线"这一步。按阻塞原因分三类：

### 类型 A：缺 Rule 包装器（1 个，最易解锁）

| 模块 | 核心引擎 | 缺什么 | 解锁路径 |
|---|---|---|---|
| 🟢 **subflow** (#20) | SubvariableFlow 引擎完整 + 8/9 Rule 已移植+接入 oppool1/cleanup（2026-07-01） | **仅剩 RulePtrFlow**(5624, ruleaction.cc:9177)；RuleSubfloatConvert 的 TransformManager.apply 待补 | 移植 RulePtrFlow → L3。需 arch 构造 + trialSetPtrFlow/propagateFlowToDef/Reads/truncatePointer |
| 🟢 **double_precis** (新增) | SplitVarnode 核心 + 4 Rule(RuleDoubleLoad/Store/In/Out) 已移植+接入 oppool1(5643-5646)，21 测试 | *Form 子类(double.cc:1433-3196)依赖 block 级控制流，apply_rule_in 为骨架 | 移植 *Form（需 dominance/CBRANCH flip 基础设施）→ L3 |

### 类型 B：Ghidra 设计上不属于 universalAction（4 个，非 bug）

| 模块 | Ghidra 真实定位 | 为什么不接入 |
|---|---|---|
| 🟢 **callgraph** (#51) | 程序级全局对象，仅控制台命令 `IfcCallGraphBuild`（ifacedecomp.cc:2721）构建 | universalAction 是 per-function 的，与 CallGraph 全局粒度不匹配 |
| 🟢 **unify** (#27) | **规则编译器代码生成工具**（rulecompile.cc/ruleparse.y），构建时生成自定义 Rule 的 C++ | 运行时不被调用；Rugra 的 Rule 全部手写，与 Ghidra 内置 Rule 一致 |
| 🟢 **float_emulate** (#41) | Ghidra **无** float emulation Action；float 语义由 Rule 处理 | RuleFloatRange/RuleFloatCast 等已在 oppool1/cleanup（L3）；float_emulate.rs 作为底层求值库被间接使用 |
| 🟢 **grammar** (#50) | .cspec/.pspec 解析器，架构初始化时用 | 非反编译运行时 Action。注意：同条的 expression.rs **已接入**主管线（printc 用 TermOrder 排序） |

### 类型 C：被 Sleigh 基础设施阻塞（3 个 + 1 个额外 L2.5）

| 模块 | 阻塞点 | 依赖链 |
|---|---|---|
| 🟢 **userop** (#26) | 缺 `architecture.cc:635 userops.initialize` | 被 ActionSegmentize（coreaction.cc:624-649）消费 → 需 .pspec CALLOTHER 注册 |
| 🟢 **pcodeinject** (#45) | 缺 `architecture.cc:638 buildPcodeInjectLibrary` | 被 ActionConstbase（coreaction.cc:686-690 `doLiveInject`）消费 → 需 .cspec decodeInject |
| 🟢 **pcodeparse** (#46) | 同上 | inject_sleigh.cc:373 `PcodeSnippet` 解析 inject payload → 需 Sleigh 架构初始化 |
| 🟢 **emulate** (#39) | 缺 BreakTable/EmulateFunction 集成包装器 | jumptable.rs 已用 EmulateFunction（L3）；emulate.rs 核心引擎（execute_current_op dispatch + execute 主循环 + LOAD/STORE）完整，4 测试 |

> **类型 C 共同根因**：缺 Sleigh 架构初始化层（architecture.cc:635/638）。这是 userop/pcodeinject/pcodeparse 三个模块的共同阻塞点。Rugra 用 iced-x86 替代 Sleigh，需补一个轻量"架构初始化"阶段从 .cspec/.pspec 加载编译器规范。

### 额外 L2.5（审计 paramid 时发现）

| 模块 | 核心算法 | 缺什么 |
|---|---|---|
| 🟢 **paramid** (#58) | walk_forward/backward 数据流分类 + calculate_rank + analyze 全部真实实现（9 函数，0 stub） | 缺 Funcdata 集成 + isLoopIn（需 BlockBasic）+ XML encode。算法完整，仅集成层缺口 |

### L2.5 接入优先级建议

1. **🔥 最高 ROI：subflow（类型 A）** — 只需写 9 个 Rule 包装器，无需新基础设施，接入后能改善子变量识别（uVar 碎片减少）
2. **emulate（类型 C）** — 核心引擎已就绪，补 BreakTable/EmulateFunction 包装器即可（jumptable 已用其 L3 部分）
3. **Sleigh 架构初始化层（解锁类型 C 全部 3 个）** — 大工程，但一次解锁 userop + pcodeinject + pcodeparse
4. **类型 B（4 个）** — Ghidra 设计如此，保持 L2.5 即可，不强行接入

---

## 模块依赖关系图（2026-06-29 新增）

> 箭头表示"被依赖 ← 依赖者"。分层从底（基础设施）到顶（输出层）。

```
┌─────────────────────────────────────────────────────────────────────┐
│ 输出层（L3）                                                          │
│  printc ← prettyprint ← printlanguage ← expression(TermOrder)        │
│    ↑                                                                 │
│    └── varmap(L2, stack spacebase 缺口) ← variable(L3, HighVariable)  │
└─────────────────────────────────────────────────────────────────────┘
         ↑
┌─────────────────────────────────────────────────────────────────────┐
│ 结构化 + 类型层                                                       │
│  blockaction(L2, orderLoopBodies) ← TraceDAG(L2, check_open)          │
│    ↑                                                                 │
│  condexe(L3) → ActionConditionalExe                                  │
│  cast(L3) ← datatype(L3) ← type_infer(分析层)                        │
└─────────────────────────────────────────────────────────────────────┘
         ↑
┌─────────────────────────────────────────────────────────────────────┐
│ 优化/简化层（Rule 池，oppool1 + actcleanup）                          │
│  ruleaction(L2, 缺~30 Rule) ←── subflow(🟢L2.5, 缺9个Rule包装器)       │
│      ↑                            ↑                                  │
│      ├── unify(🟢L2.5, 设计非管线)  transform(L3, TransformManager)    │
│      ├── constseq(L3, 已接入)      float_emulate(🟢L2.5, 底层库)        │
│      └── emulate(🟢L2.5) ←── opbehavior(L3) ←── memstate(L3)          │
└─────────────────────────────────────────────────────────────────────┘
         ↑
┌─────────────────────────────────────────────────────────────────────┐
│ 分析层（SSA/Heritage/ParamID）                                        │
│  heritage(L3) → ActionHeritage                                       │
│    ↑                                                                 │
│  funcdata(L2) ← merge(L2) ← paramid(🟢L2.5)                           │
│         ↑                                                            │
│    unionresolve(L2, scoreTrialDown/Up 缺失)                          │
└─────────────────────────────────────────────────────────────────────┘
         ↑
┌─────────────────────────────────────────────────────────────────────┐
│ IR 基础设施层（全部 L3）                                               │
│  address ← varnode ← op ← pcoderaw ← opcodes ← space ← typeop         │
│  block ← cover ← rangeutil                                           │
└─────────────────────────────────────────────────────────────────────┘
         ↑
┌─────────────────────────────────────────────────────────────────────┐
│ Sleigh 基础设施层（阻塞链根因）                                        │
│  architecture.cc:635 userops.initialize ──→ 阻塞 userop(🟢L2.5)        │
│  architecture.cc:638 buildPcodeInjectLibrary ──→ 阻塞:                │
│         pcodeinject(🟢L2.5) ← pcodeparse(🟢L2.5)                       │
│         ← grammar(🟢L2.5, .cspec 解析)                                 │
│  Rugra 替代：iced-x86（仅 x86-64）                                    │
└─────────────────────────────────────────────────────────────────────┘
```

**关键依赖链（影响 curl/httpd 输出质量）**：

1. **变量恢复链**：`varmap(L2) ← variable(L3) ← printc(L3)`。varmap 的 stack spacebase 缺口导致 uVar 碎片。这是**最高 ROI 的 L2→L3 目标**。
2. **结构化链**：`blockaction(L2) ← TraceDAG(L2) ← jumptable(L3)`。orderLoopBodies 嵌套循环 + identify_internal 死锁。
3. **Rule 补全链**：`ruleaction(L2, 缺~30 Rule) ← subflow(🟢L2.5, 缺9个Rule包装器)`。subflow 接入后子变量识别改善。
4. **Sleigh 阻塞链**：`architecture 初始化 ← {userop, pcodeinject, pcodeparse}`。一次补 Sleigh 层可解锁 3 个 L2.5。

---

## 优先级路线图（按对 curl/httpd 输出质量影响排序）

### P0（最高优先级，直接影响输出质量）

1. **`varmap.cc`** (L2，stack spacebase **已解除 2026-06-29**) — ActionSpacebase 接入后 RSP 输入标记为 SPACEBASE，varmap/printc 正确识别栈指针，**curl uVar 149→0**。**剩余阻碍**：alias_block_level、LoadGuard addGuard、RIP-relative 全局 LOAD/STORE 类型传播。
2. **`blockaction.cc` orderLoopBodies 嵌套循环** (L2→L3) — 循环/if 结构化
3. **TraceDAG 完整评分** (L2→L3) — 多入边 CBR goto 标记
4. **`coreaction.cc` 缺失 30 Actions** (L1→L3) — P-code 优化
5. **`ruleaction.cc` 缺失 60 Rules** (L1→L3) — P-code 简化

### P1（高优先级，影响语义恢复）

6. **`signature.cc`** (L2→L3) — 标准库签名匹配（骨架已存在）
7. **`jumptable.cc`** (已 L3) — Switch 跳转表分析（已完成，需回归验证）
8. **`condexe.cc`** (L2→L3) — 条件执行图重写（**核心算法全部缺失**，首个攻坚目标）
9. **`type.cc` typegrp** (L2→L3) — 类型约束求解

### P0.5（2026-07-27 新增，解锁 printc PTRSUB/CAST 发射）

> **背景**：2026-07-27 完成 RPN 路径 `dispatch_op_rpn` 的 `opPtrsub`/`opTypeCast` faithful port（见 docs/api/printc.md），但实测 curl 中**不存在** `CPUI_PTRSUB`/`CPUI_CAST` op，故新 dispatch 不触发。解锁需补以下两条底层 infra：

10. **`RulePtrsub` 创建规则缺失** (L1→L3) — Rugra 只移植了消费现有 PTRSUB 的规则（`RulePtrsubUndo`/`RulePtrsubCharConstant`/`RulePtraddUndo`，见 action.rs:680-681,723），**缺** Ghidra 的 `RulePtrsub`（INT_ADD(指针,常量)→PTRSUB 的创建规则）与 `RulePtradd`。补齐后 curl 结构体字段访问 `ptr->field` 才能产生 PTRSUB op，printc dispatch 即生效。
11. **`ActionSetCasts` PTRSUB/PTRADD pointer-fit + castOutput 延后** (✅ 已 L3, 2026-07-27) — coreaction.rs:2893-2897 注释：当前 `castInput` 只走 integer binary/unary 路径，PTRADD/PTRSUB pointer-fit 检查、resolveUnion、checkPointerIssues、castOutput 均延后。补齐后 CPUI_CAST op 在 curl 中产生，printc `(type)x` dispatch 即生效。次要：`ActionSetCasts::apply` 返回 `NO_CHANGE` 即使 count>0（coreaction.rs:2915，可能是 bug，需核实 Ghidra 返回值）。

    **✅ 2026-07-27 已修复**：新增 `cast_input_ptr`（PTRSUB/PTRADD slot-0 pointer-fit + CAST 插入）+ `ptr_input_reqtype`（从 output pointer 类型派生 slot-0 reqtype）+ apply 接入 `cast_output` 第二轮遍历 + `output_metatype` 排除指针产生 op（PTRSUB/PTRADD/LOAD/CALL/COPY/etc. → None）+ apply 返回值修正（count>0 → CHANGE）+ 5 新单元测试（1292 全过）。剩余 `resolveUnion`/`checkPointerIssues`/完整 struct-field resolution 仍延后。

10. **`transform.cc`** (已 L3) — P-code 变换基础设施（已完成）

### P2（🟢 L2.5 — 代码完整，最高 ROI 解锁路径）

11. **`subflow.cc`** (🟢 L2.5，类型 A) — SubvariableFlow 引擎完整（`subflow.rs`），但驱动它的 9 个 Rule（RuleSubvarAnd/RuleSubvarSubpiece/RuleSplitFlow/RulePtrFlow 等，coreaction.cc:5621-5633）未移植。**移植这 9 个 Rule → oppool1 → L3**。无需新基础设施。
12. **`constseq.cc`** (✅ 已 L3, 2026-06-29) — RuleStringCopy/RuleStringStore 已接入 cleanup 池。transform 阶段（CALLOTHER 替换）待 userop 基础设施。
13. **`rangeutil.cc`** (✅ 已 L3) — CircleRange 已被 jumptable 使用。
14. **`emulate.cc`** (🟢 L2.5，类型 C) — 核心引擎（execute_current_op + execute 主循环 + LOAD/STORE）完整，4 测试。缺 BreakTable/EmulateFunction 集成包装器。补包装器即可接入。
15. **`paramid.cc`** (🟢 L2.5，额外发现) — walk_forward/backward + calculate_rank + analyze 全部真实实现（9 函数，0 stub）。缺 Funcdata 集成 + isLoopIn + XML encode。

### P3（🟢 L2.5 — 设计上非主管线模块，代码完整不强行接入）

16. **`unify.cc`** (🟢 L2.5，类型 B) — Ghidra 的 unify 引擎是**规则编译器代码生成工具**（rulecompile.cc/ruleparse.y），构建时生成自定义 Rule 的 C++，运行时不被 universalAction 调用。Rugra 的 Rule 全部手写，与 Ghidra 内置 Rule 一致。
17. **`float.cc` + `double.cc`** (🟢 L2.5，类型 B) — Ghidra **无** float emulation Action；float 语义由 Rule 处理（RuleFloatRange/RuleFloatCast 等已在 oppool1/cleanup）。float_emulate.rs 作为底层求值库。
18. **`callgraph.cc`** (🟢 L2.5，类型 B) — 程序级全局对象，Ghidra 仅通过控制台命令（ifacedecomp.cc:2721）构建，非 universalAction。Rugra 主管线是 per-function，粒度不匹配。
19. **`grammar.cc`** (🟢 L2.5，类型 B) — .cspec/.pspec 解析器，架构初始化时用（非反编译运行时）。同条 expression.rs 已接入。

### P4（🟢 L2.5 — 被 Sleigh 基础设施阻塞）

20. **`userop.cc`** + **`pcodeinject.cc`** + **`pcodeparse.cc`** (🟢 L2.5，类型 C) — Ghidra 在 architecture.cc:635/638 初始化 UserOpManage 和 PcodeInjectLibrary，被 ActionSegmentize/ActionConstbase 消费。Rugra 缺 Sleigh 架构初始化 + .cspec/.pspec 解析。**这是 3 个模块的共同阻塞点**——一次补 Sleigh 架构初始化层可全部解锁。
21. **Sleigh 多架构** (战略排除) — ARM/MIPS/RISC-V 支持（需 Sleigh，见〇节）

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


---

## 2026-07-16 并发审计结果（blockaction + printc + op + varnode）

来源：3 个 Explore agent 交叉审计 + 直接修复。

### 已修复（已 commit）

| commit | 文件 | 修复内容 | 根因 |
|---|---|---|---|
| d5de768 | op.rs | PcodeOp::isMoveable 完整移植（op.cc:178-271） | 此前是 stub（return true）；另修 Arc::as_ptr 对 dyn FlowBlock 的 cast 编译错误 |
| deff71a | op.rs | opcode_flags 全量表 + 接入 create/change_opcode | set_opcode_flags 只处理 7 个 opcode 组，其余 fallthrough 到 0；且从未被调用 → get_eval_type() 对所有算术 op 返回 0 |
| 61e916a | varnode.rs | contains + overlap 常量空间短路 | 缺 Ghidra IPTR_CONSTANT→3/-1 短路（varnode.cc:109 / address.cc:159） |
| 220c14c | op.rs/opcodes.rs | INT_LEFT/INT_DIV 不可交换 + INT_CARRY/INT_SCARRY 可交换 | opcode_flags 表 + is_commutative 均误；typeop.cc:1505/1645/1335/1351 |
| 6419b44 | varmap.rs | gatherVarnodes PIECE/SUBPIECE 分支 | 此前落入 default 无条件 addFixedType；varmap.cc:1165-1196 |
| 34e6f9c | blockaction.rs | try_rule_or 调用 negate_condition | **B1：18 回归根因**。此前有注释但从未调用 → BlockCondition 极性错误 |
| b4b4617 | printc.rs | goto 标签 LAB_ → code_r0xXXXX | 无 Ghidra 对应物；现镜像 emitLabel（printc.cc:3164） |

### blockaction collapseAll 5-step 移植阻断清单（来自审计）

Ghidra `collapseAll`（blockaction.cc:1877-1893）5 步：orderLoopBodies → collapseConditions → collapseInternal(NULL) → selectGoto 循环 → collapseInternal(targetbl)。Rugra 当前是 7-phase。**B1（try_rule_or negateCondition）已修复**。**B2（new_block_condition/if/if_else 工厂层）已修复（37f99a2）**。**B4（set_goto_branch 3-op 完整化）已修复（0377b4c）**。**B8（collapse_conditions fixpoint + 删除 collapse_bool_conditions）已修复（18d227a）**。剩余阻断：

- ~~**B2**: 缺 `new_block_condition`/`new_block_if`/etc. 工厂层~~ **已修复（37f99a2）**。
- ~~**B3**: `try_rule_inf_loop`（blockaction.rs:3261）不创建 BlockInfLoop（只 eprintln）。缺 BlockInfLoop struct。~~ **已修复（c77a545）**：新增 BlockInfLoop struct + new_block_inf_loop 工厂 + try_rule_inf_loop 真正创建节点 + printc emit_structured_infloop。
- ~~**B4**: `set_goto_branch` 不完整~~ **已修复（0377b4c）**：现做 Ghidra 3 件事（edge flag + source INTERIOR_GOTOOUT + target INTERIOR_GOTOIN）。
- ~~**B5**: 缺 `update_loop_body` 状态机（cc:1193-1253）+ loopbodyiter 推进。~~ **已修复（952eeb7）**：update_loop_body + select_goto 状态机实现，接入 run_goto_cascade 为首选路径。
- ~~**B6**: 缺 `finaltrace`/`likelygoto`/`likelyiter`/`likelylistfull` 状态字段。~~ **已修复（952eeb7）**：5 个状态字段加入 CollapseStructure。
- ~~**B7**: TraceDAG 边一次性快照，非 Ghidra 的每轮重新解析（getCurrentEdge）。~~ **已修复（952eeb7）**：FloatingEdge::get_current_edge 按轮重新解析。
- ~~**B8**: collapse_conditions 单遍非 fixpoint~~ **已修复（18d227a）**：现 do-while fixpoint，删除 collapse_bool_conditions 重复实现。
- ~~**B9**: apply_rules_to_block 缺 try_rule_if_no_exit + try_rule_case_fallthru（cc:1840 第二内循环）。~~ **已修复（e6731bb）**：phase2 加 collapseInternal 第二趟（IfNoExit per-block + CaseFallthru batch），外层 'fullchange 循环包裹内层 fixpoint。

**最小路径**：B1（已修）→ ~~B2/B3/B4/B5/B6/B7/B8/B9~~（**全部已修**）→ ~~重写 collapse_all 为 5 步~~ **已实现（76bbead）+ 硬化（7f3debf）+ 突破（413728c）+ 默认切换（30600b1）**：`collapse_all_5step` 字面 5 步现是**默认**（`RUGRA_7PHASE=1` 回退 7-phase）。调和：collapse_loops + collapse_switches（7-phase phase1 方法）在 collapse_internal 前运行，消除 while-break→WhileDo + switch→BlockSwitch 分歧。**953/953 测试通过，curl 24/24 defects=0 numbering=485（与 7-phase 完全一致），httpd 27/29 gcc-clean（同 baseline）**。collapseAll 5-step 移植完成。

### printc 对齐缺口（来自审计，按影响排序）

- **P1（最高潜在缺陷）**: 无 OpToken 优先级引擎 / 无括号化。Ghidra printlanguage.cc:269 parentheses + emitOp。Rugra op_binary/op_unary 直接拼 infix 串，嵌套表达式可能语义错误（如 `a + b << c`、`x && y == z`）。curl 语料未触发但风险高。
- ~~**P2**: goto/label 发射在 op 层非 block 层；无 flat/no_branch/only_branch mod 栈。~~ **已关闭（非活跃）**：分析发现 Rugra 的结构化输出已正确抑制分支——`emit_block_ops` 在结构化路径用 `skip_terminal=true` 跳过 CBRANCH/BRANCH/BRANCHIND（printc.rs:479-488），BRANCH 无条件跳过（:475）。curl 输出 0 个 `goto`/`if(...)goto`。op_cbranch/op_branch 仅在 skip_terminal=false 时调用（flat/非结构化回退），而 Rugra 不产 flat 输出，故 P2 非活跃缺口。Ghidra 的 flat-mod gating 在 Rugra 无对应输出模式，不需要。
- **P3（已修）**: 标签格式 LAB_ vs code_r0xXXXX。✅ b4b4617
- **P4**: 变量声明/编号顺序用 op 遍历首次触及顺序，非 Ghidra nametree 顺序。是 numbering diff 的主因。**分析（2026-07-16）**：Ghidra `assignDefaultNames` 遍历 `SymbolNameTree`（按 name 排序，tie-break `nameDedup`）。**栈变量路径已对齐**：`doc_variable_decls_from_funcdata` 按 `scope.symbols`（stack offset 顺序）遍历。**寄存器变量已改进（3118552）**：`preallocate_register_compact_names` 按 def-op 地址序预分配 compact 名（近似 Ghidra nameDedup 创建序）。numbering=485 不变（defects=0，编号是外观差异；Ghidra 精确 nameDedup 是 HighVariable 创建序，def-op 地址是近似）。
- ~~**P5**: for 循环 init/iter 是预算字符串非重发表达式；无 comma_separate。~~ **部分修复（8277ce7）**：for-loop header 发射现激活 comma_separate mod（对齐 emitForLoop printc.cc:2973-2990）。init/iter 仍烘焙字符串（非 raw PcodeOp 重发），但 latent（curl 0 个 for 循环）。
- **P6**: switch 加 `(long)` cast（Ghidra 无）；case 用 char 字面量（Ghidra 用 pushConstant 数值）；break 抑制逻辑不同；无 fallthrough 处理。
- **P7**: ~~缺 BlockInfLoop~~ **已修复（c77a545）**：emit_structured_infloop 输出 `do { } while(true);`。~~剩余 overflow_syntax while 形式~~ **已修复（65b0eda）**：BlockWhileDo.overflow_syntax 字段 + try_rule_while_do 设 bl.is_complex() + emit_structured_whiledo 发射 while(true)+if(cond)break（cc:3017-3044）。P7 完成。
- ~~**P8**: emitBlockCondition 复合 &&/|| 发射为独立语句非合并条件。~~ **已修复（1f24f18）**：emit_structured_condition 对顶层 BlockCondition 现发射 `if (left && right) {}`，capture_block_condition 递归处理嵌套。
- ~~**P9**: 无 else if 链化（pending_brace）；总是 `else { if... }`。~~ **已修复（dac9645）**：emit_structured_if 的 else 分支检测 else_body 是否为 BlockIf，若是发射 `else if(...)`（递归 emit_structured_if）而非 `else { if(...){} }`。
- ~~**P10**: doc_statement 无条件加 `;`；无 comma_separate。~~ **已修复（1f24f18）**：print_mods 模块 + mods/mod_stack 字段 + is_set/push_mod/pop_mod/set_mod/unset_mod；doc_statement 按 `!is_set(COMMA_SEPARATE)` 条件输出 `;`。

### op/varnode 死代码（已标注，低优先级直到接入）

`update_cover`（cover->rebuild 是 no-op TODO）、`set_num_inputs`（保留已有 slot 非 Ghidra 全清零）、`next_op_in_flow`/`previous_op_in_block`/`target_sp`（全局 alivelist 扫描非 block-local）、`print_info`/`print_cover`（debug 用，无调用者）。均为零调用者，待接入主管线时再对齐。
