# Rugra-Ghidra 完整对齐路线图

**日期**: 2026-06-26  
**目标**: 完整实现 Ghidra 反编译器的所有算法，不使用简化版。

## 图例

- **L1** (📋 计划) — 已识别差距，尚未开始实现
- **L2** (🔧 实现中) — 正在实现，核心代码已存在但功能不完整
- **L3** (✅ 已完成) — 已完整实现并对齐验证（有测试证据）

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
| 10 | `rangeutil.cc` | — | 📋 L1 | **完全缺失**：RangeMem 范围工具，影响 loop body 管理 | `rangeutil.cc` |

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
| 17 | `blockaction.cc` (~1600行) | `blockaction.rs` (~3500行) | 🔧 L2 | identifyInternal/selfIdentify ✅；ruleBlockCat/ProperIf/IfElse/WhileDo/DoWhile/Goto ✅；**缺少**：orderLoopBodies 嵌套循环结构化、TraceDAG 完整评分 | `blockaction.cc` |
| 18 | TraceDAG (blockaction.cc 内) | `tracedag.rs` | 🔧 L2 | BranchPoint/BlockTrace/BadEdgeScore 骨架已移植；**check_open 精度不足，未完整启用** | `blockaction.cc:499-1014` |
| 19 | `condexe.cc` | — | 📋 L1 | **完全缺失**：ConditionalExecution + RuleOrPredicate 条件折叠 | `condexe.cc` |
| 20 | `subflow.cc` | — | 📋 L1 | **完全缺失**：子流分析（代码可达性、不可达代码消除） | `subflow.cc` |
| 21 | **`jumptable.cc`** | `jumptable.rs` | ✅ L3 | **完整实现**：全部数据结构 + 全部算法（find_determining_varnodes DFS 深度遍历、quasi_copy 链、get_max_value、isLoadInPath、CircleRange::pullBack 全套、analyze_guards pullBack 扩展、backup2_switch 反向模拟、find_unnormalized 链遍历、flows_only_to_model、emulate_path 地址计算、build_addresses/build_labels 使用真实模拟、fold_in_one_guard + fold_in_guards CFG 重写 via Funcdata::push_branch/force_goto）。Funcdata 新增 push_branch/force_goto/set_goto_branch/move_out_edge。所有 L3 缺口已关闭 | `jumptable.cc` |

---

## 四、优化与简化规则

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 22 | `coreaction.cc` (~2000行) | `coreaction.rs` (~800行) | 🔧 L2 | 已实现 ~10 个 Action；**缺少约 30+ 个优化 Action**（见下方详细列表） | `coreaction.cc` |
| 23 | `ruleaction.cc` (~3000行) | `ruleaction.rs` (~1200行) | 🔧 L2 | 已实现 ~15 个 Rule；**缺少约 60+ 个简化规则**（见下方详细列表） | `ruleaction.cc` |
| 24 | `constseq.cc` | — | 📋 L1 | **完全缺失**：常量序列分析 | `constseq.cc` |
| 25 | `transform.cc` | — | 📋 L1 | **完全缺失**：P-code 变换基础设施（Dolphin 重写） | `transform.cc` |
| 26 | `userop.cc` | — | 📋 L1 | **完全缺失**：用户自定义操作（call其他、宏展开） | `userop.cc` |
| 27 | `unify.cc` | — | 📋 L1 | **完全缺失**：统一模式匹配（规则基础设施） | `unify.cc` |

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
| `ActionMultiCse` | 879 | MULTIEQUAL(phi) 冗余消除 | 缺 functionalEqualityLevel |
| `ActionShadowVar` | 892 | 影子变量 | INDIRECT 处理 |
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
| `RuleSelectCse` | 187 | CSE 基础设施 |
| `RulePushMulti` | 1074 | functionalEqualityLevel/opDestroy |
| `RulePullsubMulti` | 880 | minMaxUse/replaceDescendants |
| `RulePullsubIndirect` | 962 | INDIRECT 处理 |
| `RuleBooleanNegate` | 2969 | isBooleanValue/isTypeRecoveryOn |
| `RuleBoolZext` | 3015 | 后代追踪 |
| `RuleLogic2Bool` | 3138 | isBooleanValue |
| `RuleIndirectCollapse` | 3177 | INDIRECT |
| `RuleMultiCollapse` | 3254 | functionalEqualityLevel |
| `RuleEarlyRemoval` | 25 | opDestroy/doesDeadcode/isAutoLive |
| `RuleRangeMeld` | 1357 | RangeList |
| `RuleFloatRange` | 1450 | float 类型 |
| `RuleBitUndistribute` | 2634 | zext/sext 后代追踪 |
| `RuleBooleanUndistribute` | 2731 | 后代追踪 |
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
| 29 | `cast.cc` | `type_system/cast.rs` | 🔧 L2 | 基本 cast 逻辑；缺少完整的多级 cast 插入 | `cast.cc` |
| 30 | `signature.cc` + `modelrules.cc` | — | 📋 L1 | **完全缺失**：函数签名匹配 + 模型规则 | `signature.cc`, `modelrules.cc` |
| 31 | `signature_ghidra.cc` | — | 📋 L1 | **完全缺失**：Ghidra 签名格式 | `signature_ghidra.cc` |
| 32 | `analyzesigs.cc` | — | 📋 L1 | **完全缺失**：签名分析 | `analyzesigs.cc` |

---

## 六、代码生成（打印层）

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 33 | `printc.cc` (~2500行) | `printc.rs` (~3000行) | 🔧 L2 | C 输出工作（24/24 + 29/29 gcc 通过）；缺少一些格式化特性 | `printc.cc` |
| 34 | `printlanguage.cc` | `printlanguage.rs` | 🔧 L2 | Emit 架构对齐；缺少完整 markup 支持 | `printlanguage.cc` |
| 35 | `prettyprint.cc` | `prettyprint.rs` | 🔧 L2 | EmitNoMarkup 对齐；post_process 已实现 | `prettyprint.cc` |
| 36 | `fspec.cc` | `fspec.rs` | 🔧 L2 | 基本函数规格；缺少完整选项系统 | `fspec.cc` |
| 37 | `options.cc` | `options.rs` | 🔧 L2 | **骨架已移植**：ArchOption trait + OptionDatabase 分发器 + 37 个注册选项。9 个完全功能化（inferconstptr/analyzeforloops/readonly/jumptablemax/maxinstruction/aliasblock/nanignore/splitdatatype/defaultprototype 直接修改 Architecture 字段）。L3 缺 PrintLanguage/ActionDatabase 选项 + XML decode | `options.cc` |
| 38 | `comment.cc` | `comment.rs` | 🔧 L2 | **骨架已移植**：Comment + comment_type 标志 + CommentDatabaseInternal（add_comment/clear_type/comments_for_function/encode/decode）+ CommentSorter（setup_function_list/header_comments）+ Subsort。L3 缺 CommentSorter::findPosition 的基本块关联（需 Funcdata op-tree） | `comment.cc` |

---

## 七、模拟执行

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 39 | `emulate.cc` | — | 📋 L1 | **完全缺失**：P-code 模拟执行（影响常量传播/符号执行） | `emulate.cc` |
| 40 | `emulateutil.cc` | — | 📋 L1 | **完全缺失**：模拟工具 | `emulateutil.cc` |
| 41 | `float.cc` + `double.cc` + `multiprecision.cc` | — | 📋 L1 | **完全缺失**：浮点/多精度运算模拟 | `float.cc`, `double.cc`, `multiprecision.cc` |
| 42 | `opbehavior.cc` | — | 📋 L1 | **完全缺失**：操作行为模拟 | `opbehavior.cc` |
| 43 | `memstate.cc` | — | 📋 L1 | **完全缺失**：内存状态模拟 | `memstate.cc` |
| 44 | `context.cc` + `globalcontext.cc` | `context.rs` | 🔧 L2 | **骨架已移植**：ContextBitRange（位范围编码/解码）+ TrackedContext/TrackedSet + ContextBlob + ContextDatabase trait + ContextInternal（内存分区映射）+ ContextCache。解锁 Architecture::context + SegmentedResolver。L3 缺 XML encode/decode + partmap + ParserContext（SLEIGH） | `context.cc`, `globalcontext.cc` |

---

## 八、P-code 注入与重写

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 45 | `pcodeinject.cc` | — | 📋 L1 | **完全缺失**：P-code 注入引擎 | `pcodeinject.cc` |
| 46 | `pcodecompile.cc` + `pcodeparse.cc` | — | 📋 L1 | **完全缺失**：P-code 编译/解析 | `pcodecompile.cc`, `pcodeparse.cc` |

---

## 九、架构支持

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 47 | Sleigh (20+ 文件) | `iced-x86` (仅 x86-64) | 🔧 L2 | **仅支持 x86-64**；不支持 ARM/MIPS/RISC-V/PowerPC | `sleigh*.cc`, `slgh*.cc` |
| 48 | `architecture.cc` | `arch.rs` | 🔧 L2 | **骨架已移植**：Ghidra Architecture 配置容器（全部字段 + 默认值 + resetDefaultsInternal）+ ArchitectureCapability trait + CapabilityRegistry + ProtoModelEntry。L3 缺虚拟工厂钩子（buildTranslator/buildLoader 等）+ XML decode | `architecture.cc` |
| 49 | `translate.cc` | `disasm/x86_lift.rs` | 🔧 L2 | 仅 x86-64 提升 | `translate.cc` |
| 50 | `grammar.cc` + `expression.cc` | — | 📋 L1 | **完全缺失**：语法/表达式解析 | `grammar.cc`, `expression.cc` |

---

## 十、其他基础设施

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 51 | `callgraph.cc` | — | 📋 L1 | **完全缺失**：调用图构建 | `callgraph.cc` |
| 52 | `database.cc` + `database_ghidra.cc` | `database.rs` | 🔧 L2 | **XML encode/decode 已实现**：SymbolEntry/Symbol（encode_header/decode_header/encode_body/decode_body/encode/decode）/Scope（encode_recursive/decode）/Database（encode/decode）全部使用 marshal.rs 的 Encoder/Decoder trait。ID_BASE 修正为 0x4000...。L3 仅缺 rangemap/partmap（目前用线性搜索/Vec 替代） | `database.cc`, `database_ghidra.cc` |
| 53 | `xml.cc` + `marshal.cc` | `marshal.rs` | 🔧 L2 | **骨架已移植**：AttributeId/ElementId 注册表 + Element/Document DOM 树 + Encoder/Decoder trait + TreeEncoder/TreeDecoder 内存实现（完整 round-trip）。解锁 database/override/arch 的 XML encode/decode。L3 缺 PackedEncode/PackedDecode 二进制格式 + XML 文本解析 | `xml.cc`, `marshal.cc` |
| 54 | `stringmanage.cc` + `string_ghidra.cc` | `stringmanage.rs` | 🔧 L2 | **完整 UTF 解码已移植**：StringManager + StringManagerUnicode（LoadImage 集成）+ write_utf8/read_utf16/get_codepoint（UTF8/UTF16/UTF32 + 代理对）/check_characters/has_char_terminator/write_unicode/assign_string_data。L3 缺 XML encode/decode | `stringmanage.cc` |
| 55 | `crc32.cc` + `compression.cc` | — | 📋 L1 | **完全缺失**：CRC32/压缩 | `crc32.cc`, `compression.cc` |
| 56 | `override.cc` | `override_rs.rs` | ✅ L3 | **完整实现**：Override + FlowOverride 完整 in-memory + XML encode/decode（使用 marshal.rs）。所有命令类型（forcegoto/deadcodedelay/indirectover/protoover/multistagejump/flowoverride）的 insert/query/apply/encode/decode 全部实现 | `override.cc` |
| 57 | `prefersplit.cc` | `prefersplit.rs` | 🔧 L2 | **骨架已移植**：PreferSplitRecord（storage + splitoffset + 排序）+ PreferSplitManager（init/find_record/records + split stub）+ SplitInstance（fillin/lo_size/hi_size 端序计算）+ initialize 排序。L3 缺完整分裂算法（testX/splitX 需 Funcdata op 编辑） | `prefersplit.cc` |
| 58 | `paramid.cc` | — | 📋 L1 | **完全缺失**：参数 ID 分析 | `paramid.cc` |
| 59 | `unionresolve.cc` | — | 📋 L1 | **完全缺失**：联合体解析 | `unionresolve.cc` |
| 60 | `flow.cc` | — | 📋 L1 | **完全缺失**：流分析 | `flow.cc` |
| 61 | `codedata.cc` | — | 📋 L1 | **完全缺失**：代码数据分析 | `codedata.cc` |
| 62 | `capability.cc` | `capability.rs` | ✅ L3 | **完整实现**：CapabilityPoint trait（initialize）+ CapabilityRegistry（register/initialize_all/num_points）+ global_registry 全局单例。是 ArchitectureCapability/PrintLanguageCapability 等扩展点的基础 | `capability.cc` |
| 63 | `dynamic.cc` | — | 📋 L1 | **完全缺失**：动态分析 | `dynamic.cc` |
| 64 | `loadimage*.cc` (4文件) | `loadimage.rs` | 🔧 L2 | **骨架已移植**：LoadImage trait（load_fill/load/load_value/get_arch_type/adjust_vma + symbols/sections/readonly）+ RawLoadImage（从文件读取，vma 偏移）+ MemoryLoadImage（内存缓冲）。解锁 EmulateFunction/JumpBasic/Architecture 的 LoadImage 依赖 | `loadimage.cc` 等 |
| 65 | `cpool.cc` + `cpool_ghidra.cc` | `cpool.rs` | 🔧 L2 | **骨架已移植**：CPoolRecord（tag/token/value/type/byte_data + 标志）+ ConstantPool trait（get/create/put_record）+ ConstantPoolInternal（BTreeMap）+ CheapSorter（2整数引用键）。L3 缺 XML encode/decode（需 TypeFactory） | `cpool.cc` |

---

## 统计汇总

| 级别 | 数量 | 说明 |
|---|---|---|
| ✅ **L3（已完成）** | **16** | 核心 IR/数据模型，基础 Action/Rule |
| 🔧 **L2（实现中）** | **16** | 核心算法部分实现，关键功能缺失 |
| 📋 **L1（计划中）** | **33+** | 完全缺失的模块，需要从零实现 |
| **总计** | **65+** | Ghidra 114 个源文件中已覆盖/已识别 |

---

## 优先级路线图（按对 curl/httpd 输出质量影响排序）

### P0（最高优先级，直接影响输出质量）

1. **`varmap.cc`** (L2→L3) — 算法层已 1:1 对齐并接入 printc；**剩余阻碍**：RSP→Stack spacebase 提升通道（Rugra x86 lift 不产 Stack-space varnode，导致 gather_varnodes 基本为空，uVar 碎片未消除）
2. **`blockaction.cc` orderLoopBodies 嵌套循环** (L2→L3) — 循环/if 结构化
3. **TraceDAG 完整评分** (L2→L3) — 多入边 CBR goto 标记
4. **`coreaction.cc` 缺失 30 Actions** (L1→L3) — P-code 优化
5. **`ruleaction.cc` 缺失 60 Rules** (L1→L3) — P-code 简化

### P1（高优先级，影响语义恢复）

6. **`signature.cc`** (L1→L3) — 标准库签名数据库
7. **`jumptable.cc`** (L1→L3) — Switch 跳转表分析
8. **`condexe.cc`** (L1→L3) — 条件执行分析
9. **`type.cc` typegrp** (L2→L3) — 类型约束求解
10. **`transform.cc`** (L1→L3) — P-code 变换基础设施

### P2（中优先级，影响完整性）

11. **`subflow.cc`** (L1→L3) — 子流分析
12. **`unify.cc`** (L1→L3) — 模式匹配基础设施
13. **`constseq.cc`** (L1→L3) — 常量序列
14. **`userop.cc`** (L1→L3) — 用户操作
15. **`rangeutil.cc`** (L1→L3) — 范围工具

### P3（低优先级，影响边缘场景）

16. **`emulate.cc`** + `opbehavior.cc` + `memstate.cc` (L1→L3) — 模拟执行
17. **`float.cc` + `double.cc`** (L1→L3) — 浮点支持
18. **`comment.cc`** (L1→L3) — 注释恢复
19. **`callgraph.cc`** (L1→L3) — 调用图
20. **Sleigh 多架构** (L2→L3) — ARM/MIPS/RISC-V 支持
