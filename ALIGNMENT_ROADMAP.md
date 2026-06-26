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
| 21 | **`jumptable.cc`** | — | 📋 L1 | **完全缺失**：间接跳转表分析（switch 跳转表目标恢复） | `jumptable.cc` |

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

### coreaction.cc 缺失 Action 列表（L1 → L2 → L3）

| Ghidra Action | 状态 | 功能 |
|---|---|---|
| `ActionStart` | ✅ L3 | 初始化 |
| `ActionHeritage` | ✅ L3 | SSA 构建 |
| `ActionInferParams` | ✅ L3 | 参数推断 |
| `ActionCopyPropagate` | ✅ L3 | COPY 传播 |
| `ActionDeadCode` | ✅ L3 | 死代码消除 |
| `ActionBlockStructure` | ✅ L3 | 块结构化 |
| `ActionMergeType` | ✅ L3 | 类型合并 |
| `ActionTypeInfer` | ✅ L3 | 类型推断 |
| `ActionTypePropagate` | ✅ L3 | 类型传播 |
| `ActionCallParams` | ✅ L3 | CALL 参数处理 |
| `ActionConstantPtr` | ✅ L3 | 常量指针 |
| `ActionCse` | ✅ L3 | 公共子表达式消除 |
| `ActionSimplify` | ✅ L3 | P-code 简化 |
| `ActionNormalizeBranches` | ✅ L3 | 分支规范化 |
| `ActionFinalStructure` | ✅ L3 | 最终结构化 |
| `ActionRestrictLocal` | 📋 L1 | 限制局部变量 |
| `ActionRestrictGlobal` | 📋 L1 | 限制全局变量 |
| `ActionPrototypeTypes` | 📋 L1 | 原型类型 |
| `ActionPrototypeComments` | 📋 L1 | 原型注释 |
| `ActionDynamicTokens` | 📋 L1 | 动态令牌 |
| `ActionCast` | 📋 L1 | Cast 插入 |
| `ActionReturnRegression` | 📋 L1 | 返回值回归分析 |
| `Actionnodethunk` | 📋 L1 | Thunk 消除 |
| `ActionFuncbinding` | 📋 L1 | 函数绑定 |
| `ActionVmeven` | 📋 L1 | VM 事件 |
| `ActionMultiCse` | 📋 L1 | 多重 CSE |
| `ActionShadowVar` | 📋 L1 | 影子变量 |
| `ActionPreferCombine` | 📋 L1 | 优先合并 |
| `ActionBitAnalysis` | 📋 L1 | 位分析 |
| `ActionSlice` | 📋 L1 | 切片分析 |
| `ActionHhrlLocal` | 📋 L1 | 局部变量恢复 |
| `ActionLikelyTypedef` | 📋 L1 | 类型定义推断 |
| `ActionSwitch` | 📋 L1 | Switch 分析 |
| `ActionConditionalExe` | 📋 L1 | 条件执行消除 |

### ruleaction.cc 缺失 Rule 列表（L1 → L2 → L3）

**已实现（L3）：**
- `RuleCollapseConstants`, `RuleTransformCpool`, `RulePropagateCopy`, `RulePropagateCopy2`,
  `RuleSub2Sext`, `RuleSubNormal`, `RuleShiftBitops`, `RuleShiftCompare`,
  `RuleDivOpt`, `RuleSignDiv2`, `RuleSignShift`, `RuleLessEqual`,
  `RuleEquality`, `RuleLess2Zero`, `RulePtrArith`, `RuleStructPath`

**缺失（L1，约 60+ 个）：**
- `RuleMultiCollapse`, `RuleIndirectCollapse`, `RuleLoadVarnode`, `RuleStoreVarnode`,
- `RuleStoreCpool`, `RuleSubfloatCpool`, `RuleFloatCpool`, `RuleIntLessEqual`,
- `RuleTrivialArith`, `RuleTrivialBool`, `RuleZext`, `RuleSext`,
- `RuleShiftRemain`, `RuleRightShiftAlgebraic`, `RuleLeftShiftAlgebraic`,
- `RuleNotDistribute`, `RuleHighOrderSign`, `RuleSignForm`,
- `RuleSubPieceShift`, `RuleOrMultiMask`, `RuleAndMultiMask`,
- `RuleAndOr`, `RuleAndDistribute`, `RuleOrDistribute`,
- `RuleLessNotEqual`, `RuleLessAnd`, `RuleLessOr`,
- `RuleNegateIdentity`, `RuleSubRight`, `RuleAddMultCommutative`,
- `RuleAddCommutative`, `RuleAddZero`, `RuleSubZero`,
- `RuleMultZero`, `RuleMultOne`, `RuleAddUnsigned`,
- `RuleBoolNegate`, `RuleBoolZext`, `RuleBoolPiece`,
- `RuleConcatZero`, `RuleConcatLeft`, `RuleConcatRight`,
- `RuleConcatSigned`, `RuleConcatSign`,
- `RuleSubfloatCpool`, `RuleFloatRange`, `RuleFloatSign`,
- `RuleFloatZero`, `RuleFloatNan`,
- `RulePtrsubUndo`, `RulePtraddShift`, `RulePtraddPiece`,
- `RulePiece2Zext`, `RulePiece2Sext`, `RulePiece2Merged`,
- `RuleSubpieceCpool`, `RuleSubpieceShift`, `RuleSubpieceExtend`,
- `RuleShiftPiece`, `RuleShiftCpool`,
- `RuleXorCollapse`, `RuleAndMask`, `RuleOrMask`,
- `RuleFlowCollapse`, `RuleFlowFlip`, `RuleFlowNegate`,
- `Rule flowRewrite`, `Rule flowSplit`,
- ...更多见 `ruleaction.cc` 中的 Rule 注册列表

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
| 37 | `options.cc` | — | 📋 L1 | **完全缺失**：选项系统（影响配置驱动行为） | `options.cc` |
| 38 | `comment.cc` | — | 📋 L1 | **完全缺失**：注释恢复 | `comment.cc` |

---

## 七、模拟执行

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 39 | `emulate.cc` | — | 📋 L1 | **完全缺失**：P-code 模拟执行（影响常量传播/符号执行） | `emulate.cc` |
| 40 | `emulateutil.cc` | — | 📋 L1 | **完全缺失**：模拟工具 | `emulateutil.cc` |
| 41 | `float.cc` + `double.cc` + `multiprecision.cc` | — | 📋 L1 | **完全缺失**：浮点/多精度运算模拟 | `float.cc`, `double.cc`, `multiprecision.cc` |
| 42 | `opbehavior.cc` | — | 📋 L1 | **完全缺失**：操作行为模拟 | `opbehavior.cc` |
| 43 | `memstate.cc` | — | 📋 L1 | **完全缺失**：内存状态模拟 | `memstate.cc` |
| 44 | `context.cc` + `globalcontext.cc` | — | 📋 L1 | **完全缺失**：上下文/全局上下文 | `context.cc`, `globalcontext.cc` |

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
| 48 | `architecture.cc` | Rust 原生 | 🔧 L2 | 不同架构管理方式 | `architecture.cc` |
| 49 | `translate.cc` | `disasm/x86_lift.rs` | 🔧 L2 | 仅 x86-64 提升 | `translate.cc` |
| 50 | `grammar.cc` + `expression.cc` | — | 📋 L1 | **完全缺失**：语法/表达式解析 | `grammar.cc`, `expression.cc` |

---

## 十、其他基础设施

| # | Ghidra 模块 | Rugra 模块 | 状态 | 差距说明 | Ghidra 源码参考 |
|---|---|---|---|---|---|
| 51 | `callgraph.cc` | — | 📋 L1 | **完全缺失**：调用图构建 | `callgraph.cc` |
| 52 | `database.cc` + `database_ghidra.cc` | — | 📋 L1 | **完全缺失**：数据库持久化 | `database.cc`, `database_ghidra.cc` |
| 53 | `xml.cc` + `marshal.cc` | — | 📋 L1 | **完全缺失**：XML 序列化 | `xml.cc`, `marshal.cc` |
| 54 | `stringmanage.cc` + `string_ghidra.cc` | Rust 原生 | 🔧 L2 | 基础 rodata 扫描；缺少完整字符串管理 | `stringmanage.cc` |
| 55 | `crc32.cc` + `compression.cc` | — | 📋 L1 | **完全缺失**：CRC32/压缩 | `crc32.cc`, `compression.cc` |
| 56 | `override.cc` | — | 📋 L1 | **完全缺失**：用户覆盖系统 | `override.cc` |
| 57 | `prefersplit.cc` | — | 📋 L1 | **完全缺失**：偏好分裂分析 | `prefersplit.cc` |
| 58 | `paramid.cc` | — | 📋 L1 | **完全缺失**：参数 ID 分析 | `paramid.cc` |
| 59 | `unionresolve.cc` | — | 📋 L1 | **完全缺失**：联合体解析 | `unionresolve.cc` |
| 60 | `flow.cc` | — | 📋 L1 | **完全缺失**：流分析 | `flow.cc` |
| 61 | `codedata.cc` | — | 📋 L1 | **完全缺失**：代码数据分析 | `codedata.cc` |
| 62 | `capability.cc` | — | 📋 L1 | **完全缺失**：能力系统 | `capability.cc` |
| 63 | `dynamic.cc` | — | 📋 L1 | **完全缺失**：动态分析 | `dynamic.cc` |
| 64 | `loadimage*.cc` (4文件) | Rust 文件 I/O | 🔧 L2 | 不同的加载方式 | `loadimage.cc` 等 |
| 65 | `cpool.cc` + `cpool_ghidra.cc` | — | 📋 L1 | **完全缺失**：常量池 | `cpool.cc` |

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
