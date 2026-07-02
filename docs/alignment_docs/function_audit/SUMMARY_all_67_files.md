# Rugra 全量函数级对齐审计 — 总报告（2026-07-02）

> **67 个源文件全审，~5200+ 函数逐个对照 Ghidra .cc/.hh，6 批 50+ 并发子 Agent，零冲突。**
> 模式：纯只读审计（每函数判 ✅ALIGN / ⚠️DIFF / ❌MISSING / ➕EXTRA）。本文件是修复阶段输入清单。

## 一、TL;DR（结论先行）

**"L3 已对齐"的声明在 67 个文件中绝大多数不实。** 审计发现：

| 层 | 文件数 | 状态 |
|---|---|---|
| ✅ 真忠实/近完整 | 4 | capability / crc32 / prefersplit / unify（但 unify 全死码——rulecompile 缺） |
| 🟡 结构在但浅/有 bug | 50+ | varnode/op/block/heritage/merge/jumptable/coreaction/ruleaction/funcdata/varmap/printc/... |
| ❌ 桩/伪装端口/未接管线 | 13 | unionresolve（捏造算法）/dynamic（hash 位布局全错）/signature（捏造 hash）/grammar（无解析器）/database（未接）/emulate（LOAD 坏）/... |

**curl 输出残缺的 14 个头号根因（R1-R14，P0 批1）全部经子 Agent 逐函数对照 Ghidra 精确行核实**——不是猜测，是查证。修复这 14 个根因（按 ROI 排序）应能让 curl/httpd 输出接近 Ghidra。

## 二、curl 输出残缺的 14 个 P0 根因（单点最高 ROI）

| # | 根因 | 单点 ROI | 文件:行 | Ghidra 对照 |
|---|---|---|---|---|
| **R15** | **blockaction `collapse_cbranch_cascades` 把 if/else-if 链转 BlockSwitch** | switch 18→2 | blockaction.rs:4014 | blockaction.cc:1649 只 isSwitchOut(BRANCHIND) |
| **R50** | **printc `op_cbranch` 吞 None in1** | 6 语法错清零 | printc.rs:4192/4200/4207/4218 | printc.cc:536-580 |
| **R51** | **printc op_multiequal/indirect 发 `phi(...)`/`(indirect)`** | 非 C 行清零 | printc.rs:4016,4036 | printc.hh:331,332 no-op{} |
| **R9** | **RuleTrivialArith 实现错**（做 RuleIdentityEl 的活，没做 `x^x→0`）| switch((x^x)) 消 | ruleaction.rs:321-386 | ruleaction.cc:2382-2433 |
| **R73** | **Action::perform 硬 1 迭代 + ActionGroup 硬 2 迭代上限** | repeatapply 真生效 | action.rs:90,265 | action.cc:303-350 无界 |
| **R75** | **Rule::get_opcodes 无"全 opcode"默认** | 3 关键 Rule 覆盖补全 | action.rs:174 | action.cc:707-714 push ALL |
| **R77** | **ActionInputPrototype 建抛 ParamActive + 硬 `param_{N}`** | 48 param_ 占位退 | coreaction.rs:4186-4224 | coreaction.cc:4924 |
| **R5** | **ActionNameVars 是空桩** | 全占位名消 | coreaction.rs:3613 | coreaction.cc:2779-3006 |
| **R1** | **varmap create_entry 不回写 Symbol/HighVariable/ScopeInternal** | StackX_ 名占位消 | varmap.rs:1435 | varmap.cc:617-628 |
| **R3** | **varmap direction 符号反转**（x86 应 +1 Rugra -1）| 边界判断正 | varmap.rs:1278,558 | varmap.cc:700 |
| **R11** | **op-edit API 语义损坏**（set_input/destroy/unset_input 不维护 descend 链）| DCE 生效 | funcdata.rs:554,612,577,713 | funcdata_op.cc:104,203,291,92 |
| **R33** | **varnode eraseDescend/destroyDescend 缺** | op-edit 根因修 | varnode.rs（无）| varnode.cc:316,344 |
| **R7** | **StackSolver/StackEqn/analyzeExtraPop 全缺** | RSP 泄漏修 | coreaction.rs:5204 | coreaction.cc:25-318 |
| **R8** | **func_link_input 注册 0 ParamActive trial** | CALL 参数修 | coreaction.rs:4906 | coreaction.cc:1490 |

**修复顺序建议**（依赖序）: R33 → R11 → R73 → R75 → R9 → R15 → R50 → R51 → R77 → R5 → R1 → R3 → R7 → R8。**R33+R11 是地基**（op-edit 正确）；**R73+R75 是框架**（Rule 收敛 + 覆盖）；**R9+R15 是单点**（switch 消错源）；**R50+R51 是输出**（语法错/非 C 行）；其余是名字/参数/RSP。

## 三、107 个根因全表（按修复阶段分 5 组）

### 组 A — 地基损坏（先修，阻塞一切）
| R# | 文件 | 根因 | 修复路径 |
|---|---|---|---|
| R33 | varnode | eraseDescend/destroyDescend 缺 | 移植 varnode.cc:316,344 + setFlags(coverdirty) |
| R11 | funcdata | op-edit 不维护 descend 链 | 移植 funcdata_op.cc:104,203,291,92 全不变量 + destroyVarnode |
| R34 | varnode | VarnodeBank::replace 复制 size/loc 非重写读者 | 移植 varnode.cc:1332-1352 |
| R35 | funcdata | op_set_opcode 只派生 7 flag 非 14 | 建 opcode→flags 表（typeop.cc ~70 条）|
| R57 | typeop | opflags/addlflags 混淆 | 加 get_opflags() 区分 addlflags |
| R37 | funcdata | OpCode::from_i32 用于 Ghidra 整数→误分类 | funcdata.rs:2017 改用 map_ghidra_opcode |
| R16 | block | edge-flag 位值全乱 | 重编匹配 block.hh:88-118 |
| R18 | block | halfDeleteInEdge/OutEdge 修 self 非 peer | 移植 block.cc:100-127 peer 修复 |
| R73 | action | perform 迭代上限 1/2 | 删上限→Ghidra 无界 do-while |
| R74 | action | ActionGroup::apply 条件 dispatch | 改调子 perform 无条件 |
| R76 | action | build_full_pipeline 平铺非嵌套 | 恢复 Ghidra 嵌套 |

### 组 B — SSA/合并损坏（uVar_/变量合并根因）
| R# | 文件 | 根因 | 修复路径 |
|---|---|---|---|
| R70 | heritage | 无 collect/disjoint-range pass + 无 size normalization | 移植 heritage.cc:2677-2772,383-605 |
| R71 | heritage | 无 setInputVarnode→rename 空栈提升缺 | 移植 Funcdata::setInputVarnode + heritage.cc:2500-2518 |
| R72 | heritage | deadRemovalAllowed 硬 true + getDeadCodeDelay 硬 2 | buildInfoList 填 + 从 space 取 |
| R48 | cover | 无 CFG 递归填充 | 移植 addRefRecurse backward CFG walk |
| R49 | cover | 0/1/2 边界三档塌 bool + PcodeOpSet/HighIntersectTest 缺 | 加 classify_intersect + HighIntersectTest |
| R82 | variable | merge_internal 死码 + 无 numMergeClasses | 重实 merge 经 merge_internal + 投机类追踪 |
| R83 | variable | highflags 脏枚举全缺 + 无 HighIntersectTest | 加 highflags:u32 + 11 位枚举 + 移植 HighIntersectTest |
| R12 | merge | 缺 HighIntersectTest + StackAffectingOps + 强制合并 snip | 移植 merge.cc:1616,489-810 |
| R46 | rangeutil | intersect 返回约定反转 | 改 Ghidra 契约（0=成功/2=两片失败）|
| R47 | rangeutil | pullBackUnary INT_2COMP/NEGATE 优先级 bug | 括号修正 |

### 组 C — 控制流/结构化损坏（switch/goto/while）
| R# | 文件 | 根因 | 修复路径 |
|---|---|---|---|
| R15 | blockaction | collapse_cbranch_cascades 凭空转 switch | **删**该函数 + 级联支撑代码 |
| R19 | jumptable | EmulateFunction 不读 LoadImage | 接 LoadImage + 真 executeLoad |
| R20 | jumptable | JumpBasic2/Override/Assisted 三模型缺 | 移植 jumptable.cc:1656-2245 |
| R21 | coreaction | ActionSwitchNorm 后恢复桩 | 接 matchModel/recoverLabels/foldIn* |
| R22 | jumptable | calcRange 丢 intersect 返回值 | 用返回值 |
| R13 | tracedag | select_bad_edge siblingedge 极性反转 + distance 公式错 | 反转 + 移植 BranchPoint::distance via markPath |
| R14 | tracedag | check_open 用总入度非 loop-DAG 入度 | 只数 is_loop_dag_in 边 + finishblock |
| R32 | blockaction | NormalizeBranches/FinalStructure 职责对调 | 互换职责匹配 Ghidra |

### 组 D — 代码生成/输出损坏（cast/cast 名/for/语法）
| R# | 文件 | 根因 | 修复路径 |
|---|---|---|---|
| R50 | printc | op_cbranch 吞 None in1 | None 时发占位/跳语句 |
| R51 | printc | op_multiequal/indirect 发垃圾 | 改 no-op{} |
| R52 | printc | 无 opPtrsub/opCast/opPtradd/opSubpiece 独立 handler | 移植 + 加 typeop dispatch |
| R53 | printc | 无 OpToken/RPN 栈 | 长期——考虑移植 |
| R54 | prettyprint | 无 EmitPrettyPrint/Oppen | 长期——或降级声明 L1 |
| R56 | printlanguage | ~20% 表面 + 无 pushOp/recurse | 移植 RPN 引擎 |
| R6 | coreaction | ActionSetCasts 被注释 + 只 castInput | 取消注释 + 移植 castOutput/resolveUnion/testStructOffset0 |
| R23 | subflow | SubfloatFlow 整类缺 | 移植 subflow.cc:3079-3481 |
| R24 | subflow | LaneDivide 整类缺 + ActionLaneDivide 桩 | 移植 subflow.cc:3518-4128 + 解桩 |
| R62 | grammar | 整 CParse 缺 + parse_type 只 lex 2 token | 移植 CParse 或降级声明 |
| R25 | transform | create_op_replacement 丢 MULTIEQUAL→opInsertBegin | 加分支 |
| R26 | transform | constant_iop 做普通常量非 iop varnode | 经 get_op_from_const→new_varnode_iop |

### 组 E — 符号/类型/外围损坏
| R# | 文件 | 根因 | 修复路径 |
|---|---|---|---|
| R1 | varmap | create_entry 不回写 Symbol/HighVariable | 移植 varmap.cc:617-628 addSymbol |
| R2 | varmap | fake_input_symbols 硬 param_{:x} | 改空名 + makeNameUnique |
| R3 | varmap | direction 符号反转 | x86 → +1 |
| R5 | coreaction | ActionNameVars 空桩 | 移植 coreaction.cc:2779-3006 |
| R7 | coreaction | StackSolver 全缺 | 移植 coreaction.cc:25-318 |
| R8 | coreaction | func_link_input 0 trial | 移植 registerTrial + spacebase placeholder |
| R90 | database | 未接管线 + 无 queryProperties | 接 + 移植 database.cc:909-1000 |
| R59 | types | 无 sub_metatype | 加 24 值 submeta + base2sub[18] 表 |
| R60 | types | 3 Partial 子类缺 | 加 PartialStruct/Union/Enum |
| R61 | types | alignment 从 size 派生非存 | 移植 assignFieldOffsets |
| R97 | memstate | MemoryImage 持 Vec 非 LoadImage + 硬小端 | 改持 LoadImage + 加端序 |
| R95 | marshal | 全标准 ID 表未填 + ATTRIB_UNKNOWN=0 应 159 | 填表 + 改 159 |
| R96 | marshal | 无 write_space/read_space | 加 |
| R101 | float_emulate | max_exponent off-by-one | 254→255, 2046→2047 |
| R103 | emulate | execute_load/store 硬 ram | 从 input(0) 解空间 |
| R106 | double_precis | is_arithmetic_op 集错 | 改 Ghidra 集合 |
| R107 | compression | deflate/inflate 返回极性反 + finish 忽略 | 改极性 + 接 finish |
| R77 | coreaction | ActionInputPrototype 抛 ParamActive | 用 FuncCallSpecs.active_input |

（余 R36-R45, R64-R69, R91-R94, R98-R100, R102, R104-R105 见各批报告。）

## 四、按修复 ROI 排序的"如果只改 10 处"清单

1. **R15** 删 `collapse_cbranch_cascades`（blockaction.rs:4014-4283 + 级联支撑）→ switch 18→2
2. **R9** 重写 RuleTrivialArith（ruleaction.rs:321-386）→ switch((x^x)) 消
3. **R50+R51** printc op_cbranch None 处理 + multiequal/indirect 改 no-op → 6 语法错 + 非 C 行消
4. **R73** 删 Action::perform 迭代上限（action.rs:90）→ Rule 真收敛
5. **R33+R11** varnode erase_descend + funcdata op-edit 不变量 → DCE 生效（地基）
6. **R77** ActionInputPrototype 用 FuncCallSpecs.active_input → 48 param_ 退
7. **R75** Rule::get_opcodes 支持"全 opcode" → 3 关键 Rule 覆盖补全
8. **R37** funcdata.rs:2017 用 map_ghidra_opcode → 潜在全树 p-code 误分类消
9. **R97** memstate MemoryImage 读 LoadImage → switch 恢复在真二进制生效
10. **R101** float_emulate max_exponent 254→255 → 浮点 inf/NaN 解码对

## 五、方法论注记

- **每份批报告含逐函数表 + Ghidra 精确行 + 修复路径**——6 份报告共 ~4000 行审计原文，存于 `docs/alignment_docs/function_audit/BATCH1-6_audit_reports.md`。
- **3 个先前审计误判被更正**: buildOutputFromTrials 在 Ghidra 确实有（coreaction P1 否认错）；HighVariable 在 Rust 确实定义且用（varmap 审计"0 引用"错）；double_precis 是 double.cc 非 multiprecision（multiprecision 在 float_emulate.rs 用 host f64）。
- **4 个"零问题"文件**: capability.rs（L4 忠实）、crc32.rs（完美）、prefersplit.rs（近完整）、unify.rs（完整但死码——rulecompile 缺）。
- **AGENTS.md §5/§5.5/§6 的铁律被系统性验证**: 绝大多数 DIFF/MISSING 是"移植缺陷"（守卫缺/算法不完整/基础设施缺口），非 Ghidra 设计如此。修复路径明确：读 Ghidra 精确行 → 移植那个机制。

## 六、下一步

修复阶段（不在本轮）。建议从组 A（地基）开始，按 R33→R11→R73→R75 依赖序；每修一个根因跑 curl/httpd 对比验证增量。**禁止回退已验证工作（§8）；禁止简化绕过（§5/§9）——每个修复都对照 Ghidra 移植那个机制。**
