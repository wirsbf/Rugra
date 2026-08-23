# Rugra vs Ghidra 主流程管线差异分析

**日期**: 2026-07-01
**方法**: 双 agent 并行探查 — Ghidra `universalAction`（coreaction.cc:5462-5739）逐 Action 提取 vs Rugra `set_default_actions`（action.rs:383-492）逐 Action 提取，逐层对齐。
**用途**: 作为主管线对齐的权威基线。所有"接入主管线"相关工作以此为对照表。

---

## 🔴 差异 #0（最根本）：迭代模型完全不同

这是所有其他差异的总根源。

| | Ghidra `universalAction` | Rugra `set_default_actions` |
|---|---|---|
| 顶层 | `ActionRestartGroup("universal")` maxrestarts=1 — **整个管线可重启一次** | 单遍线性 `ActionGroup("decompile")` |
| 外层 | `fullloop` `rule_repeatapply` — **重复到不动点** | 无 |
| 中层 | `mainloop` `rule_repeatapply` — **重复到不动点** | 无 |
| 内层 | `stackstall` `rule_repeatapply` — **重复到不动点** | 无 |
| 规则池 | `oppool1`/`oppool2`/`cleanup` 各自 `rule_repeatapply` | 只有 ActionPool 内部 repeatapply |

**Ghidra 是 4 层嵌套的"重复到收敛"管线**，Rugra 是**单遍走完即结束**。这意味着 Rugra 里任何需要多轮传播才能收敛的东西（类型推断、copy 传播、subvar 流、指针流）都只能靠每个 Action **内部自己手写迭代循环**来弥补——这正是为什么 Rugra 有 `typeinfer`/`copypropagate`/`simplify` 这些 Ghidra **没有的**自造 Action（它们在 Ghidra 里靠外层 fullloop/mainloop 的重复来收敛，不需要 Action 内部自己迭代）。

**对齐方向**：必须把 Rugra 管线改造成 Ghidra 的嵌套 ActionGroup 结构（fullloop→mainloop→stackstall），而不是现在的扁平 24 步。

**源码锚点**：
- Ghidra: `coreaction.cc:5462` (`universalAction`) / `coreaction.cc:5418-5458` (`buildDefaultGroups`) / `action.hh:143-285` (类定义)
- Rugra: `src/action.rs:383-492` (`set_default_actions`) / `src/action.rs:69-80` (`ActionGroup::apply`)

---

## 🔴 差异 #1：顶层 37 步里 Rugra 缺失的 Action

Ghidra `universal` 顶层（`fullloop` 之后）的 37 个 Action，Rugra 的对照：

| Ghidra Action | coreaction.cc | Rugra 状态 |
|---|---|---|
| ActionStart | 5477 | ✅ `start` |
| **ActionConstbase** | 5478 | ⚠️ 有 impl 未接入 |
| **ActionNormalizeSetup** | 5479 | ⚠️ 有 impl 未接入 |
| **ActionDefaultParams** | 5480 | ⚠️ 有 impl 未接入 |
| **ActionExtraPopSetup** | 5482 | ⚠️ 有 impl 未接入 |
| **ActionPrototypeTypes** | 5483 | ⚠️ 有 impl 未接入 |
| ActionFuncLink | 5484 | ✅ `funclink` |
| **ActionFuncLinkOutOnly** | 5485 | ⚠️ 有 impl 未接入 |
| [fullloop] | 5487 | ❌ **整个外层循环缺失** |
| **ActionMappedLocalSync** | 5691 | ⚠️ 有 impl 未接入 |
| **ActionStartCleanUp** | 5692 | ❌ 完全缺失 |
| [cleanup pool] | 5694 | ⚠️ 15 条只接了 4 条 |
| **ActionPreferComplement** | 5714 | ❌ 完全缺失 |
| **ActionStructureTransform** | 5715 | ❌ 完全缺失 |
| ActionNormalizeBranches | 5716 | ✅ `normalizebranches` |
| ActionAssignHigh | 5717 | 🔶 被 `merge_type` 替代 |
| **ActionMergeRequired** | 5718 | ⚠️ stub（被 merge_all 折叠） |
| ActionMarkExplicit | 5719 | ✅ `markexplicit` |
| ActionMarkImplied | 5720 | ✅ `markimplied` |
| **ActionMergeMultiEntry** | 5721 | ⚠️ stub |
| **ActionMergeCopy** | 5722 | ⚠️ stub |
| **ActionDominantCopy** | 5723 | ❌ 缺失 |
| **ActionDynamicSymbols** | 5724 | ⚠️ 有 impl 未接入 |
| **ActionMarkIndirectOnly** | 5725 | ❌ 缺失 |
| **ActionMergeAdjacent** | 5726 | ⚠️ stub |
| ActionMergeType | 5727 | ✅ `merge_type` |
| **ActionHideShadow** | 5728 | ⚠️ 有 impl 未接入 |
| **ActionCopyMarker** | 5729 | ❌ 缺失 |
| **ActionOutputPrototype** | 5730 | ⚠️ 有 impl 未接入 |
| **ActionInputPrototype** | 5731 | ⚠️ 有 impl 未接入 |
| **ActionMapGlobals** | 5732 | ❌ 缺失 |
| **ActionDynamicSymbols** | 5733 | ⚠️ 同上 |
| **ActionNameVars** | 5734 | ⚠️ 有 impl 未接入 |
| **ActionSetCasts** | 5735 | ❌ **注释掉**（依赖未实现的 InferTypes） |
| ActionFinalStructure | 5736 | ✅ `finalstructure` |
| **ActionPrototypeWarnings** | 5737 | ⚠️ 有 impl 未接入 |
| ActionStop | 5738 | ❌ 缺失（用管线结束代替） |

**小结**：37 步里只有 **8 步真正对齐**，4 步被 `Merge::merge_all` 折叠替代（Rugra 自造，非 Ghidra 机制），**19 步有实现但没接入**，**6 步完全缺失**。

---

## 🔴 差异 #2：`fullloop` 内 11 步，Rugra 几乎全缺

Ghidra `fullloop`（重复到不动点的外层，coreaction.cc:5487→5690）：

| Ghidra | 行 | Rugra |
|---|---|---|
| [mainloop] | 5489 | ❌ 缺整个内层循环 |
| ActionLikelyTrash | 5679 | ⚠️ impl 未接入 |
| ActionDirectWrite(true) | 5680 | ⚠️ impl 未接入 |
| ActionDirectWrite(false) | 5681 | ⚠️ impl 未接入 |
| ActionDeadCode | 5682 | ✅（但位置不对，Rugra 放在管线尾部单遍） |
| **ActionDoNothing** | 5683 | ❌ **blocked**（staged→collapseInternal 迁移阻塞） |
| ActionSwitchNorm | 5684 | ⚠️ impl 未接入 |
| **ActionReturnSplit** | 5685 | ❌ 完全缺失 |
| ActionUnjustifiedParams | 5686 | ⚠️ impl 未接入 |
| **ActionStartTypes** | 5687 | ❌ 缺失 |
| ActionActiveReturn | 5688 | ⚠️ impl 未接入 |

---

## 🔴 差异 #3：`mainloop` 内 28 步，Rugra 缺约 20 步

Ghidra `mainloop`（coreaction.cc:5489→5678，`rule_repeatapply`）：

| Ghidra | 行 | Rugra |
|---|---|---|
| **ActionUnreachable** | 5490 | ❌ **blocked**（接入导致 curl 24→11 回归） |
| ActionVarnodeProps | 5491 | ⚠️ impl 未接入 |
| ActionHeritage | 5492 | ✅ `heritage` |
| ActionParamDouble | 5493 | ⚠️ impl 未接入 |
| ActionSegmentize | 5494 | ⚠️ impl 未接入 |
| ActionInternalStorage | 5495 | ⚠️ impl 未接入 |
| ActionForceGoto | 5496 | ⚠️ impl 未接入 |
| ActionDirectWrite×2 | 5497-8 | ⚠️ impl 未接入 |
| ActionActiveParam | 5499 | ⚠️ impl 未接入 |
| ActionReturnRecovery | 5500 | ⚠️ impl 未接入 |
| ActionRestrictLocal | 5502 | ✅ `restrictlocal` |
| ActionDeadCode | 5503 | ✅（重复注册） |
| ActionDynamicMapping | 5504 | ⚠️ impl 未接入 |
| ActionRestructureVarnode | 5505 | ✅ `restructureVarnode` |
| ActionSpacebase | 5506 | ✅ `spacebase` |
| **ActionNonzeroMask** | 5507 | ⚠️ impl 未接入 |
| **ActionInferTypes** | 5508 | ❌ **完全未实现**（阻塞 SetCasts） |
| [stackstall] | 5509 | ❌ 缺整个 group |
| **ActionRedundBranch** | 5658 | ❌ **blocked** |
| ActionBlockStructure | 5659 | ✅ `blockstructure` |
| ActionConstantPtr | 5660 | ✅ `constantptr` |
| **[oppool2]** | 5662 | ❌ **整个池缺失** |
| **ActionDeterminedBranch** | 5672 | ❌ **blocked** |
| **ActionUnreachable** | 5673 | ❌ **blocked** |
| **ActionNodeJoin** | 5674 | ❌ 缺失 |
| ActionConditionalExe | 5675 | ✅ `conditionalexe` |
| **ActionConditionalConst** | 5676 | ⚠️ impl 未接入 |

---

## 🔴 差异 #4：`stackstall` group + oppool1/2 的偏差

**stackstall group**（Ghidra coreaction.cc:5509-5657）：`oppool1` + LaneDivide + MultiCse + ShadowVar + Deindirect + StackPtrFlow。Rugra **没有这个 group 容器**，里面 6 个成员：

- oppool1 → ✅ `simplifypool`，但 **134 条只移植了 ~98 条**
- LaneDivide / ShadowVar / Deindirect → ⚠️ impl 未接入
- MultiCse → 🔶 Rugra 自造 `cse`（非 Ghidra 算法）
- StackPtrFlow → ✅ `stackptrflow`（但脱离了 stackstall 上下文）

**oppool1 缺失的规则族**（action.rs 标 skip）：

- 5517 RulePullsubIndirect、5551 RuleIndirectCollapse、5565 RuleTransformCpool、5606 RuleSwitchSingle
- **5621-5628 整个 subvar 族（8 条）**：SubvarAnd/Subpiece/SplitFlow/PtrFlow/CompZero/Shift/Zext/Sext — 子字传播的核心
- 5629-5648：float/segment/ptradd-undo/ptrsub-undo/double-load/double-store 族（约 15 条）

**oppool2 整个缺失**（Ghidra coreaction.cc:5662-5671）：

| Rule | 行 | 职责 |
|---|---|---|
| RulePushPtr | 5664 | 类型恢复：指针 push |
| RuleStructOffset0 | 5665 | 结构体偏移 0 |
| RulePtrArith | 5666 | 指针算术规范化 |
| RuleLoadVarnode | 5668 | **栈变量化**：LOAD → 命名 varnode |
| RuleStoreVarnode | 5669 | **栈变量化**：STORE → 命名 varnode |

这 5 条规则负责把 LOAD/STORE 转成具名栈变量，Rugra 的栈变量化靠 `restructureVarnode` 自造路径，**非 Ghidra 机制**。

**cleanup 池**（coreaction.cc:5694-5712）：Ghidra 15 条，Rugra 只接了 4 条（MultNegOne/2Comp2Sub/StringCopy/StringStore）。缺失 11 条：

- AddUnsigned(5697) / DumptyHumpLate(5699) / SubRight(5700) / FloatSignCleanup(5701) / ExpandLoad(5702) / PtrsubCharConstant(5703) / ExtensionPush(5704) / PieceStructure(5705) / SplitCopy(5706) / SplitLoad(5707) / SplitStore(5708)

---

## 🔴 差异 #5：Rugra 有 6 个 Ghidra 不存在的自造 Action

这些是 Rugra 为了在**单遍管线**里达到类似效果而自造的，Ghidra 里**没有对应物**：

| Rugra Action | 实现行 | Ghidra 里对应的工作由谁做 |
|---|---|---|
| `simplify` | coreaction.rs:637-758 | oppool1 规则 + fullloop 重复收敛 |
| `typeinfer` | coreaction.rs:1635-1906 | ActionInferTypes（5508）+ oppool2 + fullloop |
| `copypropagate` | coreaction.rs:773-876 | RulePropagateCopy（oppool1:5566）+ fullloop |
| `typepropagate` | action.rs:504-510 | ActionInferTypes 的 propagate 阶段 |
| `inferparams` | coreaction.rs:1311-1616 | ActionActiveParam + ActionDefaultParams + DirectWrite |
| `cse` | coreaction.rs:337-410 | ActionMultiCse（5653）+ RuleSelectCse/CollectTerms（oppool1） |

**问题**：这些自造 Action 的算法和 Ghidra 的不 1:1，是"结果导向"的近似实现。按 AGENTS.md 铁律 #5.5，这是技术债，应逐步替换为 Ghidra 的精确机制。

---

## 🔴 差异 #6：4 个死控制流 Action 被"blocked"

`ActionUnreachable` / `ActionDoNothing` / `ActionRedundBranch` / `ActionDeterminedBranch` 都已实现，但接入后 curl 从 24/24 掉到 11/24，所以被注释掉（action.rs:469-477）。根因是 Rugra 用的是**阶段性 structurer**（`collapse_all` 多阶段），而 Ghidra 这 4 个 Action 依赖 **collapseInternal 架构**（动作随时改 CFG，structurer 消费改后的 CFG）。这是**架构级阻塞**。

---

## 优先级建议（按解锁价值排序）

| 优先级 | 任务 | 解锁什么 | 难度 | 对应差异 |
|---|---|---|---|---|
| **P0** | 改造管线为 fullloop→mainloop→stackstall 嵌套结构 | 让所有"内部自迭代"的 Action 能删掉手写循环，回归 Ghidra 语义 | 高 | #0 |
| **P0** | 接入 19 个"有 impl 未接入"的 Action | 补齐原型恢复/类型恢复/merge 全链路 | 中 | #1-#3 |
| **P1** | 实现 ActionInferTypes + 接入 ActionSetCasts | cast 正确性 | 中高 | #1, #3 |
| **P1** | 补 oppool1 的 subvar 族（8 条）+ float/segment/double 族 | 子字传播、浮点、双载优化 | 中 | #4 |
| **P1** | 补 oppool2 整池（5 条） | 栈变量化走 Ghidra 路径 | 中 | #4 |
| **P2** | staged→collapseInternal 迁移，解锁 4 个死控制流 Action | 不可达代码消除、冗余分支消除 | 高 | #6 |
| **P2** | 补 cleanup 池剩余 11 条 | 规范化质量 | 低 | #4 |
| **P3** | 用 Ghidra 机制替换 6 个自造 Action | 消除技术债 | 高 | #5 |

---

## 附录：Ghidra universalAction 完整嵌套结构（执行顺序）

```
universal (ActionRestartGroup, maxrestarts=1)              [coreaction.cc:5474]
├─ ActionStart                          base               [5477]
├─ ActionConstbase                      base               [5478]
├─ ActionNormalizeSetup                 normalanalysis     [5479]
├─ ActionDefaultParams                  base               [5480]
├─ ActionExtraPopSetup                  base               [5482]
├─ ActionPrototypeTypes                 protorecovery      [5483]
├─ ActionFuncLink                       protorecovery      [5484]
├─ ActionFuncLinkOutOnly                noproto            [5485]
├─ fullloop (ActionGroup, repeatapply)                     [5487→5690]
│  ├─ mainloop (ActionGroup, repeatapply)                  [5489→5678]
│  │  ├─ ActionUnreachable              base               [5490]
│  │  ├─ ActionVarnodeProps             base               [5491]
│  │  ├─ ActionHeritage                 base               [5492]
│  │  ├─ ActionParamDouble              protorecovery      [5493]
│  │  ├─ ActionSegmentize               base               [5494]
│  │  ├─ ActionInternalStorage          base               [5495]
│  │  ├─ ActionForceGoto                blockrecovery      [5496]
│  │  ├─ ActionDirectWrite(true)        protorecovery_a    [5497]
│  │  ├─ ActionDirectWrite(false)       protorecovery_b    [5498]
│  │  ├─ ActionActiveParam              protorecovery      [5499]
│  │  ├─ ActionReturnRecovery           protorecovery      [5500]
│  │  ├─ ActionRestrictLocal            localrecovery      [5502]
│  │  ├─ ActionDeadCode                 deadcode           [5503]
│  │  ├─ ActionDynamicMapping           dynamic            [5504]
│  │  ├─ ActionRestructureVarnode       localrecovery      [5505]
│  │  ├─ ActionSpacebase                base               [5506]
│  │  ├─ ActionNonzeroMask              analysis           [5507]
│  │  ├─ ActionInferTypes               typerecovery       [5508]
│  │  ├─ stackstall (ActionGroup, repeatapply)             [5509→5657]
│  │  │  ├─ oppool1 (ActionPool, 134 rules + CPU-specific) [5511→5651]
│  │  │  ├─ ActionLaneDivide            base               [5652]
│  │  │  ├─ ActionMultiCse              analysis           [5653]
│  │  │  ├─ ActionShadowVar             analysis           [5654]
│  │  │  ├─ ActionDeindirect            deindirect         [5655]
│  │  │  └─ ActionStackPtrFlow          stackptrflow       [5656]
│  │  ├─ ActionRedundBranch             deadcontrolflow    [5658]
│  │  ├─ ActionBlockStructure           blockrecovery      [5659]
│  │  ├─ ActionConstantPtr              typerecovery       [5660]
│  │  ├─ oppool2 (ActionPool, 5 rules)                     [5662→5671]
│  │  │  ├─ RulePushPtr                 typerecovery       [5664]
│  │  │  ├─ RuleStructOffset0           typerecovery       [5665]
│  │  │  ├─ RulePtrArith                typerecovery       [5666]
│  │  │  ├─ RuleLoadVarnode             stackvars          [5668]
│  │  │  └─ RuleStoreVarnode            stackvars          [5669]
│  │  ├─ ActionDeterminedBranch         unreachable        [5672]
│  │  ├─ ActionUnreachable              unreachable        [5673]
│  │  ├─ ActionNodeJoin                 nodejoin           [5674]
│  │  ├─ ActionConditionalExe           conditionalexe     [5675]
│  │  └─ ActionConditionalConst         analysis           [5676]
│  ├─ ActionLikelyTrash                 protorecovery      [5679]
│  ├─ ActionDirectWrite(true)           protorecovery_a    [5680]
│  ├─ ActionDirectWrite(false)          protorecovery_b    [5681]
│  ├─ ActionDeadCode                    deadcode           [5682]
│  ├─ ActionDoNothing                   deadcontrolflow    [5683]
│  ├─ ActionSwitchNorm                  switchnorm         [5684]
│  ├─ ActionReturnSplit                 returnsplit        [5685]
│  ├─ ActionUnjustifiedParams           protorecovery      [5686]
│  ├─ ActionStartTypes                  typerecovery       [5687]
│  └─ ActionActiveReturn                protorecovery      [5688]
├─ ActionMappedLocalSync               localrecovery      [5691]
├─ ActionStartCleanUp                  cleanup            [5692]
├─ cleanup (ActionPool, 15 rules)                          [5694→5712]
├─ ActionPreferComplement              blockrecovery      [5714]
├─ ActionStructureTransform            blockrecovery      [5715]
├─ ActionNormalizeBranches             normalizebranches  [5716]
├─ ActionAssignHigh                    merge              [5717]
├─ ActionMergeRequired                 merge              [5718]
├─ ActionMarkExplicit                  merge              [5719]
├─ ActionMarkImplied                   merge              [5720]
├─ ActionMergeMultiEntry               merge              [5721]
├─ ActionMergeCopy                     merge              [5722]
├─ ActionDominantCopy                  merge              [5723]
├─ ActionDynamicSymbols                dynamic            [5724]
├─ ActionMarkIndirectOnly               merge              [5725]
├─ ActionMergeAdjacent                 merge              [5726]
├─ ActionMergeType                     merge              [5727]
├─ ActionHideShadow                    merge              [5728]
├─ ActionCopyMarker                    merge              [5729]
├─ ActionOutputPrototype               localrecovery      [5730]
├─ ActionInputPrototype                fixateproto        [5731]
├─ ActionMapGlobals                    fixateglobals      [5732]
├─ ActionDynamicSymbols                dynamic            [5733]
├─ ActionNameVars                      merge              [5734]
├─ ActionSetCasts                      casts              [5735]
├─ ActionFinalStructure                blockrecovery      [5736]
├─ ActionPrototypeWarnings             protorecovery      [5737]
└─ ActionStop                          base               [5738]
```

## 附录：Rugra 当前主管线（action.rs:383-492, 扁平单遍）

```
decompile (ActionGroup, 单遍线性)                          [action.rs:384]
├─ start                                                  [386]
├─ funclink                                               [392]
├─ heritage  (内嵌 DeadCode + 两遍 place/rename)          [393]
├─ spacebase                                              [399]
├─ stackptrflow                                           [404]
├─ inferparams       (Rugra 自造)                         [405]
├─ constantptr                                           [406]
├─ cse               (Rugra 自造)                         [407]
├─ simplify          (Rugra 自造)                         [408]
├─ simplifypool      (oppool1 子集 ~98 条)                [413]
├─ cleanup           (actcleanup 子集 4 条)               [419]
├─ typeinfer         (Rugra 自造)                         [424]
├─ copypropagate     (Rugra 自造)                         [425]
├─ typepropagate     (Rugra 自造)                         [426]
├─ restrictlocal                                         [435]
├─ deadcode                                               [436]
├─ merge_type                                             [450]
├─ markexplicit                                           [459]
├─ markimplied                                            [460]
├─ restructureVarnode                                    [483]
├─ conditionalexe                                        [486]
├─ blockstructure                                        [487]
├─ normalizebranches                                     [488]
└─ finalstructure                                        [489]
```

---

## 数字汇总

| 维度 | Ghidra | Rugra | 差距 |
|---|---|---|---|
| 管线容器层级 | 4 层嵌套（universal→fullloop→mainloop→stackstall） | 1 层扁平 | -3 层 |
| 顶层 Action 数 | 37 | 24（含 6 自造） | -13 |
| fullloop 内 Action | 11 | 0（无 fullloop） | -11 |
| mainloop 内 Action | 28 | 0（无 mainloop） | -28 |
| stackstall 内 Action | 6 | 0（无 stackstall，成员散落） | -6 |
| oppool1 规则数 | 134（+CPU 特定） | ~98 | -36 |
| oppool2 规则数 | 5 | 0 | -5 |
| cleanup 规则数 | 15 | 4 | -11 |
| 真正对齐的顶层 Action | — | 8/37 | 22% |
| Ghidra 不存在的自造 Action | 0 | 6 | +6（技术债） |
| 实现已写但未接入的 Action | — | ~19 | 待接线 |
| 完全缺失的 Action | — | ~6 | 待实现 |
| 架构级 blocked 的 Action | — | 4 | 待迁移 |
